package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	eventFilterNames []string
	eventsOutput     string
)

// eventsReconnectDelay is the delay before bladectl re-subscribes after an event stream broke
const eventsReconnectDelay = 2 * time.Second

func init() {
	cmdEvents.Flags().StringArrayVarP(&eventFilterNames, "event", "e", nil,
		fmt.Sprintf("only show these events (repeatable). One of: %s", strings.Join(eventNames(), ", ")))
	cmdEvents.Flags().StringVarP(&eventsOutput, "output", "o", "text", "output format: text or json")
	rootCmd.AddCommand(cmdEvents)
}

var cmdEvents = &cobra.Command{
	Use:   "events",
	Short: "Stream events from the compute-blade-agent",
	Long: "Streams events (button presses, identify, critical mode, ...) from one or more compute-blades as they happen.\n" +
		"The stream reconnects automatically if the agent restarts. Press Ctrl+C to stop.",
	Example: "bladectl events\n" +
		"bladectl events --all --event critical --event critical_reset\n" +
		"bladectl events -o json | jq .",
	Args: cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, _ []string) error {
		if eventsOutput != "text" && eventsOutput != "json" {
			return fmt.Errorf("invalid output format %q, must be text or json", eventsOutput)
		}

		filter, err := parseEventFilter(eventFilterNames)
		if err != nil {
			return err
		}

		ctx := cmd.Context()
		clients := clientsFromContext(ctx)
		printer := &eventPrinter{out: os.Stdout, json: eventsOutput == "json"}

		var wg sync.WaitGroup
		for idx, client := range clients {
			wg.Add(1)
			go func(name string, client bladeapiv1alpha1.BladeAgentServiceClient) {
				defer wg.Done()
				watchBladeEvents(ctx, name, client, filter, printer)
			}(bladeNames[idx], client)
		}
		wg.Wait()

		if errors.Is(context.Cause(ctx), context.Canceled) {
			return nil
		}
		return ctx.Err()
	},
}

// watchBladeEvents streams events of a single blade, re-subscribing after errors until ctx is done.
// streamBladeEvents only returns once the stream broke, so every return is reported and retried.
func watchBladeEvents(ctx context.Context, name string, client bladeapiv1alpha1.BladeAgentServiceClient, filter []bladeapiv1alpha1.Event, printer *eventPrinter) {
	for {
		err := streamBladeEvents(ctx, name, client, filter, printer)
		if ctx.Err() != nil {
			return
		}
		if status.Code(err) == codes.Unimplemented {
			_, _ = fmt.Fprintf(os.Stderr, "%s: agent does not support event streaming, please upgrade the compute-blade-agent\n", name)
			return
		}
		_, _ = fmt.Fprintf(os.Stderr, "%s: event stream interrupted: %v (reconnecting in %s)\n", name, err, eventsReconnectDelay)

		select {
		case <-ctx.Done():
			return
		case <-time.After(eventsReconnectDelay):
		}
	}
}

func streamBladeEvents(ctx context.Context, name string, client bladeapiv1alpha1.BladeAgentServiceClient, filter []bladeapiv1alpha1.Event, printer *eventPrinter) error {
	stream, err := client.WatchEvents(ctx, &bladeapiv1alpha1.WatchEventsRequest{Events: filter})
	if err != nil {
		return err
	}

	for {
		event, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("agent closed the stream")
		}
		if err != nil {
			return err
		}
		printer.print(name, event)
	}
}

// eventPrinter serialises output of concurrent event streams
type eventPrinter struct {
	mu   sync.Mutex
	out  io.Writer
	json bool
}

func (p *eventPrinter) print(name string, event *bladeapiv1alpha1.AgentEvent) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.json {
		// EmitDefaultValues keeps the event field for IDENTIFY, which is the enum's zero value
		raw, err := protojson.MarshalOptions{UseProtoNames: true, EmitDefaultValues: true}.Marshal(event)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s: failed to marshal event: %v\n", name, err)
			return
		}
		_, _ = fmt.Fprintln(p.out, string(raw))
		return
	}

	line := fmt.Sprintf("%s  %-16s  %s",
		event.GetTimestamp().AsTime().Local().Format(time.RFC3339),
		name,
		strings.ToLower(event.GetEvent().String()),
	)
	if details := formatEventDetails(event); details != "" {
		line += "  " + details
	}
	_, _ = fmt.Fprintln(p.out, line)
}

// formatEventDetails renders event-specific details as space separated key=value pairs
func formatEventDetails(event *bladeapiv1alpha1.AgentEvent) string {
	switch details := event.GetDetails().(type) {
	case *bladeapiv1alpha1.AgentEvent_Fan:
		return fmt.Sprintf("target=%d%% rpm=%d", details.Fan.GetTargetPercent(), details.Fan.GetRpm())
	case *bladeapiv1alpha1.AgentEvent_Button:
		return "source=" + details.Button.GetSource()
	case *bladeapiv1alpha1.AgentEvent_Gesture:
		g := details.Gesture
		out := "gesture=" + g.GetGesture()
		if g.GetGesture() == "long_press" {
			out += fmt.Sprintf(" held=%s", time.Duration(g.GetHeldMs())*time.Millisecond)
		} else {
			out += fmt.Sprintf(" presses=%d", g.GetPresses())
		}
		if g.GetAction() != "" {
			out += " action=" + g.GetAction()
		}
		return out
	case *bladeapiv1alpha1.AgentEvent_PowerLimit:
		p := details.PowerLimit
		out := fmt.Sprintf("reasons=%s", strings.Join(p.GetReasons(), ","))
		if p.GetGovernor() != "" {
			out += " governor=" + p.GetGovernor()
		}
		if p.GetMaxFreqMhz() != 0 {
			out += fmt.Sprintf(" max_freq=%dMHz", p.GetMaxFreqMhz())
		}
		return out
	case *bladeapiv1alpha1.AgentEvent_Throttle:
		t := details.Throttle
		return fmt.Sprintf("flags=0x%x under_voltage=%t arm_freq_capped=%t throttled=%t soft_temp_limit=%t",
			t.GetFlags(), t.GetUnderVoltage(), t.GetArmFreqCapped(), t.GetThrottled(), t.GetSoftTempLimit())
	default:
		return ""
	}
}

// eventNames returns the lower-case names of all events, as accepted by --event
func eventNames() []string {
	names := make([]string, 0, len(bladeapiv1alpha1.Event_name))
	for i := 0; i < len(bladeapiv1alpha1.Event_name); i++ {
		names = append(names, strings.ToLower(bladeapiv1alpha1.Event_name[int32(i)]))
	}
	return names
}

// parseEventFilter converts event names (case-insensitive) into API events
func parseEventFilter(names []string) ([]bladeapiv1alpha1.Event, error) {
	filter := make([]bladeapiv1alpha1.Event, 0, len(names))
	for _, name := range names {
		value, ok := bladeapiv1alpha1.Event_value[strings.ToUpper(strings.TrimSpace(name))]
		if !ok {
			return nil, fmt.Errorf("unknown event %q, must be one of: %s", name, strings.Join(eventNames(), ", "))
		}
		filter = append(filter, bladeapiv1alpha1.Event(value))
	}
	return filter, nil
}
