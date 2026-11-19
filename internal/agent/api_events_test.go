package internal_agent

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// newEventsTestAgent starts a gRPC server backed by an agent that only has the event plumbing set up.
func newEventsTestAgent(t *testing.T) (*computeBladeAgent, bladeapiv1alpha1.BladeAgentServiceClient) {
	t.Helper()

	a := &computeBladeAgent{
		eventBus: events.New(),
		hostname: "blade-test",
		shutdown: make(chan struct{}),
	}

	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	bladeapiv1alpha1.RegisterBladeAgentServiceServer(server, a)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return a, bladeapiv1alpha1.NewBladeAgentServiceClient(conn)
}

// publishUntilReceived publishes msg repeatedly until the stream receives an event. This avoids racing the
// server-side subscription, which is set up asynchronously after the client opened the stream.
func publishUntilReceived(t *testing.T, a *computeBladeAgent, stream bladeapiv1alpha1.BladeAgentService_WatchEventsClient, msg events.Message) *bladeapiv1alpha1.AgentEvent {
	t.Helper()

	received := make(chan *bladeapiv1alpha1.AgentEvent, 1)
	go func() {
		ev, err := stream.Recv()
		if err == nil {
			received <- ev
		}
	}()

	deadline := time.After(5 * time.Second)
	for {
		a.eventBus.Publish(eventsTopic, msg)
		select {
		case ev := <-received:
			return ev
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatal("timed out waiting for event")
			return nil
		}
	}
}

func TestWatchEvents_StreamsEvents(t *testing.T) {
	t.Parallel()

	a, client := newEventsTestAgent(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream, err := client.WatchEvents(ctx, &bladeapiv1alpha1.WatchEventsRequest{})
	require.NoError(t, err)

	ts := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	ev := publishUntilReceived(t, a, stream, events.Message{Event: events.CriticalEvent, Timestamp: ts})

	assert.Equal(t, bladeapiv1alpha1.Event_CRITICAL, ev.GetEvent())
	assert.Equal(t, "blade-test", ev.GetBlade())
	assert.True(t, ts.Equal(ev.GetTimestamp().AsTime()))
}

func TestWatchEvents_Filter(t *testing.T) {
	t.Parallel()

	a, client := newEventsTestAgent(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream, err := client.WatchEvents(ctx, &bladeapiv1alpha1.WatchEventsRequest{
		Events: []bladeapiv1alpha1.Event{bladeapiv1alpha1.Event_IDENTIFY},
	})
	require.NoError(t, err)

	// Wait until the subscription is live, then publish a filtered-out event followed by a matching one.
	first := publishUntilReceived(t, a, stream, events.NewMessage(events.IdentifyEvent, nil))
	assert.Equal(t, bladeapiv1alpha1.Event_IDENTIFY, first.GetEvent())

	a.eventBus.Publish(eventsTopic, events.NewMessage(events.CriticalEvent, nil))
	a.eventBus.Publish(eventsTopic, events.NewMessage(events.IdentifyEvent, nil))

	next, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, bladeapiv1alpha1.Event_IDENTIFY, next.GetEvent())
}

func TestWatchEvents_EndsOnShutdown(t *testing.T) {
	t.Parallel()

	a, client := newEventsTestAgent(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream, err := client.WatchEvents(ctx, &bladeapiv1alpha1.WatchEventsRequest{})
	require.NoError(t, err)
	publishUntilReceived(t, a, stream, events.NewMessage(events.EdgeButtonEvent, nil))

	a.shutdownOnce.Do(func() { close(a.shutdown) })

	_, err = stream.Recv()
	assert.True(t, errors.Is(err, io.EOF), "expected EOF, got %v", err)
}

func TestToProtoEvent_InternalEventsAreNotPublished(t *testing.T) {
	t.Parallel()

	_, err := toProtoEvent(events.NewMessage(events.NoopEvent, nil), "blade")
	assert.Error(t, err)
}
