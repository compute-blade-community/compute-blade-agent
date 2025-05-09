package main

import (
	"fmt"

	"github.com/sierrasoftworks/humane-errors-go"
	"github.com/spf13/cobra"
	bladeapiv1alpha1 "github.com/uptime-industries/compute-blade-agent/api/bladeapi/v1alpha1"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	confirm bool
	wait    bool
)

func init() {
	cmdSetIdentify.Flags().BoolVarP(&confirm, "confirm", "c", false, "confirm the identify state")
	cmdSetIdentify.Flags().BoolVarP(&wait, "wait", "w", false, "Wait for the identify state to be confirmed (e.g. by a physical button press)")
	cmdSet.AddCommand(cmdSetIdentify)
	cmdRemove.AddCommand(cmdRmIdentify)
}

var cmdSetIdentify = &cobra.Command{
	Use:     "identify",
	Example: "bladectl set identify --wait",
	Short:   "interact with the compute-blade identity LED",
	RunE:    runSetIdentify,
}

var cmdRmIdentify = &cobra.Command{
	Use:     "identify",
	Example: "bladectl unset identify",
	Short:   "remove the identify state with the compute-blade identity LED",
	RunE:    runRemoveIdentify,
}

func runSetIdentify(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	client := clientFromContext(ctx)

	// Check if we should wait for the identify state to be confirmed
	event := bladeapiv1alpha1.Event_IDENTIFY
	if confirm {
		event = bladeapiv1alpha1.Event_IDENTIFY_CONFIRM
	}

	// Emit the event to the compute-blade-agent
	_, err := client.EmitEvent(ctx, &bladeapiv1alpha1.EmitEventRequest{Event: event})
	if err != nil {
		return fmt.Errorf(humane.Wrap(err,
			"failed to emit event",
			"ensure the compute-blade agent is running and responsive to requests",
			"check the compute-blade agent logs for more information using 'journalctl -u compute-blade-agent.service'",
		).Display(),
		)
	}

	// Check if we should wait for the identify state to be confirmed
	if !wait {
		return nil
	}

	if _, err := client.WaitForIdentifyConfirm(ctx, &emptypb.Empty{}); err != nil {
		return humane.Wrap(err, "unable to wait for confirmation", "ensure the compute-blade agent is running and responsive to requests", "check the compute-blade agent logs for more information using 'journalctl -u compute-blade-agent.service'")
	}

	return nil
}

func runRemoveIdentify(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	client := clientFromContext(ctx)

	// Emit the event to the compute-blade-agent
	_, err := client.EmitEvent(ctx, &bladeapiv1alpha1.EmitEventRequest{Event: bladeapiv1alpha1.Event_IDENTIFY_CONFIRM})
	if err != nil {
		return fmt.Errorf(humane.Wrap(err,
			"failed to emit event",
			"ensure the compute-blade agent is running and responsive to requests",
			"check the compute-blade agent logs for more information using 'journalctl -u compute-blade-agent.service'",
		).Display(),
		)
	}

	return nil
}
