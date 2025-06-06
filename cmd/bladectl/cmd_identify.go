package main

import (
	"errors"
	"fmt"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/sierrasoftworks/humane-errors-go"
	"github.com/spf13/cobra"
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
	cmdGet.AddCommand(cmdGetIdentify)
}

var (
	cmdSetIdentify = &cobra.Command{
		Use:     "identify",
		Example: "bladectl set identify --wait",
		Short:   "interact with the compute-blade identity LED",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if len(bladeNames) > 1 && wait {
				return fmt.Errorf("cannot enable identify on multiple compute-blades at the same with the --wait flag")
			}

			ctx := cmd.Context()
			clients := clientsFromContext(ctx)

			for _, client := range clients {
				// Check if we should wait for the identify state to be confirmed
				event := bladeapiv1alpha1.Event_IDENTIFY
				if confirm {
					event = bladeapiv1alpha1.Event_IDENTIFY_CONFIRM
				}

				// Emit the event to the compute-blade-agent
				_, err := client.EmitEvent(ctx, &bladeapiv1alpha1.EmitEventRequest{Event: event})
				if err != nil {
					return errors.New(humane.Wrap(err,
						"failed to emit event",
						"ensure the compute-blade agent is running and responsive to requests",
						"check the compute-blade agent logs for more information using 'journalctl -u compute-blade-agent.service'",
					).Display())
				}

				// Check if we should wait for the identify state to be confirmed
				if wait {
					if _, err := client.WaitForIdentifyConfirm(ctx, &emptypb.Empty{}); err != nil {
						return errors.New(
							humane.Wrap(err, "unable to wait for confirmation",
								"ensure the compute-blade agent is running and responsive to requests",
								"check the compute-blade agent logs for more information using 'journalctl -u compute-blade-agent.service'",
							).Display())
					}
				}
			}

			return nil
		},
	}

	cmdRmIdentify = &cobra.Command{
		Use:     "identify",
		Example: "bladectl unset identify",
		Short:   "remove the identify state with the compute-blade identity LED",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			clients := clientsFromContext(ctx)

			for _, client := range clients {
				// Emit the event to the compute-blade-agent
				_, err := client.EmitEvent(ctx, &bladeapiv1alpha1.EmitEventRequest{Event: bladeapiv1alpha1.Event_IDENTIFY_CONFIRM})
				if err != nil {
					return errors.New(humane.Wrap(err,
						"failed to emit event",
						"ensure the compute-blade agent is running and responsive to requests",
						"check the compute-blade agent logs for more information using 'journalctl -u compute-blade-agent.service'",
					).Display())
				}
			}

			return nil
		},
	}

	cmdGetIdentify = &cobra.Command{
		Use:     "identify",
		Example: "bladectl get identify",
		Short:   "get the identify state of the compute-blade identity LED",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			clients := clientsFromContext(ctx)

			for idx, client := range clients {
				bladeStatus, err := client.GetStatus(ctx, &emptypb.Empty{})
				if err != nil {
					return err
				}

				rowPrefix := bladeNames[idx]
				if len(bladeNames) > 1 {
					rowPrefix += ": "
				} else {
					rowPrefix = ""
				}

				fmt.Println(activeStyle(bladeStatus.IdentifyActive).Render(rowPrefix, activeLabel(bladeStatus.IdentifyActive)))
			}

			return nil
		},
	}
)
