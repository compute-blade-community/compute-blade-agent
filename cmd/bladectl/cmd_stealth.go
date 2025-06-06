package main

import (
	"fmt"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"
)

var disable bool

func init() {
	cmdSetStealth.Flags().BoolVarP(&disable, "disable", "e", false, "disable stealth mode")

	cmdSet.AddCommand(cmdSetStealth)
	cmdRemove.AddCommand(cmdRmStealth)
	cmdGet.AddCommand(cmdGetStealth)
}

var (
	cmdSetStealth = &cobra.Command{
		Use:     "stealth",
		Short:   "Enable or disable stealth mode on the compute-blade",
		Example: "bladectl set stealth --disable",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			clients := clientsFromContext(ctx)
			for _, client := range clients {
				_, err := client.SetStealthMode(ctx, &bladeapiv1alpha1.StealthModeRequest{Enable: !disable})
				if err != nil {
					return err
				}
			}

			return nil
		},
	}

	cmdRmStealth = &cobra.Command{
		Use:     "stealth",
		Short:   "Disable stealth mode on the compute-blade",
		Example: "bladectl remove stealth",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			clients := clientsFromContext(ctx)
			for _, client := range clients {
				_, err := client.SetStealthMode(ctx, &bladeapiv1alpha1.StealthModeRequest{Enable: false})
				if err != nil {
					return err
				}
			}

			return nil
		},
	}

	cmdGetStealth = &cobra.Command{
		Use:     "stealth",
		Short:   "Get the stealth mode status of the compute-blade",
		Example: "bladectl get stealth",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
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

				fmt.Println(activeStyle(bladeStatus.StealthMode).Render(rowPrefix, activeLabel(bladeStatus.StealthMode)))
			}

			return nil
		},
	}
)
