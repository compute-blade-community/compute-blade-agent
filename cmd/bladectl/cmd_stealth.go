package main

import (
	"fmt"

	"github.com/spf13/cobra"
	bladeapiv1alpha1 "github.com/uptime-industries/compute-blade-agent/api/bladeapi/v1alpha1"
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
			client := clientFromContext(ctx)

			_, err := client.SetStealthMode(ctx, &bladeapiv1alpha1.StealthModeRequest{
				Enable: !disable,
			})

			return err
		},
	}

	cmdRmStealth = &cobra.Command{
		Use:     "stealth",
		Short:   "Disable stealth mode on the compute-blade",
		Example: "bladectl remove stealth",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			client := clientFromContext(ctx)

			_, err := client.SetStealthMode(ctx, &bladeapiv1alpha1.StealthModeRequest{
				Enable: false,
			})

			return err
		},
	}

	cmdGetStealth = &cobra.Command{
		Use:     "stealth",
		Short:   "Get the stealth mode status of the compute-blade",
		Example: "bladectl get stealth",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error

			ctx := cmd.Context()
			client := clientFromContext(ctx)

			bladeStatus, err := client.GetStatus(ctx, &emptypb.Empty{})
			if err != nil {
				return err
			}

			if bladeStatus.StealthMode {
				fmt.Println("Stealth mode active")
			} else {
				fmt.Println("Not set")
			}

			return nil
		},
	}
)
