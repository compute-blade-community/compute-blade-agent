package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/uptime-industries/compute-blade-agent/pkg/hal"
	"google.golang.org/protobuf/types/known/emptypb"
)

func init() {
	cmdGet.AddCommand(cmdGetTemp)
	cmdGet.AddCommand(cmdGetCritical)
	cmdGet.AddCommand(cmdGetPowerStatus)
}

var (
	cmdGetTemp = &cobra.Command{
		Use:     "temp",
		Aliases: []string{"temperature"},
		Short:   "Get the temperature of the compute-blade",
		Example: "bladectl get temp",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			client := clientFromContext(ctx)
			bladeStatus, err := client.GetStatus(ctx, &emptypb.Empty{})
			if err != nil {
				return err
			}

			fmt.Printf("%d°C\n", bladeStatus.Temperature)
			return nil
		},
	}

	cmdGetCritical = &cobra.Command{
		Use:     "critical",
		Short:   "Get the critical of the compute-blade",
		Example: "bladectl get critical",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			client := clientFromContext(ctx)
			bladeStatus, err := client.GetStatus(ctx, &emptypb.Empty{})
			if err != nil {
				return err
			}

			if bladeStatus.CriticalActive {
				fmt.Println("Critical mode active")
			} else {
				fmt.Println("Not set")
			}

			return nil
		},
	}

	cmdGetPowerStatus = &cobra.Command{
		Use:     "power_status",
		Aliases: []string{"powerstatus", "power"},
		Short:   "Get the power status of the compute-blade",
		Example: "bladectl get power",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			client := clientFromContext(ctx)
			bladeStatus, err := client.GetStatus(ctx, &emptypb.Empty{})
			if err != nil {
				return err
			}

			fmt.Println(hal.PowerStatus(bladeStatus.PowerStatus).String())
			return nil
		},
	}
)
