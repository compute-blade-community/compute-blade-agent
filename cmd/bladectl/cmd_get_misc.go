package main

import (
	"fmt"

	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"github.com/spf13/cobra"
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
			clients := clientsFromContext(ctx)

			for idx, client := range clients {
				bladeStatus, err := client.GetStatus(ctx, &emptypb.Empty{})
				if err != nil {
					return err
				}

				temp := bladeStatus.Temperature
				rowPrefix := bladeNames[idx]
				if len(bladeNames) > 1 {
					rowPrefix += ": "
				} else {
					rowPrefix = ""
				}

				fmt.Println(tempStyle(temp, bladeStatus.CriticalTemperatureThreshold).Render(rowPrefix + tempLabel(temp)))
			}
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

				fmt.Println(activeStyle(bladeStatus.CriticalActive).Render(rowPrefix + activeLabel(bladeStatus.CriticalActive)))
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

				fmt.Println(rowPrefix + hal.PowerStatus(bladeStatus.PowerStatus).String())
			}

			return nil
		},
	}
)
