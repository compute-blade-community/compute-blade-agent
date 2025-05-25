package main

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	bladeapiv1alpha1 "github.com/uptime-industries/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/uptime-industries/compute-blade-agent/pkg/util"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	percent int
	auto    bool
)

func init() {
	cmdSetFan.Flags().IntVarP(&percent, "percent", "p", 40, "Fan speed in percent (Default: 40).")
	cmdSetFan.Flags().BoolVarP(&auto, "auto", "a", false, "Set fan speed to automatic mode.")

	cmdSet.AddCommand(cmdSetFan)
	cmdGet.AddCommand(cmdGetFan)
	cmdRemove.AddCommand(cmdRmFan)
	cmdDescribe.AddCommand(cmdDescribeFan)
}

var (
	fanAliases = []string{"fan_speed", "rpm"}

	cmdSetFan = &cobra.Command{
		Use:     "fan",
		Aliases: fanAliases,
		Short:   "Control the fan behavior of the compute-blade",
		Example: "bladectl set fan --percent 50",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error

			ctx := cmd.Context()
			client := clientFromContext(ctx)

			if auto {
				_, err = client.SetFanSpeedAuto(ctx, &emptypb.Empty{})
			} else {
				_, err = client.SetFanSpeed(ctx, &bladeapiv1alpha1.SetFanSpeedRequest{
					Percent: int64(percent),
				})
			}

			return err
		},
	}

	cmdRmFan = &cobra.Command{
		Use:     "fan",
		Aliases: fanAliases,
		Short:   "Remove the fan speed override of the compute-blade",
		Example: "bladectl unset fan",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			client := clientFromContext(ctx)

			_, err := client.SetFanSpeedAuto(ctx, &emptypb.Empty{})
			return err
		},
	}

	cmdGetFan = &cobra.Command{
		Use:     "fan",
		Aliases: fanAliases,
		Short:   "Get the fan speed of the compute-blade",
		Example: "bladectl get fan",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			client := clientFromContext(ctx)

			bladeStatus, err := client.GetStatus(ctx, &emptypb.Empty{})
			if err != nil {
				return err
			}

			if bladeStatus.FanSpeedAutomatic {
				fmt.Printf("%d RPM (%d%%)\n", bladeStatus.FanRpm, bladeStatus.FanPercent)
			} else {
				fmt.Printf("%d RPM (Override: %d%%)\n", bladeStatus.FanRpm, bladeStatus.FanPercent)
			}
			return nil
		},
	}

	cmdDescribeFan = &cobra.Command{
		Use:     "fan",
		Aliases: fanAliases,
		Short:   "Get the fan speed curve of the compute-blade",
		Example: "bladectl describe fan",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			client := clientFromContext(ctx)

			bladeStatus, err := client.GetStatus(ctx, &emptypb.Empty{})
			if err != nil {
				return err
			}

			values := make([]util.KeyValuePair, len(bladeStatus.FanCurveSteps))
			for idx, step := range bladeStatus.FanCurveSteps {
				values[idx] = util.KeyValuePair{
					Key:    fmt.Sprintf("%d°C", step.Temperature),
					Format: "%d%%",
					Value:  []any{step.Percent},
					Style: func([]any) lipgloss.Style {
						return tempStyle(step.Temperature, bladeStatus.CriticalTemperatureThreshold)
					},
				}
			}

			fmt.Println(util.PrintKeyValues(values))
			return nil
		},
	}
)
