package main

import (
	"fmt"
	"os"
	"sort"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/spf13/cobra"
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
			autoSet := cmd.Flags().Changed("auto")
			percentSet := cmd.Flags().Changed("percent")

			if autoSet && percentSet {
				return fmt.Errorf("only one of --auto or --percent can be specified")
			}

			if !autoSet && !percentSet {
				return fmt.Errorf("you must specify either --auto or --percent")
			}

			ctx := cmd.Context()
			clients := clientsFromContext(ctx)

			for _, client := range clients {
				var err error

				if auto {
					_, err = client.SetFanSpeedAuto(ctx, &emptypb.Empty{})
				} else {
					_, err = client.SetFanSpeed(ctx, &bladeapiv1alpha1.SetFanSpeedRequest{
						Percent: int64(percent),
					})
				}

				if err != nil {
					return err
				}
			}

			return nil
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
			clients := clientsFromContext(ctx)

			for _, client := range clients {
				if _, err := client.SetFanSpeedAuto(ctx, &emptypb.Empty{}); err != nil {
					return err
				}
			}

			return nil
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
			clients := clientsFromContext(ctx)

			for idx, client := range clients {
				bladeStatus, err := client.GetStatus(ctx, &emptypb.Empty{})
				if err != nil {
					return err
				}

				rpm := bladeStatus.FanRpm
				percent := bladeStatus.FanPercent
				rowPrefix := bladeNames[idx]
				if len(bladeNames) > 1 {
					rowPrefix += ": "
				} else {
					rowPrefix = ""
				}

				fmt.Println(rpmStyle(rpm).Render(fmt.Sprint(rowPrefix + rpmLabel(rpm) + " (" + percentLabel(percent) + ")")))
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
			clients := clientsFromContext(ctx)

			bladeFanCurves := make([][]*bladeapiv1alpha1.FanCurveStep, len(clients))
			criticalTemps := make([]int64, len(clients))
			for idx, client := range clients {
				bladeStatus, err := client.GetStatus(ctx, &emptypb.Empty{})
				if err != nil {
					return err
				}

				bladeFanCurves[idx] = bladeStatus.FanCurveSteps
				criticalTemps[idx] = bladeStatus.CriticalTemperatureThreshold
			}

			printFanCurveTable(bladeFanCurves, criticalTemps)
			return nil
		},
	}
)

func printFanCurveTable(bladeValues [][]*bladeapiv1alpha1.FanCurveStep, criticalTemps []int64) {
	bladeCount := len(bladeValues)

	// Map blade index -> temperature -> step
	bladeTempMap := make([]map[int64]*bladeapiv1alpha1.FanCurveStep, bladeCount)
	allTempsSet := make(map[int64]struct{})

	for bladeIdx, steps := range bladeValues {
		bladeTempMap[bladeIdx] = make(map[int64]*bladeapiv1alpha1.FanCurveStep)
		for _, step := range steps {
			temp := step.Temperature
			bladeTempMap[bladeIdx][temp] = step
			allTempsSet[temp] = struct{}{}
		}
	}

	// Sorted temperature list
	var allTemps []int64
	for t := range allTempsSet {
		allTemps = append(allTemps, t)
	}

	sort.Slice(allTemps, func(i, j int) bool {
		return allTemps[i] < allTemps[j]
	})

	// Header: Blade | Temp1 | Temp2 | ...
	header := []string{"Blade"}
	for _, t := range allTemps {
		header = append(header, tempLabel(t))
	}

	// Table writer setup
	tbl := tablewriter.NewTable(os.Stdout,
		tablewriter.WithHeader(header),
		tablewriter.WithHeaderAlignment(tw.AlignLeft),
		tablewriter.WithHeaderAutoFormat(tw.Off),
	)

	// Rows: one per blade
	for bladeIdx, tempMap := range bladeTempMap {
		row := []string{bladeNames[bladeIdx]}
		for _, t := range allTemps {
			if step, ok := tempMap[t]; ok {
				style := tempStyle(step.Temperature, criticalTemps[bladeIdx])
				colored := style.Render(percentLabel(step.Percent))
				row = append(row, colored)
			} else {
				row = append(row, "")
			}
		}
		_ = tbl.Append(row)
	}

	_ = tbl.Render()
}
