package main

import (
	"os"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"
)

func init() {
	cmdGet.AddCommand(cmdGetStatus)
}

var cmdGetStatus = &cobra.Command{
	Use:     "status",
	Short:   "Get in-depth information about the current state of the compute-blade",
	Example: "bladectl get status",
	Args:    cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		clients := clientsFromContext(ctx)

		bladeStatus := make([]*bladeapiv1alpha1.StatusResponse, len(clients))
		for idx, client := range clients {
			var err error
			if bladeStatus[idx], err = client.GetStatus(ctx, &emptypb.Empty{}); err != nil {
				return err
			}
		}

		printStatusTable(bladeStatus)
		return nil
	},
}

func printStatusTable(bladeStatus []*bladeapiv1alpha1.StatusResponse) {
	// Header: Blade | Stat1 | Stat2 | ...
	header := []string{
		"Blade",
		"Temperature",
		"Fan Speed Override",
		"Fan Speed",
		"Stealth Mode",
		"Identify",
		"Critical Mode",
		"Power Status",
	}

	// Table writer setup
	tbl := tablewriter.NewTable(os.Stdout,
		tablewriter.WithHeader(header),
		tablewriter.WithHeaderAlignment(tw.AlignLeft),
		tablewriter.WithHeaderAutoFormat(tw.Off),
	)

	// Rows: one per blade
	for bladeIdx, status := range bladeStatus {
		row := []string{
			bladeNames[bladeIdx],
			tempStyle(status.Temperature, status.CriticalTemperatureThreshold).Render(tempLabel(status.Temperature)),
			speedOverrideStyle(status.FanSpeedAutomatic).Render(fanSpeedOverrideLabel(status.FanSpeedAutomatic, status.FanPercent)),
			rpmStyle(status.FanRpm).Render(rpmLabel(status.FanRpm) + " (" + percentLabel(status.FanPercent) + ")"),
			activeStyle(status.StealthMode).Render(activeLabel(status.StealthMode)),
			activeStyle(status.IdentifyActive).Render(activeLabel(status.IdentifyActive)),
			activeStyle(status.CriticalActive).Render(activeLabel(status.CriticalActive)),
			okStyle().Render(hal.PowerStatus(status.PowerStatus).String()),
		}

		_ = tbl.Append(row)
	}

	_ = tbl.Render()
}
