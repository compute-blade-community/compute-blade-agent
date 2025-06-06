package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"
)

func init() {
	rootCmd.AddCommand(cmdMonitor)
}

var cmdMonitor = &cobra.Command{
	Use:     "monitor",
	Aliases: fanAliases,
	Short:   "Render a line-chart of the fan speed and temperature of the compute-blade",
	Example: "bladectl chart status",
	Args:    cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(bladeNames) > 1 {
			return fmt.Errorf("cannot monitor multiple blades at once, please specify a single blade with --blade")
		}

		ctx := cmd.Context()
		client := clientFromContext(ctx)

		if err := ui.Init(); err != nil {
			return fmt.Errorf("failed to initialize UI: %w", err)
		}
		defer ui.Close()

		events := ui.PollEvents()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		labelBox := widgets.NewParagraph()
		labelBox.Title = fmt.Sprintf(" %s: Blade Status ", bladeNames[0])
		labelBox.Border = true
		labelBox.TextStyle = ui.NewStyle(ui.ColorWhite)

		fanPlot := newPlot(fmt.Sprintf(" %s: Fan Speed (RPM) ", bladeNames[0]), ui.ColorGreen)
		tempPlot := newPlot(fmt.Sprintf(" %s: SoC Temperature (\u00b0C) ", bladeNames[0]), ui.ColorCyan)

		fanData := []float64{math.NaN(), math.NaN()}
		tempData := []float64{math.NaN(), math.NaN()}

		for {
			select {
			case <-ctx.Done():
				if errors.Is(ctx.Err(), context.Canceled) {
					return nil
				}
				return ctx.Err()

			case e := <-events:
				switch e.ID {
				case "q", "<C-c>":
					return nil
				case "<Resize>":
					renderCharts(nil, fanPlot, tempPlot, labelBox)
					ui.Clear()
					ui.Render(labelBox, fanPlot, tempPlot)
				}

			case <-ticker.C:
				status, err := client.GetStatus(ctx, &emptypb.Empty{})
				if err != nil {
					labelBox.Text = "Error retrieving blade status: " + err.Error()
					ui.Render(labelBox)
					continue
				}

				fanData = append(fanData, float64(status.FanRpm))
				tempData = append(tempData, float64(status.Temperature))

				fanPlot.Data[0] = reversedFloats(fanData)
				tempPlot.Data[0] = reversedFloats(tempData)

				renderCharts(status, fanPlot, tempPlot, labelBox)
				ui.Render(labelBox, fanPlot, tempPlot)
			}
		}
	},
}

func reversedFloats(s []float64) []float64 {
	r := make([]float64, len(s))
	for i := range s {
		r[len(s)-1-i] = s[i]
	}
	return r
}

func newPlot(title string, color ui.Color) *widgets.Plot {
	plot := widgets.NewPlot()
	plot.Title = title
	plot.Data = [][]float64{{}}
	plot.LineColors = []ui.Color{color}
	plot.AxesColor = ui.ColorWhite
	plot.DrawDirection = widgets.DrawLeft
	plot.HorizontalScale = 2
	return plot
}

func renderCharts(status *bladeapiv1alpha1.StatusResponse, fanPlot, tempPlot *widgets.Plot, labelBox *widgets.Paragraph) {
	width, height := ui.TerminalDimensions()
	labelHeight := 4

	if status != nil {
		if status.CriticalActive {
			labelBox.Text = fmt.Sprintf(
				"Critical: %s | %s",
				activeLabel(status.CriticalActive),
				labelBox.Text,
			)
		}

		labelBox.Text = fmt.Sprintf(
			"Temp: %d°C | Fan: %d RPM (%d%%)",
			status.Temperature,
			status.FanRpm,
			status.FanPercent,
		)

		if !status.FanSpeedAutomatic {
			labelBox.Text = fmt.Sprintf(
				"%s | Fan Override: %s",
				labelBox.Text,
				fanSpeedOverrideLabel(status.FanSpeedAutomatic, status.FanPercent),
			)
		}

		if status.StealthMode {
			labelBox.Text = fmt.Sprintf(
				"%s | Stealth: %s",
				labelBox.Text,
				activeLabel(status.StealthMode),
			)
		}

		labelBox.Text = fmt.Sprintf(
			"%s | Identify: %s | Power: %s",
			labelBox.Text,
			activeLabel(status.IdentifyActive),
			hal.PowerStatus(status.PowerStatus).String(),
		)

	}

	labelBox.SetRect(0, 0, width, labelHeight)

	if width >= 140 {
		fanPlot.SetRect(0, labelHeight, width/2, height)
		tempPlot.SetRect(width/2, labelHeight, width, height)
	} else {
		midY := (height-labelHeight)/2 + labelHeight
		fanPlot.SetRect(0, labelHeight, width, midY)
		tempPlot.SetRect(0, midY, width, height)
	}
}
