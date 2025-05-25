package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/charmbracelet/lipgloss"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/spf13/cobra"
	bladeapiv1alpha1 "github.com/uptime-industries/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/uptime-industries/compute-blade-agent/pkg/hal"
	"github.com/uptime-industries/compute-blade-agent/pkg/util"
	"google.golang.org/protobuf/types/known/emptypb"
)

const chartWindowSize = 60

func init() {
	cmdGet.AddCommand(cmdGetStatus)
	rootCmd.AddCommand(cmdMonitor)
}

var (
	cmdGetStatus = &cobra.Command{
		Use:     "status",
		Short:   "Get in-depth information about the current state of the compute-blade",
		Example: "bladectl get status",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			client := clientFromContext(ctx)
			bladeStatus, err := client.GetStatus(ctx, &emptypb.Empty{})
			if err != nil {
				return err
			}
			fmt.Println(util.PrintKeyValues(buildStatusKeyValues(bladeStatus)))
			return nil
		},
	}

	cmdMonitor = &cobra.Command{
		Use:     "monitor",
		Aliases: fanAliases,
		Short:   "Render a line-chart of the fan speed and temperature of the compute-blade",
		Example: "bladectl chart status",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			labelBox.Title = "Blade Status"
			labelBox.Border = true
			labelBox.TextStyle = ui.NewStyle(ui.ColorWhite)

			fanPlot := newPlot("Fan Speed (RPM)", ui.ColorGreen)
			tempPlot := newPlot("SoC Temperature (\u00b0C)", ui.ColorCyan)

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

					fanData = appendAndTrim(fanData, float64(status.FanRpm))
					tempData = appendAndTrim(tempData, float64(status.Temperature))

					fanPlot.Data[0] = padToSize(fanData, chartWindowSize)
					tempPlot.Data[0] = padToSize(tempData, chartWindowSize)

					renderCharts(status, fanPlot, tempPlot, labelBox)
					ui.Render(labelBox, fanPlot, tempPlot)
				}
			}
		},
	}
)

func newPlot(title string, color ui.Color) *widgets.Plot {
	plot := widgets.NewPlot()
	plot.Title = title
	plot.Data = [][]float64{{}}
	plot.LineColors = []ui.Color{color}
	plot.AxesColor = ui.ColorWhite
	plot.DrawDirection = widgets.DrawRight
	plot.HorizontalScale = 1
	return plot
}

func appendAndTrim(slice []float64, value float64) []float64 {
	slice = append(slice, value)
	if len(slice) > chartWindowSize {
		return slice[len(slice)-chartWindowSize:]
	}
	return slice
}

func padToSize(data []float64, size int) []float64 {
	pad := size - len(data)
	if pad <= 0 {
		// Ensure at least 2 points
		if len(data) < 2 {
			return append(data, data[len(data)-1])
		}
		return data
	}
	padded := make([]float64, pad)
	for i := range padded {
		padded[i] = math.NaN()
	}
	padded = append(padded, data...)

	// Ensure ≥ 2 points
	if len(padded) == 1 {
		padded = append(padded, padded[0])
	}
	return padded
}

func renderCharts(status *bladeapiv1alpha1.StatusResponse, fanPlot, tempPlot *widgets.Plot, labelBox *widgets.Paragraph) {
	width, height := ui.TerminalDimensions()
	labelHeight := 4
	if width >= 140 {
		width = 140
	}

	if status != nil {
		if status.CriticalActive {
			labelBox.Text = fmt.Sprintf(
				"Critical: %s | %s",
				activeLabel(status.CriticalActive)[0],
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
				fanSpeedOverrideLabel(status.FanSpeedAutomatic, status.FanPercent)[0],
			)
		}

		if status.StealthMode {
			labelBox.Text = fmt.Sprintf(
				"%s | Stealth: %s",
				labelBox.Text,
				activeLabel(status.StealthMode)[0],
			)
		}

		labelBox.Text = fmt.Sprintf(
			"%s | Identify: %s | Power: %s",
			labelBox.Text,
			activeLabel(status.IdentifyActive)[0],
			hal.PowerStatus(status.PowerStatus).String(),
		)

	}

	labelBox.SetRect(0, 0, width, labelHeight)

	if width >= 140 {
		if height >= 25 {
			height = 25
		}
		fanPlot.SetRect(0, labelHeight, 70, height)
		tempPlot.SetRect(70, labelHeight, 140, height)
	} else {
		if height >= 50 {
			height = 50
		}
		midY := (height-labelHeight)/2 + labelHeight
		fanPlot.SetRect(0, labelHeight, 70, midY)
		tempPlot.SetRect(0, midY, 70, height)
	}
}

func buildStatusKeyValues(status *bladeapiv1alpha1.StatusResponse) []util.KeyValuePair {
	return []util.KeyValuePair{
		{
			Key:    "SoC Temperature",
			Format: "%d°C",
			Value:  []any{status.Temperature},
			Style:  func(a []any) lipgloss.Style { return tempStyle(a[0].(int64), status.CriticalTemperatureThreshold) },
		},
		{
			Key:    "Fan Speed Override",
			Format: "%s",
			Value:  fanSpeedOverrideLabel(status.FanSpeedAutomatic, status.FanPercent),
			Style:  speedOverrideStyle,
		},
		{
			Key:    "Fan Speed",
			Format: "%d RPM (%d%%)",
			Value:  []any{status.FanRpm, status.FanPercent},
			Style:  rpmStyle,
		},
		{
			Key:    "Stealth Mode",
			Format: "%s",
			Value:  activeLabel(status.StealthMode),
			Style:  activeStyle,
		},
		{
			Key:    "Identify",
			Format: "%s",
			Value:  activeLabel(status.IdentifyActive),
			Style:  activeStyle,
		},
		{
			Key:    "Critical Mode",
			Format: "%s",
			Value:  activeLabel(status.CriticalActive),
			Style:  activeStyle,
		},
		{
			Key:    "Power Status",
			Format: "%s",
			Value:  []any{hal.PowerStatus(status.PowerStatus).String()},
			Style:  util.OkStyle,
		},
	}
}

func fanSpeedOverrideLabel(automatic bool, percent uint32) []any {
	if automatic {
		return []any{"Not set"}
	}
	return []any{fmt.Sprintf("%d%%", percent)}
}

func activeLabel(b bool) []any {
	if b {
		return []any{"Active"}
	}
	return []any{"Off"}
}

func speedOverrideStyle(a []any) lipgloss.Style {
	color := util.ColorCritical

	if active := a[0].(string); active == "Not set" {
		color = util.ColorOk
	}

	return lipgloss.NewStyle().Foreground(color)
}

func activeStyle(a []any) lipgloss.Style {
	color := util.ColorUnknown

	switch active := a[0].(string); active {
	case "Active":
		color = util.ColorCritical

	case "Off":
		color = util.ColorOk
	}

	return lipgloss.NewStyle().Foreground(color)
}

func tempStyle(temp int64, criticalTemp int64) lipgloss.Style {
	color := util.ColorOk

	if temp >= criticalTemp {
		color = util.ColorCritical
	} else if temp >= criticalTemp-10 {
		color = util.ColorWarning
	}

	return lipgloss.NewStyle().Foreground(color)
}

func rpmStyle(a []any) lipgloss.Style {
	color := util.ColorOk

	if rpm := a[0].(int64); rpm > 6000 {
		color = util.ColorCritical
	} else if rpm := a[0].(int64); rpm > 5250 {
		color = util.ColorWarning
	}

	return lipgloss.NewStyle().Foreground(color)
}
