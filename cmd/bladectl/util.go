package main

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/uptime-industries/compute-blade-agent/pkg/util"
)

func fanSpeedOverrideLabel(automatic bool, percent uint32) string {
	if automatic {
		return "Not set"
	}
	return fmt.Sprintf("%d%%", percent)
}

func tempLabel(temp int64) string {
	return fmt.Sprintf("%d°C", temp)
}

func percentLabel(percent uint32) string {
	return fmt.Sprintf("%d%%", percent)
}

func rpmLabel(rpm int64) string {
	return fmt.Sprintf("%d RPM", rpm)
}

func activeLabel(b bool) string {
	if b {
		return "Active"
	}
	return "Off"
}

func speedOverrideStyle(automaticMode bool) lipgloss.Style {
	if automaticMode {
		return lipgloss.NewStyle().Foreground(util.ColorOk)
	}

	return lipgloss.NewStyle().Foreground(util.ColorCritical)
}

func activeStyle(active bool) lipgloss.Style {
	if active {
		return lipgloss.NewStyle().Foreground(util.ColorCritical)
	}

	return lipgloss.NewStyle().Foreground(util.ColorOk)
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

func rpmStyle(rpm int64) lipgloss.Style {
	color := util.ColorOk

	if rpm > 6000 {
		color = util.ColorCritical
	} else if rpm > 5250 {
		color = util.ColorWarning
	}

	return lipgloss.NewStyle().Foreground(color)
}
