package main

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

const (
	ColorCritical = lipgloss.Color("#cc0000")
	ColorWarning  = lipgloss.Color("#e69138")
	ColorOk       = lipgloss.Color("#04B575")
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
		return lipgloss.NewStyle().Foreground(ColorOk)
	}

	return lipgloss.NewStyle().Foreground(ColorCritical)
}

func activeStyle(active bool) lipgloss.Style {
	if active {
		return lipgloss.NewStyle().Foreground(ColorCritical)
	}

	return lipgloss.NewStyle().Foreground(ColorOk)
}

func tempStyle(temp int64, criticalTemp int64) lipgloss.Style {
	color := ColorOk

	if temp >= criticalTemp {
		color = ColorCritical
	} else if temp >= criticalTemp-10 {
		color = ColorWarning
	}

	return lipgloss.NewStyle().Foreground(color)
}

func rpmStyle(rpm int64) lipgloss.Style {
	color := ColorOk

	if rpm > 6000 {
		color = ColorCritical
	} else if rpm > 5250 {
		color = ColorWarning
	}

	return lipgloss.NewStyle().Foreground(color)
}

func okStyle() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(ColorOk)
}
