package util

import (
	"github.com/charmbracelet/lipgloss"
)

const (
	ColorCritical = lipgloss.Color("#cc0000")
	ColorWarning  = lipgloss.Color("#e69138")
	ColorOk       = lipgloss.Color("#04B575")
	ColorUnknown  = lipgloss.Color("#68228B")
)

func OkStyle() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(ColorOk)
}
