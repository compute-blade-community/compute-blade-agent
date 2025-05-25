package util

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

const (
	ColorCritical = lipgloss.Color("#cc0000")
	ColorWarning  = lipgloss.Color("#e69138")
	ColorOk       = lipgloss.Color("#04B575")
	ColorUnknown  = lipgloss.Color("#68228B")
)

func OkStyle([]any) lipgloss.Style {
	return lipgloss.NewStyle().Foreground(ColorOk)
}

type StyleFunc func(any []any) lipgloss.Style

type KeyValuePair struct {
	Key    string
	Format string
	Value  []any
	Style  StyleFunc
}

func PrintKeyValues(values []KeyValuePair) string {
	maxKeyLen := 0
	maxValLen := 0
	for _, v := range values {
		keyLen := len(v.Key + ": ")
		valLen := len(fmt.Sprintf(v.Format, v.Value))

		if keyLen > maxKeyLen {
			maxKeyLen = keyLen
		}

		if valLen > maxValLen {
			maxValLen = valLen
		}
	}

	rows := make([]string, len(values))

	for idx, v := range values {
		rows[idx] = fmtSprintfRow(maxKeyLen, maxValLen, v.Key+": ", v.Style(v.Value), v.Format, v.Value...)
	}

	style := lipgloss.NewStyle().Align(lipgloss.Left)
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, rows...))
}

func fmtSprintfRow(maxKeyLen, maxValLen int, key string, valueStyle lipgloss.Style, format string, args ...any) string {
	keyStyle := lipgloss.NewStyle().Bold(true)
	rowStyle := lipgloss.NewStyle().Padding(0, 0)

	keyStyleFormat := fmt.Sprintf("%%-%ds", maxKeyLen)
	valueStyleFormat := fmt.Sprintf("%%-%ds", maxValLen)

	return rowStyle.Render(
		lipgloss.JoinHorizontal(
			lipgloss.Top,
			keyStyle.Render(fmt.Sprintf(keyStyleFormat, key)),
			valueStyle.Render(fmt.Sprintf(valueStyleFormat, fmt.Sprintf(format, args...))),
		),
	)
}
