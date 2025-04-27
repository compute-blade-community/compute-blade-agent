package main

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(cmdGet)
	rootCmd.AddCommand(cmdSet)
}

var (
	cmdGet = &cobra.Command{
		Use:   "get",
		Short: "Display compute-blade related information",
		Long:  "Prints information about compute-blade related information, e.g. fan speed, temperature, etc.",
	}

	cmdSet = &cobra.Command{
		Use:   "set",
		Short: "Configure compute-blade",
		Long:  "These commands allow you make changes to compute-blade related information.",
	}
)
