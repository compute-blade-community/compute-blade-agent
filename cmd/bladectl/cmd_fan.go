package main

import (
	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/spf13/cobra"
)

var (
	percent int
)

func init() {
	cmdFan.Flags().IntVarP(&percent, "percent", "p", 40, "Fan speed in percent (Default: 40).")
	_ = cmdFan.MarkFlagRequired("percent")

	cmdSet.AddCommand(cmdFan)
}

var (
	cmdFan = &cobra.Command{
		Use:     "fan",
		Short:   "Control the fan behavior of the compute-blade",
		Example: "bladectl set fan --percent 50",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error

			ctx := cmd.Context()
			client := clientFromContext(ctx)

			_, err = client.SetFanSpeed(ctx, &bladeapiv1alpha1.SetFanSpeedRequest{
				Percent: int64(percent),
			})

			return err
		},
	}
)
