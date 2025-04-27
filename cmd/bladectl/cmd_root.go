package main

import (
	"context"
	humane "github.com/sierrasoftworks/humane-errors-go"
	"github.com/spf13/cobra"
	bladeapiv1alpha1 "github.com/uptime-induestries/compute-blade-agent/api/bladeapi/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"os"
	"os/signal"
	"syscall"
)

var rootCmd = &cobra.Command{
	Use:   "bladectl",
	Short: "bladectl interacts with the compute-blade-agent and allows you to manage hardware-features of your compute blade(s)",
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		origCtx := cmd.Context()

		// setup signal handlers for SIGINT and SIGTERM
		ctx, cancelCtx := context.WithTimeout(origCtx, timeout)

		// setup signal handler channels
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			// Wait for context cancel or signal
			select {
			case <-ctx.Done():
			case <-sigs:
				// On signal, cancel context
				cancelCtx()
			}
		}()

		conn, err := grpc.Dial(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return humane.Wrap(err, "failed to dial grpc server", "ensure the gRPC server you are trying to connect to is running and the address is correct")
		}
		client := bladeapiv1alpha1.NewBladeAgentServiceClient(conn)

		cmd.SetContext(clientIntoContext(ctx, client))
		return nil
	},
}
