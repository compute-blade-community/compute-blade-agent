package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sierrasoftworks/humane-errors-go"
	"github.com/spf13/cobra"
	bladeapiv1alpha1 "github.com/uptime-industries/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/uptime-industries/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	grpcAddr string
	timeout  time.Duration
)

func init() {
	rootCmd.PersistentFlags().StringVar(&grpcAddr, "addr", "unix:///tmp/compute-blade-agent.sock", "address of the compute-blade-agent gRPC server")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", time.Minute, "timeout for gRPC requests")
}

var rootCmd = &cobra.Command{
	Use:   "bladectl",
	Short: "bladectl interacts with the compute-blade-agent and allows you to manage hardware-features of your compute blade(s)",
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		origCtx := cmd.Context()

		// setup signal handlers for SIGINT and SIGTERM
		ctx, cancelCtx := context.WithTimeout(origCtx, timeout)

		// setup signal handler channels
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		go func() {
			select {
			// Wait for context cancel
			case <-ctx.Done():

			// Wait for signal
			case sig := <-sigs:
				switch sig {
				case syscall.SIGTERM:
					fallthrough
				case syscall.SIGINT:
					fallthrough
				case syscall.SIGQUIT:
					// On terminate signal, cancel context causing the program to terminate
					cancelCtx()

				default:
					log.FromContext(ctx).Warn("Received unknown signal", zap.String("signal", sig.String()))
				}
			}
		}()

		// Create our gRPC Transport Credentials
		credentials := insecure.NewCredentials()
		conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(credentials))
		if err != nil {
			return fmt.Errorf(
				humane.Wrap(err,
					"failed to dial grpc server",
					"ensure the gRPC server you are trying to connect to is running and the address is correct",
				).Display(),
			)
		}

		client := bladeapiv1alpha1.NewBladeAgentServiceClient(conn)
		cmd.SetContext(clientIntoContext(ctx, client))
		return nil
	},
}
