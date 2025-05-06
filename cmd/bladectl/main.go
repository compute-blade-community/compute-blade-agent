package main

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/spf13/viper"
	bladeapiv1alpha1 "github.com/uptime-induestries/compute-blade-agent/api/bladeapi/v1alpha1"
)

type grpcClientContextKey int

const (
	defaultGrpcClientContextKey     grpcClientContextKey = 0
	defaultGrpcClientConnContextKey grpcClientContextKey = 1
)

var (
	bladeName string
	timeout   time.Duration

	Version string
	Commit  string
	Date    string
)

func init() {
	rootCmd.PersistentFlags().StringVar(&bladeName, "blade", "", "Name of the compute-blade to control. If not provided, the compute-blade specified in `current-blade` will be used.")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", time.Minute, "timeout for gRPC requests")
}

func clientIntoContext(ctx context.Context, client bladeapiv1alpha1.BladeAgentServiceClient) context.Context {
	return context.WithValue(ctx, defaultGrpcClientContextKey, client)
}

func clientFromContext(ctx context.Context) bladeapiv1alpha1.BladeAgentServiceClient {
	client, ok := ctx.Value(defaultGrpcClientContextKey).(bladeapiv1alpha1.BladeAgentServiceClient)
	if !ok {
		panic("grpc client not found in context")
	}
	return client
}

func main() {
	// Setup configuration
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("$HOME/.config/bladectl")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
