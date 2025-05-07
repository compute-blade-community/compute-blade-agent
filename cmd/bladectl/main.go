package main

import (
	"context"
	"log"
	"strings"

	"github.com/spf13/viper"
	bladeapiv1alpha1 "github.com/uptime-industries/compute-blade-agent/api/bladeapi/v1alpha1"
)

type grpcClientContextKey int

const (
	defaultGrpcClientContextKey grpcClientContextKey = 0
)

var (
	Version string
	Commit  string
	Date    string
)

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
