package main

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/spf13/viper"
)

type grpcClientContextKey int

const (
	defaultGrpcClientContextKey  grpcClientContextKey = 0
	defaultGrpcClientsContextKey grpcClientContextKey = 1
)

var (
	Version   string
	Commit    string
	Date      string
	BuildTime time.Time
)

func clientIntoContext(ctx context.Context, client bladeapiv1alpha1.BladeAgentServiceClient) context.Context {
	return context.WithValue(ctx, defaultGrpcClientContextKey, client)
}

func clientsIntoContext(ctx context.Context, clients []bladeapiv1alpha1.BladeAgentServiceClient) context.Context {
	return context.WithValue(ctx, defaultGrpcClientsContextKey, clients)
}

func clientFromContext(ctx context.Context) bladeapiv1alpha1.BladeAgentServiceClient {
	client, ok := ctx.Value(defaultGrpcClientContextKey).(bladeapiv1alpha1.BladeAgentServiceClient)
	if !ok {
		panic("grpc client not found in context")
	}
	return client
}

func clientsFromContext(ctx context.Context) []bladeapiv1alpha1.BladeAgentServiceClient {
	clients, ok := ctx.Value(defaultGrpcClientsContextKey).([]bladeapiv1alpha1.BladeAgentServiceClient)
	if !ok {
		panic("grpc client not found in context")
	}
	return clients
}

func main() {
	if Date != "" {
		if unixTimestamp, err := strconv.ParseInt(Date, 10, 64); err == nil {
			BuildTime = time.Unix(unixTimestamp, 0)
		} else {
			BuildTime = time.Unix(0, 0)
		}
	}

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
