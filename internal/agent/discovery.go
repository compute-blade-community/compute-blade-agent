package internal_agent

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/compute-blade-community/compute-blade-agent/pkg/discovery"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
)

// runDiscovery announces the gRPC API via mDNS until ctx is done, if enabled and the API listens on TCP.
func (a *computeBladeAgent) runDiscovery(ctx context.Context) {
	if !a.config.Discovery.MDNS.Enabled {
		return
	}
	if a.config.Listen.GrpcListenMode != string(ModeTcp) {
		log.FromContext(ctx).Info("Not announcing the API via mDNS: it only listens on a unix socket")
		return
	}

	port, err := grpcPort(a.config.Listen.Grpc)
	if err != nil {
		log.FromContext(ctx).WithError(err).Warn("Not announcing the API via mDNS")
		return
	}

	ad := discovery.Advertisement{
		Instance:      a.hostname,
		Port:          port,
		Version:       a.agentInfo.Version,
		Authenticated: a.config.Listen.GrpcAuthenticated,
	}
	log.FromContext(ctx).Info("Announcing the API via mDNS",
		zap.String("service", discovery.ServiceType),
		zap.String("instance", ad.Instance),
		zap.Int("port", ad.Port),
	)

	if err := discovery.Advertise(ctx, ad); err != nil {
		log.FromContext(ctx).WithError(err).Warn("mDNS announcement failed")
	}
}

// grpcPort extracts the port from a TCP listen address such as ":8081" or "0.0.0.0:8081".
func grpcPort(listen string) (int, error) {
	_, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return 0, fmt.Errorf("invalid gRPC listen address %q: %w", listen, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid port in gRPC listen address %q", listen)
	}
	return port, nil
}
