// Command watch-events is a minimal compute-blade-agent client: it streams the health events of one blade and
// prints them. It reads the blade's address and mTLS credentials from the bladectl config, so it works with any blade
// bladectl can talk to.
//
//	go run ./examples/watch-events --blade blade-pi1
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/compute-blade-community/compute-blade-agent/cmd/bladectl/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
)

func main() {
	bladeName := flag.String("blade", "", "blade from the bladectl config (default: its current-blade)")
	all := flag.Bool("all", false, "stream every event, not only health events")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	blade, err := loadBlade(*bladeName)
	if err != nil {
		log.Fatal(err)
	}
	client, err := dial(blade)
	if err != nil {
		log.Fatal(err)
	}

	// Only the health events; an empty list streams everything
	req := &bladeapiv1alpha1.WatchEventsRequest{}
	if !*all {
		req.Events = []bladeapiv1alpha1.Event{
			bladeapiv1alpha1.Event_FAN_STALL, bladeapiv1alpha1.Event_FAN_STALL_CLEAR,
			bladeapiv1alpha1.Event_UNDERVOLTAGE, bladeapiv1alpha1.Event_UNDERVOLTAGE_CLEAR,
			bladeapiv1alpha1.Event_CRITICAL, bladeapiv1alpha1.Event_CRITICAL_RESET,
		}
	}

	// The stream ends when the agent restarts: reconnect until interrupted
	for ctx.Err() == nil {
		err := watch(ctx, client, req)
		if ctx.Err() == nil {
			log.Printf("stream interrupted: %v, reconnecting", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
}

// watch prints events until the stream ends, and returns why it ended
func watch(ctx context.Context, client bladeapiv1alpha1.BladeAgentServiceClient, req *bladeapiv1alpha1.WatchEventsRequest) error {
	stream, err := client.WatchEvents(ctx, req)
	if err != nil {
		return err
	}
	for {
		ev, err := stream.Recv()
		if err != nil {
			return err
		}
		fmt.Printf("%s %s %s", ev.GetTimestamp().AsTime().Format(time.RFC3339), ev.GetBlade(), ev.GetEvent())
		if fan := ev.GetFan(); fan != nil {
			fmt.Printf(" target=%d%% rpm=%d", fan.GetTargetPercent(), fan.GetRpm())
		}
		fmt.Println()
	}
}

// loadBlade reads a blade from ~/.config/bladectl/config.yaml
func loadBlade(name string) (*config.Blade, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(home, ".config", "bladectl", "config.yaml"))
	if err != nil {
		return nil, err
	}
	var cfg config.BladectlConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	named, herr := cfg.FindBlade(name)
	if herr != nil {
		return nil, herr
	}
	return &named.Blade, nil
}

// dial connects to the blade, with mTLS if the config has credentials for it
func dial(blade *config.Blade) (bladeapiv1alpha1.BladeAgentServiceClient, error) {
	creds := insecure.NewCredentials()
	if blade.Certificate.ClientCertificateData != "" {
		tlsConfig, err := tlsConfig(blade)
		if err != nil {
			return nil, err
		}
		creds = credentials.NewTLS(tlsConfig)
	}

	conn, err := grpc.NewClient(blade.Server, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	return bladeapiv1alpha1.NewBladeAgentServiceClient(conn), nil
}

func tlsConfig(blade *config.Blade) (*tls.Config, error) {
	decode := base64.StdEncoding.DecodeString
	certPEM, err1 := decode(blade.Certificate.ClientCertificateData)
	keyPEM, err2 := decode(blade.Certificate.ClientKeyData)
	caPEM, err3 := decode(blade.Certificate.CertificateAuthorityData)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, fmt.Errorf("invalid certificate data: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid CA certificate")
	}

	// The server certificate names the blade's host name, not the port
	host, _, err := net.SplitHostPort(blade.Server)
	if err != nil {
		host = blade.Server
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: host}, nil
}
