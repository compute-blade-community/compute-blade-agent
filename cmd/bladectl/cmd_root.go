package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/compute-blade-community/compute-blade-agent/cmd/bladectl/config"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"github.com/sierrasoftworks/humane-errors-go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	allBlades  bool
	bladeNames []string
	timeout    time.Duration
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&allBlades, "all", "a", false, "control all compute-blades at the same time")
	rootCmd.PersistentFlags().StringArrayVar(&bladeNames, "blade", []string{""}, "Name of the compute-blade to control. If not provided, the compute-blade specified in `current-blade` will be used.")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", time.Minute, "timeout for gRPC requests")
}

var rootCmd = &cobra.Command{
	Use:   "bladectl",
	Short: "bladectl interacts with the compute-blade-agent and allows you to manage hardware-features of your compute blade(s)",
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancelCtx := context.WithCancelCause(cmd.Context())

		// load configuration
		var bladectlCfg config.BladectlConfig
		if err := viper.ReadInConfig(); err != nil {
			cancelCtx(err)
			return err
		}
		if err := viper.Unmarshal(&bladectlCfg); err != nil {
			cancelCtx(err)
			return err
		}

		// setup signal handlers for SIGINT and SIGTERM
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		go func() {
			select {
			// Wait for context cancel
			case <-ctx.Done():

			// Wait for signal
			case sig := <-sigs:
				fmt.Println("Received signal", sig.String())

				switch sig {
				case syscall.SIGTERM:
					fallthrough
				case syscall.SIGINT:
					fallthrough
				case syscall.SIGQUIT:
					// On terminate signal, cancel context causing the program to terminate
					cancelCtx(context.Canceled)

				default:
					log.FromContext(ctx).Warn("Received unknown signal", zap.String("signal", sig.String()))
				}
			}
		}()

		// Allow to easily select all blades
		if allBlades {
			bladeNames = make([]string, len(bladectlCfg.Blades))
			for idx, blade := range bladectlCfg.Blades {
				bladeNames[idx] = blade.Name
			}
		}

		clients := make([]bladeapiv1alpha1.BladeAgentServiceClient, len(bladeNames))
		for idx, bladeName := range bladeNames {
			namedBlade, herr := bladectlCfg.FindBlade(bladeName)
			if herr != nil {
				cancelCtx(herr)
				return errors.New(herr.Display())
			}

			bladeNames[idx] = namedBlade.Name

			client, herr := buildClient(&namedBlade.Blade)
			if herr != nil {
				cancelCtx(herr)
				return errors.New(herr.Display())
			}

			clients[idx] = client
		}

		ctx = clientIntoContext(ctx, clients[0]) // Add the default client
		ctx = clientsIntoContext(ctx, clients)   // Add all clients
		cmd.SetContext(ctx)
		return nil
	},
}

func loadTlsCredentials(server string, certData config.Certificate) (credentials.TransportCredentials, humane.Error) {
	// Decode base64 certificate, key, and CA
	certPEM, err := base64.StdEncoding.DecodeString(certData.ClientCertificateData)
	if err != nil {
		return nil, humane.Wrap(err, "invalid base64 client cert")
	}

	keyPEM, err := base64.StdEncoding.DecodeString(certData.ClientKeyData)
	if err != nil {
		return nil, humane.Wrap(err, "invalid base64 client key")
	}

	caPEM, err := base64.StdEncoding.DecodeString(certData.CertificateAuthorityData)
	if err != nil {
		return nil, humane.Wrap(err, "invalid base64 CA cert")
	}

	// Load client cert/key pair
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, humane.Wrap(err, "failed to parse client cert/key pair")
	}

	// Load CA into CertPool
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, humane.Wrap(err, "failed to append CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      caPool,
		ServerName:   server,
	}

	return credentials.NewTLS(tlsConfig), nil
}

func buildClient(blade *config.Blade) (bladeapiv1alpha1.BladeAgentServiceClient, humane.Error) {
	// Create our gRPC Transport Credentials
	creds := insecure.NewCredentials()
	certData := blade.Certificate

	// If we're presented with certificate data in the config, we try to create a mTLS connection
	if len(certData.ClientCertificateData) > 0 && len(certData.ClientKeyData) > 0 && len(certData.CertificateAuthorityData) > 0 {
		serverName := blade.Server
		if strings.Contains(serverName, ":") {
			var err error
			if serverName, _, err = net.SplitHostPort(blade.Server); err != nil {
				return nil, humane.Wrap(err, "failed to parse server address")
			}
		}

		var err humane.Error
		if creds, err = loadTlsCredentials(serverName, certData); err != nil {
			return nil, err
		}
	}

	conn, err := grpc.NewClient(blade.Server, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, humane.Wrap(err,
			"failed to dial grpc server",
			"ensure the gRPC server you are trying to connect to is running and the address is correct",
		)
	}

	return bladeapiv1alpha1.NewBladeAgentServiceClient(conn), nil
}
