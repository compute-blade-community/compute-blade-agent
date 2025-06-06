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
	bladeName string
	timeout   time.Duration
)

func init() {
	rootCmd.PersistentFlags().StringVar(&bladeName, "blade", "", "Name of the compute-blade to control. If not provided, the compute-blade specified in `current-blade` will be used.")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", time.Minute, "timeout for gRPC requests")
}

var rootCmd = &cobra.Command{
	Use:   "bladectl",
	Short: "bladectl interacts with the compute-blade-agent and allows you to manage hardware-features of your compute blade(s)",
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		origCtx := cmd.Context()

		// Load potential file configs
		if err := viper.ReadInConfig(); err != nil {
			return err
		}

		// load configuration
		var bladectlCfg config.BladectlConfig
		if err := viper.Unmarshal(&bladectlCfg); err != nil {
			return err
		}

		var blade *config.Blade

		blade, herr := bladectlCfg.FindBlade(bladeName)
		if herr != nil {
			return errors.New(herr.Display())
		}

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
		certData := blade.Certificate

		// If we're presented with certificate data in the config, we try to create a mTLS connection
		if len(certData.ClientCertificateData) > 0 && len(certData.ClientKeyData) > 0 && len(certData.CertificateAuthorityData) > 0 {
			var err error

			serverName := blade.Server
			if strings.Contains(serverName, ":") {
				if serverName, _, err = net.SplitHostPort(blade.Server); err != nil {
					return fmt.Errorf("failed to parse server address: %w", err)
				}
			}

			if credentials, err = loadTlsCredentials(serverName, certData); err != nil {
				return err
			}
		}

		conn, err := grpc.NewClient(blade.Server, grpc.WithTransportCredentials(credentials))
		if err != nil {
			return errors.New(
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

func loadTlsCredentials(server string, certData config.Certificate) (credentials.TransportCredentials, error) {
	// Decode base64 certificate, key, and CA
	certPEM, err := base64.StdEncoding.DecodeString(certData.ClientCertificateData)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 client cert: %w", err)
	}

	keyPEM, err := base64.StdEncoding.DecodeString(certData.ClientKeyData)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 client key: %w", err)
	}

	caPEM, err := base64.StdEncoding.DecodeString(certData.CertificateAuthorityData)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 CA cert: %w", err)
	}

	// Load client cert/key pair
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client cert/key pair: %w", err)
	}

	// Load CA into CertPool
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to append CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      caPool,
		ServerName:   server,
	}

	return credentials.NewTLS(tlsConfig), nil
}
