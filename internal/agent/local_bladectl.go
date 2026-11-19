package internal_agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/compute-blade-community/compute-blade-agent/cmd/bladectl/config"
	"github.com/compute-blade-community/compute-blade-agent/pkg/certificate"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"github.com/compute-blade-community/compute-blade-agent/pkg/util"
	"github.com/sierrasoftworks/humane-errors-go"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// EnsureLocalBladectlConfig makes sure the bladectl config of the user running the agent can reach this agent with its
// current listen settings, so `bladectl` works on the blade itself.
//
// The agent owns the entry named after the hostname. It's created if missing and rewritten when it no longer fits the
// listen mode or authentication, e.g. after switching from the Unix socket to TCP with mTLS. Other entries are kept,
// and so is an entry that still fits (its host name may have been edited).
func EnsureLocalBladectlConfig(ctx context.Context, listenAddr string, mode ListenMode, authenticated bool) humane.Error {
	configDir, herr := config.EnsureBladectlConfigHome()
	if herr != nil {
		return herr
	}
	configPath := filepath.Join(configDir, "config.yaml")

	hostname, err := os.Hostname()
	if err != nil {
		return humane.Wrap(err, "failed to determine the hostname")
	}

	server, herr := localServerAddress(listenAddr, mode)
	if herr != nil {
		return herr
	}

	var cfg config.BladectlConfig
	if util.FileExists(configPath) {
		raw, err := os.ReadFile(configPath)
		if err != nil {
			return humane.Wrap(err, "failed to read bladectl config",
				fmt.Sprintf("ensure the config file %s is readable by the agent user", configPath),
			)
		}
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return humane.Wrap(err, "failed to parse bladectl config",
				fmt.Sprintf("fix or delete %s, the agent writes a new one", configPath),
			)
		}
	}

	idx := localBladeIndex(&cfg, hostname)
	if idx >= 0 && localEntryFits(cfg.Blades[idx].Blade, listenAddr, mode, authenticated) {
		return nil
	}

	entry := config.Blade{Server: server}
	if authenticated {
		caPEM, certPEM, keyPEM, herr := GenerateClientCert("localhost")
		if herr != nil {
			return herr
		}
		entry.Certificate = config.Certificate{
			CertificateAuthorityData: base64.StdEncoding.EncodeToString(caPEM),
			ClientCertificateData:    base64.StdEncoding.EncodeToString(certPEM),
			ClientKeyData:            base64.StdEncoding.EncodeToString(keyPEM),
		}
	}

	action := "Created"
	if idx >= 0 {
		action = "Updated"
		cfg.Blades[idx].Blade = entry
	} else {
		cfg.Blades = append(cfg.Blades, config.NamedBlade{Name: hostname, Blade: entry})
	}
	if cfg.CurrentBlade == "" {
		cfg.CurrentBlade = hostname
	}

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return humane.Wrap(err, "failed to marshal the bladectl config")
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		return humane.Wrap(err, "failed to write the bladectl config",
			"ensure the home directory is writable by the agent user",
		)
	}

	log.FromContext(ctx).Info(action+" the local bladectl config for the current listen settings",
		zap.String("path", configPath),
		zap.String("blade", hostname),
		zap.String("server", server),
		zap.Bool("authenticated", authenticated),
	)
	return nil
}

// localServerAddress is the address bladectl on the blade uses: the socket path, or localhost and the TCP port.
func localServerAddress(listenAddr string, mode ListenMode) (string, humane.Error) {
	if mode != ModeTcp {
		return listenAddr, nil
	}
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", humane.Wrap(err, "failed to extract the port from the gRPC listen address",
			"check listen.grpc in the agent config, e.g. :8081",
		)
	}
	return net.JoinHostPort("localhost", port), nil
}

// localBladeIndex finds the entry for this blade: the one named after the hostname, or -1.
func localBladeIndex(cfg *config.BladectlConfig, hostname string) int {
	for idx := range cfg.Blades {
		if cfg.Blades[idx].Name == hostname {
			return idx
		}
	}
	return -1
}

// localEntryFits reports whether a bladectl entry can talk to the agent with its current listen settings.
func localEntryFits(blade config.Blade, listenAddr string, mode ListenMode, authenticated bool) bool {
	isSocket := strings.HasPrefix(blade.Server, "/") || strings.HasPrefix(blade.Server, "unix:")
	switch mode {
	case ModeUnix:
		if blade.Server != listenAddr && blade.Server != "unix:"+listenAddr {
			return false
		}
	case ModeTcp:
		if isSocket {
			return false
		}
		_, port, err := net.SplitHostPort(blade.Server)
		_, listenPort, listenErr := net.SplitHostPort(listenAddr)
		if err != nil || listenErr != nil || port != listenPort {
			return false
		}
	}

	hasCredentials := blade.Certificate.ClientCertificateData != "" && blade.Certificate.ClientKeyData != ""
	if !authenticated {
		return !hasCredentials
	}
	if !hasCredentials {
		return false
	}

	certPEM, err1 := base64.StdEncoding.DecodeString(blade.Certificate.ClientCertificateData)
	keyPEM, err2 := base64.StdEncoding.DecodeString(blade.Certificate.ClientKeyData)
	if err1 != nil || err2 != nil {
		return false
	}
	_, _, herr := certificate.ValidateCertificate(certPEM, keyPEM)
	return herr == nil
}
