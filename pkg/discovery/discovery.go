// Package discovery advertises compute-blade-agents on the local network via mDNS / DNS-SD and finds them again.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"github.com/libp2p/zeroconf/v2"
	"go.uber.org/zap"
)

const (
	// ServiceType is the DNS-SD service type of the agent's gRPC API
	ServiceType = "_compute-blade._tcp"
	// Domain is the mDNS domain
	Domain = "local."

	txtVersion = "version"
	txtAPI     = "api"
	txtAuth    = "auth"

	// APIVersion is advertised so clients can tell which API the agent speaks
	APIVersion = "v1alpha1"

	authMTLS = "mtls"
	authNone = "none"
)

// Advertisement describes what an agent announces.
type Advertisement struct {
	// Instance is the service instance name, the blade's hostname
	Instance string
	// Port is the gRPC API port
	Port int
	// Version is the agent version
	Version string
	// Authenticated is true if the API requires mTLS client certificates
	Authenticated bool
}

// TXT returns the TXT records of the advertisement.
func (a Advertisement) TXT() []string {
	auth := authNone
	if a.Authenticated {
		auth = authMTLS
	}
	return []string{
		txtVersion + "=" + a.Version,
		txtAPI + "=" + APIVersion,
		txtAuth + "=" + auth,
	}
}

// errAvahiUnavailable is returned by advertiseAvahi if avahi-daemon isn't running
var errAvahiUnavailable = errors.New("avahi-daemon is not available")

// Advertise announces the agent until ctx is done. It registers the service with avahi-daemon if it runs, so the
// host keeps a single mDNS responder, and otherwise answers mDNS queries itself.
func Advertise(ctx context.Context, ad Advertisement) error {
	err := advertiseAvahi(ctx, ad)
	if !errors.Is(err, errAvahiUnavailable) {
		return err
	}
	log.FromContext(ctx).Info("avahi-daemon not available, announcing via the built-in mDNS responder", zap.String("reason", err.Error()))
	return advertiseBuiltin(ctx, ad)
}

// advertiseBuiltin runs an mDNS responder for the service and the host's address records until ctx is done.
// It must not run next to another responder such as avahi, which would see the host's name as taken.
func advertiseBuiltin(ctx context.Context, ad Advertisement) error {
	server, err := zeroconf.Register(ad.Instance, ServiceType, Domain, ad.Port, ad.TXT(), nil)
	if err != nil {
		return fmt.Errorf("failed to register mDNS service: %w", err)
	}
	defer server.Shutdown()

	<-ctx.Done()
	return nil
}

// Blade is an agent found on the network.
type Blade struct {
	// Name is the service instance name (the blade's hostname)
	Name string
	// Host is the blade's mDNS host name, e.g. blade-pi1.local
	Host string
	// Port is the gRPC API port
	Port int
	// Addresses are the blade's IP addresses
	Addresses []net.IP
	// Version is the agent version
	Version string
	// API is the API version the agent speaks
	API string
	// Authenticated is true if the API requires mTLS client certificates
	Authenticated bool
}

// Server returns the address bladectl should connect to. The host name is used rather than an IP address because it
// survives DHCP changes and is part of the agent's TLS certificate.
func (b Blade) Server() string {
	return net.JoinHostPort(b.Host, strconv.Itoa(b.Port))
}

// Browse looks for agents for the given duration and returns them sorted by name.
func Browse(ctx context.Context, wait time.Duration) ([]Blade, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()

	entries := make(chan *zeroconf.ServiceEntry)
	var (
		mu     sync.Mutex
		blades = map[string]Blade{}
		done   = make(chan struct{})
	)
	go func() {
		defer close(done)
		for entry := range entries {
			blade := FromServiceEntry(entry)
			mu.Lock()
			blades[blade.Name] = blade
			mu.Unlock()
		}
	}()

	err := zeroconf.Browse(ctx, ServiceType, Domain, entries)
	<-done
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		return nil, fmt.Errorf("mDNS browse failed: %w", err)
	}

	mu.Lock()
	defer mu.Unlock()
	result := make([]Blade, 0, len(blades))
	for _, blade := range blades {
		result = append(result, blade)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

// FromServiceEntry converts a DNS-SD browse result into a Blade.
func FromServiceEntry(entry *zeroconf.ServiceEntry) Blade {
	blade := Blade{
		Name:      unescapeInstance(entry.Instance),
		Host:      strings.TrimSuffix(entry.HostName, "."),
		Port:      entry.Port,
		Addresses: append(append([]net.IP{}, entry.AddrIPv4...), entry.AddrIPv6...),
	}

	for _, record := range entry.Text {
		key, value, _ := strings.Cut(record, "=")
		switch key {
		case txtVersion:
			blade.Version = value
		case txtAPI:
			blade.API = value
		case txtAuth:
			blade.Authenticated = value == authMTLS
		}
	}

	if blade.Host == "" {
		blade.Host = blade.Name + ".local"
	}
	return blade
}

// unescapeInstance removes DNS escaping from an instance name (e.g. "blade\ 1" -> "blade 1")
func unescapeInstance(instance string) string {
	return strings.ReplaceAll(instance, `\`, "")
}
