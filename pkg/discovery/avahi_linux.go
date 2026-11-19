//go:build linux

package discovery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"github.com/godbus/dbus/v5"
	"go.uber.org/zap"
)

// Avahi D-Bus API, see https://github.com/avahi/avahi/tree/master/avahi-daemon (org.freedesktop.Avahi.*.xml)
const (
	avahiService     = "org.freedesktop.Avahi"
	avahiServerIface = avahiService + ".Server"
	avahiGroupIface  = avahiService + ".EntryGroup"

	avahiIfaceUnspec = int32(-1)
	avahiProtoUnspec = int32(-1)

	// server states (AvahiServerState)
	avahiServerRegistering = 1
	avahiServerRunning     = 2
	avahiServerCollision   = 3

	// entry group states (AvahiEntryGroupState)
	avahiGroupEstablished = 2
	avahiGroupCollision   = 3
	avahiGroupFailure     = 4

	avahiCallTimeout = 5 * time.Second
)

// avahiAdvertiser registers the service with a running avahi-daemon, so avahi stays the only mDNS responder for the
// host's name. Running a second responder next to avahi makes it detect a conflict and rename the host.
type avahiAdvertiser struct {
	conn  *dbus.Conn
	ad    Advertisement
	name  string
	group dbus.BusObject
}

// advertiseAvahi announces ad via avahi until ctx is done. Returns errAvahiUnavailable if avahi isn't running.
func advertiseAvahi(ctx context.Context, ad Advertisement) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("%w: %w", errAvahiUnavailable, err)
	}
	defer func() { _ = conn.Close() }()

	a := &avahiAdvertiser{conn: conn, ad: ad, name: ad.Instance}

	// Don't start avahi through D-Bus activation if it was deliberately stopped
	state, err := a.serverState(ctx, dbus.FlagNoAutoStart)
	if err != nil {
		return fmt.Errorf("%w: %w", errAvahiUnavailable, err)
	}

	for _, match := range [][]dbus.MatchOption{
		{dbus.WithMatchInterface(avahiServerIface), dbus.WithMatchMember("StateChanged")},
		{dbus.WithMatchInterface(avahiGroupIface), dbus.WithMatchMember("StateChanged")},
		{dbus.WithMatchInterface("org.freedesktop.DBus"), dbus.WithMatchMember("NameOwnerChanged"), dbus.WithMatchArg(0, avahiService)},
	} {
		if err := conn.AddMatchSignalContext(ctx, match...); err != nil {
			return fmt.Errorf("failed to subscribe to avahi signals: %w", err)
		}
	}
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	defer conn.RemoveSignal(signals)

	log.FromContext(ctx).Info("Announcing via avahi", zap.String("instance", a.name))
	if state == avahiServerRunning {
		a.register(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			a.unregister(context.WithoutCancel(ctx))
			return nil
		case sig, ok := <-signals:
			if !ok {
				return errors.New("lost the D-Bus connection to avahi")
			}
			a.handleSignal(ctx, sig)
		}
	}
}

func (a *avahiAdvertiser) handleSignal(ctx context.Context, sig *dbus.Signal) {
	switch sig.Name {
	case "org.freedesktop.DBus.NameOwnerChanged":
		// avahi-daemon stopped or (re)started: its entry groups are gone
		if len(sig.Body) < 3 {
			return
		}
		a.group = nil
		if newOwner, _ := sig.Body[2].(string); newOwner == "" {
			log.FromContext(ctx).Warn("avahi-daemon stopped, the API is no longer announced until it's back")
			return
		}
		if state, err := a.serverState(ctx, 0); err == nil && state == avahiServerRunning {
			a.register(ctx)
		}

	case avahiServerIface + ".StateChanged":
		state, ok := signalState(sig)
		if !ok {
			return
		}
		switch state {
		case avahiServerRunning:
			if a.group == nil {
				a.register(ctx)
			}
		case avahiServerRegistering, avahiServerCollision:
			// avahi is (re)claiming its host name: entry groups have to be withdrawn and added again once it runs
			a.unregister(ctx)
		}

	case avahiGroupIface + ".StateChanged":
		state, ok := signalState(sig)
		if !ok || a.group == nil || sig.Path != a.group.Path() {
			return
		}
		switch state {
		case avahiGroupEstablished:
			log.FromContext(ctx).Info("Service registered with avahi", zap.String("instance", a.name))
		case avahiGroupCollision:
			a.unregister(ctx)
			alternative, err := a.alternativeName(ctx)
			if err != nil {
				log.FromContext(ctx).WithError(err).Warn("Service name taken on the network and no alternative available")
				return
			}
			log.FromContext(ctx).Warn("Service name taken on the network, using an alternative",
				zap.String("instance", a.name), zap.String("alternative", alternative))
			a.name = alternative
			a.register(ctx)
		case avahiGroupFailure:
			reason := ""
			if len(sig.Body) > 1 {
				reason, _ = sig.Body[1].(string)
			}
			log.FromContext(ctx).Warn("avahi failed to register the service", zap.String("reason", reason))
		}
	}
}

func signalState(sig *dbus.Signal) (int32, bool) {
	if len(sig.Body) == 0 {
		return 0, false
	}
	state, ok := sig.Body[0].(int32)
	return state, ok
}

func (a *avahiAdvertiser) server() dbus.BusObject {
	return a.conn.Object(avahiService, "/")
}

func (a *avahiAdvertiser) serverState(ctx context.Context, flags dbus.Flags) (int32, error) {
	ctx, cancel := context.WithTimeout(ctx, avahiCallTimeout)
	defer cancel()

	var state int32
	err := a.server().CallWithContext(ctx, avahiServerIface+".GetState", flags).Store(&state)
	return state, err
}

func (a *avahiAdvertiser) alternativeName(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, avahiCallTimeout)
	defer cancel()

	var name string
	err := a.server().CallWithContext(ctx, avahiServerIface+".GetAlternativeServiceName", 0, a.name).Store(&name)
	return name, err
}

// register adds the service in a new entry group. Errors are logged: the next avahi state change retries.
func (a *avahiAdvertiser) register(ctx context.Context) {
	if err := a.tryRegister(ctx); err != nil {
		log.FromContext(ctx).WithError(err).Warn("Failed to register the service with avahi")
	}
}

func (a *avahiAdvertiser) tryRegister(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, avahiCallTimeout)
	defer cancel()

	var path dbus.ObjectPath
	if err := a.server().CallWithContext(ctx, avahiServerIface+".EntryGroupNew", 0).Store(&path); err != nil {
		return fmt.Errorf("failed to create entry group: %w", err)
	}
	group := a.conn.Object(avahiService, path)

	txt := make([][]byte, 0, len(a.ad.TXT()))
	for _, record := range a.ad.TXT() {
		txt = append(txt, []byte(record))
	}

	// An empty domain and host name stand for avahi's defaults: .local and avahi's own host name
	err := group.CallWithContext(ctx, avahiGroupIface+".AddService", 0,
		avahiIfaceUnspec, avahiProtoUnspec, uint32(0), a.name, ServiceType, "", "", uint16(a.ad.Port), txt,
	).Err
	if err == nil {
		err = group.CallWithContext(ctx, avahiGroupIface+".Commit", 0).Err
	}
	if err != nil {
		_ = group.CallWithContext(ctx, avahiGroupIface+".Free", 0).Err
		return fmt.Errorf("failed to add the service: %w", err)
	}

	a.group = group
	return nil
}

// unregister withdraws the service, if registered
func (a *avahiAdvertiser) unregister(ctx context.Context) {
	if a.group == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, avahiCallTimeout)
	defer cancel()

	_ = a.group.CallWithContext(ctx, avahiGroupIface+".Free", 0).Err
	a.group = nil
}
