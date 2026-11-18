package internal_agent

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/compute-blade-community/compute-blade-agent/pkg/agent"
	"github.com/compute-blade-community/compute-blade-agent/pkg/cpufreq"
	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sierrasoftworks/humane-errors-go"
	"go.uber.org/zap"
)

const (
	// Reasons for a power limit, as reported in events and metrics
	powerLimitReasonUndervoltage = "undervoltage"
	powerLimitReasonLimitedPower = "limited_power"

	// cpufreqStatePath persists the original cpufreq settings while a limit is applied (tmpfs, cleared on reboot)
	cpufreqStatePath = "/run/compute-blade-agent/cpufreq-original.json"
)

var powerLimitActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "computeblade",
	Name:      "power_limit_active",
	Help:      "CPU limited by the power policy (1) or not (0), by reason",
}, []string{"reason"})

// powerLimitCPU is the part of cpufreq.Controller the power policy needs
type powerLimitCPU interface {
	Validate(cpufreq.Limits) error
	Apply(cpufreq.Limits) error
	Restore() error
}

// powerPolicy limits the CPU while the blade is short on power
type powerPolicy struct {
	mu  sync.Mutex
	cpu powerLimitCPU

	limitedPower cpufreq.Limits
	undervoltage cpufreq.Limits

	// limitedPowerActive remembers the last known power source, so a failed read doesn't flip the policy
	limitedPowerActive bool
	// reasons currently applied
	reasons []string
	stopped bool
}

func toLimits(cfg agent.CPULimitsConfig) cpufreq.Limits {
	return cpufreq.Limits{Governor: cfg.Governor, MaxFreqKHz: uint64(cfg.MaxFreqMHz) * 1000}
}

// setupPowerPolicy enables the power policy if any limit is configured and the system supports cpufreq.
func (a *computeBladeAgent) setupPowerPolicy(ctx context.Context) error {
	cfg := a.config.PowerPolicy
	limitedPower, undervoltage := toLimits(cfg.LimitedPower), toLimits(cfg.Undervoltage)
	if limitedPower.IsZero() && undervoltage.IsZero() {
		return nil
	}

	cpu, err := cpufreq.New("/", cpufreqStatePath)
	if errors.Is(err, cpufreq.ErrNotSupported) {
		log.FromContext(ctx).Warn("Power policy configured but cpufreq is not available, power policy disabled")
		return nil
	}
	if err != nil {
		return humane.Wrap(err, "failed to initialise cpufreq for the power policy")
	}

	policy, err := newPowerPolicy(cpu, limitedPower, undervoltage)
	if err != nil {
		return err
	}

	// Start from the original settings. This undoes limits left behind by a previous agent instance that didn't shut
	// down cleanly (the originals were persisted to cpufreqStatePath).
	if err := cpu.Restore(); err != nil {
		log.FromContext(ctx).WithError(err).Warn("Failed to restore original CPU settings")
	}

	if !undervoltage.IsZero() && a.undervoltageDetector == nil {
		log.FromContext(ctx).Warn("power_policy.undervoltage is configured but under-voltage detection is disabled, it will never apply")
	}

	log.FromContext(ctx).Info("Power policy enabled",
		zap.Any("limited_power", limitedPower),
		zap.Any("undervoltage", undervoltage),
	)
	a.powerPolicy = policy
	return nil
}

func newPowerPolicy(cpu powerLimitCPU, limitedPower, undervoltage cpufreq.Limits) (*powerPolicy, error) {
	if err := cpu.Validate(limitedPower); err != nil {
		return nil, humane.Wrap(err, "invalid power_policy.limited_power")
	}
	if err := cpu.Validate(undervoltage); err != nil {
		return nil, humane.Wrap(err, "invalid power_policy.undervoltage")
	}
	return &powerPolicy{cpu: cpu, limitedPower: limitedPower, undervoltage: undervoltage}, nil
}

// desired combines the limits of all active reasons: the lowest frequency cap wins, the under-voltage governor takes
// precedence over the limited-power one.
func (p *powerPolicy) desired(limitedPower, undervoltage bool) (cpufreq.Limits, []string) {
	var (
		limits  cpufreq.Limits
		reasons []string
	)

	add := func(reason string, l cpufreq.Limits) {
		if l.IsZero() {
			return
		}
		reasons = append(reasons, reason)
		if limits.Governor == "" {
			limits.Governor = l.Governor
		}
		if l.MaxFreqKHz != 0 && (limits.MaxFreqKHz == 0 || l.MaxFreqKHz < limits.MaxFreqKHz) {
			limits.MaxFreqKHz = l.MaxFreqKHz
		}
	}

	if undervoltage {
		add(powerLimitReasonUndervoltage, p.undervoltage)
	}
	if limitedPower {
		add(powerLimitReasonLimitedPower, p.limitedPower)
	}
	return limits, reasons
}

// update applies the limits for the given state. Returns the applied limits and reasons, and whether they changed.
func (p *powerPolicy) update(limitedPower, undervoltage bool) (cpufreq.Limits, []string, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stopped {
		return cpufreq.Limits{}, nil, false, nil
	}

	limits, reasons := p.desired(limitedPower, undervoltage)
	if fmt.Sprint(reasons) == fmt.Sprint(p.reasons) {
		return limits, reasons, false, nil
	}

	if err := p.cpu.Apply(limits); err != nil {
		return limits, reasons, false, err
	}
	p.reasons = reasons
	return limits, reasons, true, nil
}

// stop restores the original CPU settings and prevents further changes.
func (p *powerPolicy) stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopped = true
	p.reasons = nil
	return p.cpu.Restore()
}

// evaluatePowerPolicy applies or lifts CPU limits based on the power source and the under-voltage condition.
func (a *computeBladeAgent) evaluatePowerPolicy(ctx context.Context) {
	p := a.powerPolicy

	if !p.limitedPower.IsZero() {
		status, err := a.blade.GetPowerStatus()
		if err != nil {
			log.FromContext(ctx).WithError(err).Warn("Failed to read power status, keeping the current power policy")
		} else {
			p.limitedPowerActive = status != hal.PowerPoe802at
		}
	}
	undervoltage := a.undervoltageDetector != nil && a.undervoltageDetector.Active()

	limits, reasons, changed, err := p.update(p.limitedPowerActive, undervoltage)
	if err != nil {
		log.FromContext(ctx).WithError(err).Error("Failed to apply power policy")
		return
	}
	if !changed {
		return
	}

	for _, reason := range []string{powerLimitReasonUndervoltage, powerLimitReasonLimitedPower} {
		active := 0.0
		for _, r := range reasons {
			if r == reason {
				active = 1
			}
		}
		powerLimitActive.WithLabelValues(reason).Set(active)
	}

	details := events.PowerLimitDetails{
		Reasons:    reasons,
		Governor:   limits.Governor,
		MaxFreqMHz: uint(limits.MaxFreqKHz / 1000),
	}
	if len(reasons) == 0 {
		log.FromContext(ctx).Info("Power limit lifted, original CPU settings restored")
		a.emitMessage(ctx, events.NewMessage(events.PowerLimitClearEvent, details))
		return
	}

	log.FromContext(ctx).Warn("CPU limited by power policy",
		zap.Strings("reasons", reasons),
		zap.String("governor", limits.Governor),
		zap.Uint64("max_freq_khz", limits.MaxFreqKHz),
	)
	a.emitMessage(ctx, events.NewMessage(events.PowerLimitEvent, details))
}
