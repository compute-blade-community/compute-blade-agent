package internal_agent

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/compute-blade-community/compute-blade-agent/pkg/agent"
	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/compute-blade-community/compute-blade-agent/pkg/health"
	"github.com/compute-blade-community/compute-blade-agent/pkg/ledengine"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"github.com/sierrasoftworks/humane-errors-go"
	"go.uber.org/zap"
)

const (
	// LED layer names of the built-in indicators
	ledLayerIdentify = "identify"
	ledLayerCritical = "critical"

	// Built-in indicators always outrank configurable health indicators
	ledPriorityIdentify = 1000
	ledPriorityCritical = 2000
	// maxIndicatorPriority is the highest priority a configured health indicator may use
	maxIndicatorPriority = ledPriorityIdentify - 1
)

// setupLeds creates the LED stacks for both LEDs, with identify on the edge LED, critical mode on the top LED and the
// configured health indicators on either.
func (a *computeBladeAgent) setupLeds() error {
	var err error

	a.edgeLeds, err = ledengine.NewStack(a.edgeLedEngine, ledengine.NewStaticPattern(a.config.IdleLedColor))
	if err != nil {
		return err
	}
	if err := a.edgeLeds.Define(ledLayerIdentify, ledPriorityIdentify,
		ledengine.NewBurstPattern(led.Color{}, a.config.IdentifyLedColor)); err != nil {
		return err
	}

	a.topLeds, err = ledengine.NewStack(a.topLedEngine, ledengine.NewStaticPattern(led.Color{}))
	if err != nil {
		return err
	}
	if err := a.topLeds.Define(ledLayerCritical, ledPriorityCritical,
		ledengine.NewSlowBlinkPattern(led.Color{}, a.config.CriticalLedColor)); err != nil {
		return err
	}

	a.indicatorLeds = make(map[string]*ledengine.Stack)

	// iterate in a stable order so configuration errors are reported deterministically
	conditions := make([]string, 0, len(a.config.Indicators))
	for condition := range a.config.Indicators {
		conditions = append(conditions, condition)
	}
	sort.Strings(conditions)

	for _, condition := range conditions {
		if err := a.setupIndicator(condition, a.config.Indicators[condition]); err != nil {
			return err
		}
	}

	return nil
}

func (a *computeBladeAgent) setupIndicator(condition string, cfg agent.IndicatorConfig) error {
	if !slices.Contains(events.Conditions, condition) {
		return humane.New(fmt.Sprintf("unknown health condition %q in indicators", condition),
			fmt.Sprintf("valid conditions are: %v", events.Conditions),
		)
	}

	var stack *ledengine.Stack
	switch cfg.Led {
	case agent.IndicatorLedTop:
		stack = a.topLeds
	case agent.IndicatorLedEdge:
		stack = a.edgeLeds
	case agent.IndicatorLedNone, "":
		return nil
	default:
		return humane.New(fmt.Sprintf("invalid led %q for indicator %s", cfg.Led, condition),
			"valid values are: top, edge, none",
		)
	}

	if cfg.Priority < 0 || cfg.Priority > maxIndicatorPriority {
		return humane.New(fmt.Sprintf("invalid priority %d for indicator %s", cfg.Priority, condition),
			fmt.Sprintf("priority must be between 0 and %d, identify and critical mode always take precedence", maxIndicatorPriority),
		)
	}

	pattern, err := ledengine.PatternFromName(cfg.Pattern, cfg.Color)
	if err != nil {
		return humane.Wrap(err, fmt.Sprintf("invalid pattern for indicator %s", condition))
	}

	if err := stack.Define(condition, cfg.Priority, pattern); err != nil {
		return err
	}
	a.indicatorLeds[condition] = stack
	return nil
}

// setIndicator shows or hides the LED indicator of a health condition, if one is configured.
func (a *computeBladeAgent) setIndicator(condition string, active bool) error {
	stack, ok := a.indicatorLeds[condition]
	if !ok {
		return nil
	}
	if active {
		return stack.Activate(condition)
	}
	return stack.Deactivate(condition)
}

// setupFanStallDetection enables fan stall detection if configured and supported by the fan unit.
func (a *computeBladeAgent) setupFanStallDetection(ctx context.Context) {
	cfg := a.config.Health.FanStall
	if !cfg.Enabled {
		log.FromContext(ctx).Info("Fan stall detection disabled by configuration")
		return
	}
	if !a.blade.FanRPMSupported() {
		log.FromContext(ctx).Warn("Fan stall detection disabled: the fan unit doesn't report its speed (RPM reporting disabled or no tachometer)")
		return
	}

	log.FromContext(ctx).Info("Fan stall detection enabled",
		zap.Uint8("min_percent", cfg.MinPercent),
		zap.Float64("min_rpm", cfg.MinRPM),
		zap.Duration("grace_period", cfg.GracePeriod),
	)
	a.fanStallDetector = &health.FanStallDetector{Config: cfg}
}
