package agent

import (
	"context"
	"sort"
	"sync"

	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/spechtlabs/go-otel-utils/otelzap"
	"go.uber.org/zap"
)

var (
	stateMetric = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "computeblade_state",
		Name:      "state",
		Help:      "ComputeBlade state (label values are critical, identify, normal and the health conditions, e.g. fan_stall)",
	}, []string{"state"})
)

type ComputebladeState interface {
	RegisterEvent(event events.Event)
	IdentifyActive() bool
	WaitForIdentifyConfirm(ctx context.Context) error
	CriticalActive() bool
	WaitForCriticalClear(ctx context.Context) error
	// ConditionActive reports whether the given health condition (e.g. events.ConditionFanStall) is raised
	ConditionActive(condition string) bool
	// ActiveConditions returns the raised health conditions, sorted by name
	ActiveConditions() []string
}

type computebladeStateImpl struct {
	mutex sync.Mutex

	// identifyActive indicates whether the blade is currently in identify mode
	identifyActive      bool
	identifyConfirmChan chan struct{}
	// criticalActive indicates whether the blade is currently in critical mode
	criticalActive      bool
	criticalConfirmChan chan struct{}
	// conditions holds the raised health conditions
	conditions map[string]bool
}

func NewComputeBladeState() ComputebladeState {
	return &computebladeStateImpl{
		identifyConfirmChan: make(chan struct{}),
		criticalConfirmChan: make(chan struct{}),
		conditions:          make(map[string]bool),
	}
}

func (s *computebladeStateImpl) RegisterEvent(event events.Event) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if condition, active, ok := event.ConditionChange(); ok {
		s.conditions[condition] = active
	}

	switch event {
	case events.IdentifyEvent:
		s.identifyActive = true
	case events.IdentifyConfirmEvent:
		s.identifyActive = false
		close(s.identifyConfirmChan)
		s.identifyConfirmChan = make(chan struct{})
	case events.CriticalEvent:
		s.criticalActive = true
		s.identifyActive = false
	case events.CriticalResetEvent:
		s.criticalActive = false
		close(s.criticalConfirmChan)
		s.criticalConfirmChan = make(chan struct{})

	case events.NoopEvent, events.EdgeButtonEvent:
	default:
		if _, _, ok := event.ConditionChange(); !ok {
			otelzap.L().Warn("Unknown event", zap.String("event", event.String()))
		}
	}

	// Set identify state metric
	if s.identifyActive {
		stateMetric.WithLabelValues("identify").Set(1)
	} else {
		stateMetric.WithLabelValues("identify").Set(0)
	}

	// Set critical state metric
	if s.criticalActive {
		stateMetric.WithLabelValues("critical").Set(1)
	} else {
		stateMetric.WithLabelValues("critical").Set(0)
	}

	// Set health condition metrics
	anyCondition := false
	for _, condition := range events.Conditions {
		if s.conditions[condition] {
			anyCondition = true
			stateMetric.WithLabelValues(condition).Set(1)
		} else {
			stateMetric.WithLabelValues(condition).Set(0)
		}
	}

	// Set normal state metric
	if !s.criticalActive && !s.identifyActive && !anyCondition {
		stateMetric.WithLabelValues("normal").Set(1)
	} else {
		stateMetric.WithLabelValues("normal").Set(0)
	}
}

func (s *computebladeStateImpl) IdentifyActive() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.identifyActive
}

func (s *computebladeStateImpl) WaitForIdentifyConfirm(ctx context.Context) error {
	s.mutex.Lock()
	confirmChan := s.identifyConfirmChan
	s.mutex.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-confirmChan:
		return nil
	}
}

func (s *computebladeStateImpl) CriticalActive() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.criticalActive
}

func (s *computebladeStateImpl) WaitForCriticalClear(ctx context.Context) error {
	s.mutex.Lock()
	clearChan := s.criticalConfirmChan
	s.mutex.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-clearChan:
		return nil
	}
}

func (s *computebladeStateImpl) ConditionActive(condition string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.conditions[condition]
}

func (s *computebladeStateImpl) ActiveConditions() []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	active := make([]string, 0, len(s.conditions))
	for condition, isActive := range s.conditions {
		if isActive {
			active = append(active, condition)
		}
	}
	sort.Strings(active)
	return active
}
