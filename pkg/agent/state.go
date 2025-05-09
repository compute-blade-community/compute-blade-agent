package agent

import (
	"context"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/spechtlabs/go-otel-utils/otelzap"
	"github.com/uptime-industries/compute-blade-agent/pkg/events"
	"go.uber.org/zap"
)

var (
	stateMetric = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "computeblade_state",
		Name:      "state",
		Help:      "ComputeBlade state (label values are critical, identify, normal)",
	}, []string{"state"})
)

type ComputebladeState interface {
	RegisterEvent(event events.Event)
	IdentifyActive() bool
	WaitForIdentifyConfirm(ctx context.Context) error
	CriticalActive() bool
	WaitForCriticalClear(ctx context.Context) error
}

type computebladeStateImpl struct {
	mutex sync.Mutex

	// identifyActive indicates whether the blade is currently in identify mode
	identifyActive      bool
	identifyConfirmChan chan struct{}
	// criticalActive indicates whether the blade is currently in critical mode
	criticalActive      bool
	criticalConfirmChan chan struct{}
}

func NewComputeBladeState() ComputebladeState {
	return &computebladeStateImpl{
		identifyConfirmChan: make(chan struct{}),
		criticalConfirmChan: make(chan struct{}),
	}
}

func (s *computebladeStateImpl) RegisterEvent(event events.Event) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
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

	default:
		otelzap.L().Warn("Unknown event", zap.String("event", event.String()))
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

	// Set critical state metric
	if !s.criticalActive && !s.identifyActive {
		stateMetric.WithLabelValues("normal").Set(1)
	} else {
		stateMetric.WithLabelValues("normal").Set(0)
	}
}

func (s *computebladeStateImpl) IdentifyActive() bool {
	return s.identifyActive
}

func (s *computebladeStateImpl) WaitForIdentifyConfirm(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.identifyConfirmChan:
		return nil
	}
}

func (s *computebladeStateImpl) CriticalActive() bool {
	return s.criticalActive
}

func (s *computebladeStateImpl) WaitForCriticalClear(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.criticalConfirmChan:
		return nil
	}
}
