//go:build !tinygo

package hal

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	fanTargetPercent = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "computeblade",
		Name:      "fan_target_percent",
		Help:      "Target fan speed in percent",
	})
	fanSpeed = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "computeblade",
		Name:      "fan_speed",
		Help:      "Fan speed in RPM",
	})
	socTemperature = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "computeblade",
		Name:      "soc_temperature",
		Help:      "SoC temperature in °C",
	})
	airFlowTemperature = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "computeblade",
		Name:      "airflow_temperature",
		Help:      "airflow temperature in °C",
	})
	computeModule = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "computeblade",
		Name:      "compute_module_present",
		Help:      "Compute module type",
	}, []string{"type"})
	ledColorChangeEventCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "computeblade",
		Name:      "led_color_change_event_count",
		Help:      "Led color change event_count",
	})
	powerStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "computeblade",
		Name:      "power_status",
		Help:      "Power status of the blade",
	}, []string{"type"})
	stealthModeEnabled = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "computeblade",
		Name:      "stealth_mode_enabled",
		Help:      "Stealth mode enabled",
	})
	fanUnit = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "computeblade",
		Name:      "fan_unit",
		Help:      "Fan unit",
	}, []string{"type"})
	throttleActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "computeblade",
		Name:      "throttle_active",
		Help:      "Raspberry Pi firmware throttle flags currently active (1) or not (0)",
	}, []string{"flag"})
	throttleOccurred = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "computeblade",
		Name:      "throttle_occurred",
		Help:      "Raspberry Pi firmware throttle flags that occurred since boot (1) or not (0)",
	}, []string{"flag"})
	edgeButtonEventCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "computeblade",
		Name:      "edge_button_event_count",
		Help:      "Number of edge button presses",
	})
)
