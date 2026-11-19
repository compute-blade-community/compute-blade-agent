# Monitor blades with Prometheus

Every agent serves metrics on port 9666. The full list is in [Prometheus metrics](../reference/metrics.md).

## Scrape the blades

```yaml
scrape_configs:
  - job_name: compute-blade
    static_configs:
      - targets:
          - blade-pi1:9666
          - blade-pi2:9666
          - blade-pi3:9666
          - blade-pi4:9666
```

With the Prometheus Operator, scrape the blades through a `ScrapeConfig` or a `ServiceMonitor` on a headless Service
that points at the nodes' port 9666.

The port also serves `/debug/pprof/` without authentication. Keep it on a management network or firewall it to your
Prometheus server.

## Alert on blade health

```yaml
groups:
  - name: compute-blade
    rules:
      - alert: ComputeBladeFanStalled
        expr: computeblade_state_state{state="fan_stall"} == 1
        for: 1m
        annotations:
          summary: "Fan of {{ $labels.instance }} stopped"

      - alert: ComputeBladeUndervoltage
        expr: computeblade_state_state{state="undervoltage"} == 1
        for: 5m
        annotations:
          summary: "{{ $labels.instance }} gets too little power, check the PoE budget of its switch"

      - alert: ComputeBladeCritical
        expr: computeblade_state_state{state="critical"} == 1
        for: 5m
        annotations:
          summary: "{{ $labels.instance }} stays above its critical temperature"

      - alert: ComputeBladeNotOnPoEPlus
        expr: computeblade_power_status{type="poe+"} == 0
        for: 15m
        annotations:
          summary: "{{ $labels.instance }} runs on 802.3af PoE or USB-C, not PoE+"

      - alert: ComputeBladeAgentDown
        expr: up{job="compute-blade"} == 0
        for: 5m
```

`computeblade_throttle_occurred` tells you whether a flag was set at any time since boot, even between two scrapes.
It's useful to spot short under-voltage dips:

```promql
max by (instance) (computeblade_throttle_occurred{flag="under_voltage"})
```

## Useful queries

```promql
# Temperature and fan speed per blade
computeblade_soc_temperature
computeblade_fan_speed

# Blades whose CPU is limited by the power policy
sum by (instance, reason) (computeblade_power_limit_active) > 0

# Button gestures per day
increase(computeblade_agent_events_count{type="button_gesture"}[1d])
```
