# Prometheus metrics

The agent serves metrics at `http://<blade>:9666/metrics` (`listen.metrics`). Besides the metrics below, the endpoint
has the standard Go runtime and process metrics (`go_*`, `process_*`).

## Hardware

| Metric                                    | Type    | Labels | Description |
|-------------------------------------------|---------|--------|-------------|
| `computeblade_soc_temperature`            | gauge   |        | SoC temperature in °C. |
| `computeblade_airflow_temperature`        | gauge   |        | Airflow temperature in °C, reported by the smart fan unit. |
| `computeblade_fan_target_percent`         | gauge   |        | Fan speed the agent commands, in percent. |
| `computeblade_fan_speed`                  | gauge   |        | Measured fan speed in RPM. |
| `computeblade_fan_unit`                   | gauge   | `type` | 1 for the detected fan unit: `standard`, `smart`, `sysfs` (RK3588) or `simulated`. |
| `computeblade_compute_module_present`     | gauge   | `type` | 1 for the detected module: `cm4`, `cm5`, `radxa-cm5` or `simulated`. |
| `computeblade_power_status`               | gauge   | `type` | 1 for the current power source: `poe+` or `poeOrUsbC`. |
| `computeblade_stealth_mode_enabled`       | gauge   |        | 1 while stealth mode is on. |
| `computeblade_led_color_change_event_count` | counter |      | LED color changes written to the hardware. |
| `computeblade_edge_button_event_count`    | counter |        | Button presses, edge button and fan unit button. |
| `computeblade_button_events_dropped_count` | counter |       | Button transitions dropped because the agent fell behind. |

## Firmware throttle flags

Raspberry Pi only. `flag` is one of `under_voltage`, `arm_freq_capped`, `throttled` and `soft_temp_limit`.

| Metric                              | Type  | Labels | Description |
|-------------------------------------|-------|--------|-------------|
| `computeblade_throttle_active`      | gauge | `flag` | 1 while the firmware reports the flag. |
| `computeblade_throttle_occurred`    | gauge | `flag` | 1 if the flag occurred since boot. |

If the agent can only read the `rpi_volt` hwmon device (see [Power, throttling and the power
policy](../explanation/power-and-throttling.md#where-the-flags-come-from)), only `throttle_active{flag="under_voltage"}`
exists.

## Agent state

| Metric                                       | Type    | Labels   | Description |
|----------------------------------------------|---------|----------|-------------|
| `computeblade_state_state`                   | gauge   | `state`  | 1 while the state is active. `state` is `normal`, `identify`, `critical` or a health condition: `fan_stall`, `undervoltage`, `throttled`. |
| `computeblade_power_limit_active`            | gauge   | `reason` | 1 while the power policy limits the CPU for `reason`: `undervoltage` or `limited_power`. |
| `computeblade_agent_events_count`            | counter | `type`   | Events handled, by event name (see [Events](events.md)). |
| `computeblade_agent_events_dropped_count`    | counter | `type`   | Events dropped because the event loop was full. |

[Monitor blades with Prometheus](../how-to/prometheus-monitoring.md) has scrape configs and alert rules.
