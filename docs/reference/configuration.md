# Configuration file

The agent reads `/etc/compute-blade-agent/config.yaml` when it starts. There is no reload: restart the service after
changing it (`systemctl restart compute-blade-agent`). The packages install a commented copy of every setting, the
same as [`cmd/agent/default-config.yaml`](../../cmd/agent/default-config.yaml).

Settings missing from the file fall back to the defaults listed here. A config file written for an older release keeps
working after an upgrade, because package managers don't replace a config file you changed.

## Environment variables

Every key can be overridden with an environment variable: prefix it with `BLADE_`, upper-case it and replace dots with
underscores. `listen.metrics` becomes `BLADE_LISTEN_METRICS`, `critical_temperature_threshold` becomes
`BLADE_CRITICAL_TEMPERATURE_THRESHOLD`.

A variable only takes effect for keys that appear in the config file or have a built-in default. Lists and maps (fan
curve steps, indicators, exec commands) can't be set through the environment.

To set variables for the service, use a systemd drop-in:

```ini
# /etc/systemd/system/compute-blade-agent.service.d/override.conf
[Service]
Environment=BLADE_STEALTH_MODE=true
```

OpenTelemetry export is configured with the standard `OTEL_*` variables, for example `OTEL_EXPORTER_OTLP_ENDPOINT`.

## Command line flags

| Flag            | Description                                                    |
|-----------------|----------------------------------------------------------------|
| `-v`, `--debug` | Human-readable debug logging instead of JSON production logs. |

## Top-level settings

| Key                              | Type    | Default        | Description |
|----------------------------------|---------|----------------|-------------|
| `stealth_mode`                   | bool    | `false`        | Turn all LEDs off. Critical mode turns them back on. |
| `critical_temperature_threshold` | integer | `60`           | SoC temperature in °C at which the agent enters critical mode. It leaves critical mode 5°C below. `0` disables automatic critical mode. |
| `idle_led_color`                 | color   | `0, 16, 0`     | Edge LED color when nothing else is shown. |
| `identify_led_color`             | color   | `16, 0, 16`    | Edge LED color while identify is active. |
| `critical_led_color`             | color   | `64, 0, 0`     | Top LED color in critical mode. |

A color is a map with `red`, `green` and `blue`, each 0 to 255. The LEDs are bright: values above 64 are rarely
needed.

```yaml
critical_led_color:
  red: 64
  green: 0
  blue: 0
```

`criticalLedColor` is the old name of `critical_led_color`. The agent still reads it and logs a deprecation warning.

## `listen`

| Key                    | Type   | Default                         | Description |
|------------------------|--------|---------------------------------|-------------|
| `listen.metrics`       | string | `:9666`                         | Address of the HTTP server for `/metrics` and `/debug/pprof/`. |
| `listen.mode`          | string | `unix`                          | `unix` for a local socket, `tcp` to accept network connections. |
| `listen.grpc`          | string | `/tmp/compute-blade-agent.sock` | Socket path in `unix` mode, `host:port` (e.g. `:8081`) in `tcp` mode. |
| `listen.authenticated` | bool   | `false`                         | Require mTLS client certificates. Only applies in `tcp` mode. |

See [Security model](../explanation/security.md) for what `authenticated` sets up.

## `hal`

| Key                                   | Type | Default | Description |
|---------------------------------------|------|---------|-------------|
| `hal.rpm_reporting_standard_fan_unit` | bool | `true`  | Measure the fan speed of a standard fan unit. Counting tachometer pulses costs a little CPU. Without it, fan stall detection is off for standard fan units. The smart fan unit always reports its speed. |

## `fan_controller`

The fan curve maps the SoC temperature to a fan speed.

| Key                    | Type | Default                  | Description |
|------------------------|------|--------------------------|-------------|
| `fan_controller.steps` | list | `45°C: 40%`, `55°C: 80%` | Points of the curve. Each has `temperature` (°C) and `percent` (0 to 100). |

Below the first step the fan runs at the first step's speed, above the last step at the last step's speed. Between two
steps the agent interpolates linearly. Temperatures must strictly increase and speeds must not decrease, otherwise the
agent refuses to start.

```yaml
fan_controller:
  steps:
    - temperature: 45
      percent: 40
    - temperature: 55
      percent: 80
```

## `health`

| Key                               | Type     | Default | Description |
|-----------------------------------|----------|---------|-------------|
| `health.fan_stall.enabled`        | bool     | `true`  | Detect a fan that doesn't spin although it should. Needs RPM reporting. |
| `health.fan_stall.min_percent`    | integer  | `20`    | Only judge the fan when it's commanded to at least this speed. Many fans stop at low duty cycles. |
| `health.fan_stall.min_rpm`        | number   | `100`   | Below this speed the fan counts as stopped. |
| `health.fan_stall.grace_period`   | duration | `15s`   | How long the fan must stay below `min_rpm` before the stall is raised. Covers spin-up. |
| `health.undervoltage.enabled`     | bool     | `true`  | Raise `undervoltage` when the firmware reports a too low supply voltage. Raspberry Pi only. |
| `health.undervoltage.clear_after` | duration | `30s`   | How long the voltage has to be fine before the condition clears. |
| `health.throttling.enabled`       | bool     | `true`  | Raise `throttled` when the firmware caps or throttles the CPU. Raspberry Pi only. |
| `health.throttling.clear_after`   | duration | `30s`   | How long the CPU has to run unthrottled before the condition clears. |

Durations use Go syntax: `500ms`, `15s`, `2m`.

## `indicators`

An indicator shows a health condition on an LED. The map key is the condition name: `fan_stall`, `undervoltage` or
`throttled`.

| Key        | Type    | Description |
|------------|---------|-------------|
| `led`      | string  | `top`, `edge` or `none` to not show the condition. |
| `pattern`  | string  | `static`, `slow-blink`, `fast-blink` or `burst`. See [LEDs](leds.md#patterns). |
| `color`    | color   | Color of the pattern. |
| `priority` | integer | 0 to 999. When several indicators are active on the same LED, the highest priority is shown. Identify and critical mode always win. |

Defaults:

| Condition      | `led`  | `pattern`    | `color`      | `priority` |
|----------------|--------|--------------|--------------|------------|
| `fan_stall`    | `top`  | `fast-blink` | `64, 24, 0`  | 30         |
| `undervoltage` | `top`  | `burst`      | `64, 40, 0`  | 20         |
| `throttled`    | `none` | `slow-blink` | `32, 32, 0`  | 10         |

You can override single fields: `indicators.fan_stall.led: edge` keeps the default pattern, color and priority.

## `power_policy`

Limits the CPU while the blade is short on power. Each reason takes a `governor` (a cpufreq governor such as
`powersave`, empty to leave it alone) and `max_freq_mhz` (a frequency cap, `0` for none). The policy is off as long as
every field is empty or zero.

| Key                                       | Default | Applies while |
|-------------------------------------------|---------|---------------|
| `power_policy.limited_power.governor`     | `""`    | the blade is not powered by 802.3at PoE+ (802.3af PoE or USB-C) |
| `power_policy.limited_power.max_freq_mhz` | `0`     | same |
| `power_policy.undervoltage.governor`      | `""`    | the `undervoltage` condition is raised |
| `power_policy.undervoltage.max_freq_mhz`  | `0`     | same |

If both reasons apply, the lower frequency cap wins and the `undervoltage` governor takes precedence. The agent
refuses to start if a governor isn't offered by the kernel. The RK3588 HAL can't detect PoE+ and always reports
802.3af/USB-C, so `limited_power` would always apply there.

## `button`

Binds actions to gestures of the edge button. An action is either a built-in `action` or an `exec` command, never
both. See [Bind actions to button gestures](../how-to/button-gestures.md).

| Key                          | Type     | Default                     | Description |
|------------------------------|----------|-----------------------------|-------------|
| `button.gesture_window`      | duration | `400ms`                     | Longest gap between two presses of one series. |
| `button.single`              | action   | `action: identify-toggle`   | One short press. `action: none` disables it. |
| `button.double`              | action   | nothing                     | Two short presses. |
| `button.long_press.hold`     | duration | `5s`                        | How long the button has to be held. Must be more than 1s. |
| `button.long_press`          | action   | nothing                     | Holding the button for `hold`. |
| `button.multi_press.count`   | integer  | `5`                         | Number of short presses, at least 3. |
| `button.multi_press`         | action   | nothing                     | `count` short presses. Fires as soon as the count is reached. |

An action has these fields:

| Field     | Type     | Description |
|-----------|----------|-------------|
| `action`  | string   | `none`, `identify-toggle`, `shutdown`, `reboot` or `emergency-poweroff`. |
| `exec`    | list     | Command and arguments, run directly without a shell. |
| `timeout` | duration | How long `exec` may run before it's killed. Default `30s`. |

The environment of an `exec` command is described in [Events](events.md#environment-of-exec-actions).

```yaml
button:
  double:
    exec: ["/usr/local/bin/drain-node.sh"]
    timeout: 2m
  long_press:
    hold: 5s
    action: shutdown
```

## `discovery`

| Key                         | Type | Default | Description |
|-----------------------------|------|---------|-------------|
| `discovery.mdns.enabled`    | bool | `true`  | Announce the API as `_compute-blade._tcp` via mDNS. Only in `tcp` listen mode. See [Discovery](../explanation/discovery.md). |

## Settings without effect

`log.mode` and `fan_speed` are accepted for compatibility with old config files but do nothing. Use `--debug` for
verbose logs and `bladectl set fan --percent` for a fixed fan speed.
