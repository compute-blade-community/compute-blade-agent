# Events

Everything the agent reacts to or detects is an event. The agent handles events one at a time and publishes each of
them to the [`WatchEvents`](grpc-api.md#watchevents) stream, which `bladectl events` prints.

Event names come in two spellings: lower case (`fan_stall`) in `bladectl events --event`, metrics and the
`BLADE_EVENT` variable, upper case (`FAN_STALL`) in the gRPC `Event` enum and the JSON output.

## Event types

| Event                | Emitted when                                                                                         | Details |
|----------------------|------------------------------------------------------------------------------------------------------|---------|
| `identify`           | Identify starts: `bladectl set identify`, the `identify-toggle` action or a fan unit button press.   | none |
| `identify_confirm`   | Identify stops: `bladectl set identify --confirm`, `bladectl remove identify`, a toggle or button.   | none |
| `critical`           | The SoC reaches `critical_temperature_threshold`, or a client sent the event with `EmitEvent`.      | none |
| `critical_reset`     | The SoC cooled to 5°C below the threshold, or a client sent the event.                              | none |
| `button_press`       | A button was pressed (on press, not release).                                                       | `button` |
| `button_gesture`     | The edge button completed a gesture, whether or not an action is bound to it.                       | `gesture` |
| `fan_stall`          | The fan stayed below `min_rpm` for `grace_period` while commanded to at least `min_percent`.        | `fan` |
| `fan_stall_clear`    | The fan reached `min_rpm` again.                                                                     | `fan` |
| `undervoltage`       | The firmware reports under-voltage.                                                                  | `throttle` |
| `undervoltage_clear` | No under-voltage for `health.undervoltage.clear_after`.                                              | `throttle` |
| `throttled`          | The firmware reports a capped, throttled or soft-limited CPU.                                        | `throttle` |
| `throttled_clear`    | No throttling for `health.throttling.clear_after`.                                                   | `throttle` |
| `power_limit`        | The power policy applied a CPU limit or changed it (e.g. a second reason started to apply).          | `power_limit` |
| `power_limit_clear`  | The power policy lifted all limits and restored the original CPU settings.                           | `power_limit` |

Raise and clear events come in pairs. A condition is raised once, then cleared once, so a stream consumer can keep
state by watching the pairs.

## Details

| Details       | Fields |
|---------------|--------|
| `button`      | `source`: `edge` or `fan_unit`. |
| `gesture`     | `gesture`: `single`, `double`, `multi_press` or `long_press`. `presses`: number of presses (0 for a long press). `held_ms`: how long a long press was held. `action`: the built-in action that ran, `exec`, or empty if nothing is bound. |
| `fan`         | `target_percent`: commanded fan speed. `rpm`: measured fan speed. |
| `throttle`    | `flags`: raw firmware bitfield, as `vcgencmd get_throttled` prints it. `under_voltage`, `arm_freq_capped`, `throttled`, `soft_temp_limit`: the decoded current-state bits. |
| `power_limit` | `reasons`: `undervoltage` and/or `limited_power`, empty when cleared. `governor`: governor set by the limit. `max_freq_mhz`: frequency cap, 0 for none. |

A series of short presses whose count isn't bound to anything (e.g. three presses with `multi_press.count: 5`) is still
published, as `multi_press` with an empty action.

## Delivery

Delivery is best effort. Each subscriber has a buffer of 64 events. A subscriber that falls further behind misses
events, and the agent never blocks on a slow subscriber. Events aren't stored: a client that connects later doesn't
see what happened before. Use `bladectl get status` or [`GetStatus`](grpc-api.md#getstatus) to learn the current state
after (re)connecting.

## Environment of exec actions

Commands bound to a button gesture with `exec` run as root, without a shell, with the agent's environment plus:

| Variable            | Value |
|---------------------|-------|
| `BLADE_EVENT`       | `button_gesture` |
| `BLADE_GESTURE`     | `single`, `double`, `multi_press` or `long_press` |
| `BLADE_PRESS_COUNT` | Number of presses, `0` for a long press |
| `BLADE_HOLD_MS`     | How long the button was held, `0` for presses |
| `BLADE_HOSTNAME`    | The blade's hostname |

The agent logs the command's output. A command that runs longer than its `timeout` (default 30s) is killed. While a
command of a gesture still runs, new triggers of the same gesture are dropped with a warning.
