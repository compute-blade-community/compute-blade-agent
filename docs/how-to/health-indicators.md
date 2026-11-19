# Configure health indicators

A health indicator shows a raised health condition on one of the LEDs. There are three conditions: `fan_stall`,
`undervoltage` and `throttled`. By default the first two blink on the top LED and `throttled` isn't shown. See
[LEDs](../reference/leds.md) for what everything looks like.

## Show throttling on the edge LED

```yaml
indicators:
  throttled:
    led: edge
    pattern: slow-blink
    color: { red: 32, green: 32, blue: 0 }
```

Restart the agent. Fields you leave out keep their defaults.

## Hide an indicator

```yaml
indicators:
  undervoltage:
    led: none
```

The condition is still detected, published as an event, exported as a metric and listed by `bladectl get status`.
To stop detecting it, disable it under `health` instead:

```yaml
health:
  undervoltage:
    enabled: false
```

## Decide which indicator wins

Several indicators can be active on the same LED at once. The one with the highest `priority` (0 to 999) is shown.
When it clears, the next one shows again.

```yaml
indicators:
  undervoltage:
    priority: 50   # now above fan_stall (30)
```

Identify (edge LED) and critical mode (top LED) always win over indicators.

## Tune fan stall detection

The agent raises `fan_stall` when the fan is commanded to at least `min_percent` but stays below `min_rpm` for
`grace_period`. If your fan stalls slowly or spins down for a long time, adjust these:

```yaml
health:
  fan_stall:
    min_percent: 30   # judge the fan only from 30% on
    min_rpm: 300
    grace_period: 30s
```

Fan stall detection needs the fan speed. A standard fan unit only reports it with
`hal.rpm_reporting_standard_fan_unit: true`, the default.

To test the indicator without breaking a fan, set `min_rpm` above what your fan reaches at its current speed (see
`bladectl get fan`). The stall appears after the grace period. `bladectl set fan --percent 100` clears it if the fan
then spins faster than `min_rpm`.
