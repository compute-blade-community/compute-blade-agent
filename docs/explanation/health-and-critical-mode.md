# Health conditions and critical mode

The agent watches for problems a blade can't solve by itself but a human or another program can: a dead fan, a
switch running out of PoE budget, a CPU slowing down. It reports them as **health conditions**. **Critical mode** is
different: the agent reacts to it itself, because waiting for someone would cost the hardware.

## Critical mode

Every 5 seconds the fan controller reads the SoC temperature. When it reaches `critical_temperature_threshold`, the
agent enters critical mode:

- the fan runs at 100%, whatever the curve or an override say
- stealth mode turns off, so the LEDs can be seen
- the top LED blinks in `critical_led_color`
- a `critical` event goes out

It leaves critical mode when the temperature drops below the threshold minus 5°C. Without that gap, a blade hovering
around the threshold would switch in and out every few seconds: fan at full speed, temperature drops a degree, fan
slows down, temperature rises a degree. The 5°C of hysteresis turn that into one clean episode.

While critical mode is active, the agent refuses to set a fan speed override or stealth mode through the API. It
doesn't forget an override that was set before: when critical mode ends, the fan goes back to it.

A client can also enter critical mode with `EmitEvent(CRITICAL)`, for example to test the alerting. Such a manual
critical mode stays until someone sends `CRITICAL_RESET`, unless the temperature crosses the threshold in the meantime.
Then the temperature takes over and clears it once the blade cooled down.

The Raspberry Pi firmware has its own protection and throttles the CPU from 80°C on. The agent's threshold sits
below that, to cool the blade before the firmware has to slow it down.

## Health conditions

| Condition      | Raised when | Cleared when |
|----------------|-------------|--------------|
| `fan_stall`    | the fan is commanded to at least `min_percent` but stays below `min_rpm` for `grace_period` | the fan reaches `min_rpm` |
| `undervoltage` | the firmware reports under-voltage | the flag stayed off for `clear_after` |
| `throttled`    | the firmware reports a capped frequency, throttling or the soft temperature limit | the flags stayed off for `clear_after` |

A raised condition:

- emits a raise event (`fan_stall`) and later a clear event (`fan_stall_clear`), once each
- shows on an LED, if an indicator is configured
- appears in `bladectl get status` and `GetStatus().conditions`
- sets `computeblade_state_state{state="fan_stall"}` to 1

The agent doesn't act on conditions beyond that. What a stalled fan means depends on the setup: a blade in a
well-ventilated rack may run fine without its fan, another one needs draining right away. The events let you decide,
see [React to events](../how-to/react-to-events.md). The one exception is the power policy, which you can configure
to limit the CPU during under-voltage.

### Why the fan stall rules look like this

A fan that doesn't turn reads 0 RPM. So does a fan that was told to stop: many fans stop below 20 to 30% duty
cycle. The detector therefore only judges the fan when it's commanded to at least `min_percent`. Below that, it can't
tell a stalled fan from a resting one and keeps its current state.

A fan also needs a moment to spin up, and the smart fan unit reports the RPM every 2 seconds. `grace_period` (15s)
covers both, so a fan spinning up from standstill isn't reported.

A stall clears as soon as the fan is seen turning again, whatever its commanded speed. Seeing it turn is proof
enough.

Two blades share a smart fan unit and its fan. The fan runs at the higher of the two requested speeds, and both blades
see the same RPM. If one blade asks for 40% and its neighbour for 100%, the fan spins fast and neither reports a
stall. If the fan dies, both do.

### Why under-voltage and throttling wait before clearing

The firmware flags flicker. A blade on the edge of its PoE budget can dip under the voltage limit for a moment, every
few seconds, under load. Raising the condition on the first dip is right: something is wrong. Clearing it on the first
good reading would make the LED, the events and any automation flap along with the voltage. The condition clears only
after the flag stayed off for `clear_after` (30s).

## How it ends up on the LEDs

Conditions, identify and critical mode share two LEDs through priority stacks, see [LEDs](../reference/leds.md).
Identify on the edge LED and critical mode on the top LED always win. A health indicator shows again once they're
gone. Among indicators, the configured priority decides.
