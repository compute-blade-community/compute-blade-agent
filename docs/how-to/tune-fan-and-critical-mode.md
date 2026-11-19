# Tune the fan curve and critical mode

## Change the fan curve

The fan speed follows the SoC temperature along `fan_controller.steps`. Between two steps the agent interpolates, below
the first step it uses the first speed, above the last step the last speed.

For a quieter blade that still ramps up under load:

```yaml
fan_controller:
  steps:
    - temperature: 50
      percent: 25
    - temperature: 60
      percent: 60
    - temperature: 70
      percent: 100
```

Restart the agent and check the curve it loaded:

```bash
sudo systemctl restart compute-blade-agent
bladectl describe fan
```

Temperatures must increase from step to step and speeds must not decrease. Otherwise the agent logs the problem and
doesn't start.

Many fans stop below 20 to 30% duty cycle. Fan stall detection only judges the fan at or above
`health.fan_stall.min_percent` (20%). If your fan stops at 25%, raise `min_percent` above that, or the agent reports a
stall whenever the curve goes there.

On a smart fan unit, two blades share one fan, and it runs at the higher speed of the two. Tune both blades together.

## Run the fan at a fixed speed for a while

```bash
bladectl set fan --percent 70    # fixed speed
bladectl set fan --auto          # back to the curve
```

The override lasts until you remove it or the agent restarts. Critical mode runs the fan at 100% regardless and
returns to your override when it ends. While critical mode is active the agent refuses new overrides.

## Change the critical temperature

The agent enters critical mode when the SoC reaches `critical_temperature_threshold` (default 60°C): fan at 100%,
stealth mode off, top LED blinking red. It leaves critical mode once the SoC is 5°C below the threshold.

```yaml
critical_temperature_threshold: 70
```

The Raspberry Pi firmware starts throttling the CPU at 80°C, so a threshold between 60 and 75 gives the blade a chance
to cool before the CPU slows down. Set it to `0` to disable automatic critical mode. You can still
trigger it through the API with `EmitEvent`.

Raising the threshold makes sense if your blades run hot under normal load and critical mode fires every day. Check
how often it does:

```promql
increase(computeblade_agent_events_count{type="critical"}[1d])
```

## Test critical mode

Put a load on all cores and watch the events. Run the load with a time limit so it stops even if you lose the
session:

```bash
for i in 1 2 3 4; do timeout 300 sh -c 'while :; do :; done' & done
bladectl events --event critical --event critical_reset
```

To try it without heating the blade, lower the threshold below the current temperature (`bladectl get temp`) for the
test and restart the agent.
