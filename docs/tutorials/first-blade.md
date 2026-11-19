# Set up your first blade

In this tutorial you install the agent on a Compute Blade, look at what it reports, make the blade blink and watch
it react to the button. It takes about 15 minutes.

You need:

- a Compute Blade with a Raspberry Pi CM4 or CM5, running a 64-bit Raspberry Pi OS, Debian or Ubuntu
- SSH access to the blade with `sudo`
- physical access to the blade, to see the LEDs and press the edge button

## 1. Install the agent

Log in to the blade and run the install script:

```bash
curl -L -o /tmp/compute-blade-agent-installer.sh \
  https://raw.githubusercontent.com/compute-blade-community/compute-blade-agent/main/hack/autoinstall.sh
chmod +x /tmp/compute-blade-agent-installer.sh
/tmp/compute-blade-agent-installer.sh
```

It downloads the latest release, installs the package and starts the `compute-blade-agent` service. The package also
installs `bladectl`.

Check that the service runs:

```bash
systemctl status compute-blade-agent
```

You should see `active (running)`. The edge LED at the front of the blade now glows dim green: the agent's idle color.

## 2. Ask the agent how the blade is doing

```bash
sudo bladectl get status
```

You need `sudo` because the agent only listens on a socket that belongs to root for now. The answer looks like this:

```text
┌───────────┬─────────────┬────────────────────┬────────────────┬──────────────┬──────────┬───────────────┬──────────────┬────────┐
│ BLADE     │ TEMPERATURE │ FAN SPEED OVERRIDE │ FAN SPEED      │ STEALTH MODE │ IDENTIFY │ CRITICAL MODE │ POWER STATUS │ HEALTH │
├───────────┼─────────────┼────────────────────┼────────────────┼──────────────┼──────────┼───────────────┼──────────────┼────────┤
│ blade-pi1 │ 47°C        │ Not set            │ 4386 RPM (48%) │ Off          │ Off      │ Off           │ poe+         │ OK     │
└───────────┴─────────────┴────────────────────┴────────────────┴──────────────┴──────────┴───────────────┴──────────────┴────────┘
```

The fan speed follows the SoC temperature along a fan curve. `poe+` means the blade gets 802.3at PoE+, enough
power for full load. `HEALTH` lists problems the agent detected, such as a stalled fan.

See the curve the fan follows:

```bash
sudo bladectl describe fan
```

## 3. Find the blade in the rack

In a rack full of identical blades, finding the right one is the hard part. Let the agent help:

```bash
sudo bladectl set identify --wait
```

The edge LED starts flashing purple and the command waits. Walk to the rack, find the flashing blade and press its
edge button once. The LED goes back to green and the command returns.

The button press confirmed the identify request. You can also stop it remotely with `sudo bladectl remove identify`.

## 4. Watch the blade's events

Everything the agent notices is an event. Open a second SSH session and stream them:

```bash
sudo bladectl events
```

Press the edge button once and wait half a second. Three lines appear:

```text
2026-11-19T12:10:03+01:00  blade-pi1         button_press  source=edge
2026-11-19T12:10:03+01:00  blade-pi1         button_gesture  gesture=single presses=1 action=identify-toggle
2026-11-19T12:10:03+01:00  blade-pi1         identify
```

The agent saw a press, recognised it as a single press, and ran the action bound to it: toggle identify. The LED is
flashing again. Press once more to stop it, and an `identify_confirm` event appears.

The half second is the agent waiting whether a second press follows. Press twice quickly and you get a `double`
gesture instead, which does nothing yet. Leave the stream open for the next step.

## 5. Change the configuration

The agent reads `/etc/compute-blade-agent/config.yaml`. Make the idle LED blue instead of green:

```bash
sudo nano /etc/compute-blade-agent/config.yaml
```

Find `idle_led_color` and change it:

```yaml
idle_led_color:
  red: 0
  green: 0
  blue: 16
```

Save, then restart the agent:

```bash
sudo systemctl restart compute-blade-agent
```

The edge LED turns blue. In the other session, `bladectl events` reports that the stream was interrupted and
reconnects by itself.

## 6. Look at the metrics

The agent exports Prometheus metrics on port 9666:

```bash
curl -s localhost:9666/metrics | grep -E '^computeblade_(soc_temperature|fan_speed|state_state)'
```

```text
computeblade_fan_speed 4386.6
computeblade_soc_temperature 47.2
computeblade_state_state{state="critical"} 0
computeblade_state_state{state="fan_stall"} 0
computeblade_state_state{state="identify"} 0
computeblade_state_state{state="normal"} 1
...
```

## What you did

You installed the agent, read the blade's state, used identify to find it, saw how a button press turns into a
gesture and an action, and changed the configuration.

Next:

- Control many blades from your own machine: [Manage a rack from your workstation](manage-a-rack.md).
- Bind your own actions to the button: [Bind actions to button gestures](../how-to/button-gestures.md).
- Learn what the agent watches: [Health conditions and critical mode](../explanation/health-and-critical-mode.md).
