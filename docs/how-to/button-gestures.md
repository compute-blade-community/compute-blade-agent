# Bind actions to button gestures

The edge button at the front of the blade knows four gestures. You bind each one to a built-in action or a command in
`/etc/compute-blade-agent/config.yaml`, under `button`.

| Gesture       | How                                          | Default |
|---------------|----------------------------------------------|---------|
| `single`      | one short press                              | `identify-toggle` |
| `double`      | two short presses                            | nothing |
| `multi_press` | `count` short presses in a row (default 5)   | nothing |
| `long_press`  | hold for `hold` (default 5s)                 | nothing |

Short presses belong to the same series as long as the next press follows within `gesture_window` (400ms).

## Bind a built-in action

```yaml
button:
  long_press:
    hold: 5s
    action: shutdown
  multi_press:
    count: 5
    action: emergency-poweroff
```

| Action               | Effect |
|----------------------|--------|
| `identify-toggle`    | Start identify, or stop it if it's on. |
| `shutdown`           | `systemctl poweroff`, or `shutdown -h now` without systemd. |
| `reboot`             | `systemctl reboot`, or `shutdown -r now`. |
| `emergency-poweroff` | Power off right away. See the warning below. |
| `none`               | Nothing. Use it to unbind `single`. |

`emergency-poweroff` doesn't stop services or unmount file systems. It flushes data to disk for up to 2 seconds, then
powers off. Use it for a blade whose regular shutdown hangs, and expect file system checks on the next boot. It doesn't
cut PoE power: the blade stays off until its port is power cycled.

## Run a command

`exec` takes the command and its arguments as a list. The agent runs it as root, directly, without a shell:

```yaml
button:
  double:
    exec: ["/usr/local/bin/drain-node.sh", "--force"]
    timeout: 2m
```

Need shell features such as pipes or variables? Run a shell yourself:

```yaml
button:
  double:
    exec: ["/bin/sh", "-c", "logger -t blade \"$BLADE_GESTURE pressed on $BLADE_HOSTNAME\""]
```

The command gets `BLADE_EVENT`, `BLADE_GESTURE`, `BLADE_PRESS_COUNT`, `BLADE_HOLD_MS` and `BLADE_HOSTNAME` in its
environment (see [Events](../reference/events.md#environment-of-exec-actions)). Its output ends up in the agent's
journal. It's killed after `timeout` (default 30s). Pressing the gesture again while the command still runs does
nothing.

## Apply and test

```bash
sudo systemctl restart compute-blade-agent
sudo bladectl events --event button_gesture
```

Press the button. Each gesture prints a line, with the action that ran:

```text
2026-11-19T12:01:12+01:00  blade-pi2         button_gesture  gesture=double presses=2 action=exec
```

While you hold the button towards a bound long press, the edge LED blinks white after 1 second. Let go before `hold`
to cancel.

If the agent doesn't start after your change, check the journal (`journalctl -u compute-blade-agent`). It refuses
invalid bindings, for example an action and an `exec` on the same gesture, `multi_press.count` below 3 or a
`long_press.hold` of 1 second or less.

## Leave a gesture to other tools

Every gesture is published as a `button_gesture` event, bound or not. A program watching the event stream can react to
a gesture the agent leaves unbound, for example to cordon a Kubernetes node. See
[React to events](react-to-events.md).
