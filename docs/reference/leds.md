# LEDs

A blade has two RGB LEDs: the **edge LED** at the front, next to the edge button, and the **top LED** on the board.
The agent decides what each LED shows by priority. The highest-priority active layer wins, and when it ends the next
one shows again.

## What the LEDs show

Edge LED, highest priority first:

| Priority | Layer               | Pattern     | Default color    | Active while |
|----------|---------------------|-------------|------------------|--------------|
| 1500     | Long press feedback | fast blink  | white (32,32,32) | the button is held towards a bound long press, from 1s on |
| 1000     | Identify            | burst       | `identify_led_color`, purple (16,0,16) | identify is on |
| 0-999    | Health indicators   | configured  | configured       | a condition with `led: edge` is raised |
| base     | Idle                | static      | `idle_led_color`, green (0,16,0) | always |

Top LED, highest priority first:

| Priority | Layer             | Pattern    | Default color    | Active while |
|----------|-------------------|------------|------------------|--------------|
| 2000     | Critical mode     | slow blink | `critical_led_color`, red (64,0,0) | critical mode is on |
| 0-999    | Health indicators | configured | configured       | a condition with `led: top` is raised |
| base     | Off               | static     | off              | always |

By default `fan_stall` blinks orange (fast blink, priority 30) and `undervoltage` bursts amber (priority 20) on the top
LED, `throttled` isn't shown. See [Configure health indicators](../how-to/health-indicators.md).

Stealth mode switches both LEDs off, whatever they would show. Critical mode switches stealth mode off. When it ends, stealth mode
goes back to the configured `stealth_mode`, even if it was changed with `bladectl` before.

## Patterns

| Name         | Sequence |
|--------------|----------|
| `static`     | Solid color. |
| `slow-blink` | 1s on, 1s off. |
| `fast-blink` | 250ms on, 250ms off. |
| `burst`      | Three 100ms flashes, then 500ms off. |

Blinking patterns alternate between the color and off.

## Colors

Colors are `red`, `green`, `blue`, each 0 to 255. The LEDs are bright, the defaults stay at or below 64.
