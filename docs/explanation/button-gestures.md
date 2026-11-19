# Button gestures

The edge button is the only input a blade has. It used to do one thing: toggle identify. Gestures let it do more
without making the common case harder.

## From transitions to gestures

The HAL reports raw transitions: pressed, released, with a timestamp. Mechanical buttons bounce, so each edge
starts a 20ms timer and the HAL reports the button's level once it settled. The kernel's own 10ms debounce on the
GPIO line filters the worst of it before that.

The recognizer (`pkg/button`) turns transitions into gestures:

- A press shorter than `long_press.hold` is a short press. Short presses that follow each other within
  `gesture_window` (400ms) form a series. The series ends when the window passes without another press, and its
  length decides the gesture: 1 is `single`, 2 is `double`, `multi_press.count` is `multi_press`.
- Holding the button for `long_press.hold` is a `long_press`. It fires while the button is still held, so the blade
  reacts without waiting for the release. Releasing it afterwards doesn't count as a press.

The recognizer has no timers of its own. The button handler feeds it transitions and calls `Tick` at the deadline it
asks for. This makes it a plain state machine: tests feed it timestamps and check the output, no sleeps involved.

## Why a single press waits

A single press can't fire on release: a second press might follow, making it a double press. So the agent waits for
`gesture_window` before it toggles identify. 400ms is short enough to feel immediate and long enough for a
comfortable double press. Shorten it if nobody on your team uses double presses.

`multi_press` doesn't wait. It fires as soon as the count is reached, because more presses would only be ignored.
That matters for `emergency-poweroff`: the blade reacts on the fifth press, not 400ms later.

## Feedback while holding

Holding a button for five seconds without any sign of progress feels broken, and people let go. When a long press is
bound to an action, the edge LED starts blinking white after one second. The blinking tells the person holding the
button that something will happen if they keep holding. Letting go before `hold` cancels it.

## Actions

A gesture runs either a built-in action or a command. The built-ins cover what a person at the rack needs: identify,
a clean shutdown or reboot, and the emergency power-off. Everything else is a command.

Commands run without a shell. A config like `exec: ["/usr/local/bin/drain.sh", "--force"]` can't be misread, and
there's no quoting to get wrong. If you need a pipe, start `/bin/sh -c` yourself and the shell is visible in the
config.

Each gesture runs one action at a time. If the button is pressed again while the last command of the same gesture
still runs, the new trigger is dropped and logged. Without this, an impatient person pressing five times would start
five drain scripts.

## The emergency power-off

`emergency-poweroff` exists for one situation: the blade hangs on shutdown, for example on an unresponsive NFS mount,
and nobody wants to walk to the switch to cut PoE. The action flushes file system buffers for up to 2 seconds and
then calls the kernel's power-off directly, skipping services and unmounting. It's the same as pulling power after a
`sync`, with the same risk to file systems. That's why it isn't bound by default and why five presses are needed.

It powers the SoC off but doesn't cut the PoE power. The blade stays off until its switch port is power cycled.

## The fan unit button

The smart fan unit has a button too, shared by two blades. Its firmware counts presses to pick the blade: one press
for the left blade, two for the right one. Since the count is already taken, the fan unit button can't do gestures.
It toggles identify on the selected blade.

## Gestures as events

Every gesture is published as a `button_gesture` event, bound or not. A gesture the agent leaves unbound can be
handled by a program watching the event stream, on another machine, with credentials the blade doesn't have, like a
Kubernetes controller that cordons the node.
