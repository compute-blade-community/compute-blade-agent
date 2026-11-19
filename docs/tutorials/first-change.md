# Make your first change to the agent

*For developers.* In this tutorial you set up the development tools, find your way around the code, change how the
blade looks while someone holds the edge button, and run your build on a real blade. It takes about 30 minutes.

You need:

- [mise](https://mise.jdx.dev) and git on your machine (Linux or macOS)
- a blade with the agent installed that you can reach over SSH, and someone (you) at the rack to press its button

## 1. Get the code and the tools

```bash
git clone https://github.com/compute-blade-community/compute-blade-agent.git
cd compute-blade-agent
mise install
```

mise installs the exact versions of Go, TinyGo, golangci-lint and the other tools the project uses. Check that
everything works before you change anything:

```bash
mise run ci
```

It regenerates the API code, checks formatting, lints, runs the tests and builds the fan unit firmware. Every task
should end without `ERROR`. The CI pipeline runs the same tasks, so if this passes on your machine, it passes there
too.

## 2. Find your way around

The parts you'll meet first:

| Directory             | What's there |
|-----------------------|--------------|
| `cmd/agent`           | `main`: reads the config, creates the agent, handles signals |
| `internal/agent`      | the agent itself: event loop, gRPC API, LEDs, buttons, health, power policy |
| `pkg/hal`             | hardware access per compute module |
| `pkg/ledengine`       | LED patterns and the priority stack deciding what an LED shows |
| `pkg/button`          | turns presses and releases into gestures |
| `cmd/bladectl`        | the CLI |

[Architecture](../explanation/architecture.md) explains how they fit together. For now, you only need one file.

## 3. Change the hold feedback

When someone holds the edge button towards a long press, the edge LED blinks white after a second, so they know
something is about to happen. Make it blink orange, like a warning.

Open `internal/agent/buttons.go` and find where the feedback layer is defined:

```go
if a.buttons.holdFeedback {
    if err := a.edgeLeds.Define(ledLayerButtonHold, ledPriorityButtonHold,
        ledengine.NewFastBlinkPattern(led.Color{}, led.Color{Red: 32, Green: 32, Blue: 32})); err != nil {
```

`edgeLeds` is the priority stack of the edge LED. `Define` registers a layer with a priority and a pattern. While the
layer is active and nothing with a higher priority is, the LED shows its pattern. Change the color:

```go
        ledengine.NewFastBlinkPattern(led.Color{}, led.Color{Red: 64, Green: 24, Blue: 0})); err != nil {
```

Run the tests of the package and the linter:

```bash
go test ./internal/agent/
mise run lint
```

The button tests drive fake presses through the gesture recognizer and check that the feedback layer shows up. They
pass, because they check the layer, not its color.

## 4. Build for the blade

The blade is a 64-bit ARM Linux machine. Go cross-compiles without extra tools:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
  -ldflags "-X=main.Version=0.0.0-dev.$(git rev-parse --short HEAD)" \
  -o /tmp/compute-blade-agent ./cmd/agent
```

## 5. Run it on the blade

Follow [Run a development build on a blade](../how-to/test-on-a-blade.md) to install the binary next to the packaged
agent. The hold feedback only shows when a long press is bound to an action, so bind a harmless one in
`/etc/compute-blade-agent/config.yaml` on the blade:

```yaml
button:
  long_press:
    hold: 5s
    exec: ["/usr/bin/logger", "-t", "my-first-change", "long press"]
```

Restart the agent and check that your build runs:

```bash
sudo systemctl restart compute-blade-agent
journalctl -u compute-blade-agent -n 5 | grep 0.0.0-dev
```

Now hold the edge button. After one second the edge LED blinks orange. Keep holding for five seconds in total, then
let go. The journal shows your command ran:

```bash
journalctl -t my-first-change
```

## 6. Clean up

Switch the blade back to the packaged agent as described at the end of the how-to, and remove the `long_press` binding
if you don't want it.

## What you did

You set up the toolchain, ran the same checks as CI, changed the agent, cross-compiled it and verified it on
hardware. That's the whole development loop.

When you have a change worth sharing, commit it with a [Conventional Commits](https://www.conventionalcommits.org)
message, run `mise run ci` once more and open a pull request. [CONTRIBUTING.md](../../CONTRIBUTING.md) has the
details.

Next:

- [Architecture](../explanation/architecture.md), to know where things happen
- [Add an event or a health condition](../how-to/add-an-event-or-condition.md)
- [Change the gRPC API](../how-to/change-the-api.md)
