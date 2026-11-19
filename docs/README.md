# compute-blade-agent documentation

The compute-blade-agent runs on every [Compute Blade](https://computeblade.com). It drives the fan and the LEDs,
watches the blade's health, reacts to the buttons and exposes all of it through a gRPC API, Prometheus metrics and an
event stream. `bladectl` is the command line client for that API.

The docs follow the [Diátaxis](https://diataxis.fr) framework. Pick the section that matches what you're doing right
now:

| You want to...                         | Go to                         |
|----------------------------------------|-------------------------------|
| learn the agent by using it            | [Tutorials](#tutorials)       |
| get a specific job done                | [How-to guides](#how-to-guides) |
| look up a key, flag, metric or message | [Reference](#reference)       |
| understand how and why it works        | [Explanation](#explanation)   |

Operators and developers share these docs. Pages written mainly for people working on the code say so in their first
line.

## Tutorials

Start here if you're new. Each tutorial is a complete lesson with a working result at the end.

1. [Set up your first blade](tutorials/first-blade.md): install the agent, look at its status, blink a blade and
   watch its events.
2. [Manage a rack from your workstation](tutorials/manage-a-rack.md): expose the API over mTLS, find your blades
   with `bladectl discover` and control all of them at once.
3. [Make your first change to the agent](tutorials/first-change.md) (developers): build the agent, change its
   behaviour and run your build on a real blade.

## How-to guides

Recipes for operators:

- [Install, upgrade and remove the agent](how-to/install-upgrade-remove.md)
- [Bind actions to button gestures](how-to/button-gestures.md)
- [Tune the fan curve and critical mode](how-to/tune-fan-and-critical-mode.md)
- [Configure health indicators](how-to/health-indicators.md)
- [Limit the CPU when power is short](how-to/power-policy.md)
- [Monitor blades with Prometheus](how-to/prometheus-monitoring.md)
- [React to events from scripts and programs](how-to/react-to-events.md)
- [Rotate the API certificates](how-to/rotate-certificates.md)
- [Update the smart fan unit firmware](how-to/update-fan-unit-firmware.md)
- [Troubleshoot common problems](how-to/troubleshooting.md)

Recipes for developers:

- [Build, test and lint](how-to/build-and-test.md)
- [Run a development build on a blade](how-to/test-on-a-blade.md)
- [Change the gRPC API](how-to/change-the-api.md)
- [Add an event or a health condition](how-to/add-an-event-or-condition.md)

## Reference

- [Configuration file](reference/configuration.md)
- [bladectl](reference/bladectl.md)
- [Events](reference/events.md)
- [gRPC API](reference/grpc-api.md)
- [Prometheus metrics](reference/metrics.md)
- [LEDs](reference/leds.md)
- [Files, ports and network services](reference/files-and-ports.md)
- [Supported hardware](reference/hardware.md)
- [Smart fan unit protocol](reference/fan-unit-protocol.md)

## Explanation

- [Architecture](explanation/architecture.md)
- [Health conditions and critical mode](explanation/health-and-critical-mode.md)
- [Button gestures](explanation/button-gestures.md)
- [Power, throttling and the power policy](explanation/power-and-throttling.md)
- [Discovery](explanation/discovery.md)
- [Security model](explanation/security.md)

Releases and the contribution workflow are described in [CONTRIBUTING.md](../CONTRIBUTING.md).
