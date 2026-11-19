# compute-blade-agent

> :warning: **Beta Release**: This software is currently in beta, and both configurations and APIs may undergo breaking changes. It is not yet 100% feature complete, but it functions as intended.

The compute-blade-agent runs on every [Compute Blade](https://computeblade.com) and takes care of the hardware:

- drives the fan along a temperature curve and enters **critical mode** (fan at 100%, red LED) when the SoC overheats
- detects **stalled fans**, **under-voltage** and **CPU throttling**, and shows them on the LEDs
- turns the edge button into **gestures** (single, double, multi-press, long press) that run built-in actions or your
  own commands
- optionally **limits the CPU** when the blade runs on 802.3af PoE or gets too little power
- publishes everything as an **event stream**, serves a **gRPC API** with mutual TLS and exports **Prometheus
  metrics**
- announces itself via **mDNS**, so `bladectl discover` finds your blades

`bladectl` is the command line client. `fanunit.uf2` is the firmware for the smart fan unit.

## Quick start

On the blade:

```bash
curl -L -o /tmp/compute-blade-agent-installer.sh https://raw.githubusercontent.com/compute-blade-community/compute-blade-agent/main/hack/autoinstall.sh
chmod +x /tmp/compute-blade-agent-installer.sh
/tmp/compute-blade-agent-installer.sh

sudo bladectl get status
sudo bladectl set identify --wait   # the edge LED blinks until you press the edge button
```

## Documentation

The [documentation](docs/README.md) has tutorials, how-to guides, reference and background:

- [Set up your first blade](docs/tutorials/first-blade.md)
- [Manage a rack from your workstation](docs/tutorials/manage-a-rack.md)
- [Configuration file reference](docs/reference/configuration.md)
- [bladectl reference](docs/reference/bladectl.md)
- [Bind actions to button gestures](docs/how-to/button-gestures.md)
- [Monitor blades with Prometheus](docs/how-to/prometheus-monitoring.md)
- [Troubleshooting](docs/how-to/troubleshooting.md)

## Contributing

The toolchain and all build tasks are pinned in `mise.toml`. `mise install` sets you up and `mise run ci` runs every
check the CI pipeline runs. Start with [Make your first change to the agent](docs/tutorials/first-change.md) and
[CONTRIBUTING.md](CONTRIBUTING.md).
