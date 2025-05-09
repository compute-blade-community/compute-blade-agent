# compute-blade-agent

> :warning: **Beta Release**: This software is currently in beta, and both configurations and APIs may undergo breaking changes. It is not yet 100% feature complete, but it functions as intended.

## Quick Start

Install the agent with the one-liner below:

```bash
curl -L -o /tmp/compute-blade-agent-installer.sh https://raw.githubusercontent.com/uptime-industries/compute-blade-agent/main/hack/autoinstall.sh
chmod +x /tmp/compute-blade-agent-installer.sh
/tmp/compute-blade-agent-installer.sh
```

## Components

### `compute-blade-agent`: Hardware Interaction & Monitoring

The agent runs as a system service and monitors various hardware states and events:

- Reacts to button presses and SoC temperature.
- Automatically enters **critical mode** (fan 100%, red LED) when overheating.
- Exposes system metrics via a Prometheus endpoint (`/metrics`).

The _identify_ function can be triggered via `bladectl` or a physical button press. It makes the edge LED blink to assist locating a blade in a rack.

### `bladectl`: User Command-Line Tool

`bladectl` is a CLI utility for remote or local interaction with the running agent. Example use cases:

```bash
bladectl set identify --wait    # Blink LED until button is pressed
bladectl set identify --confirm # Cancel identification
bladectl unset identify         # Cancel identification (alternative)
```

### `fanunit.uf2`: Smart Fan Unit Firmware

This firmware runs on the fan unit microcontroller and:

- Controls fan speed via UART commands from blade agents.
- Reports RPM and airflow temperature back to the blade.
- Forwards button events (1x = left blade, 2x = right blade).
- Uses EMC2101 for optional advanced features like airflow-based fan control.

To install it, [download the `fanunit.uf2`](https://github.com/uptime-industries/compute-blade-agent/releases/latest), and follow the firmware upgrade instructions [here](https://docs.computeblade.com/fan-unit/uart#update-firmware).

## Installation

Install the agent with the one-liner below:

```bash
curl -L -o /tmp/compute-blade-agent-installer.sh https://raw.githubusercontent.com/uptime-industries/compute-blade-agent/main/hack/autoinstall.sh
chmod +x /tmp/compute-blade-agent-installer.sh
/tmp/compute-blade-agent-installer.sh
```

> Note: `bladectl` requires root privileges when used locally, due to restricted access to the Unix socket (`/tmp/compute-blade-agent.sock`).

## Configuration

The default configuration file is located at:

```bash
/etc/compute-blade-agent/config.yaml
```

You can also override any config option via environment variables using the `BLADE_` prefix.

### Examples

#### YAML:
```yaml
listen:
  metrics: ":9666"
```

#### Environment variable override:

```bash
BLADE_LISTEN_METRICS=":1234"
```

### Common Overrides

| Variable                                          | Description                              |
|---------------------------------------------------|------------------------------------------|
| `BLADE_STEALTH_MODE=false`                        | Enable/disable stealth mode              |
| `BLADE_FAN_SPEED_PERCENT=80`                      | Set static fan speed                     |
| `BLADE_CRITICAL_TEMPERATURE_THRESHOLD=60`         | Set critical temp threshold (°C)         |
| `BLADE_HAL_RPM_REPORTING_STANDARD_FAN_UNIT=false` | Disable RPM monitoring for lower CPU use |
| `OTEL_EXPORTER_OTLP_ENDPOINT`                     | Endpoint for the OTLP exporter           |

## Exposing the gRPC API for Remote Access

To allow secure remote use of `bladectl` over the network:

### 1. Update your config (`/etc/compute-blade-agent/config.yaml`):

```yaml
listen:
  metrics: ":9666"
  grpc: ":8081"
  authenticated: true
  mode: tcp
```

### 2. Restart the agent:

```bash
systemctl restart compute-blade-agent
```

This will:

- Generate new mTLS server and client certificates in `/etc/compute-blade-agent/*.pem`
- Write a new bladectl config to: `~/.config/bladectl/config.yaml` with the client certificates in place

## Using `bladectl` from your local machine

1. Copy the config from the blade:

```bash
scp root@blade-pi1:~/.config/bladectl/config.yaml ~/.config/bladectl/config.yaml
```

2. Fix the server address to point to the blade:

```bash
yq e '.blades[] | select(.name == "blade-pi1") .blade.server = "blade-pi1.local:8081"' -i ~/.config/bladectl/config.yaml
```

Your `bladectl` tool can now securely talk to the remote agent via gRPC over mTLS.
