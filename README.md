# compute-blade-agent

> :warning: **Beta Release**: This software is currently in beta, and both configurations and APIs may undergo breaking changes. It is not yet 100% feature complete, but it functions as intended.

The `compute-blade-agent` serves as an operating system agent interfacing with [ComputeBlade](http://computeblade.com) hardware. It takes charge of fan speed, LEDs, and manages common events, such as identifying or locating an individual blade in a server rack. Additionally, it exposes hardware- and agent-related metrics on a [Prometheus](http://prometheus.io) endpoint.

**Quick Setup with TL;DR**:
```bash
curl -L -o /tmp/compute-blade-agent-installer.sh https://raw.githubusercontent.com/github.com/uptime-industries/compute-blade-agent/main/hack/autoinstall.sh
chmod +x /tmp/compute-blade-agent-installer.sh
/tmp/compute-blade-agent-installer.sh
```

## Components

### compute-blade-agent
This event-loop handler responds to system events, such as button presses and temperature changes. It offers a Prometheus endpoint for monitoring core metrics, including Power over Ethernet (PoE) status.

In normal operation mode, the agent maintains static LEDs and fan speed based on the configuration. If the System on Chip (SoC) temperature exceeds a predefined level, the critical mode is activated, setting the fan speed to 100% and changing the LED color to red. The _identify_ action, independent of the mode, makes the edge LED blink. This can be toggled using `bladectl` on the blade (`bladectl identify`) or by pressing the edge button (or smart fan unit button).

### Smart Fan Unit Firmware
This firmware controls fan speed and LEDs on the fan unit using a UART-based protocol with agents running on the blades. It reports metrics (fan RPM and airflow temperature) regularly to the blades and forwards button presses (1x -> left blade, 2x -> right blade). The fan unit determines the highest requested fan speed, configuring the fan control chip on the board. Advanced functionalities, such as airflow-based fan curve control, are possible with the EMC2101 chip on the smart fan unit, currently implemented in software on the agent side.

### bladectl - interacting with the agent
`bladectl` interacts with the blade-local API exposed by the compute-blade-agent. For instance, you can identify the blade in a rack using `bladectl identify --wait`, which blocks and makes the edge LED blink until the button is pressed.

## Installation Options

The agent and `bladectl` are available as packages for Debian, RPM, and ArchLinux or as an OCI image to run within Docker/Kubernetes. Packages include a systemd unit, which can be enabled using `systemd enable compute-blade-agent.service --now`.

For global access, `bladectl` requires root privileges since the socket (default `/tmp/compute-blade-agent.sock`) does not have user/group access due to privileged access to critical resources.

<!-- WIP
**Kubernetes Deployment**:
A Kustomize environment can be found in `hack/deploy`. Use `kubectl -k hack/deploy` or employ a GitOps tool like FluxCD.
-->

## Configuration
Configuration can be driven by a config file or environment variables. Linux packages ship with the default configuration in `/etc/compute-blade-agent/config.yaml`. Alternatively, especially for Kubernetes, all parameters in the YAML configuration can be overwritten using environment variables prefixed with `BLADE_`.

For example, changing the metric address defined in YAML:
```yaml
# Listen configuration
listen:
  metrics: ":9666"
```
can be achieved with the environment variable `BLADE_LISTEN_METRICS=":1234"`.

Some useful parameters:
- `BLADE_STEALTH_MODE=false`: Enables/disables stealth mode.
- `BLADE_FAN_SPEED_PERCENT=80`: Sets static fan speed (by default, there's a linear fan curve of 40-80%).
- `BLADE_CRITICAL_TEMPERATURE_THRESHOLD=60`: Configures the critical temperature threshold of the agent.
- `BLADE_HAL_RPM_REPORTING_STANDARD_FAN_UNIT=false`: Enables/disables fan speed measurement (disabling it reduces CPU load of the agent).
