# Files, ports and network services

## Files

| Path                                                     | Owner     | Description |
|----------------------------------------------------------|-----------|-------------|
| `/usr/bin/compute-blade-agent`                           | package   | The agent. |
| `/usr/bin/bladectl`                                      | package   | The CLI. |
| `/etc/systemd/system/compute-blade-agent.service`        | package   | systemd unit. Runs the agent as root, restarts it on failure. |
| `/etc/compute-blade-agent/config.yaml`                   | package, you | Configuration. Marked as a config file: upgrades keep your changes. |
| `/etc/compute-blade-agent/ca.pem`, `ca-key.pem`          | agent     | CA for the API's mTLS certificates. Valid for 10 years. |
| `/etc/compute-blade-agent/server.pem`, `server-key.pem`  | agent     | Server certificate. Valid for 1 year. |
| `/root/.config/bladectl/config.yaml`                     | agent     | `bladectl` config with a client certificate for this blade (valid for 1 year). Written once, if missing. |
| `/tmp/compute-blade-agent.sock`                          | agent     | API socket in `unix` listen mode. |
| `/run/compute-blade-agent/cpufreq-original.json`         | agent     | Original CPU settings while the power policy limits the CPU. Lets the next start undo the limit after a crash. |
| `/usr/share/compute-blade-agent/fanunit.uf2`             | package   | Smart fan unit firmware matching this release. |
| `~/.config/bladectl/config.yaml`                         | you       | `bladectl` config on your workstation. |

The agent generates missing certificates when it starts in `tcp` mode with `authenticated: true`. It doesn't renew
them. See [Rotate the API certificates](../how-to/rotate-certificates.md).

## Hardware interfaces

| Interface                                | Used for |
|------------------------------------------|----------|
| `/sys/firmware/devicetree/base/compatible` | Detecting the platform. |
| `gpiochip0`                              | Edge button, PoE detection, stealth mode, standard fan unit tachometer. |
| `/dev/mem`                               | PWM for the fan and the WS281x LEDs. |
| `/dev/ttyAMA5` (CM4), `/dev/ttyAMA4` (CM5) | Smart fan unit UART, 115200 baud. |
| `/sys/class/thermal/thermal_zone0/temp`  | SoC temperature. |
| `/dev/vcio`                              | Raspberry Pi firmware throttle flags. |
| `/sys/devices/system/cpu/cpufreq/policy*` | CPU limits of the power policy. |

## Ports

| Port | Protocol | Setting          | Description |
|------|----------|------------------|-------------|
| 9666 | HTTP     | `listen.metrics` | `/metrics` (Prometheus) and `/debug/pprof/` (Go profiler). No authentication: don't expose it to untrusted networks. |
| 8081 | gRPC     | `listen.grpc`    | The API, in `tcp` mode. The default config uses the Unix socket instead. |
| 5353 | mDNS     | `discovery.mdns.enabled` | Service announcement, `tcp` mode only. Through avahi-daemon when it runs. |

## mDNS service

| Property      | Value |
|---------------|-------|
| Service type  | `_compute-blade._tcp` |
| Instance name | the blade's hostname |
| Port          | the gRPC port |
| TXT `version` | agent version, e.g. `0.12.0` |
| TXT `api`     | `v1alpha1` |
| TXT `auth`    | `mtls` or `none` |
