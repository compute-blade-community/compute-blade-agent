# Run a development build on a blade

*For developers.* Unit tests don't touch GPIOs, LEDs or the fan. Before you open a pull request that changes how the
agent talks to hardware, run your build on a real blade. This guide installs it next to the packaged agent, so you
can switch back with one command.

## Build

```bash
SHA=$(git rev-parse --short HEAD)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
  -ldflags "-X=main.Version=0.0.0-dev.$SHA -X=main.Commit=$SHA" \
  -o /tmp/compute-blade-agent ./cmd/agent
```

## Install next to the packaged agent

Copy the binary to the blade and point the service at it with a systemd drop-in:

```bash
scp /tmp/compute-blade-agent blade-pi1:/tmp/
ssh blade-pi1
sudo install -D -m 0755 /tmp/compute-blade-agent /usr/local/lib/cba-dev/compute-blade-agent
sudo mkdir -p /etc/systemd/system/compute-blade-agent.service.d
sudo tee /etc/systemd/system/compute-blade-agent.service.d/dev.conf <<'CONF'
[Service]
ExecStart=
ExecStart=/usr/local/lib/cba-dev/compute-blade-agent --debug
CONF
sudo systemctl daemon-reload
sudo systemctl restart compute-blade-agent
journalctl -u compute-blade-agent -f
```

The log shows your version in every line.

## Use a test config without touching the real one

If the blade's config is managed by configuration management, or you want to try settings without losing the real
ones, mount a test config over it for the service only. Add a line to the drop-in:

```ini
BindReadOnlyPaths=/etc/compute-blade-agent-dev/config.yaml:/etc/compute-blade-agent/config.yaml
```

The rest of the system, and your configuration management, keep seeing the original file.

## Exercise your change

Watch the events from your workstation while you test:

```bash
bladectl --blade blade-pi1 events
```

Some ideas that don't need physical access:

- Simulate a fan stall: set `health.fan_stall.min_rpm` above what the fan reaches (see `bladectl get fan`). Force
  `bladectl set fan --percent 100` to clear it again.
- Trigger critical mode: lower `critical_temperature_threshold` below the current temperature, or load the CPU:
  `for i in 1 2 3 4; do timeout 300 sh -c 'while :; do :; done' & done`.
- Test the crash recovery of the power policy: stop the agent, limit the CPU by hand as a crashed agent would have
  left it, write the originals to `/run/compute-blade-agent/cpufreq-original.json` (e.g.
  `{"policy0":{"governor":"ondemand","max_freq_khz":1500000}}`) and start the agent. It restores the originals and
  logs a warning.

Buttons, LEDs and unplugging a fan need someone at the rack.

## Switch back

```bash
sudo rm /etc/systemd/system/compute-blade-agent.service.d/dev.conf
sudo systemctl daemon-reload
sudo systemctl restart compute-blade-agent
sudo rm -rf /usr/local/lib/cba-dev
```
