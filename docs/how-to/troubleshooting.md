# Troubleshoot common problems

Start with the agent's log. It names the problem in most cases:

```bash
journalctl -u compute-blade-agent -b
```

For more detail, run the agent with `--debug` through a systemd drop-in (`systemctl edit compute-blade-agent`):

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/compute-blade-agent --debug
```

## The agent doesn't start

The agent checks its configuration on start and exits if something doesn't fit, for example a fan curve with
decreasing speeds, an unknown indicator pattern, a governor the kernel doesn't offer or an invalid button binding. The
log names the key and what's wrong with it. Compare your config with
[Configuration file](../reference/configuration.md).

`unsupported platform` means the device tree doesn't describe a CM4, CM5 or RK3588. See
[Supported hardware](../reference/hardware.md).

## `bladectl` on the blade says permission denied

The default Unix socket `/tmp/compute-blade-agent.sock` belongs to root, and so does the bladectl config the agent
wrote. Run `sudo bladectl`.

## `bladectl` can't connect over the network

`connection refused`: the agent listens on the Unix socket. Set `listen.mode: tcp` and `listen.grpc: ":8081"`, see
[Manage a rack from your workstation](../tutorials/manage-a-rack.md).

`certificate is valid for ..., not ...`: the server certificate only names `localhost`, the hostname,
`<hostname>.local` and the IP addresses the blade had when the certificate was created. Use one of those in
`server`, or [renew the server certificate](rotate-certificates.md) after an IP change.

`certificate has expired`: the certificates are valid for one year. [Rotate them](rotate-certificates.md).

`current blade not found in configuration`: `--blade` names a blade that isn't in `~/.config/bladectl/config.yaml`,
or `current-blade` points to a missing entry.

## `bladectl discover` finds nothing

The agent only announces itself in `tcp` mode, with `discovery.mdns.enabled: true`. Check its log for
`Announcing the API via mDNS`.

mDNS uses multicast on UDP port 5353 and doesn't cross routers or VLANs. Your workstation has to be on the same
network segment as the blades, and firewalls on both ends must let mDNS through. Try `--wait 10s` on busy networks.

## The blade's host name turned into `<hostname>-2.local`

avahi-daemon renames the host when another responder on the network or the same machine claims its name. Agents up
to 0.11 announced the service with their own responder next to avahi and caused this. Current agents register through
avahi when it runs. Restart avahi to take the name back:

```bash
sudo systemctl restart avahi-daemon
```

## Fan stall reported, but the fan spins

The fan unit reports a lower speed than `health.fan_stall.min_rpm`, or the fan stops on purpose at low duty cycles.
Raise `min_percent` above the speed at which your fan stops, or lower `min_rpm`. See
[Configure health indicators](health-indicators.md#tune-fan-stall-detection).

On a standard fan unit, `hal.rpm_reporting_standard_fan_unit: false` turns off speed measurement and with it stall
detection.

## Throttling is never detected

The agent logs where it reads the firmware flags from. `only under-voltage is reported` means it couldn't use
`/dev/vcio`, for example inside a container without the device. Throttling then can't be detected, under-voltage
still works. `throttle status unavailable` means there's no Raspberry Pi firmware at all, as on the Radxa CM5.

## Critical mode fires often

The SoC regularly reaches `critical_temperature_threshold`. Check the airflow and the fan curve, or raise the
threshold. See [Tune the fan curve and critical mode](tune-fan-and-critical-mode.md).

## The fan runs at full speed after the agent stopped

That's on purpose. When the agent exits, it runs the fan at 100% and turns the LEDs off, because nothing controls the
temperature anymore. With a smart fan unit this also affects the neighbouring blade, since the fan unit follows the
higher of the two requests.

## The log warns about a deprecated configuration key

The config uses an old name for a setting. The warning names the key. Rename it as listed in
[Configuration file](../reference/configuration.md). The old name keeps working until it's removed in a later
release.
