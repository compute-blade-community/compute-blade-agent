# Limit the CPU when power is short

A CM4 or CM5 under full load can draw more than 802.3af PoE delivers. The power policy lowers the CPU's maximum
frequency, or switches its cpufreq governor, while the blade is short on power. It's off by default.

## Limit blades that don't get PoE+

```yaml
power_policy:
  limited_power:
    max_freq_mhz: 1200
```

`limited_power` applies while the blade isn't powered by 802.3at PoE+, so on 802.3af PoE and USB-C.

## Limit the CPU during under-voltage

```yaml
power_policy:
  undervoltage:
    governor: powersave
    max_freq_mhz: 1000
```

This applies while the `undervoltage` condition is raised. It needs `health.undervoltage.enabled: true` (the default)
and the Raspberry Pi firmware flags, so it does nothing on the Radxa CM5.

When both apply, the lower frequency cap wins and the `undervoltage` governor is used.

## Apply and check

```bash
sudo systemctl restart compute-blade-agent
journalctl -u compute-blade-agent | grep -i 'power policy'
```

The agent logs `Power policy enabled` with the limits it understood. While a limit is active:

```bash
cat /sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq
cat /sys/devices/system/cpu/cpufreq/policy0/scaling_governor
```

The agent also publishes `power_limit` and `power_limit_clear` events and exports
`computeblade_power_limit_active{reason="..."}`.

The original settings come back when the limit ends and when the agent stops. If the agent crashes while a limit is
active, the next start restores the originals from `/run/compute-blade-agent/cpufreq-original.json` and logs a
warning. A reboot also restores them, because `/run` doesn't survive it.

Governors the kernel doesn't offer stop the agent from starting. `cat
/sys/devices/system/cpu/cpufreq/policy0/scaling_available_governors` lists them.
