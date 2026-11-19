# Power, throttling and the power policy

## PoE classes

A blade gets its power over the network cable. Two standards matter:

| Standard          | Power at the blade |
|-------------------|--------------------|
| 802.3af (PoE)     | 12.95 W |
| 802.3at (PoE+)    | 25.5 W  |

A CM4 or CM5 with an NVMe drive and peripherals can draw more than 802.3af delivers when all cores are busy. The blade
signals which class it negotiated on a GPIO, and the agent reports it as `poe+` or `poeOrUsbC` (802.3af, or a USB-C
supply). A switch with too little PoE budget for all its ports is the other common cause of power problems: each blade
negotiated PoE+, but the switch can't deliver it to all of them at once.

## The firmware throttle flags

The Raspberry Pi firmware tracks power and temperature problems in a bitfield, the one `vcgencmd get_throttled` prints:

| Bit | Meaning now            | Bit | Meaning since boot |
|-----|------------------------|-----|--------------------|
| 0   | under-voltage          | 16  | under-voltage occurred |
| 1   | ARM frequency capped   | 17  | frequency capping occurred |
| 2   | throttled              | 18  | throttling occurred |
| 3   | soft temperature limit | 19  | soft temperature limit occurred |

The agent reads it every 2 seconds. Bit 0 raises `undervoltage`. Bits 1 to 3 raise `throttled`. All bits are
exported as `computeblade_throttle_active` and `computeblade_throttle_occurred`.

## Where the flags come from

There are three ways to read the flags, and which ones work depends on the kernel:

1. The firmware mailbox, `/dev/vcio`. This is what `vcgencmd` uses. The agent sends the firmware's `get_throttled`
   property request and gets the full bitfield. Works on current Raspberry Pi kernels.
2. The `get_throttled` file of the firmware driver in sysfs. Older kernels had it, the 6.x kernels of Raspberry Pi OS
   don't.
3. The `rpi_volt` hwmon device. It only reports under-voltage.

The agent tries them in this order and logs which one it uses. If it ends up with `rpi_volt`, it warns that
throttling can't be detected. That happens in containers without `/dev/vcio`, for example.

Throttling is normal under sustained load, which is why `throttled` has no LED indicator by default. Under-voltage is
never normal.

## The power policy

When a blade is short on power, the CPU drawing less helps more than anything else. The power policy uses the kernel's
cpufreq interface to cap the maximum frequency, switch the governor, or both:

- `limited_power` applies while the blade isn't on PoE+
- `undervoltage` applies while the `undervoltage` condition is raised

If both apply, the lower frequency cap wins and the `undervoltage` governor is used. Under-voltage is the more urgent
problem.

The policy is off by default. A capped CPU makes every workload slower, and only you know whether that's better than
the risk of a brown-out for your workloads.

### Undoing a limit

A limit must not outlive its reason. The agent saves the original settings before it applies the first limit and
restores them when no limit applies anymore and when it stops.

If the agent crashes while a limit is active, nobody restores the settings. To handle that, the originals are written
to `/run/compute-blade-agent/cpufreq-original.json`. The next start finds the file, restores the originals and logs a
warning, even if the power policy was disabled in the meantime. Without the file, the next start would read the
limited values and take them for the originals. `/run` is cleared on reboot, and so are cpufreq settings, so a stale
file can't survive the state it describes.
