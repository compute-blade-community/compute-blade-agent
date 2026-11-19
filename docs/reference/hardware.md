# Supported hardware

The agent picks its hardware abstraction layer (HAL) from the device tree's `compatible` string when it starts and
refuses to start on anything else.

## Compute modules

| Feature                          | Raspberry Pi CM4 (`bcm2711`) | Raspberry Pi CM5 (`bcm2712`) | Radxa CM5 (`rockchip,rk3588`) |
|----------------------------------|:---:|:---:|:---:|
| Fan control                      | yes | yes | yes, through the kernel's pwm-fan driver |
| Fan speed (RPM)                  | yes | yes | no |
| Smart fan unit                   | yes (`/dev/ttyAMA5`) | yes (`/dev/ttyAMA4`) | no |
| Edge button and gestures         | yes | yes | no |
| LEDs, identify, indicators       | yes | yes | no |
| Stealth mode                     | yes | yes | no |
| PoE+ detection                   | yes | yes | no, always reports 802.3af/USB-C |
| Under-voltage and throttle flags | yes | yes | no |
| Power policy (cpufreq)           | yes | yes | yes, but `limited_power` always applies |
| Critical mode, events, API       | yes | yes | yes |

The RK3588 HAL is minimal: the mapping of the Rockchip pins to the blade's connector isn't known yet.

On macOS the agent uses a simulated HAL for development. It reports a fixed temperature and logs instead of driving
hardware.

## Pins (CM4 and CM5)

| GPIO | Direction | Function |
|------|-----------|----------|
| 12   | out       | Fan PWM (standard fan unit) or UART TX to the smart fan unit |
| 13   | in        | Fan tachometer (standard fan unit) or UART RX from the smart fan unit |
| 18   | out       | WS281x data for both LEDs |
| 20   | in        | Edge button, active low |
| 21   | out       | Stealth mode: switches the blade's LEDs off |
| 23   | in        | PoE+ detection: high on 802.3at power |

## Fan units

| Fan unit  | Detection | Speed control | RPM | Extras |
|-----------|-----------|---------------|-----|--------|
| Standard  | default   | PWM from the blade | tachometer on GPIO 13, if `hal.rpm_reporting_standard_fan_unit` is on | none |
| Smart     | the agent listens on the UART for up to 3s at start and uses the smart fan unit if it hears from one | commands over UART | reported by the fan unit | airflow temperature, a button |

A smart fan unit serves two neighbouring blades and runs the fan at the higher of the two requested speeds. It
reports the same RPM to both. Its button forwards a single press to the left blade and a double press to the right
blade, where it toggles identify. The firmware is described in [Smart fan unit protocol](fan-unit-protocol.md).
