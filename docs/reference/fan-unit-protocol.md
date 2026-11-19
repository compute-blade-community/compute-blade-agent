# Smart fan unit protocol

*For developers working on the agent or the fan unit firmware ([`cmd/fanunit`](../../cmd/fanunit)).*

The smart fan unit is an RP2040 board with an EMC2101 fan controller. It talks to each of its two blades over a
separate UART at 115200 baud, 8N1. The firmware is built with TinyGo (`mise run build:fanunit`) and released as
`fanunit.uf2`.

## Framing

Every packet carries a command byte and three data bytes:

```text
SOF  CMD  D0  D1  D2  CHK  EOF
0x7E                        0x7F
```

`CHK` is the XOR of `CMD`, `D0`, `D1` and `D2`. Between `SOF` and `EOF`, any byte equal to `0x7E`, `0x7F` or the escape
byte `0x7D` is sent as `0x7D` followed by the byte XOR `0x20`. A reader drops bytes until it sees a valid packet, so a
blade can start listening at any time. The code is in [`pkg/smartfanunit/proto`](../../pkg/smartfanunit/proto).

## Commands

Blade to fan unit:

| Command | Name                    | Data |
|---------|-------------------------|------|
| `0x01`  | Set fan speed percent   | `D0`: speed 0 to 100. The fan unit runs the fan at the higher of the two blades' requests. |
| `0x02`  | Set LED                 | `D0` blue, `D1` green, `D2` red. |

Fan unit to blade:

| Command | Name                    | Data |
|---------|-------------------------|------|
| `0xA1`  | Button press            | none. One press goes to the left blade, a double press (within 600ms) to the right blade. |
| `0xA2`  | Airflow temperature     | 24-bit big-endian value in tenths of °C. The left blade gets the EMC2101's internal sensor, the right blade the external one. |
| `0xA3`  | Fan speed               | 24-bit big-endian value in tenths of RPM. |

The fan unit sends temperature and fan speed every 2 seconds. The agent uses the first packet it receives within 3
seconds of starting to detect a smart fan unit.

On power-up the fan unit runs the fan at 40% until a blade sends a speed.
