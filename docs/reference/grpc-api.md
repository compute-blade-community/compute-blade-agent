# gRPC API

The agent serves `api.bladeapi.v1alpha1.BladeAgentService`, defined in
[`api/bladeapi/v1alpha1/blade.proto`](../../api/bladeapi/v1alpha1/blade.proto). Go clients can import the generated
package `github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1`.

The API is `v1alpha1`: messages and RPCs may still change between releases. New fields and enum values are added in a
backwards compatible way, so clients should ignore what they don't know.

## Connecting

| `listen.mode` | `listen.authenticated` | Address                         | Transport |
|---------------|------------------------|---------------------------------|-----------|
| `unix`        | ignored                | `/tmp/compute-blade-agent.sock` | Plain gRPC over a Unix socket, root only. |
| `tcp`         | `false`                | `listen.grpc`, e.g. `:8081`     | Plain gRPC, no authentication. |
| `tcp`         | `true`                 | `listen.grpc`, e.g. `:8081`     | TLS, the server requires a client certificate signed by the blade's CA. |

With mTLS, take the CA certificate, client certificate and key from the `bladectl` config the agent wrote on the blade
(base64-encoded PEM, see [bladectl](bladectl.md#configuration-file)). The server certificate is valid for `localhost`,
the hostname, `<hostname>.local` and the blade's IP addresses at the time it was created.

## RPCs

### `GetStatus`

`GetStatus(Empty) returns (StatusResponse)`: a snapshot of the blade.

| Field                            | Type                  | Description |
|----------------------------------|-----------------------|-------------|
| `stealth_mode`                   | bool                  | All LEDs off. |
| `identify_active`                | bool                  | Identify is on. |
| `critical_active`                | bool                  | Critical mode is on. |
| `temperature`                    | int64                 | SoC temperature in °C. |
| `fan_rpm`                        | int64                 | Measured fan speed. 0 without RPM reporting. |
| `fan_percent`                    | uint32                | Fan speed the agent commands right now: 100 in critical mode, the override or the fan curve otherwise. |
| `fan_speed_automatic`            | bool                  | `false` while a fan speed override is set. |
| `power_status`                   | `PowerStatus`         | `POE_OR_USBC` (0) or `POE_802_AT` (1). |
| `critical_temperature_threshold` | int64                 | Configured threshold in °C. |
| `fan_curve_steps`                | repeated `FanCurveStep` | The fan curve: `temperature` and `percent` per step. |
| `version`                        | `VersionInfo`         | Agent `version`, `commit` and build `date` (Unix seconds). |
| `conditions`                     | repeated string       | Raised health conditions, e.g. `fan_stall`. Empty when healthy. |

### `EmitEvent`

`EmitEvent(EmitEventRequest) returns (Empty)`: inject an event. Only `IDENTIFY`, `IDENTIFY_CONFIRM`, `CRITICAL` and
`CRITICAL_RESET` are accepted, anything else fails with `InvalidArgument`. A `CRITICAL` sent this way stays active until
`CRITICAL_RESET`, unless the temperature crosses the threshold in between.

### `WaitForIdentifyConfirm`

`WaitForIdentifyConfirm(Empty) returns (Empty)`: blocks until identify is confirmed, usually by someone pressing the
button on the blade. `bladectl set identify --wait` uses it.

### `SetFanSpeed`

`SetFanSpeed(SetFanSpeedRequest) returns (Empty)`: override the fan curve with a fixed `percent` (0 to 100). Fails
while critical mode is active.

### `SetFanSpeedAuto`

`SetFanSpeedAuto(Empty) returns (Empty)`: remove the override and return to the fan curve.

### `SetStealthMode`

`SetStealthMode(StealthModeRequest) returns (Empty)`: `enable: true` turns all LEDs off. Fails while critical mode is
active.

### `WatchEvents`

`WatchEvents(WatchEventsRequest) returns (stream AgentEvent)`: streams events as the agent handles them, until the
client disconnects or the agent shuts down (the stream then ends with `EOF`).

`WatchEventsRequest.events` filters the stream. Empty means all events. See [Events](events.md) for when each event
is emitted and for the delivery guarantees.

## Messages

### `AgentEvent`

| Field       | Type                        | Description |
|-------------|-----------------------------|-------------|
| `event`     | `Event`                     | What happened. |
| `timestamp` | `google.protobuf.Timestamp` | When it happened on the blade. |
| `blade`     | string                      | Hostname of the blade. |
| `details`   | oneof                       | `fan` (10), `throttle` (11), `power_limit` (12), `button` (13) or `gesture` (14), depending on the event. |

The detail messages are `FanDetails`, `ThrottleDetails`, `PowerLimitDetails`, `ButtonDetails` and `GestureDetails`.
Their fields are listed in [Events](events.md#details).

### `Event`

| Value | Name                 | Value | Name                 |
|-------|----------------------|-------|----------------------|
| 0     | `IDENTIFY`           | 7     | `UNDERVOLTAGE`       |
| 1     | `IDENTIFY_CONFIRM`   | 8     | `UNDERVOLTAGE_CLEAR` |
| 2     | `CRITICAL`           | 9     | `THROTTLED`          |
| 3     | `CRITICAL_RESET`     | 10    | `THROTTLED_CLEAR`    |
| 4     | `BUTTON_PRESS`       | 11    | `POWER_LIMIT`        |
| 5     | `FAN_STALL`          | 12    | `POWER_LIMIT_CLEAR`  |
| 6     | `FAN_STALL_CLEAR`    | 13    | `BUTTON_GESTURE`     |

`IDENTIFY` is the enum's zero value. JSON encoders that skip default values drop it, so set `EmitDefaultValues` (Go
`protojson`) or the equivalent when you serialize events.

## Example with grpcurl

The API has no server reflection, so pass the proto file:

```bash
grpcurl -import-path api/bladeapi/v1alpha1 -proto blade.proto \
  -cacert ca.pem -cert client.pem -key client-key.pem \
  blade-pi1:8081 api.bladeapi.v1alpha1.BladeAgentService/GetStatus
```

[React to events from scripts and programs](../how-to/react-to-events.md) shows a complete Go client.
