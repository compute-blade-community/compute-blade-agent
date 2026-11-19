# bladectl

`bladectl` talks to the agent's gRPC API. It runs on the blade itself or on any machine that can reach the blade's
API over the network. Release packages exist for Linux (amd64, arm64), macOS and Windows.

## Configuration file

`bladectl` reads `~/.config/bladectl/config.yaml`. The agent writes this file for the user it runs as (root) when it
starts and the file doesn't exist yet. It holds a list of blades and the one to use by default:

```yaml
blades:
  - name: blade-pi1
    blade:
      server: blade-pi1:8081
      cert:
        certificate-authority-data: <base64 PEM of the blade's CA>
        client-certificate-data: <base64 client certificate>
        client-key-data: <base64 client key>
  - name: blade-pi2
    blade:
      server: blade-pi2:8081
      cert: { ... }
current-blade: blade-pi1
```

| Field                                     | Description |
|-------------------------------------------|-------------|
| `blades[].name`                           | Name used with `--blade`. The agent uses the blade's hostname. |
| `blades[].blade.server`                   | `host:port` for TCP, or the socket path (e.g. `/tmp/compute-blade-agent.sock`) on the blade itself. |
| `blades[].blade.cert`                     | mTLS credentials. Leave it out for an unauthenticated API. |
| `current-blade`                           | Blade used when neither `--blade` nor `--all` is given. |

The certificate fields are secrets: anyone with them controls the blade.

## Global flags

| Flag            | Default         | Description |
|-----------------|-----------------|-------------|
| `--blade NAME`  | `current-blade` | Blade to talk to. |
| `-A`, `--all`   | `false`         | Run the command against every blade in the config. |
| `--timeout D`   | `1m`            | Meant as the timeout for gRPC requests, but not applied yet: requests wait until they finish or you press Ctrl+C. |

## Commands

### `bladectl get`

| Command                       | Prints |
|-------------------------------|--------|
| `get status`                  | Temperature, fan speed and override, stealth mode, identify, critical mode, power source and health conditions, as a table. |
| `get fan` (`fan_speed`, `rpm`) | Fan speed in RPM and percent. |
| `get temp` (`temperature`)    | SoC temperature. |
| `get critical`                | Whether critical mode is active. |
| `get identify`                | Whether identify is active. |
| `get stealth`                 | Whether stealth mode is active. |
| `get power_status`            | Power source: `poe+` (802.3at) or `poeOrUsbC`. |

### `bladectl describe`

| Command        | Prints |
|----------------|--------|
| `describe fan` | The configured fan curve. |

### `bladectl set`

| Command                         | Effect |
|---------------------------------|--------|
| `set identify`                  | Start identify: the edge LED blinks. |
| `set identify --wait`, `-w`     | Start identify and block until someone confirms it with the button on the blade. |
| `set identify --confirm`, `-c`  | Stop identify, as if the button was pressed. |
| `set fan --percent N`, `-p N`   | Run the fan at a fixed speed (0 to 100), overriding the fan curve. Default 40. Refused while critical mode is active. Critical mode runs the fan at 100% and keeps the override for afterwards. |
| `set fan --auto`, `-a`          | Return to the fan curve. |
| `set stealth`                   | Turn all LEDs off. Refused while critical mode is active. |
| `set stealth --disable`, `-e`   | Turn the LEDs back on. |

### `bladectl remove`

Aliases: `rm`, `delete`, `del`, `unset`.

| Command           | Effect |
|-------------------|--------|
| `remove identify` | Stop identify. |
| `remove fan`      | Remove the fan speed override. |
| `remove stealth`  | Turn the LEDs back on. |

### `bladectl events`

Streams events until interrupted and reconnects (after 2s) when a blade restarts or the connection drops.

| Flag                 | Description |
|----------------------|-------------|
| `-e`, `--event NAME` | Only show this event. Repeatable. Names are listed in [Events](events.md). |
| `-o`, `--output F`   | `text` (default) or `json`, one object per line. |

Text output, one line per event:

```text
2026-11-19T11:29:01+01:00  blade-pi3         fan_stall  target=52% rpm=4316
```

JSON output uses the field names of the [`AgentEvent`](grpc-api.md#agentevent) message:

```json
{"event":"FAN_STALL","timestamp":"2026-11-19T10:29:01.813817865Z","blade":"blade-pi3","fan":{"target_percent":52,"rpm":4316}}
```

### `bladectl monitor`

Aliases: `fan_speed`, `rpm`. Draws a live chart of temperature and fan speed in the terminal.

### `bladectl discover`

Looks for agents that announce their API via mDNS and prints them with their address, version and authentication.

| Flag              | Default | Description |
|-------------------|---------|-------------|
| `-w`, `--wait D`  | `3s`    | How long to listen for announcements. |
| `--save`          | `false` | Write the result to the config file. |

The `CONFIG` column shows what `--save` does, or did, for each blade:

| Value                | Meaning |
|----------------------|---------|
| `configured`         | The configured address still reaches the blade. It's kept, even if it's written differently (`blade-pi1:8081` and `blade-pi1.local:8081` both count). |
| `address changed`    | The configured address no longer matches. `--save` replaces it with the discovered one and keeps the certificates. |
| `new`                | Unknown blade without authentication. `--save` adds it. |
| `new, needs mTLS credentials` | Unknown blade that requires mTLS. Copy its client certificate first, see [Manage a rack from your workstation](../tutorials/manage-a-rack.md). |
| `configured (local)` | Configured with a socket or localhost address. Never changed. |

### `bladectl version`

Prints the version of `bladectl` and of the agent it talks to.
