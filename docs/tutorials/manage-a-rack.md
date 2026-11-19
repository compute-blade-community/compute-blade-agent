# Manage a rack from your workstation

In this tutorial you open the agents' API to the network, secured with mutual TLS, and set up `bladectl` on your own
machine to control every blade from there. You finish by watching the whole rack in one event stream.

You need:

- two or more blades with the agent installed, as in [Set up your first blade](first-blade.md)
- a workstation on the same network segment as the blades, with `bladectl` installed (see
  [Install bladectl on your workstation](../how-to/install-upgrade-remove.md#install-bladectl-on-your-workstation))

The examples use the blades `blade-pi1` and `blade-pi2`. Use your own host names.

## 1. Let the agent listen on the network

On each blade, edit `/etc/compute-blade-agent/config.yaml` and change the `listen` section:

```yaml
listen:
  metrics: ":9666"
  grpc: ":8081"
  authenticated: true
  mode: tcp
```

Restart the agent:

```bash
sudo systemctl restart compute-blade-agent
journalctl -u compute-blade-agent -b | grep -E 'grpc server|bladectl config'
```

On its first start with `authenticated: true` the agent creates a certificate authority, a server certificate and a
client certificate, all in `/etc/compute-blade-agent/` and root's bladectl config. The log confirms it:

```text
... Updated the local bladectl config for the current listen settings  {"server": "localhost:8081", "authenticated": true}
... Starting grpc server  {"address": ":8081"}
```

Check that `bladectl` on the blade still works. It now connects over TCP with the new client certificate:

```bash
sudo bladectl get status
```

## 2. Copy the client credentials to your workstation

Every blade has its own CA, so you need each blade's client certificate. It's in root's bladectl config on the blade.
Collect them into one config on your workstation. For the first blade, copy the file:

```bash
mkdir -p ~/.config/bladectl
ssh blade-pi1 sudo cat /root/.config/bladectl/config.yaml > ~/.config/bladectl/config.yaml
chmod 600 ~/.config/bladectl/config.yaml
```

For every further blade, append its entry to the `blades` list. With [yq](https://github.com/mikefarah/yq):

```bash
ssh blade-pi2 sudo cat /root/.config/bladectl/config.yaml > /tmp/blade-pi2.yaml
yq -i '.blades += load("/tmp/blade-pi2.yaml").blades' ~/.config/bladectl/config.yaml
rm /tmp/blade-pi2.yaml
```

The file contains private keys. Keep it at mode 600 and don't commit it anywhere.

## 3. Point the entries at the blades

The copied entries still say `localhost:8081`, because they were written for use on the blade. Let `bladectl` find the
real addresses:

```bash
bladectl discover
```

```text
┌───────────┬──────────────────────┬──────────────┬─────────┬──────┬─────────────────┐
│ BLADE     │ SERVER               │ ADDRESSES    │ VERSION │ AUTH │ CONFIG          │
├───────────┼──────────────────────┼──────────────┼─────────┼──────┼─────────────────┤
│ blade-pi1 │ blade-pi1.local:8081 │ 192.168.0.30 │ 0.12.0  │ mTLS │ address changed │
│ blade-pi2 │ blade-pi2.local:8081 │ 192.168.0.182│ 0.12.0  │ mTLS │ address changed │
└───────────┴──────────────────────┴──────────────┴─────────┴──────┴─────────────────┘
```

The agents announce themselves via mDNS. `address changed` means `--save` will replace `localhost:8081` with the
discovered address and keep the certificates:

```bash
bladectl discover --save
bladectl discover
```

The second run shows `configured` for every blade.

If discovery finds nothing, your workstation and the blades are probably on different network segments. Set each
`server` by hand instead, for example to `blade-pi1:8081`. Use a name the blade's certificate covers: its hostname,
`<hostname>.local` or its IP address.

## 4. Control the rack

Talk to one blade:

```bash
bladectl --blade blade-pi2 get status
bladectl --blade blade-pi2 set identify
```

Or to all of them with `-A`:

```bash
bladectl -A get status
bladectl -A remove identify
```

Choose the blade that `bladectl` uses without `--blade` by setting `current-blade` in the config.

## 5. Watch the whole rack

```bash
bladectl events -A
```

One stream shows the events of every blade, each line tagged with the blade's name. Press the edge button of any
blade and its line appears. Restart an agent and `bladectl` reconnects to it by itself.

## What you did

You switched the agents to TCP with mutual TLS, collected the client credentials in one config, let discovery fill in
the addresses and controlled several blades at once.

Next:

- Feed the rack into Prometheus: [Monitor blades with Prometheus](../how-to/prometheus-monitoring.md).
- React to the event stream in your own tools: [React to events](../how-to/react-to-events.md).
- Understand what the certificates protect: [Security model](../explanation/security.md).
- The certificates expire after a year: [Rotate the API certificates](../how-to/rotate-certificates.md).
