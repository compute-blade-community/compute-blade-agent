# Security model

The agent can switch a blade's fan off, run commands as root on button presses and power the blade off. Who can talk
to it matters.

## The API

The API has three modes, set by `listen.mode` and `listen.authenticated`:

**Unix socket** (the default). Only root on the blade can connect. Nothing is exposed to the network.

**TCP without authentication.** Anyone who can reach the port controls the blade's fan, LEDs and identify. Use it only
on a network you trust completely, or behind a firewall that limits who can connect.

**TCP with mutual TLS.** Both sides prove who they are with certificates. On its first start in this mode the agent
creates:

- a certificate authority (CA), valid for 10 years
- a server certificate signed by the CA, valid for one year, for `localhost`, the hostname, `<hostname>.local` and
  the blade's IP addresses at that time
- a client certificate signed by the CA, valid for one year, stored in root's bladectl config

The server only accepts clients with a certificate from its CA. Every blade has its own CA, so a client certificate
for one blade doesn't open another one.

The CA key stays on the blade, in `/etc/compute-blade-agent/ca-key.pem`, readable by root only. There's no tooling to
issue more client certificates yet. Clients share the one the agent created, so treat it like a root password for the
blade's hardware.

The agent doesn't renew certificates. After a year, clients can't connect until you
[rotate them](../how-to/rotate-certificates.md).

## What a client can do

With access to the API, a client can:

- set the fan to any speed, including 0%
- turn the LEDs off (stealth mode)
- start and stop identify
- enter and leave critical mode
- read the status and the event stream

A client can't run commands, change the configuration, power off the blade or limit the CPU. Those only come from the
configuration file and the button.

Setting the fan to 0% can't overheat a blade as long as critical mode is enabled: it runs the fan at full speed once
the threshold is reached, and the API refuses to change the fan speed during critical mode. With
`critical_temperature_threshold: 0` that protection is gone.

## The metrics port

Port 9666 serves Prometheus metrics and Go's `/debug/pprof/` endpoints without authentication. The metrics reveal
little. pprof lets anyone who can reach the port collect CPU profiles and execution traces of the agent, which costs
CPU time on the blade. Restrict the port to your monitoring network.

## Button actions

Commands bound to gestures run as root. Anyone who can edit `/etc/compute-blade-agent/config.yaml` can already run
anything as root, so this adds no new privilege. It does mean the commands themselves have to be safe to run as root,
by whoever is standing at the rack.

Physical access always wins: anyone at the rack can pull a blade. The button gestures add no risk beyond that, as long
as the bound actions don't do more than pulling the blade would. `emergency-poweroff` is equivalent to pulling it.

## Discovery

mDNS announcements tell everyone on the network segment that a blade runs the agent, its version and whether the API
requires mTLS. They carry no credentials. Turn discovery off with `discovery.mdns.enabled: false` if that's too much.
