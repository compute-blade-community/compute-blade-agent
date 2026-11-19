# Discovery

Typing IP addresses into a config file works for one blade. For a rack it's tedious, and DHCP makes it fragile.
Agents listening on TCP announce themselves on the local network, and `bladectl discover` finds them.

## mDNS and DNS-SD

The announcement uses multicast DNS with service discovery (DNS-SD), the protocol behind printers and AirPlay
devices showing up by themselves. Each agent announces a service of type `_compute-blade._tcp` named after its
hostname, pointing at its gRPC port. TXT records carry the agent version, the API version and whether the API
requires mTLS, so `bladectl` can tell what it found before connecting.

mDNS works within one network segment. Routers don't forward it, so blades on another VLAN stay invisible unless
something reflects mDNS between the segments.

## avahi or the built-in responder

Every host on a network segment answers mDNS questions about its own names. On Linux, avahi-daemon usually does that
job: it owns the host's name, such as `blade-pi1.local`, and answers for it.

A DNS-SD service needs a host name to point to. If the agent ran its own mDNS responder next to avahi, both would
claim `blade-pi1.local`. Avahi treats that as a conflict and renames the host to `blade-pi1-2.local`, which breaks
everything that used the old name. Agents up to 0.11 did exactly that.

So the agent asks avahi over D-Bus to publish the service, pointing at avahi's own host name. Avahi stays the only
responder. When avahi restarts, the agent registers again. If another device on the network already uses the
service name, avahi reports a collision and the agent picks the alternative name avahi suggests.

Only if avahi doesn't run does the agent answer mDNS queries itself, for the service and the host's addresses. It
never starts avahi through D-Bus activation: if someone stopped avahi, that was on purpose.

## What discover does with the results

`bladectl discover` listens for a few seconds and lists what it heard. With `--save`, it merges the results into
`~/.config/bladectl/config.yaml`, matching blades by name:

- A configured address that still reaches the blade stays as it is. `blade-pi1:8081` and `blade-pi1.local:8081` name
  the same blade in different domains, so `discover` keeps whatever you wrote. The same goes for an IP address the
  blade announced.
- An address that no longer matches gets replaced with `<hostname>.local:<port>`. A host name survives DHCP changes
  and is one of the names in the blade's server certificate, an IP address isn't guaranteed to be either.
- A `localhost` entry for another blade was copied from that blade's own config and can't work from here, so it's
  replaced too. A `localhost` entry for the machine `bladectl` runs on, and Unix socket entries, stay.
- Unknown blades without authentication are added. Unknown blades with mTLS can't be: their client certificate has to
  come from the blade, and discovery doesn't carry secrets.
