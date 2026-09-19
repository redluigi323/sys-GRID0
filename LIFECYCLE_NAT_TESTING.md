# Lifecycle and router mapping test build

These changes are compiled and host-tested, not yet verified on a Switch.
No new console logs or fatal reports accompanied this request, so the code
defects below are confirmed findings, not a proven diagnosis of every crash.

## Changes

- NIFM request/general objects now close their owned forward service sessions.
  Their event objects were already RAII-owned; those are not closed twice.
- Cancel/Submit reset the per-request recovery flags for another LAN attempt.
- A single BSD IPC session closing no longer wipes every virtual socket owned
  by that process. Explicit socket closure, full socket shutdown, and process
  exit own cleanup.
- Parked BSD sessions carry their PID. A once-per-second kernel process-list
  check releases exited games' parked handles, shadow sockets, counters and
  the retained Splatoon 2 registration. Failed or truncated queries retain
  resources rather than guessing that a game exited.
- Successful full ShutdownAllSockets releases already-abandoned sessions for
  that process, without releasing active sessions or its proxy TMEM owner.
  This is the live-process reinitialization boundary; arbitrary NIFM changes
  do not close another service's socket pool.
- Retired BSD sessions drop their kernel handles without synchronous CMIF
  close. The normal registered/live-client transfer-memory close path remains.

## NAT support and limits

`port_mapping = 1` is the default in `config.ini`, including when the key is
absent. Set it to `0` and reboot to isolate NAT support from lifecycle testing.

The port now uses the bundled upstream MiniUPnPc and libnatpmp libraries on a
low-priority worker. NAT-PMP is tried first, then UPnP IGD. A separate UDP port
derived from the node identity receives mapped traffic; the ZeroTier core
receives the public endpoint and preserves that socket on replies. Normal
hole punching and root UDP relaying remain available if mapping fails.

Router-controlled allocations are capped at 64 KiB total / 32 KiB per
allocation. The worker stack is 64 KiB. HTTP connects/reads are bounded and
cancellable; discovery cannot block the node's packet loop. Only literal IPv4
HTTP URLs pointing to the current physical gateway are accepted. NAT-PMP
responses are length-checked before the upstream parser. No mapping belonging
to a different UPnP client/application is deliberately replaced.

Leases last at most 600 seconds locally and renew halfway through. The module
does not request permanent UPnP leases: old finite leases expire after radio
changes, shutdown, or power loss. Routers supporting only permanent leases,
non-gateway IGDs or hostname-only control URLs are not supported by this
initial bounded implementation. Obsolete/expired results are not advertised.

This is **not complete desktop OneService transport parity**: IPv6 transport,
its full secondary-socket strategy and TCP fallback relay transport are not
implemented here. UPnP cannot open a carrier's CGNAT or override a firewall
that forbids UDP. A successful mapping alone is not proof of a direct path;
use peers.txt to verify the actual connection.

References: [ZeroTier router/firewall guidance](https://docs.zerotier.com/corporate-firewalls/)
and the pinned `ZeroTierOne/osdep/PortMapper.cpp` implementation. Dependency
licenses are included in the release ZIP.

## Console validation

Enable detailed logs. Keep each run's logs separately before the next reboot.

1. First use `port_mapping = 0` to isolate teardown. In MK8, Splatoon 2 and
   Splatoon 3, host/join a LAN room, play, close the game from HOME, and reopen
   it. Repeat five times without rebooting. Check that uplink/status continue
   advancing and that `lifetime reaped` appears for exited PIDs in bsd.log.
2. Without closing Splatoon, enter local wireless, change to LAN, play/leave,
   return to local wireless, and enter LAN again. Repeat five times. Check
   full `ShutdownAllSockets ... retired` lines when the game uses that command.
   Some titles do not issue it; retained BSD handles then wait for process exit.
3. Verify host discovery, joining and rejoining between two Switches as well
   as Switch/Ryujinx. A lifecycle change must not regress the working packet path.
4. Enable `port_mapping = 1`, reboot, and repeat a short match. Check the `nat`
   line in status.txt and `NAT NAT-PMP mapped` or `NAT UPnP mapped` in uplink.log.
   Test NAT-PMP-only and UPnP-only routers separately if available. Leave the
   session open for over ten minutes to exercise renewal, not just creation.
5. With mapping enabled, test sleep/wake, airplane mode, and two Shoal radio
   transitions. Repeat with router mapping disabled: unavailable mapping must
   not prevent normal ZeroTier connectivity.

If a crash persists, save bsd.log, nifm.log, uplink.log, status.txt, peers.txt
and the Atmosphere report. State the game, repetition number, whether the game
was closed, and whether port mapping was enabled. Hardware validation of these
IPC lifetimes is still essential even when host tests and builds pass.
