# Intercepting `bsd:u` — the only piece that matters for LAN-play titles

Games with a native **LAN Play** mode (Mario Kart 8 Deluxe, Splatoon 2 and 3,
ARMS, Pokkén Tournament DX, Mario Tennis Aces, Nintendo Switch Sports,
Civilization VI, and others) never touch the `ldn` services.
They use ordinary BSD sockets on the console's ordinary network connection.
That makes the whole project one component instead of three: get those sockets
onto the ZeroTier network.

This document is the specification for that component.

## 1. What the game actually does

The pattern every LAN-play title follows, and the reason `switch-lan-play`
works on completely stock consoles:

1. Open a UDP socket, `setsockopt(SO_BROADCAST)`, `bind()` to a fixed port.
2. Send discovery datagrams to the subnet broadcast address (or
   `255.255.255.255`).
3. Learn about peers from the source address of the replies — `recvfrom`'s
   `src_addr`, not from any configured list.
4. Exchange gameplay traffic as unicast UDP to those learned addresses.

Nothing in that sequence requires the game to know its own IP address, which is
a large simplification: **the shim does not have to lie about the console's
address anywhere**, as long as the source address it writes into outgoing
IPv4 headers is the console's ZeroTier address. Peers learn it from step 3.

Evidence this holds in practice: `switch-lan-play` puts consoles on
`10.13.0.0/255.255.0.0` with a gateway at `10.13.37.1`
(`switch-lan-play/src/config.h`), which is nobody's real home subnet, and the
games work. LAN-play titles do not care what subnet they are on.

## 1a. What transfers from `switch-lan-play`, and what does not

The established solutions capture with `pcap`. That mechanism does not transfer:
it runs on a PC, sniffing the console's frames off the wire in promiscuous
mode. Horizon gives a sysmodule no promiscuous L2 access and no TUN/TAP, which
is the entire reason this project intercepts at the IPC boundary instead.

The consequence is worth stating plainly, because it is the central difficulty
of this whole component:

> `switch-lan-play` works **below** the socket layer. It forwards raw Ethernet
> frames and therefore never has to decide what is game traffic. We work
> **above** it, so we must classify every socket -- and a wrong answer does not
> merely break the game, it breaks the console's networking.

That asymmetry argues for making the virtualisation rule as *broad* as is safe
rather than as narrow as possible: narrow means silently missing traffic the
game needs, with no error anywhere to show for it. Section 4 starts
conservative deliberately, but expect to widen it once real traffic is
observed, not to tighten it.

What does transfer, from reading their source:

- **Scope confirmation.** `arp.c` handles exactly ARP plus IPv4, which is what
  `source/net/` already implements. Nothing in their client suggests a
  LAN-play title needs anything else.
- **MTU 1500** (`config.h`, `ETHER_MTU`). Matches the recommendation here.
- **Peers are learned from traffic, never configured.** Their design has no
  member list at all -- exactly the property section 1 relies on.
- **The subnet trick is theirs, not ours.** They put consoles on
  `10.13.0.0/16` with a fabricated gateway at `10.13.37.1` and tell users to
  ignore the failed connectivity test, because the PC provides the internet.
  We must not do this: the console's real IP configuration has to keep working,
  since ZeroTier's own transport rides on it.

## 2. The interception point

Horizon has no TUN/TAP and `bsd:u` refuses `SOCK_RAW` except for IPv4 ICMP, so
there is no way to add a virtual interface to the system's stack. The only
place to divert the traffic is the IPC boundary between the game and the
`bsd` service, using Atmosphère's MITM framework.

`sm` decides per **client program**, not per service — `IsMitmDisallowed`
(`Atmosphere/stratosphere/sm/source/impl/sm_service_manager.cpp:397`) blocks
only `loader`, `pm`, `spl`, `boot`, `ncm`, `creport` and the MITM module
itself. Applications are fair game, and `sm` additionally asks the MITM module
per client (command `65000`, "should I mitm this one?"), so the module can
answer yes only for the running application and let every system process reach
the real service untouched.

Ryujinx arrived at the same layer from the other direction: its LDN
implementation "proxies BSD sockets created while connected to local wireless
over the internet". Socket-level is where this belongs.

## 3. The command table

From `libnx/nx/source/services/bsd.c`. The MITM must relay all of these; the
**Logic** column is what actually needs thought.

| Cmd | Name | Logic |
|----:|------|-------|
| 0 | `RegisterClient` | Normally relay the transfer-memory copy handle and record the client PID. For Splatoon 2, keep command 0 but register one 592 KiB proxy TransferMemory with a bounded configuration. Retain that process-wide real-BSD registration and answer later nnSdk registration cycles from its cached response; the game's own rapidly reused pages are never copied to real BSD. |
| 1 | `StartMonitoring` | Relay. |
| 2 | `Socket` | Relay to get a real fd (so the fd namespace never collides), then mark it as a candidate in the process's socket table. |
| 3 | `SocketExempt` | Relay. |
| 4 | `Open` | Relay. |
| 5 | `Select` | **Split.** Partition the fd sets into virtual and real, poll ours, relay theirs, merge. |
| 6 | `Poll` | **Split**, same as Select. |
| 7 | `Sysctl` | Relay. |
| 8 | `Recv` | Virtual: dequeue. Real: relay. |
| 9 | `RecvFrom` | Virtual: dequeue and fill `src_addr` with the peer's ZeroTier address. Real: relay. |
| 10 | `Send` | Virtual: emit on a connected virtual socket. Real: relay. |
| 11 | `SendTo` | **The hot path.** Virtual: assemble Ethernet/IPv4/UDP and hand to `ZT_Node_processVirtualNetworkFrame`. Real: relay. |
| 12 | `Accept` | Relay (no TCP in v1). |
| 13 | `Bind` | **The decision point.** See §4. |
| 14 | `Connect` | Virtual if the destination is on the virtual subnet. |
| 15 | `GetPeerName` | Virtual: answer from our table. |
| 16 | `GetSockName` | Virtual: answer with the ZeroTier address and the bound port. |
| 17 | `GetSockOpt` | Virtual: answer from our table. |
| 18 | `Listen` | Relay. |
| 19 | `Ioctl` | Watch for `SIOCGIFCONF` / `SIOCGIFADDR` — a game that asks this way must be told about the virtual interface. |
| 20 | `Fcntl` | Virtual: track `O_NONBLOCK`. |
| 21 | `SetSockOpt` | Virtual: track `SO_BROADCAST`, `SO_REUSEADDR`, `SO_RCVBUF`. |
| 22 | `Shutdown` | Virtual: tear down. |
| 23 | `ShutdownAllSockets` | Virtual: tear down all of ours, then relay. |
| 24 | `Write` / 25 `Read` | Same as Send/Recv. |
| 26 | `Close` | Virtual: free our state, then relay to release the real fd. |
| 27 | `DuplicateSocket` | Virtual: alias in our table. |
| 29 | `RecvMMsg` / 30 `SendMMsg` | Batched forms of 9 and 11. Some titles use these. |
| 33 | `RegisterClientShared` | Relay only when the client genuinely selects this HOS 10+ interface. It is not a transparent replacement for command 0: nnSdk selects it under different service/option conditions and interprets its output differently. |

## 4. When does a socket become virtual?

The policy that keeps online play, the eShop and system services working:

> A socket becomes virtual at `Bind` time if it is `SOCK_DGRAM`, `AF_INET`, and
> either `SO_BROADCAST` is set or the bound port is in the configured
> LAN-play port set. Everything else stays real, forever.

Start conservative — an explicit per-title port list in the config file — and
loosen it only once real traffic has been observed. A wrong answer here does
not merely break the game; it breaks the console's networking.

Traffic to a *real* destination on a socket that has gone virtual should still
be relayed. Keep the two paths independent per datagram, not per socket, if any
title turns out to need it.

## 5. Two IPC hazards that will cost a day each

**The return convention.** `bsd` commands do not use the normal Horizon result
convention. Every response begins with a raw `{ int ret; int errno; }` pair
*before* any other output data, and the IPC result is `0` even when the socket
call failed (`_bsdDispatchImpl`, `bsd.c:116`). A MITM built on libstratosphere's
typed `sf` interfaces must model this explicitly as leading `sf::Out<int>`
parameters. Get it wrong and every call appears to succeed while returning
garbage.

**Sessions are a pool, not a channel.** libnx opens `num_bsd_sessions` sessions
and dispatches each call on whichever is free (`sessionmgrAttachClient`). A
single fd is therefore used across several sessions of the same process. **Key
the socket table on the client PID, never on the session.** This is the bug
that will look like random intermittent failures under load.

Buffers on the hot commands are `HipcAutoSelect` — libstratosphere's
`sf::InAutoSelectBuffer` / `sf::OutAutoSelectBuffer` map onto them directly.

## 6. What sits under the socket layer

No lwIP in v1. LAN-play traffic is UDP, and the shim only needs:

- an **ARP responder** for the console's ZeroTier address, plus ARP requests for
  peers so PC ZeroTier clients see a normal neighbour;
- **IPv4** assembly and parsing, with fragmentation on the send side (ZeroTier's
  virtual MTU is 2800 by default — set the network's MTU to 1500 in ZeroTier
  Central so a PC client and the console agree);
- **UDP** header assembly, checksum, and a port-to-socket demultiplexer;
- **ICMP echo**, purely so `ping` works from a PC during bring-up. Worth the
  fifty lines.

That is roughly 600 lines and no dependency. lwIP only becomes necessary if a
target title turns out to use TCP.

Two ZeroTier network settings are not optional: **broadcast must be enabled**
(`ZT_NETWORKCONFIG_FLAG_ENABLE_BROADCAST`) or discovery never happens, and the
`multicastLimit` must be at least the number of players.

## 7. `nifm`: settled on link type, NOT settled on arbitration

Nintendo's support page says Mario Kart 8 Deluxe LAN Play requires consoles to
be **wired** to the same router, which raised the possibility that the game
checks the link type and that the sysmodule would have to lie about the
connection medium as well.

Confirmed on hardware: **it does not.** Mario Kart 8 Deluxe and the other LAN
titles enter LAN Play over Wi-Fi. Nintendo's wording is a recommendation about
latency, not a check.

So no `nifm` MITM is needed *for the link type*. That is the only thing this
section originally settled, and the heading used to overstate it.

### 7.1 The part that is not settled: who gets to keep the internet

Observed on hardware: when a LAN-Play title enters LAN mode, the console stops
having an internet connection. It stays on the router — LAN Play over Wi-Fi
works, so the radio is still associated and still carrying IP — but the route
off-subnet goes away.

For `switch-lan-play` that costs nothing, because the PC provides the internet
half; its own setup instructions have users configure a bogus gateway of
`10.13.37.1` and ignore the failed connectivity test. For a console-only design
it is fatal: ZeroTier's transport is UDP/9993 to a public endpoint, and if the
console cannot route off its subnet the node is deaf for the whole match.

This is arbitration, not radio. The candidates, from the `IGeneralService`
command table:

| Cmd | Name | Effect if the application calls it |
|----:|------|---|
| 26 | `SetExclusiveClient` | one client owns the interface; everyone else is cut off |
| 34 | `SetBackgroundRequestEnabled` | disables non-foreground requests — ours |
| 40 | `SetAcceptableNetworkTypeFlag` | restricts the connection to a non-internet type |
| 16 | `SetWirelessCommunicationEnabled` | would drop the radio; ruled out, Wi-Fi LAN Play works |

plus `IRequest` cmd 5 `SetRequirement` / 6 `SetRequirementPreset`, which is how
a title declares it wants a local network rather than an internet one.

Escalation, cheapest first:

1. **Measure.** `uplink.log` records wire tx/rx/fail and `errno` every 30 s.
   `ENETUNREACH`/`EHOSTUNREACH` during LAN mode means route loss.
2. **Hold our own request.** `nifm:a` (`NifmServiceType_Admin`, which ldn_mitm
   already uses from a sysmodule), with `IRequest` `SetPersistent` (12),
   `SetGreedy` (16), `SetKeptInSleep` (23) and `RegisterSocketDescriptor` (24)
   against the UDP/9993 socket. If nifm honours a system-level persistent
   request there is no MITM to write.
3. **MITM `nifm:u`.** Pass through and log to find which call the title makes,
   then swallow that one for the application only. It never needs LAN mode to
   be real: its sockets are diverted by the `bsd:u` layer regardless.

Admin (`nifm:a`) for us versus User (`nifm:u`) for the game is the same split
that keeps `bsd:s` and `bsd:u` from colliding.

So v1 is `bsd:u` plus, most likely, a small `nifm:u` MITM. Still no `ldn:u`.

(For the link type itself the escape hatch remains small and known-shaped —
`nifm` reports `NifmInternetConnectionType_Ethernet = 2` versus `_WiFi = 1` in
`libnx/include/switch/services/nifm.h`.)
