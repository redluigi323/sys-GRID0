# sys-zerotier

A very work in progress port of ZeroTier to the nintendo switch as a sysmodule, very AI assisted in the making, yet extremely functional with better results than i had hoped. Get the latest release from the releases page, or read the build instructions in build.md

## where sys-zerotier is at right now

The whole point of this was to make native LAN play work over the internet
without needing a PC relay or another console sitting on the same network. We
have reached that point, and it has worked in actual matches.

Here is what is working at the moment:

- ZeroTier runs as a Horizon sysmodule, joins a network, keeps its identity and
  managed IP, and survives normal sleep and wake.
- The virtual IPv4 side handles ARP, IPv4, UDP and ICMP. The host tests are at
  88/88, with fuzz testing of the packet path as well.
- The `bsd:u` and `nifm:u` MITMs are doing their job. LAN discovery and game
  sockets can be sent through ZeroTier while ordinary Switch networking keeps
  working too.
- Mario Kart 8 Deluxe, Splatoon 2 and Splatoon 3 have all managed LAN play over
  ZeroTier with Switch and Ryujinx players. The other games in the whitelist
  are ready for people to try and report back on.
- There is now a proper Ultrahand overlay. It shows the current status, lets a
  user pick a saved network or type the entire 16-digit network ID, applies a
  network change without rebooting, and has switches for the sysmodule, BSD,
  NIFM and detailed logging.
- New installs turn on the sysmodule and both MITMs automatically. Saved
  networks live in `/config/sys-zerotier/networks.ini`, so an update does not
  wipe them out.
- A lot of memory work and logging cleanup has gone into keeping the module
  alive on real hardware. The larger BSD/NIFM logs are optional; the normal
  build keeps the small boot, status and uplink logs running.

## current limitations

The latest test build adds game-exit/reinitialization cleanup and automatic
UPnP/NAT-PMP router mapping. Those changes still need repeated-session testing
on hardware; see [the test notes](LIFECYCLE_NAT_TESTING.md). Router mapping can
help restrictive connections, but cannot promise a direct path through CGNAT
or networks that block UDP.

There are still things left to do. Games that only support local wireless mode
need an `ldn:u` MITM before they can use ZeroTier. The LAN whitelist covers the
games tested so far, but more compatibility testing is welcome. If something
breaks, include `status.txt`, `uplink.log`, and (when enabled) `bsd.log` and
`nifm.log` with the report so it can actually be investigated.

## the important folders

```text
source/                 sysmodule, ZeroTier port and LAN MITMs
source/net/             virtual IPv4 network and packet handling
overlay/                Ultrahand/Tesla overlay
compat/                 Horizon and dependency compatibility shims
patches/                small Horizon-specific ZeroTier patch
tests/                  host-side VNet tests and packet reference data
Atmosphere-libs/        pinned Atmosphère dependency submodule
ZeroTierOne/            pinned ZeroTier dependency submodule
```

For prerequisites, submodules, build outputs, installation, and tests, see
[build.md](build.md).

## licensing

The ZeroTier `node/` sources are MPL-2.0. Atmosphère/libstratosphere and the
other bundled dependencies retain their upstream licenses. The port, shim and
overlay code should be distributed with the license terms of the project as it
is released; do not add ZeroTier's separately licensed `libzt` component.
