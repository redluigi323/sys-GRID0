# Building sys-zerotier

These instructions build the sysmodule and its Ultrahand overlay from a clean
checkout. The supported target is an aarch64 Nintendo Switch running
Atmosphère.

## Prerequisites

Install devkitPro with:

- devkitA64
- libnx
- the Switch portlibs for curl, zlib and mbedTLS
- `bsdtar` (used to create the release archive)
- Python 3 (only needed for the reference packet tool)

The repository keeps Atmosphere-libs, ZeroTierOne and libultrahand as Git
submodules. From a fresh clone, initialize them with:

```sh
git clone --recurse-submodules <your-sys-zerotier-repository>
cd sys-zerotier
```

For an existing checkout:

```sh
git submodule sync --recursive
git submodule update --init --recursive
```

If devkitPro is installed somewhere other than `/opt/devkitpro`, export its
location before building. Otherwise load the standard environment:

```sh
source /opt/devkitpro/switchvars.sh
```

## Build the release archive

Build the ZeroTier core first. This produces the static `libztcore.a` used by
the sysmodule:

```sh
make zt-core
```

Then build and package everything:

```sh
make bundle
```

If the portlibs are in a non-standard location, pass their Switch include/lib
directory explicitly, for example:

```sh
make zt-core
make bundle PORTLIBS=/opt/devkitpro/portlibs/switch
```

The finished archive is:

```text
dist/sys-zerotier.zip
```

`make bundle` builds both components and places these files in the archive:

```text
atmosphere/contents/4200000000005A54/exefs.nsp
atmosphere/contents/4200000000005A54/flags/boot2.flag
switch/.overlays/sys-zerotier.ovl
licenses/sys-zerotier/MiniUPnPc.txt
licenses/sys-zerotier/libnatpmp.txt
```

Extract the archive at the root of the Switch SD card. The sysmodule creates
its runtime configuration under `/config/sys-zerotier/` on first start.

## Network configuration

Saved networks belong in `/config/sys-zerotier/networks.ini`:

```ini
[Friends]
nwid = 0123456789abcdef

[Tournament]
nwid = fedcba9876543210
```

Open `sys-zerotier.ovl` from Ultrahand/Tesla to select a saved network or enter
a complete 16-digit network ID. Changes are applied while the console is
running; switch networks before opening a game's LAN room so fresh virtual
sockets are created.

The generated `config.ini` enables the sysmodule, BSD MITM and NIFM MITM by
default. Existing explicit settings are preserved. Detailed packet/service
logging is off by default and can be enabled from the overlay while diagnosing
a compatibility issue.

Router mapping is enabled by default. Set `port_mapping = 0` in `config.ini`
and reboot to disable it. It tries finite NAT-PMP/UPnP UDP leases on the
physical router; it cannot bypass carrier-grade NAT or a UDP-blocking firewall.
See [lifecycle/NAT validation](LIFECYCLE_NAT_TESTING.md) for test steps and limits.

## Tests and diagnostics

The VNet tests run on the host and do not require a Switch toolchain:

```sh
make -C tests
python3 tests/reference.py
```

To compile the packet shim for aarch64 as an additional check:

```sh
make -C tests cross
```

To check which system headers the ZeroTier core can see through devkitA64:

```sh
make -f zt-core.mk probe
```

On hardware, the most useful files are `boot.log`, `status.txt` and
`uplink.log`. Enable detailed logging only for a reproduction and collect
`bsd.log` and `nifm.log` as well.

## Cleaning generated files

```sh
make clean
make zt-core-clean
make overlay-clean
```

These commands remove only generated build products. They do not touch source
files, configuration on the Switch, or Git submodule history.
