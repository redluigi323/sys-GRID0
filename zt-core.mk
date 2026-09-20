# Build ZeroTier's platform-independent core (node/) into a static library for
# aarch64 / Horizon.
#
#   make -f zt-core.mk ZT_ROOT=../ZeroTierOne OUTDIR=build-ztcore
#
# Verified: all 31 of these translation units compile clean with these flags
# using a generic aarch64 GCC 13.3. They have NOT yet been compiled with
# devkitA64, which is the one difference that still has to be proven -- see
# PORTING.md section 3 for the three source edits needed first.

# Everything resolves relative to THIS makefile, not to CURDIR: the parent
# Makefile is a devkitPro template that re-invokes make from a build/ subdir,
# which silently turned ZT_ROOT into a path with no sources in it.
THIS_DIR   := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
# Prefer a checkout inside the project; fall back to a sibling. Override with
# ZT_ROOT=... if you keep it somewhere else entirely.
ifneq ($(wildcard $(THIS_DIR)ZeroTierOne/node),)
ZT_ROOT    ?= $(THIS_DIR)ZeroTierOne
else
ZT_ROOT    ?= $(THIS_DIR)../ZeroTierOne
endif
OUTDIR     ?= $(THIS_DIR)build-ztcore
COMPAT_DIR ?= $(THIS_DIR)compat

ifeq ($(strip $(DEVKITPRO)),)
  $(error DEVKITPRO is not set; source the devkitPro environment first)
endif

DKA64 := $(DEVKITPRO)/devkitA64

CXX := $(DKA64)/bin/aarch64-none-elf-g++
CC  := $(DKA64)/bin/aarch64-none-elf-gcc
AR  := $(DKA64)/bin/aarch64-none-elf-gcc-ar

# This makefile compiles outside the devkitPro template, so nothing adds the
# Switch include paths or the toolchain's arch flags for us.
#
# The arch flags are copied from Atmosphere-libs
# (config/arch/arm64/cpu/cortex_a57/cpu.mk and arch/arm64/arch.mk). They are not
# cosmetic: -mtp=soft and -fPIE have to match the sysmodule these objects link
# into, or you get a link that succeeds and a module that does not run.
ARCH := -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIE

SWITCH_INCLUDES := -I$(DEVKITPRO)/libnx/include \
                   -I$(DEVKITPRO)/portlibs/switch/include \
                   -I$(DKA64)/aarch64-none-elf/include

# -march=armv8-a+crypto is not optional: it is what makes AES_armcrypto.cpp
# reachable, and hardware AES-GMAC versus a software one is the difference
# between a rounding error and a visible chunk of the system core.
#
# ZT_NO_PEER_METRICS drops the prometheus include chain, which is the only
# thing in node/ that reaches into ext/.
# compat/ must come first on the include path: it replaces the bundled
# prometheus-cpp-lite with stubs. Without it the core needs RTTI (the real
# library uses dynamic_cast) and hauls a metrics registry into a sysmodule that
# nothing will ever scrape. See compat/prometheus/simpleapi.h.
CXXFLAGS := -std=gnu++17 -O2 -g $(ARCH) \
            -fexceptions -fno-rtti -ffunction-sections -fdata-sections \
            -MMD -MP \
            -DZT_NO_PEER_METRICS=1 -DZT_SOFTWARE_UPDATE_DEFAULT='"disable"' \
            -D__SWITCH__ -DATMOSPHERE_OS_HORIZON -DATMOSPHERE_ARCH_ARM64 \
            -D__UNIX_LIKE__ \
            -I$(COMPAT_DIR) \
            -I$(ZT_ROOT) -I$(ZT_ROOT)/include -isystem $(ZT_ROOT)/ext \
            $(SWITCH_INCLUDES)

# Every .cpp in node/ except the x86-only AES path.
SRCS := $(filter-out %/AES_aesni.cpp,$(wildcard $(ZT_ROOT)/node/*.cpp))
.DEFAULT_GOAL := $(OUTDIR)/libztcore.a

OBJS := $(patsubst $(ZT_ROOT)/node/%.cpp,$(OUTDIR)/%.o,$(SRCS))

# Our replacement for the handful of osdep/OSUtils.cpp functions node/ calls.
OBJS += $(OUTDIR)/ZtOSUtilsSwitch.o

# Upstream's BSD-licensed router-mapping dependencies, without desktop
# discovery daemons or platform gateway enumeration. Horizon supplies gateway
# information through NIFM instead.
UPNP_NAMES := igd_desc_parse minisoap minissdpc miniupnpc miniwget minixml portlistingparse upnpcommands upnpdev upnperrors upnpreplyparse
OBJS += $(addprefix $(OUTDIR)/upnp_,$(addsuffix .o,$(UPNP_NAMES))) $(OUTDIR)/natpmp.o $(OUTDIR)/nat_support.o
NAT_CFLAGS := -O2 -g $(ARCH) -ffunction-sections -fdata-sections -MMD -MP \
              -D__SWITCH__ -DNEED_STRUCT_IP_MREQN -DMINIUPNPC_SET_SOCKET_TIMEOUT \
              -DOS_STRING='"Horizon"' -DMINIUPNPC_VERSION_STRING='"2.0.20171212"' \
              -DUPNP_VERSION_STRING='"UPnP/1.1"' -I$(COMPAT_DIR)/nat $(SWITCH_INCLUDES)

$(OUTDIR)/upnp_%.o: $(ZT_ROOT)/ext/miniupnpc/%.c
	@mkdir -p $(OUTDIR)
	@$(CC) $(NAT_CFLAGS) -include $(COMPAT_DIR)/nat/platform.h -c $< -o $@

$(OUTDIR)/natpmp.o: $(ZT_ROOT)/ext/libnatpmp/natpmp.c
	@mkdir -p $(OUTDIR)
	@$(CC) $(NAT_CFLAGS) -include arpa/inet.h -Drecvfrom=ztnx_nat_recvfrom -c $< -o $@

$(OUTDIR)/nat_support.o: $(COMPAT_DIR)/nat/support.c
	@mkdir -p $(OUTDIR)
	@$(CC) $(NAT_CFLAGS) -c $< -o $@

$(OUTDIR)/ZtOSUtilsSwitch.o: $(COMPAT_DIR)/ZtOSUtilsSwitch.cpp
	@mkdir -p $(OUTDIR)
	@echo "  CXX $(notdir $<)"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

# Never silently produce an empty archive again.
ifeq ($(strip $(SRCS)),)
$(error No .cpp files under $(ZT_ROOT)/node -- check ZT_ROOT)
endif

# Header dependencies. Without these, editing include/ZeroTierOne.h rebuilds
# nothing: only the .cpp timestamps are consulted, so a change to the array
# limits that size NetworkConfig silently kept the old 475 KB objects and the
# archive was rebuilt from stale members. That cost a boot cycle to notice.
DEPS := $(OBJS:.o=.d)
-include $(DEPS)

# Compiler flags and selected compatibility sources are part of the build.
$(OBJS): $(THIS_DIR)zt-core.mk

$(OUTDIR)/libztcore.a: $(OBJS)
	@$(RM) $@
	@$(AR) rcs $@ $^
	@echo "built $@ ($(words $(OBJS)) objects)"

$(OUTDIR)/%.o: $(ZT_ROOT)/node/%.cpp
	@mkdir -p $(OUTDIR)
	@echo "  CXX $(notdir $<)"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(OUTDIR)

# ---------------------------------------------------------------------------
# make -f zt-core.mk probe
#
# ZeroTier's core includes a handful of headers that a hosted libc has and
# newlib may not. This says which ones are missing in one go, instead of
# finding out one failed compile at a time. Anything listed needs a shim in
# compat/ (see compat/endian.h for the pattern).
# ---------------------------------------------------------------------------
PROBE_HEADERS := endian.h sys/endian.h machine/endian.h sys/param.h sys/uio.h \
                 sys/socket.h sys/stat.h sys/types.h netinet/in.h arpa/inet.h \
                 dirent.h fcntl.h unistd.h pthread.h errno.h time.h math.h

.PHONY: probe
probe:
	@echo "probing $(CXX)"
	@for h in $(PROBE_HEADERS); do \
		if echo "#include <$$h>" | $(CXX) $(CXXFLAGS) -x c++ -fsyntax-only - >/dev/null 2>&1; then \
			printf "  ok      %s\n" "$$h"; \
		else \
			printf "  MISSING %s\n" "$$h"; \
		fi; \
	done

# WHY -D__UNIX_LIKE__
#
# node/Mutex.hpp defines class Mutex only under __UNIX_LIKE__ or __WINDOWS__.
# Constants.hpp derives __UNIX_LIKE__ from __linux__/__APPLE__/BSD and friends,
# so on Horizon it is neither -- and ZeroTier's most-used type simply does not
# exist. Every "'Mutex' does not name a type" error across Trace, Network,
# Peer, Topology and Switch traces back to that one line.
#
# newlib gives us the pthread_mutex_* functions Mutex.hpp wants, so declaring
# ourselves UNIX-like is honest here rather than a workaround. The paths this
# also switches on (the /dev/urandom read in Utils.cpp, <sys/uio.h>) are
# already handled by patches/0001-horizon-port.patch and compat/.
