#---------------------------------------------------------------------------------
# Where this makefile lives. Must be computed before any include, or
# MAKEFILE_LIST points at the last included file instead of this one.
#---------------------------------------------------------------------------------
SZT_DIR := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

#---------------------------------------------------------------------------------
# pull in common stratosphere sysmodule configuration
#---------------------------------------------------------------------------------
# Atmosphere-libs lives inside the project (ldn_mitm keeps it one level up as
# a sibling submodule; we don't need that layout).
AMS_LIBS ?= $(SZT_DIR)Atmosphere-libs
include $(AMS_LIBS)/config/templates/stratosphere.mk

#---------------------------------------------------------------------------------
# version control constants
#---------------------------------------------------------------------------------
TARGET_VERSION := $(shell git describe --tags --dirty 2>/dev/null || echo v0.1.0-dev)

#---------------------------------------------------------------------------------
# options for code generation
#---------------------------------------------------------------------------------
VERSION_DEFINES	:= -DGITDESCVER="\"${TARGET_VERSION}\""


CFLAGS		+= $(VERSION_DEFINES)
CXXFLAGS	+= $(VERSION_DEFINES)

#---------------------------------------------------------------------------------
# no real need to edit anything past this point unless you need to add additional
# rules for different file extensions
#---------------------------------------------------------------------------------
ifneq ($(BUILD),$(notdir $(CURDIR)))
#---------------------------------------------------------------------------------

export OUTPUT	:=	$(CURDIR)/$(TARGET)
export TOPDIR	:=	$(CURDIR)

export VPATH	:=	$(foreach dir,$(SOURCES),$(CURDIR)/$(dir)) \
			$(foreach dir,$(DATA),$(CURDIR)/$(dir))

export DEPSDIR	:=	$(CURDIR)/$(BUILD)


CFILES      :=	$(foreach dir,$(SOURCES),$(filter-out $(notdir $(wildcard $(dir)/*.arch.*.c)) $(notdir $(wildcard $(dir)/*.board.*.c)) $(notdir $(wildcard $(dir)/*.os.*.c)), \
                                                      $(notdir $(wildcard $(dir)/*.c))))
CFILES      +=  $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.arch.$(ATMOSPHERE_ARCH_NAME).c)))
CFILES      +=  $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.board.$(ATMOSPHERE_BOARD_NAME).c)))
CFILES      +=  $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.os.$(ATMOSPHERE_OS_NAME).c)))

CPPFILES    :=	$(foreach dir,$(SOURCES),$(filter-out $(notdir $(wildcard $(dir)/*.arch.*.cpp)) $(notdir $(wildcard $(dir)/*.board.*.cpp)) $(notdir $(wildcard $(dir)/*.os.*.cpp)), \
                                                      $(notdir $(wildcard $(dir)/*.cpp))))
CPPFILES    +=  $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.arch.$(ATMOSPHERE_ARCH_NAME).cpp)))
CPPFILES    +=  $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.board.$(ATMOSPHERE_BOARD_NAME).cpp)))
CPPFILES    +=  $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.os.$(ATMOSPHERE_OS_NAME).cpp)))

SFILES      :=	$(foreach dir,$(SOURCES),$(filter-out $(notdir $(wildcard $(dir)/*.arch.*.s)) $(notdir $(wildcard $(dir)/*.board.*.s)) $(notdir $(wildcard $(dir)/*.os.*.s)), \
                                                      $(notdir $(wildcard $(dir)/*.s))))
SFILES      +=  $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.arch.$(ATMOSPHERE_ARCH_NAME).s)))
SFILES      +=  $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.board.$(ATMOSPHERE_BOARD_NAME).s)))
SFILES      +=  $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.os.$(ATMOSPHERE_OS_NAME).s)))

BINFILES	:=	$(foreach dir,$(DATA),$(notdir $(wildcard $(dir)/*.*)))

#---------------------------------------------------------------------------------
# use CXX for linking C++ projects, CC for standard C
#---------------------------------------------------------------------------------
ifeq ($(strip $(CPPFILES)),)
#---------------------------------------------------------------------------------
	export LD	:=	$(CC)
#---------------------------------------------------------------------------------
else
#---------------------------------------------------------------------------------
	export LD	:=	$(CXX)
#---------------------------------------------------------------------------------
endif
#---------------------------------------------------------------------------------

export OFILES	:=	$(addsuffix .o,$(BINFILES)) \
			$(CPPFILES:.cpp=.o) $(CFILES:.c=.o) $(SFILES:.s=.o)

export INCLUDE	:=	$(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
			$(foreach dir,$(LIBDIRS),-I$(dir)/include) \
			$(foreach dir,$(AMS_LIBDIRS),-I$(dir)/include) \
			-I$(CURDIR)/$(BUILD)

export LIBPATHS	:=	$(foreach dir,$(LIBDIRS),-L$(dir)/lib) \
					$(foreach dir,$(AMS_LIBDIRS),-L$(dir)/lib) \
					$(foreach dir,$(AMS_LIBDIRS),-L$(dir)/$(ATMOSPHERE_LIBRARY_DIR))

export BUILD_EXEFS_SRC := $(TOPDIR)/$(EXEFS_SRC)

export APP_JSON := $(TOPDIR)/res/app.json

.PHONY: $(BUILD) clean all

#---------------------------------------------------------------------------------
all: $(BUILD)

$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

#---------------------------------------------------------------------------------
clean:
	@echo clean ...
	@rm -fr $(BUILD) $(TARGET).kip $(TARGET).elf $(TARGET).nso $(TARGET).npdm $(TARGET).nsp

#---------------------------------------------------------------------------------
else
.PHONY:	all

DEPENDS	:=	$(OFILES:.o=.d)

#---------------------------------------------------------------------------------
# main targets
#---------------------------------------------------------------------------------
all: $(OUTPUT).nsp

$(OUTPUT).kip :	$(OUTPUT).elf
$(OUTPUT).nsp :	$(OUTPUT).nso $(OUTPUT).npdm
$(OUTPUT).nso :	$(OUTPUT).elf

$(OUTPUT).elf :	$(OFILES) $(SZT_DIR)build-ztcore/libztcore.a

$(OFILES) : $(ATMOSPHERE_LIBRARIES_DIR)/libstratosphere/$(ATMOSPHERE_LIBRARY_DIR)/libstratosphere.a

%.npdm  :   %.npdm.json
	@echo built ... $< $@
	@npdmtool $< $@
	@echo built ... $(notdir $@)

#---------------------------------------------------------------------------------
# you need a rule like this for each extension you use as binary data
#---------------------------------------------------------------------------------
%.bin.o	:	%.bin
#---------------------------------------------------------------------------------
	@echo $(notdir $<)
	@$(bin2o)

-include $(DEPENDS)

#---------------------------------------------------------------------------------------
endif
#---------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------
# sys-zerotier additions
#
# The ZeroTier core is built separately into libztcore.a by zt-core.mk rather
# than being folded into SOURCES. The stratosphere template builds VPATH as
# $(CURDIR)/$(dir), so an out-of-tree absolute path does not work, and node/
# needs its own flags (-march=armv8-a+crypto, its own include roots, and one
# file excluded). A static library keeps both problems in one place.
#
#   make zt-core     build libztcore.a from $(ZT_ROOT)
#   make             build the sysmodule and link against it
#
# Only node/ is used (MPL-2.0). Do NOT add libzt: it is BSL-1.1. See PORTING.md.
#---------------------------------------------------------------------------------
# Prefer an in-project checkout, fall back to a sibling. SZT_DIR is set at the
# top of this file; CURDIR is unusable here because the devkitPro template
# re-invokes make from a build/ subdir.
ifneq ($(wildcard $(SZT_DIR)ZeroTierOne/node),)
ZT_ROOT     ?= $(SZT_DIR)ZeroTierOne
else
ZT_ROOT     ?= $(SZT_DIR)../ZeroTierOne
endif
ZT_LIBDIR   := $(SZT_DIR)build-ztcore

SOURCES     += source/net source/mitm
INCLUDES    += source
CXXFLAGS    += -I$(ZT_ROOT) -I$(ZT_ROOT)/include
LIBS        += -L$(ZT_LIBDIR) -lztcore
# libztcore is a static archive and itself depends on libstratosphere/libnx.
# Repeat those archives after it so the one-pass static linker can satisfy the
# symbols it introduces (the template adds them before project libraries).
LIBS        += -lstratosphere -lnx
# Both libstratosphere and the ZeroTier core are static archives with circular
# references. A group makes archive extraction reach a fixed point.
LIBS        += -Wl,--start-group -lztcore -lstratosphere -lnx -Wl,--end-group

# The core is already built with -ffunction-sections -fdata-sections (see
# zt-core.mk), but nothing was discarding the unreferenced ones. This module
# calls a narrow slice of ZeroTier -- no TCP fallback, no cluster, no
# controller -- so let the linker drop the rest. Also applies to the parts of
# libstratosphere we never touch.
#
# If the module ever builds but misbehaves in a way that makes no sense, this
# is the first line to comment out: --gc-sections is the one change here that
# can remove something the linker script should have kept.
CXXFLAGS    += -ffunction-sections -fdata-sections
LDFLAGS     += -Wl,--gc-sections

# SOURCES is extended below the template's original C++/C linker selection,
# after it has already evaluated CPPFILES. This is a C++ sysmodule and must
# link through the cross C++ driver (for libstdc++ and the exception wrappers),
# never the host `ld`.
export LD := $(CXX)

.PHONY: zt-core zt-core-clean overlay-build overlay-clean

zt-core:
	@$(MAKE) -f $(SZT_DIR)zt-core.mk OUTDIR=$(ZT_LIBDIR)

zt-core-clean:
	@rm -rf $(ZT_LIBDIR)

overlay-build:
	@$(MAKE) -C $(SZT_DIR)overlay

overlay-clean:
	@$(MAKE) -C $(SZT_DIR)overlay clean

# This project carries a small libstratosphere patch for BSD MITM fallback and
# framework-level HIPC tracing.  Atmosphere's installed archive is otherwise an
# opaque input to this Makefile, so source edits used to leave a stale archive
# linked into an apparently successful package.  Track the patched files
# explicitly and rebuild the local release archive before compiling dependants.
STRATOSPHERE_ARCHIVE := $(ATMOSPHERE_LIBRARIES_DIR)/libstratosphere/$(ATMOSPHERE_LIBRARY_DIR)/libstratosphere.a
STRATOSPHERE_PATCH_SOURCES := \
	$(SZT_DIR)Atmosphere-libs/libstratosphere/include/stratosphere/sf/hipc/sf_hipc_server_session_manager.hpp \
	$(SZT_DIR)Atmosphere-libs/libstratosphere/source/sf/cmif/sf_cmif_service_dispatch.cpp \
	$(SZT_DIR)Atmosphere-libs/libstratosphere/source/sf/hipc/sf_hipc_server_session_manager.cpp

$(STRATOSPHERE_ARCHIVE): $(STRATOSPHERE_PATCH_SOURCES)
	@$(MAKE) -C $(SZT_DIR)Atmosphere-libs/libstratosphere nx_release

# The template normally exports OFILES from the outer make into its recursive
# build invocation. Declare this project's five C++ objects here as well so a
# direct/recovered build from build/ cannot accidentally link only archives.
ifeq ($(BUILD),$(notdir $(CURDIR)))
$(OUTPUT).elf : main.o zt_port.o vnet.o bsd_shim.o nifm_shim.o nat_mapper.o
endif

# Produce an SD-root package containing only the sysmodule. The analyzed
# Splatoon 3 startup workaround remains in exefs/ for optional/manual use, but
# is deliberately excluded from the default test artifact.
ifneq ($(BUILD),$(notdir $(CURDIR)))
BUNDLE_ROOT    := $(SZT_DIR)dist/sys-zerotier-base
BUNDLE_ARCHIVE := $(SZT_DIR)dist/sys-zerotier.zip

.PHONY: bundle
bundle: all overlay-build
	@rm -rf $(BUNDLE_ROOT)
	@mkdir -p $(BUNDLE_ROOT)/atmosphere/contents/4200000000005A54/flags
	@cp -f $(SZT_DIR)sys-zerotier.nsp $(BUNDLE_ROOT)/atmosphere/contents/4200000000005A54/exefs.nsp
	@touch $(BUNDLE_ROOT)/atmosphere/contents/4200000000005A54/flags/boot2.flag
	@mkdir -p $(BUNDLE_ROOT)/switch/.overlays
	@cp -f $(SZT_DIR)overlay/sys-zerotier.ovl $(BUNDLE_ROOT)/switch/.overlays/sys-zerotier.ovl
	@mkdir -p $(BUNDLE_ROOT)/licenses/sys-zerotier
	@cp $(ZT_ROOT)/ext/miniupnpc/LICENSE $(BUNDLE_ROOT)/licenses/sys-zerotier/MiniUPnPc.txt
	@cp $(ZT_ROOT)/ext/libnatpmp/LICENSE $(BUNDLE_ROOT)/licenses/sys-zerotier/libnatpmp.txt
	@mkdir -p $(SZT_DIR)dist
	@bsdtar -a -cf $(BUNDLE_ARCHIVE) -C $(BUNDLE_ROOT) atmosphere switch licenses
	@echo built ... $(BUNDLE_ARCHIVE)
endif
