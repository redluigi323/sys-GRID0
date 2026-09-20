/*
 * sys-zerotier -- Horizon OS port layer for the ZeroTier core.
 *
 * NOT YET COMPILED. See README.md.
 */
#include "zt_port.hpp"
#include "mitm/bsd_shim.hpp"
#include "nat_mapper.hpp"

#include <stratosphere.hpp>

/* os::, fs::, R_ABORT_UNLESS and friends all live in namespace ams. */
using namespace ams;

/* BSD socket calls are written ::qualified throughout this file. libvapours
 * declares a result-module namespace called ams::socket, which makes a bare
 * ::socket() ambiguous once ams is in scope. */

extern "C" {
#include <switch.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
}

#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace ztnx {

    namespace {

        /* Outbound frame queue: the shim produces frames on whichever thread
         * the game's socket call arrived on, and the node thread consumes them.
         * Bounded, and it drops rather than blocks -- a stalled game is worse
         * than a lost datagram. */
        /* A browse reply can fan out to several matching listeners and emit
         * ARP/IPv4 frames back-to-back. Eight entries were enough for a single
         * peer but dropped bursts during Switch-host discovery. Keep this
         * bounded at 32 entries; the extra ~64 KiB is cheaper than losing a
         * lobby packet and remains far below the module's available margin. */
        constexpr size_t FrameQueueDepth = 32;
        constexpr size_t MaxFrameLen     = net::MaxFrame;

        struct QueuedFrame {
            uint64_t     dstMac;
            uint16_t     etherType;
            unsigned int len;
            uint8_t      data[MaxFrameLen];
        };

        QueuedFrame  g_frames[FrameQueueDepth];
        size_t       g_head = 0, g_tail = 0;
        os::SdkMutex g_frameLock;

        /* Map a ZT_StateObjectType + id pair to a file name, matching the
         * layout OneService uses on desktop so an identity can be moved between
         * a PC and the console by hand. */
        bool StatePath(char *out, size_t outlen, enum ZT_StateObjectType type,
                       const uint64_t id[2])
        {
            switch (type) {
                case ZT_STATE_OBJECT_IDENTITY_PUBLIC:
                    std::snprintf(out, outlen, "%s/identity.public", StateRoot); return true;
                case ZT_STATE_OBJECT_IDENTITY_SECRET:
                    std::snprintf(out, outlen, "%s/identity.secret", StateRoot); return true;
                case ZT_STATE_OBJECT_PLANET:
                    std::snprintf(out, outlen, "%s/planet", StateRoot); return true;
                case ZT_STATE_OBJECT_NETWORK_CONFIG:
                    std::snprintf(out, outlen, "%s/networks.d/%.16llx.conf", StateRoot,
                                  (unsigned long long)id[0]); return true;
                case ZT_STATE_OBJECT_PEER:
                    std::snprintf(out, outlen, "%s/peers.d/%.10llx.peer", StateRoot,
                                  (unsigned long long)id[0]); return true;
                default:
                    return false;
            }
        }

    }  // namespace

    /* What Node::Node's single malloc needs, measured from the DWARF in
     * sys-zerotier.elf after ZT_RX_QUEUE_SIZE was cut to 4:
     *
     *   Trace 64 + Switch ~281 KB + Multicaster 48 + Topology 968 +
     *   SelfAwareness 48 + Bond 15960 + PacketMultiplexer 144, each rounded
     *   up to 16, plus 16 for alignment slack.
     *
     * Rounded up and given room to move if a ZeroTier update grows a member.
     * If this trips, the fix is MallocBufferSize, not this number. */
    constexpr size_t NodeAllocLowWater = 384 * 1024;

    int64_t NowMs()
    {
        /* Wall-clock milliseconds, anchored ONCE and advanced by the monotonic
         * tick thereafter.
         *
         * The previous version returned
         *
         *     wall_seconds * 1000 + (tick_milliseconds % 1000)
         *
         * which is not monotonic and is not even close. Those two counters roll
         * over at unrelated phases: the wall-clock second boundary has nothing
         * to do with where the 19.2 MHz tick happens to sit in its own 1000 ms
         * cycle. Simulated over three seconds of real time it steps BACKWARDS
         * three times, by up to 999 ms each -- once per second, forever.
         *
         * ZeroTier times everything from this: path liveness, packet dedup and
         * expiry windows, credential validity, background-task deadlines. A
         * clock that lurches a second into the past every second is not a
         * rounding error, it is a peer that never establishes a path -- which
         * is precisely what `zerotier-cli peers` reported: latency -1, RELAY,
         * never a single round trip.
         *
         * timeInitialize() must still have succeeded and the console must still
         * have a plausible clock; see PORTING.md 3.3. But it is read once, for
         * the epoch, and never again. */
        static int64_t s_anchorMs   = 0;
        static u64     s_anchorTick = 0;

        const u64 ticks = armGetSystemTick();

        if (s_anchorMs == 0) {
            u64 seconds = 0;
            if (R_FAILED(timeGetCurrentTime(TimeType_Default, std::addressof(seconds)))) {
                return 0;   /* no epoch yet; caller retries */
            }
            s_anchorMs   = (int64_t)seconds * 1000;
            s_anchorTick = ticks;
            return s_anchorMs;
        }

        /* 19200 ticks per millisecond. The subtraction is done in ticks so the
         * division never straddles the anchor. */
        return s_anchorMs + (int64_t)((ticks - s_anchorTick) / 19200);
    }

    /* ---- ZeroTier's 2 MB identity scratch buffer -------------------------
     *
     * _computeMemoryHardHash() wants ZT_IDENTITY_GEN_MEMORY of scratch. It runs
     * during local identity validation/generation and when previously unseen
     * peer identities are validated.
     *
     * As .bss that was 2 MB resident forever, out of a SYSTEM resource limit
     * group that Atmosphere can only grow by 14 MB total on HOS 20.0.0+. It is
     * why am was aborting at boot with svc::ResultLimitReached.
     *
     * The process heap is charged only while it is mapped, so take it there and
     * give it straight back. Local validation now runs during early boot,
     * before a title can consume the narrow shared-System margin; the old
     * 20-second startup delay let that margin fall below the required 2 MB.
     *
     * 2 MB is exactly os::MemoryHeapUnitSize and os::MemoryBlockUnitSize, so
     * both alignment assertions are satisfied by construction. */
    namespace {
        constexpr size_t GenMemSize   = 2_MB;
        uintptr_t        g_genmemAddr = 0;
        int              g_genmemFails = 0;
    }

    extern "C" char *ztnx_genmem_alloc(void)
    {
        /* Neither ZeroTier call site checks the return, so handing back null
         * would be a 2 MB memset from address zero -- the exact Data Abort this
         * whole path was introduced to fix. Wait for the memory instead;
         * nothing on the node thread is time-critical. */
        for (;;) {
            if (R_SUCCEEDED(os::SetMemoryHeapSize(GenMemSize)) &&
                R_SUCCEEDED(os::AllocateMemoryBlock(std::addressof(g_genmemAddr), GenMemSize))) {
                Trace("genmem: mapped %u KB", (unsigned)(GenMemSize / 1024));
                return reinterpret_cast<char *>(g_genmemAddr);
            }

            g_genmemAddr = 0;
            (void)os::SetMemoryHeapSize(0);
            if (g_genmemFails++ < 3) {
                Trace("genmem: %u KB unavailable, retrying in 3s", (unsigned)(GenMemSize / 1024));
            }
            os::SleepThread(TimeSpan::FromSeconds(3));
        }
    }

    extern "C" void ztnx_genmem_free(char *p)
    {
        if (g_genmemAddr == 0 || reinterpret_cast<uintptr_t>(p) != g_genmemAddr) { return; }

        os::FreeMemoryBlock(g_genmemAddr, GenMemSize);
        g_genmemAddr = 0;

        /* Shrinking the heap back to zero is what actually returns the pages to
         * the SYSTEM resource limit. Without this the 2 MB stays charged and
         * the whole exercise buys nothing. */
        (void)os::SetMemoryHeapSize(0);
        Trace("genmem: released");
    }

    /* How much of the fixed malloc arena ZeroTier really uses. Traced only when
     * the low-water mark drops by a further 256 KB, so it costs at most a dozen
     * lines in boot.log however long the module runs -- and it is what tells us
     * whether MallocBufferSize can come down from 3 MB. */
    void TraceArenaWatermark()
    {
        static size_t s_low = ~size_t(0);

        auto *allocator = ams::init::GetAllocator();
        if (allocator == nullptr) { return; }

        const size_t freeNow    = allocator->GetTotalFreeSize();
        const size_t largestNow = allocator->GetAllocatableSize();
        if (freeNow + 256_KB > s_low) { return; }

        s_low = freeNow;
        Trace("arena: %u KB free, %u KB largest (low-water)",
              (unsigned)(freeNow / 1024), (unsigned)(largestNow / 1024));
    }

    void SecureRandom(void *buf, size_t len)
    {
        /* csrngInitialize() once at startup. This is the hardware CSPRNG; it is
         * what replaces the core's /dev/urandom read. */
        R_ABORT_UNLESS(csrngGetRandomBytes(buf, len));
    }

    namespace {

        /* The generated template is roughly 2.4 KiB. The former 1 KiB local
         * buffers rejected that very file, so a fresh install could create
         * config.ini and then never read its nwid. Leave room for Ultrahand to
         * append the section while migrating an older flat config. */
        constexpr size_t ConfigFileCapacity = 4096;

        /* CreateDirectory on a path that already exists is success here. */
        bool EnsureDir(const char *path)
        {
            const ams::Result r = fs::CreateDirectory(path);
            return R_SUCCEEDED(r) || fs::ResultPathAlreadyExists::Includes(r);
        }

        bool ReadWholeFile(const char *path, char *buf, size_t bufLen, size_t *outLen)
        {
            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Read))) { return false; }
            ON_SCOPE_EXIT { fs::CloseFile(f); };

            s64 size = 0;
            if (R_FAILED(fs::GetFileSize(std::addressof(size), f))) { return false; }
            if (size < 0 || (size_t)size >= bufLen) { return false; }
            if (R_FAILED(fs::ReadFile(f, 0, buf, (size_t)size))) { return false; }

            buf[size] = '\0';
            *outLen = (size_t)size;
            return true;
        }

        /* Counts failures rather than swallowing them. A log that silently
         * stops recording is indistinguishable from a program that silently
         * stops running, and we have now spent three captures on exactly that
         * ambiguity. */
        unsigned g_writeFails = 0;

        bool WriteWholeFile(const char *path, const char *text)
        {
            const size_t len = std::strlen(text);
            (void)fs::DeleteFile(path);
            if (R_FAILED(fs::CreateFile(path, (s64)len))) { ++g_writeFails; return false; }

            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Write))) {
                ++g_writeFails;
                return false;
            }
            ON_SCOPE_EXIT { fs::CloseFile(f); };

            if (R_FAILED(fs::WriteFile(f, 0, text, len, fs::WriteOption::Flush))) {
                ++g_writeFails;
                return false;
            }
            return true;
        }

        /* Looks for a line like `nwid = 8056c2e21c000001`.
         *
         * Parses line by line and skips anything whose first non-blank
         * character is # or ; -- the previous version searched the whole file
         * for "nwid" and only checked the single character before it, so a
         * commented example line parsed as real config and the console spent
         * every boot trying to join a network that does not exist. That is
         * also why ConfigTemplate below carries no example nwid value: with
         * allow_commented set this scanner is reused to detect a real id that
         * the user left commented out, and an example would be a false hit. */
        bool ParseNwid(const char *text, uint64_t *out, bool allow_commented = false)
        {
            bool found = false;
            const char *line = text;
            while (*line) {
                const char *eol = line;
                while (*eol && *eol != '\n') { ++eol; }

                const char *p = line;
                while (p < eol && (*p == ' ' || *p == '\t')) { ++p; }

                /* Skip the comment marker when we are only looking for one, so
                 * the same scanner can answer "is there a commented-out nwid?"
                 * -- which is worth telling the user about explicitly. */
                if (allow_commented) {
                    while (p < eol && (*p == '#' || *p == ';' || *p == ' ' || *p == '\t')) { ++p; }
                }

                if (p < eol && (allow_commented || (*p != '#' && *p != ';')) &&
                    (eol - p) >= 4 && std::strncmp(p, "nwid", 4) == 0) {
                    const char *q = p + 4;
                    while (q < eol && (*q == ' ' || *q == '\t')) { ++q; }
                    if (q < eol && *q == '=') {
                        ++q;
                        while (q < eol && (*q == ' ' || *q == '\t')) { ++q; }

                        uint64_t v = 0;
                        int digits = 0;
                        for (; digits < 16 && q < eol; ++digits, ++q) {
                            const char c = *q;
                            uint64_t d;
                            if (c >= '0' && c <= '9')      { d = (uint64_t)(c - '0'); }
                            else if (c >= 'a' && c <= 'f') { d = (uint64_t)(c - 'a' + 10); }
                            else if (c >= 'A' && c <= 'F') { d = (uint64_t)(c - 'A' + 10); }
                            else { break; }
                            v = (v << 4) | d;
                        }
                        if (digits == 16 && v != 0) {
                            *out = v;
                            found = true;
                        }
                    }
                }

                line = (*eol == '\n') ? (eol + 1) : eol;
            }
            /* Last assignment wins. This matches normal INI behavior and lets
             * the Ultrahand package append a section to an older, flat config
             * without the stale pre-section nwid shadowing the new choice. */
            return found;
        }

        bool ParseConfigString(const char *text, const char *key, char *out, size_t out_len)
        {
            if (out_len == 0) { return false; }
            bool found = false;
            const size_t key_len = std::strlen(key);
            const char *line = text;
            while (*line) {
                const char *eol = line;
                while (*eol && *eol != '\n') { ++eol; }
                const char *p = line;
                while (p < eol && (*p == ' ' || *p == '\t')) { ++p; }
                if (p < eol && *p != '#' && *p != ';' &&
                    static_cast<size_t>(eol - p) >= key_len &&
                    std::strncmp(p, key, key_len) == 0) {
                    const char *q = p + key_len;
                    while (q < eol && (*q == ' ' || *q == '\t')) { ++q; }
                    if (q < eol && *q == '=') {
                        ++q;
                        while (q < eol && (*q == ' ' || *q == '\t')) { ++q; }
                        const char *end = eol;
                        while (end > q && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r')) { --end; }
                        size_t len = static_cast<size_t>(end - q);
                        if (len >= 2 && ((*q == '\'' && end[-1] == '\'') ||
                                         (*q == '"' && end[-1] == '"'))) {
                            ++q;
                            len -= 2;
                        }
                        if (len > 0 && len < out_len) {
                            std::memcpy(out, q, len);
                            out[len] = '\0';
                            found = true;
                        } else {
                            out[0] = '\0';
                            found = false;
                        }
                    }
                }
                line = (*eol == '\n') ? eol + 1 : eol;
            }
            return found;
        }

        bool ParseSavedNetwork(const char *text, const char *wanted, uint64_t *out)
        {
            bool in_section = false;
            const char *line = text;
            while (*line) {
                const char *eol = line;
                while (*eol && *eol != '\n') { ++eol; }
                const char *p = line;
                while (p < eol && (*p == ' ' || *p == '\t')) { ++p; }

                if (p < eol && *p == '[') {
                    const char *close = p + 1;
                    while (close < eol && *close != ']') { ++close; }
                    const size_t wanted_len = std::strlen(wanted);
                    in_section = close < eol &&
                                 static_cast<size_t>(close - (p + 1)) == wanted_len &&
                                 std::strncmp(p + 1, wanted, wanted_len) == 0;
                } else if (in_section && p < eol && *p != '#' && *p != ';' &&
                           static_cast<size_t>(eol - p) >= 4 &&
                           std::strncmp(p, "nwid", 4) == 0) {
                    const char *q = p + 4;
                    while (q < eol && (*q == ' ' || *q == '\t')) { ++q; }
                    if (q < eol && *q == '=') {
                        ++q;
                        while (q < eol && (*q == ' ' || *q == '\t')) { ++q; }
                        uint64_t value = 0;
                        int digits = 0;
                        for (; digits < 16 && q < eol; ++digits, ++q) {
                            const char c = *q;
                            uint64_t d = 0;
                            if (c >= '0' && c <= '9')      { d = static_cast<uint64_t>(c - '0'); }
                            else if (c >= 'a' && c <= 'f') { d = static_cast<uint64_t>(c - 'a' + 10); }
                            else if (c >= 'A' && c <= 'F') { d = static_cast<uint64_t>(c - 'A' + 10); }
                            else { break; }
                            value = (value << 4) | d;
                        }
                        if (digits == 16 && value != 0) {
                            *out = value;
                            return true;
                        }
                        return false;
                    }
                }
                line = (*eol == '\n') ? eol + 1 : eol;
            }
            return false;
        }

        bool ParseFirstSavedNetwork(const char *text, char *name, size_t name_len,
                                    uint64_t *out)
        {
            char section[96] = {};
            char candidate[96] = {};
            uint64_t candidate_nwid = 0;
            int valid_count = 0;
            bool usable_section = false;
            const char *line = text;
            while (*line) {
                const char *eol = line;
                while (*eol && *eol != '\n') { ++eol; }
                const char *p = line;
                while (p < eol && (*p == ' ' || *p == '\t')) { ++p; }

                if (p < eol && *p == '[') {
                    const char *close = p + 1;
                    while (close < eol && *close != ']') { ++close; }
                    const size_t len = static_cast<size_t>(close - (p + 1));
                    usable_section = close < eol && len > 0 && len < sizeof(section);
                    if (usable_section) {
                        std::memcpy(section, p + 1, len);
                        section[len] = '\0';
                        usable_section = std::strcmp(section, "sys-zerotier") != 0;
                    }
                } else if (usable_section && p < eol && *p != '#' && *p != ';' &&
                           static_cast<size_t>(eol - p) >= 4 &&
                           std::strncmp(p, "nwid", 4) == 0) {
                    const char *q = p + 4;
                    while (q < eol && (*q == ' ' || *q == '\t')) { ++q; }
                    if (q < eol && *q == '=') {
                        ++q;
                        while (q < eol && (*q == ' ' || *q == '\t')) { ++q; }
                        uint64_t value = 0;
                        int digits = 0;
                        for (; digits < 16 && q < eol; ++digits, ++q) {
                            const char c = *q;
                            uint64_t d = 0;
                            if (c >= '0' && c <= '9')      { d = static_cast<uint64_t>(c - '0'); }
                            else if (c >= 'a' && c <= 'f') { d = static_cast<uint64_t>(c - 'a' + 10); }
                            else if (c >= 'A' && c <= 'F') { d = static_cast<uint64_t>(c - 'A' + 10); }
                            else { break; }
                            value = (value << 4) | d;
                        }
                        const size_t section_len = std::strlen(section);
                        if (digits == 16 && value != 0 && section_len < name_len) {
                            if (valid_count == 0) {
                                std::memcpy(candidate, section, section_len + 1);
                                candidate_nwid = value;
                            }
                            ++valid_count;
                        }
                    }
                }
                line = (*eol == '\n') ? eol + 1 : eol;
            }
            if (valid_count != 1) { return false; }
            std::memcpy(name, candidate, std::strlen(candidate) + 1);
            *out = candidate_nwid;
            return true;
        }

        /* Resolve the currently requested network without blocking or logging.
         *
         * This is shared by startup and the node-thread watcher. Ultrahand
         * rewrites networks.ini as one small whole-file update, so a failed or
         * incomplete read simply means "try again next poll" rather than
         * "disconnect now". The catalog is read
         * even when config.ini does not exist yet: the overlay can therefore be
         * the first sys-zerotier component that creates configuration on a new
         * install. */
        bool ResolveConfiguredNetworkId(uint64_t *out)
        {
            char config[ConfigFileCapacity] = {};
            char saved[ConfigFileCapacity] = {};
            char selected[96] = {};
            size_t config_len = 0, saved_len = 0;
            const bool have_config = ReadWholeFile(ConfigPath, config, sizeof(config),
                                                   std::addressof(config_len));
            const bool have_saved = ReadWholeFile(SavedNetworksPath, saved, sizeof(saved),
                                                  std::addressof(saved_len));

            bool have_selection = have_saved &&
                ParseConfigString(saved, "selected", selected, sizeof(selected));
            if (!have_selection && have_config) {
                have_selection = ParseConfigString(config, "network", selected,
                                                   sizeof(selected));
            }
            if (have_selection && have_saved &&
                ParseSavedNetwork(saved, selected, out)) {
                return true;
            }

            /* Keep the legacy direct config.ini key as a compatibility path. */
            if (have_config && ParseNwid(config, out)) { return true; }

            /* One valid catalog entry is unambiguous even before a selector
             * exists. This is useful on a clean install and for old packages. */
            return have_saved && ParseFirstSavedNetwork(saved, selected,
                                                        sizeof(selected), out);
        }

        constexpr const char *ConfigTemplate =
            "# sys-zerotier\n"
            "#\n"
            "# Put your ZeroTier network id -- the 16-hex-digit value copied\n"
            "# from ZeroTier Central -- after the '=' on the nwid line below,\n"
            "# or use the sys-zerotier overlay to enter/select one while running.\n"
            "#\n"
            "# Every line starting with '#' or ';' is ignored. If the console\n"
            "# sits at \"waiting for a network id\" with an id that looks set,\n"
            "# check that its line does not start with '#'; boot.log says so\n"
            "# explicitly when that is what happened.\n"
            "#\n"
            "# On first boot the console appears in ZeroTier Central as a new\n"
            "# member and has to be authorised there. Its assigned address then\n"
            "# shows up in status.txt beside this file.\n"
            "\n"
            "[sys-zerotier]\n"
            "network =\n"
            "nwid =\n"
            "bsd_mitm = 1\n"
            "nifm_mitm = 1\n"
            "debug_logging = 0\n"
            "# Try finite UPnP/NAT-PMP UDP mappings on the physical router.\n"
            "port_mapping = 1\n"
            "\n"
            "# Bring-up announcement. The console broadcasts an ICMP echo to the\n"
            "# subnet broadcast address every 5 seconds, so every other member\n"
            "# learns its MAC and address. Until the bsd:u MITM exists this is\n"
            "# the only thing that makes the console transmit at all, and a\n"
            "# member that never transmits is one nobody looks up.\n"
            "#\n"
            "# That needs no configuration. `probe` additionally sends a unicast\n"
            "# echo to one specific member, which exercises address resolution:\n"
            "#\n"
            "# probe = 10.147.17.191\n"
            "\n"
            "# debug_logging writes the detailed bsd.log and nifm.log traces.\n"
            "# Leave it off for normal play; enable it, reboot, reproduce one\n"
            "# problem, then turn it off again. boot.log, status.txt and the\n"
            "# compact uplink.log remain available either way.\n"
            "#\n"
            "# Diagnostics. Each of these switches off one init step so the\n"
            "# service sessions the module holds can be bisected without a\n"
            "# rebuild. All default to 1 (enabled).\n"
            "#\n"
            "# init_time  = 1\n"
            "\n"
            "# Power-state handling. When enabled the module registers with psc so\n"
            "# it can close its socket and stop writing to the SD card before\n"
            "# sleep suspends fs and the network. Without it, sleeping has hung\n"
            "# the console. WITH it, an omm/spsm fatal (2165-0001) appeared that\n"
            "# has not yet been ruled out as ours -- so it is off until proven.\n"
            "#\n"
            "# psc_enable = 0\n"
            "\n"
            "# psc module id, used only when psc_enable = 1.\n"
            "# so it can close its socket and stop writing to the SD card before\n"
            "# sleep suspends fs and the network -- without that, sleeping hangs\n"
            "# the console with no error report and no way back but the power\n"
            "# psc has no id range reserved for third-party modules, so this\n"
            "# number is a guess; boot.log says whether it was accepted. Note\n"
            "# 127 is spsm itself -- try 57-60 or 62-100 before crowding it.\n"
            "#\n"
            "# psc_module_id = 126\n"
            "# init_csrng = 1\n"
            "# init_bsd   = 1\n"
            "# run_node   = 1\n";

    }  // namespace

    namespace {
        std::atomic<bool> g_diagnosticsEnabled{false};
    }

    void SetDiagnosticsEnabled(bool enabled)
    {
        g_diagnosticsEnabled.store(enabled, std::memory_order_release);
    }

    bool DiagnosticsEnabled()
    {
        return g_diagnosticsEnabled.load(std::memory_order_acquire);
    }

    namespace {
        /* Print the name, not just the number.
         *
         * newlib's errno values are NOT Linux's, and I have already reasoned
         * out loud from Linux numbers in this project at least once. Switching
         * on the macros means the toolchain decides, so the log cannot be
         * misread however the libc numbers them. */
        const char *ErrnoName(int e)
        {
            switch (e) {
                case 0:            return "ok";
                case EACCES:       return "EACCES";
                case EAGAIN:       return "EAGAIN";
                case EBADF:        return "EBADF";
                case EINVAL:       return "EINVAL";
                case EIO:          return "EIO";
                case EMSGSIZE:     return "EMSGSIZE";
                case ENOBUFS:      return "ENOBUFS";
                case ENOTSOCK:     return "ENOTSOCK";
                case EPERM:        return "EPERM";
                case EPIPE:        return "EPIPE";
                case ETIMEDOUT:    return "ETIMEDOUT";
                case ECONNREFUSED: return "ECONNREFUSED";
                case ECONNRESET:   return "ECONNRESET";
                case ECONNABORTED: return "ECONNABORTED";
                case ENETDOWN:     return "ENETDOWN";
                case ENETUNREACH:  return "ENETUNREACH";
                case ENOTCONN:     return "ENOTCONN";
                case EALREADY:     return "EALREADY";
                case EINPROGRESS:  return "EINPROGRESS";
                case EHOSTUNREACH: return "EHOSTUNREACH";
#ifdef EDESTADDRREQ
                case EDESTADDRREQ: return "EDESTADDRREQ";
#endif
#ifdef ENETRESET
                case ENETRESET:    return "ENETRESET";
#endif
#ifdef EHOSTDOWN
                case EHOSTDOWN:    return "EHOSTDOWN";
#endif
                default:           return "?";
            }
        }

        const char *NetStatusName(int st)
        {
            switch (st) {
                case ZT_NETWORK_STATUS_REQUESTING_CONFIGURATION: return "requesting-configuration";
                case ZT_NETWORK_STATUS_OK:                       return "ok";
                case ZT_NETWORK_STATUS_ACCESS_DENIED:            return "access-denied (authorise this node in ZeroTier Central)";
                case ZT_NETWORK_STATUS_NOT_FOUND:                return "not-found (check the network id in config.ini)";
                case ZT_NETWORK_STATUS_PORT_ERROR:               return "port-error";
                case ZT_NETWORK_STATUS_CLIENT_TOO_OLD:           return "client-too-old";
                case ZT_NETWORK_STATUS_AUTHENTICATION_REQUIRED:  return "authentication-required";
                default:                                         return "no-config-yet";
            }
        }
    }

    namespace {
        constexpr size_t TraceCapacity = 4096;
        char   g_trace[TraceCapacity];
        size_t g_traceLen = 0;
        bool   g_traceLive = false;   /* true once the SD card is writable */
    }

    void Trace(const char *fmt, ...)
    {
        if (g_traceLen + 128 >= TraceCapacity) { return; }

        /* Prefix each line with the system tick so the gaps are visible --
         * a long pause before a step is as informative as a missing one. */
        const u64 ms = armGetSystemTick() / 19200;
        int n = std::snprintf(g_trace + g_traceLen, TraceCapacity - g_traceLen, "[%6llu] ",
                              (unsigned long long)ms);
        if (n > 0) { g_traceLen += (size_t)n; }

        va_list ap;
        va_start(ap, fmt);
        n = std::vsnprintf(g_trace + g_traceLen, TraceCapacity - g_traceLen, fmt, ap);
        va_end(ap);
        if (n > 0) { g_traceLen += (size_t)n; }

        if (g_traceLen < TraceCapacity - 1) { g_trace[g_traceLen++] = '\n'; }
        g_trace[g_traceLen] = '\0';

        if (g_traceLive) { FlushTrace(); }
    }

    namespace {
        /* A line ring rather than an ever-growing file: bounded memory, and it
         * keeps the END of a session, which is the part that matters when the
         * question is "what happened when the match started". */
        /* At one heartbeat per 30 seconds, 48 entries preserve about 24
         * minutes even before accounting for sparse transition-only periods.
         * That covers the longest validation match while returning 2.25 KiB
         * of always-resident .bss. */
        constexpr int    EventLines  = 48;
        constexpr size_t EventLineLen = 96;
        char   g_events[EventLines][EventLineLen];
        int    g_eventCount = 0;      /* total ever written */
        os::SdkMutex g_eventLock;
    }

    void Event(const char *fmt, ...)
    {
        std::scoped_lock lk(g_eventLock);

        char *dst = g_events[g_eventCount % EventLines];
        int n = std::snprintf(dst, EventLineLen, "[%8llu] ",
                              (unsigned long long)(armGetSystemTick() / 19200));
        if (n < 0 || (size_t)n >= EventLineLen) { n = 0; }

        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(dst + n, EventLineLen - (size_t)n, fmt, ap);
        va_end(ap);

        ++g_eventCount;

        /* Rewrite the whole file. Small, and it happens on transitions and once
         * every 30 s -- not on the packet path. */
        char text[EventLines * EventLineLen + 64];
        size_t off = 0;
        const int first = (g_eventCount > EventLines) ? (g_eventCount - EventLines) : 0;
        for (int i = first; i < g_eventCount && off + EventLineLen + 2 < sizeof(text); ++i) {
            const char *line = g_events[i % EventLines];
            const size_t len = std::strlen(line);
            std::memcpy(text + off, line, len);
            off += len;
            text[off++] = '\n';
        }
        text[off] = '\0';
        WriteWholeFile(UplinkLogPath, text);
    }

    bool WriteTextFile(const char *path, const char *text) { return WriteWholeFile(path, text); }

    bool WriteBinaryFile(const char *path, const void *data, size_t len)
    {
        if (path == nullptr || (data == nullptr && len != 0)) { return false; }
        (void)fs::DeleteFile(path);
        if (R_FAILED(fs::CreateFile(path, static_cast<s64>(len)))) {
            ++g_writeFails;
            return false;
        }

        fs::FileHandle f;
        if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Write))) {
            ++g_writeFails;
            return false;
        }
        ON_SCOPE_EXIT { fs::CloseFile(f); };

        if (R_FAILED(fs::WriteFile(f, 0, data, len, fs::WriteOption::Flush))) {
            ++g_writeFails;
            return false;
        }
        return true;
    }

    void FlushTrace()
    {
        WriteWholeFile(BootLogPath, g_trace);
    }

    bool MountState()
    {
        /* The SD card is not necessarily ready the instant a sysmodule starts,
         * so the caller retries. */
        if (R_FAILED(fs::MountSdCard("sdmc"))) { return false; }

        bool ok = true;
        ok &= EnsureDir("sdmc:/atmosphere/contents/4200000000005A54");
        ok &= EnsureDir(StateRoot);

        char sub[256];
        std::snprintf(sub, sizeof(sub), "%s/networks.d", StateRoot);
        ok &= EnsureDir(sub);
        std::snprintf(sub, sizeof(sub), "%s/peers.d", StateRoot);
        ok &= EnsureDir(sub);

        ok &= EnsureDir("sdmc:/config");
        ok &= EnsureDir(ConfigDir);

        /* Saved network IDs are user data. Create the list once, outside the
         * release package, so extracting an update can never replace it. */
        fs::FileHandle saved_networks;
        if (R_SUCCEEDED(fs::OpenFile(std::addressof(saved_networks), SavedNetworksPath,
                                    fs::OpenMode_Read))) {
            fs::CloseFile(saved_networks);
        } else {
            const ams::Result r = fs::CreateFile(SavedNetworksPath, 0);
            ok &= R_SUCCEEDED(r) || fs::ResultPathAlreadyExists::Includes(r);
        }

        g_traceLive = true;
        Trace("mount: state directories ready (ok=%d)", (int)ok);
        return ok;
    }

    /* Decimal integer form of ConfigFlag. Exists so psc_module_id can be
     * changed from the SD card: the id we register with is a guess (the psc
     * header has no range reserved for third-party modules) and finding a
     * working one should not cost a rebuild each time. */
    int ConfigValue(const char *key, int dflt)
    {
        char buf[ConfigFileCapacity];
        size_t len = 0;
        if (!ReadWholeFile(ConfigPath, buf, sizeof(buf), std::addressof(len))) { return dflt; }

        const size_t klen = std::strlen(key);
        int result = dflt;
        const char *line = buf;
        while (*line) {
            const char *eol = line;
            while (*eol && *eol != '\n') { ++eol; }

            const char *p = line;
            while (p < eol && (*p == ' ' || *p == '\t')) { ++p; }

            if (p < eol && *p != '#' && *p != ';' &&
                (size_t)(eol - p) >= klen && std::strncmp(p, key, klen) == 0) {
                const char *q = p + klen;
                while (q < eol && (*q == ' ' || *q == '\t')) { ++q; }
                if (q < eol && *q == '=') {
                    ++q;
                    while (q < eol && (*q == ' ' || *q == '\t')) { ++q; }

                    int v = 0, digits = 0;
                    for (; q < eol && *q >= '0' && *q <= '9'; ++q, ++digits) {
                        v = v * 10 + (*q - '0');
                    }
                    if (digits > 0) { result = v; }
                }
            }
            line = (*eol == '\n') ? (eol + 1) : eol;
        }
        return result;
    }

    uint32_t ConfigIpv4(const char *key)
    {
        char buf[ConfigFileCapacity];
        size_t len = 0;
        if (!ReadWholeFile(ConfigPath, buf, sizeof(buf), std::addressof(len))) { return 0; }

        const size_t klen = std::strlen(key);
        uint32_t result = 0;
        const char *line = buf;
        while (*line) {
            const char *eol = line;
            while (*eol && *eol != '\n') { ++eol; }

            const char *p = line;
            while (p < eol && (*p == ' ' || *p == '\t')) { ++p; }

            if (p < eol && *p != '#' && *p != ';' &&
                (size_t)(eol - p) >= klen && std::strncmp(p, key, klen) == 0) {
                const char *q = p + klen;
                while (q < eol && (*q == ' ' || *q == '\t')) { ++q; }
                if (q < eol && *q == '=') {
                    ++q;
                    while (q < eol && (*q == ' ' || *q == '\t')) { ++q; }

                    uint32_t ip = 0;
                    for (int octet = 0; octet < 4; ++octet) {
                        int v = 0, digits = 0;
                        for (; q < eol && *q >= '0' && *q <= '9'; ++q, ++digits) {
                            v = v * 10 + (*q - '0');
                        }
                        if (digits == 0 || v > 255) { return 0; }
                        ip = (ip << 8) | (uint32_t)v;
                        if (octet < 3) {
                            if (q >= eol || *q != '.') { return 0; }
                            ++q;
                        }
                    }
                    result = ip;
                }
            }
            line = (*eol == '\n') ? (eol + 1) : eol;
        }
        return result;
    }

    bool ConfigFlag(const char *key, bool dflt)
    {
        char buf[ConfigFileCapacity];
        size_t len = 0;
        if (!ReadWholeFile(ConfigPath, buf, sizeof(buf), std::addressof(len))) { return dflt; }

        const size_t klen = std::strlen(key);
        bool result = dflt;
        const char *line = buf;
        while (*line) {
            const char *eol = line;
            while (*eol && *eol != '\n') { ++eol; }

            const char *p = line;
            while (p < eol && (*p == ' ' || *p == '\t')) { ++p; }

            if (p < eol && *p != '#' && *p != ';' &&
                (size_t)(eol - p) >= klen && std::strncmp(p, key, klen) == 0) {
                const char *q = p + klen;
                while (q < eol && (*q == ' ' || *q == '\t')) { ++q; }
                if (q < eol && *q == '=') {
                    ++q;
                    while (q < eol && (*q == ' ' || *q == '\t')) { ++q; }
                    if (q < eol) { result = (*q != '0'); }
                }
            }
            line = (*eol == '\n') ? (eol + 1) : eol;
        }
        return result;
    }

    uint64_t WaitForConfiguredNetworkId()
    {
        char buf[ConfigFileCapacity];
        bool wroteTemplate  = false;
        bool warnedCommented = false;

        for (;;) {
            uint64_t nwid = 0;
            if (ResolveConfiguredNetworkId(std::addressof(nwid))) {
                Trace("config: resolved network %.16llx", (unsigned long long)nwid);
                return nwid;
            }

            size_t len = 0;
            if (ReadWholeFile(ConfigPath, buf, sizeof(buf), std::addressof(len))) {
                /* The failure mode this catches: the template's example line
                 * gets its value replaced with a real network id but keeps the
                 * leading '#', so the module correctly ignores it and sits here
                 * looking like it has hung. Said once, it costs one log line;
                 * unsaid, it costs an afternoon. */
                if (!warnedCommented &&
                    ParseNwid(buf, std::addressof(nwid), /* allow_commented */ true)) {
                    warnedCommented = true;
                    Trace("config: nwid %.16llx is on a COMMENTED line -- delete the "
                          "leading '#' or use the overlay", (unsigned long long)nwid);
                }
            } else if (!wroteTemplate) {
                WriteWholeFile(ConfigPath, ConfigTemplate);
                wroteTemplate = true;
            }

            /* No network configured yet. Idle cheaply and look again, so that
             * dropping the file in is all it takes -- and so that
             * a missing config is never a reason to abort a system module. */
            os::SleepThread(TimeSpan::FromSeconds(5));
        }
    }

    /* ------------------------------------------------------------------ */
    /* ZT_Node_Callbacks                                                   */
    /* ------------------------------------------------------------------ */

    int Port::cbStateGet(ZT_Node *, void *, void *, enum ZT_StateObjectType type,
                         const uint64_t id[2], void *data, unsigned int maxlen)
    {
        char path[256];
        if (!StatePath(path, sizeof(path), type, id)) return -1;

        fs::FileHandle f;
        if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Read))) return -1;
        ON_SCOPE_EXIT { fs::CloseFile(f); };

        s64 size = 0;
        if (R_FAILED(fs::GetFileSize(std::addressof(size), f)) || size > (s64)maxlen) return -1;
        if (R_FAILED(fs::ReadFile(f, 0, data, size))) return -1;
        return (int)size;
    }

    void Port::cbStatePut(ZT_Node *, void *, void *, enum ZT_StateObjectType type,
                          const uint64_t id[2], const void *data, int len)
    {
        char path[256];
        if (!StatePath(path, sizeof(path), type, id)) return;

        if (len < 0) {                    /* negative length means "delete" */
            (void)fs::DeleteFile(path);
            return;
        }

        /* SD writes are slow and bursty, and peer state is written often. On a
         * real console this wants a dirty set flushed on a timer rather than a
         * write-through on every call. */
        (void)fs::DeleteFile(path);
        if (R_FAILED(fs::CreateFile(path, len))) return;

        fs::FileHandle f;
        if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Write))) return;
        ON_SCOPE_EXIT { fs::CloseFile(f); };
        (void)fs::WriteFile(f, 0, data, len, fs::WriteOption::Flush);
    }

    int Port::cbWireSend(ZT_Node *, void *uptr, void *, int64_t localSocket,
                         const struct sockaddr_storage *addr, const void *data,
                         unsigned int len, unsigned int)
    {
        auto *self = static_cast<Port *>(uptr);
        if (self->m_wireFd < 0) return -1;
        const bool mapped = localSocket > 0;
        if (mapped && (localSocket != self->m_mappedSocketId || self->m_mappedFd < 0)) return -1;
        const int fd = mapped ? self->m_mappedFd : self->m_wireFd;

        /* The wire socket is AF_INET. ZeroTier keeps offering IPv6 endpoints
         * for its roots, and sendto() rejects every one with EINVAL -- that was
         * the steady `errno 22` in uplink.log, fifteen failures before the node
         * had even come online. Decline without the syscall: it is not an error
         * condition, it is an address family we do not carry. */
        if (addr->ss_family != AF_INET) {
            ++self->m_wireSkipV6;
            return -1;
        }

        const auto *dst = reinterpret_cast<const struct sockaddr_in *>(addr);
        self->m_wireLastDstIp = ntohl(dst->sin_addr.s_addr);
        self->m_wireLastDstPort = ntohs(dst->sin_port);

        const socklen_t alen = sizeof(struct sockaddr_in);
        const ssize_t n = ::sendto(fd, data, len, 0,
                                 (const struct sockaddr *)addr, alen);
        if (n == (ssize_t)len) {
            ++self->m_wireTx;
            self->m_wireFailStreak = 0;
            self->m_wireReachable.store(true, std::memory_order_release);
            if (self->m_wireRecovering) { self->m_wireRecoveryConfirmed = true; }
            return 0;
        }

        /* Record rather than log: this is the packet path, and a console that
         * has lost its route fails every send. heartbeat() reports the rate. */
        ++self->m_wireTxFail;
        if (!mapped) ++self->m_wireFailStreak;
        self->m_wireErrno = errno;
        self->m_wireReachable.store(false, std::memory_order_release);
        return -1;
    }

    void Port::cbVirtualFrame(ZT_Node *, void *uptr, void *, uint64_t nwid, void **,
                              uint64_t srcMac, uint64_t destMac, unsigned int etherType,
                              unsigned int, const void *data, unsigned int len)
    {
        auto *self = static_cast<Port *>(uptr);
        if (nwid != self->m_nwid) return;
        std::scoped_lock lk(self->m_vnetLock);
        self->m_vnet.onFrame(srcMac, destMac, (uint16_t)etherType, data, len);
    }

    int Port::OpenLanSocket()
    {
        std::scoped_lock lk(m_vnetLock);
        return m_vnet.configured() ? m_vnet.udpOpen() : net::InvalidSocket;
    }

    bool Port::BindLanSocket(int vfd, u16 port)
    {
        std::scoped_lock lk(m_vnetLock);
        return m_vnet.configured() && m_vnet.udpBind(vfd, 0, port) == 0;
    }

    bool Port::MirrorLanDatagram(int vfd, u32 dst_ip, u16 port,
                                 const void *data, unsigned int len)
    {
        std::scoped_lock lk(m_vnetLock);
        if (!m_vnet.configured()) { return false; }
        const u32 mask = m_vnet.netmask();
        if ((dst_ip & mask) != (m_vnet.localIp() & mask)) { return false; }
        return m_vnet.udpSendTo(vfd, dst_ip, port, data, len) >= 0;
    }

    bool Port::MirrorLanBroadcast(int vfd, u16 port,
                                  const void *data, unsigned int len)
    {
        std::scoped_lock lk(m_vnetLock);
        if (!m_vnet.configured()) { return false; }
        return m_vnet.udpSendTo(vfd, m_vnet.broadcastIp(), port, data, len) >= 0;
    }

    bool Port::LanSocketReadable(int vfd)
    {
        std::scoped_lock lk(m_vnetLock);
        return m_vnet.udpReadable(vfd);
    }

    int Port::ReceiveLanDatagram(int vfd, void *data, unsigned int max,
                                  u32 *src_ip, u16 *src_port, bool peek)
    {
        std::scoped_lock lk(m_vnetLock);
        return m_vnet.udpRecvFrom(vfd, data, max, src_ip, src_port, peek);
    }

    void Port::CloseLanSocket(int vfd)
    {
        std::scoped_lock lk(m_vnetLock);
        m_vnet.udpClose(vfd);
    }

    bool Port::GetLanIpConfig(u32 *ip, u32 *netmask)
    {
        std::scoped_lock lk(m_vnetLock);
        if (!m_vnet.configured()) { return false; }
        if (ip != nullptr) { *ip = m_vnet.localIp(); }
        if (netmask != nullptr) { *netmask = m_vnet.netmask(); }
        return true;
    }

    bool Port::LanTransportReady()
    {
        if (!m_wireReachable.load(std::memory_order_acquire)) { return false; }
        std::scoped_lock lk(m_vnetLock);
        return m_vnet.configured();
    }

    bool Port::WaitForLanTransportReady(int64_t timeout_ms)
    {
        if (this->LanTransportReady()) { return true; }
        if (timeout_ms <= 0) { return false; }

        constexpr u64 TicksPerMillisecond = 19200;
        const u64 started = armGetSystemTick();
        const u64 timeout_ticks = static_cast<u64>(timeout_ms) * TicksPerMillisecond;
        do {
            os::SleepThread(TimeSpan::FromMilliSeconds(50));
            if (this->LanTransportReady()) { return true; }
        } while (armGetSystemTick() - started < timeout_ticks);
        return false;
    }

    int Port::cbNetworkConfig(ZT_Node *, void *uptr, void *, uint64_t nwid, void **,
                              enum ZT_VirtualNetworkConfigOperation op,
                              const ZT_VirtualNetworkConfig *conf)
    {
        auto *self = static_cast<Port *>(uptr);

        if (op == ZT_VIRTUAL_NETWORK_CONFIG_OPERATION_DESTROY ||
            op == ZT_VIRTUAL_NETWORK_CONFIG_OPERATION_DOWN) {
            self->m_wireReachable.store(false, std::memory_order_release);
            std::scoped_lock lk(self->m_vnetLock);
            self->m_vnet.reset();
            self->m_vnet.setEmit(&Port::cbEmit, self);
            return 0;
        }

        /* Whether or not we got an address, the status says why: NOT_FOUND and
         * ACCESS_DENIED are the two a user actually hits, and without surfacing
         * them a mistyped network id looks identical to a working one. */
        self->m_netStatus = (int)conf->status;
        self->m_nwid = nwid;

        /* Broadcast being disabled on the network is a silent failure: the
         * subscription succeeds, and nothing ever arrives. Say what we were
         * given rather than assuming. */
        ztnx::Event("netconf  bcast %d  mtu %u  addrs %u  subs %u  type %d  status %d",
                    conf->broadcastEnabled, (unsigned)conf->mtu,
                    (unsigned)conf->assignedAddressCount,
                    (unsigned)conf->multicastSubscriptionCount,
                    (int)conf->type, (int)conf->status);

        /* Take the first IPv4 the controller assigned us. This address is what
         * the bsd:u MITM presents to the game, and what peers will see as the
         * source of everything the console sends. */
        for (unsigned int i = 0; i < conf->assignedAddressCount; ++i) {
            const auto *sa = (const struct sockaddr_in *)&conf->assignedAddresses[i];
            if (sa->sin_family != AF_INET) continue;

            const uint32_t ip = ntohl(sa->sin_addr.s_addr);
            /* ZeroTier encodes the prefix length in sin_port. */
            const unsigned int bits = ntohs(sa->sin_port);
            const uint32_t netmask = bits ? (0xFFFFFFFFu << (32 - bits)) : 0;

            self->m_nwid = nwid;
            {
                std::scoped_lock lk(self->m_vnetLock);
                self->m_vnet.configure(conf->mac, ip, netmask, (uint16_t)conf->mtu);
            }
            break;
        }

        /* Re-assert the broadcast subscription after every config update -- a
         * refresh from the controller is exactly when it could be lost.
         *
         * But NOT from here. This callback runs inside Network::setConfiguration
         * with Network::_lock held, and ZT_Node_multicastSubscribe reaches
         * Network::multicastSubscribe, which takes that same non-recursive
         * lock. Calling it here deadlocks the node thread. Raise a flag and let
         * the run loop do it outside the callback. */
        self->m_needSubscribe = true;
        return 0;
    }

    void Port::cbEvent(ZT_Node *, void *uptr, void *, enum ZT_Event ev, const void *)
    {
        auto *self = static_cast<Port *>(uptr);
        switch (ev) {
            case ZT_EVENT_ONLINE:
                self->m_online = true;
                ztnx::Event("ONLINE   tx %u rx %u fail %u", (unsigned)self->m_wireTx,
                      (unsigned)self->m_wireRx, (unsigned)self->m_wireTxFail);
                break;
            case ZT_EVENT_OFFLINE:
                self->m_online = false;
                self->m_wireReachable.store(false, std::memory_order_release);
                ztnx::Event("OFFLINE  tx %u rx %u fail %u errno %d", (unsigned)self->m_wireTx,
                      (unsigned)self->m_wireRx, (unsigned)self->m_wireTxFail,
                      self->m_wireErrno);
                break;
            case ZT_EVENT_DOWN:
                self->m_online = false;
                self->m_wireReachable.store(false, std::memory_order_release);
                ztnx::Event("DOWN");
                break;
            default: break;
        }
    }

    void Port::cbEmit(void *ctx, uint64_t dstMac, uint16_t etherType,
                      const void *payload, unsigned int len)
    {
        auto *self = static_cast<Port *>(ctx);
        (void)self;
        if (len > MaxFrameLen) return;

        std::scoped_lock lk(g_frameLock);
        const size_t next = (g_head + 1) % FrameQueueDepth;
        if (next == g_tail) return;       /* full: drop, never block the game */

        auto &q = g_frames[g_head];
        q.dstMac = dstMac;
        q.etherType = etherType;
        q.len = len;
        std::memcpy(q.data, payload, len);
        g_head = next;
    }

    /* ------------------------------------------------------------------ */

    bool Port::Initialize(uint64_t nwid)
    {
        m_nwid = nwid;
        m_vnet.reset();
        m_vnet.setEmit(&Port::cbEmit, this);

        Trace("port: opening UDP/%u", (unsigned)DefaultWirePort);
        if (!this->openWireSocket()) { return false; }

        Trace("port: wire socket bound, creating node");

        /* Node::Node performs ONE ::malloc covering Trace + Switch +
         * Multicaster + Topology + SelfAwareness + Bond + PacketMultiplexer,
         * and throws std::bad_alloc if it fails. There is no recovering from
         * that throw: libstratosphere's linker script discards .eh_frame
         * outright (`/DISCARD/ ... EXCLUDE_FILE(*crtbegin.o) *(.eh_frame)`) and
         * wraps __cxa_allocate_exception with a stub that aborts, so a throw
         * anywhere inside libztcore is a fatal error screen even when ZeroTier
         * catches it two lines later.
         *
         * So check the arena first and refuse loudly rather than die. This is
         * the exact failure that produced report_0000000024c4cc92.bin: the
         * arena was 1 MB and that single malloc wanted 2.16 MB. */
        if (auto *allocator = ams::init::GetAllocator(); allocator != nullptr) {
            const size_t largest = allocator->GetAllocatableSize();
            Trace("port: arena largest free block %u KB", (unsigned)(largest / 1024));
            if (largest < NodeAllocLowWater) {
                Trace("port: REFUSING ZT_Node_new -- needs ~%u KB contiguous, have %u KB. "
                      "Raise MallocBufferSize in main.cpp.",
                      (unsigned)(NodeAllocLowWater / 1024), (unsigned)(largest / 1024));
                return false;
            }
        }

        static const ZT_Node_Callbacks callbacks = {
            .version                       = 0,
            .statePutFunction              = &Port::cbStatePut,
            .stateGetFunction              = &Port::cbStateGet,
            .wirePacketSendFunction        = &Port::cbWireSend,
            .virtualNetworkFrameFunction   = &Port::cbVirtualFrame,
            .virtualNetworkConfigFunction  = &Port::cbNetworkConfig,
            .eventCallback                 = &Port::cbEvent,
            .pathCheckFunction             = nullptr,
            .pathLookupFunction            = nullptr,
        };

        /* ZT_Node_new(node, config, uptr, tptr, callbacks, now).
         *
         * The second parameter is the config, NOT uptr -- and Node's
         * constructor does an unconditional
         *   memcpy(&_config, config, sizeof(ZT_Node_Config))
         * so passing nullptr here is a memcpy from address zero. That was the
         * Data Abort at Node.cpp:62. */
        static const ZT_Node_Config node_config = {
            .enableEncryptedHello = 0,
            .lowBandwidthMode     = 0,
        };

        if (ZT_Node_new(&m_node, &node_config, this, nullptr, &callbacks, NowMs()) != ZT_RESULT_OK) {
            ::close(m_wireFd);
            m_wireFd = -1;
            return false;
        }

        /* join can fail outright -- a bad network id, or the node being out of
         * memory. Ignoring it left the module spinning forever with no way to
         * tell that it never joined anything. */
        Trace("port: node created, joining %.16llx", (unsigned long long)nwid);
        const ZT_ResultCode jrc = ZT_Node_join(m_node, nwid, nullptr, nullptr);
        if (jrc != ZT_RESULT_OK) {
            m_lastError = (int)jrc;
            Trace("port: join failed, ZT_ResultCode %d", (int)jrc);
            this->writeStatus(true);
            return false;
        }

        Trace("port: joined");
        m_natEnabled = StartNatMapper(ZT_Node_address(m_node));
        m_startedMs = NowMs();

        /* Echo the configuration we actually parsed.
         *
         * Twice now a run has been spent wondering whether a setting was
         * present on the SD card, because the copy in the project folder was
         * stale. The module is the only thing that knows for certain, so let it
         * say so rather than being asked. */
        {
            const uint32_t p = ztnx::ConfigIpv4("probe");
            ztnx::Event("config   nwid %.16llx  probe %u.%u.%u.%u  psc %d",
                        (unsigned long long)m_nwid,
                        (unsigned)((p >> 24) & 0xFF), (unsigned)((p >> 16) & 0xFF),
                        (unsigned)((p >> 8) & 0xFF),  (unsigned)(p & 0xFF),
                        (int)ztnx::ConfigFlag("psc_enable", false));
        }
        this->subscribeBroadcast();
        this->writeStatus(true);
        return true;
    }

    bool Port::switchNetwork(uint64_t nwid)
    {
        if (nwid == 0 || nwid == m_nwid || m_node == nullptr) { return false; }

        const uint64_t old_nwid = m_nwid;
        ztnx::Event("network   switching %.16llx -> %.16llx",
                    (unsigned long long)old_nwid,
                    (unsigned long long)nwid);

        /* Frames queued for the old virtual LAN must never be emitted on the
         * new one. The game-facing socket table is reset by the network-config
         * DESTROY callback; titles should open LAN mode after switching. */
        {
            std::scoped_lock lk(g_frameLock);
            g_tail = g_head;
        }
        m_wireReachable.store(false, std::memory_order_release);
        m_needSubscribe = false;
        m_subscribed = false;
        m_netStatus = -1;
        m_firstFrameLogged = false;

        const ZT_ResultCode lrc = ZT_Node_leave(m_node, old_nwid, nullptr, nullptr);
        if (lrc != ZT_RESULT_OK) {
            m_lastError = (int)lrc;
            ztnx::Event("network   leave %.16llx failed rc %d",
                        (unsigned long long)old_nwid, (int)lrc);
            this->writeStatus(true);
            return false;
        }

        m_nwid = nwid;
        const ZT_ResultCode jrc = ZT_Node_join(m_node, nwid, nullptr, nullptr);
        if (jrc == ZT_RESULT_OK) {
            m_lastError = 0;
            m_nextDeadline = 0;
            ztnx::Event("network   joined %.16llx; waiting for controller",
                        (unsigned long long)nwid);
            this->writeStatus(true);
            return true;
        }

        /* A failed live join should not strand an otherwise working console.
         * Best-effort rejoin the old network and leave a precise error trail. */
        m_lastError = (int)jrc;
        ztnx::Event("network   join %.16llx failed rc %d; restoring %.16llx",
                    (unsigned long long)nwid, (int)jrc,
                    (unsigned long long)old_nwid);
        m_nwid = old_nwid;
        const ZT_ResultCode rrc = ZT_Node_join(m_node, old_nwid, nullptr, nullptr);
        if (rrc != ZT_RESULT_OK) {
            m_lastError = (int)rrc;
            ztnx::Event("network   restore %.16llx failed rc %d",
                        (unsigned long long)old_nwid, (int)rrc);
        }
        m_nextDeadline = 0;
        this->writeStatus(true);
        return false;
    }

    void Port::pollNetworkSelection()
    {
        const int64_t now = NowMs();
        if (m_lastNetworkPollMs != 0 && (now - m_lastNetworkPollMs) < 1000) { return; }
        m_lastNetworkPollMs = now;

        uint64_t requested = 0;
        if (ResolveConfiguredNetworkId(std::addressof(requested)) && requested != m_nwid) {
            (void)this->switchNetwork(requested);
        }
    }

    void Port::drainOutbound()
    {
        /* While infrastructure Wi-Fi is absent (for example while Splatoon 3
         * is still in the Shoal's local-wireless mode), consume and discard
         * the bounded queue instead of feeding game traffic into ZeroTier.
         * The physical BSD call still happens, so local wireless/LAN behaviour
         * is unchanged; we resume mirroring after the uplink proves itself. */
        const bool paused = m_wireFd < 0 || m_wireRecovering;
        for (;;) {
            QueuedFrame f;
            {
                std::scoped_lock lk(g_frameLock);
                if (g_tail == g_head) break;
                f = g_frames[g_tail];
                g_tail = (g_tail + 1) % FrameQueueDepth;
            }
            if (paused) { continue; }
            if (!m_firstFrameLogged) {
                m_firstFrameLogged = true;
                ztnx::Event("frame    first outbound: type %04x len %u to %.12llx",
                            f.etherType, f.len, (unsigned long long)f.dstMac);
            }

            volatile int64_t deadline = 0;
            ZT_Node_processVirtualNetworkFrame(m_node, nullptr, NowMs(), m_nwid,
                                               /* srcMac */ m_vnet.localMac(), f.dstMac,
                                               f.etherType, 0, f.data, f.len, &deadline);
            m_nextDeadline = deadline;
        }
    }

    namespace {
        /* ManualClear on both: the node thread and the psc thread each need to
         * see the edge regardless of which got there first. */
        os::Event g_quiesced(os::EventClearMode_ManualClear);
        os::Event g_resumed (os::EventClearMode_ManualClear);
        std::atomic<bool> g_sleepRequested{false};
    }

    void RequestQuiesce()
    {
        g_quiesced.Clear();
        g_resumed.Clear();
        g_sleepRequested = true;
    }

    bool WaitQuiesced(int64_t timeout_ms)
    {
        return g_quiesced.TimedWait(TimeSpan::FromMilliSeconds(timeout_ms));
    }

    void SignalResume()
    {
        g_sleepRequested = false;
        g_resumed.Signal();
    }

    bool SleepRequested() { return g_sleepRequested; }

    bool Port::openWireSocket()
    {
        m_wireFd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (m_wireFd < 0) { return false; }

        struct sockaddr_in bindAddr = {};
        bindAddr.sin_family      = AF_INET;
        bindAddr.sin_addr.s_addr = INADDR_ANY;
        /* OneService normally carries both UDP/9993 and an additional
         * randomized source port.  A single fixed mapping is not enough for
         * every symmetric/endpoint-dependent NAT.  We still start on 9993,
         * but recovery alternates with an ephemeral source port so reopening
         * the socket actually gives a difficult router a fresh mapping. */
        bindAddr.sin_port        = htons(m_wireEphemeral ? 0 : DefaultWirePort);
        if (::bind(m_wireFd, (struct sockaddr *)&bindAddr, sizeof(bindAddr)) != 0) {
            ::close(m_wireFd);
            m_wireFd = -1;
            return false;
        }

        struct sockaddr_in local = {};
        socklen_t localLen = sizeof(local);
        m_wireLocalPort = (::getsockname(m_wireFd, reinterpret_cast<struct sockaddr *>(&local),
                                         &localLen) == 0)
                            ? ntohs(local.sin_port) : 0;
        return true;
    }

    void Port::closeNatWire()
    {
        ConfigureNatMapper(0);
        if (m_mappedFd >= 0) { ::close(m_mappedFd); m_mappedFd = -1; }
        m_mappedPort = 0;
        if (m_node && (m_natAddress || m_natPublicPort)) ZT_Node_clearLocalInterfaceAddresses(m_node);
        m_natAddress = 0; m_natPublicPort = 0;
    }

    void Port::maintainNatWire()
    {
        if (!m_natEnabled) return;
        if (m_wireFd < 0) { closeNatWire(); return; }
        if (m_mappedFd < 0 && m_wireReachable.load(std::memory_order_acquire) && NowMs() >= m_natRetryMs) {
            m_natRetryMs = NowMs() + 30000;
            const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
            if (fd >= 0) {
                sockaddr_in local{};
                local.sin_family = AF_INET;
                local.sin_port = htons(20000 + (ZT_Node_address(m_node) % 40000));
                if (::bind(fd, reinterpret_cast<sockaddr *>(&local), sizeof(local)) == 0) {
                    m_mappedFd = fd;
                    m_mappedPort = ntohs(local.sin_port);
                    ++m_mappedSocketId;
                    ConfigureNatMapper(m_mappedPort);
                } else { ::close(fd); }
            }
        }
        const auto endpoint = GetNatEndpoint();
        if (endpoint.address != m_natAddress || endpoint.port != m_natPublicPort) {
            ZT_Node_clearLocalInterfaceAddresses(m_node);
            m_natAddress = endpoint.address; m_natPublicPort = endpoint.port;
            if (m_mappedFd >= 0 && endpoint.address && endpoint.port) {
                sockaddr_storage surface{};
                auto *ipv4 = reinterpret_cast<sockaddr_in *>(&surface);
                ipv4->sin_family = AF_INET; ipv4->sin_addr.s_addr = endpoint.address;
                ipv4->sin_port = htons(endpoint.port);
                ZT_Node_addLocalInterfaceAddress(m_node, &surface);
            }
        }
        if (m_mappedFd < 0) return;
        pollfd pfd{m_mappedFd, POLLIN, 0};
        if (::poll(&pfd, 1, 0) <= 0) return;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) { closeNatWire(); return; }
        if (!(pfd.revents & POLLIN)) return;
        uint8_t packet[2048];
        /* The primary poll can sleep for 10 ms. Drain a bounded burst here,
         * otherwise mapped-only traffic would be artificially capped at
         * 100 datagrams/s regardless of the actual connection bandwidth. */
        for (unsigned burst = 0; burst < 16; ++burst) {
            sockaddr_storage from{};
            socklen_t length = sizeof(from);
            const auto n = ::recvfrom(m_mappedFd, packet, sizeof(packet), MSG_DONTWAIT,
                                     reinterpret_cast<sockaddr *>(&from), &length);
            if (n <= 0) break;
            ++m_wireRx;
            m_wireReachable.store(true, std::memory_order_release);
            if (m_wireRecovering) m_wireRecoveryConfirmed = true;
            volatile int64_t deadline = 0;
            ZT_Node_processWirePacket(m_node, nullptr, NowMs(), m_mappedSocketId,
                                      &from, packet, static_cast<unsigned>(n), &deadline);
            m_nextDeadline = deadline;
        }
    }

    void Port::HandleSleep()
    {
        /* Everything that touches fs or bsd has to happen HERE, while those
         * services are still up -- psc has notified us precisely because we
         * declared them as dependencies, and it is holding the transition open
         * until we acknowledge. Write the log line first, then let go. */
        ztnx::Event("SLEEP    quiescing: tx %u rx %u fail %u", m_wireTx, m_wireRx, m_wireTxFail);
        if (!QuiesceNatMapper()) ztnx::Event("SLEEP    NAT worker quiesce timeout");
        closeNatWire();

        if (m_wireFd >= 0) {
            m_wireReachable.store(false, std::memory_order_release);
            ::close(m_wireFd);
            m_wireFd = -1;
        }

        /* From this point until g_resumed we make no fs and no socket calls at
         * all: cbWireSend sees m_wireFd < 0 and returns -1, which ZeroTier
         * treats as a failed send and retries later. */
        g_quiesced.Signal();
        g_resumed.Wait();

        if (!this->openWireSocket()) {
            /* bsd may not have finished coming back. The run loop calls us
             * again next iteration only if psc asks; so retry here instead. */
            for (int attempt = 0; attempt < 30 && m_wireFd < 0; ++attempt) {
                os::SleepThread(TimeSpan::FromSeconds(1));
                (void)this->openWireSocket();
            }
        }

        /* The clock jumped by however long the console slept. Force ZeroTier to
         * re-run its timers immediately rather than sitting on a deadline that
         * is now hours in the past. */
        m_nextDeadline = 0;
        m_lastBeatMs   = 0;

        ztnx::Event("WAKE     socket %s", m_wireFd >= 0 ? "reopened" : "FAILED to reopen");
    }

    /* Continuous form of main.cpp's one-shot ProbeResourceLimits.
     *
     * That one samples only early boot and then stops, which cannot see the
     * failure we are chasing: a heavy title -- Splatoon 3
     * entering the Shoal, say -- can drain the shared SYSTEM pool long after we
     * stopped looking. When that pool ran dry before, hid aborted with
     * 2001-0132, and hid is what drives the Joy-Cons.
     *
     * Sampled every 5 s; logged only when free memory sets a new low at least
     * 256 KB below the last one reported, so a whole play session costs a
     * handful of SD writes rather than a stream of them. */
    void Port::watchSystemMemory()
    {
        static svc::Handle s_rl       = svc::InvalidHandle;
        static bool        s_tried    = false;
        static s64         s_limit    = 0;
        static s64         s_reported = INT64_MAX;
        static int64_t     s_nextMs   = 0;

        const int64_t now = NowMs();
        if (now < s_nextMs) { return; }
        s_nextMs = now + 5000;

        if (!s_tried) {
            s_tried = true;
            u64 raw = 0;
            if (R_SUCCEEDED(svc::GetInfo(std::addressof(raw), svc::InfoType_ResourceLimit,
                                         svc::InvalidHandle, 0)) ||
                R_SUCCEEDED(svc::GetInfo(std::addressof(raw), svc::InfoType_ResourceLimit,
                                         svc::PseudoHandle::CurrentProcess, 0))) {
                s_rl = static_cast<svc::Handle>(raw);
                (void)svc::GetResourceLimitLimitValue(std::addressof(s_limit), s_rl,
                                                      svc::LimitableResource_PhysicalMemoryMax);
            }
        }
        if (s_rl == svc::InvalidHandle || s_limit == 0) { return; }

        s64 cur = 0;
        if (R_FAILED(svc::GetResourceLimitCurrentValue(std::addressof(cur), s_rl,
                         svc::LimitableResource_PhysicalMemoryMax))) {
            return;
        }

        const s64 freeKb = (s_limit - cur) / 1024;
        if (freeKb + 256 > s_reported) { return; }
        s_reported = freeKb;
        ztnx::Event("sysmem   free %lld KB (new low)", (long long)freeKb);
    }

    /* Bring the wire socket back after the network goes away underneath it.
     *
     * Evidence: uplink.log, a session where at ~811 s every send began failing
     * with EPIPE and never recovered -- 172 consecutive failures, zero bytes
     * sent, and ZT_EVENT_ONLINE still latched because nothing had told ZeroTier
     * otherwise. That is what entering local wireless does to an infrastructure
     * socket, and it is what any network transition will do.
     *
     * Recycling costs one socket() and one bind(); backing off means a console
     * with no network spends a few syscalls a minute rather than forty. */
    void Port::maintainWireSocket()
    {
        constexpr int FailStreakMax = 8;
        constexpr int BackoffMaxMs  = 30000;

        const int64_t now = NowMs();

        if (m_wireRecoveryConfirmed) {
            ztnx::Event("wire     RESUMED after %d ms down; uplink send confirmed",
                        (int)(now - m_wireDownAtMs));
            m_wireRecoveryConfirmed = false;
            m_wireRecovering = false;
            m_wireFailStreak = 0;
            m_wireBackoffMs = 0;
            m_wireErrno = 0;
            m_wireReopenFail = 0;
            m_wireHup = false;
            m_nextDeadline = 0;
        }

        if (m_wireFd < 0) {
            if (now < m_wireReopenAtMs) { return; }

            const bool first = (m_wireReopenFail == 0);
            if (first) { ztnx::Event("wire     reopen attempt 1"); }

            if (this->openWireSocket()) {
                ++m_wireReopenFail;
                ztnx::Event("wire     probe socket open attempt %d after %d ms down",
                            m_wireReopenFail, (int)(now - m_wireDownAtMs));
                m_wireFailStreak = 0;
                m_wireHup        = false;
                /* Paths are stale after an outage; make ZeroTier re-run its
                 * timers now instead of waiting out the old deadline. */
                m_nextDeadline = 0;
            } else {
                m_wireBackoffMs = (m_wireBackoffMs == 0) ? 2000 : (m_wireBackoffMs * 2);
                if (m_wireBackoffMs > BackoffMaxMs) { m_wireBackoffMs = BackoffMaxMs; }
                m_wireReopenAtMs = now + m_wireBackoffMs;

                /* Say so. A recycle line with nothing after it is ambiguous --
                 * it could mean recovered-and-quiet or dead-and-silent, and
                 * that ambiguity already cost us a reading. First failure, then
                 * once per capped backoff. */
                if (m_wireReopenFail == 0 || m_wireBackoffMs >= BackoffMaxMs) {
                    ztnx::Event("wire     reopen attempt %d failed (%s), retry in %d ms",
                                m_wireReopenFail + 1, ErrnoName(errno), m_wireBackoffMs);
                }
                ++m_wireReopenFail;
            }
            return;
        }

        if (m_wireFailStreak < FailStreakMax && !m_wireHup) { return; }

        /* Fenced on purpose. Three uplink.log captures in a row have ended on
         * exactly the recycle line with no beat after it, and the one call in
         * here that can block is ::close() on a socket whose bsd session has
         * already gone bad. If the log stops between these two lines, close()
         * is where the node thread died and the recycler needs a different
         * mechanism -- probably tearing down and re-initialising the whole
         * socket layer rather than one descriptor. */
        ztnx::Event("wire     PAUSE after %d failures (%s)%s -- closing fd %d",
                    m_wireFailStreak, ErrnoName(m_wireErrno),
                    m_wireHup ? " + POLLHUP" : "", m_wireFd);

        const int doomed = m_wireFd;
        closeNatWire();
        m_wireReachable.store(false, std::memory_order_release);
        m_wireFd = -1;              /* nothing may touch it while close runs */
        ::close(doomed);

        if (!m_wireRecovering) {
            m_wireDownAtMs = now;
            m_wireReopenFail = 0;
            m_wireBackoffMs = 0;
        }
        m_wireRecovering = true;
        m_wireRecoveryConfirmed = false;

        /* Do not keep recreating the exact NAT tuple that just failed.  The
         * next probe alternates between ZeroTier's conventional source port
         * and an OS-selected port.  This costs no additional live socket and
         * therefore preserves the sysmodule's tight memory/session budget. */
        m_wireEphemeral = !m_wireEphemeral;
        ztnx::Event("wire     next source %s (previous local %u, dst %u.%u.%u.%u:%u)",
                    m_wireEphemeral ? "ephemeral" : "UDP/9993",
                    (unsigned)m_wireLocalPort,
                    (unsigned)((m_wireLastDstIp >> 24) & 0xFF),
                    (unsigned)((m_wireLastDstIp >> 16) & 0xFF),
                    (unsigned)((m_wireLastDstIp >> 8) & 0xFF),
                    (unsigned)(m_wireLastDstIp & 0xFF),
                    (unsigned)m_wireLastDstPort);

        m_wireBackoffMs = (m_wireBackoffMs == 0) ? 2000 : (m_wireBackoffMs * 2);
        if (m_wireBackoffMs > BackoffMaxMs) { m_wireBackoffMs = BackoffMaxMs; }
        ztnx::Event("wire     paused, probing again in %d ms", m_wireBackoffMs);
        m_wireReopenAtMs = now + m_wireBackoffMs;
    }

    /* Subscribe to the Ethernet broadcast group.
     *
     * ZeroTier does not deliver multicast or broadcast frames to a member that
     * has not asked for the group -- there is no implicit "everything"
     * subscription. Without this, ARP requests (which go to
     * ff:ff:ff:ff:ff:ff) never reach virtualNetworkFrameFunction, so the ARP
     * responder never fires, and a PC on the network gets "Destination Host
     * Unreachable" while status.txt sits at `rx frames 0` forever. That is
     * exactly what happened.
     *
     * It matters far beyond ping: every LAN-play title discovers peers by
     * broadcasting, so nothing in this project works without it.
     *
     * Idempotent, so it is safe to call again whenever a network config
     * arrives -- the subscription has to outlive a config refresh. */
    void Port::subscribeBroadcast()
    {
        if (m_node == nullptr || m_nwid == 0) { return; }

        constexpr uint64_t BroadcastMac = 0xffffffffffffULL;   /* ff:ff:ff:ff:ff:ff */

        /* TWO groups, and the second is the one that makes ping work.
         *
         * ZeroTier does not carry ARP on plain Ethernet broadcast. From
         * MulticastGroup::deriveMulticastGroupForAddressResolution:
         *
         *   "IPv4 wants broadcast MACs, so we shove the V4 address itself into
         *    the Multicast Group ADI field. Making V4 ARP work is basically why
         *    ADI was added."
         *
         * So an ARP query for 10.147.17.243 is addressed to
         * (ff:ff:ff:ff:ff:ff, ADI = 0x0A9311F3) -- the address in host byte
         * order -- and a member subscribed only to ADI 0 never sees it. That is
         * a different group, and it is why the first attempt at this changed
         * nothing at all.
         *
         *   ADI 0        -- ordinary broadcast: 255.255.255.255, which is how
         *                   every LAN-play title discovers its peers.
         *   ADI = our IP -- address resolution: how anyone finds us at all.
         *
         * Both are needed. localIp() is already host order (cbNetworkConfig
         * ntohl's it), which is exactly what ZeroTier wants in the ADI. */
        struct { unsigned long adi; const char *what; } groups[] = {
            { 0UL,                                     "broadcast"  },
            { (unsigned long)m_vnet.localIp(),         "arp"        },
        };

        for (auto &g : groups) {
            if (g.adi == 0 && g.what[0] == 'a') { continue; }   /* no address yet */

            const enum ZT_ResultCode rc =
                ZT_Node_multicastSubscribe(m_node, nullptr, m_nwid, BroadcastMac, g.adi);

            if (rc != ZT_RESULT_OK) {
                ztnx::Event("mcast    %s subscribe FAILED rc %d", g.what, (int)rc);
            }
        }

        const uint32_t ip = m_vnet.localIp();
        if (!m_subscribed && ip != 0) {
            m_subscribed = true;
            ztnx::Event("mcast    ff:ff:ff:ff:ff:ff adi 0 + adi %u.%u.%u.%u (0x%08x)",
                        (unsigned)((ip >> 24) & 0xFF), (unsigned)((ip >> 16) & 0xFF),
                        (unsigned)((ip >> 8) & 0xFF),  (unsigned)(ip & 0xFF),
                        (unsigned)ip);
        }
    }

    /* The console's own view of the mesh, which we have never once looked at.
     *
     * `zerotier-cli peers` on the PC said the console was LEAF, latency -1,
     * RELAY -- never a single round trip. The mirror image of that from this
     * side is the missing half of the picture: does the console see the PC at
     * all, does it have any path to it, and is that path alive or expired. */
    void Port::writePeers()
    {
        if (m_node == nullptr) { return; }

        const int64_t now = NowMs();
        if (m_lastPeersMs != 0 && (now - m_lastPeersMs) < 30000) { return; }
        m_lastPeersMs = now;

        ZT_PeerList *pl = ZT_Node_peers(m_node);
        if (pl == nullptr) { return; }
        ON_SCOPE_EXIT { ZT_Node_freeQueryResult(m_node, pl); };

        char  text[1536];
        size_t off = 0;
        off += (size_t)std::snprintf(text + off, sizeof(text) - off,
                                     "peers %u   (uptime %llu s)\n",
                                     (unsigned)pl->peerCount,
                                     (unsigned long long)(now - m_startedMs) / 1000);

        for (unsigned i = 0; i < pl->peerCount && off + 256 < sizeof(text); ++i) {
            const ZT_Peer &p = pl->peers[i];
            off += (size_t)std::snprintf(text + off, sizeof(text) - off,
                       "%.10llx role %d  latency %d  paths %u  v%d.%d.%d\n",
                       (unsigned long long)p.address, (int)p.role, p.latency,
                       (unsigned)p.pathCount, p.versionMajor, p.versionMinor,
                       p.versionRev);

            for (unsigned j = 0; j < p.pathCount && off + 128 < sizeof(text); ++j) {
                const ZT_PeerPhysicalPath &q = p.paths[j];
                const auto *sin = (const struct sockaddr_in *)&q.address;
                const uint32_t a = ntohl(sin->sin_addr.s_addr);
                off += (size_t)std::snprintf(text + off, sizeof(text) - off,
                           "    %u.%u.%u.%u:%u  expired %d preferred %d  "
                           "lastSend %lld ms  lastRecv %lld ms\n",
                           (unsigned)((a >> 24) & 0xFF), (unsigned)((a >> 16) & 0xFF),
                           (unsigned)((a >> 8) & 0xFF),  (unsigned)(a & 0xFF),
                           (unsigned)ntohs(sin->sin_port),
                           q.expired, q.preferred,
                           (long long)(q.lastSend    ? (now - (int64_t)q.lastSend)    : -1),
                           (long long)(q.lastReceive ? (now - (int64_t)q.lastReceive) : -1));
            }
        }

        text[off] = '\0';
        (void)WriteWholeFile(PeersPath, text);
    }

    /* Make first contact instead of waiting to be discovered.
     *
     * The console has been an entirely passive member: joined, addressed,
     * subscribed, and `tx frames 0` -- it has never put a single frame onto the
     * virtual network. Nothing on the other side has any reason to look it up,
     * and neither peer list contains the other.
     *
     * With `probe = <ip>` in config.ini it sends an ICMP echo request there
     * every five seconds. If the peer's MAC is unknown the shim emits an ARP
     * request instead, which is the more valuable half: that goes to the
     * broadcast group and announces us. Either way it exercises the entire
     * transmit path -- VNet -> cbEmit -> drainOutbound ->
     * ZT_Node_processVirtualNetworkFrame -- which has never once run. */
    void Port::probePeer()
    {
        if (m_wireFd < 0 || m_wireRecovering) { return; }
        if (!m_vnet.configured()) { return; }

        if (!m_probeRead) {
            m_probeRead = true;
            m_probeIp   = ztnx::ConfigIpv4("probe");     /* optional extra target */
            ztnx::Event("probe    announcing to %u.%u.%u.%u every 5 s",
                        (unsigned)((m_vnet.broadcastIp() >> 24) & 0xFF),
                        (unsigned)((m_vnet.broadcastIp() >> 16) & 0xFF),
                        (unsigned)((m_vnet.broadcastIp() >> 8)  & 0xFF),
                        (unsigned)(m_vnet.broadcastIp() & 0xFF));
        }

        const int64_t now = NowMs();
        if (m_lastProbeMs != 0 && (now - m_lastProbeMs) < 5000) { return; }
        m_lastProbeMs = now;

        /* Announce to the whole network, not to one hand-configured address.
         *
         * The obvious primitive would be a gratuitous ARP, and it does not
         * work here. Switch.cpp routes an outgoing ARP request into the group
         * named by the address it is LOOKING FOR -- offset 24 of the payload,
         * the target IP -- so an ARP for our own address lands in ADI =
         * 10.147.17.243, a group nobody but us subscribes to. It would announce
         * us to an empty room.
         *
         * Non-ARP broadcast frames take the other branch and go to plain
         * ADI 0, which every member subscribes to. So the announcement is an
         * IP broadcast: an ICMP echo to the subnet broadcast address. Whether
         * anything replies barely matters (Linux ignores broadcast pings by
         * default) -- what matters is that every member now sees our MAC and
         * our address, which is the whole problem. */
        m_vnet.sendEchoRequest(m_vnet.broadcastIp());

        /* An optional unicast target exercises the other half: resolution via
         * the ADI = <address> group, which is the path a peer uses to find us. */
        if (m_probeIp != 0) { m_vnet.sendEchoRequest(m_probeIp); }
    }

    void Port::RunLoop()
    {
        uint8_t rx[2048];

        for (;;) {
            ++m_loops;

            /* 0. sleep. Before any fs or socket work, not after. */
            if (SleepRequested()) { this->HandleSleep(); }

            /* The overlay records a selection with a small INI rewrite. Poll
             * cheaply on the node thread so leave/join can never race ZeroTier's
             * packet and timer APIs. This is the no-reboot network switch. */
            this->pollNetworkSelection();

            /* 1. wire -> node */
            this->maintainWireSocket();
            this->maintainNatWire();

            /* poll() is the only thing pacing this loop. With the socket down
             * there is nothing to poll, so sleep the same 10 ms by hand --
             * otherwise the loop free-runs on a system core, which is a fine
             * way to make a console feel broken. */
            if (m_wireFd < 0) { os::SleepThread(TimeSpan::FromMilliSeconds(10)); }

            struct pollfd pfd = { .fd = m_wireFd, .events = POLLIN, .revents = 0 };
            const int pr = (m_wireFd >= 0) ? ::poll(&pfd, 1, 10) : 0;

            if (pr < 0) {
                /* An erroring poll returns instantly, so without this the loop
                 * free-runs. Count it and pace by hand. */
                ++m_pollErr;
                m_pollErrno = errno;
                os::SleepThread(TimeSpan::FromMilliSeconds(10));
            } else if (pr == 0) {
                ++m_pollZero;
            } else if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                /* A hung-up descriptor is instantly "ready" forever, so
                 * ignoring this spun the loop at ~1000 iterations/sec on a
                 * system core -- 99774 loops against only 6272 real timeouts.
                 * It is also the same condition sendto reports as EPIPE, so
                 * treat it as what it is: a dead socket, to be recycled. */
                ++m_pollBad;
                m_wireReachable.store(false, std::memory_order_release);
                m_wireHup = true;
                os::SleepThread(TimeSpan::FromMilliSeconds(10));
            }

            if (pr > 0 && (pfd.revents & POLLIN)) {
                struct sockaddr_storage from = {};
                socklen_t fromlen = sizeof(from);
                const ssize_t n = ::recvfrom(m_wireFd, rx, sizeof(rx), 0,
                                           (struct sockaddr *)&from, &fromlen);
                if (n > 0) {
                    ++m_wireRx;
                    m_wireReachable.store(true, std::memory_order_release);
                    if (m_wireRecovering) { m_wireRecoveryConfirmed = true; }
                    volatile int64_t deadline = 0;
                    ZT_Node_processWirePacket(m_node, nullptr, NowMs(), 0, &from,
                                              rx, (unsigned int)n, &deadline);
                    m_nextDeadline = deadline;
                }
            }

            if (m_needSubscribe) {
                m_needSubscribe = false;
                this->subscribeBroadcast();
            }

            /* 2. game -> virtual network */
            drainOutbound();

            /* 3. status, for a sysmodule that would otherwise be a black box */
            this->writeStatus(false);
            this->heartbeat();
            this->watchSystemMemory();
            this->writePeers();
            ztnx::mitm::FlushObservations();
            ztnx::mitm::BsdShim::CleanupAbandonedServices();
            this->probePeer();
            TraceArenaWatermark();

            /* 4. timers */
            const int64_t now = NowMs();
            if (m_wireFd >= 0 && now >= m_nextDeadline) {
                volatile int64_t deadline = 0;
                ZT_Node_processBackgroundTasks(m_node, nullptr, now, &deadline);
                m_nextDeadline = deadline;
            }
        }
    }

    /* One line every 30 seconds, whatever else is happening.
     *
     * This exists for one specific question: a LAN-Play title takes the console
     * off the internet (Nintendo's own LAN Play page says only that the consoles
     * must share a router, and switch-lan-play goes as far as telling users to
     * set a bogus gateway and ignore the failed connectivity test). If that also
     * kills our route to UDP/9993, ZeroTier stops and the whole design falls
     * over. status.txt cannot answer it -- it only shows the present -- so this
     * records the shape of a whole session: start a match, play, quit, then read
     * uplink.log and see whether the rates ever went to zero. */
    void Port::heartbeat()
    {
        /* 30 s when healthy; 5 s while the wire socket is down. During an
         * outage the beat IS the liveness proof for this thread -- if it stops,
         * the loop stopped, and that is a different bug from a dead socket. */
        const int64_t interval = (m_wireFd < 0 || m_wireRecovering) ? 5000 : 30000;

        const int64_t now = NowMs();
        if (m_lastBeatMs != 0 && (now - m_lastBeatMs) < interval) { return; }
        m_lastBeatMs = now;

        const unsigned tx = m_wireTx, rx = m_wireRx;
        /* No peer count: ZT_Node_peers() allocates a ZT_PeerList out of the
         * same fixed arena and would have to be freed again every 30 s. The
         * send/receive rates are the signal we actually need. */
        ztnx::Event("beat %s %s %s tx +%u rx +%u fail %u errno %d %s v6skip %u",
              m_online ? "ONLINE " : "offline",
              NetStatusName(m_netStatus),
              m_wireRecovering ? "PAUSED " : "running",
              tx - m_beatLastTx, rx - m_beatLastRx,
              (unsigned)m_wireTxFail, m_wireErrno, ErrnoName(m_wireErrno),
              m_wireSkipV6);
        m_beatLastTx = tx;
        m_beatLastRx = rx;
    }

    void Port::writeStatus(bool force)
    {
        const int64_t now = NowMs();
        const uint32_t ip      = m_vnet.localIp();
        const uint32_t netmask = m_vnet.netmask();
        const uint64_t mac     = m_vnet.localMac();

        /* Every 10 s, whether or not anything changed.
         *
         * It used to write only on change -- the second condition below made
         * the timer dead code -- so status.txt froze the moment the node
         * settled, which is why three captures in a row were byte-identical.
         * On a timer it becomes a liveness channel independent of uplink.log:
         * a fresh uptime here beside a stale uplink.log means the LOGGING
         * stopped, and both stale means the THREAD stopped. */
        const bool changed = (m_online != m_lastStatusOnline) || (ip != m_lastStatusIp) ||
                             (m_netStatus != m_lastStatusNetStatus);
        if (!force && !changed && (now - m_lastStatusMs) < 10000) { return; }

        m_lastStatusMs = now;
        m_lastStatusOnline = m_online;
        m_lastStatusIp = ip;
        m_lastStatusNetStatus = m_netStatus;

        const auto &s = m_vnet.stats();
        char text[768];
        std::snprintf(text, sizeof(text),
            "uptime    %llu s   loops %llu\n"
            "wire      fd %d  %s  local %u (%s)  tx %u  rx %u  fail %u  v6skip %u  errno %d %s\n"
            "wirelast  dst %u.%u.%u.%u:%u\n"
            "nat       %s local %u public %u.%u.%u.%u:%u\n"
            "poll      err %u (%s)  timeout %u  hup %u\n"
            "writefail %u\n"
            "network   %.16llx\n"
            "online    %s\n"
            "netstatus %s\n"
            "lasterror %d\n"
            "address   %u.%u.%u.%u/%u\n"
            "mac       %.12llx\n"
            "rx        frames %u  ip %u  udp %u  arp %u  icmp %u\n"
            "tx        frames %u  udp %u  arp %u  icmp %u\n"
            "drops     nosock %u  nobuf %u  csum %u  malformed %u\n"
            "nosock    last %u.%u.%u.%u:%u -> port %u len %u\n",
            (unsigned long long)(armGetSystemTick() / (19200 * 1000)),
            (unsigned long long)m_loops,
            m_wireFd, m_wireRecovering ? "paused" : "running",
            (unsigned)m_wireLocalPort, m_wireEphemeral ? "adaptive" : "primary",
            m_wireTx, m_wireRx, m_wireTxFail, m_wireSkipV6,
            m_wireErrno, ErrnoName(m_wireErrno),
            (unsigned)((m_wireLastDstIp >> 24) & 0xFF),
            (unsigned)((m_wireLastDstIp >> 16) & 0xFF),
            (unsigned)((m_wireLastDstIp >> 8) & 0xFF),
            (unsigned)(m_wireLastDstIp & 0xFF),
            (unsigned)m_wireLastDstPort,
            m_natEnabled ? "enabled" : "disabled", unsigned(m_mappedPort),
            unsigned((ntohl(m_natAddress) >> 24) & 255), unsigned((ntohl(m_natAddress) >> 16) & 255),
            unsigned((ntohl(m_natAddress) >> 8) & 255), unsigned(ntohl(m_natAddress) & 255),
            unsigned(m_natPublicPort),
            m_pollErr, ErrnoName(m_pollErrno), m_pollZero, m_pollBad,
            g_writeFails,
            (unsigned long long)m_nwid,
            m_online ? "yes" : "no",
            NetStatusName(m_netStatus),
            m_lastError,
            (unsigned)((ip >> 24) & 0xFF), (unsigned)((ip >> 16) & 0xFF),
            (unsigned)((ip >> 8) & 0xFF),  (unsigned)(ip & 0xFF),
            (unsigned)__builtin_popcount(netmask),
            (unsigned long long)mac,
            s.rxFrames, s.rxIp, s.rxUdp, s.rxArp, s.rxIcmp,
            s.txFrames, s.txUdp, s.txArp, s.txIcmp,
            s.dropNoSocket, s.dropNoBuffer, s.dropBadChecksum, s.dropMalformed,
            (unsigned)((s.lastNoSocketSrcIp >> 24) & 0xFF),
            (unsigned)((s.lastNoSocketSrcIp >> 16) & 0xFF),
            (unsigned)((s.lastNoSocketSrcIp >> 8) & 0xFF),
            (unsigned)(s.lastNoSocketSrcIp & 0xFF),
            (unsigned)s.lastNoSocketSrcPort,
            (unsigned)s.lastNoSocketDstPort,
            (unsigned)s.lastNoSocketLen);

        WriteWholeFile(StatusPath, text);
    }

    void Port::Finalize()
    {
        QuiesceNatMapper();
        closeNatWire();
        m_wireReachable.store(false, std::memory_order_release);
        if (m_node)   { ZT_Node_delete(m_node); m_node = nullptr; }
        if (m_wireFd >= 0) { ::close(m_wireFd); m_wireFd = -1; }
    }

}  // namespace ztnx

/* ------------------------------------------------------------------------ */
/* The one symbol ZeroTier's core asks the port layer for.                    */
/*                                                                            */
/* patches/0001-horizon-port.patch replaces the /dev/urandom read in           */
/* Utils::getSecureRandom() with a call to this. It stays extern "C" and takes */
/* plain types so that node/Utils.cpp needs no header from us -- the core keeps */
/* its independence from libnx.                                               */
/* ------------------------------------------------------------------------ */
extern "C" void ztnx_secure_random_fill(void *buf, unsigned long len)
{
    ztnx::SecureRandom(buf, static_cast<size_t>(len));
}
