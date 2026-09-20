/*
 * sys-zerotier -- bsd:u MITM, stage 4a: transparent relay plus observation.
 *
 * Every command is forwarded to the real service unchanged. Nothing is
 * diverted yet. The point of this stage is to convert the assumptions in
 * BSD_MITM.md into measured fact -- which commands a LAN-play title actually
 * uses, which ports it binds, whether it sets SO_BROADCAST, where it sends --
 * before a single packet is rerouted.
 *
 * If the relay is faithful the game cannot tell we are here.
 */
#include "bsd_shim.hpp"
#include "lan_titles.hpp"
#include "../zt_port.hpp"
#include "../net/lifetime.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <vector>

namespace ztnx::mitm {

    namespace {

        /* Observation log. A ring, like uplink.log, so a long session keeps its
         * most recent traffic rather than its first few seconds. */
        /* Splatoon creates a 13-session BSD clone pool during Shoal startup.
         * Its control setup and teardown alone consume almost the old 64-line
         * ring, hiding the NIFM command that preceded an nnSdk abort. */
        constexpr int    LogLines   = 96;
        constexpr size_t LogLineLen = 112;
        constexpr size_t LogBytes = LogLines * LogLineLen;
        /* These forensic buffers used to cost about 36 KiB of resident .bss
         * even during ordinary play. Allocate the smaller release rings only
         * when debug_logging is enabled. A failed diagnostic allocation drops
         * logs; it must never affect networking. */
        char  *g_log = nullptr;
        char  *g_flushText = nullptr;
        int    g_logCount = 0;
        ams::os::SdkMutex g_logLock;
        bool   g_logDirty = false;

        /* NIFM's 17-request Shoal chronology was completely displaced by
         * Splatoon's two BSD clone-pool setup/teardown bursts. Keep the
         * compact post-dispatch results in their own bounded file. */
        constexpr int    NifmLogLines   = 24;
        constexpr size_t NifmLogLineLen = 112;
        constexpr size_t NifmLogBytes = NifmLogLines * NifmLogLineLen;
        char  *g_nifmLog = nullptr;
        char  *g_nifmFlushText = nullptr;
        int    g_nifmLogCount = 0;
        ams::os::SdkMutex g_nifmLogLock;
        bool   g_nifmLogDirty = false;

        bool EnsureBsdLogBuffersLocked()
        {
            if (g_log != nullptr && g_flushText != nullptr) { return true; }
            char *ring = static_cast<char *>(std::malloc(LogBytes));
            char *text = static_cast<char *>(std::malloc(LogBytes + 64));
            if (ring == nullptr || text == nullptr) {
                std::free(ring);
                std::free(text);
                return false;
            }
            std::memset(ring, 0, LogBytes);
            g_log = ring;
            g_flushText = text;
            return true;
        }

        bool EnsureNifmLogBuffersLocked()
        {
            if (g_nifmLog != nullptr && g_nifmFlushText != nullptr) { return true; }
            char *ring = static_cast<char *>(std::malloc(NifmLogBytes));
            char *text = static_cast<char *>(std::malloc(NifmLogBytes + 64));
            if (ring == nullptr || text == nullptr) {
                std::free(ring);
                std::free(text);
                return false;
            }
            std::memset(ring, 0, NifmLogBytes);
            g_nifmLog = ring;
            g_nifmFlushText = text;
            return true;
        }

        void FlushNifmTrace() {
            std::scoped_lock lk(g_nifmLogLock);
            if (!g_nifmLogDirty || g_nifmLog == nullptr || g_nifmFlushText == nullptr) { return; }
            g_nifmLogDirty = false;

            size_t off = 0;
            const int first = (g_nifmLogCount > NifmLogLines) ?
                (g_nifmLogCount - NifmLogLines) : 0;
            for (int i = first; i < g_nifmLogCount &&
                 off + NifmLogLineLen + 2 < NifmLogBytes + 64; ++i) {
                const char *line = g_nifmLog + (i % NifmLogLines) * NifmLogLineLen;
                const size_t len = std::strlen(line);
                std::memcpy(g_nifmFlushText + off, line, len);
                off += len;
                g_nifmFlushText[off++] = '\n';
            }
            g_nifmFlushText[off] = '\0';
            ztnx::WriteTextFile(NifmLogPath, g_nifmFlushText);
        }

        /* Hot discovery/session flows repeat indefinitely and used to erase
         * all setup evidence from the 64-line ring. Keep a small allocation-
         * free key table and log each flow at counts 1,2,4,8,... instead. */
        constexpr int FlowSlots = 24;
        struct FlowCounter {
            u8 kind;
            s32 fd;
            u32 ip;
            u16 port;
            u16 len;
            u32 count;
            bool used;
        };
        FlowCounter g_flows[FlowSlots] = {};
        ams::os::SdkMutex g_flowLock;

        /* PIA 5.7--5.45 browse traffic is cryptographically challenged. UDP
         * delivery alone therefore cannot tell us whether a later reply is
         * usable. Retain only hashes/counters from the latest request so the
         * diagnostic log can prove whether the host's advertised session-key
         * parameter follows the request that triggered its reply. */
        struct BrowseRequestObservation {
            u64 pid;
            s32 fd;
            u32 srcIp;
            u64 counter;
            u32 keyHash;
            u32 count;
        };
        BrowseRequestObservation g_last_browse_request{};
        ams::os::SdkMutex g_browse_observation_lock;

        /* Capture matched PIA browse exchanges for offline validation.
         * The game-specific AES key is outside this shim, so hashes cannot
         * distinguish a bad challenge response from a bad advertised host.
         * Keep the first and latest request/reply pair for the current process
         * and network id. (Different PIA 5.9 games both begin at 11f3c000.)
         * That lets one run compare the room before a peer joins with the same
         * still-open room after it leaves. Allocation is diagnostics-only
         * and bounded to seven protocol-maximum packets (9548 bytes, including
         * the two reusable flush copies). */
        constexpr size_t PiaPacketMax = 1364;
        u8 *g_pia_latest_request = nullptr;
        u8 *g_pia_first_request = nullptr;
        u8 *g_pia_first_reply = nullptr;
        u8 *g_pia_capture_request = nullptr;
        u8 *g_pia_capture_reply = nullptr;
        u8 *g_pia_flush_request = nullptr;
        u8 *g_pia_flush_reply = nullptr;
        size_t g_pia_latest_request_len = 0;
        size_t g_pia_first_request_len = 0;
        size_t g_pia_first_reply_len = 0;
        size_t g_pia_capture_request_len = 0;
        size_t g_pia_capture_reply_len = 0;
        u64 g_pia_capture_pid = 0;
        u32 g_pia_capture_network_id = 0;
        bool g_pia_first_dirty = false;
        bool g_pia_capture_dirty = false;

        bool EnsurePiaCaptureBuffersLocked() {
            if (g_pia_latest_request != nullptr && g_pia_first_request != nullptr &&
                g_pia_first_reply != nullptr && g_pia_capture_request != nullptr &&
                g_pia_capture_reply != nullptr && g_pia_flush_request != nullptr &&
                g_pia_flush_reply != nullptr) {
                return true;
            }
            u8 *latest = static_cast<u8 *>(std::malloc(PiaPacketMax));
            u8 *first_request = static_cast<u8 *>(std::malloc(PiaPacketMax));
            u8 *first_reply = static_cast<u8 *>(std::malloc(PiaPacketMax));
            u8 *request = static_cast<u8 *>(std::malloc(PiaPacketMax));
            u8 *reply = static_cast<u8 *>(std::malloc(PiaPacketMax));
            u8 *flush_request = static_cast<u8 *>(std::malloc(PiaPacketMax));
            u8 *flush_reply = static_cast<u8 *>(std::malloc(PiaPacketMax));
            if (latest == nullptr || first_request == nullptr || first_reply == nullptr ||
                request == nullptr || reply == nullptr || flush_request == nullptr ||
                flush_reply == nullptr) {
                std::free(latest);
                std::free(first_request);
                std::free(first_reply);
                std::free(request);
                std::free(reply);
                std::free(flush_request);
                std::free(flush_reply);
                return false;
            }
            g_pia_latest_request = latest;
            g_pia_first_request = first_request;
            g_pia_first_reply = first_reply;
            g_pia_capture_request = request;
            g_pia_capture_reply = reply;
            g_pia_flush_request = flush_request;
            g_pia_flush_reply = flush_reply;
            return true;
        }

        void FlushPiaCapture() {
            size_t request_len = 0;
            size_t reply_len = 0;
            bool write_first = false;
            {
                std::scoped_lock lk(g_browse_observation_lock);
                if (!g_pia_first_dirty && !g_pia_capture_dirty) { return; }
                if (!EnsurePiaCaptureBuffersLocked()) { return; }
                if (g_pia_first_dirty) {
                    request_len = g_pia_first_request_len;
                    reply_len = g_pia_first_reply_len;
                    std::memcpy(g_pia_flush_request, g_pia_first_request, request_len);
                    std::memcpy(g_pia_flush_reply, g_pia_first_reply, reply_len);
                    g_pia_first_dirty = false;
                    write_first = true;
                }
            }
            if (write_first) {
                (void)ztnx::WriteBinaryFile(PiaFirstRequestCapturePath,
                                            g_pia_flush_request, request_len);
                (void)ztnx::WriteBinaryFile(PiaFirstReplyCapturePath,
                                            g_pia_flush_reply, reply_len);
            }

            request_len = 0;
            reply_len = 0;
            {
                std::scoped_lock lk(g_browse_observation_lock);
                if (!g_pia_capture_dirty || !EnsurePiaCaptureBuffersLocked()) { return; }
                request_len = g_pia_capture_request_len;
                reply_len = g_pia_capture_reply_len;
                std::memcpy(g_pia_flush_request, g_pia_capture_request, request_len);
                std::memcpy(g_pia_flush_reply, g_pia_capture_reply, reply_len);
                g_pia_capture_dirty = false;
            }
            (void)ztnx::WriteBinaryFile(PiaRequestCapturePath,
                                        g_pia_flush_request, request_len);
            (void)ztnx::WriteBinaryFile(PiaReplyCapturePath,
                                        g_pia_flush_reply, reply_len);
        }

        /* sendmmsg serialises scatter/gather vectors into one IPC buffer.
         * PIA browse replies are at most 1364 bytes, so one bounded assembly
         * area is enough to mirror a multi-iovec message without heap use or
         * a large allocation on the 16 KiB MITM server stack. */
        constexpr size_t MMsgPayloadMax = 2048;
        alignas(8) u8 g_mmsgPayload[MMsgPayloadMax];
        ams::os::SdkMutex g_mmsgLock;

        bool SampleFlow(u8 kind, s32 fd, u32 ip, u16 port, u16 len, u32 *count) {
            if (!ztnx::DiagnosticsEnabled()) { return false; }
            std::scoped_lock lk(g_flowLock);
            FlowCounter *slot = nullptr;
            for (auto &flow : g_flows) {
                if (flow.used && flow.kind == kind && flow.fd == fd && flow.ip == ip &&
                    flow.port == port && flow.len == len) {
                    slot = std::addressof(flow);
                    break;
                }
                if (!flow.used && slot == nullptr) { slot = std::addressof(flow); }
            }
            if (slot == nullptr) { return false; }
            if (!slot->used) {
                *slot = FlowCounter{kind, fd, ip, port, len, 0, true};
            }
            *count = ++slot->count;
            return (*count & (*count - 1)) == 0;
        }

        void Note(const char *fmt, ...) {
            if (!ztnx::DiagnosticsEnabled()) { return; }
            std::scoped_lock lk(g_logLock);
            if (!EnsureBsdLogBuffersLocked()) { return; }
            char *dst = g_log + (g_logCount % LogLines) * LogLineLen;
            va_list ap;
            va_start(ap, fmt);
            std::vsnprintf(dst, LogLineLen, fmt, ap);
            va_end(ap);
            ++g_logCount;
            g_logDirty = true;
        }

        /* Decode just enough of a sockaddr_in to be readable in the log. */
        void FormatAddr(char *out, size_t n, const void *addr, size_t len) {
            if (addr == nullptr || len < 8) { std::snprintf(out, n, "?"); return; }
            const u8 *p = static_cast<const u8 *>(addr);
            /* BSD sockaddr: u8 len, u8 family, u16 port(BE), u32 addr(BE) */
            const unsigned port = (unsigned)((p[2] << 8) | p[3]);
            std::snprintf(out, n, "%u.%u.%u.%u:%u", p[4], p[5], p[6], p[7], port);
        }

    }

    void NoteSync(const char *fmt, ...) {
        if (!ztnx::DiagnosticsEnabled()) { return; }
        {
            std::scoped_lock lk(g_logLock);
            if (!EnsureBsdLogBuffersLocked()) { return; }
            char *dst = g_log + (g_logCount % LogLines) * LogLineLen;
            va_list ap;
            va_start(ap, fmt);
            std::vsnprintf(dst, LogLineLen, fmt, ap);
            va_end(ap);
            ++g_logCount;
            g_logDirty = true;
        }
        FlushObservations();
    }

    void NoteNifmSync(const char *fmt, ...) {
        if (!ztnx::DiagnosticsEnabled()) { return; }
        {
            std::scoped_lock lk(g_nifmLogLock);
            if (!EnsureNifmLogBuffersLocked()) { return; }
            char *dst = g_nifmLog + (g_nifmLogCount % NifmLogLines) * NifmLogLineLen;
            va_list ap;
            va_start(ap, fmt);
            std::vsnprintf(dst, NifmLogLineLen, fmt, ap);
            va_end(ap);
            ++g_nifmLogCount;
            g_nifmLogDirty = true;
        }
        FlushNifmTrace();
    }

    void NoteNifm(const char *fmt, ...) {
        if (!ztnx::DiagnosticsEnabled()) { return; }
        std::scoped_lock lk(g_nifmLogLock);
        if (!EnsureNifmLogBuffersLocked()) { return; }
        char *dst = g_nifmLog + (g_nifmLogCount % NifmLogLines) * NifmLogLineLen;
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(dst, NifmLogLineLen, fmt, ap);
        va_end(ap);
        ++g_nifmLogCount;
        g_nifmLogDirty = true;
    }

    void FlushObservations() {
        {
            std::scoped_lock lk(g_logLock);
            if (g_logDirty && g_log != nullptr && g_flushText != nullptr) {
                g_logDirty = false;

                size_t off = 0;
                const int first = (g_logCount > LogLines) ? (g_logCount - LogLines) : 0;
                for (int i = first; i < g_logCount &&
                     off + LogLineLen + 2 < LogBytes + 64; ++i) {
                    const char *line = g_log + (i % LogLines) * LogLineLen;
                    const size_t len = std::strlen(line);
                    std::memcpy(g_flushText + off, line, len);
                    off += len;
                    g_flushText[off++] = '\n';
                }
                g_flushText[off] = '\0';
                ztnx::WriteTextFile(BsdLogPath, g_flushText);
            }
        }
        FlushPiaCapture();
    }

    namespace {

        /* Unregistered forward sessions belonging to clients that connected
         * to bsd:u through us and then released the MITM object.
         *
         * Closing such a session freezes the system. This is not our finding --
         * ryu_ldn_nx (a working bsd:u MITM) documents exactly the same failure
         * and uses exactly this workaround: keep a reference forever so the
         * shared_ptr never reaches zero and serviceClose is never called. The
         * retention is one Service handle per torn-down session. The node
         * maintenance pass releases them after confirmed process exit; never
         * close a live client's retained sessions merely to hit a size cap.
         *
         * Why it plausibly matters here: some nnSdk clients create and discard
         * a session before command 0 lands. That is precisely an unregistered
         * session. Registered sessions are deliberately excluded: real bsd
         * owns a copy of their transfer-memory handle, and retaining one past
         * socket teardown leaves the pages locked for the next initialization. */
        struct ParkedService { u64 pid; std::shared_ptr<::Service> service; };
        std::vector<ParkedService> g_parked_forward_services;
        ams::os::SdkMutex                       g_parked_lock;

        bool ProcessHasExited(u64 pid) {
            u64 live[128]{};
            s32 count = 0;
            const auto rc = svcGetProcessList(&count, live, 128);
            return net::ProcessListConfirmsExit(pid, live, count, 128, R_SUCCEEDED(rc));
        }

        void ReleaseRetiredService(std::shared_ptr<::Service> &service) {
            if (service && service->own_handle && service->session != INVALID_HANDLE) {
                /* These forward services are non-domain sessions. Skip the
                 * synchronous CMIF close, which can hang on an abandoned
                 * session. Caller must prove process exit or full BSD shutdown. */
                svcCloseHandle(service->session);
                *service = {};
            }
            service.reset();
        }

        /* bsd:u sessions opened per client process, counted monotonically in
         * ShouldMitm. A session teardown must not decrement this counter: the
         * first skipped connection is a one-time dummy, not the first
         * currently-live connection. Splatoon closes its registered setup
         * session before opening the monitor/socket sessions, and decrementing
         * here made the next real connection look like session #2 again.
         *
         * THE FIRST SESSION MUST NOT BE INTERCEPTED. A game opens a bsd:u
         * session, never sends RegisterClient on it, and drops it; the real
         * networking happens on session #2 onward. ryu_ldn_nx puts it plainly:
         *
         *   "Games typically open a 'dummy' first session that is never used
         *    (no RegisterClient is ever called on it). Intercepting this
         *    session causes system instability/crashes even if we try to
         *    handle it gracefully."
         *
         * That is our exact symptom -- two accepts, no handler ever reached,
         * nnSdk aborting inside CreateClientServiceByHipc -- so this is the
         * single change most likely to be the fix.
         *
         * Fixed table rather than a map: this runs on the sm callback path and
         * must not allocate. The larger count also tolerates many successive
         * hardware test launches before the sysmodule is restarted. */
        constexpr int MaxTrackedClients = 32;
        struct ClientSessions { u64 pid; int count; };
        ClientSessions    g_client_sessions[MaxTrackedClients] = {};
        ams::os::SdkMutex g_client_sessions_lock;

        /* BSD fds are per client process, while the virtual socket number is
         * local to VNet. Keep both values in this fixed table: MITM handlers
         * can arrive on any one of a game's bsd:u sessions, so session-local
         * state would be intermittently wrong. */
        constexpr int MaxLanSockets = 8;
        struct LanSocket {
            u64 pid;
            s32 bsdFd;
            s32 vnetFd;
            u16 boundPort;
            u16 connectedPort;
            u32 connectedIp;
            bool udp;
            bool broadcast;
            bool mirrored;
            bool connected;
        };
        LanSocket g_lan_sockets[MaxLanSockets] = {};
        ams::os::SdkMutex g_lan_sockets_lock;
        ztnx::Port *g_port = nullptr;
        u32 g_physicalIp = 0;
        u32 g_physicalMask = 0;

        /* Splatoon 2 tears down and recreates nn::socket environments quickly.
         * Forwarding the game's TransferMemory handle gives real bsd a copy
         * whose asynchronous session teardown can leave the game's reusable
         * pages locked; the next CreateTransferMemory then returns 0xD401.
         *
         * Command 33 was tested as a handle-free substitute and is NOT a
         * transparent bsd:u command-0 replacement: real bsd returned output 1
         * and nnSdk asserted in InitializeCommon before StartMonitoring. Keep
         * command 0 and its exact ABI. Instead, give real bsd a title-private
         * TransferMemory object. The game keeps and closes its own object
         * normally, while delayed real-bsd handle destruction can lock only
         * these dedicated pages.
         *
         * Preserve the initial TCP buffers, UDP buffers, and efficiency, but
         * remove TCP growth headroom so the required work area is exactly 592
         * KiB for Splatoon 2's observed config. Splatoon LAN is UDP; this
         * avoids paying the game's 6016 KiB over-allocation out of the
         * sysmodule's tight memory budget.
         *
         * Do not give real bsd the same TransferMemory object in a later
         * registration. Hardware proved the first registration and monitoring
         * work, then a second registration stopped inside real bsd. Retain the
         * first registered forward session for this game process and answer
         * later command-0 cycles from the cached successful response. This is
         * also substantially cheaper than a second work area: the fatal report
         * proved Atmosphere's fatal process could not obtain its required 2 MiB
         * display block with only 1308 KiB of global system memory free. */
        constexpr u64 BsdWorkPage = 0x1000;
        constexpr size_t Splatoon2ProxyTmemSize = 0x94000;
        alignas(BsdWorkPage) constinit u8
            g_splatoon2_proxy_tmem_buffer[Splatoon2ProxyTmemSize];
        constinit ams::os::TransferMemoryType g_splatoon2_proxy_tmem{};
        bool g_splatoon2_proxy_tmem_ready = false;
        ams::os::SdkMutex g_splatoon2_proxy_tmem_lock;

        /* Real bsd's registration is process-wide even though nnSdk creates a
         * fresh command-0 session for each socket environment. Keep the one
         * forward session that owns the proxy registration alive, and cache
         * the exact service output for later command-0 calls from the same
         * process. A new process id retires the old owner before registering. */
        ams::os::SdkMutex g_splatoon2_registration_lock;
        std::shared_ptr<::Service> g_splatoon2_registration_owner;
        u64 g_splatoon2_registered_pid = 0;
        u64 g_splatoon2_registered_out = 0;

        bool BuildSplatoon2ProxyConfig(const BsdServiceConfig &requested,
                                       BsdServiceConfig *proxy,
                                       u64 *minimum_work_size) {
            if (proxy == nullptr || minimum_work_size == nullptr ||
                requested.sb_efficiency == 0) {
                return false;
            }

            *proxy = requested;
            proxy->tcp_tx_buf_max_size = requested.tcp_tx_buf_size;
            proxy->tcp_rx_buf_max_size = requested.tcp_rx_buf_size;

            const u64 sum = static_cast<u64>(proxy->tcp_tx_buf_size) +
                            static_cast<u64>(proxy->tcp_rx_buf_size) +
                            static_cast<u64>(proxy->udp_tx_buf_size) +
                            static_cast<u64>(proxy->udp_rx_buf_size);
            const u64 aligned = (sum + (BsdWorkPage - 1)) & ~(BsdWorkPage - 1);
            if (aligned < BsdWorkPage || aligned > Splatoon2ProxyTmemSize) {
                return false;
            }

            const u64 maximum_efficiency = Splatoon2ProxyTmemSize / aligned;
            u32 efficiency = proxy->sb_efficiency;
            if (static_cast<u64>(efficiency) > maximum_efficiency) {
                efficiency = static_cast<u32>(maximum_efficiency);
            }
            if (efficiency == 0 || aligned * efficiency > Splatoon2ProxyTmemSize) {
                return false;
            }

            proxy->sb_efficiency = efficiency;
            *minimum_work_size = aligned * efficiency;
            return true;
        }

        ams::Result EnsureSplatoon2ProxyTmem(::Handle *out_handle) {
            std::scoped_lock lk(g_splatoon2_proxy_tmem_lock);
            if (!g_splatoon2_proxy_tmem_ready) {
                R_TRY(ams::os::CreateTransferMemory(
                    std::addressof(g_splatoon2_proxy_tmem),
                    g_splatoon2_proxy_tmem_buffer,
                    Splatoon2ProxyTmemSize,
                    ams::os::MemoryPermission_None));
                g_splatoon2_proxy_tmem_ready = true;
            }
            *out_handle = g_splatoon2_proxy_tmem.handle;
            R_SUCCEED();
        }

        bool IsPiaLanPort(u16 port) {
            /* PIA browse moved from 30000 to 35000 in newer protocol
             * revisions. 40000 is the browse-response socket observed in
             * MK8D; 49152--49155 carry session setup, keepalive and gameplay. */
            return port == 30000 || port == 35000 || port == 40000 ||
                   (port >= 49152 && port <= 49155);
        }

        LanSocket *FindLanSocketLocked(u64 pid, s32 fd) {
            if (fd == net::InvalidSocket) { return nullptr; }
            for (auto &s : g_lan_sockets) {
                if (s.pid == pid && s.bsdFd == fd) { return std::addressof(s); }
            }
            return nullptr;
        }

        void ForgetLanSocket(u64 pid, s32 fd) {
            s32 vfd = net::InvalidSocket;
            u16 bound_port = 0;
            bool found = false;
            {
                std::scoped_lock lk(g_lan_sockets_lock);
                if (LanSocket *s = FindLanSocketLocked(pid, fd); s != nullptr) {
                    found = true;
                    vfd = s->vnetFd;
                    bound_port = s->boundPort;
                    *s = LanSocket{};
                }
            }
            if (vfd != net::InvalidSocket && g_port != nullptr) { g_port->CloseLanSocket(vfd); }
            if (found) {
                Note("Close shadow    fd %d released", fd);
            }
            if (bound_port == 30000) {
                std::scoped_lock lk(g_browse_observation_lock);
                if (g_last_browse_request.pid == pid &&
                    g_last_browse_request.fd == fd) {
                    g_last_browse_request = BrowseRequestObservation{};
                    g_pia_latest_request_len = 0;
                }
            }
        }

        int ForgetLanSocketsForPid(u64 pid) {
            /* A process exit closes its real BSD descriptors without
             * necessarily issuing command 26 for each one. Keeping the
             * corresponding shadow sockets consumes both fixed socket tables
             * and, once remote broadcasts arrive, all eight shared RX packet
             * buffers. Collect under the table lock and close through Port
             * afterwards so the lock order never nests g_lan_sockets_lock with
             * Port's VNet lock. */
            s32 vfds[MaxLanSockets];
            int count = 0;
            {
                std::scoped_lock lk(g_lan_sockets_lock);
                for (auto &s : g_lan_sockets) {
                    if (s.pid != pid) { continue; }
                    if (s.vnetFd != net::InvalidSocket && count < MaxLanSockets) {
                        vfds[count++] = s.vnetFd;
                    }
                    s = LanSocket{};
                }
            }
            if (g_port != nullptr) {
                for (int i = 0; i < count; ++i) { g_port->CloseLanSocket(vfds[i]); }
            }
            {
                std::scoped_lock lk(g_browse_observation_lock);
                if (g_last_browse_request.pid == pid) { g_last_browse_request = {}; }
            }
            return count;
        }

        s32 GetLanVfd(u64 pid, s32 fd) {
            std::scoped_lock lk(g_lan_sockets_lock);
            if (LanSocket *s = FindLanSocketLocked(pid, fd); s != nullptr && s->mirrored) {
                return s->vnetFd;
            }
            return net::InvalidSocket;
        }

        s32 EnsureLanMirror(u64 pid, s32 fd, u16 port, const char *reason) {
            if (g_port == nullptr || port == 0) { return net::InvalidSocket; }
            {
                std::scoped_lock lk(g_lan_sockets_lock);
                LanSocket *s = FindLanSocketLocked(pid, fd);
                if (s == nullptr || !s->udp) { return net::InvalidSocket; }
                if (s->mirrored) { return s->vnetFd; }
            }

            const s32 candidate = g_port->OpenLanSocket();
            if (candidate == net::InvalidSocket || !g_port->BindLanSocket(candidate, port)) {
                if (candidate != net::InvalidSocket) { g_port->CloseLanSocket(candidate); }
                Note("LAN mirror      fd %d port %u unavailable (%s)", fd, port, reason);
                return net::InvalidSocket;
            }

            s32 selected = net::InvalidSocket;
            bool installed = false;
            {
                std::scoped_lock lk(g_lan_sockets_lock);
                if (LanSocket *s = FindLanSocketLocked(pid, fd); s != nullptr && s->udp) {
                    if (!s->mirrored) {
                        s->vnetFd = candidate;
                        s->mirrored = true;
                        selected = candidate;
                        installed = true;
                    } else {
                        selected = s->vnetFd;
                    }
                }
            }
            if (!installed) { g_port->CloseLanSocket(candidate); }
            if (installed) { Note("LAN mirror      fd %d port %u -> vfd %d (%s)", fd, port, candidate, reason); }
            return selected;
        }

        bool GetConnectedLanPeer(u64 pid, s32 fd, s32 *vfd, u32 *ip, u16 *port) {
            std::scoped_lock lk(g_lan_sockets_lock);
            LanSocket *s = FindLanSocketLocked(pid, fd);
            if (s == nullptr || !s->mirrored || !s->connected) { return false; }
            *vfd = s->vnetFd;
            *ip = s->connectedIp;
            *port = s->connectedPort;
            return true;
        }

        bool IsOverlayDestination(u32 ip, bool *broadcast) {
            if (g_port == nullptr || broadcast == nullptr) { return false; }
            u32 local = 0;
            u32 mask = 0;
            if (!g_port->GetLanIpConfig(std::addressof(local), std::addressof(mask))) {
                return false;
            }
            *broadcast = ip == 0xFFFFFFFFu || ip == (local | ~mask);
            return *broadcast || (ip & mask) == (local & mask);
        }

        u32 ReadBe32(const u8 *p) {
            return (static_cast<u32>(p[0]) << 24) |
                   (static_cast<u32>(p[1]) << 16) |
                   (static_cast<u32>(p[2]) << 8) | p[3];
        }

        u64 ReadBe64(const u8 *p) {
            return (static_cast<u64>(ReadBe32(p)) << 32) | ReadBe32(p + 4);
        }

        u32 Fingerprint32(const u8 *p, size_t len) {
            /* FNV-1a is sufficient here: this is a change detector in an
             * opt-in trace, not a cryptographic decision. Never log keys. */
            u32 hash = 2166136261u;
            for (size_t i = 0; i < len; ++i) {
                hash ^= p[i];
                hash *= 16777619u;
            }
            return hash;
        }

        int FindIpOffset(const u8 *data, size_t len, u32 ip) {
            if (data == nullptr || len < 4 || ip == 0) { return -1; }
            const u8 bytes[4] = {
                static_cast<u8>(ip >> 24), static_cast<u8>(ip >> 16),
                static_cast<u8>(ip >> 8), static_cast<u8>(ip)
            };
            for (size_t i = 0; i + sizeof(bytes) <= len; ++i) {
                if (std::memcmp(data + i, bytes, sizeof(bytes)) == 0) {
                    return static_cast<int>(i);
                }
            }
            return -1;
        }

        void ObserveBrowseRequest(u64 pid, s32 fd, const void *data, size_t len,
                                  u32 src_ip, u16 src_port) {
            if (!ztnx::DiagnosticsEnabled()) { return; }
            const u8 *packet = static_cast<const u8 *>(data);
            if (packet == nullptr || len < 5 || packet[0] != 0 || src_port != 30000) {
                return;
            }
            const u32 criteria_size = ReadBe32(packet + 1);
            const size_t challenge_offset = 5 + static_cast<size_t>(criteria_size);
            if (challenge_offset > len || len - challenge_offset < 42) { return; }
            const u8 *challenge = packet + challenge_offset;
            const u64 counter = ReadBe64(challenge + 2);
            const u32 key_hash = Fingerprint32(challenge + 10, 16);
            u32 count = 0;
            {
                std::scoped_lock lk(g_browse_observation_lock);
                count = g_last_browse_request.count + 1;
                g_last_browse_request = { pid, fd, src_ip, counter, key_hash, count };
                if (len <= PiaPacketMax && EnsurePiaCaptureBuffersLocked()) {
                    std::memcpy(g_pia_latest_request, data, len);
                    g_pia_latest_request_len = len;
                }
            }
            if ((count & (count - 1)) == 0) {
                Note("[%8llu] browse req fd %d v%u enc%u ctr %llx key %08x from %08x x%u",
                     (unsigned long long)(armGetSystemTick() / 19200), fd,
                     (unsigned)challenge[0], (unsigned)challenge[1],
                     (unsigned long long)counter, key_hash, src_ip, count);
            }
        }

        bool MirrorLanPayload(u64 pid, s32 fd, s32 vfd, u32 dst_ip,
                              u16 dst_port, bool broadcast,
                              const void *data, size_t len) {
            if (g_port == nullptr) { return false; }
            if (dst_port != 30000 || data == nullptr || len < 5 ||
                static_cast<const u8 *>(data)[0] != 1) {
                return broadcast
                    ? g_port->MirrorLanBroadcast(vfd, dst_port, data, static_cast<unsigned int>(len))
                    : g_port->MirrorLanDatagram(vfd, dst_ip, dst_port, data, static_cast<unsigned int>(len));
            }

            /* Keep browse replies byte-for-byte intact. The session body is
             * covered by PIA's challenge/identity validation; rewriting its
             * address and derived ids made Switch-hosted rooms disappear even
             * though the reply reached the peer. The managed source/destination
             * already provide the ZeroTier transport address, so the safe path
             * is transparent forwarding plus diagnostics. */
            const u8 *packet = static_cast<const u8 *>(data);
            const u32 session_size = ReadBe32(packet + 1);
            const size_t body_size = std::min(len - 5, static_cast<size_t>(session_size));
            const u8 *body = packet + 5;
            const u32 network_id = body_size >= 8 ? ReadBe32(body + 4) : 0;
            const u16 players = body_size > 0x21 ?
                static_cast<u16>((body[0x20] << 8) | body[0x21]) : 0xffff;
            u32 managed_ip = 0;
            u32 physical_ip = 0;
            {
                std::scoped_lock lk(g_lan_sockets_lock);
                physical_ip = g_physicalIp;
            }
            (void)g_port->GetLanIpConfig(std::addressof(managed_ip), nullptr);

            /* Snapshot the exact request and byte-for-byte reply together.
             * The destination check prevents pairing this response with an
             * unrelated peer's most recent broadcast. */
            {
                std::scoped_lock lk(g_browse_observation_lock);
                if (len <= PiaPacketMax && g_pia_latest_request_len != 0 &&
                    g_last_browse_request.pid == pid &&
                    g_last_browse_request.srcIp == dst_ip &&
                    EnsurePiaCaptureBuffersLocked()) {
                    std::memcpy(g_pia_capture_request, g_pia_latest_request,
                                g_pia_latest_request_len);
                    std::memcpy(g_pia_capture_reply, data, len);
                    g_pia_capture_request_len = g_pia_latest_request_len;
                    g_pia_capture_reply_len = len;
                    g_pia_capture_dirty = true;
                    if (g_pia_first_request_len == 0 ||
                        g_pia_capture_pid != pid ||
                        g_pia_capture_network_id != network_id) {
                        std::memcpy(g_pia_first_request, g_pia_latest_request,
                                    g_pia_latest_request_len);
                        std::memcpy(g_pia_first_reply, data, len);
                        g_pia_first_request_len = g_pia_latest_request_len;
                        g_pia_first_reply_len = len;
                        g_pia_capture_pid = pid;
                        g_pia_capture_network_id = network_id;
                        g_pia_first_dirty = true;
                    }
                }
            }
            u32 count = 0;
            if (SampleFlow(8, fd, physical_ip, dst_port, 0, std::addressof(count))) {
                const u8 system_version = body_size > 0x26 ? body[0x26] : 0xff;
                const u16 maximum = body_size > 0x25 ?
                    static_cast<u16>((body[0x24] << 8) | body[0x25]) : 0xffff;
                const u8 opened = body_size > 0x1AE ? body[0x1AE] : 0xff;
                Note("[%8llu] browse reply fd %d net %08x open %u players %u/%u sys %u x%u",
                     (unsigned long long)(armGetSystemTick() / 19200), fd, network_id,
                     (unsigned)opened, (unsigned)players, (unsigned)maximum,
                     (unsigned)system_version, count);
                Note("browse addr    managed@%d physical@%d host %08x",
                     FindIpOffset(body, body_size, managed_ip),
                     FindIpOffset(body, body_size, physical_ip),
                     body_size >= 0x1AF + 35 ?
                         Fingerprint32(body + 0x1AF, 35) : 0);

                /* MK8D's observed 1298-byte LanSessionInfo is the PIA
                 * 5.7--5.9 layout: session key param at 0x4F2, followed by a
                 * 58-byte challenge response. Log fingerprints only. */
                constexpr size_t SessionKeyOffset = 0x4F2;
                const size_t response_offset = 5 + body_size;
                if (body_size >= SessionKeyOffset + 32 && response_offset <= len &&
                    len - response_offset >= 58) {
                    const u8 *response = packet + response_offset;
                    const u32 saved_reply_key = Fingerprint32(body + SessionKeyOffset, 16);
                    const u32 saved_request_key = Fingerprint32(body + SessionKeyOffset + 16, 16);
                    const u32 response_key = Fingerprint32(response + 10, 16);
                    u32 latest_request_key = 0;
                    u64 latest_request_counter = 0;
                    bool same_request = false;
                    {
                        std::scoped_lock lk(g_browse_observation_lock);
                        if (g_last_browse_request.pid == pid &&
                            g_last_browse_request.srcIp == dst_ip) {
                            latest_request_key = g_last_browse_request.keyHash;
                            latest_request_counter = g_last_browse_request.counter;
                            same_request = saved_request_key == latest_request_key;
                        }
                    }
                    Note("[%8llu] crypto v%u e%u c%llx rq%llx k%08x/%08x/%08x m%u",
                         (unsigned long long)(armGetSystemTick() / 19200),
                         (unsigned)response[0], (unsigned)response[1],
                         (unsigned long long)ReadBe64(response + 2),
                         (unsigned long long)latest_request_counter,
                         saved_reply_key, saved_request_key, response_key,
                         same_request ? 1u : 0u);
                }
                Note("browse path    physical %08x managed %08x len %u body %u",
                     physical_ip, managed_ip, (unsigned)len, (unsigned)body_size);
            }
            return g_port->MirrorLanDatagram(vfd, dst_ip, dst_port, data,
                                             static_cast<unsigned int>(len));
        }

        bool MirrorConnectedLanDatagram(u64 pid, s32 fd, const void *data,
                                        size_t len, const char *operation) {
            s32 vfd = net::InvalidSocket;
            u32 ip = 0;
            u16 port = 0;
            if (g_port == nullptr || !GetConnectedLanPeer(pid, fd, std::addressof(vfd),
                                                          std::addressof(ip),
                                                          std::addressof(port))) {
                return false;
            }
            if (!g_port->MirrorLanDatagram(vfd, ip, port, data, (unsigned int)len)) {
                return false;
            }
            u32 count = 0;
            if (SampleFlow(3, fd, ip, port, (u16)len, std::addressof(count))) {
                Note("ZT %-10s fd %d -> %u.%u.%u.%u:%u len %u x%u", operation, fd,
                     (unsigned)(ip >> 24), (unsigned)(ip >> 16) & 0xff,
                     (unsigned)(ip >> 8) & 0xff, (unsigned)ip,
                     port, (unsigned)len, count);
            }
            return true;
        }

        bool LanSocketReadable(u64 pid, s32 fd) {
            const s32 vfd = GetLanVfd(pid, fd);
            return vfd != net::InvalidSocket && g_port != nullptr && g_port->LanSocketReadable(vfd);
        }

        int ReceiveLanDatagram(u64 pid, s32 fd, void *data, size_t max,
                               u32 *src_ip, u16 *src_port, bool peek = false) {
            const s32 vfd = GetLanVfd(pid, fd);
            if (vfd == net::InvalidSocket || g_port == nullptr) { return -1; }
            const int n = g_port->ReceiveLanDatagram(vfd, data, (unsigned int)max,
                                                     src_ip, src_port, peek);
            if (n >= 0) {
                /* PIA may probe with MSG_PEEK before consuming a datagram.
                 * Count and capture the packet once, on the consuming read. */
                if (!peek) {
                    ObserveBrowseRequest(pid, fd, data, static_cast<size_t>(n),
                                         *src_ip, *src_port);
                } else {
                    u32 peek_count = 0;
                    if (SampleFlow(9, fd, *src_ip, *src_port,
                                   static_cast<u16>(n),
                                   std::addressof(peek_count))) {
                        Note("ZT peek         fd %d <- %u.%u.%u.%u:%u len %d x%u",
                             fd, (unsigned)(*src_ip >> 24),
                             (unsigned)(*src_ip >> 16) & 0xff,
                             (unsigned)(*src_ip >> 8) & 0xff,
                             (unsigned)*src_ip & 0xff, *src_port, n, peek_count);
                    }
                }
                u32 count = 0;
                if (!peek && SampleFlow(2, fd, *src_ip, *src_port,
                                        (u16)n, std::addressof(count))) {
                    const u8 *bytes = static_cast<const u8 *>(data);
                    const u8 b0 = n > 0 ? bytes[0] : 0;
                    const u8 b1 = n > 1 ? bytes[1] : 0;
                    const u8 b2 = n > 2 ? bytes[2] : 0;
                    const u8 b3 = n > 3 ? bytes[3] : 0;
                    Note("ZT recv         fd %d <- %u.%u.%u.%u:%u len %d head %02x%02x%02x%02x x%u", fd,
                         (unsigned)(*src_ip >> 24), (unsigned)(*src_ip >> 16) & 0xff,
                         (unsigned)(*src_ip >> 8) & 0xff, (unsigned)*src_ip & 0xff,
                         *src_port, n, b0, b1, b2, b3, count);
                }
            }
            return n;
        }

        bool SuppressPhysicalUdpError(u64 pid, s32 fd, BsdResult *result,
                                      const char *operation) {
            if (result->ret >= 0 || GetLanVfd(pid, fd) == net::InvalidSocket) { return false; }
            const s32 original = result->err;
            switch (original) {
                case 101: /* ENETUNREACH */
                case 102: /* ENETRESET */
                case 104: /* ECONNRESET */
                case 110: /* ETIMEDOUT */
                case 111: /* ECONNREFUSED */
                case 113: /* EHOSTUNREACH */
                    break;
                default:
                    return false;
            }
            /* The mirrored socket's authoritative path is VNet. A late ICMP
             * or route error belongs to the physical duplicate and must not
             * tear down Pia's otherwise healthy overlay session. Report the
             * same no-data-yet condition as a nonblocking empty receive. */
            result->err = 11; /* EAGAIN / EWOULDBLOCK */
            u32 count = 0;
            if (SampleFlow(6, fd, 0, (u16)original, 0, std::addressof(count))) {
                Note("%-15s fd %d physical errno %d -> EAGAIN x%u",
                     operation, fd, original, count);
            }
            return true;
        }

        struct MMsgCursor {
            const u8 *at;
            const u8 *end;
        };

        struct MMsgView {
            const u8 *name;
            u32 nameLen;
            const u8 *iov;
            const u8 *iovEnd;
            u32 iovCount;
            size_t payloadLen;
        };

        bool MMsgTake(MMsgCursor *cursor, size_t size, const u8 **out) {
            if (cursor == nullptr || size > static_cast<size_t>(cursor->end - cursor->at)) {
                return false;
            }
            if (out != nullptr) { *out = cursor->at; }
            cursor->at += size;
            return true;
        }

        bool MMsgReadU32(MMsgCursor *cursor, u32 *out) {
            const u8 *p = nullptr;
            if (!MMsgTake(cursor, sizeof(*out), std::addressof(p))) { return false; }
            std::memcpy(out, p, sizeof(*out));
            return true;
        }

        bool MMsgReadU64(MMsgCursor *cursor, u64 *out) {
            const u8 *p = nullptr;
            if (!MMsgTake(cursor, sizeof(*out), std::addressof(p))) { return false; }
            std::memcpy(out, p, sizeof(*out));
            return true;
        }

        bool ParseMMsg(MMsgCursor *cursor, MMsgView *view) {
            u32 name_len = 0;
            if (!MMsgReadU32(cursor, std::addressof(name_len))) { return false; }
            const u8 *name = nullptr;
            if (!MMsgTake(cursor, name_len, std::addressof(name))) { return false; }

            u32 iov_count = 0;
            if (!MMsgReadU32(cursor, std::addressof(iov_count)) || iov_count > 64) {
                return false;
            }
            const u8 *iov = cursor->at;
            size_t payload_len = 0;
            for (u32 i = 0; i < iov_count; ++i) {
                u64 len = 0;
                if (!MMsgReadU64(cursor, std::addressof(len)) ||
                    len > MMsgPayloadMax || payload_len > MMsgPayloadMax - static_cast<size_t>(len) ||
                    !MMsgTake(cursor, static_cast<size_t>(len), nullptr)) {
                    return false;
                }
                payload_len += static_cast<size_t>(len);
            }
            const u8 *iov_end = cursor->at;

            u32 control_len = 0;
            if (!MMsgReadU32(cursor, std::addressof(control_len)) ||
                !MMsgTake(cursor, control_len, nullptr) ||
                !MMsgTake(cursor, sizeof(u32), nullptr) || /* msg_flags */
                !MMsgTake(cursor, sizeof(u32), nullptr)) { /* msg_len */
                return false;
            }
            *view = MMsgView{name, name_len, iov, iov_end, iov_count, payload_len};
            return true;
        }

        bool ResolveMMsgDestination(u64 pid, s32 fd, const MMsgView &view,
                                    s32 *vfd, u32 *ip, u16 *port, bool *broadcast) {
            if (view.nameLen == 0) {
                if (!GetConnectedLanPeer(pid, fd, vfd, ip, port)) { return false; }
                return IsOverlayDestination(*ip, broadcast);
            }
            if (view.nameLen < 8 || view.name[1] != 2) { return false; }
            *vfd = GetLanVfd(pid, fd);
            if (*vfd == net::InvalidSocket) { return false; }
            *port = static_cast<u16>((view.name[2] << 8) | view.name[3]);
            *ip = (static_cast<u32>(view.name[4]) << 24) |
                  (static_cast<u32>(view.name[5]) << 16) |
                  (static_cast<u32>(view.name[6]) << 8) | view.name[7];
            return IsOverlayDestination(*ip, broadcast);
        }

        bool AssembleMMsgPayload(const MMsgView &view, const void **data) {
            MMsgCursor cursor{view.iov, view.iovEnd};
            size_t offset = 0;
            const u8 *single = nullptr;
            for (u32 i = 0; i < view.iovCount; ++i) {
                u64 len = 0;
                const u8 *part = nullptr;
                if (!MMsgReadU64(std::addressof(cursor), std::addressof(len)) ||
                    !MMsgTake(std::addressof(cursor), static_cast<size_t>(len), std::addressof(part))) {
                    return false;
                }
                if (view.iovCount == 1) { single = part; }
                else if (len != 0) {
                    std::memcpy(g_mmsgPayload + offset, part, static_cast<size_t>(len));
                }
                offset += static_cast<size_t>(len);
            }
            *data = view.iovCount == 1 ? single : g_mmsgPayload;
            return true;
        }

        bool MirrorMMsgBuffer(u64 pid, s32 fd, s32 vlen, const void *data,
                              size_t size, s32 *sent_count) {
            if (g_port == nullptr || data == nullptr || sent_count == nullptr ||
                vlen <= 0 || vlen > 64 || size < 1) {
                return false;
            }
            std::scoped_lock lk(g_mmsgLock);
            const u8 *bytes = static_cast<const u8 *>(data);

            /* Validate every message before emitting the first one. If this is
             * not Nintendo's serialised mmsghdr layout, forwarding remains
             * byte-for-byte identical and no overlay duplicate was sent. */
            MMsgCursor check{bytes + 1, bytes + size};
            for (s32 i = 0; i < vlen; ++i) {
                MMsgView view{};
                s32 vfd = net::InvalidSocket;
                u32 ip = 0;
                u16 port = 0;
                bool broadcast = false;
                if (!ParseMMsg(std::addressof(check), std::addressof(view)) ||
                    !ResolveMMsgDestination(pid, fd, view, std::addressof(vfd),
                                            std::addressof(ip), std::addressof(port),
                                            std::addressof(broadcast))) {
                    return false;
                }
            }

            MMsgCursor cursor{bytes + 1, bytes + size};
            s32 sent = 0;
            for (; sent < vlen; ++sent) {
                MMsgView view{};
                s32 vfd = net::InvalidSocket;
                u32 ip = 0;
                u16 port = 0;
                bool broadcast = false;
                const void *payload = nullptr;
                if (!ParseMMsg(std::addressof(cursor), std::addressof(view)) ||
                    !ResolveMMsgDestination(pid, fd, view, std::addressof(vfd),
                                            std::addressof(ip), std::addressof(port),
                                            std::addressof(broadcast)) ||
                    !AssembleMMsgPayload(view, std::addressof(payload))) {
                    break;
                }
                const bool ok = broadcast
                    ? g_port->MirrorLanBroadcast(vfd, port, payload, static_cast<unsigned int>(view.payloadLen))
                    : g_port->MirrorLanDatagram(vfd, ip, port, payload, static_cast<unsigned int>(view.payloadLen));
                if (!ok) { break; }
                u32 count = 0;
                if (SampleFlow(7, fd, ip, port, static_cast<u16>(view.payloadLen), std::addressof(count))) {
                    const u8 *p = static_cast<const u8 *>(payload);
                    const u8 head = view.payloadLen != 0 ? p[0] : 0;
                    Note("ZT mmsg         fd %d -> %u.%u.%u.%u:%u len %u head %02x x%u", fd,
                         (unsigned)(ip >> 24), (unsigned)(ip >> 16) & 0xff,
                         (unsigned)(ip >> 8) & 0xff, (unsigned)ip & 0xff, port,
                         (unsigned)view.payloadLen, head, count);
                }
            }
            if (sent == 0) { return false; }
            *sent_count = sent;
            return true;
        }

        bool FdIsSet(s32 fd, const void *fds, size_t size) {
            if (fd < 0 || fds == nullptr || (size_t)(fd / 8) >= size) { return false; }
            return (static_cast<const u8 *>(fds)[fd / 8] & (u8)(1u << (fd % 8))) != 0;
        }

        void FdSet(s32 fd, void *fds, size_t size) {
            if (fd < 0 || fds == nullptr || (size_t)(fd / 8) >= size) { return; }
            static_cast<u8 *>(fds)[fd / 8] |= (u8)(1u << (fd % 8));
        }

        /* Returns the post-increment connection number for pid, or -1 if the
         * table is full (in which case we refuse to mitm rather than guess). */
        int CountClientSession(u64 pid) {
            std::scoped_lock lk(g_client_sessions_lock);
            for (int i = 0; i < MaxTrackedClients; ++i) {
                if (g_client_sessions[i].pid == pid) {
                    return ++g_client_sessions[i].count;
                }
            }
            for (int i = 0; i < MaxTrackedClients; ++i) {
                if (g_client_sessions[i].pid == 0) {
                    g_client_sessions[i].pid   = pid;
                    g_client_sessions[i].count = 1;
                    return 1;
                }
            }
            return -1;
        }

    }

    void SetPort(ztnx::Port *port) { g_port = port; }

    void ObservePhysicalIpConfig(u32 ip, u32 mask) {
        std::scoped_lock lk(g_lan_sockets_lock);
        g_physicalIp = ip;
        g_physicalMask = mask;
    }

    void BsdShim::CleanupAbandonedServices() {
        /* Snapshot candidates BEFORE querying the kernel: a newly launched
         * process must never be classified dead using an older process list.
         * Called only by the node maintenance thread, never the SM callback. */
        static u64 last_tick = 0;
        const u64 tick = armGetSystemTick();
        if (tick - last_tick < 19'200'000) { return; }
        last_tick = tick;
        u64 candidates[128]{};
        size_t count = 0;
        auto remember = [&](u64 pid) {
            if (pid == 0 || count == 128) { return; }
            for (size_t i = 0; i < count; ++i) { if (candidates[i] == pid) { return; } }
            candidates[count++] = pid;
        };
        {
            std::scoped_lock lk(g_parked_lock);
            for (const auto &entry : g_parked_forward_services) { remember(entry.pid); }
        }
        {
            std::scoped_lock lk(g_client_sessions_lock);
            for (const auto &entry : g_client_sessions) { remember(entry.pid); }
        }
        {
            /* RegisterClient holds this across a forwarded IPC. Maintenance
             * must never stall ZeroTier behind a blocked game-side service. */
            std::unique_lock lk(g_splatoon2_registration_lock, std::try_to_lock);
            if (!lk.owns_lock()) { return; }
            remember(g_splatoon2_registered_pid);
        }
        if (count == 0) { return; }
        u64 live[128]{};
        s32 live_count = 0;
        const auto rc = svcGetProcessList(&live_count, live, 128);
        /* Fail closed on denied access or truncation; neither proves exit. */
        if (R_FAILED(rc) || live_count < 0 || live_count >= 128) { return; }
        for (size_t i = 0; i < count; ++i) {
            const u64 pid = candidates[i];
            if (!net::ProcessListConfirmsExit(pid, live, live_count, 128, true)) { continue; }
            const int shadows = ForgetLanSocketsForPid(pid);
            size_t released = 0;
            {
                std::scoped_lock lk(g_parked_lock);
                for (auto it = g_parked_forward_services.begin(); it != g_parked_forward_services.end();) {
                    if (it->pid != pid) { ++it; continue; }
                    if (it->service.use_count() > 1) { ++it; continue; }
                    ReleaseRetiredService(it->service);
                    it = g_parked_forward_services.erase(it);
                    ++released;
                }
            }
            {
                std::unique_lock lk(g_splatoon2_registration_lock, std::try_to_lock);
                if (!lk.owns_lock()) { continue; } // retain counter for next pass
                if (g_splatoon2_registered_pid == pid) {
                    if (g_splatoon2_registration_owner.use_count() > 1) { continue; }
                    ReleaseRetiredService(g_splatoon2_registration_owner);
                    g_splatoon2_registered_pid = 0;
                    g_splatoon2_registered_out = 0;
                }
            }
            {
                std::scoped_lock lk(g_client_sessions_lock);
                for (auto &entry : g_client_sessions) {
                    if (entry.pid == pid) { entry = {}; }
                }
            }
            Note("lifetime reaped pid %llu parked %u shadows %d",
                 (unsigned long long)pid, (unsigned)released, shadows);
        }
    }

    BsdShim::~BsdShim() {
        if (!m_forward_service) { return; }

        if (m_proxy_registration_owner) {
            const unsigned long long now = armGetSystemTick() / 19200;
            const unsigned long long pid = m_client_info.process_id.value;
            bool retained = false;
            {
                std::scoped_lock lk(g_splatoon2_registration_lock);
                if (g_splatoon2_registered_pid == pid) {
                    if (!g_splatoon2_registration_owner) {
                        g_splatoon2_registration_owner = std::move(m_forward_service);
                    } else {
                        m_forward_service.reset();
                    }
                    retained = true;
                }
            }
            if (retained) {
                NoteSync("[%8llu] lifetime registered pid %llu retaining bsd/proxy owner",
                         now, pid);
                return;
            }
        }

        if (ProcessHasExited(m_client_info.process_id.value)) {
            /* The framework may still own a reference during object teardown.
             * Let maintenance drop the handle after that reference is gone. */
            std::scoped_lock lk(g_parked_lock);
            g_parked_forward_services.push_back({m_client_info.process_id.value, std::move(m_forward_service)});
            return;
        }

        /* Match the working ryu_ldn_nx lifetime policy: only a session that
         * never completed RegisterClient receives the close-avoidance
         * workaround. Once registered, closing the real service is required
         * to release its transfer-memory handle and unlock the client's socket
         * pool before nnSdk attempts a second CreateTransferMemory. */
        if (!m_registered) {
            std::scoped_lock lk(g_parked_lock);
            g_parked_forward_services.push_back({m_client_info.process_id.value, std::move(m_forward_service)});
            NoteSync("lifetime        unregistered session parked (#%d held)",
                     (int)g_parked_forward_services.size());
            return;
        }

        const unsigned long long now = armGetSystemTick() / 19200;
        const unsigned long long pid = m_client_info.process_id.value;
        /* Other sessions belonging to this process may still use its socket
         * table. Explicit Close/ShutdownAllSockets and confirmed process exit
         * own that cleanup, not destruction of an individual IPC session. */
        NoteSync("[%8llu] lifetime registered pid %llu releasing %s",
                 now, pid, m_proxy_registration ? "bsd/proxy" : "bsd/tmem");
        m_forward_service.reset();
        NoteSync("[%8llu] lifetime registered pid %llu released %s",
                 (unsigned long long)(armGetSystemTick() / 19200), pid,
                 m_proxy_registration ? "bsd/proxy" : "bsd/tmem");
    }

    bool BsdShim::ShouldMitm(const ams::sm::MitmProcessInfo &client) {
        /* Counted, because the gap between this and OnNeedsToAccept is the one
         * remaining place the failure can hide.
         *
         * sm calls ShouldMitm once per connection ATTEMPT; OnNeedsToAccept runs
         * only once sm has also managed to open a forward session to the real
         * service. bsd.log showed two accepts and then nothing, which has two
         * readings:
         *
         *   asks == accepts   the game only ever wanted two sessions, and the
         *                     failure is somewhere else entirely
         *   asks >  accepts   sm could not create the forward session for the
         *                     rest -- bsd:u has been capped at 0xF sessions
         *                     since 18.0.0, and a mitm needs TWO per client
         *                     session, so we exhaust it at half the depth the
         *                     game expects
         *
         * Those need completely different fixes, and one line here separates
         * them. */
        static int s_asks = 0;

        /* Applications only.
         *
         * sm refuses to mitm loader, pm, spl, boot, ncm and creport, and that
         * is the whole of its protection -- ns, am, nifm and every other system
         * process reach bsd through this same service name and would be handed
         * to us. Intercepting those does not break a game, it breaks the
         * console's networking. */
        if (!ams::ncm::IsApplicationId(client.program_id) ||
            FindLanTitle(client.program_id.value) == nullptr) {
            return false;
        }

        /* Never ourselves. We open bsd sockets for the ZeroTier uplink; being
         * handed our own session is an immediate recursion into a service we
         * are in the middle of answering. */
        if (client.program_id.value == 0x4200000000005A54ull) {
            return false;
        }

        const int n = CountClientSession(client.process_id.value);

        /* Table full: refuse rather than guess a session index. */
        if (n < 0) {
            NoteSync("ShouldMitm      ask #%d  pid %llu -> no (table full)",
                     ++s_asks, (unsigned long long)client.process_id.value);
            return false;
        }

        /* THE DUMMY SESSION. See the comment on g_client_sessions above: the
         * first bsd:u session a game opens never receives RegisterClient, and
         * intercepting it destabilises the system. Let it go straight to the
         * real service. */
        if (n == 1) {
            NoteSync("ShouldMitm      ask #%d  pid %llu -> no (dummy session #1)",
                     ++s_asks, (unsigned long long)client.process_id.value);
            return false;
        }

        NoteSync("ShouldMitm      ask #%d  program %016llx session #%d -> yes",
                 ++s_asks, (unsigned long long)client.program_id.value, n);
        return true;
    }

/* ---------------------------------------------------------------------- */
/* Forwarding                                                              */
/*                                                                         */
/* override_pid matters on every one of these: bsd keys its socket table on  */
/* the client process, so a forwarded call must carry the GAME's pid, not    */
/* ours, or the real service answers for the wrong process.                  */
/* ---------------------------------------------------------------------- */

#define ZTNX_PID   .override_pid = m_client_info.process_id.value
#define ZTNX_RET(o) do { ret.SetValue((o).ret); err.SetValue((o).err); } while (0)

/* Both designators spelled out. libnx writes these in C, where a designated
 * initialiser may be followed by positional ones; C++20 forbids that mix, so
 * `.buffer_attrs = X, { ... }` does not compile even though bsd.c does exactly
 * it. Each macro therefore supplies .buffer_attrs AND .buffers. */
#define ZTNX_IN_BUF(b)  .buffer_attrs = { SfBufferAttr_HipcAutoSelect | SfBufferAttr_In  }, \
                        .buffers      = { { (b).GetPointer(), (b).GetSize() } }
#define ZTNX_OUT_BUF(b) .buffer_attrs = { SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out }, \
                        .buffers      = { { (b).GetPointer(), (b).GetSize() } }

    Result BsdShim::RegisterClient(ams::sf::Out<u64> out_pid, const BsdServiceConfig &config,
                                   const ams::sf::ClientProcessId &client_pid, u64 tmem_size,
                                   ams::sf::CopyHandle &&tmem) {
        AMS_UNUSED(client_pid);

        /* Keep Splatoon 2 on the command it actually issued. Only substitute
         * the backing TransferMemory and bounded real-bsd buffer config; the
         * outward command id, response, and monitoring sequence stay exact. */
        if (IsSplatoon2ProgramId(m_client_info.program_id.value)) {
            BsdServiceConfig proxy_config{};
            u64 minimum_work_size = 0;
            if (BuildSplatoon2ProxyConfig(config, std::addressof(proxy_config),
                                          std::addressof(minimum_work_size))) {
                std::scoped_lock registration_lk(g_splatoon2_registration_lock);
                const u64 current_pid = m_client_info.process_id.value;
                if (g_splatoon2_registered_pid == current_pid) {
                    const ::Handle received_handle = tmem.GetOsHandle();
                    out_pid.SetValue(g_splatoon2_registered_out);
                    m_proxy_registration = true;
                    /* The new real-bsd forward session did not receive command
                     * 0, so leave m_registered false and let the existing
                     * unregistered-session workaround park it on teardown. */
                    NoteSync("[%8llu] RegisterClient PROXY REUSE pid %llx out %llx; client handle %x closing",
                             (unsigned long long)(armGetSystemTick() / 19200),
                             (unsigned long long)current_pid,
                             (unsigned long long)g_splatoon2_registered_out,
                             (unsigned)received_handle);
                    R_SUCCEED();
                }

                if (g_splatoon2_registered_pid != 0) {
                    /* The backing buffer is global: never lend it to two
                     * live BSD registrations. A failed process-list query
                     * also does not authorize retiring the previous owner. */
                    R_UNLESS(ProcessHasExited(g_splatoon2_registered_pid), ams::svc::ResultBusy());
                    R_UNLESS(g_splatoon2_registration_owner.use_count() <= 1, ams::svc::ResultBusy());
                    NoteSync("[%8llu] RegisterClient PROXY retiring owner pid %llx for new pid %llx",
                             (unsigned long long)(armGetSystemTick() / 19200),
                             (unsigned long long)g_splatoon2_registered_pid,
                             (unsigned long long)current_pid);
                    ReleaseRetiredService(g_splatoon2_registration_owner);
                    g_splatoon2_registered_pid = 0;
                    g_splatoon2_registered_out = 0;
                }

                ::Handle proxy_handle = INVALID_HANDLE;
                const ams::Result proxy_tmem_rc = EnsureSplatoon2ProxyTmem(
                    std::addressof(proxy_handle));
                if (R_FAILED(proxy_tmem_rc)) {
                    NoteSync("[%8llu] RegisterClient PROXY tmem create failed 0x%x (2%03d-%04d); using client tmem",
                             (unsigned long long)(armGetSystemTick() / 19200),
                             proxy_tmem_rc.GetValue(), proxy_tmem_rc.GetModule(),
                             proxy_tmem_rc.GetDescription());
                } else {
                    const struct {
                        BsdServiceConfig config;
                        u64              pid_placeholder;
                        u64              tmem_size;
                    } proxy_in = { proxy_config, 0, Splatoon2ProxyTmemSize };

                    const ::Handle received_handle = tmem.GetOsHandle();
                    NoteSync("[%8llu] RegisterClient PROXY title %016llx client-h %x %lluK -> proxy-h %x %lluK min %lluK",
                             (unsigned long long)(armGetSystemTick() / 19200),
                             (unsigned long long)m_client_info.program_id.value,
                             (unsigned)received_handle,
                             (unsigned long long)(tmem_size / 1024),
                             (unsigned)proxy_handle,
                             (unsigned long long)(Splatoon2ProxyTmemSize / 1024),
                             (unsigned long long)(minimum_work_size / 1024));
                    NoteSync("[%8llu] PROXY cfg tcp %x/%x max %x/%x udp %x/%x eff %u->%u",
                             (unsigned long long)(armGetSystemTick() / 19200),
                             config.tcp_tx_buf_size, config.tcp_rx_buf_size,
                             proxy_config.tcp_tx_buf_max_size,
                             proxy_config.tcp_rx_buf_max_size,
                             proxy_config.udp_tx_buf_size,
                             proxy_config.udp_rx_buf_size,
                             (unsigned)config.sb_efficiency,
                             (unsigned)proxy_config.sb_efficiency);

                    u64 proxy_out = 0;
                    const ams::Result proxy_rc = serviceMitmDispatchInOut(
                        m_forward_service.get(), 0, proxy_in, proxy_out,
                        .in_send_pid = true,
                        .in_num_handles = 1,
                        .in_handles = { proxy_handle },
                        ZTNX_PID);
                    if (R_FAILED(proxy_rc)) {
                        NoteSync("[%8llu] RegisterClient PROXY forward failed 0x%x (2%03d-%04d)",
                                 (unsigned long long)(armGetSystemTick() / 19200),
                                 proxy_rc.GetValue(), proxy_rc.GetModule(), proxy_rc.GetDescription());
                        R_THROW(proxy_rc);
                    }

                    out_pid.SetValue(proxy_out);
                    m_registered = true;
                    m_proxy_registration = true;
                    m_proxy_registration_owner = true;
                    /* Retain ownership now, not only when the setup object is
                     * destroyed. An exited game's in-flight forward reference
                     * must prevent lending its TMEM to the next process. */
                    g_splatoon2_registration_owner = m_forward_service;
                    g_splatoon2_registered_pid = current_pid;
                    g_splatoon2_registered_out = proxy_out;
                    NoteSync("[%8llu] RegisterClient PROXY complete pid %llx out %llx; client handle %x closing",
                             (unsigned long long)(armGetSystemTick() / 19200),
                             (unsigned long long)m_client_info.process_id.value,
                             (unsigned long long)proxy_out,
                             (unsigned)received_handle);
                    /* `tmem` remains managed and closes only the MITM process's
                     * received copy on return. Real bsd has never seen it. */
                    R_SUCCEED();
                }
            } else {
                NoteSync("[%8llu] RegisterClient PROXY config cannot fit; using client tmem",
                         (unsigned long long)(armGetSystemTick() / 19200));
            }
        }

        /* Rebuild exactly what libnx sends: the placeholder word goes back in
         * the middle, zeroed, and in_send_pid + override_pid fill it with the
         * game's pid rather than ours. */
        const struct {
            BsdServiceConfig config;
            u64              pid_placeholder;
            u64              tmem_size;
        } in = { config, 0, tmem_size };

        /* Logged on ENTRY, before the forward.
         *
         * bsd.log showed two accepts and no RegisterClient at all, which has
         * two very different explanations: sf rejected the request before the
         * handler ran (a signature mismatch), or the handler ran and the
         * forward failed, in which case R_TRY returns before any logging. This
         * line separates them, and the failure line below names the Result. */
        NoteSync("[%8llu] RegisterClient ENTER tmem %llu KB sb_eff %u",
                 (unsigned long long)(armGetSystemTick() / 19200),
                 (unsigned long long)(tmem_size / 1024), (unsigned)config.sb_efficiency);

        u64 out = 0;
        const ::Handle h = tmem.GetOsHandle();
        /* HIPC copy-handle semantics give the real bsd service its own handle
         * during this synchronous forward. Keep our sf::CopyHandle managed so
         * its destructor closes only the MITM process's received copy when the
         * handler returns. Detaching here leaked a second reference to the
         * transfer-memory object and could keep the client's pages locked. */
        const ams::Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 0, in, out,
                                                       .in_send_pid = true,
                                                       .in_num_handles = 1,
                                                       .in_handles = { h },
                                                       ZTNX_PID);
        if (R_FAILED(rc)) {
            NoteSync("[%8llu] RegisterClient FORWARD FAILED 0x%x (2%03d-%04d)",
                     (unsigned long long)(armGetSystemTick() / 19200),
                     rc.GetValue(), rc.GetModule(), rc.GetDescription());
            R_THROW(rc);
        }
        out_pid.SetValue(out);
        m_registered = true;

        /* Synchronous: this is the first command every client sends, so its
         * presence or absence in bsd.log is the single most useful fact if the
         * game dies immediately afterwards. */
        NoteSync("[%8llu] RegisterClient pid %llx token %llx tmem %lluK eff %u",
                 (unsigned long long)(armGetSystemTick() / 19200),
                 (unsigned long long)m_client_info.process_id.value,
                 (unsigned long long)out,
                 (unsigned long long)(tmem_size / 1024),
                 (unsigned)config.sb_efficiency);
        NoteSync("[%8llu] RegisterClient tmem handle %x forwarded; MITM copy managed",
                 (unsigned long long)(armGetSystemTick() / 19200), (unsigned)h);
        R_SUCCEED();
    }

    Result BsdShim::StartMonitoring(ams::sf::Out<s32> out_errno, u64 pid) {
        /* nnSdk's BSD interface differs from current libnx here. The working
         * ryu_ldn_nx MITM observes an eight-byte BSD client token and returns
         * one s32 errno, with no PID descriptor. Forward that ABI exactly and
         * log synchronously so another pre-socket abort is no longer opaque. */
        NoteSync("[%8llu] StartMonitoring ENTER token %016llx",
                 (unsigned long long)(armGetSystemTick() / 19200),
                 (unsigned long long)pid);

        s32 errno_out = 0;
        const ams::Result rc = serviceMitmDispatchInOut(
            m_forward_service.get(), 1, pid, errno_out);
        out_errno.SetValue(errno_out);

        NoteSync("[%8llu] StartMonitoring EXIT rc 0x%x (2%03d-%04d) errno %d",
                 (unsigned long long)(armGetSystemTick() / 19200),
                 rc.GetValue(), rc.GetModule(), rc.GetDescription(), errno_out);
        R_RETURN(rc);
    }

    /* [10.0.0+] "Same input/output as RegisterClient except this doesn't take
     * an input handle" -- switchbrew. Modern nnSdk may open with this instead
     * of command 0, and an undeclared command is ResultUnknownCommandId, which
     * is indistinguishable from a bad signature: both give sessions accepted,
     * no handler reached, and an abort inside CreateClientServiceByHipc.
     *
     * Both this and RegisterClient log on ENTER, so bsd.log now says WHICH one
     * the game uses -- or, if neither appears, proves it is not a command-id
     * problem at all. */
    Result BsdShim::RegisterClientShared(ams::sf::Out<u64> out_pid, const BsdServiceConfig &config,
                                         const ams::sf::ClientProcessId &client_pid, u64 work_size) {
        AMS_UNUSED(client_pid);

        NoteSync("RegClientShared ENTER work %llu KB sb_eff %u",
                 (unsigned long long)(work_size / 1024), (unsigned)config.sb_efficiency);

        const struct {
            BsdServiceConfig config;
            u64              pid_placeholder;
            u64              work_size;
        } in = { config, 0, work_size };

        u64 out = 0;
        const ams::Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 33, in, out,
                                                       .in_send_pid = true, ZTNX_PID);
        if (R_FAILED(rc)) {
            NoteSync("RegClientShared FORWARD FAILED 0x%x (2%03d-%04d)",
                     rc.GetValue(), rc.GetModule(), rc.GetDescription());
            R_THROW(rc);
        }
        out_pid.SetValue(out);
        m_registered = true;
        R_SUCCEED();
    }

    Result BsdShim::Socket(ams::sf::Out<s32> ret, ams::sf::Out<s32> err,
                           s32 domain, s32 type, s32 protocol) {
        const struct { s32 d, t, p; } in = { domain, type, protocol };
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 2, in, out, ZTNX_PID));
        ZTNX_RET(out);
        if (out.ret >= 0 && domain == 2 && type == 2 && (protocol == 0 || protocol == 17)) {
            bool tracked = false;
            {
                std::scoped_lock lk(g_lan_sockets_lock);
                for (auto &s : g_lan_sockets) {
                    if (s.pid != 0) { continue; }
                    s = LanSocket{};
                    s.pid = m_client_info.process_id.value;
                    s.bsdFd = out.ret;
                    s.vnetFd = net::InvalidSocket;
                    s.udp = true;
                    tracked = true;
                    break;
                }
            }
            if (!tracked) { Note("LAN table       full; fd %d untracked", out.ret); }
        }
        /* AF_INET = 2, SOCK_DGRAM = 2. Everything this project cares about is
         * that pair; anything else is noted once so we know it existed. */
        Note("Socket          domain %d type %d proto %d -> fd %d", domain, type, protocol, out.ret);
        R_SUCCEED();
    }

    Result BsdShim::SocketExempt(ams::sf::Out<s32> ret, ams::sf::Out<s32> err,
                                 s32 domain, s32 type, s32 protocol) {
        const struct { s32 d, t, p; } in = { domain, type, protocol };
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 3, in, out, ZTNX_PID));
        ZTNX_RET(out);
        R_SUCCEED();
    }

    Result BsdShim::Bind(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd,
                         const ams::sf::InAutoSelectBuffer &addr) {
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 13, sockfd, out,
                                       ZTNX_IN_BUF(addr), ZTNX_PID));
        ZTNX_RET(out);
        /* Bind is where a known Pia LAN fd receives a VNet shadow socket; the
         * real bind is still forwarded. Do not require SO_BROADCAST here:
         * session/gameplay sockets on the same Pia ports can be unicast-only,
         * and leaving those physical-only produces discovery followed by a
         * peer timeout. */
        if (out.ret == 0 && addr.GetSize() >= 8 && g_port != nullptr) {
            const u8 *p = static_cast<const u8 *>(addr.GetPointer());
            const u16 port = (u16)((p[2] << 8) | p[3]);
            bool should_mirror = false;
            {
                std::scoped_lock lk(g_lan_sockets_lock);
                if (LanSocket *s = FindLanSocketLocked(m_client_info.process_id.value, sockfd);
                    s != nullptr && s->udp) {
                    s->boundPort = port;
                    should_mirror = IsPiaLanPort(port) || s->broadcast;
                }
            }
            if (should_mirror) {
                (void)EnsureLanMirror(m_client_info.process_id.value, sockfd, port,
                                      IsPiaLanPort(port) ? "PIA port" : "SO_BROADCAST");
            }
        }
        /* The decision point of BSD_MITM.md section 4. Log every one. */
        char a[48];
        FormatAddr(a, sizeof(a), addr.GetPointer(), addr.GetSize());
        Note("Bind            fd %d  %s  -> %d", sockfd, a, out.ret);
        R_SUCCEED();
    }

    Result BsdShim::SetSockOpt(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd,
                               s32 level, s32 optname,
                               const ams::sf::InAutoSelectBuffer &optval) {
        BsdResult out;
        const struct { s32 fd, level, optname; } in = { sockfd, level, optname };
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 21, in, out,
                                       ZTNX_IN_BUF(optval), ZTNX_PID));
        ZTNX_RET(out);
        /* SOL_SOCKET is 0xFFFF, SO_BROADCAST is 0x20. That combination is the
         * strongest signal a socket is about to do LAN discovery. */
        /* GetPointer() is const u8*, and the buffer carries no alignment
         * guarantee, so read it out rather than casting a pointer at it. */
        s32 v = -1;
        if (optval.GetSize() >= sizeof(v)) { std::memcpy(std::addressof(v), optval.GetPointer(), sizeof(v)); }
        if (out.ret == 0 && level == 0xFFFF && optname == 0x20) {
            u16 bound_port = 0;
            {
                std::scoped_lock lk(g_lan_sockets_lock);
                if (LanSocket *s = FindLanSocketLocked(m_client_info.process_id.value, sockfd); s != nullptr) {
                    s->broadcast = (v != 0);
                    bound_port = s->boundPort;
                }
            }
            if (v != 0 && bound_port != 0) {
                (void)EnsureLanMirror(m_client_info.process_id.value, sockfd,
                                      bound_port, "SO_BROADCAST");
            }
        }
        Note("SetSockOpt      fd %d  level %04x opt %04x val %d", sockfd, level, optname, v);
        R_SUCCEED();
    }

    Result BsdShim::SendTo(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, u32 flags,
                           const ams::sf::InAutoSelectBuffer &buf,
                           const ams::sf::InAutoSelectBuffer &addr) {
        /* A shadow socket is an observed PIA LAN socket. Bridge every UDP
         * datagram it sends: physical directed broadcasts become ZeroTier's
         * directed broadcast, while a ZeroTier-subnet unicast is kept as a
         * unicast. This carries discovery, the PIA 49152--49155 session flow,
         * and later gameplay without interpreting encrypted payloads.
         *
         * Once VNet accepts the datagram, do not also hand the managed
         * 10.x destination to the physical Wi-Fi socket. The physical route
         * can return an asynchronous ICMP error on the next RecvFrom; Pia
         * treats that unrelated error as a dead LAN session and closes every
         * socket. A disabled MITM remains the local-LAN compatibility path. */
        bool overlay_sent = false;
        if (addr.GetSize() >= 8 && g_port != nullptr) {
            const u8 *p = static_cast<const u8 *>(addr.GetPointer());
            const u16 port = (u16)((p[2] << 8) | p[3]);
            const u32 dst_ip = ((u32)p[4] << 24) | ((u32)p[5] << 16) |
                               ((u32)p[6] << 8) | p[7];
            const bool directed_broadcast = p[7] == 0xff;
            s32 vfd = net::InvalidSocket;
            u16 bound_port = 0;
            {
                std::scoped_lock lk(g_lan_sockets_lock);
                if (LanSocket *s = FindLanSocketLocked(m_client_info.process_id.value, sockfd);
                    s != nullptr && s->udp) {
                    bound_port = s->boundPort;
                    if (s->mirrored) { vfd = s->vnetFd; }
                }
            }
            if (vfd == net::InvalidSocket && directed_broadcast && bound_port != 0) {
                vfd = EnsureLanMirror(m_client_info.process_id.value, sockfd,
                                      bound_port, "first broadcast");
            }
            overlay_sent = vfd != net::InvalidSocket &&
                MirrorLanPayload(m_client_info.process_id.value,
                                 sockfd, vfd,
                                 dst_ip, port, directed_broadcast,
                                 buf.GetPointer(), buf.GetSize());
            if (overlay_sent) {
                u32 count = 0;
                if (SampleFlow(1, sockfd, dst_ip, port, (u16)buf.GetSize(), std::addressof(count))) {
                    Note("ZT only         fd %d -> %u.%u.%u.%u:%u len %u x%u", sockfd,
                         (unsigned)(dst_ip >> 24), (unsigned)(dst_ip >> 16) & 0xff,
                         (unsigned)(dst_ip >> 8) & 0xff, (unsigned)dst_ip & 0xff,
                         port, (unsigned)buf.GetSize(), count);
                }
            }
        }
        if (overlay_sent) {
            ret.SetValue(static_cast<s32>(buf.GetSize()));
            err.SetValue(0);
            R_SUCCEED();
        }
        BsdResult out;
        const struct { s32 fd; u32 flags; } in = { sockfd, flags };
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 11, in, out,
                   .buffer_attrs = { SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                                     SfBufferAttr_HipcAutoSelect | SfBufferAttr_In },
                   .buffers = { { buf.GetPointer(), buf.GetSize() },
                                { addr.GetPointer(), addr.GetSize() } },
                   ZTNX_PID));
        ZTNX_RET(out);
        /* The hot path. Rate-limited: one line per distinct destination is
         * plenty to learn the pattern, and a per-datagram log would be an SD
         * write per packet. */
        if (addr.GetSize() >= 8) {
            const u8 *p = static_cast<const u8 *>(addr.GetPointer());
            const u32 d = ((u32)p[4] << 24) | ((u32)p[5] << 16) | ((u32)p[6] << 8) | p[7];
            const u16 pt = (u16)((p[2] << 8) | p[3]);
            u32 count = 0;
            if (SampleFlow(0, sockfd, d, pt, (u16)buf.GetSize(), std::addressof(count))) {
                char a[48];
                FormatAddr(a, sizeof(a), addr.GetPointer(), addr.GetSize());
                Note("SendTo          fd %d -> %s len %u x%u", sockfd, a,
                     (unsigned)buf.GetSize(), count);
            }
        }
        R_SUCCEED();
    }

    /* ---- plain in/out, no buffers ------------------------------------- */

    Result BsdShim::Listen(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, s32 backlog) {
        const struct { s32 fd, backlog; } in = { sockfd, backlog };
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 18, in, out, ZTNX_PID));
        ZTNX_RET(out);
        R_SUCCEED();
    }

    Result BsdShim::Fcntl(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 fd, s32 cmd, s32 arg) {
        const struct { s32 fd, cmd, arg; } in = { fd, cmd, arg };
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 20, in, out, ZTNX_PID));
        ZTNX_RET(out);
        R_SUCCEED();
    }

    Result BsdShim::Shutdown(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, s32 how) {
        const struct { s32 fd, how; } in = { sockfd, how };
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 22, in, out, ZTNX_PID));
        ZTNX_RET(out);
        R_SUCCEED();
    }

    Result BsdShim::ShutdownAllSockets(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 how) {
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 23, how, out, ZTNX_PID));
        ZTNX_RET(out);
        const int shadows = out.ret == 0 ?
            ForgetLanSocketsForPid(m_client_info.process_id.value) : 0;
        unsigned retired = 0;
        if (out.ret == 0 && how == SHUT_RDWR) {
            /* This is a confirmed socket-layer teardown within a live game,
             * not destruction of one arbitrary IPC session. Release only
             * sessions that the game already abandoned. The proxy TMEM owner
             * and all active sessions remain intact for the next LAN attempt. */
            std::scoped_lock lk(g_parked_lock);
            for (auto it = g_parked_forward_services.begin(); it != g_parked_forward_services.end();) {
                if (it->pid != m_client_info.process_id.value) { ++it; continue; }
                if (it->service.use_count() > 1) { ++it; continue; }
                ReleaseRetiredService(it->service);
                it = g_parked_forward_services.erase(it);
                ++retired;
            }
        }
        Note("ShutdownAllSockets how %d shadows %d retired %u", how, shadows, retired);
        R_SUCCEED();
    }

    Result BsdShim::Close(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 fd) {
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 26, fd, out, ZTNX_PID));
        ZTNX_RET(out);
        if (out.ret == 0) { ForgetLanSocket(m_client_info.process_id.value, fd); }
        R_SUCCEED();
    }

    Result BsdShim::DuplicateSocket(ams::sf::Out<s32> ret, ams::sf::Out<s32> err,
                                    s32 sockfd, u64 reserved) {
        const struct { s32 fd; u32 pad; u64 reserved; } in = { sockfd, 0, reserved };
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 27, in, out, ZTNX_PID));
        ZTNX_RET(out);
        R_SUCCEED();
    }

    /* ---- one input buffer --------------------------------------------- */

    Result BsdShim::Connect(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd,
                            const ams::sf::InAutoSelectBuffer &addr) {
        /* A mirrored UDP connect is overlay state, not a physical route
         * request. PIA hosts may connect their browse socket to a requester
         * before sending the three browse replies. Asking physical Wi-Fi to
         * connect to the managed address can fail before Send ever reaches
         * the mirror, making Switch-hosted rooms invisible. */
        if (addr.GetSize() >= 2 && GetLanVfd(m_client_info.process_id.value, sockfd) != net::InvalidSocket) {
            const u8 *p = static_cast<const u8 *>(addr.GetPointer());
            if (p[1] == 0) { /* AF_UNSPEC disconnect */
                std::scoped_lock lk(g_lan_sockets_lock);
                if (LanSocket *s = FindLanSocketLocked(m_client_info.process_id.value, sockfd);
                    s != nullptr && s->udp) {
                    s->connectedPort = 0;
                    s->connectedIp = 0;
                    s->connected = false;
                    ret.SetValue(0);
                    err.SetValue(0);
                    Note("ZT disconnect    fd %d", sockfd);
                    R_SUCCEED();
                }
            } else if (p[1] == 2 && addr.GetSize() >= 8) {
                const u16 port = static_cast<u16>((p[2] << 8) | p[3]);
                const u32 ip = (static_cast<u32>(p[4]) << 24) |
                               (static_cast<u32>(p[5]) << 16) |
                               (static_cast<u32>(p[6]) << 8) | p[7];
                bool broadcast = false;
                if (IsOverlayDestination(ip, std::addressof(broadcast))) {
                    std::scoped_lock lk(g_lan_sockets_lock);
                    if (LanSocket *s = FindLanSocketLocked(m_client_info.process_id.value, sockfd);
                        s != nullptr && s->udp && s->mirrored) {
                        s->connectedPort = port;
                        s->connectedIp = ip;
                        s->connected = true;
                        ret.SetValue(0);
                        err.SetValue(0);
                        Note("ZT connect       fd %d -> %u.%u.%u.%u:%u", sockfd,
                             (unsigned)(ip >> 24), (unsigned)(ip >> 16) & 0xff,
                             (unsigned)(ip >> 8) & 0xff, (unsigned)ip & 0xff, port);
                        R_SUCCEED();
                    }
                }
            }
        }
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 14, sockfd, out,
                                       ZTNX_IN_BUF(addr), ZTNX_PID));
        ZTNX_RET(out);
        if (out.ret == 0 && addr.GetSize() >= 2) {
            const u8 *p = static_cast<const u8 *>(addr.GetPointer());
            std::scoped_lock lk(g_lan_sockets_lock);
            if (LanSocket *s = FindLanSocketLocked(m_client_info.process_id.value, sockfd);
                s != nullptr && s->udp) {
                if (p[1] == 2 && addr.GetSize() >= 8) {
                    s->connectedPort = (u16)((p[2] << 8) | p[3]);
                    s->connectedIp = ((u32)p[4] << 24) | ((u32)p[5] << 16) |
                                     ((u32)p[6] << 8) | p[7];
                    s->connected = true;
                } else if (p[1] == 0) {
                    /* AF_UNSPEC disconnects a datagram socket. */
                    s->connectedPort = 0;
                    s->connectedIp = 0;
                    s->connected = false;
                }
            }
        }
        char a[48];
        FormatAddr(a, sizeof(a), addr.GetPointer(), addr.GetSize());
        Note("Connect         fd %d  %s  -> %d", sockfd, a, out.ret);
        R_SUCCEED();
    }

    Result BsdShim::Send(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, u32 flags,
                         const ams::sf::InAutoSelectBuffer &buf) {
        const bool mirrored = MirrorConnectedLanDatagram(m_client_info.process_id.value, sockfd,
                                                         buf.GetPointer(), buf.GetSize(), "send");
        if (mirrored) {
            ret.SetValue(static_cast<s32>(buf.GetSize()));
            err.SetValue(0);
            R_SUCCEED();
        }
        const struct { s32 fd; u32 flags; } in = { sockfd, flags };
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 10, in, out,
                                       ZTNX_IN_BUF(buf), ZTNX_PID));
        ZTNX_RET(out);
        u32 count = 0;
        if (SampleFlow(4, sockfd, 0, 0, (u16)buf.GetSize(), std::addressof(count))) {
            Note("Send            fd %d len %u -> %d zt %d x%u", sockfd,
                 (unsigned)buf.GetSize(), out.ret, mirrored ? 1 : 0, count);
        }
        R_SUCCEED();
    }

    Result BsdShim::Write(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 fd,
                          const ams::sf::InAutoSelectBuffer &buf) {
        const bool mirrored = MirrorConnectedLanDatagram(m_client_info.process_id.value, fd,
                                                         buf.GetPointer(), buf.GetSize(), "write");
        if (mirrored) {
            ret.SetValue(static_cast<s32>(buf.GetSize()));
            err.SetValue(0);
            R_SUCCEED();
        }
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 24, fd, out,
                                       ZTNX_IN_BUF(buf), ZTNX_PID));
        ZTNX_RET(out);
        u32 count = 0;
        if (SampleFlow(5, fd, 0, 0, (u16)buf.GetSize(), std::addressof(count))) {
            Note("Write           fd %d len %u -> %d zt %d x%u", fd,
                 (unsigned)buf.GetSize(), out.ret, mirrored ? 1 : 0, count);
        }
        R_SUCCEED();
    }

    Result BsdShim::SendMMsg(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd,
                             s32 vlen, s32 flags, const ams::sf::InAutoSelectBuffer &buf) {
        s32 mirrored = 0;
        if (MirrorMMsgBuffer(m_client_info.process_id.value, sockfd, vlen,
                             buf.GetPointer(), buf.GetSize(), std::addressof(mirrored))) {
            ret.SetValue(mirrored);
            err.SetValue(0);
            R_SUCCEED();
        }
        const struct { s32 fd, vlen, flags; } in = { sockfd, vlen, flags };
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 30, in, out,
                                       ZTNX_IN_BUF(buf), ZTNX_PID));
        ZTNX_RET(out);
        Note("SendMMsg        fd %d vlen %d", sockfd, vlen);
        R_SUCCEED();
    }

    /* ---- one output buffer -------------------------------------------- */

    Result BsdShim::Recv(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, u32 flags,
                         const ams::sf::OutAutoSelectBuffer &buf) {
        constexpr u32 MsgPeek = 0x2;
        u32 src_ip = 0;
        u16 src_port = 0;
        const int n = ReceiveLanDatagram(m_client_info.process_id.value, sockfd,
                                         buf.GetPointer(), buf.GetSize(),
                                         std::addressof(src_ip),
                                         std::addressof(src_port),
                                         (flags & MsgPeek) != 0);
        if (n >= 0) {
            ret.SetValue(n);
            err.SetValue(0);
            R_SUCCEED();
        }
        const struct { s32 fd; u32 flags; } in = { sockfd, flags };
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 8, in, out,
                                       ZTNX_OUT_BUF(buf), ZTNX_PID));
        (void)SuppressPhysicalUdpError(m_client_info.process_id.value, sockfd,
                                       std::addressof(out), "Recv");
        ZTNX_RET(out);
        R_SUCCEED();
    }

    Result BsdShim::Read(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 fd,
                         const ams::sf::OutAutoSelectBuffer &buf) {
        u32 src_ip = 0;
        u16 src_port = 0;
        const int n = ReceiveLanDatagram(m_client_info.process_id.value, fd,
                                         buf.GetPointer(), buf.GetSize(),
                                         std::addressof(src_ip),
                                         std::addressof(src_port));
        if (n >= 0) {
            ret.SetValue(n);
            err.SetValue(0);
            R_SUCCEED();
        }
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 25, fd, out,
                                       ZTNX_OUT_BUF(buf), ZTNX_PID));
        (void)SuppressPhysicalUdpError(m_client_info.process_id.value, fd,
                                       std::addressof(out), "Read");
        ZTNX_RET(out);
        R_SUCCEED();
    }

    Result BsdShim::GetResourceStatistics(ams::sf::Out<s32> err,
                                           ams::sf::OutBuffer stats, u64 pid) {
        s32 out_err = 0;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 28, pid, out_err,
                                       .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
                                       .buffers = { { stats.GetPointer(), stats.GetSize() } }, ZTNX_PID));
        err.SetValue(out_err);
        R_SUCCEED();
    }

    Result BsdShim::RecvMMsg(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd,
                             s32 vlen, s32 flags, s32 timeout,
                             const ams::sf::OutAutoSelectBuffer &buf) {
        const struct { s32 fd, vlen, flags, timeout; } in = { sockfd, vlen, flags, timeout };
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 29, in, out,
                                       ZTNX_OUT_BUF(buf), ZTNX_PID));
        ZTNX_RET(out);
        R_SUCCEED();
    }

    Result BsdShim::EventFd(ams::sf::Out<s32> ret, ams::sf::Out<s32> err,
                            u64 initial_value, s32 flags) {
        const struct { u64 initial_value; s32 flags; u32 pad; } in = { initial_value, flags, 0 };
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 31, in, out, ZTNX_PID));
        ZTNX_RET(out);
        R_SUCCEED();
    }

    Result BsdShim::RegisterResourceStatisticsName(ams::sf::Out<s32> err, u64 pid,
                                                    const ams::sf::InBuffer &name) {
        s32 out_err = 0;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 32, pid, out_err,
                                       .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_In },
                                       .buffers = { { name.GetPointer(), name.GetSize() } }, ZTNX_PID));
        err.SetValue(out_err);
        R_SUCCEED();
    }

    /* ---- output buffer plus a trailing length -------------------------- */

    Result BsdShim::Accept(ams::sf::Out<s32> ret, ams::sf::Out<s32> err,
                           ams::sf::Out<u32> addrlen, s32 sockfd,
                           const ams::sf::OutAutoSelectBuffer &addr) {
        struct { BsdResult r; u32 addrlen; } out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 12, sockfd, out,
                                       ZTNX_OUT_BUF(addr), ZTNX_PID));
        ZTNX_RET(out.r);
        addrlen.SetValue(out.addrlen);
        R_SUCCEED();
    }

    Result BsdShim::GetPeerName(ams::sf::Out<s32> ret, ams::sf::Out<s32> err,
                                ams::sf::Out<u32> addrlen, s32 sockfd,
                                const ams::sf::OutAutoSelectBuffer &addr) {
        s32 vfd = net::InvalidSocket;
        u32 ip = 0;
        u16 port = 0;
        if (GetConnectedLanPeer(m_client_info.process_id.value, sockfd,
                                std::addressof(vfd), std::addressof(ip),
                                std::addressof(port))) {
            if (addr.GetSize() >= 16) {
                u8 *sa = static_cast<u8 *>(addr.GetPointer());
                std::memset(sa, 0, 16);
                sa[0] = 16;
                sa[1] = 2;
                sa[2] = static_cast<u8>(port >> 8);
                sa[3] = static_cast<u8>(port);
                sa[4] = static_cast<u8>(ip >> 24);
                sa[5] = static_cast<u8>(ip >> 16);
                sa[6] = static_cast<u8>(ip >> 8);
                sa[7] = static_cast<u8>(ip);
                ret.SetValue(0);
                err.SetValue(0);
                addrlen.SetValue(16);
                R_SUCCEED();
            }
            ret.SetValue(-1);
            err.SetValue(22); /* EINVAL */
            addrlen.SetValue(0);
            R_SUCCEED();
        }
        struct { BsdResult r; u32 addrlen; } out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 15, sockfd, out,
                                       ZTNX_OUT_BUF(addr), ZTNX_PID));
        ZTNX_RET(out.r);
        addrlen.SetValue(out.addrlen);
        R_SUCCEED();
    }

    Result BsdShim::GetSockName(ams::sf::Out<s32> ret, ams::sf::Out<s32> err,
                                ams::sf::Out<u32> addrlen, s32 sockfd,
                                const ams::sf::OutAutoSelectBuffer &addr) {
        struct { BsdResult r; u32 addrlen; } out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 16, sockfd, out,
                                       ZTNX_OUT_BUF(addr), ZTNX_PID));
        ZTNX_RET(out.r);
        addrlen.SetValue(out.addrlen);
        if (out.r.ret == 0 && addr.GetSize() >= 4) {
            const u8 *sa = static_cast<const u8 *>(addr.GetPointer());
            const u16 port = (u16)((sa[2] << 8) | sa[3]);
            std::scoped_lock lk(g_lan_sockets_lock);
            if (LanSocket *s = FindLanSocketLocked(m_client_info.process_id.value, sockfd);
                s != nullptr && s->udp && port != 0) {
                s->boundPort = port;
            }
        }
        /* A Pia host serialises its station address into browse/session
         * replies. NIFM supplies the interface identity, but getsockname is a
         * second identity path; exposing the physical Wi-Fi address here makes
         * a remote peer discover the room and then reply to an unreachable
         * address. Preserve the real port and replace only the IPv4 address. */
        if (out.r.ret == 0 && addr.GetSize() >= 8 &&
            GetLanVfd(m_client_info.process_id.value, sockfd) != net::InvalidSocket &&
            g_port != nullptr) {
            u32 ip = 0;
            if (g_port->GetLanIpConfig(std::addressof(ip), nullptr)) {
                u8 *sa = static_cast<u8 *>(addr.GetPointer());
                sa[0] = 16;
                sa[1] = 2;
                sa[4] = (u8)(ip >> 24); sa[5] = (u8)(ip >> 16);
                sa[6] = (u8)(ip >> 8);  sa[7] = (u8)ip;
                if (out.addrlen < 16) { addrlen.SetValue(16); }
            }
        }
        char a[48];
        FormatAddr(a, sizeof(a), addr.GetPointer(), addr.GetSize());
        Note("GetSockName     fd %d  -> %s", sockfd, a);
        R_SUCCEED();
    }

    Result BsdShim::GetSockOpt(ams::sf::Out<s32> ret, ams::sf::Out<s32> err,
                               ams::sf::Out<u32> optlen, s32 sockfd, s32 level, s32 optname,
                               const ams::sf::OutAutoSelectBuffer &optval) {
        const struct { s32 fd, level, optname; } in = { sockfd, level, optname };
        struct { BsdResult r; u32 optlen; } out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 17, in, out,
                                       ZTNX_OUT_BUF(optval), ZTNX_PID));
        ZTNX_RET(out.r);
        optlen.SetValue(out.optlen);
        R_SUCCEED();
    }

    /* ---- two output buffers, plus a length ---------------------------- */

    Result BsdShim::RecvFrom(ams::sf::Out<s32> ret, ams::sf::Out<s32> err,
                             ams::sf::Out<u32> addrlen, s32 sockfd, u32 flags,
                             const ams::sf::OutAutoSelectBuffer &buf,
                             const ams::sf::OutAutoSelectBuffer &addr) {
        /* A queued virtual datagram wins over the real socket. Empty queues
         * stay on the normal BSD path, preserving local-LAN traffic, blocking
         * behavior, and every error code the game already expects. MSG_PEEK
         * returns the virtual head without consuming it, matching BSD. */
        constexpr u32 MsgPeek = 0x2;
        u32 src_ip = 0;
        u16 src_port = 0;
        const int n = ReceiveLanDatagram(m_client_info.process_id.value, sockfd,
                                         buf.GetPointer(), buf.GetSize(),
                                         std::addressof(src_ip),
                                         std::addressof(src_port),
                                         (flags & MsgPeek) != 0);
        if (n >= 0) {
            if (addr.GetSize() >= 16) {
                u8 *sa = static_cast<u8 *>(addr.GetPointer());
                std::memset(sa, 0, 16);
                sa[0] = 16; sa[1] = 2;  /* sockaddr_in, AF_INET */
                sa[2] = (u8)(src_port >> 8); sa[3] = (u8)src_port;
                sa[4] = (u8)(src_ip >> 24); sa[5] = (u8)(src_ip >> 16);
                sa[6] = (u8)(src_ip >> 8);  sa[7] = (u8)src_ip;
                addrlen.SetValue(16);
            } else {
                addrlen.SetValue(0);
            }
            ret.SetValue(n);
            err.SetValue(0);
            R_SUCCEED();
        }
        const struct { s32 fd; u32 flags; } in = { sockfd, flags };
        struct { BsdResult r; u32 addrlen; } out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 9, in, out,
                   .buffer_attrs = { SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out,
                                     SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out },
                   .buffers      = { { buf.GetPointer(), buf.GetSize() },
                                     { addr.GetPointer(), addr.GetSize() } },
                   ZTNX_PID));
        if (SuppressPhysicalUdpError(m_client_info.process_id.value, sockfd,
                                     std::addressof(out.r), "RecvFrom")) {
            out.addrlen = 0;
        }
        ZTNX_RET(out.r);
        addrlen.SetValue(out.addrlen);
        R_SUCCEED();
    }

    /* ---- the awkward ones ---------------------------------------------- */

    Result BsdShim::Open(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 flags,
                         const ams::sf::InAutoSelectBuffer &path) {
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 4, flags, out,
                                       ZTNX_IN_BUF(path), ZTNX_PID));
        ZTNX_RET(out);
        R_SUCCEED();
    }

    Result BsdShim::Select(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 nfds,
                           const BsdSelectTimeval &timeout,
                           const ams::sf::InAutoSelectBuffer &rd,
                           const ams::sf::InAutoSelectBuffer &wr,
                           const ams::sf::InAutoSelectBuffer &ex,
                           const ams::sf::OutAutoSelectBuffer &ord,
                           const ams::sf::OutAutoSelectBuffer &owr,
                           const ams::sf::OutAutoSelectBuffer &oex) {
        /* We cannot wait on a VNet queue and a physical bsd fd in one kernel
         * call. Bound the physical wait to 10 ms whenever a mirrored read fd
         * is present, then merge both readiness sets. This closes the race in
         * which a ZT packet arrived immediately after our pre-check and stayed
         * invisible inside a long/infinite physical select. */
        bool watches_vnet = false;
        bool vnet_ready_now = false;
        for (s32 fd = 0; fd < nfds; ++fd) {
            if (FdIsSet(fd, rd.GetPointer(), rd.GetSize()) &&
                GetLanVfd(m_client_info.process_id.value, fd) != net::InvalidSocket) {
                watches_vnet = true;
                if (LanSocketReadable(m_client_info.process_id.value, fd)) {
                    vnet_ready_now = true;
                    break;
                }
            }
        }
        BsdSelectTimeval wait = timeout;
        if (vnet_ready_now) {
            wait.value.seconds = 0;
            wait.value.microseconds = 0;
            wait.is_null = false;
        } else if (watches_vnet && (wait.is_null || wait.value.seconds != 0 || wait.value.microseconds > 10000)) {
            wait.value.seconds = 0;
            wait.value.microseconds = 10000;
            wait.is_null = false;
        }
        const struct { s32 nfds; u32 pad; BsdSelectTimeval timeout; } in = { nfds, 0, wait };
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 5, in, out,
                   .buffer_attrs = { SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                                     SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                                     SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                                     SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out,
                                     SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out,
                                     SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out },
                   .buffers      = { { rd.GetPointer(),  rd.GetSize()  },
                                     { wr.GetPointer(),  wr.GetSize()  },
                                     { ex.GetPointer(),  ex.GetSize()  },
                                     { ord.GetPointer(), ord.GetSize() },
                                     { owr.GetPointer(), owr.GetSize() },
                                     { oex.GetPointer(), oex.GetSize() } },
                   ZTNX_PID));
        ZTNX_RET(out);
        if (out.ret >= 0 && watches_vnet) {
            int merged = out.ret;
            for (s32 fd = 0; fd < nfds; ++fd) {
                if (!FdIsSet(fd, rd.GetPointer(), rd.GetSize()) ||
                    !LanSocketReadable(m_client_info.process_id.value, fd)) { continue; }
                if (!FdIsSet(fd, ord.GetPointer(), ord.GetSize())) { ++merged; }
                FdSet(fd, ord.GetPointer(), ord.GetSize());
            }
            if (merged != out.ret) { Note("ZT select       %d real + virtual", merged); }
            ret.SetValue(merged);
            err.SetValue(0);
        }
        R_SUCCEED();
    }

    Result BsdShim::Poll(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 nfds, s32 timeout,
                         const ams::sf::InAutoSelectBuffer &in_fds,
                         const ams::sf::OutAutoSelectBuffer &out_fds) {
        struct PollFd { s32 fd; s16 events; s16 revents; } __attribute__((packed));
        static_assert(sizeof(PollFd) == 8);
        constexpr s16 PollIn = 0x0001;
        const size_t count = nfds > 0 ? std::min((size_t)nfds, out_fds.GetSize() / sizeof(PollFd)) : 0;
        bool watches_vnet = false;
        bool vnet_ready_now = false;
        if (out_fds.GetSize() >= in_fds.GetSize()) {
            std::memcpy(out_fds.GetPointer(), in_fds.GetPointer(), in_fds.GetSize());
        }
        for (size_t i = 0; i < count; ++i) {
            PollFd p{};
            std::memcpy(std::addressof(p), static_cast<const u8 *>(in_fds.GetPointer()) + i * sizeof(p), sizeof(p));
            if ((p.events & PollIn) && GetLanVfd(m_client_info.process_id.value, p.fd) != net::InvalidSocket) {
                watches_vnet = true;
                if (LanSocketReadable(m_client_info.process_id.value, p.fd)) { vnet_ready_now = true; }
            }
        }
        const s32 physical_timeout = vnet_ready_now ? 0 :
            (watches_vnet && (timeout < 0 || timeout > 10) ? 10 : timeout);
        const struct { s32 nfds, timeout; } in = { nfds, physical_timeout };
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 6, in, out,
                   .buffer_attrs = { SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                                     SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out },
                   .buffers      = { { in_fds.GetPointer(),  in_fds.GetSize()  },
                                     { out_fds.GetPointer(), out_fds.GetSize() } },
                   ZTNX_PID));
        ZTNX_RET(out);
        if (out.ret >= 0 && watches_vnet) {
            int merged = out.ret;
            for (size_t i = 0; i < count; ++i) {
                PollFd p{};
                std::memcpy(std::addressof(p), static_cast<const u8 *>(out_fds.GetPointer()) + i * sizeof(p), sizeof(p));
                if ((p.events & PollIn) && LanSocketReadable(m_client_info.process_id.value, p.fd)) {
                    if (p.revents == 0) { ++merged; }
                    p.revents |= PollIn;
                    std::memcpy(static_cast<u8 *>(out_fds.GetPointer()) + i * sizeof(p), std::addressof(p), sizeof(p));
                }
            }
            if (merged != out.ret) { Note("ZT poll         %d real + virtual", merged); }
            ret.SetValue(merged);
            err.SetValue(0);
        }
        R_SUCCEED();
    }

    Result BsdShim::Sysctl(ams::sf::Out<s32> ret, ams::sf::Out<s32> err,
                           ams::sf::Out<u32> out_len,
                           const ams::sf::InAutoSelectBuffer &name,
                           const ams::sf::InAutoSelectBuffer &oldp,
                           const ams::sf::OutAutoSelectBuffer &newp) {
        struct { BsdResult r; u32 len; } out;
        R_TRY(serviceMitmDispatch(m_forward_service.get(), 7,
                   .buffer_attrs = { SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                                     SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                                     SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out },
                   .buffers      = { { name.GetPointer(), name.GetSize() },
                                     { oldp.GetPointer(), oldp.GetSize() },
                                     { newp.GetPointer(), newp.GetSize() } },
                   ZTNX_PID));
        AMS_UNUSED(out);
        ret.SetValue(0); err.SetValue(0); out_len.SetValue(0);
        R_SUCCEED();
    }

    Result BsdShim::Ioctl(ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 fd, s32 request,
                          u32 bufcount, const ams::sf::InAutoSelectBuffer &b1,
                          const ams::sf::InAutoSelectBuffer &b2,
                          const ams::sf::OutAutoSelectBuffer &b3,
                          const ams::sf::OutAutoSelectBuffer &b4) {
        const struct { s32 fd, request; u32 bufcount; } in = { fd, request, bufcount };
        BsdResult out;
        R_TRY(serviceMitmDispatchInOut(m_forward_service.get(), 19, in, out,
                   .buffer_attrs = { SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                                     SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                                     SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out,
                                     SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out },
                   .buffers      = { { b1.GetPointer(), b1.GetSize() },
                                     { b2.GetPointer(), b2.GetSize() },
                                     { b3.GetPointer(), b3.GetSize() },
                                     { b4.GetPointer(), b4.GetSize() } },
                   ZTNX_PID));
        ZTNX_RET(out);
        /* SIOCGIFCONF / SIOCGIFADDR would mean the game asks the interface
         * directly instead of learning peers from recvfrom -- section 4 calls
         * that out as the case that would need extra work. */
        Note("Ioctl           fd %d request %08x", fd, request);
        R_SUCCEED();
    }

}

/* Called only by this project's custom libstratosphere when a declared MITM
 * command failed CMIF metadata validation. Restrict the compatibility policy
 * to IBsdShim; NIFM and every other MITM retain strict validation. */
extern "C" bool ztnxShouldForwardInvalidMitmCmifRequest(u32 interface_id,
                                                         u32 command_id,
                                                         u32 result) {
    constexpr u32 BsdShimInterfaceId = 0x5A54B5D0;
    if (interface_id != BsdShimInterfaceId) { return false; }

    ztnx::mitm::NoteSync("cmif fallback   interface %08x cmd %u result 0x%x -> raw forward",
                         interface_id, command_id, result);
    return true;
}

/* Pre-dispatch diagnostics from the custom libstratosphere session manager.
 * BSD arrives as a framework-managed MITM session, while the NIFM child
 * proxies deliberately arrive as ordinary local sessions. */
extern "C" void ztnxTraceMitmHipcRequest(u32 event,
                                         u32 session_handle,
                                         u32 sequence,
                                         u32 command_type,
                                         u32 cmif_magic,
                                         u32 cmif_version,
                                         u32 command_id,
                                         u32 cmif_token,
                                         u32 raw_words,
                                         u32 send_pid,
                                         u32 buffers,
                                         u32 handles,
                                         u32 statics,
                                         u32 pointer_buffer_size,
                                         u32 is_mitm,
                                         u32 result) {
    /* BSD is the framework-managed MITM (0x1000 pointer buffer). NIFM is a
     * deliberately local proxy (0x1f4) so unknown child commands cannot use
     * framework raw forwarding. Trace both, but ignore libstratosphere's
     * unrelated local helper/query sessions. */
    const bool is_bsd = is_mitm != 0;
    const bool is_nifm = !is_bsd && pointer_buffer_size == 0x1F4;
    if (!is_bsd && !is_nifm) { return; }

    if (is_nifm) {
        switch (event) {
            case 0:
                /* Success/failure retains the same parsed request metadata;
                 * wait until then so one compact line represents each call. */
                break;
            case 1:
                ztnx::mitm::NoteNifmSync(
                    "ok h%x n%u t%u cmd%08x v%u out 0x%x raw%u pid%u b%x h%x s%x",
                    session_handle, sequence, command_type, command_id,
                    cmif_version, result, raw_words, send_pid, buffers, handles, statics);
                break;
            case 2: {
                const ams::Result rc(result);
                ztnx::mitm::NoteNifmSync(
                    "FAIL h%x n%u t%u cmd%08x v%u framework 0x%x (2%03d-%04d)",
                    session_handle, sequence, command_type, command_id,
                    cmif_version, result, rc.GetModule(), rc.GetDescription());
                break;
            }
            case 3:
                ztnx::mitm::NoteNifmSync("peer close h%x after %u request(s)",
                                              session_handle, sequence);
                break;
            case 4:
                ztnx::mitm::NoteNifmSync("cmif close h%x after %u request(s)",
                                              session_handle, sequence);
                break;
            default:
                break;
        }
        return;
    }
    const char *scope = is_nifm ? "nifm" : "bsd";

    const u32 send_buffers = buffers & 0xFF;
    const u32 recv_buffers = (buffers >> 8) & 0xFF;
    const u32 exch_buffers = (buffers >> 16) & 0xFF;
    const u32 copy_handles = handles & 0xFF;
    const u32 move_handles = (handles >> 8) & 0xFF;
    const u32 send_statics = statics & 0xFF;
    const u32 recv_statics = (statics >> 8) & 0xFF;

    switch (event) {
        case 0:
            /* This hook runs before libstratosphere dispatches the request.
             * Do not perform filesystem IPC here: Horizon IPC reuses this
             * server thread's TLS message buffer, which still contains the
             * BSD request.  Queue the lines in memory and flush them only
             * from the post-dispatch success/failure events below. */
            ztnx::mitm::Note(
                "%s hipc enter  h%x n%u t%u cmd%08x m%08x v%u tok%08x",
                scope, session_handle, sequence, command_type, command_id, cmif_magic,
                cmif_version, cmif_token);
            ztnx::mitm::Note(
                "%s hipc meta   h%x n%u raw%u pid%u b%u/%u/%u h%u/%u s%u/%u",
                scope, session_handle, sequence, raw_words, send_pid,
                send_buffers, recv_buffers, exch_buffers,
                copy_handles, move_handles, send_statics, recv_statics);
            break;
        case 1:
            ztnx::mitm::NoteSync("%s hipc ok     h%x n%u t%u cmd%08x v%u",
                                 scope, session_handle, sequence, command_type, command_id,
                                 cmif_version);
            break;
        case 2: {
            const ams::Result rc(result);
            ztnx::mitm::NoteSync("%s hipc FAIL   h%x n%u t%u cmd%08x v%u rc 0x%x (2%03d-%04d)",
                                 scope, session_handle, sequence, command_type, command_id,
                                 cmif_version, result, rc.GetModule(), rc.GetDescription());
            break;
        }
        case 3:
            ztnx::mitm::NoteSync("%s hipc peer close h%x after %u request(s)",
                                 scope, session_handle, sequence);
            break;
        case 4:
            ztnx::mitm::NoteSync("%s hipc cmif close h%x after %u request(s)",
                                 scope, session_handle, sequence);
            break;
        default:
            break;
    }
}
