/*
 * sys-zerotier -- Atmosphere sysmodule entry point.
 *
 * REFERENCE SKELETON. Never compiled. Structure follows
 * ldn_mitm/ldn_mitm/source/ldnmitm_main.cpp, which is the reference for how a
 * stratosphere sysmodule brings up bsd sockets.
 */
#include <stratosphere.hpp>

extern "C" {
#include <switch.h>
#include <switch/services/bsd.h>
}

#include "zt_port.hpp"
#include "mitm/bsd_shim.hpp"
#include "mitm/nifm_shim.hpp"

namespace ams {

    namespace {

        /* Everything the module will ever allocate comes out of here. There is
         * no growth path -- a sysmodule that runs the heap dry takes the
         * console down with it. Budget notes in PORTING.md section 6. */
        /* Sized against what ZeroTier actually allocates, read out of the
         * DWARF in sys-zerotier.elf rather than guessed:
         *
         *   Node::Node's single ::malloc   ~298 KB  (Trace+Switch+Multicaster+
         *                                            Topology+SelfAwareness+
         *                                            Bond+PacketMultiplexer)
         *   Node                            ~38 KB
         *   Network (one)                  ~127 KB
         *   two transient Buffer<33768>     ~66 KB
         *   peers 1568 B and paths 769 B apiece
         *
         * ~550 KB steady state, so 1536 KB is roughly 3x headroom. Cutting this
         * to 1 MB is what produced report_0000000024c4cc92.bin: at the time
         * sizeof(Switch) was 2,248,912 and that one malloc could not be served,
         * ZeroTier threw std::bad_alloc, and a throw in this module is fatal.
         *
         * TraceArenaWatermark() logs the low-water mark to boot.log. Do not
         * shrink this without reading that number first. */
        /* 1536 KB -> 1024 KB was enough to create and run the node, but not
         * enough to transmit its first queued Ethernet multicast.
         *
         * boot.log from the first run with the mitm resident:
         *
         *     res: memory  peak 311104 / 313344 KB  free 2240
         *     genmem: 2048 KB unavailable, retrying in 3s   (forever)
         *
         * The mitm costs ~320 KB (per-session pointer buffers, saved-message
         * buffers, the manager, a thread stack), which pushed free below what
         * the 2 MB identity-validation block needs -- so the node never got
         * created at all this boot.
         *
         * The first MK8 broadcast exposed the missing workload: with 1024 KB,
         * `Multicaster::send` queues a 30,144-byte OutboundMulticast and its
         * `operator new` returned null. The total free arena was 278 KB, but
         * no contiguous 30 KB block remained. The resulting write at null+16
         * produced report_0000000066005c2f.bin.
         *
         * 1280 KB fixed the first multicast crash. Later full-Splatoon boots
         * showed the arena still had a 544 KB low-water mark and a roughly
         * 500 KB largest block after the node was running, but the shared
         * System pool had fallen to 1996 KB before the mandatory 2048 KB
         * identity-validation mapping. 1152 KB returns 128 KB to that pool
         * while retaining hundreds of KB above the observed 30 KB contiguous
         * allocation requirement. Watch both `genmem: mapped` and the arena
         * watermark; 1024 KB remains known-bad. */
        constexpr size_t MallocBufferSize = 1152_KB;
        alignas(os::MemoryPageSize) constinit u8 g_malloc_buffer[MallocBufferSize];

        consteval size_t GetBsdTransferMemorySize(const ::SocketInitConfig *c) {
            const u32 tcp_tx = c->tcp_tx_buf_max_size ?: c->tcp_tx_buf_size;
            const u32 tcp_rx = c->tcp_rx_buf_max_size ?: c->tcp_rx_buf_size;
            return c->sb_efficiency *
                   util::AlignUp(tcp_tx + tcp_rx + c->udp_tx_buf_size + c->udp_rx_buf_size,
                                 os::MemoryPageSize);
        }

        /* ZeroTier is UDP-only on the wire. The small TCP buffers also serve
         * bounded router-local UPnP HTTP requests; TCP relay is not enabled.
         * bsd:s is chosen
         * over bsd:u because bsd:u was cut to 0xF sessions in firmware 18.0.0
         * and games need those. */
        constexpr const ::SocketInitConfig SocketConfig = {
            .tcp_tx_buf_size     = 0x800,
            .tcp_rx_buf_size     = 0x800,
            .tcp_tx_buf_max_size = 0x800,
            .tcp_rx_buf_max_size = 0x800,
            .udp_tx_buf_size     = 0x2000,
            /* A ZeroTier wire datagram is below 4 KB. 8 KB still holds two
             * maximum-size datagrams while returning 16 KB of transfer
             * memory (sb_efficiency=2) to the shared System pool. */
            .udp_rx_buf_size     = 0x2000,
            .sb_efficiency       = 2,
            .num_bsd_sessions    = 2,
            .bsd_service_type    = BsdServiceType_System,
        };

        alignas(os::MemoryPageSize) constinit
        u8 g_socket_tmem[GetBsdTransferMemorySize(std::addressof(SocketConfig))];

        constexpr const ::BsdInitConfig BsdConfig = {
            .version             = 1,
            .tmem_buffer         = g_socket_tmem,
            .tmem_buffer_size    = sizeof(g_socket_tmem),
            .tcp_tx_buf_size     = SocketConfig.tcp_tx_buf_size,
            .tcp_rx_buf_size     = SocketConfig.tcp_rx_buf_size,
            .tcp_tx_buf_max_size = SocketConfig.tcp_tx_buf_max_size,
            .tcp_rx_buf_max_size = SocketConfig.tcp_rx_buf_max_size,
            .udp_tx_buf_size     = SocketConfig.udp_tx_buf_size,
            .udp_rx_buf_size     = SocketConfig.udp_rx_buf_size,
            .sb_efficiency       = SocketConfig.sb_efficiency,
        };

        /* os::CreateThread takes a libstratosphere USER priority in 0..31, not
         * a raw Horizon priority: it adds UserThreadPriorityOffset (28) to get
         * the Horizon value, so 0..31 maps onto Horizon 28..59.
         *
         * The 42 that used to be here became Horizon 70, past the end of the
         * range, and CreateThread returned svc::ResultInvalidPriority -- which
         * R_ABORT_UNLESS turned into a fatal error at boot.
         *
         * DefaultThreadPriority is 16 (Horizon 44). Four steps less urgent
         * than that keeps the node thread behind anything a game is doing. */
        constexpr s32 NodeThreadPriority = os::DefaultThreadPriority + 4;

        /* ZeroTier expects a desktop-sized stack. Its deepest chains --
         * _doNETWORK_CREDENTIALS -> Capability::deserialize -> sort -> crypto
         * -- are 3-4 KB per frame, and it passes Buffer<10024> objects around
         * by value. 32 KB overflowed inside Network::Network: the fatal report
         * had FAR == SP, which is the signature of running off the stack
         * rather than dereferencing something bad. */
        /* 32 KB overflowed inside Network::Network (FAR == SP in the fatal
         * report), which took this to 256 KB. I then cut it to 128 KB during
         * the memory work -- having only ever exercised node construction and
         * the inbound path.
         *
         * The first outbound frame this project ever sent died immediately.
         * Multicaster.cpp:222 declares
         *
         *     OutboundMulticast out;
         *
         * as a STACK LOCAL, and sizeof(OutboundMulticast) is 30,128 bytes --
         * it embeds a whole Packet. That sits on top of
         * Node::processVirtualNetworkFrame -> Switch::onLocalEthernet, with
         * OutboundMulticast::init -> sendOnly copying further 10 KB Packets
         * beneath it. 128 KB does not survive that chain.
         *
         * Back to 256 KB. Against ~2.5 MB of free system memory this is the
         * cheapest insurance in the project, and the outbound path is the one
         * every LAN-play frame will take. */
        constexpr size_t NodeThreadStackSize = 256_KB;
        alignas(os::MemoryPageSize) u8 g_node_thread_stack[NodeThreadStackSize];
        os::ThreadType g_node_thread;

        /* fs wants its own allocator with a sized deallocate. Give it a
         * dedicated expheap rather than the main malloc arena, the way ldn_mitm
         * does -- filesystem churn should not fragment the node's heap. */
        alignas(0x40) constinit u8 g_fs_heap_memory[32_KB];
        constinit lmem::HeapHandle g_fs_heap_handle;
        constinit bool g_fs_heap_initialized;
        constinit os::SdkMutex g_fs_heap_init_mutex;

        lmem::HeapHandle GetFsHeapHandle() {
            if (AMS_UNLIKELY(!g_fs_heap_initialized)) {
                std::scoped_lock lk(g_fs_heap_init_mutex);
                if (AMS_LIKELY(!g_fs_heap_initialized)) {
                    g_fs_heap_handle = lmem::CreateExpHeap(g_fs_heap_memory, sizeof(g_fs_heap_memory),
                                                           lmem::CreateOption_ThreadSafe);
                    g_fs_heap_initialized = true;
                }
            }
            return g_fs_heap_handle;
        }

        void *FsAllocate(size_t size) {
            return lmem::AllocateFromExpHeap(GetFsHeapHandle(), size);
        }

        void FsDeallocate(void *p, size_t size) {
            AMS_UNUSED(size);
            return lmem::FreeToExpHeap(GetFsHeapHandle(), p);
        }

        /* ---- which kernel resource is actually running out ----------------
         *
         * am aborts at boot with 2001-0132 == svc::ResultLimitReached. The
         * kernel returns that when a process asks for something its *resource
         * limit group* has no headroom left for, and there are exactly five
         * such counters: physical memory, threads, events, transfer memory,
         * sessions. Every system process shares one group and pm put us in it,
         * so the whole question is which of those five our presence tips over.
         *
         * svc::GetInfo(InfoType_ResourceLimit) hands back a handle to our own
         * group's limit -- which *is* that shared System limit -- and SVCs
         * 0x30/0x31 read the cap and the live value out of it. Both are
         * already granted in res/app.json.
         *
         * Sampled rather than read once, because the moment that matters is
         * whenever am asks, not whenever we happen to look. */
        /* LimitableResource_Count is an enumerator of an unsigned enum, so
         * comparing a loop `int` against it directly is -Wsign-compare, which
         * this build treats as an error. Pin it to an int once. */
        constexpr int ResourceCount = static_cast<int>(svc::LimitableResource_Count);

        constexpr const char *ResourceNames[ResourceCount] = {
            "memory", "threads", "events", "tmem", "sessions",
        };

        void ProbeResourceLimits(TimeSpan window) {
            svc::Handle rl = svc::InvalidHandle;
            u64 raw = 0;

            /* Documented as taking InvalidHandle (it returns the *current*
             * process's limit); try CurrentProcess too rather than lose the
             * whole measurement to a wrong guess about the convention. */
            if (R_SUCCEEDED(svc::GetInfo(std::addressof(raw), svc::InfoType_ResourceLimit, svc::InvalidHandle, 0)) ||
                R_SUCCEEDED(svc::GetInfo(std::addressof(raw), svc::InfoType_ResourceLimit, svc::PseudoHandle::CurrentProcess, 0))) {
                rl = static_cast<svc::Handle>(raw);
            }

            if (rl == svc::InvalidHandle) {
                ztnx::Trace("res: no resource-limit handle, just sleeping");
                os::SleepThread(window);
                return;
            }
            ON_SCOPE_EXIT { (void)svc::CloseHandle(rl); };

            s64 limit[ResourceCount] = {};
            s64 peak [ResourceCount] = {};
            for (int i = 0; i < ResourceCount; ++i) {
                (void)svc::GetResourceLimitLimitValue(std::addressof(limit[i]), rl,
                                                      static_cast<svc::LimitableResource>(i));
            }

            const int iterations = static_cast<int>(window.GetMilliSeconds() / 250);
            for (int n = 0; n < iterations; ++n) {
                for (int i = 0; i < ResourceCount; ++i) {
                    s64 v = 0;
                    if (R_SUCCEEDED(svc::GetResourceLimitCurrentValue(std::addressof(v), rl,
                                        static_cast<svc::LimitableResource>(i))) && v > peak[i]) {
                        peak[i] = v;
                    }
                }
                os::SleepThread(TimeSpan::FromMilliSeconds(250));
            }

            for (int i = 0; i < ResourceCount; ++i) {
                const s64 div = (i == static_cast<int>(svc::LimitableResource_PhysicalMemoryMax)) ? 1024 : 1;
                ztnx::Trace("res: %-8s peak %lld / %lld%s   free %lld",
                            ResourceNames[i],
                            (long long)(peak[i] / div), (long long)(limit[i] / div),
                            (div == 1024) ? " KB" : "",
                            (long long)((limit[i] - peak[i]) / div));
            }
        }

        /* ---- power state ---------------------------------------------------
         *
         * Putting the console to sleep with this module running hung it: no
         * fatal report, no wake, hold the power button.
         *
         * That shape -- a hang rather than a crash -- points at the power
         * transition itself rather than at any one bad instruction. Horizon
         * suspends fs and the socket stack when it sleeps, and psc walks the
         * modules in dependency order, waiting for each to acknowledge before
         * taking down what it depends on. A process sitting inside
         * fs::WriteFile or ::poll() across that point holds a service busy and
         * the walk never completes. Our run loop does both, every iteration,
         * forever.
         *
         * The fix is to join the walk. Declaring Fs and WlanSockets as
         * dependencies means psc notifies us BEFORE either goes down, and holds
         * the transition until we acknowledge -- which we do only once the node
         * thread confirms it has closed the wire socket and stopped writing.
         * erpt does the same thing with { PmModuleId_Fs }; see
         * libstratosphere/source/erpt/srv/erpt_srv_service.cpp. */
        constexpr const psc::PmModuleId PscDependencies[] = {
            psc::PmModuleId_Fs,
            psc::PmModuleId_WlanSockets,
            psc::PmModuleId_Nifm, // NAT worker must quiesce before route queries stop
        };

        /* psc_pm_module_id.hpp has no id for third-party modules, so we borrow
         * an unused slot. This is the one number here that is a guess, so it is
         * settable from config.ini and Initialize's Result is checked rather
         * than aborted: if psc rejects it, boot.log says so and the module
         * carries on without sleep support instead of taking the console down. */
        constexpr u32 DefaultPscModuleId = 126;

        /* TypedStorage rather than a plain global: psc::PmModule owns an
         * os::SystemEvent and is not constant-initializable, and this keeps it
         * out of the static-constructor phase entirely -- the phase that once
         * dereferenced a null heap and cost us a boot. */
        constinit util::TypedStorage<psc::PmModule> g_pm_module_storage = {};
        constinit psc::PmModule *g_pm_module = nullptr;
        alignas(os::MemoryPageSize) u8 g_psc_thread_stack[16_KB];
        os::ThreadType g_psc_thread;

        void PscThreadMain(void *) {
            auto *event = g_pm_module->GetEventPointer();
            for (;;) {
                event->Wait();

                psc::PmState   state;
                psc::PmFlagSet flags;
                if (R_FAILED(g_pm_module->GetRequest(std::addressof(state), std::addressof(flags)))) {
                    continue;
                }

                switch (state) {
                    case psc::PmState_SleepReady:
                    case psc::PmState_EssentialServicesSleepReady:
                    case psc::PmState_ShutdownReady:
                        /* Ask the node thread to let go, and wait for it. The
                         * timeout is a deadlock guard: acknowledging late is
                         * bad, never acknowledging is a console that cannot be
                         * woken, which is the bug we are fixing. */
                        ztnx::RequestQuiesce();
                        if (!ztnx::WaitQuiesced(3000)) {
                            ztnx::Event("SLEEP    node thread did not quiesce in 3s, acking anyway");
                        }
                        break;

                    case psc::PmState_FullAwake:
                    case psc::PmState_MinimumAwake:
                    case psc::PmState_EssentialServicesAwake:
                        ztnx::SignalResume();
                        break;

                    default:
                        break;
                }

                /* Always acknowledge. A module that does not is exactly what
                 * stalls the transition. */
                (void)g_pm_module->Acknowledge(state, ResultSuccess());
            }
        }

        void StartPowerMonitor() {
            /* OFF by default, and deliberately so.
             *
             * This was written to fix a sleep hang, but it is unvalidated and it
             * joins the power-state dependency graph -- and the very next fatal
             * report was `omm` aborting with 2165-0001, which is an *spsm*
             * error: module 165 is spsm, the sleep/power-state manager. We also
             * register in the PmModuleId space directly beside it
             * (PmModuleId_Spsm is 127, we borrow 126).
             *
             * That may be coincidence; omm failing to complete a shutdown is
             * also exactly what a wedged local-wireless transition would look
             * like. But two unvalidated changes to the same subsystem is one
             * too many to debug at once, so this stays behind a switch until a
             * boot.log proves it is harmless. */
            if (!ztnx::ConfigFlag("psc_enable", false)) {
                ztnx::Trace("psc: disabled (set psc_enable = 1 in config.ini to test)");
                return;
            }

            const u32 mid = (u32)ztnx::ConfigValue("psc_module_id", (int)DefaultPscModuleId);

            g_pm_module = util::ConstructAt(g_pm_module_storage);

            const ams::Result r = g_pm_module->Initialize(static_cast<psc::PmModuleId>(mid),
                                                          PscDependencies,
                                                          util::size(PscDependencies),
                                                          os::EventClearMode_ManualClear);
            if (R_FAILED(r)) {
                ztnx::Trace("psc: Initialize(id=%u) failed 0x%x -- no sleep handling",
                            (unsigned)mid, r.GetValue());
                return;
            }
            ztnx::Trace("psc: registered as module id %u", (unsigned)mid);

            if (R_FAILED(os::CreateThread(std::addressof(g_psc_thread), PscThreadMain, nullptr,
                                          g_psc_thread_stack, sizeof(g_psc_thread_stack),
                                          os::DefaultThreadPriority))) {
                ztnx::Trace("psc: could not create monitor thread");
                return;
            }
            os::StartThread(std::addressof(g_psc_thread));
        }

        constinit ztnx::Port g_port;

        /* ---- bsd:u MITM ----------------------------------------------------
         *
         * Stage 4a: every command is relayed to the real service untouched,
         * and the interesting ones are logged. Nothing is diverted yet.
         *
         * Sizing. Each intercepted session costs one real session to forward
         * on, so we roughly double whatever the game opens -- boot.log has
         * reported `res: sessions peak 903 / 1126`, leaving 223 spare, and a
         * title opens a handful. Comfortable, but it is the number to watch if
         * a game ever fails to reach the network with this enabled.
         *
         * The server manager needs its own thread; 16 KB is ample for
         * forwarding, which allocates nothing and recurses nowhere. */
        /* Each session costs a pointer buffer plus a saved-message buffer.
         * libnx opens num_bsd_sessions plus a monitor session, and bsd.log
         * shows MK8 taking two. Eight is ample and gives back memory the
         * identity block needs. */
        /* 16, matching ryu_ldn_nx's working value. Was 8, which is thin once
         * a game opens several bsd:u sessions and each costs us one client
         * session plus one forward session. */
        /* Splatoon 3 builds a larger nnSdk BSD client/session graph than MK8.
         * Sixteen was too thin while nn::socket cloned its pool. Hardware
         * traces now show the graph topping out around 15 simultaneous
         * objects, so 24 retains nine spare slots without permanently paying
         * for eight unused 4 KB pointer buffers and session metadata. */
        constexpr size_t MitmSessions  = 24;
        constexpr int    PortIndex_Bsd = 0;
        constexpr int    PortIndex_Count = 1;

        /* DefaultServerManagerOptions sets CanManageMitmServers = false, and
         * RegisterMitmServer asserts on it. Same shape ams_mitm uses. */
        /* PointerBufferSize is the one that matters.
         *
         * RegisterMitmSessionImpl asserts
         *   our pointer buffer size >= the forwarded service's
         * (sf_hipc_server_session_manager.cpp:148), and
         * DefaultServerManagerOptions::PointerBufferSize is 0. bsd:u uses
         * HipcAutoSelect buffers on nearly every command, so it has a real
         * pointer buffer and that assert fired at session setup, before a
         * single command was relayed -- which is why bsd.log came back empty.
         *
         * The cost is per session: MitmSessions * PointerBufferSize of .bss.
         * 12 * 0x1000 is 48 KB, affordable against ~2.5 MB free. If bsd's is
         * larger than this the assert fires again -- but OnNeedsToAccept now
         * records the real number to bsd.log before accepting, so the next
         * report will name it instead of us guessing twice. */
        struct MitmServerOptions {
            static constexpr size_t PointerBufferSize   = 0x1000;
            /* NOT the defaults, which are 0 and 0.
             *
             * A HIPC client may convert its session into a DOMAIN before it
             * sends a single service command -- ConvertCurrentObjectToDomain is
             * a control request, answered by the framework, and no handler of
             * ours would ever see it. With MaxDomains = 0 that conversion fails
             * inside libstratosphere, the client's service-creation path takes
             * the error, and the game dies without one command reaching us.
             *
             * Which is exactly the failure we have been chasing: sessions
             * accepted, no handler reached, nnSdk aborting inside
             * nn::socket::detail::CreateClientServiceByHipc.
             *
             * ryu_ldn_nx, whose bsd:u MITM works, uses 0x10 / 0x100. */
            static constexpr size_t MaxDomains          = MitmSessions;
            /* Keep the working ryu_ldn_nx/MK8 capacity. Splatoon 3 creates
             * enough cloned nnSdk BSD objects that the prior 0x20 memory
             * optimisation can fail during CreateClientServiceByHipc, before
             * any socket command is issued. The restored capacity costs only
             * 24 KiB over 0x20. */
            static constexpr size_t MaxDomainObjects    = 0x100;
            static constexpr bool CanDeferInvokeRequest = sf::hipc::DefaultServerManagerOptions::CanDeferInvokeRequest;
            static constexpr bool CanManageMitmServers  = true;
        };

        /* Indexed ports require OnNeedsToAccept: the manager hands us the
         * acknowledged session and we construct the object that will serve it,
         * one per client process. */
        class MitmServerManager final : public sf::hipc::ServerManager<PortIndex_Count, MitmServerOptions, MitmSessions> {
            private:
                virtual Result OnNeedsToAccept(int port_index, Server *server) override {
                    std::shared_ptr<::Service> fsrv;
                    sm::MitmProcessInfo client_info;
                    server->AcknowledgeMitmSession(std::addressof(fsrv), std::addressof(client_info));

                    /* Written synchronously: if the pointer-buffer assert below
                     * fires, the process dies before anything else can flush. */
                    static int s_accepts = 0;
                    ztnx::mitm::NoteSync("accept #%d       program %016llx  fwd pbuf 0x%x  ours 0x%x",
                                         ++s_accepts,
                                         (unsigned long long)client_info.program_id.value,
                                         (unsigned)fsrv->pointer_buffer_size,
                                         (unsigned)MitmServerOptions::PointerBufferSize);

                    switch (port_index) {
                        case PortIndex_Bsd:
                            R_RETURN(this->AcceptMitmImpl(
                                server,
                                sf::CreateSharedObjectEmplaced<ztnx::mitm::IBsdShim, ztnx::mitm::BsdShim>(decltype(fsrv)(fsrv), client_info),
                                fsrv));
                        AMS_UNREACHABLE_DEFAULT_CASE();
                    }
                }
        };

        constinit ams::util::TypedStorage<MitmServerManager> g_mitm_manager_storage = {};
        MitmServerManager *g_mitm_manager = nullptr;

        alignas(os::MemoryPageSize) u8 g_mitm_thread_stack[16_KB];
        os::ThreadType g_mitm_thread;

        void MitmThreadMain(void *) {
            g_mitm_manager->LoopProcess();
        }

        /* A server manager has one pointer-buffer size for every port it
         * serves. bsd:u uses 0x1000, while the NIFM forward session measured
         * on hardware is 0x1f4. NIFM must therefore have its own manager. */
        struct NifmMitmServerOptions {
            static constexpr size_t PointerBufferSize   = 0x1F4;
            static constexpr size_t MaxDomains          = 4;
            /* Four clients, each with root/general/request, fit in 12. */
            static constexpr size_t MaxDomainObjects    = 0x10;
            static constexpr bool CanDeferInvokeRequest = sf::hipc::DefaultServerManagerOptions::CanDeferInvokeRequest;
            static constexpr bool CanManageMitmServers  = true;
        };
        constexpr size_t NifmMitmSessions = 4;
        class NifmMitmServerManager final : public sf::hipc::ServerManager<1, NifmMitmServerOptions, NifmMitmSessions> {
            private:
                virtual Result OnNeedsToAccept(int, Server *server) override {
                    std::shared_ptr<::Service> fsrv;
                    sm::MitmProcessInfo client_info;
                    server->AcknowledgeMitmSession(std::addressof(fsrv), std::addressof(client_info));
                    ztnx::mitm::NoteSync("nifm accept      fwd pbuf 0x%x  ours 0x%x",
                                         (unsigned)fsrv->pointer_buffer_size,
                                         (unsigned)NifmMitmServerOptions::PointerBufferSize);
                    /* Do not attach the target session as framework-managed
                     * MITM forwarding. NIFM closes that session when
                     * libstratosphere mirrors the client's ConvertToDomain.
                     * Our service owns the client-side domain locally and
                     * relays commands manually over fsrv instead. */
                    const Result accept_result = this->AcceptImpl(
                        server,
                        sf::CreateSharedObjectEmplaced<ztnx::mitm::INifmShim, ztnx::mitm::NifmShim>(decltype(fsrv)(fsrv), client_info));
                    ztnx::mitm::NoteSync("nifm accept      local result 0x%x", accept_result.GetValue());
                    ztnx::Trace("nifm: local session accept result 0x%x", accept_result.GetValue());
                    R_RETURN(accept_result);
                }
        };
        using NifmMitmManagerBase = sf::hipc::ServerManager<1, NifmMitmServerOptions, NifmMitmSessions>;
        constinit ams::util::TypedStorage<NifmMitmServerManager> g_nifm_mitm_manager_storage = {};
        NifmMitmManagerBase *g_nifm_mitm_manager = nullptr;
        alignas(os::MemoryPageSize) u8 g_nifm_mitm_thread_stack[16_KB];
        os::ThreadType g_nifm_mitm_thread;
        void NifmMitmThreadMain(void *) { g_nifm_mitm_manager->LoopProcess(); }

        /* GCC 14 loses the derived template arguments while inlining
         * RegisterMitmServer into this function and diagnoses a bogus
         * cross-manager TypedStorage bounds access. The instantiated NIFM
         * manager is 19 KB and contains its own one-server storage. */
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Warray-bounds"
        void StartNifmMitm() {
            if (!ztnx::ConfigFlag("nifm_mitm", true)) {
                ztnx::Trace("mitm: nifm:u DISABLED by config (nifm_mitm = 0)");
                return;
            }
            g_nifm_mitm_manager = ams::util::ConstructAt(g_nifm_mitm_manager_storage);
            const ams::Result r = g_nifm_mitm_manager->RegisterMitmServer<ztnx::mitm::NifmShim>(
                0, ams::sm::ServiceName::Encode("nifm:u"));
            if (R_FAILED(r)) { ztnx::Trace("mitm: RegisterMitmServer(nifm:u) failed 0x%x", r.GetValue()); return; }
            if (R_FAILED(os::CreateThread(std::addressof(g_nifm_mitm_thread), NifmMitmThreadMain, nullptr,
                                          g_nifm_mitm_thread_stack, sizeof(g_nifm_mitm_thread_stack),
                                          os::DefaultThreadPriority))) {
                ztnx::Trace("mitm: could not create nifm server thread");
                return;
            }
            os::StartThread(std::addressof(g_nifm_mitm_thread));
            ztnx::Trace("mitm: nifm:u registered (pbuf 0x1f4)");
        }
        #pragma GCC diagnostic pop

        void StartBsdMitm() {
            if (!ztnx::ConfigFlag("bsd_mitm", true)) {
                ztnx::Trace("mitm: bsd:u DISABLED by config (bsd_mitm = 0)");
                return;
            }

            g_mitm_manager = ams::util::ConstructAt(g_mitm_manager_storage);

            /* The template argument is the IMPL, not the interface --
             * RegisterMitmServerImpl takes &Interface::ShouldMitm, and
             * ShouldMitm is a static member of BsdShim. */
            const ams::Result r = g_mitm_manager->RegisterMitmServer<ztnx::mitm::BsdShim>(
                                      PortIndex_Bsd, ams::sm::ServiceName::Encode("bsd:u"));
            if (R_FAILED(r)) {
                ztnx::Trace("mitm: RegisterMitmServer(bsd:u) failed 0x%x", r.GetValue());
                return;
            }

            if (R_FAILED(os::CreateThread(std::addressof(g_mitm_thread), MitmThreadMain, nullptr,
                                          g_mitm_thread_stack, sizeof(g_mitm_thread_stack),
                                          os::DefaultThreadPriority))) {
                ztnx::Trace("mitm: could not create server thread");
                return;
            }
            os::StartThread(std::addressof(g_mitm_thread));
            ztnx::Trace("mitm: bsd:u registered, relaying");
            StartNifmMitm();
        }

        /* Everything that takes a service session happens here, on the node
         * thread, not in InitializeSystemModule.
         *
         * boot2 starts us while am, ns and friends are still coming up, and
         * svcConnectToPort returns svc::ResultLimitReached when a port is at
         * its max_sessions -- the same 0x10801 am was aborting on. Nothing we
         * do needs to happen early, so we get out of the way and take our
         * sessions once the system has settled. */
        bool LateInitialize(bool want_time, bool want_csrng, bool want_bsd) {
            if (want_time) {
                if (R_FAILED(timeInitialize()))  { return false; }
                ztnx::Trace("late: time");
            } else {
                ztnx::Trace("late: time SKIPPED by config");
            }

            if (want_csrng) {
                if (R_FAILED(csrngInitialize())) { return false; }
                ztnx::Trace("late: csrng");
            } else {
                ztnx::Trace("late: csrng SKIPPED by config");
            }

            /* No nifm. We used it only to wait for the console to associate,
             * which ZeroTier does not need -- it retries sends forever anyway.
             * Holding a nifm session buys us nothing and nifm's ports have few
             * sessions, which makes us a plausible reason for am to get
             * svc::ResultLimitReached from svcConnectToPort later in boot. */

            if (want_bsd) {
                if (R_FAILED(bsdInitialize(&BsdConfig, SocketConfig.num_bsd_sessions,
                                           SocketConfig.bsd_service_type))) { return false; }
                ztnx::Trace("late: bsd");

                if (R_FAILED(socketInitialize(&SocketConfig))) { return false; }
                ztnx::Trace("late: socket");
            } else {
                ztnx::Trace("late: bsd/socket SKIPPED by config");
            }
            return true;
        }

        void NodeThreadMain(void *) {
            /* Sample the shared System resource limit, but do not sit idle
             * while applications consume it. The former 20-second diagnostic
             * window delayed the mandatory 2 MB identity workspace until the
             * pool had only 1996 KB left, so ZeroTier could never create its
             * node. A single 250 ms sample preserves the evidence while
             * moving identity validation to the early-boot memory window. */
            ProbeResourceLimits(TimeSpan::FromMilliSeconds(250));

            /* Mount first: it needs only sm and fs, which we already hold, and
             * it is what makes config.ini readable. Everything after this can
             * be switched off from the SD card. */
            for (int attempt = 0; !ztnx::MountState(); ++attempt) {
                if (attempt >= 30) { break; }   /* run anyway; it just forgets */
                os::SleepThread(TimeSpan::FromSeconds(2));
            }

            /* What we actually cost the system, measured rather than guessed.
             * If am is failing on a memory reservation, this is the number
             * that matters -- and it settles whether the .bss estimate from
             * the ELF matches what the kernel charged us. */
            {
                u64 used = 0, total = 0;
                svcGetInfo(&used,  InfoType_UsedMemorySize,  CUR_PROCESS_HANDLE, 0);
                svcGetInfo(&total, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0);
                ztnx::Trace("mem: used %llu KB of %llu KB (pool_partition in app.json)",
                            (unsigned long long)(used / 1024),
                            (unsigned long long)(total / 1024));
            }

            const bool want_time  = ztnx::ConfigFlag("init_time",  true);
            const bool want_csrng = ztnx::ConfigFlag("init_csrng", true);
            const bool want_bsd   = ztnx::ConfigFlag("init_bsd",   true);
            const bool want_node  = ztnx::ConfigFlag("run_node",   true);
            const bool diagnostics = ztnx::ConfigFlag("debug_logging", false);
            ztnx::SetDiagnosticsEnabled(diagnostics);
            ztnx::Trace("flags: time=%d csrng=%d bsd=%d node=%d",
                        (int)want_time, (int)want_csrng, (int)want_bsd, (int)want_node);
            ztnx::Trace("logging: detailed BSD/NIFM diagnostics %s",
                        diagnostics ? "enabled" : "disabled");

            /* After the flags are known and before anything long-running:
             * psc has to be listening before the first time the user presses
             * the power button, not merely before the node comes online. */
            StartPowerMonitor();
            ztnx::mitm::SetPort(std::addressof(g_port));
            ztnx::mitm::SetNifmPort(std::addressof(g_port));
            StartBsdMitm();

            while (!LateInitialize(want_time, want_csrng, want_bsd)) {
                ztnx::Trace("thread: late init failed, retrying in 5s");
                os::SleepThread(TimeSpan::FromSeconds(5));
            }

            if (!want_node || !want_bsd) {
                /* Nothing more to do: hold here so the module stays resident
                 * with exactly the sessions the flags selected. */
                ztnx::Trace("thread: idling (node disabled)");
                for (;;) { os::SleepThread(TimeSpan::FromSeconds(30)); }
            }

            /* Blocks until config.ini names a network, writing a template on
             * first run. A missing config must never be a reason to abort. */
            ztnx::Trace("thread: waiting for a network id in config.ini");
            const uint64_t nwid = ztnx::WaitForConfiguredNetworkId();
            ztnx::Trace("thread: nwid = %.16llx", (unsigned long long)nwid);

            /* Retry rather than AMS_ABORT_UNLESS. Aborting here is a fatal
             * error screen on boot, which is a poor way to find out that the
             * network stack was still coming up. */
            while (!g_port.Initialize(nwid)) {
                ztnx::Trace("thread: Initialize failed, retrying");
                os::SleepThread(TimeSpan::FromSeconds(5));
            }

            ztnx::Trace("thread: entering run loop");
            g_port.RunLoop();
        }

    }  // namespace

    void Main() {
        ztnx::Trace("main: entered");

        /* Main does nothing but start the node thread and wait. Everything
         * that needs a service session -- including the wait for nifm to
         * associate -- now happens on that thread, after the system has had
         * time to finish booting. */
        R_ABORT_UNLESS(os::CreateThread(std::addressof(g_node_thread), NodeThreadMain, nullptr,
                                        g_node_thread_stack, NodeThreadStackSize,
                                        /* priority */ NodeThreadPriority));
        os::StartThread(std::addressof(g_node_thread));

        /* The ldn:u and bsd:u MITM servers are hosted here. Both are installed
         * with sm::mitm::InstallMitm and answer sm's ShouldMitm query
         * (command 65000) so that only the running application is intercepted
         * and system processes keep talking to the real services. */
        // mitm::ldn::StartServer(std::addressof(g_port));
        // mitm::bsd::StartServer(std::addressof(g_port));

        os::WaitThread(std::addressof(g_node_thread));
    }

    namespace init {

        /* Runs BEFORE the C++ static constructors -- which is the only place
         * the allocator can go.
         *
         * libstratosphere's startup order is:
         *   __appInit() -> InitializeSystemModuleBeforeConstructors()
         *   -> __libc_init_array()   <-- static constructors
         *   -> main() -> InitializeSystemModule() -> Startup() -> Main()
         *
         * ZeroTier's node/Metrics.cpp has a global
         *   std::shared_ptr<Registry> registry_ptr = std::make_shared<Registry>();
         * plus ~100 counter and gauge globals, all constructed during
         * __libc_init_array. With the allocator initialized in
         * InitializeSystemModule they ran std::malloc before any heap existed,
         * got nullptr back, and dereferenced it -- Data Abort with FAR = 0,
         * before Main() was ever reached. */
        void InitializeSystemModuleBeforeConstructors() {
            init::InitializeAllocator(g_malloc_buffer, sizeof(g_malloc_buffer));
        }

        void InitializeSystemModule() {
            R_ABORT_UNLESS(sm::Initialize());
            ztnx::Trace("init: sm");

            fs::InitializeForSystem();
            fs::SetAllocator(FsAllocate, FsDeallocate);
            fs::SetEnabledAutoAbort(false);
            ztnx::Trace("init: fs");


        }

        void FinalizeSystemModule() { /* never reached */ }
        void Startup() { /* nothing */ }

    }  // namespace init

}  // namespace ams
