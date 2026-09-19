/*
 * sys-zerotier -- the bsd:u MITM interface.
 *
 * WHY THIS FILE IS SHAPED LIKE THIS
 *
 * The methods below are the commands sys-zerotier observes or modifies. This
 * is an AMS_SF_DEFINE_MITM_INTERFACE: libstratosphere's MITM dispatcher raw-
 * forwards an unknown command to the attached target session. Consequently
 * HOS 15--22 additions (34--43, 200 and 201) remain wire-exact without us
 * guessing their private structures, and future commands inherit the same
 * behaviour. Only add a command here when sys-zerotier needs to inspect it and
 * its complete IPC signature has been verified.
 *
 * THE RETURN CONVENTION (BSD_MITM.md section 5)
 *
 * bsd does not use the normal Horizon result convention. Every response begins
 * with a raw
 *
 *     struct { int ret; int errno_; }
 *
 * BEFORE any other output, and the IPC Result is 0 even when the socket call
 * failed (libnx `_bsdDispatchImpl`, bsd.c:116). errno_ is only meaningful when
 * ret < 0. Modelled here as two leading sf::Out<s32> parameters, which
 * libstratosphere serialises into the raw data section in declaration order --
 * exactly the layout libnx expects to read back.
 *
 * Commands 0 and 1 are setup exceptions. RegisterClient returns its BSD client
 * token directly. Splatoon 3 uses the nnSdk StartMonitoring variant observed
 * by ryu_ldn_nx: one raw u64 token and one s32 output, without the normal
 * ret/errno pair. Keeping command 1 typed also gives us synchronous proof of
 * whether initialization passed monitoring before the client session pool is
 * cloned.
 *
 * Buffers on the hot commands are HipcAutoSelect, which is what
 * sf::InAutoSelectBuffer / sf::OutAutoSelectBuffer map onto.
 *
 * Signatures verified against libnx nx/source/services/bsd.c.
 *
 * SAFETY
 *
 * This is on by default. The kill switch is `bsd_mitm = 0` in config.ini,
 * which is readable from the SD card without a rebuild -- that is what it is
 * for, not for gating development.
 *
 * The property that actually keeps the console safe is ShouldMitm, not the
 * flag. sm blocks loader, pm, spl, boot, ncm and creport from being mitm'd,
 * but it does NOT block ns, am, nifm, or any other system process -- those
 * reach bsd through the same service name and would be handed to us. So
 * ShouldMitm answers yes only for a real application id and nothing else. Get
 * that wrong and it is not the game that breaks, it is the console's
 * networking.
 */
#pragma once

#include <stratosphere.hpp>

namespace ztnx { class Port; }

namespace ztnx::mitm {

    /* AMS_SF_METHOD_INFO emits `hos::Version_Min, hos::Version_Max`
     * UNQUALIFIED into the generated interface. Every interface in Atmosphere
     * is declared in a namespace nested inside `ams` -- ams::psc::sf,
     * ams::erpt::sf -- where that resolves by enclosing-namespace lookup. Ours
     * is ztnx::mitm, where it does not, and the whole template argument list
     * fails to parse: thirty "conflicting return type" errors downstream of
     * two real ones.
     *
     * Aliasing both names into this namespace is the smallest fix and keeps
     * the interface reading like the ones in Atmosphere-libs. */
    namespace hos = ::ams::hos;
    using Result  = ::ams::Result;

    /* libnx BsdServiceConfig -- the raw request data for RegisterClient, NOT a
     * buffer (bsd.c:91 builds one struct and hands it to serviceDispatchInOut
     * with a copy handle for the transfer memory).
     *
     * What libnx actually sends is 48 bytes:
     *
     *     config (32) + pid_placeholder (8) + tmem_size (8)
     *
     * and that middle word IS the ClientProcessId slot -- sf::ClientProcessId
     * is an 8-byte raw in-data parameter that occupies its declared position.
     * Declaring a 48-byte struct that included the placeholder AND a separate
     * ClientProcessId made sf expect 56 bytes, so it rejected the request
     * before the handler ran. The game's first bsd call failed and its
     * enl::TaskThread asserted. Hence: 32 bytes here, and the placeholder
     * spelled out as a parameter in the middle. */
    struct BsdServiceConfig {
        u32 version;
        u32 tcp_tx_buf_size;
        u32 tcp_rx_buf_size;
        u32 tcp_tx_buf_max_size;
        u32 tcp_rx_buf_max_size;
        u32 udp_tx_buf_size;
        u32 udp_rx_buf_size;
        u32 sb_efficiency;
    };
    static_assert(sizeof(BsdServiceConfig) == 0x20);

    /* Every bsd response opens with this pair, before any other output. */
    struct BsdResult {
        s32 ret;
        s32 err;
    };

    /* Raw command-5 timeout layout used by libnx/nnSdk. The previous shim
     * declared only nfds, which made forwarded selects lose their timeout and
     * also prevented us from bounding the physical wait while a VNet socket
     * is being watched. */
    struct BsdTimeval {
        s64 seconds;
        s64 microseconds;
    };
    struct BsdSelectTimeval {
        BsdTimeval value;
        bool is_null;
        u8 padding[7];
    };
    static_assert(sizeof(BsdSelectTimeval) == 0x18);

}

#define AMS_ZTNX_I_BSD_INTERFACE_INFO(C, H)                                                                                                                                                                                       \
    AMS_SF_METHOD_INFO(C, H,  0, Result, RegisterClient,        (ams::sf::Out<u64> out_pid, const ztnx::mitm::BsdServiceConfig &config, const ams::sf::ClientProcessId &client_pid, u64 tmem_size, ams::sf::CopyHandle &&tmem), (out_pid, config, client_pid, tmem_size, std::move(tmem)))                                    \
    AMS_SF_METHOD_INFO(C, H,  1, Result, StartMonitoring,       (ams::sf::Out<s32> out_errno, u64 pid),                                                                                                                           (out_errno, pid))                                                    \
    AMS_SF_METHOD_INFO(C, H,  2, Result, Socket,                (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 domain, s32 type, s32 protocol),                                                                              (ret, err, domain, type, protocol))                                 \
    AMS_SF_METHOD_INFO(C, H,  3, Result, SocketExempt,          (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 domain, s32 type, s32 protocol),                                                                              (ret, err, domain, type, protocol))                                 \
    AMS_SF_METHOD_INFO(C, H,  4, Result, Open,                  (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 flags, const ams::sf::InAutoSelectBuffer &path),                                                              (ret, err, flags, path))                                            \
    AMS_SF_METHOD_INFO(C, H,  5, Result, Select,                (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 nfds, const ztnx::mitm::BsdSelectTimeval &timeout, const ams::sf::InAutoSelectBuffer &rd, const ams::sf::InAutoSelectBuffer &wr, const ams::sf::InAutoSelectBuffer &ex, const ams::sf::OutAutoSelectBuffer &ord, const ams::sf::OutAutoSelectBuffer &owr, const ams::sf::OutAutoSelectBuffer &oex), (ret, err, nfds, timeout, rd, wr, ex, ord, owr, oex)) \
    AMS_SF_METHOD_INFO(C, H,  6, Result, Poll,                  (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 nfds, s32 timeout, const ams::sf::InAutoSelectBuffer &in_fds, const ams::sf::OutAutoSelectBuffer &out_fds),   (ret, err, nfds, timeout, in_fds, out_fds))                         \
    AMS_SF_METHOD_INFO(C, H,  7, Result, Sysctl,                (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, ams::sf::Out<u32> out_len, const ams::sf::InAutoSelectBuffer &name, const ams::sf::InAutoSelectBuffer &oldp, const ams::sf::OutAutoSelectBuffer &newp), (ret, err, out_len, name, oldp, newp))          \
    AMS_SF_METHOD_INFO(C, H,  8, Result, Recv,                  (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, u32 flags, const ams::sf::OutAutoSelectBuffer &buf),                                                  (ret, err, sockfd, flags, buf))                                     \
    AMS_SF_METHOD_INFO(C, H,  9, Result, RecvFrom,              (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, ams::sf::Out<u32> addrlen, s32 sockfd, u32 flags, const ams::sf::OutAutoSelectBuffer &buf, const ams::sf::OutAutoSelectBuffer &addr), (ret, err, addrlen, sockfd, flags, buf, addr))    \
    AMS_SF_METHOD_INFO(C, H, 10, Result, Send,                  (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, u32 flags, const ams::sf::InAutoSelectBuffer &buf),                                                   (ret, err, sockfd, flags, buf))                                     \
    AMS_SF_METHOD_INFO(C, H, 11, Result, SendTo,                (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, u32 flags, const ams::sf::InAutoSelectBuffer &buf, const ams::sf::InAutoSelectBuffer &addr),          (ret, err, sockfd, flags, buf, addr))                               \
    AMS_SF_METHOD_INFO(C, H, 12, Result, Accept,                (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, ams::sf::Out<u32> addrlen, s32 sockfd, const ams::sf::OutAutoSelectBuffer &addr),                                 (ret, err, addrlen, sockfd, addr))                                  \
    AMS_SF_METHOD_INFO(C, H, 13, Result, Bind,                  (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, const ams::sf::InAutoSelectBuffer &addr),                                                             (ret, err, sockfd, addr))                                           \
    AMS_SF_METHOD_INFO(C, H, 14, Result, Connect,               (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, const ams::sf::InAutoSelectBuffer &addr),                                                             (ret, err, sockfd, addr))                                           \
    AMS_SF_METHOD_INFO(C, H, 15, Result, GetPeerName,           (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, ams::sf::Out<u32> addrlen, s32 sockfd, const ams::sf::OutAutoSelectBuffer &addr),                                 (ret, err, addrlen, sockfd, addr))                                  \
    AMS_SF_METHOD_INFO(C, H, 16, Result, GetSockName,           (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, ams::sf::Out<u32> addrlen, s32 sockfd, const ams::sf::OutAutoSelectBuffer &addr),                                 (ret, err, addrlen, sockfd, addr))                                  \
    AMS_SF_METHOD_INFO(C, H, 17, Result, GetSockOpt,            (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, ams::sf::Out<u32> optlen, s32 sockfd, s32 level, s32 optname, const ams::sf::OutAutoSelectBuffer &optval),        (ret, err, optlen, sockfd, level, optname, optval))                 \
    AMS_SF_METHOD_INFO(C, H, 18, Result, Listen,                (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, s32 backlog),                                                                                         (ret, err, sockfd, backlog))                                        \
    AMS_SF_METHOD_INFO(C, H, 19, Result, Ioctl,                 (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 fd, s32 request, u32 bufcount, const ams::sf::InAutoSelectBuffer &b1, const ams::sf::InAutoSelectBuffer &b2, const ams::sf::OutAutoSelectBuffer &b3, const ams::sf::OutAutoSelectBuffer &b4), (ret, err, fd, request, bufcount, b1, b2, b3, b4)) \
    AMS_SF_METHOD_INFO(C, H, 20, Result, Fcntl,                 (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 fd, s32 cmd, s32 arg),                                                                                        (ret, err, fd, cmd, arg))                                           \
    AMS_SF_METHOD_INFO(C, H, 21, Result, SetSockOpt,            (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, s32 level, s32 optname, const ams::sf::InAutoSelectBuffer &optval),                                   (ret, err, sockfd, level, optname, optval))                         \
    AMS_SF_METHOD_INFO(C, H, 22, Result, Shutdown,              (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, s32 how),                                                                                             (ret, err, sockfd, how))                                            \
    AMS_SF_METHOD_INFO(C, H, 23, Result, ShutdownAllSockets,    (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 how),                                                                                                         (ret, err, how))                                                    \
    AMS_SF_METHOD_INFO(C, H, 24, Result, Write,                 (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 fd, const ams::sf::InAutoSelectBuffer &buf),                                                                  (ret, err, fd, buf))                                                \
    AMS_SF_METHOD_INFO(C, H, 25, Result, Read,                  (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 fd, const ams::sf::OutAutoSelectBuffer &buf),                                                                 (ret, err, fd, buf))                                                \
    AMS_SF_METHOD_INFO(C, H, 26, Result, Close,                 (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 fd),                                                                                                          (ret, err, fd))                                                     \
    AMS_SF_METHOD_INFO(C, H, 27, Result, DuplicateSocket,       (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, u64 reserved),                                                                                         (ret, err, sockfd, reserved))                                       \
    AMS_SF_METHOD_INFO(C, H, 28, Result, GetResourceStatistics,(ams::sf::Out<s32> err, ams::sf::OutBuffer stats, u64 pid),                                                                                                (err, stats, pid))                                                   \
    AMS_SF_METHOD_INFO(C, H, 29, Result, RecvMMsg,              (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, s32 vlen, s32 flags, s32 timeout, const ams::sf::OutAutoSelectBuffer &buf),                           (ret, err, sockfd, vlen, flags, timeout, buf), hos::Version_3_0_0)  \
    AMS_SF_METHOD_INFO(C, H, 33, Result, RegisterClientShared,  (ams::sf::Out<u64> out_pid, const ztnx::mitm::BsdServiceConfig &config, const ams::sf::ClientProcessId &client_pid, u64 work_size),                                                              (out_pid, config, client_pid, work_size), hos::Version_10_0_0)      \
    AMS_SF_METHOD_INFO(C, H, 30, Result, SendMMsg,              (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, s32 sockfd, s32 vlen, s32 flags, const ams::sf::InAutoSelectBuffer &buf),                                         (ret, err, sockfd, vlen, flags, buf), hos::Version_3_0_0)           \
    AMS_SF_METHOD_INFO(C, H, 31, Result, EventFd,               (ams::sf::Out<s32> ret, ams::sf::Out<s32> err, u64 initial_value, s32 flags),                                                                                    (ret, err, initial_value, flags), hos::Version_7_0_0)               \
    AMS_SF_METHOD_INFO(C, H, 32, Result, RegisterResourceStatisticsName, (ams::sf::Out<s32> err, u64 pid, const ams::sf::InBuffer &name),                                                                             (err, pid, name), hos::Version_15_0_0)

AMS_SF_DEFINE_MITM_INTERFACE(ztnx::mitm, IBsdShim, AMS_ZTNX_I_BSD_INTERFACE_INFO, 0x5A54B5D0)

namespace ztnx::mitm {

    class BsdShim {
        private:
            std::shared_ptr<::Service> m_forward_service;
            ams::sm::MitmProcessInfo   m_client_info;

            /* Set by RegisterClient / RegisterClientShared. Unregistered
             * workaround sessions are parked, but a registered session must
             * close normally so real bsd releases its transfer-memory copy
             * before nnSdk initializes a replacement socket environment. */
            bool                       m_registered = false;

            /* Splatoon 2 remains on ordinary command 0, but real bsd receives
             * a proxy TransferMemory instead of the game's rapidly reused
             * pages. Its first registered forward session is retained and
             * subsequent nnSdk environments reuse that process registration. */
            bool                       m_proxy_registration = false;
            bool                       m_proxy_registration_owner = false;
        public:
            BsdShim(std::shared_ptr<::Service> &&s, const ams::sm::MitmProcessInfo &c)
                : m_forward_service(std::move(s)), m_client_info(c) { /* ... */ }

            ~BsdShim();

            static bool ShouldMitm(const ams::sm::MitmProcessInfo &client);

            /* Periodic node-thread maintenance. Reclaims parked services and
             * virtual sockets only for kernel-confirmed exited processes. */
            static void CleanupAbandonedServices();

        public:
            #define ZTNX_DECLARE(CLASS, ID, RET, NAME, ARGS, ARGNAMES, V0, V1) RET NAME ARGS;
            AMS_ZTNX_I_BSD_INTERFACE_INFO(BsdShim, ZTNX_DECLARE)
            #undef ZTNX_DECLARE
    };

    /* Rewrites BsdLogPath from the in-memory ring. Called from the node thread,
     * never from an IPC handler: an SD write inside a forwarded socket call
     * would put filesystem latency directly into the game's send path. */
    void FlushObservations();

    /* Append one line and write the file immediately.
     *
     * Only for session setup, never the command path -- an SD write inside a
     * forwarded socket call would put filesystem latency into the game's send
     * path. It exists because the interesting failures happen during accept,
     * and an abort there kills the process before the node thread ever gets to
     * flush the ring. */
    void NoteSync(const char *fmt, ...);

    /* Append one compact line to the dedicated NIFM result log and flush it
     * immediately. This keeps typed IRequest state/policy observations from
     * being displaced by Splatoon's large BSD clone teardown burst. */
    void NoteNifmSync(const char *fmt, ...);

    /* Append to the dedicated NIFM ring without touching fs. Typed service
     * handlers use this while libstratosphere still owns the caller's TLS;
     * the framework's post-dispatch observation appends its result and flushes
     * both lines only after command serialization has completed. */
    void NoteNifm(const char *fmt, ...);

    /* Install the long-lived Port owned by main before accepting MITM
     * sessions. It is a non-owning pointer; main owns it for module life. */
    void SetPort(ztnx::Port *port);

    /* NIFM reports the real interface before substituting the managed
     * address. Preserve that observation so PIA 5.x browse replies can replace
     * host identifiers cached from the physical interface. */
    void ObservePhysicalIpConfig(u32 ip, u32 mask);

}
