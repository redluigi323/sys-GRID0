/*
 * sys-zerotier -- Horizon OS port layer for the ZeroTier core (node/).
 *
 * This file is the entire boundary between ZeroTier's platform-independent
 * core and Horizon: six callbacks and a clock. Everything above it (the packet
 * shim in net/) is host-testable; everything in it needs a console.
 *
 * NOT YET COMPILED -- devkitPro is required and was unreachable from the
 * machine this was written on. See README.md for status.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <atomic>
#include <stratosphere.hpp>

#include <ZeroTierOne.h>

#include "net/vnet.hpp"

namespace ztnx {

    /* Where state objects live on the SD card. Must match res/app.json's
     * title_id, or ZeroTier regenerates its identity on every boot -- which
     * costs a proof-of-work each time and gives the console a different
     * address every time, so nothing can ever find it twice. */
    constexpr const char *StateRoot   = "sdmc:/atmosphere/contents/4200000000005A54/zt";
    constexpr const char *ConfigPath  = "sdmc:/config/sys-zerotier/config.ini";
    constexpr const char *ConfigDir   = "sdmc:/config/sys-zerotier";
    constexpr const char *SavedNetworksPath = "sdmc:/config/sys-zerotier/networks.ini";
    constexpr const char *UplinkLogPath = "sdmc:/config/sys-zerotier/uplink.log";
    constexpr const char *StatusPath  = "sdmc:/config/sys-zerotier/status.txt";
    constexpr const char *PeersPath   = "sdmc:/config/sys-zerotier/peers.txt";
    constexpr const char *BsdLogPath  = "sdmc:/config/sys-zerotier/bsd.log";
    constexpr const char *NifmLogPath = "sdmc:/config/sys-zerotier/nifm.log";
    constexpr const char *BootLogPath = "sdmc:/config/sys-zerotier/boot.log";
    constexpr const char *PiaFirstRequestCapturePath = "sdmc:/config/sys-zerotier/pia-first-request.bin";
    constexpr const char *PiaFirstReplyCapturePath   = "sdmc:/config/sys-zerotier/pia-first-reply.bin";
    constexpr const char *PiaRequestCapturePath = "sdmc:/config/sys-zerotier/pia-request.bin";
    constexpr const char *PiaReplyCapturePath   = "sdmc:/config/sys-zerotier/pia-reply.bin";

    /* ZeroTier's transport port. 9993 is the default and the one most home
     * routers already have a working UPnP or NAT-PMP mapping for. */
    constexpr uint16_t DefaultWirePort = 9993;

    class Port {
      public:
        /* true on success. Deliberately not an ams::Result: there is no
         * result module here and nothing useful to distinguish. */
        bool Initialize(uint64_t nwid);
        void   Finalize();

        /* Services the wire socket, the outbound frame queue and ZeroTier's
         * background timer. Give it its own thread. */
        void RunLoop();

        /* The virtual interface the bsd:u MITM drives. Valid once
         * vnet().configured() reports true, which happens when the network
         * controller has assigned this node an address. */
        net::VNet &vnet() { return m_vnet; }

        bool Online() const { return m_online; }

        /* Called only by the BSD MITM. These keep VNet's fixed socket table
         * serialised with ZeroTier's virtual-frame callback on the node
         * thread. The first data-plane stage mirrors only observed LAN
         * broadcasts; it deliberately does not alter the BSD result path. */
        int  OpenLanSocket();
        bool BindLanSocket(int vfd, u16 port);
        /* Emits to a peer or broadcast on the ZeroTier-assigned LAN subnet.
         * This intentionally rejects ordinary Wi-Fi destinations: the BSD
         * call remains responsible for those. */
        bool MirrorLanDatagram(int vfd, u32 dst_ip, u16 port,
                               const void *data, unsigned int len);
        bool MirrorLanBroadcast(int vfd, u16 port,
                                const void *data, unsigned int len);
        bool LanSocketReadable(int vfd);
        int  ReceiveLanDatagram(int vfd, void *data, unsigned int max,
                                u32 *src_ip, u16 *src_port, bool peek = false);
        void CloseLanSocket(int vfd);

        /* Snapshot of the ZeroTier IPv4 identity, in host order. */
        bool GetLanIpConfig(u32 *ip, u32 *netmask);

        /* True only after a real ZeroTier wire send/receive has succeeded and
         * the virtual network still has a managed IPv4. NIFM can report the
         * physical interface available a few seconds before this becomes
         * true after Splatoon's radio-mode transition. */
        bool LanTransportReady();
        bool WaitForLanTransportReady(int64_t timeout_ms);

      private:
        /* --- the six ZT_Node_Callbacks --- */
        static int  cbStateGet(ZT_Node *, void *uptr, void *tptr, enum ZT_StateObjectType,
                               const uint64_t id[2], void *data, unsigned int maxlen);
        static void cbStatePut(ZT_Node *, void *uptr, void *tptr, enum ZT_StateObjectType,
                               const uint64_t id[2], const void *data, int len);
        static int  cbWireSend(ZT_Node *, void *uptr, void *tptr, int64_t localSocket,
                               const struct sockaddr_storage *addr, const void *data,
                               unsigned int len, unsigned int ttl);
        static void cbVirtualFrame(ZT_Node *, void *uptr, void *tptr, uint64_t nwid,
                                   void **nuptr, uint64_t srcMac, uint64_t destMac,
                                   unsigned int etherType, unsigned int vlanId,
                                   const void *data, unsigned int len);
        static int  cbNetworkConfig(ZT_Node *, void *uptr, void *tptr, uint64_t nwid,
                                    void **nuptr, enum ZT_VirtualNetworkConfigOperation op,
                                    const ZT_VirtualNetworkConfig *conf);
        static void cbEvent(ZT_Node *, void *uptr, void *tptr, enum ZT_Event ev,
                            const void *meta);

        /* net::VNet emits here; we queue and hand to ZeroTier on our own
         * thread, so the shim never blocks the caller that produced the frame. */
        static void cbEmit(void *ctx, uint64_t dstMac, uint16_t etherType,
                           const void *payload, unsigned int len);

        void drainOutbound();
        void pollNetworkSelection();
        bool switchNetwork(uint64_t nwid);
        void writeStatus(bool force);
        void heartbeat();

        /* Called from the node loop when the psc thread has asked us to stop.
         * Closes the wire socket, signals that we are quiesced, blocks until
         * resume, then reopens it. */
        void HandleSleep();
        bool openWireSocket();
        void watchSystemMemory();
        void subscribeBroadcast();
        void writePeers();
        void probePeer();
        void maintainWireSocket();

        int64_t m_lastBeatMs = 0;
        int64_t m_lastNetworkPollMs = 0;
        unsigned m_beatLastTx = 0, m_beatLastRx = 0;

        ZT_Node   *m_node   = nullptr;
        int        m_wireFd = -1;          /* primary or adaptive UDP socket on bsd:s */
        int        m_mappedFd = -1;
        int64_t    m_mappedSocketId = 0;
        uint16_t   m_mappedPort = 0;
        bool       m_natEnabled = false;
        int64_t    m_natRetryMs = 0;
        uint32_t   m_natAddress = 0;
        uint16_t   m_natPublicPort = 0;
        void maintainNatWire();
        void closeNatWire();
        uint16_t   m_wireLocalPort = 0;
        bool       m_wireEphemeral = false;
        uint64_t   m_nwid   = 0;
        net::VNet  m_vnet;
        ams::os::SdkMutex m_vnetLock;

        volatile bool m_online = false;

        /* Wire socket health. The question these answer: when a game enters LAN
         * Play and the console "leaves the internet", does our UDP/9993 socket
         * keep working? A rising m_wireTxFail with errno 101/113 is the console
         * losing its route; steady m_wireRx is proof it did not.
         * Not volatile: every one of these is written and read on the node
         * thread only -- cbWireSend and RunLoop are both on it -- and C++20
         * deprecates ++ on a volatile lvalue. If a second thread ever touches
         * them, make them std::atomic, not volatile. */
        unsigned m_wireTx     = 0;
        unsigned m_wireRx     = 0;
        unsigned m_wireTxFail = 0;
        unsigned m_wireSkipV6 = 0;   /* AF_INET6 destinations we never attempt */
        int      m_wireErrno  = 0;
        uint32_t m_wireLastDstIp = 0; /* host order; explains route failures */
        uint16_t m_wireLastDstPort = 0;

        /* Recovery. uplink.log showed the socket dying with EPIPE and every
         * subsequent send failing forever -- 172 failures and zero bytes sent
         * over the rest of the session, while ZeroTier still believed it was
         * online. A UDP socket does not come back on its own; it has to be
         * recycled. */
        int      m_wireFailStreak = 0;
        int      m_wireBackoffMs  = 0;
        int64_t  m_wireReopenAtMs = 0;
        int64_t  m_wireDownAtMs   = 0;
        int      m_wireReopenFail = 0;
        bool     m_wireRecovering = false;
        bool     m_wireRecoveryConfirmed = false;
        std::atomic<bool> m_wireReachable{false};

        /* Liveness. status.txt is now written on a timer rather than on change,
         * so a stale uplink.log next to a fresh status.txt means the LOGGING
         * died, and both stale means the THREAD died. Those are different bugs
         * and one file could not tell them apart. */
        uint64_t m_loops = 0;
        int64_t  m_lastPeersMs = 0;
        int64_t  m_lastProbeMs   = 0;
        uint32_t m_probeIp     = 0;
        bool     m_probeRead   = false;
        bool     m_firstFrameLogged = false;
        int64_t  m_startedMs   = 0;
        bool     m_subscribed   = false;
        volatile bool m_needSubscribe = false;   /* set in a callback, acted on in the loop */

        /* 64620 iterations in 171 s is 378/sec, against a poll() timeout of
         * 10 ms that should cap the loop at ~100/sec. Either poll returns
         * early or it returns an error we never looked at -- and a sysmodule
         * spinning on a system core while a game runs is not free. */
        unsigned m_pollErr   = 0;
        unsigned m_pollZero  = 0;
        unsigned m_pollBad   = 0;   /* POLLERR / POLLHUP / POLLNVAL */
        int      m_pollErrno = 0;
        bool     m_wireHup   = false;
        volatile int64_t m_nextDeadline = 0;
        int  m_netStatus = -1;   /* ZT_VirtualNetworkStatus, -1 = no config yet */
        int  m_lastError = 0;    /* last ZT_ResultCode that was not OK */
        int64_t m_lastStatusMs = 0;
        bool    m_lastStatusOnline = false;
        uint32_t m_lastStatusIp = 0;
        int      m_lastStatusNetStatus = -2;
    };

    /* Milliseconds since epoch. MUST be real wall-clock time before the node is
     * created -- see PORTING.md section 3.3. */
    int64_t NowMs();

    /* Fills buf from the console CSPRNG (csrng). Replaces the core's
     * /dev/urandom path. */
    void SecureRandom(void *buf, size_t len);

    /* Records a line of boot progress. Buffered in memory, because the most
     * interesting part of startup happens before the SD card is mounted;
     * FlushTrace() writes the whole thing out once it is. Safe to call from
     * anywhere, including before the allocator exists. */
    void Trace(const char *fmt, ...);

    /* Append-only event log at UplinkLogPath, kept as the last EventLines lines
     * in memory and rewritten whole. Unlike status.txt -- which only ever shows
     * the current state -- this preserves transitions, so an uplink that drops
     * and recovers during a match is still visible afterwards. */
    void Event(const char *fmt, ...);

    /* Whole-file write, exposed for the mitm observation log. */
    bool WriteTextFile(const char *path, const char *text);
    bool WriteBinaryFile(const char *path, const void *data, size_t len);

    /* ---- sleep gate -------------------------------------------------------
     *
     * Horizon suspends fs and the socket stack when the console sleeps. A
     * thread that is inside fs::WriteFile or ::poll() when that happens holds a
     * service busy across the transition, and the transition never finishes --
     * which is a console that looks asleep and cannot be woken.
     *
     * psc exists to prevent exactly that: a module declares which services it
     * depends on, is notified before those services go down, and acknowledges
     * once it has stopped touching them. These four functions are that
     * handshake, split across the psc thread and the node thread.
     *
     * psc thread:   RequestQuiesce() -> WaitQuiesced() -> [ack] ... SignalResume()
     * node thread:  SleepRequested() -> Port::HandleSleep()
     */
    void RequestQuiesce();
    /* Milliseconds, not TimeSpan: this header is included before
     * <stratosphere.hpp> and stays free of ams types on purpose. */
    bool WaitQuiesced(int64_t timeout_ms);
    void SignalResume();
    bool SleepRequested();
    void FlushTrace();

    /* Mounts the SD card and creates the state directories. ZeroTier writes
     * state through fs::CreateFile, which fails if the parent directory does
     * not exist -- silently, because the callback returns void. Returns false
     * if state will not persist; the node still runs, it just forgets. */
    bool MountState();

    /* Reads a `key = 0/1` line from config.ini. Returns dflt when the key is
     * absent. Lets individual init steps be switched off from the SD card, so
     * bisecting which service session upsets am costs a text edit and a reboot
     * rather than a full rebuild. */
    bool ConfigFlag(const char *key, bool dflt);
    int  ConfigValue(const char *key, int dflt);
    uint32_t ConfigIpv4(const char *key);   /* 0 when absent or unparseable */

    /* The packet/MITM traces are intentionally opt-in in release builds. They
     * are invaluable for a bug report, but formatting and rewriting them on
     * every service call is needless SD and CPU churn during normal play.
     * Loaded once after config.ini becomes available; changing it therefore
     * takes effect on the next reboot, just like the MITM enable switches. */
    void SetDiagnosticsEnabled(bool enabled);
    bool DiagnosticsEnabled();

    /* Blocks until config.ini or networks.ini names a network. Writes a
     * commented template on first run. Returns a valid 16-hex-digit ID. */
    uint64_t WaitForConfiguredNetworkId();

}  // namespace ztnx
