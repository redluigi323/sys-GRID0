/*
 * sys-zerotier -- the virtual network interface.
 *
 * Sits between the game's intercepted BSD sockets and ZeroTier's virtual layer
 * 2. Owns the console's address on the ZeroTier network, an ARP cache, IPv4
 * assembly and reassembly, a UDP demultiplexer and an ICMP echo responder.
 *
 * There is no lwIP here and no TCP: native LAN-play titles use UDP broadcast
 * for discovery and UDP unicast for gameplay. If a target title turns out to
 * need TCP, that is the point at which lwIP earns its megabytes.
 *
 * Host-testable: no Horizon dependency, no allocation, no exceptions.
 * Not thread-safe -- the caller serialises (the sysmodule owns one lock over
 * the whole shim; contention is irrelevant at LAN-play packet rates).
 */
#pragma once

#include "net.hpp"

namespace ztnx::net {

    /* Sizing. Every buffer in the shim is accounted for here, because a
     * sysmodule that grows its own memory is a sysmodule that takes the console
     * down. Current total: 32*2064 (pool) + 4*2176 (reasm) + tables ~= 75 KB.
     *
     * MaxDatagram is deliberately larger than one MTU's worth of payload so the
     * send path fragments and the receive path reassembles; LAN-play traffic is
     * far smaller than this, but a peer on a PC is under no obligation to be. */
    constexpr int    MaxSockets    = 8;
    constexpr int    PoolPackets   = 32;
    constexpr size_t MaxDatagram   = 2048;
    constexpr int    ArpEntries    = 16;
    constexpr int    ReasmSlots    = 4;
    constexpr size_t ReasmMax      = 2176;   /* >= MaxDatagram + UDP header */
    constexpr size_t MaxFrame      = 1520;

    constexpr int InvalidSocket = -1;

    /* Emitted frames carry no Ethernet header: ZT_Node_processVirtualNetworkFrame
     * takes the MACs and ethertype as arguments and the payload separately. */
    typedef void (*EmitFn)(void *ctx, u64 dstMac, u16 etherType,
                           const void *payload, unsigned int len);

    struct Stats {
        u32 rxFrames, rxIp, rxUdp, rxArp, rxIcmp;
        u32 txFrames, txUdp, txArp, txIcmp;
        u32 dropNotForUs, dropBadChecksum, dropNoSocket, dropNoBuffer,
            dropTooBig, dropMalformed, dropReasm;
        u32 lastNoSocketSrcIp;
        u16 lastNoSocketSrcPort, lastNoSocketDstPort, lastNoSocketLen;
    };

    class VNet {
      public:
        void reset();

        /* Called from ZeroTier's virtualNetworkConfigFunction once the
         * controller has assigned an address. */
        void configure(u64 mac, u32 ip, u32 netmask, u16 mtu);
        void setEmit(EmitFn fn, void *ctx) { m_emit = fn; m_emitCtx = ctx; }

        bool configured() const { return m_configured; }
        u64  localMac()   const { return m_mac; }
        u32  localIp()    const { return m_ip; }
        u32  netmask()    const { return m_netmask; }
        u32  broadcastIp() const { return m_ip | ~m_netmask; }
        const Stats &stats() const { return m_stats; }

        /* Send an ICMP echo request. Exists so the console can be the one to
         * make first contact: a member that never transmits is one nobody has
         * a reason to look up. If the peer's MAC is unknown this emits an ARP
         * request instead and drops the echo, which is exactly the announcement
         * we want -- the ARP goes to the broadcast group and tells the other
         * side we exist. */
        bool sendEchoRequest(u32 dstIp);

        /* --- from ZeroTier: a frame arrived on the virtual network --- */
        void onFrame(u64 srcMac, u64 dstMac, u16 etherType,
                     const void *payload, unsigned int len);

        /* --- the socket API the bsd:u MITM drives --- */
        int  udpOpen();
        int  udpBind(int vfd, u32 ip, u16 port);        /* port 0 -> ephemeral */
        int  udpSendTo(int vfd, u32 dstIp, u16 dstPort,
                       const void *buf, unsigned int len);
        int  udpRecvFrom(int vfd, void *buf, unsigned int max,
                         u32 *srcIp, u16 *srcPort,
                         bool peek = false);            /* -1 when empty */
        bool udpReadable(int vfd) const;
        void udpSetBroadcast(int vfd, bool on);
        u16  udpLocalPort(int vfd) const;
        void udpClose(int vfd);

      private:
        struct Pkt {
            u16 len;
            u32 srcIp;
            u16 srcPort;
            int next;
            u8  data[MaxDatagram];
        };

        struct Socket {
            bool used;
            bool broadcast;
            u32  localIp;      /* 0 == INADDR_ANY */
            u16  localPort;    /* host order */
            int  qHead, qTail, qCount;
        };

        struct ArpEntry {
            u32 ip;
            u64 mac;
            u32 lastUsed;
        };

        struct Reasm {
            bool used;
            u32  srcIp, dstIp;
            u16  id;
            u8   proto;
            u16  received;     /* bytes filled */
            u16  total;        /* known once the last fragment arrives, else 0 */
            u32  age;
            u8   data[ReasmMax];
        };

        /* receive */
        void onArp(u64 srcMac, const u8 *p, unsigned int len);
        void onIpv4(u64 srcMac, const u8 *p, unsigned int len);
        void deliverIpv4(u32 srcIp, u32 dstIp, u8 proto, const u8 *payload, unsigned int len);
        void onUdp(u32 srcIp, u32 dstIp, const u8 *p, unsigned int len);
        void onIcmp(u32 srcIp, const u8 *p, unsigned int len);

        /* transmit */
        void sendIpv4(u32 dstIp, u8 proto, const u8 *payload, unsigned int len);
        void emitIpFragment(u64 dstMac, u32 dstIp, u8 proto, u16 id,
                            u16 fragOffsetBlocks, bool more,
                            const u8 *payload, unsigned int len);
        void sendArpRequest(u32 targetIp);

        /* helpers */
        bool isForUs(u32 dstIp) const;
        bool isBroadcast(u32 dstIp) const;
        u64  lookupMac(u32 ip) const;
        void learnMac(u32 ip, u64 mac);
        int  allocPkt();
        void freePkt(int idx);
        void pushToSocket(int sockIdx, u32 srcIp, u16 srcPort,
                          const u8 *data, unsigned int len);
        EmitFn m_emit = nullptr;
        void  *m_emitCtx = nullptr;

        bool m_configured = false;
        u64  m_mac = 0;
        u32  m_ip = 0, m_netmask = 0;
        u16  m_mtu = 1500;
        u16  m_echoSeq = 0;
        u16  m_ipId = 1;
        u16  m_nextEphemeral = 49152;
        u32  m_tick = 0;

        Socket   m_socks[MaxSockets] = {};
        Pkt      m_pool[PoolPackets] = {};
        int      m_freeList = 0;
        ArpEntry m_arp[ArpEntries] = {};
        Reasm    m_reasm[ReasmSlots] = {};
        Stats    m_stats = {};
    };

}  // namespace ztnx::net
