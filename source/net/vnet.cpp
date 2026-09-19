#include "vnet.hpp"

namespace ztnx::net {

    /* ------------------------------------------------------------------ */
    /* lifecycle                                                           */
    /* ------------------------------------------------------------------ */

    void VNet::reset()
    {
        m_configured = false;
        m_mac = 0; m_ip = 0; m_netmask = 0; m_mtu = 1500;
        m_ipId = 1; m_nextEphemeral = 49152; m_tick = 0;

        for (int i = 0; i < MaxSockets; ++i) {
            m_socks[i] = Socket{};
            m_socks[i].qHead = m_socks[i].qTail = -1;
        }
        for (int i = 0; i < PoolPackets; ++i) {
            m_pool[i].next = (i + 1 < PoolPackets) ? (i + 1) : -1;
        }
        m_freeList = 0;

        for (int i = 0; i < ArpEntries; ++i) { m_arp[i] = ArpEntry{}; }
        for (int i = 0; i < ReasmSlots; ++i) { m_reasm[i].used = false; }
        m_stats = Stats{};
    }

    void VNet::configure(u64 mac, u32 ip, u32 netmask, u16 mtu)
    {
        m_mac = mac; m_ip = ip; m_netmask = netmask;
        m_mtu = (mtu >= 576 && mtu <= MaxFrame - 14) ? mtu : 1500;
        m_configured = true;
    }

    /* ------------------------------------------------------------------ */
    /* address helpers                                                     */
    /* ------------------------------------------------------------------ */

    bool VNet::isBroadcast(u32 dstIp) const
    {
        return dstIp == IpBroadcast || (m_netmask != 0 && dstIp == (m_ip | ~m_netmask));
    }

    bool VNet::isForUs(u32 dstIp) const
    {
        return dstIp == m_ip || isBroadcast(dstIp);
    }

    u64 VNet::lookupMac(u32 ip) const
    {
        if (isBroadcast(ip)) { return MacBroadcast; }
        for (int i = 0; i < ArpEntries; ++i) {
            if (m_arp[i].mac != 0 && m_arp[i].ip == ip) { return m_arp[i].mac; }
        }
        return 0;
    }

    void VNet::learnMac(u32 ip, u64 mac)
    {
        if (ip == 0 || mac == 0 || mac == MacBroadcast) { return; }

        int oldest = 0;
        for (int i = 0; i < ArpEntries; ++i) {
            if (m_arp[i].mac != 0 && m_arp[i].ip == ip) {
                m_arp[i].mac = mac;
                m_arp[i].lastUsed = ++m_tick;
                return;
            }
            if (m_arp[i].mac == 0) { oldest = i; break; }
            if (m_arp[i].lastUsed < m_arp[oldest].lastUsed) { oldest = i; }
        }
        m_arp[oldest].ip = ip;
        m_arp[oldest].mac = mac;
        m_arp[oldest].lastUsed = ++m_tick;
    }

    /* ------------------------------------------------------------------ */
    /* packet pool                                                         */
    /* ------------------------------------------------------------------ */

    int VNet::allocPkt()
    {
        if (m_freeList < 0) { return -1; }
        const int idx = m_freeList;
        m_freeList = m_pool[idx].next;
        m_pool[idx].next = -1;
        return idx;
    }

    void VNet::freePkt(int idx)
    {
        if (idx < 0 || idx >= PoolPackets) { return; }
        m_pool[idx].next = m_freeList;
        m_freeList = idx;
    }

    /* ------------------------------------------------------------------ */
    /* inbound                                                             */
    /* ------------------------------------------------------------------ */

    void VNet::onFrame(u64 srcMac, u64 dstMac, u16 etherType,
                       const void *payload, unsigned int len)
    {
        m_stats.rxFrames++;
        if (!m_configured || payload == nullptr || len == 0) { return; }

        /* ZeroTier only delivers frames addressed to us or to broadcast, but
         * do not rely on that. */
        if (dstMac != m_mac && dstMac != MacBroadcast) {
            m_stats.dropNotForUs++;
            return;
        }

        const u8 *p = static_cast<const u8 *>(payload);
        switch (etherType) {
            case EtherType_ARP:  onArp(srcMac, p, len);  break;
            case EtherType_IPv4: onIpv4(srcMac, p, len); break;
            default: break;      /* IPv6 and friends: not our business */
        }
    }

    void VNet::onArp(u64 srcMac, const u8 *p, unsigned int len)
    {
        m_stats.rxArp++;
        if (len < arp4::Size) { m_stats.dropMalformed++; return; }
        if (rd16(p + arp4::HwType) != 1 || rd16(p + arp4::ProtoType) != EtherType_IPv4) { return; }
        if (p[arp4::HwLen] != 6 || p[arp4::ProtoLen] != 4) { return; }

        const u16 op       = rd16(p + arp4::Op);
        const u32 senderIp = rd32(p + arp4::SenderIp);
        const u32 targetIp = rd32(p + arp4::TargetIp);
        const u64 senderMac = macFromBytes(p + arp4::SenderMac);

        /* Learn from both requests and replies -- a peer that ARPs for us has
         * just told us everything we need to reply to it. */
        learnMac(senderIp, senderMac ? senderMac : srcMac);

        if (op != arp4::OpRequest || targetIp != m_ip) { return; }

        u8 reply[arp4::Size];
        wr16(reply + arp4::HwType, 1);
        wr16(reply + arp4::ProtoType, EtherType_IPv4);
        reply[arp4::HwLen]   = 6;
        reply[arp4::ProtoLen] = 4;
        wr16(reply + arp4::Op, arp4::OpReply);
        macToBytes(m_mac, reply + arp4::SenderMac);
        wr32(reply + arp4::SenderIp, m_ip);
        macToBytes(senderMac, reply + arp4::TargetMac);
        wr32(reply + arp4::TargetIp, senderIp);

        if (m_emit) {
            m_emit(m_emitCtx, senderMac, EtherType_ARP, reply, sizeof(reply));
            m_stats.txFrames++; m_stats.txArp++;
        }
    }

    void VNet::onIpv4(u64 srcMac, const u8 *p, unsigned int len)
    {
        m_stats.rxIp++;
        if (len < ip4::MinHeader) { m_stats.dropMalformed++; return; }

        const unsigned int ihl = (unsigned int)(p[ip4::VerIhl] & 0x0F) * 4;
        if ((p[ip4::VerIhl] >> 4) != 4 || ihl < ip4::MinHeader || ihl > len) {
            m_stats.dropMalformed++; return;
        }
        if (checksum16(p, ihl) != 0) { m_stats.dropBadChecksum++; return; }

        unsigned int total = rd16(p + ip4::TotalLen);
        if (total < ihl || total > len) {
            /* Some stacks pad short frames; tolerate total <= len only. */
            if (total < ihl) { m_stats.dropMalformed++; return; }
            total = len;
        }

        const u32 srcIp = rd32(p + ip4::Src);
        const u32 dstIp = rd32(p + ip4::Dst);
        if (!isForUs(dstIp)) { m_stats.dropNotForUs++; return; }

        learnMac(srcIp, srcMac);

        const u8  proto      = p[ip4::Proto];
        const u16 flagsFrag  = rd16(p + ip4::FlagsFrag);
        const u16 fragOffset = (u16)((flagsFrag & ip4::FragOffsetMask) * 8);
        const bool more      = (flagsFrag & ip4::FlagMoreFragments) != 0;

        const u8 *payload = p + ihl;
        const unsigned int plen = total - ihl;

        if (fragOffset == 0 && !more) {
            deliverIpv4(srcIp, dstIp, proto, payload, plen);
            return;
        }

        /* --- reassembly ------------------------------------------------
         * Deliberately simple: one contiguous buffer per slot, byte count
         * compared against the total learned from the last fragment. It does
         * not defend against overlapping or duplicated fragments, which do not
         * occur on a ZeroTier virtual network between cooperating peers. */
        const u16 id = rd16(p + ip4::Id);
        int slot = -1, victim = 0;
        for (int i = 0; i < ReasmSlots; ++i) {
            if (m_reasm[i].used && m_reasm[i].id == id &&
                m_reasm[i].srcIp == srcIp && m_reasm[i].dstIp == dstIp &&
                m_reasm[i].proto == proto) {
                slot = i;
                break;
            }
            if (!m_reasm[i].used) { victim = i; }
            else if (m_reasm[i].age < m_reasm[victim].age) { victim = i; }
        }
        if (slot < 0) {
            slot = victim;
            m_reasm[slot].used = true;
            m_reasm[slot].srcIp = srcIp; m_reasm[slot].dstIp = dstIp;
            m_reasm[slot].id = id; m_reasm[slot].proto = proto;
            m_reasm[slot].received = 0; m_reasm[slot].total = 0;
        }
        m_reasm[slot].age = ++m_tick;

        if ((size_t)fragOffset + plen > ReasmMax) {
            m_reasm[slot].used = false;
            m_stats.dropReasm++;
            return;
        }
        memcpy(m_reasm[slot].data + fragOffset, payload, plen);
        m_reasm[slot].received = (u16)(m_reasm[slot].received + plen);
        if (!more) { m_reasm[slot].total = (u16)(fragOffset + plen); }

        if (m_reasm[slot].total != 0 && m_reasm[slot].received >= m_reasm[slot].total) {
            m_reasm[slot].used = false;
            deliverIpv4(srcIp, dstIp, proto, m_reasm[slot].data, m_reasm[slot].total);
        }
    }

    void VNet::deliverIpv4(u32 srcIp, u32 dstIp, u8 proto,
                           const u8 *payload, unsigned int len)
    {
        switch (proto) {
            case IpProto_UDP:  onUdp(srcIp, dstIp, payload, len); break;
            case IpProto_ICMP: onIcmp(srcIp, payload, len);       break;
            default: break;
        }
    }

    void VNet::onUdp(u32 srcIp, u32 dstIp, const u8 *p, unsigned int len)
    {
        m_stats.rxUdp++;
        if (len < udp4::Header) { m_stats.dropMalformed++; return; }

        const u16 srcPort = rd16(p + udp4::SrcPort);
        const u16 dstPort = rd16(p + udp4::DstPort);
        unsigned int udpLen = rd16(p + udp4::Length);
        if (udpLen < udp4::Header || udpLen > len) { udpLen = len; }

        /* A zero checksum means "not computed", which is legal for IPv4 UDP. */
        const u16 csum = rd16(p + udp4::Csum);
        if (csum != 0) {
            u32 pseudo = (srcIp >> 16) + (srcIp & 0xFFFF) +
                         (dstIp >> 16) + (dstIp & 0xFFFF) +
                         IpProto_UDP + udpLen;
            if (checksum16(p, udpLen, pseudo) != 0) {
                m_stats.dropBadChecksum++;
                return;
            }
        }

        /* A title can bind more than one socket to the same discovery port.
         * Broadcast is delivery to every matching listener, not whichever
         * table entry happened to be first. */
        bool delivered = false;
        for (int sock = 0; sock < MaxSockets; ++sock) {
            const Socket &s = m_socks[sock];
            if (!s.used || s.localPort != dstPort) { continue; }
            if (s.localIp == dstIp || s.localIp == 0 || isBroadcast(dstIp)) {
                pushToSocket(sock, srcIp, srcPort,
                             p + udp4::Header, udpLen - (unsigned int)udp4::Header);
                delivered = true;
            }
        }
        if (!delivered) {
            m_stats.dropNoSocket++;
            m_stats.lastNoSocketSrcIp = srcIp;
            m_stats.lastNoSocketSrcPort = srcPort;
            m_stats.lastNoSocketDstPort = dstPort;
            m_stats.lastNoSocketLen = (u16)(udpLen - (unsigned int)udp4::Header);
        }
    }

    bool VNet::sendEchoRequest(u32 dstIp)
    {
        if (!m_configured || dstIp == 0) { return false; }

        u8 icmp[16] = {};
        icmp[icmp4::Type] = icmp4::EchoRequest;
        icmp[icmp4::Code] = 0;
        wr16(icmp + icmp4::Csum, 0);
        wr16(icmp + 4, 0x5A54);            /* id: 'ZT' */
        wr16(icmp + 6, m_echoSeq++);
        memset(icmp + 8, 0x5A, 8);         /* payload */
        wr16(icmp + icmp4::Csum, checksum16(icmp, sizeof(icmp)));

        sendIpv4(dstIp, IpProto_ICMP, icmp, sizeof(icmp));
        m_stats.txIcmp++;
        return true;
    }

    void VNet::onIcmp(u32 srcIp, const u8 *p, unsigned int len)
    {
        m_stats.rxIcmp++;
        if (len < 8 || p[icmp4::Type] != icmp4::EchoRequest) { return; }
        if (checksum16(p, len) != 0) { m_stats.dropBadChecksum++; return; }
        if (len > MaxDatagram) { m_stats.dropTooBig++; return; }

        /* Echo the payload back verbatim. Exists so that `ping` works from a PC
         * during bring-up, which is worth a great deal when nothing else does
         * yet. */
        u8 reply[MaxDatagram];
        memcpy(reply, p, len);
        reply[icmp4::Type] = icmp4::EchoReply;
        wr16(reply + icmp4::Csum, 0);
        wr16(reply + icmp4::Csum, checksum16(reply, len));

        sendIpv4(srcIp, IpProto_ICMP, reply, len);
        m_stats.txIcmp++;
    }

    /* ------------------------------------------------------------------ */
    /* socket table                                                        */
    /* ------------------------------------------------------------------ */

    void VNet::pushToSocket(int sockIdx, u32 srcIp, u16 srcPort,
                            const u8 *data, unsigned int len)
    {
        if (len > MaxDatagram) { m_stats.dropTooBig++; return; }

        const int idx = allocPkt();
        if (idx < 0) { m_stats.dropNoBuffer++; return; }

        Pkt &pk = m_pool[idx];
        pk.len = (u16)len;
        pk.srcIp = srcIp;
        pk.srcPort = srcPort;
        pk.next = -1;
        if (len) { memcpy(pk.data, data, len); }

        Socket &s = m_socks[sockIdx];
        if (s.qTail < 0) { s.qHead = s.qTail = idx; }
        else { m_pool[s.qTail].next = idx; s.qTail = idx; }
        s.qCount++;
    }

    int VNet::udpOpen()
    {
        for (int i = 0; i < MaxSockets; ++i) {
            if (!m_socks[i].used) {
                m_socks[i] = Socket{};
                m_socks[i].used = true;
                m_socks[i].qHead = m_socks[i].qTail = -1;
                return i;
            }
        }
        return InvalidSocket;
    }

    int VNet::udpBind(int vfd, u32 ip, u16 port)
    {
        if (vfd < 0 || vfd >= MaxSockets || !m_socks[vfd].used) { return -1; }

        if (port == 0) {
            for (int tries = 0; tries < 4096; ++tries) {
                const u16 candidate = m_nextEphemeral++;
                if (m_nextEphemeral == 0) { m_nextEphemeral = 49152; }
                bool taken = false;
                for (int i = 0; i < MaxSockets; ++i) {
                    if (m_socks[i].used && m_socks[i].localPort == candidate) { taken = true; break; }
                }
                if (!taken) { port = candidate; break; }
            }
            if (port == 0) { return -1; }
        }

        m_socks[vfd].localIp = (ip == m_ip) ? 0 : ip;   /* our own address behaves as ANY */
        m_socks[vfd].localPort = port;
        return 0;
    }

    void VNet::udpSetBroadcast(int vfd, bool on)
    {
        if (vfd >= 0 && vfd < MaxSockets && m_socks[vfd].used) { m_socks[vfd].broadcast = on; }
    }

    u16 VNet::udpLocalPort(int vfd) const
    {
        if (vfd < 0 || vfd >= MaxSockets || !m_socks[vfd].used) { return 0; }
        return m_socks[vfd].localPort;
    }

    bool VNet::udpReadable(int vfd) const
    {
        return vfd >= 0 && vfd < MaxSockets && m_socks[vfd].used && m_socks[vfd].qCount > 0;
    }

    int VNet::udpRecvFrom(int vfd, void *buf, unsigned int max,
                          u32 *srcIp, u16 *srcPort, bool peek)
    {
        if (vfd < 0 || vfd >= MaxSockets || !m_socks[vfd].used) { return -1; }

        Socket &s = m_socks[vfd];
        if (s.qHead < 0) { return -1; }

        const int idx = s.qHead;
        Pkt &pk = m_pool[idx];

        /* Datagram semantics: an undersized buffer truncates, it does not
         * leave the remainder queued. MSG_PEEK is the exception: it returns
         * the same truncated view without consuming the datagram. */
        const unsigned int n = (pk.len < max) ? pk.len : max;
        if (n && buf) { memcpy(buf, pk.data, n); }
        if (srcIp)   { *srcIp = pk.srcIp; }
        if (srcPort) { *srcPort = pk.srcPort; }

        if (!peek) {
            s.qHead = pk.next;
            if (s.qHead < 0) { s.qTail = -1; }
            s.qCount--;
            freePkt(idx);
        }
        return (int)n;
    }

    void VNet::udpClose(int vfd)
    {
        if (vfd < 0 || vfd >= MaxSockets || !m_socks[vfd].used) { return; }
        int idx = m_socks[vfd].qHead;
        while (idx >= 0) {
            const int next = m_pool[idx].next;
            freePkt(idx);
            idx = next;
        }
        m_socks[vfd] = Socket{};
        m_socks[vfd].qHead = m_socks[vfd].qTail = -1;
    }

    /* ------------------------------------------------------------------ */
    /* outbound                                                            */
    /* ------------------------------------------------------------------ */

    int VNet::udpSendTo(int vfd, u32 dstIp, u16 dstPort,
                        const void *buf, unsigned int len)
    {
        if (vfd < 0 || vfd >= MaxSockets || !m_socks[vfd].used) { return -1; }
        if (!m_configured) { return -1; }
        if (len > MaxDatagram) { m_stats.dropTooBig++; return -1; }

        Socket &s = m_socks[vfd];
        if (s.localPort == 0 && udpBind(vfd, 0, 0) != 0) { return -1; }

        u8 datagram[udp4::Header + MaxDatagram];
        wr16(datagram + udp4::SrcPort, s.localPort);
        wr16(datagram + udp4::DstPort, dstPort);
        wr16(datagram + udp4::Length, (u16)(udp4::Header + len));
        wr16(datagram + udp4::Csum, 0);
        if (len && buf) { memcpy(datagram + udp4::Header, buf, len); }

        const unsigned int udpLen = (unsigned int)udp4::Header + len;
        u32 pseudo = (m_ip >> 16) + (m_ip & 0xFFFF) +
                     (dstIp >> 16) + (dstIp & 0xFFFF) +
                     IpProto_UDP + udpLen;
        u16 csum = checksum16(datagram, udpLen, pseudo);
        /* RFC 768: a computed checksum of zero is transmitted as all ones,
         * because zero means "no checksum". */
        if (csum == 0) { csum = 0xFFFF; }
        wr16(datagram + udp4::Csum, csum);

        sendIpv4(dstIp, IpProto_UDP, datagram, udpLen);
        m_stats.txUdp++;
        return (int)len;
    }

    void VNet::sendIpv4(u32 dstIp, u8 proto, const u8 *payload, unsigned int len)
    {
        const u64 dstMac = lookupMac(dstIp);
        if (dstMac == 0) {
            /* Unknown neighbour. In practice this is rare: every LAN-play
             * exchange starts with a broadcast and we learn MACs passively from
             * inbound frames. Ask, and drop this one -- the game will retry. */
            sendArpRequest(dstIp);
            return;
        }

        const unsigned int maxPayload = (unsigned int)(m_mtu - ip4::MinHeader);
        const u16 id = m_ipId++;

        if (len <= maxPayload) {
            emitIpFragment(dstMac, dstIp, proto, id, 0, false, payload, len);
            return;
        }

        /* Fragment offsets count 8-byte blocks, so each fragment except the
         * last must be a multiple of 8 bytes. */
        const unsigned int chunk = (maxPayload / 8) * 8;
        unsigned int off = 0;
        while (off < len) {
            const unsigned int take = (len - off > chunk) ? chunk : (len - off);
            const bool more = (off + take) < len;
            emitIpFragment(dstMac, dstIp, proto, id, (u16)(off / 8), more,
                           payload + off, take);
            off += take;
        }
    }

    void VNet::emitIpFragment(u64 dstMac, u32 dstIp, u8 proto, u16 id,
                              u16 fragOffsetBlocks, bool more,
                              const u8 *payload, unsigned int len)
    {
        if (!m_emit) { return; }
        if (ip4::MinHeader + len > MaxFrame) { m_stats.dropTooBig++; return; }

        u8 pkt[MaxFrame];
        pkt[ip4::VerIhl] = 0x45;
        pkt[ip4::Tos] = 0;
        wr16(pkt + ip4::TotalLen, (u16)(ip4::MinHeader + len));
        wr16(pkt + ip4::Id, id);
        wr16(pkt + ip4::FlagsFrag, (u16)((more ? ip4::FlagMoreFragments : 0) | fragOffsetBlocks));
        pkt[ip4::Ttl] = 64;
        pkt[ip4::Proto] = proto;
        wr16(pkt + ip4::Csum, 0);
        wr32(pkt + ip4::Src, m_ip);
        wr32(pkt + ip4::Dst, dstIp);
        wr16(pkt + ip4::Csum, checksum16(pkt, ip4::MinHeader));
        memcpy(pkt + ip4::MinHeader, payload, len);

        m_emit(m_emitCtx, dstMac, EtherType_IPv4, pkt, (unsigned int)(ip4::MinHeader + len));
        m_stats.txFrames++;
    }

    void VNet::sendArpRequest(u32 targetIp)
    {
        if (!m_emit) { return; }

        u8 req[arp4::Size];
        wr16(req + arp4::HwType, 1);
        wr16(req + arp4::ProtoType, EtherType_IPv4);
        req[arp4::HwLen] = 6;
        req[arp4::ProtoLen] = 4;
        wr16(req + arp4::Op, arp4::OpRequest);
        macToBytes(m_mac, req + arp4::SenderMac);
        wr32(req + arp4::SenderIp, m_ip);
        memset(req + arp4::TargetMac, 0, 6);
        wr32(req + arp4::TargetIp, targetIp);

        m_emit(m_emitCtx, MacBroadcast, EtherType_ARP, req, sizeof(req));
        m_stats.txFrames++; m_stats.txArp++;
    }

}  // namespace ztnx::net
