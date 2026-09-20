/*
 * Host tests for the virtual network shim.
 *
 * Builds with a plain host compiler -- the shim has no Horizon dependency, so
 * every byte it puts on the wire can be checked before any of it goes near a
 * console. Reference packet bytes in this file were produced independently
 * (see tests/reference.py) rather than by running the code under test.
 *
 *   make -C tests && tests/test_vnet
 */
#include "../source/net/vnet.hpp"
#include "../source/net/lifetime.hpp"

#include <cstdio>
#include <cstring>
#include <vector>
#include <string>

using namespace ztnx::net;

/* ------------------------------------------------------------------ */
/* tiny test framework                                                 */
/* ------------------------------------------------------------------ */

static int g_checks = 0, g_failures = 0;
static const char *g_case = "";

static void expect(bool ok, const char *what)
{
    ++g_checks;
    if (!ok) {
        ++g_failures;
        std::printf("  FAIL  %s :: %s\n", g_case, what);
    }
}

static void expectEqU(unsigned long long got, unsigned long long want, const char *what)
{
    ++g_checks;
    if (got != want) {
        ++g_failures;
        std::printf("  FAIL  %s :: %s (got %llu, want %llu)\n", g_case, what, got, want);
    }
}

static std::string hex(const u8 *p, size_t n)
{
    static const char *d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 0xF]; }
    return s;
}

static void expectBytes(const u8 *got, size_t gotLen, const char *wantHex, const char *what)
{
    ++g_checks;
    const std::string g = hex(got, gotLen);
    if (g != wantHex) {
        ++g_failures;
        std::printf("  FAIL  %s :: %s\n        got  %s\n        want %s\n",
                    g_case, what, g.c_str(), wantHex);
    }
}

/* ------------------------------------------------------------------ */
/* capture of emitted frames                                           */
/* ------------------------------------------------------------------ */

struct Frame {
    u64 dstMac;
    u16 etherType;
    std::vector<u8> payload;
};

struct Capture {
    std::vector<Frame> frames;
    void clear() { frames.clear(); }
};

static void onEmit(void *ctx, u64 dstMac, u16 etherType, const void *payload, unsigned int len)
{
    Capture *c = static_cast<Capture *>(ctx);
    Frame f;
    f.dstMac = dstMac;
    f.etherType = etherType;
    f.payload.assign(static_cast<const u8 *>(payload),
                     static_cast<const u8 *>(payload) + len);
    c->frames.push_back(f);
}

/* Our node: 10.147.20.50/24, MAC 02:ab:cd:00:11:22.
 * The peer: 10.147.20.51,   MAC 02:ab:cd:00:33:44. */
static constexpr u64 OurMac  = 0x02abcd001122ull;
static constexpr u64 PeerMac = 0x02abcd003344ull;
static constexpr u32 OurIp   = 0x0A93'1432u;   /* 10.147.20.50 */
static constexpr u32 PeerIp  = 0x0A93'1433u;   /* 10.147.20.51 */
static constexpr u32 Mask    = 0xFFFFFF00u;
static constexpr u32 Bcast   = 0x0A9314FFu;    /* 10.147.20.255 */

static Capture g_cap;

static void setup(VNet &v)
{
    v.reset();
    v.setEmit(onEmit, &g_cap);
    v.configure(OurMac, OurIp, Mask, 1500);
    g_cap.clear();
}

/* Build an inbound IPv4+UDP payload (no ethernet header -- ZeroTier hands us
 * the payload and the MACs separately). */
static std::vector<u8> buildUdp(u32 srcIp, u32 dstIp, u16 srcPort, u16 dstPort,
                                const void *data, size_t len, bool withCsum = true)
{
    std::vector<u8> pkt(ip4::MinHeader + udp4::Header + len, 0);
    u8 *p = pkt.data();

    p[ip4::VerIhl] = 0x45;
    wr16(p + ip4::TotalLen, (u16)pkt.size());
    wr16(p + ip4::Id, 0x1234);
    p[ip4::Ttl] = 64;
    p[ip4::Proto] = IpProto_UDP;
    wr32(p + ip4::Src, srcIp);
    wr32(p + ip4::Dst, dstIp);
    wr16(p + ip4::Csum, checksum16(p, ip4::MinHeader));

    u8 *u = p + ip4::MinHeader;
    const unsigned int udpLen = (unsigned int)(udp4::Header + len);
    wr16(u + udp4::SrcPort, srcPort);
    wr16(u + udp4::DstPort, dstPort);
    wr16(u + udp4::Length, (u16)udpLen);
    if (len) { memcpy(u + udp4::Header, data, len); }
    if (withCsum) {
        u32 pseudo = (srcIp >> 16) + (srcIp & 0xFFFF) + (dstIp >> 16) + (dstIp & 0xFFFF) +
                     IpProto_UDP + udpLen;
        u16 c = checksum16(u, udpLen, pseudo);
        if (c == 0) { c = 0xFFFF; }
        wr16(u + udp4::Csum, c);
    }
    return pkt;
}

/* ------------------------------------------------------------------ */
/* cases                                                               */
/* ------------------------------------------------------------------ */

static void test_checksum()
{
    g_case = "checksum";

    /* RFC 1071 worked example. */
    const u8 rfc[] = { 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    expectEqU(checksum16(rfc, sizeof(rfc)), 0x220d, "RFC 1071 example");

    /* A real IPv4 header verifies to zero including its own checksum field. */
    const u8 hdr[] = {
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61,
        0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7
    };
    expectEqU(checksum16(hdr, sizeof(hdr)), 0, "header verifies to zero");

    /* Odd length must pad the final byte high. */
    const u8 odd[] = { 0x12, 0x34, 0x56 };
    expectEqU(checksum16(odd, sizeof(odd)), (u16)(~(0x1234 + 0x5600) & 0xFFFF), "odd length");
}

static void test_arp_reply()
{
    g_case = "arp reply";
    VNet v; setup(v);

    u8 req[arp4::Size] = {};
    wr16(req + arp4::HwType, 1);
    wr16(req + arp4::ProtoType, EtherType_IPv4);
    req[arp4::HwLen] = 6; req[arp4::ProtoLen] = 4;
    wr16(req + arp4::Op, arp4::OpRequest);
    macToBytes(PeerMac, req + arp4::SenderMac);
    wr32(req + arp4::SenderIp, PeerIp);
    wr32(req + arp4::TargetIp, OurIp);

    v.onFrame(PeerMac, MacBroadcast, EtherType_ARP, req, sizeof(req));

    expectEqU(g_cap.frames.size(), 1, "one frame emitted");
    if (g_cap.frames.empty()) { return; }

    const Frame &f = g_cap.frames[0];
    expectEqU(f.etherType, EtherType_ARP, "ethertype");
    expectEqU(f.dstMac, PeerMac, "unicast back to requester");
    expectBytes(f.payload.data(), f.payload.size(),
                "0001080006040002"          /* hw=eth proto=ip lens op=reply */
                "02abcd0011220a931432"      /* sender mac + ip (us)          */
                "02abcd0033440a931433",     /* target mac + ip (peer)        */
                "arp reply bytes");

    /* An ARP request for someone else must not be answered. */
    g_cap.clear();
    wr32(req + arp4::TargetIp, 0x0A931499u);
    v.onFrame(PeerMac, MacBroadcast, EtherType_ARP, req, sizeof(req));
    expectEqU(g_cap.frames.size(), 0, "silent for other targets");
}

static void test_udp_send_broadcast()
{
    g_case = "udp send (broadcast)";
    VNet v; setup(v);

    const int s = v.udpOpen();
    expect(s >= 0, "socket allocated");
    expectEqU(v.udpBind(s, 0, 11451), 0, "bind");
    v.udpSetBroadcast(s, true);

    const char msg[] = "SCAN";
    expectEqU(v.udpSendTo(s, Bcast, 11451, msg, 4), 4, "sendto returns length");
    expectEqU(g_cap.frames.size(), 1, "one frame emitted");
    if (g_cap.frames.empty()) { return; }

    const Frame &f = g_cap.frames[0];
    expectEqU(f.dstMac, MacBroadcast, "broadcast MAC");
    expectEqU(f.etherType, EtherType_IPv4, "ethertype");

    /* Reference bytes computed independently in tests/reference.py. */
    expectBytes(f.payload.data(), f.payload.size(),
                "450000200001000040113c760a9314320a9314ff"  /* IPv4 header */
                "2cbb2cbb000cd377"                          /* UDP header  */
                "5343414e",                                 /* "SCAN"      */
                "ipv4+udp bytes");

    /* And the emitted header must verify. */
    expectEqU(checksum16(f.payload.data(), ip4::MinHeader), 0, "ip checksum verifies");
}

static void test_udp_receive_and_learn()
{
    g_case = "udp receive";
    VNet v; setup(v);

    const int s = v.udpOpen();
    v.udpBind(s, 0, 11451);

    const char msg[] = "HELLO";
    auto pkt = buildUdp(PeerIp, Bcast, 40000, 11451, msg, 5);
    v.onFrame(PeerMac, MacBroadcast, EtherType_IPv4, pkt.data(), (unsigned)pkt.size());

    expect(v.udpReadable(s), "socket readable");

    char buf[64] = {};
    u32 srcIp = 0; u16 srcPort = 0;
    char peek[3] = {};
    expectEqU(v.udpRecvFrom(s, peek, sizeof(peek), &srcIp, &srcPort, true),
              3, "peek returns truncated view");
    expect(memcmp(peek, "HEL", 3) == 0, "peek payload");
    expectEqU(srcIp, PeerIp, "peek source address");
    expectEqU(srcPort, 40000, "peek source port");
    expect(v.udpReadable(s), "peek does not drain queue");
    expectEqU(v.udpRecvFrom(s, buf, sizeof(buf), &srcIp, &srcPort), 5, "recvfrom length");
    expect(memcmp(buf, "HELLO", 5) == 0, "payload");
    expectEqU(srcIp, PeerIp, "source address is how peers are discovered");
    expectEqU(srcPort, 40000, "source port");
    expect(!v.udpReadable(s), "queue drained");
    expectEqU(v.udpRecvFrom(s, buf, sizeof(buf), &srcIp, &srcPort), (unsigned long long)-1, "empty returns -1");

    /* The MAC was learned passively, so a unicast reply needs no ARP. */
    g_cap.clear();
    v.udpSendTo(s, PeerIp, 40000, "OK", 2);
    expectEqU(g_cap.frames.size(), 1, "one frame");
    if (!g_cap.frames.empty()) {
        expectEqU(g_cap.frames[0].dstMac, PeerMac, "unicast to learned MAC, no ARP round trip");
        expectEqU(g_cap.frames[0].etherType, EtherType_IPv4, "ethertype");
    }
}

static void test_arp_request_when_unknown()
{
    g_case = "arp request";
    VNet v; setup(v);

    const int s = v.udpOpen();
    v.udpBind(s, 0, 11451);
    v.udpSendTo(s, PeerIp, 11451, "X", 1);

    expectEqU(g_cap.frames.size(), 1, "one frame");
    if (g_cap.frames.empty()) { return; }
    expectEqU(g_cap.frames[0].etherType, EtherType_ARP, "asks before sending");
    expectEqU(g_cap.frames[0].dstMac, MacBroadcast, "broadcast request");
}

static void test_demux()
{
    g_case = "demux";
    VNet v; setup(v);

    const int a = v.udpOpen(); v.udpBind(a, 0, 1000);
    const int b = v.udpOpen(); v.udpBind(b, 0, 2000);

    auto toB = buildUdp(PeerIp, OurIp, 5, 2000, "b", 1);
    v.onFrame(PeerMac, OurMac, EtherType_IPv4, toB.data(), (unsigned)toB.size());
    expect(!v.udpReadable(a), "wrong socket untouched");
    expect(v.udpReadable(b), "right socket has it");

    auto toNobody = buildUdp(PeerIp, OurIp, 5, 3000, "x", 1);
    v.onFrame(PeerMac, OurMac, EtherType_IPv4, toNobody.data(), (unsigned)toNobody.size());
    expectEqU(v.stats().dropNoSocket, 1, "unbound port counted, not crashed");

    /* A socket bound to our specific address still gets broadcast. */
    const int c = v.udpOpen(); v.udpBind(c, OurIp, 4000);
    auto bc = buildUdp(PeerIp, Bcast, 5, 4000, "y", 1);
    v.onFrame(PeerMac, MacBroadcast, EtherType_IPv4, bc.data(), (unsigned)bc.size());
    expect(v.udpReadable(c), "bound socket receives broadcast");

    /* LAN discovery commonly has more than one listener on a port. A
     * broadcast must reach all of them, rather than only the first VNet slot. */
    const int d = v.udpOpen(); v.udpBind(d, 0, 5000);
    const int e = v.udpOpen(); v.udpBind(e, OurIp, 5000);
    auto fanout = buildUdp(PeerIp, Bcast, 5, 5000, "f", 1);
    v.onFrame(PeerMac, MacBroadcast, EtherType_IPv4, fanout.data(), (unsigned)fanout.size());
    expect(v.udpReadable(d), "wildcard listener receives broadcast");
    expect(v.udpReadable(e), "specific listener receives broadcast too");
}

static void test_rejects_bad_input()
{
    g_case = "rejects bad input";
    VNet v; setup(v);

    const int s = v.udpOpen(); v.udpBind(s, 0, 11451);

    auto pkt = buildUdp(PeerIp, OurIp, 5, 11451, "z", 1);
    pkt[ip4::Csum] ^= 0xFF;                       /* corrupt the IP checksum */
    v.onFrame(PeerMac, OurMac, EtherType_IPv4, pkt.data(), (unsigned)pkt.size());
    expectEqU(v.stats().dropBadChecksum, 1, "bad ip checksum dropped");
    expect(!v.udpReadable(s), "nothing delivered");

    auto good = buildUdp(PeerIp, OurIp, 5, 11451, "z", 1);
    good[ip4::MinHeader + udp4::Csum] ^= 0xFF;    /* corrupt the UDP checksum */
    v.onFrame(PeerMac, OurMac, EtherType_IPv4, good.data(), (unsigned)good.size());
    expectEqU(v.stats().dropBadChecksum, 2, "bad udp checksum dropped");

    /* Zero UDP checksum is legal and must be accepted. */
    auto nocsum = buildUdp(PeerIp, OurIp, 5, 11451, "z", 1, /*withCsum=*/false);
    v.onFrame(PeerMac, OurMac, EtherType_IPv4, nocsum.data(), (unsigned)nocsum.size());
    expect(v.udpReadable(s), "zero checksum accepted");

    /* Traffic for another host must not be delivered. */
    auto elsewhere = buildUdp(PeerIp, 0x0A931401u, 5, 11451, "z", 1);
    v.onFrame(PeerMac, OurMac, EtherType_IPv4, elsewhere.data(), (unsigned)elsewhere.size());
    expect(v.stats().dropNotForUs > 0, "foreign destination dropped");

    /* Truncated garbage must not read past the buffer. */
    const u8 runt[] = { 0x45, 0x00, 0x00 };
    v.onFrame(PeerMac, OurMac, EtherType_IPv4, runt, sizeof(runt));
    expect(v.stats().dropMalformed > 0, "runt dropped");
}

static void test_icmp_echo()
{
    g_case = "icmp echo";
    VNet v; setup(v);

    u8 icmp[16] = {};
    icmp[icmp4::Type] = icmp4::EchoRequest;
    wr16(icmp + 4, 0x0042);          /* id */
    wr16(icmp + 6, 0x0001);          /* seq */
    memcpy(icmp + 8, "pingdata", 8);
    wr16(icmp + icmp4::Csum, checksum16(icmp, sizeof(icmp)));

    std::vector<u8> pkt(ip4::MinHeader + sizeof(icmp), 0);
    u8 *p = pkt.data();
    p[ip4::VerIhl] = 0x45;
    wr16(p + ip4::TotalLen, (u16)pkt.size());
    p[ip4::Ttl] = 64;
    p[ip4::Proto] = IpProto_ICMP;
    wr32(p + ip4::Src, PeerIp);
    wr32(p + ip4::Dst, OurIp);
    wr16(p + ip4::Csum, checksum16(p, ip4::MinHeader));
    memcpy(p + ip4::MinHeader, icmp, sizeof(icmp));

    v.onFrame(PeerMac, OurMac, EtherType_IPv4, pkt.data(), (unsigned)pkt.size());

    expectEqU(g_cap.frames.size(), 1, "reply emitted");
    if (g_cap.frames.empty()) { return; }
    const u8 *r = g_cap.frames[0].payload.data() + ip4::MinHeader;
    expectEqU(r[icmp4::Type], icmp4::EchoReply, "echo reply type");
    expectEqU(checksum16(r, sizeof(icmp)), 0, "icmp checksum verifies");
    expect(memcmp(r + 8, "pingdata", 8) == 0, "payload echoed verbatim");
}

static void test_fragmentation_roundtrip()
{
    g_case = "fragmentation";
    VNet v; setup(v);

    const int s = v.udpOpen();
    v.udpBind(s, 0, 11451);

    /* 1600 bytes of UDP payload does not fit a 1500-byte MTU. */
    u8 big[1600];
    for (size_t i = 0; i < sizeof(big); ++i) { big[i] = (u8)(i * 31 + 7); }

    /* Over one MTU's worth of payload, under MaxDatagram: the send path has to
     * fragment and the receive path has to put it back together. */
    const unsigned int payloadLen = 1500;
    expectEqU(v.udpSendTo(s, PeerIp, 11451, big, payloadLen), payloadLen, "send accepted");

    /* First frame is the ARP request (peer unknown), then the fragments. */
    g_cap.clear();
    v.onFrame(PeerMac, OurMac, EtherType_ARP, [] {
        static u8 reply[arp4::Size];
        wr16(reply + arp4::HwType, 1);
        wr16(reply + arp4::ProtoType, EtherType_IPv4);
        reply[arp4::HwLen] = 6; reply[arp4::ProtoLen] = 4;
        wr16(reply + arp4::Op, arp4::OpReply);
        macToBytes(PeerMac, reply + arp4::SenderMac);
        wr32(reply + arp4::SenderIp, PeerIp);
        macToBytes(OurMac, reply + arp4::TargetMac);
        wr32(reply + arp4::TargetIp, OurIp);
        return reply;
    }(), arp4::Size);
    g_cap.clear();

    expectEqU(v.udpSendTo(s, PeerIp, 11451, big, payloadLen), payloadLen, "second send");
    expect(g_cap.frames.size() == 2, "split into two fragments");
    if (g_cap.frames.size() != 2) { return; }

    const u8 *f0 = g_cap.frames[0].payload.data();
    const u8 *f1 = g_cap.frames[1].payload.data();
    expect((rd16(f0 + ip4::FlagsFrag) & ip4::FlagMoreFragments) != 0, "first has MF set");
    expect((rd16(f1 + ip4::FlagsFrag) & ip4::FlagMoreFragments) == 0, "last has MF clear");
    expectEqU(rd16(f0 + ip4::FlagsFrag) & ip4::FragOffsetMask, 0, "first at offset 0");
    expectEqU((rd16(f1 + ip4::FlagsFrag) & ip4::FragOffsetMask) * 8,
              g_cap.frames[0].payload.size() - ip4::MinHeader, "second offset follows first");
    expectEqU(rd16(f0 + ip4::Id), rd16(f1 + ip4::Id), "same id");
    expectEqU(checksum16(f0, ip4::MinHeader), 0, "fragment 0 checksum verifies");
    expectEqU(checksum16(f1, ip4::MinHeader), 0, "fragment 1 checksum verifies");

    /* Stand up a second instance playing the part of the peer and feed it the
     * exact fragments we just produced, untouched -- checksums, addresses and
     * all. If the two halves of the shim agree, the socket on the other side
     * sees the original datagram.  (Copy the frames first: setting up the
     * second instance resets the capture.) */
    const std::vector<Frame> frags = g_cap.frames;

    VNet w;
    w.reset();
    w.setEmit(onEmit, &g_cap);
    w.configure(PeerMac, PeerIp, Mask, 1500);
    const int r = w.udpOpen();
    w.udpBind(r, 0, 11451);

    for (const Frame &f : frags) {
        w.onFrame(OurMac, PeerMac, EtherType_IPv4, f.payload.data(), (unsigned)f.payload.size());
    }

    expect(w.udpReadable(r), "reassembled datagram delivered");
    u8 out[MaxDatagram] = {};
    u32 srcIp = 0; u16 srcPort = 0;
    const int n = w.udpRecvFrom(r, out, sizeof(out), &srcIp, &srcPort);
    expectEqU((unsigned)n, payloadLen, "reassembled length");
    expect(memcmp(out, big, payloadLen) == 0, "reassembled payload matches");
    expectEqU(srcIp, OurIp, "source survives reassembly");
    expectEqU(srcPort, 11451, "source port survives reassembly");
}

static void test_pool_exhaustion()
{
    g_case = "pool exhaustion";
    VNet v; setup(v);

    const int s = v.udpOpen();
    v.udpBind(s, 0, 11451);

    for (int i = 0; i < PoolPackets + 8; ++i) {
        auto pkt = buildUdp(PeerIp, OurIp, 5, 11451, "q", 1);
        v.onFrame(PeerMac, OurMac, EtherType_IPv4, pkt.data(), (unsigned)pkt.size());
    }
    expectEqU(v.stats().dropNoBuffer, 8, "excess dropped, counted");

    int drained = 0;
    u8 buf[8];
    while (v.udpRecvFrom(s, buf, sizeof(buf), nullptr, nullptr) >= 0) { ++drained; }
    expectEqU(drained, PoolPackets, "everything queued comes back out");

    /* And the pool is whole again afterwards. */
    auto pkt = buildUdp(PeerIp, OurIp, 5, 11451, "r", 1);
    v.onFrame(PeerMac, OurMac, EtherType_IPv4, pkt.data(), (unsigned)pkt.size());
    expect(v.udpReadable(s), "pool recycled");
}

static void test_truncation_and_close()
{
    g_case = "truncation and close";
    VNet v; setup(v);

    const int s = v.udpOpen();
    v.udpBind(s, 0, 11451);

    auto pkt = buildUdp(PeerIp, OurIp, 5, 11451, "abcdefgh", 8);
    v.onFrame(PeerMac, OurMac, EtherType_IPv4, pkt.data(), (unsigned)pkt.size());

    u8 small[3] = {};
    expectEqU(v.udpRecvFrom(s, small, sizeof(small), nullptr, nullptr), 3, "truncates to buffer");
    expect(memcmp(small, "abc", 3) == 0, "prefix returned");
    expect(!v.udpReadable(s), "remainder discarded, datagram semantics");

    /* Closing with queued packets must return them to the pool. */
    for (int i = 0; i < 4; ++i) {
        auto q = buildUdp(PeerIp, OurIp, 5, 11451, "q", 1);
        v.onFrame(PeerMac, OurMac, EtherType_IPv4, q.data(), (unsigned)q.size());
    }
    v.udpClose(s);

    const int s2 = v.udpOpen();
    v.udpBind(s2, 0, 11451);
    int got = 0;
    for (int i = 0; i < PoolPackets; ++i) {
        auto q = buildUdp(PeerIp, OurIp, 5, 11451, "q", 1);
        v.onFrame(PeerMac, OurMac, EtherType_IPv4, q.data(), (unsigned)q.size());
    }
    u8 b[8];
    while (v.udpRecvFrom(s2, b, sizeof(b), nullptr, nullptr) >= 0) { ++got; }
    expectEqU(got, PoolPackets, "no buffers leaked by close");
}

static void test_ephemeral_ports()
{
    g_case = "ephemeral ports";
    VNet v; setup(v);

    const int a = v.udpOpen();
    const int b = v.udpOpen();
    expectEqU(v.udpBind(a, 0, 0), 0, "bind port 0");
    expectEqU(v.udpBind(b, 0, 0), 0, "bind port 0 again");
    expect(v.udpLocalPort(a) != 0, "assigned a port");
    expect(v.udpLocalPort(a) != v.udpLocalPort(b), "ports are distinct");
    expect(v.udpLocalPort(a) >= 49152, "in the ephemeral range");
}

static void test_unconfigured_is_inert()
{
    g_case = "unconfigured";
    VNet v;
    v.reset();
    v.setEmit(onEmit, &g_cap);
    g_cap.clear();

    const int s = v.udpOpen();
    v.udpBind(s, 0, 11451);
    expect(v.udpSendTo(s, PeerIp, 11451, "x", 1) < 0, "send fails before ZeroTier assigns an address");
    expectEqU(g_cap.frames.size(), 0, "nothing emitted");

    auto pkt = buildUdp(PeerIp, OurIp, 5, 11451, "x", 1);
    v.onFrame(PeerMac, OurMac, EtherType_IPv4, pkt.data(), (unsigned)pkt.size());
    expect(!v.udpReadable(s), "nothing received");
}

static void test_fuzz()
{
    g_case = "fuzz";
    VNet v; setup(v);

    const int s = v.udpOpen();
    v.udpBind(s, 0, 11451);

    /* Deterministic xorshift so a failure is reproducible. Everything this
     * shim parses arrives from a network, and on the console a wild read is a
     * kernel panic, not a segfault -- so hammer it under the sanitizers. */
    u64 state = 0x243F6A8885A308D3ull;
    auto next = [&state]() {
        state ^= state << 13; state ^= state >> 7; state ^= state << 17;
        return state;
    };

    u8 buf[MaxFrame];
    for (int iter = 0; iter < 200000; ++iter) {
        const unsigned int len = (unsigned int)(next() % (MaxFrame + 1));
        for (unsigned int i = 0; i < len; ++i) { buf[i] = (u8)(next() >> 24); }

        /* Half the time, start from something header-shaped so the parser gets
         * past its first few guards and the deeper paths see garbage too. */
        if ((next() & 1) && len >= ip4::MinHeader) {
            buf[ip4::VerIhl] = 0x45;
            wr32(buf + ip4::Dst, (next() & 1) ? OurIp : Bcast);
            wr16(buf + ip4::Csum, 0);
            wr16(buf + ip4::Csum, checksum16(buf, ip4::MinHeader));
        }

        const u16 ethertype = (next() & 1) ? EtherType_IPv4 : EtherType_ARP;
        v.onFrame(PeerMac, (next() & 1) ? OurMac : MacBroadcast, ethertype, buf, len);

        /* Drain occasionally so the pool cycles rather than simply filling. */
        if ((iter & 0x3F) == 0) {
            u8 out[MaxDatagram];
            while (v.udpRecvFrom(s, out, sizeof(out), nullptr, nullptr) >= 0) { }
        }
    }

    expect(true, "200k malformed frames without a sanitizer trip");
}

int main()
{
    std::printf("vnet tests\n");
    g_case = "process lifetime";
    const uint64_t live[] = {42, 77, 99};
    expect(!ProcessListConfirmsExit(42, live, 3, 4, true), "live owner retained");
    expect(ProcessListConfirmsExit(43, live, 3, 4, true), "exited owner reaped");
    expect(!ProcessListConfirmsExit(43, live, 3, 4, false), "query failure retains owner");
    expect(!ProcessListConfirmsExit(43, live, 3, 3, true), "full/truncated list retains owner");
    expect(!ProcessListConfirmsExit(43, live, -1, 4, true), "invalid count retains owner");
    expect(!ProcessListConfirmsExit(0, live, 3, 4, true), "empty registry entry ignored");
    expect(ProcessListConfirmsExit(43, live, 0, 4, true), "complete empty list permits cleanup");

    test_checksum();
    test_arp_reply();
    test_udp_send_broadcast();
    test_udp_receive_and_learn();
    test_arp_request_when_unknown();
    test_demux();
    test_rejects_bad_input();
    test_icmp_echo();
    test_fragmentation_roundtrip();
    test_pool_exhaustion();
    test_truncation_and_close();
    test_ephemeral_ports();
    test_unconfigured_is_inert();
    test_fuzz();

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
