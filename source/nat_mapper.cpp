#include "nat_mapper.hpp"
#include "zt_port.hpp"
#include <stratosphere.hpp>
#include <atomic>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstdlib>
extern "C" {
#include <switch.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ext/libnatpmp/natpmp.h>
#include <ext/miniupnpc/miniupnpc.h>
#include <ext/miniupnpc/upnpcommands.h>
}

namespace {
using namespace ams;
alignas(os::MemoryPageSize) u8 stack[64 * 1024];
os::ThreadType worker;
os::SdkMutex result_lock;
std::atomic<uint64_t> desired{0};
std::atomic<bool> idle{true};
bool started = false; // only node thread accesses this
uint64_t active = 0; // only worker accesses these three
uint32_t gateway = 0;
int64_t deadline = 0;
char description[48];
ztnx::NatEndpoint endpoint;
uint64_t endpoint_generation = 0;
int64_t endpoint_expiry = 0;
int64_t Now() { return armGetSystemTick() / 19200; }
void Sleep(int ms) { os::SleepThread(TimeSpan::FromMilliSeconds(ms)); }
void Publish(ztnx::NatEndpoint value = {}, int64_t expiry = 0) {
    std::scoped_lock lock(result_lock);
    endpoint = value; endpoint_generation = active; endpoint_expiry = expiry;
}
}

extern "C" int ztnx_nat_cancelled() {
    return desired.load(std::memory_order_acquire) != active ||
           ztnx::SleepRequested() || Now() >= deadline;
}
extern "C" uint32_t ztnx_nat_gateway() { return gateway; }

namespace {
bool ReadPmp(natpmp_t &pmp, natpmpresp_t &response, uint16_t type) {
    const int64_t end = Now() + 2200;
    while (!ztnx_nat_cancelled() && Now() < end) {
        int rc = readnatpmpresponseorretry(&pmp, &response);
        if (!rc) return response.type == type;
        if (rc != NATPMP_TRYAGAIN) return false;
        Sleep(50);
    }
    return false;
}

bool MapPmp(uint16_t port, ztnx::NatEndpoint &out, unsigned &lease) {
    natpmp_t pmp{};
    pmp.s = -1;
    const int rc = initnatpmp(&pmp, 1, gateway);
    bool ok = false;
    if (!rc) {
        natpmpresp_t response{};
        if (sendpublicaddressrequest(&pmp) >= 0 &&
            ReadPmp(pmp, response, NATPMP_RESPTYPE_PUBLICADDRESS)) {
            out.address = response.pnu.publicaddress.addr.s_addr;
            if (out.address && sendnewportmappingrequest(&pmp, NATPMP_PROTOCOL_UDP,
                    port, port, 600) >= 0 && ReadPmp(pmp, response, NATPMP_RESPTYPE_UDPPORTMAPPING)) {
                out.port = response.pnu.newportmapping.mappedpublicport;
                lease = response.pnu.newportmapping.lifetime;
                ok = response.pnu.newportmapping.privateport == port && out.port && lease >= 30;
            }
        }
    }
    /* Upstream initnatpmp leaves its socket open on some initialization errors. */
    if (pmp.s >= 0) closenatpmp(&pmp);
    return ok;
}

bool MapUpnp(uint16_t port, uint32_t physical, ztnx::NatEndpoint &out) {
    char local[INET_ADDRSTRLEN]{};
    in_addr address{physical};
    if (!inet_ntop(AF_INET, &address, local, sizeof(local))) return false;
    int error = 0;
    UPNPDev *devices = upnpDiscover(600, local, nullptr, 0, 0, 2, &error);
    if (!devices) return false;
    UPNPUrls urls{};
    IGDdatas data{};
    char lan[64]{};
    const int found = UPNP_GetValidIGD(devices, &urls, &data, lan, sizeof(lan));
    freeUPNPDevlist(devices);
    bool ok = false;
    if (found == 1 && urls.controlURL && !ztnx_nat_cancelled()) {
        char external[64]{};
        in_addr external_address{};
        if (UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, external) == 0 &&
            inet_pton(AF_INET, external, &external_address) == 1 && external_address.s_addr) {
            char internal_port[8];
            std::snprintf(internal_port, sizeof(internal_port), "%u", port);
            for (unsigned attempt = 0; attempt < 4 && !ztnx_nat_cancelled(); ++attempt) {
                const unsigned candidate = 20000 + ((port - 20000u + attempt) % 40000);
                char external_port[8], client[64]{}, assigned[16]{}, desc[80]{}, enabled[16]{}, duration[16]{};
                std::snprintf(external_port, sizeof(external_port), "%u", candidate);
                const int existing = UPNP_GetSpecificPortMappingEntry(urls.controlURL,
                    data.first.servicetype, external_port, "UDP", nullptr,
                    client, assigned, desc, enabled, duration);
                /* Never replace a mapping owned by another application/console.
                 * 714 is the protocol's explicit NoSuchEntryInArray response. */
                if (existing != 714 && (existing != 0 || std::strcmp(client, local) ||
                    std::strcmp(assigned, internal_port) || std::strcmp(desc, description))) continue;
                const int rc = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                    external_port, internal_port, local, description, "UDP", nullptr, "600");
                /* Do not fall back to permanent mappings (725). Finite leases
                 * expire after a power cut or a radio/interface transition. */
                if (!rc) { out = {external_address.s_addr, static_cast<uint16_t>(candidate)}; ok = true; break; }
            }
        }
    }
    FreeUPNPUrls(&urls);
    return ok;
}

void Main(void *) {
    bool nifm_ready = false;
    uint32_t previous_ip = 0, previous_gateway = 0;
    int64_t retry_at = 0;
    uint64_t previous_generation = 0;
    for (;;) {
        idle.store(true, std::memory_order_release);
        Sleep(100);
        const uint64_t request = desired.load(std::memory_order_acquire);
        if (!(request & 0xffff) || ztnx::SleepRequested()) continue;
        idle.store(false, std::memory_order_release);
        active = request;
        deadline = Now() + 15000;
        if (ztnx_nat_cancelled()) continue;
        if (!nifm_ready) nifm_ready = R_SUCCEEDED(nifmInitialize(NifmServiceType_User));
        uint32_t ip = 0, mask = 0, gw = 0, dns1 = 0, dns2 = 0;
        if (!nifm_ready || R_FAILED(nifmGetCurrentIpConfigInfo(&ip, &mask, &gw, &dns1, &dns2)) || !ip || !gw) {
            Publish(); previous_ip = previous_gateway = 0;
            Sleep(900);
            continue;
        }
        gateway = gw;
        if (ip != previous_ip || gw != previous_gateway || active != previous_generation) {
            Publish(); retry_at = 0;
            previous_ip = ip; previous_gateway = gw; previous_generation = active;
        }
        if (Now() >= retry_at && !ztnx_nat_cancelled()) {
            ztnx::NatEndpoint mapped{};
            unsigned lease = 600;
            const char *method = "NAT-PMP";
            bool ok = MapPmp(static_cast<uint16_t>(active), mapped, lease);
            if (!ok && !ztnx_nat_cancelled()) {
                method = "UPnP";
                ok = MapUpnp(static_cast<uint16_t>(active), ip, mapped);
            }
            if (!ztnx_nat_cancelled()) {
                if (ok) {
                    lease = std::min(lease, 600u);
                    Publish(mapped, Now() + lease * 1000);
                    retry_at = Now() + lease * 500;
                    ztnx::Event("NAT %s mapped UDP %u -> %u lease %us", method,
                                unsigned(active & 0xffff), unsigned(mapped.port), lease);
                } else {
                    /* Keep a previous lease until expiry during a transient
                     * renewal failure; GetNatEndpoint rejects expired leases. */
                    retry_at = Now() + 60000;
                    ztnx::Event("NAT mapping unavailable; retaining normal ZeroTier traversal");
                }
            } else if (desired.load(std::memory_order_acquire) == active) {
                retry_at = Now() + 60000;
            }
        }
        // Quiescence is checked at most 100 ms after all router calls finish.
        idle.store(true, std::memory_order_release);
        for (int i = 0; i < 9 && !ztnx_nat_cancelled(); ++i) Sleep(100);
    }
}
}

namespace ztnx {
bool StartNatMapper(uint64_t node_id) {
    if (started) return true;
    if (!ConfigFlag("port_mapping", true)) return false;
    std::snprintf(description, sizeof(description), "sys-zerotier-%010llx", (unsigned long long)node_id);
    const auto rc = ams::os::CreateThread(&worker, Main, nullptr, stack, sizeof(stack),
                                        ams::os::DefaultThreadPriority + 5);
    if (R_FAILED(rc)) { Event("NAT worker unavailable rc %x", rc.GetValue()); return false; }
    started = true;
    ams::os::StartThread(&worker);
    return true;
}
void ConfigureNatMapper(uint16_t port) {
    const uint64_t old = desired.load(std::memory_order_relaxed);
    if (uint16_t(old) != port) desired.store(((old >> 16) + 1) << 16 | port, std::memory_order_release);
}
NatEndpoint GetNatEndpoint() {
    std::scoped_lock lock(result_lock);
    if (endpoint_generation != desired.load(std::memory_order_acquire) || Now() >= endpoint_expiry) return {};
    return endpoint;
}
bool QuiesceNatMapper() {
    ConfigureNatMapper(0);
    const int64_t until = Now() + 2000;
    while (started && !idle.load(std::memory_order_acquire) && Now() < until) Sleep(10);
    return !started || idle.load(std::memory_order_acquire);
}
}
