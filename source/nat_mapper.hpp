#pragma once
#include <cstdint>

namespace ztnx {
struct NatEndpoint {
    uint32_t address = 0; // network byte order
    uint16_t port = 0;    // host byte order
};
/* One low-priority worker, never calls the ZeroTier core. Configuration and
 * snapshots are node-thread-only; a generation rejects obsolete results. */
bool StartNatMapper(uint64_t node_id);
void ConfigureNatMapper(uint16_t local_port);
NatEndpoint GetNatEndpoint();
bool QuiesceNatMapper();
}
