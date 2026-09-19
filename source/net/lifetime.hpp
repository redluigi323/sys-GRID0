#pragma once
#include <cstddef>
#include <cstdint>

namespace ztnx::net {
/* Absence only proves death when the kernel query succeeded and the list is
 * complete. Callers must snapshot candidate PIDs before querying this list. */
inline bool ProcessListConfirmsExit(uint64_t pid, const uint64_t *live,
                                    int count, size_t capacity, bool success) {
    if (!pid || !success || count < 0 || size_t(count) >= capacity) return false;
    for (int i = 0; i < count; ++i) if (live[i] == pid) return false;
    return true;
}
}
