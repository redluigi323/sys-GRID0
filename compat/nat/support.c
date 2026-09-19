/* Horizon glue for upstream MiniUPnPc/libnatpmp. Only the mapper worker calls
 * these functions. Bound both router-controlled allocations and socket waits. */
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>

extern int ztnx_nat_cancelled(void);
extern uint32_t ztnx_nat_gateway(void);
typedef union { size_t size; max_align_t alignment; } Allocation;
static size_t allocated;
enum { Budget = 64 * 1024, MaxAllocation = 32 * 1024 };
void *ztnx_nat_malloc(size_t size) {
    if (size > MaxAllocation || size > Budget - allocated) return NULL;
    Allocation *p = malloc(sizeof(*p) + size);
    if (!p) return NULL;
    p->size = size; allocated += size;
    return p + 1;
}
void ztnx_nat_free(void *ptr) {
    if (!ptr) return;
    Allocation *p = (Allocation *)ptr - 1;
    allocated -= p->size; free(p);
}
char *ztnx_nat_strdup(const char *str) {
    size_t length = strlen(str) + 1;
    char *p = ztnx_nat_malloc(length);
    if (p) memcpy(p, str, length);
    return p;
}
void *ztnx_nat_calloc(size_t count, size_t size) {
    if (count && size > MaxAllocation / count) return NULL;
    void *p = ztnx_nat_malloc(count * size);
    if (p) memset(p, 0, count * size);
    return p;
}
void *ztnx_nat_realloc(void *ptr, size_t size) {
    if (!ptr) return ztnx_nat_malloc(size);
    if (!size) { ztnx_nat_free(ptr); return NULL; }
    Allocation *p = (Allocation *)ptr - 1;
    size_t old = p->size;
    if (size > MaxAllocation || size > Budget - allocated + old) return NULL;
    p = realloc(p, sizeof(*p) + size);
    if (!p) return NULL;
    p->size = size; allocated = allocated - old + size;
    return p + 1;
}

/* Explicit gateway from NIFM is mandatory; never guess a desktop route. */
int getdefaultgateway(in_addr_t *address) { (void)address; return -1; }

/* The vendored NAT-PMP parser predates packet-length validation. Do not let a
 * truncated datagram make it read uninitialized fields as a public mapping. */
ssize_t ztnx_nat_recvfrom(int fd, void *data, size_t length, int flags,
                         struct sockaddr *address, socklen_t *address_length) {
    ssize_t n = recvfrom(fd, data, length, flags, address, address_length);
    if (n < 0) return n;
    const unsigned char *p = data;
    if (n < 8 || ((!p[2] && !p[3]) &&
        ((p[1] == 128 && n < 12) || ((p[1] == 129 || p[1] == 130) && n < 16)))) {
        errno = EAGAIN;
        return -1;
    }
    return n;
}

static int wait_socket(int fd, short events, int milliseconds) {
    while (milliseconds > 0 && !ztnx_nat_cancelled()) {
        int slice = milliseconds < 100 ? milliseconds : 100;
        struct pollfd p = {fd, events, 0};
        int rc = poll(&p, 1, slice);
        if (rc < 0) { if (errno == EINTR) continue; return -1; }
        if (rc > 0) return (p.revents & events) ? 1 : -1;
        milliseconds -= slice;
    }
    return 0;
}

int connecthostport(const char *host, unsigned short port, unsigned int scope_id) {
    (void)scope_id;
    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET; dest.sin_port = htons(port);
    /* SSDP is untrusted input. Do not fetch arbitrary Internet URLs or DNS
     * names advertised by devices; only our current IPv4 gateway is eligible. */
    if (ztnx_nat_cancelled() || inet_pton(AF_INET, host, &dest.sin_addr) != 1 ||
        dest.sin_addr.s_addr != ztnx_nat_gateway()) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) goto fail;
    int rc = connect(fd, (struct sockaddr *)&dest, sizeof(dest));
    if (rc < 0) {
        if (errno != EINPROGRESS || wait_socket(fd, POLLOUT, 2000) != 1) goto fail;
        int error = 0; socklen_t len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error) goto fail;
    }
    if (fcntl(fd, F_SETFL, flags) < 0) goto fail;
    struct timeval timeout = {0, 500000};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) goto fail;
    return fd;
fail:
    close(fd); return -1;
}

int receivedata(int fd, char *data, int length, int timeout, unsigned int *scope_id) {
    if (scope_id) *scope_id = 0;
    if (wait_socket(fd, POLLIN, timeout > 2000 ? 2000 : timeout) != 1) return -1;
    return recv(fd, data, length, MSG_DONTWAIT);
}
