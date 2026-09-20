#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

void *ztnx_nat_malloc(size_t);
void *ztnx_nat_calloc(size_t, size_t);
void *ztnx_nat_realloc(void *, size_t);
void ztnx_nat_free(void *);
char *ztnx_nat_strdup(const char *);
int connecthostport(const char *, unsigned short, unsigned int);
int receivedata(int, char *, int, int, unsigned int *);
ssize_t ztnx_nat_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
static int cancelled;
int ztnx_nat_cancelled(void) { return cancelled; }
uint32_t ztnx_nat_gateway(void) { return htonl(INADDR_LOOPBACK); }

int main(void) {
    for (int i = 0; i < 100; ++i) {
        void *a = ztnx_nat_malloc(32768), *b = ztnx_nat_malloc(32768);
        assert(a && b && (uintptr_t)a % _Alignof(max_align_t) == 0);
        assert(ztnx_nat_malloc(1) == NULL);
        ztnx_nat_free(a); ztnx_nat_free(b);
    }
    assert(!ztnx_nat_malloc(32769));
    assert(!ztnx_nat_calloc(SIZE_MAX, 8));
    char *p = ztnx_nat_strdup("preserved");
    assert(p && !strcmp(p, "preserved"));
    assert(!ztnx_nat_realloc(p, 32769));
    assert(!strcmp(p, "preserved"));
    p = ztnx_nat_realloc(p, 64);
    assert(p && !strcmp(p, "preserved"));
    ztnx_nat_free(p);
    p = ztnx_nat_calloc(10, 1);
    assert(p);
    for (int i = 0; i < 10; ++i) assert(p[i] == 0);
    ztnx_nat_free(p);
    // Rejected before opening a socket: no DNS or off-router HTTP requests.
    assert(connecthostport("example.com", 80, 0) == -1);
    assert(connecthostport("192.0.2.1", 80, 0) == -1);
    cancelled = 1;
    assert(connecthostport("127.0.0.1", 80, 0) == -1);
    char buffer[8];
    assert(receivedata(-1, buffer, sizeof(buffer), 60000, NULL) == -1);
    cancelled = 0;
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(write(sockets[0], "ok", 2) == 2);
    assert(receivedata(sockets[1], buffer, sizeof(buffer), 1000, NULL) == 2);
    assert(!memcmp(buffer, "ok", 2));
    cancelled = 1;
    assert(receivedata(sockets[1], buffer, sizeof(buffer), 60000, NULL) == -1);
    close(sockets[0]); close(sockets[1]);
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == 0);
    unsigned char response[16] = {0, 129};
    assert(write(sockets[0], response, 2) == 2);
    assert(ztnx_nat_recvfrom(sockets[1], response, sizeof(response), 0, NULL, NULL) == -1);
    assert(write(sockets[0], response, 12) == 12);
    assert(ztnx_nat_recvfrom(sockets[1], response, sizeof(response), 0, NULL, NULL) == -1);
    assert(write(sockets[0], response, 16) == 16);
    assert(ztnx_nat_recvfrom(sockets[1], response, sizeof(response), 0, NULL, NULL) == 16);
    response[1] = 128;
    assert(write(sockets[0], response, 12) == 12);
    assert(ztnx_nat_recvfrom(sockets[1], response, sizeof(response), 0, NULL, NULL) == 12);
    close(sockets[0]); close(sockets[1]);
    puts("NAT allocation, endpoint restriction, receive and cancellation checks passed");
    return 0;
}
