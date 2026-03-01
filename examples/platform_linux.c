/*
 * Platform integration example for Linux
 * Uses POSIX sockets, /dev/urandom, clock_gettime
 */
#define MTPROTO_IMPLEMENTATION
#define _POSIX_C_SOURCE 199309L
#include "../mtproto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

static int g_fd = -1;

static uint64_t linux_get_time_ms(void* ud) {
    (void)ud;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int linux_random_bytes(void* ud, void* buf, size_t count) {
    (void)ud;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, count);
    close(fd);
    return (n == (ssize_t)count) ? 1 : 0;
}

static int linux_send(void* ud, const void* buf, size_t count) {
    (void)ud;
    if (g_fd < 0) return -1;
    ssize_t r = send(g_fd, buf, count, MSG_NOSIGNAL);
    return (r > 0) ? (int)r : -1;
}

static int linux_recv(void* ud, void* buf, size_t max_count) {
    (void)ud;
    if (g_fd < 0) return -1;
    ssize_t r = recv(g_fd, buf, max_count, 0);
    return (r > 0) ? (int)r : ((r == 0) ? 0 : -1);
}

/* Automatic DC connection - TCP connect using mtproto_get_dc_address */
static int linux_connect_to_dc(void* ud, int dc_id, int server) {
    char host[64];
    int port;
    struct sockaddr_in addr;
    (void)ud;
    (void)server;
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
    if (!mtproto_get_dc_address(dc_id, server, host, sizeof(host), &port)) return 0;
    g_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_fd < 0) return 0;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) { close(g_fd); g_fd = -1; return 0; }
    if (connect(g_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(g_fd); g_fd = -1; return 0; }
    return 1;
}

void mtproto_linux_example(void) {
    mtproto_callbacks_t cbs = {
        .get_time_ms = linux_get_time_ms,
        .random_bytes = linux_random_bytes,
        .send_data = linux_send,
        .recv_data = linux_recv,
        .log = NULL,
        .auth_callback = NULL,
        .connect_to_dc = linux_connect_to_dc,
        .userdata = NULL
    };
    mtproto_state_t* state = mtproto_create(&cbs);
    mtproto_session_t* session = NULL;
    if (state) {
        session = mtproto_connect(state, 2, MTPROTO_SERVER_PRODUCTION);
        if (session) {
            /* mtproto_do_auth_handshake, send_phone, etc. */
            mtproto_disconnect(session);
        }
        mtproto_destroy(state);
    }
}
