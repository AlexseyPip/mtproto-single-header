/*
 * Minimal MTProto console client example
 * Demonstrates initialization, callbacks, and basic flow
 *
 * Build: gcc -std=c99 -DMTPROTO_IMPLEMENTATION -I.. minimal_client.c -o minimal_client
 * Note: Requires platform-specific socket implementation for real connectivity
 */
#define MTPROTO_IMPLEMENTATION
#include "../mtproto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

static int g_sock = -1;

static uint64_t get_time_ms(void* ud) {
    (void)ud;
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

static int random_bytes(void* ud, void* buf, size_t count) {
    (void)ud;
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) {
#ifdef _WIN32
        /* Use rand() as fallback - NOT cryptographically secure */
        for (size_t i = 0; i < count; i++) ((uint8_t*)buf)[i] = (uint8_t)rand();
        return 1;
#else
        return 0;
#endif
    }
    size_t n = fread(buf, 1, count, f);
    fclose(f);
    return (n == count) ? 1 : 0;
}

static int send_data(void* ud, const void* buf, size_t count) {
    (void)ud;
    if (g_sock < 0) return -1;
#ifdef _WIN32
    int r = send(g_sock, (const char*)buf, (int)count, 0);
#else
    ssize_t r = send(g_sock, buf, count, 0);
#endif
    return (r > 0) ? (int)r : -1;
}

static int recv_data(void* ud, void* buf, size_t max_count) {
    (void)ud;
    if (g_sock < 0) return -1;
#ifdef _WIN32
    int r = recv(g_sock, (char*)buf, (int)max_count, 0);
#else
    ssize_t r = recv(g_sock, buf, max_count, 0);
#endif
    return (r > 0) ? (int)r : ((r == 0) ? 0 : -1);
}

static void log_msg(void* ud, int level, const char* msg) {
    (void)ud;
    const char* lvl = level == 0 ? "ERR" : (level == 1 ? "INF" : "DBG");
    fprintf(stderr, "[%s] %s\n", lvl, msg);
}

int main(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    mtproto_callbacks_t cbs = {0};
    cbs.get_time_ms = get_time_ms;
    cbs.random_bytes = random_bytes;
    cbs.send_data = send_data;
    cbs.recv_data = recv_data;
    cbs.log = log_msg;
    cbs.userdata = NULL;

    mtproto_state_t* state = mtproto_create(&cbs);
    if (!state) {
        fprintf(stderr, "Failed to create state: %s\n", mtproto_get_last_error());
        return 1;
    }

    mtproto_session_t* session = mtproto_connect(state, 2, MTPROTO_SERVER_PRODUCTION);
    if (!session) {
        fprintf(stderr, "Failed to connect\n");
        mtproto_destroy(state);
        return 1;
    }

    /* Note: Actual TCP connection to Telegram DC must be established
       and g_sock set before send/recv will work. This example shows
       the callback setup. For full connectivity, add socket connect. */

    printf("MTProto minimal client initialized\n");
    printf("Session created. Use mtproto_req_pq(), mtproto_send_phone(), etc.\n");

    mtproto_disconnect(session);
    mtproto_destroy(state);

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
