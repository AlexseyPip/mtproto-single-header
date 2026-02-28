/*
 * Simple echo bot example - receives messages and echoes them back
 * Skeleton showing the flow: poll -> parse updates -> send_message
 *
 * Build: gcc -std=c99 -DMTPROTO_IMPLEMENTATION -I.. echo_bot.c -o echo_bot
 */
#define MTPROTO_IMPLEMENTATION
#include "../mtproto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t get_time(void* u) { (void)u; return 0; }
static int get_random(void* u, void* b, size_t n) { (void)u; memset(b, 0, n); return 1; }
static int do_send(void* u, const void* b, size_t n) { (void)u; (void)b; (void)n; return (int)n; }
static int do_recv(void* u, void* b, size_t n) { (void)u; memset(b, 0, n); return 0; }

int main(void) {
    mtproto_callbacks_t cbs = {0};
    cbs.get_time_ms = get_time;
    cbs.random_bytes = get_random;
    cbs.send_data = do_send;
    cbs.recv_data = do_recv;

    mtproto_state_t* state = mtproto_create(&cbs);
    mtproto_session_t* session = mtproto_connect(state, 2, MTPROTO_SERVER_PRODUCTION);
    if (!session) {
        fprintf(stderr, "Connect failed\n");
        return 1;
    }

    printf("Echo bot skeleton - poll and reply loop\n");
    for (int i = 0; i < 3; i++) {
        mtproto_poll(session);
    }

    mtproto_disconnect(session);
    mtproto_destroy(state);
    return 0;
}
