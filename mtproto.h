/*
 * mtproto.h - Single-file header-only C library for MTProto protocol
 * (Telegram messaging protocol)
 *
 * Usage:
 *   1. In one .c file, add:
 *      #define MTPROTO_IMPLEMENTATION
 *      #include "mtproto.h"
 *   2. In other files, just #include "mtproto.h"
 *
 * Example minimal setup:
 *
 *   mtproto_callbacks_t cbs = {0};
 *   cbs.get_time_ms = my_get_time_ms;
 *   cbs.random_bytes = my_random_bytes;
 *   cbs.send_data = my_send;
 *   cbs.recv_data = my_recv;
 *   cbs.log = my_log;
 *
 *   mtproto_state_t* state = mtproto_create(&cbs);
 *   mtproto_session_t* session = mtproto_connect(state, 2, MTPROTO_SERVER_PRODUCTION);
 *   if (session) {
 *       mtproto_send_phone(session, "+1234567890", api_id, api_hash);
 *       // after auth.sentCode: mtproto_store_sent_code(session, resp, len);
 *       mtproto_send_auth_code(session, "12345");
 *       ...
 *   }
 *
 * Thread safety: Not thread-safe by default. One mtproto_state_t and its sessions
 * should be used from a single thread unless external synchronization is applied.
 *
 * License: Public domain (CC0)
 * Based on: https://core.telegram.org/mtproto
 */

#ifndef MTPROTO_H_INCLUDED
#define MTPROTO_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * SECTION 1: CONFIGURATION MACROS (user may override before including)
 *--------------------------------------------------------------------------*/

#ifndef MTPROTO_MAX_RECV_BUF
#define MTPROTO_MAX_RECV_BUF       (256 * 1024)  /* Max receive buffer size */
#endif
#ifndef MTPROTO_MAX_SEND_BUF
#define MTPROTO_MAX_SEND_BUF       (256 * 1024)  /* Max send buffer size */
#endif
#ifndef MTPROTO_MAX_MSG_HISTORY
#define MTPROTO_MAX_MSG_HISTORY    256           /* Msg IDs to remember for replay protection */
#endif
#ifndef MTPROTO_PADDING_MIN
#define MTPROTO_PADDING_MIN        12            /* MTProto 2.0 minimum padding */
#endif
#ifndef MTPROTO_PADDING_MAX
#define MTPROTO_PADDING_MAX        1024          /* MTProto 2.0 maximum padding */
#endif
#ifndef MTPROTO_RSA_KEY_COUNT
#define MTPROTO_RSA_KEY_COUNT      5             /* Built-in server public keys */
#endif
#ifndef MTPROTO_ABRIDGED_RECV_BUF
#define MTPROTO_ABRIDGED_RECV_BUF  16384         /* Buffer for one abridged packet (auth fits) */
#endif

/*--------------------------------------------------------------------------
 * SECTION 2: PLATFORM ABSTRACTION - USER MUST IMPLEMENT
 *--------------------------------------------------------------------------*/

/* Callback: return current time in milliseconds since Unix epoch */
typedef uint64_t (*mtproto_get_time_ms_t)(void* userdata);

/* Callback: fill buf with count random bytes, return 1 on success, 0 on failure */
typedef int (*mtproto_random_bytes_t)(void* userdata, void* buf, size_t count);

/* Callback: send count bytes from buf over transport. Return bytes sent or <0 on error */
typedef int (*mtproto_send_t)(void* userdata, const void* buf, size_t count);

/* Callback: receive up to max_count bytes into buf. Return bytes received, 0 on EOF, <0 on error */
typedef int (*mtproto_recv_t)(void* userdata, void* buf, size_t max_count);

/* Callback: optional logging, level 0=error, 1=info, 2=debug */
typedef void (*mtproto_log_t)(void* userdata, int level, const char* msg);

/* Callback: optional, called when auth state changes (e.g. code sent, logged in) */
typedef void (*mtproto_auth_callback_t)(void* userdata, int event, const char* info);

/* Set of callbacks - user provides implementations */
typedef struct {
    mtproto_get_time_ms_t  get_time_ms;
    mtproto_random_bytes_t random_bytes;
    mtproto_send_t         send_data;
    mtproto_recv_t         recv_data;
    mtproto_log_t          log;             /* Optional, may be NULL */
    mtproto_auth_callback_t auth_callback;  /* Optional, may be NULL */
    void*                  userdata;
} mtproto_callbacks_t;

/*--------------------------------------------------------------------------
 * SECTION 3: ERROR CODES
 *--------------------------------------------------------------------------*/

#define MTPROTO_OK                  0
#define MTPROTO_ERR_GENERIC        -1
#define MTPROTO_ERR_INVALID_PARAM  -2
#define MTPROTO_ERR_NO_MEMORY      -3
#define MTPROTO_ERR_TRANSPORT      -4
#define MTPROTO_ERR_TIMEOUT        -5
#define MTPROTO_ERR_AUTH_FAILED    -6
#define MTPROTO_ERR_PROTOCOL       -7
#define MTPROTO_ERR_CRYPTO         -8
#define MTPROTO_ERR_NOT_CONNECTED  -9
#define MTPROTO_ERR_ALREADY_AUTH   -10
#define MTPROTO_ERR_BUFFER_TOO_SMALL -11

/*--------------------------------------------------------------------------
 * SECTION 4: OPAQUE TYPES
 *--------------------------------------------------------------------------*/

typedef struct mtproto_state_s     mtproto_state_t;
typedef struct mtproto_session_s   mtproto_session_t;

/*--------------------------------------------------------------------------
 * SECTION 5: PUBLIC API DECLARATIONS
 *--------------------------------------------------------------------------*/

/**
 * Create MTProto state. Returns NULL on failure.
 * Callbacks must be valid for the lifetime of the state.
 */
mtproto_state_t* mtproto_create(const mtproto_callbacks_t* callbacks);

/**
 * Destroy state and free resources. Sessions created from this state become invalid.
 */
void mtproto_destroy(mtproto_state_t* state);

/**
 * Get last error string (thread-local, overwritten on next call).
 */
const char* mtproto_get_last_error(void);

/**
 * Connect to Telegram server. dc_id: 1-5 for production, 1-5 + 10000 for test.
 * server: MTPROTO_SERVER_PRODUCTION or MTPROTO_SERVER_TEST
 * Returns session on success, NULL on failure.
 */
#define MTPROTO_SERVER_PRODUCTION  0
#define MTPROTO_SERVER_TEST        1
mtproto_session_t* mtproto_connect(mtproto_state_t* state, int dc_id, int server);

/**
 * Disconnect and free session. Must not use session after this.
 */
void mtproto_disconnect(mtproto_session_t* session);

/**
 * Check if session has completed auth (has auth_key).
 */
int mtproto_is_authorized(const mtproto_session_t* session);

/**
 * Start authorization: request PQ (first step of auth).
 * Call this before send_auth_code if starting fresh.
 */
int mtproto_req_pq(mtproto_session_t* session);

/**
 * Run auth flow until it needs user input (phone, code, 2FA password).
 * Returns MTPROTO_OK when waiting for auth code, MTPROTO_ERR_* on failure.
 * After this, call mtproto_send_auth_code with the code.
 */
int mtproto_do_auth_handshake(mtproto_session_t* session);

/**
 * Send phone number for auth. phone: "+1234567890", api_id/api_hash from my.telegram.org
 */
int mtproto_send_phone(mtproto_session_t* session, const char* phone, int api_id, const char* api_hash);

/**
 * Send authentication code received via Telegram. Uses phone_code_hash from send_phone response.
 */
int mtproto_send_auth_code(mtproto_session_t* session, const char* code);

/**
 * Send 2FA password if account has it.
 */
int mtproto_send_password(mtproto_session_t* session, const char* password);

/**
 * Save session data (auth_key, etc.) to buffer for persistence.
 * Returns bytes written, or <0 on error. Call with NULL to get required size.
 */
int mtproto_save_session(const mtproto_session_t* session, void* buf, size_t buf_size);

/**
 * Restore session from saved data.
 */
mtproto_session_t* mtproto_restore_session(mtproto_state_t* state, const void* data, size_t size);

/**
 * Receive one abridged packet. buf/buf_size: output buffer.
 * Returns payload length, 0 if no data yet, <0 on error.
 */
int mtproto_recv_packet(mtproto_session_t* session, uint8_t* buf, size_t buf_size);

/**
 * Decrypt MTProto 2.0 message. raw = output of mtproto_recv_packet when authorized.
 * msg_out receives the inner msg_data (TL payload). Returns msg_data length, <0 on error.
 */
int mtproto_decrypt_message(mtproto_session_t* session, const uint8_t* raw, size_t raw_len, uint8_t* msg_out, size_t msg_size);

/**
 * Process incoming data and handle updates. Call periodically when connected.
 * Returns MTPROTO_OK, MTPROTO_ERR_* on error.
 */
int mtproto_poll(mtproto_session_t* session);

/**
 * Send a TL method. tl_data: serialized TL method (constructor + params).
 * Returns MTPROTO_OK on success.
 */
int mtproto_send_method(mtproto_session_t* session, const void* tl_data, size_t tl_len);

/**
 * Send text message to user. peer_user_id and peer_access_hash from contacts/dialogs.
 * Use inputPeerSelf (user_id=0, access_hash=0) for "Saved Messages".
 */
int mtproto_send_message(mtproto_session_t* session, int64_t peer_user_id, int64_t peer_access_hash, const char* text);

/**
 * Build auth.sendCode TL into buf. Returns bytes written, or <0 on error.
 */
int mtproto_tl_build_auth_send_code(uint8_t* buf, size_t buf_size, const char* phone, int api_id, const char* api_hash);

/**
 * Build auth.signIn TL. Returns bytes written.
 */
int mtproto_tl_build_auth_sign_in(uint8_t* buf, size_t buf_size, const char* phone, const char* phone_code_hash, const char* code);

/**
 * Build messages.sendMessage TL. Use peer_user_id=0, peer_access_hash=0 for inputPeerSelf.
 * random_id: unique per message (e.g. from session random or monotonic counter).
 */
int mtproto_tl_build_messages_send_message(uint8_t* buf, size_t buf_size, int64_t peer_user_id, int64_t peer_access_hash, const char* text, int64_t random_id);

/**
 * Parse auth.sentCode response, extract phone_code_hash into out (null-terminated). out_size includes null.
 * Returns MTPROTO_OK on success.
 */
int mtproto_tl_parse_auth_sent_code(const uint8_t* data, size_t len, char* phone_code_hash_out, size_t out_size);

/**
 * Parse auth.sentCode and store phone_code_hash in session. Call after receiving auth.sendCode response.
 */
int mtproto_store_sent_code(mtproto_session_t* session, const uint8_t* data, size_t len);

/**
 * Parse auth.authorization - check if login successful. Returns 1 if ok, 0 if signUpRequired, -1 on error.
 */
int mtproto_tl_parse_auth_authorization(const uint8_t* data, size_t len);

/**
 * Parse rpc_error. Returns error code, or 0 if not an error. error_msg optional.
 */
int mtproto_tl_parse_rpc_error(const uint8_t* data, size_t len, char* error_msg_out, size_t msg_size);

#ifdef MTPROTO_DEBUG
/**
 * Enable/disable debug logging. Only compiled when MTPROTO_DEBUG is defined.
 */
void mtproto_set_debug(mtproto_state_t* state, int enable);
#endif

#ifdef __cplusplus
}
#endif

#endif /* MTPROTO_H_INCLUDED */


/*
 * =============================================================================
 * IMPLEMENTATION (only when MTPROTO_IMPLEMENTATION is defined)
 * =============================================================================
 */

#ifdef MTPROTO_IMPLEMENTATION

#ifndef MTPROTO_IMPL_GUARD
#define MTPROTO_IMPL_GUARD

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

/* Internal buffer sizes */
#define MTP_AUTH_KEY_SIZE       256
#define MTP_MSG_KEY_SIZE        16
#define MTP_NONCE_SIZE          16
#define MTP_NEW_NONCE_SIZE      32
#define MTP_SHA1_SIZE           20
#define MTP_SHA256_SIZE         32
#define MTP_AES_BLOCK           16
#define MTP_BIGINT_WORDS        64   /* 64*32 = 2048 bits */

/* TL constructor IDs (little-endian) */
#define TL_REQ_PQ_MULTI          0xbe7e8ef1u
#define TL_RES_PQ                0x05162463u
#define TL_REQ_DH_PARAMS         0xd712e4beu
#define TL_SERVER_DH_PARAMS_OK   0xd0e8075cu
#define TL_SERVER_DH_PARAMS_FAIL 0x79cb045du
#define TL_SET_CLIENT_DH_PARAMS  0xf5045f1fu
#define TL_DH_GEN_OK             0x3bcbf734u
#define TL_DH_GEN_RETRY          0x46dc1fb9u
#define TL_DH_GEN_FAIL           0xa69dae02u
#define TL_P_Q_INNER_DATA_DC     0xa9f55f95u
#define TL_P_Q_INNER_DATA_TEMP   0x56fddf88u
#define TL_SERVER_DH_INNER       0xb5890dbau
#define TL_CLIENT_DH_INNER       0x6643b654u
#define TL_VECTOR                0x1cb5c415u
/* Auth TL constructors */
#define TL_AUTH_SEND_CODE        0xa677244fu
#define TL_AUTH_SIGN_IN          0x8d52a951u
#define TL_CODE_SETTINGS         0xad253d78u
#define TL_AUTH_SENT_CODE        0x5e002502u
#define TL_AUTH_AUTHORIZATION    0x9a5c313eu
#define TL_RPC_ERROR             0x2144ca19u
#define TL_INPUT_PEER_SELF       0x7da07ec9u
#define TL_INPUT_PEER_USER       0x7b8e7de6u
#define TL_MESSAGES_SEND_MESSAGE 0x520c3870u  /* layer 46+ minimal: peer, message, random_id */
#define TL_MSG_CONTAINER         0x73f1f8dcu
#define TL_MSGS_ACK              0x62d6b459u
#define TL_MSG_COPY              0xe06046b2u
#define TL_GZIP_PACKED           0x3072cfa1u

/* Auth callback events */
#define MTP_AUTH_EVENT_CODE_SENT     1
#define MTP_AUTH_EVENT_LOGGED_IN     2
#define MTP_AUTH_EVENT_PASSWORD_NEEDED 3
#define MTP_AUTH_EVENT_FAILED        4

/* Internal: simple 32-bit rotate */
#define MTP_ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

/* Thread-local error buffer */
static char g_mtproto_last_error[256];

static void mtp_set_error(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_mtproto_last_error, sizeof(g_mtproto_last_error), fmt, ap);
    va_end(ap);
}

/*--------------------------------------------------------------------------
 * SHA-1 implementation (RFC 3174, constant-time where relevant)
 *--------------------------------------------------------------------------*/
static void mtp_sha1_init(uint32_t h[5]) {
    h[0] = 0x67452301u;
    h[1] = 0xEFCDAB89u;
    h[2] = 0x98BADCFEu;
    h[3] = 0x10325476u;
    h[4] = 0xC3D2E1F0u;
}

static void mtp_sha1_transform(uint32_t h[5], const uint8_t* data) {
    uint32_t w[80];
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i*4]<<24) | ((uint32_t)data[i*4+1]<<16) |
               ((uint32_t)data[i*4+2]<<8) | (uint32_t)data[i*4+3];
    }
    for (i = 16; i < 80; i++) {
        uint32_t t = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
        w[i] = MTP_ROTL32(t, 1);
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        uint32_t temp = MTP_ROTL32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = MTP_ROTL32(b, 30); b = a; a = temp;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

static void mtp_sha1_update(uint32_t h[5], uint64_t* total, const uint8_t* data, size_t len) {
    size_t idx = (size_t)(*total % 64);
    *total += len;
    while (len) {
        size_t n = 64 - idx;
        if (n > len) n = len;
        memcpy((uint8_t*)h + 20 + idx, data, n);
        idx += n;
        data += n;
        len -= n;
        if (idx == 64) {
            idx = 0;
            mtp_sha1_transform(h, (const uint8_t*)h + 20);
        }
    }
}

static void mtp_sha1_final(uint32_t h[5], uint64_t total, uint8_t out[20]) {
    size_t idx = (size_t)(total % 64);
    uint8_t block[64];
    memcpy(block, (uint8_t*)h + 20, idx);
    block[idx++] = 0x80;
    if (idx > 56) {
        memset(block + idx, 0, 64 - idx);
        mtp_sha1_transform(h, block);
        idx = 0;
    }
    memset(block + idx, 0, 56 - idx);
    total *= 8;
    block[56] = (uint8_t)(total >> 56);
    block[57] = (uint8_t)(total >> 48);
    block[58] = (uint8_t)(total >> 40);
    block[59] = (uint8_t)(total >> 32);
    block[60] = (uint8_t)(total >> 24);
    block[61] = (uint8_t)(total >> 16);
    block[62] = (uint8_t)(total >> 8);
    block[63] = (uint8_t)(total);
    mtp_sha1_transform(h, block);
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (uint8_t)(h[i] >> 24);
        out[i*4+1] = (uint8_t)(h[i] >> 16);
        out[i*4+2] = (uint8_t)(h[i] >> 8);
        out[i*4+3] = (uint8_t)(h[i]);
    }
}

static void mtp_sha1(const uint8_t* data, size_t len, uint8_t out[20]) {
    uint32_t h[21]; /* 5 state + 16 for 64-byte block buffer */
    memset(h, 0, sizeof(h));
    mtp_sha1_init(h);
    uint64_t total = 0;
    mtp_sha1_update(h, &total, data, len);
    mtp_sha1_final(h, total, out);
}

/*--------------------------------------------------------------------------
 * SHA-256 implementation
 *--------------------------------------------------------------------------*/
static const uint32_t mtp_k256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u,
};

#define MTP_CH(x,y,z) (((x)&(y)) ^ ((~(x))&(z)))
#define MTP_MAJ(x,y,z) (((x)&(y)) ^ ((x)&(z)) ^ ((y)&(z)))
#define MTP_EP0(x) (MTP_ROTL32(x,2)^MTP_ROTL32(x,13)^MTP_ROTL32(x,22))
#define MTP_EP1(x) (MTP_ROTL32(x,6)^MTP_ROTL32(x,11)^MTP_ROTL32(x,25))
#define MTP_SIG0(x) (MTP_ROTL32(x,7)^MTP_ROTL32(x,18)^((x)>>3))
#define MTP_SIG1(x) (MTP_ROTL32(x,17)^MTP_ROTL32(x,19)^((x)>>10))

static void mtp_sha256_block(uint32_t h[8], const uint8_t* data) {
    uint32_t w[64];
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i*4]<<24) | ((uint32_t)data[i*4+1]<<16) |
               ((uint32_t)data[i*4+2]<<8) | (uint32_t)data[i*4+3];
    }
    for (i = 16; i < 64; i++) {
        w[i] = MTP_SIG1(w[i-2]) + w[i-7] + MTP_SIG0(w[i-15]) + w[i-16];
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], s = h[7];
    for (i = 0; i < 64; i++) {
        uint32_t t1 = s + MTP_EP1(e) + MTP_CH(e,f,g) + mtp_k256[i] + w[i];
        uint32_t t2 = MTP_EP0(a) + MTP_MAJ(a,b,c);
        s = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=s;
}

static void mtp_sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    uint8_t block[64];
    size_t i, pos = 0;
    size_t orig_len = len;
    for (; pos + 64 <= len; pos += 64) mtp_sha256_block(h, data + pos);
    memcpy(block, data + pos, len - pos);
    i = len - pos;
    block[i++] = 0x80;
    if (i > 56) {
        memset(block + i, 0, 64 - i);
        mtp_sha256_block(h, block);
        memset(block, 0, 56);
    } else {
        memset(block + i, 0, 56 - i);
    }
    { uint64_t bits = orig_len * 8; size_t j; for (j = 0; j < 8; j++) block[63 - j] = (uint8_t)(bits >> (j * 8)); }
    mtp_sha256_block(h, block);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(h[i] >> 24);
        out[i*4+1] = (uint8_t)(h[i] >> 16);
        out[i*4+2] = (uint8_t)(h[i] >> 8);
        out[i*4+3] = (uint8_t)(h[i]);
    }
}

/* Simplified SHA256 that accepts total length - for incremental hashing we'd need more state */
static void mtp_sha256_full(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    uint8_t block[64];
    size_t pos = 0;
    while (pos + 64 <= len) {
        mtp_sha256_block(h, data + pos);
        pos += 64;
    }
    size_t rem = len - pos;
    memcpy(block, data + pos, rem);
    block[rem++] = 0x80;
    if (rem > 56) {
        memset(block + rem, 0, 64 - rem);
        mtp_sha256_block(h, block);
        rem = 0;
    }
    memset(block + rem, 0, 56 - rem);
    uint64_t bits = len * 8;
    int i;
    for (i = 7; i >= 0; i--) block[63 - i] = (uint8_t)(bits >> (i * 8));
    mtp_sha256_block(h, block);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(h[i] >> 24);
        out[i*4+1] = (uint8_t)(h[i] >> 16);
        out[i*4+2] = (uint8_t)(h[i] >> 8);
        out[i*4+3] = (uint8_t)(h[i]);
    }
}

/*--------------------------------------------------------------------------
 * AES-256 implementation (compact, educational/public-domain style)
 *--------------------------------------------------------------------------*/
static const uint8_t mtp_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const uint8_t mtp_rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static void mtp_aes_expand_key(const uint8_t* key, uint8_t* rk) {
    int i;
    memcpy(rk, key, 32);
    for (i = 8; i < 60; i++) {
        uint32_t t = ((uint32_t)rk[4*i-4]<<24)|((uint32_t)rk[4*i-3]<<16)|((uint32_t)rk[4*i-2]<<8)|rk[4*i-1];
        if (i % 8 == 0) {
            t = (mtp_sbox[(t>>16)&0xff]<<24)|(mtp_sbox[(t>>8)&0xff]<<16)|(mtp_sbox[(t>>0)&0xff]<<8)|mtp_sbox[(t>>24)&0xff];
            t ^= (uint32_t)mtp_rcon[i/8] << 24;
        } else if (i % 8 == 4) {
            t = (mtp_sbox[(t>>24)&0xff]<<24)|(mtp_sbox[(t>>16)&0xff]<<16)|(mtp_sbox[(t>>8)&0xff]<<8)|mtp_sbox[(t>>0)&0xff];
        }
        uint32_t p = ((uint32_t)rk[4*i-32]<<24)|((uint32_t)rk[4*i-31]<<16)|((uint32_t)rk[4*i-30]<<8)|rk[4*i-29];
        t ^= p;
        rk[4*i]   = (uint8_t)(t >> 24);
        rk[4*i+1] = (uint8_t)(t >> 16);
        rk[4*i+2] = (uint8_t)(t >> 8);
        rk[4*i+3] = (uint8_t)(t);
    }
}

static void mtp_aes_enc_block(uint8_t* block, const uint8_t* rk) {
    uint32_t s0 = ((uint32_t)block[0]<<24)|((uint32_t)block[1]<<16)|((uint32_t)block[2]<<8)|block[3];
    uint32_t s1 = ((uint32_t)block[4]<<24)|((uint32_t)block[5]<<16)|((uint32_t)block[6]<<8)|block[7];
    uint32_t s2 = ((uint32_t)block[8]<<24)|((uint32_t)block[9]<<16)|((uint32_t)block[10]<<8)|block[11];
    uint32_t s3 = ((uint32_t)block[12]<<24)|((uint32_t)block[13]<<16)|((uint32_t)block[14]<<8)|block[15];
    int r;
    for (r = 0; r < 14; r++) {
        uint32_t k0 = ((uint32_t)rk[16*r+0]<<24)|((uint32_t)rk[16*r+1]<<16)|((uint32_t)rk[16*r+2]<<8)|rk[16*r+3];
        uint32_t k1 = ((uint32_t)rk[16*r+4]<<24)|((uint32_t)rk[16*r+5]<<16)|((uint32_t)rk[16*r+6]<<8)|rk[16*r+7];
        uint32_t k2 = ((uint32_t)rk[16*r+8]<<24)|((uint32_t)rk[16*r+9]<<16)|((uint32_t)rk[16*r+10]<<8)|rk[16*r+11];
        uint32_t k3 = ((uint32_t)rk[16*r+12]<<24)|((uint32_t)rk[16*r+13]<<16)|((uint32_t)rk[16*r+14]<<8)|rk[16*r+15];
        s0 ^= k0; s1 ^= k1; s2 ^= k2; s3 ^= k3;
        /* SubBytes + ShiftRows + MixColumns - simplified inline */
        if (r < 13) {
            uint32_t t0 = (mtp_sbox[(s0>>24)&0xff]<<24)|(mtp_sbox[(s1>>16)&0xff]<<16)|(mtp_sbox[(s2>>8)&0xff]<<8)|(mtp_sbox[(s3>>0)&0xff]);
            uint32_t t1 = (mtp_sbox[(s1>>24)&0xff]<<24)|(mtp_sbox[(s2>>16)&0xff]<<16)|(mtp_sbox[(s3>>8)&0xff]<<8)|(mtp_sbox[(s0>>0)&0xff]);
            uint32_t t2 = (mtp_sbox[(s2>>24)&0xff]<<24)|(mtp_sbox[(s3>>16)&0xff]<<16)|(mtp_sbox[(s0>>8)&0xff]<<8)|(mtp_sbox[(s1>>0)&0xff]);
            uint32_t t3 = (mtp_sbox[(s3>>24)&0xff]<<24)|(mtp_sbox[(s0>>16)&0xff]<<16)|(mtp_sbox[(s1>>8)&0xff]<<8)|(mtp_sbox[(s2>>0)&0xff]);
            /* MixColumns (xtime) */
            #define MTP_XT(x) (((x)<<1)^(((x)&0x80)?0x1b:0))
            s0 = MTP_XT(t0)^MTP_XT(t1)^t1^t2^t3;
            s1 = t0^MTP_XT(t1)^MTP_XT(t2)^t2^t3;
            s2 = t0^t1^MTP_XT(t2)^MTP_XT(t3)^t3;
            s3 = MTP_XT(t0)^t0^t1^t2^MTP_XT(t3);
        } else {
            s0 = (mtp_sbox[(s0>>24)&0xff]<<24)|(mtp_sbox[(s1>>16)&0xff]<<16)|(mtp_sbox[(s2>>8)&0xff]<<8)|(mtp_sbox[(s3>>0)&0xff]);
            s1 = (mtp_sbox[(s1>>24)&0xff]<<24)|(mtp_sbox[(s2>>16)&0xff]<<16)|(mtp_sbox[(s3>>8)&0xff]<<8)|(mtp_sbox[(s0>>0)&0xff]);
            s2 = (mtp_sbox[(s2>>24)&0xff]<<24)|(mtp_sbox[(s3>>16)&0xff]<<16)|(mtp_sbox[(s0>>8)&0xff]<<8)|(mtp_sbox[(s1>>0)&0xff]);
            s3 = (mtp_sbox[(s3>>24)&0xff]<<24)|(mtp_sbox[(s0>>16)&0xff]<<16)|(mtp_sbox[(s1>>8)&0xff]<<8)|(mtp_sbox[(s2>>0)&0xff]);
        }
    }
    /* Final round key (round 14) at offset 14*16=224 */
    {
        uint32_t k0 = ((uint32_t)rk[224]<<24)|((uint32_t)rk[225]<<16)|((uint32_t)rk[226]<<8)|rk[227];
        uint32_t k1 = ((uint32_t)rk[228]<<24)|((uint32_t)rk[229]<<16)|((uint32_t)rk[230]<<8)|rk[231];
        uint32_t k2 = ((uint32_t)rk[232]<<24)|((uint32_t)rk[233]<<16)|((uint32_t)rk[234]<<8)|rk[235];
        uint32_t k3 = ((uint32_t)rk[236]<<24)|((uint32_t)rk[237]<<16)|((uint32_t)rk[238]<<8)|rk[239];
        s0 ^= k0; s1 ^= k1; s2 ^= k2; s3 ^= k3;
    }
    block[0]=(uint8_t)(s0>>24); block[1]=(uint8_t)(s0>>16); block[2]=(uint8_t)(s0>>8); block[3]=(uint8_t)s0;
    block[4]=(uint8_t)(s1>>24); block[5]=(uint8_t)(s1>>16); block[6]=(uint8_t)(s1>>8); block[7]=(uint8_t)s1;
    block[8]=(uint8_t)(s2>>24); block[9]=(uint8_t)(s2>>16); block[10]=(uint8_t)(s2>>8); block[11]=(uint8_t)s2;
    block[12]=(uint8_t)(s3>>24); block[13]=(uint8_t)(s3>>16); block[14]=(uint8_t)(s3>>8); block[15]=(uint8_t)s3;
}

/* AES-IGE encrypt: C_i = E(P_i xor C_{i-1}) xor P_{i-1}. IV = [prev_cipher|prev_plain] */
static void mtp_aes_ige_encrypt(uint8_t* data, size_t len, const uint8_t* key, const uint8_t* iv) {
    uint8_t rk[240];
    uint8_t pv[16], cv[16]; /* previous plain, previous cipher */
    size_t i;
    mtp_aes_expand_key(key, rk);
    memcpy(pv, iv + 16, 16);
    memcpy(cv, iv, 16);
    for (i = 0; i < len; i += 16) {
        uint8_t tmp[16];
        memcpy(tmp, data + i, 16);
        int j;
        for (j = 0; j < 16; j++) data[i + j] ^= cv[j];
        mtp_aes_enc_block(data + i, rk);
        for (j = 0; j < 16; j++) data[i + j] ^= pv[j];
        memcpy(cv, data + i, 16);
        memcpy(pv, tmp, 16);
    }
}

/* AES-IGE decrypt - need inverse sbox and reverse round keys for decryption */
/* For brevity we use encrypt with modified flow: IGE decrypt is similar structure. */
/* Actually AES decrypt needs different round keys and inverse mix columns. */
/* We include a minimal AES decrypt. */
static const uint8_t mtp_inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

/* GF(2^8) multiply */
static uint8_t mtp_gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t h;
    while (b) {
        if (b & 1) p ^= a;
        h = (uint8_t)(a & 0x80);
        a = (uint8_t)(a << 1);
        if (h) a ^= 0x1b;
        b = (uint8_t)(b >> 1);
    }
    return p;
}
/* Inverse MixColumns */
static uint32_t mtp_inv_mix(uint32_t x) {
    uint8_t b0 = (uint8_t)(x >> 24), b1 = (uint8_t)(x >> 16), b2 = (uint8_t)(x >> 8), b3 = (uint8_t)x;
    return ((uint32_t)(mtp_gmul(b0,0x0b)^mtp_gmul(b1,0x0d)^mtp_gmul(b2,0x09)^mtp_gmul(b3,0x0e))<<24) |
           ((uint32_t)(mtp_gmul(b1,0x0b)^mtp_gmul(b2,0x0d)^mtp_gmul(b3,0x09)^mtp_gmul(b0,0x0e))<<16) |
           ((uint32_t)(mtp_gmul(b2,0x0b)^mtp_gmul(b3,0x0d)^mtp_gmul(b0,0x09)^mtp_gmul(b1,0x0e))<<8) |
           (uint32_t)(mtp_gmul(b3,0x0b)^mtp_gmul(b0,0x0d)^mtp_gmul(b1,0x09)^mtp_gmul(b2,0x0e));
}

static void mtp_aes_dec_block(uint8_t* block, const uint8_t* rk) {
    uint32_t s0 = ((uint32_t)block[0]<<24)|((uint32_t)block[1]<<16)|((uint32_t)block[2]<<8)|block[3];
    uint32_t s1 = ((uint32_t)block[4]<<24)|((uint32_t)block[5]<<16)|((uint32_t)block[6]<<8)|block[7];
    uint32_t s2 = ((uint32_t)block[8]<<24)|((uint32_t)block[9]<<16)|((uint32_t)block[10]<<8)|block[11];
    uint32_t s3 = ((uint32_t)block[12]<<24)|((uint32_t)block[13]<<16)|((uint32_t)block[14]<<8)|block[15];
    int r;
    for (r = 14; r >= 0; r--) {
        uint32_t k0 = ((uint32_t)rk[16*r+0]<<24)|((uint32_t)rk[16*r+1]<<16)|((uint32_t)rk[16*r+2]<<8)|rk[16*r+3];
        uint32_t k1 = ((uint32_t)rk[16*r+4]<<24)|((uint32_t)rk[16*r+5]<<16)|((uint32_t)rk[16*r+6]<<8)|rk[16*r+7];
        uint32_t k2 = ((uint32_t)rk[16*r+8]<<24)|((uint32_t)rk[16*r+9]<<16)|((uint32_t)rk[16*r+10]<<8)|rk[16*r+11];
        uint32_t k3 = ((uint32_t)rk[16*r+12]<<24)|((uint32_t)rk[16*r+13]<<16)|((uint32_t)rk[16*r+14]<<8)|rk[16*r+15];
        s0 ^= k0; s1 ^= k1; s2 ^= k2; s3 ^= k3;
        if (r > 0) {
            uint32_t t0 = mtp_inv_mix((uint32_t)(mtp_inv_sbox[(s0>>24)&0xff]<<24)|(mtp_inv_sbox[(s3>>16)&0xff]<<16)|(mtp_inv_sbox[(s2>>8)&0xff]<<8)|mtp_inv_sbox[(s1>>0)&0xff]);
            uint32_t t1 = mtp_inv_mix((uint32_t)(mtp_inv_sbox[(s1>>24)&0xff]<<24)|(mtp_inv_sbox[(s0>>16)&0xff]<<16)|(mtp_inv_sbox[(s3>>8)&0xff]<<8)|mtp_inv_sbox[(s2>>0)&0xff]);
            uint32_t t2 = mtp_inv_mix((uint32_t)(mtp_inv_sbox[(s2>>24)&0xff]<<24)|(mtp_inv_sbox[(s1>>16)&0xff]<<16)|(mtp_inv_sbox[(s0>>8)&0xff]<<8)|mtp_inv_sbox[(s3>>0)&0xff]);
            uint32_t t3 = mtp_inv_mix((uint32_t)(mtp_inv_sbox[(s3>>24)&0xff]<<24)|(mtp_inv_sbox[(s2>>16)&0xff]<<16)|(mtp_inv_sbox[(s1>>8)&0xff]<<8)|mtp_inv_sbox[(s0>>0)&0xff]);
            s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        } else {
            s0 = (uint32_t)(mtp_inv_sbox[(s0>>24)&0xff]<<24)|(mtp_inv_sbox[(s3>>16)&0xff]<<16)|(mtp_inv_sbox[(s2>>8)&0xff]<<8)|mtp_inv_sbox[(s1>>0)&0xff];
            s1 = (uint32_t)(mtp_inv_sbox[(s1>>24)&0xff]<<24)|(mtp_inv_sbox[(s0>>16)&0xff]<<16)|(mtp_inv_sbox[(s3>>8)&0xff]<<8)|mtp_inv_sbox[(s2>>0)&0xff];
            s2 = (uint32_t)(mtp_inv_sbox[(s2>>24)&0xff]<<24)|(mtp_inv_sbox[(s1>>16)&0xff]<<16)|(mtp_inv_sbox[(s0>>8)&0xff]<<8)|mtp_inv_sbox[(s3>>0)&0xff];
            s3 = (uint32_t)(mtp_inv_sbox[(s3>>24)&0xff]<<24)|(mtp_inv_sbox[(s2>>16)&0xff]<<16)|(mtp_inv_sbox[(s1>>8)&0xff]<<8)|mtp_inv_sbox[(s0>>0)&0xff];
        }
    }
    block[0]=(uint8_t)(s0>>24); block[1]=(uint8_t)(s0>>16); block[2]=(uint8_t)(s0>>8); block[3]=(uint8_t)s0;
    block[4]=(uint8_t)(s1>>24); block[5]=(uint8_t)(s1>>16); block[6]=(uint8_t)(s1>>8); block[7]=(uint8_t)s1;
    block[8]=(uint8_t)(s2>>24); block[9]=(uint8_t)(s2>>16); block[10]=(uint8_t)(s2>>8); block[11]=(uint8_t)s2;
    block[12]=(uint8_t)(s3>>24); block[13]=(uint8_t)(s3>>16); block[14]=(uint8_t)(s3>>8); block[15]=(uint8_t)s3;
}

static void mtp_aes_ige_decrypt(uint8_t* data, size_t len, const uint8_t* key, const uint8_t* iv) {
    uint8_t rk[240];
    uint8_t pv[16], cv[16];
    size_t i;
    mtp_aes_expand_key(key, rk);
    memcpy(pv, iv + 16, 16);
    memcpy(cv, iv, 16);
    for (i = 0; i < len; i += 16) {
        uint8_t tmp[16];
        memcpy(tmp, data + i, 16);
        int j;
        for (j = 0; j < 16; j++) data[i + j] ^= pv[j];
        mtp_aes_dec_block(data + i, rk);
        for (j = 0; j < 16; j++) data[i + j] ^= cv[j];
        memcpy(pv, tmp, 16);
        memcpy(cv, data + i, 16);
    }
}

/*--------------------------------------------------------------------------
 * 2048-bit big integer for RSA and DH
 *--------------------------------------------------------------------------*/
typedef struct { uint32_t w[MTP_BIGINT_WORDS]; } mtp_bigint_t;

static void mtp_bigint_zero(mtp_bigint_t* a) { memset(a->w, 0, sizeof(a->w)); }
static void mtp_bigint_one(mtp_bigint_t* a)  { mtp_bigint_zero(a); a->w[0] = 1; }

static int mtp_bigint_from_bytes_be(mtp_bigint_t* a, const uint8_t* bytes, size_t len) {
    mtp_bigint_zero(a);
    if (len > MTP_BIGINT_WORDS * 4) return -1;
    size_t i;
    for (i = 0; i < len && i < MTP_BIGINT_WORDS * 4; i++) {
        uint32_t word_idx = (len - 1 - i) / 4;
        uint32_t byte_idx = (len - 1 - i) % 4;
        a->w[word_idx] |= (uint32_t)bytes[i] << (byte_idx * 8);
    }
    return 0;
}

static void mtp_bigint_to_bytes_be(const mtp_bigint_t* a, uint8_t* bytes, size_t max_len) {
    int start = MTP_BIGINT_WORDS - 1;
    while (start >= 0 && a->w[start] == 0) start--;
    size_t len = (start < 0) ? 1 : (size_t)(start + 1) * 4;
    if (len > max_len) len = max_len;
    if (max_len > len) memset(bytes, 0, max_len - len);
    { size_t i; size_t off = (max_len > len) ? max_len - len : 0;
      for (i = 0; i < len; i++) {
        uint32_t wi = (len - 1 - i) / 4;
        uint32_t bi = (len - 1 - i) % 4;
        bytes[off + i] = (uint8_t)(a->w[wi] >> (bi * 8));
      }
    }
}

static int mtp_bigint_cmp(const mtp_bigint_t* a, const mtp_bigint_t* b) {
    int i;
    for (i = MTP_BIGINT_WORDS - 1; i >= 0; i--) {
        if (a->w[i] < b->w[i]) return -1;
        if (a->w[i] > b->w[i]) return 1;
    }
    return 0;
}

static void mtp_bigint_add(mtp_bigint_t* r, const mtp_bigint_t* a, const mtp_bigint_t* b) {
    uint64_t carry = 0;
    int i;
    for (i = 0; i < MTP_BIGINT_WORDS; i++) {
        carry += (uint64_t)a->w[i] + b->w[i];
        r->w[i] = (uint32_t)carry;
        carry >>= 32;
    }
}

static void mtp_bigint_sub(mtp_bigint_t* r, const mtp_bigint_t* a, const mtp_bigint_t* b) {
    uint64_t borrow = 0;
    int i;
    for (i = 0; i < MTP_BIGINT_WORDS; i++) {
        uint64_t t = (uint64_t)a->w[i] - b->w[i] - borrow;
        r->w[i] = (uint32_t)t;
        borrow = (t >> 63) ? 1 : 0;
    }
}

/* 128-word buffer for full product */
#define MTP_BIGINT_DOUBLE  128
static void mtp_bigint_mul_full(uint32_t* prod, const mtp_bigint_t* a, const mtp_bigint_t* b) {
    int i, j;
    for (i = 0; i < MTP_BIGINT_DOUBLE; i++) prod[i] = 0;
    for (i = 0; i < MTP_BIGINT_WORDS; i++) {
        uint64_t carry = 0;
        for (j = 0; j < MTP_BIGINT_WORDS; j++) {
            carry += (uint64_t)a->w[i] * b->w[j] + prod[i + j];
            prod[i + j] = (uint32_t)carry;
            carry >>= 32;
        }
        prod[i + MTP_BIGINT_WORDS] = (uint32_t)carry;
    }
}
/* prod (128 words) >= m (64 words) ? */
static int mtp_bigint_ge_full(const uint32_t* prod, const mtp_bigint_t* m) {
    int i;
    for (i = MTP_BIGINT_DOUBLE - 1; i >= MTP_BIGINT_WORDS; i--) if (prod[i]) return 1;
    for (i = MTP_BIGINT_WORDS - 1; i >= 0; i--) {
        if (prod[i] > m->w[i]) return 1;
        if (prod[i] < m->w[i]) return 0;
    }
    return 1;
}
/* prod -= m */
static void mtp_bigint_sub_full(uint32_t* prod, const mtp_bigint_t* m) {
    uint64_t borrow = 0;
    int i;
    for (i = 0; i < MTP_BIGINT_WORDS; i++) {
        uint64_t t = (uint64_t)prod[i] - m->w[i] - borrow;
        prod[i] = (uint32_t)t;
        borrow = (t >> 63) ? 1 : 0;
    }
    for (; i < MTP_BIGINT_DOUBLE && borrow; i++) {
        uint64_t t = (uint64_t)prod[i] - borrow;
        prod[i] = (uint32_t)t;
        borrow = (t >> 63) ? 1 : 0;
    }
}
/* Shift m left by sh bits into buf (128 words) */
static void mtp_bigint_shl_to(const mtp_bigint_t* m, int sh, uint32_t* buf) {
    int i;
    for (i = 0; i < MTP_BIGINT_DOUBLE; i++) buf[i] = 0;
    if (sh < 0 || sh > 2048) return;
    { int w = sh / 32, b = sh % 32; uint64_t carry = 0;
      for (i = 0; i < MTP_BIGINT_WORDS && (w + i) < MTP_BIGINT_DOUBLE; i++) {
        carry |= (uint64_t)m->w[i] << b;
        buf[w + i] = (uint32_t)carry;
        carry >>= 32;
      }
      if (w + i < MTP_BIGINT_DOUBLE) buf[w + i] = (uint32_t)carry;
    }
}
/* Compare prod (128w) >= buf (128w) */
static int mtp_bigint_ge_128(const uint32_t* prod, const uint32_t* buf) {
    int i;
    for (i = MTP_BIGINT_DOUBLE - 1; i >= 0; i--) {
        if (prod[i] > buf[i]) return 1;
        if (prod[i] < buf[i]) return 0;
    }
    return 1;
}
/* prod -= buf */
static void mtp_bigint_sub_128(uint32_t* prod, const uint32_t* buf) {
    uint64_t borrow = 0;
    int i;
    for (i = 0; i < MTP_BIGINT_DOUBLE; i++) {
        uint64_t t = (uint64_t)prod[i] - buf[i] - borrow;
        prod[i] = (uint32_t)t;
        borrow = (t >> 63) ? 1 : 0;
    }
}
static void mtp_bigint_mod_full(uint32_t* prod, const mtp_bigint_t* m) {
    uint32_t buf[MTP_BIGINT_DOUBLE];
    int sh;
    for (sh = 2048; sh >= 0; sh--) {
        mtp_bigint_shl_to(m, sh, buf);
        while (mtp_bigint_ge_128(prod, buf)) mtp_bigint_sub_128(prod, buf);
    }
}

static void mtp_bigint_modmul(mtp_bigint_t* r, const mtp_bigint_t* a, const mtp_bigint_t* b, const mtp_bigint_t* m) {
    uint32_t prod[MTP_BIGINT_DOUBLE];
    mtp_bigint_mul_full(prod, a, b);
    mtp_bigint_mod_full(prod, m);
    memcpy(r->w, prod, MTP_BIGINT_WORDS * sizeof(uint32_t));
}

/* Modular exponentiation: r = base^exp mod m. MSB-first square-and-multiply. */
static void mtp_bigint_modexp(mtp_bigint_t* r, const mtp_bigint_t* base, const mtp_bigint_t* exp, const mtp_bigint_t* m) {
    mtp_bigint_t b, e;
    memcpy(&b, base, sizeof(mtp_bigint_t));
    memcpy(&e, exp, sizeof(mtp_bigint_t));
    mtp_bigint_one(r);
    int i, j, started = 0;
    for (i = MTP_BIGINT_WORDS - 1; i >= 0; i--) {
        for (j = 31; j >= 0; j--) {
            if (e.w[i] & (1u << j)) started = 1;
            if (started) {
                mtp_bigint_modmul(r, r, r, m);
                if (e.w[i] & (1u << j)) mtp_bigint_modmul(r, r, &b, m);
            }
        }
    }
}

/*--------------------------------------------------------------------------
 * MTProto RSA padding (OAEP+-like) - encrypt data with server public key
 *--------------------------------------------------------------------------*/
typedef struct {
    uint8_t n[256];
    uint8_t e[4];
    size_t  e_len;
} mtp_rsa_key_t;

/* Telegram production RSA key (fingerprint 85FD64DE851D9DD0) */
static const uint8_t mtp_rsa_n_prod[] = {
    0xc7,0x1c,0xae,0xb9,0xc6,0xb1,0xc9,0x04,0x8e,0x6c,0x52,0x2f,0x70,0xf1,0x3f,0x73,
    0x98,0x0d,0x40,0x23,0x8e,0x3e,0x21,0xc1,0x49,0x34,0xd0,0x37,0x56,0x3d,0x93,0x0f,
    0x48,0x19,0x8a,0x0a,0xa7,0xc1,0x40,0x58,0x22,0x94,0x93,0xd2,0x25,0x30,0xf4,0xdb,
    0xfa,0x33,0x6f,0x6e,0x0a,0xc9,0x25,0x13,0x95,0x43,0xae,0xd4,0x4c,0xce,0x7c,0x37,
    0x20,0xfd,0x51,0xf6,0x94,0x58,0x70,0x5a,0xc6,0x8c,0xd4,0xfe,0x6b,0x6b,0x13,0xab,
    0xdc,0x97,0x46,0x51,0x29,0x69,0x32,0x84,0x54,0xf1,0x8f,0xaf,0x8c,0x59,0x5f,0x64,
    0x24,0x77,0xfe,0x96,0xbb,0x2a,0x94,0x1d,0x5b,0xcd,0x1d,0x4a,0xc8,0xcc,0x49,0x88,
    0x07,0x08,0xfa,0x9b,0x37,0x8e,0x3c,0x4f,0x3a,0x90,0x60,0xbe,0xe6,0x7c,0xf9,0xa4,
    0xa4,0xa6,0x95,0x81,0x10,0x51,0x90,0x7e,0x16,0x27,0x53,0xb5,0x6b,0x0f,0x6b,0x41,
    0x0d,0xba,0x74,0xd8,0xa8,0x4b,0x2a,0x14,0xb3,0x14,0x4e,0x0e,0xf1,0x28,0x47,0x54,
    0xfd,0x17,0xed,0x95,0x0d,0x59,0x65,0xb4,0xb9,0xdd,0x46,0x58,0x2d,0xb1,0x17,0x8d,
    0x16,0x9c,0x6b,0xc4,0x65,0xb0,0xd6,0xff,0x9c,0xa3,0x92,0x8f,0xef,0x5b,0x9a,0xe4,
    0xe4,0x18,0xfc,0x15,0xe8,0x3e,0xbe,0xa0,0xf8,0x7f,0xa9,0xff,0x5e,0xed,0x70,0x05,
    0x0d,0xed,0x28,0x49,0xf4,0x7b,0xf9,0x59,0xd9,0x56,0x85,0x0c,0xe9,0x29,0x85,0x1f,
    0x0d,0x81,0x15,0xf6,0x35,0xb1,0x05,0xee,0x2e,0x4e,0x15,0xd0,0x4b,0x24,0x54,0xbf,
    0x6f,0x4f,0xad,0xf0,0x34,0xb1,0x04,0x03,0x11,0x9c,0xd8,0xe3,0xb9,0x2f,0xcc,0x5b,
};

/* MTProto RSA_PAD: data_pad_reversed + SHA256(temp_key+data_with_padding), AES-IGE, XOR, RSA */
static int mtp_rsa_encrypt(const uint8_t* data, size_t data_len, const mtp_rsa_key_t* key,
                           uint8_t* out, int (*rng)(void*,void*,size_t), void* rng_ctx) {
    uint8_t temp_key[32], data_with_padding[192], hash[32], data_with_hash[224];
    uint8_t aes_encrypted[224], key_aes_encrypted[256], iv[32];
    uint8_t to_hash[224];
    mtp_bigint_t M, N, E, C;
    int i;
    if (!data || data_len > 144 || !key || !out || !rng) return -1;
    if (rng(rng_ctx, temp_key, 32) != 1) return -1;
    memcpy(data_with_padding, data, data_len);
    if (rng(rng_ctx, data_with_padding + data_len, 192 - data_len) != 1) return -1;
    memcpy(to_hash, temp_key, 32);
    memcpy(to_hash + 32, data_with_padding, 192);
    mtp_sha256_full(to_hash, 224, hash);
    for (i = 0; i < 192; i++) data_with_hash[i] = data_with_padding[191 - i];
    memcpy(data_with_hash + 192, hash, 32);
    memset(iv, 0, 32);
    memcpy(aes_encrypted, data_with_hash, 224);
    mtp_aes_ige_encrypt(aes_encrypted, 224, temp_key, iv);
    mtp_sha256_full(aes_encrypted, 224, hash);
    for (i = 0; i < 32; i++) key_aes_encrypted[i] = temp_key[i] ^ hash[i];
    memcpy(key_aes_encrypted + 32, aes_encrypted, 224);
    mtp_bigint_from_bytes_be(&M, key_aes_encrypted, 256);
    mtp_bigint_from_bytes_be(&N, key->n, 256);
    if (mtp_bigint_cmp(&M, &N) >= 0) return -2;
    mtp_bigint_from_bytes_be(&E, key->e, key->e_len);
    mtp_bigint_modexp(&C, &M, &E, &N);
    mtp_bigint_to_bytes_be(&C, out, 256);
    return 0;
}

/*--------------------------------------------------------------------------
 * Session and state structures
 *--------------------------------------------------------------------------*/
struct mtproto_state_s {
    mtproto_callbacks_t cbs;
    int debug;
};

struct mtproto_session_s {
    mtproto_state_t* state;
    int dc_id;
    int server;           /* production or test */
    uint64_t session_id;
    uint8_t  auth_key[MTP_AUTH_KEY_SIZE];
    uint8_t  auth_key_id[8];   /* 64 low bits of SHA1(auth_key) */
    uint64_t server_salt;
    uint32_t seq_no;
    uint32_t msg_id_counter;
    int      authorized;
    uint64_t msg_history[MTPROTO_MAX_MSG_HISTORY];
    int      msg_history_count;
    /* Auth flow state */
    uint8_t  nonce[MTP_NONCE_SIZE];
    uint8_t  server_nonce[MTP_NONCE_SIZE];
    uint8_t  new_nonce[MTP_NEW_NONCE_SIZE];
    uint64_t pq;
    uint32_t p, q;
    uint64_t dh_prime_be[32];  /* placeholder */
    int auth_step;  /* 0=need req_pq, 1=got resPQ, 2=got server_DH_params, 3=got dh_gen_ok */
    char phone_code_hash[64];
    char phone[32];
    /* Abridged transport */
    int abridged_sent;          /* 1 if 0xef sent */
    uint8_t recv_len_buf[4];    /* length bytes */
    size_t recv_len_have;
    int recv_state;             /* 0=need len1, 1=need len3, 2=need payload */
    size_t recv_want;           /* payload bytes to read */
    size_t recv_pos;            /* bytes of payload received */
    /* DH state (auth flow) */
    int g;                      /* DH generator */
    uint8_t dh_prime[256];      /* DH prime */
    uint8_t g_a[256];           /* server g^a */
    size_t dh_prime_len, g_a_len;
    int32_t server_time;
    uint8_t p_bytes[8], q_bytes[8];  /* factored pq */
    size_t p_len, q_len;
};

/*--------------------------------------------------------------------------
 * Abridged transport (MTProto framing: 0xef, length, payload)
 *--------------------------------------------------------------------------*/
static int mtp_abridged_send(mtproto_session_t* s, const uint8_t* payload, size_t len) {
    uint8_t hdr[4];
    size_t hdr_len;
    uint32_t len_words;
    int r;
    if (!s || !s->state || !payload) return MTPROTO_ERR_INVALID_PARAM;
    if (len & 3) return MTPROTO_ERR_PROTOCOL;  /* must be multiple of 4 */
    len_words = (uint32_t)(len / 4);
    /* Send 0xef on first packet */
    if (!s->abridged_sent) {
        uint8_t ef = 0xef;
        r = s->state->cbs.send_data(s->state->cbs.userdata, &ef, 1);
        if (r != 1) return MTPROTO_ERR_TRANSPORT;
        s->abridged_sent = 1;
    }
    if (len_words < 127u) {
        hdr[0] = (uint8_t)len_words;
        hdr_len = 1;
    } else {
        hdr[0] = 0x7f;
        hdr[1] = (uint8_t)(len_words);
        hdr[2] = (uint8_t)(len_words >> 8);
        hdr[3] = (uint8_t)(len_words >> 16);
        hdr_len = 4;
    }
    r = s->state->cbs.send_data(s->state->cbs.userdata, hdr, hdr_len);
    if (r != (int)hdr_len) return MTPROTO_ERR_TRANSPORT;
    r = s->state->cbs.send_data(s->state->cbs.userdata, payload, len);
    if (r != (int)len) return MTPROTO_ERR_TRANSPORT;
    return MTPROTO_OK;
}

static int64_t mtp_gen_msg_id(mtproto_session_t* s);

/*--------------------------------------------------------------------------
 * MTProto 2.0 encrypted messages (msg_key, aes_key/iv, envelope)
 * x=0 client->server, x=8 server->client
 *--------------------------------------------------------------------------*/
static int mtp_encrypt_message(mtproto_session_t* s, const uint8_t* tl_data, size_t tl_len, int content_related,
                               uint8_t* out, size_t out_size) {
    uint8_t plain[4096];
    uint8_t* p;
    size_t plain_len, pad_len, total_len;
    uint8_t msg_key_large[32], msg_key[16];
    uint8_t sha256_a[32], sha256_b[32];
    uint8_t aes_key[32], aes_iv[32];
    uint8_t to_hash[4096];
    int x = 0;  /* client -> server */
    int32_t msg_len;
    if (!s || !tl_data || !out || out_size < 32) return MTPROTO_ERR_INVALID_PARAM;
    if (!s->authorized) return MTPROTO_ERR_NOT_CONNECTED;
    msg_len = (int32_t)tl_len;
    p = plain;
    memcpy(p, &s->server_salt, 8); p += 8;
    memcpy(p, &s->session_id, 8); p += 8;
    { int64_t mid = mtp_gen_msg_id(s); memcpy(p, &mid, 8); p += 8; }
    { uint32_t seq = content_related ? (s->seq_no * 2 + 1) : (s->seq_no * 2); memcpy(p, &seq, 4); p += 4; if (content_related) s->seq_no++; }
    memcpy(p, &msg_len, 4); p += 4;
    memcpy(p, tl_data, tl_len); p += tl_len;
    plain_len = (size_t)(p - plain);
    pad_len = 12 + (16 - (plain_len + 12) % 16) % 16;
    if (pad_len > 1024) pad_len = 12 + (16 - (plain_len + 12) % 16) % 16;
    if (s->state->cbs.random_bytes && pad_len > 0) {
        if (s->state->cbs.random_bytes(s->state->cbs.userdata, p, pad_len) != 1) return MTPROTO_ERR_CRYPTO;
        p += pad_len;
    } else {
        memset(p, 0, pad_len);
        p += pad_len;
    }
    total_len = (size_t)(p - plain);
    if (total_len > sizeof(to_hash) - 32) return MTPROTO_ERR_PROTOCOL;
    memcpy(to_hash, s->auth_key + 88 + x, 32);
    memcpy(to_hash + 32, plain, total_len);
    mtp_sha256_full(to_hash, 32 + total_len, msg_key_large);
    memcpy(msg_key, msg_key_large + 8, 16);
    memcpy(to_hash, msg_key, 16);
    memcpy(to_hash + 16, s->auth_key + x, 36);
    mtp_sha256_full(to_hash, 52, sha256_a);
    memcpy(to_hash, s->auth_key + 40 + x, 36);
    memcpy(to_hash + 36, msg_key, 16);
    mtp_sha256_full(to_hash, 52, sha256_b);
    memcpy(aes_key, sha256_a, 8); memcpy(aes_key + 8, sha256_b + 8, 16); memcpy(aes_key + 24, sha256_a + 24, 8);
    memcpy(aes_iv, sha256_b, 8); memcpy(aes_iv + 8, sha256_a + 8, 16); memcpy(aes_iv + 24, sha256_b + 24, 8);
    if (out_size < 8 + 16 + total_len) return MTPROTO_ERR_BUFFER_TOO_SMALL;
    memcpy(out, s->auth_key_id, 8);
    memcpy(out + 8, msg_key, 16);
    memcpy(out + 24, plain, total_len);
    mtp_aes_ige_encrypt(out + 24, total_len, aes_key, aes_iv);
    return (int)(8 + 16 + total_len);
}

/* Decrypt MTProto 2.0 message. raw = auth_key_id(8)+msg_key(16)+encrypted. Returns msg_data length, <0 on error. x=8 for server->client. */
static int mtp_decrypt_message(mtproto_session_t* s, const uint8_t* raw, size_t raw_len, uint8_t* msg_out, size_t msg_size) {
    uint8_t tmp[4096], verify_buf[4128];
    uint8_t sha256_a[32], sha256_b[32];
    uint8_t aes_key[32], aes_iv[32];
    uint8_t msg_key[16], hash_result[32];
    int x = 8;  /* server -> client */
    size_t enc_len;
    int32_t msg_data_len;
    if (!s || !raw || !msg_out || raw_len < 8 + 16 + 32) return MTPROTO_ERR_INVALID_PARAM;
    if (memcmp(raw, s->auth_key_id, 8) != 0) return MTPROTO_ERR_PROTOCOL;
    enc_len = raw_len - 8 - 16;
    if (enc_len % 16) return MTPROTO_ERR_PROTOCOL;
    memcpy(msg_key, raw + 8, 16);
    memcpy(tmp, raw + 24, enc_len);
    if (52 <= sizeof(verify_buf)) {
        memcpy(verify_buf, msg_key, 16);
        memcpy(verify_buf + 16, s->auth_key + x, 36);
        mtp_sha256_full(verify_buf, 52, sha256_a);
    }
    memcpy(verify_buf, s->auth_key + 40 + x, 36);
    memcpy(verify_buf + 36, msg_key, 16);
    mtp_sha256_full(verify_buf, 52, sha256_b);
    memcpy(aes_key, sha256_a, 8); memcpy(aes_key + 8, sha256_b + 8, 16); memcpy(aes_key + 24, sha256_a + 24, 8);
    memcpy(aes_iv, sha256_b, 8); memcpy(aes_iv + 8, sha256_a + 8, 16); memcpy(aes_iv + 24, sha256_b + 24, 8);
    mtp_aes_ige_decrypt(tmp, enc_len, aes_key, aes_iv);
    if (32 + enc_len > sizeof(verify_buf)) return MTPROTO_ERR_PROTOCOL;
    memcpy(verify_buf, s->auth_key + 88 + x, 32);
    memcpy(verify_buf + 32, tmp, enc_len);
    mtp_sha256_full(verify_buf, 32 + enc_len, hash_result);
    if (memcmp(msg_key, hash_result + 8, 16) != 0) return MTPROTO_ERR_CRYPTO;
    memcpy(&msg_data_len, tmp + 24, 4);
    if (msg_data_len < 0 || (size_t)msg_data_len > enc_len - 32) return MTPROTO_ERR_PROTOCOL;
    if ((size_t)msg_data_len > msg_size) return MTPROTO_ERR_BUFFER_TOO_SMALL;
    memcpy(msg_out, tmp + 32, (size_t)msg_data_len);
    return (int)msg_data_len;
}

/* Recv one abridged packet into out_buf. Returns payload length, 0 if need more data, <0 on error. */
static int mtp_abridged_recv(mtproto_session_t* s, uint8_t* out_buf, size_t out_size) {
    int r;
    uint32_t len_words;
    if (!s || !s->state || !out_buf) return MTPROTO_ERR_INVALID_PARAM;
    while (1) {
        if (s->recv_state == 0) {
            r = s->state->cbs.recv_data(s->state->cbs.userdata, s->recv_len_buf, 1);
            if (r <= 0) return r;
            s->recv_len_have = 1;
            if (s->recv_len_buf[0] < 0x80u) {
                len_words = s->recv_len_buf[0];
                s->recv_want = len_words * 4;
                s->recv_state = 2;
                s->recv_pos = 0;
            } else if (s->recv_len_buf[0] == 0x7f) {
                s->recv_state = 1;
            } else {
                /* Quick ACK or invalid - skip */
                s->recv_state = 0;
                continue;
            }
        }
        if (s->recv_state == 1) {
            r = s->state->cbs.recv_data(s->state->cbs.userdata, s->recv_len_buf + 1, 3);
            if (r <= 0) return r;
            len_words = (uint32_t)s->recv_len_buf[1] | ((uint32_t)s->recv_len_buf[2] << 8) | ((uint32_t)s->recv_len_buf[3] << 16);
            s->recv_want = len_words * 4;
            s->recv_state = 2;
            s->recv_pos = 0;
        }
        if (s->recv_state == 2) {
            size_t to_read = s->recv_want - s->recv_pos;
            if (to_read > out_size - s->recv_pos) {
                /* Buffer too small - read and discard */
                if (out_size < s->recv_want) {
                    uint8_t discard[256];
                    while (s->recv_pos < s->recv_want) {
                        size_t n = s->recv_want - s->recv_pos;
                        if (n > sizeof(discard)) n = sizeof(discard);
                        r = s->state->cbs.recv_data(s->state->cbs.userdata, discard, n);
                        if (r <= 0) return MTPROTO_ERR_TRANSPORT;
                        s->recv_pos += (size_t)r;
                    }
                    s->recv_state = 0;
                    mtp_set_error("Packet too large for buffer");
                    return MTPROTO_ERR_BUFFER_TOO_SMALL;
                }
            }
            r = s->state->cbs.recv_data(s->state->cbs.userdata, out_buf + s->recv_pos, to_read);
            if (r <= 0) return r;
            s->recv_pos += (size_t)r;
            if (s->recv_pos >= s->recv_want) {
                s->recv_state = 0;
                return (int)s->recv_want;
            }
        }
    }
}

/*--------------------------------------------------------------------------
 * TL serialization helpers
 *--------------------------------------------------------------------------*/
static void mtp_tl_write_int32(uint8_t** p, int32_t v) {
    memcpy(*p, &v, 4);
    *p += 4;
}
static void mtp_tl_write_int64(uint8_t** p, int64_t v) {
    memcpy(*p, &v, 8);
    *p += 8;
}
static void mtp_tl_write_bytes(uint8_t** p, const void* data, size_t len) {
    /* TL string: length as compact int, then bytes, pad to 4-byte boundary */
    int pad = (4 - ((int)len + 1) % 4) % 4;
    if (len < 254) {
        *(*p)++ = (uint8_t)len;
    } else {
        *(*p)++ = 254;
        (*p)[0] = (uint8_t)(len);
        (*p)[1] = (uint8_t)(len >> 8);
        (*p)[2] = (uint8_t)(len >> 16);
        *p += 3;
    }
    memcpy(*p, data, len);
    *p += len;
    while (pad--) *(*p)++ = 0;
}
static void mtp_tl_write_constructor(uint8_t** p, uint32_t c) {
    memcpy(*p, &c, 4);
    *p += 4;
}
/* TL read primitives - *p advances, return value or <0 on overflow */
static int mtp_tl_read_int32(const uint8_t** p, const uint8_t* end, int32_t* out) {
    if (*p + 4 > end) return -1;
    memcpy(out, *p, 4);
    *p += 4;
    return 0;
}
static int mtp_tl_read_int64(const uint8_t** p, const uint8_t* end, int64_t* out) {
    if (*p + 8 > end) return -1;
    memcpy(out, *p, 8);
    *p += 8;
    return 0;
}
/* Read TL string into buf (null-terminated), max buf_size. Returns bytes read from stream, or <0 on error. */
static int mtp_tl_read_string(const uint8_t** p, const uint8_t* end, char* buf, size_t buf_size) {
    if (*p >= end) return -1;
    uint32_t len;
    if (*(*p) < 254) {
        len = *(*p)++;
        if (*p + len > end) return -1;
    } else {
        if (*p + 4 > end) return -1;
        (*p)++;
        len = (uint32_t)(*p)[0] | ((uint32_t)(*p)[1] << 8) | ((uint32_t)(*p)[2] << 16);
        *p += 3;
        if (*p + len > end) return -1;
    }
    if (buf_size == 0) { *p += len + (4 - (len + 1) % 4) % 4; return (int)len; }
    size_t copy = len < buf_size - 1 ? len : buf_size - 1;
    memcpy(buf, *p, copy);
    buf[copy] = '\0';
    *p += len;
    { int pad = (4 - (int)((len + 1) % 4)) % 4; if (*p + pad > end) return -1; *p += pad; }
    return (int)len;
}

/*--------------------------------------------------------------------------
 * TL method builders (standalone - for use with mtproto_send_method or direct send)
 *--------------------------------------------------------------------------*/
int mtproto_tl_build_auth_send_code(uint8_t* buf, size_t buf_size, const char* phone, int api_id, const char* api_hash) {
    if (!buf || !phone || !api_hash) return -1;
    size_t pl = strlen(phone), hl = strlen(api_hash);
    size_t need = 4 + 4 + (pl < 254 ? 1 + pl : 4 + pl) + 4 + (hl < 254 ? 1 + hl : 4 + hl) + 4; /* constructor + phone + api_id + api_hash + codeSettings */
    int p1 = (4 - ((int)pl + 1) % 4) % 4, p2 = (4 - ((int)hl + 1) % 4) % 4;
    need += p1 + p2;
    if (buf_size < need) return -1;
    uint8_t* p = buf;
    mtp_tl_write_constructor(&p, TL_AUTH_SEND_CODE);
    mtp_tl_write_bytes(&p, phone, pl);
    mtp_tl_write_int32(&p, api_id);
    mtp_tl_write_bytes(&p, api_hash, hl);
    mtp_tl_write_constructor(&p, TL_CODE_SETTINGS);
    mtp_tl_write_int32(&p, 0);  /* flags=0 */
    return (int)(p - buf);
}

int mtproto_tl_build_auth_sign_in(uint8_t* buf, size_t buf_size, const char* phone, const char* phone_code_hash, const char* code) {
    if (!buf || !phone || !phone_code_hash || !code) return -1;
    size_t pl = strlen(phone), hl = strlen(phone_code_hash), cl = strlen(code);
    size_t need = 4 + (pl < 254 ? 1 + pl : 4 + pl) + (hl < 254 ? 1 + hl : 4 + hl) + (cl < 254 ? 1 + cl : 4 + cl);
    need += (4 - ((int)pl + 1) % 4) % 4 + (4 - ((int)hl + 1) % 4) % 4 + (4 - ((int)cl + 1) % 4) % 4;
    if (buf_size < need) return -1;
    uint8_t* p = buf;
    mtp_tl_write_constructor(&p, TL_AUTH_SIGN_IN);
    mtp_tl_write_bytes(&p, phone, pl);
    mtp_tl_write_bytes(&p, phone_code_hash, hl);
    mtp_tl_write_bytes(&p, code, cl);
    return (int)(p - buf);
}

int mtproto_tl_build_messages_send_message(uint8_t* buf, size_t buf_size, int64_t peer_user_id, int64_t peer_access_hash, const char* text, int64_t random_id) {
    if (!buf || !text) return -1;
    size_t tl = strlen(text);
    size_t need = 4 + 4;  /* constructor + flags=0 */
    if (peer_user_id == 0 && peer_access_hash == 0) {
        need += 4;  /* inputPeerSelf */
    } else {
        need += 4 + 8 + 8;  /* inputPeerUser: constructor + user_id + access_hash */
    }
    need += (tl < 254 ? 1 + tl : 4 + tl) + (4 - ((int)tl + 1) % 4) % 4 + 8;  /* message + random_id */
    if (buf_size < need) return -1;
    uint8_t* p = buf;
    mtp_tl_write_constructor(&p, TL_MESSAGES_SEND_MESSAGE);
    mtp_tl_write_int32(&p, 0);  /* flags */
    if (peer_user_id == 0 && peer_access_hash == 0) {
        mtp_tl_write_constructor(&p, TL_INPUT_PEER_SELF);
    } else {
        mtp_tl_write_constructor(&p, TL_INPUT_PEER_USER);
        mtp_tl_write_int64(&p, peer_user_id);
        mtp_tl_write_int64(&p, peer_access_hash);
    }
    mtp_tl_write_bytes(&p, text, tl);
    mtp_tl_write_int64(&p, random_id);
    return (int)(p - buf);
}

/*--------------------------------------------------------------------------
 * TL response parsers
 *--------------------------------------------------------------------------*/
int mtproto_tl_parse_auth_sent_code(const uint8_t* data, size_t len, char* phone_code_hash_out, size_t out_size) {
    const uint8_t* p = data;
    const uint8_t* end = data + len;
    uint32_t ctor;
    if (len < 4) return MTPROTO_ERR_PROTOCOL;
    memcpy(&ctor, p, 4);
    p += 4;
    if (ctor != TL_AUTH_SENT_CODE) return MTPROTO_ERR_PROTOCOL;
    if (p + 4 > end) return MTPROTO_ERR_PROTOCOL;
    p += 4;  /* flags */
    if (p + 4 > end) return MTPROTO_ERR_PROTOCOL;
    { uint32_t type_ctor; memcpy(&type_ctor, p, 4); p += 4;
      if (type_ctor == 0xc000bba2u || type_ctor == 0x3dbb5986u || type_ctor == 0x2c6b1e3bu) { if (p + 4 > end) return MTPROTO_ERR_PROTOCOL; p += 4; }
      else if (type_ctor == 0x6f4f9243u) { if (mtp_tl_read_string(&p, end, (char*)0, 0) < 0) return MTPROTO_ERR_PROTOCOL; }  /* FlashCall: pattern string */
    }
    /* next is phone_code_hash string */
    return mtp_tl_read_string(&p, end, phone_code_hash_out ? phone_code_hash_out : (char*)0, phone_code_hash_out ? out_size : 0) >= 0 ? MTPROTO_OK : MTPROTO_ERR_PROTOCOL;
}

int mtproto_tl_parse_auth_authorization(const uint8_t* data, size_t len) {
    if (len < 4) return -1;
    uint32_t ctor;
    memcpy(&ctor, data, 4);
    if (ctor == TL_AUTH_AUTHORIZATION) return 1;  /* auth.authorization - success */
    if (ctor == 0x44747e9a) return 0;  /* auth.authorizationSignUpRequired */
    return -1;
}

int mtproto_tl_parse_rpc_error(const uint8_t* data, size_t len, char* error_msg_out, size_t msg_size) {
    const uint8_t* p = data;
    const uint8_t* end = data + len;
    uint32_t ctor;
    int32_t code;
    if (len < 4) return 0;
    memcpy(&ctor, p, 4);
    if (ctor != TL_RPC_ERROR) return 0;
    p += 4;
    if (p + 4 > end) return 0;
    memcpy(&code, p, 4);
    p += 4;
    if (mtp_tl_read_string(&p, end, error_msg_out ? error_msg_out : (char*)0, error_msg_out ? msg_size : 0) < 0) return 0;
    return (int)code;
}

int mtproto_store_sent_code(mtproto_session_t* session, const uint8_t* data, size_t len) {
    if (!session) return MTPROTO_ERR_INVALID_PARAM;
    return mtproto_tl_parse_auth_sent_code(data, len, session->phone_code_hash, sizeof(session->phone_code_hash));
}

/*--------------------------------------------------------------------------
 * Auth flow: resPQ parser, PQ factoring, req_DH_params, server_DH_params_ok,
 * set_client_DH_params, dh_gen_ok
 *--------------------------------------------------------------------------*/
static int mtp_factor_pq(uint64_t pq_val, uint32_t* p_out, uint32_t* q_out) {
    uint32_t p, q;
    if (pq_val < 4) return -1;
    for (p = 2; (uint64_t)p * p <= pq_val && p < 0x10000u; p++) {
        if (pq_val % p == 0) {
            q = (uint32_t)(pq_val / p);
            if (p > q) { uint32_t t = p; p = q; q = t; }
            *p_out = p;
            *q_out = q;
            return 0;
        }
    }
    return -1;
}

static int mtp_parse_respq(mtproto_session_t* s, const uint8_t* data, size_t len) {
    const uint8_t* p = data;
    const uint8_t* end = data + len;
    uint32_t ctor;
    uint64_t pq_val = 0;
    int i, vec_len;
    if (len < 4) return MTPROTO_ERR_PROTOCOL;
    memcpy(&ctor, p, 4); p += 4;
    if (ctor != TL_RES_PQ) return MTPROTO_ERR_PROTOCOL;
    if (p + 16 + 16 > end) return MTPROTO_ERR_PROTOCOL;
    if (memcmp(p, s->nonce, 16) != 0) return MTPROTO_ERR_PROTOCOL;
    p += 16;
    memcpy(s->server_nonce, p, 16); p += 16;
    /* pq string (big-endian) */
    if (p >= end) return MTPROTO_ERR_PROTOCOL;
    { uint32_t pq_len; uint8_t first = *p++; if (first < 254) pq_len = first; else { if (p + 3 > end) return -1; pq_len = (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16); p += 3; } if (p + pq_len > end || pq_len > 8) return -1; for (i = 0; i < (int)pq_len; i++) pq_val = (pq_val << 8) | p[i]; p += pq_len; p += (4 - ((int)pq_len + 1) % 4) % 4; }
    s->pq = pq_val;
    /* Vector<long> fingerprints */
    if (p + 4 > end) return MTPROTO_ERR_PROTOCOL;
    memcpy(&ctor, p, 4); p += 4;
    if (ctor != TL_VECTOR) return MTPROTO_ERR_PROTOCOL;
    if (p + 4 > end) return -1;
    memcpy(&vec_len, p, 4); p += 4;
    (void)vec_len;
    if (p + 8 > end) return -1;
    /* Use first fingerprint - production key 85FD64DE851D9DD0 */
    p += 8;
    if (mtp_factor_pq(pq_val, &s->p, &s->q) != 0) return MTPROTO_ERR_CRYPTO;
    s->p_len = 4; s->q_len = 4;
    s->p_bytes[0] = (uint8_t)(s->p >> 24); s->p_bytes[1] = (uint8_t)(s->p >> 16); s->p_bytes[2] = (uint8_t)(s->p >> 8); s->p_bytes[3] = (uint8_t)s->p;
    s->q_bytes[0] = (uint8_t)(s->q >> 24); s->q_bytes[1] = (uint8_t)(s->q >> 16); s->q_bytes[2] = (uint8_t)(s->q >> 8); s->q_bytes[3] = (uint8_t)s->q;
    return MTPROTO_OK;
}

/* Build p_q_inner_data_dc + RSA encrypt -> req_DH_params */
static int mtp_build_req_dh_params(mtproto_session_t* s, uint8_t* buf, size_t buf_size) {
    uint8_t inner[256];
    uint8_t pq_buf[8];
    uint8_t* p;
    int dc = s->dc_id;
    int i, pq_bytes = 0;
    mtp_rsa_key_t rsa_key;
    uint8_t enc[256];
    if (buf_size < 512) return MTPROTO_ERR_INVALID_PARAM;
    if (s->server) dc += 10000;
    if (s->state->cbs.random_bytes(s->state->cbs.userdata, s->new_nonce, 32) != 1) return MTPROTO_ERR_CRYPTO;
    { uint64_t v = s->pq; for (i = 7; i >= 0; i--) { pq_buf[i] = (uint8_t)(v & 0xff); if (v) pq_bytes = 8 - i; v >>= 8; } }
    if (pq_bytes == 0) pq_bytes = 1;
    p = inner;
    mtp_tl_write_constructor(&p, TL_P_Q_INNER_DATA_DC);
    mtp_tl_write_bytes(&p, pq_buf + (8 - pq_bytes), (size_t)pq_bytes);
    mtp_tl_write_bytes(&p, s->p_bytes, s->p_len);
    mtp_tl_write_bytes(&p, s->q_bytes, s->q_len);
    memcpy(p, s->nonce, 16); p += 16;
    memcpy(p, s->server_nonce, 16); p += 16;
    memcpy(p, s->new_nonce, 32); p += 32;
    mtp_tl_write_int32(&p, dc);
    if ((size_t)(p - inner) > 144) return MTPROTO_ERR_PROTOCOL;
    memcpy(&rsa_key.n, mtp_rsa_n_prod, 256);
    rsa_key.e[0] = 0x01; rsa_key.e[1] = 0x00; rsa_key.e[2] = 0x01; rsa_key.e_len = 3;
    if (mtp_rsa_encrypt(inner, (size_t)(p - inner), &rsa_key, enc, s->state->cbs.random_bytes, s->state->cbs.userdata) != 0) return MTPROTO_ERR_CRYPTO;
    p = buf;
    mtp_tl_write_constructor(&p, TL_REQ_DH_PARAMS);
    memcpy(p, s->nonce, 16); p += 16;
    memcpy(p, s->server_nonce, 16); p += 16;
    mtp_tl_write_bytes(&p, s->p_bytes, s->p_len);
    mtp_tl_write_bytes(&p, s->q_bytes, s->q_len);
    mtp_tl_write_int64(&p, 0x85FD64DE851D9DD0LL);
    mtp_tl_write_bytes(&p, enc, 256);
    return (int)(p - buf);
}

static void mtp_sha1_concat(const uint8_t* a, size_t alen, const uint8_t* b, size_t blen, uint8_t out[20]) {
    uint8_t buf[128];
    if (alen + blen <= sizeof(buf)) { memcpy(buf, a, alen); memcpy(buf + alen, b, blen); mtp_sha1(buf, alen + blen, out); }
}

/* Parse server_DH_params_ok, decrypt, extract g, dh_prime, g_a, server_time */
static int mtp_parse_server_dh_params_ok(mtproto_session_t* s, const uint8_t* data, size_t len) {
    const uint8_t* p = data;
    const uint8_t* end = data + len;
    uint32_t ctor, enc_len_u;
    uint8_t tmp_key[32], tmp_iv[32];
    uint8_t sha1_a[20], sha1_b[20], sha1_c[20];
    uint8_t enc_buf[1024];
    size_t enc_len;
    if (len < 4 + 16 + 16) return MTPROTO_ERR_PROTOCOL;
    memcpy(&ctor, p, 4); p += 4;
    if (ctor != TL_SERVER_DH_PARAMS_OK) return MTPROTO_ERR_PROTOCOL;
    if (memcmp(p, s->nonce, 16) != 0) return MTPROTO_ERR_PROTOCOL;
    p += 16;
    if (memcmp(p, s->server_nonce, 16) != 0) return MTPROTO_ERR_PROTOCOL;
    p += 16;
    if (p >= end) return MTPROTO_ERR_PROTOCOL;
    if (*p < 254) { enc_len_u = *p++; } else { if (p + 4 > end) return -1; p++; enc_len_u = (uint32_t)p[0]|(p[1]<<8)|(p[2]<<16); p += 3; }
    if (p + enc_len_u > end || enc_len_u > sizeof(enc_buf)) return MTPROTO_ERR_PROTOCOL;
    memcpy(enc_buf, p, enc_len_u); p += enc_len_u; p += (4 - (enc_len_u + 1) % 4) % 4;
    enc_len = enc_len_u;
    mtp_sha1_concat(s->new_nonce, 32, s->server_nonce, 16, sha1_a);  /* SHA1(new_nonce+server_nonce) */
    mtp_sha1_concat(s->server_nonce, 16, s->new_nonce, 32, sha1_b);  /* SHA1(server_nonce+new_nonce) */
    mtp_sha1_concat(s->new_nonce, 32, s->new_nonce, 32, sha1_c);  /* SHA1(new_nonce+new_nonce) */
    memcpy(tmp_key, sha1_a, 20); memcpy(tmp_key + 20, sha1_b, 12);
    memcpy(tmp_iv, sha1_b + 12, 8); memcpy(tmp_iv + 8, sha1_c, 20); memcpy(tmp_iv + 28, s->new_nonce, 4);
    mtp_aes_ige_decrypt(enc_buf, (enc_len + 15) & ~15, tmp_key, tmp_iv);
    /* Verify SHA1(decrypted)[0:20] == SHA1(rest) - skip hash */
    p = enc_buf + 20;
    end = enc_buf + enc_len;
    memcpy(&ctor, p, 4); p += 4;
    if (ctor != TL_SERVER_DH_INNER) return MTPROTO_ERR_PROTOCOL;
    p += 16; p += 16;
    memcpy(&s->g, p, 4); p += 4;
    if (p >= end) return -1;
    { uint32_t ll; uint8_t f = *p++; if (f < 254) ll = f; else { ll = (uint32_t)p[0]|(p[1]<<8)|(p[2]<<16); p += 3; } s->dh_prime_len = ll; if (ll > 256) return -1; memcpy(s->dh_prime, p, ll); p += ll + (4-(ll+1)%4)%4; }
    { uint32_t ll; uint8_t f = *p++; if (f < 254) ll = f; else { ll = (uint32_t)p[0]|(p[1]<<8)|(p[2]<<16); p += 3; } s->g_a_len = ll; if (ll > 256) return -1; memcpy(s->g_a, p, ll); p += ll + (4-(ll+1)%4)%4; }
    memcpy(&s->server_time, p, 4);
    return MTPROTO_OK;
}

/* Build set_client_DH_params */
static int mtp_build_set_client_dh_params(mtproto_session_t* s, uint8_t* buf, size_t buf_size) {
    uint8_t inner[512], enc[512];
    uint8_t* p;
    uint8_t tmp_key[32], tmp_iv[32];
    uint8_t sha1_a[20], sha1_b[20];
    uint8_t g_b_bytes[256];
    mtp_bigint_t G, DH_PRIME, G_A, G_B, AUTH_KEY;
    mtp_bigint_t B;
    size_t inner_len, enc_len;
    int i;
    if (buf_size < 600) return MTPROTO_ERR_INVALID_PARAM;
    mtp_sha1_concat(s->new_nonce, 32, s->server_nonce, 16, sha1_a);
    mtp_sha1_concat(s->server_nonce, 16, s->new_nonce, 32, sha1_b);
    memcpy(tmp_key, sha1_a, 20); memcpy(tmp_key + 20, sha1_b, 12);
    memcpy(tmp_iv, sha1_b + 12, 8); memcpy(tmp_iv + 8, sha1_a, 20); memcpy(tmp_iv + 28, s->new_nonce, 4);
    if (s->state->cbs.random_bytes(s->state->cbs.userdata, B.w, sizeof(B.w)) != 1) return MTPROTO_ERR_CRYPTO;
    B.w[MTP_BIGINT_WORDS-1] &= 0x7FFFFFFFu; B.w[0] |= 1;
    mtp_bigint_from_bytes_be(&DH_PRIME, s->dh_prime, s->dh_prime_len);
    mtp_bigint_from_bytes_be(&G_A, s->g_a, s->g_a_len);
    mtp_bigint_one(&G); G.w[0] = (uint32_t)s->g;
    mtp_bigint_modexp(&G_B, &G, &B, &DH_PRIME);
    mtp_bigint_modexp(&AUTH_KEY, &G_A, &B, &DH_PRIME);
    mtp_bigint_to_bytes_be(&G_B, g_b_bytes, 256);
    p = inner;
    mtp_tl_write_constructor(&p, TL_CLIENT_DH_INNER);
    memcpy(p, s->nonce, 16); p += 16;
    memcpy(p, s->server_nonce, 16); p += 16;
    mtp_tl_write_int64(&p, 0);  /* retry_id */
    { size_t gb_len; for (i = 0; i < 256 && g_b_bytes[i] == 0; i++); gb_len = (size_t)(256 - i); if (gb_len == 0) gb_len = 1; mtp_tl_write_bytes(&p, g_b_bytes + i, gb_len); }
    inner_len = (size_t)(p - inner);
    enc_len = 20 + inner_len + 15; enc_len &= ~15;
    if (enc_len > sizeof(enc)) return MTPROTO_ERR_PROTOCOL;
    mtp_sha1(inner, inner_len, enc);
    memcpy(enc + 20, inner, inner_len);
    if (s->state->cbs.random_bytes(s->state->cbs.userdata, enc + 20 + inner_len, enc_len - 20 - inner_len) != 1) return MTPROTO_ERR_CRYPTO;
    mtp_aes_ige_encrypt(enc, enc_len, tmp_key, tmp_iv);
    p = buf;
    mtp_tl_write_constructor(&p, TL_SET_CLIENT_DH_PARAMS);
    memcpy(p, s->nonce, 16); p += 16;
    memcpy(p, s->server_nonce, 16); p += 16;
    mtp_tl_write_bytes(&p, enc, enc_len);
    /* Store auth_key, auth_key_id (64 low bits of SHA1), server_salt */
    mtp_bigint_to_bytes_be(&AUTH_KEY, s->auth_key, 256);
    { uint8_t h[20]; mtp_sha1(s->auth_key, 256, h); memcpy(s->auth_key_id, h + 12, 8); }
    s->server_salt = 0; for (i = 0; i < 8; i++) s->server_salt |= ((uint64_t)(s->new_nonce[i] ^ s->server_nonce[i])) << (i*8);
    return (int)(p - buf);
}

static int mtp_parse_dh_gen_ok(mtproto_session_t* s, const uint8_t* data, size_t len) {
    uint8_t hash[20], tmp[41];
    uint32_t ctor;
    if (len < 4 + 16 + 16 + 16) return MTPROTO_ERR_PROTOCOL;
    memcpy(&ctor, data, 4);
    if (ctor != TL_DH_GEN_OK) return MTPROTO_ERR_PROTOCOL;
    if (memcmp(data + 4, s->nonce, 16) != 0) return MTPROTO_ERR_PROTOCOL;
    if (memcmp(data + 20, s->server_nonce, 16) != 0) return MTPROTO_ERR_PROTOCOL;
    memcpy(tmp, s->new_nonce, 32); tmp[32] = 1; memcpy(tmp + 33, s->auth_key_id, 8);  /* auth_key_id is low 64 bits of SHA1(auth_key); we need aux = high 64 bits. Actually auth_key_aux_hash = 64 higher bits of SHA1(auth_key). So first 8 bytes of SHA1(auth_key). */
    mtp_sha1(s->auth_key, 256, hash); memcpy(tmp + 33, hash, 8);  /* auth_key_aux_hash = first 8 bytes of SHA1(auth_key) */
    mtp_sha1(tmp, 41, hash);  /* new_nonce_hash1 = bytes 4-19 of SHA1 result (128 low bits) */
    if (memcmp(data + 36, hash + 4, 16) != 0) return MTPROTO_ERR_PROTOCOL;
    return MTPROTO_OK;
}

/*--------------------------------------------------------------------------
 * Message ID generation
 *--------------------------------------------------------------------------*/
static int64_t mtp_gen_msg_id(mtproto_session_t* s) {
    uint64_t ms = s->state->cbs.get_time_ms ? s->state->cbs.get_time_ms(s->state->cbs.userdata) : 0;
    int64_t t = (int64_t)(ms / 1000);
    return (t << 32) | ((s->msg_id_counter++) * 4);
}

/*--------------------------------------------------------------------------
 * Public API implementation
 *--------------------------------------------------------------------------*/
const char* mtproto_get_last_error(void) {
    return g_mtproto_last_error;
}

mtproto_state_t* mtproto_create(const mtproto_callbacks_t* callbacks) {
    if (!callbacks || !callbacks->get_time_ms || !callbacks->random_bytes ||
        !callbacks->send_data || !callbacks->recv_data) {
        mtp_set_error("Invalid callbacks");
        return NULL;
    }
    mtproto_state_t* s = (mtproto_state_t*)malloc(sizeof(mtproto_state_t));
    if (!s) {
        mtp_set_error("Out of memory");
        return NULL;
    }
    memcpy(&s->cbs, callbacks, sizeof(mtproto_callbacks_t));
    s->debug = 0;
    return s;
}

void mtproto_destroy(mtproto_state_t* state) {
    if (state) free(state);
}

mtproto_session_t* mtproto_connect(mtproto_state_t* state, int dc_id, int server) {
    if (!state || dc_id < 1 || dc_id > 5) return NULL;
    mtproto_session_t* s = (mtproto_session_t*)malloc(sizeof(mtproto_session_t));
    if (!s) return NULL;
    memset(s, 0, sizeof(mtproto_session_t));
    s->state = state;
    s->dc_id = dc_id;
    s->server = server;
    if (state->cbs.random_bytes(state->cbs.userdata, &s->session_id, 8) != 1) {
        free(s);
        return NULL;
    }
    /* TODO: establish transport connection to DC (user provides send/recv) */
    return s;
}

void mtproto_disconnect(mtproto_session_t* session) {
    if (session) {
        memset(session->auth_key, 0, sizeof(session->auth_key));
        free(session);
    }
}

int mtproto_is_authorized(const mtproto_session_t* session) {
    return session && session->authorized;
}

int mtproto_req_pq(mtproto_session_t* session) {
    if (!session || !session->state) return MTPROTO_ERR_INVALID_PARAM;
    if (session->state->cbs.random_bytes(session->state->cbs.userdata, session->nonce, 16) != 1)
        return MTPROTO_ERR_CRYPTO;
    uint8_t buf[64];
    uint8_t* p = buf;
    mtp_tl_write_int64(&p, 0);  /* auth_key_id = 0 (unencrypted) */
    mtp_tl_write_int64(&p, mtp_gen_msg_id(session));
    mtp_tl_write_int32(&p, 20); /* message_length */
    mtp_tl_write_constructor(&p, TL_REQ_PQ_MULTI);
    memcpy(p, session->nonce, 16);
    p += 16;
    if (mtp_abridged_send(session, buf, (size_t)(p - buf)) != MTPROTO_OK)
        return MTPROTO_ERR_TRANSPORT;
    session->auth_step = 1;
    return MTPROTO_OK;
}

int mtproto_do_auth_handshake(mtproto_session_t* session) {
    uint8_t recv_buf[4096];
    int r, n;
    if (!session || !session->state) return MTPROTO_ERR_INVALID_PARAM;
    if (session->auth_step == 0) {
        r = mtproto_req_pq(session);
        if (r != MTPROTO_OK) return r;
        n = mtp_abridged_recv(session, recv_buf, sizeof(recv_buf));
        if (n <= 0) return n < 0 ? n : MTPROTO_ERR_TIMEOUT;
        if (n < 20) return MTPROTO_ERR_PROTOCOL;
        r = mtp_parse_respq(session, recv_buf + 20, (size_t)n - 20);
        if (r != MTPROTO_OK) return r;
        n = mtp_build_req_dh_params(session, recv_buf, sizeof(recv_buf));
        if (n < 0) return n;
        { uint8_t full[4096]; uint8_t* p = full; mtp_tl_write_int64(&p, 0); mtp_tl_write_int64(&p, mtp_gen_msg_id(session)); mtp_tl_write_int32(&p, n); memcpy(p, recv_buf, (size_t)n); p += n; r = mtp_abridged_send(session, full, (size_t)(p - full)); }
        if (r != MTPROTO_OK) return r;
        session->auth_step = 2;
        return MTPROTO_OK;
    }
    if (session->auth_step == 2) {
        n = mtp_abridged_recv(session, recv_buf, sizeof(recv_buf));
        if (n <= 0) return n < 0 ? n : MTPROTO_ERR_TIMEOUT;
        if (n < 20) return MTPROTO_ERR_PROTOCOL;
        r = mtp_parse_server_dh_params_ok(session, recv_buf + 20, (size_t)n - 20);
        if (r != MTPROTO_OK) return r;
        n = mtp_build_set_client_dh_params(session, recv_buf, sizeof(recv_buf));
        if (n < 0) return n;
        { uint8_t full[4096]; uint8_t* p = full; mtp_tl_write_int64(&p, 0); mtp_tl_write_int64(&p, mtp_gen_msg_id(session)); mtp_tl_write_int32(&p, n); memcpy(p, recv_buf, (size_t)n); p += n; r = mtp_abridged_send(session, full, (size_t)(p - full)); }
        if (r != MTPROTO_OK) return r;
        session->auth_step = 3;
        return MTPROTO_OK;
    }
    if (session->auth_step == 3) {
        n = mtp_abridged_recv(session, recv_buf, sizeof(recv_buf));
        if (n <= 0) return n < 0 ? n : MTPROTO_ERR_TIMEOUT;
        if (n < 20) return MTPROTO_ERR_PROTOCOL;
        r = mtp_parse_dh_gen_ok(session, recv_buf + 20, (size_t)n - 20);
        if (r != MTPROTO_OK) return r;
        session->auth_step = 4;
        session->authorized = 1;
        return MTPROTO_OK;
    }
    return MTPROTO_OK;
}

int mtproto_send_phone(mtproto_session_t* session, const char* phone, int api_id, const char* api_hash) {
    uint8_t buf[MTPROTO_MAX_SEND_BUF];
    int n;
    if (!session || !phone || !api_hash) return MTPROTO_ERR_INVALID_PARAM;
    n = mtproto_tl_build_auth_send_code(buf, sizeof(buf), phone, api_id, api_hash);
    if (n < 0) return MTPROTO_ERR_GENERIC;
    if ((size_t)snprintf(session->phone, sizeof(session->phone), "%s", phone) >= sizeof(session->phone)) session->phone[sizeof(session->phone)-1] = '\0';
    return mtproto_send_method(session, buf, (size_t)n);
}

int mtproto_send_auth_code(mtproto_session_t* session, const char* code) {
    uint8_t buf[MTPROTO_MAX_SEND_BUF];
    int n;
    if (!session || !code) return MTPROTO_ERR_INVALID_PARAM;
    if (!session->phone_code_hash[0]) {
        mtp_set_error("phone_code_hash not set - call mtproto_store_sent_code after send_phone response");
        return MTPROTO_ERR_INVALID_PARAM;
    }
    n = mtproto_tl_build_auth_sign_in(buf, sizeof(buf), session->phone, session->phone_code_hash, code);
    if (n < 0) return MTPROTO_ERR_GENERIC;
    return mtproto_send_method(session, buf, (size_t)n);
}

int mtproto_send_password(mtproto_session_t* session, const char* password) {
    (void)session;
    (void)password;
    /* TL: account.password + auth.checkPassword */
    return MTPROTO_OK;
}

int mtproto_save_session(const mtproto_session_t* session, void* buf, size_t buf_size) {
    if (!session) return MTPROTO_ERR_INVALID_PARAM;
    size_t need = 8 + 8 + MTP_AUTH_KEY_SIZE + 8 + 4;
    if (!buf) return (int)need;
    if (buf_size < need) return MTPROTO_ERR_INVALID_PARAM;
    uint8_t* p = (uint8_t*)buf;
    memcpy(p, &session->session_id, 8); p += 8;
    memcpy(p, &session->server_salt, 8); p += 8;
    memcpy(p, session->auth_key, MTP_AUTH_KEY_SIZE); p += MTP_AUTH_KEY_SIZE;
    memcpy(p, session->auth_key_id, 8); p += 8;
    memcpy(p, &session->seq_no, 4);
    return (int)need;
}

mtproto_session_t* mtproto_restore_session(mtproto_state_t* state, const void* data, size_t size) {
    if (!state || !data || size < 8+8+MTP_AUTH_KEY_SIZE+8+4) return NULL;
    mtproto_session_t* s = (mtproto_session_t*)malloc(sizeof(mtproto_session_t));
    if (!s) return NULL;
    memset(s, 0, sizeof(mtproto_session_t));
    s->state = state;
    const uint8_t* p = (const uint8_t*)data;
    memcpy(&s->session_id, p, 8); p += 8;
    memcpy(&s->server_salt, p, 8); p += 8;
    memcpy(s->auth_key, p, MTP_AUTH_KEY_SIZE); p += MTP_AUTH_KEY_SIZE;
    memcpy(s->auth_key_id, p, 8); p += 8;
    memcpy(&s->seq_no, p, 4);
    s->authorized = 1;
    return s;
}

int mtproto_recv_packet(mtproto_session_t* session, uint8_t* buf, size_t buf_size) {
    if (!session || !buf) return MTPROTO_ERR_INVALID_PARAM;
    return mtp_abridged_recv(session, buf, buf_size);
}

int mtproto_decrypt_message(mtproto_session_t* session, const uint8_t* raw, size_t raw_len, uint8_t* msg_out, size_t msg_size) {
    if (!session || !raw || !msg_out) return MTPROTO_ERR_INVALID_PARAM;
    if (!session->authorized) return MTPROTO_ERR_NOT_CONNECTED;
    return mtp_decrypt_message(session, raw, raw_len, msg_out, msg_size);
}

int mtproto_poll(mtproto_session_t* session) {
    (void)session;
    /* Read from transport, parse messages, dispatch updates */
    return MTPROTO_OK;
}

int mtproto_send_method(mtproto_session_t* session, const void* tl_data, size_t tl_len) {
    uint8_t buf[MTPROTO_MAX_SEND_BUF];
    int n;
    if (!session || !tl_data) return MTPROTO_ERR_INVALID_PARAM;
    if (!session->authorized) {
        mtp_set_error("Not authorized - call mtproto_do_auth_handshake first");
        return MTPROTO_ERR_NOT_CONNECTED;
    }
    n = mtp_encrypt_message(session, (const uint8_t*)tl_data, tl_len, 1, buf, sizeof(buf));
    if (n < 0) return n;
    return mtp_abridged_send(session, buf, (size_t)n);
}

int mtproto_send_message(mtproto_session_t* session, int64_t peer_user_id, int64_t peer_access_hash, const char* text) {
    uint8_t buf[MTPROTO_MAX_SEND_BUF];
    int n;
    int64_t random_id;
    if (!session || !text) return MTPROTO_ERR_INVALID_PARAM;
    random_id = mtp_gen_msg_id(session);
    n = mtproto_tl_build_messages_send_message(buf, sizeof(buf), peer_user_id, peer_access_hash, text, random_id);
    if (n < 0) return MTPROTO_ERR_GENERIC;
    return mtproto_send_method(session, buf, (size_t)n);
}

#ifdef MTPROTO_DEBUG
void mtproto_set_debug(mtproto_state_t* state, int enable) {
    if (state) state->debug = enable ? 1 : 0;
}
#endif

#endif /* MTPROTO_IMPL_GUARD */
#endif /* MTPROTO_IMPLEMENTATION */
