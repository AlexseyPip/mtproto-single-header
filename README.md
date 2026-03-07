# mtproto-single-header

Single-file header-only C library for the MTProto protocol (Telegram messaging).

**Goal:** simplify porting of Telegram clients to any platform — from bare-metal and custom OS to embedded systems. No external dependencies; all platform-specific code is abstracted behind callbacks.

---

## Independence & Portability

| Requirement | Status |
|-------------|--------|
| **External libs** | None — only standard C library (memcpy, memset, malloc/free) |
| **OS APIs** | None — user provides send/recv, time, random via callbacks |
| **C runtime** | C99 minimum |
| **Targets** | Linux, Windows, macOS, bare-metal, RTOS, custom kernels |

### Minimal platform layer (user implements)

```c
uint64_t get_time_ms(void* ud);                    /* Milliseconds since Unix epoch */
int      random_bytes(void* ud, void* buf, size_t n);   /* CSPRNG */
int      send_data(void* ud, const void* buf, size_t n); /* Raw byte stream */
int      recv_data(void* ud, void* buf, size_t n);      /* Raw byte stream */
```

User owns: TCP/socket, TLS (if used), `/dev/urandom` or HW RNG, RTC or `time()`. The library only sends/receives bytes.

Optional `connect_to_dc` callback: the library calls it before creating a session. Use `mtproto_get_dc_address(dc_id, server, host, host_size, &port)` to get DC host/port, then establish TCP and wire `send_data`/`recv_data` to that socket. See `examples/platform_linux.c` for POSIX.

---

## Usage

**One .c file:**
```c
#define MTPROTO_IMPLEMENTATION
#include "mtproto.h"
```

**Other files:**
```c
#include "mtproto.h"
```

**Minimal setup:**
```c
mtproto_callbacks_t cbs = {0};
cbs.get_time_ms   = my_get_time;
cbs.random_bytes  = my_random;
cbs.send_data     = my_send;
cbs.recv_data     = my_recv;

mtproto_state_t*   state   = mtproto_create(&cbs);
mtproto_session_t* session = mtproto_connect(state, 2, MTPROTO_SERVER_PRODUCTION);
```

---

## Implemented

| Component | Status |
|-----------|--------|
| SHA-1, SHA-256 | ✅ |
| AES-256 encrypt/decrypt, IGE mode | ✅ |
| Big integer (2048-bit), RSA, DH | ✅ |
| RSA encrypt (MTProto OAEP+), Telegram production key | ✅ |
| req_pq, session save/restore (dc_id persisted) | ✅ |
| auth.sendCode, auth.signIn, messages.sendMessage (TL builders) | ✅ |
| initConnection + invokeWithLayer wrapper (first API call) | ✅ |
| auth.sentCode, auth.authorization, rpc_error parsers | ✅ |
| bad_server_salt handler, dh_gen_retry / dh_gen_fail | ✅ |
| Abridged transport (MTProto framing) | ✅ |
| Full auth flow (req_pq → resPQ → req_DH_params → dh_gen_ok) | ✅ |
| MTProto 2.0 encrypted messages (msg_key, envelope) | ✅ |
| mtproto_poll (recv → decrypt → auth callbacks) | ✅ |
| MTPROTO_CUSTOM_ALLOC (optional malloc/free) | ✅ |

---

## Structure

```
mtproto.h       — library (declarations + implementation)
ROADMAP.md      — implementation status and remaining work
tests/          — crypto, protocol tests
examples/       — minimal client, echo bot, platform stubs
```

---

## Build

```bash
gcc -std=c99 -DMTPROTO_IMPLEMENTATION -I. your_app.c -o your_app
```

---

## API Reference (selected)

| Function | Description |
|----------|-------------|
| `mtproto_create` | Create state with callbacks |
| `mtproto_connect` | Create session for DC (1–5), connect TCP via callback |
| `mtproto_do_auth_handshake` | Run DH auth (req_pq → dh_gen_ok) |
| `mtproto_send_phone` | Send phone, initConnection-wrapped |
| `mtproto_send_auth_code` | Sign in with SMS code |
| `mtproto_send_method` | Send arbitrary TL method (encrypted) |
| `mtproto_poll` | Recv one packet, decrypt, handle auth/service, optional app msg output |
| `mtproto_handle_bad_server_salt` | Update salt and retry on bad_server_salt |
| `mtproto_save_session` | Save auth_key, server_salt, dc_id |
| `mtproto_restore_session` | Restore from saved blob |

**Error codes:** `MTPROTO_ERR_RETRY_SALT` — bad_server_salt handled, retry last request.

**Optional:** Define `MTPROTO_MALLOC`/`MTPROTO_FREE` before including for custom allocator.

---

## License

MIT License
