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
| req_pq, session save/restore | ✅ |
| auth.sendCode, auth.signIn, messages.sendMessage (TL builders) | ✅ |
| auth.sentCode, auth.authorization, rpc_error parsers | ✅ |
| Auth flow (resPQ → dh_gen_ok), abridged transport, encrypted messages | ⏳ In progress |

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

## License

MIT License
