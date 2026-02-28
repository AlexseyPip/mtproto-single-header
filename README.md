# mtproto.h

Single-file header-only C library for the MTProto protocol (Telegram messaging).

**Goal:** simplify porting of Telegram clients to any platform — from bare-metal and custom OS to embedded systems. No external dependencies; all platform-specific code is abstracted behind callbacks.

---

## Independence & Portability

| Requirement | Status |
|-------------|--------|
| **External libs** | None — only standard C library (memcpy, memset, malloc/free) |
| **OS APIs** | None — user provides send/recv, time, random via callbacks |
| **C runtime** | C99 minimum; optional: `MTPROTO_CUSTOM_ALLOC` for user malloc |
| **Targets** | Linux, Windows, macOS, bare-metal, RTOS, custom kernels |

### Minimal platform layer (user implements)

```c
/* Only 4 callbacks required */
uint64_t get_time_ms(void* ud);           /* Milliseconds since Unix epoch */
int      random_bytes(void* ud, void* buf, size_t n);  /* CSPRNG */
int      send_data(void* ud, const void* buf, size_t n);  /* Raw byte stream */
int      recv_data(void* ud, void* buf, size_t n);     /* Raw byte stream */
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
cbs.get_time_ms  = my_get_time;
cbs.random_bytes = my_random;
cbs.send_data    = my_send;
cbs.recv_data    = my_recv;

mtproto_state_t*  state   = mtproto_create(&cbs);
mtproto_session_t* session = mtproto_connect(state, 2, MTPROTO_SERVER_PRODUCTION);
```

---

## Structure

```
mtproto.h       — library (declarations + implementation)
tests/          — crypto, protocol, integration tests
examples/       — minimal client, echo bot, platform stubs
```

---

## Build

```bash
gcc -std=c99 -DMTPROTO_IMPLEMENTATION -I. your_app.c -o your_app
```

For custom allocator (embedded/RTOS):
```c
#define MTPROTO_CUSTOM_ALLOC
#define MTPROTO_MALLOC(sz)   my_malloc(sz)
#define MTPROTO_FREE(ptr)    my_free(ptr)
#define MTPROTO_IMPLEMENTATION
#include "mtproto.h"
```

---

## Current status

Library is in **development**. See `ROADMAP.md` for what is implemented and what remains for a minimal working client.

---

## License

MIT License
