# MTProto Library Examples

## Contents

- **minimal_client.c** - Minimal setup with all callbacks (time, random, send, recv, log)
- **echo_bot.c** - Skeleton echo bot: poll for updates, send messages back
- **platform_linux.c** - Linux-specific integration (POSIX sockets, /dev/urandom)
- **platform_windows.c** - Windows-specific (WinSock, CryptGenRandom) - see minimal_client.c for WinSock usage
- **platform_embedded.c** - Embedded-friendly (user provides HW RNG, custom transport)

## Building

```bash
gcc -std=c99 -DMTPROTO_IMPLEMENTATION -I.. examples/minimal_client.c -o minimal_client
gcc -std=c99 -DMTPROTO_IMPLEMENTATION -I.. examples/echo_bot.c -o echo_bot
gcc -std=c99 -DMTPROTO_IMPLEMENTATION -I.. examples/platform_linux.c -c -o platform_linux.o
```

## Platform Integration Guide

1. **get_time_ms**: Return milliseconds since Unix epoch. Use `clock_gettime`, `GetTickCount64`, or RTC.
2. **random_bytes**: Cryptographically secure entropy. Use `/dev/urandom`, `CryptGenRandom`, or hardware RNG.
3. **send_data / recv_data**: Raw TCP or custom transport. Connect to `149.154.167.50:443` (DC2) or use Telegram's IP list.
4. **log** (optional): Forward to your logging system.
5. **auth_callback** (optional): React to auth events (code sent, logged in, etc.).

## Telegram DC Addresses (Production)

- DC1: 149.154.175.50
- DC2: 149.154.167.50
- DC3: 149.154.175.100
- DC4: 149.154.167.91
- DC5: 91.108.56.151

Port: 443 (TCP), use TLS or MTProto proxy as needed.
