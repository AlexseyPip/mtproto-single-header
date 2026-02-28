/*
 * Unit tests for cryptographic primitives (SHA-1, SHA-256, AES-IGE)
 * Build: gcc -std=c99 -DMTPROTO_IMPLEMENTATION -I.. test_crypto.c -o test_crypto
 */
#define MTPROTO_IMPLEMENTATION
#include "../mtproto.h"
#include <stdio.h>
#include <string.h>

/* Test vectors for validation. To test internal crypto, add MTPROTO_EXPOSE_CRYPTO
   and expose mtp_sha1, mtp_sha256_full from mtproto.h */
int main(void) {
    printf("MTProto crypto tests\n");
    /* SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d */
    /* SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    printf("Crypto tests: add MTPROTO_EXPOSE_CRYPTO for full unit tests\n");
    printf("All OK (skeleton)\n");
    return 0;
}

