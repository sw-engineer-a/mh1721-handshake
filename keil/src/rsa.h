#ifndef RSA_H
#define RSA_H

#include <stdint.h>

/* 2048-bit RSA, PKCS#1 v1.5. Same padding as Android RSA/ECB/PKCS1Padding. */

int rsa_selftest(void);
int rsa_open(const uint8_t *cipher, int cipher_len, uint8_t *out, int out_cap);
int rsa_public_block(uint8_t *out, int cap);

#endif
