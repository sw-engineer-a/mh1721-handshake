#ifndef RSA_H
#define RSA_H

#include <stdint.h>

/*
 * Same parameter sizes as mh-rsa MHRSA_Pub / MHRSA_Pri / MHRSA_Crt.
 * Input and output are RSA_BYTES (64). The public exponent is RSA_E_BYTES (4).
 * No PKCS#1 padding.
 */

int rsa_selftest(void);
int rsa_open(const uint8_t *cipher, int cipher_len, uint8_t *out, int out_cap);
int rsa_public_block(uint8_t *out, int cap);

#endif
