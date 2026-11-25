#include "rsa.h"
#include "key.h"
#include "mh_rsa.h"
#include "mh_misc.h"

#include <stddef.h>
#include <string.h>

static void seal_key(MH_RSA_KEY *key)
{
    key->u32Crc = MHCRC_CalcBuff(0xffff, key, (uint32_t)offsetof(MH_RSA_KEY, u32Crc));
}

static void seal_call(MH_RSA_CALL *call)
{
    call->u32Crc = MHCRC_CalcBuff(0xffff, call, (uint32_t)offsetof(MH_RSA_CALL, u32Crc));
}

static uint32_t load_key(MH_RSA_KEY *key, MH_RSA_KEY_SPACE *space)
{
    uint8_t n[RSA_BYTES];
    uint8_t e[RSA_E_BYTES];
    uint8_t d[RSA_BYTES];
    uint8_t p[RSA_BYTES / 2];
    uint8_t q[RSA_BYTES / 2];
    uint8_t dp[RSA_BYTES / 2];
    uint8_t dq[RSA_BYTES / 2];
    uint8_t qi[RSA_BYTES / 2];

    memcpy(n, RSA_N, sizeof(n));
    memcpy(e, RSA_E, sizeof(e));
    memcpy(d, RSA_D, sizeof(d));
    memcpy(p, RSA_P, sizeof(p));
    memcpy(q, RSA_Q, sizeof(q));
    memcpy(dp, RSA_DP, sizeof(dp));
    memcpy(dq, RSA_DQ, sizeof(dq));
    memcpy(qi, RSA_QI, sizeof(qi));

    memset(key, 0, sizeof(*key));
    key->u16NBits = RSA_N_BITS;
    key->u16EBits = RSA_E_BITS;
    key->pu8N = n;
    key->pu8E = e;
    key->pu8D = d;
    key->pu8P = p;
    key->pu8Q = q;
    key->pu8Dp = dp;
    key->pu8Dq = dq;
    key->pu8Qi = qi;
    seal_key(key);
    return MHRSA_SetKey(key, space, 0);
}

static int raw_private(const uint8_t *cipher, int cipher_len, uint8_t *out, int out_cap)
{
    MH_RSA_KEY key;
    MH_RSA_KEY_SPACE space;
    MH_RSA_CALL call;
    uint32_t ret;

    if (!cipher || !out || cipher_len != RSA_BYTES || out_cap < RSA_BYTES) {
        return -1;
    }
    if (load_key(&key, &space) != MH_RET_RSA_SUCCESS) {
        return -1;
    }
    memset(&call, 0, sizeof(call));
    call.pu8Input = (uint8_t *)cipher;
    call.pu8Output = out;
    call.u32InLen = (uint32_t)RSA_BYTES;
    call.KeyBase = &space;
    seal_call(&call);
    ret = MHRSA_Crt(&call);
    if (ret != MH_RET_RSA_SUCCESS || call.u32OutLen != (uint32_t)RSA_BYTES) {
        return -1;
    }
    return RSA_BYTES;
}

int rsa_open(const uint8_t *cipher, int cipher_len, uint8_t *out, int out_cap)
{
    return raw_private(cipher, cipher_len, out, out_cap);
}

int rsa_public_block(uint8_t *out, int cap)
{
    int total = 2 + RSA_BYTES + 2 + RSA_E_BYTES;
    if (!out || cap < total) {
        return -1;
    }
    out[0] = (uint8_t)(RSA_BYTES >> 8);
    out[1] = (uint8_t)RSA_BYTES;
    memcpy(out + 2, RSA_N, RSA_BYTES);
    out[2 + RSA_BYTES] = (uint8_t)(RSA_E_BYTES >> 8);
    out[3 + RSA_BYTES] = (uint8_t)RSA_E_BYTES;
    memcpy(out + 4 + RSA_BYTES, RSA_E, RSA_E_BYTES);
    return total;
}

int rsa_selftest(void)
{
    MH_RSA_KEY key;
    MH_RSA_KEY_SPACE space;
    MH_RSA_CALL call;
    uint8_t cipher[RSA_BYTES];
    uint8_t plain[RSA_BYTES];

    if (load_key(&key, &space) != MH_RET_RSA_SUCCESS) {
        return 0;
    }
    memset(&call, 0, sizeof(call));
    call.pu8Input = (uint8_t *)RSA_PLAIN;
    call.pu8Output = cipher;
    call.u32InLen = RSA_BYTES;
    call.KeyBase = &space;
    seal_call(&call);
    if (MHRSA_Pub(&call) != MH_RET_RSA_SUCCESS || memcmp(cipher, RSA_CIPHER, RSA_BYTES) != 0) {
        return 0;
    }
    call.pu8Input = cipher;
    call.pu8Output = plain;
    call.u32InLen = RSA_BYTES;
    seal_call(&call);
    if (MHRSA_Pri(&call) != MH_RET_RSA_SUCCESS || memcmp(plain, RSA_PLAIN, RSA_BYTES) != 0) {
        return 0;
    }
    if (rsa_open(RSA_CIPHER, RSA_BYTES, plain, RSA_BYTES) != RSA_BYTES) {
        return 0;
    }
    return memcmp(plain, RSA_PLAIN, RSA_BYTES) == 0;
}
