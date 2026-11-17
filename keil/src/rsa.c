#include "rsa.h"
#include "key.h"

#include <string.h>

#define RSA_LIMBS (RSA_BYTES / 4)

typedef struct {
    uint32_t v[RSA_LIMBS];
} bn;

static int bn_cmp(const bn *a, const bn *b) {
    int i;
    for (i = RSA_LIMBS - 1; i >= 0; i--) {
        if (a->v[i] > b->v[i]) {
            return 1;
        }
        if (a->v[i] < b->v[i]) {
            return -1;
        }
    }
    return 0;
}

static void bn_sub(bn *r, const bn *a, const bn *b) {
    uint64_t borrow = 0;
    int i;
    for (i = 0; i < RSA_LIMBS; i++) {
        uint64_t wide = (uint64_t)a->v[i] - b->v[i] - borrow;
        r->v[i] = (uint32_t)wide;
        borrow = (wide >> 63) & 1u;
    }
}

static void bn_from_be(bn *out, const uint8_t *in, int len) {
    int i;
    memset(out, 0, sizeof(*out));
    for (i = 0; i < len; i++) {
        int bit = (len - 1 - i) * 8;
        out->v[bit / 32] |= (uint32_t)in[i] << (bit % 32);
    }
}

static void bn_to_be(const bn *a, uint8_t *out) {
    int i;
    for (i = 0; i < RSA_BYTES; i++) {
        int bit = (RSA_BYTES - 1 - i) * 8;
        out[i] = (uint8_t)(a->v[bit / 32] >> (bit % 32));
    }
}

static uint32_t inv32(uint32_t n0) {
    uint32_t x = 1;
    int i;
    for (i = 0; i < 5; i++) {
        x *= 2u - n0 * x;
    }
    return 0u - x;
}

static void dbl_mod(bn *x, const bn *n) {
    uint64_t carry = 0;
    int j;
    for (j = 0; j < RSA_LIMBS; j++) {
        uint64_t wide = ((uint64_t)x->v[j] << 1) + carry;
        x->v[j] = (uint32_t)wide;
        carry = wide >> 32;
    }
    if (carry || bn_cmp(x, n) >= 0) {
        uint64_t borrow = 0;
        for (j = 0; j < RSA_LIMBS; j++) {
            uint64_t wide = (uint64_t)x->v[j] - n->v[j] - borrow;
            x->v[j] = (uint32_t)wide;
            borrow = (wide >> 63) & 1u;
        }
        carry -= borrow;
    }
    if (carry || bn_cmp(x, n) >= 0) {
        bn_sub(x, x, n);
    }
}

static void mont_r2(bn *r2, const bn *n) {
    int i;
    memset(r2, 0, sizeof(*r2));
    r2->v[0] = 1;
    for (i = 0; i < RSA_BYTES * 16; i++) {
        dbl_mod(r2, n);
    }
}

static void mont_mul(bn *r, const bn *a, const bn *b, const bn *n, uint32_t n0inv) {
    uint32_t t[RSA_LIMBS + 2];
    int i;
    int j;
    memset(t, 0, sizeof(t));
    for (i = 0; i < RSA_LIMBS; i++) {
        uint64_t carry = 0;
        uint32_t m;
        for (j = 0; j < RSA_LIMBS; j++) {
            carry += (uint64_t)t[j] + (uint64_t)a->v[j] * b->v[i];
            t[j] = (uint32_t)carry;
            carry >>= 32;
        }
        carry += t[RSA_LIMBS];
        t[RSA_LIMBS] = (uint32_t)carry;
        t[RSA_LIMBS + 1] = (uint32_t)(carry >> 32);

        m = t[0] * n0inv;
        carry = (uint64_t)t[0] + (uint64_t)m * n->v[0];
        carry >>= 32;
        for (j = 1; j < RSA_LIMBS; j++) {
            carry += (uint64_t)t[j] + (uint64_t)m * n->v[j];
            t[j - 1] = (uint32_t)carry;
            carry >>= 32;
        }
        carry += t[RSA_LIMBS];
        t[RSA_LIMBS - 1] = (uint32_t)carry;
        carry >>= 32;
        t[RSA_LIMBS] = t[RSA_LIMBS + 1] + (uint32_t)carry;
        t[RSA_LIMBS + 1] = 0;
    }
    memcpy(r->v, t, sizeof(r->v));
    if (t[RSA_LIMBS] || bn_cmp(r, n) >= 0) {
        bn_sub(r, r, n);
    }
}

static int modexp(const bn *base, const bn *exp, const bn *mod, bn *out) {
    bn r2;
    bn a;
    bn x;
    bn one;
    uint32_t n0inv;
    int bits;
    int i;
    if ((mod->v[0] & 1u) == 0 || bn_cmp(base, mod) >= 0) {
        return -1;
    }
    n0inv = inv32(mod->v[0]);
    mont_r2(&r2, mod);
    memset(&one, 0, sizeof(one));
    one.v[0] = 1;
    mont_mul(&a, &one, &r2, mod, n0inv);
    mont_mul(&x, base, &r2, mod, n0inv);
    bits = RSA_BYTES * 8;
    while (bits > 0) {
        uint32_t limb = exp->v[(bits - 1) >> 5];
        if ((limb >> ((bits - 1) & 31)) & 1u) {
            break;
        }
        bits--;
    }
    for (i = bits - 1; i >= 0; i--) {
        bn sq;
        mont_mul(&sq, &a, &a, mod, n0inv);
        a = sq;
        if ((exp->v[i >> 5] >> (i & 31)) & 1u) {
            bn prod;
            mont_mul(&prod, &a, &x, mod, n0inv);
            a = prod;
        }
    }
    memset(&one, 0, sizeof(one));
    one.v[0] = 1;
    mont_mul(out, &a, &one, mod, n0inv);
    return 0;
}

static int modexp_be(const uint8_t *base, int base_len, const uint8_t *exp, int exp_len,
                     uint8_t out[RSA_BYTES]) {
    bn b;
    bn e;
    bn n;
    bn m;
    bn_from_be(&b, base, base_len);
    bn_from_be(&e, exp, exp_len);
    bn_from_be(&n, RSA_N, RSA_BYTES);
    if (modexp(&b, &e, &n, &m) != 0) {
        return -1;
    }
    bn_to_be(&m, out);
    return 0;
}

int rsa_open(const uint8_t *cipher, int cipher_len, uint8_t *out, int out_cap) {
    uint8_t em[RSA_BYTES];
    int i;
    int msg_len;
    if (!cipher || !out || cipher_len != RSA_BYTES) {
        return -1;
    }
    if (modexp_be(cipher, cipher_len, RSA_D, (int)sizeof(RSA_D), em) != 0) {
        return -1;
    }
    if (em[0] != 0x00 || em[1] != 0x02) {
        return -1;
    }
    i = 2;
    while (i < RSA_BYTES && em[i] != 0) {
        i++;
    }
    if (i < 10 || i >= RSA_BYTES) {
        return -1;
    }
    msg_len = RSA_BYTES - (i + 1);
    if (msg_len > out_cap) {
        return -1;
    }
    if (msg_len > 0) {
        memcpy(out, em + i + 1, (size_t)msg_len);
    }
    return msg_len;
}

int rsa_public_block(uint8_t *out, int cap) {
    int elen = (int)sizeof(RSA_E);
    int total = 2 + RSA_BYTES + 2 + elen;
    if (!out || cap < total) {
        return -1;
    }
    out[0] = (uint8_t)(RSA_BYTES >> 8);
    out[1] = (uint8_t)RSA_BYTES;
    memcpy(out + 2, RSA_N, RSA_BYTES);
    out[2 + RSA_BYTES] = (uint8_t)(elen >> 8);
    out[3 + RSA_BYTES] = (uint8_t)elen;
    memcpy(out + 4 + RSA_BYTES, RSA_E, (size_t)elen);
    return total;
}

int rsa_selftest(void) {
    uint8_t got[RSA_BYTES];
    uint8_t msg[32];
    int n;
    if (sizeof(RSA_N) != RSA_BYTES || sizeof(RSA_D) != RSA_BYTES) {
        return 0;
    }
    if (modexp_be(RSA_SELF_CIPHER, RSA_BYTES, RSA_D, (int)sizeof(RSA_D), got) != 0) {
        return 0;
    }
    if (memcmp(got, RSA_SELF_EM, RSA_BYTES) != 0) {
        return 0;
    }
    if (modexp_be(RSA_SELF_EM, RSA_BYTES, RSA_E, (int)sizeof(RSA_E), got) != 0) {
        return 0;
    }
    if (memcmp(got, RSA_SELF_CIPHER, RSA_BYTES) != 0) {
        return 0;
    }
    n = rsa_open(RSA_SELF_CIPHER, RSA_BYTES, msg, (int)sizeof(msg));
    return n == (int)sizeof(RSA_SELF_MSG) && memcmp(msg, RSA_SELF_MSG, sizeof(RSA_SELF_MSG)) == 0;
}
