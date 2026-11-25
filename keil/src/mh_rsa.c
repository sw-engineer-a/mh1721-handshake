#include "mh_rsa.h"
#include "mh_misc.h"
#include "mh_rand.h"

#include <stddef.h>
#include <string.h>

#define BN_LIMBS 140
#define MAGIC 0x52534131u

typedef struct {
    uint32_t n;
    uint32_t d[BN_LIMBS];
} bn_t;

typedef struct {
    int neg;
    bn_t n;
} zi_t;

typedef struct {
    int used;
    bn_t n, e, d, p, q, dp, dq, qi;
    int has_crt;
    uint16_t nbits;
    uint16_t ebits;
} slot_t;

static slot_t g_slot[1];

static void bn_zero(bn_t *a)
{
    a->n = 0;
}

static void bn_norm(bn_t *a)
{
    while (a->n > 0 && a->d[a->n - 1] == 0) {
        a->n--;
    }
}

static void bn_set_u32(bn_t *a, uint32_t v)
{
    bn_zero(a);
    if (v) {
        a->d[0] = v;
        a->n = 1;
    }
}

static int bn_cmp(const bn_t *a, const bn_t *b)
{
    uint32_t i;
    if (a->n != b->n) {
        return a->n > b->n ? 1 : -1;
    }
    for (i = a->n; i-- > 0;) {
        if (a->d[i] != b->d[i]) {
            return a->d[i] > b->d[i] ? 1 : -1;
        }
    }
    return 0;
}

static void bn_add(bn_t *r, const bn_t *a, const bn_t *b)
{
    uint32_t i;
    uint32_t n;
    uint64_t c = 0;
    n = a->n > b->n ? a->n : b->n;
    for (i = 0; i < n; i++) {
        uint64_t v = c;
        if (i < a->n) {
            v += a->d[i];
        }
        if (i < b->n) {
            v += b->d[i];
        }
        r->d[i] = (uint32_t)v;
        c = v >> 32;
    }
    if (c) {
        r->d[n++] = (uint32_t)c;
    }
    r->n = n;
}

static void bn_sub(bn_t *r, const bn_t *a, const bn_t *b)
{
    uint32_t i;
    uint32_t borrow = 0;
    for (i = 0; i < a->n; i++) {
        uint64_t av = a->d[i];
        uint64_t bv = (i < b->n ? b->d[i] : 0) + borrow;
        if (av < bv) {
            r->d[i] = (uint32_t)(av + (1ull << 32) - bv);
            borrow = 1;
        } else {
            r->d[i] = (uint32_t)(av - bv);
            borrow = 0;
        }
    }
    r->n = a->n;
    bn_norm(r);
}

static void bn_mul(bn_t *r, const bn_t *a, const bn_t *b)
{
    uint32_t i, j, k;
    uint32_t tmp[BN_LIMBS];
    uint32_t n = 0;
    memset(tmp, 0, sizeof(tmp));
    for (i = 0; i < a->n; i++) {
        uint64_t c = 0;
        for (j = 0; j < b->n; j++) {
            k = i + j;
            if (k >= BN_LIMBS) {
                break;
            }
            {
                uint64_t v = (uint64_t)tmp[k] + (uint64_t)a->d[i] * b->d[j] + c;
                tmp[k] = (uint32_t)v;
                c = v >> 32;
            }
        }
        k = i + b->n;
        while (c && k < BN_LIMBS) {
            uint64_t v = (uint64_t)tmp[k] + c;
            tmp[k] = (uint32_t)v;
            c = v >> 32;
            k++;
        }
    }
    for (i = 0; i < BN_LIMBS; i++) {
        r->d[i] = tmp[i];
        if (tmp[i]) {
            n = i + 1;
        }
    }
    r->n = n;
}

static int bn_bit(const bn_t *a, uint32_t i)
{
    uint32_t limb = i >> 5;
    if (limb >= a->n) {
        return 0;
    }
    return (int)((a->d[limb] >> (i & 31)) & 1u);
}

static uint32_t bn_bits(const bn_t *a)
{
    uint32_t v;
    uint32_t b;
    if (a->n == 0) {
        return 0;
    }
    v = a->d[a->n - 1];
    b = (a->n - 1) * 32;
    while (v) {
        v >>= 1;
        b++;
    }
    return b;
}

static void bn_shl1(bn_t *a)
{
    uint32_t c = 0;
    uint32_t i;
    for (i = 0; i < a->n; i++) {
        uint32_t v = a->d[i];
        a->d[i] = (v << 1) | c;
        c = v >> 31;
    }
    if (c && a->n < BN_LIMBS) {
        a->d[a->n++] = c;
    }
}

static void bn_shr1(bn_t *a)
{
    uint32_t i;
    uint32_t c = 0;
    if (a->n == 0) {
        return;
    }
    for (i = a->n; i-- > 0;) {
        uint32_t v = a->d[i];
        a->d[i] = (v >> 1) | (c << 31);
        c = v & 1u;
    }
    bn_norm(a);
}

static void bn_divmod(bn_t *q, bn_t *rem, const bn_t *u, const bn_t *v)
{
    bn_t qq, rr;
    int bit;
    bn_zero(&qq);
    bn_zero(&rr);
    if (v->n == 0) {
        if (q) {
            *q = qq;
        }
        if (rem) {
            *rem = rr;
        }
        return;
    }
    for (bit = (int)bn_bits(u) - 1; bit >= 0; bit--) {
        bn_shl1(&rr);
        if (bn_bit(u, (uint32_t)bit)) {
            if (rr.n == 0) {
                rr.d[0] = 1;
                rr.n = 1;
            } else {
                rr.d[0] |= 1u;
            }
        }
        if (bn_cmp(&rr, v) >= 0) {
            bn_sub(&rr, &rr, v);
            {
                uint32_t limb = (uint32_t)bit >> 5;
                uint32_t mask = 1u << (bit & 31);
                if (qq.n <= limb) {
                    uint32_t k;
                    for (k = qq.n; k <= limb; k++) {
                        qq.d[k] = 0;
                    }
                    qq.n = limb + 1;
                }
                qq.d[limb] |= mask;
            }
        }
    }
    bn_norm(&qq);
    if (q) {
        *q = qq;
    }
    if (rem) {
        *rem = rr;
    }
}

static void bn_mod(bn_t *r, const bn_t *a, const bn_t *m)
{
    bn_divmod(NULL, r, a, m);
}

static void bn_from_be(bn_t *a, const uint8_t *p, uint32_t len)
{
    uint32_t i;
    bn_zero(a);
    for (i = 0; i < len; i++) {
        uint32_t from_end = len - 1u - i;
        uint32_t limb = from_end >> 2;
        uint32_t shift = (from_end & 3u) * 8u;
        if (limb >= BN_LIMBS) {
            continue;
        }
        a->d[limb] |= (uint32_t)p[i] << shift;
        if (a->n < limb + 1u) {
            a->n = limb + 1u;
        }
    }
    bn_norm(a);
}

static void bn_to_be(uint8_t *p, uint32_t len, const bn_t *a)
{
    uint32_t i;
    memset(p, 0, len);
    for (i = 0; i < len; i++) {
        uint32_t from_end = len - 1u - i;
        uint32_t limb = from_end >> 2;
        uint32_t shift = (from_end & 3u) * 8u;
        if (limb < a->n) {
            p[i] = (uint8_t)(a->d[limb] >> shift);
        }
    }
}

static void bn_modexp(bn_t *r, const bn_t *base, const bn_t *exp, const bn_t *mod)
{
    bn_t result, b, e;
    bn_set_u32(&result, 1);
    bn_mod(&b, base, mod);
    e = *exp;
    while (e.n) {
        if (e.d[0] & 1u) {
            bn_t t;
            bn_mul(&t, &result, &b);
            bn_mod(&result, &t, mod);
        }
        bn_shr1(&e);
        if (e.n) {
            bn_t t;
            bn_mul(&t, &b, &b);
            bn_mod(&b, &t, mod);
        }
    }
    *r = result;
}

static void bn_gcd(bn_t *g, const bn_t *aa, const bn_t *bb)
{
    bn_t a = *aa;
    bn_t b = *bb;
    while (b.n) {
        bn_t r;
        bn_mod(&r, &a, &b);
        a = b;
        b = r;
    }
    *g = a;
}

static void zi_from_bn(zi_t *z, const bn_t *n, int neg)
{
    z->n = *n;
    z->neg = (neg && n->n) ? 1 : 0;
}

static void zi_sub(zi_t *r, const zi_t *a, const zi_t *b)
{
    if (a->neg == b->neg) {
        if (bn_cmp(&a->n, &b->n) >= 0) {
            bn_sub(&r->n, &a->n, &b->n);
            r->neg = a->neg && r->n.n;
        } else {
            bn_sub(&r->n, &b->n, &a->n);
            r->neg = !a->neg && r->n.n;
        }
    } else {
        bn_add(&r->n, &a->n, &b->n);
        r->neg = a->neg && r->n.n;
    }
}

static int bn_modinv(bn_t *inv, const bn_t *aa, const bn_t *mm)
{
    bn_t r0 = *mm;
    bn_t r1;
    zi_t s0, s1;
    bn_t one;
    bn_mod(&r1, aa, mm);
    bn_set_u32(&one, 1);
    bn_zero(&s0.n);
    s0.neg = 0;
    zi_from_bn(&s1, &one, 0);
    while (r1.n) {
        bn_t q, r;
        zi_t prod, next, tmp;
        bn_divmod(&q, &r, &r0, &r1);
        r0 = r1;
        r1 = r;
        bn_mul(&prod.n, &q, &s1.n);
        prod.neg = s1.neg && prod.n.n;
        zi_sub(&next, &s0, &prod);
        tmp = s1;
        s1 = next;
        s0 = tmp;
    }
    if (bn_cmp(&r0, &one) != 0) {
        return -1;
    }
    if (s0.neg) {
        bn_mod(&s0.n, &s0.n, mm);
        if (s0.n.n == 0) {
            bn_zero(inv);
        } else {
            bn_sub(inv, mm, &s0.n);
        }
    } else {
        bn_mod(inv, &s0.n, mm);
    }
    return 0;
}

static uint32_t nbytes(uint16_t bits)
{
    return ((uint32_t)bits + 7u) >> 3;
}

static uint32_t hbytes(uint16_t bits)
{
    return ((uint32_t)bits + 15u) >> 4;
}

static uint32_t key_prefix(void)
{
    return (uint32_t)offsetof(MH_RSA_KEY, u32Crc);
}

static int crc_key(const MH_RSA_KEY *k)
{
    return MHCRC_CalcBuff(0xffff, k, key_prefix()) == k->u32Crc;
}

static int crc_call(const MH_RSA_CALL *c)
{
    /* CRC covers the call up to, but not including, u32Crc. KeyBase follows u32Crc. */
    uint32_t len = (uint32_t)((const uint8_t *)&c->u32Crc - (const uint8_t *)c);
    return MHCRC_CalcBuff(0xffff, c, len) == c->u32Crc;
}

static slot_t *slot_of(MH_RSA_KEY_SPACE *base, int create)
{
    if (!base) {
        return NULL;
    }
    if (base->au32Reserve[1] != MAGIC) {
        if (!create) {
            return NULL;
        }
        memset(&g_slot[0], 0, sizeof(g_slot[0]));
        g_slot[0].used = 1;
        base->au32Reserve[0] = 0;
        base->au32Reserve[1] = MAGIC;
    }
    return &g_slot[0];
}

static void load_key(slot_t *s, const MH_RSA_KEY *k)
{
    memset(s, 0, sizeof(*s));
    s->used = 1;
    s->nbits = k->u16NBits;
    s->ebits = k->u16EBits;
    if (k->pu8N) {
        bn_from_be(&s->n, k->pu8N, nbytes(k->u16NBits));
    }
    if (k->pu8E && k->u16EBits) {
        bn_from_be(&s->e, k->pu8E, nbytes(k->u16EBits));
    }
    if (k->pu8D) {
        bn_from_be(&s->d, k->pu8D, nbytes(k->u16NBits));
    }
    if (k->pu8P) {
        bn_from_be(&s->p, k->pu8P, hbytes(k->u16NBits));
    }
    if (k->pu8Q) {
        bn_from_be(&s->q, k->pu8Q, hbytes(k->u16NBits));
    }
    if (k->pu8Dp) {
        bn_from_be(&s->dp, k->pu8Dp, hbytes(k->u16NBits));
    }
    if (k->pu8Dq) {
        bn_from_be(&s->dq, k->pu8Dq, hbytes(k->u16NBits));
    }
    if (k->pu8Qi) {
        bn_from_be(&s->qi, k->pu8Qi, hbytes(k->u16NBits));
    }
    s->has_crt = s->p.n && s->q.n && s->dp.n && s->dq.n && s->qi.n;
}

static void store_bytes(uint8_t *dst, uint32_t len, const bn_t *a)
{
    if (dst) {
        bn_to_be(dst, len, a);
    }
}

static int fill_crt(slot_t *s)
{
    bn_t pm1, qm1;
    if (s->p.n == 0 || s->q.n == 0 || s->d.n == 0) {
        return -1;
    }
    bn_set_u32(&pm1, 1);
    bn_sub(&pm1, &s->p, &pm1);
    bn_set_u32(&qm1, 1);
    bn_sub(&qm1, &s->q, &qm1);
    bn_mod(&s->dp, &s->d, &pm1);
    bn_mod(&s->dq, &s->d, &qm1);
    if (bn_modinv(&s->qi, &s->q, &s->p) != 0) {
        return -1;
    }
    s->has_crt = 1;
    return 0;
}

static int derive_d(slot_t *s)
{
    bn_t pm1, qm1, g, phi, t;
    bn_t one;
    if (s->p.n == 0 || s->q.n == 0 || s->e.n == 0) {
        return -1;
    }
    bn_mul(&s->n, &s->p, &s->q);
    bn_set_u32(&one, 1);
    bn_sub(&pm1, &s->p, &one);
    bn_sub(&qm1, &s->q, &one);
    bn_gcd(&g, &pm1, &qm1);
    bn_divmod(&t, NULL, &pm1, &g);
    bn_mul(&phi, &t, &qm1);
    bn_gcd(&g, &s->e, &phi);
    if (bn_cmp(&g, &one) != 0) {
        return -2;
    }
    if (bn_modinv(&s->d, &s->e, &phi) != 0) {
        return -1;
    }
    return fill_crt(s);
}

static int derive_e(slot_t *s)
{
    bn_t pm1, qm1, g, phi, t, one;
    if (s->p.n == 0 || s->q.n == 0 || s->d.n == 0) {
        return -1;
    }
    if (s->n.n == 0) {
        bn_mul(&s->n, &s->p, &s->q);
    }
    bn_set_u32(&one, 1);
    bn_sub(&pm1, &s->p, &one);
    bn_sub(&qm1, &s->q, &one);
    bn_gcd(&g, &pm1, &qm1);
    bn_divmod(&t, NULL, &pm1, &g);
    bn_mul(&phi, &t, &qm1);
    if (bn_modinv(&s->e, &s->d, &phi) != 0) {
        return -1;
    }
    s->ebits = (uint16_t)bn_bits(&s->e);
    if (s->ebits < 17) {
        s->ebits = 32;
    }
    return fill_crt(s);
}

static int small_prime(uint32_t x)
{
    uint32_t d;
    if (x < 2) {
        return 0;
    }
    for (d = 2; d * d <= x; d++) {
        if (x % d == 0) {
            return 0;
        }
    }
    return 1;
}

static int trial(const bn_t *n)
{
    static uint32_t pr[200];
    static int ready;
    int i;
    int count = 0;
    if (!ready) {
        uint32_t x;
        for (x = 2; x < 1200 && count < 200; x++) {
            if (small_prime(x)) {
                pr[count++] = x;
            }
        }
        ready = 1;
    }
    for (i = 0; i < 200 && pr[i]; i++) {
        bn_t p, r;
        bn_set_u32(&p, pr[i]);
        if (bn_cmp(n, &p) == 0) {
            return 1;
        }
        bn_mod(&r, n, &p);
        if (r.n == 0) {
            return 0;
        }
    }
    return 1;
}

static int miller_rabin(const bn_t *n)
{
    bn_t d, one, n1, a, x;
    uint32_t s = 0;
    int round;
    static const uint32_t bases[] = {2, 3, 5, 7, 11, 13, 23, 29};
    if (n->n == 0 || (n->d[0] & 1u) == 0) {
        return 0;
    }
    bn_set_u32(&one, 1);
    bn_sub(&n1, n, &one);
    d = n1;
    while (d.n && (d.d[0] & 1u) == 0) {
        bn_shr1(&d);
        s++;
    }
    for (round = 0; round < 8; round++) {
        uint32_t r;
        int ok = 0;
        bn_set_u32(&a, bases[round]);
        if (bn_cmp(&a, n) >= 0) {
            continue;
        }
        bn_modexp(&x, &a, &d, n);
        if (bn_cmp(&x, &one) == 0 || bn_cmp(&x, &n1) == 0) {
            continue;
        }
        for (r = 1; r < s; r++) {
            bn_t t;
            bn_mul(&t, &x, &x);
            bn_mod(&x, &t, n);
            if (bn_cmp(&x, &n1) == 0) {
                ok = 1;
                break;
            }
            if (bn_cmp(&x, &one) == 0) {
                return 0;
            }
        }
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

static int gen_prime(bn_t *p, uint32_t bits)
{
    uint32_t bytes = (bits + 7) >> 3;
    uint8_t buf[256];
    int attempt;
    if (bytes > sizeof(buf)) {
        return -1;
    }
    for (attempt = 0; attempt < 4000; attempt++) {
        if (mh_rand(buf, bytes) != 0) {
            return -2;
        }
        buf[0] |= 0x80;
        buf[bytes - 1] |= 0x01;
        bn_from_be(p, buf, bytes);
        if (bn_bits(p) < bits) {
            continue;
        }
        if (!trial(p)) {
            continue;
        }
        if (miller_rabin(p)) {
            return 0;
        }
    }
    return -1;
}

static uint32_t modexp_io(MH_RSA_CALL *c, const bn_t *exp, const slot_t *s)
{
    bn_t in, out;
    uint32_t nb;
    if (!c || !c->pu8Input || !c->pu8Output || !crc_call(c)) {
        return MH_RET_RSA_PARAM_ERR;
    }
    nb = nbytes(s->nbits);
    if (c->u32InLen == 0 || c->u32InLen > nb) {
        return MH_RET_RSA_PARAM_ERR;
    }
    bn_from_be(&in, c->pu8Input, c->u32InLen);
    if (bn_cmp(&in, &s->n) >= 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    bn_modexp(&out, &in, exp, &s->n);
    bn_to_be(c->pu8Output, nb, &out);
    c->u32OutLen = nb;
    return MH_RET_RSA_SUCCESS;
}

uint32_t MHRSA_Init(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase)
{
    if (!pKeySrc || !pKeyBase) {
        return MH_RET_RSA_PARAM_ERR;
    }
    memset(pKeyBase, 0, sizeof(*pKeyBase));
    pKeySrc->u32Crc = MHCRC_CalcBuff(0xffff, pKeySrc, key_prefix());
    return MH_RET_RSA_SUCCESS;
}

uint32_t MHRSA_SetKey(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase, uint8_t *pu8Base)
{
    slot_t *s;
    (void)pu8Base;
    if (!pKeySrc || !pKeyBase || !crc_key(pKeySrc)) {
        return MH_RET_RSA_PARAM_ERR;
    }
    if (pKeySrc->u16NBits < 256 || (pKeySrc->u16NBits & 15u)) {
        return MH_RET_RSA_PARAM_ERR;
    }
    memset(pKeyBase, 0, sizeof(*pKeyBase));
    s = slot_of(pKeyBase, 1);
    if (!s) {
        return MH_RET_RSA_ERR;
    }
    load_key(s, pKeySrc);
    if (s->n.n == 0 || s->e.n == 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    return MH_RET_RSA_SUCCESS;
}

uint32_t MHRSA_Pub(MH_RSA_CALL *pCall)
{
    slot_t *s;
    if (!pCall || !pCall->KeyBase) {
        return MH_RET_RSA_PARAM_ERR;
    }
    s = slot_of(pCall->KeyBase, 0);
    if (!s || s->e.n == 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    return modexp_io(pCall, &s->e, s);
}

uint32_t MHRSA_Pri(MH_RSA_CALL *pCall)
{
    slot_t *s;
    if (!pCall || !pCall->KeyBase) {
        return MH_RET_RSA_PARAM_ERR;
    }
    s = slot_of(pCall->KeyBase, 0);
    if (!s || s->d.n == 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    return modexp_io(pCall, &s->d, s);
}

uint32_t MHRSA_Crt(MH_RSA_CALL *pCall)
{
    slot_t *s;
    bn_t in, m1, m2, h, t, out;
    uint32_t nb;
    if (!pCall || !pCall->KeyBase || !pCall->pu8Input || !pCall->pu8Output || !crc_call(pCall)) {
        return MH_RET_RSA_PARAM_ERR;
    }
    s = slot_of(pCall->KeyBase, 0);
    if (!s || !s->has_crt) {
        return MH_RET_RSA_PARAM_ERR;
    }
    nb = nbytes(s->nbits);
    if (pCall->u32InLen == 0 || pCall->u32InLen > nb) {
        return MH_RET_RSA_PARAM_ERR;
    }
    bn_from_be(&in, pCall->pu8Input, pCall->u32InLen);
    if (bn_cmp(&in, &s->n) >= 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    bn_modexp(&m1, &in, &s->dp, &s->p);
    bn_modexp(&m2, &in, &s->dq, &s->q);
    bn_mod(&t, &m2, &s->p);
    if (bn_cmp(&m1, &t) >= 0) {
        bn_sub(&t, &m1, &t);
    } else {
        bn_sub(&t, &t, &m1);
        bn_sub(&t, &s->p, &t);
    }
    bn_mul(&h, &t, &s->qi);
    bn_mod(&h, &h, &s->p);
    bn_mul(&t, &h, &s->q);
    bn_add(&out, &m2, &t);
    bn_mod(&out, &out, &s->n);
    bn_to_be(pCall->pu8Output, nb, &out);
    pCall->u32OutLen = nb;
    return MH_RET_RSA_SUCCESS;
}

uint32_t MHRSA_CompleteKey(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase,
                           uint8_t *pu8Base, uint32_t u32CompType)
{
    slot_t *s;
    int rc;
    (void)pu8Base;
    if (!pKeySrc || !pKeyBase || !IS_RSA_COMPLETE_TYPE(u32CompType) || !crc_key(pKeySrc)) {
        return MH_RET_RSA_PARAM_ERR;
    }
    memset(pKeyBase, 0, sizeof(*pKeyBase));
    s = slot_of(pKeyBase, 1);
    if (!s) {
        return MH_RET_RSA_ERR;
    }
    load_key(s, pKeySrc);
    if (u32CompType == MH_RSA_COMPLETE_D || u32CompType == MH_RSA_COMPLETE_E) {
        if (s->p.n == 0 || s->q.n == 0) {
            return MH_RET_RSA_PARAM_ERR;
        }
    }
    if (u32CompType == MH_RSA_COMPLETE_D) {
        rc = derive_d(s);
    } else if (u32CompType == MH_RSA_COMPLETE_E) {
        rc = derive_e(s);
    } else {
        if (s->n.n == 0 && s->p.n && s->q.n) {
            bn_mul(&s->n, &s->p, &s->q);
        }
        rc = fill_crt(s);
    }
    if (rc == -2) {
        return MH_RET_RSA_GCD_ISNOT_ONE;
    }
    if (rc != 0) {
        return MH_RET_RSA_ERR;
    }
    store_bytes(pKeySrc->pu8N, nbytes(pKeySrc->u16NBits), &s->n);
    if (pKeySrc->u16EBits == 0) {
        pKeySrc->u16EBits = s->ebits ? s->ebits : 32;
    }
    store_bytes(pKeySrc->pu8E, nbytes(pKeySrc->u16EBits), &s->e);
    store_bytes(pKeySrc->pu8D, nbytes(pKeySrc->u16NBits), &s->d);
    store_bytes(pKeySrc->pu8Dp, hbytes(pKeySrc->u16NBits), &s->dp);
    store_bytes(pKeySrc->pu8Dq, hbytes(pKeySrc->u16NBits), &s->dq);
    store_bytes(pKeySrc->pu8Qi, hbytes(pKeySrc->u16NBits), &s->qi);
    pKeySrc->u32Crc = MHCRC_CalcBuff(0xffff, pKeySrc, key_prefix());
    return MH_RET_RSA_SUCCESS;
}

uint32_t MHRSA_GenKey(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase,
                      uint8_t *pu8Base, uint32_t u32GenKeyType)
{
    slot_t *s;
    uint32_t half;
    bn_t one, g;
    int guard;
    (void)pu8Base;
    if (!pKeySrc || !pKeyBase || !IS_RSA_GENKEY_TYPE(u32GenKeyType)) {
        return MH_RET_RSA_PARAM_ERR;
    }
    if (pKeySrc->u16NBits < 256 || (pKeySrc->u16NBits & 15u) || !pKeySrc->pu8N || !pKeySrc->pu8E) {
        return MH_RET_RSA_PARAM_ERR;
    }
    half = pKeySrc->u16NBits / 2u;
    memset(pKeyBase, 0, sizeof(*pKeyBase));
    s = slot_of(pKeyBase, 1);
    if (!s) {
        return MH_RET_RSA_ERR;
    }
    s->used = 1;
    s->nbits = pKeySrc->u16NBits;
    if (u32GenKeyType == MH_RSA_GENKEY_EFC) {
        if (pKeySrc->u16EBits == 0 || !pKeySrc->pu8E) {
            return MH_RET_RSA_PARAM_ERR;
        }
        bn_from_be(&s->e, pKeySrc->pu8E, nbytes(pKeySrc->u16EBits));
        s->ebits = pKeySrc->u16EBits;
    } else {
        bn_set_u32(&s->e, 0x10001u);
        s->ebits = 32;
        pKeySrc->u16EBits = 32;
    }
    bn_set_u32(&one, 1);
    for (guard = 0; guard < 64; guard++) {
        if (gen_prime(&s->p, half) != 0 || gen_prime(&s->q, half) != 0) {
            return MH_RET_RSA_ERR;
        }
        if (bn_cmp(&s->p, &s->q) == 0) {
            continue;
        }
        {
            bn_t pm1, qm1;
            bn_sub(&pm1, &s->p, &one);
            bn_sub(&qm1, &s->q, &one);
            bn_gcd(&g, &s->e, &pm1);
            if (bn_cmp(&g, &one) != 0) {
                continue;
            }
            bn_gcd(&g, &s->e, &qm1);
            if (bn_cmp(&g, &one) != 0) {
                continue;
            }
        }
        if (derive_d(s) == 0) {
            break;
        }
    }
    if (!s->has_crt) {
        return MH_RET_PRIME_NOT_ACCEPTABLE;
    }
    store_bytes(pKeySrc->pu8N, nbytes(s->nbits), &s->n);
    store_bytes(pKeySrc->pu8E, nbytes(s->ebits), &s->e);
    store_bytes(pKeySrc->pu8D, nbytes(s->nbits), &s->d);
    store_bytes(pKeySrc->pu8P, hbytes(s->nbits), &s->p);
    store_bytes(pKeySrc->pu8Q, hbytes(s->nbits), &s->q);
    store_bytes(pKeySrc->pu8Dp, hbytes(s->nbits), &s->dp);
    store_bytes(pKeySrc->pu8Dq, hbytes(s->nbits), &s->dq);
    store_bytes(pKeySrc->pu8Qi, hbytes(s->nbits), &s->qi);
    pKeySrc->u32Crc = MHCRC_CalcBuff(0xffff, pKeySrc, key_prefix());
    return MH_RET_RSA_SUCCESS;
}
