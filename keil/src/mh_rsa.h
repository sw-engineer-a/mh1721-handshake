#ifndef __MH_RSA_H
#define __MH_RSA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "mh_bignum.h"

#define MH_RET_RSA_INIT                 (0x52A659AAu)
#define MH_RET_RSA_PARAM_ERR            (MH_RET_RSA_INIT + 0x01u)
#define MH_RET_RSA_TRNG_ERR             (MH_RET_RSA_INIT + 0x02u)
#define MH_RET_RSA_ERR                  (MH_RET_RSA_INIT + 0x03u)
#define MH_RET_RSA_DFA_LOCK             (MH_RET_RSA_INIT + 0x04u)
#define MH_RET_PRIME_IS_PRIME           (MH_RET_RSA_INIT + 0x05u)
#define MH_RET_PRIME_NOT_ACCEPTABLE     (MH_RET_RSA_INIT + 0x06u)
#define MH_RET_RSA_GCD_ISNOT_ONE        (MH_RET_RSA_INIT + 0x07u)
#define MH_RET_RSA_PATH_CHECK_FAIL      (MH_RET_RSA_INIT + 0x08u)
#define MH_RET_RSA_SUCCESS              (MH_RET_RSA_INIT + 0x0100u)

typedef struct
{
    /* Key info */
    uint16_t u16NBits;          /* Public key N bits */
    uint16_t u16EBits;          /* Public key E bits */
    /* Pub key */
    uint8_t *pu8N;              /* len: (Nbits + 7) >> 3 */
    uint8_t *pu8E;              /* len: (Ebits + 7) >> 3 */
    uint8_t *pu8D;              /* len: (Nbits + 7) >> 3 */
    /* CRT key */
    uint8_t *pu8P;              /* len: (Nbits + 15) >> 4 */
    uint8_t *pu8Q;
    uint8_t *pu8Dp;
    uint8_t *pu8Dq;
    uint8_t *pu8Qi;
    uint32_t u32Crc;
} MH_RSA_KEY;

/* Same size as the RSA internal key context. At least 12 words. */
typedef struct
{
    uint32_t au32Reserve[12];
} MH_RSA_KEY_SPACE;

typedef struct
{
    uint8_t *pu8Input;
    uint8_t *pu8Output;
    uint32_t u32InLen;
    uint32_t u32OutLen;
    uint32_t u32Crc;
    MH_RSA_KEY_SPACE *KeyBase;
} MH_RSA_CALL;

#define MH_RSA_COMPLETE_E               (0u)
#define MH_RSA_COMPLETE_D               (1u)
#define MH_RSA_COMPLETE_CRT             (2u)
#define IS_RSA_COMPLETE_TYPE(TYPE) \
    (((TYPE) == MH_RSA_COMPLETE_E) || ((TYPE) == MH_RSA_COMPLETE_D) || ((TYPE) == MH_RSA_COMPLETE_CRT))

#define MH_RSA_GENKEY_EFC               (0u)
#define MH_RSA_GENKEY_GENE              (1u)
#define IS_RSA_GENKEY_TYPE(TYPE) \
    (((TYPE) == MH_RSA_GENKEY_EFC) || ((TYPE) == MH_RSA_GENKEY_GENE))

uint32_t MHRSA_Init(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase);
uint32_t MHRSA_SetKey(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase, uint8_t *pu8Base);
uint32_t MHRSA_Pub(MH_RSA_CALL *pCall);
uint32_t MHRSA_Pri(MH_RSA_CALL *pCall);
uint32_t MHRSA_Crt(MH_RSA_CALL *pCall);
uint32_t MHRSA_GenKey(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase, uint8_t *pu8Base, uint32_t u32GenKeyType);
uint32_t MHRSA_CompleteKey(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase, uint8_t *pu8Base, uint32_t u32CompType);

#ifdef __cplusplus
}
#endif

#endif
