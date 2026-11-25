#include "mh_misc.h"

uint32_t MHCRC_CalcBuff(uint16_t init, const void *buf, uint32_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    uint16_t crc = init;
    uint32_t i;
    int b;

    for (i = 0; i < len; i++) {
        crc ^= p[i];
        for (b = 0; b < 8; b++) {
            if (crc & 1u) {
                crc = (uint16_t)((crc >> 1) ^ 0xA001u);
            } else {
                crc = (uint16_t)(crc >> 1);
            }
        }
    }
    return crc;
}
