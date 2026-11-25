#include "mh_rand.h"

uint32_t mh_rand(uint8_t *buf, uint32_t len)
{
    static uint32_t s = 0xA5C31E79u;
    uint32_t i;

    if (!buf || len == 0) {
        return 1;
    }
    for (i = 0; i < len; i++) {
        s = s * 1664525u + 1013904223u;
        buf[i] = (uint8_t)(s >> 24);
    }
    return 0;
}
