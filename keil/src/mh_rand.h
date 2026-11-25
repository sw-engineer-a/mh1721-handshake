#ifndef __MH_RAND_H
#define __MH_RAND_H

#include <stdint.h>

/* Fill buf with random bytes. Returns 0 on success. */
uint32_t mh_rand(uint8_t *buf, uint32_t len);

#endif
