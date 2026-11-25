#ifndef __MH_MISC_H
#define __MH_MISC_H

#include <stdint.h>

uint32_t MHCRC_CalcBuff(uint16_t init, const void *buf, uint32_t len);

#endif
