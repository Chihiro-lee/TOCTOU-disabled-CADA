#ifndef SHA256_MSP430_H
#define SHA256_MSP430_H

#ifdef __cplusplus
extern "C" {
#endif

#include "core.h"

#ifndef _SIZE_T_DEFINED
#define _SIZE_T_DEFINED
typedef uint16_t size_t;
#endif

#ifndef UINT32_C
#  define UINT32_C(x)  (x ## UL)
#endif
#ifndef UINT64_C
#  define UINT64_C(x)  (x ## ULL)
#endif

//extern volatile uint64_t r6_value;

void sha256_compute(void);

extern void uint64_to_bytes(uint64_t value, uint8_t bytes[8]);
extern void uart_send_byte(uint8_t byte);
extern void uart_send_hex_data(uint8_t *data, uint8_t length);

#ifdef __cplusplus
}
#endif

#endif
