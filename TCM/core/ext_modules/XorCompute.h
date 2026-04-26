#ifndef XOR_COMPUTE_HEADER
#define XOR_COMPUTE_HEADER
#include "core.h"
void uint8_to_bytes(uint8_t value, uint8_t bytes);
void uint16_to_bytes(uint16_t value, uint8_t bytes[2]);
void uint32_to_bytes(uint32_t value, uint8_t bytes[4]);
void uint64_to_bytes(uint64_t value, uint8_t bytes[8]);
uint64_t combine_uint32_to_uint64(uint32_t high, uint32_t low);
void uart_send_byte(uint8_t byte);
void uart_send_hex_data(uint8_t *data, uint8_t length);
void XorResult();
#endif
