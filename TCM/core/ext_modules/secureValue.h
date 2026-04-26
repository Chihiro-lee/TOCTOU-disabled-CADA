#ifndef HEADER_FILE_SEC_SEND
#define HEADER_FILE_SEC_SEND
#include "core.h"
extern void uint16_to_bytes(uint16_t value, uint8_t bytes[2]);
extern void uart_send_byte(uint8_t byte);
extern void uart_send_hex_data(uint8_t *data, uint8_t length);
void secureValue();
#endif
