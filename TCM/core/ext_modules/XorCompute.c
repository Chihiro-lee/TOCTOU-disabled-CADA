 #include <stdlib.h>
#include <msp430.h>
#include "core.h"
#include "XorCompute.h"

volatile uint32_t address_xor = 0;
volatile uint32_t address_sr = 0;

volatile uint32_t tmp_r4 = 0;
volatile uint32_t tmp_r5 = 0;
volatile uint32_t tmp_r6 = 0;

volatile uint16_t write_count_lee = 0;
uint8_t write_count_lee_bytes[2];

uint8_t combined_bytes[10];

extern volatile uint16_t key_cnt;
extern const uint32_t key_set[1024];

/*** PUBLIC FUNCTIONS ****/

__attribute__((section(".tcm:codeUpper"))) void uint8_to_bytes(uint8_t value, uint8_t bytes) {
    bytes = value & 0xFF;
}
__attribute__((section(".tcm:codeUpper"))) void uint16_to_bytes(uint16_t value, uint8_t bytes[2]) {
    bytes[0] = (value >> 8) & 0xFF;
    bytes[1] = value & 0xFF;
}
__attribute__((section(".tcm:codeUpper"))) void uint32_to_bytes(uint32_t value, uint8_t bytes[4]) {
    bytes[0] = (value >> 24) & 0xFF;
    bytes[1] = (value >> 16) & 0xFF;
    bytes[2] = (value >> 8) & 0xFF;
    bytes[3] = value & 0xFF;
}
__attribute__((section(".tcm:codeUpper"))) void uint64_to_bytes(uint64_t value, uint8_t bytes[8]) {
    bytes[0] = (value >> 56) & 0xFF;
    bytes[1] = (value >> 48) & 0xFF;
    bytes[2] = (value >> 40) & 0xFF;
    bytes[3] = (value >> 32) & 0xFF;
    bytes[4] = (value >> 24) & 0xFF;
    bytes[5] = (value >> 16) & 0xFF;
    bytes[6] = (value >> 8) & 0xFF;
    bytes[7] = value & 0xFF;
}
__attribute__((section(".tcm:codeUpper"))) uint64_t combine_uint32_to_uint64(uint32_t high, uint32_t low) {
    return ((uint64_t)high << 32) | low;
}
__attribute__((section(".tcm:codeUpper"))) void uart_send_byte(uint8_t byte) {
    while (!(UCA1IFG&UCTXIFG));
    UCA1TXBUF = byte;
}

__attribute__((section(".tcm:codeUpper"))) void uart_send_hex_data(uint8_t *data, uint8_t length) {
    const char hex_chars[] = "0123456789ABCDEF";
    for (uint8_t i = 0; i < length; i++) {
        uart_send_byte(hex_chars[(data[i] >> 4) & 0x0F]);
        uart_send_byte(hex_chars[data[i] & 0x0F]);
    }
    uart_send_byte(0x20); // space
}

__attribute__((section(".tcm:codeUpper"))) void XorResult(){

    WDTCTL = WDTPW | WDTHOLD;

    __dint();
    
    __asm("mov.w r8, &write_count_lee");
    P4SEL |= BIT4+BIT5;    //Configure UART in both TX and RX
    UCA1CTL1 |= UCSWRST;   // Put the USCI state machine in reset
    UCA1CTL1 |= UCSSEL_1;

    //Set the baudrate
    UCA1BR0 = 3;
    UCA1MCTL = 0xD6;
    UCA1CTL0 = 0x00;
    UCA1CTL1 &= ~UCSWRST;

    UCA1IE |= UCRXIE;
    
    volatile uint16_t key_cnt_used = key_cnt - 1;
    uint16_t* ptr = (uint16_t*)&key_set[key_cnt_used];
    uint32_t low  = ptr[0];   // low  16
    uint32_t high = ptr[1];   // high 16
    address_xor = (high << 16) | address_xor;
    address_sr  = (high << 16) | address_sr;
    
    uint64_t combined = combine_uint32_to_uint64(address_sr, address_xor);
    
    uint64_to_bytes(combined,combined_bytes);
    uint16_to_bytes(verify_count, combined_bytes+8);
    //convert write_count_lee to char array
    uint16_to_bytes(write_count_lee, write_count_lee_bytes);
    
    uart_send_hex_data(combined_bytes,10);
    
    uart_send_hex_data(write_count_lee_bytes, 2);
    uart_send_byte(0x54); //T
    uart_send_byte(0x0A);
    uart_send_byte(0x0D); //endline & CR
    __asm("mov.w &write_count_lee, r8");
}
