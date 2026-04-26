#include "msp430.h"
#include "stdlib.h"
#include "secureValue.h"

uint32_t read_DFI_MAX = 0x24001;
uint8_t read_input_bytes[1];

__attribute__((section(".tcm:code"))) void secureValue(){
   
    //stop watchdog timer
    WDTCTL = WDTPW | WDTHOLD;

    //Disable interrupts during setup phase
    __dint();
    __asm("mova r4, &tmp_r4");
    P4SEL |= BIT4+BIT5;    //Configure UART in both TX and RX
    UCA1CTL1 |= UCSWRST;   // Put the USCI state machine in reset
    UCA1CTL1 |= UCSSEL_1;

    //Set the baudrate
    UCA1BR0 = 3;
    UCA1MCTL = 0xD6;
    UCA1CTL0 = 0x00;
    UCA1CTL1 &= ~UCSWRST;  

    /* SET UP LEDS for feedback. */
    P4DIR |= BIT7; //Set 4.7 pin in output (green LED)
    P1DIR |= BIT0; //Set 1.0 pin in output (red LED)
    
    P4OUT |= BIT7; 
    
    //send record_input
    //uint16_t record_input_size = 0;
    //uint8_t record_input_size_bytes[2];
    while(read_DFI_MAX != DFI_MAX+1){
        read_input_bytes[0] = *(uint8_t*)read_DFI_MAX;
        read_DFI_MAX--;
        uart_send_hex_data(read_input_bytes, 1);
        uart_send_byte(0x54);
        uart_send_byte(0x0A);
        uart_send_byte(0x0D);
        //record_input_size++;
    }
    //uart_send_byte(0x0A);
    //uart_send_byte(0x0D);
    //uint16_to_bytes(record_input_size, record_input_size_bytes);
    //uart_send_hex_data(record_input_size_bytes, 2);
    //uart_send_byte(0x0A);
    //uart_send_byte(0x0D);

    //DFI_MAX = 0x024000;
    P1OUT |= BIT0;
    P4OUT &= 0x7f;
    __asm("mova &tmp_r4, r4");
}


