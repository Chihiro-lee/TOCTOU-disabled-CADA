#include <RAhook.h>
typedef unsigned char uint8_t;
typedef unsigned int uint16_t;
/************************ UART INIT CODE *************************/

#define BAUD 57600
#define MCLK_FREQ 1000000UL // 1 MHz DCO
#define BRDIV ((MCLK_FREQ / BAUD) / 16)
#define MOD ((MCLK_FREQ / BAUD) % 16)

void uart_init(void) {

    UCSCTL4 = SELA__REFOCLK | SELS__DCOCLKDIV | SELM__DCOCLKDIV;
    UCSCTL0 = 0;
    UCSCTL1 = DCORSEL_2; 
    UCSCTL2 = FLLD_0 | ((MCLK_FREQ / 32768) - 1); 
    __delay_cycles(1000); 


    P4SEL |= BIT4 | BIT5; // P4.4 = TXD, P4.5 = RXD
    UCA1CTL1 |= UCSWRST; 
    UCA1CTL1 |= UCSSEL_2; 
    UCA1BR0 = BRDIV & 0xFF;
    UCA1BR1 = (BRDIV >> 8) & 0xFF;
    UCA1MCTL = (MOD << 4) | UCOS16; 
    UCA1CTL0 = 0; 
    UCA1CTL1 &= ~UCSWRST; 
    UCA1IE |= UCRXIE | UCTXIE; 
}

void uart_putchar(char c) {
    while (!(UCA1IFG & UCTXIFG)); 
    UCA1TXBUF = c;
}

void uart_puts(char *c) {
    while (*c) {
        if (*c == '\n')
            uart_putchar('\r');
        uart_putchar(*c++);
    }
}

/**************** READ AND WRITE TO FLASH (EEPROM EQUIVALENT) ******************/

int main(void) {
    WDTCTL = WDTPW | WDTHOLD; 

    uint8_t wr_array[256];
    uint8_t rd_array[256];

    uart_init();
    uart_puts("eval_storage_process\n");


    P2DIR |= BIT0 | BIT1; // P2.0 = MOSI, P2.1 = MISO
    P2OUT = 0x00; 


    uint16_t i;
    for (i = 0; i < 256; i++) {
        wr_array[i] = i + 5;
    }


    __delay_cycles(5000 * (MCLK_FREQ / 1000000)); 

    uart_puts("Start writing\n");
    P2OUT = BIT0; 


    FCTL3 = FWKEY;
    FCTL1 = FWKEY | ERASE; 
    *(uint16_t *)0x1800 = 0; 
    FCTL1 = FWKEY; 
    FCTL3 = FWKEY | LOCK; 


    FCTL3 = FWKEY;
    FCTL1 = FWKEY | WRT; 
    for (i = 0; i < 256; i += 2) { 
        *(uint16_t *)(0x1800 + i) = (wr_array[i + 1] << 8) | wr_array[i];
    }
    FCTL1 = FWKEY; 
    FCTL3 = FWKEY | LOCK; 

    P2OUT = 0x00; 
    uart_puts("end writing\n");

    __delay_cycles(500 * (MCLK_FREQ / 1000000)); 

    uart_puts("start reading\n");
    P2OUT = BIT0; 


    for (i = 0; i < 256; i++) {
        rd_array[i] = *(uint8_t *)(0x1800 + i);
    }

    P2OUT = 0x00; 
    uart_puts("end reading\n");
}
