#include <RAhook.h>
typedef unsigned char uint8_t;
typedef int int16_t;
typedef unsigned long uint32_t;
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

/**************** SIMULATED TEMPERATURE DATA ******************/
#define TEMP_SLA_ADDR 0x40

int main(void) {
    WDTCTL = WDTPW | WDTHOLD; 

    uint8_t buf[2];
    uint32_t conv_buf;
    int16_t temp;

    uart_init();
    uart_puts("eval_sensor_process\n");


    P2DIR |= BIT0 | BIT2; 
    P2OUT |= BIT2; 

    uart_puts("Waiting.\n");
    __delay_cycles(5000 * (MCLK_FREQ / 1000000)); 


    uart_puts("Starting sampling\n");
    P2OUT = BIT0 | BIT2; 


    buf[0] = 0x3A; 
    buf[1] = 0x98; 


    conv_buf = (uint32_t)(((buf[0] << 8) + buf[1]) & ~0x0003);
    conv_buf *= 17572;
    conv_buf = conv_buf >> 16;
    temp = (int16_t)conv_buf - 4685;


    P2OUT = BIT2; 
    uart_puts("Finished sampling\n");

    uart_putchar((uint8_t)((temp & 0xFF00) >> 8));
    uart_putchar((uint8_t)(temp & 0x00FF));
}
