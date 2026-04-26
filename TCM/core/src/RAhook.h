#ifndef HEADER_FILE_RA_HOOK
#define HEADER_FILE_RA_HOOK

#include <msp430.h>

#define callSendUpdate() ({asm("BR #0xfef8");})/*{asm("BR #0xfe3e");*/
//#define callSendXor() ({asm("BR #0xff16");})
//#define callSendValue() ({asm("BR #0xff1A");})



void initUART() {

    WDTCTL = WDTPW | WDTHOLD;
    
    __dint();
    
    P4SEL |= BIT4+BIT5;    
    UCA1CTL1 |= UCSWRST;
    UCA1CTL1 |= UCSSEL_1;

    //Set the baudrate
    UCA1BR0 = 3;
    UCA1MCTL = 0xD6;
    UCA1CTL0 = 0x00;
    UCA1CTL1 &= ~UCSWRST;  
    
    UCA1IE |= UCRXIE;
    
    //__eint();
    __bis_SR_register(GIE);   
}

void cada_exit(){
    initUART();
    UCA1TXBUF = 0x0a;
    while (UCA1STAT & UCBUSY);
    UCA1TXBUF = 0x0d;
    while (UCA1STAT & UCBUSY);
}
#endif
