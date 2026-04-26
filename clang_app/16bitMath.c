/*******************************************************************************
**
Name : 16-bit Math
* Purpose : Benchmark 16-bit math functions.
*
*******************************************************************************/
#include <klee/klee.h>
#include <stdio.h>

typedef unsigned short UInt16;
UInt16 add(UInt16 a, UInt16 b) {
    return (a + b);
}
UInt16 mul(UInt16 a, UInt16 b) {
    return (a * b);
}
UInt16 div(UInt16 a, UInt16 b) {
    return (b != 0 ? (a / b) : 0);
    //return (a / b);
}
void main(void) {
     //WDTCTL = WDTPW | WDTHOLD;   // stop watchdog timer
    // Setup leds
    //P1DIR |= BIT0;
    //P4DIR |= BIT7;
    //P4OUT &= 0x7f;
    //P1OUT &= 0xfe;

    //P4OUT |= BIT7; //Green led is the first verification 
    //TA0CTL = TASSEL_2 + ID_0 + MC_2; // Start the timer

    volatile UInt16 result[4];
    klee_make_symbolic(result, sizeof(result), "result");
    //result[0] = 231;
    //result[1] = 12;
    result[2] = add(result[0], result[1]);
    result[1] = mul(result[0], result[2]);
    result[3] = div(result[1], result[2]);
    klee_assert(result[3] >= 0);
    //register unsigned int stop = TA0R; // Stop timer
    //P1OUT |= BIT0; // Red light
    //callSendHash();
    
    //while(1);
    return ;
}
