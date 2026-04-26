/*******************************************************************************
**
Name : 8-bit Math
* Purpose : Benchmark 8-bit math functions.
*
*******************************************************************************/
//#include <RAhook.h>
#include <klee/klee.h>
#include <stdio.h>
typedef unsigned char UInt8;
UInt8 add(UInt8 a, UInt8 b) {
    return (a + b);
}
UInt8 mul(UInt8 a, UInt8 b) {
    return (a * b);
}
UInt8 div(UInt8 a, UInt8 b) {
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
    volatile UInt8 result[4];
    //result[0] = 12;
    //result[1] = 3;
    klee_make_symbolic(result, sizeof(result), "result");
    
    result[2] = add(result[0], result[1]);
    result[1] = mul(result[0], result[2]);
    result[3] = div(result[1], result[2]);
    
    klee_assert(result[3] >= 0);
    //P1OUT |= BIT0; // Red light
    
    //callSendHash();
    return;
}
