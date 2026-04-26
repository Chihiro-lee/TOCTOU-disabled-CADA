/*******************************************************************************
**
Name : 32-bit Math
* Purpose : Benchmark 32-bit math functions.
*
*******************************************************************************/

#include <klee/klee.h>
#include <stdio.h>

typedef unsigned long UInt32;
UInt32 add(UInt32 a, UInt32 b) {
    return (a + b);
}
UInt32 mul(UInt32 a, UInt32 b) {
    return (a * b);
}
UInt32 div(UInt32 a, UInt32 b) {
    return (b != 0 ? (a / b) : 0);
    //return (a / b);
}
void main(void) {
    /****************** GENERAL DEBUG SET-UP *******************/
    //WDTCTL = WDTPW | WDTHOLD;   // stop watchdog timer
    // Setup leds
    //P1DIR |= BIT0;
    //P4DIR |= BIT7;
    //P4OUT &= 0x7f;
    //P1OUT &= 0xfe;

    //P4OUT |= BIT7; //Green led is the first verification

    //TA0CTL = TASSEL_2 + ID_0 + MC_2; // Start the timer
    /****************** START APPLICATION ********************/
    volatile UInt32 result[4];
    klee_make_symbolic(result, sizeof(result), "result");
    //result[0] = 43125;
    //result[1] = 14567;
    result[2] = add(result[0], result[1]);
    result[1] = mul(result[0], result[2]);
    result[3] = div(result[1], result[2]);
    klee_assert(result[3] >= 0);
    //callSendHash();
/**************** END OF APP ***************************/
    //register unsigned int stop = TA0R; // Stop timer
    //P1OUT |= BIT0; // Red light
    //while(1);
    return ;
}
