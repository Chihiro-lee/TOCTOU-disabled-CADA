/*******************************************************************************
**
Name : Floating-point Math
* Purpose : Benchmark floating-point math functions.
*
*******************************************************************************/
#include <klee/klee.h>
#include <stdio.h>

float add(float a, float b) {
    return (a + b);
}
float mul(float a, float b) {
    return (a * b);
}
float div(float a, float b) {
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
    volatile float result[4];
    klee_make_symbolic(result, sizeof(result), "result");
    //result[0] = 54.567;
    //result[1] = 14346.67;
    result[2] = add(result[0], result[1]);
    result[1] = mul(result[0], result[2]);
    result[3] = div(result[1], result[2]);
    klee_assert(result[3] >= 0);
    //P1OUT |= BIT0; // Red light
    //callSendHash();
    return;
}
