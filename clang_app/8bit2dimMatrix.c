/*******************************************************************************
**
Name : 8-bit 2-dim Matrix
* Purpose : Benchmark copying 8-bit values.
*
*******************************************************************************/
#include <klee/klee.h>
#include <stdio.h>

typedef unsigned char UInt8;
const UInt8 m1[16][4] = {
    { 0x12, 0x56, 0x90, 0x34 }, { 0x78, 0x12, 0x56, 0x90 }, { 0x34, 0x78, 0x12, 0x56 }, { 0x90, 0x34, 0x78, 0x12 }, { 0x12, 0x56, 0x90, 0x34 }, { 0x78, 0x12, 0x56, 0x90 }, { 0x34, 0x78, 0x12, 0x56 }, { 0x90, 0x34, 0x78, 0x12 }, { 0x12, 0x56, 0x90, 0x34 }, { 0x78, 0x12, 0x56, 0x90 }, { 0x34, 0x78, 0x12, 0x56 }, { 0x90, 0x34, 0x78, 0x12 }, { 0x12, 0x56, 0x90, 0x34 }, { 0x78, 0x12, 0x56, 0x90 }, { 0x34, 0x78, 0x12, 0x56 }, { 0x90, 0x34, 0x78, 0x12 }
};
void main(void) {
    //WDTCTL = WDTPW | WDTHOLD;   // stop watchdog timer
    // Setup leds
    //P1DIR |= BIT0;
    //P4DIR |= BIT7;
    //P4OUT &= 0x7f;
    //P1OUT &= 0xfe;

    //P4OUT |= BIT7; //Green led is the first verification
    //TA0CTL = TASSEL_2 + ID_0 + MC_2; // Start the timer with frequency of 32768 Hz
    int i, j;
    volatile UInt8 m2[16][4], m3[16][4];
    //klee_make_symbolic(m2, sizeof(m2), "m2");
    //klee_make_symbolic(m3, sizeof(m3), "m3");
    
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 4; j++) {
            m2[i][j] = m1[i][j];
            m3[i][j] = m2[i][j];
        }
    }
    
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 4; j++) {
            klee_assert(m3[i][j] == m1[i][j]);
        }
    }
    //register unsigned int stop = TA0R; // Stop timer
    //P1OUT |= BIT0; // Red light
    //callSendHash();
    //callSendCount();
    //while(1);
    return;
}
