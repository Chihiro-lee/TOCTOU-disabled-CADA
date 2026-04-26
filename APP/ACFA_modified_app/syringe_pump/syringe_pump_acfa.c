#include <RAhook.h>
#include <stdio.h>

/* -- Constants -- */
#define SYRINGE_VOLUME_ML 30.0
#define SYRINGE_BARREL_LENGTH_MM 8.0

#define THREADED_ROD_PITCH 1.25
#define STEPS_PER_REVOLUTION 4.0
#define MICROSTEPS_PER_STEP 16.0

#define SPEED_MICROSECONDS_DELAY 100 // longer delay = lower speed

#define cr              '\r'
/// Simulate non-attack input
char user_input[5] = {1, 2, 3, 4, '\r'};
char verify_entry = 0;
/* -- Function Declarations -- */
void waitForInput();
int read_data(char * entry);
void delayMicroseconds(unsigned int delay);
char getserialinput(uint8_t inputserialpointer);
int syringepump();

void waitForInput(){
    char entry[5] = {0, 0, 0, 0};
    verify_entry = read_data(entry);
}

int read_data(char * entry){
    int  i = 0;
    while(user_input[i] != cr){
        entry[i] = user_input[i];
        i++;
    }
    char entryCode[5]= {1, 2, 3, 4};
    int j = 0;
    while(j < 4){
        if(entry[j] != entryCode[j]){
            return 0;
        }
        j++;
    }
    return 1;
}

void delayMicroseconds(unsigned int delay)
{
    volatile unsigned int j = 0;
    for (; j < delay; j++);
}

char getserialinput(uint8_t inputserialpointer)
{
    uint8_t maxinputpointer = 2;
    char input[2] = "+\n";
    if (inputserialpointer < maxinputpointer)
    {
        return input[inputserialpointer];
    }
    return 0;
}

int syringepump()
{
    /* -- Global variables -- */
    volatile uint8_t inputserialpointer = -1;
    uint16_t inputStrLen = 0;
    char inputStr[10]; // input string storage

    // Bolus size
    uint16_t mLBolus = 5;

    // Steps per ml
    int ustepsPerML = (MICROSTEPS_PER_STEP * STEPS_PER_REVOLUTION * SYRINGE_BARREL_LENGTH_MM) / (SYRINGE_VOLUME_ML * THREADED_ROD_PITCH );

    int inner = 0;
    int outer = 0;
    int steps = 0;

    while (outer < 1)
    {
        char c = getserialinput(++inputserialpointer);
        while (inner < 10)
        {
            if (c == '\n') // Custom EOF
            {
                break;
            }
            if (c == 0)
            {
                outer = 10;
                break;
            }
            inputStr[inputStrLen++] = c;
            c = getserialinput(++inputserialpointer);
            inner += 1;
        }
        inputStr[inputStrLen++] = '\0';
        steps = mLBolus * ustepsPerML;

        if (inputStr[0] == '+' || inputStr[0] == '-')
        {
            for (int i = 0; i < steps; i++)
            {
                P3OUT = 0xFF;
                delayMicroseconds(SPEED_MICROSECONDS_DELAY);
                P3OUT = 0x00;
                delayMicroseconds(SPEED_MICROSECONDS_DELAY);
            }
        }
        inputStrLen = 0;
        outer += 1;
    }
    return steps;
}

int main()
{
    WDTCTL = WDTPW | WDTHOLD;   // Stop watchdog timer

    P2DIR = 0x00;   // Set Port 2 as input
    P5DIR = 0xFF;   // Set Port 5 as output for LED
    P3DIR = 0xFF;   // Set Port 3 as output for motor control
    P3OUT = 0x00;   // Initialize motor control pins to low
    waitForInput();
    if (verify_entry){
        syringepump();
	}
    else
	P1OUT = 0x00;
    
    // Add more logic here if needed

    return 0;
}

