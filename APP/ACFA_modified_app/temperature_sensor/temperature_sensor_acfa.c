#include <RAhook.h>
#include <stdint.h>

/* -- Constants -- */
#define TEMP_PIN        BIT2        // P2.2 as TEMP_PIN
#define MAX_READINGS    83

// Temperature sensor output data
uint8_t data[5] = {0, 0, 0, 0, 0};
uint8_t valid_reading = 0;

/* -- Function Declarations -- */
void delay(unsigned int us);
void read_data();
uint16_t get_temperature();
uint16_t get_humidity();

void delay(unsigned int us) {
    volatile unsigned int i;
    for (i = 0; i < us; i++);
}

void read_data() {
    uint8_t counter = 0;
    uint16_t j = 0, i;

    // Pull signal high & delay
    P2OUT |= TEMP_PIN;
    delay(250);

    // Pull signal low for 20us
    P2OUT &= ~TEMP_PIN;
    delay(20);

    // Pull signal high for 40us
    P2OUT |= TEMP_PIN;
    delay(40);

    // Read timings
    for (i = 0; i < MAX_READINGS; i++) {
        counter += (P2IN & TEMP_PIN);

        // Ignore first 3 transitions
        if ((i >= 4) && ((i & 0x01) == 0x00)) {
            // Shove each bit into the storage bytes
            data[j >> 3] <<= 1;
            if (counter > 6)
                data[j >> 3] |= 1;
            j++;
        }
    }

    // Check we read 40 bits and that the checksum matches
    if ((j >= 40) && (data[4] == ((data[0] + data[1] + data[2] + data[3]) & 0xFF))) {
        valid_reading = 1;
    } else {
        valid_reading = 0;
    }
}

uint16_t get_temperature() {
    read_data();

    uint16_t t = data[2];
    t |= (data[3] << 8);
    return t;
}

uint16_t get_humidity() {
    read_data();

    uint16_t h = data[0];
    h |= (data[1] << 8);
    return h;
}

int main() {
    WDTCTL = WDTPW | WDTHOLD;   // Stop watchdog timer

    P2DIR &= ~TEMP_PIN;         // Set P2.2 as input (TEMP_PIN)
    P5DIR = 0xFF;               // Set P5 as output (LED control)
    P5OUT = 0x00;               // Initialize LED to be off
    
    //TA0CTL = TASSEL_1 + ID_0 + MC_2;   // Start the timer with frequency of 32768 Hz
    // Get sensor readings
    uint16_t temp = get_temperature();
    // uint16_t humidity = get_humidity(); // Uncomment if needed
    //register unsigned int stop = TA0R; // Stop timer
    // Add more processing or output code if needed

    return 0;
}

