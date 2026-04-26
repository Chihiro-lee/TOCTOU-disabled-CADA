#include <RAhook.h>
#include <stdint.h>
#include <string.h>

// Pin Definitions
#define CLK_PIN         BIT2    // P4.2 (Pin 39, TM1637 CLK)
#define DIO_PIN         BIT1    // P4.1 (Pin 38, TM1637 DIO)
#define LED_PIN         BIT0    // P1.0 (Red LED)

// TM1637 Constants
#define ADDR_AUTO       0x40
#define ADDR_FIXED      0x44
#define START_ADDR      0xC0
#define DISP_CTRL       0x88    // Base display control (brightness added later)
#define BRIGHT_TYPICAL  2
#define POINT_ON        1

// Segment data for digits 0-9 (same as TubeTab)
static const uint8_t tube_tab[] = {
    0x3F, 0x06, 0x5B, 0x4F, 0x66, 0x6D, 0x7D, 0x07, 0x7F, 0x6F
};

// Global variables
static uint8_t point_flag = POINT_ON;  // Display colon
static int8_t bits[4] = {0};           // Array to store single digits of distance

// Function prototypes
void init_clock(void);
void init_gpio(void);
void delay_ms(uint16_t ms);
void tm1637_init(void);
void tm1637_clear_display(void);
void tm1637_start(void);
void tm1637_stop(void);
void tm1637_write_byte(uint8_t wr_data);
void tm1637_display_digit(uint8_t bit_addr, int8_t disp_data);
uint8_t tm1637_coding(int8_t disp_data);
long ultrasonic_measure_cm(long input_distance);

// Main function
void main(void)
{
    WDTCTL = WDTPW | WDTHOLD;  // Stop watchdog timer

    init_clock();               // Configure 16 MHz DCO
    init_gpio();                // Setup GPIO pins

    // Initialize TM1637 display
    tm1637_init();              // Initialize and clear display
    tm1637_start();
    tm1637_write_byte(DISP_CTRL + BRIGHT_TYPICAL);
    tm1637_stop();

    // Simulate ultrasonic distance: 123 cm
    long input_distance = 321;
    long distance = ultrasonic_measure_cm(input_distance);

    if (distance >= 0 && distance <= 400) {  // Valid range: 0-400 cm
        // Prepare display data
        memset(bits, 0, sizeof(bits));
        for (int i = 3; i >= 0; i--) {
            bits[i] = distance % 10;
            distance /= 10;
            tm1637_display_digit(i, bits[i]);  // Display each digit
        }

        // Blink LED to indicate successful read
        P1OUT |= LED_PIN;
        delay_ms(100);
        P1OUT &= ~LED_PIN;
    } else {
        // Blink LED to indicate invalid distance
        P1OUT |= LED_PIN;
        delay_ms(500);
        P1OUT &= ~LED_PIN;
    }
    return;
}

// Initialize 16 MHz DCO clock
void init_clock(void)
{
    UCSCTL3 |= SELREF_2;                    // FLL reference = REFO
    UCSCTL4 |= SELA_2;                      // ACLK = REFO
    __bis_SR_register(SCG0);                // Disable FLL
    UCSCTL0 = 0;                            // Set lowest DCOx, MODx
    UCSCTL1 = DCORSEL_5;                   // Select DCO range 16 MHz
    UCSCTL2 = FLLD_1 + 487;                // DCO = 16 MHz (487 * 32768 * 2)
    __bic_SR_register(SCG0);                // Enable FLL
    __delay_cycles(250000);                 // Wait for DCO to stabilize
}

// Initialize GPIO pins
void init_gpio(void)
{
    // TM1637 pins (P4.1, P4.2)
    P4DIR |= CLK_PIN | DIO_PIN;             // CLK and DIO as output
    P4OUT |= CLK_PIN | DIO_PIN;             // Set high initially

    // LED pin (P1.0)
    P1DIR |= LED_PIN;                       // LED as output
    P1OUT &= ~LED_PIN;                      // LED off
}

// Delay in milliseconds
void delay_ms(uint16_t ms)
{
    while (ms--) {
        __delay_cycles(16000);  // 16 MHz clock
    }
}

// Initialize TM1637 display
void tm1637_init(void)
{
    P4DIR |= CLK_PIN | DIO_PIN;  // Set CLK and DIO as output
    P4OUT |= CLK_PIN | DIO_PIN;  // Set high initially
    tm1637_clear_display();      // Clear display
}

// Clear TM1637 display
void tm1637_clear_display(void)
{
    tm1637_display_digit(0, 0x7F);  // Clear digit 0
    tm1637_display_digit(1, 0x7F);  // Clear digit 1
    tm1637_display_digit(2, 0x7F);  // Clear digit 2
    tm1637_display_digit(3, 0x7F);  // Clear digit 3
}

// TM1637 start signal
void tm1637_start(void)
{
    P4OUT |= CLK_PIN;
    P4OUT |= DIO_PIN;
    P4OUT &= ~DIO_PIN;
    P4OUT &= ~CLK_PIN;
}

// TM1637 stop signal
void tm1637_stop(void)
{
    P4OUT &= ~CLK_PIN;
    P4OUT &= ~DIO_PIN;
    P4OUT |= CLK_PIN;
    P4OUT |= DIO_PIN;
}

// Write a byte to TM1637
void tm1637_write_byte(uint8_t wr_data)
{
    uint8_t i, count1 = 0;
    for (i = 0; i < 8; i++) {
        P4OUT &= ~CLK_PIN;
        if (wr_data & 0x01) P4OUT |= DIO_PIN;
        else P4OUT &= ~DIO_PIN;
        wr_data >>= 1;
        P4OUT |= CLK_PIN;
    }
    P4OUT &= ~CLK_PIN;
    P4OUT |= DIO_PIN;
    P4OUT |= CLK_PIN;
    P4DIR &= ~DIO_PIN;  // Input for ACK
    while (P4IN & DIO_PIN) {
        count1++;
        if (count1 == 200) {
            P4DIR |= DIO_PIN;
            P4OUT &= ~DIO_PIN;
            count1 = 0;
        }
    }
    P4DIR |= DIO_PIN;   // Back to output
}

// Display a single digit
void tm1637_display_digit(uint8_t bit_addr, int8_t disp_data)
{
    uint8_t seg_data = tm1637_coding(disp_data);
    tm1637_start();
    tm1637_write_byte(ADDR_FIXED);
    tm1637_stop();
    tm1637_start();
    tm1637_write_byte(bit_addr | 0xC0);
    tm1637_write_byte(seg_data);
    tm1637_stop();
    tm1637_start();
    tm1637_write_byte(DISP_CTRL + BRIGHT_TYPICAL);
    tm1637_stop();
}

// Convert digit to segment data
uint8_t tm1637_coding(int8_t disp_data)
{
    uint8_t point_data = point_flag ? 0x80 : 0;
    if (disp_data == 0x7F) disp_data = 0;
    else disp_data = tube_tab[disp_data];
    return disp_data + point_data;
}

// Simulate ultrasonic distance measurement
long ultrasonic_measure_cm(long input_distance)
{
    if (input_distance >= 0 && input_distance <= 400) {
        return input_distance;  // Return valid input distance
    }
    return -1;  // Invalid distance
}
