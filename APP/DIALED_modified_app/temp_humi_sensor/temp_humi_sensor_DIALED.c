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
const uint8_t tube_tab[] = {
    0x3F, 0x06, 0x5B, 0x4F, 0x66, 0x6D, 0x7D, 0x07, 0x7F, 0x6F
};
// Simulate DHT22 data: humidity 65.5% (655), temperature 25.2°C (252)
char input_data[6] = {
        0x02,  // High byte of humidity (655 = 0x028F)
        0x8F,  // Low byte of humidity
        0x00,  // High byte of temperature (252 = 0x00FC)
        0xFC,  // Low byte of temperature
        0x2B,   // Checksum (0x02 + 0x8F + 0x00 + 0xFC = 0x12B, low 8 bits = 0x2B)
        '\r'
    };
// Global variables
volatile char data[5];         // DHT22 data buffer
uint8_t point_flag = POINT_ON;  // Display colon

// Function prototypes
void init_clock(void);
void init_gpio(void);
void delay_ms(uint16_t ms);
void delay_us(uint16_t us);
void tm1637_start(void);
void tm1637_stop(void);
void tm1637_write_byte(uint8_t wr_data);
void tm1637_clear_display(void);
void tm1637_display_digit(uint8_t bit_addr, uint8_t disp_data);
uint8_t tm1637_coding(uint8_t disp_data);

// Main function
void main(void)
{
    WDTCTL = WDTPW | WDTHOLD;  // Stop watchdog timer

    init_clock();               // Configure 16 MHz DCO
    init_gpio();                // Setup GPIO pins

    // Initialize TM1637 display
    tm1637_clear_display();     // Clear display
    tm1637_start();
    tm1637_write_byte(DISP_CTRL + BRIGHT_TYPICAL);
    tm1637_stop();

    // Read simulated DHT22 data
    int i = 0;
    while(input_data[i] != 'r'){
       data[i] = input_data[i];
       i++;
    }
    // Extract humidity and temperature
    uint16_t humidity = (data[0] << 8) | data[1];
    humidity /= 10;  // Convert to integer
    uint16_t temperature = ((data[2] & 0x7F) << 8) | data[3];
    temperature /= 10;  // Convert to integer
    if (data[2] & 0x80) temperature = -temperature;  // Handle negative temp

    // Prepare display data
    uint8_t t_bits[2], h_bits[2];
    memset(t_bits, 0, sizeof(t_bits));
    memset(h_bits, 0, sizeof(h_bits));

    t_bits[0] = temperature % 10;         // Units of temperature
    t_bits[1] = (temperature / 10) % 10;  // Tens of temperature
    h_bits[0] = humidity % 10;            // Units of humidity
    h_bits[1] = (humidity / 10) % 10;     // Tens of humidity

    // Display data
    tm1637_display_digit(0, t_bits[1]);   // Tens of temperature
    tm1637_display_digit(1, t_bits[0]);   // Units of temperature
    tm1637_display_digit(2, h_bits[1]);   // Tens of humidity
    tm1637_display_digit(3, h_bits[0]);   // Units of humidity

    // Blink LED to indicate successful read
    P1OUT |= LED_PIN;
    delay_ms(100);
    P1OUT &= ~LED_PIN;
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

// Delay in microseconds
void delay_us(uint16_t us)
{
    while (us--) {
        __delay_cycles(16);     // 16 MHz clock
    }
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

// Clear TM1637 display
void tm1637_clear_display(void)
{
    tm1637_display_digit(0, 0x7F);  // Clear digit 0
    tm1637_display_digit(1, 0x7F);  // Clear digit 1
    tm1637_display_digit(2, 0x7F);  // Clear digit 2
    tm1637_display_digit(3, 0x7F);  // Clear digit 3
}

// Display a single digit
void tm1637_display_digit(uint8_t bit_addr, uint8_t disp_data)
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
uint8_t tm1637_coding(uint8_t disp_data)
{
    uint8_t point_data = point_flag ? 0x80 : 0;
    if (disp_data == 0x7F) disp_data = 0;
    else disp_data = tube_tab[disp_data];
    return disp_data + point_data;
}
