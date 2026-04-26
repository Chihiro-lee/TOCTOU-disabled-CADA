#include <klee/klee.h>
#include <stdio.h>
#include <stdint.h>

#define MAX_READINGS 83

uint8_t data[5];
uint8_t valid_reading;
uint8_t sensor_response[5];  // Symbolic input: 5 bytes from sensor

void read_data() {
    uint16_t j = 0, i;
    uint8_t counter;
    uint8_t bit_index = 0;

    for (i = 0; i < MAX_READINGS; i++) {
        // Symbolic bit decision
        if (bit_index < 40) {
            uint8_t byte_idx = bit_index / 8;
            uint8_t bit_pos = 7 - (bit_index % 8);
            uint8_t bit = (sensor_response[byte_idx] >> bit_pos) & 1;
            counter = bit ? 12 : 4;  // 1 → counter > 6 → set bit
        } else {
            counter = 0;
        }

        if ((i >= 4) && ((i & 0x01) == 0x00)) {
            data[j >> 3] <<= 1;
            if (counter > 6) {
                data[j >> 3] |= 1;
            }
            j++;
        }

        if (i >= 4 && (i % 2) == 1) bit_index++;
    }

    // Path conditions
    if (j >= 40) {
        uint8_t checksum = (data[0] + data[1] + data[2] + data[3]) & 0xFF;
        if (data[4] == checksum) {
            valid_reading = 1;
            klee_print_expr("VALID READING ACCEPTED: Temp=", (data[2] << 8) | data[3],
                            "Humidity=", (data[0] << 8) | data[1]);
        } else {
            valid_reading = 0;
            printf("Checksum failed (safe reject).\n");
        }
    } else {
        valid_reading = 0;
        printf("Incomplete data (j < 40).\n");
    }
}

int main() {
    // Symbolize the 5-byte sensor response
    klee_make_symbolic(sensor_response, sizeof(sensor_response), "sensor_response");

    // Optional constraints: realistic ranges
    // klee_assume(sensor_response[1] < 10);  // decimal part < 10
    // klee_assume(sensor_response[3] < 10);

    read_data();

    if (valid_reading) {
        printf("TRUSTED: Sensor data accepted.\n");
    }

    return 0;
}
