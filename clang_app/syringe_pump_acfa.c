#include <klee/klee.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define SYRINGE_VOLUME_ML 30.0
#define SYRINGE_BARREL_LENGTH_MM 8.0
#define THREADED_ROD_PITCH 1.25
#define STEPS_PER_REVOLUTION 4.0
#define MICROSTEPS_PER_STEP 16.0

int ustepsPerML = (int)((MICROSTEPS_PER_STEP * STEPS_PER_REVOLUTION * SYRINGE_BARREL_LENGTH_MM) / (SYRINGE_VOLUME_ML * THREADED_ROD_PITCH));  // 13

char user_input[5];
char verify_entry;

int read_data(char *entry) {
    int i = 0;
    while (i < 4 && user_input[i] != '\r') {  // Safe bound
        entry[i] = user_input[i];
        i++;
    }
    char entryCode[4] = {1, 2, 3, 4};
    for (int j = 0; j < 4; j++) {
        if (entry[j] != entryCode[j]) {
            return 0;
        }
    }
    return 1;
}

void syringepump() {
    int steps = 5 * ustepsPerML;  // 65
    klee_print_expr("CRITICAL: Pump executing overdose bolus, steps =", steps);
}

int main() {
    // Symbolize the 5-byte input (4 bytes + terminator)
    klee_make_symbolic(user_input, sizeof(user_input), "user_input");
    // Common: last byte often \r or \n
    // user_input[4] = '\r';  // Optional: fix terminator

    char entry[5] = {0};
    verify_entry = read_data(entry);

    if (verify_entry) {
        printf("VERIFICATION BYPASSED - EXECUTING PUMP!\n");
        syringepump();
    } else {
        printf("Safe: Verification failed.\n");
    }

    return 0;
}
