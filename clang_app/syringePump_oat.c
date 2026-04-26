#include <klee/klee.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define SYRINGE_VOLUME_ML 30.0
#define SYRINGE_BARREL_LENGTH_MM 80.0
#define THREADED_ROD_PITCH 1.25
#define STEPS_PER_REVOLUTION 200.0
#define MICROSTEPS_PER_STEP 16.0

long ustepsPerML = (MICROSTEPS_PER_STEP * STEPS_PER_REVOLUTION * SYRINGE_BARREL_LENGTH_MM) / (SYRINGE_VOLUME_ML * THREADED_ROD_PITCH);

enum {PUSH, PULL};
float mLBolus = 0.500;

char user_input[5];  // Will be symbolic

int read_data(char *entry) {
    int i = 0;
    while (i < 4 && user_input[i] != '\r') {  // Prevent overflow
        entry[i] = user_input[i];
        i++;
    }
    entry[i] = '\0';

    char entryCode[4] = {1, 2, 3, 4};
    for (int j = 0; j < 4; j++) {
        if (entry[j] != entryCode[j]) {
            return 0;
        }
    }
    return 1;
}

void bolus(int direction) {
    long steps = (long)(mLBolus * ustepsPerML);
    if (direction == PUSH) {
        klee_print_expr("DANGEROUS: Executing bolus (overdose possible), steps =", steps);
    }
}

int main() {
    // Make user_input symbolic (5 bytes: 4 data + \r)
    klee_make_symbolic(user_input, sizeof(user_input), "user_input");
    user_input[4] = '\r';  // Fix terminator (common in protocols)

    char verify_entry = read_data(user_input);  // Pass buffer directly

    if (verify_entry != 0) {
        klee_print_expr("CRITICAL PATH REACHED: Input verified, executing bolus!", verify_entry);
        bolus(PUSH);
        bolus(PUSH);
        bolus(PUSH);  // Simulate multiple
    } else {
        printf("Input rejected (safe).\n");
    }

    return 0;
}
