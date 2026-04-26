#include <klee/klee.h>
#include <stdio.h>
#include <stdint.h>

#define ULT_PIN 0x02
#define MAX_DURATION 1000

unsigned long pulseIn(void) {
    // 符号化模拟距离（0 ~ 400 cm，HC-SR04 有效范围）
    int simulated_distance_cm;
    klee_make_symbolic(&simulated_distance_cm, sizeof(simulated_distance_cm), "distance_cm");
    klee_assume(simulated_distance_cm >= 0);
    klee_assume(simulated_distance_cm <= 400);

    unsigned long duration = 0;
    unsigned long expected_high_us = (unsigned long)(simulated_distance_cm * 58);

    int i = 0;
    while (i < MAX_DURATION) {
        if (i < expected_high_us && expected_high_us < MAX_DURATION) {
            duration += 2;  // Bit high
        }
        // else add 0
        i++;
    }
    return duration;
}

long getUltrasonicReading(void) {
    unsigned long duration = pulseIn();
    return (long)duration;
}

int main() {
    long reading = getUltrasonicReading();

    // 添加实际可能的分支逻辑（创建多路径）
    if (reading < 400) {  // < ~3.4cm (极近)
        printf("Object very close! reading=%ld\n", reading);
    } else if (reading < 11600) {  // < ~100cm
        printf("Object detected within 1m: %ld\n", reading);
    } else if (reading < 46400) {  // < ~400cm
        printf("Far object: %ld\n", reading);
    } else {
        printf("No object or out of range: %ld\n", reading);
    }

    // 模拟危险分支：如果误判为“无障碍”却实际很近（潜在自动驾驶/机器人bug）
    if (reading > 2000) {  // 认为“安全”
        klee_print_expr("SAFE ASSUMED (potentially dangerous if miscalibrated)", reading);
    }

    return 0;
}
