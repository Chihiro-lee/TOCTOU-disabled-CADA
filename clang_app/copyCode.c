#include <klee/klee.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define SIZE (512 * 3)  // 1536 bytes
#define WORD_COUNT (SIZE / 2)

uint16_t src[WORD_COUNT];  // 符号化源缓冲区
uint16_t dst[WORD_COUNT];

bool verify_copy() {
    for (size_t i = 0; i < WORD_COUNT; i++) {
        if (dst[i] != src[i]) {
            return false;
        }
    }
    return true;
}

int main() {
    // 符号化前 100 个字（200 字节），避免路径爆炸
    klee_make_symbolic(src, 100 * sizeof(uint16_t), "src_partial");

    // 其余部分填固定值（模拟真实程序）
    for (size_t i = 100; i < WORD_COUNT; i++) {
        src[i] = 0xABCD + (uint16_t)i;
    }

    // 模拟手动 memcpy
    memcpy(dst, src, SIZE);

    // 校验
    if (verify_copy()) {
        printf("Copy verification PASSED (normal operation)\n");
    } else {
        klee_print_expr("CRITICAL: Memory corruption detected! Modified word index =", 
                        (int)klee_get_argc());  // 示例标记
        printf("Copy verification FAILED -> Red LED (integrity breach)\n");
    }

    // 模拟 DMA 拷贝（相同）
    memcpy(dst, src, SIZE);

    if (verify_copy()) {
        printf("DMA simulation verification PASSED -> Green LED\n");
    } else {
        printf("DMA verification FAILED -> Red LED\n");
    }

    return 0;
}
