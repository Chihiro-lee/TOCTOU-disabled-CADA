#include <stdio.h>
#include <stdint.h>
#include <klee/klee.h>

#define BLOCK_SIZE 16  

int main() {
    uint16_t src[BLOCK_SIZE];
    uint16_t dst[BLOCK_SIZE];

    // 符号化源
    klee_make_symbolic(src, sizeof(src), "src");

    // 模拟传输
    for (int i = 0; i < BLOCK_SIZE; i++) {
        dst[i] = src[i];
    }

    // 添加分支：求和阈值
    uint32_t sum = 0;
    for (int i = 0; i < BLOCK_SIZE; i++) {
        sum += src[i];
    }
    if (sum > 0xFFFF) {
        printf("High sum: %u\n", sum);
    } else {
        printf("Low sum: %u\n", sum);
    }

    // 拷贝检查分支
    int mismatch = 0;
    for (int i = 0; i < BLOCK_SIZE; i++) {
        if (dst[i] != src[i]) {
            mismatch = 1;
            break;
        }
    }
    if (mismatch) {
        printf("Copy mismatch!\n");
    } else {
        printf("Copy successful.\n");
    }

    return 0;
}
