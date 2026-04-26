#include <stdio.h>
#include <klee/klee.h>

#define MAX_BYTES 10  // 限制大小避免路径爆炸，实际可调

int main(){
    unsigned char bytes[MAX_BYTES];
    int p1out = 0;

    // 符号化输入字节
    klee_make_symbolic(bytes, sizeof(bytes), "bytes");

    for (int i = 0; i < MAX_BYTES; i++) {
        unsigned char byte = bytes[i];

        // 模拟 echo（打印代替 write）
        printf("Echo: 0x%02X\n", byte);

        // 翻转 p1out
        p1out ^= 1;

        // 添加分支演示 KLEE（e.g., 如果字节 > 128，特殊处理）
        if (byte > 128) {
            printf("High byte: 0x%02X, P1OUT: %d\n", byte, p1out);
        } else {
            printf("Low byte: 0x%02X, P1OUT: %d\n", byte, p1out);
        }
    }

    return 0;
}
