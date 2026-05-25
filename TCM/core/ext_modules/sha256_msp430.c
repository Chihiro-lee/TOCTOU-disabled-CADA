#include <msp430.h>
#include "sha256_msp430.h"

static uint8_t g_sha256_state[32] = {0};
static uint8_t g_msg40[40];
volatile uint64_t r6_value = 0;

static const uint32_t K256[64] __attribute__((section(".tcm:rodata"))) = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static const uint32_t Initial_Hash[8] __attribute__((section(".tcm:rodata"))) = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
};

#define SR(x,a)          ((x) >> (a))
#define ROTR(x,n)        (((x) >> (n)) | ((x) << (32U - (n))))
#define Ch(x,y,z)        (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x,y,z)       (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGZ(x)          (ROTR((x),2U) ^ ROTR((x),13U) ^ ROTR((x),22U))
#define SIG1(x)          (ROTR((x),6U) ^ ROTR((x),11U) ^ ROTR((x),25U))
#define sigmaZ(x)        (ROTR((x),7U) ^ ROTR((x),18U) ^ SR((x),3U))
#define sigma1(x)        (ROTR((x),17U) ^ ROTR((x),19U) ^ SR((x),10U))

__attribute__((section(".tcm:codeUpper")))
static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         | (uint32_t)p[3];
}

__attribute__((section(".tcm:codeUpper")))
static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

__attribute__((section(".tcm:codeUpper")))
static void shaHelper(uint32_t *message, uint32_t *Hash)
{
    uint32_t W[16] = {0U};
    uint8_t t;

    uint32_t a = Hash[0];
    uint32_t b = Hash[1];
    uint32_t c = Hash[2];
    uint32_t d = Hash[3];
    uint32_t e = Hash[4];
    uint32_t f = Hash[5];
    uint32_t g = Hash[6];
    uint32_t h = Hash[7];

    for (t = 0U; t < 64U; t++) {
        if (t < 16U) {
            W[t] = message[t];
        } else {
            W[t % 16U] = sigma1(W[(t - 2U) % 16U]) + W[(t - 7U) % 16U]
                       + sigmaZ(W[(t - 15U) % 16U]) + W[(t - 16U) % 16U];
        }

        {
            uint32_t temp1 = h + SIG1(e) + Ch(e, f, g) + K256[t] + W[t % 16U];
            uint32_t temp2 = Maj(a, b, c) + SIGZ(a);

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
    }

    Hash[0] += a;
    Hash[1] += b;
    Hash[2] += c;
    Hash[3] += d;
    Hash[4] += e;
    Hash[5] += f;
    Hash[6] += g;
    Hash[7] += h;
}

__attribute__((section(".tcm:codeUpper")))
static void SHA_2(uint32_t *Message, uint32_t MessageLengthBytes, uint32_t *Hash)
{
    uint64_t Mbit_Length = (uint64_t)MessageLengthBytes * 8U;
    uint64_t M_Length = Mbit_Length >> 5;
    uint64_t Nblocks = M_Length >> 4;
    uint32_t leftoverlong = (uint32_t)(M_Length % 16U);
    uint32_t leftoverbits = (uint32_t)(Mbit_Length % 32U);
    uint32_t onemask = 0x80000000UL >> leftoverbits;
    uint32_t zeromask = ~(0x7FFFFFFFUL >> leftoverbits);
    uint32_t lastchunk = (uint32_t)(16U * Nblocks);
    uint32_t total_blocks;
    uint32_t i;

    for (i = 0U; i < 8U; i++) {
        Hash[i] = Initial_Hash[i];
    }

    Message[M_Length] = (Message[M_Length] | onemask);
    Message[M_Length] = (Message[M_Length] & zeromask);

    if ((Mbit_Length % 512U) < 448U) {
        uint32_t v;
        for (v = 1U; v < (14U - leftoverlong); v++) {
            Message[lastchunk + leftoverlong + v] = 0U;
        }
        Message[lastchunk + 14U] = (uint32_t)(Mbit_Length >> 32U);
        Message[lastchunk + 15U] = (uint32_t)(Mbit_Length & 0xFFFFFFFFULL);
    } else {
        uint32_t p;
        for (p = 1U; p < (16U - leftoverlong); p++) {
            Message[lastchunk + leftoverlong + p] = 0U;
        }
        for (p = 0U; p < 14U; p++) {
            Message[lastchunk + 16U + p] = 0U;
        }
        Message[lastchunk + 30U] = (uint32_t)(Mbit_Length >> 32U);
        Message[lastchunk + 31U] = (uint32_t)(Mbit_Length & 0xFFFFFFFFULL);
    }

    total_blocks = (uint32_t)((Mbit_Length + 64U) / 512U)
                 + (uint32_t)((((Mbit_Length + 64U) & 0x1FFU) != 0U) ? 1U : 0U);

    for (i = 0U; i < total_blocks; i++) {
        shaHelper(Message + (16U * i), Hash);
    }
}

__attribute__((section(".tcm:codeUpper")))
static void sha256_update_chain(uint64_t rv)
{
    uint16_t i;
    uint32_t message_words[32] = {0U};
    uint32_t hash_words[8] = {0U};

    for (i = 0U; i < 32U; i++) {
        g_msg40[i] = g_sha256_state[i];
    }
    for (i = 0U; i < 8U; i++) {
        g_msg40[32U + i] = (uint8_t)(rv >> (8U * i));
    }

    for (i = 0U; i < 10U; i++) {
        message_words[i] = load_be32(g_msg40 + (i * 4U));
    }

    SHA_2(message_words, 40U, hash_words);

    for (i = 0U; i < 8U; i++) {
        store_be32(g_sha256_state + (i * 4U), hash_words[i]);
    }
}

__attribute__((section(".tcm:codeUpper")))
void sha256_compute(void)
{
    WDTCTL = WDTPW | WDTHOLD;
    __dint();

    __asm("mov.w r8, &write_count_lee");

    P4SEL |= BIT4 + BIT5;
    UCA1CTL1 |= UCSWRST;
    UCA1CTL1 |= UCSSEL_1;
    UCA1BR0 = 3;
    UCA1MCTL = 0xD6;
    UCA1CTL0 = 0x00;
    UCA1CTL1 &= ~UCSWRST;
    UCA1IE |= UCRXIE;

    uint64_t rv = r6_value;

    sha256_update_chain(rv);

    uart_send_hex_data(g_sha256_state, 32);
    uart_send_byte(0x54);
    uart_send_byte(0x0A);
    uart_send_byte(0x0D);

    __asm("mov.w &write_count_lee, r8");
}

__attribute__((section(".tcm:codeUpper")))
void sha256_compute_no_send(void)
{
    WDTCTL = WDTPW | WDTHOLD;
    __dint();

    __asm("mov.w r8, &write_count_lee");

    uint64_t rv = r6_value;

    sha256_update_chain(rv);
    
    __asm("mov.w &write_count_lee, r8");
}

__attribute__((section(".tcm:codeUpper")))
void sha256_send(void)
{
    WDTCTL = WDTPW | WDTHOLD;
    __dint();

    __asm("mov.w r8, &write_count_lee");

    P4SEL |= BIT4 + BIT5;
    UCA1CTL1 |= UCSWRST;
    UCA1CTL1 |= UCSSEL_1;
    UCA1BR0 = 3;
    UCA1MCTL = 0xD6;
    UCA1CTL0 = 0x00;
    UCA1CTL1 &= ~UCSWRST;
    UCA1IE |= UCRXIE;

    uart_send_hex_data(g_sha256_state, 32);
    uart_send_byte(0x54);
    uart_send_byte(0x0A);
    uart_send_byte(0x0D);

    __asm("mov.w &write_count_lee, r8");
}

__attribute__((section(".tcm:codeUpper")))
void sha256_send_with_write_count(void)
{
    WDTCTL = WDTPW | WDTHOLD;
    __dint();

    __asm("mov.w r8, &write_count_lee");

    P4SEL |= BIT4 + BIT5;
    UCA1CTL1 |= UCSWRST;
    UCA1CTL1 |= UCSSEL_1;
    UCA1BR0 = 3;
    UCA1MCTL = 0xD6;
    UCA1CTL0 = 0x00;
    UCA1CTL1 &= ~UCSWRST;
    UCA1IE |= UCRXIE;

    uart_send_hex_data(g_sha256_state, 32);
    
    uint16_to_bytes(write_count_lee, write_count_lee_bytes);
    
    uart_send_hex_data(write_count_lee_bytes, 2);
    
    uart_send_byte(0x54);
    uart_send_byte(0x0A);
    uart_send_byte(0x0D);

    __asm("mov.w &write_count_lee, r8");
}
