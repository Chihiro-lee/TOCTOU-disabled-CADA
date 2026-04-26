#include <msp430.h>
#include "sha256_msp430.h"

static uint8_t g_sha256_state[32] = {0};
static uint8_t g_msg40[40];
volatile uint64_t r6_value = 0;

static const uint32_t k_sha256[64] __attribute__((section(".tcm:rodata"))) = {
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

__attribute__((section(".tcm:codeUpper")))
static uint32_t rotr32(uint32_t x, uint8_t n)
{
    return (x >> n) | (x << (32U - n));
}

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
static void sha256_hash_40(const uint8_t *msg, uint8_t *out)
{
    uint32_t h0 = 0x6a09e667U;
    uint32_t h1 = 0xbb67ae85U;
    uint32_t h2 = 0x3c6ef372U;
    uint32_t h3 = 0xa54ff53aU;
    uint32_t h4 = 0x510e527fU;
    uint32_t h5 = 0x9b05688cU;
    uint32_t h6 = 0x1f83d9abU;
    uint32_t h7 = 0x5be0cd19U;

    uint8_t blk[64] = {0};
    uint8_t blk2[64] = {0};
    uint32_t w[64];
    uint8_t i;

    for (i = 0; i < 40U; i++) {
        blk[i] = msg[i];
    }
    blk[40] = 0x80U;
    blk2[63] = 320U;

    {
        uint8_t t;
        for (t = 0; t < 16U; t++) {
            w[t] = load_be32(blk + (uint16_t)t * 4U);
        }
        for (t = 16U; t < 64U; t++) {
            uint32_t s0 = rotr32(w[t - 15U], 7U) ^ rotr32(w[t - 15U], 18U) ^ (w[t - 15U] >> 3U);
            uint32_t s1 = rotr32(w[t - 2U], 17U) ^ rotr32(w[t - 2U], 19U) ^ (w[t - 2U] >> 10U);
            w[t] = w[t - 16U] + s0 + w[t - 7U] + s1;
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        for (t = 0; t < 64U; t++) {
            uint32_t S1 = rotr32(e, 6U) ^ rotr32(e, 11U) ^ rotr32(e, 25U);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + k_sha256[t] + w[t];
            uint32_t S0 = rotr32(a, 2U) ^ rotr32(a, 13U) ^ rotr32(a, 22U);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    {
        uint8_t t;
        for (t = 0; t < 16U; t++) {
            w[t] = load_be32(blk2 + (uint16_t)t * 4U);
        }
        for (t = 16U; t < 64U; t++) {
            uint32_t s0 = rotr32(w[t - 15U], 7U) ^ rotr32(w[t - 15U], 18U) ^ (w[t - 15U] >> 3U);
            uint32_t s1 = rotr32(w[t - 2U], 17U) ^ rotr32(w[t - 2U], 19U) ^ (w[t - 2U] >> 10U);
            w[t] = w[t - 16U] + s0 + w[t - 7U] + s1;
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        for (t = 0; t < 64U; t++) {
            uint32_t S1 = rotr32(e, 6U) ^ rotr32(e, 11U) ^ rotr32(e, 25U);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + k_sha256[t] + w[t];
            uint32_t S0 = rotr32(a, 2U) ^ rotr32(a, 13U) ^ rotr32(a, 22U);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    store_be32(out + 0U, h0);
    store_be32(out + 4U, h1);
    store_be32(out + 8U, h2);
    store_be32(out + 12U, h3);
    store_be32(out + 16U, h4);
    store_be32(out + 20U, h5);
    store_be32(out + 24U, h6);
    store_be32(out + 28U, h7);
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

    {
        uint16_t i;
        uint64_t rv = r6_value;
        for (i = 0; i < 32; i++) {
            g_msg40[i] = g_sha256_state[i];
        }
        for (i = 0; i < 8; i++) {
            g_msg40[32 + i] = (uint8_t)(rv >> (8U * i));
        }
    }

    sha256_hash_40(g_msg40, g_sha256_state);

    uart_send_hex_data(g_sha256_state, 32);
    uart_send_byte(0x54);
    uart_send_byte(0x0A);
    uart_send_byte(0x0D);

    __asm("mov.w &write_count_lee, r8");
}
