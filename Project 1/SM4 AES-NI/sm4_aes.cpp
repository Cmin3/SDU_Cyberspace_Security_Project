#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <emmintrin.h>  // SSE2

// -------------------- T-table 已初始化 --------------------
extern uint32_t T0[256], T1[256], T2[256], T3[256];
void sm4_init_ttable(); // 初始化 T-table

// -------------------- SM4 Key 扩展 --------------------
void sm4_key_schedule(const uint8_t MK[16], uint32_t rk[32]);

// -------------------- SSE2 批量加密 4 块 --------------------
void sm4_encrypt_4blocks_sse(uint8_t in[4][16], uint8_t out[4][16], const uint32_t rk[32]) {
    __m128i X[36];

    // 初始化 X0~X3
    for (int i = 0; i < 4; i++) {
        X[i] = _mm_loadu_si128((__m128i*)in[i]);
    }

    // 临时存储每轮值
    __m128i tmp, t;

    // 32 轮加密
    for (int r = 0; r < 32; r++) {
        // 轮函数：X[i+4] = X[i] ^ T(X[i+1]^X[i+2]^X[i+3]^rk[r])
        tmp = _mm_xor_si128(_mm_xor_si128(X[r+1], X[r+2]), X[r+3]);

        // 由于 SSE2 无法直接做 32-bit 查表，这里演示思想：
        // 1. 将 tmp 拆成 4 个 uint32
        // 2. 对每个 uint32 做 T0~T3 查表
        uint32_t val[4];
        _mm_storeu_si128((__m128i*)val, tmp);
        for (int i = 0; i < 4; i++) {
            uint32_t x = val[i] ^ rk[r];
            uint32_t t_val = T0[(x >> 24) & 0xFF] ^
                             T1[(x >> 16) & 0xFF] ^
                             T2[(x >> 8) & 0xFF] ^
                             T3[x & 0xFF];
            val[i] = ((uint32_t*)X[r])[i] ^ t_val;
        }
        X[r+4] = _mm_loadu_si128((__m128i*)val);
    }

    // 输出
    for (int i = 0; i < 4; i++) {
        _mm_storeu_si128((__m128i*)out[i], X[35-i]);
    }
}

// -------------------- 性能测试 --------------------
void performance_test(int num_tests) {
    uint8_t keys[4][16], plaintexts[4][16], ciphertexts[4][16];
    uint32_t rk[32];
    srand((unsigned)time(NULL));
    clock_t start = clock();

    for (int i = 0; i < num_tests; i+=4) {
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 16; k++) {
                keys[j][k] = rand() % 256;
                plaintexts[j][k] = rand() % 256;
            }
            sm4_key_schedule(keys[j], rk); // 每块独立 key
        }
        sm4_encrypt_4blocks_sse(plaintexts, ciphertexts, rk);
    }

    clock_t end = clock();
    double total_time_us = (double)(end - start) / CLOCKS_PER_SEC * 1e6;
    printf("测试次数: %d\n", num_tests);
    printf("总耗时: %.2f 微秒\n", total_time_us);
    printf("平均耗时: %.2f 微秒/块\n", total_time_us / num_tests);
}

int main() {
    sm4_init_ttable();
    performance_test(1000); // 测试 1000 块
    return 0;
}
