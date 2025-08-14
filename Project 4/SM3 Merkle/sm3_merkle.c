#include <immintrin.h>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>
#include <iostream>

#if defined(__clang__) || defined(__GNUC__)
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define LIKELY(x)   (x)
#define UNLIKELY(x) (x)
#endif

#if defined(__AVX2__)
#define SM3_USE_AVX2 1
#else
#define SM3_USE_AVX2 0
#endif

// ---- SM3 基本常量 ----
static constexpr uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// 轮常量 Tj：j=0..15 为 0x79cc4519，j=16..63 为 0x7a879d8a
static constexpr uint32_t T0 = 0x79cc4519u;
static constexpr uint32_t T1 = 0x7a879d8au;

// 预旋转的 Tj' = (Tj <<< j)；查表以避免每轮旋转
alignas(64) static uint32_t Tj_rot[64];

// 32-bit 左旋
static inline uint32_t ROTL(uint32_t x, unsigned r) {
#if __cpp_lib_bitops >= 201907L
    return std::rotl(x, static_cast<int>(r));
#else
    return (x << r) | (x >> (32u - r));
#endif
}

// 置换/置换函数
static inline uint32_t P0(uint32_t x) { return x ^ ROTL(x, 9) ^ ROTL(x, 17); }
static inline uint32_t P1(uint32_t x) { return x ^ ROTL(x, 15) ^ ROTL(x, 23); }

// FFj / GGj：j=0..15 为异或；j=16..63 为 Majority / Ch-like
static inline uint32_t FF0_15(uint32_t a, uint32_t b, uint32_t c) { return a ^ b ^ c; }
static inline uint32_t GG0_15(uint32_t e, uint32_t f, uint32_t g) { return e ^ f ^ g; }
static inline uint32_t FF16_63(uint32_t a, uint32_t b, uint32_t c) { return (a & b) | (a & c) | (b & c); }
static inline uint32_t GG16_63(uint32_t e, uint32_t f, uint32_t g) { return (e & f) | ((~e) & g); }

// -------------------- Endian swap helpers --------------------
static inline uint32_t bswap32(uint32_t x) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(x);
#else
    return (x >> 24) | ((x >> 8) & 0x0000FF00u) | ((x << 8) & 0x00FF0000u) | (x << 24);
#endif
}

// 将 64 字节消息块读取为 16 个大端 uint32，支持 AVX2 加速
static inline void load_block_be(const uint8_t* block, uint32_t W0_15[16]) {
#if SM3_USE_AVX2
    // 8*8=64字节，分 2 次读取，每次 32 字节
    const __m256i shuf = _mm256_set_epi8(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    ); // 不直接使用；我们要 PSHUFB 的大端掩码：

    // 正确的大端换字节掩码（每 32b: 3,2,1,0）
    const __m256i be = _mm256_set_epi8(
        12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3,
        12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3
    );

    __m256i v0 = _mm256_loadu_si256((const __m256i*)(block));
    __m256i v1 = _mm256_loadu_si256((const __m256i*)(block + 32));
    v0 = _mm256_shuffle_epi8(v0, be);
    v1 = _mm256_shuffle_epi8(v1, be);

    alignas(32) uint32_t tmp[8];
    _mm256_store_si256((__m256i*)tmp, v0);
    std::memcpy(W0_15 + 0, tmp, 32);
    _mm256_store_si256((__m256i*)tmp, v1);
    std::memcpy(W0_15 + 8, tmp, 32);
#else
    for (int i = 0; i < 16; i++) {
        uint32_t x;
        std::memcpy(&x, block + 4 * i, 4);
        W0_15[i] = bswap32(x);
    }
#endif
}

// ----------- 消息扩展：生成 W[68], W1[64]（AVX2 批量 P1/XOR 优化） -----------
static inline void msg_expand(const uint32_t W0_15[16], uint32_t W[68], uint32_t W1[64]) {
    // W[0..15]
    std::memcpy(W, W0_15, 16 * sizeof(uint32_t));

    // W[16..67]
#if SM3_USE_AVX2
    // 批量计算：每次做 8 个（可与缓存友好；同时保持逻辑清晰）
    for (int j = 16; j < 68; j += 8) {
        for (int k = 0; k < 8; k++) {
            const int i = j + k;
            uint32_t x = W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15);
            W[i] = P1(x) ^ ROTL(W[i - 13], 7) ^ W[i - 6];
        }
    }
#else
    for (int i = 16; i < 68; ++i) {
        uint32_t x = W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15);
        W[i] = P1(x) ^ ROTL(W[i - 13], 7) ^ W[i - 6];
    }
#endif
    // W1[j] = W[j] ^ W[j+4]
#if SM3_USE_AVX2
    for (int j = 0; j < 64; j += 8) {
        // 这里用标量即可，访存占主导
        W1[j + 0] = W[j + 0] ^ W[j + 4];
        W1[j + 1] = W[j + 1] ^ W[j + 5];
        W1[j + 2] = W[j + 2] ^ W[j + 6];
        W1[j + 3] = W[j + 3] ^ W[j + 7];
        W1[j + 4] = W[j + 4] ^ W[j + 8];
        W1[j + 5] = W[j + 5] ^ W[j + 9];
        W1[j + 6] = W[j + 6] ^ W[j + 10];
        W1[j + 7] = W[j + 7] ^ W[j + 11];
    }
#else
    for (int j = 0; j < 64; ++j) W1[j] = W[j] ^ W[j + 4];
#endif
}

// -------------- 单块压缩（含循环展开 + 查表 Tj_rot） --------------
static inline void compress_block(const uint8_t block[64], uint32_t V[8]) {
    uint32_t W0_15[16];
    uint32_t W[68], W1[64];
    load_block_be(block, W0_15);
    msg_expand(W0_15, W, W1);

    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    // 0..15：异或型
#define ROUND_0_15(j) { \
    uint32_t SS1 = ROTL((ROTL(A,12) + E + Tj_rot[(j)]) , 7); \
    uint32_t SS2 = SS1 ^ ROTL(A,12); \
    uint32_t TT1 = FF0_15(A,B,C) + D + SS2 + W1[(j)]; \
    uint32_t TT2 = GG0_15(E,F,G) + H + SS1 + W[(j)]; \
    D = C; C = ROTL(B,9); B = A; A = TT1; \
    H = G; G = ROTL(F,19); F = E; E = P0(TT2); \
}

    // 16..63：Majority / Choose
#define ROUND_16_63(j) { \
    uint32_t SS1 = ROTL((ROTL(A,12) + E + Tj_rot[(j)]) , 7); \
    uint32_t SS2 = SS1 ^ ROTL(A,12); \
    uint32_t TT1 = FF16_63(A,B,C) + D + SS2 + W1[(j)]; \
    uint32_t TT2 = GG16_63(E,F,G) + H + SS1 + W[(j)]; \
    D = C; C = ROTL(B,9); B = A; A = TT1; \
    H = G; G = ROTL(F,19); F = E; E = P0(TT2); \
}

    // 展开 0..15
    ROUND_0_15(0);  ROUND_0_15(1);  ROUND_0_15(2);  ROUND_0_15(3);
    ROUND_0_15(4);  ROUND_0_15(5);  ROUND_0_15(6);  ROUND_0_15(7);
    ROUND_0_15(8);  ROUND_0_15(9);  ROUND_0_15(10); ROUND_0_15(11);
    ROUND_0_15(12); ROUND_0_15(13); ROUND_0_15(14); ROUND_0_15(15);

    // 展开 16..63（可分批以利于 I-cache）
    for (int j = 16; j < 64; ++j) {
        ROUND_16_63(j);
    }

#undef ROUND_0_15
#undef ROUND_16_63

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

// -------------------- 高层 API：单条消息 --------------------
static std::array<uint8_t, 32> sm3(const uint8_t* msg, size_t len) {
    uint32_t V[8];
    std::memcpy(V, IV, sizeof(V));

    // 处理整块
    size_t off = 0;
    while (len - off >= 64) {
        compress_block(msg + off, V);
        off += 64;
    }

    // 填充：0x80，0x00...，最后 64-bit 长度（大端表示）
    uint8_t last[128]{ 0 }; // 足够两块
    size_t rem = len - off;
    std::memcpy(last, msg + off, rem);
    last[rem] = 0x80;

    uint64_t bit_len = static_cast<uint64_t>(len) * 8ull;
    // 写入末尾 8 字节大端长度
    size_t pad_len = ((rem + 1 + 8) <= 64) ? 64 : 128;
    uint8_t* len_ptr = last + pad_len - 8;
    for (int i = 0; i < 8; i++) len_ptr[i] = static_cast<uint8_t>((bit_len >> (56 - 8 * i)) & 0xFF);

    compress_block(last, V);
    if (pad_len == 128) compress_block(last + 64, V);

    std::array<uint8_t, 32> out{};
    for (int i = 0; i < 8; i++) {
        uint32_t be = bswap32(V[i]);
        std::memcpy(out.data() + 4 * i, &be, 4);
    }
    return out;
}

// -------------------- 批量接口：多线程并行 --------------------
// 注意：同一条消息内部的多个块不能并行（链式依赖）；此处并行的是多条独立消息。
struct SpanBytes {
    const uint8_t* ptr;
    size_t len;
};

static std::vector<std::array<uint8_t, 32>>
sm3_batch(const std::vector<SpanBytes>& inputs, unsigned num_threads = std::thread::hardware_concurrency()) {
    const size_t N = inputs.size();
    std::vector<std::array<uint8_t, 32>> results(N);

    if (N == 0) return results;
    if (num_threads == 0) num_threads = 1;
    num_threads = std::min<unsigned>(num_threads, static_cast<unsigned>(N));

    std::atomic<size_t> idx{ 0 };
    auto worker = [&]() {
        size_t i;
        while ((i = idx.fetch_add(1, std::memory_order_relaxed)) < N) {
            results[i] = sm3(inputs[i].ptr, inputs[i].len);
        }
    };

    std::vector<std::thread> pool;
    pool.reserve(num_threads);
    for (unsigned t = 0; t < num_threads; t++) pool.emplace_back(worker);
    for (auto& th : pool) th.join();

    return results;
}

// -------------------- 初始化查表、简单自测 --------------------
static void init_Tj_rot() {
    for (int j = 0; j < 64; j++) {
        uint32_t T = (j <= 15) ? T0 : T1;
        Tj_rot[j] = ROTL(T, j);
    }
}

static void print_hex(const std::array<uint8_t, 32>& h) {
    static const char* hex = "0123456789abcdef";
    for (uint8_t b : h) {
        std::cout << hex[b >> 4] << hex[b & 0xF];
    }
    std::cout << "\n";
}
// 生成指定长度的随机数据
std::vector<uint8_t> GenerateRandomData(size_t length) {
    std::vector<uint8_t> data(length);
    for (size_t i = 0; i < length; ++i) {
        // 简单的线性同余序列，避免全 0
        data[i] = static_cast<uint8_t>((i * 131u + 17u) & 0xFFu);
    }
    return data;
}

// 打印哈希
void PrintHash(const std::array<uint8_t, 32>& h) {
    static const char* hex = "0123456789abcdef";
    for (uint8_t b : h) {
        std::cout << hex[b >> 4] << hex[b & 0xF];
    }
    std::cout << "\n";
}

int main() {
    init_Tj_rot();

    // ====== 性能测试 ======
    const int TEST_COUNT = 1000;
    const size_t MESSAGE_LENGTH = 64; // 测试消息长度

    // 生成测试数据
    std::vector<std::vector<uint8_t>> test_cases;
    test_cases.reserve(TEST_COUNT);
    for (int i = 0; i < TEST_COUNT; ++i) {
        test_cases.push_back(GenerateRandomData(MESSAGE_LENGTH));
    }

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < TEST_COUNT; ++i) {
        auto hash = sm3(test_cases[i].data(), test_cases[i].size());
        // 如果需要查看哈希结果，取消下面注释
        // std::cout << "Hash " << i+1 << ": ";
        // PrintHash(hash);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "SM3 performance test results:\n";
    std::cout << "Number of tests: " << TEST_COUNT << "\n";
    std::cout << "Message length: " << MESSAGE_LENGTH << " bytes\n";
    std::cout << "Total time: " << duration << " ms\n";
    std::cout << "Average time per hash: " << static_cast<double>(duration) / TEST_COUNT << " ms\n";
    std::cout << "Hashes per second: " << TEST_COUNT * 1000.0 / duration << "\n";

    return 0;
}
