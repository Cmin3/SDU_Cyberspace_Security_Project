#include <iostream>
#include <iomanip>
#include <vector>
#include <random>
#include <chrono>
#include <string>
#include <bitset>

// 常量定义
const uint32_t T[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

// 初始值IV
const uint32_t IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

// 布尔函数
uint32_t FF(uint32_t X, uint32_t Y, uint32_t Z, uint32_t j) {
    if (j < 16) {
        return X ^ Y ^ Z;
    } else {
        return (X & Y) | (X & Z) | (Y & Z);
    }
}

uint32_t GG(uint32_t X, uint32_t Y, uint32_t Z, uint32_t j) {
    if (j < 16) {
        return X ^ Y ^ Z;
    } else {
        return (X & Y) | (~X & Z);
    }
}

// 置换函数
uint32_t P0(uint32_t X) {
    return X ^ ((X << 9) | (X >> 23)) ^ ((X << 17) | (X >> 15));
}

uint32_t P1(uint32_t X) {
    return X ^ ((X << 15) | (X >> 17)) ^ ((X << 23) | (X >> 9));
}

// 消息扩展
void MessageExtension(const uint8_t* block, uint32_t* W, uint32_t* W1) {
    // 将消息分组划分为16个字
    for (int i = 0; i < 16; ++i) {
        W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | 
                (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    
    // 扩展132个字
    for (int j = 16; j < 68; ++j) {
        W[j] = P1(W[j-16] ^ W[j-9] ^ ((W[j-3] << 15) | (W[j-3] >> 17))) ^ 
               ((W[j-13] << 7) | (W[j-13] >> 25)) ^ W[j-6];
    }
    
    // 扩展64个字W'
    for (int j = 0; j < 64; ++j) {
        W1[j] = W[j] ^ W[j+4];
    }
}

// 压缩函数
void CompressionFunction(uint32_t* V, const uint32_t* W, const uint32_t* W1) {
    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];
    
    for (int j = 0; j < 64; ++j) {
        uint32_t SS1 = ((A << 12) | (A >> 20)) + E + ((T[j] << (j % 32)) | (T[j] >> (32 - (j % 32))));
        SS1 = ((SS1 << 7) | (SS1 >> 25));
        uint32_t SS2 = SS1 ^ ((A << 12) | (A >> 20));
        
        uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];
        
        D = C;
        C = (B << 9) | (B >> 23);
        B = A;
        A = TT1;
        H = G;
        G = (F << 19) | (F >> 13);
        F = E;
        E = P0(TT2);
    }
    
    V[0] ^= A;
    V[1] ^= B;
    V[2] ^= C;
    V[3] ^= D;
    V[4] ^= E;
    V[5] ^= F;
    V[6] ^= G;
    V[7] ^= H;
}

// SM3哈希函数
std::vector<uint8_t> SM3(const uint8_t* message, size_t length) {
    // 初始化变量
    uint32_t V[8];
    for (int i = 0; i < 8; ++i) {
        V[i] = IV[i];
    }
    
    // 填充消息
    size_t block_count = (length + 1 + 8 + 63) / 64;
    std::vector<uint8_t> padded_message(block_count * 64, 0);
    std::copy(message, message + length, padded_message.begin());
    padded_message[length] = 0x80;
    
    uint64_t bit_length = length * 8;
    for (int i = 0; i < 8; ++i) {
        padded_message[block_count * 64 - 8 + i] = (bit_length >> (56 - i * 8)) & 0xff;
    }
    
    // 处理消息分组
    uint32_t W[68], W1[64];
    for (size_t i = 0; i < block_count; ++i) {
        MessageExtension(&padded_message[i * 64], W, W1);
        CompressionFunction(V, W, W1);
    }
    
    // 生成哈希值
    std::vector<uint8_t> hash(32);
    for (int i = 0; i < 8; ++i) {
        hash[i * 4] = (V[i] >> 24) & 0xff;
        hash[i * 4 + 1] = (V[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (V[i] >> 8) & 0xff;
        hash[i * 4 + 3] = V[i] & 0xff;
    }
    
    return hash;
}

// 生成随机数据
std::vector<uint8_t> GenerateRandomData(size_t length) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    std::vector<uint8_t> data(length);
    for (size_t i = 0; i < length; ++i) {
        data[i] = static_cast<uint8_t>(dis(gen));
    }
    return data;
}

// 打印哈希值
void PrintHash(const std::vector<uint8_t>& hash) {
    for (uint8_t byte : hash) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
}

int main() {
    const int TEST_COUNT = 1000;
    const size_t MESSAGE_LENGTH = 64; // 测试消息长度，可根据需要调整
    
    // 生成测试数据
    std::vector<std::vector<uint8_t>> test_cases;
    for (int i = 0; i < TEST_COUNT; ++i) {
        test_cases.push_back(GenerateRandomData(MESSAGE_LENGTH));
    }
    
    // 性能测试
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < TEST_COUNT; ++i) {
        auto hash = SM3(test_cases[i].data(), test_cases[i].size());
        // 如果需要查看哈希结果，取消下面注释
        // std::cout << "Hash " << i+1 << ": ";
        // PrintHash(hash);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    std::cout << "SM3 performance test results:" << std::endl;
    std::cout << "Number of tests: " << TEST_COUNT << std::endl;
    std::cout << "Message length: " << MESSAGE_LENGTH << " bytes" << std::endl;
    std::cout << "Total time: " << duration << " ms" << std::endl;
    std::cout << "Average time per hash: " << static_cast<double>(duration) / TEST_COUNT << " ms" << std::endl;
    std::cout << "Hashes per second: " << TEST_COUNT * 1000.0 / duration << std::endl;
    
    return 0;
}