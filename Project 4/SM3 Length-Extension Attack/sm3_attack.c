#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <algorithm> // For std::copy
#include <cstdint>   // For uint32_t, uint64_t, etc.

// =======================================================================
// SM3 HASH IMPLEMENTATION (Based on GM/T 0004-2012)
// =======================================================================

// Constants
const uint32_t IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

uint32_t T(size_t j) {
    return (j >= 0 && j <= 15) ? 0x79cc4519 : 0x7a879d8a;
}

uint32_t FF(uint32_t x, uint32_t y, uint32_t z, size_t j) {
    return (j >= 0 && j <= 15) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

uint32_t GG(uint32_t x, uint32_t y, uint32_t z, size_t j) {
    return (j >= 0 && j <= 15) ? (x ^ y ^ z) : ((x & y) | (~x & z));
}

uint32_t P0(uint32_t x) {
    return x ^ ((x << 9) | (x >> (32 - 9))) ^ ((x << 17) | (x >> (32 - 17)));
}

uint32_t P1(uint32_t x) {
    return x ^ ((x << 15) | (x >> (32 - 15))) ^ ((x << 23) | (x >> (32 - 23)));
}

uint32_t RotL(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

void CompressionFunction(uint32_t V[8], const uint32_t* B) {
    uint32_t W[68];
    uint32_t W_prime[64];

    for (int j = 0; j < 16; ++j) {
        W[j] = B[j];
    }
    for (int j = 16; j < 68; ++j) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ RotL(W[j - 3], 15)) ^ RotL(W[j - 13], 7) ^ W[j - 6];
    }
    for (int j = 0; j < 64; ++j) {
        W_prime[j] = W[j] ^ W[j + 4];
    }

    uint32_t A = V[0], B_ = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
    uint32_t SS1, SS2, TT1, TT2;

    for (int j = 0; j < 64; ++j) {
        SS1 = RotL(RotL(A, 12) + E + RotL(T(j), j), 7);
        SS2 = SS1 ^ RotL(A, 12);
        TT1 = FF(A, B_, C, j) + D + SS2 + W_prime[j];
        TT2 = GG(E, F, G, j) + H + SS1 + W[j];
        D = C;
        C = RotL(B_, 9);
        B_ = A;
        A = TT1;
        H = G;
        G = RotL(F, 19);
        F = E;
        E = P0(TT2);
    }
    V[0] ^= A; V[1] ^= B_; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

/**
 * @brief Main SM3 Hash function with extensions for length attack.
 * * @param message The input message data.
 * @param length The length of the input message in bytes.
 * @param initial_state Optional initial state (IV). If nullptr, uses standard IV.
 * @param initial_len_bytes Optional initial length in bytes to add to the total.
 * @return The 32-byte SM3 hash.
 */
std::vector<uint8_t> SM3(const uint8_t* message, size_t length, const uint32_t* initial_state = nullptr, uint64_t initial_len_bytes = 0) {
    uint32_t V[8];
    if (initial_state) {
        for (int i = 0; i < 8; ++i) V[i] = initial_state[i];
    }
    else {
        for (int i = 0; i < 8; ++i) V[i] = IV[i];
    }

    // Process full blocks
    size_t num_blocks = length / 64;
    for (size_t i = 0; i < num_blocks; ++i) {
        uint32_t B[16];
        for (int j = 0; j < 16; ++j) {
            B[j] = (message[i * 64 + j * 4] << 24) |
                (message[i * 64 + j * 4 + 1] << 16) |
                (message[i * 64 + j * 4 + 2] << 8) |
                (message[i * 64 + j * 4 + 3]);
        }
        CompressionFunction(V, B);
    }

    // Padding
    size_t remaining_len = length % 64;
    std::vector<uint8_t> last_block(64 * 2, 0); // Allocate enough space for up to two blocks
    std::copy(message + num_blocks * 64, message + length, last_block.begin());
    last_block[remaining_len] = 0x80;

    uint64_t total_bit_length = (initial_len_bytes + length) * 8;

    size_t final_block_count = (remaining_len < 56) ? 1 : 2;

    for (int i = 0; i < 8; ++i) {
        last_block[final_block_count * 64 - 8 + i] = (total_bit_length >> (56 - i * 8)) & 0xff;
    }

    for (size_t i = 0; i < final_block_count; ++i) {
        uint32_t B[16];
        for (int j = 0; j < 16; ++j) {
            B[j] = (last_block[i * 64 + j * 4] << 24) |
                (last_block[i * 64 + j * 4 + 1] << 16) |
                (last_block[i * 64 + j * 4 + 2] << 8) |
                (last_block[i * 64 + j * 4 + 3]);
        }
        CompressionFunction(V, B);
    }

    std::vector<uint8_t> hash(32);
    for (int i = 0; i < 8; ++i) {
        hash[i * 4] = (V[i] >> 24) & 0xff;
        hash[i * 4 + 1] = (V[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (V[i] >> 8) & 0xff;
        hash[i * 4 + 3] = V[i] & 0xff;
    }
    return hash;
}


// =======================================================================
// ATTACK DEMONSTRATION
// =======================================================================

// Helper to print hash bytes
void PrintHash(const std::vector<uint8_t>& hash) {
    std::cout << std::hex << std::setfill('0');
    for (uint8_t byte : hash) {
        std::cout << std::setw(2) << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
}

// Helper to convert hash bytes back to internal state
void HashToState(const std::vector<uint8_t>& hash, uint32_t* state) {
    for (int i = 0; i < 8; ++i) {
        state[i] = (static_cast<uint32_t>(hash[i * 4]) << 24) |
            (static_cast<uint32_t>(hash[i * 4 + 1]) << 16) |
            (static_cast<uint32_t>(hash[i * 4 + 2]) << 8) |
            (static_cast<uint32_t>(hash[i * 4 + 3]));
    }
}

void LengthExtensionAttack() {
    // 1. 原始消息和密钥（攻击者不知道密钥）
    std::string secret_key = "myverystrongsecretkey";
    std::string original_message = "user=guest&data=payload";
    std::string full_message = secret_key + original_message;

    // 2. 计算原始哈希（这是攻击者拥有的信息）
    std::vector<uint8_t> original_hash = SM3(
        reinterpret_cast<const uint8_t*>(full_message.data()),
        full_message.size());

    std::cout << "===== Setup =====" << std::endl;
    std::cout << "Original message: " << original_message << std::endl;
    std::cout << "Original hash (H(key || message)): ";
    PrintHash(original_hash);
    std::cout << std::endl;

    // 3. 攻击者不知道 secret_key，但知道其长度（或通过尝试猜对）
    // 他想附加的数据是 ";admin=true"
    std::string extension = ";admin=true";
    size_t guessed_key_length = secret_key.size(); // 攻击者猜对了密钥长度

    std::cout << "===== Attacker's Side =====" << std::endl;
    std::cout << "Guessed key length: " << guessed_key_length << std::endl;
    std::cout << "Data to append: " << extension << std::endl;


    // 4. 攻击者根据猜测的密钥长度，重新构造填充(padding)
    size_t original_full_length = guessed_key_length + original_message.size();

    // 计算需要多少个块来容纳原始消息+填充
    // (original_full_length + 1 for 0x80 + 8 for length)
    size_t num_blocks_original = (original_full_length + 1 + 8 + 63) / 64;
    size_t padded_original_len = num_blocks_original * 64;

    // 构造填充数据
    std::vector<uint8_t> padding;
    padding.push_back(0x80);
    // 计算需要填充的0的数量
    // (padded_original_len - original_full_length - 1 byte for 0x80 - 8 bytes for length)
    size_t zero_padding_len = padded_original_len - original_full_length - 1 - 8;
    padding.insert(padding.end(), zero_padding_len, 0);

    // 添加8字节的原始消息位长度
    uint64_t original_bit_length = original_full_length * 8;
    for (int i = 0; i < 8; ++i) {
        padding.push_back((original_bit_length >> (56 - i * 8)) & 0xff);
    }

    // 5. 将原始哈希转换回内部状态
    uint32_t forged_initial_state[8];
    HashToState(original_hash, forged_initial_state);

    // 6. 使用原始哈希作为初始状态，计算扩展部分的哈希
    // 关键：将原始填充后的长度作为初始长度传入
    std::vector<uint8_t> forged_hash = SM3(
        reinterpret_cast<const uint8_t*>(extension.data()),
        extension.size(),
        forged_initial_state,
        padded_original_len // *** 核心修正 ***
    );

    std::cout << "Constructed message to send to server: " << original_message << "(+padding)+" << extension << std::endl;
    std::cout << "Forged hash: ";
    PrintHash(forged_hash);
    std::cout << std::endl;


    // 7. 验证攻击是否成功（服务器端的操作）
    std::cout << "===== Server's Side (Verification) =====" << std::endl;

    // 服务器会把收到的消息（原始消息+填充+扩展）和密钥拼接起来
    std::string padding_str(padding.begin(), padding.end());
    std::string full_attack_message_str = secret_key + original_message + padding_str + extension;

    std::cout << "Server computes hash of: key || original_message || padding || extension" << std::endl;

    // 计算真实的哈希值
    std::vector<uint8_t> real_hash = SM3(
        reinterpret_cast<const uint8_t*>(full_attack_message_str.data()),
        full_attack_message_str.size());

    std::cout << "Real hash computed by server: ";
    PrintHash(real_hash);
    std::cout << std::endl;

    // 8. 比较伪造的哈希和真实的哈希
    if (forged_hash == real_hash) {
        std::cout << "\033[1;32mSUCCESS: Length extension attack worked!\033[0m" << std::endl;
    }
    else {
        std::cout << "\033[1;31mFAILED: Length extension attack didn't work.\033[0m" << std::endl;
    }
}


int main() {
    LengthExtensionAttack();
    return 0;
}