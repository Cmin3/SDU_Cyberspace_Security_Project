import random
import time
from typing import Tuple

# === 椭圆曲线参数（SM2 推荐参数） ===
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


# ========== SM3 哈希函数实现（Python 纯实现） ==========
def _rotl(x, n):
    return ((x << n) & 0xFFFFFFFF) | ((x >> (32 - n)) & 0xFFFFFFFF)


def _sm3_ff_j(x, y, z, j):
    return (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))


def _sm3_gg_j(x, y, z, j):
    return (x ^ y ^ z) if j < 16 else ((x & y) | (~x & z))


def _sm3_p0(x):
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _sm3_p1(x):
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def sm3_hash(msg: bytes) -> bytes:
    # 初始向量
    iv = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
    msg_len = len(msg)
    reserve1 = msg_len % 64
    msg_padding = msg + b"\x80" + b"\x00" * ((56 - (reserve1 + 1) % 64) % 64) + (msg_len * 8).to_bytes(8, "big")
    nblocks = len(msg_padding) // 64

    V = iv[:]
    for i in range(nblocks):
        block = msg_padding[64 * i : 64 * (i + 1)]
        W = [int.from_bytes(block[j : j + 4], "big") for j in range(0, 64, 4)]
        for j in range(16, 68):
            W.append(_sm3_p1(W[j - 16] ^ W[j - 9] ^ _rotl(W[j - 3], 15)) ^ _rotl(W[j - 13], 7) ^ W[j - 6])
        W_ = [W[j] ^ W[j + 4] for j in range(64)]
        A, B, C, D, E, F, G, H = V
        for j in range(64):
            Tj = 0x79CC4519 if j < 16 else 0x7A879D8A
            SS1 = _rotl((_rotl(A, 12) + E + _rotl(Tj, j % 32)) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ _rotl(A, 12)
            TT1 = (_sm3_ff_j(A, B, C, j) + D + SS2 + W_[j]) & 0xFFFFFFFF
            TT2 = (_sm3_gg_j(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = _rotl(B, 9)
            B = A
            A = TT1
            H = G
            G = _rotl(F, 19)
            F = E
            E = _sm3_p0(TT2)
        V = [a ^ b for a, b in zip(V, [A, B, C, D, E, F, G, H])]
    return b"".join(x.to_bytes(4, "big") for x in V)


# ========== 椭圆曲线工具 ==========
def mod_inv(a: int, p: int) -> int:
    return pow(a, -1, p)


class ECPoint:
    def __init__(self, x: int, y: int):
        self.x = x
        self.y = y

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __add__(self, other):
        if self.x == 0 and self.y == 0:
            return other
        if other.x == 0 and other.y == 0:
            return self
        if self.x == other.x:
            if (self.y + other.y) % P == 0:
                return ECPoint(0, 0)
            else:
                lam = (3 * self.x * self.x + A) * mod_inv(2 * self.y, P) % P
        else:
            lam = (other.y - self.y) * mod_inv((other.x - self.x) % P, P) % P

        x3 = (lam * lam - self.x - other.x) % P
        y3 = (lam * (self.x - x3) - self.y) % P
        return ECPoint(x3, y3)

    def __mul__(self, scalar: int):
        result = ECPoint(0, 0)
        addend = self
        while scalar:
            if scalar & 1:
                result += addend
            addend += addend
            scalar >>= 1
        return result

    def __rmul__(self, scalar: int):
        return self.__mul__(scalar)


# 基点
G = ECPoint(Gx, Gy)


# ========== SM2 核心 ==========
def generate_keypair() -> Tuple[int, ECPoint]:
    private_key = random.randint(1, N - 1)
    public_key = private_key * G
    return private_key, public_key


def calc_ZA(user_id: bytes, public_key: ECPoint) -> bytes:
    entl = (len(user_id) * 8).to_bytes(2, "big")
    a_bytes = A.to_bytes(32, "big")
    b_bytes = B.to_bytes(32, "big")
    gx_bytes = Gx.to_bytes(32, "big")
    gy_bytes = Gy.to_bytes(32, "big")
    px_bytes = public_key.x.to_bytes(32, "big")
    py_bytes = public_key.y.to_bytes(32, "big")
    return sm3_hash(entl + user_id + a_bytes + b_bytes + gx_bytes + gy_bytes + px_bytes + py_bytes)


def sm2_sign(private_key: int, msg: bytes, user_id: bytes = b"1234567812345678") -> Tuple[int, int]:
    pub_key = private_key * G
    ZA = calc_ZA(user_id, pub_key)
    e = int.from_bytes(sm3_hash(ZA + msg), "big")
    while True:
        k = random.randint(1, N - 1)
        x1y1 = k * G
        r = (e + x1y1.x) % N
        if r == 0 or (r + k) % N == 0:
            continue
        s = (mod_inv(1 + private_key, N) * (k - r * private_key)) % N
        if s != 0:
            return r, s


def sm2_verify(public_key: ECPoint, msg: bytes, signature: Tuple[int, int], user_id: bytes = b"1234567812345678") -> bool:
    r, s = signature
    if not (1 <= r < N and 1 <= s < N):
        return False
    ZA = calc_ZA(user_id, public_key)
    e = int.from_bytes(sm3_hash(ZA + msg), "big")
    t = (r + s) % N
    if t == 0:
        return False
    x1y1 = s * G + t * public_key
    R = (e + x1y1.x) % N
    return R == r


# ========== 性能测试 ==========
def performance_test():
    # 生成 100 组测试数据
    test_cases = []
    for _ in range(100):
        priv, pub = generate_keypair()
        msg = random.randbytes(random.randint(10, 100))
        test_cases.append((priv, pub, msg))

    start = time.time()
    sigs = [sm2_sign(priv, msg) for priv, _, msg in test_cases]
    sign_time = time.time() - start
    print(f"签名100次耗时: {sign_time:.4f}秒, 平均每次: {sign_time*1000/1000:.4f}毫秒")

    start = time.time()
    results = [sm2_verify(pub, msg, sig) for (_, pub, msg), sig in zip(test_cases, sigs)]
    verify_time = time.time() - start
    print(f"验签100次耗时: {verify_time:.4f}秒, 平均每次: {verify_time*1000/1000:.4f}毫秒")

    if all(results):
        print("所有验签结果正确 ✅")
    else:
        print(f"验签错误: {results.count(False)} 个失败 ❌")


if __name__ == "__main__":
    performance_test()
