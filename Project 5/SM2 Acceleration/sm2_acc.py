import random
import time
import gmpy2
from typing import Tuple

# === 椭圆曲线参数（SM2 推荐参数） ===
P = gmpy2.mpz(0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF)
A = gmpy2.mpz(0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC)
B = gmpy2.mpz(0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93)
N = gmpy2.mpz(0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123)
Gx = gmpy2.mpz(0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7)
Gy = gmpy2.mpz(0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0)

# 预计算字节参数
A_bytes = int(A).to_bytes(32, "big")
B_bytes = int(B).to_bytes(32, "big")
Gx_bytes = int(Gx).to_bytes(32, "big")
Gy_bytes = int(Gy).to_bytes(32, "big")


# ========== SM3 哈希函数 ==========
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
    iv = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
    msg_len = len(msg)
    msg_padding = msg + b"\x80" + b"\x00" * ((56 - (msg_len + 1) % 64) % 64) + (msg_len * 8).to_bytes(8, "big")
    nblocks = len(msg_padding) // 64

    V = iv[:]
    for i in range(nblocks):
        block = msg_padding[64 * i : 64 * (i + 1)]
        W = [int.from_bytes(block[j : j + 4], "big") for j in range(0, 64, 4)]
        for j in range(16, 68):
            W.append(_sm3_p1(W[j - 16] ^ W[j - 9] ^ _rotl(W[j - 3], 15)) ^ _rotl(W[j - 13], 7) ^ W[j - 6])
        W_ = [W[j] ^ W[j + 4] for j in range(64)]
        A_, B_, C_, D_, E_, F_, G_, H_ = V
        for j in range(64):
            Tj = 0x79CC4519 if j < 16 else 0x7A879D8A
            SS1 = _rotl((_rotl(A_, 12) + E_ + _rotl(Tj, j % 32)) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ _rotl(A_, 12)
            TT1 = (_sm3_ff_j(A_, B_, C_, j) + D_ + SS2 + W_[j]) & 0xFFFFFFFF
            TT2 = (_sm3_gg_j(E_, F_, G_, j) + H_ + SS1 + W[j]) & 0xFFFFFFFF
            D_, C_, B_, A_ = C_, _rotl(B_, 9), A_, TT1
            H_, G_, F_, E_ = G_, _rotl(F_, 19), E_, _sm3_p0(TT2)
        V = [a ^ b for a, b in zip(V, [A_, B_, C_, D_, E_, F_, G_, H_])]
    return b"".join(x.to_bytes(4, "big") for x in V)


# ========== 椭圆曲线工具 ==========
def mod_inv(a, p):
    return gmpy2.invert(a, p)


class ECPoint:
    __slots__ = ("x", "y")

    def __init__(self, x, y):
        self.x = gmpy2.mpz(x)
        self.y = gmpy2.mpz(y)

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
            lam = (3 * self.x * self.x + A) * mod_inv(2 * self.y, P) % P
        else:
            lam = (other.y - self.y) * mod_inv((other.x - self.x) % P, P) % P
        x3 = (lam * lam - self.x - other.x) % P
        y3 = (lam * (self.x - x3) - self.y) % P
        return ECPoint(x3, y3)

    def __mul__(self, scalar):
        result = ECPoint(0, 0)
        addend = self
        k = gmpy2.mpz(scalar)
        while k:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1
        return result

    def __rmul__(self, scalar):
        return self.__mul__(scalar)  # 让 int * ECPoint 也能运行


# 基点
G = ECPoint(Gx, Gy)


# ========== SM2 核心 ==========
def generate_keypair():
    priv = random.randint(1, int(N - 1))
    return priv, priv * G


def calc_ZA(user_id: bytes, public_key: ECPoint) -> bytes:
    entl = (len(user_id) * 8).to_bytes(2, "big")
    px_bytes = int(public_key.x).to_bytes(32, "big")
    py_bytes = int(public_key.y).to_bytes(32, "big")
    return sm3_hash(entl + user_id + A_bytes + B_bytes + Gx_bytes + Gy_bytes + px_bytes + py_bytes)


def sm2_sign(private_key, msg: bytes, user_id: bytes = b"1234567812345678"):
    pub_key = private_key * G
    ZA = calc_ZA(user_id, pub_key)
    e = int.from_bytes(sm3_hash(ZA + msg), "big")
    while True:
        k = random.randint(1, int(N - 1))
        x1y1 = k * G
        r = (e + x1y1.x) % N
        if r == 0 or (r + k) % N == 0:
            continue
        s = (mod_inv(1 + private_key, N) * (k - r * private_key)) % N
        if s != 0:
            return int(r), int(s)


def sm2_verify(public_key: ECPoint, msg: bytes, signature, user_id: bytes = b"1234567812345678"):
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
    test_cases = [(generate_keypair() + (random.randbytes(random.randint(10, 100)),)) for _ in range(1000)]

    start = time.time()
    sigs = [sm2_sign(priv, msg) for priv, _, msg in test_cases]
    sign_time = time.time() - start
    print(f"签名1000次耗时: {sign_time:.4f}秒, 平均每次: {sign_time*1000/1000:.4f}毫秒")

    start = time.time()
    results = [sm2_verify(pub, msg, sig) for (_, pub, msg), sig in zip(test_cases, sigs)]
    verify_time = time.time() - start
    print(f"验签1000次耗时: {verify_time:.4f}秒, 平均每次: {verify_time*1000/1000:.4f}毫秒")

    print("所有验签结果正确 ✅" if all(results) else f"验签错误: {results.count(False)} 个失败 ❌")


if __name__ == "__main__":
    performance_test()
