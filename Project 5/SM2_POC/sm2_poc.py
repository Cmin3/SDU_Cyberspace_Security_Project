import hashlib
import os
from random import randint

# --- SM2 国密推荐曲线参数 (来自 PDF 第2页) --- [cite: 125, 126, 127, 128]
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
G = (Gx, Gy)


# --- 椭圆曲线基本运算 ---
def inv(a, n):
    return pow(a, n - 2, n)


def add_points(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        l = ((3 * x1 * x1 + A) * inv(2 * y1, P)) % P
    else:
        l = ((y2 - y1) * inv(x2 - x1, P)) % P
    x3 = (l * l - x1 - x2) % P
    y3 = (l * (x1 - x3) - y1) % P
    return (x3, y3)


def multiply_point(p, k):
    res = None
    app = p
    while k > 0:
        if k & 1:
            res = add_points(res, app)
        app = add_points(app, app)
        k >>= 1
    return res


# --- SM2 签名函数 (简化版) ---
def sm2_sign(e_hash, private_key, k):
    R = multiply_point(G, k)
    x1 = R[0]
    r = (e_hash + x1) % N  # [cite: 146]
    s_inv_part = inv(1 + private_key, N)
    s = (s_inv_part * (k - r * private_key)) % N  # [cite: 148]
    return r, s


# --- PoC: 随机数 k 泄露 ---
def poc_leaking_k():
    print("--- PoC: 随机数 k 泄露攻击 ---")

    # 1. 秘密设置
    private_key = randint(1, N - 1)
    message = b"Hello, SM2!"
    # 假设 k 由于某种原因被泄露
    leaked_k = randint(1, N - 1)

    # 2. 生成签名
    e_hash = int.from_bytes(hashlib.sha256(message).digest(), "big")
    r, s = sm2_sign(e_hash, private_key, leaked_k)
    print(f"  - 原始私钥: {hex(private_key)}")
    print(f"  - 泄露的 k: {hex(leaked_k)}")
    print(f"  - 生成的签名 (r, s): ({hex(r)}, {hex(s)})")

    # 3. 攻击者恢复私钥
    # 使用公式: d = (k-s) * (s+r)^-1 mod n
    s_plus_r_inv = inv(s + r, N)
    recovered_d = ((leaked_k - s) * s_plus_r_inv) % N
    print(f"  - 恢复的私钥: {hex(recovered_d)}")

    # 4. 验证
    if recovered_d == private_key:
        print("  - [成功] 恢复的私钥与原始私钥匹配！\n")
    else:
        print("  - [失败] 私钥恢复失败。\n")


poc_leaking_k()
