import ecdsa
import hashlib
import os
from ecdsa import ellipticcurve  # Import the ellipticcurve module

# --- 1. 场景设置 ---
# 使用比特币所用的椭圆曲线 SECP256k1
curve = ecdsa.SECP256k1
n = curve.order  # 曲线的阶

# 模拟中本聪的密钥对 (在真实世界中，没人知道他的私钥)
# 为了实验，我们在此生成一个全新的密钥对
private_key = ecdsa.SigningKey.generate(curve=curve)
public_key = private_key.get_verifying_key()

print("--- 密钥信息 ---")
print(f"私钥 (十六进制): {private_key.to_string().hex()}")
print(f"公钥 (十六进制): {public_key.to_string('compressed').hex()}")
print("-" * 60)

# --- 2. 攻击者设定目标 ---
# 这是攻击者想要让别人相信是中本聪签名的消息
forged_message = b"I, Satoshi Nakamoto, hereby transfer 1 million BTC to the attacker's address."

print("--- 攻击场景 ---")
print(f"攻击者想要伪造对以下消息的签名:\n'{forged_message.decode()}'")
print("-" * 60)


# --- 3. 执行签名伪造算法 ---
# 攻击者不需要私钥，只需要目标的公钥
print("--- 开始伪造签名 (无需私钥) ---")

# 步骤 1: 攻击者选择两个随机数 u1 和 u2
u1 = int.from_bytes(os.urandom(32), "big") % n
u2 = int.from_bytes(os.urandom(32), "big") % n
print(f"1. 攻击者选择随机数 u1, u2")

# 步骤 2: 计算伪造的点 R' = u1*G + u2*pubKey
# G 是曲线的生成点
G = curve.generator
R_prime = u1 * G + u2 * public_key.pubkey.point
print(f"2. 计算伪造点 R' = u1*G + u2*pubKey")

# #################################################
# ##                 CORRECTED LINE              ##
# #################################################
if R_prime == ellipticcurve.INFINITY:
    raise ValueError("计算出的R'是无穷远点，请重新选择u1, u2")

# 步骤 3: 从 R' 构造伪造的 r' 和 s'
# r' 是 R' 点的 x 坐标
forged_r = R_prime.x()
# s' = r' * u2⁻¹ mod n
# modInverse(a, m) 计算 a 在模 m 下的乘法逆元
forged_s = (forged_r * ecdsa.numbertheory.inverse_mod(u2, n)) % n
print(f"3. 构造伪造签名 r' 和 s'")
print(f"   伪造的 r' = {forged_r}")
print(f"   伪造的 s' = {forged_s}")

# 步骤 4: 构造对应的伪造哈希 e'
# e' = s' * u1 mod n
forged_hash_int = (forged_s * u1) % n
print(f"4. 构造可通过验证的伪造哈希 e'")
print(f"   伪造的 e' (整数形式) = {forged_hash_int}")

# 将伪造的哈希转换为字节形式，以便传递给验证函数
# 实际场景中，哈希通常是32字节
forged_hash_bytes = forged_hash_int.to_bytes(32, "big")

# 将 r 和 s 编码成一个签名对象
forged_signature = ecdsa.util.sigencode_der(forged_r, forged_s, n)
print("-" * 60)


# --- 4. 脆弱的验证过程 ---
# 这个验证函数存在安全漏洞：它直接接受外部传入的哈希值
def vulnerable_verify(vk, signature, provided_hash_bytes):
    """一个有漏洞的验证函数，它信任外部提供的哈希值。"""
    try:
        # ecdsa库的verify_digest方法正是用于这种情况
        # 它假设你已经安全地计算了哈希摘要
        return vk.verify_digest(signature, provided_hash_bytes, sigdecode=ecdsa.util.sigdecode_der)
    except ecdsa.BadSignatureError:
        return False


print("--- 场景A: 脆弱的验证过程 ---")
print("验证者直接使用攻击者提供的伪造哈希进行验证...")

is_valid_vulnerable = vulnerable_verify(public_key, forged_signature, forged_hash_bytes)

print(f"\n验证结果: {is_valid_vulnerable}")
if is_valid_vulnerable:
    print("✅ 攻击成功！伪造的签名通过了脆弱的验证。")
    print("   这意味着，验证者错误地相信了中本聪签署了伪造的消息。")
else:
    print("❌ 攻击失败。")
print("-" * 60)


# --- 5. 正确且安全的验证过程 ---
# 这个验证函数是安全的：它忽略外部哈希，自己对原始消息进行哈希计算
def secure_verify(vk, signature, original_message):
    """一个安全的验证函数，它总是自己计算消息的哈希值。"""
    try:
        # ecdsa库的verify方法会先对message进行哈希（默认SHA-1，需指定）
        return vk.verify(signature, original_message, hashfunc=hashlib.sha256, sigdecode=ecdsa.util.sigdecode_der)
    except ecdsa.BadSignatureError:
        return False


print("--- 场景B: 安全的验证过程 ---")
print("验证者忽略外部哈希，独立对伪造的消息进行哈希计算...")

# 让我们看看用伪造消息的真实哈希来验证会发生什么
real_hash_of_forged_message = hashlib.sha256(forged_message).digest()
print(f"伪造消息的真实哈希 (bytes): {real_hash_of_forged_message.hex()}")
print(f"攻击者构造的伪造哈希 (bytes): {forged_hash_bytes.hex()}")

is_valid_secure = secure_verify(public_key, forged_signature, forged_message)

print(f"\n验证结果: {is_valid_secure}")
if not is_valid_secure:
    print("✅ 防御成功！伪造的签名未能通过安全的验证。")
    print("   因为签名的数学关系与消息的真实哈希不匹配。")
else:
    print("❌ 防御失败，这不应该发生！")
print("-" * 60)
