import random
import hashlib
from phe import paillier
from py_ecc.bls12_381 import G1, multiply, add, eq, neg, Z1, FQ
from typing import List, Set, Dict, Tuple, Any

# --- Cryptographic Primitives & Helpers ---

# G 是由 py_ecc.bls12_381.G1 定义的椭圆曲线群
# 群的阶 (order)
CURVE_ORDER = FQ.field_modulus


def hash_to_int(s: str) -> int:
    """使用 SHA256 将字符串哈希到一个整数"""
    # 在实际应用中，需要确保哈希输出在 CURVE_ORDER 范围内，
    # 这里为了演示，直接取模
    h = hashlib.sha256(s.encode()).hexdigest()
    return int(h, 16) % CURVE_ORDER


def hash_to_curve(v: str) -> Any:
    """
    协议中的 H 函数: 将标识符映射到群 G 中的一个元素
    这是一个简化的实现，实际应用需要使用标准的 hash-to-curve 算法。
    """
    h_int = hash_to_int(v)
    # G1 是群的生成元，h_int * G1 相当于 g^h
    return multiply(G1, h_int)


def shuffle_list(data: list) -> list:
    """对列表进行乱序"""
    random.shuffle(data)
    return data


# --- Protocol Participants ---


class Party1:
    """
    协议参与方 P1
    持有集合 V = {v_1, v_2, ...}
    """

    def __init__(self, V: Set[str]):
        print(f"[P1] 初始化，持有数据: {V}")
        self.V = V
        # 步骤 Setup: P1 选择私钥 k1
        self.k1 = random.randint(1, CURVE_ORDER - 1)
        print("[P1] 已生成私钥 k1。")

        # 用于存储从 P2 接收的数据
        self.pk_he = None
        self.Z_from_p2 = None
        self.pairs_from_p2 = None

    def setup_receive_pk(self, pk_he):
        """接收 P2 的同态加密公钥"""
        self.pk_he = pk_he
        print("[P1] 已收到 P2 的同态加密公钥。")

    def execute_round1(self) -> List[Any]:
        """
        执行 Round 1:
        1. 对每个 v_i, 计算 H(v_i)^k1
        2. 乱序后发送给 P2
        """
        print("\n--- [P1] 执行 Round 1 ---")
        processed_V = []
        for v_i in self.V:
            h_v = hash_to_curve(v_i)
            # ECC 中 g^k 对应 k * g
            h_v_k1 = multiply(h_v, self.k1)
            processed_V.append(h_v_k1)

        print(f"[P1] 已计算 {len(processed_V)} 个 H(v)^k1。")
        shuffled_V = shuffle_list(processed_V)
        print("[P1] 数据已乱序，准备发送给 P2。")
        return shuffled_V

    def execute_round3(self) -> paillier.EncryptedNumber:
        """
        执行 Round 3:
        1. 找出交集
        2. 计算交集元素对应值的同态和
        3. 随机化并返回结果
        """
        print("\n--- [P1] 执行 Round 3 ---")
        # 将 Z 集合转换为字典，使用点的字符串表示作为键
        z_dict = {str(point): point for point in self.Z_from_p2}
        print(f"[P1] 已收到 {len(z_dict)} 个来自P2的Z集合元素。")
        print(f"[P1] 已收到 {len(self.pairs_from_p2)} 个来自P2的(H(w)^k2, AEnc(t))对。")

        intersection_ciphertexts = []

        # 遍历 P2 发来的数据对 (H(w_j)^k2, t_ciphertext)
        for h_w_k2, t_ciphertext in self.pairs_from_p2:
            # P1 使用自己的私钥 k1 计算 (H(w_j)^k2)^k1
            h_w_k2_k1 = multiply(h_w_k2, self.k1)

            # 如果结果在 Z 集合中，说明 w_j 是交集元素
            if str(h_w_k2_k1) in z_dict:
                intersection_ciphertexts.append(t_ciphertext)

        print(f"[P1] 发现交集大小为: {len(intersection_ciphertexts)}")

        # 如果没有交集，返回加密的0
        if not intersection_ciphertexts:
            print("[P1] 交集为空，返回加密的0。")
            return self.pk_he.encrypt(0)

        # 同态求和
        encrypted_sum = intersection_ciphertexts[0]
        for i in range(1, len(intersection_ciphertexts)):
            encrypted_sum += intersection_ciphertexts[i]

        print("[P1] 已完成交集元素关联值的同态求和。")

        # 随机化 (ARefresh)
        randomized_sum = encrypted_sum + self.pk_he.encrypt(0)
        print("[P1] 已对结果进行随机化，准备发送给 P2。")

        return randomized_sum


class Party2:
    """
    协议参与方 P2
    持有数据对 {(w_j, t_j)}
    """

    def __init__(self, WT_pairs: Dict[str, int]):
        print(f"[P2] 初始化，持有数据: {WT_pairs}")
        self.WT_pairs = WT_pairs

        # 步骤 Setup: P2 选择私钥 k2
        self.k2 = random.randint(1, CURVE_ORDER - 1)
        print("[P2] 已生成私钥 k2。")

        # 步骤 Setup: P2 生成同态加密密钥对 (pk, sk)
        print("[P2] 正在生成同态加密密钥对 (可能需要几秒钟)...")
        self.pk_he, self.sk_he = paillier.generate_paillier_keypair(n_length=2048)
        print("[P2] 同态加密密钥对已生成。")

    def setup_send_pk(self) -> paillier.PaillierPublicKey:
        """发送同态加密公钥给 P1"""
        return self.pk_he

    def execute_round2(self, p1_data: List[Any]) -> Tuple[List[Any], List[Tuple[Any, paillier.EncryptedNumber]]]:
        """
        执行 Round 2:
        1. 对收到的每个 H(v)^k1, 计算 (H(v)^k1)^k2, 得到 Z
        2. 对自己的每个 (w_j, t_j), 计算 (H(w_j)^k2, AEnc(t_j))
        3. 分别乱序后发送给 P1
        """
        print("\n--- [P2] 执行 Round 2 ---")
        print(f"[P2] 已收到 {len(p1_data)} 个来自 P1 的元素。")

        # 步骤 1 & 2: 计算 Z 并乱序
        Z = []
        for h_v_k1 in p1_data:
            h_v_k1_k2 = multiply(h_v_k1, self.k2)
            Z.append(h_v_k1_k2)
        shuffled_Z = shuffle_list(Z)
        print(f"[P2] 已计算并乱序 Z 集合，大小为 {len(shuffled_Z)}。")

        # 步骤 3 & 4: 处理自己的数据并乱序
        processed_WT = []
        for w_j, t_j in self.WT_pairs.items():
            h_w = hash_to_curve(w_j)
            h_w_k2 = multiply(h_w, self.k2)

            # 使用自己的公钥加密 t_j
            encrypted_t = self.pk_he.encrypt(t_j)
            processed_WT.append((h_w_k2, encrypted_t))

        shuffled_WT = shuffle_list(processed_WT)
        print(f"[P2] 已处理并乱序自己的数据对，大小为 {len(shuffled_WT)}。")

        print("[P2] 数据已备好，准备发送给 P1。")
        return shuffled_Z, shuffled_WT

    def output_decrypt(self, final_ciphertext: paillier.EncryptedNumber) -> int:
        """
        输出阶段：
        解密 P1 发来的最终密文，得到交集和
        """
        print("\n--- [P2] 输出阶段 ---")
        print("[P2] 收到 P1 发来的最终加密总和。")

        # 使用自己的私钥 sk 解密
        intersection_sum = self.sk_he.decrypt(final_ciphertext)
        print("[P2] 解密完成。")
        return intersection_sum


# --- 模拟协议执行 ---


def simulate_protocol():
    """主函数，用于编排和模拟整个协议的执行过程"""

    # 1. 定义双方的初始数据
    # 假设交集是 {'apple', 'cherry'}
    # 期望的和是 100 (apple) + 300 (cherry) = 400
    p1_set = {"apple", "banana", "cherry", "date"}
    p2_pairs = {"apple": 100, "cherry": 300, "fig": 500, "grape": 250}

    expected_sum = sum(p2_pairs[k] for k in p1_set.intersection(p2_pairs.keys()))

    print("=" * 50)
    print("协议开始: Private Intersection-Sum")
    print("=" * 50)

    # 2. 初始化双方
    p1 = Party1(p1_set)
    p2 = Party2(p2_pairs)

    # --- SETUP 阶段 ---
    print("\n--- SETUP 阶段 ---")
    pk_he = p2.setup_send_pk()
    p1.setup_receive_pk(pk_he)
    print("Setup 阶段完成。")

    # --- ROUND 1 (P1 -> P2) ---
    p1_to_p2_data = p1.execute_round1()

    # --- ROUND 2 (P2 -> P1) ---
    p2_to_p1_Z, p2_to_p1_pairs = p2.execute_round2(p1_to_p2_data)
    # P1 接收数据
    p1.Z_from_p2 = p2_to_p1_Z
    p1.pairs_from_p2 = p2_to_p1_pairs

    # --- ROUND 3 (P1 -> P2) ---
    p1_to_p2_final_ciphertext = p1.execute_round3()

    # --- OUTPUT (P2 解密) ---
    final_sum = p2.output_decrypt(p1_to_p2_final_ciphertext)

    # 6. 结果验证
    print("\n" + "=" * 50)
    print("协议执行完毕")
    print("=" * 50)
    print(f"P1的原始数据: {p1_set}")
    print(f"P2的原始数据: {p2_pairs}")
    print(f"期望的交集和: {expected_sum}")
    print(f"协议计算出的交集和: {final_sum}")

    if final_sum == expected_sum:
        print("\n[✔] 成功: 协议计算结果与期望值一致！")
    else:
        print("\n[❌] 失败: 协议计算结果与期望值不符！")


if __name__ == "__main__":
    simulate_protocol()
