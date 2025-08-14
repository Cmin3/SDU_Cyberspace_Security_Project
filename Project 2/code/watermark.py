#!/usr/bin/env python3
"""
DCT-based image watermark embedding and extraction (demo)

依赖：
    pip install numpy opencv-python pillow

说明：
- 使用基于 DCT 的半盲水印：在亮度通道（Y）的每个 8x8 块的中频系数上叠加一个伪随机序列来表示比特（扩频）。
- 抗性测试包括：水平/垂直翻转、平移、裁剪、改变对比度。
- 这是教学/实验代码，便于二次开发和调参。

主要函数：
- embed_watermark(img_path, message_bits, out_path, alpha=5, seed=123)
- extract_watermark(watermarked_img_path, message_length, seed=123)
- apply_attacks(img, attack_type, **kwargs)
- test_robustness(...) 演示并保存结果

注意：实际工程中请增加鲁棒的同步/注册机制以对抗几何失配。
"""

import os
import math
import numpy as np
from PIL import Image, ImageEnhance
import cv2

# ---------- 工具函数 ----------


def load_image_as_gray_uint8(path):
    img = Image.open(path).convert("RGB")
    arr = np.array(img)
    return arr


def save_rgb_array(arr, path):
    img = Image.fromarray(np.uint8(np.clip(arr, 0, 255)))
    img.save(path)


# ---------- DCT block helpers ----------

BLOCK = 8


def block_process(channel, func):
    """对 channel 的每个 8x8 块应用 func(block) 并返回重组后的结果。"""
    h, w = channel.shape
    h_blocks = h // BLOCK
    w_blocks = w // BLOCK
    out = np.zeros_like(channel, dtype=float)
    for by in range(h_blocks):
        for bx in range(w_blocks):
            y0 = by * BLOCK
            x0 = bx * BLOCK
            block = channel[y0 : y0 + BLOCK, x0 : x0 + BLOCK].astype(np.float32)
            out_block = func(block)
            out[y0 : y0 + BLOCK, x0 : x0 + BLOCK] = out_block
    return out


# ---------- Embed / Extract ----------


def embed_watermark(img_path, message_bits, out_path, alpha=5.0, seed=123):
    """
    在图像中嵌入二进制消息（list/ndarray of 0/1）。
    - alpha: 嵌入强度，越大越鲁棒但对可感知性影响越大。
    - seed: 用于生成伪随机序列
    返回：保存的文件路径
    """
    img_rgb = load_image_as_gray_uint8(img_path)
    h, w, _ = img_rgb.shape
    # 裁剪为 8 的倍数
    h_crop = (h // BLOCK) * BLOCK
    w_crop = (w // BLOCK) * BLOCK
    img_rgb = img_rgb[:h_crop, :w_crop, :]

    # 转为 YCrCb，使用 Y 通道嵌入
    img_ycc = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2YCrCb).astype(np.float32)
    Y = img_ycc[:, :, 0]

    h_blocks = h_crop // BLOCK
    w_blocks = w_crop // BLOCK
    num_blocks = h_blocks * w_blocks

    msg_len = len(message_bits)
    if msg_len > num_blocks:
        raise ValueError("消息太长，超过可用块数")

    # 为每个比特分配多个块以做扩频：块_per_bit
    blocks_per_bit = max(1, num_blocks // msg_len)

    rng = np.random.RandomState(seed)
    # 为每个块生成一个伪随机序列（+1/-1）用于扩频
    prn = rng.choice([-1.0, 1.0], size=(num_blocks,))

    def embed_blockwise(block_dct, block_index=None, bit_for_block=None):
        # 修改中频系数 (u=4,v=3) 或其他位置
        # block_dct 是 spatial block, 先做 DCT
        d = cv2.dct(block_dct)
        # 选择一个中频坐标
        u, v = 3, 4
        if bit_for_block is not None:
            d[u, v] += alpha * prn[block_index] * (1.0 if bit_for_block == 1 else -1.0)
        return cv2.idct(d)

    # 将 message 按照 blocks_per_bit 展开到每个块对应的 bit
    bit_for_block = np.zeros((num_blocks,), dtype=np.int32)
    for i in range(msg_len):
        start = i * blocks_per_bit
        end = min(start + blocks_per_bit, num_blocks)
        bit_for_block[start:end] = 1 if int(message_bits[i]) == 1 else 0
    # 若仍有剩余块，填充为0

    # 对每个块做嵌入
    def func_spatial(block, by_bx=[0]):
        # by_bx 用于闭包存储块序号
        idx = by_bx[0]
        b = embed_blockwise(block, block_index=idx, bit_for_block=bit_for_block[idx])
        by_bx[0] += 1
        return b

    # 因为 Python 闭包的限制，采用另一种循环实现
    Y_out = np.zeros_like(Y, dtype=float)
    idx = 0
    for by in range(h_blocks):
        for bx in range(w_blocks):
            y0 = by * BLOCK
            x0 = bx * BLOCK
            block = Y[y0 : y0 + BLOCK, x0 : x0 + BLOCK].astype(np.float32)
            d = cv2.dct(block)
            u, v = 3, 4
            d[u, v] += alpha * prn[idx] * (1.0 if bit_for_block[idx] == 1 else -1.0)
            block_idct = cv2.idct(d)
            Y_out[y0 : y0 + BLOCK, x0 : x0 + BLOCK] = block_idct
            idx += 1

    img_ycc[:, :, 0] = Y_out
    img_rgb_out = cv2.cvtColor(img_ycc.astype(np.uint8), cv2.COLOR_YCrCb2RGB)
    save_rgb_array(img_rgb_out, out_path)
    return out_path


def extract_watermark(img_path, message_length, seed=123):
    """
    从图像中提取二进制消息（近似），返回 0/1 列表。
    需要和 embed 时相同的 seed 以产生相同 PRN。
    """
    img_rgb = load_image_as_gray_uint8(img_path)
    img_ycc = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2YCrCb).astype(np.float32)
    Y = img_ycc[:, :, 0]
    h, w = Y.shape
    h_blocks = h // BLOCK
    w_blocks = w // BLOCK
    num_blocks = h_blocks * w_blocks

    rng = np.random.RandomState(seed)
    prn = rng.choice([-1.0, 1.0], size=(num_blocks,))

    # 读取每个块的中频系数并与 prn 做相关
    coeffs = np.zeros((num_blocks,), dtype=float)
    idx = 0
    for by in range(h_blocks):
        for bx in range(w_blocks):
            y0 = by * BLOCK
            x0 = bx * BLOCK
            block = Y[y0 : y0 + BLOCK, x0 : x0 + BLOCK].astype(np.float32)
            d = cv2.dct(block)
            u, v = 3, 4
            coeffs[idx] = d[u, v]
            idx += 1

    # 现在将 coeffs 按照 blocks_per_bit 聚合并做相关检测
    blocks_per_bit = max(1, num_blocks // message_length)
    bits = []
    for i in range(message_length):
        start = i * blocks_per_bit
        end = min(start + blocks_per_bit, num_blocks)
        segment = coeffs[start:end]
        prn_segment = prn[start:end]
        # 相关性： dot(segment, prn_segment)
        corr = np.dot(segment, prn_segment)
        bits.append(1 if corr > 0 else 0)
    return bits


# ---------- 攻击函数 ----------


def attack_flip(img_arr, mode="horizontal"):
    if mode == "horizontal":
        return np.fliplr(img_arr)
    elif mode == "vertical":
        return np.flipud(img_arr)
    else:
        raise ValueError("mode must be horizontal or vertical")


def attack_translate(img_arr, tx=10, ty=5):
    h, w = img_arr.shape[:2]
    M = np.float32([[1, 0, tx], [0, 1, ty]])
    shifted = cv2.warpAffine(img_arr, M, (w, h), borderMode=cv2.BORDER_REPLICATE)
    return shifted


def attack_crop(img_arr, crop_ratio=0.9):
    # crop_ratio: 保留比例
    h, w = img_arr.shape[:2]
    new_h = int(h * crop_ratio)
    new_w = int(w * crop_ratio)
    y0 = (h - new_h) // 2
    x0 = (w - new_w) // 2
    cropped = img_arr[y0 : y0 + new_h, x0 : x0 + new_w]
    # 将裁剪后的图像再放到原始大小画布中心（便于提取，没有注册的话会受影响）
    canvas = np.zeros_like(img_arr)
    y1 = (h - new_h) // 2
    x1 = (w - new_w) // 2
    canvas[y1 : y1 + new_h, x1 : x1 + new_w] = cropped
    return canvas


def attack_contrast(img_arr, factor=1.2):
    pil = Image.fromarray(np.uint8(img_arr))
    enhancer = ImageEnhance.Contrast(pil)
    out = enhancer.enhance(factor)
    return np.array(out)


# ---------- 测试鲁棒性 demo ----------


def bits_accuracy(a, b):
    a = np.array(a, dtype=int)
    b = np.array(b, dtype=int)
    assert a.shape == b.shape
    return float((a == b).sum()) / a.size


def test_robustness(original_path, message_bits, workdir="demo_out"):
    os.makedirs(workdir, exist_ok=True)
    print("Embedding...")
    watermarked_path = os.path.join(workdir, "watermarked.png")
    embed_watermark(original_path, message_bits, watermarked_path, alpha=6.0, seed=123)
    print("Saved watermarked:", watermarked_path)

    attacks = [
        ("flip_h", lambda img: attack_flip(img, "horizontal")),
        ("flip_v", lambda img: attack_flip(img, "vertical")),
        ("translate", lambda img: attack_translate(img, tx=10, ty=15)),
        ("crop", lambda img: attack_crop(img, crop_ratio=0.8)),
        ("contrast_low", lambda img: attack_contrast(img, 0.7)),
        ("contrast_high", lambda img: attack_contrast(img, 1.4)),
    ]

    # 读取水印图像为数组
    wm_img = load_image_as_gray_uint8(watermarked_path)

    results = {}
    for name, fn in attacks:
        out = fn(wm_img)
        out_path = os.path.join(workdir, f"attacked_{name}.png")
        save_rgb_array(out, out_path)
        # 现在尝试提取
        extracted = extract_watermark(out_path, message_length=len(message_bits), seed=123)
        acc = bits_accuracy(message_bits, extracted)
        print(f"Attack {name}: bit-accuracy={acc:.3f} saved -> {out_path}")
        results[name] = (acc, out_path)

    # baseline: extract from original watermarked
    extracted_orig = extract_watermark(watermarked_path, message_length=len(message_bits), seed=123)
    print("Original extraction accuracy:", bits_accuracy(message_bits, extracted_orig))
    results["original"] = (bits_accuracy(message_bits, extracted_orig), watermarked_path)

    return results


# ---------- 简单命令行示例 ----------
if __name__ == "__main__":
    # 使用方法示例：
    # 准备消息（例如 32 bits）
    msg_len = 32
    rng = np.random.RandomState(2025)
    message = rng.randint(0, 2, size=(msg_len,)).tolist()
    print("message:", message)

    # 请替换为你机器上的图片路径（最好是彩色照片）
    sample_img = "sample.png"  # <- 将此替换为你的图片文件
    if not os.path.exists(sample_img):
        print("请将一张图片命名为 sample.jpg 放在当前目录，或修改 sample_img 变量。")
    else:
        res = test_robustness(sample_img, message, workdir="demo_out")
        print("结果:", res)

    print("Done.")
