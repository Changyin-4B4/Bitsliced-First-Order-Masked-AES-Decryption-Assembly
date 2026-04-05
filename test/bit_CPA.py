"""
文件功能与背景说明：
这是一个用于执行单比特相关功耗分析 (Bit-level Correlation Power Analysis, CPA) 攻击的脚本。

核心功能：
1. 目标：针对 AES 解密算法，利用已知的密文 (Ciphertext) 和对应的功耗波形 (Traces)，通过分析逆 S-Box (INV_SBOX) 输出的某一个特定比特 (Bit)，来恢复密钥字节。
2. 功耗模型：使用单比特模型 (Single-bit Model)，即假设功耗泄漏与逆 S-Box 输出状态的特定位 (0 或 1) 直接相关。
3. 计算方法：通过自定义的高效皮尔逊相关系数计算函数 (fast_pearson_correlation)，快速评估 256 种可能密钥猜测下的理论单比特泄漏与实际波形的相关性。
4. 结果输出：打印出相关性最高的 Top 5 密钥猜测，并绘制 256 条猜测的相关系数曲线图，高亮显示最佳猜测 (Best Guess)。

使用场景：
当标准的基于汉明重量 (Hamming Weight) 或汉明距离 (Hamming Distance) 的 CPA 攻击失效或效果不佳时，针对特定寄存器位或特定硬件架构进行更为细粒度的单比特侧信道攻击。
"""

import argparse
import os
import sys
import time

import h5py
import matplotlib.pyplot as plt
import numpy as np


INV_SBOX = np.array([
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
], dtype=np.uint8)


def parse_args():
    """
    解析命令行参数。
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--h5",
        default=r"",
        help="H5 trace 文件绝对路径"
    )
    parser.add_argument("--traces-ds", default="traces", help="功耗波形数据集名称")
    parser.add_argument("--ciphertext-ds", default="ciphertext", help="密文数据集名称")
    parser.add_argument("--byte-index", type=int, default=0, help="攻击的字节序号")
    parser.add_argument("--target-bit", type=int, default=2, help="攻击的目标 bit 序号，范围 0-7")
    parser.add_argument(
        "--output",
        default=r"h:\python_programme\VISION_AES\cpa_attack_result_bit.png",
        help="输出图路径"
    )
    return parser.parse_args()


def fast_pearson_correlation(model_values, traces):
    """
    高效计算一维模型值与二维波形矩阵的皮尔逊相关系数。
    """
    trace_count = traces.shape[0]
    model_values = model_values.reshape(-1, 1).astype(np.float64)

    sum_model = np.sum(model_values, axis=0)
    sum_traces = np.sum(traces, axis=0)

    sum_model_sq = np.sum(model_values ** 2, axis=0)
    sum_traces_sq = np.sum(traces ** 2, axis=0)

    sum_model_traces = np.dot(model_values.T, traces)[0]

    numerator = trace_count * sum_model_traces - sum_model * sum_traces
    denominator = np.sqrt(
        (trace_count * sum_model_sq - sum_model ** 2) *
        (trace_count * sum_traces_sq - sum_traces ** 2)
    )

    denominator[denominator == 0] = 1e-10
    return numerator / denominator


def load_data(h5_path, traces_ds, ciphertext_ds):
    """
    从 H5 文件中加载波形和密文数据。
    """
    with h5py.File(h5_path, "r") as file_handle:
        traces = file_handle[traces_ds][...].astype(np.float64)
        ciphertext = file_handle[ciphertext_ds][...].astype(np.uint8)
    return traces, ciphertext


def run_bit_cpa(traces, ciphertext, byte_index, target_bit):
    """
    对指定字节和指定 bit 执行单比特 CPA 攻击。
    """
    ct_byte = ciphertext[:, byte_index]
    max_correlations = np.zeros(256, dtype=np.float64)
    correlation_traces = []

    for guess in range(256):
        hypothetical_intermediate = INV_SBOX[np.bitwise_xor(ct_byte, guess)]
        bit_model = ((hypothetical_intermediate >> target_bit) & 1).astype(np.float64)
        correlation_trace = fast_pearson_correlation(bit_model, traces)
        max_correlations[guess] = np.max(np.abs(correlation_trace))
        correlation_traces.append(correlation_trace)

        if guess % 32 == 0:
            print(f"已遍历密钥猜测: 0x{guess:02x} ...")

    correlation_traces = np.array(correlation_traces, dtype=np.float64)
    best_guess = int(np.argmax(max_correlations))
    best_corr_value = float(max_correlations[best_guess])

    return best_guess, best_corr_value, max_correlations, correlation_traces


def print_top_guesses(max_correlations, top_n=5):
    """
    打印相关系数最高的若干个密钥猜测。
    """
    ranking = np.argsort(max_correlations)[::-1][:top_n]
    print("\nTop guesses:")
    for rank, guess in enumerate(ranking, start=1):
        print(f"{rank}. guess=0x{guess:02x}, max|corr|={max_correlations[guess]:.6f}")


def plot_correlation_traces(correlation_traces, best_guess, output_path, byte_index, target_bit):
    """
    绘制 256 个猜测的相关系数曲线，并高亮最佳猜测。
    """
    plt.figure(figsize=(12, 6))

    for guess in range(256):
        if guess != best_guess:
            plt.plot(
                correlation_traces[guess],
                color="lightgray",
                linewidth=0.5,
                alpha=0.5
            )

    plt.plot(
        correlation_traces[best_guess],
        color="red",
        linewidth=1.0,
        label=f"Best Guess: 0x{best_guess:02x}"
    )

    plt.title(f"Single-Bit CPA, byte {byte_index}, bit {target_bit}")
    plt.xlabel("Sample Index")
    plt.ylabel("Pearson Correlation")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def main():
    """
    执行针对 AES 解密第 0 字节指定 bit 的单比特 CPA 攻击。
    """
    args = parse_args()

    if not os.path.isfile(args.h5):
        print(f"H5 file not found: {args.h5}")
        sys.exit(1)

    if not (0 <= args.byte_index <= 15):
        print("byte-index 必须在 0 到 15 之间")
        sys.exit(1)

    if not (0 <= args.target_bit <= 7):
        print("target-bit 必须在 0 到 7 之间")
        sys.exit(1)

    print("加载数据中...")
    traces, ciphertext = load_data(args.h5, args.traces_ds, args.ciphertext_ds)

    print(
        f"开始单比特 CPA 攻击... "
        f"共有 {traces.shape[0]} 条波形，{traces.shape[1]} 个采样点，"
        f"目标字节={args.byte_index}，目标 bit={args.target_bit}"
    )

    start_time = time.time()
    best_guess, best_corr_value, max_correlations, correlation_traces = run_bit_cpa(
        traces,
        ciphertext,
        args.byte_index,
        args.target_bit
    )
    elapsed = time.time() - start_time

    print(f"攻击完成，耗时: {elapsed:.2f} 秒")
    print("\n" + "=" * 40)
    print(f"CPA 爆破结果：最有可能的密钥猜测是 0x{best_guess:02x}")
    print(f"最大相关系数值: {best_corr_value:.6f}")
    print("=" * 40)

    print_top_guesses(max_correlations, top_n=5)
    plot_correlation_traces(
        correlation_traces,
        best_guess,
        args.output,
        args.byte_index,
        args.target_bit
    )
    print(f"\n攻击对比图已保存为: {args.output}")


if __name__ == "__main__":
    main()
