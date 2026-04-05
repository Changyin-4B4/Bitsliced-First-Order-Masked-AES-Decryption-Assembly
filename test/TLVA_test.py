"""
文件功能与说明：
该脚本用于对 AES 解密过程中的中间变量执行 TLVA（Test Vector Leakage Assessment）检测，

核心流程：
1. 从 H5 文件中读取功耗波形、密文和明文数据。
2. 根据内置的 AES 逆向运算流程与固定密钥，逐条 trace 重建解密过程中的关键中间状态，
   包括 ct0、各轮 InvSubBytes 输出（invsb_r10 到 invsb_r1）以及最终 pt0。
3. 对每个中间状态的 bit 统计 1 的比例，并按偏度（与 0.5 的偏离程度）从高到低选出候选 bit。
4. 以候选 bit 的取值将 traces 分成两组，计算 Welch t-test 曲线，评估该 bit 是否存在显著泄漏。
5. 输出每个候选 bit 的首次越阈位置、末次越阈位置、泄漏点数量，并保存对应图像。

用途：
该脚本适合用于快速定位 AES 解密中间阶段的潜在侧信道泄漏点，辅助判断哪些中间变量或 bit
在实际实现中更容易产生可观测泄漏。
"""

import argparse
import csv
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

INV_SBOX_HEX = (
    "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb"
    "547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd125"
    "72f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d84"
    "90d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b"
    "3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e"
    "47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af4"
    "1fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cef"
    "a0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d"
)
AES_KEY_HEX = "800cc057f79fd9191f5c976b93efd1c2"
RCON = (1, 2, 4, 8, 16, 32, 64, 128, 27, 54)

def require_dependencies():
    """
    Imports required third-party packages and provides a clear error message if missing.
    """
    try:
        import numpy as np
        import h5py
        import matplotlib.pyplot as plt
        return np, h5py, plt
    except Exception as exc:
        print("Missing dependencies. Please install: numpy, h5py, matplotlib")
        print(f"Import error: {exc}")
        sys.exit(1)

def parse_args():
    """
    Parses command-line arguments for TLVA analysis configuration.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--h5",
        default=r"",
        help="Absolute path to the H5 file"
    )
    parser.add_argument("--plaintext-ds", default="plaintext", help="Plaintext dataset name")
    parser.add_argument("--ciphertext-ds", default="ciphertext", help="Ciphertext dataset name")
    parser.add_argument("--traces-ds", default="traces", help="Traces dataset name")
    parser.add_argument("--topk", type=int, default=5, help="Number of bits to analyze")
    parser.add_argument("--threshold", type=float, default=4.5, help="t-value threshold line")
    parser.add_argument("--out-dir", default=r"", help="Output directory for plots")
    return parser.parse_args()

def load_dataset(h5_file, dataset_name):
    """
    Loads a dataset as a NumPy array.
    """
    return h5_file[dataset_name][...]

def expand_round_keys(np_module):
    """
    Expands the AES-128 key into 11 round keys.
    """
    inv_sbox = np_module.frombuffer(bytes.fromhex(INV_SBOX_HEX), dtype=np_module.uint8)
    sbox = np_module.empty(256, dtype=np_module.uint8)
    sbox[inv_sbox] = np_module.arange(256, dtype=np_module.uint8)
    words = [list(bytes.fromhex(AES_KEY_HEX)[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = words[i - 1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [int(sbox[x]) for x in temp]
            temp[0] ^= RCON[i // 4 - 1]
        words.append([(words[i - 4][j] ^ temp[j]) & 0xFF for j in range(4)])
    return [[b for word in words[r * 4:(r + 1) * 4] for b in word] for r in range(11)]

def add_round_key(state, round_key):
    """
    Applies AddRoundKey to a 16-byte state.
    """
    return [(state[i] ^ round_key[i]) & 0xFF for i in range(16)]

def inv_shift_rows(state):
    """
    Applies InvShiftRows to a 16-byte state.
    """
    return [state[0], state[13], state[10], state[7], state[4], state[1], state[14], state[11], state[8], state[5], state[2], state[15], state[12], state[9], state[6], state[3]]

def gmul(a, b):
    """
    Multiplies two bytes in GF(2^8).
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return result

def inv_mix_columns(state):
    """
    Applies InvMixColumns to a 16-byte state.
    """
    out = []
    for col in range(4):
        a0, a1, a2, a3 = state[col * 4:col * 4 + 4]
        out.extend([gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9), gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13), gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11), gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14)])
    return out

def compute_decryption_stage_data(np_module, ciphertext):
    """
    Computes full 16-byte targets for ciphertext, all InvSubBytes outputs, and final plaintext.
    """
    inv_sbox = list(bytes.fromhex(INV_SBOX_HEX))
    round_keys = expand_round_keys(np_module)
    tags = ["ct0", "invsb_r10", "invsb_r9", "invsb_r8", "invsb_r7", "invsb_r6", "invsb_r5", "invsb_r4", "invsb_r3", "invsb_r2", "invsb_r1", "pt0"]
    series = [np_module.zeros_like(ciphertext) for _ in tags]
    recovered = np_module.zeros_like(ciphertext)
    for idx, block in enumerate(ciphertext):
        state = [int(x) for x in block]
        series[0][idx, :] = state
        state = add_round_key(state, round_keys[10])
        for round_key in range(9, 0, -1):
            state = inv_shift_rows(state)
            state = [inv_sbox[x] for x in state]
            series[10 - round_key][idx, :] = state
            state = add_round_key(state, round_keys[round_key])
            state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = [inv_sbox[x] for x in state]
        series[10][idx, :] = state
        state = add_round_key(state, round_keys[0])
        series[11][idx, :] = state
        recovered[idx, :] = state
    return list(zip(tags, series)), recovered

def compute_bit_ratios(np_module, plaintext):
    """
    Computes the ratio of ones for each bit across 16 bytes (128 bits).
    """
    n = plaintext.shape[0]
    ratios = []
    for byte_index in range(plaintext.shape[1]):
        column = plaintext[:, byte_index]
        for bit_index in range(8):
            ones = np_module.sum((column >> bit_index) & 1)
            ratio = float(ones) / float(n)
            ratios.append((byte_index, bit_index, ratio))
    return ratios

def select_candidate_bits(ratios, topk):
    """
    Returns the top-k bits with the highest bias away from 0.5.
    """
    ranked = []
    for byte_index, bit_index, ratio in ratios:
        bias = abs(ratio - 0.5)
        ranked.append((bias, byte_index, bit_index, ratio))
    ranked.sort(key=lambda x: x[0], reverse=True)
    return ranked[:topk]

def build_bit_mask(np_module, plaintext, byte_index, bit_index):
    """
    Builds a boolean mask for traces based on a specific plaintext bit.
    """
    return ((plaintext[:, byte_index] >> bit_index) & 1).astype(np_module.uint8)

def welch_t_for_bit(np_module, traces_dataset, bit_mask):
    """
    Computes Welch t-values for the given bit mask using streaming statistics.
    """
    num_traces, num_samples = traces_dataset.shape
    mean_a = np_module.zeros(num_samples, dtype=np_module.float64)
    mean_b = np_module.zeros(num_samples, dtype=np_module.float64)
    m2_a = np_module.zeros(num_samples, dtype=np_module.float64)
    m2_b = np_module.zeros(num_samples, dtype=np_module.float64)
    n_a = 0
    n_b = 0

    for i in range(num_traces):
        trace = traces_dataset[i].astype(np_module.float64, copy=False)
        if bit_mask[i] == 0:
            n_a += 1
            delta = trace - mean_a
            mean_a += delta / n_a
            m2_a += delta * (trace - mean_a)
        else:
            n_b += 1
            delta = trace - mean_b
            mean_b += delta / n_b
            m2_b += delta * (trace - mean_b)

    if n_a < 2 or n_b < 2:
        return np_module.zeros(num_samples, dtype=np_module.float64), n_a, n_b

    var_a = m2_a / (n_a - 1)
    var_b = m2_b / (n_b - 1)
    denom = np_module.sqrt(var_a / n_a + var_b / n_b)
    t_values = np_module.zeros(num_samples, dtype=np_module.float64)
    nonzero = denom > 0
    t_values[nonzero] = (mean_a[nonzero] - mean_b[nonzero]) / denom[nonzero]
    return t_values, n_a, n_b

def plot_t_curve(plt_module, t_values, threshold, title, output_path):
    """
    Plots the t-value curve with threshold lines and saves to file.
    """
    plt_module.figure(figsize=(12, 4))
    plt_module.plot(t_values, linewidth=1.0)
    plt_module.axhline(threshold, color="red", linewidth=1.0)
    plt_module.axhline(-threshold, color="red", linewidth=1.0)
    plt_module.title(title)
    plt_module.xlabel("Sample Index")
    plt_module.ylabel("t-value")
    plt_module.tight_layout()
    plt_module.savefig(output_path, dpi=150)
    plt_module.close()

def crossing_stats(np_module, t_values, threshold):
    """
    Returns the first index, last index, and count where |t| exceeds the threshold.
    """
    indices = np_module.where(np_module.abs(t_values) > threshold)[0]
    if indices.size == 0:
        return -1, -1, 0
    return int(indices[0]), int(indices[-1]), int(indices.size)

def ensure_dir(path):
    """
    Ensures the output directory exists.
    """
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)

def prompt_analysis_mode():
    """
    Prompts the user to select an analysis mode from the console.
    """
    print("请选择分析模式:")
    print("  1) byte0_plot        - 只分析每个阶段的 byte0，并保存图像")
    print("  2) all_bytes_console - 分析每个阶段的 byte0~byte15，只输出控制台结果")
    while True:
        choice = input("请输入 1 或 2: ").strip()
        if choice == "1":
            return "byte0_plot"
        if choice == "2":
            return "all_bytes_console"
        print("输入无效，请重新输入 1 或 2。")

def analyze_bit_task(np_module, traces, label, byte_index, byte_data, bit_index, ratio, bias, threshold):
    """
    Analyzes one selected bit and returns console/CSV summary fields.
    """
    bit_mask = build_bit_mask(np_module, byte_data, 0, bit_index)
    t_values, n_a, n_b = welch_t_for_bit(np_module, traces, bit_mask)
    first_idx, last_idx, leak_count = crossing_stats(np_module, t_values, threshold)
    span = last_idx - first_idx if first_idx >= 0 else "none"
    return {
        "label": label,
        "byte_index": byte_index,
        "bit_index": bit_index,
        "ratio": ratio,
        "bias": bias,
        "n_a": n_a,
        "n_b": n_b,
        "first_crossing": first_idx if first_idx >= 0 else "none",
        "last_crossing": last_idx if last_idx >= 0 else "none",
        "crossing_span": span,
        "leakage_count": leak_count,
    }

def write_summary_csv(rows, output_path):
    """
    Writes all-bytes console summary rows to CSV.
    """
    with open(output_path, "w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["label", "byte_index", "bit_index", "ratio", "bias", "n_a", "n_b", "first_crossing", "last_crossing", "crossing_span", "leakage_count"])
        writer.writeheader()
        writer.writerows(rows)

def analyze_stage(np_module, plt_module, traces, label, analysis_data, topk, threshold, out_dir, mode):
    """
    Analyzes one stage in either byte0 plotting mode or all-bytes console mode.
    """
    if mode == "byte0_plot":
        byte_indices = [0]
        summary_rows = []
        for target_byte_index in byte_indices:
            byte_data = analysis_data[:, target_byte_index:target_byte_index + 1]
            ratios = compute_bit_ratios(np_module, byte_data)
            selected = select_candidate_bits(ratios, topk)
            if not selected:
                print(f"No bits found for {label}.byte{target_byte_index}.")
                continue
            print(f"Selected bits for {label}.byte{target_byte_index} (highest bias first):")
            for bias, _, bit_index, ratio in selected:
                print(f"{label}[{target_byte_index}].bit{bit_index} ratio={ratio:.4f}, bias={bias:.4f}")
                result = analyze_bit_task(np_module, traces, label, target_byte_index, byte_data, bit_index, ratio, bias, threshold)
                title = f"TLVA: {label}[{target_byte_index}].bit{bit_index} (ratio={ratio:.4f}, A={result['n_a']}, B={result['n_b']})"
                output_path = os.path.join(out_dir, f"tlva_{label}_{target_byte_index}_{bit_index}.png")
                bit_mask = build_bit_mask(np_module, byte_data, 0, bit_index)
                t_values, _, _ = welch_t_for_bit(np_module, traces, bit_mask)
                plot_t_curve(plt_module, t_values, threshold, title, output_path)
                print(f"First crossing: {label}[{target_byte_index}].bit{bit_index} -> {result['first_crossing']}")
                print(f"Last crossing: {label}[{target_byte_index}].bit{bit_index} -> {result['last_crossing']}")
                print(f"Crossing span: {label}[{target_byte_index}].bit{bit_index} -> {result['crossing_span']}")
                print(f"Leakage count: {label}[{target_byte_index}].bit{bit_index} -> {result['leakage_count']}")
                print(f"Saved: {output_path}")
        return summary_rows

    tasks = []
    for target_byte_index in range(16):
        byte_data = analysis_data[:, target_byte_index:target_byte_index + 1]
        ratios = compute_bit_ratios(np_module, byte_data)
        selected = select_candidate_bits(ratios, topk)
        if not selected:
            print(f"No bits found for {label}.byte{target_byte_index}.")
            continue
        print(f"Selected bits for {label}.byte{target_byte_index} (highest bias first):")
        for bias, _, bit_index, ratio in selected:
            print(f"{label}[{target_byte_index}].bit{bit_index} ratio={ratio:.4f}, bias={bias:.4f}")
            tasks.append((target_byte_index, byte_data, bit_index, ratio, bias))

    summary_rows = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(analyze_bit_task, np_module, traces, label, byte_index, byte_data, bit_index, ratio, bias, threshold) for byte_index, byte_data, bit_index, ratio, bias in tasks]
        for future in as_completed(futures):
            summary_rows.append(future.result())

    summary_rows.sort(key=lambda row: (row["label"], row["byte_index"], row["bit_index"]))
    for row in summary_rows:
        print(f"First crossing: {row['label']}[{row['byte_index']}].bit{row['bit_index']} -> {row['first_crossing']}")
        print(f"Last crossing: {row['label']}[{row['byte_index']}].bit{row['bit_index']} -> {row['last_crossing']}")
        print(f"Crossing span: {row['label']}[{row['byte_index']}].bit{row['bit_index']} -> {row['crossing_span']}")
        print(f"Leakage count: {row['label']}[{row['byte_index']}].bit{row['bit_index']} -> {row['leakage_count']}")
    return summary_rows

def main():
    """
    Runs TLVA analysis for intermediate decryption stages and saves plots.
    """
    args = parse_args()
    selected_mode = prompt_analysis_mode()
    np_module, h5py, plt_module = require_dependencies()

    if not os.path.isfile(args.h5):
        print(f"H5 file not found: {args.h5}")
        sys.exit(1)

    ensure_dir(args.out_dir)

    with h5py.File(args.h5, "r") as h5_file:
        required = [args.traces_ds, args.plaintext_ds, args.ciphertext_ds]
        if any(name not in h5_file for name in required):
            print("Dataset names not found in H5 file.")
            print(f"Available datasets: {list(h5_file.keys())}")
            sys.exit(1)

        traces = h5_file[args.traces_ds] if selected_mode == "byte0_plot" else load_dataset(h5_file, args.traces_ds)
        ciphertext = load_dataset(h5_file, args.ciphertext_ds)
        plaintext = load_dataset(h5_file, args.plaintext_ds)
        targets, recovered = compute_decryption_stage_data(np_module, ciphertext)
        matched = np_module.all(recovered == plaintext, axis=1)
        print(f"Key verification: {int(matched.sum())}/{matched.size} traces matched")
        if not matched.all():
            print(f"First mismatch trace: {int(np_module.where(~matched)[0][0])}")
        print("Analysis source: intermediate")
        print("Intermediate stages: ct0, invsb_r10 ... invsb_r1, pt0")
        print(f"Analysis mode: {selected_mode}")

        summary_rows = []
        for label, analysis_data in targets:
            summary_rows.extend(analyze_stage(
                np_module,
                plt_module,
                traces,
                label,
                analysis_data,
                args.topk,
                args.threshold,
                args.out_dir,
                selected_mode,
            ))
        if selected_mode == "all_bytes_console":
            summary_path = os.path.join(args.out_dir, "tlva_all_bytes_summary.csv")
            write_summary_csv(summary_rows, summary_path)
            print(f"Summary CSV saved: {summary_path}")

if __name__ == "__main__":
    main()