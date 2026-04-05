import os
import sys
from itertools import combinations


H5_FILE_PATH = r""
OUTPUT_DIR = r""
GROUP_NAMES = ["group_0", "group_1", "group_2"]
TRACES_DATASET = "traces"
PLAINTEXT_DATASET = "plaintext"
THRESHOLD = 4.5


def require_dependencies():
    """导入脚本运行所需依赖，并返回对应模块。"""
    try:
        import numpy as np
        import h5py
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return np, h5py, plt
    except Exception as exc:
        print(f"Missing dependencies: {exc}")
        sys.exit(1)


def ensure_dir(path):
    """确保输出目录存在。"""
    os.makedirs(path, exist_ok=True)


def format_bytes_row(row):
    """将一行 uint8 数组格式化为十六进制字符串。"""
    return "".join(f"{int(x):02x}" for x in row)


def validate_fixed_plaintext(np, plaintext, group_name):
    """验证同一组内的 plaintext 是否完全一致。"""
    if plaintext.ndim != 2 or plaintext.shape[0] == 0:
        print(f"{group_name} 的 plaintext 形状异常: {plaintext.shape}")
        sys.exit(1)

    if not np.all(plaintext == plaintext[0]):
        print(f"警告: {group_name} 中的 plaintext 并非完全一致，请检查数据。")


def load_group_data(np, h5py, h5_path, group_name):
    """从 HDF5 指定 group 中读取 traces 与 plaintext。"""
    with h5py.File(h5_path, "r") as handle:
        if group_name not in handle:
            print(f"HDF5 中不存在分组: {group_name}")
            sys.exit(1)

        group = handle[group_name]

        if TRACES_DATASET not in group or PLAINTEXT_DATASET not in group:
            print(f"{group_name} 缺少必要数据集: {TRACES_DATASET} 或 {PLAINTEXT_DATASET}")
            sys.exit(1)

        traces = group[TRACES_DATASET][...]
        plaintext = group[PLAINTEXT_DATASET][...]

    if traces.ndim != 2:
        print(f"{group_name} 的 traces 形状异常: {traces.shape}")
        sys.exit(1)

    validate_fixed_plaintext(np, plaintext, group_name)
    return traces, plaintext[0]


def welch_t_test(np, traces_a, traces_b):
    """对两组 traces 按采样点执行 Welch t-test。"""
    if traces_a.ndim != 2 or traces_b.ndim != 2:
        print("输入 traces 维度错误，必须为二维数组。")
        sys.exit(1)

    if traces_a.shape[1] != traces_b.shape[1]:
        print(
            f"两组 traces 的采样点数量不一致: "
            f"{traces_a.shape[1]} vs {traces_b.shape[1]}"
        )
        sys.exit(1)

    n_a = traces_a.shape[0]
    n_b = traces_b.shape[0]

    if n_a < 2 or n_b < 2:
        print("每组至少需要 2 条 trace 才能计算无偏方差。")
        sys.exit(1)

    mean_a = np.mean(traces_a, axis=0, dtype=np.float64)
    mean_b = np.mean(traces_b, axis=0, dtype=np.float64)
    var_a = np.var(traces_a, axis=0, dtype=np.float64, ddof=1)
    var_b = np.var(traces_b, axis=0, dtype=np.float64, ddof=1)

    denom = np.sqrt(var_a / n_a + var_b / n_b)
    t_values = np.zeros_like(mean_a, dtype=np.float64)

    nonzero = denom > 0
    t_values[nonzero] = (mean_a[nonzero] - mean_b[nonzero]) / denom[nonzero]

    return t_values, n_a, n_b


def crossing_stats(np, t_values, threshold):
    """统计超过阈值的采样点位置与数量。"""
    indices = np.where(np.abs(t_values) > threshold)[0]
    if indices.size == 0:
        return -1, -1, 0
    return int(indices[0]), int(indices[-1]), int(indices.size)


def plot_and_save(plt, t_values, threshold, title, output_path):
    """绘制 t-value 曲线并保存为 PNG 图像。"""
    plt.figure(figsize=(14, 4))
    plt.plot(t_values, linewidth=0.8, color="steelblue")
    plt.axhline(threshold, color="red", linewidth=1.0, linestyle="--", label=f"+{threshold}")
    plt.axhline(-threshold, color="red", linewidth=1.0, linestyle="--", label=f"-{threshold}")
    plt.axhline(0, color="gray", linewidth=0.6, linestyle=":")
    plt.title(title)
    plt.xlabel("Sample Index")
    plt.ylabel("t-value")
    plt.legend(loc="upper right")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()


def load_all_groups(np, h5py, h5_path):
    """读取全部目标分组的数据，并返回分组列表。"""
    groups = []

    for group_name in GROUP_NAMES:
        print(f"读取分组: {group_name}")
        traces, plaintext0 = load_group_data(np, h5py, h5_path, group_name)
        print(f"  traces shape : {traces.shape}")
        print(f"  plaintext[0] : {format_bytes_row(plaintext0)}")
        groups.append((group_name, traces, plaintext0))

    return groups


def run_fixed_vs_fixed_tvla(np, plt, groups, output_dir):
    """对所有 group 两两组合执行 Fixed-vs-Fixed TVLA。"""
    for idx_a, idx_b in combinations(range(len(groups)), 2):
        name_a, traces_a, pt_a = groups[idx_a]
        name_b, traces_b, pt_b = groups[idx_b]

        label = f"{name_a}_vs_{name_b}"
        print("\n" + "=" * 60)
        print(f"分析对: {label}")
        print(f"  输入 A: {format_bytes_row(pt_a)}  ({traces_a.shape[0]} traces)")
        print(f"  输入 B: {format_bytes_row(pt_b)}  ({traces_b.shape[0]} traces)")

        t_values, n_a, n_b = welch_t_test(np, traces_a, traces_b)
        first, last, count = crossing_stats(np, t_values, THRESHOLD)

        print(f"  阈值       : ±{THRESHOLD}")
        print(f"  首次破限   : sample {first if first >= 0 else 'none'}")
        print(f"  末次破限   : sample {last if last >= 0 else 'none'}")
        print(f"  破限跨度   : {last - first if first >= 0 else 'none'}")
        print(f"  破限点数量 : {count}")

        if count == 0:
            verdict = "PASS — 未检测到显著泄漏"
        else:
            verdict = f"FAIL — 存在 {count} 个泄漏点"
        print(f"  结论       : {verdict}")

        title = (
            f"Fixed-vs-Fixed TVLA: {label}\n"
            f"A={format_bytes_row(pt_a)[:8]}... ({n_a} traces)  "
            f"B={format_bytes_row(pt_b)[:8]}... ({n_b} traces)  "
            f"threshold=±{THRESHOLD}"
        )
        output_path = os.path.join(output_dir, f"fvf_{label}.png")
        plot_and_save(plt, t_values, THRESHOLD, title, output_path)
        print(f"  图像已保存 : {output_path}")


def main():
    """执行单文件三分组的 Fixed-vs-Fixed TVLA 分析流程。"""
    np, h5py, plt = require_dependencies()

    if not os.path.isfile(H5_FILE_PATH):
        print(f"HDF5 文件不存在: {H5_FILE_PATH}")
        sys.exit(1)

    ensure_dir(OUTPUT_DIR)
    groups = load_all_groups(np, h5py, H5_FILE_PATH)
    run_fixed_vs_fixed_tvla(np, plt, groups, OUTPUT_DIR)

    print("\n完成，所有图像保存于:")
    print(OUTPUT_DIR)


if __name__ == "__main__":
    main()