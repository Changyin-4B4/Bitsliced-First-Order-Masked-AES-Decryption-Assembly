
# Bitsliced First-Order Masked AES-128 Decryption — ARM Cortex-M0 Assembly

# 比特切片一阶掩码 AES-128 解密 — ARM Cortex-M0 汇编实现

## Overview / 项目概述

This project provides an ARM Cortex-M0 assembly implementation of AES-128 decryption
with first-order Boolean masking, using a bitsliced representation.

本项目提供了一个 ARM Cortex-M0 汇编实现的 AES-128 解密，采用比特切片表示并施加一阶布尔掩码。

The original motivation: when working on a smart card course project, no usable reference
implementation of bitsliced first-order masked AES in assembly could be found.
C implementations are difficult to secure against side-channel attacks due to
compiler optimizations that may violate masking invariants.
This project was written from scratch to fill that gap.

开源初衷：在课程项目中，没能找到任何可参考的比特切片一阶掩码 AES 汇编实现。
C 语言实现在编译器优化下难以保证掩码方案的安全性不被破坏，因此从零开始写了这份汇编实现。

**Platform / 平台:** STM32F051 (ARM Cortex-M0, 8 MHz)
**Algorithm / 算法:** AES-128 Decryption / AES-128 解密
**Cycle count / 指令周期:** 26,801 cycles
**Masking / 掩码方案:** First-order Boolean masking / 一阶布尔掩码
**Representation / 数据表示:** Bitsliced, 16-bit per bit-plane / 比特切片，每比特平面 16 位

---

## Implementation Notes / 实现说明

AES decryption consists of four core operations plus pack/unpack steps.
Only key design decisions are noted here; please read the source for full details.

AES 解密包含四个核心步骤以及打包/解包两个辅助步骤。
以下仅说明关键设计决策，完整细节请阅读源码。

### Bitslice Representation / 比特切片表示

The 128-bit AES state is represented as 8 × 32-bit words.
Each word holds one bit-plane: bit `b` of all 16 state bytes is packed into
the lower 16 bits of word `b`.
The upper 16 bits of each word carry the corresponding Boolean mask share.

128 位 AES 状态表示为 8 个 32 位字，每个字存储一个比特平面：
第 `b` 个字的低 16 位存放所有 16 个状态字节的第 `b` 位，高 16 位存放对应的布尔掩码 share。

### InvShiftRows

Implemented directly as bit-plane operations derived from the mathematical
definition of InvShiftRows. No lookup table required.

基于 InvShiftRows 的数学定义，直接在比特平面上进行对应操作，无需查表。

### InvSubBytes

Based on the circuit from:

> Boyar, J., & Peralta, R. (2012). A small depth-16 circuit for the AES S-box.

Manual instruction scheduling was applied under Cortex-M0 register constraints
to minimize cycle count and avoid Hamming-distance leakage on the bus.
ISW multiplication is used for all AND gates in the masked circuit.

基于 Boyar-Peralta 的论文电路，在 Cortex-M0 寄存器约束下进行了手动指令调度，
压缩指令周期并避免总线上的汉明距离泄漏。
电路中所有 AND 门均使用 ISW 乘法实现掩码。

### InvMixColumns

Fixed-coefficient xtime multiplications were simplified algebraically:
each output bit is expressed as a linear combination of input bits,
eliminating conditional branches entirely and minimizing instruction count.
The derivation worksheet is included as `InvMixColumns.csv`.

对固定系数的 xtime 乘法进行了代数化简，将每个输出 bit 写成输入 bit 的线性组合，
彻底消除了条件分支，并尽可能缩减了指令周期数。
化简草稿附于 `InvMixColumns.csv`。

---

## Usage / 使用方法

See `aes_usage_example.c` for the complete calling convention, including:

- Key pre-processing (standard expansion → bitslice conversion)
- Round-key masking
- Function signature and argument format
- Refresh sequence after each decryption

详见 `aes_usage_example.c`，包含：

- 密钥预处理（标准扩展 → 比特切片转换）
- 轮密钥掩码填充
- 函数调用格式与参数说明
- 每次解密后的随机池刷新流程

### Random Pool / 随机数池

A reference PRNG implementation is provided in `prng_reference.c`.
See `prng_verify.py` for statistical quality verification.
Callers may substitute any entropy source that satisfies the interface
documented in `aes_usage_example.c`.

参考随机数方案见 `prng_reference.c`，统计质量验证脚本见 `prng_verify.py`。
调用方可替换为任何满足 `aes_usage_example.c` 中接口约定的熵源。

---

## Security Evaluation / 安全性评估

Traces were collected on a physical STM32F051 board.
All analysis scripts are in the `test/` directory (no inline comments).

迹线采集于实际 STM32F051 硬件。所有分析脚本见 `test/` 目录（无内联注释）。

### Fixed-vs-Random TVLA (5,000 traces, random input)

Intermediate targets analyzed: ciphertext, InvSubBytes output for rounds 10–1,
and plaintext, across all 16 bytes.

分析目标：密文、第 10 至第 1 轮 InvSubBytes 输出、明文，覆盖全部 16 字节。

| Stage / 阶段         | Result / 结果                                   |
| -------------------- | ----------------------------------------------- |
| Ciphertext (ct)      | ✓ Pass                                         |
| invsb_r10 ~ invsb_r2 | ✓ Pass — no statistically significant leakage |
| invsb_r1 / plaintext | ✗ Fail (sample ~73,000 onward)                 |

The leakage at invsb_r1 and plaintext is expected and theoretically unavoidable:
both correspond to the unmasking boundary where the final state is written out
in unmasked form. Since invsb_r1 and plaintext differ only by a constant round
key XOR, their TVLA curves are identical — they represent the same physical
operation. This leakage does not enable key recovery.

invsb_r1 和 plaintext 的泄漏是理论必然的端点泄漏（endpoint leakage）：
两者对应去掩码边界，最终状态以非掩码形式写出。由于两者仅相差一个固定轮密钥的
异或，TVLA 曲线完全一致，本质上是同一操作的两种视角。此泄漏不能用于恢复密钥。

Detailed results: `tlva_all_bytes_summary.csv`

### Fixed-vs-Fixed TVLA (1,500 × 3 traces, fixed input)

The three fixed input groups have different Hamming weights (HW = 59 / 65 / 71),
which introduces a systematic power baseline difference unrelated to the masking
scheme. This is believed to be the primary cause of the observed leakage.
A corrected evaluation using inputs with identical Hamming weight is recommended
for reproduction.

三组固定输入的汉明重量不同（HW = 59 / 65 / 71），导致功耗基线存在系统性差异，
与掩码方案无关，猜测这是观察到泄漏的主要原因。
建议复现时使用汉明重量相同的输入进行 Fixed-vs-Fixed 测试。

Comparison plots: `test/overlay_compare_output/`

### CPA (5,000 traces, random input)

Single-bit CPA was performed against the random-input traces.
No key byte with statistically significant correlation was found.

针对随机输入迹线进行了单 bit CPA 攻击，未能找到具有显著相关性的密钥字节。

CPA plots: `test/cpa_output/`

---

## Contributions Welcome / 欢迎继续

总的来说测试表现还是不错的。不过受限于课程条件，评估的样本量和攻击手段都有限，
希望有人可以在更大的样本下检验它，或者测试攻破它所需的 trace 数量——
这对于评估一个掩码实现的实际安全裕量来说才是最有说服力的数字。

Overall the results look decent. That said, evaluation was limited by course
constraints in both trace count and attack coverage. We'd love to see someone
push this further — either with a larger dataset, or by finding out exactly
how many traces it takes to break it. That number, more than anything else,
tells you how much security margin a masked implementation actually has.

具体来说，以下问题仍然开放 / Specifically, the following remain open:

1. **增大迹线数量进行一阶 TVLA 验证****Extend trace count for first-order TVLA**当前 5,000 条已有一定说服力，50,000 条以上会更好。The current 5,000-trace result is reasonable; 50,000+ would be more convincing.
2. **二阶 TVLA 和二阶 CPA****Second-order TVLA and CPA**一阶掩码理论上无法抵抗二阶攻击，攻破本实现所需的迹线数量目前未知。A first-order masking scheme is theoretically vulnerable to second-order attacks.
   The number of traces required to break this implementation is an open question.
3. **使用汉明重量相同的输入重新进行 Fixed-vs-Fixed 测试****Re-run Fixed-vs-Fixed TVLA with HW-balanced inputs**初始测试中三组固定输入的汉明重量不同（HW = 59 / 65 / 71），
   导致结果存在干扰，需要重新评估。The initial Fixed-vs-Fixed evaluation was confounded by differing Hamming
   weights (HW = 59 / 65 / 71) across the three input groups; a clean
   re-evaluation is needed.
4. **模板攻击 / Template attacks**
   尚未评估，有条件的可以试试。
   Not evaluated. If you have a clone device, feel free to try.

---

## Alternative Implementation / 备选实现
https://github.com/Changyin-4B4/Masked-AES-Decryption-CortexM0/blob/main/readme.md
`fault_implement/` 里还有另一个版本，把同一数据的两个 share 分别打包在
同一寄存器的高低 16 位来做并行计算。当时的想法是这样能省点事，
结果没快多少，反而埋了个坑。

There's an alternative version in `fault_implement/` that packs both Boolean
shares of each word into the upper and lower 16 bits of the same register,
aiming for parallel computation. It didn't end up being meaningfully faster,
and as it turns out, it has a problem.

**该版本存在一个已知的时间一阶泄漏漏洞，不应用于任何安全敏感场景。**
**This version has a known first-order leakage vulnerability (in the time domain)
and should NOT be used in any security-sensitive context.**

有意思的是，一位同学对这个版本进行了实际的 DPA 攻击，采集了 400,000 条迹线，
依然没能攻破——因为用了错误的攻击模型。
但漏洞是真实存在的，只是需要对症下药。
至于是什么漏洞、该怎么攻，留给感兴趣的人自己去找，
这也算是这个版本唯一的价值了。

Interestingly, a peer ran a physical DPA attack against this version —
400,000 traces, still no key.
Not because the implementation is secure,
but because the wrong attack model was used.
The vulnerability is real; it just requires the right approach to exploit.
Finding it is left as an exercise for the interested reader —
which is honestly the only reason this version is worth including at all.

该版本未附注释，源码仅供参考。调用方式与主版本略有不同。
No annotation has been written for this version; source is provided as-is.
The calling convention differs slightly from the primary implementation.

---

## References / 参考文献

1. *Boyar, J., & Peralta, R. (2012). A small depth-16 circuit for the AES S-box.
   In D. Gritzalis, S. Furnell, & M. Theoharidou (Eds.),
   Information Security and Privacy Research (SEC 2012).
   IFIP Advances in Information and Communication Technology, vol. 376,
   pp. 287–298. Springer, Berlin, Heidelberg.
   https://doi.org/10.1007/978-3-642-30436-1_24
   (Source of the depth-16 AES S-box Boolean circuit / AES S 盒布尔电路来源)*

---

## License / 许可证

MIT License. If this code is used in academic work, please cite this repository.
MIT 许可证。若在学术工作中使用本代码，请注明出处。
