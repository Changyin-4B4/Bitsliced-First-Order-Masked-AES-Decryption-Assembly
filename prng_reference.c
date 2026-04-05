// --------------------------------------------------------
// EmbeddedPRNG Implementation
// 嵌入式三层级联 PRNG 实现
// --------------------------------------------------------
//
// 设计概述 / Design Overview:
//
//   三个 256 字节的状态池（Pool 1/2/3）级联更新，熵源来自 ADC 温度传感器最低位。
//   Three 256-byte state pools (Pool 1/2/3) are updated in a cascaded manner,
//   seeded by the LSB of the ADC temperature sensor reading.
//
//   更新频率 / Update frequency:
//     Pool 1：每输出 1 字节更新一次（最高频）
//     Pool 2：Pool 1 指针溢出（每 256 字节）时更新一次
//     Pool 3：Pool 2 指针溢出（每 65536 字节）时更新一次（最低频）
//
//     Pool 1: updated every 1 byte output (highest frequency)
//     Pool 2: updated every 256 bytes (on Pool 1 pointer wrap)
//     Pool 3: updated every 65536 bytes (on Pool 2 pointer wrap)
//
//   每次调用 prng_fill_reserve_pool() 输出 1792 字节，
//   Pool 3 在单次调用中不会触发更新（1792 < 65536）。
//   Each call to prng_fill_reserve_pool() outputs 1792 bytes;
//   Pool 3 is not triggered within a single call (1792 < 65536).
//
// ⚠️  安全声明 / Security Notice:
//   本方案未经正式密码学分析，但在大样本下通过了统计质量测试（详见 prng_verify.py）。
//   设计目标是在资源受限的 Cortex-M0 上为一阶 ISW 掩码提供足够的随机性。
//   不建议直接用于其他安全场景，如需复用请先针对目标场景进行独立评估。
//
//   This PRNG has not undergone formal cryptographic analysis, but has passed
//   statistical quality tests on large sample sizes (see prng_verify.py).
//   It is designed to provide sufficient randomness for first-order ISW masking
//   on a resource-constrained Cortex-M0.
//   It is NOT recommended for other security-critical applications without
//   independent evaluation for the target use case.
// --------------------------------------------------------

uint8_t pool1[256] __attribute__((aligned(4))); // 主输出池 / Primary output pool
uint8_t pool2[256];                              // 二级种子池 / Secondary seed pool
uint8_t pool3[256];                              // 三级熵池，ADC 直接注入 / Tertiary entropy pool, fed directly by ADC
uint8_t reserve_pool[1792] __attribute__((aligned(4))); // 对齐要求来自 asm_aes 的 LDMIA/STMIA / Alignment required by LDMIA/STMIA in asm_aes
/*
 * reserve_pool 大小说明 / Reserve Pool Size Rationale
 *
 * 理论最小需求 / Theoretical minimum requirement:
 *
 *   - ISW 乘法随机数：asm_aes 汇编中实际 AND 门数量为 340 个。
 *     每个 AND 门消耗一个随机数。理论上每个随机数只需 16 位，
 *     但 asm_aes 使用 LDMIA Rn!, {Rt} 逐个加载随机数并自动递进指针。
 *     Cortex-M0 上 LDRH 不支持自动后递进，若改用 LDRH 则每次需要
 *     额外的 ADDS 指令来移动基址，引入不必要的开销。
 *     因此选择 LDMIA（4 字节对齐，自动后递进），每次读取 4 字节，
 *     仅使用低 16 位，高 16 位丢弃。
 *     这是以空间换指令数的有意取舍，随机池的产出速率足以覆盖此开销。
 *     小计：340 × 4 = 1360 字节
 *
 *   - 初始密文掩码：16 字节
 *
 *   - 轮密钥掩码：11 轮 × 8 个比特平面 × 2 字节 = 176 字节
 *     （由 fill_high_16bits_random 从池子末尾取用）
 *
 *   理论合计：1360 + 16 + 176 = 1552 字节（如有出入请以实际统计为准）
 *
 * 实际取值 1792 的原因 / Why 1792:
 *
 *   1792 = 7 × 256
 *
 *   配套的 prng_fill_reserve_pool 以 256 字节为单位生成随机数，
 *   取整数倍可避免边界处理，简化实现。
 *
 * 如需移植或修改 / If you need to adapt this:
 *
 *   1. 重新统计汇编中 AND 门的数量（若修改了 S 盒电路）
 *   2. 按上述公式重新计算理论最小值
 *   3. 向上取整到你的 PRNG 批量大小的整数倍
 *   4. 对应修改 fill_high_16bits_random 中的 pool_idx 起始值
 *
 * ---------------------------------------------------------------------
 *
 * The pool size is determined by three consumers:
 *
 *   - ISW multiplication randomness: 340 AND gates, counted directly
 *     from the assembly (includes all AND instructions after ISW
 *     masking expansion, not an estimate from the unmasked circuit).
 *   - Each AND gate consumes one random value. Only 16 bits are needed
 *     per value, but asm_aes loads them with LDMIA Rn!, {Rt}, which
 *     auto-increments the base pointer by 4 after each load.
 *     On Cortex-M0, LDRH does not support auto-increment; using LDRH
 *     would require an additional ADDS instruction per load to advance
 *     the base pointer, adding unnecessary overhead.
 *     LDMIA (4-byte aligned, auto-increment) is therefore used instead:
 *     4 bytes are loaded each time, only the lower 16 bits are used,
 *     and the upper 16 bits are discarded.
 *     This is a deliberate space-for-instructions trade-off; the PRNG
 *     throughput is sufficient to absorb the wasted bytes.
 *     Subtotal: 340 × 4 = 1,360 bytes
 *
 *   - Initial ciphertext masking: 16 bytes
 *
 *   - Round-key masking: 11 rounds × 8 bit-planes × 2 bytes = 176 bytes
 *     (consumed from the END of the pool by fill_high_16bits_random)
 *
 *   Theoretical total: 1360 + 16 + 176 = 1552 bytes (verify against
 *   actual assembly if modified)
 *
 * 1792 = 7 × 256 is chosen because prng_fill_reserve_pool generates
 * randomness in 256-byte batches; using an integer multiple avoids
 * boundary handling in the PRNG implementation.
 *
 * To adapt for a different S-box circuit or PRNG batch size:
 *   1. Re-count AND gates in the modified circuit
 *   2. Recalculate the theoretical minimum using the formula above
 *   3. Round up to the nearest multiple of your PRNG batch size
 *   4. Update the pool_idx starting value in fill_high_16bits_random
 */

uint8_t idx1 = 0;    // Pool 1 当前指针，溢出自动模 256 / Pool 1 pointer, wraps mod 256 automatically
uint8_t idx2 = 0;    // Pool 2 当前指针 / Pool 2 pointer
uint8_t idx3 = 0;    // Pool 3 当前指针 / Pool 3 pointer
uint16_t reserve_idx = 0; // reserve_pool 填充进度（当前未使用） / Fill progress for reserve_pool (currently unused)

static uint8_t func1(uint8_t val, uint8_t feedback) {
    // 非线性混合：异或 + 位移 + 常数扰动
    // Nonlinear mixing: XOR + bit shifts + constant perturbation
    uint8_t x = (val ^ feedback);
    x ^= (x << 3);
    x ^= (x >> 5);
    x ^= 0x1B; // AES 域的不可约多项式常数，无特殊含义，仅作扰动
                // Irreducible polynomial constant from AES field, used as perturbation only
    return x;
}

static uint8_t func2(uint8_t val, uint8_t feedback) {
    // 非线性混合：乘法 + 加法（利用 uint8_t 自动模 256）
    // Nonlinear mixing: multiplication + addition (mod 256 via uint8_t overflow)
    uint8_t x = (val ^ feedback);
    x = (x * 31 + 13);
    return x;
}

static uint8_t func3(uint8_t val, uint8_t feedback, uint8_t idx) {
    // 非线性混合：位旋转 + 取反，旋转量随索引变化
    // Nonlinear mixing: bit rotation + bitwise NOT, rotation amount varies with index
    uint8_t temp = (val ^ feedback);
    uint8_t shift = idx % 8;
    uint8_t x = (temp << shift) | (temp >> (8 - shift));
    x = ~x;
    return x;
}

static void prng_init(void) {
    // 用 ADC 采样填充三个池子的初始状态
    // Initialize all three pools with ADC samples
    // 注：每次采样的最低位作为熵，其余位也保留（增加初始状态多样性）
    // Note: LSB of each sample carries entropy; higher bits are retained for diversity
    for (int i = 0; i < 256; i++) {
        pool1[i] = adc_read_raw() & 0xFF;
        pool2[i] = adc_read_raw() & 0xFF;
        pool3[i] = adc_read_raw() & 0xFF;
    }
}

static void _advance_pool3(void) {
    uint8_t current_idx = idx3;

    // 混合 Pool 1[0] 和新鲜 ADC 采样作为熵注入
    // Mix Pool 1[0] with a fresh ADC sample as entropy input
    uint8_t adc_noise = adc_read_raw() & 0xFF;
    uint8_t seed_entropy = (pool1[0] + adc_noise);

    pool3[current_idx] = func3(pool3[current_idx], seed_entropy, current_idx);
    idx3++; // uint8_t 自动模 256 / Implicit mod 256 for uint8_t
}

static void _advance_pool2(void) {
    uint8_t current_idx = idx2;

    // 以 Pool 3 当前位置的值作为种子，取完即触发 Pool 3 刷新该位置。
    // 这是有意为之的"拿即刷"设计：Pool 2 消费 Pool 3[idx3] 的旧值，
    // 消费行为本身触发了对该位置的更新，而非取更新后的新值。
    //
    // Use the current Pool 3 value as seed; this read is immediately
    // followed by a Pool 3 refresh of that same position.
    // This is intentional "read-then-refresh" design: Pool 2 consumes
    // the old value at Pool 3[idx3], and that consumption triggers
    // the update of that position — not the value after the update.
    uint8_t seed_p3 = pool3[idx3];

    pool2[current_idx] = func2(pool2[current_idx], seed_p3);
    idx2++;

    // Pool 2 溢出时级联触发 Pool 3 更新
    // Cascade: trigger Pool 3 advance when Pool 2 wraps
    if (idx2 == 0) {
        _advance_pool3();
    }
}

void prng_fill_reserve_pool(void) {
    // 填充 reserve_pool，供下一次 asm_aes 调用使用
    // Fill reserve_pool for the next asm_aes call
    //
    // 输出逻辑：读取 Pool 1 当前值后立即用 Pool 2 的种子更新它，
    // 保证输出值与下一次更新解耦。
    // Output logic: the current Pool 1 value is read BEFORE being updated
    // with Pool 2's seed, decoupling the output from the next update.
    reserve_idx = 0;

    for (int i = 0; i < 1792; i++) {
        uint8_t val      = pool1[idx1];
        uint8_t seed_p2  = pool2[idx2];

        pool1[idx1] = func1(val, seed_p2); // 更新后不影响本次输出 / Update does not affect current output

        reserve_pool[i] = val;

        idx1++;
        // Pool 1 溢出时级联触发 Pool 2 更新
        // Cascade: trigger Pool 2 advance when Pool 1 wraps
        if (idx1 == 0) {
            _advance_pool2();
        }
    }
}
