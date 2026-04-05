// 声明汇编实现的 AES 函数 / Declare the assembly-implemented AES function
extern void asm_aes(uint8_t *in_out, uint32_t *round_keys, uint8_t *random_pool);
extern uint8_t reserve_pool[1792]; // 随机数池大小的依据，详见 prng_reference.c / Reserve pool size rationale, see prng_reference.c
extern void prng_fill_reserve_pool(void); // 该函数详见 prng_reference.c / See prng_reference.c for this function

// AES-128 密钥（来自 test_decryption.py） / AES-128 key (from test_decryption.py)
static const uint8_t aes_key[16] = {
    0x80, 0x0c, 0xc0, 0x57, 0xf7, 0x9f, 0xd9, 0x19,
    0x1f, 0x5c, 0x97, 0x6b, 0x93, 0xef, 0xd1, 0xc2
};

// 预计算的轮密钥缓存，避免每次解密都重新扩展 / Precomputed round-key cache to avoid re-expansion on every decryption
static aligned_state_t round_keys[11];

// 比特切片后的轮密钥：11 轮，每轮 8 个 bit 平面（32 位存储） / Bitsliced round keys: 11 rounds, 8 bit-planes per round (stored in 32-bit words)
static uint32_t BsRoundKeys[11][8];

static void convert_to_bitslice(void) {
    /*
     * ⚠️  WARNING: Do NOT modify the byte_order array or the bit-plane
     *     layout without fully understanding asm_aes internals.
     *
     * This function encodes three tightly coupled conventions that must
     * remain consistent with the assembly implementation:
     *
     *   1. Round-key order is REVERSED:
     *      BsRoundKeys[0] <- RoundKeys[10]  (used in decryption round 1)
     *      BsRoundKeys[10]<- RoundKeys[0]   (used in decryption round 10)
     *
     *   2. Byte-to-bit-plane mapping is defined by byte_order[]:
     *      The 16 state bytes are NOT packed in natural order.
     *      This ordering is dictated by the fixed byte layout of the
     *      bit-planes inside asm_aes. The key packing here must conform
     *      to that layout — if the byte order does not match, each round
     *      key byte will operate on the wrong state byte, producing
     *      silently incorrect plaintexts.
     *      In short: byte_order[] adapts the key to fit the assembly,
     *      not the other way around.
     *
     *   3. Bit-plane storage: bit b of the state occupies BsRoundKeys[r][b],
     *      where the lower 16 bits hold key material and the upper 16 bits
     *      hold the corresponding random mask (filled by fill_high_16bits_random).
     *
     * If you modify the assembly (e.g. change the ShiftRows rotation direction
     * or the register allocation for shares), you must re-derive byte_order[]
     * from scratch by tracing the new data flow in asm_aes.
     *
     * -------------------------------------------------------------------------
     *
     * ⚠️  警告：在完全理解 asm_aes 汇编实现之前，请勿修改 byte_order 数组
     *     或比特平面的布局。
     *
     * 本函数编码了三个与汇编实现严格耦合的约定，任何一个发生变化都必须
     * 同步修改另外两处，否则解密结果将静默出错（不会报错，但明文不正确）：
     *
     *   1. 轮密钥顺序是倒序的：
     *      BsRoundKeys[0] <- RoundKeys[10]  （解密第1轮使用）
     *      BsRoundKeys[10]<- RoundKeys[0]   （解密第10轮使用）
     *
     *   2. 字节到比特平面的映射由 byte_order[] 定义：
     *      16个状态字节并非按自然顺序打包。
     *      此顺序由 asm_aes 中比特平面的字节序决定——
     *      汇编函数内部的数据排布是固定的，密钥的切片方式
     *      必须与之严格对齐，否则密钥字节会作用在错误的状态
     *      字节上，导致解密结果静默错误。
     *      换句话说：这里的 byte_order[] 是在"迁就"汇编，
     *      而不是汇编在"迁就"这里。
     *
     *   3. 比特平面存储格式：状态的第 b 位存放在 BsRoundKeys[r][b] 中，
     *      其中低16位存储密钥数据，高16位存储对应的随机掩码
     *      （由 fill_high_16bits_random 填充）。
     *
     * 如果你修改了汇编实现（例如改变了 ShiftRows 的旋转方向，或调整了
     * share 寄存器的分配），必须重新从汇编数据流推导 byte_order[]，
     * 不能沿用原有的值。
     */
    
    const uint8_t byte_order[16] = {
        // bit 0-7：目标顺序按高到低为 2, 6, 10, 14, 3, 7, 11, 15；因此填充顺序需反向 / bit 0-7: target high-to-low order is 2, 6, 10, 14, 3, 7, 11, 15, so filling order must be reversed
        15, 11, 7, 3, 14, 10, 6, 2,
        // bit 8-15：目标顺序按高到低为 0, 4, 8, 12, 1, 5, 9, 13；因此填充顺序需反向 / bit 8-15: target high-to-low order is 0, 4, 8, 12, 1, 5, 9, 13, so filling order must be reversed
        13, 9, 5, 1, 12, 8, 4, 0
    };

    for (int r = 0; r < 11; r++) {
        // 倒序读取 RoundKeys：r=0 对应 RoundKeys[10]，r=10 对应 RoundKeys[0] / Read RoundKeys in reverse order: r=0 maps to RoundKeys[10], r=10 maps to RoundKeys[0]
        const uint8_t *rk = round_keys[10 - r].bytes;
        
        for (int b = 0; b < 8; b++) { // 遍历 bit 0 到 7 / Iterate through bit 0 to 7
            uint32_t accumulator = 0;
            for (int k = 0; k < 16; k++) {
                // 获取当前字节位置 / Get the current byte position
                uint8_t byte_idx = byte_order[k];
                // 提取第 b 位 / Extract bit b
                uint8_t bit_val = (rk[byte_idx] >> b) & 1;
                
                if (bit_val) {
                    // 填充到对应位置，从 bit 0 开始向上填充 / Fill the target position, starting upward from bit 0
                    accumulator |= (1UL << k);
                }
            }
            BsRoundKeys[r][b] = accumulator;
        }
    }
}

static void fill_high_16bits_random(void) {
    // 使用 reserve_pool 填充 BsRoundKeys 的高 16 位，仅填充不做异或掩码，并从池尾取数以避免与 AES 流程复用 / Fill the upper 16 bits of BsRoundKeys from reserve_pool without XOR masking, reading from the end of the pool to avoid reuse with the AES flow
    // reserve_pool 总大小为 1792，需要消耗 11 轮 × 8 位平面 × 2 字节 = 176 字节 / reserve_pool size is 1792 bytes, and this step consumes 11 rounds × 8 bit-planes × 2 bytes = 176 bytes
    int pool_idx = 1792 - 1; // 从最后一个字节开始 / Start from the last byte

    for (int r = 0; r < 11; r++) {
        for (int b = 0; b < 8; b++) {
            // 取两个字节组成 16 位随机数 / Combine two bytes into one 16-bit random value
            uint8_t high_byte = reserve_pool[pool_idx];
            uint8_t low_byte = reserve_pool[pool_idx - 1];
            pool_idx -= 2;

            uint16_t rand_val = ((uint16_t)high_byte << 8) | low_byte;

            // 清除高 16 位并填入随机数，低 16 位保持为 bitsliced round keys / Clear the upper 16 bits and write the random value while keeping the lower 16 bits as the bitsliced round keys
            BsRoundKeys[r][b] &= 0x0000FFFF;
            BsRoundKeys[r][b] |= ((uint32_t)rand_val << 16);
        }
    }
}

uint8_t ciphertext[16];
for (int i = 0; i < 16; i++) {
    ciphertext[i] = sys_usart_recv_byte();
}
// 复制密文到解密缓冲区，asm_aes 会原地修改数据 / Copy ciphertext into the decryption buffer; asm_aes modifies the buffer in place
memcpy(decrypted_data, ciphertext, 16);

// 使用汇编实现的掩码 AES 解密 / Decrypt with the assembly-implemented masked AES
// 参数1：数据，输入为密文，输出为明文 / Arg1: data, ciphertext in and plaintext out
// 参数2：轮密钥，必须为比特切片格式 / Arg2: round keys in bitsliced format
// 参数3：随机数池，用于掩码防护 / Arg3: random pool used for masking protection
asm_aes(decrypted_data, (uint32_t*)BsRoundKeys, reserve_pool);
// 发送 16 字节解密结果 / Send the 16-byte decrypted result
sys_usart_send(decrypted_data, 16);
prng_fill_reserve_pool(); // 刷新随机数池 / Refresh the random pool
fill_high_16bits_random(); // 重新为 BsRoundKeys 的高 16 位填充随机数 / Refill the upper 16 bits of BsRoundKeys with random data
