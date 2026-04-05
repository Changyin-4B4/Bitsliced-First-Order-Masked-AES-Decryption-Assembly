// 声明汇编实现的AES函数
extern void asm_aes(uint8_t *in_out, uint32_t *round_keys, uint8_t *random_pool);
extern uint8_t reserve_pool[2048];
extern void prng_fill_reserve_pool(void);

// AES-128密钥 (从test_decryption.py)
static const uint8_t aes_key[16] = {
    0x80, 0x0c, 0xc0, 0x57, 0xf7, 0x9f, 0xd9, 0x19,
    0x1f, 0x5c, 0x97, 0x6b, 0x93, 0xef, 0xd1, 0xc2
};

// 预计算的轮密钥缓存 (避免每次解密都重新扩展)
static aligned_state_t round_keys[11];

// 比特切片后的轮密钥: 11轮, 每轮8个bit平面 (32位存储)
static uint32_t BsRoundKeys[11][8];

static void convert_to_bitslice(void) {
    // 目标格式: 
    // 1. 轮数倒序: BsRoundKeys[0] 对应 RoundKeys[10] (最后一轮), BsRoundKeys[10] 对应 RoundKeys[0]
    // 2. 每一组内的8个32位数组代表了原密钥byte的bit0-bit7
    
    const uint8_t byte_order[16] = {
        // Bits 16-23 (Target High-to-Low: 2, 6, 10, 14, 3, 7, 11, 15)
        // So Low-to-High (filling order) must be reversed:
        15, 11, 7, 3, 14, 10, 6, 2,
        // Bits 24-31 (Target High-to-Low: 0, 4, 8, 12, 1, 5, 9, 13)
        // So Low-to-High (filling order) must be reversed:
        13, 9, 5, 1, 12, 8, 4, 0
    };

    for (int r = 0; r < 11; r++) {
        // 倒序读取 RoundKeys: r=0 -> RoundKeys[10], r=10 -> RoundKeys[0]
        const uint8_t *rk = round_keys[10 - r].bytes;
        
        for (int b = 0; b < 8; b++) { // bit 0 to 7
            uint32_t accumulator = 0;
            for (int k = 0; k < 16; k++) {
                // 获取当前Byte位置
                uint8_t byte_idx = byte_order[k];
                // 提取第b位
                uint8_t bit_val = (rk[byte_idx] >> b) & 1;
                
                if (bit_val) {
                    // 填充到对应位置 (从 bit 16 开始向上填充)
                    accumulator |= (1UL << (16 + k));
                }
            }
            BsRoundKeys[r][b] = accumulator;
        }
    }
}


uint8_t ciphertext[16];
for (int i = 0; i < 16; i++) {
    ciphertext[i] = sys_usart_recv_byte();
}
// 复制密文到解密缓冲区（asm_aes是原地修改）
memcpy(decrypted_data, ciphertext, 16);

// 使用汇编实现的掩码AES解密
// 参数1: 数据 (输入密文 -> 输出明文)
// 参数2: 轮密钥 (必须是比特切片后的格式)
// 参数3: 随机数池 (用于掩码防护)
asm_aes(decrypted_data, (uint32_t*)BsRoundKeys, reserve_pool);
prng_fill_reserve_pool();
// 发送16字节解密数据
sys_usart_send(decrypted_data, 16);