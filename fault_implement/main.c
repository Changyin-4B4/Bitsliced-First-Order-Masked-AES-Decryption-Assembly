#include <string.h>
#include "sc_system.h"
#include "aes_decrypt.h"

// 声明汇编实现的AES函数
// 参数1: in_out - 密文输入/明文输出 (原地修改)
// 参数2: round_keys - 比特切片后的轮密钥 (uint32_t数组)
// 参数3: random_pool - 随机数池 (uint8_t数组)
//extern void asm_aes(uint8_t *in_out, uint32_t *round_keys, uint8_t *random_pool);

static void sys_adc_init_internal(void) {
    rcc_periph_clock_enable(RCC_ADC1);
    adc_power_off(ADC1);
    
    // 关键：使能内部温度传感器和参考电压通道
    ADC_CCR(ADC1) |= ADC_CCR_TSEN | ADC_CCR_VREFEN;

    adc_set_clk_source(ADC1, ADC_CLKSOURCE_ADC);
    adc_calibrate(ADC1);
    adc_set_operation_mode(ADC1, ADC_MODE_SCAN); // 扫描模式
    adc_set_sample_time_on_all_channels(ADC1, ADC_SMPR_SMP_239DOT5); // 最长采样时间，增加噪声积累
    
    // 选择通道 16 (温度传感器)
    uint8_t channels[] = {ADC_CHANNEL_TEMP};
    adc_set_regular_sequence(ADC1, 1, channels);
    
    adc_power_on(ADC1);
    // 等待 ADC 稳定
    for (int i = 0; i < 1000; i++) __asm__("nop");
}

static uint16_t adc_read_raw(void) {
    adc_start_conversion_regular(ADC1);
    while (!adc_eoc(ADC1));
    return adc_read_regular(ADC1);
}

// --------------------------------------------------------
// EmbeddedPRNG Implementation
// --------------------------------------------------------

uint8_t pool1[256] __attribute__((aligned(4)));
uint8_t pool2[256];
uint8_t pool3[256];
uint8_t reserve_pool[1536] __attribute__((aligned(4)));

uint8_t idx1 = 0;
uint8_t idx2 = 0;
uint8_t idx3 = 0;
uint16_t reserve_idx = 0;

static uint8_t func1(uint8_t val, uint8_t feedback) {
    uint8_t x = (val ^ feedback);
    x ^= (x << 3);
    x ^= (x >> 5);
    x ^= 0x1B;
    return x;
}

static uint8_t func2(uint8_t val, uint8_t feedback) {
    // Strategy 2: Nonlinear with multiplication for Pool 2
    uint8_t x = (val ^ feedback);
    x = (x * 31 + 13);
    return x;
}

static uint8_t func3(uint8_t val, uint8_t feedback, uint8_t idx) {
    // Strategy 3: Bit rotation for Pool 3
    uint8_t temp = (val ^ feedback);
    uint8_t shift = idx % 8;
    uint8_t x = (temp << shift) | (temp >> (8 - shift));
    x = ~x;
    return x;
}

static void prng_init(void) {
    // Fill pools with ADC entropy
    for (int i = 0; i < 256; i++) {
        pool1[i] = adc_read_raw() & 0xFF;
        pool2[i] = adc_read_raw() & 0xFF;
        pool3[i] = adc_read_raw() & 0xFF;
    }
}

static void _advance_pool3(void);
static void _advance_pool2(void);

static void _advance_pool3(void) {
    uint8_t current_idx = idx3;
    
    // Get entropy (Pool 1 [0] + ADC)
    uint8_t adc_noise = adc_read_raw() & 0xFF;
    uint8_t seed_entropy = (pool1[0] + adc_noise);
    
    // Refresh Pool 3 current position
    pool3[current_idx] = func3(pool3[current_idx], seed_entropy, current_idx);
    
    // Pool 3 pointer advance
    idx3++; // Implicit mod 256 for uint8_t
}

static void _advance_pool2(void) {
    uint8_t current_idx = idx2;
    
    // Get seed from Pool 3
    uint8_t seed_p3 = pool3[idx3];
    
    // Refresh Pool 2 current position
    pool2[current_idx] = func2(pool2[current_idx], seed_p3);
    
    // Pool 2 pointer advance
    idx2++;
    
    // If Pool 2 wraps, trigger Pool 3 advance
    if (idx2 == 0) {
        _advance_pool3();
    }
}

void prng_fill_reserve_pool(void);

void prng_fill_reserve_pool(void) {
    reserve_idx = 0;
    
    // Fill reserve pool 4 bytes at a time (total 4096 bytes = 1024 iterations of 4 bytes)
    // Actually we just fill byte by byte but handle pool1 update logic
    for (int i = 0; i < 1536; i++) {
        uint8_t val = pool1[idx1];
        uint8_t seed_p2 = pool2[idx2];
        
        // Update pool1
        pool1[idx1] = func1(val, seed_p2);
        
        // Store to reserve pool
        reserve_pool[i] = val;
        
        idx1++;
        if (idx1 == 0) {
            _advance_pool2();
        }
    }
}