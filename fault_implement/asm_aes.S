.syntax unified
    .cpu cortex-m0
    .fpu softvfp
    .thumb
    
    /* 宏：从源寄存器提取4个bit到目标寄存器 
     * 利用 LSRS 将 bit 移入 Carry，再利用 ADCS (Rd = Rd + Rd + Carry) 将其移入目标寄存器
     * 相当于: dst = (dst << 1) | bit
     * 
     * 参数： 
     *   src  - 源寄存器 (被破坏)
     *   dst0 - 目标寄存器0 (收集第1个bit)
     *   dst1 - 目标寄存器1 (收集第2个bit)
     *   dst2 - 目标寄存器2 (收集第3个bit)
     *   dst3 - 目标寄存器3 (收集第4个bit)
     */
    .macro EXTRACT_4BITS src, dst0, dst1, dst2, dst3 
        lsrs \src, \src, #1     // 移出 bit0 -> Carry 
        adcs \dst0, \dst0       // dst0 = (dst0 << 1) | Carry
        lsrs \src, \src, #1     // 移出 bit1 -> Carry 
        adcs \dst1, \dst1       // dst1 = (dst1 << 1) | Carry
        lsrs \src, \src, #1     // 移出 bit2 -> Carry 
        adcs \dst2, \dst2       // dst2 = (dst2 << 1) | Carry
        lsrs \src, \src, #1     // 移出 bit3 -> Carry 
        adcs \dst3, \dst3       // dst3 = (dst3 << 1) | Carry
    .endm

    /* 宏：连续处理4个寄存器的切片，结果累加到 R4-R7
     * 参数:
     *   src0, src1, src2, src3 - 源寄存器列表 (如 r0, r1, r2, r3)
     */
    .macro SLICE_4BITS_TO_R4R7 src0, src1, src2, src3
        EXTRACT_4BITS \src0, r4, r5, r6, r7
        EXTRACT_4BITS \src1, r4, r5, r6, r7
        EXTRACT_4BITS \src2, r4, r5, r6, r7
        EXTRACT_4BITS \src3, r4, r5, r6, r7
    .endm

    /* 宏：执行比特切片与打包 (Bit Slicing & Packing)
     * 包括掩码预处理 (Masking Preparation) 和 切片打包逻辑
     * 
     * 输入:
     *   R0 = in_out (Cipher Ptr)
     *   R1 = round_keys (Key Ptr)
     *   R2 = random_pool (Random Ptr)
     *
     * 输出:
     *   栈上 [SP, #0..#12] = U0-U3
     *   R4-R7             = U4-U7
     */
    .macro BS_PACKING
        /* -------------------------------------------------------------------------
         * Masking Preparation (掩码预处理)
         * ------------------------------------------------------------------------- */
        
        /* 保存 RoundKey 指针和 Input/Output 指针到栈上备用 */
        str     r1, [sp, #196]      /* Save RoundKey Ptr */
        str     r0, [sp, #200]      /* Save Cipher Ptr */

        /* 加载 16字节 随机数掩码 (Mask) 到 R4-R7 */
        ldmia   r2!, {r4, r5, r6, r7}
        mov     r12, r2             /* 保存自增后的 RandomPool 指针到 R12 */

        /* 
         * 加载密文 (Ciphertext) 到 R0-R3 
         * 技巧：先用 R4 (已存随机数) 暂存到 R8，腾出 R4 做指针
         */
        mov     r8, r4              /* 备份 R4 (Random[0]) 到 R8 */
        mov     r4, r0              /* R4 = Cipher Ptr */
        ldmia   r4!, {r0, r1, r2, r3} /* 加载密文到 R0-R3 */
        mov     r4, r8              /* 恢复 R4 (Random[0]) */

        /* 执行 Boolean Masking: State = Cipher ^ Mask */
        eors    r0, r4
        eors    r1, r5
        eors    r2, r6
        eors    r3, r7

        /* 备份 Mask 到 R8-R11 */
        mov     r8, r4
        mov     r9, r5
        mov     r10, r6
        mov     r11, r7
        
        /* -------------------------------------------------------------------------
         * Bit Slicing & Packing (比特切片与打包)
         * ------------------------------------------------------------------------- */

        /* 第一步：处理 CipherText (R0-R3) 的 bit 0-3 */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        STR_R4R7_0

        /* 第二步：处理 CipherText (R0-R3) 的 bit 4-7 */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        STR_R4R7_16
        LDR_R4R7_0

        /* 第三步：继续切片... (Cipher bit 8-11) */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        STR_R4R7_0
        LDR_R4R7_16

        /* 第四步：继续切片... (Cipher bit 12-15) */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        STR_R4R7_16
        LDR_R4R7_0

        /* 第五步：继续切片... (Cipher bit 16-19) */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        STR_R4R7_0
        LDR_R4R7_16

        /* 第六步：继续切片... (Cipher bit 20-23) */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3    
        STR_R4R7_16
        LDR_R4R7_0

        /* 第七步：继续切片... (Cipher bit 24-27) */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3 
        STR_R4R7_0
        LDR_R4R7_16

        /* 第八步：继续切片... (Cipher bit 28-31) */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3 
        STR_R4R7_16
        LDR_R4R7_0

        /* -------------------------------------------------------------------------
         * 处理 Mask (R8-R11)
         * ------------------------------------------------------------------------- */
        mov     r0, r8
        mov     r1, r9
        mov     r2, r10
        mov     r3, r11

        /* Mask bit 0-3 */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        STR_R4R7_0
        LDR_R4R7_16

        /* Mask bit 4-7 */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        STR_R4R7_16
        LDR_R4R7_0

        /* Mask bit 8-11 */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        STR_R4R7_0
        LDR_R4R7_16

        /* Mask bit 12-15 */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        STR_R4R7_16
        LDR_R4R7_0

        /* Mask bit 16-19 */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        STR_R4R7_0
        LDR_R4R7_16

        /* Mask bit 20-23 */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        STR_R4R7_16
        LDR_R4R7_0

        /* Mask bit 24-27 */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        STR_R4R7_0
        LDR_R4R7_16

        /* Mask bit 28-31 */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        STR_R4R7_16
    .endm

    /* 宏：Add Round Key (轮密钥加)
     * 
     *   RoundKey Ptr 存储在 [sp, #196]
     *   U0-U3 存储在 [sp, #0..#12]
     *   U4-U7 存储在 [sp, #16..#28]
     */
    .macro ARK
        /* 1. Load Round Key Address from Stack (Saved at SP+196) into R0 */
        ldr     r0, [sp, #196]
        
        /* 2. Load K0, K1, K2 from RoundKey Ptr */
        ldmia   r0!, {r1, r2, r3}
        
        /* 3. Backup U4-U7 to R8-R11 */
        mov     r8, r4
        mov     r9, r5
        mov     r10, r6
        mov     r11, r7
        
        /* 4. Load U0-U3 from SP+0..12 into R4-R7 */
        LDR_R4R7_0
        
        /* 5. XOR U0-U2 with K0-K2 (R4-R6 ^ R1-R3) */
        eors    r4, r1
        eors    r5, r2
        eors    r6, r3
        
        /* 6. Store updated U0'-U2' back to Stack */
        str     r4, [sp, #0]
        str     r5, [sp, #4]
        str     r6, [sp, #8]
        
        /* Note: R7 currently holds U3 */
        
        /* 7. Load K3, K4, K5 */
        ldmia   r0!, {r1, r2, r3}
        
        /* 8. Restore U4-U6 from R8-R10 to R4-R6 */
        mov     r4, r8
        mov     r5, r9
        mov     r6, r10
        
        /* 9. XOR U3, U4, U5 with K3, K4, K5 */
        /* U3 (R7) ^ K3 (R1) -> U3' (R7) */
        eors    r7, r1
        /* U4 (R4) ^ K4 (R2) -> U4' (R4) */
        eors    r4, r2
        /* U5 (R5) ^ K5 (R3) -> U5' (R5) */
        eors    r5, r3
        
        /* 10. Store U3', U4', U5' to Stack */
        str     r7, [sp, #12]
        str     r4, [sp, #16]
        str     r5, [sp, #20]
        
        /* 11. Load K6, K7 */
        ldmia   r0!, {r1, r2}
        
        /* 12. Restore U7 from R11 to R3 */
        /* Note: Using R3 as temp register for U7 */
        mov     r3, r11
        
        /* 13. XOR U6, U7 with K6, K7 */
        /* U6 is in R6 (from step 8, untouched in step 9) */
        eors    r6, r1
        eors    r3, r2
        
        /* 14. Store U6', U7' to Stack */
        str     r6, [sp, #24]
        str     r3, [sp, #28]
        
        /* Save updated Round Key Address back to Stack */
        str     r0, [sp, #196]
    .endm

    .macro ROW_PERM reg, shift_r, shift_l
        movs    r1, r0
        ands    r1, \reg
        lsrs    r2, r1, #\shift_r
        lsls    r1, r1, #\shift_l
        orrs    r1, r2
        ands    r1, r0
        bics    \reg, r0
        orrs    \reg, r1
    .endm

    // STR 版本1：偏移 0, 4, 8, 12 
    .macro STR_R4R7_0 
        str r4, [sp, #0] 
        str r5, [sp, #4] 
        str r6, [sp, #8] 
        str r7, [sp, #12] 
    .endm 

    // STR 版本2：偏移 16, 20, 24, 28 
    .macro STR_R4R7_16 
        str r4, [sp, #16] 
        str r5, [sp, #20] 
        str r6, [sp, #24] 
        str r7, [sp, #28] 
    .endm 

    // LDR 版本1：偏移 0, 4, 8, 12 
    .macro LDR_R4R7_0 
        ldr r4, [sp, #0] 
        ldr r5, [sp, #4] 
        ldr r6, [sp, #8] 
        ldr r7, [sp, #12] 
    .endm 

    // LDR 版本2：偏移 16, 20, 24, 28 
    .macro LDR_R4R7_16 
        ldr r4, [sp, #16] 
        ldr r5, [sp, #20] 
        ldr r6, [sp, #24] 
        ldr r7, [sp, #28] 
    .endm 

    /* 宏：PREPARE_CONSTANTS_TO_STACK
     * 功能: 将常用的大数常量加载到栈上，避免在代码中间使用 LDR =Const 导致的偏移越界
     * 栈位置:
     *   [SP, #204] = 0x000F000F
     *   [SP, #208] = 0x00F000F0
     *   [SP, #212] = 0x0F000F00
     *   [SP, #216] = 0x00FF00FF
     *   [SP, #220] = 0x0FFF0FFF
     */
    .macro PREPARE_CONSTANTS_TO_STACK
        movs    r4, #0x0F
        lsls    r5, r4, #16
        orrs    r4, r5          /*R4 = 0x000F000F*/
        str     r4, [sp, #204]

        movs    r4, #0xF0
        lsls    r5, r4, #16
        orrs    r4, r5          /*R4 = 0x00F000F0*/
        str     r4, [sp, #208]
        
        movs    r4, #0x0F
        lsls    r4, r4, #8
        lsls    r5, r4, #16
        orrs    r4, r5          /*R4 = 0x0F000F00*/
        str     r4, [sp, #212]

        movs    r4, #0xFF
        lsls    r5, r4, #16
        orrs    r4, r5          /*R4 = 0x00FF00FF*/
        str     r4, [sp, #216]

        movs    r4, #0xFF
        lsls    r5, r4, #4
        orrs    r4, r5
        lsls    r5, r4, #16
        orrs    r4, r5          /*R4 = 0x0FFF0FFF*/
        str     r4, [sp, #220]
    .endm 

    /* 宏：SECURE_XOR a, b, tmp 
     * 输入: a=[a1:a0], b=[b1:b0] (掩码格式) 
     * 输出: a=[c1:c0] 其中 c=a⊕b 
     */ 
    .macro SECURE_XOR a, b, tmp 
        uxth    \tmp, \b          // tmp = b0 
        eors    \a, \tmp          // a = [a1 : a0^b0] 
        lsrs    \tmp, \b, #16     // tmp = b1 
        lsls    \tmp, \tmp, #16   // tmp = [b1 : 0] 
        eors    \a, \tmp          // a = [a1^b1 : a0^b0] 
    .endm 

    /* 宏：SECURE_XNOR a, b, tmp 
     * 输入: a=[a1:a0], b=[b1:b0] 
     * 输出: a=[c1:c0] 其中 c=~(a⊕b) 
     * 关键: 只对低位份额取反，避免掩码抵消 
     */ 
    .macro SECURE_XNOR a, b, tmp 
        // 第一步：低位异或 
        uxth    \tmp, \b 
        eors    \a, \tmp 

        // 第二步：低位取反 
        movs    \tmp, #0xFF 
        lsls    \tmp, \tmp, #8 
        adds    \tmp, #0xFF       // tmp = 0x0000FFFF 
        eors    \a, \tmp 

        //第三步：高位异或 
        lsrs    \tmp, \b, #16 
        lsls    \tmp, \tmp, #16 
        eors    \a, \tmp 
    .endm 

    /* 宏：SECURE_AND out, a, b, r, tmp1, tmp2, tmp3 
     * 输入: out, a, b, r, tmp1, tmp2, tmp3 (寄存器索引) 
     * 隐含: R12 (随机数指针) 
     */ 
    .macro SECURE_AND out, a, b, r, tmp1, tmp2, tmp3 
        // === 0. 随机数加载 & 备份a === 
        mov     \tmp3, r12        // tmp3 = 随机数指针 
        ldmia   \tmp3!, {\r}      // r = [r|r], tmp3自增
        mov     r12, \tmp3        // 回写指针 
        lsls    \r, \r, #16
        lsrs    \tmp3, \r, #16
        orrs    \r, \tmp3         // 【关键】将32bit随机数r调整为r = [r|r] 16bit|16bit
        mov     \tmp3, \a         // 【关键】备份a到tmp3 

        // === 阶段1: c0 = (a0 & b0) ^ r === 
        uxth    \tmp1, \a         // tmp1 = a0 
        uxth    \tmp2, \b         // tmp2 = b0 
        ands    \tmp1, \tmp2      // tmp1 = a0 & b0 
        uxth    \tmp2, \r         // tmp2 = r的低16位 
        eors    \tmp1, \tmp2      // tmp1 = c0 

        // === 阶段2: c1_partial = (a1 & b1) ^ r === 
        lsrs    \a, \tmp3, #16    // a = a1 (从备份提取，可以破坏a) 
        lsrs    \tmp2, \b, #16    // tmp2 = b1 
        ands    \a, \tmp2         // a = a1 & b1 
        lsrs    \tmp2, \r, #16    // tmp2 = r的高16位 
        eors    \a, \tmp2         // a = (a1 & b1) ^ r 

        // === 阶段3: 交叉项1 - (a0 & b1) === 
        uxth    \tmp2, \tmp3      // tmp2 = a0 (从备份) 
        lsrs    \out, \b, #16     // out = b1 
        ands    \tmp2, \out       // tmp2 = a0 & b1 
        eors    \a, \tmp2         // a ^= (a0 & b1) 
       
        // === 阶段4: 交叉项2 - (a1 & b0) === 
        lsrs    \tmp2, \tmp3, #16 // tmp2 = a1 (从备份) 
        uxth    \out, \b          // out = b0 
        ands    \tmp2, \out       // tmp2 = a1 & b0 
        eors    \a, \tmp2         // a ^= (a1 & b0) 
        // 现在 a = c1 完整 

        // === 阶段5: 合并 [c1:c0] === 
        lsls    \a, \a, #16       // a = [c1 : 0] 
        mov     \out, \tmp1       // out = [0 : c0] 
        orrs    \out, \a          // out = [c1 : c0] 
    .endm 

    /* 宏：InvMixColumns_0FFF
     * 掩码: 0x0FFF0FFF
     * 参数: target, term, temp, lsl, lsr
     */
    .macro InvMixColumns_0FFF target, term, temp, lsl, lsr
        ldr     \temp, [sp, #220]
        ands    \temp, \term
        eors    \term, \temp
        lsls    \temp, \temp, #\lsl
        lsrs    \term, \term, #\lsr
        orrs    \term, \temp
        eors    \target, \term
    .endm

    /* 宏：InvMixColumns_00FF
     * 掩码: 0x00FF00FF
     * 参数: target, term, temp, lsl, lsr
     */
    .macro InvMixColumns_00FF target, term, temp, lsl, lsr
        ldr     \temp, [sp, #216]
        ands    \temp, \term
        eors    \term, \temp
        lsls    \temp, \temp, #\lsl
        lsrs    \term, \term, #\lsr
        orrs    \term, \temp
        eors    \target, \term
    .endm

    /* 宏：InvMixColumns_000F
     * 掩码: 0x000F000F
     * 参数: target, term, temp, lsl, lsr
     */
    .macro InvMixColumns_000F target, term, temp, lsl, lsr
        ldr     \temp, [sp, #204]
        ands    \temp, \term
        eors    \term, \temp
        lsls    \temp, \temp, #\lsl
        lsrs    \term, \term, #\lsr
        orrs    \term, \temp
        eors    \target, \term
    .endm 

    /* 宏：InvShiftRows
     */
    .macro InvShiftRows
        ldr     r0, [sp, #204]
        mov     r10, r0
        ldr     r0, [sp, #208]
        mov     r9, r0
        ldr     r0, [sp, #212]
        mov     r8, r0
        
        ROW_PERM r4, 1, 3
        ROW_PERM r5, 1, 3
        ROW_PERM r6, 1, 3
        ROW_PERM r7, 1, 3

        mov     r0, r9
        ROW_PERM r4, 2, 2
        ROW_PERM r5, 2, 2
        ROW_PERM r6, 2, 2
        ROW_PERM r7, 2, 2

        mov     r0, r10
        ROW_PERM r4, 3, 1
        ROW_PERM r5, 3, 1
        ROW_PERM r6, 3, 1
        ROW_PERM r7, 3, 1

        str     r4, [sp, #16]
        str     r5, [sp, #20]
        str     r6, [sp, #24]
        str     r7, [sp, #12]

        mov     r7, r3
        ldr     r4, [sp, #0]
        ldr     r5, [sp, #4]
        ldr     r6, [sp, #8]

        ROW_PERM r4, 3, 1
        ROW_PERM r5, 3, 1
        ROW_PERM r6, 3, 1
        ROW_PERM r7, 3, 1

        mov     r0, r9
        ROW_PERM r4, 2, 2
        ROW_PERM r5, 2, 2
        ROW_PERM r6, 2, 2
        ROW_PERM r7, 2, 2

        mov     r0, r8
        ROW_PERM r4, 1, 3
        ROW_PERM r5, 1, 3
        ROW_PERM r6, 1, 3
        ROW_PERM r7, 1, 3

        str     r4, [sp, #0]
        str     r5, [sp, #4]
        str     r6, [sp, #8]
        str     r7, [sp, #28]
    .endm 

    /* 宏名称: InvSubBytes
     * 依赖宏: SECURE_XOR, SECURE_XNOR, SECURE_AND
     */
    .macro InvSubBytes
    
        // === 第1步：加载U3-U6到R0-R3 ===
        LDR R0, [SP, #12]
        LDR R1, [SP, #16]
        LDR R2, [SP, #20]
        LDR R3, [SP, #24]

        // === 第2步：反序存储到栈 (BitReverse_Pre) ===
        STR R7, [SP, #0]
        STR R3, [SP, #4]
        STR R2, [SP, #8]
        STR R1, [SP, #12]
        STR R0, [SP, #16]
        STR R6, [SP, #20]
        STR R5, [SP, #24]
        STR R4, [SP, #28]

        // === 第3步：调整寄存器顺序 R4-R7 ===
        MOV R5, R4              // R5 = U0 (临时保存)
        MOV R4, R7              // R4 = U7
        MOV R7, R5              // R7 = U0
        MOV R5, R3              // R5 = U6
        MOV R6, R2              // R6 = U5

        // === 核心逻辑步骤 1-351 ===
        
        // 1→MOV R2 R4
        MOV R2, R4
        // 2→SECURE_XNOR R4 R5 R0
        SECURE_XNOR R4, R5, R0
        // 3→LDR R3 SP#12
        LDR R3, [SP, #12]
        // 4→MOV R9 R5
        MOV R9, R5
        // 5→SECURE_XNOR R5 R3 R0
        SECURE_XNOR R5, R3, R0
        // 6→MOV R8 R2
        MOV R8, R2
        // 7→SECURE_XOR R2 R3 R0
        SECURE_XOR R2, R3, R0
        // 8→LDR R1 SP#16
        LDR R1, [SP, #16]
        // 9→SECURE_XOR R3 R1 R0
        SECURE_XOR R3, R1, R0
        // 10→SECURE_XNOR R1 R7 R0
        SECURE_XNOR R1, R7, R0
        // 11→MOV R10 R1
        MOV R10, R1
        // 12→LDR R1 SP#24
        LDR R1, [SP, #24]
        // 13→SECURE_XOR R1 R7 R0
        SECURE_XOR R1, R7, R0
        // 14→SECURE_XNOR R7 R3 R0
        SECURE_XNOR R7, R3, R0
        // 15→MOV R11 R1
        MOV R11, R1
        // 16→LDR R1 SP#20
        LDR R1, [SP, #20]
        // 17→SECURE_XNOR R1 R6 R0
        SECURE_XNOR R1, R6, R0
        // 18→MOV R0 R8
        MOV R0, R8
        // 19→MOV R8 R6
        MOV R8, R6
        // 20→SECURE_XOR R0 R1 R6
        SECURE_XOR R0, R1, R6
        // 21→STR R7 SP#32
        STR R7, [SP, #32]
        // 22→STR R2 SP#36
        STR R2, [SP, #36]
        // 23→MOV R6 R9
        MOV R6, R9
        // 24→SECURE_XNOR R2 R6 R7
        SECURE_XNOR R2, R6, R7
        // 25→MOV R9 R5
        MOV R9, R5
        // 26→LDR R5 SP#24
        LDR R5, [SP, #24]
        // 27→SECURE_XOR R6 R5 R7
        SECURE_XOR R6, R5, R7
        // 28→STR R0 SP#40
        STR R0, [SP, #40]
        // 29→LDR R0 SP#20
        LDR R0, [SP, #20]
        // 30→SECURE_XNOR R0 R5 R7
        SECURE_XNOR R0, R5, R7
        // 31→MOV R5 R8
        MOV R5, R8
        // 32→MOV R8 R3
        MOV R8, R3
        // 33→SECURE_XNOR R3 R5 R7
        SECURE_XNOR R3, R5, R7
        // 34→STR R3 SP#44
        STR R3, [SP, #44]
        // 35→LDR R3 SP#16
        LDR R3, [SP, #16]
        // 36→STR R2 SP#48
        STR R2, [SP, #48]
        // 37→SECURE_XOR R2 R3 R7
        SECURE_XOR R2, R3, R7
        // 38→SECURE_XNOR R3 R5 R7
        SECURE_XNOR R3, R5, R7
        // 39→MOV R5 R9
        MOV R5, R9
        // 40→SECURE_XOR R1 R5 R7
        SECURE_XOR R1, R5, R7
        // 41→SECURE_XOR R3 R6 R7
        SECURE_XOR R3, R6, R7
        // 42→MOV R5 R10
        MOV R5, R10
        // 43→SECURE_XOR R6 R5 R7
        SECURE_XOR R6, R5, R7
        // 44→STR R6 SP#52
        STR R6, [SP, #52]
        // 45→MOV R6 R11
        MOV R6, R11
        // 46→SECURE_XOR R6 R4 R7
        SECURE_XOR R6, R4, R7
        // 47→STR R2 SP#56
        STR R2, [SP, #56]
        // 48→STR R5 SP#60
        STR R5, [SP, #60]
        // 49→SECURE_XOR R5 R4 R7
        SECURE_XOR R5, R4, R7
        // 50→STR R4 SP#64
        STR R4, [SP, #64]
        // 51→MOV R2 R9
        MOV R2, R9
        // 52→MOV R4 R11
        MOV R4, R11
        // 53→SECURE_XOR R2 R4 R7
        SECURE_XOR R2, R4, R7
        // 54→LDR R4 SP#8
        LDR R4, [SP, #8]
        // 55→SECURE_XNOR R4 R2 R7
        SECURE_XNOR R4, R2, R7
        // 56→MOV R7 R8
        MOV R7, R8
        // 57→MOV R8 R1
        MOV R8, R1
        // 58→MOV R1 R11
        MOV R1, R11
        // 59→MOV R11 R2
        MOV R11, R2
        // 60→SECURE_XOR R1 R7 R2
        SECURE_XOR R1, R7, R2
        // 61→STR R7 SP#68
        STR R7, [SP, #68]
        // 62→SECURE_XOR R7 R0 R2
        SECURE_XOR R7, R0, R2
        // 63→SECURE_XOR R0 R5 R2
        SECURE_XOR R0, R5, R2
        // 64→STR R5 SP#72
        STR R5, [SP, #72]
        // 65→SECURE_XOR R5 R7 R2
        SECURE_XOR R5, R7, R2
        // 66→MOV R10 R1
        MOV R10, R1
        // 67→SECURE_XOR R1 R3 R2
        SECURE_XOR R1, R3, R2
        // 68→MOV R2 R8
        MOV R2, R8
        // 69→MOV R8 R0
        MOV R8, R0
        // 70→STR R1 SP#76
        STR R1, [SP, #76]
        // 71→STR R4 SP#80
        STR R4, [SP, #80]
        // 72→STR R5 SP#84
        STR R5, [SP, #84]
        // 73→STR R6 SP#88
        STR R6, [SP, #88]
        // 74→STR R7 SP#92
        STR R7, [SP, #92]
        // 75→SECURE_AND R0 R6 R2 R1 R4,R5,R7
        SECURE_AND R0, R6, R2, R1, R4, R5, R7
        // 76→MOV R1 R8
        MOV R1, R8
        // 77→SECURE_XOR R1 R0
        SECURE_XOR R1, R0, R4
        // 78→MOV R8 R0
        MOV R8, R0
        // 79→STR R2 SP#96
        STR R2, [SP, #96]
        // 80→MOV R0 R10
        MOV R0, R10
        // 81→STR R0 SP#100
        STR R0, [SP, #100]
        // 82→SECURE_AND R2 R0 R3 R4 R5,R6,R7
        SECURE_AND R2, R0, R3, R4, R5, R6, R7
        // 83→STR R3 SP#104
        STR R3, [SP, #104]
        // 84→MOV R10 R1
        MOV R10, R1
        // 85→MOV R0 R11
        MOV R0, R11
        // 86→LDR R1 SP#40
        LDR R1, [SP, #40]
        // 87→SECURE_AND R3 R1 R0 R4 R5,R6,R7
        SECURE_AND R3, R1, R0, R4, R5, R6, R7
        // 88→STR R0 SP#108
        STR R0, [SP, #108]
        // 89→MOV R1 R8
        MOV R1, R8
        // 90→SECURE_XOR R1 R3 R4
        SECURE_XOR R1, R3, R4
        // 91→MOV R8 R1
        MOV R8, R1
        // 92→LDR R0 SP#36
        LDR R0, [SP, #36]
        // 93→LDR R1 SP#48
        LDR R1, [SP, #48]
        // 94→SECURE_AND R3 R0 R1 R4 R5,R6,R7
        SECURE_AND R3, R0, R1, R4, R5, R6, R7
        // 95→MOV R0 R10
        MOV R0, R10
        // 96→SECURE_XOR R0 R3 R4
        SECURE_XOR R0, R3, R4
        // 97→LDR R3 SP#76
        LDR R3, [SP, #76]
        // 98→SECURE_XOR R3 R2 R4
        SECURE_XOR R3, R2, R4
        // 99→MOV R1 R9
        MOV R1, R9
        // 100→MOV R11 R0
        MOV R11, R0
        // 101→MOV R10 R2
        MOV R10, R2
        // 102→LDR R0 SP#32
        LDR R0, [SP, #32]
        // 103→SECURE_AND R2 R0 R1 R4 R5,R6,R7
        SECURE_AND R2, R0, R1, R4, R5, R6, R7
        // 104→SECURE_XOR R2 R3 R4
        SECURE_XOR R2, R3, R4
        // 105→STR R1 SP#112
        STR R1, [SP, #112]
        // 106→MOV R0 R8
        MOV R0, R8
        // 107→LDR R1 SP#60
        LDR R1, [SP, #60]
        // 108→SECURE_XOR R0 R1 R3
        SECURE_XOR R0, R1, R3
        // 109→MOV R8 R2
        MOV R8, R2
        // 110→LDR R1 SP#68
        LDR R1, [SP, #68]
        // 111→LDR R2 SP#84
        LDR R2, [SP, #84]
        // 112→SECURE_AND R3 R1 R2 R4 R5,R6,R7
        SECURE_AND R3, R1, R2, R4, R5, R6, R7
        // 113→MOV R9 R0
        MOV R9, R0
        // 114→LDR R0 SP#64
        LDR R0, [SP, #64]
        // 115→LDR R1 SP#72
        LDR R1, [SP, #72]
        // 116→SECURE_AND R2 R0 R1 R4 R5,R6,R7
        SECURE_AND R2, R0, R1, R4, R5, R6, R7
        // 117→SECURE_XOR R2 R3 R0
        SECURE_XOR R2, R3, R0
        // 118→MOV R0 R9
        MOV R0, R9
        // 119→SECURE_XOR R0 R2 R1
        SECURE_XOR R0, R2, R1
        // 120→MOV R9 R0
        MOV R9, R0
        // 121→STR R2 SP#116
        STR R2, [SP, #116]
        // 122→LDR R0 SP#56
        LDR R0, [SP, #56]
        // 123→LDR R1 SP#92
        LDR R1, [SP, #92]
        // 124→SECURE_AND R2 R0 R1 R4 R5,R6,R7
        SECURE_AND R2, R0, R1, R4, R5, R6, R7
        // 125→SECURE_XOR R2 R3 R1
        SECURE_XOR R2, R3, R1
        // 126→MOV R0 R11
        MOV R0, R11
        // 127→SECURE_XOR R0 R2 R3
        SECURE_XOR R0, R2, R3
        // 128→MOV R1 R8
        MOV R1, R8
        // 129→SECURE_XOR R1 R2 R3
        SECURE_XOR R1, R2, R3
        // 130→MOV R2 R9
        MOV R2, R9
        // 131→SECURE_XOR R2 R0 R3
        SECURE_XOR R2, R0, R3
        // 132→MOV R8 R0
        MOV R8, R0
        // 133→MOV R11 R2
        MOV R11, R2
        // 134→LDR R0 SP#52
        LDR R0, [SP, #52]
        // 135→LDR R2 SP#80
        LDR R2, [SP, #80]
        // 136→SECURE_AND R3 R0 R2 R4 R5,R6,R7
        SECURE_AND R3, R0, R2, R4, R5, R6, R7
        // 137→MOV R0 R10
        MOV R0, R10
        // 138→SECURE_XOR R0 R3 R2
        SECURE_XOR R0, R3, R2
        // 139→LDR R2 SP#116
        LDR R2, [SP, #116]
        // 140→SECURE_XOR R0 R2 R3
        SECURE_XOR R0, R2, R3
        // 141→LDR R2 SP#44
        LDR R2, [SP, #44]
        // 142→SECURE_XOR R0 R2 R3
        SECURE_XOR R0, R2, R3
        // 143→MOV R10 R0
        MOV R10, R0
        // 144→MOV R0 R8
        MOV R0, R8
        // 145→SECURE_AND R2 R0 R1 R3 R4,R5,R6
        SECURE_AND R2, R0, R1, R3, R4, R5, R6
        // 146→MOV R0 R8
        MOV R0, R8
        // 147→MOV R8 R1
        MOV R8, R1
        // 148→MOV R1 R10
        MOV R1, R10
        // 149→SECURE_AND R3 R0 R1 R4 R5,R6,R7
        SECURE_AND R3, R0, R1, R4, R5, R6, R7
        // 150→MOV R1 R9
        MOV R1, R9
        // 151→SECURE_XOR R1 R2 R0
        SECURE_XOR R1, R2, R0
        // 152→MOV R0 R8
        MOV R0, R8
        // 153→MOV R4 R10
        MOV R4, R10
        // 154→SECURE_XOR R0 R4 R5
        SECURE_XOR R0, R4, R5
        // 155→STR R2 SP#120
        STR R2, [SP, #120]
        // 156→SECURE_AND R2 R1 R0 R4 R5,R6,R7
        SECURE_AND R2, R1, R0, R4, R5, R6, R7
        // 157→MOV R1 R8
        MOV R1, R8
        // 158→MOV R8 R0
        MOV R8, R0
        // 159→MOV R0 R9
        MOV R0, R9
        // 160→MOV R9 R2
        MOV R9, R2
        // 161→SECURE_AND R2 R1 R0 R4 R5,R6,R7
        SECURE_AND R2, R1, R0, R4, R5, R6, R7
        // 162→MOV R1 R10
        MOV R1, R10
        // 163→LDR R4 SP#120
        LDR R4, [SP, #120]
        // 164→SECURE_XOR R1 R4 R5
        SECURE_XOR R1, R4, R5
        // 165→MOV R5 R9
        MOV R5, R9
        // 166→MOV R6 R10
        MOV R6, R10
        // 167→SECURE_XOR R5 R6 R7
        SECURE_XOR R5, R6, R7
        // 168→STR R5 SP#124
        STR R5, [SP, #124]
        // 169→MOV R5 R11
        MOV R5, R11
        // 170→MOV R9 R2
        MOV R9, R2
        // 171→MOV R10 R3
        MOV R10, R3
        // 172→MOV R11 R4
        MOV R11, R4
        // 173→SECURE_AND R2 R1 R5 R3 R4,R6,R7
        SECURE_AND R2, R1, R5, R3, R4, R6, R7
        // 174→SECURE_XOR R0 R2 R1
        SECURE_XOR R0, R2, R1
        // 175→MOV R2 R10
        MOV R2, R10
        // 176→SECURE_AND R1 R2 R5 R3 R4,R6,R7
        SECURE_AND R1, R2, R5, R3, R4, R6, R7
        // 177→MOV R2 R11
        MOV R2, R11
        // 178→SECURE_XOR R5 R2 R3
        SECURE_XOR R5, R2, R3
        // 179→MOV R3 R8
        MOV R3, R8
        // 180→SECURE_XOR R2 R3 R4
        SECURE_XOR R2, R3, R4
        // 181→SECURE_XOR R1 R5 R4
        SECURE_XOR R1, R5, R4
        // 182→MOV R8 R0
        MOV R8, R0
        // 183→MOV R10 R1
        MOV R10, R1
        // 184→MOV R0 R9
        MOV R0, R9
        // 185→SECURE_AND R1 R0 R3 R4 R5,R6,R7
        SECURE_AND R1, R0, R3, R4, R5, R6, R7
        // 186→SECURE_XOR R1 R2 R3
        SECURE_XOR R1, R2, R3
        // 187→MOV R0 R8
        MOV R0, R8
        // 188→MOV R2 R10
        MOV R2, R10
        // 189→SECURE_XOR R2 R0 R3
        SECURE_XOR R2, R0, R3
        // 190→LDR R3 SP#124
        LDR R3, [SP, #124]
        // 191→STR R0 SP#156
        STR R0, [SP, #156]
        // 192→SECURE_XOR R0 R3 R4
        SECURE_XOR R0, R3, R4
        // 193→SECURE_XOR R3 R1 R4
        SECURE_XOR R3, R1, R4
        // 194→MOV R4 R10
        MOV R4, R10
        // 195→SECURE_XOR R4 R1 R5
        SECURE_XOR R4, R1, R5
        // 196→MOV R5 R4
        MOV R5, R4
        // 197→SECURE_XOR R4 R0 R6
        SECURE_XOR R4, R0, R6
        // 198→MOV R8 R1
        MOV R8, R1
        // 199→MOV R9 R2
        MOV R9, R2
        // 200→MOV R11 R3
        MOV R11, R3
        // 201→STR R5 SP#128
        STR R5, [SP, #128]
        // 202→LDR R1 SP#84
        LDR R1, [SP, #84]
        // 203→SECURE_AND R2 R1 R0 R3 R5,R6,R7
        SECURE_AND R2, R1, R0, R3, R5, R6, R7
        // 204→STR R2 SP#132
        STR R2, [SP, #132]
        // 205→LDR R1 SP#68
        LDR R1, [SP, #68]
        // 206→SECURE_AND R2 R1 R0 R3 R5,R6,R7
        SECURE_AND R2, R1, R0, R3, R5, R6, R7
        // 207→LDR R0 SP#92
        LDR R0, [SP, #92]
        // 208→SECURE_AND R1 R0 R4 R3 R5,R6,R7
        SECURE_AND R1, R0, R4, R3, R5, R6, R7
        // 209→STR R1 SP#136
        STR R1, [SP, #136]
        // 210→LDR R0 SP#56
        LDR R0, [SP, #56]
        // 211→SECURE_AND R1 R0 R4 R3 R5,R6,R7
        SECURE_AND R1, R0, R4, R3, R5, R6, R7
        // 212→MOV R4 R10
        MOV R4, R10
        // 213→MOV R10 R1
        MOV R10, R1
        // 214→LDR R0 SP#32
        LDR R0, [SP, #32]
        // 215→SECURE_AND R1 R0 R4 R3 R5,R6,R7
        SECURE_AND R1, R0, R4, R3, R5, R6, R7
        // 216→STR R1 SP#140
        STR R1, [SP, #140]
        // 217→LDR R0 SP#112
        LDR R0, [SP, #112]
        // 218→SECURE_AND R1 R0 R4 R3 R5,R6,R7
        SECURE_AND R1, R0, R4, R3, R5, R6, R7
        // 219→MOV R4 R11
        MOV R4, R11
        // 220→MOV R11 R1
        MOV R11, R1
        // 221→LDR R0 SP#96
        LDR R0, [SP, #96]
        // 222→SECURE_AND R1 R0 R4 R3 R5,R6,R7
        SECURE_AND R1, R0, R4, R3, R5, R6, R7
        // 223→STR R1 SP#144
        STR R1, [SP, #144]
        // 224→LDR R0 SP#88
        LDR R0, [SP, #88]
        // 225→SECURE_AND R1 R0 R4 R3 R5,R6,R7
        SECURE_AND R1, R0, R4, R3, R5, R6, R7
        // 226→MOV R4 R8
        MOV R4, R8
        // 227→MOV R8 R1
        MOV R8, R1
        // 228→LDR R0 SP#48
        LDR R0, [SP, #48]
        // 229→SECURE_AND R1 R0 R4 R3 R5,R6,R7
        SECURE_AND R1, R0, R4, R3, R5, R6, R7
        // 230→STR R1 SP#148
        STR R1, [SP, #148]
        // 231→LDR R0 SP#36
        LDR R0, [SP, #36]
        // 232→SECURE_AND R1 R0 R4 R3 R5,R6,R7
        SECURE_AND R1, R0, R4, R3, R5, R6, R7
        // 233→MOV R4 R9
        MOV R4, R9
        // 234→MOV R9 R1
        MOV R9, R1
        // 235→LDR R0 SP#104
        LDR R0, [SP, #104]
        // 236→SECURE_AND R1 R0 R4 R3 R5,R6,R7
        SECURE_AND R1, R0, R4, R3, R5, R6, R7
        // 237→STR R2 SP#152
        STR R2, [SP, #152]
        // 238→LDR R0 SP#100
        LDR R0, [SP, #100]
        // 239→SECURE_AND R2 R0 R4 R3 R5,R6,R7
        SECURE_AND R2, R0, R4, R3, R5, R6, R7
        // 240→STR R1 SP#160
        STR R1, [SP, #160]
        // 241→LDR R4 SP#124
        LDR R4, [SP, #124]
        // 242→LDR R0 SP#108
        LDR R0, [SP, #108]
        // 243→SECURE_AND R1 R0 R4 R3 R5,R6,R7
        SECURE_AND R1, R0, R4, R3, R5, R6, R7
        // 244→STR R1 SP#164
        STR R1, [SP, #164]
        // 245→LDR R0 SP#40
        LDR R0, [SP, #40]
        // 246→SECURE_AND R1 R0 R4 R3 R5,R6,R7
        SECURE_AND R1, R0, R4, R3, R5, R6, R7
        // 247→STR R1 SP#168
        STR R1, [SP, #168]
        // 248→LDR R4 SP#156
        LDR R4, [SP, #156]
        // 249→LDR R0 SP#52
        LDR R0, [SP, #52]
        // 250→SECURE_AND R1 R0 R4 R3 R5,R6,R7
        SECURE_AND R1, R0, R4, R3, R5, R6, R7
        // 251→STR R1 SP#172
        STR R1, [SP, #172]
        // 252→LDR R0 SP#80
        LDR R0, [SP, #80]
        // 253→SECURE_AND R1 R0 R4 R3 R5,R6,R7
        SECURE_AND R1, R0, R4, R3, R5, R6, R7
        // 254→STR R1 SP#176
        STR R1, [SP, #176]
        // 255→LDR R4 SP#128
        LDR R4, [SP, #128]
        // 256→LDR R0 SP#72
        LDR R0, [SP, #72]
        // 257→SECURE_AND R1 R0 R4 R3 R5,R6,R7
        SECURE_AND R1, R0, R4, R3, R5, R6, R7
        // 258→STR R1 SP#180
        STR R1, [SP, #180]
        // 259→LDR R0 SP#64
        LDR R0, [SP, #64]
        // 260→SECURE_AND R1 R0 R4 R3 R5,R6,R7
        SECURE_AND R1, R0, R4, R3, R5, R6, R7
        // 261→MOV R0 R8
        MOV R0, R8
        // 262→SECURE_XOR R0 R1 R4
        SECURE_XOR R0, R1, R4
        // 263→MOV R3 R9
        MOV R3, R9
        // 264→LDR R4 SP#168
        LDR R4, [SP, #168]
        // 265→SECURE_XOR R3 R4 R5
        SECURE_XOR R3, R4, R5
        // 266→LDR R5 SP#144
        LDR R5, [SP, #144]
        // 267→SECURE_XOR R4 R5 R6
        SECURE_XOR R4, R5, R6
        // 268→LDR R6 SP#176
        LDR R6, [SP, #176]
        // 269→SECURE_XOR R5 R6 R7
        SECURE_XOR R5, R6, R7
        // 270→MOV R8 R4
        MOV R8, R4
        // 271→MOV R9 R0
        MOV R9, R0
        // 272→MOV R0 R11
        MOV R0, R11
        // 273→SECURE_XOR R0 R2 R4
        SECURE_XOR R0, R2, R4
        // 274→SECURE_XOR R1 R5 R4
        SECURE_XOR R1, R5, R4
        // 275→MOV R4 R11
        MOV R4, R11
        // 276→MOV R11 R1
        MOV R11, R1
        // 277→LDR R1 SP#180
        LDR R1, [SP, #180]
        // 278→SECURE_XOR R4 R1 R7
        SECURE_XOR R4, R1, R7
        // 279→MOV R7 R10
        MOV R7, R10
        // 280→MOV R10 R4
        MOV R10, R4
        // 281→SECURE_XOR R1 R7 R4
        SECURE_XOR R1, R7, R4
        // 282→SECURE_XOR R2 R1 R4
        SECURE_XOR R2, R1, R4
        // 283→STR R2 SP#184
        STR R2, [SP, #184]
        // 284→LDR R2 SP#132
        LDR R2, [SP, #132]
        // 285→LDR R4 SP#152
        LDR R4, [SP, #152]
        // 286→SECURE_XOR R2 R4 R6
        SECURE_XOR R2, R4, R6
        // 287→SECURE_XOR R0 R2 R6
        SECURE_XOR R0, R2, R6
        // 288→STR R7 SP#188
        STR R7, [SP, #188]
        // 289→LDR R4 SP#148
        LDR R4, [SP, #148]
        // 290→LDR R6 SP#140
        LDR R6, [SP, #140]
        // 291→SECURE_XOR R4 R6 R7
        SECURE_XOR R4, R6, R7
        // 292→SECURE_XOR R2 R4 R7
        SECURE_XOR R2, R4, R7
        // 293→SECURE_XOR R4 R1 R7
        SECURE_XOR R4, R1, R7
        // 294→SECURE_XOR R1 R0 R7
        SECURE_XOR R1, R0, R7
        // 295→SECURE_XOR R5 R0 R7
        SECURE_XOR R5, R0, R7
        // 296→STR R5 SP#192
        STR R5, [SP, #192]
        // 297→LDR R5 SP#136
        LDR R5, [SP, #136]
        // 298→SECURE_XOR R5 R6 R7
        SECURE_XOR R5, R6, R7
        // 299→SECURE_XOR R0 R5 R6
        SECURE_XOR R0, R5, R6
        // 300→LDR R5 SP#164
        LDR R5, [SP, #164]
        // 301→LDR R6 SP#152
        LDR R6, [SP, #152]
        // 302→SECURE_XOR R6 R5 R7
        SECURE_XOR R6, R5, R7
        // 303→SECURE_XOR R5 R3 R7
        SECURE_XOR R5, R3, R7
        // 304→MOV R7 R11
        MOV R7, R11
        // 305→MOV R11 R0
        MOV R11, R0
        // 306→SECURE_XOR R7 R5 R0
        SECURE_XOR R7, R5, R0
        // 307→MOV R0 R9
        MOV R0, R9
        // 308→MOV R9 R1
        MOV R9, R1
        // 309→SECURE_XOR R6 R0 R1
        SECURE_XOR R6, R0, R1
        // 310→SECURE_XOR R0 R2 R1
        SECURE_XOR R0, R2, R1
        // 311→MOV R1 R8
        MOV R1, R8
        // 312→MOV R8 R6
        MOV R8, R6
        // 313→MOV R6 R9
        MOV R6, R9
        // 314→MOV R9 R0
        MOV R9, R0
        // 315→SECURE_XOR R1 R6 R0
        SECURE_XOR R1, R6, R0
        // 316→STR R1 SP#16
        STR R1, [SP, #16]
        // 317→MOV R0 R11
        MOV R0, R11
        // 318→SECURE_XOR R7 R0 R1
        SECURE_XOR R7, R0, R1
        // 319→STR R7 SP#12
        STR R7, [SP, #12]
        // 320→LDR R0 SP#160
        LDR R0, [SP, #160]
        // 321→LDR R1 SP#172
        LDR R1, [SP, #172]
        // 322→SECURE_XOR R1 R0 R7
        SECURE_XOR R1, R0, R7
        // 323→SECURE_XOR R3 R1 R7
        SECURE_XOR R3, R1, R7
        // 324→SECURE_XOR R1 R5 R7
        SECURE_XOR R1, R5, R7
        // 325→SECURE_XOR R1 R2 R5
        SECURE_XOR R1, R2, R5
        // 326→LDR R2 SP#176
        LDR R2, [SP, #176]
        // 327→SECURE_XOR R2 R0 R5
        SECURE_XOR R2, R0, R5
        // 328→SECURE_XOR R2 R6 R5
        SECURE_XOR R2, R6, R5
        // 329→LDR R5 SP#184
        LDR R5, [SP, #184]
        // 330→SECURE_XOR R1 R5 R6
        SECURE_XOR R1, R5, R6
        // 331→MOV R5 R10
        MOV R5, R10
        // 332→SECURE_XOR R3 R5 R6
        SECURE_XOR R3, R5, R6
        // 333→MOV R5 R9
        MOV R5, R9
        // 334→SECURE_XOR R3 R5 R6
        SECURE_XOR R3, R5, R6
        // 335→LDR R6 SP#192
        LDR R6, [SP, #192]
        // 336→SECURE_XOR R4 R6 R7
        SECURE_XOR R4, R6, R7
        // 337→LDR R6 SP#188
        LDR R6, [SP, #188]
        // 338→SECURE_XOR R0 R6 R7
        SECURE_XOR R0, R6, R7
        // 339→MOV R6 R11
        MOV R6, R11
        // 340→SECURE_XOR R0 R6 R5
        SECURE_XOR R0, R6, R5
        // 341→MOV R7 R2
        MOV R7, R2
        // 342→MOV R6 R3
        MOV R6, R3
        // 343→MOV R5 R1
        MOV R5, R1
        // 344→STR R4 SP#8;W5
        STR R4, [SP, #8]
        // 345→LDR R4 SP#16;W3
        LDR R4, [SP, #16]
        // 346→STR R2 SP#28;W0
        STR R2, [SP, #28]
        // 347→STR R3 SP#24;W1
        STR R3, [SP, #24]
        // 348→STR R1 SP#20
        STR R1, [SP, #20]
        // 349→STR R0 SP#4
        STR R0, [SP, #4]
        // 350→MOV R0 R8
        MOV R0, R8
        // 351→STR R0 SP#0;W7
        STR R0, [SP, #0]
    .endm

    /* 宏名称: InvMixColumns
     */
    .macro InvMixColumns
        ldr r1, [sp, #4]
        ldr r2, [sp, #8]

        mov     r0, r1
        eors    r0, r7
        eors    r0, r4
        eors    r0, r5
        eors    r0, r6
        eors    r0, r3
        mov     r8, r0

        mov     r0, r1
        eors    r0, r2
        eors    r0, r4
        eors    r0, r5
        eors    r0, r3
        mov     r9, r0

        mov     r0, r1
        eors    r0, r4
        eors    r0, r5
        eors    r0, r6
        mov     r10, r0

        mov     r0, r1
        eors    r0, r2
        eors    r0, r7
        eors    r0, r5

        mov     r7, r3

        mov     r1, r8
        InvMixColumns_0FFF r0, r1, r3, 4, 12
        mov     r1, r9
        InvMixColumns_00FF r0, r1, r3, 8, 8
        mov     r1, r10
        InvMixColumns_000F r0, r1, r3, 12, 4

        str     r0, [sp, #16]
        /* --- U4 Done--- */

        ldr r3, [sp, #12]

        mov     r0, r2
        eors    r0, r4
        eors    r0, r5
        eors    r0, r6
        eors    r0, r7
        mov     r8, r0

        mov     r0, r2
        eors    r0, r3
        eors    r0, r5
        eors    r0, r6
        mov     r9, r0

        mov     r0, r2
        eors    r0, r5
        eors    r0, r6
        eors    r0, r7
        mov     r10, r0

        mov     r0, r2
        eors    r0, r3
        eors    r0, r4
        eors    r0, r6

        mov     r1, r8
        InvMixColumns_0FFF r0, r1, r2, 4, 12
        mov     r1, r9
        InvMixColumns_00FF r0, r1, r2, 8, 8
        mov     r1, r10
        InvMixColumns_000F r0, r1, r2, 12, 4

        str     r0, [sp, #20]
        /* --- U5 Done--- */

        mov     r0, r3
        eors    r0, r5
        eors    r0, r6
        eors    r0, r7
        mov     r8, r0

        mov     r0, r3
        eors    r0, r4
        eors    r0, r6
        eors    r0, r7
        mov     r9, r0

        mov     r0, r3
        eors    r0, r6
        eors    r0, r7
        mov     r10, r0

        mov     r0, r3
        eors    r0, r4
        eors    r0, r5
        eors    r0, r7

        mov     r1, r8
        InvMixColumns_0FFF r0, r1, r2, 4, 12
        mov     r1, r9
        InvMixColumns_00FF r0, r1, r2, 8, 8
        mov     r1, r10
        InvMixColumns_000F r0, r1, r2, 12, 4

        str     r0, [sp, #24]
        /* --- U6 Done--- */

        mov     r0, r4
        eors    r0, r6
        eors    r0, r7
        mov     r8, r0

        mov     r0, r4
        eors    r0, r5
        eors    r0, r7
        mov     r9, r0

        mov     r0, r4
        eors    r0, r7
        mov     r10, r0

        mov     r0, r4
        eors    r0, r5
        eors    r0, r6

        mov     r1, r8
        InvMixColumns_0FFF r0, r1, r2, 4, 12
        mov     r1, r9
        InvMixColumns_00FF r0, r1, r2, 8, 8
        mov     r1, r10
        InvMixColumns_000F r0, r1, r2, 12, 4

        str     r0, [sp, #28]
        /* --- U7 Done--- */

        ldr r1, [sp, #0]
        ldr r2, [sp, #4]
        ldr r4, [sp, #8]

        mov     r0, r1
        eors    r0, r4
        eors    r0, r3
        eors    r0, r5
        mov     r8, r0

        mov     r0, r1
        eors    r0, r2
        eors    r0, r3
        eors    r0, r5
        eors    r0, r6
        eors    r0, r7
        mov     r9, r0

        mov     r0, r1
        eors    r0, r3
        eors    r0, r5
        eors    r0, r7
        mov     r10, r0

        mov     r0, r1
        eors    r0, r2
        eors    r0, r4
        eors    r0, r5
        eors    r0, r6

        mov     r1, r8
        InvMixColumns_0FFF r0, r1, r2, 4, 12
        mov     r1, r9
        InvMixColumns_00FF r0, r1, r2, 8, 8
        mov     r1, r10
        InvMixColumns_000F r0, r1, r2, 12, 4

        str     r0, [sp, #12]
        /* --- U3 Done--- */

        ldr r2, [sp, #0]
        ldr r3, [sp, #4]

        mov     r0, r3
        eors    r0, r4
        eors    r0, r6
        eors    r0, r7
        mov     r8, r0

        mov     r0, r2
        eors    r0, r4
        eors    r0, r6
        mov     r9, r0

        mov     r0, r4
        eors    r0, r6
        eors    r0, r7
        mov     r10, r0

        mov     r0, r2
        eors    r0, r3
        eors    r0, r6

        mov     r1, r8
        InvMixColumns_0FFF r0, r1, r2, 4, 12
        mov     r1, r9
        InvMixColumns_00FF r0, r1, r2, 8, 8
        mov     r1, r10
        InvMixColumns_000F r0, r1, r2, 12, 4

        str     r0, [sp, #8]
        /* --- U2 Done--- */

        ldr r4, [sp, #0]

        mov     r0, r4
        eors    r0, r3
        eors    r0, r5
        eors    r0, r6
        eors    r0, r7
        mov     r8, r0

        mov     r0, r3
        eors    r0, r5
        eors    r0, r7
        mov     r9, r0

        mov     r0, r3
        eors    r0, r5
        eors    r0, r6
        mov     r10, r0

        mov     r0, r4
        eors    r0, r5

        mov     r1, r8
        InvMixColumns_0FFF r0, r1, r2, 4, 12
        mov     r1, r9
        InvMixColumns_00FF r0, r1, r2, 8, 8
        mov     r1, r10
        InvMixColumns_000F r0, r1, r2, 12, 4

        str     r0, [sp, #4]
        /* --- U1 Done--- */

        mov     r0, r4
        eors    r0, r5
        eors    r0, r7
        mov     r8, r0

        mov     r0, r4
        eors    r0, r5
        eors    r0, r6
        mov     r9, r0

        mov     r0, r4
        eors    r0, r5
        mov     r10, r0

        mov     r0, r5
        eors    r0, r6
        eors    r0, r7

        mov     r1, r8
        InvMixColumns_0FFF r0, r1, r2, 4, 12
        mov     r1, r9
        InvMixColumns_00FF r0, r1, r2, 8, 8
        mov     r1, r10
        InvMixColumns_000F r0, r1, r2, 12, 4

        str     r0, [sp, #0]
        /* --- U0 Done--- */

        ldr     r3, [sp, #28]
        ldr     r4, [sp, #16]
        ldr     r5, [sp, #20]
        ldr     r6, [sp, #24]
        ldr     r7, [sp, #12]
    .endm

    /* 宏：BIT2BYTE_PART1
     * 功能: 将比特切片格式转换回字节格式的第一部分
     */
    .macro BIT2BYTE_PART1
        lsls r7, r7, #1
        adcs r0, r0
        lsls r6, r6, #1
        adcs r0, r0
        lsls r5, r5, #1
        adcs r0, r0
        lsls r4, r4, #1
        adcs r0, r0

        lsls r7, r7, #1
        adcs r1, r1
        lsls r6, r6, #1
        adcs r1, r1
        lsls r5, r5, #1
        adcs r1, r1
        lsls r4, r4, #1
        adcs r1, r1

        lsls r7, r7, #1
        adcs r2, r2
        lsls r6, r6, #1
        adcs r2, r2
        lsls r5, r5, #1
        adcs r2, r2
        lsls r4, r4, #1
        adcs r2, r2

        lsls r7, r7, #1
        adcs r3, r3
        lsls r6, r6, #1
        adcs r3, r3
        lsls r5, r5, #1
        adcs r3, r3
        lsls r4, r4, #1
        adcs r3, r3
    .endm

    /* 宏：BIT2BYTE_PART2
     * 功能: 将比特切片格式转换回字节格式的第二部分
     */
    .macro BIT2BYTE_PART2
        lsls r0, r0, #4
        lsls r1, r1, #4
        lsls r2, r2, #4
        lsls r3, r3, #4
    .endm

    /* 宏：REVERSE_BYTES
     * 功能: 反转 32 位寄存器的字节序 (Little Endian <-> Big Endian)
     */
    .macro REVERSE_BYTES reg
        mov  r4, \reg
        lsrs \reg, \reg, #24
        lsls r5, r4, #24
        lsrs r4, r4, #8
        lsls r6, r4, #24
        lsrs r4, r4, #8
        lsls r7, r4, #24
        lsrs r7, r7, #16
        lsrs r6, r6, #8
        orrs \reg, r5
        orrs \reg, r6
        orrs \reg, r7
    .endm

    .global asm_aes

/*
 * void asm_aes(uint8_t *in_out, uint32_t *round_keys, uint8_t *random_pool);
 *
 * 遵循 AAPCS 调用约定:
 * R0 = in_out      (密文输入/明文输出指针)
 * R1 = round_keys  (比特切片轮密钥指针)
 * R2 = random_pool (随机数池指针)
 */
asm_aes:
    /* -------------------------------------------------------------------------
     * Prologue (函数序言)
     * 1. 保存被调用者保存寄存器 (R4-R7) 和 链接寄存器 (LR)
     * ------------------------------------------------------------------------- */
    push    {r4-r7, lr}

    /* 
     * 2. 保存高组寄存器 (R8-R12)
     * Cortex-M0 不能直接 PUSH/POP 高组寄存器，需要先搬移到低组寄存器 (R3-R7)。
     * R3 是调用者保存寄存器，此时可随意使用。
     * R4-R7 刚刚已保存到栈中，现在也可以随意使用。
     */
    mov     r3, r8
    mov     r4, r9
    mov     r5, r10
    mov     r6, r11
    mov     r7, r12
    push    {r3-r7}

    /* 
     * 3. 分配栈空间 (Local Variables)
     * 分配 256 字节用于存放中间状态或 S-box 
     */
    sub     sp, #256

    PREPARE_CONSTANTS_TO_STACK

    BS_PACKING
    /* 切片后: [SP+0..12]=U0-U3; [SP+16..28]=U4-U7; R4-R7=U4-U7 */

    /* 轮密钥加 (Add Round Key 10) */
    ARK
    /* ARK后状态: R0-R2/R8-R11:废数据; R12:随机数池指针; [SP+0..28]:U0'-U7'(轮加后)
     * R3:U7'; R4:U4'; R5:U5'; R6:U6'; R7:U3' */

    /* --------------------------------round 9------------------------------------ */

    InvShiftRows
    /* 此时R0-R3 废数据，R4-R7 U0 U1 U2 U7；R8-R11，废数据，R12:随机数池指针; [SP+0..28]:U0'-U7'(处理后) */

    InvSubBytes
    /* R0-R7依次为：U0 U5 U7 U6 U4 U5 U6 U7 R8-R11废数据；R12随机数池指针；SP0-28依次为U0-U7 */

    /* 轮密钥加 (Add Round Key 9) */
    ARK
    /* ARK后状态: R0-R2/R8-R11:废数据; R12:随机数池指针; [SP+0..28]:U0'-U7'(轮加后)
     * R3:U7'; R4:U4'; R5:U5'; R6:U6'; R7:U3' */

    InvMixColumns

    /* --------------------------------round 8------------------------------------ */

    InvShiftRows
    /* 此时R0-R3 废数据，R4-R7 U0 U1 U2 U7；R8-R11，废数据，R12:随机数池指针; [SP+0..28]:U0'-U7'(处理后) */

    InvSubBytes
    /* R0-R7依次为：U0 U5 U7 U6 U4 U5 U6 U7 R8-R11废数据；R12随机数池指针；SP0-28依次为U0-U7 */

    /* 轮密钥加 (Add Round Key 8) */
    ARK
    /* ARK后状态: R0-R2/R8-R11:废数据; R12:随机数池指针; [SP+0..28]:U0'-U7'(轮加后)
     * R3:U7'; R4:U4'; R5:U5'; R6:U6'; R7:U3' */

    InvMixColumns

    /* --------------------------------round 7------------------------------------ */

    InvShiftRows
    /* 此时R0-R3 废数据，R4-R7 U0 U1 U2 U7；R8-R11，废数据，R12:随机数池指针; [SP+0..28]:U0'-U7'(处理后) */

    InvSubBytes
    /* R0-R7依次为：U0 U5 U7 U6 U4 U5 U6 U7 R8-R11废数据；R12随机数池指针；SP0-28依次为U0-U7 */

    /* 轮密钥加 (Add Round Key 7) */
    ARK
    /* ARK后状态: R0-R2/R8-R11:废数据; R12:随机数池指针; [SP+0..28]:U0'-U7'(轮加后)
     * R3:U7'; R4:U4'; R5:U5'; R6:U6'; R7:U3' */

    InvMixColumns

    /* --------------------------------round 6------------------------------------ */

    InvShiftRows
    /* 此时R0-R3 废数据，R4-R7 U0 U1 U2 U7；R8-R11，废数据，R12:随机数池指针; [SP+0..28]:U0'-U7'(处理后) */

    InvSubBytes
    /* R0-R7依次为：U0 U5 U7 U6 U4 U5 U6 U7 R8-R11废数据；R12随机数池指针；SP0-28依次为U0-U7 */

    /* 轮密钥加 (Add Round Key 6) */
    ARK
    /* ARK后状态: R0-R2/R8-R11:废数据; R12:随机数池指针; [SP+0..28]:U0'-U7'(轮加后)
     * R3:U7'; R4:U4'; R5:U5'; R6:U6'; R7:U3' */

    InvMixColumns

    /* --------------------------------round 5------------------------------------ */

    InvShiftRows
    /* 此时R0-R3 废数据，R4-R7 U0 U1 U2 U7；R8-R11，废数据，R12:随机数池指针; [SP+0..28]:U0'-U7'(处理后) */

    InvSubBytes
    /* R0-R7依次为：U0 U5 U7 U6 U4 U5 U6 U7 R8-R11废数据；R12随机数池指针；SP0-28依次为U0-U7 */

    /* 轮密钥加 (Add Round Key 5) */
    ARK
    /* ARK后状态: R0-R2/R8-R11:废数据; R12:随机数池指针; [SP+0..28]:U0'-U7'(轮加后)
     * R3:U7'; R4:U4'; R5:U5'; R6:U6'; R7:U3' */

    InvMixColumns

    /* --------------------------------round 4------------------------------------ */

    InvShiftRows
    /* 此时R0-R3 废数据，R4-R7 U0 U1 U2 U7；R8-R11，废数据，R12:随机数池指针; [SP+0..28]:U0'-U7'(处理后) */

    InvSubBytes
    /* R0-R7依次为：U0 U5 U7 U6 U4 U5 U6 U7 R8-R11废数据；R12随机数池指针；SP0-28依次为U0-U7 */

    /* 轮密钥加 (Add Round Key 4) */
    ARK
    /* ARK后状态: R0-R2/R8-R11:废数据; R12:随机数池指针; [SP+0..28]:U0'-U7'(轮加后)
     * R3:U7'; R4:U4'; R5:U5'; R6:U6'; R7:U3' */

    InvMixColumns

    /* --------------------------------round 3------------------------------------ */

    InvShiftRows
    /* 此时R0-R3 废数据，R4-R7 U0 U1 U2 U7；R8-R11，废数据，R12:随机数池指针; [SP+0..28]:U0'-U7'(处理后) */

    InvSubBytes
    /* R0-R7依次为：U0 U5 U7 U6 U4 U5 U6 U7 R8-R11废数据；R12随机数池指针；SP0-28依次为U0-U7 */

    /* 轮密钥加 (Add Round Key 3) */
    ARK
    /* ARK后状态: R0-R2/R8-R11:废数据; R12:随机数池指针; [SP+0..28]:U0'-U7'(轮加后)
     * R3:U7'; R4:U4'; R5:U5'; R6:U6'; R7:U3' */

    InvMixColumns

    /* --------------------------------round 2------------------------------------ */

    InvShiftRows
    /* 此时R0-R3 废数据，R4-R7 U0 U1 U2 U7；R8-R11，废数据，R12:随机数池指针; [SP+0..28]:U0'-U7'(处理后) */

    InvSubBytes
    /* R0-R7依次为：U0 U5 U7 U6 U4 U5 U6 U7 R8-R11废数据；R12随机数池指针；SP0-28依次为U0-U7 */

    /* 轮密钥加 (Add Round Key 2) */
    ARK
    /* ARK后状态: R0-R2/R8-R11:废数据; R12:随机数池指针; [SP+0..28]:U0'-U7'(轮加后)
     * R3:U7'; R4:U4'; R5:U5'; R6:U6'; R7:U3' */

    InvMixColumns

    /* --------------------------------round 1------------------------------------ */

    InvShiftRows
    /* 此时R0-R3 废数据，R4-R7 U0 U1 U2 U7；R8-R11，废数据，R12:随机数池指针; [SP+0..28]:U0'-U7'(处理后) */

    InvSubBytes
    /* R0-R7依次为：U0 U5 U7 U6 U4 U5 U6 U7 R8-R11废数据；R12随机数池指针；SP0-28依次为U0-U7 */

    /* 轮密钥加 (Add Round Key 1) */
    ARK
    /* ARK后状态: R0-R2/R8-R11:废数据; R12:随机数池指针; [SP+0..28]:U0'-U7'(轮加后)
     * R3:U7'; R4:U4'; R5:U5'; R6:U6'; R7:U3' */

    InvMixColumns

    /* --------------------------------round 0------------------------------------ */

    InvShiftRows
    /* 此时R0-R3 废数据，R4-R7 U0 U1 U2 U7；R8-R11，废数据，R12:随机数池指针; [SP+0..28]:U0'-U7'(处理后) */

    InvSubBytes
    /* R0-R7依次为：U0 U5 U7 U6 U4 U5 U6 U7 R8-R11废数据；R12随机数池指针；SP0-28依次为U0-U7 */

    /* 轮密钥加 (Add Round Key 0) */
    ARK
    /* ARK后状态: R0-R2/R8-R11:废数据; R12:随机数池指针; [SP+0..28]:U0'-U7'(轮加后)
     * R3:U7'; R4:U4'; R5:U5'; R6:U6'; R7:U3' */

    /* --------------------------------return to byte----------------------------- */

    mov r7, r3
    mov r0, r4
    lsls r0, r0, #16
    eors r4, r0

    mov r1, r5
    lsls r1, r1, #16
    eors r5, r1

    mov r2, r6
    lsls r2, r2, #16
    eors r6, r2

    mov r3, r7
    lsls r3, r3, #16
    eors r7, r3

    BIT2BYTE_PART1
    BIT2BYTE_PART2

    BIT2BYTE_PART1
    BIT2BYTE_PART2

    BIT2BYTE_PART1
    BIT2BYTE_PART2

    BIT2BYTE_PART1
    BIT2BYTE_PART2

    mov r8, r0
    mov r9, r1
    mov r10, r2
    mov r11, r3

    ldr r4, [sp, #0]
    ldr r5, [sp, #4]
    ldr r6, [sp, #8]
    ldr r7, [sp, #12]

    mov r0, r4
    lsls r0, r0, #16
    eors r4, r0

    mov r1, r5
    lsls r1, r1, #16
    eors r5, r1

    mov r2, r6
    lsls r2, r2, #16
    eors r6, r2

    mov r3, r7
    lsls r3, r3, #16
    eors r7, r3

    movs r0, #0
    movs r1, #0
    movs r2, #0
    movs r3, #0

    BIT2BYTE_PART1
    BIT2BYTE_PART2

    BIT2BYTE_PART1
    BIT2BYTE_PART2

    BIT2BYTE_PART1
    BIT2BYTE_PART2

    BIT2BYTE_PART1

    mov r4, r8
    orrs r0, r4
    mov r5, r9
    orrs r1, r5
    mov r6, r10
    orrs r2, r6
    mov r7, r11
    orrs r3, r7

    REVERSE_BYTES r0
    REVERSE_BYTES r1
    REVERSE_BYTES r2
    REVERSE_BYTES r3

    /* ------------------------upload results------------------------------------- */

    ldr r4, [sp, #200]
    stmia r4!, {r0-r3}

    /* -------------------------------------------------------------------------
     * 调试代码，记得删除
     * ------------------------------------------------------------------------- */

    /*LDR_R4R7_0*/
    /*LDR_R4R7_16*/
    /*ldr r0, [sp, #200]*/
    /*stmia r0!, {r4-r7}*/
    /*ldmia r1!, {r4-r7}*/

    /* -------------------------------------------------------------------------
     * 调试代码，记得删除;调试阶段让起始掩码为0了，记得改；让AND门加载的随机掩码也全都为0了，记得改
     * ------------------------------------------------------------------------- */

    /* -------------------------------------------------------------------------
     * Epilogue (函数结语)
     * 1. 释放栈空间
     * ------------------------------------------------------------------------- */
    add     sp, #256

    /* 2. 恢复高组寄存器 (R8-R12) */
    pop     {r3-r7}
    mov     r8, r3
    mov     r9, r4
    mov     r10, r5
    mov     r11, r6
    mov     r12, r7

    /* 2. 恢复低组寄存器并返回 */
    pop     {r4-r7, pc}