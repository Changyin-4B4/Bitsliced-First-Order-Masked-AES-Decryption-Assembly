.syntax unified
    .cpu cortex-m0
    .fpu softvfp
    .thumb
    
    /* Macro: Extract 4 bits from src to dst registers.(8cycles)
     * 宏：从源寄存器提取4个比特到目标寄存器。
     * Params/参数:
     *   src  - Source Reg (destroyed) / 源寄存器 (被破坏)
     *   dst0-3 - Dest Regs (collect bits) / 目标寄存器0-3 (收集比特)
     */
    .macro EXTRACT_4BITS src, dst0, dst1, dst2, dst3 
        lsrs \src, \src, #1     // mov bit0 -> Carry 
        adcs \dst0, \dst0       // dst0 = (dst0 << 1) | Carry
        lsrs \src, \src, #1     // mov bit1 -> Carry 
        adcs \dst1, \dst1       // dst1 = (dst1 << 1) | Carry
        lsrs \src, \src, #1     // mov bit2 -> Carry 
        adcs \dst2, \dst2       // dst2 = (dst2 << 1) | Carry
        lsrs \src, \src, #1     // mov bit3 -> Carry 
        adcs \dst3, \dst3       // dst3 = (dst3 << 1) | Carry
    .endm

    /* Macro: Slice 4 registers, accumulate in R4-R7.(32cycles)
     * 宏：切片4个寄存器，结果累加到 R4-R7。
     * Params/参数: src0-3 - Source Regs / 源寄存器列表 */
    .macro SLICE_4BITS_TO_R4R7 src0, src1, src2, src3
        EXTRACT_4BITS \src0, r4, r5, r6, r7
        EXTRACT_4BITS \src1, r4, r5, r6, r7
        EXTRACT_4BITS \src2, r4, r5, r6, r7
        EXTRACT_4BITS \src3, r4, r5, r6, r7
    .endm

    /* Macro: Bit Slicing & Packing.(786cycles)
     * 宏：比特切片与打包。
     * Includes masking preparation and slicing logic.
     * 包括掩码预处理和切片逻辑。 */
    .macro BS_PACKING

        /* 保存 RoundKey 指针和 Input/Output 指针到栈上备用 空置栈220、224、228、232、236，460-476*/
        str     r1, [sp, #460]      /* Save RoundKey Ptr */
        str     r0, [sp, #464]      /* Save Cipher Ptr */

        /* Load 16-byte Random Mask to R4-R7 / 加载 16字节 随机数掩码到 R4-R7 */
        ldmia   r2!, {r4, r5, r6, r7}
        mov     r12, r2             /* Save incremented RandomPool ptr to R12 / 保存自增后的 RandomPool 指针到 R12 */

        mov     r8, r4
        mov     r4, r0
        ldmia   r4!, {r0, r1, r2, r3}
        mov     r4, r8

        eors    r0, r4
        eors    r1, r5
        eors    r2, r6
        eors    r3, r7

        mov     r8, r4
        mov     r9, r5
        mov     r10, r6
        mov     r11, r7

        eors r4,r4
        eors r5,r5
        eors r6,r6
        eors r7,r7
        
        /* Bit Slicing & Packing (比特切片与打包) */

        //r0-3 maskbyte 3 2 1 0;7 6 5 4;11 10 9 8;15 14 13 12;

        /* Step 1: BYTE0,4,8,12; BIT0-3 to R4-R7 / 第一步：BYTE0,4,8,12; BIT0-3 到 R4-R7 */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        str r4, [sp, #0]
        str r5, [sp, #4]
        str r6, [sp, #8]
        str r7, [sp, #12]

        eors r4,r4
        eors r5,r5
        eors r6,r6
        eors r7,r7

        /* BYTE0,4,8,12;BIT4-7 to R4-R7 */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        str r4, [sp, #16]
        str r5, [sp, #20]
        str r6, [sp, #24]
        str r7, [sp, #28] 
        ldr r4, [sp, #0]
        ldr r5, [sp, #4]
        ldr r6, [sp, #8]
        ldr r7, [sp, #12]

        /* BYTE1,5,9,13 */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        str r4, [sp, #0]
        str r5, [sp, #4]
        str r6, [sp, #8]
        str r7, [sp, #12]
        ldr r4, [sp, #16]
        ldr r5, [sp, #20]
        ldr r6, [sp, #24]
        ldr r7, [sp, #28]

        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        str r4, [sp, #16]
        str r5, [sp, #20]
        str r6, [sp, #24]
        str r7, [sp, #28]
        ldr r4, [sp, #0]
        ldr r5, [sp, #4]
        ldr r6, [sp, #8]
        ldr r7, [sp, #12]

        /* BYTE2,6,10,14 */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        str r4, [sp, #0]
        str r5, [sp, #4]
        str r6, [sp, #8]
        str r7, [sp, #12]
        ldr r4, [sp, #16]
        ldr r5, [sp, #20]
        ldr r6, [sp, #24]
        ldr r7, [sp, #28]

        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3    
        str r4, [sp, #16]
        str r5, [sp, #20]
        str r6, [sp, #24]
        str r7, [sp, #28]
        ldr r4, [sp, #0]
        ldr r5, [sp, #4]
        ldr r6, [sp, #8]
        ldr r7, [sp, #12]

        /* BYTE3,7,11,15 */
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3 
        str r4, [sp, #0]
        str r5, [sp, #4]
        str r6, [sp, #8]
        str r7, [sp, #12]
        ldr r4, [sp, #16]
        ldr r5, [sp, #20]
        ldr r6, [sp, #24]
        ldr r7, [sp, #28]

        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3 
        str r4, [sp, #16]
        str r5, [sp, #20]
        str r6, [sp, #24]
        str r7, [sp, #28]

        /* 处理 Mask (R8-R11) */
        mov     r0, r8
        mov     r1, r9
        mov     r2, r10
        mov     r3, r11

        eors r4,r4
        eors r5,r5
        eors r6,r6
        eors r7,r7

        /* Mask0,4,8,12;BIT0-3 to R4-R7*/
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        str r4, [sp, #240]
        str r5, [sp, #244]
        str r6, [sp, #248]
        str r7, [sp, #252]

        eors r4,r4
        eors r5,r5
        eors r6,r6
        eors r7,r7

        /* Mask0,4,8,12;BIT4-7 to R4-R7*/
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        str r4, [sp, #256]
        str r5, [sp, #260]
        str r6, [sp, #264]
        str r7, [sp, #268]
        ldr r4, [sp, #240]
        ldr r5, [sp, #244]
        ldr r6, [sp, #248]
        ldr r7, [sp, #252]

        /* Mask1,5,9,13*/
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        str r4, [sp, #240]
        str r5, [sp, #244]
        str r6, [sp, #248]
        str r7, [sp, #252]
        ldr r4, [sp, #256]
        ldr r5, [sp, #260]
        ldr r6, [sp, #264]
        ldr r7, [sp, #268]

        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        str r4, [sp, #256]
        str r5, [sp, #260]
        str r6, [sp, #264]
        str r7, [sp, #268]
        ldr r4, [sp, #240]
        ldr r5, [sp, #244]
        ldr r6, [sp, #248]
        ldr r7, [sp, #252]

        /* Mask2,6,10,14*/
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        str r4, [sp, #240]
        str r5, [sp, #244]
        str r6, [sp, #248]
        str r7, [sp, #252]
        ldr r4, [sp, #256]
        ldr r5, [sp, #260]
        ldr r6, [sp, #264]
        ldr r7, [sp, #268]

        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        str r4, [sp, #256]
        str r5, [sp, #260]
        str r6, [sp, #264]
        str r7, [sp, #268]
        ldr r4, [sp, #240]
        ldr r5, [sp, #244]
        ldr r6, [sp, #248]
        ldr r7, [sp, #252]

        /* Mask3,7,11,15*/
        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        str r4, [sp, #240]
        str r5, [sp, #244]
        str r6, [sp, #248]
        str r7, [sp, #252]
        ldr r4, [sp, #256]
        ldr r5, [sp, #260]
        ldr r6, [sp, #264]
        ldr r7, [sp, #268]

        SLICE_4BITS_TO_R4R7 r0, r1, r2, r3
        str r4, [sp, #256]
        str r5, [sp, #260]
        str r6, [sp, #264]
        str r7, [sp, #268]

        mov r8,r0
        mov r9,r0
        mov r10,r0
        mov r11,r0
    .endm

    /* Macro: Add Round Key.(71cycles)
     * 宏：轮密钥加。
     * Input: RoundKey Ptr at [sp, #460].
     * 输入：轮密钥指针位于 [sp, #460]。
     */
    .macro ARK
        /* Load Round Key Address from Stack into R0 */
        ldr     r0, [sp, #460]
        
        ldmia   r0!, {r1, r2, r3}
        
        mov     r8, r4
        mov     r9, r5
        mov     r10, r6
        mov     r11, r7
        
        // r8-r11=share0 bit4-7
        ldr r4, [sp, #240]
        ldr r5, [sp, #244]
        ldr r6, [sp, #248]
        ldr r7, [sp, #252]
        
        eors    r4, r1
        eors    r5, r2
        eors    r6, r3

        lsls r4,r4,#16
        lsls r5,r5,#16
        lsls r6,r6,#16

        lsrs r4,r4,#16
        lsrs r5,r5,#16
        lsrs r6,r6,#16
        
        str     r4, [sp, #240]
        str     r5, [sp, #244]
        str     r6, [sp, #248]

        mov r4,r8
        mov r5,r9
        mov r6,r10

        //for 4,5,6,7=share0.bit4,5,6,3
        
        /*Load K3, K4, K5 */
        ldmia   r0!, {r1, r2, r3}
        
        /* U3 (R7) ^ K3 (R1) -> U3' (R7) */
        eors    r7, r1
        /* U4 (R4) ^ K4 (R2) -> U4' (R4) */
        eors    r4, r2
        /* U5 (R5) ^ K5 (R3) -> U5' (R5) */
        eors    r5, r3

        lsls r4,r4,#16
        lsls r5,r5,#16
        lsls r7,r7,#16
        
        lsrs r4,r4,#16
        lsrs r5,r5,#16
        lsrs r7,r7,#16 
        
        str     r7, [sp, #252]
        str     r4, [sp, #256]
        str     r5, [sp, #260]
        
        /*Load K6, K7 */
        ldmia   r0!, {r1, r2}
        
        mov     r3, r11
        //r3,4,5,6,7=share0.bit 7 4 5 6 3
        
        eors    r6, r1
        eors    r3, r2

        lsls r3,r3,#16
        lsls r6,r6,#16

        lsrs r3,r3,#16
        lsrs r6,r6,#16
        
        str     r6, [sp, #264]
        str     r3, [sp, #268]
        
        /* Save updated Round Key Address back to Stack */
        str     r0, [sp, #460]
    .endm
    
    .macro ROW_PERM reg, shift_r, shift_l//(8cycles)
        movs    r1, r0
        ands    r1, \reg
        lsrs    r2, r1, #\shift_r
        lsls    r1, r1, #\shift_l
        orrs    r1, r2
        ands    r1, r0
        bics    \reg, r0
        orrs    \reg, r1
    .endm

    /* Macro: Load constants to stack.(33cycles)
     * 宏：加载常量到栈。
     * Avoids LDR offset limits.
     * 避免 LDR 偏移越界。
     */
    .macro PREPARE_CONSTANTS_TO_STACK
        movs    r4, #0x0F
        lsls    r5, r4, #16
        orrs    r4, r5          /*R4 = 0x000F000F*/
        str     r4, [sp, #220]

        movs    r4, #0xF0
        lsls    r5, r4, #16
        orrs    r4, r5          /*R4 = 0x00F000F0*/
        str     r4, [sp, #224]
        
        movs    r4, #0x0F
        lsls    r4, r4, #8
        lsls    r5, r4, #16
        orrs    r4, r5          /*R4 = 0x0F000F00*/
        str     r4, [sp, #228]

        movs    r4, #0xFF
        lsls    r5, r4, #16
        orrs    r4, r5          /*R4 = 0x00FF00FF*/
        str     r4, [sp, #232]

        movs    r4, #0xFF
        lsls    r5, r4, #4
        orrs    r4, r5
        lsls    r5, r4, #16
        orrs    r4, r5          /*R4 = 0x0FFF0FFF*/
        str     r4, [sp, #236]

        movs    r4, #0xFF
        lsls    r5, r4, #8
        orrs    r4, r5          /*R4 = 0xFFFF*/
        str     r4, [sp, #468]
    .endm 

    /* Macro: InvMixColumns helper (Mask 0x0FFF0FFF).(8cycles)
     * 宏：列混淆辅助宏 (掩码 0x0FFF0FFF)。
     */
    .macro InvMixColumns_0FFF target, term, temp, lsl, lsr
        ldr     \temp, [sp, #236]
        ands    \temp, \term
        eors    \term, \temp
        lsls    \temp, \temp, #\lsl
        lsrs    \term, \term, #\lsr
        orrs    \term, \temp
        eors    \target, \term
    .endm

    /* Macro: InvMixColumns helper (Mask 0x00FF00FF).(8cycles)
     * 宏：列混淆辅助宏 (掩码 0x00FF00FF)。
     */
    .macro InvMixColumns_00FF target, term, temp, lsl, lsr
        ldr     \temp, [sp, #232]
        ands    \temp, \term
        eors    \term, \temp
        lsls    \temp, \temp, #\lsl
        lsrs    \term, \term, #\lsr
        orrs    \term, \temp
        eors    \target, \term
    .endm

    /* Macro: InvMixColumns helper (Mask 0x000F000F).(8cycles)
     * 宏：列混淆辅助宏 (掩码 0x000F000F)。
     */
    .macro InvMixColumns_000F target, term, temp, lsl, lsr
        ldr     \temp, [sp, #220]
        ands    \temp, \term
        eors    \term, \temp
        lsls    \temp, \temp, #\lsl
        lsrs    \term, \term, #\lsr
        orrs    \term, \temp
        eors    \target, \term
    .endm 

    /* Macro: Inverse ShiftRows.(296cycles)
     * 宏：逆行移位。 */
    .macro InvShiftRows
        ldr     r0, [sp, #220] // Pre-stored large constants 0x000F000F; 0x00F000F0; 0x0F000F00 / 预存大常数
        mov     r10, r0
        ldr     r0, [sp, #224]
        mov     r9, r0
        ldr     r0, [sp, #228]
        mov     r8, r0

        lsls r7,r7,#16
        orrs r7,r3
        ldr r3, [sp,#240]
        lsls r4,r4,#16
        orrs r4,r3
        ldr r3, [sp,#244]
        lsls r5,r5,#16
        orrs r5,r3
        ldr r3, [sp,#248]
        lsls r6,r6,#16
        orrs r6,r3
        //r3,4,5,6,7=share0.bit 2 4|0 5|1 6|2 3|7
        
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

        uxth r3,r4
        str r3,[sp,#240]
        lsrs r4,r4,#16
        str r4,[sp,#256]
        uxth r3,r5
        str r3,[sp,#244]
        lsrs r5,r5,#16
        str r5,[sp,#260]
        uxth r3,r6
        str r3,[sp,#248]
        lsrs r6,r6,#16
        str r6,[sp,#264]
        uxth r3,r7
        str r3,[sp,#268]
        lsrs r7,r7,#16
        str r7,[sp,#252]

        eors r3,r3
        eors r4,r4
        eors r5,r5
        eors r6,r6
        eors r7,r7

        ldr     r4, [sp, #0]
        ldr     r5, [sp, #4]
        ldr     r6, [sp, #8]
        ldr     r7, [sp, #12]

        ldr r3,[sp,#16]
        lsls r4,r4,#16
        orrs r4,r3
        ldr r3, [sp,#20]
        lsls r5,r5,#16
        orrs r5,r3
        ldr r3, [sp,#24]
        lsls r6,r6,#16
        orrs r6,r3
        ldr r3, [sp,#28]
        lsls r7,r7,#16
        orrs r7,r3

        //r3,4,5,6,7=share1.bit 7 0|4 1|5 2|6 3|7

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

        uxth r3,r4
        str r3,[sp,#16]
        lsrs r4,r4,#16
        str r4,[sp,#0]
        uxth r3,r5
        str r3,[sp,#20]
        lsrs r5,r5,#16
        str r5,[sp,#4]
        uxth r3,r6
        str r3,[sp,#24]
        lsrs r6,r6,#16
        str r6,[sp,#8]
        uxth r3,r7
        str r3,[sp,#28]
        lsrs r7,r7,#16
        str r7,[sp,#12]
    .endm

    /* Macro: ISW AND (Gadget).(14cycles)
     * 宏：ISW 与运算 (组件)。
     * Logic/逻辑: c0 = (a0&b0)^r; c1 = (a1&b1)^r ^ (a0&b1)^(a1&b0)
     * Cost/耗时: 14 Cycles
     */
    .macro S_ISW_AND a0crack, a1crack, b0out1, b1, out0, tmp
        // --- 1. Load Random Number / 加载随机数 (5 cycles) ---
        mov     \out0, r12
        ldmia   \out0!, {\tmp}      // tmp = Random
        mov     r12, \out0          // write back / 回写指针
        uxth    \tmp, \tmp          // tmp = [0 | r]

        // --- 2. Calculate C0 / 计算 C0 (3 cycles) ---
        mov     \out0, \a0crack     // out0 = a0
        ands    \out0, \b0out1      // out0 = a0 & b0
        eors    \out0, \tmp         // out0 = c0 (Result Ready!)

        // --- 3. Cross Term A / 交叉项 A (2 cycles) ---
        ands    \a0crack, \b1
        eors    \a0crack, \tmp         // a0crack = a0b1^r

        // --- 4. Cross Term B / 交叉项 B (1 cycle) ---
        ands    \b0out1, \a1crack        // b0out1=b0a1

        // --- 5. Calculate C1 / 计算 C1 (3 cycles) ---
        ands    \a1crack, \b1        // a1crack=a1b1
        eors    \b0out1, \a0crack
        eors    \b0out1, \a1crack       // b0out1 = c1
    .endm

    /* Macro: Secure XNOR (+1).(4cycles)
     * 宏：安全同或 (取反)。 */ 
    .macro S_XNOR a, b, tmp 
        eors    \a, \b
        ldr     \tmp, [sp, #468]
        eors    \a, \tmp
    .endm

    /* Macro: Secure XNOR (no+1).(2cycles)
     * 宏：安全同或 (无取反)。 */ 
    .macro S_XNOR_no a, b, tmp 
        eors    \a, \b
        eors    \tmp, \tmp
    .endm

    /* Macro: Inverse SubBytes (S-box).(1438cycles)
     * 宏：逆字节代换 (S盒)。 */
    .macro InvSubBytes
        mov     r2, r6
        S_XNOR  r2, r5, r1
        mov     r1, r5
        eors    r1, r4
        ldr    r0, [sp, #24]
        eors    r5, r0
        mov     r8, r2
        mov     r9, r5
        ldr    r2, [sp, #20]
        S_XNOR  r6, r2, r5
        mov     r10, r6
        mov     r5, r4
        S_XNOR  r4, r7, r6
        ldr    r6, [sp, #16]
        mov     r11, r4
        mov     r4, r6
        eors    r4, r7
        S_XNOR  r5, r4, r0
        ldr    r0, [sp, #24]
        str    r5, [sp, #32]
        mov     r5, r6
        eors    r5, r3
        str    r5, [sp, #36]
        S_XNOR  r6, r0, r5
        str    r6, [sp, #40]
        eors    r6, r1
        str    r6, [sp, #44]
        mov     r5, r3
        S_XNOR  r3, r0, r6
        mov     r6, r10
        eors    r5, r6
        str    r5, [sp, #48]
        ldr    r5, [sp, #36]
        S_XNOR  r0, r5, r6
        mov     r5, r7
        S_XNOR  r5, r2, r6
        eors    r7, r0
        str    r0, [sp, #52]
        mov     r0, r2
        S_XNOR  r0, r4, r6
        str    r0, [sp, #56]
        ldr    r0, [sp, #44]
        S_XNOR  r2, r0, r6
        mov     r6, r1
        eors    r1, r3
        eors    r6, r4
        mov     r0, r9
        eors    r5, r0
        str    r5, [sp, #60]
        eors    r5, r6
        str    r6, [sp, #64]
        mov     r6, r11
        eors    r0, r6
        str    r6, [sp, #68]
        eors    r6, r3
        str    r4, [sp, #72]
        str    r5, [sp, #76]
        mov     r5, r8
        eors    r4, r5
        eors    r5, r6
        str    r6, [sp, #80]
        eors    r6, r4
        str    r6, [sp, #84]
        mov     r6, r10
        str    r0, [sp, #88]
        ldr    r0, [sp, #40]
        eors    r0, r6
        str    r0, [sp, #92]
        str    r1, [sp, #96]
        str    r2, [sp, #100]
        str    r3, [sp, #104]
        str    r4, [sp, #108]
        str    r5, [sp, #112]
        str    r7, [sp, #116]
        eors    r0, r0
        mov     r1, r0
        mov     r2, r0
        mov     r3, r0
        mov     r4, r0
        mov     r5, r0
        mov     r6, r0
        mov     r7, r0
        mov     r8, r0
        mov     r9, r0
        mov     r10, r0
        mov     r11, r0
        ldr    r3, [sp, #268]
        ldr    r4, [sp, #240]
        ldr    r5, [sp, #244]
        ldr    r6, [sp, #248]
        ldr    r7, [sp, #252]
        mov     r2, r6
        S_XNOR_no  r2, r5, r1
        mov     r1, r5
        eors    r1, r4
        ldr    r0, [sp, #264]
        eors    r5, r0
        mov     r8, r2
        mov     r9, r5
        ldr    r2, [sp, #260]
        S_XNOR_no  r6, r2, r5
        mov     r10, r6
        mov     r5, r4
        S_XNOR_no  r4, r7, r6
        ldr    r6, [sp, #256]
        mov     r11, r4
        mov     r4, r6
        eors    r4, r7
        S_XNOR_no  r5, r4, r0
        ldr    r0, [sp, #264]
        str    r5, [sp, #272]
        mov     r5, r6
        eors    r5, r3
        str    r5, [sp, #276]
        S_XNOR_no  r6, r0, r5
        str    r6, [sp, #280]
        eors    r6, r1
        str    r6, [sp, #284]
        mov     r5, r3
        S_XNOR_no  r3, r0, r6
        mov     r6, r10
        eors    r5, r6
        str    r5, [sp, #288]
        ldr    r5, [sp, #276]
        S_XNOR_no  r0, r5, r6
        mov     r5, r7
        S_XNOR_no  r5, r2, r6
        eors    r7, r0
        str    r0, [sp, #292]
        mov     r0, r2
        S_XNOR_no  r0, r4, r6
        str    r0, [sp, #296]
        ldr    r0, [sp, #284]
        S_XNOR_no  r2, r0, r6
        mov     r6, r1
        eors    r1, r3
        eors    r6, r4
        mov     r0, r9
        eors    r5, r0
        str    r5, [sp, #300]
        eors    r5, r6
        str    r6, [sp, #304]
        mov     r6, r11
        eors    r0, r6
        str    r6, [sp, #308]
        eors    r6, r3
        str    r4, [sp, #312]
        str    r5, [sp, #316]
        mov     r5, r8
        eors    r4, r5
        eors    r5, r6
        str    r6, [sp, #320]
        eors    r6, r4
        str    r6, [sp, #324]
        mov     r6, r10
        str    r0, [sp, #328]
        ldr    r0, [sp, #280]
        eors    r0, r6
        str    r0, [sp, #332]
        str    r1, [sp, #336]
        str    r2, [sp, #340]
        str    r3, [sp, #344]
        str    r4, [sp, #348]
        str    r5, [sp, #352]
        str    r7, [sp, #356]
        eors    r2, r2
        mov     r3, r2
        mov     r5, r2
        mov     r6, r2
        mov     r8, r2
        mov     r9, r2
        mov     r10, r2
        mov     r11, r2
        ldr    r2, [sp, #92]
        ldr    r3, [sp, #96]
        S_ISW_AND r0, r2, r1, r3, r5, r6
        ldr    r2, [sp, #116]
        ldr    r3, [sp, #108]
        S_ISW_AND r4, r3, r7, r2, r0, r6
        mov     r8, r1
        mov     r9, r5
        eors    r1, r1
        ldr    r5, [sp, #312]
        ldr    r2, [sp, #84]
        ldr    r3, [sp, #72]
        ldr    r1, [sp, #324]
        S_ISW_AND r1, r2, r5, r3, r4, r6
        eors    r0, r4
        eors    r7, r5
        mov     r10, r0
        mov     r11, r7
        eors    r7, r7
        ldr    r0, [sp, #344]
        ldr    r2, [sp, #80]
        ldr    r3, [sp, #104]
        ldr    r6, [sp, #320]
        S_ISW_AND r0, r3, r6, r2, r1, r7
        eors    r1, r4
        eors    r5, r6
        eors    r6, r6
        ldr    r0, [sp, #284]
        ldr    r2, [sp, #48]
        ldr    r3, [sp, #44]
        ldr    r4, [sp, #288]
        S_ISW_AND r0, r3, r4, r2, r6, r7
        mov     r0, r9
        mov     r7, r8
        eors    r4, r7
        eors    r6, r0
        ldr    r0, [sp, #308]
        ldr    r7, [sp, #236]
        ldr    r7, [sp, #68]
        eors    r0, r6
        eors    r4, r7
        eors    r0, r1
        eors    r4, r5
        ldr    r3, [sp, #352]
        mov     r2, r8
        mov     r6, r9
        ldr    r7, [sp, #228]
        ldr    r7, [sp, #112]
        eors    r2, r7
        eors    r3, r6
        str    r0, [sp, #360]
        ldr    r0, [sp, #276]
        str    r4, [sp, #120]
        ldr    r4, [sp, #36]
        mov     r8, r5
        mov     r9, r1
        ldr    r1, [sp, #292]
        ldr    r5, [sp, #232]
        ldr    r5, [sp, #52]
        S_ISW_AND r0, r4, r1, r5, r6, r7
        eors    r1, r2
        eors    r3, r6
        mov     r0, r10
        mov     r4, r11
        eors    r0, r3
        eors    r1, r4
        str    r0, [sp, #368]
        ldr    r0, [sp, #328]
        str    r1, [sp, #128]
        ldr    r2, [sp, #100]
        ldr    r1, [sp, #88]
        ldr    r3, [sp, #340]
        S_ISW_AND r0, r1, r3, r2, r4, r5
        ldr    r2, [sp, #64]
        ldr    r0, [sp, #60]
        ldr    r6, [sp, #304]
        ldr    r1, [sp, #300]
        S_ISW_AND r1, r0, r6, r2, r5, r7
        eors    r3, r6
        eors    r4, r5
        ldr    r0, [sp, #316]
        ldr    r1, [sp, #224]
        ldr    r1, [sp, #76]
        eors    r0, r5
        eors    r1, r6
        mov     r2, r8
        mov     r5, r9
        eors    r2, r3
        eors    r4, r5
        ldr    r3, [sp, #56]
        ldr    r6, [sp, #40]
        ldr    r5, [sp, #296]
        eors    r2, r3
        eors    r4, r5
        str    r2, [sp, #124]
        ldr    r2, [sp, #32]
        str    r4, [sp, #364]
        ldr    r4, [sp, #272]
        ldr    r5, [sp, #280]
        S_ISW_AND r4, r2, r5, r6, r7, r3
        eors    r0, r7
        eors    r1, r5
        mov     r2, r10
        mov     r3, r11
        eors    r0, r2
        eors    r1, r3
        ldr    r2, [sp, #364]
        ldr    r7, [sp, #368]
        ldr    r3, [sp, #124]
        mov     r9, r0
        eors    r2, r0
        eors    r3, r1
        ldr    r6, [sp, #128]
        S_ISW_AND r7, r6, r0, r1, r4, r5
        str    r2, [sp, #372]
        ldr    r5, [sp, #360]
        str    r3, [sp, #132]
        eors    r2, r4
        eors    r3, r0
        mov     r10, r2
        mov     r11, r3
        mov     r2, r9
        ldr    r3, [sp, #120]
        S_ISW_AND r2, r1, r5, r3, r6, r7
        ldr    r1, [sp, #372]
        ldr    r2, [sp, #220]
        ldr    r2, [sp, #132]
        S_ISW_AND r6, r5, r1, r2, r7, r3
        mov     r3, r10
        mov     r5, r11
        eors    r1, r5
        eors    r3, r7
        str    r1, [sp, #136]
        ldr    r1, [sp, #120]
        str    r3, [sp, #376]
        ldr    r3, [sp, #360]
        eors    r1, r0
        eors    r3, r4
        ldr    r7, [sp, #372]
        S_ISW_AND r3, r1, r7, r2, r6, r5
        ldr    r1, [sp, #364]
        ldr    r2, [sp, #128]
        ldr    r3, [sp, #124]
        eors    r6, r1
        eors    r7, r3
        mov     r8, r0
        mov     r9, r4
        eors    r0, r3
        eors    r4, r1
        str    r6, [sp, #380]
        ldr    r6, [sp, #368]
        str    r7, [sp, #140]
        S_ISW_AND r1, r3, r6, r2, r5, r7
        ldr    r1, [sp, #120]
        ldr    r3, [sp, #368]
        ldr    r7, [sp, #360]
        eors    r2, r1
        eors    r3, r7
        mov     r10, r3
        S_ISW_AND r4, r0, r3, r2, r7, r1
        mov     r0, r10
        S_ISW_AND r5, r6, r0, r2, r1, r4
        mov     r4, r8
        mov     r5, r9
        mov     r6, r10
        eors    r2, r4
        eors    r5, r6
        ldr    r4, [sp, #220]
        ldr    r4, [sp, #120]
        ldr    r6, [sp, #220]
        ldr    r6, [sp, #360]
        eors    r3, r4
        eors    r6, r7
        eors    r0, r2
        eors    r1, r5
        str    r0, [sp, #144]
        str    r3, [sp, #148]
        str    r1, [sp, #384]
        str    r6, [sp, #388]
        mov     r2, r0
        mov     r4, r1
        eors    r0, r3
        eors    r1, r6
        ldr    r5, [sp, #380]
        str    r0, [sp, #152]
        ldr    r7, [sp, #140]
        eors    r3, r7
        eors    r6, r5
        ldr    r0, [sp, #136]
        str    r1, [sp, #392]
        ldr    r1, [sp, #376]
        eors    r2, r0
        eors    r4, r1
        eors    r0, r7
        eors    r1, r5
        str    r3, [sp, #156]
        str    r2, [sp, #160]
        str    r6, [sp, #396]
        eors    r3, r2
        eors    r6, r4
        str    r0, [sp, #164]
        str    r4, [sp, #400]
        ldr    r0, [sp, #348]
        str    r1, [sp, #404]
        ldr    r1, [sp, #108]
        mov     r8, r6
        S_ISW_AND r0, r1, r6, r3, r4, r2
        mov     r0, r8
        ldr    r1, [sp, #356]
        ldr    r2, [sp, #220]
        ldr    r2, [sp, #116]
        S_ISW_AND r0, r3, r1, r2, r5, r7
        mov     r8, r1
        mov     r9, r5
        ldr    r0, [sp, #384]
        ldr    r1, [sp, #272]
        ldr    r2, [sp, #144]
        ldr    r3, [sp, #32]
        S_ISW_AND r0, r2, r1, r3, r5, r7
        eors    r4, r5
        eors    r6, r1
        str    r4, [sp, #408]
        ldr    r0, [sp, #376]
        ldr    r2, [sp, #292]
        str    r6, [sp, #168]
        ldr    r3, [sp, #136]
        ldr    r4, [sp, #52]
        S_ISW_AND r0, r3, r2, r4, r7, r6
        eors    r1, r2
        eors    r5, r7
        str    r1, [sp, #172]
        ldr    r0, [sp, #152]
        ldr    r1, [sp, #60]
        str    r5, [sp, #412]
        ldr    r2, [sp, #392]
        ldr    r3, [sp, #300]
        S_ISW_AND r2, r0, r3, r1, r5, r4
        mov     r0, r9
        mov     r1, r8
        eors    r0, r5
        eors    r1, r3
        str    r0, [sp, #416]
        ldr    r0, [sp, #388]
        ldr    r2, [sp, #328]
        str    r1, [sp, #176]
        ldr    r1, [sp, #148]
        ldr    r4, [sp, #88]
        S_ISW_AND r2, r4, r0, r1, r6, r7
        eors    r0, r3
        eors    r6, r5
        str    r0, [sp, #180]
        ldr    r0, [sp, #100]
        str    r6, [sp, #420]
        ldr    r2, [sp, #388]
        ldr    r4, [sp, #340]
        S_ISW_AND r2, r1, r4, r0, r6, r7
        eors    r3, r4
        eors    r5, r6
        str    r3, [sp, #184]
        ldr    r0, [sp, #164]
        ldr    r1, [sp, #92]
        str    r5, [sp, #424]
        ldr    r2, [sp, #404]
        ldr    r3, [sp, #332]
        S_ISW_AND r2, r0, r3, r1, r5, r7
        eors    r4, r3
        eors    r6, r5
        mov     r10, r6
        mov     r11, r4
        ldr    r0, [sp, #380]
        ldr    r1, [sp, #288]
        ldr    r2, [sp, #140]
        ldr    r4, [sp, #48]
        S_ISW_AND r0, r2, r1, r4, r6, r7
        eors    r3, r1
        eors    r5, r6
        str    r3, [sp, #188]
        ldr    r0, [sp, #136]
        ldr    r2, [sp, #36]
        str    r5, [sp, #428]
        ldr    r3, [sp, #376]
        ldr    r4, [sp, #276]
        S_ISW_AND r3, r0, r4, r2, r5, r7
        eors    r1, r4
        eors    r5, r6
        ldr    r0, [sp, #400]
        ldr    r2, [sp, #320]
        ldr    r3, [sp, #160]
        ldr    r4, [sp, #80]
        S_ISW_AND r0, r3, r2, r4, r6, r7
        mov     r0, r8
        mov     r3, r9
        eors    r0, r2
        eors    r3, r6
        mov     r8, r0
        mov     r9, r3
        str    r1, [sp, #192]
        ldr    r0, [sp, #144]
        ldr    r1, [sp, #40]
        str    r5, [sp, #432]
        ldr    r3, [sp, #384]
        ldr    r4, [sp, #280]
        S_ISW_AND r3, r0, r4, r1, r5, r7
        eors    r2, r4
        eors    r6, r5
        str    r2, [sp, #196]
        ldr    r0, [sp, #152]
        ldr    r1, [sp, #64]
        str    r6, [sp, #436]
        ldr    r2, [sp, #392]
        ldr    r3, [sp, #304]
        S_ISW_AND r2, r0, r3, r1, r6, r7
        eors    r4, r3
        eors    r5, r6
        mov     r0, r8
        mov     r2, r9
        eors    r3, r0
        eors    r6, r2
        str    r0, [sp, #200]
        str    r3, [sp, #204]
        ldr    r0, [sp, #156]
        ldr    r1, [sp, #84]
        str    r2, [sp, #440]
        str    r6, [sp, #444]
        ldr    r2, [sp, #396]
        ldr    r3, [sp, #324]
        S_ISW_AND r3, r1, r2, r0, r6, r7
        mov     r8, r4
        mov     r9, r5
        ldr    r1, [sp, #72]
        ldr    r3, [sp, #396]
        ldr    r4, [sp, #312]
        S_ISW_AND r3, r0, r4, r1, r5, r7
        eors    r2, r4
        eors    r6, r5
        mov     r0, r8
        mov     r1, r9
        eors    r0, r2
        eors    r1, r6
        mov     r8, r4
        mov     r9, r5
        ldr    r3, [sp, #172]
        ldr    r4, [sp, #200]
        ldr    r5, [sp, #412]
        ldr    r7, [sp, #440]
        eors    r2, r3
        eors    r6, r5
        eors    r3, r4
        eors    r5, r7
        eors    r4, r0
        eors    r7, r1
        str    r2, [sp, #208]
        str    r3, [sp, #212]
        str    r6, [sp, #448]
        str    r5, [sp, #452]
        ldr    r2, [sp, #184]
        ldr    r3, [sp, #188]
        ldr    r5, [sp, #424]
        ldr    r6, [sp, #428]
        eors    r2, r4
        eors    r5, r7
        eors    r3, r4
        eors    r6, r7
        str    r2, [sp, #28]
        str    r3, [sp, #16]
        str    r5, [sp, #268]
        str    r6, [sp, #256]
        mov     r2, r10
        mov     r3, r11
        eors    r2, r1
        eors    r3, r0
        ldr    r4, [sp, #212]
        ldr    r5, [sp, #168]
        ldr    r6, [sp, #452]
        ldr    r7, [sp, #408]
        eors    r2, r6
        eors    r3, r4
        eors    r0, r5
        eors    r1, r7
        ldr    r4, [sp, #176]
        str    r3, [sp, #8]
        ldr    r5, [sp, #416]
        str    r2, [sp, #248]
        eors    r4, r0
        eors    r5, r1
        str    r4, [sp, #4]
        ldr    r2, [sp, #160]
        ldr    r3, [sp, #104]
        str    r5, [sp, #244]
        ldr    r4, [sp, #400]
        ldr    r5, [sp, #344]
        S_ISW_AND r4, r2, r5, r3, r6, r7
        mov     r2, r10
        mov     r4, r11
        eors    r2, r6
        eors    r4, r5
        mov     r10, r2
        mov     r11, r4
        str    r5, [sp, #216]
        ldr    r2, [sp, #140]
        ldr    r3, [sp, #44]
        str    r6, [sp, #456]
        ldr    r4, [sp, #380]
        ldr    r5, [sp, #284]
        S_ISW_AND r4, r2, r5, r3, r6, r7
        ldr    r2, [sp, #192]
        mov     r4, r5
        eors    r4, r2
        mov     r7, r11
        eors    r7, r4
        eors    r0, r7
        str    r0, [sp, #12]
        ldr    r0, [sp, #432]
        mov     r7, r6
        eors    r6, r0
        mov     r3, r10
        eors    r3, r6
        eors    r1, r3
        ldr    r3, [sp, #420]
        str    r1, [sp, #252]
        ldr    r1, [sp, #180]
        eors    r0, r3
        eors    r2, r1
        eors    r1, r4
        eors    r3, r6
        mov     r4, r8
        mov     r6, r9
        eors    r4, r5
        eors    r6, r7
        mov     r8, r4
        mov     r9, r6
        ldr    r4, [sp, #196]
        ldr    r5, [sp, #164]
        ldr    r6, [sp, #436]
        eors    r0, r6
        eors    r2, r4
        mov     r10, r0
        mov     r11, r2
        ldr    r0, [sp, #96]
        ldr    r2, [sp, #404]
        ldr    r4, [sp, #336]
        S_ISW_AND r2, r5, r4, r0, r6, r7
        ldr    r0, [sp, #216]
        ldr    r2, [sp, #208]
        ldr    r5, [sp, #456]
        ldr    r7, [sp, #448]
        eors    r0, r4
        eors    r5, r6
        mov     r4, r0
        eors    r0, r2
        mov     r6, r11
        eors    r0, r6
        str    r0, [sp, #24]
        mov     r0, r5
        eors    r0, r7
        mov     r6, r7
        mov     r7, r10
        eors    r0, r7
        eors    r1, r2
        eors    r3, r6
        ldr    r2, [sp, #204]
        str    r0, [sp, #264]
        ldr    r6, [sp, #444]
        eors    r1, r2
        eors    r3, r6
        mov     r6, r8
        mov     r7, r9
        eors    r4, r6
        eors    r5, r7
        str    r1, [sp, #20]
        str    r4, [sp, #0]
        str    r3, [sp, #260]
        str    r5, [sp, #240]
        mov     r5, r3
        eors    r0, r0
        mov     r1, r0
        mov     r2, r0
        mov     r3, r0
        mov     r4, r0
        mov     r7, r0
        mov     r8, r0
        mov     r9, r0
        mov     r10, r0
        mov     r11, r0
        ldr    r4, [sp, #256]
        ldr    r6, [sp, #264]
        ldr    r7, [sp, #268]
    .endm

    /* Macro: Inverse MixColumns.(830cycles)
     * 宏：逆列混淆。 */
    .macro InvMixColumns
        ldr r1, [sp, #244]
        ldr r2, [sp, #248]

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

        str     r0, [sp, #256]
        /* --- U4 Done--- */

        ldr r3, [sp, #252]

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

        str     r0, [sp, #260]
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

        str     r0, [sp, #264]
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

        str     r0, [sp, #268]
        /* --- U7 Done--- */

        ldr r1, [sp, #240]
        ldr r2, [sp, #244]
        ldr r4, [sp, #248]

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

        str     r0, [sp, #252]
        /* --- U3 Done--- */

        ldr r2, [sp, #240]
        ldr r3, [sp, #244]

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

        str     r0, [sp, #248]
        /* --- U2 Done--- */

        ldr r4, [sp, #240]

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

        str     r0, [sp, #244]
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

        str     r0, [sp, #240]
        /* --- U0 Done--- */

        eors r0,r0
        mov r1,r0
        mov r2,r0
        mov r3,r0
        mov r4,r0
        mov r5,r0
        mov r6,r0
        mov r7,r0
        mov r8,r0
        mov r9,r0
        mov r10,r0
        mov r11,r0

        ldr r1,[sp, #4]
        ldr r2,[sp, #8]
        ldr r3,[sp, #28]
        ldr r4,[sp, #16]
        ldr r5,[sp, #20]
        ldr r6,[sp, #24]
        ldr r7,[sp, #12]

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

        eors r0,r0
        mov r1,r0
        mov r2,r0
        mov r3,r0
        mov r4,r0
        mov r5,r0
        mov r6,r0
        mov r7,r0
        mov r8,r0
        mov r9,r0
        mov r10,r0
        mov r11,r0

        ldr     r3, [sp, #268]
        ldr     r4, [sp, #256]
        ldr     r5, [sp, #260]
        ldr     r6, [sp, #264]
        ldr     r7, [sp, #252]
    .endm

    /* Macro: Convert bitslice to byte (Part 1).(32cycles)
     * 宏：比特切片转字节 (第一部分)。 */
    .macro BIT2BYTE_PART1
        lsrs r7, r7, #1
        adcs r3, r3
        lsrs r6, r6, #1
        adcs r3, r3
        lsrs r5, r5, #1
        adcs r3, r3
        lsrs r4, r4, #1
        adcs r3, r3

        lsrs r7, r7, #1
        adcs r2, r2
        lsrs r6, r6, #1
        adcs r2, r2
        lsrs r5, r5, #1
        adcs r2, r2
        lsrs r4, r4, #1
        adcs r2, r2

        lsrs r7, r7, #1
        adcs r1, r1
        lsrs r6, r6, #1
        adcs r1, r1
        lsrs r5, r5, #1
        adcs r1, r1
        lsrs r4, r4, #1
        adcs r1, r1
        
        lsrs r7, r7, #1
        adcs r0, r0
        lsrs r6, r6, #1
        adcs r0, r0
        lsrs r5, r5, #1
        adcs r0, r0
        lsrs r4, r4, #1
        adcs r0, r0
    .endm

    /* Macro: Convert bitslice to byte (Part 2).(4cycles)
     * 宏：比特切片转字节 (第二部分)。 */
    .macro BIT2BYTE_PART2
        lsls r0, r0, #4
        lsls r1, r1, #4
        lsls r2, r2, #4
        lsls r3, r3, #4
    .endm

    .global asm_aes

/*
 * void asm_aes(uint8_t *in_out, uint32_t *round_keys, uint8_t *random_pool);(26801cycles)
 *
 * 遵循 AAPCS 调用约定:
 * R0 = in_out      (密文输入/明文输出指针)
 * R1 = round_keys  (比特切片轮密钥指针)
 * R2 = random_pool (随机数池指针)
 */
asm_aes:
    /* -------------------------------------------------------------------------
     * Prologue (函数序言)
     * 1. Save Callee-Saved Registers (R4-R7) and Link Register (LR) / 保存被调用者保存寄存器 (R4-R7) 和 链接寄存器 (LR)
     * ------------------------------------------------------------------------- */
    push    {r4-r7, lr}

    /* 
     * 2. Save High Registers (R8-R12) / 保存高组寄存器 (R8-R12)
     * Cortex-M0 cannot PUSH/POP high registers directly; must move to low registers (R3-R7) first.
     * Cortex-M0 不能直接 PUSH/POP 高组寄存器，需要先搬移到低组寄存器 (R3-R7)。
     */
    mov     r3, r8
    mov     r4, r9
    mov     r5, r10
    mov     r6, r11
    mov     r7, r12
    push    {r3-r7}

    /* 
     * 3. 分配栈空间 (Local Variables)
     * Allocate 480 bytes for intermediate state or S-box / 分配 480 字节用于存放中间状态或 S-box 
     */
    sub     sp, #480

    PREPARE_CONSTANTS_TO_STACK

    BS_PACKING
    //end state:r0-r3,r8-r11=0;r4-r7:share0 bit4-7;

    //start state:r0-r3,r8-r11=0;r4-r7:share0 bit4-7;
    ARK
    //end state:r3,4,5,6,7=share0.bit 7 4 5 6 3
    /* --------------------------------round 9------------------------------------ */

    //start state:r3,4,5,6,7=share0.bit 7 4 5 6 3
    InvShiftRows
    //end state:r3,4,5,6,7=share1.bit 7 0 1 2 3
    //start state:r3,4,5,6,7=share1.bit 7 0 1 2 3
    InvSubBytes
    //end state:r0-r3,r8-r11=0;r4-r7:share0 bit4-7;
    //start state:r0-r3,r8-r11=0;r4-r7:share0 bit4-7;
    ARK
    //end state:r3,4,5,6,7=share0.bit 7 4 5 6 3
    //start state:r3,4,5,6,7=share0.bit 7 4 5 6 3
    InvMixColumns
    //end state:r3,4,5,6,7=share1.bit 7 0 1 2 3

    /* --------------------------------round 8------------------------------------ */

    InvShiftRows
    InvSubBytes
    ARK
    InvMixColumns

    /* --------------------------------round 7------------------------------------ */

    InvShiftRows
    InvSubBytes
    ARK
    InvMixColumns

    /* --------------------------------round 6------------------------------------ */

    InvShiftRows
    InvSubBytes
    ARK
    InvMixColumns

    /* --------------------------------round 5------------------------------------ */

    InvShiftRows
    InvSubBytes
    ARK
    InvMixColumns

    /* --------------------------------round 4------------------------------------ */

    InvShiftRows
    InvSubBytes
    ARK
    InvMixColumns

    /* --------------------------------round 3------------------------------------ */

    InvShiftRows
    InvSubBytes
    ARK
    InvMixColumns

    /* --------------------------------round 2------------------------------------ */

    InvShiftRows
    InvSubBytes
    ARK
    InvMixColumns

    /* --------------------------------round 1------------------------------------ */

    InvShiftRows
    InvSubBytes
    ARK
    InvMixColumns

    /* --------------------------------round 0------------------------------------ */

    InvShiftRows
    InvSubBytes
    ARK
    //end state:r3,4,5,6,7=share0.bit 7 4 5 6 3

    /* --------------------------------return to byte----------------------------- */
    
    //start state:r3,4,5,6,7=share0.bit 7 4 5 6 3
    mov r8,r7
    ldr r0, [sp, #16]
    ldr r1,[sp,#20]
    ldr r2,[sp,#24]
    ldr r7,[sp,#28]

    eors r0,r4
    eors r1,r5
    eors r2,r6
    eors r3,r7

    mov r7,r8
    mov r8,r0
    mov r9,r1
    mov r10,r2
    mov r11,r3

    ldr r0, [sp, #0]
    ldr r1,[sp,#4]
    ldr r2,[sp,#8]
    ldr r3,[sp,#12]

    ldr r4, [sp, #240]
    ldr r5,[sp,#244]
    ldr r6,[sp,#248]

    eors r0,r4
    eors r1,r5
    eors r2,r6
    eors r3,r7

    mov r4,r8
    mov r5,r9
    mov r6,r10
    mov r7,r11

    mov r8,r0
    mov r9,r1
    mov r10,r2
    mov r11,r3

    BIT2BYTE_PART1
    BIT2BYTE_PART2

    BIT2BYTE_PART1
    BIT2BYTE_PART2

    BIT2BYTE_PART1
    BIT2BYTE_PART2

    BIT2BYTE_PART1
    BIT2BYTE_PART2

    mov r4,r8
    mov r5,r9
    mov r6,r10
    mov r7,r11

    mov r8,r0
    mov r9,r1
    mov r10,r2
    mov r11,r3

    eors r0,r0
    eors r1,r1
    eors r2,r2
    eors r3,r3

    BIT2BYTE_PART1
    BIT2BYTE_PART2

    BIT2BYTE_PART1
    BIT2BYTE_PART2

    BIT2BYTE_PART1
    BIT2BYTE_PART2

    BIT2BYTE_PART1

    mov r4,r8
    mov r5,r9
    mov r6,r10
    mov r7,r11

    orrs r0,r4
    orrs r1,r5
    orrs r2,r6
    orrs r3,r7

    /* ------------------------upload results------------------------------------- */

    ldr r4, [sp, #464]
    stmia r4!, {r0-r3}

    /* -------------------------------------------------------------------------
     * Epilogue (函数结语)
     * 1. Free Stack Space / 释放栈空间
     * ------------------------------------------------------------------------- */
    add     sp, #480

    /* 2. Restore High Registers (R8-R12) / 恢复高组寄存器 (R8-R12) */
    pop     {r3-r7}
    mov     r8, r3
    mov     r9, r4
    mov     r10, r5
    mov     r11, r6
    mov     r12, r7

    /* 3. Restore Low Registers and Return / 恢复低组寄存器并返回 */
    pop     {r4-r7, pc}