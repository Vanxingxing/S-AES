public class SAES {
    // S盒与逆S盒（标准定义，逐位核对）
    private static final int[] S_BOX = {0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7};
    private static final int[] INV_S_BOX = {0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE};

    // 修正：GF(2^4)乘法（严格按不可约多项式x⁴+x+1=0x13计算）
    private static int gfMult(int a, int b) {
        int p = 0;
        a &= 0xF; // 确保a为4位（0~15）
        b &= 0xF; // 确保b为4位
        for (int i = 0; i < 4; i++) {
            if ((b & 1) == 1) {
                p ^= a; // 若b的最低位为1，累加a
            }
            // 左移a，若溢出则模0x13（x⁴+x+1）
            boolean overflow = (a & 0x8) != 0; // 检查a的第4位（最高位）是否为1
            a <<= 1;
            if (overflow) {
                a ^= 0x13; // 关键修正：模不可约多项式0x13
            }
            a &= 0xF; // 保持a为4位
            b >>= 1; // 处理b的下一位
        }
        return p;
    }

    // RotWord：8bit字高低4bit互换（正确）
    private static int rotWord(int w) {
        return ((w & 0x0F) << 4) | ((w >> 4) & 0x0F);
    }

    // SubWord：S盒替换（正确）
    private static int subWord(int w) {
        int high = (w >> 4) & 0x0F;
        int low = w & 0x0F;
        return (S_BOX[high] << 4) | S_BOX[low];
    }

    // 密钥扩展（轮常量RC1=0x80，RC2=0x30，严格按标准流程）
    private static int[] keyExpansion(int key) {
        int w0 = (key >> 8) & 0xFF;
        int w1 = key & 0xFF;

        // 轮1：w2 = w0 ^ subWord(rotWord(w1)) ^ 0x80
        int w2 = w0 ^ subWord(rotWord(w1)) ^ 0x80;
        int w3 = w2 ^ w1;

        // 轮2：w4 = w2 ^ subWord(rotWord(w3)) ^ 0x30
        int w4 = w2 ^ subWord(rotWord(w3)) ^ 0x30;
        int w5 = w4 ^ w3;

        return new int[]{
                (w0 << 8) | w1,    // 初始轮密钥（轮0）
                (w2 << 8) | w3,    // 轮1密钥
                (w4 << 8) | w5     // 轮2密钥
        };
    }

    // 字节替换（正确）
    private static int subBytes(int state) {
        int n0 = (state >> 12) & 0xF;
        int n1 = (state >> 8) & 0xF;
        int n2 = (state >> 4) & 0xF;
        int n3 = state & 0xF;
        return (S_BOX[n0] << 12) | (S_BOX[n1] << 8) | (S_BOX[n2] << 4) | S_BOX[n3];
    }

    // 行移位（正确：交换第二行两个nibble）
    private static int shiftRows(int state) {
        int n0 = (state >> 12) & 0xF;
        int n1 = (state >> 8) & 0xF;
        int n2 = (state >> 4) & 0xF;
        int n3 = state & 0xF;
        return (n0 << 12) | (n1 << 8) | (n3 << 4) | n2; // 交换n2和n3
    }

    // 列混淆（严格按矩阵[1 4; 4 1]计算）
    private static int mixColumns(int state) {
        int n0 = (state >> 12) & 0xF;
        int n1 = (state >> 8) & 0xF;
        int n2 = (state >> 4) & 0xF;
        int n3 = state & 0xF;

        int newN0 = gfMult(1, n0) ^ gfMult(4, n2);
        int newN1 = gfMult(1, n1) ^ gfMult(4, n3);
        int newN2 = gfMult(4, n0) ^ gfMult(1, n2);
        int newN3 = gfMult(4, n1) ^ gfMult(1, n3);

        return (newN0 << 12) | (newN1 << 8) | (newN2 << 4) | newN3;
    }

    // 轮密钥加（正确）
    private static int addRoundKey(int state, int roundKey) {
        return state ^ roundKey;
    }

    // 加密流程（标准步骤）
    public static int encrypt(int plaintext, int key) {
        int[] roundKeys = keyExpansion(key);
        int state = addRoundKey(plaintext, roundKeys[0]); // 初始轮密钥加

        // 轮1：SubBytes→ShiftRows→MixColumns→轮密钥加
        state = subBytes(state);
        state = shiftRows(state);
        state = mixColumns(state);
        state = addRoundKey(state, roundKeys[1]);

        // 轮2：SubBytes→ShiftRows→轮密钥加（无MixColumns）
        state = subBytes(state);
        state = shiftRows(state);
        state = addRoundKey(state, roundKeys[2]);

        return state;
    }

    // 逆字节替换（正确）
    private static int invSubBytes(int state) {
        int n0 = (state >> 12) & 0xF;
        int n1 = (state >> 8) & 0xF;
        int n2 = (state >> 4) & 0xF;
        int n3 = state & 0xF;
        return (INV_S_BOX[n0] << 12) | (INV_S_BOX[n1] << 8) | (INV_S_BOX[n2] << 4) | INV_S_BOX[n3];
    }

    // 逆列混淆（矩阵[9 2; 2 9]）
    private static int invMixColumns(int state) {
        int n0 = (state >> 12) & 0xF;
        int n1 = (state >> 8) & 0xF;
        int n2 = (state >> 4) & 0xF;
        int n3 = state & 0xF;

        int newN0 = gfMult(9, n0) ^ gfMult(2, n2);
        int newN1 = gfMult(9, n1) ^ gfMult(2, n3);
        int newN2 = gfMult(2, n0) ^ gfMult(9, n2);
        int newN3 = gfMult(2, n1) ^ gfMult(9, n3);

        return (newN0 << 12) | (newN1 << 8) | (newN2 << 4) | newN3;
    }

    // 解密流程（标准步骤）
    public static int decrypt(int ciphertext, int key) {
        int[] roundKeys = keyExpansion(key);
        int state = addRoundKey(ciphertext, roundKeys[2]); // 初始轮（用最后一轮密钥）

        // 逆轮1：ShiftRows→InvSubBytes→轮密钥加→InvMixColumns
        state = shiftRows(state);
        state = invSubBytes(state);
        state = addRoundKey(state, roundKeys[1]);
        state = invMixColumns(state);

        // 逆轮2：ShiftRows→InvSubBytes→轮密钥加
        state = shiftRows(state);
        state = invSubBytes(state);
        state = addRoundKey(state, roundKeys[0]);

        return state;
    }
}