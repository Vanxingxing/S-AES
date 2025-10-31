import java.util.Random;

public class CBCMode {
    // 生成16bit随机初始向量IV
    public static int generateIV() {
        return new Random().nextInt(0x10000); // 0~65535
    }

    // CBC模式加密（返回密文块数组，首块为IV）
    public static int[] cbcEncrypt(String plainStr, int key, Integer iv) {
        int[] plainBlocks = StringHandler.strToBlocks(plainStr);
        int actualIV = (iv == null) ? generateIV() : iv; // 若未指定则自动生成
        int[] cipherBlocks = new int[plainBlocks.length + 1];
        cipherBlocks[0] = actualIV; // 密文首块存储IV

        int prev = actualIV; // 前一块（初始为IV）
        for (int i = 0; i < plainBlocks.length; i++) {
            int c = SAES.encrypt(plainBlocks[i] ^ prev, key); // 明文块与前一块异或后加密
            cipherBlocks[i + 1] = c;
            prev = c; // 更新前一块为当前密文块
        }
        return cipherBlocks;
    }

    // CBC模式解密
    public static String cbcDecrypt(int[] cipherBlocks, int key) {
        if (cipherBlocks.length < 1) return "";
        int iv = cipherBlocks[0];
        int[] plainBlocks = new int[cipherBlocks.length - 1];

        int prev = iv; // 前一块（初始为IV）
        for (int i = 1; i < cipherBlocks.length; i++) {
            int p = SAES.decrypt(cipherBlocks[i], key) ^ prev; // 解密后与前一块异或
            plainBlocks[i - 1] = p;
            prev = cipherBlocks[i]; // 更新前一块为当前密文块
        }
        return StringHandler.blocksToStr(plainBlocks);
    }

    // 测试密文篡改影响
    public static void testTampering() {
        int key = 0b0010010100110111; // 16bit密钥（0x2537）
        String plain = "Hello, S-AES CBC Mode!";
        int[] cipherBlocks = cbcEncrypt(plain, key, null); // 自动生成IV

        System.out.println("=== CBC模式篡改测试 ===");
        System.out.println("原始明文：" + plain);
        System.out.println("正常解密：" + cbcDecrypt(cipherBlocks, key));

        // 篡改第2个密文块（索引1，非IV块）
        int[] tampered = cipherBlocks.clone();
        tampered[1] ^= 0b1000000000000000; // 翻转最高位
        System.out.println("篡改后解密：" + cbcDecrypt(tampered, key)); // 前2块错误
        System.out.println("======================\n");
    }
}