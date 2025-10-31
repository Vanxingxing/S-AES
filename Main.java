public class Main {
    public static void main(String[] args) {
        // 运行所有测试
        testBasicEncryptDecrypt();    // 第1关：基础加解密
        testStringEncryptDecrypt();   // 第3关：字符串处理
        testDoubleEncryptAndAttack(); // 第4关：双重加密与攻击
        testTripleEncrypt();          // 第4关：三重加密
        CBCMode.testTampering();      // 第5关：CBC模式

    }

    // 测试基础加解密（第1关）
    private static void testBasicEncryptDecrypt() {
        int plain = 0b0001001000110100; // 0x1234
        int key = 0b0010010100110111;   // 0x2537
        int cipher = SAES.encrypt(plain, key);
        int decrypted = SAES.decrypt(cipher, key);

        System.out.println("=== 基础加解密测试 ===");
        System.out.println("明文（二进制）：" + Integer.toBinaryString(plain));
        System.out.println("密文（二进制）：" + Integer.toBinaryString(cipher));
        System.out.println("解密后（二进制）：" + Integer.toBinaryString(decrypted));
        System.out.println("验证结果：" + (decrypted == plain ? "成功" : "失败") + "\n");
    }

    // 测试字符串加解密（第3关）
    private static void testStringEncryptDecrypt() {
        String plainStr = "TestS-AES";
        int key = 0b0010010100110111; // 0x2537
        int[] cipherBlocks = StringHandler.encryptStr(plainStr, key);
        String decryptedStr = StringHandler.decryptStr(cipherBlocks, key);

        System.out.println("=== 字符串加解密测试 ===");
        System.out.println("原始字符串：" + plainStr);
        System.out.println("解密后字符串：" + decryptedStr);
        System.out.println("验证结果：" + (decryptedStr.equals(plainStr) ? "成功" : "失败") + "\n");
    }

    // 测试双重加密与中间相遇攻击（第4关）
    private static void testDoubleEncryptAndAttack() {
        int plain = 0b0000000000000000; // 0x0000
        int key32 = 0b00010010001101000011010000100101; // K1=0x1234, K2=0x3425
        int cipher = MultiEncrypt.doubleEncrypt(plain, key32);

        // 中间相遇攻击破解密钥
        int[] keys = MultiEncrypt.meetInTheMiddle(plain, cipher);

        System.out.println("=== 双重加密与攻击测试 ===");
        System.out.println("预期K1（二进制）：" + Integer.toBinaryString((key32 >> 16) & 0xFFFF));
        System.out.println("预期K2（二进制）：" + Integer.toBinaryString(key32 & 0xFFFF));
        if (keys != null) {
            System.out.println("破解K1（二进制）：" + Integer.toBinaryString(keys[0]));
            System.out.println("破解K2（二进制）：" + Integer.toBinaryString(keys[1]));
            System.out.println("攻击结果：" + (keys[0] == (key32 >> 16) && keys[1] == (key32 & 0xFFFF) ? "成功" : "失败"));
        } else {
            System.out.println("攻击结果：失败（未找到密钥）");
        }
        System.out.println("======================\n");
    }

    // 测试三重加密（第4关）
    private static void testTripleEncrypt() {
        int plain = 0x1122; // 16bit明文
        long key48 = 0x111122223333L; // 48bit密钥（K1=0x1111, K2=0x2222, K3=0x3333）
        int cipher = MultiEncrypt.tripleEncrypt(plain, key48);
        int decrypted = MultiEncrypt.tripleDecrypt(cipher, key48);

        System.out.println("=== 三重加密测试 ===");
        System.out.println("明文（十六进制）：0x" + Integer.toHexString(plain).toUpperCase());
        System.out.println("解密后（十六进制）：0x" + Integer.toHexString(decrypted).toUpperCase());
        System.out.println("验证结果：" + (decrypted == plain ? "成功" : "失败") + "\n");
    }
}