import java.util.HashMap;
import java.util.Map;

public class MultiEncrypt {
    // 双重加密（32bit密钥：K1+K2）
    public static int doubleEncrypt(int plaintext, int key32) {
        int k1 = (key32 >> 16) & 0xFFFF; // 前16bit
        int k2 = key32 & 0xFFFF;         // 后16bit
        return SAES.encrypt(SAES.encrypt(plaintext, k1), k2);
    }

    // 双重解密
    public static int doubleDecrypt(int ciphertext, int key32) {
        int k1 = (key32 >> 16) & 0xFFFF;
        int k2 = key32 & 0xFFFF;
        return SAES.decrypt(SAES.decrypt(ciphertext, k2), k1);
    }

    // 中间相遇攻击（返回K1和K2）
    public static int[] meetInTheMiddle(int plain, int cipher) {
        Map<Integer, Integer> tMap = new HashMap<>();
        // 预计算所有K1对应的中间值T = E(K1, P)
        for (int k1 = 0; k1 < 0x10000; k1++) {
            int t = SAES.encrypt(plain, k1);
            tMap.put(t, k1);
        }
        // 查找K2使得D(K2, C) = T
        for (int k2 = 0; k2 < 0x10000; k2++) {
            int tPrime = SAES.decrypt(cipher, k2);
            if (tMap.containsKey(tPrime)) {
                int k1 = tMap.get(tPrime);
                // 验证密钥正确性
                if (doubleEncrypt(plain, (k1 << 16) | k2) == cipher) {
                    return new int[]{k1, k2};
                }
            }
        }
        return null; // 未找到
    }

    // 三重加密（48bit密钥：K1+K2+K3，用long存储避免截断）
    public static int tripleEncrypt(int plaintext, long key48) {
        int k1 = (int) ((key48 >> 32) & 0xFFFF); // 高16位
        int k2 = (int) ((key48 >> 16) & 0xFFFF); // 中16位
        int k3 = (int) (key48 & 0xFFFF);         // 低16位
        return SAES.encrypt(SAES.encrypt(SAES.encrypt(plaintext, k1), k2), k3);
    }

    // 三重解密
    public static int tripleDecrypt(int ciphertext, long key48) {
        int k1 = (int) ((key48 >> 32) & 0xFFFF);
        int k2 = (int) ((key48 >> 16) & 0xFFFF);
        int k3 = (int) (key48 & 0xFFFF);
        return SAES.decrypt(SAES.decrypt(SAES.decrypt(ciphertext, k3), k2), k1);
    }
}