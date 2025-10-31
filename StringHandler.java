public class StringHandler {
    // ASCII字符串转16bit分组数组
    public static int[] strToBlocks(String s) {
        int len = (s.length() + 1) / 2; // 向上取整（奇数长度补位）
        int[] blocks = new int[len];
        for (int i = 0; i < len; i++) {
            int b1 = (i * 2 < s.length()) ? s.charAt(i * 2) : 0; // 高8位
            int b2 = (i * 2 + 1 < s.length()) ? s.charAt(i * 2 + 1) : 0; // 低8位
            blocks[i] = (b1 << 8) | b2; // 组合为16bit
        }
        return blocks;
    }

    // 16bit分组数组转ASCII字符串
    public static String blocksToStr(int[] blocks) {
        StringBuilder sb = new StringBuilder();
        for (int block : blocks) {
            int b1 = (block >> 8) & 0xFF; // 提取高8位
            int b2 = block & 0xFF;        // 提取低8位
            if (b1 != 0) sb.append((char) b1); // 忽略补位的0
            if (b2 != 0) sb.append((char) b2);
        }
        return sb.toString();
    }

    // 加密ASCII字符串
    public static int[] encryptStr(String s, int key) {
        int[] blocks = strToBlocks(s);
        for (int i = 0; i < blocks.length; i++) {
            blocks[i] = SAES.encrypt(blocks[i], key);
        }
        return blocks;
    }

    // 解密为ASCII字符串
    public static String decryptStr(int[] cipherBlocks, int key) {
        int[] plainBlocks = new int[cipherBlocks.length];
        for (int i = 0; i < plainBlocks.length; i++) {
            plainBlocks[i] = SAES.decrypt(cipherBlocks[i], key);
        }
        return blocksToStr(plainBlocks);
    }
}