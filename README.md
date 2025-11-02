# S-AES
本项目基于 Java语言实现 S-AES 全功能加密系统，支持多种加密模式和攻击分析。
# 项目简介
本项目实现了 S-AES 算法的完整功能，包括：  
· 16位数据块的加解密
· ASCII 字符串加解密
· 双重加密与三重加密
· 中间相遇攻击
· CBC 工作模式
· 完整的测试验证

# 环境要求
依赖项  | 版本要求  | 说明
------------- | ------------- | -------------
Java  | 8及以上  | 需要 JDK 8 或更高版本
第三方库  | 无  | 纯 Java 标准库实现，无需额外依赖

# 快速启动
*获取代码*  
将提供的 Java 代码文件保存到同一目录下，包括：
Main.java - 主程序与测试类
SAES.java - S-AES 核心算法实现
StringHandler.java - 字符串处理功能
MultiEncrypt.java - 多重加密与攻击
CBCMode.java - CBC 工作模式
SAES_GUI.java - 图形用户界面程序

*编译运行*
打开终端 / 命令提示符，进入代码所在目录，执行以下命令：
# 编译所有Java文件
javac *.java
# 运行主程序
java Main
# 运行GUI图形界面程序
java SAES_GUI
运行后将自动执行所有测试用例，显示详细的测试结果

# 核心功能与使用指南
*界面布局说明*  
GUI 窗口分为 4 个核心区域，操作逻辑清晰：  
区域       | 位置         | 功能                                                         
---------- | ------------ | ------------------------------------------------------------ 
明文输入区 | 顶部第一行   | 输入待加密的字符串（如 “Hello S - DES”）
密钥输入区 | 顶部第二行   | 输入至少 2 个字符（自动提取前 10 位二进制作为密钥）                            
功能按钮区 | 中间         | 包含 “加密”“解密” 2 个操作按钮               
结果输出区 | 底部         | 输出加密或解密结果  
# 代码结构解析  
    # 核心类与方法
SAES.java
    public static int encrypt(int plain, int key)     // 16位数据块加密
    public static int decrypt(int cipher, int key)    // 16位数据块解密
    private static int subBytes(int state)            // 字节替换
    private static int shiftRows(int state)           // 行移位
    private static int mixColumns(int state)          // 列混淆
    private static int addRoundKey(int state, int key) // 轮密钥加
    private static int keyExpansion(int key)          // 密钥扩展

StringHandler.java
    public static int[] encryptStr(String str, int key) // 字符串加密
    public static String decryptStr(int[] blocks, int key) // 字符串解密
    private static int charToBlock(char c1, char c2)   // 字符转16位块
    private static String blockToChars(int block)      // 16位块转字符

MultiEncrypt.java
    public static int doubleEncrypt(int plain, int key32) // 双重加密
    public static int doubleDecrypt(int cipher, int key32) // 双重解密
    public static int tripleEncrypt(int plain, long key48) // 三重加密
    public static int tripleDecrypt(int cipher, long key48) // 三重解密
    public static int[] meetInTheMiddle(int plain, int cipher) // 中间相遇攻击

CBCMode.java
    public static void testTampering()                // CBC模式篡改测试
    public static int[] cbcEncrypt(int[] blocks, int key, int iv) // CBC加密
    public static int[] cbcDecrypt(int[] blocks, int key, int iv) // CBC解密

# 注意事项     

1. 数据格式要求
二进制输入：使用Java二进制字面量（如 0b0001001000110100）
密钥长度：
基本加密：16位
双重加密：32位
三重加密：48位（long类型）
字符串输入：自动按2字节分组，支持ASCII字符

2. 数值表示
使用 Integer.toBinaryString() 显示二进制格式
使用 Integer.toHexString() 显示十六进制格式
所有运算基于16位整数处理

3. 兼容性保证
使用标准S-AES算法参数
确保算法实现的正确性和一致性
支持与其他标准实现的交叉测试

4. 性能说明
基本加解密操作高效完成
中间相遇攻击需要遍历2^16种可能密钥
字符串处理支持任意长度文本
