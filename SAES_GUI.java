import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;

public class SAES_GUI extends JFrame {
    private JTextField dataField, keyField, resultField;

    public SAES_GUI() {
        setTitle("S-AES加解密工具");
        setSize(400, 200);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new GridLayout(4, 2, 10, 10));
        setLocationRelativeTo(null); // 居中显示

        // 组件初始化
        add(new JLabel("16bit数据（二进制）:"));
        dataField = new JTextField();
        add(dataField);

        add(new JLabel("16bit密钥（二进制）:"));
        keyField = new JTextField();
        add(keyField);

        JButton encryptBtn = new JButton("加密");
        encryptBtn.addActionListener(this::encryptAction);
        add(encryptBtn);

        JButton decryptBtn = new JButton("解密");
        decryptBtn.addActionListener(this::decryptAction);
        add(decryptBtn);

        add(new JLabel("结果（二进制）:"));
        resultField = new JTextField();
        resultField.setEditable(false);
        add(resultField);
    }

    // 二进制字符串转16bit整数
    private int binToInt(String bin) throws IllegalArgumentException {
        if (bin.length() != 16 || !bin.matches("[01]+")) {
            throw new IllegalArgumentException("请输入16位二进制数");
        }
        return Integer.parseInt(bin, 2);
    }

    // 16bit整数转二进制字符串
    private String intToBin(int num) {
        String bin = Integer.toBinaryString(num);
        return String.format("%16s", bin).replace(' ', '0'); // 补前导零
    }

    private void encryptAction(ActionEvent e) {
        try {
            int data = binToInt(dataField.getText().trim());
            int key = binToInt(keyField.getText().trim());
            int cipher = SAES.encrypt(data, key);
            resultField.setText(intToBin(cipher));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void decryptAction(ActionEvent e) {
        try {
            int data = binToInt(dataField.getText().trim());
            int key = binToInt(keyField.getText().trim());
            int plain = SAES.decrypt(data, key);
            resultField.setText(intToBin(plain));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new SAES_GUI().setVisible(true));
    }
}