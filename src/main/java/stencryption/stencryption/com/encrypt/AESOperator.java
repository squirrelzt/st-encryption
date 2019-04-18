package stencryption.stencryption.com.encrypt;

import stencryption.stencryption.com.signature.SignatureException;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class AESOperator {

    private final static String AES_IV = "ed16234234kjd8d4";
    private static AESOperator instance = null;

    private AESOperator() {

    }

    public static AESOperator getInstance() {
        if (instance == null){
            instance = new AESOperator();
        }
        return instance;
    }

    // 加密
    public String encrypt(String sSrc,String sKey) throws SignatureException {
        try {
            // 创建密码器
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] raw = sKey.getBytes();
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            // 使用CBC模式，需要一个向量iv，可增加加密算法的强度
            IvParameterSpec iv = new IvParameterSpec(AES_IV.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            byte[] encrypted = cipher.doFinal(sSrc.getBytes("utf-8"));
            // 此处使用BASE64做转码
            String encrypt =  new BASE64Encoder().encode(encrypted);
            return encrypt.replaceAll("[\\s*\t\n\r]", "");
        }catch (Exception ex){
            throw new SignatureException(ex);
        }
    }

    // 解密
    public String decrypt(String sSrc,String sKey) throws SignatureException {
        try {
            byte[] raw = sKey.getBytes("ASCII");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(AES_IV.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            // 先用base64解密
            byte[] encrypted1 = new BASE64Decoder().decodeBuffer(sSrc);
            byte[] original = cipher.doFinal(encrypted1);
            String originalString = new String(original, "utf-8");
            return originalString;
        } catch (Exception ex) {
            throw new SignatureException(ex);
        }
    }


    public static void main(String[] args) {
        try {
//            String tt =  AESOperator.getInstance().encrypt("{'trdAcctName':'1111111111111111111111111111111'}","7d11b70ca35cd9e31fa05565ba25e55f");
//            System.out.println(tt);

            String tt = "diLbAaFHfoiV49SgRwWfnnyJBFvHT+xAzVg/g2JrVYpVw9GDjnMVlWfKzPQUQOJLRXUsWIjUK3Dam8o7PNTVchPb6Pvv2Tf7T5enWQTEYWNIWvjKIrl2XvSKyShguegjauKPYdyc5cr8KnIMHCYGRsXGn9Z0ylrW5yzLlqovUSJQ/1MVlHQ0yj0KLSt0lrqyLCXoXuOWXV/5crzXZK9e2bo038dkCHIIAsklJEwIrjhn6SqcjQo64ug0qGcnQX+GaRLCQDq3+ciPPYg4WzbjEpQVnw8eYV4pCTydPMmBT+mTctHgBMdRHZ0YDnd+CubeA2sUt4lnR3yrtYOu5Kw/zQ==";
            String src = AESOperator.getInstance().decrypt(tt,"7d11b70ca35cd9e31fa05565ba25e55f");
            System.out.printf(src);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }

}
