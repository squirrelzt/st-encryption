package stencryption.stencryption.com.encrypt;

import org.apache.tomcat.util.codec.binary.Base64;
import stencryption.stencryption.com.signature.Constants;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Encrypt {
    /**
     * RSA 算法
     */

    /** 指定key的大小 */
    private static int KEYSIZE = 2048;
    public static final String CHAR_ENCODING = "UTF-8";
    public static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";

    /**
     * AES算法
     */
    private static final String AES_CBC_PCK_ALG = "AES/CBC/PKCS7Padding";

    private static final byte[] AES_IV   = initIv(AES_CBC_PCK_ALG);

    /**
     *   加密
     *
     * @param content
     * @param encryptType
     * @param encryptKey
     * @param charset
     * @return
     * @throws SignatureException
     */
    public static String encryptContent(String content, String encryptType, String encryptKey,
                                        String charset) throws SignatureException {

        if (Constants.ENCRYPT_TYPE_AES.equals(encryptType)) {
            return aesEncrypt(content, encryptKey, charset);
        } else {
            throw new SignatureException("当前不支持该算法类型：encrypeType=" + encryptType);
        }

    }

    /**
     *  解密
     *
     * @param content
     * @param encryptType
     * @param encryptKey
     * @param charset
     * @return
     * @throws SignatureException
     */
    public static String decryptContent(String content, String encryptType, String encryptKey,
                                        String charset) throws SignatureException {

        if (Constants.ENCRYPT_TYPE_AES.equals(encryptType)) {

            return aesDecrypt(content, encryptKey, charset);

        } else {

            throw new SignatureException("当前不支持该算法类型：encrypeType=" + encryptType);
        }

    }

    /**
     * AES加密
     *
     * @param content
     * @param aesKey
     * @param charset
     * @return
     * @throws SignatureException
     */
    private static String aesEncrypt(String content, String aesKey, String charset)
            throws SignatureException {

        try {
            //创建密码器
            Cipher cipher = Cipher.getInstance(AES_CBC_PCK_ALG);

            IvParameterSpec iv = new IvParameterSpec(AES_IV);
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(Base64.decodeBase64(aesKey.getBytes()), Constants.ENCRYPT_TYPE_AES), iv);

            byte[] encryptBytes = cipher.doFinal(content.getBytes(charset));
            return new String(Base64.encodeBase64(encryptBytes));
        } catch (Exception e) {
            throw new SignatureException("AES加密失败：Aescontent = " + content + "; charset = "
                    + charset, e);
        }

    }

    /**
     * AES解密
     *
     * @param content
     * @param key
     * @param charset
     * @return
     * @throws SignatureException
     */
    private static String aesDecrypt(String content, String key, String charset)
            throws SignatureException {
        try {
            Cipher cipher = Cipher.getInstance(AES_CBC_PCK_ALG);
            IvParameterSpec iv = new IvParameterSpec(initIv(AES_CBC_PCK_ALG));
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(Base64.decodeBase64(key.getBytes()),
                    Constants.ENCRYPT_TYPE_AES), iv);

            byte[] cleanBytes = cipher.doFinal(Base64.decodeBase64(content.getBytes()));
            return new String(cleanBytes, charset);
        } catch (Exception e) {
            throw new SignatureException("AES解密失败：Aescontent = " + content + "; charset = "
                    + charset, e);
        }
    }

    /**
     * 初始向量的方法, 全部为0. 这里的写法适合于其它算法,针对AES算法的话,IV值一定是128位的(16字节).
     *
     * @param fullAlg
     * @return
     * @throws GeneralSecurityException
     */
    private static byte[] initIv(String fullAlg) {

        try {
            Cipher cipher = Cipher.getInstance(fullAlg);
            int blockSize = cipher.getBlockSize();
            byte[] iv = new byte[blockSize];
            for (int i = 0; i < blockSize; ++i) {
                iv[i] = 0;
            }
            return iv;
        } catch (Exception e) {

            int blockSize = 16;
            byte[] iv = new byte[blockSize];
            for (int i = 0; i < blockSize; ++i) {
                iv[i] = 0;
            }
            return iv;
        }
    }


    /**
     * 生成密钥对
     */
    public static Map<String, String> generateKeyPair() throws Exception {
        /** RSA算法要求有一个可信任的随机数源 */
        SecureRandom sr = new SecureRandom();
        /** 为RSA算法创建一个KeyPairGenerator对象 */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        /** 利用上面的随机数据源初始化这个KeyPairGenerator对象 */
        kpg.initialize(KEYSIZE, sr);
        /** 生成密匙对 */
        KeyPair kp = kpg.generateKeyPair();
        /** 得到公钥 */
        Key publicKey = kp.getPublic();
        byte[] publicKeyBytes = publicKey.getEncoded();
        String pub = new String(Base64.encodeBase64(publicKeyBytes),
                CHAR_ENCODING);
        /** 得到私钥 */
        Key privateKey = kp.getPrivate();
        byte[] privateKeyBytes = privateKey.getEncoded();
        String pri = new String(Base64.encodeBase64(privateKeyBytes),
                CHAR_ENCODING);

        Map<String, String> map = new HashMap<String, String>();
        map.put("publicKey", pub);
        map.put("privateKey", pri);
        RSAPublicKey rsp = (RSAPublicKey) kp.getPublic();
        BigInteger bint = rsp.getModulus();
        byte[] b = bint.toByteArray();
        byte[] deBase64Value = Base64.encodeBase64(b);
        String retValue = new String(deBase64Value);
        map.put("modulus", retValue);
        return map;
    }

    /**
     * 加密方法 source： 源数据
     */
    public static String encrypt(String source, String publicKey)
            throws Exception {
        Key key = getPublicKey(publicKey);
        /** 得到Cipher对象来实现对源数据的RSA加密 */
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] b = source.getBytes();
        /** 执行加密操作 */
        byte[] b1 = cipher.doFinal(b);
        return new String(Base64.encodeBase64(b1),
                CHAR_ENCODING);
    }

    /**
     * 解密算法 cryptograph:密文
     */
    public static String decrypt(String cryptograph, String privateKey)
            throws Exception {
        Key key = getPrivateKey(privateKey);
        /** 得到Cipher对象对已用公钥加密的数据进行RSA解密 */
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] b1 = Base64.decodeBase64(cryptograph.getBytes());
        /** 执行解密操作 */
        byte[] b = cipher.doFinal(b1);
        return new String(b);
    }

    /**
     * 得到公钥
     *
     * @param key
     *            密钥字符串（经过base64编码）
     * @throws Exception
     */
    public static PublicKey getPublicKey(String key) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(
                Base64.decodeBase64(key.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 得到私钥
     *
     * @param key
     *            密钥字符串（经过base64编码）
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(String key) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
                Base64.decodeBase64(key.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    public static String getAesKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        // kg.init(128);//要生成多少位，只需要修改这里即可128, 192或256
        //SecureRandom是生成安全随机数序列，password.getBytes()是种子，只要种子相同，序列就一样，所以生成的秘钥就一样。
        kg.init(128, new SecureRandom(password.getBytes()));
        SecretKey sk = kg.generateKey();
        byte[] b = sk.getEncoded();
        String s = byteToHexString(b);
        return s;
    }

    private static String byteToHexString(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String strHex=Integer.toHexString(bytes[i]);
            if(strHex.length() > 3) {
                sb.append(strHex.substring(6));
            } else {
                if(strHex.length() < 2) {
                    sb.append("0" + strHex);
                } else {
                    sb.append(strHex);
                }
            }
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> keyPair = Encrypt.generateKeyPair();
        Set<String> keys = keyPair.keySet();
        Set<Map.Entry<String, String>> entrySet = keyPair.entrySet();
        for (Map.Entry<String, String> entry: entrySet) {
            String key = entry.getKey();
            String value = entry.getValue();
            System.out.println(key + "-->" + value);

        }
    }
}
