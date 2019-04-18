package stencryption.stencryption.com.md5;

import org.springframework.util.DigestUtils;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5 {
    public static String md5Encrypt(String text, String key) {
        return DigestUtils.md5DigestAsHex(text.getBytes(Charset.forName("UTF-8")));
//        return DigestUtils.appendMd5DigestAsHex(text.getBytes(Charset.forName("UTF-8")), new StringBuilder(key)).toString();
    }

    public static String javaMd5Encrypt(String text, String key) throws NoSuchAlgorithmException {
        MessageDigest messageDigest =MessageDigest.getInstance("MD5");
        byte[] inputByteArray = text.getBytes();
        messageDigest.update(inputByteArray);
        byte[] resultByteArray = messageDigest.digest();
        return DigestUtils.md5DigestAsHex(resultByteArray);

    }

    public static void main(String[] args) throws Exception {
        String text = "hello md5 home";
        String key = "myKey";
        String encode = MD5.md5Encrypt(text, key);
        System.out.println(encode);
        String javaEncode = MD5.javaMd5Encrypt(text, key);
        System.out.println(javaEncode);
    }

}
