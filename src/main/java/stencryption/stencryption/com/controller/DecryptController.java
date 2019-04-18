package stencryption.stencryption.com.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import stencryption.stencryption.com.encrypt.AESOperator;
import stencryption.stencryption.com.signature.SignatureException;

@Slf4j
@RestController
@RequestMapping("/decrypt")
public class DecryptController {

    @Value("${encrypt.aes.publicKey}")
    private String privateKey;

    @RequestMapping("/aes")
    public String aes(@RequestBody String signData) {
        LOGGER.info("AES解密入参: " + signData);
        String result = null;
        try {
            result = AESOperator.getInstance().decrypt(signData, privateKey);
        } catch (SignatureException e) {
            LOGGER.error(e.getErrMsg(), e);
            result = e.getErrMsg();
        }
        LOGGER.info("AES解密返回值: " + result);
        return result;
    }
}
