package stencryption.stencryption.com.controller;

import com.alibaba.fastjson.JSON;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import stencryption.stencryption.com.encrypt.AESOperator;
import stencryption.stencryption.com.signature.SignatureException;
import stencryption.stencryption.com.vo.SignReqVO;

@Slf4j
@RestController
@RequestMapping("/encrypt")
public class EncryptController {

    @Value("${encrypt.aes.publicKey}")
    private String privateKey;

    @RequestMapping("/aes")
    public String aes(@RequestBody SignReqVO reqVO) {
        LOGGER.info("AES加密入参: " + JSON.toJSONString(reqVO));
        String jsonStr = JSON.toJSONString(reqVO);
        String signData = null;
        try {
            signData =  AESOperator.getInstance().encrypt(jsonStr, privateKey);
        } catch (SignatureException e) {
            LOGGER.error(e.getErrMsg(), e);
            signData =  e.getErrMsg();
        }
        LOGGER.info("AES加密返回值: " + signData);
        return signData;
    }
}
