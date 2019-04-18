package stencryption.stencryption.com.controller;

import com.alibaba.fastjson.JSON;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import stencryption.stencryption.com.signature.Signature;
import stencryption.stencryption.com.vo.SignReqVO;

@Slf4j
@RestController
@RequestMapping("/sign")
public class SignatureController {

    @Value("${encrypt.aes.privateKey}")
    private String privateKey;

    @Value("${encrypt.aes.publicKey}")
    private String publicKey;

    @RequestMapping("/rsa")
    public String sign(@RequestBody SignReqVO reqVO) {
        LOGGER.info("RSA加签入参: " + JSON.toJSONString(reqVO));
        try {
            String signContent = Signature.rsaSign(JSON.toJSONString(reqVO), privateKey, "utf-8");
            LOGGER.info("RSA加签结果: " + signContent);
            return signContent;
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            return e.getMessage();
        }
    }

    @RequestMapping("/verify")
    public boolean verify(@RequestBody String signData) {
        LOGGER.info("RSA验签入参: " + signData);
        String content = "{\"acctName\":\"太阳系银行\",\"acctNum\":\"1234567890\"}";
        signData = "Ztih/qZP007vP3TaBXdLHnqVnhSZsIViBjP9DN8mCHVX9aiy12rt8+E6E684G5nNXvGJlLpIiVraL1vPXoHcMAEKQEkgKf9xlVsLK6qFsB/POX533nIL8pt+ybUYvaLCD+nrhAGIDJGBVWDlmGQWxGCGCiRatuuztVnc3kQST3ockeBugC8n9n7YpadLnOdpKFO/WJ1kKtbs+6chicBioagbnbZLoySrFW4O/2gI4nC1v9ld7foHxo4se0O+K+sZTEoIqyGijEXN9G1HMf6NQWUuYhbx0bqY/Mjo7OrFMIV6EuJGpNaaGFGgyddjWXSmn3OYH/rbr4EraluZ6kgbtQ==";
        try {
            return Signature.rsaCheck(content, signData, publicKey, "utf-8", "RSA");
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            return false;
        }
    }
}
