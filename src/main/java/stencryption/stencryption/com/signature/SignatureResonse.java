package stencryption.stencryption.com.signature;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class SignatureResonse implements Serializable {
    private Integer respCode;
    private String respMsg;
    private String result;
    private String responseTime;
    private String signType;
    private String sign;

    public SignatureResonse() {}

    public Map<String,String> toMap(){
        Map<String,String> signMap = new HashMap<>();
        signMap.put("respCode",String.valueOf(this.respCode));
        signMap.put("respMsg",this.respMsg);
        signMap.put("result",this.result);
        signMap.put("responseTime",responseTime);
        return signMap;
    }
}
