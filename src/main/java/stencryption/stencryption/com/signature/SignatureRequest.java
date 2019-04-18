package stencryption.stencryption.com.signature;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class SignatureRequest implements Serializable {
    private String channel;
    private String platform;

    public SignatureRequest() {}

    public Map<String, String> toMap() {
        Map<String, String> signMap = new HashMap<>();
        signMap.put("channel", this.channel);
        signMap.put("platform", this.platform);
        return signMap;
    }
}
