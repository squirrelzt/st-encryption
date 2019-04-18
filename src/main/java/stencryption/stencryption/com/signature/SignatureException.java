package stencryption.stencryption.com.signature;

import java.io.IOException;
import java.io.Serializable;

public class SignatureException extends IOException implements Serializable {
    private String errCode;
    private String errMsg;

    public String getErrCode() {
        return errCode;
    }

    public String getErrMsg() {
        return errMsg;
    }

    public SignatureException() {}

    public SignatureException(String message, Throwable cause) {
        super(message, cause);
    }

    public SignatureException(String message) {
        super(message);
    }

    public SignatureException(Throwable cause) {
        super(cause);
    }

    public SignatureException(String errCode, String errMsg) {
        super(errCode + ":" + errMsg);
        this.errCode = errCode;
        this.errMsg = errMsg;
    }
}
