package com.baimurzin.itlabel.core.security.exception;

public class CommonSecurityException extends RuntimeException {
    public CommonSecurityException() {
    }

    public CommonSecurityException(String message) {
        super(message);
    }

    public CommonSecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    public CommonSecurityException(Throwable cause) {
        super(cause);
    }
}
