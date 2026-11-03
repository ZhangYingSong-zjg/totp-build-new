package com.pjy.totp;

public class TotpManager {
    static {
        System.loadLibrary("totp-lib");
    }
    public native String generateTotp(long timestamp);
    public native long calcExpireTime(long networkTime);
}
