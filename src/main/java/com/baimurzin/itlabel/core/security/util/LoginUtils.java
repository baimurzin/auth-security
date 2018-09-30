package com.baimurzin.itlabel.core.security.util;

import org.springframework.util.Assert;

public class LoginUtils {
    public static String validateAndTrimLogin(String login){
        Assert.notNull(login, "email cannot be null");
        login = login.trim();
        Assert.hasLength(login, "email should have length");
        Assert.isTrue(!login.startsWith("facebook_"), "email should have length");
        return login;
    }
}
