package com.baimurzin.itlabel.core.security;

import org.springframework.util.Assert;

public class LoginUtils {
    public static String validateAndTrimLogin(String login){
        Assert.notNull(login, "login cannot be null");
        login = login.trim();
        Assert.hasLength(login, "login should have length");
        Assert.isTrue(!login.startsWith("facebook_"), "login should have length");
        return login;
    }
}
