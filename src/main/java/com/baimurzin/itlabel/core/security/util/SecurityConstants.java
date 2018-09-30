package com.baimurzin.itlabel.core.security.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

public class SecurityConstants {

    public static final String API_LOGIN_URL = "/api/login";
    public static final String API_LOGOUT_URL = "/api/logout";

    public static final String USERNAME_PARAMETER = "username";
    public static final String PASSWORD_PARAMETER = "password";
    public static final String REMEMBER_ME_PARAMETER = "remember-me";
    public static final String API_LOGIN_FACEBOOK = "/api/login/facebook";
    public static final String API_LOGIN_GITHUB = "/api/login/github";
}
