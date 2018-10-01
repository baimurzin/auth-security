package com.baimurzin.itlabel.core.security.authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.token.Token;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.Collection;

public class AuthenticationWithToken extends PreAuthenticatedAuthenticationToken {
    public AuthenticationWithToken(Object aPrincipal, Object aCredentials) {
        super(aPrincipal, aCredentials);
    }

    public AuthenticationWithToken(Object aPrincipal, Object aCredentials, Collection<? extends GrantedAuthority> anAuthorities) {
        super(aPrincipal, aCredentials, anAuthorities);
    }

    public void setToken(Token token) {
        setDetails(token);
    }

    public Token getToken() {
        return (Token)getDetails();
    }
}
