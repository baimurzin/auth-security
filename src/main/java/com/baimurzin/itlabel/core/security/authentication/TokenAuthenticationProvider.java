package com.baimurzin.itlabel.core.security.authentication;

import com.baimurzin.itlabel.core.security.service.AppTokenService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.token.DefaultToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public class TokenAuthenticationProvider implements AuthenticationProvider {

    private AppTokenService appTokenService;

    public TokenAuthenticationProvider(AppTokenService appTokenService) {
        this.appTokenService = appTokenService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        DefaultToken token = (DefaultToken) authentication.getPrincipal();
        if (token == null) {
            throw new BadCredentialsException("Invalid token");
        }
        if (!appTokenService.contains(token)) {
            throw new BadCredentialsException("Invalid token or token expired");
        }
        return appTokenService.retrieve(token);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(PreAuthenticatedAuthenticationToken.class);
    }
}
