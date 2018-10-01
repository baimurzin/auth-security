package com.baimurzin.itlabel.core.security.authentication;

import com.baimurzin.itlabel.core.converter.UserAccountConverter;
import com.baimurzin.itlabel.core.domain.UserAccount;
import com.baimurzin.itlabel.core.repository.UserAccountRepository;
import com.baimurzin.itlabel.core.security.service.AppTokenService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.token.Token;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;


public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    private final UserAccountRepository userService;
    private final AppTokenService tokenService;

    public UsernamePasswordAuthenticationProvider(UserAccountRepository userService, AppTokenService tokenService) {
        this.userService = userService;
        this.tokenService = tokenService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String passwordObj = (String) authentication.getCredentials();

        String email = (String) authentication.getPrincipal();


        UserAccount userAccount = userService.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (passwordObj.isEmpty() || email == null || email.isEmpty()) {
            throw new BadCredentialsException("Authentication error. Password not provided.");
        }


        if (userAccount.getPassword() == null || userAccount.getPassword().isEmpty()) {
            throw new BadCredentialsException("Probably you account no provide password. Use different method to login: facebook or gmail");
        }

        if (bCryptPasswordEncoder.matches(passwordObj, userAccount.getPassword())) {
            Token newToken = tokenService.generateNewToken(userAccount);
            AuthenticationWithToken authToken = new AuthenticationWithToken(UserAccountConverter.convertToUserAccountDetailsDTO(userAccount),
                    null);

            authToken.setToken(newToken);

            SecurityContextHolder.getContext().setAuthentication(authToken);
            tokenService.store(newToken, authToken);
            return authToken;
        } else {
            throw new BadCredentialsException("Bad user password or smth");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
