package com.baimurzin.itlabel.core.security.userdetails;

import com.baimurzin.itlabel.core.converter.UserAccountConverter;
import com.baimurzin.itlabel.core.repository.UserAccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class UserAccountDetailService implements UserDetailsService {

    @Autowired
    private UserAccountRepository userAccountRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userAccountRepository
                .findByUsername(username)
                .map(UserAccountConverter::convertToUserAccountDetailsDTO)
                .orElseThrow(() -> new UsernameNotFoundException("User with email '" + username + "' not found"));
    }
}
