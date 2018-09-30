package com.baimurzin.itlabel.core.converter;

import com.baimurzin.itlabel.core.domain.RegistrationType;
import com.baimurzin.itlabel.core.domain.UserAccount;
import com.baimurzin.itlabel.core.domain.UserRole;
import com.baimurzin.itlabel.core.dto.UserAccountDetailsDTO;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import static com.baimurzin.itlabel.core.security.util.AuthorityUtils.getDefaultUserRole;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;

public class UserAccountConverter {

    public static UserAccountDetailsDTO convertToUserAccountDetailsDTO(UserAccount userAccount) {
        if (userAccount == null) { return null; }
        return new UserAccountDetailsDTO(
                userAccount.getId(),
                userAccount.getEmail(),
                userAccount.getAvatar(),
                userAccount.getPassword(),
                userAccount.isExpired(),
                userAccount.isLocked(),
                userAccount.isEnabled(),
                new ArrayList<GrantedAuthority>(){{
                    add(convertRole(userAccount.getRole()));
                }},
                userAccount.getUsername()
        );
    }

    private static SimpleGrantedAuthority convertRole(UserRole role) {
        if (role==null) {return null;}
        return new SimpleGrantedAuthority(role.name());
    }

}
