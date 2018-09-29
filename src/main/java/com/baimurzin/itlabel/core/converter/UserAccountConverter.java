package com.baimurzin.itlabel.core.converter;

import com.baimurzin.itlabel.core.domain.RegistrationType;
import com.baimurzin.itlabel.core.domain.UserAccount;
import com.baimurzin.itlabel.core.domain.UserRole;
import com.baimurzin.itlabel.core.dto.UserAccountDetailsDTO;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import static com.baimurzin.itlabel.core.security.filter.AuthorityUtils.getDefaultUserRole;

import java.util.Collections;

public class UserAccountConverter {

    public static UserAccountDetailsDTO convertToUserAccountDetailsDTO(UserAccount userAccount) {
        if (userAccount == null) { return null; }
        return new UserAccountDetailsDTO(
                userAccount.getId(),
                userAccount.getUsername(),
                userAccount.getAvatar(),
                userAccount.getPassword(),
                userAccount.isExpired(),
                userAccount.isLocked(),
                userAccount.isEnabled(),
                Collections.singletonList(convertRole(userAccount.getRole())),
                userAccount.getEmail(),
                userAccount.getFacebookId()
        );
    }

    private static SimpleGrantedAuthority convertRole(UserRole role) {
        if (role==null) {return null;}
        return new SimpleGrantedAuthority(role.name());
    }

    public static UserAccount buildUserAccountEntityForFacebookInsert(String facebookId, String login, String maybeImageUrl) {
        final boolean expired = false;
        final boolean locked = false;
        final boolean enabled = true;

        final UserRole newUserRole = getDefaultUserRole();

        return new UserAccount(
                RegistrationType.FACEBOOK,
                login,
                null,
                maybeImageUrl,
                expired,
                locked,
                enabled,
                newUserRole,
                null,
                facebookId
        );
    }
}
