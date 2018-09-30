package com.baimurzin.itlabel.core.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;

/**
 * Internal class for Spring Security, it shouldn't be passed to browser via Rest API
 */

@EqualsAndHashCode(callSuper = true)
@Data
public class UserAccountDetailsDTO extends UserAccountDTO implements UserDetails {

    private String password; // password hash
    private boolean expired;
    private boolean locked;
    private boolean enabled; // synonym to "confirmed"

    private Collection<GrantedAuthority> roles = new HashSet<>();
    private String email;


    public UserAccountDetailsDTO() {}

    public UserAccountDetailsDTO(
            Long id,
            String email,
            String avatar,
            String password,
            boolean expired,
            boolean locked,
            boolean enabled,
            Collection<GrantedAuthority> roles,
            String name
    ) {
        super(id, email, avatar, name);
        this.password = password;
        this.expired = expired;
        this.locked = locked;
        this.enabled = enabled;
        this.roles = roles;
        this.email = email;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return super.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return !expired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
