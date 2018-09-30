package com.baimurzin.itlabel.core.domain;


import lombok.Data;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.Date;
import java.util.List;


@Table(name = "users")
@Entity
@Data
public class UserAccount {

    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long id;
    private String username;
    private String password; // hash
    private String avatar;
    private boolean expired;
    private boolean locked;
    private boolean enabled; // synonym to "confirmed"
    @Column(unique = true)
    private String email;
//
//    @NotNull
//    @Enumerated(EnumType.STRING)
//    @Column(name = "registration_type")
//    private RegistrationType registrationType;

    private Date lastAccess;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "role")
    private UserRole role; // synonym to "authority"

    @OneToMany(fetch = FetchType.EAGER)
    private List<AuthProviderUserDetail> authProviderUserDetails;

    public UserAccount() { }


    public UserAccount(String username, String password, String avatar, boolean expired, boolean locked, boolean enabled, String email, Date lastAccess, @NotNull UserRole role) {
        this.username = username;
        this.password = password;
        this.avatar = avatar;
        this.expired = expired;
        this.locked = locked;
        this.enabled = enabled;
        this.email = email;
        this.lastAccess = lastAccess;
        this.role = role;
    }
}
