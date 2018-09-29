package com.baimurzin.itlabel.core.domain;


import lombok.Data;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.Date;


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
    private String email;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "registration_type")
    private RegistrationType registrationType;

    private String facebookId;

    private Date lastAccess;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "role")
    private UserRole role; // synonym to "authority"


    public UserAccount() { }

    public UserAccount(RegistrationType creationType, String username, String password, String avatar, boolean expired, boolean locked, boolean enabled, UserRole role, String email, String facebookId) {
        this.registrationType = creationType;
        this.username = username;
        this.password = password;
        this.avatar = avatar;
        this.expired = expired;
        this.locked = locked;
        this.enabled = enabled;
        this.role = role;
        this.email = email;
        this.facebookId = facebookId;
    }

}
