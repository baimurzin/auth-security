package com.baimurzin.itlabel.core.domain;

import lombok.Data;
import lombok.EqualsAndHashCode;

import javax.persistence.*;
import java.util.Date;

@Table(name = "auth_provider_user_details")
@Entity
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name = "provider_type", discriminatorType = DiscriminatorType.STRING)
@Data
@EqualsAndHashCode
public abstract class AuthProviderUserDetail {


    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long id;

    private String name;

    private String email;

    private String avatar;

    private String providerId;

    private String gender;

    @Column(name = "provider_type", insertable = false, updatable = false)
    private String providerType;

}
