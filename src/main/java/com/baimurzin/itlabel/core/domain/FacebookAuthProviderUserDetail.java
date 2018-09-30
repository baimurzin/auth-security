package com.baimurzin.itlabel.core.domain;

import lombok.Data;
import lombok.EqualsAndHashCode;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

@Entity
@DiscriminatorValue("facebook")
@Data
@EqualsAndHashCode(callSuper = true)
public class FacebookAuthProviderUserDetail extends AuthProviderUserDetail {
}
