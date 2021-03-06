package com.baimurzin.itlabel.core.security.facebook;

import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.baimurzin.itlabel.core.security.util.AuthorityUtils.getDefaultGrantedAuthority;

public class FacebookAuthoritiesExtractor implements AuthoritiesExtractor {
    @Override
    public List<GrantedAuthority> extractAuthorities(Map<String, Object> map) {
        return Collections.singletonList(getDefaultGrantedAuthority());
    }
}
