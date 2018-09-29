package com.baimurzin.itlabel.core.security;

import com.baimurzin.itlabel.core.converter.UserAccountConverter;
import com.baimurzin.itlabel.core.domain.UserAccount;
import com.baimurzin.itlabel.core.repository.UserAccountRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import java.util.Map;
import java.util.Optional;

@Component
@Transactional
public class FacebookPrincipalExtractor implements PrincipalExtractor {

    @Autowired
    private UserAccountRepository userAccountRepository;

    private static final Logger LOGGER = LoggerFactory.getLogger(FacebookPrincipalExtractor.class);

    public static final String LOGIN_PREFIX = "facebook_";

    private String getAvatarUrl(Map<String, Object> map){
        try {
            return (String) ((Map<String, Object>) ((Map<String, Object>) map.get("picture")).get("data")).get("url");
        } catch (Exception e){
            LOGGER.info("Cannot get image url from {}, returning null", map);
            return null;
        }
    }

    @Override
    public Object extractPrincipal(Map<String, Object> map) {
        String facebookId = (String) map.get("id");
        String maybeImageUrl = getAvatarUrl(map);
        Assert.notNull(facebookId, "facebookId cannot be null");

        UserAccount userAccount;
        Optional<UserAccount> userAccountOpt = userAccountRepository.findByFacebookId(facebookId);
        if (!userAccountOpt.isPresent()){
            String login = getLogin(map);
            userAccount = UserAccountConverter.buildUserAccountEntityForFacebookInsert(facebookId, login, maybeImageUrl);
            userAccount = userAccountRepository.save(userAccount);
        } else {
            userAccount = userAccountOpt.get();
        }

        return UserAccountConverter.convertToUserAccountDetailsDTO(userAccount);
    }

    private String getLogin(Map<String, Object> map) {
        String login = (String) map.get("name");
        Assert.hasLength(login, "facebook name cannot be null");
        login = login.trim();
        String facebookId = (String) map.get("id");
        if (userAccountRepository.findByUsername(login).isPresent()){
            LOGGER.info("User with login '{}' already present in database, so we' ll generate login", login);
            return LOGIN_PREFIX+facebookId;
        } else {
            return login;
        }
    }
}