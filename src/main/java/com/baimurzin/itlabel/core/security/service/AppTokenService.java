package com.baimurzin.itlabel.core.security.service;

import com.baimurzin.itlabel.core.domain.UserAccount;
import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.token.KeyBasedPersistenceTokenService;
import org.springframework.security.core.token.Token;

import java.security.SecureRandom;

public class AppTokenService extends KeyBasedPersistenceTokenService {

    private static final Logger logger = LoggerFactory.getLogger(AppTokenService.class);
    private static final Cache restApiAuthTokenCache = CacheManager.getInstance().getCache("restApiAuthTokenCache");

    private static final int HALF_AN_HOUR_IN_MILLISECONDS_TIME_TO_EVICT_EXPIRED_TOKENS = 30 * 60 * 1000;


    public AppTokenService() {
        //todo
        setSecureRandom(new SecureRandom());
        setServerInteger(1);
        setServerSecret("todo-secret-find-out-what-is-it");
    }

    @Scheduled(fixedRate = HALF_AN_HOUR_IN_MILLISECONDS_TIME_TO_EVICT_EXPIRED_TOKENS)
    public void evictExpiredTokens() {
        logger.info("Evicting expired tokens");
        restApiAuthTokenCache.evictExpiredElements();
    }

    public Token generateNewToken(UserAccount userAccount) {
        return allocateToken(userAccount.getEmail());
    }

    public void store(Token token, Authentication authentication) {
        restApiAuthTokenCache.put(new Element(token, authentication));
    }

    public boolean contains(Token token) {
        return restApiAuthTokenCache.get(token) != null;
    }

    public Authentication retrieve(Token token) {
        return (Authentication) restApiAuthTokenCache.get(token).getObjectValue();
    }
}
