package com.baimurzin.itlabel.core.security.facebook;

import com.baimurzin.itlabel.core.converter.UserAccountConverter;
import com.baimurzin.itlabel.core.domain.AuthProviderUserDetail;
import com.baimurzin.itlabel.core.domain.FacebookAuthProviderUserDetail;
import com.baimurzin.itlabel.core.domain.UserAccount;
import com.baimurzin.itlabel.core.domain.UserRole;
import com.baimurzin.itlabel.core.repository.AuthProviderUserDetailRepository;
import com.baimurzin.itlabel.core.repository.UserAccountRepository;
import com.baimurzin.itlabel.core.security.exception.CommonSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

import static com.baimurzin.itlabel.core.security.util.AuthorityUtils.getDefaultUserRole;

@Component
@Transactional
public class FacebookPrincipalExtractor implements PrincipalExtractor {

    private static final Logger log = LoggerFactory.getLogger(FacebookPrincipalExtractor.class);

    @Autowired
    private UserAccountRepository userAccountRepository;

    @Autowired
    private AuthProviderUserDetailRepository authProviderUserDetailRepository;

    private static final Logger LOGGER = LoggerFactory.getLogger(FacebookPrincipalExtractor.class);

    public static final String LOGIN_PREFIX = "facebook_";

    private String getAvatarUrl(Map<String, Object> map) {
        try {
            return (String) ((Map<String, Object>) ((Map<String, Object>) map.get("picture")).get("data")).get("url");
        } catch (Exception e) {
            LOGGER.info("Cannot get image url from {}, returning null", map);
            return null;
        }
    }

    @Override
    @Transactional
    public Object extractPrincipal(Map<String, Object> map) {
        String facebookId = (String) map.get("id");
        String maybeImageUrl = getAvatarUrl(map);
        Assert.notNull(facebookId, "facebookId cannot be null");
        String name = (String) map.get("name");
        String gender = (String) map.get("gender");
        Date birthDay = getBirthDay(map);
        String email = getEmail(map);

        UserAccount userAccount;
        Optional<UserAccount> userAccountOpt = userAccountRepository.findByEmail(email);
        if (!userAccountOpt.isPresent()) {
            //create
            final boolean expired = false;
            final boolean locked = false;
            final boolean enabled = true;

            final UserRole newUserRole = getDefaultUserRole();

            userAccount = new UserAccount();
            userAccount.setAvatar(maybeImageUrl);
            userAccount.setEmail(email);
            userAccount.setEnabled(enabled);
            userAccount.setExpired(expired);
            userAccount.setLocked(locked);
            userAccount.setLastAccess(new Date());
            userAccount.setRole(newUserRole);
            userAccount.setUsername(name);

            AuthProviderUserDetail authProviderUserDetail = new FacebookAuthProviderUserDetail();
            authProviderUserDetail.setAvatar(maybeImageUrl);
            authProviderUserDetail.setEmail(email);
            authProviderUserDetail.setGender(gender);
            authProviderUserDetail.setName(name);
            authProviderUserDetail.setProviderId(facebookId);
            authProviderUserDetailRepository.save(authProviderUserDetail);

            userAccount.setAuthProviderUserDetails(new ArrayList<AuthProviderUserDetail>() {{
                add(authProviderUserDetail);
            }});

            userAccount = userAccountRepository.save(userAccount);
        } else {
            //TODO create composite key from provider ID and provider type
            userAccount = userAccountOpt.get();
            //if account exist, but facebook provider not
            Optional<AuthProviderUserDetail> facebookProviderUserDetail = userAccount.getAuthProviderUserDetails().stream()
                    .filter(authProviderUserDetail -> authProviderUserDetail.getProviderType().equals("facebook"))
                    .findFirst();
            if (!facebookProviderUserDetail.isPresent()) {
                AuthProviderUserDetail authProviderUserDetail = new FacebookAuthProviderUserDetail();
                authProviderUserDetail.setAvatar(maybeImageUrl);
                authProviderUserDetail.setEmail(email);
                authProviderUserDetail.setGender(gender);
                authProviderUserDetail.setName(name);
                authProviderUserDetail.setProviderId(facebookId);
                authProviderUserDetailRepository.save(authProviderUserDetail);
            }
            //todo optimize this logic
        }

        return UserAccountConverter.convertToUserAccountDetailsDTO(userAccount);
    }

    private Date getBirthDay(Map<String, Object> map) {
        String birthday = (String) map.get("birthday");
        if (birthday == null) {
            log.info("No birthday extracted from fb account.", map);
            return null;
        }
        SimpleDateFormat formatter = new SimpleDateFormat("MM/dd/yyyy");
        try {
            return formatter.parse(birthday);
        } catch (ParseException e) {
            log.error("Cannot ", new CommonSecurityException(e));
            return null;
        }
    }

    private String getEmail(Map<String, Object> map) {
        return (String) map.get("email");
    }
}
