package com.baimurzin.itlabel.core.security.filter;

import com.baimurzin.itlabel.core.security.CheckedUserInfoTokenServices;
import com.baimurzin.itlabel.core.security.ClientResources;
import com.baimurzin.itlabel.core.security.PrincipalExtractorBuilder;
import com.baimurzin.itlabel.core.security.StateKeyGeneratorWithRedirectUrl;
import com.baimurzin.itlabel.core.security.checks.AppPostAuthenticationChecks;
import com.baimurzin.itlabel.core.security.checks.AppPreAuthenticationChecks;
import com.baimurzin.itlabel.core.security.handlers.OAuth2AuthenticationSuccessHandler;
import lombok.Builder;
import lombok.Data;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.util.Assert;

import javax.servlet.Filter;

@Builder
@Data
public class ServletFilterBuilder {

    private AuthorizationCodeResourceDetails client;
    private String path;
    private ClientResources clientResources;
    private PrincipalExtractor principalExtractor;
    private AuthoritiesExtractor authoritiesExtractor;
    private OAuth2ClientContext oauth2ClientContext;
    private AppPreAuthenticationChecks appPreAuthenticationChecks;
    private AppPostAuthenticationChecks appPostAuthenticationChecks;


    public Filter getFilter() {
        Assert.notNull(client, "Client shouldn't be null");
        Assert.notNull(path, "Path shouldn't be null");
        Assert.notNull(clientResources, "ClientResource shouldn't be null");
        Assert.notNull(principalExtractor, "PrincipalExtractor shouldn't be null");
        Assert.notNull(authoritiesExtractor, "AuthoritiesExtractor shouldn't be null");
        Assert.notNull(oauth2ClientContext, "OAuth2ClientContext shouldn't be null");

        OAuth2ClientAuthenticationProcessingFilter oAuth2ClientAuthenticationFilter = new OAuth2ClientAuthenticationProcessingFilter(path);
        AuthorizationCodeAccessTokenProvider authorizationCodeAccessTokenProviderWithUrl = new AuthorizationCodeAccessTokenProvider();
        authorizationCodeAccessTokenProviderWithUrl.setStateKeyGenerator(new StateKeyGeneratorWithRedirectUrl());

        OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(client, oauth2ClientContext);
        oAuth2RestTemplate.setAccessTokenProvider(authorizationCodeAccessTokenProviderWithUrl);
        oAuth2ClientAuthenticationFilter.setRestTemplate(oAuth2RestTemplate);

        UserInfoTokenServices userInfoTokenServices = new CheckedUserInfoTokenServices(
                clientResources.getResource().getUserInfoUri(),
                client.getClientId(),
                principalExtractor,
                appPreAuthenticationChecks,
                appPostAuthenticationChecks
        );
        userInfoTokenServices.setAuthoritiesExtractor(authoritiesExtractor);
        userInfoTokenServices.setRestTemplate(oAuth2RestTemplate);
        oAuth2ClientAuthenticationFilter.setTokenServices(userInfoTokenServices);
        oAuth2ClientAuthenticationFilter.setAuthenticationSuccessHandler(new OAuth2AuthenticationSuccessHandler());
        return oAuth2ClientAuthenticationFilter;
    }
}
