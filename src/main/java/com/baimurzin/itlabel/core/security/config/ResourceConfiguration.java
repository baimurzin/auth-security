package com.baimurzin.itlabel.core.security.config;

import com.baimurzin.itlabel.core.config.CustomConfig;
import com.baimurzin.itlabel.core.domain.UserRole;
import com.baimurzin.itlabel.core.security.*;
import com.baimurzin.itlabel.core.security.checks.AppPostAuthenticationChecks;
import com.baimurzin.itlabel.core.security.checks.AppPreAuthenticationChecks;
import com.baimurzin.itlabel.core.security.filter.FacebookAuthoritiesExtractor;
import com.baimurzin.itlabel.core.security.filter.ServletFilterBuilder;
import com.baimurzin.itlabel.core.security.handlers.OAuth2AuthenticationSuccessHandler;
import com.baimurzin.itlabel.core.security.handlers.RESTAuthenticationFailureHandler;
import com.baimurzin.itlabel.core.security.handlers.RESTAuthenticationLogoutSuccessHandler;
import com.baimurzin.itlabel.core.security.handlers.RESTAuthenticationSuccessHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.server.ConfigurableWebServerFactory;
import org.springframework.boot.web.server.ErrorPage;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;

import static com.baimurzin.itlabel.core.security.SecurityConstants.API_LOGIN_FACEBOOK;
import static com.baimurzin.itlabel.core.security.SecurityConstants.API_LOGOUT_URL;

//@EnableOAuth2Client
@EnableWebSecurity
//@EnableAuthorizationServer
@Import(value = {OAuth2AppClientConfiguration.class})
@Order(6)
@Configuration
public class ResourceConfiguration extends WebSecurityConfigurerAdapter {


    @Autowired
    private OAuth2ClientContext oauth2ClientContext;

    @Autowired
    private CustomConfig customConfig;

    @Autowired
    private UserAccountDetailService userAccountDetailService;

    @Autowired
    private RESTAuthenticationEntryPoint restAuthenticationEntryPoint;

    @Autowired
    private RESTAuthenticationSuccessHandler restAuthenticationSuccessHandler;

    @Autowired
    private RESTAuthenticationFailureHandler restAuthenticationFailureHandler;

    @Autowired
    private RESTAuthenticationLogoutSuccessHandler restAuthenticationLogoutSuccessHandler;


    @Autowired
    private FacebookPrincipalExtractor facebookPrincipalExtractor;

    @Autowired
    private AppPostAuthenticationChecks appPostAuthenticationChecks;

    @Autowired
    private AppPreAuthenticationChecks appPreAuthenticationChecks;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userAccountDetailService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        authenticationProvider.setPreAuthenticationChecks(appPreAuthenticationChecks());
        authenticationProvider.setPostAuthenticationChecks(appPostAuthenticationChecks());
        return authenticationProvider;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.antMatcher("/**").authorizeRequests()
                .antMatchers("/", "/h2-console", "/health", "/login**", "/webjars/**", "/error**", "/static**").permitAll();

        http.authorizeRequests()
                .antMatchers("/app**").hasAuthority(UserRole.ROLE_USER.name());

        http.csrf().csrfTokenRepository(csrfTokenRepository());

        http.exceptionHandling().authenticationEntryPoint(restAuthenticationEntryPoint);


        http.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);

        http.formLogin()
                .loginPage(SecurityConstants.API_LOGIN_URL).usernameParameter(SecurityConstants.USERNAME_PARAMETER)
                .passwordParameter(SecurityConstants.PASSWORD_PARAMETER).permitAll()
                .successHandler(restAuthenticationSuccessHandler)
                .failureHandler(restAuthenticationFailureHandler)

                .and().logout().logoutUrl(API_LOGOUT_URL).logoutSuccessHandler(restAuthenticationLogoutSuccessHandler).permitAll();

        http.authorizeRequests().requestMatchers(EndpointRequest.toAnyEndpoint()).permitAll();

        http.headers().frameOptions().disable();

        http.headers().cacheControl().disable();

        // @formatter:on
    }


    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        return CookieCsrfTokenRepository.withHttpOnlyFalse();
    }

    @Bean
    public RESTAuthenticationLogoutSuccessHandler restAuthenticationLogoutSuccessHandler(ObjectMapper objectMapper) {
        return new RESTAuthenticationLogoutSuccessHandler(csrfTokenRepository(), objectMapper);
    }

    @Configuration
    @EnableResourceServer
    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http.antMatcher("/me").authorizeRequests().anyRequest().authenticated();
            // @formatter:on
        }
    }

//    @Bean
//    public FilterRegistrationBean<OAuth2ClientContextFilter> oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
//        FilterRegistrationBean<OAuth2ClientContextFilter> registration = new FilterRegistrationBean<OAuth2ClientContextFilter>();
//        registration.setFilter(filter);
//        registration.setOrder(-100);
//        return registration;
//    }

    @Bean
    @ConfigurationProperties("facebook.client")
    public AuthorizationCodeResourceDetails facebook() {
        AuthorizationCodeResourceDetails authorizationCodeResourceDetails = new AuthorizationCodeResourceDetails();
        authorizationCodeResourceDetails.setPreEstablishedRedirectUri(customConfig.getBaseUrl()+API_LOGIN_FACEBOOK);
        authorizationCodeResourceDetails.setUseCurrentUri(false);
        return authorizationCodeResourceDetails;
    }

    @Bean
    @ConfigurationProperties("facebook.resource")
    public ResourceServerProperties facebookResource() {
        return new ResourceServerProperties();
    }

    private Filter ssoFilter() {
        OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter(API_LOGIN_FACEBOOK);
        OAuth2RestTemplate facebookTemplate = new OAuth2RestTemplate(facebook(), oauth2ClientContext);


        AuthorizationCodeAccessTokenProvider authorizationCodeAccessTokenProviderWithUrl = new AuthorizationCodeAccessTokenProvider();
        authorizationCodeAccessTokenProviderWithUrl.setStateKeyGenerator(new StateKeyGeneratorWithRedirectUrl());

        facebookTemplate.setAccessTokenProvider(authorizationCodeAccessTokenProviderWithUrl);
        facebookFilter.setRestTemplate(facebookTemplate);

        UserInfoTokenServices tokenServices = new CheckedUserInfoTokenServices(
                facebookResource().getUserInfoUri(), facebook().getClientId(),
                facebookPrincipalExtractor, appPreAuthenticationChecks(), appPostAuthenticationChecks());
        tokenServices.setAuthoritiesExtractor(new FacebookAuthoritiesExtractor());
        tokenServices.setRestTemplate(facebookTemplate);
        facebookFilter.setTokenServices(tokenServices);
        facebookFilter.setAuthenticationSuccessHandler(new OAuth2AuthenticationSuccessHandler());
        return facebookFilter;
    }

    @Configuration
    protected static class ServletCustomizer {
        @Bean
        public WebServerFactoryCustomizer<ConfigurableWebServerFactory> customizer() {
            return container -> {
                container.addErrorPages(new ErrorPage(HttpStatus.UNAUTHORIZED, "/unauthenticated"));
            };
        }
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // default strength is BCrypt.GENSALT_DEFAULT_LOG2_ROUNDS=10
    }

    @Bean
    public AppPreAuthenticationChecks appPreAuthenticationChecks() {
        return new AppPreAuthenticationChecks();
    }

    @Bean
    public AppPostAuthenticationChecks appPostAuthenticationChecks() {
        return new AppPostAuthenticationChecks();
    }

}
