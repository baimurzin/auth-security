package com.baimurzin.itlabel.core.security.config;

import com.baimurzin.itlabel.core.config.CustomConfig;
import com.baimurzin.itlabel.core.domain.UserRole;
import com.baimurzin.itlabel.core.repository.UserAccountRepository;
import com.baimurzin.itlabel.core.security.CheckedUserInfoTokenServices;
import com.baimurzin.itlabel.core.security.RESTAuthenticationEntryPoint;
import com.baimurzin.itlabel.core.security.StateKeyGeneratorWithRedirectUrl;
import com.baimurzin.itlabel.core.security.authentication.TokenAuthenticationProvider;
import com.baimurzin.itlabel.core.security.authentication.UsernamePasswordAuthenticationProvider;
import com.baimurzin.itlabel.core.security.checks.AppPostAuthenticationChecks;
import com.baimurzin.itlabel.core.security.checks.AppPreAuthenticationChecks;
import com.baimurzin.itlabel.core.security.facebook.FacebookAuthoritiesExtractor;
import com.baimurzin.itlabel.core.security.facebook.FacebookPrincipalExtractor;
import com.baimurzin.itlabel.core.security.handlers.OAuth2AuthenticationSuccessHandler;
import com.baimurzin.itlabel.core.security.handlers.RESTAuthenticationFailureHandler;
import com.baimurzin.itlabel.core.security.handlers.RESTAuthenticationLogoutSuccessHandler;
import com.baimurzin.itlabel.core.security.handlers.RESTAuthenticationSuccessHandler;
import com.baimurzin.itlabel.core.security.service.AppTokenService;
import com.baimurzin.itlabel.core.security.service.UserAccountDetailService;
import com.baimurzin.itlabel.core.security.util.SecurityConstants;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;

import javax.servlet.Filter;

import static com.baimurzin.itlabel.core.security.util.SecurityConstants.API_LOGIN_FACEBOOK;
import static com.baimurzin.itlabel.core.security.util.SecurityConstants.API_LOGOUT_URL;

@EnableOAuth2Client
@EnableWebSecurity
//@EnableAuthorizationServer
//@Import(value = {OAuth2AppClientConfiguration.class})
@Order(6)
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class ResourceConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2ClientContext oauth2ClientContext;

    @Autowired
    private CustomConfig customConfig;

    @Autowired
    private UserAccountDetailService userAccountDetailService;

    @Autowired
    private UserAccountRepository userAccountRepository;

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
        auth.authenticationProvider(tokenAuthenticationProvider())
            .authenticationProvider(usernamePasswordAuthenticationProvider());
    }

//    @Bean
//    public AuthenticationProvider authenticationProvider() {
//        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
//        authenticationProvider.setUserDetailsService(userAccountDetailService);
//        authenticationProvider.setPasswordEncoder(passwordEncoder());
//        authenticationProvider.setPreAuthenticationChecks(appPreAuthenticationChecks());
//        authenticationProvider.setPostAuthenticationChecks(appPostAuthenticationChecks());
//        return authenticationProvider;
//    }

    @Bean
    public AuthenticationProvider tokenAuthenticationProvider() {
        return new TokenAuthenticationProvider(tokenService());
    }

    @Bean
    public AppTokenService tokenService() {
        return new AppTokenService();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.antMatcher("/**").authorizeRequests()
                .antMatchers("/", "/health", "/api/login**", "/webjars/**", "/error**", "/static**").permitAll();

        http.authorizeRequests()
                .antMatchers("/app**").hasAuthority(UserRole.ROLE_USER.name());

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.csrf().disable();

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
    public RESTAuthenticationLogoutSuccessHandler restAuthenticationLogoutSuccessHandler(ObjectMapper objectMapper) {
        return new RESTAuthenticationLogoutSuccessHandler(objectMapper);
    }

//    @Configuration
//    @EnableResourceServer
//    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
//        @Override
//        public void configure(HttpSecurity http) throws Exception {
//            // @formatter:off
//            http.antMatcher("/me").authorizeRequests().anyRequest().authenticated();
//            // @formatter:on
//        }
//    }

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
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // default strength is BCrypt.GENSALT_DEFAULT_LOG2_ROUNDS=10
    }
    @Bean
    public UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider() {
        return new UsernamePasswordAuthenticationProvider(userAccountRepository, tokenService());
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
