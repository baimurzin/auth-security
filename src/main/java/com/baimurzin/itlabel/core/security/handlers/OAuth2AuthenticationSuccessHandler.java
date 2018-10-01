package com.baimurzin.itlabel.core.security.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuth2AuthenticationSuccessHandler.class);

    public static final String DEFAULT = "/";
    public static final String SEPARATOR = ",";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//        super.onAuthenticationSuccess(request, response, authentication);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        response.setStatus(HttpServletResponse.SC_OK);
        DefaultOAuth2AccessToken tokenResponse = new DefaultOAuth2AccessToken(authentication.getDetails().toString());
        String tokenJsonResponse = new ObjectMapper().writeValueAsString(tokenResponse);
        response.addHeader("Content-Type", "application/json");
        response.getWriter().print(tokenJsonResponse);
        //todo make better
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request,
                                        HttpServletResponse response) {

        UriComponents uriComponents = UriComponentsBuilder.newInstance()
                .query(request.getQueryString())
                .build();

        MultiValueMap<String, String> queryParams = uriComponents.getQueryParams();
        String stateEncoded = queryParams.getFirst("state");
        if (stateEncoded == null) {
            return DEFAULT;
        }
        String stateDecoded = null;
        try {
            stateDecoded = URLDecoder.decode(stateEncoded, String.valueOf(StandardCharsets.UTF_8));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        String[] split = stateDecoded.split(SEPARATOR);
        if (split.length != 2){
            return DEFAULT;
        } else {
            return split[1];
        }
    }
}
