package com.baimurzin.itlabel.core.security.handlers;

import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    public static final String DEFAULT = "/";
    public static final String SEPARATOR = ",";

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
