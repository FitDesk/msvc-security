package com.security.services.oauth2;

import com.security.services.Impl.GoogleOAuth2UserInfoImpl;
import com.security.services.OAuth2UserInfo;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;


import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if ("google".equalsIgnoreCase(registrationId)) {
            return new GoogleOAuth2UserInfoImpl(attributes);
        }
        throw new OAuth2AuthenticationException("Login con " + registrationId + " no está soportado");
    }
}
