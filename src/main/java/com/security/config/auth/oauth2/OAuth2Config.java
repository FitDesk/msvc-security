package com.security.config.auth.oauth2;

import com.security.services.AuthService;
import com.security.services.CookieService;
import com.security.services.oauth2.CustomOAuth2UserService;
import com.security.services.oauth2.CustomOidcUser;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;


@Configuration
public class OAuth2Config {

    @Bean
    public OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler(
            AuthService authService,
            CookieService cookieService) {
        return new OAuth2AuthenticationSuccessHandler(authService, cookieService);
    }

    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> customOidcUserService(
            CustomOAuth2UserService customOAuth2UserService) {
        return new OidcUserService() {
            @Override
            public OidcUser loadUser(OidcUserRequest userRequest) {
                OAuth2UserRequest oauth2UserRequest = new OAuth2UserRequest(
                        userRequest.getClientRegistration(),
                        userRequest.getAccessToken(),
                        userRequest.getAdditionalParameters()
                );
                OAuth2User oauth2User = customOAuth2UserService.loadUser(oauth2UserRequest);
                if (oauth2User instanceof com.security.services.oauth2.CustomOAuth2User customUser) {
                    return new CustomOidcUser(customUser, userRequest.getIdToken());
                }
                return super.loadUser(userRequest);
            }
        };
    }

    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
        return new HttpSessionOAuth2AuthorizationRequestRepository();
    }
}