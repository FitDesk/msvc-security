package com.security.services.oauth2;

import com.security.entity.UserEntity;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.Map;

@Getter
@RequiredArgsConstructor
public class CustomOidcUser implements OidcUser {
    private final CustomOAuth2User customOAuth2User;
    private final OidcIdToken idToken;

    @Override
    public Map<String, Object> getClaims() {
        return idToken.getClaims();
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return null;
    }

    @Override
    public OidcIdToken getIdToken() {
        return idToken;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return customOAuth2User.getAttributes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return customOAuth2User.getAuthorities();
    }

    @Override
    public String getName() {
        return customOAuth2User.getName();
    }

    public UserEntity getUser() {
        return customOAuth2User.getUser();
    }

}