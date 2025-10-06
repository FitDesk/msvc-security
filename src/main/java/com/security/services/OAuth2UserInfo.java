package com.security.services;

public interface OAuth2UserInfo {
    String getId();
    String getEmail();
    String getFirstName();
    String getLastName();
    String getProfileImageUrl();
}
