package com.security.services;

import com.security.Entity.UserEntity;

import java.time.Instant;

public interface TokenService {

    String generateTokenForUser(UserEntity user);

    Instant getTokenExpiration(String token);

    boolean isTokenValid(String token);

    void invalidateToken(String token);
}