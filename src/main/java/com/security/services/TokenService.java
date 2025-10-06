package com.security.services;

import com.security.entity.UserEntity;

public interface TokenService {
    String generateRefreshToken(UserEntity user);

    String generateAccessToken(UserEntity user);
}
