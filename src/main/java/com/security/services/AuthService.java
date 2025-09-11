package com.security.services;

import com.security.DTOs.LoginRequestDTO;
import com.security.DTOs.LoginResponseDTO;
import com.security.Entity.UserEntity;

public interface AuthService {

    LoginResponseDTO authenticateUser(LoginRequestDTO loginRequest);

    void logout(String token);

    LoginResponseDTO refreshToken(String refreshToken);

}