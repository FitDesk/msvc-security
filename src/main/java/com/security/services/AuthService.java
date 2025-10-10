package com.security.services;

import com.security.dtos.auth.ChangePasswordRequestDto;
import com.security.dtos.auth.LoginRequestDTO;
import com.security.dtos.auth.LoginResponseDTO;
import com.security.dtos.auth.RegisterRequestDto;
import com.security.entity.UserEntity;


public interface AuthService {
    LoginResponseDTO authenticateUser(LoginRequestDTO loginRequest);
    void logout(String token);
    LoginResponseDTO registerUser(RegisterRequestDto registerRequestDto);
    LoginResponseDTO refreshToken(String refreshToken);
    LoginResponseDTO createTokensForOAuth2User(UserEntity user);
    void changePassword(ChangePasswordRequestDto request, String userEmail);


}