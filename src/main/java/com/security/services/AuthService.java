package com.security.services;

import com.security.DTOs.LoginRequestDTO;
import com.security.DTOs.LoginResponseDTO;
import com.security.DTOs.RegisterRequestDto;


public interface AuthService {

    LoginResponseDTO authenticateUser(LoginRequestDTO loginRequest);

    void logout(String token);


    LoginResponseDTO registerUser(RegisterRequestDto registerRequestDto);

    LoginResponseDTO refreshToken(String refreshToken);

}