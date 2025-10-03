package com.security.services;

import com.security.dtos.auth.LoginRequestDTO;
import com.security.dtos.auth.LoginResponseDTO;
import com.security.dtos.auth.RegisterRequestDto;


public interface AuthService {

    LoginResponseDTO authenticateUser(LoginRequestDTO loginRequest);

    void logout(String token);


    LoginResponseDTO registerUser(RegisterRequestDto registerRequestDto);

    LoginResponseDTO refreshToken(String refreshToken);

}