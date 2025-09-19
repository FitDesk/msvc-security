package com.security.services;

import com.security.dtos.LoginRequestDTO;
import com.security.dtos.LoginResponseDTO;
import com.security.dtos.RegisterRequestDto;


public interface AuthService {

    LoginResponseDTO authenticateUser(LoginRequestDTO loginRequest);

    void logout(String token);


    LoginResponseDTO registerUser(RegisterRequestDto registerRequestDto);

    LoginResponseDTO refreshToken(String refreshToken);

}