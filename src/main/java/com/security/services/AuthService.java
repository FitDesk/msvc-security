package com.security.services;

import com.security.DTOs.LoginRequestDTO;
import com.security.DTOs.LoginResponseDTO;

public interface AuthService {

    LoginResponseDTO authenticateUser(LoginRequestDTO loginRequest);

    void logout(String token);

    boolean validateToken(String token);
}