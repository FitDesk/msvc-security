package com.security.services;


import com.security.DTOs.LoginResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface CookieService {
    void setSecureTokenCookies(HttpServletResponse response, LoginResponseDTO authResponse);

    String extractAccessTokenFromCookies(HttpServletRequest request);

    String extractRefreshTokenFromCookies(HttpServletRequest request);

    void clearTokenCookies(HttpServletResponse response);
}