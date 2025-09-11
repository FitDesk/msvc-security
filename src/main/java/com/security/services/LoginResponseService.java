package com.security.services;

import com.security.DTOs.LoginResponseDTO;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;

@Service
public class LoginResponseService {


    public Map<String, Object> createSafeLoginResponse(LoginResponseDTO authResponse) {
        return Map.of(
                "success", true,
                "message", authResponse.getMessage(),
                "user", Map.of(
                        "id", authResponse.getUser().getId(),
                        "username", authResponse.getUser().getUsername(),
                        "email", authResponse.getUser().getEmail(),
                        "firstName", authResponse.getUser().getFirstName(),
                        "lastName", authResponse.getUser().getLastName(),
                        "roles", authResponse.getUser().getRoles()
                ),
                "expiresAt", authResponse.getExpiresAt(),
                "timestamp", Instant.now()
        );
    }


    private Map<String, Object> createUserResponse(LoginResponseDTO authResponse) {
        return Map.of(
                "id", authResponse.getUser().getId(),
                "username", authResponse.getUser().getUsername(),
                "email", authResponse.getUser().getEmail(),
                "firstName", authResponse.getUser().getFirstName(),
                "lastName", authResponse.getUser().getLastName(),
                "roles", authResponse.getUser().getRoles()
        );
    }


    public Map<String, Object> createErrorResponse(String message) {
        return Map.of(
                "success", false,
                "message", message,
                "timestamp", Instant.now()
        );
    }

    public Map<String, Object> createSuccessResponse(String message) {
        return Map.of(
                "success", true,
                "message", message,
                "timestamp", Instant.now()
        );
    }
}