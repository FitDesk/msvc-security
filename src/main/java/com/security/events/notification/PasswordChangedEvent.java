package com.security.dtos.auth;

public record PasswordChangedEvent(
        String userId,
        String email
) {}