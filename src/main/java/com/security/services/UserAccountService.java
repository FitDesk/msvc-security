package com.security.services;

import com.security.dtos.auth.AuthResponseDTO;

import java.util.UUID;

public interface UserAccountService {
    AuthResponseDTO deactivateUser(UUID userId, String reason, String admin);

    AuthResponseDTO activateUser(UUID userId, String admin);
}
