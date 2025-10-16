package com.security.services;

import com.security.dtos.auth.AuthResponseDTO;

import java.util.Map;
import java.util.UUID;

public interface UserAccountService {
    AuthResponseDTO deactivateUser(UUID userId, String reason, String admin);
    Map<String, Object> getUserStatistics();
    AuthResponseDTO activateUser(UUID userId, String admin);
}
