package com.security.services;

import com.security.DTOs.AuthResponseDTO;
import com.security.DTOs.RolesResponseDTO;

import java.util.Set;
import java.util.UUID;

public interface UserRoleService {
    RolesResponseDTO getUserRoles(UUID userId);

    AuthResponseDTO addRoleToUser(UUID userId, String roleName);

    AuthResponseDTO removeRoleFromUser(UUID userId, String roleName);

}
