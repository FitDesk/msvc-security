package com.security.services;

import com.security.dtos.auth.AuthResponseDTO;
import com.security.dtos.autorization.RolesResponseDTO;
import com.security.dtos.roles.RoleDetailsDto;
import com.security.dtos.roles.RoleStatisticsDto;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface UserRoleService {
    RolesResponseDTO getUserRoles(UUID userId);
    AuthResponseDTO addRoleToUser(UUID userId, String roleName);
    AuthResponseDTO removeRoleFromUser(UUID userId, String roleName);
    RoleStatisticsDto getUserStatistics();
    List<RoleDetailsDto> getRoleDetails();

}
