package com.security.dtos.autorization;

import java.util.Set;
import java.util.UUID;

public record RolesResponseDTO(
        UUID userId,
        Set<String> roles
) {
}
