package com.security.DTOs;

import jakarta.validation.constraints.NotBlank;

public record RoleChangeRequestDTO(
        @NotBlank(message = "El nombre del rol es requerido")
        String role
) {
}
