package com.security.DTOs;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequestDto(
        @NotBlank(message = "El primer nombre es obligatorio")
        @Size(max = 50, message = "El primer nombre es demasiado largo")
        String firstName,

        @NotBlank(message = "El apellido es obligatorio")
        @Size(max = 50, message = "El apellido es demasiado largo")
        String lastName,

        @NotBlank(message = "El email es obligatorio")
        @Email(message = "El formato del email no es válido")
        String email,

        @NotBlank(message = "El DNI es obligatorio")
        @Pattern(regexp = "\\d{6,9}", message = "El DNI debe contener sólo dígitos (6-9 digitos)")
        String dni,

        @NotBlank(message = "La contraseña es obligatoria")
        @Size(min = 8, message = "La contraseña debe tener al menos 8 caracteres")
        String password,
        @NotBlank(message = "El telefono es obligatorio")
        @Size(min = 9, max = 9, message = "El telefono debe tener 9 digitos")
        String phone
) {
}
