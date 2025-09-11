package com.security.DTOs;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

@Data
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class LoginRequestDTO {
    @NotBlank(message = "El email es obligatorio")
    @Email(message = "El formato del email no es valido")
    private String email;

    @NotBlank(message = "La contraseña es obligatoria")
//    @Size()
    private String password;
}
