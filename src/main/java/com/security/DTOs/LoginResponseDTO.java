package com.security.DTOs;

import lombok.*;

import java.time.Instant;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponseDTO {

    private String accessToken;
    private String tokenType;
    private Instant expiresAt;
    private String scope;
    private UserDTO user;
    private String message;

}
