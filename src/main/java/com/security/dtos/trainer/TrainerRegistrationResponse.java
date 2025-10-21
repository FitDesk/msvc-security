package com.security.dtos.trainer;

import lombok.*;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TrainerRegistrationResponse {
    private UUID id;
    private String email;
    private String message;
}