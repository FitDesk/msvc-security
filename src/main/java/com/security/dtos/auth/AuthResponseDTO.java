package com.security.dtos.auth;

import java.time.Instant;

public record AuthResponseDTO(
        boolean success,
        String message,
        Instant timestamp
) {
}
