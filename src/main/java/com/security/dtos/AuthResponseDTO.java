package com.security.dtos;

import java.time.Instant;

public record AuthResponseDTO(
        boolean success,
        String message,
        Instant timestamp
) {
}
