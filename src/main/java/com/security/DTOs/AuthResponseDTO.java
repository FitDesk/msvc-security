package com.security.DTOs;

import java.time.Instant;

public record AuthResponseDTO(
        boolean success,
        String message,
        Instant timestamp
) {
}
