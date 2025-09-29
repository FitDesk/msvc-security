package com.security.events;

public record CreatedUserEvent(
        String userId,
        String firstName,
        String lastName,
        String dni,
        String phone
) {
}
