package com.security.events.notification;

public record CreatedUserEvent(
        String userId,
        String firstName,
        String lastName,
        String dni,
        String phone
) {
}
