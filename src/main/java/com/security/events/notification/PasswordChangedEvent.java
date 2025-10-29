package com.security.events.notification;

public record PasswordChangedEvent(
        String userId,
        String email
) {}