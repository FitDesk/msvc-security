package com.security.events;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


public record NotificationEvent(
        String message
) {
}