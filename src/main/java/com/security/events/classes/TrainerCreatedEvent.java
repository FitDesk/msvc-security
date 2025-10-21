package com.security.events.classes;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.*;

import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

@Builder
public record TrainerCreatedEvent(
        UUID id,
        String email,
        String firstName,
        String lastName,
        String dni,
        String phone,

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSZ", timezone = "UTC")
        Instant occurredAt,

        String eventId,
        String eventType
) implements Serializable {

    public static TrainerCreatedEvent create(UUID userId, String email, String firstName,
                                             String lastName, String dni, String phone) {
        return TrainerCreatedEvent.builder()
                .id(userId)
                .email(email)
                .firstName(firstName)
                .lastName(lastName)
                .dni(dni)
                .phone(phone)
                .occurredAt(Instant.now())
                .eventId(UUID.randomUUID().toString())
                .eventType("TRAINER_CREATED")
                .build();
    }
}