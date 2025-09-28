package com.security.services.Impl;

import com.security.events.NotificationEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
public class NotificationServiceImpl {
    private final KafkaTemplate<String, NotificationEvent> kafkaTemplate;

    @Transactional
    public void sendNotification(String message) {
        log.info("Antes de publicar el mensaje");
        NotificationEvent event = new NotificationEvent(message);
        kafkaTemplate.send("user-created-event-topic", event);
        log.info("Mensaje enviado {}", event);
    }

}
