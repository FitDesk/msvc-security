package com.security.services.Impl;

import com.security.events.notification.NotificationEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.CompletableFuture;

@Service
@Slf4j
@RequiredArgsConstructor
public class NotificationServiceImpl {
    private final KafkaTemplate<String, Object> kafkaTemplate;

    @Transactional
    public void sendNotification(String message) {
        try {
            log.info("Enviando notificación: {}", message);
            NotificationEvent event = new NotificationEvent(message);

            // Envío asíncrono con callback
            CompletableFuture<SendResult<String, Object>> future =
                    kafkaTemplate.send("user-created-event-topic", event);

            future.whenComplete((result, exception) -> {
                if (exception == null) {
                    log.info("✅ Notificación enviada exitosamente: offset={}",
                            result.getRecordMetadata().offset());
                } else {
                    log.error("❌ Error enviando notificación", exception);
                }
            });

        } catch (Exception e) {
            log.error("❌ Error en sendNotification", e);
            throw e;
        }
    }
}