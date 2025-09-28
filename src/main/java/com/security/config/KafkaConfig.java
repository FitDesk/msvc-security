package com.security.config;

import com.security.events.NotificationEvent;
import lombok.RequiredArgsConstructor;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.support.serializer.JsonSerializer;

import java.util.HashMap;
import java.util.Map;

@Configuration
@RequiredArgsConstructor
public class KafkaConfig {

    //    private final KafkaProperties kafkaProperties;
    @Value("${spring.kafka.producer.bootstrap-servers}")
    private String bootstrapServers;
    @Value("${spring.kafka.producer.acks}")
    private String acks;
    @Value("${spring.kafka.producer.properties.delivery.timeout.ms}")
    private String deliveryTimeout;
    @Value("${spring.kafka.producer.properties.linger.ms}")
    private String linger;
//    @Value("${spring.kafka.producer.properties.request.timeout.ms}")
//    private String requestTimeout;

    @Value("${spring.kafka.producer.properties.enable.idempotence}")
    private boolean idempotence;
    @Value("${spring.kafka.producer.properties.max.in.flight.requests.per.connection:5}")
    private Integer inflightRequests;

    @Bean
    Map<String, Object> producerConfigs() {
        Map<String, Object> config = new HashMap<>();
        config.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        config.putIfAbsent(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        config.putIfAbsent(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
        config.putIfAbsent(ProducerConfig.ACKS_CONFIG, acks);
        config.putIfAbsent(ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG,deliveryTimeout);
        config.putIfAbsent(ProducerConfig.LINGER_MS_CONFIG, linger);
        config.putIfAbsent(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, idempotence);
        config.putIfAbsent(ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION, inflightRequests);
        config.putIfAbsent(ProducerConfig.RETRIES_CONFIG, 10);


        return config;
    }

    @Bean
    ProducerFactory<String, NotificationEvent> producerFactory() {
        return new DefaultKafkaProducerFactory<>(producerConfigs());
    }

    @Bean
    public KafkaTemplate<String, NotificationEvent> kafkaTemplate() {
        return new KafkaTemplate<String, NotificationEvent>(producerFactory());
    }

    @Bean
    NewTopic createNotificationTopic() {
        return TopicBuilder
                .name("user-created-event-topic")
                .partitions(1)
                .replicas(1)
                .configs(Map.of("min.insync.replicas", "1"))
                .build();
    }

}
