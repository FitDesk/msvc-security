package com.security.services.Impl;

import com.security.dtos.trainer.TrainerRegistrationRequest;
import com.security.dtos.trainer.TrainerRegistrationResponse;
import com.security.entity.RoleEntity;
import com.security.entity.UserEntity;
import com.security.enums.AuthProvider;
import com.security.events.classes.TrainerCreatedEvent;
import com.security.repository.RoleRepository;
import com.security.repository.UserRepository;
import com.security.services.TrainerService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.common.errors.DuplicateResourceException;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class TrainerServiceImpl implements TrainerService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final KafkaTemplate<String, Object> kafkaTemplate;

    private static final String TRAINER_ROLE = "TRAINER";


    @Transactional
    @Override
    public TrainerRegistrationResponse registerTrainer(TrainerRegistrationRequest request) {
        log.info("Iniciando registro de trainer con email: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateResourceException("El email ya está registrado");
        }

        RoleEntity trainerRole = roleRepository.findByName(TRAINER_ROLE)
                .orElseThrow(() -> new IllegalStateException("Rol TRAINER no encontrado en el sistema"));

        UserEntity user = UserEntity.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .provider(AuthProvider.LOCAL)
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .roles(Set.of(trainerRole))
                .build();

        UserEntity savedUser = userRepository.save(user);
        log.info("Usuario trainer creado con ID: {}", savedUser.getId());

        publishTrainerCreatedEvent(savedUser, request);

        return TrainerRegistrationResponse.builder()
                .id(savedUser.getId())
                .email(savedUser.getEmail())
                .message("Trainer registrado exitosamente")
                .build();
    }

    private void publishTrainerCreatedEvent(UserEntity user, TrainerRegistrationRequest request) {
        TrainerCreatedEvent event = TrainerCreatedEvent.create(
                user.getId(),
                user.getEmail(),
                request.getFirstName(),
                request.getLastName(),
                request.getDni(),
                request.getPhone()
        );

        kafkaTemplate.send("trainer-created-event-topic", event)
                .whenComplete((result, ex) -> {
                    if (ex == null) {
                        log.info("Evento publicado correctamente - userId: {} , partition {} ,offset: {}",
                                user.getId(),
                                result.getRecordMetadata().partition(),
                                result.getRecordMetadata().offset());
                    } else {
                        log.error("Error al publicar evento para userId {}", user.getId(), ex);
                    }
                });
    }

    public void compensateTrainerCreation(UUID userId) {
        log.warn("Compensando creación de trainer para userId: {}", userId);
        userRepository.findById(userId).ifPresent(user -> {
            user.setEnabled(false);
            userRepository.save(user);
            log.info("Usuario deshabilitado como compensación: {}", userId);
        });
    }
}