package com.security.services.oauth2;

import com.security.entity.RoleEntity;
import com.security.entity.UserEntity;
import com.security.enums.AuthProvider;
import com.security.events.notification.CreatedUserEvent;
import com.security.repository.RoleRepository;
import com.security.repository.UserRepository;
import com.security.services.OAuth2UserInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final KafkaTemplate<String, Object> kafkaTemplate;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        try {
            OAuth2User result = processOAuth2User(userRequest, oAuth2User);
            log.info("CustomOAuth2UserService retornó: {}", result.getClass().getName());
            return result;
        } catch (Exception ex) {
            log.error(" Error procesando usuario OAuth2", ex);
            throw new OAuth2AuthenticationException("Error procesando usuario OAuth2: " + ex.getMessage());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.info("Procesando OAuth2 user desde: {}", registrationId);

        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
                registrationId,
                oAuth2User.getAttributes());

        if (userInfo.getEmail() == null || userInfo.getEmail().isEmpty()) {
            throw new OAuth2AuthenticationException("Email no encontrado en la respuesta de OAuth2");
        }

        log.info(" Email extraído: {}", userInfo.getEmail());

        UserEntity user = userRepository.findByEmail(userInfo.getEmail())
                .map(existingUser -> {
                    log.info(" Usuario existente encontrado: {}", existingUser.getEmail());
                    return updateExistingUser(existingUser, userInfo);
                })
                .orElseGet(() -> {
                    log.info(" Registrando nuevo usuario: {}", userInfo.getEmail());
                    return registerNewUser(userInfo, registrationId);
                });

        if (user == null) {
            throw new OAuth2AuthenticationException("Usuario es NULL después de guardar/actualizar");
        }

        if (user.getId() == null) {
            throw new OAuth2AuthenticationException("Usuario no tiene ID después de guardar");
        }

        log.info("✅ Usuario procesado correctamente: ID={}, Email={}", user.getId(), user.getEmail());

        CustomOAuth2User customUser = new CustomOAuth2User(user, oAuth2User.getAttributes());
        log.info(" Retornando CustomOAuth2User para: {}", user.getEmail());
        return customUser;
    }

    private UserEntity registerNewUser(OAuth2UserInfo userInfo, String provider) {
        log.info(" Registrando nuevo usuario OAuth2: {}", userInfo.getEmail());

        RoleEntity userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> {
                    log.error("Rol USER no encontrado");
                    return new OAuth2AuthenticationException("Rol USER no encontrado");
                });

        UserEntity user = UserEntity.builder()
                .email(userInfo.getEmail())
                .googleId(userInfo.getId())
                .provider(AuthProvider.valueOf(provider.toUpperCase()))
                .enabled(true)
                .roles(Set.of(userRole))
                .build();

        UserEntity savedUser = userRepository.save(user);
        log.info("✅ Usuario guardado: ID={}, Email={}", savedUser.getId(), savedUser.getEmail());

        try {
            publishUserCreatedEvent(savedUser, userInfo);
        } catch (Exception e) {
            log.error(" Error publicando evento de usuario creado (no crítico)", e);
        }

        return savedUser;
    }

    private UserEntity updateExistingUser(UserEntity existingUser, OAuth2UserInfo userInfo) {
        log.info(" Actualizando usuario existente: {}", existingUser.getEmail());

        boolean updated = false;

        if (userInfo.getId() != null && !userInfo.getId().equals(existingUser.getGoogleId())) {
            existingUser.setGoogleId(userInfo.getId());
            updated = true;
        }

        if (updated) {
            UserEntity savedUser = userRepository.save(existingUser);
            log.info("Usuario actualizado: ID={}, Email={}", savedUser.getId(), savedUser.getEmail());

            try {
                publishUserUpdateEvent(savedUser, userInfo);
            } catch (Exception e) {
                log.error("⚠️ Error publicando evento de usuario actualizado (no crítico)", e);
            }

            return savedUser;
        }

        return existingUser;
    }

    private void publishUserCreatedEvent(UserEntity user, OAuth2UserInfo userInfo) {
        CreatedUserEvent event = new CreatedUserEvent(
                user.getId().toString(),
                userInfo.getFirstName(),
                userInfo.getLastName(),
                null,
                null,
                userInfo.getEmail(),
                userInfo.getProfileImageUrl());

        log.info(" Publicando evento de usuario creado: {}", event);
        kafkaTemplate.send("user-created-event-topic", event);
    }

    private void publishUserUpdateEvent(UserEntity user, OAuth2UserInfo userInfo) {
        CreatedUserEvent event = new CreatedUserEvent(
                user.getId().toString(),
                userInfo.getFirstName(),
                userInfo.getLastName(),
                null,
                null,
                userInfo.getEmail(),
                userInfo.getProfileImageUrl());

        kafkaTemplate.send("user-updated-event-topic", event);
    }
}