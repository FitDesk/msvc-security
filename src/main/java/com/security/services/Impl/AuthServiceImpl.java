package com.security.services.Impl;

import com.security.dtos.auth.LoginRequestDTO;
import com.security.dtos.auth.LoginResponseDTO;
import com.security.dtos.auth.RegisterRequestDto;
import com.security.entity.RoleEntity;
import com.security.entity.UserEntity;
import com.security.enums.AuthProvider;
import com.security.events.notification.CreatedUserEvent;
import com.security.exceptions.AuthenticationException;
import com.security.exceptions.RoleNotFoundException;
import com.security.exceptions.UserNotFoundException;
import com.security.mappers.UserMapper;
import com.security.repository.RoleRepository;
import com.security.repository.UserRepository;
import com.security.services.AuthService;
import com.security.services.TokenService;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import io.github.resilience4j.timelimiter.annotation.TimeLimiter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;


@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final UserMapper userMapper;
    private final JwtDecoder jwtDecoder;
    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final TokenService tokenService;


    private final Set<String> validRefreshTokens = ConcurrentHashMap.newKeySet();
    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();

    @Override
    @CircuitBreaker(name = "authServiceCircuitBreaker", fallbackMethod = "authenticateUserFallback")
    @Retry(name = "databaseRetry")
    public LoginResponseDTO authenticateUser(LoginRequestDTO request) {
        log.info("Authenticating user: {}", request.getEmail());

        UserEntity user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException("Usuario no encontrado"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Credenciales inválidas");
        }

        if (!user.isEnabled()) {
            throw new BadCredentialsException("Usuario deshabilitado");
        }

        String accessToken = tokenService.generateAccessToken(user);
        String refreshToken = tokenService.generateRefreshToken(user);

        validRefreshTokens.add(refreshToken);

        return LoginResponseDTO.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                .scope("read write")
                .user(userMapper.toDTO(user))
                .message("Login exitoso")
                .build();
    }

    private LoginResponseDTO authenticateUserFallback(LoginResponseDTO request, Throwable throwable) {
        log.error("Fallback activado para  authenticateUser - Error {}", throwable.getMessage());
        throw new AuthenticationException("Servicio de autenticación no disponible.Intente de nuevo más tarde.");
    }

    @Override
    @CircuitBreaker(name = "authServiceCircuitBreaker", fallbackMethod = "refreshTokenFallback")
    @Retry(name = "databaseRetry")
    public LoginResponseDTO refreshToken(String refreshToken) {
        log.info("Refreshing token");

        if (!validRefreshTokens.contains(refreshToken)) {
            throw new BadCredentialsException("Refresh token inválido");
        }

        try {
            Jwt jwt = jwtDecoder.decode(refreshToken);
            String email = jwt.getSubject();

            UserEntity user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UserNotFoundException("Usuario no encontrado"));

            if (!user.isEnabled()) {
                throw new BadCredentialsException("Usuario deshabilitado");
            }

            validRefreshTokens.remove(refreshToken);

            String newAccessToken = tokenService.generateAccessToken(user);
            String newRefreshToken = tokenService.generateRefreshToken(user);

            validRefreshTokens.add(newRefreshToken);

            return LoginResponseDTO.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .tokenType("Bearer")
                    .expiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                    .scope("read write")
                    .user(userMapper.toDTO(user))
                    .message("Token renovado")
                    .build();

        } catch (
                Exception e) {
            log.error("Error refreshing token", e);
            throw new BadCredentialsException("Refresh token inválido");
        }
    }

    private LoginResponseDTO refreshTokenFallback(String refreshToken, Throwable throwable) {
        log.error("Fallback activado para refreshToken - Error: {}", throwable.getMessage());
        throw new AuthenticationException("Servicio de renovación de tokens no disponible");
    }

    @Override
    public LoginResponseDTO createTokensForOAuth2User(UserEntity user) {
        log.info("Creando tokens para usuarios OAuth2: {}", user.getEmail());

        String accessToken = tokenService.generateAccessToken(user);
        String refreshToken = tokenService.generateRefreshToken(user);

        validRefreshTokens.add(refreshToken);
        return LoginResponseDTO.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                .scope("read write")
                .user(userMapper.toDTO(user))
                .message("Login OAuth2 exitoso")
                .build();
    }

    @Override
    public void logout(String accessToken) {
        log.info("Logging out user");

        try {
            if (accessToken != null && !accessToken.trim().isEmpty()) {
                blacklistedTokens.add(accessToken);

                Jwt jwt = jwtDecoder.decode(accessToken);
                String email = jwt.getSubject();

                validRefreshTokens.removeIf(token -> {
                    try {
                        Jwt refreshJwt = jwtDecoder.decode(token);
                        return email.equals(refreshJwt.getSubject());
                    } catch (
                            Exception e) {
                        return true;
                    }
                });
            }
        } catch (
                Exception e) {
            log.error("Error during logout", e);
        }
    }


    @Override
    @CircuitBreaker(name = "authServiceCircuitBreaker", fallbackMethod = "registerUserFallback")
    @Retry(name = "databaseRetry")
    public LoginResponseDTO registerUser(RegisterRequestDto registerRequestDto) {
        if (userRepository.existsByEmail(registerRequestDto.email())) {
            throw new AuthenticationException("Error al registrar usuario intente de nuevo");
        }


        RoleEntity userRole = roleRepository.findByName("USER").orElseThrow(() -> new RoleNotFoundException("Error al encontrar el rol USER"));


        UserEntity user = UserEntity.builder()
                .email(registerRequestDto.email())
                .password(passwordEncoder.encode(registerRequestDto.password()))
                .provider(AuthProvider.LOCAL)
                .roles(Set.of(userRole))
                .enabled(true)
                .build();

        userRepository.save(user);

        sendUserCreatedEvent(user, registerRequestDto);

        return LoginResponseDTO.builder()
                .accessToken(tokenService.generateAccessToken(user))
                .refreshToken(tokenService.generateRefreshToken(user))
                .tokenType("Bearer")
                .expiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                .scope("read write")
                .user(userMapper.toDTO(user))
                .message("Registro exitoso")
                .build();
    }

    private LoginResponseDTO registerUserFallback(RegisterRequestDto registerRequestDto, Throwable throwable) {
        log.error("Fallback activado para registerUser- Error {}", throwable.getMessage());
        throw new AuthenticationException("Servicio de registro temporalmente no disponible");
    }


    @CircuitBreaker(name = "kafkaCircuitBreaker", fallbackMethod = "sendUserCreatedEventFallback")
    @Retry(name = "kafkaRetry")
    private void sendUserCreatedEvent(UserEntity user, RegisterRequestDto registerRequestDto) {
        CreatedUserEvent event = new CreatedUserEvent(
                user.getId().toString(),
                registerRequestDto.firstName(),
                registerRequestDto.lastName(),
                registerRequestDto.dni(),
                registerRequestDto.phone(),
                registerRequestDto.email(),
                null
        );

        log.info("Enviando evento de usuario creado: {}", event);
        kafkaTemplate.send("user-created-event-topic", event);
        log.info("Evento enviado correctamente");
    }

    private void sendUserCreatedEventFallback(UserEntity user, RegisterRequestDto registerRequestDto, Throwable throwable) {
        log.error("Fallback de Kafka - No se pudo enviar evento de usuario creado. Error: {}", throwable.getMessage());
        log.warn("Evento no enviado será reintentado posteriormente para usuario: {}", user.getEmail());
    }
}