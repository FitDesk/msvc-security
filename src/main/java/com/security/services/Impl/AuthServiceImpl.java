package com.security.services.Impl;

import com.security.DTOs.LoginRequestDTO;
import com.security.DTOs.LoginResponseDTO;
import com.security.Entity.UserEntity;
import com.security.Mappers.UserMapper;
import com.security.Repository.UserRepository;
import com.security.services.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.security.services.TokenService;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final TokenService tokenService;

    @Override
    public LoginResponseDTO authenticateUser(LoginRequestDTO loginRequest) {
        log.info("Attempting to authenticate user with email: {}", loginRequest.getEmail());

        try {
            UserEntity user = findUserByEmail(loginRequest.getEmail());
            validatePassword(loginRequest.getPassword(), user.getPassword());
            validateUserStatus(user);
            String accessToken = tokenService.generateTokenForUser(user);

            // 5. Crear respuesta usando mapper
            return LoginResponseDTO.builder()
                    .accessToken(accessToken)
                    .tokenType("Bearer")
                    .expiresAt(tokenService.getTokenExpiration(accessToken))
                    .scope("read write")
                    .user(userMapper.toDTO(user))
                    .message("Login exitoso")
                    .build();

        } catch (
                Exception e) {
            log.error("Authentication failed for email: {}", loginRequest.getEmail(), e);
            throw e;
        }
    }

    @Override
    public void logout(String token) {
        log.info("User logged out with token: {}", maskToken(token));
        tokenService.invalidateToken(token);
    }

    @Override
    public boolean validateToken(String token) {
        return tokenService.isTokenValid(token);
    }

    private UserEntity findUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("User not found with email: {}", email);
                    return new UsernameNotFoundException("Usuario no encontrado con el email: " + email);
                });
    }

    private void validatePassword(String rawPassword, String encodedPassword) {
        log.debug("Validating password - Raw length: {}, Encoded length: {}",
                rawPassword != null ? rawPassword.length() : 0,
                encodedPassword != null ? encodedPassword.length() : 0);

        if (encodedPassword == null || encodedPassword.trim().isEmpty()) {
            log.error("Encoded password is null or empty");
            throw new BadCredentialsException("Contraseña incorrecta");
        }

        if (rawPassword == null || rawPassword.trim().isEmpty()) {
            log.error("Raw password is null or empty");
            throw new BadCredentialsException("Contraseña incorrecta");
        }

        if (!passwordEncoder.matches(rawPassword, encodedPassword)) {
            log.warn("Password validation failed");
            throw new BadCredentialsException("Contraseña incorrecta");
        }

        log.debug("Password validation successful");
    }


    private void validateUserStatus(UserEntity user) {
        if (!user.getEnabled()) {
            log.warn("User account is disabled: {}", user.getEmail());
            throw new DisabledException("La cuenta de usuario está deshabilitada");
        }

        if (!user.isAccountNonLocked()) {
            log.warn("User account is locked: {}", user.getEmail());
            throw new DisabledException("La cuenta de usuario está bloqueada");
        }

        if (!user.isAccountNonExpired()) {
            log.warn("User account is expired: {}", user.getEmail());
            throw new DisabledException("La cuenta de usuario ha expirado");
        }
    }

    private String maskToken(String token) {
        if (token == null || token.length() < 10) {
            return "***";
        }
        return token.substring(0, 10) + "...";
    }
}