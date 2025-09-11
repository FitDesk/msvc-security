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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final TokenService tokenService;
    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;


    private final Set<String> validRefreshTokens = ConcurrentHashMap.newKeySet();
    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();

    @Override
    public LoginResponseDTO authenticateUser(LoginRequestDTO request) {
        log.info("Authenticating user: {}", request.getEmail());

        UserEntity user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new BadCredentialsException("Usuario no encontrado"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Credenciales inválidas");
        }

        if (!user.isEnabled()) {
            throw new BadCredentialsException("Usuario deshabilitado");
        }

        String accessToken = generateAccessToken(user);
        String refreshToken = generateRefreshToken(user);

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

    @Override
    public LoginResponseDTO refreshToken(String refreshToken) {
        log.info("Refreshing token");

        if (!validRefreshTokens.contains(refreshToken)) {
            throw new BadCredentialsException("Refresh token inválido");
        }

        try {
            Jwt jwt = jwtDecoder.decode(refreshToken);
            String email = jwt.getSubject();

            UserEntity user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new BadCredentialsException("Usuario no encontrado"));

            if (!user.isEnabled()) {
                throw new BadCredentialsException("Usuario deshabilitado");
            }

            validRefreshTokens.remove(refreshToken);

            String newAccessToken = generateAccessToken(user);
            String newRefreshToken = generateRefreshToken(user);

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


//    @Override
//    public boolean validateToken(String token) {
//        return tokenService.isTokenValid(token);
//    }

//    private UserEntity findUserByEmail(String email) {
//        return userRepository.findByEmail(email)
//                .orElseThrow(() -> {
//                    log.warn("User not found with email: {}", email);
//                    return new UsernameNotFoundException("Usuario no encontrado con el email: " + email);
//                });
//    }

//    private void validatePassword(String rawPassword, String encodedPassword) {
//        log.debug("Validating password - Raw length: {}, Encoded length: {}",
//                rawPassword != null ? rawPassword.length() : 0,
//                encodedPassword != null ? encodedPassword.length() : 0);
//
//        if (encodedPassword == null || encodedPassword.trim().isEmpty()) {
//            log.error("Encoded password is null or empty");
//            throw new BadCredentialsException("Contraseña incorrecta");
//        }
//
//        if (rawPassword == null || rawPassword.trim().isEmpty()) {
//            log.error("Raw password is null or empty");
//            throw new BadCredentialsException("Contraseña incorrecta");
//        }
//
//        if (!passwordEncoder.matches(rawPassword, encodedPassword)) {
//            log.warn("Password validation failed");
//            throw new BadCredentialsException("Contraseña incorrecta");
//        }
//
//        log.debug("Password validation successful");
//    }


//    private void validateUserStatus(UserEntity user) {
//        if (!user.getEnabled()) {
//            log.warn("User account is disabled: {}", user.getEmail());
//            throw new DisabledException("La cuenta de usuario está deshabilitada");
//        }
//
//        if (!user.isAccountNonLocked()) {
//            log.warn("User account is locked: {}", user.getEmail());
//            throw new DisabledException("La cuenta de usuario está bloqueada");
//        }
//
//        if (!user.isAccountNonExpired()) {
//            log.warn("User account is expired: {}", user.getEmail());
//            throw new DisabledException("La cuenta de usuario ha expirado");
//        }
//    }

//    private String maskToken(String token) {
//        if (token == null || token.length() < 10) {
//            return "***";
//        }
//        return token.substring(0, 10) + "...";
//    }

    private String generateRefreshToken(UserEntity user) {
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("http://localhost:9091")
                .issuedAt(now)
                .expiresAt(now.plus(7, ChronoUnit.DAYS))
                .subject(user.getEmail())
                .claim("type", "refresh")
                .claim("user_id", user.getId().toString())
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public boolean isTokenBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }

    private String generateAccessToken(UserEntity user) {
        Instant now = Instant.now();

        String authorities = user.getRoles().stream()
                .map(role -> "ROLE_" + role.getName())
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("http://localhost:9091")
                .issuedAt(now)
                .expiresAt(now.plus(15, ChronoUnit.MINUTES))
                .subject(user.getEmail())
                .claim("scope", "read write")
                .claim("authorities", authorities)
                .claim("user_id", user.getId().toString())
                .claim("username", user.getUsername())
                .claim("email", user.getEmail())
                .claim("firstName", user.getFirstName())
                .claim("lastName", user.getLastName())
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }


}