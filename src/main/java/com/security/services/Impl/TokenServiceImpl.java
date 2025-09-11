package com.security.services.Impl;
import com.security.Entity.UserEntity;
import com.security.services.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenServiceImpl implements TokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;

    @Override
    public String generateTokenForUser(UserEntity user) {
        try {
            Instant now = Instant.now();

            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuer("http://localhost:9091")
                    .issuedAt(now)
                    .expiresAt(now.plus(1, ChronoUnit.HOURS))
                    .subject(user.getEmail())
                    .claim("user_id", user.getId().toString())
                    .claim("username", user.getUsername())
                    .claim("email", user.getEmail())
                    .claim("firstName", user.getFirstName())
                    .claim("lastName", user.getLastName())
                    .claim("authorities", user.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList()))
                    .claim("scope", "read write")
                    .build();

            String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

            log.info("Token generated successfully for user: {}", user.getEmail());
            return token;

        } catch (Exception e) {
            log.error("Error generating token for user: {}", user.getEmail(), e);
            throw new RuntimeException("Error al generar el token", e);
        }
    }

    @Override
    public Instant getTokenExpiration(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getExpiresAt();
        } catch (JwtException e) {
            log.error("Error decoding token to get expiration", e);
            return Instant.now().plusSeconds(3600);
        }
    }

    @Override
    public boolean isTokenValid(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getExpiresAt() != null && jwt.getExpiresAt().isAfter(Instant.now());
        } catch (JwtException e) {
            log.error("Token validation failed", e);
            return false;
        }
    }

    @Override
    public void invalidateToken(String token) {
        log.info("Token invalidated: {}", maskToken(token));
    }

    private String maskToken(String token) {
        if (token == null || token.length() < 10) {
            return "***";
        }
        return token.substring(0, 10) + "...";
    }
}