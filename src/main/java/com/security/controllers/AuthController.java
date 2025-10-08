package com.security.controllers;

import com.security.dtos.auth.AuthResponseDTO;
import com.security.dtos.auth.LoginRequestDTO;
import com.security.dtos.auth.LoginResponseDTO;
import com.security.dtos.auth.RegisterRequestDto;
import com.security.annotations.AuthenticatedAccess;
import com.security.entity.UserEntity;
import com.security.services.AuthService;
import com.security.services.CookieService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Map;


@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Autenticación", description = "Endpoints para autenticación segura con cookies HttpOnly")
public class AuthController {

    private final AuthService authService;
    private final CookieService cookieService;


    @Operation(summary = "Iniciar sesión con email", description = "Autentica un usuario y establece cookies seguras")
    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(
            @Valid @RequestBody LoginRequestDTO loginRequest,
            HttpServletResponse response) {

        log.info("Login attempt for email: {}", loginRequest.getEmail());

        try {
            LoginResponseDTO authResponse = authService.authenticateUser(loginRequest);
            cookieService.setSecureTokenCookies(response, authResponse);

            log.info("Login successful for email: {}", loginRequest.getEmail());

            return ResponseEntity.ok(new AuthResponseDTO(true, "Inicio de sesion correctamente", Instant.now()));

        } catch (
                Exception e) {
            log.error("Login failed for email: {}", loginRequest.getEmail(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthResponseDTO(false, "Login fallido", Instant.now()));
        }
    }

    @Operation(summary = "Refrescar token", description = "Renueva el access token usando el refresh token")
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDTO> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) {

        try {
            String refreshToken = cookieService.extractRefreshTokenFromCookies(request);

            if (refreshToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthResponseDTO(false, "No ha iniciado sesion , intente iniciar sesion", Instant.now()));
            }

            LoginResponseDTO newTokens = authService.refreshToken(refreshToken);
            cookieService.setSecureTokenCookies(response, newTokens);

            return ResponseEntity.ok(new AuthResponseDTO(true, "Token Renovado", Instant.now()));

        } catch (
                Exception e) {
            log.error("Error al renovar el token", e);
            cookieService.clearTokenCookies(response);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthResponseDTO(false, "No se pudo renovar el token", Instant.now()));
        }
    }

    @Operation(summary = "Cerrar sesión", description = "Limpia las cookies seguras")
    @PostMapping("/logout")
    public ResponseEntity<AuthResponseDTO> logout(
            HttpServletRequest request,
            HttpServletResponse response) {

        try {
            String accessToken = cookieService.extractAccessTokenFromCookies(request);
            if (accessToken != null) {
                authService.logout(accessToken);
            }

            cookieService.clearTokenCookies(response);
            return ResponseEntity.ok(new AuthResponseDTO(true, "Sesión cerrada exitosamente", Instant.now()));

        } catch (
                Exception e) {
            log.error("Logout failed", e);
            cookieService.clearTokenCookies(response);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthResponseDTO(false, "Error al cerrar sesión", Instant.now()));
        }
    }


    @PostMapping("/register")
    public ResponseEntity<AuthResponseDTO> register(@Valid @RequestBody RegisterRequestDto registerRequestDto, HttpServletResponse response) {
        try {
            LoginResponseDTO authResponse = authService.registerUser(registerRequestDto);
            cookieService.setSecureTokenCookies(response, authResponse);
            log.info("Registro correcto con el email: {}", registerRequestDto.email());
            return ResponseEntity.status(HttpStatus.CREATED).body(new AuthResponseDTO(true, "Usuario registrado correctamente", Instant.now()));
        } catch (
                ResponseStatusException ex) {
            log.warn("Registro fallido: {}", ex.getMessage());
            throw ex;
        } catch (
                Exception e) {
            log.error("Registro Fallido", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthResponseDTO(false, "Error al registrar cuenta", Instant.now()));
        }
    }

    // Java
    @Operation(summary = "Verificar autenticación")
    @AuthenticatedAccess
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("authenticated", false, "error", "Usuario no autenticado"));
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof org.springframework.security.oauth2.jwt.Jwt jwt) {
            String id = jwt.getClaimAsString("user_id");
            String email = jwt.getClaimAsString("email");
            return ResponseEntity.ok(Map.of(
                    "authenticated", true,
                    "id", id,
                    "email", email,
                    "authorities", authentication.getAuthorities()
            ));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("authenticated", false, "error", "Usuario no autenticado"));
    }


    @Operation(summary = "Estado del servicio")
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getStatus() {
        return ResponseEntity.ok(Map.of(
                "status", "OAuth2 Authorization Server is running",
                "service", "msvc-security",
                "authentication_method", "cookie_based_secure"
        ));
    }
}