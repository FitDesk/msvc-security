package com.security.controllers;

import com.fitdesk.security.annotations.*;
import com.security.DTOs.LoginRequestDTO;
import com.security.DTOs.LoginResponseDTO;
import com.security.services.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Autenticación", description = "Endpoints para autenticación de usuarios con email y password")
public class AuthController {

    private final AuthService authService;

    @Operation(
            summary = "Iniciar sesión con email",
            description = "Autentica un usuario con email y contraseña"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Login exitoso",
                    content = @Content(schema = @Schema(implementation = LoginResponseDTO.class))
            ),
            @ApiResponse(responseCode = "401", description = "Credenciales inválidas"),
            @ApiResponse(responseCode = "403", description = "Usuario deshabilitado"),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
    })
    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(@Valid @RequestBody LoginRequestDTO loginRequest) {
        log.info("Login attempt for email: {}", loginRequest.getEmail());

        try {
            LoginResponseDTO response = authService.authenticateUser(loginRequest);
            log.info("Login successful for email: {}", loginRequest.getEmail());

            return ResponseEntity.ok(response);

        } catch (
                Exception e) {
            log.error("Login failed for email: {}", loginRequest.getEmail(), e);
            throw e;
        }
    }

    @Operation(
            summary = "Cerrar sesión",
            description = "Invalida el token del usuario actual"
    )
    @AuthenticatedAccess
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestHeader("Authorization") String authHeader) {
        log.info("Logout attempt");

        try {
            String token = extractTokenFromHeader(authHeader);
            authService.logout(token);

            return ResponseEntity.ok(Map.of(
                    "message", "Sesión cerrada exitosamente"
            ));

        } catch (
                Exception e) {
            log.error("Logout failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error al cerrar sesión"));
        }
    }

    @Operation(
            summary = "Obtener información del usuario actual",
            description = "Retorna la información del usuario autenticado"
    )
    @AuthenticatedAccess
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "email", authentication.getName(), // Ahora será el email
                "authorities", authentication.getAuthorities(),
                "authenticated", authentication.isAuthenticated(),
                "principal", authentication.getPrincipal()
        ));
    }

    @Operation(
            summary = "Información del servidor OAuth2",
            description = "Retorna endpoints y configuración del servidor de autorización"
    )
    @GetMapping("/info")
    public ResponseEntity<Map<String, String>> getAuthInfo() {
        return ResponseEntity.ok(Map.of(
                "issuer", "http://localhost:9091",
                "authorization_endpoint", "http://localhost:9091/oauth2/authorize",
                "token_endpoint", "http://localhost:9091/oauth2/token",
                "jwks_uri", "http://localhost:9091/.well-known/jwks.json",
                "userinfo_endpoint", "http://localhost:9091/userinfo",
                "login_method", "email_password"
        ));
    }

    @Operation(
            summary = "Estado del servicio",
            description = "Verifica que el servicio de autenticación esté funcionando"
    )
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getStatus() {
        return ResponseEntity.ok(Map.of(
                "status", "OAuth2 Authorization Server is running",
                "service", "msvc-security",
                "port", 9091,
                "version", "1.0.0",
                "authentication_method", "email_password"
        ));
    }

    private String extractTokenFromHeader(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        throw new IllegalArgumentException("Invalid authorization header");
    }
}