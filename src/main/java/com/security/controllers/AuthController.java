package com.security.controllers;


import com.security.DTOs.LoginRequestDTO;
import com.security.DTOs.LoginResponseDTO;
import com.security.annotations.AuthenticatedAccess;
import com.security.services.AuthService;
import com.security.services.CookieService;
import com.security.services.LoginResponseService;
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

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Autenticación", description = "Endpoints para autenticación segura con cookies HttpOnly")
public class AuthController {

    private final AuthService authService;
    private final CookieService cookieService;
    private final LoginResponseService loginResponseService;

    @Operation(summary = "Iniciar sesión con email", description = "Autentica un usuario y establece cookies seguras")
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @Valid @RequestBody LoginRequestDTO loginRequest,
            HttpServletResponse response) {

        log.info("Login attempt for email: {}", loginRequest.getEmail());

        try {
            LoginResponseDTO authResponse = authService.authenticateUser(loginRequest);
            cookieService.setSecureTokenCookies(response, authResponse);

            Map<String, Object> safeResponse = loginResponseService.createSafeLoginResponse(authResponse);
            log.info("Login successful for email: {}", loginRequest.getEmail());

            return ResponseEntity.ok(safeResponse);

        } catch (
                Exception e) {
            log.error("Login failed for email: {}", loginRequest.getEmail(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(loginResponseService.createErrorResponse("Credenciales inválidas"));
        }
    }

    @Operation(summary = "Refrescar token", description = "Renueva el access token usando el refresh token")
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) {

        try {
            String refreshToken = cookieService.extractRefreshTokenFromCookies(request);

            if (refreshToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(loginResponseService.createErrorResponse("No refresh token found"));
            }

            LoginResponseDTO newTokens = authService.refreshToken(refreshToken);
            cookieService.setSecureTokenCookies(response, newTokens);

            return ResponseEntity.ok(loginResponseService.createSuccessResponse("Token renovado"));

        } catch (
                Exception e) {
            log.error("Token refresh failed", e);
            cookieService.clearTokenCookies(response);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(loginResponseService.createErrorResponse("Token refresh failed"));
        }
    }

    @Operation(summary = "Cerrar sesión", description = "Limpia las cookies seguras")
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(
            HttpServletRequest request,
            HttpServletResponse response) {

        try {
            String accessToken = cookieService.extractAccessTokenFromCookies(request);
            if (accessToken != null) {
                authService.logout(accessToken);
            }

            cookieService.clearTokenCookies(response);
            return ResponseEntity.ok(loginResponseService.createSuccessResponse("Sesión cerrada exitosamente"));

        } catch (
                Exception e) {
            log.error("Logout failed", e);
            cookieService.clearTokenCookies(response);
            return ResponseEntity.ok(loginResponseService.createSuccessResponse("Sesión cerrada"));
        }
    }

    @Operation(summary = "Verificar autenticación")
    @AuthenticatedAccess
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "authenticated", true,
                "email", authentication.getName(),
                "authorities", authentication.getAuthorities()
        ));
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