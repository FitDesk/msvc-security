package com.security.config.auth.oauth2;

import com.security.entity.UserEntity;
import com.security.services.AuthService;
import com.security.services.CookieService;
import com.security.services.oauth2.CustomOAuth2User;
import com.security.services.oauth2.CustomOidcUser;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AuthService authService;
    private final CookieService cookieService;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException {

        Object principal = authentication.getPrincipal();
        UserEntity user = null;

        if (principal instanceof CustomOidcUser customOidcUser) {
            user = customOidcUser.getUser();
            log.info("✅ Usuario obtenido desde CustomOidcUser: {}", user.getEmail());
        } else if (principal instanceof CustomOAuth2User customOAuth2User) {
            user = customOAuth2User.getUser();
            log.info("✅ Usuario obtenido desde CustomOAuth2User: {}", user.getEmail());
        } else {
            log.error("❌ Principal NO es CustomOAuth2User ni CustomOidcUser. Tipo: {}", principal.getClass().getName());
            if (principal instanceof OAuth2User oauth2User) {
                log.error("❌ Atributos: {}", oauth2User.getAttributes());
            }

            getRedirectStrategy().sendRedirect(request, response,
                    "http://localhost:5173/auth?error=oauth_user_service_failed");
            return;
        }

        if (user == null) {
            log.error("❌ Usuario es NULL después de obtenerlo del principal");
            getRedirectStrategy().sendRedirect(request, response,
                    "http://localhost:5173/auth?error=oauth_user_null");
            return;
        }

        try {
            var loginResponse = authService.createTokensForOAuth2User(user);
            cookieService.setSecureTokenCookies(response, loginResponse);

            log.info("✅ Cookies establecidas para usuario OAuth2: {}", user.getEmail());

            // ✅ Redirigir al frontend
            String targetUrl = UriComponentsBuilder
                    .fromUriString("http://localhost:5173/auth/callback")
                    .queryParam("success", "true")
                    .build()
                    .toUriString();

            if (response.isCommitted()) {
                log.debug("⚠️ La respuesta ya fue enviada. No se puede redirigir a {}", targetUrl);
                return;
            }

            clearAuthenticationAttributes(request);
            getRedirectStrategy().sendRedirect(request, response, targetUrl);

        } catch (
                Exception e) {
            log.error("❌ Error generando tokens para OAuth2", e);
            getRedirectStrategy().sendRedirect(request, response,
                    "http://localhost:5173/auth?error=token_generation_failed");
        }
    }
}