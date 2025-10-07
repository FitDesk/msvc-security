package com.security.services.Impl;

import com.security.dtos.auth.LoginResponseDTO;
import com.security.services.CookieService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class CookieServiceImpl implements CookieService {
    @Value("${app.cookie.domain:localhost}")
    private String cookieDomain;

    @Value("${app.cookie.secure:false}")
    private boolean cookieSecure;

    @Value("${app.cookie.access-token-max-age:900}")
    private int accessTokenMaxAge;

    @Value("${app.cookie.refresh-token-max-age:604800}")
    private int refreshTokenMaxAge;

    @Override
    public void setSecureTokenCookies(HttpServletResponse response, LoginResponseDTO authResponse) {
        setSecureCookie(response, "access_token", authResponse.getAccessToken(), accessTokenMaxAge);

        setSecureCookie(response, "refresh_token", authResponse.getRefreshToken(), refreshTokenMaxAge);

        log.debug("Secure cookies set for user: {}", authResponse.getUser().getEmail());
    }

    @Override
    public void clearTokenCookies(HttpServletResponse response) {
        clearCookie(response, "access_token");
        clearCookie(response, "refresh_token");
        log.debug("Token cookies cleared");
    }

    @Override
    public String extractAccessTokenFromCookies(HttpServletRequest request) {
        return extractTokenFromCookies(request, "access_token");
    }

    @Override
    public String extractRefreshTokenFromCookies(HttpServletRequest request) {
        return extractTokenFromCookies(request, "refresh_token");
    }

    private String extractTokenFromCookies(HttpServletRequest request, String tokenName) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (tokenName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private void setSecureCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(cookieSecure);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        if (!"localhost".equals(cookieDomain)) {
            cookie.setDomain(cookieDomain);
        }
        response.addCookie(cookie);
        log.debug("Cookie '{}' establecida con maxAge={}, secure={}, path={}, domain={}",
                name, maxAge, cookieSecure, cookie.getPath(), cookie.getDomain());
        /**
         * SameSite previene ataques de CSRF -> Cross Site Request Forgery
         * 
         * Strict -> Las cookies solo se envian en solicitudes realizadas desde el mismo dominio, no se recomineda
         * si el front y el back esta en diferentes dominios
         * 
         * Lax -> Las cookies se envian en solicitudes de navegador a nivel superior (no fetch en js), adecuada para mayoria de casos
         * 
         * None -> Las cookies se envian en toda las peticiones incluidas las de cross-origin , requiere que la cookie tenga el atributo Secure habilitado osea
         * HTTPS , util si el dominio del back y front es diferente
         */
        String sameSiteValue = cookieSecure ? "None" : "Lax";

        String cookieHeader = String.format("%s=%s; Path=/; HttpOnly; Max-Age=%d; SameSite=%s%s%s",
                name,
                value,
                maxAge,
                sameSiteValue,
                cookieSecure ? "; Secure" : "",
                !"localhost".equals(cookieDomain) ? "; Domain=" + cookieDomain : "");

        response.addHeader("Set-Cookie", cookieHeader);
    }

    private void clearCookie(HttpServletResponse response, String name) {
        Cookie cookie = new Cookie(name, "");
        cookie.setMaxAge(0);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        response.addCookie(cookie);

        response.addHeader("Set-Cookie", String.format("%s=; Path=/; HttpOnly; Max-Age=0", name));
    }

}
