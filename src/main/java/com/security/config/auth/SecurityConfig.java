package com.security.config.auth;

import com.security.config.auth.oauth2.OAuth2AuthenticationSuccessHandler;
import com.security.services.oauth2.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer
                                .oidc(Customizer.withDefaults())
                )
                .oauth2ResourceServer(oauth2ResourceServer ->
                        oauth2ResourceServer.jwt(Customizer.withDefaults())
                );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(
            HttpSecurity http,
            CookieAuthenticationFilter cookieAuthenticationFilter,
            OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler,
            OAuth2UserService<OidcUserRequest, OidcUser> customOidcUserService,
            AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) throws Exception {

        return http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                "/actuator/**",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/auth/info",
                                "/auth/status",
                                "/auth/login",
                                "/auth/refresh",
                                "/auth/register",
                                "/oauth2/**",
                                "/login/oauth2/**",
                                "/test/saludo",
                                "/test/notification",
                                "/users/{id}",
                                "/users/by-email/**",
                                "/users/by-role/**",
                                "/"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 ->
                        oauth2.authorizationEndpoint(authorization ->
                                        authorization.authorizationRequestRepository(authorizationRequestRepository)
                                )
                                .userInfoEndpoint(userInfo -> userInfo
                                        .userService(customOAuth2UserService)
                                        .oidcUserService(customOidcUserService)
                                )
                                .successHandler(oAuth2AuthenticationSuccessHandler)
                )
                .oauth2Client(Customizer.withDefaults())
                .addFilterBefore(cookieAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .oauth2ResourceServer(oauth2ResourceServer ->
                        oauth2ResourceServer.jwt(Customizer.withDefaults())
                )
                .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .ignoringRequestMatchers(
                                "/actuator/**",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/auth/info",
                                "/auth/status",
                                "/auth/login",
                                "/auth/refresh",
                                "/auth/register",
                                "/oauth2/**",
                                "/login/oauth2/**",
                                "/test/saludo",
                                "/test/notification",
                                "/users/{id}",
                                "/users/by-email/**",
                                "/users/by-role/**",
                                "/"
                        )
                )
                .build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter scopeConverter = new JwtGrantedAuthoritiesConverter();
        scopeConverter.setAuthorityPrefix("SCOPE_");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>();

            Collection<GrantedAuthority> scopeAuth = scopeConverter.convert(jwt);
            if (scopeAuth != null) {
                authorities.addAll(scopeAuth);
            }

            Object claim = jwt.getClaims().get("authorities");
            if (claim instanceof String authString) {
                String[] parts = authString.trim().split("\\s+");
                for (String part : parts) {
                    if (!part.isBlank()) {
                        authorities.add(new SimpleGrantedAuthority(part));
                    }
                }
            } else if (claim instanceof Collection<?> authCollection) {
                authCollection.forEach(o -> {
                    if (o != null) {
                        authorities.add(new SimpleGrantedAuthority(o.toString()));
                    }
                });
            } else if (claim instanceof Map<?, ?> authMap) {
                authMap.values().forEach(v -> {
                    if (v != null) {
                        authorities.add(new SimpleGrantedAuthority(v.toString()));
                    }
                });
            }

            return authorities;
        });

        return converter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}