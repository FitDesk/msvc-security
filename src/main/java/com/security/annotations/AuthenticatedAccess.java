package com.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;
/**
 * Restringe el acceso a cualquier usuario autenticado, independientemente de su rol.
 *
 * <p>Ejemplo de uso:</p>
 * <pre>
 * {@code
 * @GetMapping("/account/settings")
 * @AuthenticatedAccess
 * public AccountSettingsDTO getAccountSettings() {
 *     // Cualquier usuario autenticado puede acceder a sus ajustes de cuenta
 *     return accountService.getSettingsForCurrentUser();
 * }
 * }
 * </pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("isAuthenticated()")
@Documented
public @interface AuthenticatedAccess {
}