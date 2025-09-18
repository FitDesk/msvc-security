package com.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;
/**
 * Permite a un usuario acceder únicamente a sus propios recursos basándose en su ID.
 *
 * <p>El ID del usuario debe estar disponible como un parámetro llamado {@code userId}
 * en el método controlador.</p>
 *
 * <p>Ejemplo de uso:</p>
 * <pre>
 * {@code
 * @GetMapping("/users/{userId}/profile")
 * @UserOwnResourceAccess
 * public UserProfileDTO getUserProfile(@PathVariable Long userId) {
 *     // Un usuario solo puede ver su propio perfil
 *     return userService.findProfileById(userId);
 * }
 * }
 * </pre>
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize(" hasRole('USER') AND #userId == authentication.principal.id")
@Documented
public @interface UserOwnResourceAccess {
}