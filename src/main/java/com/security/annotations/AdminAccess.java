package com.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;


/**
 * Restringe el acceso únicamente a usuarios con rol ADMIN.
 *
 * <p>Ejemplo de uso:</p>
 * <pre>
 * {@code
 * @GetMapping("/admin/users")
 * @AdminAccess
 * public List<UserDTO> getAllUsers() {
 *     // Solo administradores pueden acceder a la lista completa de usuarios
 *     return userService.findAll();
 * }
 * }
 * </pre>
 */

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@PreAuthorize("hasRole('ADMIN')")
public @interface AdminAccess {
}