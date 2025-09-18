package com.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;


/**
 * Restringe el acceso únicamente a usuarios con rol USER.
 *
 * <p>Ejemplo de uso:</p>
 * <pre>
 * {@code
 * @GetMapping("/classes/available")
 * @UserAccess
 * public List<ClassDTO> getAvailableClasses() {
 *     // Solo clientes regulares pueden ver las clases disponibles
 *     return classService.findAvailable();
 * }
 * }
 * </pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasRole('USER')")
@Documented
public @interface UserAccess {
}