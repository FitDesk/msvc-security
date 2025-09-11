package com.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;
/**
 * Restringe el acceso a usuarios con rol ADMIN o TRAINER.
 *
 * <p>Ejemplo de uso:</p>
 * <pre>
 * {@code
 * @GetMapping("/classes")
 * @AdminOrTrainerAccess
 * public List<ClassDTO> getAllClasses() {
 *     // Solo administradores y entrenadores pueden ver todas las clases
 *     return classService.findAll();
 * }
 * }
 * </pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasRole('ADMIN') or hasRole('TRAINER')")
@Documented
public @interface AdminOrTrainerAccess {
}