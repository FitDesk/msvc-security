package com.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;

/**
 * Restringe el acceso únicamente a usuarios con rol TRAINER.
 *
 * <p>Ejemplo de uso:</p>
 * <pre>
 * {@code
 * @GetMapping("/trainers/dashboard")
 * @TrainerAccess
 * public ResponseEntity<DashboardDTO> getTrainerDashboard() {
 *     // Solo accesible por entrenadores
 *     return ResponseEntity.ok(dashboardService.getTrainerDashboard());
 * }
 * }
 * </pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasRole('TRAINER')")
@Documented
public @interface TrainerAccess {
}