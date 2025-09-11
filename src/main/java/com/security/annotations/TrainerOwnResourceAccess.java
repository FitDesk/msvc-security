package com.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;
/**
 * Permite a un entrenador acceder únicamente a sus propios recursos basándose en su ID.
 *
 * <p>El ID del entrenador debe estar disponible como un parámetro llamado {@code userId}
 * en el método controlador.</p>
 *
 * <p>Ejemplo de uso:</p>
 * <pre>
 * {@code
 * @GetMapping("/trainers/{userId}/profile")
 * @TrainerOwnResourceAccess
 * public TrainerProfileDTO getTrainerProfile(@PathVariable Long userId) {
 *     // Un entrenador solo puede ver o editar su propio perfil
 *     return trainerService.findProfileById(userId);
 * }
 * }
 * </pre>
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasRole('TRAINER') AND #userId == authentication.principal.id")
@Documented
public @interface TrainerOwnResourceAccess {
}