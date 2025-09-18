package com.security.annotations;
import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;

/**
 * Permite a un entrenador acceder solo a recursos de usuarios que están asignados como sus clientes.
 *
 * <p>Requiere que exista un método {@code isTrainerOfUser} en un bean llamado {@code securityService}
 * que verifique la relación entrenador-cliente.</p>
 *
 * <p>Ejemplo de uso:</p>
 * <pre>
 * {@code
 * @GetMapping("/clients/{userId}/progress")
 * @TrainerClientAccess
 * public ProgressDTO viewClientProgress(@PathVariable Long userId) {
 *     // Solo el entrenador asignado a este cliente puede ver su progreso
 *     return progressService.getClientProgress(userId);
 * }
 * }
 * </pre>
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasRole('TRAINER') and @securityService.isTrainerOfUser(authentication.principal.id, #userId)")
@Documented
public @interface TrainerClientAccess {
}