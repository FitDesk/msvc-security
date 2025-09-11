package com.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;
/**
 * Restringe el acceso a usuarios con rol ADMIN o USER.
 *
 * <p>Ejemplo de uso:</p>
 * <pre>
 * {@code
 * @GetMapping("/memberships/plans")
 * @AdminOrUserAccess
 * public List<MembershipPlanDTO> getAvailablePlans() {
 *     // Solo administradores y usuarios regulares pueden ver los planes de membresía
 *     return membershipService.findAllPlans();
 * }
 * }
 * </pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasRole('ADMIN') or hasRole('USER')")
@Documented
public @interface AdminOrUserAccess {
}