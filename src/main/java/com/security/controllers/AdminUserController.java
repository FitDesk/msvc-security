package com.security.controllers;

import com.security.dtos.auth.AuthResponseDTO;
import com.security.dtos.autorization.RoleChangeRequestDTO;
import com.security.dtos.autorization.RolesResponseDTO;
import com.security.annotations.AdminAccess;
import com.security.dtos.roles.RoleDetailsDto;
import com.security.dtos.roles.RoleStatisticsDto;
import com.security.services.UserAccountService;
import com.security.services.UserRoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/admin/users")
@RequiredArgsConstructor
@Tag(name = "Autorizacion", description = "Endpoints para manejo de roles")
public class AdminUserController {

    private final UserRoleService userRoleService;
    private final UserAccountService userAccountService;

    @Operation(summary = "Listar roles de usuario")
    @GetMapping("/{id}/roles")
    @AdminAccess
    public ResponseEntity<RolesResponseDTO> getRoles(@PathVariable UUID id) {
        return ResponseEntity.ok(userRoleService.getUserRoles(id));
    }

    @Operation(summary = "Agregar un rol a un usuario")
    @PostMapping("/{id}/roles")
    @AdminAccess
    public ResponseEntity<AuthResponseDTO> addRole(@PathVariable UUID id,
                                                   @Valid @RequestBody RoleChangeRequestDTO request) {
        return ResponseEntity.ok(userRoleService.addRoleToUser(id, request.role()));
    }

    @Operation(summary = "Quitar un rol a un usuario")
    @DeleteMapping("/{id}/roles")
    @AdminAccess
    public ResponseEntity<AuthResponseDTO> deleteRole(@PathVariable UUID id,
                                                      @RequestBody RoleChangeRequestDTO requestDTO) {
        return ResponseEntity.ok(userRoleService.removeRoleFromUser(id, requestDTO.role()));
    }

    @Operation(summary = "Desactivar cuenta de usuario")
    @PatchMapping("/{id}/deactivate")
    @AdminAccess
    public ResponseEntity<AuthResponseDTO> deactivate(@PathVariable UUID id,
                                                      @RequestParam(required = false) String reason,
                                                      Authentication authentication) {
        String admin = authentication != null ? authentication.getName() : "system";

        return ResponseEntity.ok(userAccountService.deactivateUser(id, reason, admin));
    }

    @Operation(summary = "Activar cuenta de usuario")
    @PatchMapping("/{id}/activate")
    @AdminAccess
    public ResponseEntity<AuthResponseDTO> activate(@PathVariable UUID id,
                                                    Authentication authentication) {
        String admin = authentication != null ? authentication.getName() : "system";

        return ResponseEntity.ok(userAccountService.activateUser(id, admin));
    }

    @Operation(summary = "Obtener estadísticas de usuarios por roles y estados")
    @GetMapping("")
    @AdminAccess
    public ResponseEntity<RoleStatisticsDto> getUserStatistics() {
        return ResponseEntity.ok(userRoleService.getUserStatistics());
    }

    @Operation(summary = "Obtener lista de roles con descripciones")
    @GetMapping("/roles")
    @AdminAccess
    public ResponseEntity<List<RoleDetailsDto>> getRoleDetails() {
        return ResponseEntity.ok(userRoleService.getRoleDetails());
    }

    @Operation(summary = "Obtener estadísticas de usuarios")
    @GetMapping("/provider")
    @AdminAccess
    public ResponseEntity<Map<String, Object>> getUserProviderStatistics() {
        return ResponseEntity.ok(userAccountService.getUserStatistics());
    }

}
