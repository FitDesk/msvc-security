package com.security.controllers;

import com.security.dtos.autorization.UserDTO;
import com.security.dtos.chat.SimpleUserDto;
import com.security.services.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Tag(name = "Usuarios Públicos", description = "Endpoints públicos para consulta de usuarios")
public class UserPublicController {

    private final UserService userService;

    @Operation(summary = "Obtener usuario por ID")
    @GetMapping("/{id}")
    public UserDTO getUserById(@PathVariable UUID id) {
        return userService.getUserById(id);
    }

    @Operation(summary = "Obtener usuario por email")
    @GetMapping("/by-email/{email}")
    public UserDTO getUserByEmail(@PathVariable String email) {
        return userService.getUserByEmail(email);
    }

    @Operation(summary = "Obtener usuarios por rol")
    @GetMapping("/by-role/{role}")
    public List<SimpleUserDto> getUsersByRole(@PathVariable String role) {
        return userService.getUsersByRole(role);
    }
}