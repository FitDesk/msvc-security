package com.security.dtos.autorization;

import lombok.*;

import java.util.Set;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {

    private UUID id;

    private String username;

    private String email;

    private String firstName;

    private String lastName;

    private Boolean enabled;

    private Set<RoleDTO> roles;
}