package com.security.DTOs;

import lombok.*;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleDTO {

    private UUID id;

    private String name;

    private String description;
}