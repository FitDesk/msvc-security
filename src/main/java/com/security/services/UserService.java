package com.security.services;

import com.security.dtos.autorization.UserDTO;

import java.util.List;
import java.util.UUID;

public interface UserService {
    UserDTO getUserById(UUID id);
    UserDTO getUserByEmail(String email);
    List<UserDTO> getUsersByRole(String roleName);
}
