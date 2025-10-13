package com.security.services;

import com.security.dtos.autorization.UserDTO;
import com.security.dtos.chat.SimpleUserDto;

import java.util.List;
import java.util.UUID;

public interface UserService {
    UserDTO getUserById(UUID id);
    UserDTO getUserByEmail(String email);
    List<SimpleUserDto> getUsersByRole(String roleName);
}
