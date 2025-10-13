package com.security.services.Impl;

import com.security.dtos.autorization.UserDTO;
import com.security.dtos.chat.SimpleUserDto;
import com.security.entity.UserEntity;
import com.security.mappers.UserMapper;
import com.security.repository.UserRepository;
import com.security.services.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;

    @Transactional(readOnly = true)
    @Override
    public UserDTO getUserById(UUID id) {

        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con id: " + id));
        return userMapper.toDTO(user);
    }

    @Transactional(readOnly = true)
    @Override
    public UserDTO getUserByEmail(String email) {

        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no enconrado con email " + email));
        return userMapper.toDTO(user);
    }

    @Transactional(readOnly = true)
    @Override
    public List<SimpleUserDto> getUsersByRole(String roleName) {
        log.info("Buscando usuarios con rol: {}", roleName);

        List<UserEntity> users = userRepository.findAll().stream()
                .filter(user -> user.getRoles().stream()
                        .anyMatch(role -> role.getName().equalsIgnoreCase(roleName)))
                .toList();

        log.info("✅ Se encontraron {} usuarios con rol {}", users.size(), roleName);
        log.info(users.toString());

        return users.stream()
                .map(userMapper::toSimpleDto).toList();
    }
}
