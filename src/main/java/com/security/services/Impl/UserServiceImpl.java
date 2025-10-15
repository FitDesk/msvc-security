package com.security.services.Impl;

import com.security.dtos.autorization.UserDTO;
import com.security.dtos.chat.SimpleUserDto;
import com.security.entity.UserEntity;
import com.security.exceptions.RoleNotFoundException;
import com.security.exceptions.UserNotFoundException;
import com.security.mappers.UserMapper;
import com.security.repository.UserRepository;
import com.security.services.UserService;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import io.github.resilience4j.timelimiter.annotation.TimeLimiter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;


@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;

    @CircuitBreaker(name = "userServiceCircuitBreaker", fallbackMethod = "getUserByIdFallback")
    @Retry(name = "databaseRetry")
    @Transactional(readOnly = true)
    @Override
    public UserDTO getUserById(UUID id) {
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con id: " + id));
        return userMapper.toDTO(user);
    }

    public UserDTO getUserByIdFallback(UUID id, Throwable ex) {
        log.error("Error al obtener al usuario con id : {} {}", id, ex.getMessage());
        throw new UserNotFoundException("Error al obtener al usuario con id " + id);
    }

    @CircuitBreaker(name = "userServiceCircuitBreaker", fallbackMethod = "getUserByEmailFallback")
    @Retry(name = "databaseRetry")
    @Transactional(readOnly = true)
    @Override
    public UserDTO getUserByEmail(String email) {

        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no enconrado con email " + email));
        return userMapper.toDTO(user);
    }

    public UserDTO getUserByEmailFallback(String email, Throwable ex) {
        log.error("Error al obtener usuario por email {} ejecutando fallback  {}", email, ex.getMessage());
        throw new UsernameNotFoundException("Usuario no encontrado con email" + email);
    }

    @CircuitBreaker(name = "userServiceCircuitBreaker", fallbackMethod = "getUsersByRoleFallback")
    @Retry(name = "databaseRetry")
    @Transactional(readOnly = true)
    @Override
    public List<SimpleUserDto> getUsersByRole(String roleName) {
        log.info("Buscando usuarios con rol: {}", roleName);

        List<UserEntity> users = userRepository.findAll().stream()
                .filter(user -> user.getRoles().stream()
                        .anyMatch(role -> role.getName().equalsIgnoreCase(roleName)))
                .toList();

        log.info("Se encontraron {} usuarios con rol {}", users.size(), roleName);
        return users.stream()
                .map(userMapper::toSimpleDto).toList();
    }

    public List<SimpleUserDto> getUsersByRoleFallback(String roleName, Throwable ex) {
        log.error("Error al encontrar usuario con el rol {} ejecutanfo fallback {}", roleName, ex.getMessage());
        throw new RoleNotFoundException("Rol no encontrado: " + roleName);
    }


}
