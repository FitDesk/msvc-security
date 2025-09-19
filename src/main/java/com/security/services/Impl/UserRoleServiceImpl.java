package com.security.services.Impl;

import com.security.dtos.AuthResponseDTO;
import com.security.dtos.RolesResponseDTO;
import com.security.entity.RoleEntity;
import com.security.entity.UserEntity;
import com.security.repository.RoleRepository;
import com.security.repository.UserRepository;
import com.security.services.UserRoleService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserRoleServiceImpl implements UserRoleService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;


    @Override
    @Transactional(readOnly = true)
    public RolesResponseDTO getUserRoles(UUID userId) {
        UserEntity user = userRepository.findById(userId).orElseThrow();
        Set<String> roles = user.getRoles().stream().map(RoleEntity::getName).collect(Collectors.toSet());
        return new RolesResponseDTO(userId, roles);
    }

    @Override
    @Transactional
    public AuthResponseDTO addRoleToUser(UUID userId, String roleName) {
        UserEntity user = userRepository.findById(userId).orElseThrow();

        RoleEntity role = roleRepository.findByName(roleName).orElseThrow();
        if (user.getRoles() == null) {
            user.setRoles(Set.of(role));
        } else if (user.getRoles().stream().noneMatch(r -> r.getName().equals(roleName))) {
            HashSet<RoleEntity> mutable = new HashSet<>(user.getRoles());
            mutable.add(role);
            user.setRoles(mutable);
        }
        userRepository.save(user);

        return new AuthResponseDTO(true, "Rol agregado", Instant.now());
    }

    @Override
    @Transactional
    public AuthResponseDTO removeRoleFromUser(UUID userId, String roleName) {
        UserEntity user = userRepository.findById(userId).orElseThrow();
        if (user.getRoles() == null || user.getRoles().stream().noneMatch(r -> r.getName().equals(roleName))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El usuario no tiene ese rol");

        }

        var mutable = new HashSet<>(user.getRoles());
        mutable.removeIf(r -> r.getName().equals(roleName));
        user.setRoles(mutable);
        userRepository.save(user);
        return new AuthResponseDTO(true, "Rol removido", Instant.now());
    }
}
