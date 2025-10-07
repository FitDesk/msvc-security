package com.security.config;

import com.security.entity.RoleEntity;
import com.security.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;


@Component
@RequiredArgsConstructor
@Slf4j
public class RoleInitializer implements CommandLineRunner {
    private final RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
        createRoleIfNotExists("ADMIN", "Administrator role");
        createRoleIfNotExists("USER", "User role");
        createRoleIfNotExists("TRAINER", "Trainer role");
    }

    private void createRoleIfNotExists(String name, String description) {
        roleRepository.findByName(name)
                .orElseGet(() -> {
                    log.info("Creando {} role", name);
                    return roleRepository.save(RoleEntity.builder()
                            .name(name)
                            .description(description)
                            .build());
                });
    }
}