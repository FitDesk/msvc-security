package com.security.config;

import com.security.Entity.RoleEntity;
import com.security.Entity.UserEntity;
import com.security.Repository.RoleRepository;
import com.security.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;



    @Override
    public void run(String... args) throws Exception {
        RoleEntity adminRole = roleRepository.findByName("ADMIN")
                .orElseGet(() -> {
                    log.info("Creating ADMIN role");
                    return roleRepository.save(RoleEntity.builder()
                            .name("ADMIN")
                            .description("Administrator role")
                            .build());
                });

        RoleEntity userRole = roleRepository.findByName("USER")
                .orElseGet(() -> {
                    log.info("Creating USER role");
                    return roleRepository.save(RoleEntity.builder()
                            .name("USER")
                            .description("User role")
                            .build());
                });

        RoleEntity trainerRole = roleRepository.findByName("TRAINER")
                .orElseGet(() -> {
                    log.info("Creating TRAINER role");
                    return roleRepository.save(RoleEntity.builder()
                            .name("TRAINER")
                            .description("Trainer role")
                            .build());
                });

        if (!userRepository.existsByUsername("admin")) {
            String encodedPassword = passwordEncoder.encode("admin123");
            log.info("Creating admin user with encoded password length: {}", encodedPassword.length());

            UserEntity admin = UserEntity.builder()
                    .username("admin")
                    .email("admin@fitdesk.com")
                    .password(encodedPassword)
                    .firstName("Admin")
                    .lastName("User")
                    .roles(Set.of(adminRole))
                    .build();
            userRepository.save(admin);
            log.info("Admin user created successfully");
        } else {
            log.info("Admin user already exists");
        }

        if (!userRepository.existsByUsername("user")) {
            String encodedPassword = passwordEncoder.encode("user123");
            log.info("Creating regular user");

            UserEntity user = UserEntity.builder()
                    .username("user")
                    .email("user@fitdesk.com")
                    .password(encodedPassword)
                    .firstName("Regular")
                    .lastName("User")
                    .roles(Set.of(userRole))
                    .build();
            userRepository.save(user);
            log.info("Regular user created successfully");
        }

        if (!userRepository.existsByUsername("trainer")) {
            String encodedPassword = passwordEncoder.encode("trainer123");
            log.info("Creating trainer user");

            UserEntity trainer = UserEntity.builder()
                    .username("trainer")
                    .email("trainer@fitdesk.com")
                    .password(encodedPassword)
                    .firstName("Gym")
                    .lastName("Trainer")
                    .roles(Set.of(trainerRole))
                    .build();
            userRepository.save(trainer);
            log.info("Trainer user created successfully");
        }
    }
}