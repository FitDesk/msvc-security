package com.security.services.Impl;

import com.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.debug("Loading user by email or username: {}", email);

        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("User not found with email : {}", email);
                    return new UsernameNotFoundException("Usuario no encontrado: " + email);
                });
    }
}
