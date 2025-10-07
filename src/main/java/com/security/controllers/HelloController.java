package com.security.controllers;


import com.security.services.Impl.NotificationServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/test")
@RestController
@RequiredArgsConstructor
public class HelloController {

    private final NotificationServiceImpl notificationService;

    @GetMapping("/saludo")
    public ResponseEntity<String> saludo() {
        return ResponseEntity.ok("Hola Microservicio Security");
    }

    @PostMapping("/notification")
    public ResponseEntity<String> sendNotification(@RequestBody String message) {
        notificationService.sendNotification(message);
        return ResponseEntity.ok("Mensaje enviado a kafka: " + message);
    }

}
