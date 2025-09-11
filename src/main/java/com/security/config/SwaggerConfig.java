package com.security.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.servers.Server;

@OpenAPIDefinition(
        info = @Info(
                title = "FitDesk Security API",
                description = "Microservicio de autenticacion y autorizacion con cookies",
                termsOfService = "",
                version = "1.0.0",
                contact = @Contact(
                        name = "FitDesk Team",
                        url = "https://fitdesk.com",
                        email = "dev@fitdesk.com"
                ),
                license = @License(
                        name = "Standard Apache License Version 2.0 for FitDesk",
                        url = "https://www.apache.org/licenses/LICENSE-2.0",
                        identifier = "Apache-2.0"
                )
        ),
        servers = {
                @Server(
                        description = "Local Developer Server",
                        url = "http://localhost:9091"
                )
        }
)
public class SwaggerConfig {
}