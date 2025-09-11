package com.security.config;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.stereotype.Component;

import java.util.List;
@Data
@Component
@RefreshScope
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    private Client client = new Client();
    private Server server = new Server();

    @Data
    public static class Client {
        private List<String> redirectUris;
        private String postLogoutRedirectUri;
    }

    @Data
    public static class Server {
        private String issuer;
    }
}