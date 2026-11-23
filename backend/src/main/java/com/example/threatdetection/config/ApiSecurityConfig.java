package com.example.threatdetection.config;

import jakarta.servlet.DispatcherType;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(ApiSecurityProperties.class)
public class ApiSecurityConfig {

    private static final Pattern TOKEN_FORMAT = Pattern.compile("[A-Za-z0-9_-]{43}");

    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http, CorsConfigurationSource apiCors,
                                    OpaqueTokenIntrospector tokens) throws Exception {
        return http
                .cors(cors -> cors.configurationSource(apiCors))
                // Only Authorization header bearer tokens authenticate these stateless routes.
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(routes -> routes
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/health", "/api/threat/health").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/threat/reputation/snapshot").hasRole("BROWSER")
                        .requestMatchers(HttpMethod.GET, "/api/threat/reputation/feed-status").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/threat/session/start", "/api/threat/analyze",
                                "/api/threat/event").hasRole("BROWSER")
                        .requestMatchers(HttpMethod.GET, "/api/threat/session/{id}",
                                "/api/threat/session/{id}/summary", "/api/threat/session/{id}/timeline")
                                .hasAnyRole("ADMIN", "BROWSER")
                        .requestMatchers(HttpMethod.GET, "/api/threat/logs", "/api/threat/logs/filtered",
                                "/api/threat/logs/export", "/api/threat/alerts", "/api/threat/alerts/latest",
                                "/api/threat/alerts/unresolved", "/api/threat/dashboard/stats").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/threat/action",
                                "/api/threat/alerts/{id}/resolve").hasRole("ADMIN")
                        .anyRequest().denyAll())
                .oauth2ResourceServer(resource -> resource.opaqueToken(opaque -> opaque.introspector(tokens)))
                .build();
    }

    @Bean
    OpaqueTokenIntrospector apiTokens(ApiSecurityProperties properties) {
        Set<String> digests = new HashSet<>();
        var clients = properties.clients().entrySet().stream()
                .map(entry -> {
                    var client = entry.getValue();
                    if (!digests.add(client.tokenSha256())) {
                        throw new IllegalArgumentException("Each API client must have a different token digest");
                    }
                    return new TokenClient(entry.getKey(), client.role(), HexFormat.of().parseHex(client.tokenSha256()));
                })
                .toList();

        return token -> {
            if (!TOKEN_FORMAT.matcher(token).matches()) {
                throw new BadOpaqueTokenException("Invalid bearer token");
            }
            byte[] digest = sha256(token);
            TokenClient match = null;
            for (TokenClient client : clients) {
                if (MessageDigest.isEqual(client.digest(), digest)) {
                    match = client;
                }
            }
            if (match == null) {
                throw new BadOpaqueTokenException("Invalid bearer token");
            }
            return new DefaultOAuth2AuthenticatedPrincipal(match.id(),
                    Map.of("sub", match.id()), List.of(new SimpleGrantedAuthority("ROLE_" + match.role().name())));
        };
    }

    @Bean
    CorsConfigurationSource apiCors(ApiSecurityProperties properties) {
        properties.allowedOrigins().forEach(ApiSecurityConfig::requireExactOrigin);
        CorsConfiguration policy = new CorsConfiguration();
        policy.setAllowedOrigins(properties.allowedOrigins());
        policy.setAllowCredentials(false);
        policy.setAllowedMethods(List.of("GET", "POST"));
        policy.setAllowedHeaders(List.of(HttpHeaders.AUTHORIZATION, HttpHeaders.CONTENT_TYPE, HttpHeaders.ACCEPT));
        policy.setMaxAge(600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", policy);
        return source;
    }

    private static void requireExactOrigin(String origin) {
        URI uri;
        try {
            uri = URI.create(origin);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Invalid API CORS origin");
        }
        String host = uri.getHost();
        if (host == null || uri.getRawUserInfo() != null || !"".equals(uri.getRawPath())
                || uri.getRawQuery() != null || uri.getRawFragment() != null
                || uri.getPort() == 0 || uri.getPort() > 65535
                || !origin.equals(uri.getScheme() + "://" + host + (uri.getPort() == -1 ? "" : ":" + uri.getPort()))) {
            throw new IllegalArgumentException("API CORS origins must be exact origins without paths or wildcards");
        }
        boolean allowed = switch (uri.getScheme()) {
            case "https" -> true;
            case "http" -> Set.of("localhost", "127.0.0.1", "[::1]").contains(host);
            case "chrome-extension" -> host.matches("[a-p]{32}") && uri.getPort() == -1;
            default -> false;
        };
        if (!allowed) {
            throw new IllegalArgumentException("API CORS origins must use HTTPS, loopback HTTP, or a Chrome extension ID");
        }
    }

    private static byte[] sha256(String token) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }

    private record TokenClient(String id, ApiSecurityProperties.Role role, byte[] digest) {}
}
