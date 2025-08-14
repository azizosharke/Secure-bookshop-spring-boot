package com.bookshop.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode;
import org.springframework.boot.web.servlet.server.CookieSameSiteSupplier;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import jakarta.servlet.SessionTrackingMode;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private Object XssProtectionHeaderWriter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // HTTPS enforcement
                .requiresChannel(channel -> channel
                        .anyRequest().requiresSecure()
                )

                // CSRF Protection with token repository
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                )

                // Headers configuration
                .headers(headers -> headers
                        // X-Frame-Options to prevent clickjacking
                        .frameOptions(frameOptions -> frameOptions.sameOrigin())

                        // X-Content-Type-Options
                        .contentTypeOptions(contentTypeOptions -> {
                        })

                        // X-XSS-Protection
                        .xssProtection(xss -> xss.headerValue(XssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))

                        // Strict-Transport-Security
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31536000)
                        )

                        // Content-Security-Policy
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; " +
                                        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
                                        "style-src 'self' 'unsafe-inline'; " +
                                        "img-src 'self' data:; " +
                                        "font-src 'self'; " +
                                        "frame-ancestors 'self';")
                        )
                )

                // Authorization rules
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/", "/login", "/register", "/css/**", "/js/**", "/error").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/customer/**").hasAnyRole("CUSTOMER", "ADMIN")
                        .anyRequest().authenticated()
                )

                // Session management
                .sessionManagement(session -> session
                        .sessionFixation().migrateSession()
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(true)
                )

                // Login configuration
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/", true)
                        .permitAll()
                )

                // Logout configuration
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setHttpOnly(true);
        serializer.setSecure(true);
        serializer.setSameSite("Strict");
        serializer.setCookieName("JSESSIONID");
        serializer.setCookiePath("/");
        serializer.setCookieMaxAge(1800); // 30 minutes
        return serializer;
    }

    @Bean
    public ServletContextInitializer servletContextInitializer() {
        return servletContext -> {
            // Force session tracking to be cookie only (no URL rewriting)
            servletContext.setSessionTrackingModes(Collections.singleton(SessionTrackingMode.COOKIE));
        };
    }
}