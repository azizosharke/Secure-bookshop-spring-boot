package com.bookshop.config;

import com.bookshop.model.*;
import com.bookshop.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import java.math.BigDecimal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class DataInitializer implements CommandLineRunner {
    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BookRepository bookRepository;

    @Autowired
    private CartRepository cartRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${ADMIN_PASSWORD:Admin@123!}")
    private String adminPassword;

    @Override
    public void run(String... args) throws Exception {
        // Create admin user if not exists
        if (!userRepository.existsByUsername("admin")) {
            User admin = new User();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode(adminPassword));
            admin.setRole(UserRole.ADMIN);
            admin.setName("Admin");
            admin.setSurname("User");
            admin.setEmail("admin@bookshop.com");

            userRepository.save(admin);
            logger.info("Admin user created with username: admin");
            logger.info("Please change the default admin password immediately!");
        }

        // Create sample books if none exist
        if (bookRepository.count() == 0) {
            bookRepository.save(new Book("Java Programming", "John Doe", 2023,
                    new BigDecimal("49.99"), 10));
            bookRepository.save(new Book("Spring Boot in Action", "Jane Smith", 2022,
                    new BigDecimal("59.99"), 15));
            bookRepository.save(new Book("Database Design", "Bob Johnson", 2021,
                    new BigDecimal("39.99"), 20));

            logger.info("Sample books created");
        }
    }
}