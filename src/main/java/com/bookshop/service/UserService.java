package com.bookshop.service;

import com.bookshop.model.User;
import com.bookshop.model.UserRole;
import com.bookshop.model.Cart;
import com.bookshop.repository.UserRepository;
import com.bookshop.repository.CartRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class UserService {
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CartRepository cartRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User register(User user) {
        // Password should already be hashed from controller
        // Set default role if not set
        if (user.getRole() == null) {
            user.setRole(UserRole.CUSTOMER);
        }

        User savedUser = userRepository.save(user);
        logger.info("New user registered with ID: {}", savedUser.getId());

        // Create cart for new user
        Cart cart = new Cart(savedUser);
        cartRepository.save(cart);
        logger.info("Cart created for user ID: {}", savedUser.getId());

        return savedUser;
    }
    public User findById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + id));
    }

    public User authenticateUser(String username, String password) {
        return userRepository.findByUsername(username)
                .filter(user -> passwordEncoder.matches(password, user.getPassword()))
                .orElse(null);
    }

    public boolean usernameExists(String username) {
        boolean exists = userRepository.existsByUsername(username);
        if (exists) {
            logger.debug("Username check: {} already exists", username);
        }
        return exists;
    }

    public boolean emailExists(String email) {
        boolean exists = userRepository.existsByEmail(email);
        if (exists) {
            logger.debug("Email check: {} already exists", email);
        }
        return exists;
    }

    public User getCurrentUser(HttpSession session) {
        Long userId = (Long) session.getAttribute("userId");
        if (userId != null) {
            return userRepository.findById(userId).orElse(null);
        }
        return null;
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    public void updateUser(User user) {
        userRepository.save(user);
        logger.info("User updated: {}", user.getUsername());
    }
}