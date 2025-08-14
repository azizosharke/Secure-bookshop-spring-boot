package com.bookshop.service;

import com.bookshop.model.MFAToken;
import com.bookshop.model.User;
import com.bookshop.repository.MFATokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

@Service
@Transactional
public class MFAService {
    private static final Logger logger = LoggerFactory.getLogger(MFAService.class);
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final int TOKEN_LENGTH = 6;
    private static final int MAX_ATTEMPTS = 3;

    @Autowired
    private MFATokenRepository mfaTokenRepository;

    @Autowired(required = false)
    private JavaMailSender emailSender;

    @Autowired
    private AuditLogService auditLogService;

    @Value("${mfa.enabled:true}")
    private boolean mfaEnabled;

    @Value("${mfa.secret.key:DefaultSecretKey123!@#}")
    private String secretKey;

    @Value("${spring.mail.username:noreply@bookshop.com}")
    private String fromEmail;

    /**
     * Generate and send MFA token
     */
    public boolean generateAndSendToken(User user) {
        if (!mfaEnabled) {
            logger.info("MFA is disabled, skipping token generation for user: {}", user.getUsername());
            return true;
        }

        try {
            // Invalidate any existing tokens
            mfaTokenRepository.invalidateUserTokens(user.getId());

            // Generate new token
            String tokenValue = generateSecureToken();
            MFAToken token = new MFAToken(user, hashToken(tokenValue), MFADeliveryMethod.EMAIL);
            mfaTokenRepository.save(token);

            // Send token via email (in production, could also use SMS)
            boolean sent = sendTokenViaEmail(user, tokenValue);

            if (sent) {
                logger.info("MFA token generated and sent to user: {}", user.getUsername());
                auditLogService.logUserAction(user.getUsername(), "MFA_TOKEN_SENT",
                        "Token sent via " + token.getDeliveryMethod());
            } else {
                logger.error("Failed to send MFA token to user: {}", user.getUsername());
            }

            return sent;

        } catch (Exception e) {
            logger.error("Error generating MFA token for user: {}", user.getUsername(), e);
            return false;
        }
    }

    /**
     * Verify MFA token
     */
    public boolean verifyToken(User user, String providedToken) {
        if (!mfaEnabled) {
            return true;
        }

        if (providedToken == null || providedToken.trim().isEmpty()) {
            logger.warn("Empty MFA token provided for user: {}", user.getUsername());
            return false;
        }

        Optional<MFAToken> tokenOpt = mfaTokenRepository.findLatestValidToken(user.getId());

        if (tokenOpt.isEmpty()) {
            logger.warn("No valid MFA token found for user: {}", user.getUsername());
            auditLogService.logSecurityEvent("MFA_VERIFICATION_FAILED", user.getUsername(),
                    "No valid token found");
            return false;
        }

        MFAToken token = tokenOpt.get();

        // Check if token has exceeded max attempts
        if (token.getVerificationAttempts() >= MAX_ATTEMPTS) {
            logger.warn("MFA token exceeded max attempts for user: {}", user.getUsername());
            auditLogService.logSecurityEvent("MFA_MAX_ATTEMPTS_EXCEEDED", user.getUsername(),
                    "Token verification blocked");
            return false;
        }

        // Increment attempt counter
        token.incrementAttempts();
        mfaTokenRepository.save(token);

        // Verify token
        boolean isValid = false;
        try {
            isValid = token.isValid() && verifyTokenHash(providedToken.trim(), token.getToken());
        } catch (Exception e) {
            logger.error("Error verifying token hash", e);
        }

        if (isValid) {
            token.setUsed(true);
            mfaTokenRepository.save(token);

            logger.info("MFA token verified successfully for user: {}", user.getUsername());
            auditLogService.logUserAction(user.getUsername(), "MFA_VERIFICATION_SUCCESS",
                    "Token verified");
            return true;
        } else {
            logger.warn("Invalid MFA token provided for user: {}", user.getUsername());
            auditLogService.logSecurityEvent("MFA_VERIFICATION_FAILED", user.getUsername(),
                    "Invalid token provided");
            return false;
        }
    }

    /**
     * Generate secure random token
     */
    private String generateSecureToken() {
        int token = secureRandom.nextInt(900000) + 100000; // 6-digit token
        return String.valueOf(token);
    }

    /**
     * Hash token for secure storage
     */
    private String hashToken(String token) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hashBytes = mac.doFinal(token.getBytes());
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    /**
     * Verify token hash
     */
    private boolean verifyTokenHash(String providedToken, String storedHash)
            throws NoSuchAlgorithmException, InvalidKeyException {
        String providedHash = hashToken(providedToken);
        return constantTimeEquals(providedHash.getBytes(), storedHash.getBytes());
    }

    /**
     * Constant time comparison to prevent timing attacks
     */
    private boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /**
     * Send token via email
     */
    private boolean sendTokenViaEmail(User user, String token) {
        if (emailSender == null) {
            logger.warn("Email sender not configured, logging token for demo purposes");
            logger.info("MFA Token for {}: {}", user.getEmail(), token);
            return true; // For demo purposes
        }

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(user.getEmail());
            message.setSubject("Your Bookshop Login Verification Code");
            message.setText(String.format(
                    "Hello %s,\n\n" +
                            "Your verification code is: %s\n\n" +
                            "This code will expire in 5 minutes.\n\n" +
                            "If you did not request this code, please ignore this email.\n\n" +
                            "Best regards,\n" +
                            "Bookshop Security Team",
                    user.getName(), token
            ));

            emailSender.send(message);
            return true;
        } catch (Exception e) {
            logger.error("Failed to send email to {}: {}", user.getEmail(), e.getMessage());
            return false;
        }
    }

    /**
     * Clean up expired tokens
     */
    @Transactional
    public void cleanupExpiredTokens() {
        int deleted = mfaTokenRepository.deleteExpiredTokens(LocalDateTime.now());
        if (deleted > 0) {
            logger.info("Cleaned up {} expired MFA tokens", deleted);
        }
    }

    /**
     * Check if MFA is enabled
     */
    public boolean isMfaEnabled() {
        return mfaEnabled;
    }

    /**
     * Check if user needs MFA
     */
    public boolean userNeedsMFA(User user) {
        // Admin users always need MFA
        if ("ADMIN".equals(user.getRole().toString())) {
            return true;
        }

        // Check user preference
        return user.isMfaEnabled();
    }
}