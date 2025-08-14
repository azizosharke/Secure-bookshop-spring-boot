package com.bookshop.service;

import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
public class LoginAttemptService {
    private static final Logger logger = LoggerFactory.getLogger(LoginAttemptService.class);

    private final int MAX_ATTEMPTS = 5;
    private final int BLOCK_DURATION_MINUTES = 15;
    private final ConcurrentHashMap<String, AttemptRecord> attemptsCache = new ConcurrentHashMap<>();

    public void loginSucceeded(String key) {
        attemptsCache.remove(key);
        logger.debug("Login succeeded for: {}", key);
    }

    public void loginFailed(String key) {
        AttemptRecord attempts = attemptsCache.computeIfAbsent(key, k -> new AttemptRecord());
        attempts.incrementAttempts();

        logger.warn("Failed login attempt {} of {} for: {}",
                attempts.getAttempts(), MAX_ATTEMPTS, key);

        if (attempts.getAttempts() >= MAX_ATTEMPTS) {
            attempts.setBlockedUntil(System.currentTimeMillis() +
                    TimeUnit.MINUTES.toMillis(BLOCK_DURATION_MINUTES));
            logger.error("Blocking {} for {} minutes due to {} failed attempts",
                    key, BLOCK_DURATION_MINUTES, MAX_ATTEMPTS);
        }
    }

    public boolean isBlocked(String key) {
        AttemptRecord attempts = attemptsCache.get(key);
        if (attempts == null) {
            return false;
        }

        if (attempts.getBlockedUntil() > System.currentTimeMillis()) {
            logger.debug("Access blocked for: {}", key);
            return true;
        }

        // Unblock if time has passed
        if (attempts.getBlockedUntil() > 0 && attempts.getBlockedUntil() <= System.currentTimeMillis()) {
            attemptsCache.remove(key);
            logger.info("Unblocking: {}", key);
        }

        return false;
    }

    public void resetDailyCounters() {
    }

    private static class AttemptRecord {
        private int attempts;
        private long blockedUntil;

        public void incrementAttempts() {
            this.attempts++;
        }

        public int getAttempts() {
            return attempts;
        }

        public long getBlockedUntil() {
            return blockedUntil;
        }

        public void setBlockedUntil(long blockedUntil) {
            this.blockedUntil = blockedUntil;
        }
    }
}