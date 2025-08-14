package com.bookshop.service;

import com.bookshop.model.User;
import com.bookshop.model.UserSession;
import com.bookshop.repository.UserSessionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Transactional
public class SessionService {
    private static final Logger logger = LoggerFactory.getLogger(SessionService.class);

    // In-memory session tracking for performance
    private final ConcurrentHashMap<String, SessionInfo> activeSessions = new ConcurrentHashMap<>();

    @Autowired
    private UserSessionRepository sessionRepository;

    @Autowired
    private AuditLogService auditLogService;

    /**
     * Create new session
     */
    public UserSession createSession(User user, String sessionId, String ipAddress) {
        // Check for concurrent sessions
        List<UserSession> existingSessions = sessionRepository.findActiveSessionsByUserId(user.getId());

        if (existingSessions.size() >= 3) {
            // Invalidate oldest session if max concurrent sessions reached
            UserSession oldestSession = existingSessions.stream()
                    .min((s1, s2) -> s1.getCreatedAt().compareTo(s2.getCreatedAt()))
                    .orElse(null);

            if (oldestSession != null) {
                invalidateSession(oldestSession.getSessionId());
                logger.warn("Max concurrent sessions reached for user: {}. Invalidated oldest session.",
                        user.getUsername());
            }
        }

        // Create new session
        UserSession session = new UserSession();
        session.setUser(user);
        session.setSessionId(sessionId);
        session.setIpAddress(ipAddress);
        session.setCreatedAt(LocalDateTime.now());
        session.setLastAccessedAt(LocalDateTime.now());
        session.setActive(true);

        session = sessionRepository.save(session);

        // Cache session info
        SessionInfo info = new SessionInfo(user.getId(), user.getUsername(), ipAddress, System.currentTimeMillis());
        activeSessions.put(sessionId, info);

        logger.info("Session created for user: {} from IP: {}", user.getUsername(), ipAddress);
        auditLogService.logUserAction(user.getUsername(), "SESSION_CREATED",
                "Session ID: " + sessionId.substring(0, 8) + "...");

        return session;
    }

    /**
     * Validate session
     */
    public boolean isSessionValid(String sessionId, String currentIp) {
        // Quick check in cache
        SessionInfo cachedInfo = activeSessions.get(sessionId);
        if (cachedInfo != null) {
            // Validate IP hasn't changed (prevent session hijacking)
            if (!cachedInfo.ipAddress.equals(currentIp)) {
                logger.error("Session hijacking detected! Session: {}, Original IP: {}, Current IP: {}",
                        sessionId.substring(0, 8) + "...", cachedInfo.ipAddress, currentIp);
                auditLogService.logSecurityEvent("SESSION_HIJACKING_DETECTED",
                        cachedInfo.username,
                        "IP mismatch detected");
                invalidateSession(sessionId);
                return false;
            }

            // Update last access time
            cachedInfo.lastAccess = System.currentTimeMillis();
            return true;
        }

        // Check database if not in cache
        Optional<UserSession> sessionOpt = sessionRepository.findBySessionId(sessionId);
        if (sessionOpt.isPresent() && sessionOpt.get().isActive()) {
            UserSession session = sessionOpt.get();

            // Validate IP
            if (!session.getIpAddress().equals(currentIp)) {
                logger.error("Session hijacking detected in DB check!");
                invalidateSession(sessionId);
                return false;
            }

            // Update last access
            session.setLastAccessedAt(LocalDateTime.now());
            sessionRepository.save(session);

            // Re-cache
            SessionInfo info = new SessionInfo(
                    session.getUser().getId(),
                    session.getUser().getUsername(),
                    session.getIpAddress(),
                    System.currentTimeMillis()
            );
            activeSessions.put(sessionId, info);

            return true;
        }

        return false;
    }

    /**
     * Invalidate session
     */
    public void invalidateSession(String sessionId) {
        // Remove from cache
        SessionInfo removed = activeSessions.remove(sessionId);

        // Mark as inactive in database
        Optional<UserSession> sessionOpt = sessionRepository.findBySessionId(sessionId);
        if (sessionOpt.isPresent()) {
            UserSession session = sessionOpt.get();
            session.setActive(false);
            session.setInvalidatedAt(LocalDateTime.now());
            sessionRepository.save(session);

            if (removed != null) {
                logger.info("Session invalidated for user: {}", removed.username);
                auditLogService.logUserAction(removed.username, "SESSION_INVALIDATED",
                        "Session ended");
            }
        }
    }

    /**
     * Clean up expired sessions
     */
    @Transactional
    public void cleanupExpiredSessions() {
        LocalDateTime cutoff = LocalDateTime.now().minusHours(24);
        int deleted = sessionRepository.deleteInactiveSessions(cutoff);

        if (deleted > 0) {
            logger.info("Cleaned up {} expired sessions", deleted);
        }

        // Clean cache
        long now = System.currentTimeMillis();
        activeSessions.entrySet().removeIf(entry ->
                (now - entry.getValue().lastAccess) > 24 * 60 * 60 * 1000
        );
    }

    /**
     * Get active sessions for user
     */
    public List<UserSession> getUserActiveSessions(Long userId) {
        return sessionRepository.findActiveSessionsByUserId(userId);
    }

    /**
     * Invalidate all sessions for user
     */
    public void invalidateUserSessions(Long userId) {
        List<UserSession> sessions = sessionRepository.findActiveSessionsByUserId(userId);
        for (UserSession session : sessions) {
            invalidateSession(session.getSessionId());
        }
        logger.info("All sessions invalidated for user ID: {}", userId);
    }

    /**
     * Detect anomalous session behavior
     */
    public boolean detectSessionAnomaly(String sessionId, String userAgent, String currentIp) {
        SessionInfo info = activeSessions.get(sessionId);
        if (info == null) {
            return false;
        }

        // Check for rapid IP changes
        if (!info.ipAddress.equals(currentIp)) {
            logger.warn("IP change detected for session: {}", sessionId.substring(0, 8) + "...");
            return true;
        }

        // Check for suspicious activity patterns
        long timeSinceLastAccess = System.currentTimeMillis() - info.lastAccess;
        if (timeSinceLastAccess < 100) { // Less than 100ms between requests
            info.rapidRequestCount++;
            if (info.rapidRequestCount > 50) {
                logger.warn("Rapid request pattern detected for session: {}",
                        sessionId.substring(0, 8) + "...");
                return true;
            }
        } else {
            info.rapidRequestCount = 0;
        }

        return false;
    }

    /**
     * Internal session info class for caching
     */
    private static class SessionInfo {
        final Long userId;
        final String username;
        final String ipAddress;
        long lastAccess;
        int rapidRequestCount = 0;

        SessionInfo(Long userId, String username, String ipAddress, long lastAccess) {
            this.userId = userId;
            this.username = username;
            this.ipAddress = ipAddress;
            this.lastAccess = lastAccess;
        }
    }
}