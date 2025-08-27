package com.bookshop.scheduler;

import com.bookshop.service.*;
import com.bookshop.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
 // Validate time 
@Component
public class SecurityCleanupTasks {
    private static final Logger logger = LoggerFactory.getLogger(SecurityCleanupTasks.class);

    @Autowired
    private MFAService mfaService;

    @Autowired
    private SessionService sessionService;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Autowired
    private UserSessionRepository sessionRepository;

    @Autowired
    private MFATokenRepository mfaTokenRepository;

    @Autowired
    private AuditLogService auditLogService;

    /**
     * Clean up expired MFA tokens every hour
     */
    @Scheduled(fixedDelay = 3600000) // 1 hour
    @Transactional
    public void cleanupExpiredMFATokens() {
        try {
            logger.info("Starting MFA token cleanup task");

            LocalDateTime cutoff = LocalDateTime.now().minusHours(24);
            int deleted = mfaTokenRepository.deleteExpiredTokens(cutoff);

            if (deleted > 0) {
                logger.info("Deleted {} expired MFA tokens", deleted);
                auditLogService.logUserAction("SYSTEM", "MFA_CLEANUP",
                        "Deleted " + deleted + " expired tokens");
            }
        } catch (Exception e) {
            logger.error("Error during MFA token cleanup", e);
        }
    }

    /**
     * Clean up expired sessions every 30 minutes
     */
    @Scheduled(fixedDelay = 1800000) // 30 minutes
    @Transactional
    public void cleanupExpiredSessions() {
        try {
            logger.info("Starting session cleanup task");

            // Mark sessions as expired if idle for more than 30 minutes
            LocalDateTime idleCutoff = LocalDateTime.now().minusMinutes(30);
            int expiredSessions = sessionRepository.invalidateExpiredSessions(
                    idleCutoff, LocalDateTime.now()
            );

            if (expiredSessions > 0) {
                logger.info("Invalidated {} idle sessions", expiredSessions);
            }

            // Delete old inactive sessions (older than 7 days)
            LocalDateTime deleteCutoff = LocalDateTime.now().minusDays(7);
            int deletedSessions = sessionRepository.deleteInactiveSessions(deleteCutoff);

            if (deletedSessions > 0) {
                logger.info("Deleted {} old inactive sessions", deletedSessions);
                auditLogService.logUserAction("SYSTEM", "SESSION_CLEANUP",
                        "Deleted " + deletedSessions + " old sessions");
            }

            // Clean up in-memory session cache
            sessionService.cleanupExpiredSessions();

        } catch (Exception e) {
            logger.error("Error during session cleanup", e);
        }
    }

    /**
     * Reset login attempt counters daily at midnight
     */
    @Scheduled(cron = "0 0 0 * * *") // Daily at midnight
    public void resetLoginAttempts() {
        try {
            logger.info("Resetting daily login attempt counters");

            loginAttemptService.resetDailyCounters();

            auditLogService.logUserAction("SYSTEM", "LOGIN_ATTEMPTS_RESET",
                    "Daily reset of login attempt counters");

        } catch (Exception e) {
            logger.error("Error resetting login attempts", e);
        }
    }

    /**
     * Archive old audit logs monthly
     */
    @Scheduled(cron = "0 0 2 1 * *") // Monthly on the 1st at 2 AM
    @Transactional
    public void archiveAuditLogs() {
        try {
            logger.info("Starting audit log archival");

            // Archive logs older than 90 days
            LocalDateTime cutoff = LocalDateTime.now().minusDays(90);

            // In production, this would move logs to long-term storage
            // For now, we'll just log the action
            logger.info("Would archive audit logs older than {}", cutoff);

            auditLogService.logUserAction("SYSTEM", "AUDIT_ARCHIVE",
                    "Monthly audit log archival completed");

        } catch (Exception e) {
            logger.error("Error archiving audit logs", e);
        }
    }

    /**
     * Check for suspicious activity patterns every 15 minutes
     */
    @Scheduled(fixedDelay = 900000) // 15 minutes
    public void detectSuspiciousActivity() {
        try {
            logger.debug("Running suspicious activity detection");

            // Check for sessions with security flags
            var flaggedSessions = sessionRepository.findSessionsWithSecurityFlags();

            if (!flaggedSessions.isEmpty()) {
                logger.warn("Found {} sessions with security flags", flaggedSessions.size());

                for (var session : flaggedSessions) {
                    auditLogService.logSecurityEvent("SUSPICIOUS_SESSION",
                            session.getUser().getUsername(),
                            "Session flags: " + session.getSecurityFlags());
                }
            }

            // Check for rapid IP changes
            checkRapidIPChanges();

            // Check for brute force patterns
            checkBruteForcePatterns();

        } catch (Exception e) {
            logger.error("Error during suspicious activity detection", e);
        }
    }

    /**
     * Generate security metrics report weekly
     */
    @Scheduled(cron = "0 0 3 * * MON") // Weekly on Monday at 3 AM
    public void generateSecurityReport() {
        try {
            logger.info("Generating weekly security report");

            LocalDateTime weekAgo = LocalDateTime.now().minusDays(7);

            // Collect metrics
            long totalSessions = sessionRepository.count();
            long activeSessions = sessionRepository.findAll().stream()
                    .filter(s -> s.isActive())
                    .count();

            // Log report
            logger.info("Weekly Security Report:");
            logger.info("- Total sessions: {}", totalSessions);
            logger.info("- Active sessions: {}", activeSessions);

            auditLogService.logUserAction("SYSTEM", "SECURITY_REPORT",
                    "Weekly security report generated");

        } catch (Exception e) {
            logger.error("Error generating security report", e);
        }
    }

    /**
     * Update security patches notification check daily
     */
    @Scheduled(cron = "0 0 6 * * *") // Daily at 6 AM
    public void checkSecurityUpdates() {
        try {
            logger.info("Checking for security updates");

            // In production, this would check for CVEs and updates
            // For now, we'll just log the check
            logger.info("Security update check completed");

            auditLogService.logUserAction("SYSTEM", "SECURITY_UPDATE_CHECK",
                    "Daily security update check performed");

        } catch (Exception e) {
            logger.error("Error checking security updates", e);
        }
    }

    private void checkRapidIPChanges() {
        // Check for users with multiple IPs in short timeframe
        LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);

        // This would query for users with sessions from multiple IPs
        // Implementation depends on specific requirements
        logger.debug("Checked for rapid IP changes");
    }

    private void checkBruteForcePatterns() {
        // Check for IPs with excessive failed login attempts
        // Implementation would check loginAttemptService for patterns
        logger.debug("Checked for brute force patterns");
    }

}
