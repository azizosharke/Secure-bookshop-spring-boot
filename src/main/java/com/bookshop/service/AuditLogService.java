package com.bookshop.service;

import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Service
public class AuditLogService {
    private static final Logger auditLogger = LoggerFactory.getLogger("AUDIT");
    private static final Logger logger = LoggerFactory.getLogger(AuditLogService.class);
    private static final DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    public void logUserAction(String username, String action, String details) {
        String timestamp = LocalDateTime.now().format(formatter);
        String logEntry = String.format("[%s] USER_ACTION: User=%s, Action=%s, Details=%s",
                timestamp, username, action, details);
        auditLogger.info(logEntry);
        logger.debug("Audit logged: {}", logEntry);
    }

    public void logAdminAction(String username, String action, String details) {
        String timestamp = LocalDateTime.now().format(formatter);
        String logEntry = String.format("[%s] ADMIN_ACTION: Admin=%s, Action=%s, Details=%s",
                timestamp, username, action, details);
        auditLogger.warn(logEntry); // Higher level for admin actions
        logger.debug("Admin audit logged: {}", logEntry);
    }

    public void logSecurityEvent(String eventType, String source, String details) {
        String timestamp = LocalDateTime.now().format(formatter);
        String logEntry = String.format("[%s] SECURITY_EVENT: Type=%s, Source=%s, Details=%s",
                timestamp, eventType, source, details);
        auditLogger.error(logEntry); // Highest level for security events
        logger.warn("Security event logged: {}", logEntry);
    }

    public void logDataAccess(String username, String dataType, String operation, String details) {
        String timestamp = LocalDateTime.now().format(formatter);
        String logEntry = String.format("[%s] DATA_ACCESS: User=%s, DataType=%s, Operation=%s, Details=%s",
                timestamp, username, dataType, operation, details);
        auditLogger.info(logEntry);
        logger.debug("Data access logged: {}", logEntry);
    }
}