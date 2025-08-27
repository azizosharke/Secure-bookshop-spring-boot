package com.bookshop.exception;

import com.bookshop.service.AuditLogService;
import com.bookshop.validator.InputSanitizer;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.ui.Model;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


        // test exception 

@ControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private InputSanitizer inputSanitizer;

    /**
     * Handle validation errors
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleValidationException(MethodArgumentNotValidException e,
                                            HttpServletRequest request,
                                            Model model) {
        String errorId = UUID.randomUUID().toString();

        // Log error details internally
        logger.error("Validation error [{}]: {}", errorId, e.getMessage());

        // Generic message for user
        model.addAttribute("error", "Invalid input provided. Please check your data and try again.");
        model.addAttribute("errorId", errorId);
        model.addAttribute("timestamp", LocalDateTime.now());

        // Log security event if suspicious
        String path = request.getRequestURI();
        if (path.contains("admin") || path.contains("checkout")) {
            auditLogService.logSecurityEvent("VALIDATION_FAILURE",
                    getClientIP(request),
                    "Path: " + path);
        }

        return "error";
    }

    /**
     * Handle binding errors
     */
    @ExceptionHandler(BindException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleBindException(BindException e, Model model) {
        String errorId = UUID.randomUUID().toString();

        logger.error("Binding error [{}]: {}", errorId, e.getMessage());

        model.addAttribute("error", "Invalid data format. Please check your input.");
        model.addAttribute("errorId", errorId);

        return "error";
    }

    /**
     * Handle access denied exceptions
     */
    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public String handleAccessDeniedException(AccessDeniedException e,
                                              HttpServletRequest request,
                                              Model model) {
        String errorId = UUID.randomUUID().toString();
        String username = request.getRemoteUser();
        String path = request.getRequestURI();

        // Log security event
        logger.warn("Access denied [{}] for user {} to path {}", errorId, username, path);
        auditLogService.logSecurityEvent("ACCESS_DENIED",
                username != null ? username : getClientIP(request),
                "Path: " + path);

        model.addAttribute("error", "You do not have permission to access this resource.");
        model.addAttribute("errorId", errorId);

        return "error";
    }

    /**
     * Handle security exceptions
     */
    @ExceptionHandler(SecurityException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public String handleSecurityException(SecurityException e,
                                          HttpServletRequest request,
                                          Model model) {
        String errorId = UUID.randomUUID().toString();

        // Log full details internally
        logger.error("Security exception [{}]: {}", errorId, e.getMessage(), e);

        // Log security event
        auditLogService.logSecurityEvent("SECURITY_EXCEPTION",
                getClientIP(request),
                "Error ID: " + errorId);

        // Generic message for user
        model.addAttribute("error", "Security validation failed.");
        model.addAttribute("errorId", errorId);

        return "error";
    }

    /**
     * Handle illegal argument exceptions
     */
    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleIllegalArgumentException(IllegalArgumentException e, Model model) {
        String errorId = UUID.randomUUID().toString();

        logger.error("Illegal argument [{}]: {}", errorId, e.getMessage());

        // Check if it's a known validation error
        if (e.getMessage() != null && e.getMessage().contains("Invalid")) {
            model.addAttribute("error", "Invalid input provided.");
        } else {
            model.addAttribute("error", "The request could not be processed.");
        }

        model.addAttribute("errorId", errorId);

        return "error";
    }

    /**
     * Handle type mismatch exceptions
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleTypeMismatchException(MethodArgumentTypeMismatchException e,
                                              HttpServletRequest request,
                                              Model model) {
        String errorId = UUID.randomUUID().toString();

        logger.error("Type mismatch [{}]: Parameter {} with value {}",
                errorId, e.getName(),
                inputSanitizer.sanitizeForLog(String.valueOf(e.getValue())));

        // Check for potential attack
        String value = String.valueOf(e.getValue());
        if (inputSanitizer.containsSQLInjection(value) || inputSanitizer.containsXSS(value)) {
            auditLogService.logSecurityEvent("TYPE_MISMATCH_ATTACK",
                    getClientIP(request),
                    "Suspicious value in parameter: " + e.getName());
        }

        model.addAttribute("error", "Invalid parameter format.");
        model.addAttribute("errorId", errorId);

        return "error";
    }

    /**
     * Handle file upload size exceeded
     */
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    @ResponseStatus(HttpStatus.PAYLOAD_TOO_LARGE)
    public String handleMaxUploadSizeException(MaxUploadSizeExceededException e, Model model) {
        String errorId = UUID.randomUUID().toString();

        logger.warn("File upload size exceeded [{}]: {}", errorId, e.getMessage());

        model.addAttribute("error", "File size exceeds the maximum allowed limit.");
        model.addAttribute("errorId", errorId);

        return "error";
    }

    /**
     * Handle 404 errors
     */
    @ExceptionHandler(NoHandlerFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public String handleNotFoundException(NoHandlerFoundException e,
                                          HttpServletRequest request,
                                          Model model) {
        String errorId = UUID.randomUUID().toString();
        String path = request.getRequestURI();

        logger.debug("404 Not Found [{}]: {}", errorId, path);

        // Check for scanning attempts
        if (path.contains("admin") || path.contains("wp-") || path.contains(".php") ||
                path.contains("phpmyadmin") || path.contains(".env")) {
            logger.warn("Potential scanning attempt: {}", path);
            auditLogService.logSecurityEvent("SCANNING_ATTEMPT",
                    getClientIP(request),
                    "Path: " + inputSanitizer.sanitizeForLog(path));
        }

        model.addAttribute("error", "The requested page could not be found.");
        model.addAttribute("errorId", errorId);

        return "error";
    }

    /**
     * Handle SQL exceptions (should be rare with JPA)
     */
    @ExceptionHandler(org.springframework.dao.DataAccessException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public String handleDataAccessException(org.springframework.dao.DataAccessException e,
                                            HttpServletRequest request,
                                            Model model) {
        String errorId = UUID.randomUUID().toString();

        // Log full exception internally
        logger.error("Database error [{}]: {}", errorId, e.getMessage(), e);

        // Check for SQL injection indicators
        if (e.getMessage() != null &&
                (e.getMessage().contains("syntax") || e.getMessage().contains("SQL"))) {
            auditLogService.logSecurityEvent("POTENTIAL_SQL_INJECTION",
                    getClientIP(request),
                    "Error ID: " + errorId);
        }

        // Generic message for user
        model.addAttribute("error", "A system error occurred. Please try again later.");
        model.addAttribute("errorId", errorId);

        return "error";
    }

    /**
     * Handle runtime exceptions
     */
    @ExceptionHandler(RuntimeException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public String handleRuntimeException(RuntimeException e,
                                         HttpServletRequest request,
                                         Model model) {
        String errorId = UUID.randomUUID().toString();

        // Log full exception internally
        logger.error("Runtime exception [{}]: {}", errorId, e.getMessage(), e);

        // Check for known attack patterns
        if (e.getMessage() != null) {
            String message = e.getMessage().toLowerCase();
            if (message.contains("script") || message.contains("javascript") ||
                    message.contains("onload") || message.contains("onerror")) {
                auditLogService.logSecurityEvent("XSS_ATTEMPT",
                        getClientIP(request),
                        "Error ID: " + errorId);
            }
        }

        // Generic message for user
        model.addAttribute("error", "An unexpected error occurred.");
        model.addAttribute("errorId", errorId);

        return "error";
    }

    /**
     * Handle all other exceptions
     */
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public String handleGenericException(Exception e,
                                         HttpServletRequest request,
                                         Model model) {
        String errorId = UUID.randomUUID().toString();

        // Log full exception internally
        logger.error("Unhandled exception [{}]: {}", errorId, e.getMessage(), e);

        // Log audit event
        auditLogService.logUserAction("SYSTEM", "UNHANDLED_ERROR",
                "Error ID: " + errorId);

        // Generic message for user
        model.addAttribute("error", "An error occurred while processing your request.");
        model.addAttribute("errorId", errorId);
        model.addAttribute("supportMessage",
                "If this problem persists, please contact support with error ID: " + errorId);

        return "error";
    }

    /**
     * Get client IP address
     */
    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }

}
