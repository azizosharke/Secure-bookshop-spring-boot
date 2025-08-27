package com.bookshop.filter;

import com.bookshop.service.AuditLogService;
import com.bookshop.service.SessionService;
import com.bookshop.validator.InputSanitizer;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

 // Validate application
@Component
@Order(1)
public class SecurityFilterChain implements Filter {
    private static final Logger logger = LoggerFactory.getLogger(SecurityFilterChain.class);

    @Autowired
    private SessionService sessionService;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private InputSanitizer inputSanitizer;

    // Paths that don't require authentication
    private static final Set<String> PUBLIC_PATHS = new HashSet<>(Arrays.asList(
            "/", "/login", "/register", "/css", "/js", "/images", "/error", "/favicon.ico"
    ));

    // Security headers
    private static final String CSP_POLICY =
            "default-src 'self'; " +
                    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
                    "style-src 'self' 'unsafe-inline'; " +
                    "img-src 'self' data: https:; " +
                    "font-src 'self' data:; " +
                    "connect-src 'self'; " +
                    "frame-ancestors 'none'; " +
                    "base-uri 'self'; " +
                    "form-action 'self'; " +
                    "upgrade-insecure-requests;";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Add request ID for tracking
        String requestId = UUID.randomUUID().toString();
        httpRequest.setAttribute("requestId", requestId);

        // Set security headers
        setSecurityHeaders(httpResponse);

        // Log request
        String path = httpRequest.getRequestURI();
        String method = httpRequest.getMethod();
        String ip = getClientIP(httpRequest);

        logger.debug("Request: {} {} from {} [{}]", method, path, ip, requestId);

        // Check for malicious patterns in URL
        if (containsMaliciousPattern(path)) {
            logger.error("Malicious URL pattern detected: {} from IP: {}", path, ip);
            auditLogService.logSecurityEvent("MALICIOUS_URL", ip, "Path: " + path);
            httpResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // Validate all request parameters
        if (!validateRequestParameters(httpRequest)) {
            logger.error("Invalid request parameters from IP: {}", ip);
            auditLogService.logSecurityEvent("INVALID_PARAMETERS", ip, "Validation failed");
            httpResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // Check authentication for protected paths
        if (!isPublicPath(path)) {
            HttpSession session = httpRequest.getSession(false);

            if (session == null || session.getAttribute("userId") == null) {
                logger.debug("Unauthenticated access to protected path: {}", path);
                httpResponse.sendRedirect("/login");
                return;
            }

            // Validate session
            String sessionId = session.getId();
            if (!sessionService.isSessionValid(sessionId, ip)) {
                logger.warn("Invalid session detected for path: {} from IP: {}", path, ip);
                session.invalidate();
                httpResponse.sendRedirect("/login");
                return;
            }

            // Check for session anomalies
            String userAgent = httpRequest.getHeader("User-Agent");
            if (sessionService.detectSessionAnomaly(sessionId, userAgent, ip)) {
                logger.error("Session anomaly detected for session: {}",
                        sessionId.substring(0, 8) + "...");
                auditLogService.logSecurityEvent("SESSION_ANOMALY",
                        (String) session.getAttribute("username"),
                        "Suspicious activity detected");
                session.invalidate();
                httpResponse.sendRedirect("/login?error=security");
                return;
            }

            // Check session timeout
            Long loginTime = (Long) session.getAttribute("loginTime");
            Long lastAccess = (Long) session.getAttribute("lastAccess");
            long now = System.currentTimeMillis();

            // Absolute timeout (8 hours)
            if (loginTime != null && (now - loginTime) > 8 * 60 * 60 * 1000) {
                logger.info("Session absolute timeout for user: {}",
                        session.getAttribute("username"));
                session.invalidate();
                httpResponse.sendRedirect("/login?timeout=absolute");
                return;
            }

            // Idle timeout (30 minutes)
            if (lastAccess != null && (now - lastAccess) > 30 * 60 * 1000) {
                logger.info("Session idle timeout for user: {}",
                        session.getAttribute("username"));
                session.invalidate();
                httpResponse.sendRedirect("/login?timeout=idle");
                return;
            }

            // Update last access time
            session.setAttribute("lastAccess", now);

            // Check authorization for admin paths
            if (path.startsWith("/admin") && !"ADMIN".equals(session.getAttribute("role"))) {
                logger.warn("Unauthorized admin access attempt by user: {} for path: {}",
                        session.getAttribute("username"), path);
                auditLogService.logSecurityEvent("UNAUTHORIZED_ADMIN_ACCESS",
                        (String) session.getAttribute("username"),
                        "Attempted to access: " + path);
                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
                return;
            }
        }

        // Add response headers for caching control
        if (path.startsWith("/admin") || path.startsWith("/customer")) {
            httpResponse.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
            httpResponse.setHeader("Pragma", "no-cache");
            httpResponse.setDateHeader("Expires", 0);
        }

        // Continue with the request
        chain.doFilter(request, response);

        // Log response
        logger.debug("Response: {} for {} [{}]", httpResponse.getStatus(), path, requestId);
    }

    private void setSecurityHeaders(HttpServletResponse response) {
        // Security headers
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("X-XSS-Protection", "1; mode=block");
        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        response.setHeader("Content-Security-Policy", CSP_POLICY);
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        response.setHeader("Permissions-Policy",
                "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=()");

        // Remove server header
        response.setHeader("Server", "");
        response.setHeader("X-Powered-By", "");
    }

    private boolean isPublicPath(String path) {
        return PUBLIC_PATHS.stream().anyMatch(path::startsWith);
    }

    private boolean containsMaliciousPattern(String path) {
        // Check for path traversal
        if (path.contains("..") || path.contains("//") || path.contains("\\")) {
            return true;
        }

        // Check for encoded traversal
        String decodedPath = path.toLowerCase();
        if (decodedPath.contains("%2e%2e") || decodedPath.contains("%252e") ||
                decodedPath.contains("..%2f") || decodedPath.contains("%5c")) {
            return true;
        }

        // Check for null bytes
        if (path.contains("\0") || decodedPath.contains("%00")) {
            return true;
        }

        return false;
    }

    private boolean validateRequestParameters(HttpServletRequest request) {
        // Validate all parameter names and values
        var parameterMap = request.getParameterMap();

        for (var entry : parameterMap.entrySet()) {
            String paramName = entry.getKey();
            String[] paramValues = entry.getValue();

            // Check parameter name
            if (inputSanitizer.containsSQLInjection(paramName) ||
                    inputSanitizer.containsXSS(paramName)) {
                logger.error("Malicious parameter name detected: {}",
                        inputSanitizer.sanitizeForLog(paramName));
                return false;
            }

            // Check parameter values
            for (String value : paramValues) {
                if (value != null && value.length() > 10000) {
                    logger.error("Parameter value too long: {} characters", value.length());
                    return false;
                }

                if (inputSanitizer.containsSQLInjection(value) ||
                        inputSanitizer.containsCommandInjection(value)) {
                    logger.error("Malicious parameter value detected");
                    return false;
                }
            }
        }

        return true;
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }

}
