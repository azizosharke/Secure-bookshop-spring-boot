package com.bookshop.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "user_sessions",
        indexes = {
                @Index(name = "idx_session_id", columnList = "session_id"),
                @Index(name = "idx_user_active", columnList = "user_id, active"),
                @Index(name = "idx_created_at", columnList = "created_at")
        })
public class UserSession {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "session_id", nullable = false, unique = true, length = 100)
    private String sessionId;

    @Column(name = "ip_address", nullable = false, length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "last_accessed_at", nullable = false)
    private LocalDateTime lastAccessedAt;

    @Column(name = "invalidated_at")
    private LocalDateTime invalidatedAt;

    @Column(name = "active", nullable = false)
    private boolean active = true;

    @Column(name = "device_type", length = 50)
    private String deviceType;

    @Column(name = "browser", length = 50)
    private String browser;

    @Column(name = "os", length = 50)
    private String operatingSystem;

    @Column(name = "location", length = 100)
    private String location;

    @Column(name = "login_method", length = 20)
    private String loginMethod; // PASSWORD, MFA, SSO, etc.

    @Column(name = "security_flags")
    private int securityFlags; // Bit flags for security events

    // Security flag constants
    public static final int FLAG_SUSPICIOUS_ACTIVITY = 1;
    public static final int FLAG_IP_CHANGED = 2;
    public static final int FLAG_DEVICE_CHANGED = 4;
    public static final int FLAG_RAPID_REQUESTS = 8;
    public static final int FLAG_CONCURRENT_SESSION = 16;

    // Constructors
    public UserSession() {
        this.createdAt = LocalDateTime.now();
        this.lastAccessedAt = LocalDateTime.now();
        this.active = true;
        this.securityFlags = 0;
    }

    public UserSession(User user, String sessionId, String ipAddress) {
        this();
        this.user = user;
        this.sessionId = sessionId;
        this.ipAddress = ipAddress;
    }

    // Helper methods
    public boolean isExpired(int maxIdleMinutes) {
        if (!active) {
            return true;
        }
        return LocalDateTime.now().isAfter(lastAccessedAt.plusMinutes(maxIdleMinutes));
    }

    public void updateLastAccessed() {
        this.lastAccessedAt = LocalDateTime.now();
    }

    public void invalidate() {
        this.active = false;
        this.invalidatedAt = LocalDateTime.now();
    }

    public void addSecurityFlag(int flag) {
        this.securityFlags |= flag;
    }

    public boolean hasSecurityFlag(int flag) {
        return (this.securityFlags & flag) != 0;
    }

    public void parseUserAgent(String userAgent) {
        this.userAgent = userAgent;
        // Parse browser, OS, and device type from user agent
        // This is a simplified version - in production, use a library like user-agent-utils
        if (userAgent != null) {
            if (userAgent.contains("Mobile")) {
                this.deviceType = "Mobile";
            } else if (userAgent.contains("Tablet")) {
                this.deviceType = "Tablet";
            } else {
                this.deviceType = "Desktop";
            }

            if (userAgent.contains("Chrome")) {
                this.browser = "Chrome";
            } else if (userAgent.contains("Firefox")) {
                this.browser = "Firefox";
            } else if (userAgent.contains("Safari")) {
                this.browser = "Safari";
            } else if (userAgent.contains("Edge")) {
                this.browser = "Edge";
            } else {
                this.browser = "Other";
            }

            if (userAgent.contains("Windows")) {
                this.operatingSystem = "Windows";
            } else if (userAgent.contains("Mac")) {
                this.operatingSystem = "macOS";
            } else if (userAgent.contains("Linux")) {
                this.operatingSystem = "Linux";
            } else if (userAgent.contains("Android")) {
                this.operatingSystem = "Android";
            } else if (userAgent.contains("iOS")) {
                this.operatingSystem = "iOS";
            } else {
                this.operatingSystem = "Other";
            }
        }
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
        parseUserAgent(userAgent);
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getLastAccessedAt() {
        return lastAccessedAt;
    }

    public void setLastAccessedAt(LocalDateTime lastAccessedAt) {
        this.lastAccessedAt = lastAccessedAt;
    }

    public LocalDateTime getInvalidatedAt() {
        return invalidatedAt;
    }

    public void setInvalidatedAt(LocalDateTime invalidatedAt) {
        this.invalidatedAt = invalidatedAt;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public String getDeviceType() {
        return deviceType;
    }

    public void setDeviceType(String deviceType) {
        this.deviceType = deviceType;
    }

    public String getBrowser() {
        return browser;
    }

    public void setBrowser(String browser) {
        this.browser = browser;
    }

    public String getOperatingSystem() {
        return operatingSystem;
    }

    public void setOperatingSystem(String operatingSystem) {
        this.operatingSystem = operatingSystem;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getLoginMethod() {
        return loginMethod;
    }

    public void setLoginMethod(String loginMethod) {
        this.loginMethod = loginMethod;
    }

    public int getSecurityFlags() {
        return securityFlags;
    }

    public void setSecurityFlags(int securityFlags) {
        this.securityFlags = securityFlags;
    }
}