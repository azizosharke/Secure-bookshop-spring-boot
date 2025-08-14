package com.bookshop.validator;

import org.owasp.encoder.Encode;
import org.springframework.stereotype.Component;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class InputSanitizer {
    private static final Logger logger = LoggerFactory.getLogger(InputSanitizer.class);

    // Patterns for validation
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]{3,50}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@" +
                    "(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$"
    );
    private static final Pattern PHONE_PATTERN = Pattern.compile("^[0-9+\\-() ]{10,20}$");
    private static final Pattern NAME_PATTERN = Pattern.compile("^[a-zA-Z\\s\\-']{1,100}$");
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            ".*(;|--|'|\"|\\*|xp_|sp_|exec|execute|insert|update|delete|drop|create|alter|grant|revoke|union|select|from|where|having|group by|order by).*",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern XSS_PATTERN = Pattern.compile(
            ".*((<|&lt;)script|javascript:|on\\w+\\s*=|<iframe|<object|<embed|<applet|<meta|<link|<style|alert\\(|prompt\\(|confirm\\().*",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile(
            ".*(\\.\\./|\\.\\\\|%2e%2e|%252e%252e).*",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern COMMAND_INJECTION_PATTERN = Pattern.compile(
            ".*(;|\\||&|`|\\$\\(|<\\(|>|>>|\\n|\\r).*"
    );

    /**
     * Sanitize general input - removes dangerous characters
     */
    public String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }

        // Trim whitespace
        input = input.trim();

        // Remove null bytes
        input = input.replace("\0", "");

        // Encode HTML entities to prevent XSS
        input = Encode.forHtml(input);

        // Remove control characters
        input = input.replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", "");

        // Limit length to prevent buffer overflow
        if (input.length() > 1000) {
            input = input.substring(0, 1000);
        }

        return input;
    }

    /**
     * Sanitize input for database queries
     */
    public String sanitizeForDatabase(String input) {
        if (input == null) {
            return null;
        }

        input = sanitizeInput(input);

        // Escape single quotes for SQL
        input = input.replace("'", "''");

        // Check for SQL injection patterns
        if (SQL_INJECTION_PATTERN.matcher(input).matches()) {
            logger.warn("Potential SQL injection attempt detected in input");
            throw new IllegalArgumentException("Invalid input detected");
        }

        return input;
    }

    /**
     * Sanitize input for HTML output
     */
    public String sanitizeForHtml(String input) {
        if (input == null) {
            return null;
        }

        // Use OWASP encoder for HTML context
        return Encode.forHtml(input);
    }

    /**
     * Sanitize input for JavaScript context
     */
    public String sanitizeForJavaScript(String input) {
        if (input == null) {
            return null;
        }

        // Use OWASP encoder for JavaScript context
        return Encode.forJavaScript(input);
    }

    /**
     * Sanitize input for URL context
     */
    public String sanitizeForUrl(String input) {
        if (input == null) {
            return null;
        }

        // Check for path traversal
        if (PATH_TRAVERSAL_PATTERN.matcher(input).matches()) {
            logger.warn("Path traversal attempt detected in input");
            throw new IllegalArgumentException("Invalid path");
        }

        // Use OWASP encoder for URL context
        return Encode.forUriComponent(input);
    }

    /**
     * Sanitize input for log files (prevent log injection)
     */
    public String sanitizeForLog(String input) {
        if (input == null) {
            return null;
        }

        // Remove line breaks and control characters
        input = input.replaceAll("[\r\n]", "_");
        input = input.replaceAll("[\\p{Cntrl}]", "");

        // Limit length
        if (input.length() > 200) {
            input = input.substring(0, 200) + "...";
        }

        return input;
    }

    /**
     * Validate username format
     */
    public boolean isValidUsername(String username) {
        if (username == null) {
            return false;
        }
        return USERNAME_PATTERN.matcher(username).matches();
    }

    /**
     * Validate email format
     */
    public boolean isValidEmail(String email) {
        if (email == null) {
            return false;
        }
        return EMAIL_PATTERN.matcher(email.toLowerCase()).matches();
    }

    /**
     * Validate phone number format
     */
    public boolean isValidPhoneNumber(String phone) {
        if (phone == null) {
            return false;
        }
        return PHONE_PATTERN.matcher(phone).matches();
    }

    /**
     * Validate name format
     */
    public boolean isValidName(String name) {
        if (name == null) {
            return false;
        }
        return NAME_PATTERN.matcher(name).matches();
    }

    /**
     * Check for XSS attempts
     */
    public boolean containsXSS(String input) {
        if (input == null) {
            return false;
        }
        return XSS_PATTERN.matcher(input).matches();
    }

    /**
     * Check for SQL injection attempts
     */
    public boolean containsSQLInjection(String input) {
        if (input == null) {
            return false;
        }
        return SQL_INJECTION_PATTERN.matcher(input).matches();
    }

    /**
     * Check for command injection attempts
     */
    public boolean containsCommandInjection(String input) {
        if (input == null) {
            return false;
        }
        return COMMAND_INJECTION_PATTERN.matcher(input).matches();
    }

    /**
     * Sanitize file name to prevent path traversal
     */
    public String sanitizeFileName(String fileName) {
        if (fileName == null) {
            return null;
        }

        // Remove path separators
        fileName = fileName.replaceAll("[/\\\\]", "");

        // Remove special characters
        fileName = fileName.replaceAll("[^a-zA-Z0-9._-]", "");

        // Remove leading dots
        fileName = fileName.replaceAll("^\\.+", "");

        // Limit length
        if (fileName.length() > 255) {
            fileName = fileName.substring(0, 255);
        }

        return fileName;
    }

    /**
     * Validate and sanitize credit card number (keep only digits)
     */
    public String sanitizeCreditCard(String creditCard) {
        if (creditCard == null) {
            return null;
        }

        // Remove all non-digits
        creditCard = creditCard.replaceAll("[^0-9]", "");

        // Basic length validation
        if (creditCard.length() < 13 || creditCard.length() > 19) {
            throw new IllegalArgumentException("Invalid credit card length");
        }

        return creditCard;
    }

    /**
     * Mask sensitive data for logging
     */
    public String maskSensitiveData(String data, int visibleChars) {
        if (data == null || data.length() <= visibleChars) {
            return data;
        }

        StringBuilder masked = new StringBuilder();
        masked.append(data.substring(0, visibleChars));
        for (int i = visibleChars; i < data.length(); i++) {
            masked.append("*");
        }

        return masked.toString();
    }
}