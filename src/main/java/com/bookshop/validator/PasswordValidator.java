package com.bookshop.validator;

import org.springframework.stereotype.Component;
import java.util.regex.Pattern;

@Component
public class PasswordValidator {

    // Password must be at least 8 characters with uppercase, lowercase, number, and special character
    private static final String PASSWORD_PATTERN =
            "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{8,}$";

    private static final Pattern pattern = Pattern.compile(PASSWORD_PATTERN);

    public boolean isValid(String password) {
        if (password == null) {
            return false;
        }
        return pattern.matcher(password).matches();
    }

    public String getPasswordRequirements() {
        return "Password must be at least 8 characters long and contain at least one uppercase letter, " +
                "one lowercase letter, one number, and one special character (@#$%^&+=!)";
    }
}