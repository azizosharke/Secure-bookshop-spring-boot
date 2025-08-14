package com.bookshop.controller;

import com.bookshop.model.User;
import com.bookshop.model.UserRole;
import com.bookshop.service.*;
import com.bookshop.validator.PasswordValidator;
import com.bookshop.validator.InputSanitizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.util.UUID;

@Controller
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private static final String MFA_PENDING_SESSION_KEY = "mfa_pending_user";

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private PasswordValidator passwordValidator;

    @Autowired
    private MFAService mfaService;

    @Autowired
    private InputSanitizer inputSanitizer;

    @Autowired
    private SessionService sessionService;

    @GetMapping("/login")
    public String showLoginForm(HttpServletRequest request, Model model) {
        String ip = getClientIP(request);
        if (loginAttemptService.isBlocked(ip)) {
            model.addAttribute("error", "Too many failed attempts. Please try again later.");
            logger.warn("Blocked login attempt from IP: {}", ip);
        }

        // Generate and set CSRF token if not using Spring Security
        String csrfToken = UUID.randomUUID().toString();
        request.getSession().setAttribute("csrf_token", csrfToken);
        model.addAttribute("csrfToken", csrfToken);

        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        @RequestParam(required = false) String csrfToken,
                        HttpSession session,
                        HttpServletRequest request,
                        HttpServletResponse response,
                        Model model) {

        String ip = getClientIP(request);

        // Validate CSRF token
        String sessionCsrfToken = (String) session.getAttribute("csrf_token");
        if (sessionCsrfToken == null || !sessionCsrfToken.equals(csrfToken)) {
            logger.error("CSRF token validation failed for login attempt from IP: {}", ip);
            auditLogService.logSecurityEvent("CSRF_VALIDATION_FAILED", ip,
                    "Login attempt with invalid CSRF token");
            model.addAttribute("error", "Security validation failed. Please try again.");
            return "login";
        }

        // Check if IP is blocked
        if (loginAttemptService.isBlocked(ip)) {
            logger.warn("Blocked login attempt for user {} from IP: {}",
                    inputSanitizer.sanitizeForLog(username), ip);
            model.addAttribute("error", "Too many failed attempts. Please try again later.");
            return "login";
        }

        // Sanitize and validate input
        username = inputSanitizer.sanitizeInput(username);
        if (!inputSanitizer.isValidUsername(username)) {
            loginAttemptService.loginFailed(ip);
            logger.warn("Invalid username format in login attempt from IP: {}", ip);
            model.addAttribute("error", "Invalid credentials");
            return "login";
        }

        // Authenticate user
        User user = userService.authenticateUser(username, password);
        if (user != null) {
            // Check if MFA is required
            if (mfaService.userNeedsMFA(user)) {
                // Generate and send MFA token
                boolean tokenSent = mfaService.generateAndSendToken(user);
                if (tokenSent) {
                    // Store user temporarily in session
                    session.setAttribute(MFA_PENDING_SESSION_KEY, user.getId());
                    session.setAttribute("mfa_ip", ip);

                    logger.info("MFA required for user: {}", inputSanitizer.sanitizeForLog(username));
                    auditLogService.logUserAction(username, "LOGIN_MFA_REQUIRED",
                            "MFA token sent from IP: " + ip);

                    return "redirect:/mfa-verify";
                } else {
                    logger.error("Failed to send MFA token for user: {}",
                            inputSanitizer.sanitizeForLog(username));
                    model.addAttribute("error", "Authentication service temporarily unavailable");
                    return "login";
                }
            } else {
                // Complete login without MFA
                completeLogin(user, session, request, response);
                return getRedirectUrl(user);
            }
        }

        // Failed login
        loginAttemptService.loginFailed(ip);
        logger.warn("Failed login attempt for user: {} from IP: {}",
                inputSanitizer.sanitizeForLog(username), ip);
        auditLogService.logUserAction(username, "LOGIN_FAILED", "Failed from IP: " + ip);

        model.addAttribute("error", "Invalid credentials");
        return "login";
    }

    @GetMapping("/mfa-verify")
    public String showMFAForm(HttpSession session, Model model) {
        Long userId = (Long) session.getAttribute(MFA_PENDING_SESSION_KEY);
        if (userId == null) {
            return "redirect:/login";
        }

        model.addAttribute("message", "Please enter the verification code sent to your email");
        return "mfa-verify";
    }

    @PostMapping("/mfa-verify")
    public String verifyMFA(@RequestParam String mfaCode,
                            HttpSession session,
                            HttpServletRequest request,
                            HttpServletResponse response,
                            Model model) {

        Long userId = (Long) session.getAttribute(MFA_PENDING_SESSION_KEY);
        String originalIp = (String) session.getAttribute("mfa_ip");
        String currentIp = getClientIP(request);

        if (userId == null) {
            logger.warn("MFA verification attempted without pending session");
            return "redirect:/login";
        }

        // Verify IP hasn't changed (prevent session hijacking)
        if (!currentIp.equals(originalIp)) {
            session.invalidate();
            logger.error("IP address changed during MFA verification. Original: {}, Current: {}",
                    originalIp, currentIp);
            auditLogService.logSecurityEvent("MFA_IP_MISMATCH", currentIp,
                    "IP changed during MFA verification");
            model.addAttribute("error", "Security validation failed. Please login again.");
            return "redirect:/login";
        }

        User user = userService.findById(userId);
        if (user == null) {
            session.invalidate();
            return "redirect:/login";
        }

        // Sanitize MFA code
        mfaCode = inputSanitizer.sanitizeInput(mfaCode);

        // Verify MFA token
        if (mfaService.verifyToken(user, mfaCode)) {
            // Clear MFA session attributes
            session.removeAttribute(MFA_PENDING_SESSION_KEY);
            session.removeAttribute("mfa_ip");

            // Complete login
            completeLogin(user, session, request, response);

            logger.info("MFA verification successful for user: {}",
                    inputSanitizer.sanitizeForLog(user.getUsername()));
            auditLogService.logUserAction(user.getUsername(), "MFA_SUCCESS",
                    "Login completed from IP: " + currentIp);

            return getRedirectUrl(user);
        } else {
            loginAttemptService.loginFailed(currentIp);
            logger.warn("Invalid MFA token for user: {}",
                    inputSanitizer.sanitizeForLog(user.getUsername()));
            auditLogService.logSecurityEvent("MFA_FAILED", user.getUsername(),
                    "Invalid token from IP: " + currentIp);

            model.addAttribute("error", "Invalid verification code. Please try again.");
            return "mfa-verify";
        }
    }

    private void completeLogin(User user, HttpSession session,
                               HttpServletRequest request, HttpServletResponse response) {
        // Clear failed attempts
        loginAttemptService.loginSucceeded(getClientIP(request));

        // Regenerate session ID to prevent session fixation
        request.changeSessionId();

        // Set secure session attributes
        session.setAttribute("userId", user.getId());
        session.setAttribute("username", user.getUsername());
        session.setAttribute("role", user.getRole().toString());
        session.setAttribute("loginTime", System.currentTimeMillis());
        session.setAttribute("loginIP", getClientIP(request));

        // Set session timeout (30 minutes)
        session.setMaxInactiveInterval(1800);

        // Track session
        sessionService.createSession(user, session.getId(), getClientIP(request));

        // Set secure headers
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("X-XSS-Protection", "1; mode=block");

        logger.info("Successful login for user: {} from IP: {}",
                inputSanitizer.sanitizeForLog(user.getUsername()), getClientIP(request));
        auditLogService.logUserAction(user.getUsername(), "LOGIN",
                "Success from IP: " + getClientIP(request));
    }

    private String getRedirectUrl(User user) {
        if (user.getRole() == UserRole.ADMIN) {
            return "redirect:/admin/dashboard";
        } else {
            return "redirect:/customer/books";
        }
    }

    @GetMapping("/register")
    public String showRegisterForm(Model model) {
        model.addAttribute("user", new User());
        model.addAttribute("passwordRequirements", passwordValidator.getPasswordRequirements());
        return "register";
    }

    @PostMapping("/register")
    public String register(@Valid @ModelAttribute User user,
                           BindingResult bindingResult,
                           @RequestParam String confirmPassword,
                           @RequestParam(required = false, defaultValue = "false") boolean enableMfa,
                           HttpServletRequest request,
                           RedirectAttributes redirectAttributes) {

        String ip = getClientIP(request);

        // Sanitize all inputs
        user.setUsername(inputSanitizer.sanitizeInput(user.getUsername()));
        user.setEmail(inputSanitizer.sanitizeInput(user.getEmail()));
        user.setName(inputSanitizer.sanitizeInput(user.getName()));
        user.setSurname(inputSanitizer.sanitizeInput(user.getSurname()));
        user.setAddress(inputSanitizer.sanitizeInput(user.getAddress()));
        user.setPhoneNumber(inputSanitizer.sanitizeInput(user.getPhoneNumber()));

        // Validate inputs
        if (!inputSanitizer.isValidUsername(user.getUsername())) {
            redirectAttributes.addFlashAttribute("error", "Invalid username format");
            return "redirect:/register";
        }

        if (!inputSanitizer.isValidEmail(user.getEmail())) {
            redirectAttributes.addFlashAttribute("error", "Invalid email format");
            return "redirect:/register";
        }

        // Validate password strength
        if (!passwordValidator.isValid(user.getPassword())) {
            redirectAttributes.addFlashAttribute("error", passwordValidator.getPasswordRequirements());
            return "redirect:/register";
        }

        // Check password confirmation
        if (!user.getPassword().equals(confirmPassword)) {
            redirectAttributes.addFlashAttribute("error", "Passwords do not match");
            return "redirect:/register";
        }

        // Check for existing username or email (generic message to prevent enumeration)
        if (userService.usernameExists(user.getUsername()) ||
                userService.emailExists(user.getEmail())) {
            redirectAttributes.addFlashAttribute("error",
                    "Registration failed. Please try with different credentials.");
            logger.info("Registration attempt with existing username or email from IP: {}", ip);
            auditLogService.logUserAction("ANONYMOUS", "REGISTRATION_DUPLICATE",
                    "Attempt from IP: " + ip);
            return "redirect:/register";
        }

        // Hash password before saving
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole(UserRole.CUSTOMER);
        user.setMfaEnabled(enableMfa);

        userService.register(user);

        logger.info("New user registered: {} from IP: {}",
                inputSanitizer.sanitizeForLog(user.getUsername()), ip);
        auditLogService.logUserAction(user.getUsername(), "REGISTRATION",
                "New user registered from IP: " + ip);

        redirectAttributes.addFlashAttribute("success", "Registration successful! Please login.");
        return "redirect:/login";
    }

    @PostMapping("/logout")
    public String logout(HttpSession session, HttpServletRequest request) {
        String username = (String) session.getAttribute("username");
        String sessionId = session.getId();

        if (username != null) {
            logger.info("User logged out: {}", inputSanitizer.sanitizeForLog(username));
            auditLogService.logUserAction(username, "LOGOUT", "User logged out");
            sessionService.invalidateSession(sessionId);
        }

        session.invalidate();
        return "redirect:/";
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}