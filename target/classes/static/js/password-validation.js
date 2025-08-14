// Password validation script
function validatePassword() {
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const strengthDiv = document.getElementById('password-strength');
    
    // Check password strength
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[@#$%^&+=!]/.test(password);
    const isLongEnough = password.length >= 8;
    
    // Calculate strength
    let strength = 0;
    let strengthText = '';
    let strengthClass = '';
    
    if (hasUpperCase) strength++;
    if (hasLowerCase) strength++;
    if (hasNumbers) strength++;
    if (hasSpecialChar) strength++;
    if (isLongEnough) strength++;
    
    if (strength < 3) {
        strengthText = 'Weak';
        strengthClass = 'weak';
    } else if (strength < 5) {
        strengthText = 'Medium';
        strengthClass = 'medium';
    } else {
        strengthText = 'Strong';
        strengthClass = 'strong';
    }
    
    // Update strength indicator
    if (strengthDiv) {
        strengthDiv.innerHTML = `<span class="strength-${strengthClass}">Password Strength: ${strengthText}</span>`;
    }
    
    // Validate all requirements
    if (!isLongEnough) {
        alert('Password must be at least 8 characters long');
        return false;
    }
    
    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
        alert('Password must contain uppercase, lowercase, number, and special character (@#$%^&+=!)');
        return false;
    }
    
    // Check password match
    if (password !== confirmPassword) {
        alert('Passwords do not match');
        return false;
    }
    
    return true;
}

// Real-time password strength indicator
document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            const password = this.value;
            const strengthDiv = document.getElementById('password-strength');
            
            if (!strengthDiv) return;
            
            const hasUpperCase = /[A-Z]/.test(password);
            const hasLowerCase = /[a-z]/.test(password);
            const hasNumbers = /\d/.test(password);
            const hasSpecialChar = /[@#$%^&+=!]/.test(password);
            const isLongEnough = password.length >= 8;
            
            let requirements = [];
            if (!isLongEnough) requirements.push('8+ characters');
            if (!hasUpperCase) requirements.push('uppercase letter');
            if (!hasLowerCase) requirements.push('lowercase letter');
            if (!hasNumbers) requirements.push('number');
            if (!hasSpecialChar) requirements.push('special character');
            
            if (requirements.length > 0) {
                strengthDiv.innerHTML = `<span style="color: #ef4444;">Missing: ${requirements.join(', ')}</span>`;
            } else {
                strengthDiv.innerHTML = '<span style="color: #10b981;">✓ Password meets all requirements</span>';
            }
        });
    }
});