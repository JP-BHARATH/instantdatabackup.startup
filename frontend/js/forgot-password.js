document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const requestOtpBtn = document.getElementById('request-otp-btn');
    const verifyOtpBtn = document.getElementById('verify-otp-btn');
    const resetPasswordBtn = document.getElementById('reset-password-btn');
    const emailInput = document.getElementById('email');
    const otpInput = document.getElementById('otp');
    const newPasswordInput = document.getElementById('new-password');
    const confirmPasswordInput = document.getElementById('confirm-password');
    const stepRequestOtp = document.getElementById('step-request-otp');
    const stepVerifyOtp = document.getElementById('step-verify-otp');
    const stepResetPassword = document.getElementById('step-reset-password');
    const successMessage = document.getElementById('success-message');
    const emailError = document.getElementById('email-error');
    const otpError = document.getElementById('otp-error');
    const passwordError = document.getElementById('password-error');
    
    let resetToken = null;
    let userEmail = null;

    // Request OTP
    requestOtpBtn.addEventListener('click', async function() {
        const email = emailInput.value.trim();
        
        if (!email) {
            emailError.textContent = 'Please enter your email';
            return;
        }
        
        emailError.textContent = '';
        
        try {
            const response = await fetch('/api/auth/forgot-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to send OTP');
            }
            
            userEmail = email;
            stepRequestOtp.style.display = 'none';
            stepVerifyOtp.style.display = 'block';
            
        } catch (error) {
            emailError.textContent = error.message;
            console.error('Error requesting OTP:', error);
        }
    });

    // Verify OTP
    verifyOtpBtn.addEventListener('click', async function() {
        const otp = otpInput.value.trim();
        
        if (!otp || otp.length !== 6) {
            otpError.textContent = 'Please enter a valid 6-digit OTP';
            return;
        }
        
        otpError.textContent = '';
        
        try {
            const response = await fetch('/api/auth/verify-reset-otp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    email: userEmail, 
                    otp 
                })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Invalid OTP');
            }
            
            resetToken = data.resetToken;
            stepVerifyOtp.style.display = 'none';
            stepResetPassword.style.display = 'block';
            
        } catch (error) {
            otpError.textContent = error.message;
            console.error('Error verifying OTP:', error);
        }
    });

    // Reset Password
    resetPasswordBtn.addEventListener('click', async function() {
        const newPassword = newPasswordInput.value;
        const confirmPassword = confirmPasswordInput.value;
        
        if (newPassword.length < 6) {
            passwordError.textContent = 'Password must be at least 6 characters';
            return;
        }
        
        if (newPassword !== confirmPassword) {
            passwordError.textContent = 'Passwords do not match';
            return;
        }
        
        passwordError.textContent = '';
        
        try {
            const response = await fetch('/api/auth/reset-password', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    resetToken,
                    newPassword 
                })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to reset password');
            }
            
            stepResetPassword.style.display = 'none';
            successMessage.style.display = 'block';
            
        } catch (error) {
            passwordError.textContent = error.message;
            console.error('Error resetting password:', error);
        }
    });
});