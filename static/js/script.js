// JavaScript untuk Catatan Harian

document.addEventListener('DOMContentLoaded', function() {
    // Password toggle functionality
    setupPasswordToggle();
    
    // Form validation
    setupFormValidation();
    
    // Password strength checker
    setupPasswordStrength();
    
    // Auto-save functionality for notes (optional)
    setupAutoSave();
    
    // Initialize tooltips and popovers
    initializeBootstrapComponents();
    
    // Setup note PIN options toggle
    setupNotePinToggle();
});

function setupPasswordToggle() {
    const toggleButtons = document.querySelectorAll('#togglePassword, #toggleConfirmPassword');
    
    toggleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.id === 'togglePassword' ? 'password' : 'confirm_password';
            const passwordField = document.getElementById(targetId);
            const icon = this.querySelector('i');
            
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                passwordField.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });
    });
}

function setupFormValidation() {
    // Login form validation
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            
            if (!email || !password) {
                e.preventDefault();
                showAlert('Semua field harus diisi!', 'error');
                return false;
            }
            
            if (!isValidEmail(email)) {
                e.preventDefault();
                showAlert('Format email tidak valid!', 'error');
                return false;
            }
        });
    }
    
    // Register form validation
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            
            if (!name || !email || !password || !confirmPassword) {
                e.preventDefault();
                showAlert('Semua field harus diisi!', 'error');
                return false;
            }
            
            if (!isValidEmail(email)) {
                e.preventDefault();
                showAlert('Format email tidak valid!', 'error');
                return false;
            }
            
            if (password !== confirmPassword) {
                e.preventDefault();
                showAlert('Password dan konfirmasi password tidak cocok!', 'error');
                return false;
            }
            
            if (!isStrongPassword(password)) {
                e.preventDefault();
                showAlert('Password tidak memenuhi syarat keamanan!', 'error');
                return false;
            }
        });
    }
    
    // Note form validation
    const noteForm = document.getElementById('noteForm');
    if (noteForm) {
        noteForm.addEventListener('submit', function(e) {
            const title = document.getElementById('title').value.trim();
            const content = document.getElementById('content').value.trim();
            
            if (!title || !content) {
                e.preventDefault();
                showAlert('Judul dan isi catatan harus diisi!', 'error');
                return false;
            }
            
            if (title.length > 100) {
                e.preventDefault();
                showAlert('Judul terlalu panjang (maksimal 100 karakter)!', 'error');
                return false;
            }
        });
    }
    
    // App lock PIN validation
    const appLockForm = document.getElementById('appLockForm');
    if (appLockForm) {
        const pinInput = document.getElementById('pin');
        
        // Only allow numbers
        pinInput.addEventListener('input', function() {
            this.value = this.value.replace(/[^0-9]/g, '');
            
            // Auto-submit when 4 digits are entered
            if (this.value.length === 4) {
                appLockForm.submit();
            }
        });
        
        pinInput.addEventListener('keypress', function(e) {
            // Only allow numbers
            if (!/[0-9]/.test(e.key) && !['Backspace', 'Delete', 'Tab'].includes(e.key)) {
                e.preventDefault();
            }
        });
    }
    
    // App lock setup PIN validation
    const appLockPinInput = document.getElementById('app_lock_pin');
    if (appLockPinInput) {
        appLockPinInput.addEventListener('input', function() {
            this.value = this.value.replace(/[^0-9]/g, '');
        });
        
        appLockPinInput.addEventListener('keypress', function(e) {
            if (!/[0-9]/.test(e.key) && !['Backspace', 'Delete', 'Tab'].includes(e.key)) {
                e.preventDefault();
            }
        });
    }
}

function setupPasswordStrength() {
    const passwordInput = document.getElementById('password');
    if (passwordInput && passwordInput.closest('#registerForm')) {
        const strengthIndicator = document.createElement('div');
        strengthIndicator.className = 'password-strength';
        
        // Find the password field container (mb-3 div) and append after input-group
        const passwordContainer = passwordInput.closest('.mb-3');
        const inputGroup = passwordInput.closest('.input-group');
        
        if (passwordContainer && inputGroup) {
            // Insert the strength indicator after the input-group but before form-text
            const formText = passwordContainer.querySelector('.form-text');
            if (formText) {
                passwordContainer.insertBefore(strengthIndicator, formText);
            } else {
                passwordContainer.appendChild(strengthIndicator);
            }
        }
        
        passwordInput.addEventListener('input', function() {
            const strength = calculatePasswordStrength(this.value);
            updateStrengthIndicator(strengthIndicator, strength);
        });
    }
}

function calculatePasswordStrength(password) {
    let score = 0;
    
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    
    if (score < 3) return 'weak';
    if (score < 5) return 'medium';
    return 'strong';
}

function updateStrengthIndicator(indicator, strength) {
    indicator.className = 'password-strength';
    indicator.classList.add(`strength-${strength}`);
    
    const width = strength === 'weak' ? '33%' : strength === 'medium' ? '66%' : '100%';
    indicator.style.width = width;
}

function setupAutoSave() {
    const noteContent = document.getElementById('content');
    if (noteContent) {
        let autoSaveTimeout;
        
        noteContent.addEventListener('input', function() {
            clearTimeout(autoSaveTimeout);
            autoSaveTimeout = setTimeout(() => {
                // Optional: Implement auto-save to localStorage
                const title = document.getElementById('title').value;
                const content = this.value;
                
                if (title || content) {
                    localStorage.setItem('draft_note', JSON.stringify({
                        title: title,
                        content: content,
                        timestamp: new Date().toISOString()
                    }));
                }
            }, 1000);
        });
        
        // Load draft on page load
        const draft = localStorage.getItem('draft_note');
        if (draft) {
            try {
                const parsed = JSON.parse(draft);
                const titleInput = document.getElementById('title');
                
                if (!titleInput.value && !noteContent.value) {
                    if (confirm('Ada draft catatan yang belum disimpan. Apakah ingin melanjutkan?')) {
                        titleInput.value = parsed.title || '';
                        noteContent.value = parsed.content || '';
                    }
                }
            } catch (e) {
                console.error('Error loading draft:', e);
            }
        }
    }
}

function initializeBootstrapComponents() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
}

// Utility functions
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function isStrongPassword(password) {
    return password.length >= 8 &&
           /[a-z]/.test(password) &&
           /[A-Z]/.test(password) &&
           /[0-9]/.test(password) &&
           /[^A-Za-z0-9]/.test(password);
}

function showAlert(message, type = 'info') {
    // Create alert element
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type === 'error' ? 'danger' : 'success'} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Insert at the top of the container
    const container = document.querySelector('.container');
    if (container) {
        container.insertBefore(alertDiv, container.firstChild);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }
}

// Clear draft when note is successfully saved
window.addEventListener('beforeunload', function() {
    // Clear draft if we're leaving the note page after successful save
    if (window.location.pathname !== '/note') {
        localStorage.removeItem('draft_note');
    }
});

// Format date display (if moment.js alternative is needed)
function formatDate(dateString) {
    if (!dateString) return 'Tanggal tidak tersedia';
    
    const date = new Date(dateString);
    const options = {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    };
    
    return date.toLocaleDateString('id-ID', options);
}

function setupNotePinToggle() {
    const isLockedCheckbox = document.getElementById('is_locked');
    const isPublicCheckbox = document.getElementById('is_public');
    const pinOptions = document.getElementById('pinOptions');
    const useCustomPinRadio = document.getElementById('use_custom_pin');
    const customPinInput = document.getElementById('customPinInput');
    const notePinField = document.getElementById('note_pin');
    
    // Handle mutual exclusivity between public and locked
    if (isLockedCheckbox && isPublicCheckbox) {
        isLockedCheckbox.addEventListener('change', function() {
            if (this.checked) {
                isPublicCheckbox.checked = false;
                if (pinOptions) pinOptions.style.display = 'block';
            } else {
                if (pinOptions) {
                    pinOptions.style.display = 'none';
                    if (customPinInput) customPinInput.style.display = 'none';
                    if (notePinField) notePinField.required = false;
                }
            }
        });
        
        isPublicCheckbox.addEventListener('change', function() {
            if (this.checked) {
                isLockedCheckbox.checked = false;
                if (pinOptions) {
                    pinOptions.style.display = 'none';
                    if (customPinInput) customPinInput.style.display = 'none';
                    if (notePinField) notePinField.required = false;
                }
            }
        });
    }
    
    if (isLockedCheckbox && pinOptions) {
        // Toggle PIN options when lock checkbox is changed
        isLockedCheckbox.addEventListener('change', function() {
            if (this.checked) {
                pinOptions.style.display = 'block';
            } else {
                pinOptions.style.display = 'none';
                if (customPinInput) customPinInput.style.display = 'none';
                if (notePinField) notePinField.required = false;
            }
        });
    }
    
    if (useCustomPinRadio && customPinInput && notePinField) {
        // Toggle custom PIN input when radio is changed
        const pinOptionRadios = document.querySelectorAll('input[name="pin_option"]');
        pinOptionRadios.forEach(radio => {
            radio.addEventListener('change', function() {
                if (this.value === 'custom_pin') {
                    customPinInput.style.display = 'block';
                    notePinField.required = true;
                } else {
                    customPinInput.style.display = 'none';
                    notePinField.required = false;
                }
            });
        });
        
        // Validate PIN input (numbers only)
        notePinField.addEventListener('input', function() {
            this.value = this.value.replace(/[^0-9]/g, '');
        });
        
        notePinField.addEventListener('keypress', function(e) {
            if (!/[0-9]/.test(e.key) && !['Backspace', 'Delete', 'Tab'].includes(e.key)) {
                e.preventDefault();
            }
        });
    }
}

// Update all date displays on page load
document.addEventListener('DOMContentLoaded', function() {
    const dateElements = document.querySelectorAll('[data-date]');
    dateElements.forEach(element => {
        const dateString = element.getAttribute('data-date');
        element.textContent = formatDate(dateString);
    });
});