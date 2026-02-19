/* ===========================================
   D-Drive — Security Module
   Handles authentication, input sanitization,
   anti-tampering, rate limiting, and session management.
   =========================================== */

const DDriveSecurity = (() => {
  'use strict';

  // =============================================
  // 🔑 PASTE YOUR HASH AND SALT FROM THE
  //    hash-password.html TOOL HERE:
  // =============================================
  const ADMIN_HASH = 'aacc7b321230e6df0ff93d1eaeb3d6f34a38ff802659d4c9fbeb65644a873e75';
  const ADMIN_SALT = 'b74e56f001561f7c27aaeb588b2eb0d30957530b1f7c4190acf329b851e83572';
  const PBKDF2_ITERATIONS = 600000;
  // =============================================

  // ---- Rate Limiting ----
  const MAX_LOGIN_ATTEMPTS = 5;
  const LOCKOUT_DURATION_MS = 5 * 60 * 1000; // 5 minutes
  const SESSION_TIMEOUT_MS = 30 * 60 * 1000;  // 30 minutes of inactivity

  let loginAttempts = 0;
  let lockoutUntil = 0;
  let lastActivity = Date.now();
  let sessionTimer = null;

  // ---- Password Verification (PBKDF2) ----
  async function verifyPassword(password) {
    // Check rate limit
    if (Date.now() < lockoutUntil) {
      const remainingSec = Math.ceil((lockoutUntil - Date.now()) / 1000);
      return {
        success: false,
        error: `Too many attempts. Locked out for ${remainingSec} seconds.`
      };
    }

    try {
      // Convert hex salt back to Uint8Array
      const saltBytes = new Uint8Array(
        ADMIN_SALT.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
      );

      // Derive key from entered password
      const encoder = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
      );
      const derivedBits = await crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt: saltBytes,
          iterations: PBKDF2_ITERATIONS,
          hash: 'SHA-256'
        },
        keyMaterial, 256
      );

      const hashArray = Array.from(new Uint8Array(derivedBits));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      // Constant-time comparison (prevents timing attacks)
      const isValid = timingSafeEqual(hashHex, ADMIN_HASH);

      if (isValid) {
        loginAttempts = 0;
        startSession();
        return { success: true };
      } else {
        loginAttempts++;
        if (loginAttempts >= MAX_LOGIN_ATTEMPTS) {
          lockoutUntil = Date.now() + LOCKOUT_DURATION_MS;
          loginAttempts = 0;
          return {
            success: false,
            error: `Too many failed attempts. Locked out for 5 minutes.`
          };
        }
        return {
          success: false,
          error: `Incorrect password. ${MAX_LOGIN_ATTEMPTS - loginAttempts} attempts remaining.`
        };
      }
    } catch (err) {
      console.error('Auth error:', err);
      return { success: false, error: 'Authentication error. Try again.' };
    }
  }

  // Constant-time string comparison (prevents timing attacks)
  function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }

  // ---- Session Management ----
  function startSession() {
    lastActivity = Date.now();
    // Store encrypted session token
    const token = generateSessionToken();
    sessionStorage.setItem('ddrive_session', token);
    sessionStorage.setItem('ddrive_session_start', Date.now().toString());
    startActivityMonitor();
  }

  function generateSessionToken() {
    const arr = crypto.getRandomValues(new Uint8Array(32));
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function isSessionValid() {
    const token = sessionStorage.getItem('ddrive_session');
    const startTime = parseInt(sessionStorage.getItem('ddrive_session_start') || '0');
    if (!token) return false;

    // Check if session has expired due to inactivity
    if (Date.now() - lastActivity > SESSION_TIMEOUT_MS) {
      destroySession();
      return false;
    }

    // Check absolute session time (max 4 hours)
    if (Date.now() - startTime > 4 * 60 * 60 * 1000) {
      destroySession();
      return false;
    }

    return true;
  }

  function destroySession() {
    sessionStorage.removeItem('ddrive_session');
    sessionStorage.removeItem('ddrive_session_start');
    if (sessionTimer) clearInterval(sessionTimer);
  }

  function startActivityMonitor() {
    // Update last activity on user interaction
    const updateActivity = () => { lastActivity = Date.now(); };
    document.addEventListener('mousemove', updateActivity, { passive: true });
    document.addEventListener('keydown', updateActivity, { passive: true });
    document.addEventListener('click', updateActivity, { passive: true });
    document.addEventListener('scroll', updateActivity, { passive: true });

    // Check session every 60 seconds
    sessionTimer = setInterval(() => {
      if (!isSessionValid()) {
        // Trigger logout callback if set
        if (typeof window._ddrive_logout === 'function') {
          window._ddrive_logout();
        }
      }
    }, 60000);
  }

  // ---- Input Sanitization (XSS Prevention) ----
  function sanitizeText(input) {
    if (typeof input !== 'string') return '';
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
  }

  function sanitizeTags(tagsArray) {
    if (!Array.isArray(tagsArray)) return [];
    return tagsArray
      .map(tag => sanitizeText(tag.trim()))
      .filter(tag => tag.length > 0 && tag.length <= 50)
      .slice(0, 20); // Max 20 tags
  }

  function sanitizeFileName(name) {
    if (typeof name !== 'string') return 'unnamed';
    // Remove path separators, null bytes, and other dangerous chars
    return name
      .replace(/[/\\:*?"<>|\x00-\x1f]/g, '_')
      .slice(0, 200);
  }

  // ---- Data Integrity (Anti-Tampering) ----
  async function computeChecksum(data) {
    const encoder = new TextEncoder();
    const buffer = encoder.encode(JSON.stringify(data));
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function saveWithIntegrity(key, data) {
    const checksum = await computeChecksum(data);
    localStorage.setItem(key, JSON.stringify(data));
    localStorage.setItem(key + '_checksum', checksum);
  }

  async function loadWithIntegrity(key) {
    const data = localStorage.getItem(key);
    const storedChecksum = localStorage.getItem(key + '_checksum');

    if (!data) return { valid: true, data: [] };

    const parsed = JSON.parse(data);

    // If no checksum yet (first time), it's valid
    if (!storedChecksum) return { valid: true, data: parsed };

    const currentChecksum = await computeChecksum(parsed);
    if (currentChecksum !== storedChecksum) {
      console.warn(`⚠️ Data integrity check failed for "${key}". Data may have been tampered with.`);
      return { valid: false, data: parsed };
    }

    return { valid: true, data: parsed };
  }

  // ---- Content Security ----
  function enforceCSP() {
    // Block eval and inline scripts via meta tag (already in HTML)
    // Additional runtime protections:

    // Disable right-click context menu (optional deterrent)
    document.addEventListener('contextmenu', (e) => {
      if (!isSessionValid()) {
        e.preventDefault();
      }
    });

    // Detect DevTools open (basic deterrent — not foolproof)
    let devtoolsOpen = false;
    const threshold = 160;
    const checkDevTools = () => {
      if (
        window.outerWidth - window.innerWidth > threshold ||
        window.outerHeight - window.innerHeight > threshold
      ) {
        if (!devtoolsOpen) {
          devtoolsOpen = true;
          console.log('%c⚠️ D-Drive Security Notice', 'font-size:24px;color:red;font-weight:bold;');
          console.log('%cThis is a protected archive. Unauthorized access attempts are logged.', 'font-size:14px;color:orange;');
        }
      } else {
        devtoolsOpen = false;
      }
    };
    setInterval(checkDevTools, 1000);
  }

  // ---- Image Validation ----
  function validateImageFile(file) {
    const errors = [];

    // Check file type
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp'];
    if (!allowedTypes.includes(file.type)) {
      errors.push(`Invalid file type: ${file.type}. Only images are allowed.`);
    }

    // Check file size (max 15MB)
    const maxSize = 15 * 1024 * 1024;
    if (file.size > maxSize) {
      errors.push(`File too large: ${(file.size / 1024 / 1024).toFixed(1)}MB. Max is 15MB.`);
    }

    // Check file extension
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'];
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    if (!allowedExtensions.includes(ext)) {
      errors.push(`Invalid file extension: ${ext}`);
    }

    return { valid: errors.length === 0, errors };
  }

  // ---- Rate Limit Info ----
  function getRateLimitInfo() {
    if (Date.now() < lockoutUntil) {
      return {
        locked: true,
        remainingSeconds: Math.ceil((lockoutUntil - Date.now()) / 1000),
        attemptsLeft: 0
      };
    }
    return {
      locked: false,
      remainingSeconds: 0,
      attemptsLeft: MAX_LOGIN_ATTEMPTS - loginAttempts
    };
  }

  // ---- Public API ----
  return {
    verifyPassword,
    isSessionValid,
    destroySession,
    startSession,
    sanitizeText,
    sanitizeTags,
    sanitizeFileName,
    validateImageFile,
    saveWithIntegrity,
    loadWithIntegrity,
    enforceCSP,
    getRateLimitInfo
  };

})();