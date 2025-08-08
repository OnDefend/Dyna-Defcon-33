/**
 * Fingerprint/Biometric Authentication Security Monitoring Script
 * 
 * Comprehensive Frida hooks for monitoring biometric authentication and detecting vulnerabilities.
 * Detects authentication bypass attempts, weak implementations, and insecure fallback mechanisms.
 * 
 * Features:
 * - androidx.biometric.BiometricPrompt monitoring
 * - FingerprintManager (deprecated) monitoring
 * - Authentication callback monitoring
 * - CryptoObject validation
 * - Authentication state management monitoring
 * - Activity lifecycle bypass detection
 * 
 * @version 1.0.0
 * @author AODS Security Team
 */

Java.perform(function() {
    console.log("[FINGERPRINT-MONITOR] Starting comprehensive biometric authentication monitoring");
    
    var authEvents = [];
    var bypassAttempts = [];
    var securityViolations = [];
    
    // Helper function to send biometric event to AODS
    function sendBiometricEvent(eventType, apiType, authResult, evidence) {
        var event = {
            type: "biometric_auth_vulnerability",
            event_type: eventType,
            timestamp: Date.now(),
            api_type: apiType,
            auth_result: authResult,
            evidence: evidence || {},
            security_level: assessSecurityLevel(eventType, evidence),
            stack_trace: getCurrentStackTrace()
        };
        
        console.log("[BIOMETRIC-EVENT] " + JSON.stringify(event));
        send(event);
        authEvents.push(event);
    }
    
    // Helper function to detect and report bypass attempts
    function reportBypassAttempt(method, context, risk, evidence) {
        var bypass = {
            type: "biometric_bypass_attempt",
            method: method,
            context: context,
            risk_level: risk,
            timestamp: Date.now(),
            evidence: evidence || {},
            stack_trace: getCurrentStackTrace()
        };
        
        console.log("[BIOMETRIC-BYPASS] " + JSON.stringify(bypass));
        send(bypass);
        bypassAttempts.push(bypass);
    }
    
    // Assess security level based on event and evidence
    function assessSecurityLevel(eventType, evidence) {
        if (!evidence) return "LOW";
        
        // Critical security issues
        if (!evidence.has_crypto_object || evidence.null_crypto_object) {
            return "HIGH";
        }
        
        // Medium security issues
        if (evidence.deprecated_api || evidence.insecure_storage) {
            return "MEDIUM";
        }
        
        // General monitoring
        return "LOW";
    }
    
    // Get current stack trace for evidence
    function getCurrentStackTrace() {
        try {
            var Exception = Java.use("java.lang.Exception");
            var Log = Java.use("android.util.Log");
            return Log.getStackTraceString(Exception.$new());
        } catch (e) {
            return "Stack trace unavailable";
        }
    }
    
    // ================================
    // ANDROIDX BIOMETRICPROMPT MONITORING
    // ================================
    
    try {
        console.log("[FINGERPRINT-MONITOR] Setting up androidx.biometric.BiometricPrompt hooks...");
        
        var BiometricPrompt = Java.use("androidx.biometric.BiometricPrompt");
        
        // Hook authenticate method without CryptoObject (WEAK IMPLEMENTATION)
        BiometricPrompt.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo').implementation = function(promptInfo) {
            console.log("[BIOMETRIC] BiometricPrompt.authenticate() called WITHOUT CryptoObject");
            
            var promptTitle = "Unknown";
            var promptSubtitle = null;
            try {
                promptTitle = promptInfo.getTitle() ? promptInfo.getTitle().toString() : "Unknown";
                promptSubtitle = promptInfo.getSubtitle() ? promptInfo.getSubtitle().toString() : null;
            } catch (e) {
                console.log("[BIOMETRIC] Error getting prompt info: " + e);
            }
            
            sendBiometricEvent("auth_initiated_weak", "BiometricPrompt", "pending", {
                method: "authenticate(PromptInfo)",
                has_crypto_object: false,
                title: promptTitle,
                subtitle: promptSubtitle,
                security_risk: "HIGH - No CryptoObject for cryptographic validation"
            });
            
            // Report as security violation
            reportBypassAttempt("weak_implementation", "no_crypto_object", "HIGH", {
                reason: "Biometric authentication without CryptoObject",
                impact: "Authentication can be bypassed without cryptographic validation",
                recommendation: "Use CryptoObject for cryptographic operations",
                api_used: "BiometricPrompt.authenticate(PromptInfo)"
            });
            
            return this.authenticate(promptInfo);
        };
        
        // Hook authenticate method with CryptoObject (SECURE IMPLEMENTATION)
        try {
            BiometricPrompt.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo', 'androidx.biometric.BiometricPrompt$CryptoObject').implementation = function(promptInfo, cryptoObject) {
                console.log("[BIOMETRIC] BiometricPrompt.authenticate() called WITH CryptoObject");
                
                var hasCryptoObject = cryptoObject !== null;
                var cryptoObjectType = "null";
                
                if (cryptoObject) {
                    try {
                        cryptoObjectType = cryptoObject.getClass().getName();
                    } catch (e) {
                        console.log("[BIOMETRIC] Error getting CryptoObject type: " + e);
                    }
                }
                
                sendBiometricEvent("auth_initiated_secure", "BiometricPrompt", "pending", {
                    method: "authenticate(PromptInfo, CryptoObject)",
                    has_crypto_object: hasCryptoObject,
                    crypto_object_type: cryptoObjectType,
                    security_level: hasCryptoObject ? "HIGH" : "LOW"
                });
                
                // Check for null CryptoObject (bypass attempt)
                if (!cryptoObject) {
                    reportBypassAttempt("crypto_bypass", "null_crypto_object", "HIGH", {
                        reason: "Null CryptoObject passed to authenticate method",
                        impact: "Bypasses cryptographic validation",
                        recommendation: "Ensure CryptoObject is properly initialized"
                    });
                }
                
                return this.authenticate(promptInfo, cryptoObject);
            };
        } catch (e) {
            console.log("[FINGERPRINT-MONITOR] BiometricPrompt.authenticate with CryptoObject hook failed: " + e);
        }
        
        console.log("[FINGERPRINT-MONITOR] ✅ BiometricPrompt hooks installed");
    } catch (e) {
        console.log("[FINGERPRINT-MONITOR] ❌ BiometricPrompt hooks failed: " + e);
    }
    
    // ================================
    // BIOMETRIC AUTHENTICATION CALLBACKS
    // ================================
    
    try {
        console.log("[FINGERPRINT-MONITOR] Setting up BiometricPrompt callback hooks...");
        
        var AuthenticationCallback = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");
        
        AuthenticationCallback.onAuthenticationSucceeded.implementation = function(result) {
            console.log("[BIOMETRIC-SUCCESS] Authentication succeeded");
            
            var cryptoObjectPresent = false;
            var cryptoObjectInfo = "absent";
            
            try {
                var cryptoObject = result.getCryptoObject();
                cryptoObjectPresent = cryptoObject !== null;
                if (cryptoObject) {
                    cryptoObjectInfo = cryptoObject.getClass().getName();
                }
            } catch (e) {
                console.log("[BIOMETRIC] Error checking CryptoObject in result: " + e);
            }
            
            sendBiometricEvent("auth_success", "BiometricPrompt", "success", {
                method: "onAuthenticationSucceeded",
                crypto_object: cryptoObjectPresent ? "present" : "absent",
                crypto_object_info: cryptoObjectInfo,
                success_timestamp: Date.now()
            });
            
            // Check for successful auth without CryptoObject (potential bypass)
            if (!cryptoObjectPresent) {
                reportBypassAttempt("auth_without_crypto", "success_no_validation", "MEDIUM", {
                    reason: "Authentication succeeded without CryptoObject validation",
                    impact: "May indicate bypassed cryptographic validation",
                    recommendation: "Verify CryptoObject usage in authentication flow"
                });
            }
            
            this.onAuthenticationSucceeded(result);
        };
        
        AuthenticationCallback.onAuthenticationFailed.implementation = function() {
            console.log("[BIOMETRIC-FAILED] Authentication failed");
            
            sendBiometricEvent("auth_failure", "BiometricPrompt", "failed", {
                method: "onAuthenticationFailed",
                failure_timestamp: Date.now()
            });
            
            this.onAuthenticationFailed();
        };
        
        AuthenticationCallback.onAuthenticationError.implementation = function(errorCode, errString) {
            console.log("[BIOMETRIC-ERROR] Authentication error: " + errorCode + " - " + errString);
            
            sendBiometricEvent("auth_error", "BiometricPrompt", "error", {
                method: "onAuthenticationError",
                error_code: errorCode,
                error_string: errString.toString(),
                error_timestamp: Date.now()
            });
            
            this.onAuthenticationError(errorCode, errString);
        };
        
        console.log("[FINGERPRINT-MONITOR] ✅ BiometricPrompt callback hooks installed");
    } catch (e) {
        console.log("[FINGERPRINT-MONITOR] ❌ BiometricPrompt callback hooks failed: " + e);
    }
    
    // ================================
    // DEPRECATED FINGERPRINTMANAGER MONITORING
    // ================================
    
    try {
        console.log("[FINGERPRINT-MONITOR] Setting up deprecated FingerprintManager hooks...");
        
        var FingerprintManager = Java.use("android.hardware.fingerprint.FingerprintManager");
        
        FingerprintManager.authenticate.implementation = function(crypto, cancel, flags, callback, handler) {
            console.log("[FINGERPRINT-DEPRECATED] FingerprintManager.authenticate() called");
            
            var hasCryptoObject = crypto !== null;
            
            sendBiometricEvent("auth_initiated_deprecated", "FingerprintManager", "pending", {
                method: "authenticate(deprecated)",
                has_crypto_object: hasCryptoObject,
                deprecated_api: true,
                security_risk: "Using deprecated FingerprintManager API",
                flags: flags
            });
            
            // Report deprecated API usage
            reportBypassAttempt("deprecated_api", "fingerprintmanager_usage", "MEDIUM", {
                reason: "Using deprecated FingerprintManager instead of BiometricPrompt",
                impact: "Deprecated API may have security vulnerabilities",
                recommendation: "Migrate to androidx.biometric.BiometricPrompt",
                api_used: "FingerprintManager.authenticate"
            });
            
            return this.authenticate(crypto, cancel, flags, callback, handler);
        };
        
        console.log("[FINGERPRINT-MONITOR] ✅ FingerprintManager hooks installed");
    } catch (e) {
        console.log("[FINGERPRINT-MONITOR] ❌ FingerprintManager hooks failed: " + e);
    }
    
    // ================================
    // AUTHENTICATION STATE MONITORING
    // ================================
    
    try {
        console.log("[FINGERPRINT-MONITOR] Setting up authentication state monitoring...");
        
        var SharedPreferences = Java.use("android.content.SharedPreferences");
        
        // Monitor authentication state reads
        SharedPreferences.getBoolean.overload('java.lang.String', 'boolean').implementation = function(key, defValue) {
            var result = this.getBoolean(key, defValue);
            
            var authRelatedKeys = ['auth', 'biometric', 'fingerprint', 'login', 'authenticated', 'verified'];
            var isAuthKey = authRelatedKeys.some(authKey => key.toLowerCase().includes(authKey));
            
            if (isAuthKey) {
                console.log("[AUTH-STATE-READ] Reading auth state: " + key + " = " + result);
                
                sendBiometricEvent("auth_state_read", "SharedPreferences", result ? "authenticated" : "not_authenticated", {
                    method: "getBoolean",
                    key: key,
                    value: result,
                    default_value: defValue,
                    storage_type: "SharedPreferences"
                });
                
                // Check for potential security issue
                if (result === true) {
                    reportBypassAttempt("insecure_storage", "auth_state_in_preferences", "MEDIUM", {
                        reason: "Authentication state stored in SharedPreferences",
                        key: key,
                        impact: "Authentication state can be manipulated",
                        recommendation: "Use secure storage for authentication state"
                    });
                }
            }
            
            return result;
        };
        
        // Monitor authentication state writes
        var SharedPreferencesEditor = Java.use("android.content.SharedPreferences$Editor");
        SharedPreferencesEditor.putBoolean.implementation = function(key, value) {
            var authRelatedKeys = ['auth', 'biometric', 'fingerprint', 'login', 'authenticated', 'verified'];
            var isAuthKey = authRelatedKeys.some(authKey => key.toLowerCase().includes(authKey));
            
            if (isAuthKey) {
                console.log("[AUTH-STATE-WRITE] Writing auth state: " + key + " = " + value);
                
                sendBiometricEvent("auth_state_write", "SharedPreferences", value ? "authenticated" : "not_authenticated", {
                    method: "putBoolean",
                    key: key,
                    value: value,
                    storage_type: "SharedPreferences"
                });
                
                // Detect potential bypass via direct state manipulation
                if (value === true) {
                    reportBypassAttempt("state_manipulation", "direct_auth_write", "HIGH", {
                        reason: "Direct write of authentication success state",
                        key: key,
                        impact: "Authentication may be bypassed by direct state manipulation",
                        recommendation: "Validate authentication before setting state"
                    });
                }
            }
            
            return this.putBoolean(key, value);
        };
        
        console.log("[FINGERPRINT-MONITOR] ✅ Authentication state monitoring hooks installed");
    } catch (e) {
        console.log("[FINGERPRINT-MONITOR] ❌ Authentication state monitoring hooks failed: " + e);
    }
    
    // ================================
    // CRYPTOOBJECT VALIDATION MONITORING
    // ================================
    
    try {
        console.log("[FINGERPRINT-MONITOR] Setting up CryptoObject validation hooks...");
        
        // Hook CryptoObject creation
        var CryptoObject = Java.use("androidx.biometric.BiometricPrompt$CryptoObject");
        
        CryptoObject.$init.overload('javax.crypto.Cipher').implementation = function(cipher) {
            console.log("[CRYPTO-OBJECT] CryptoObject created with Cipher");
            
            var cipherValid = cipher !== null;
            var cipherAlgorithm = "unknown";
            
            if (cipher) {
                try {
                    cipherAlgorithm = cipher.getAlgorithm();
                } catch (e) {
                    console.log("[CRYPTO-OBJECT] Error getting cipher algorithm: " + e);
                }
            }
            
            sendBiometricEvent("crypto_object_created", "BiometricPrompt", "initialized", {
                method: "CryptoObject.init(Cipher)",
                cipher_valid: cipherValid,
                cipher_algorithm: cipherAlgorithm,
                creation_timestamp: Date.now()
            });
            
            if (!cipher) {
                reportBypassAttempt("crypto_bypass", "null_cipher", "HIGH", {
                    reason: "CryptoObject created with null Cipher",
                    impact: "Invalidates cryptographic protection",
                    recommendation: "Ensure Cipher is properly initialized"
                });
            }
            
            return this.$init(cipher);
        };
        
        console.log("[FINGERPRINT-MONITOR] ✅ CryptoObject validation hooks installed");
    } catch (e) {
        console.log("[FINGERPRINT-MONITOR] ❌ CryptoObject validation hooks failed: " + e);
    }
    
    // ================================
    // ACTIVITY LIFECYCLE BYPASS DETECTION
    // ================================
    
    try {
        console.log("[FINGERPRINT-MONITOR] Setting up activity lifecycle bypass detection...");
        
        var Activity = Java.use("android.app.Activity");
        
        Activity.onResume.implementation = function() {
            var activityName = this.getClass().getName();
            console.log("[LIFECYCLE] Activity.onResume(): " + activityName);
            
            sendBiometricEvent("lifecycle_event", "Activity", "resumed", {
                method: "onResume",
                activity: activityName,
                resume_timestamp: Date.now(),
                potential_auth_bypass: "Activity resume may bypass authentication"
            });
            
            this.onResume();
        };
        
        Activity.onPause.implementation = function() {
            var activityName = this.getClass().getName();
            console.log("[LIFECYCLE] Activity.onPause(): " + activityName);
            
            sendBiometricEvent("lifecycle_event", "Activity", "paused", {
                method: "onPause",
                activity: activityName,
                pause_timestamp: Date.now()
            });
            
            this.onPause();
        };
        
        // Monitor for suspicious activity recreation patterns
        Activity.onCreate.implementation = function(savedInstanceState) {
            var activityName = this.getClass().getName();
            var hasInstanceState = savedInstanceState !== null;
            
            console.log("[LIFECYCLE] Activity.onCreate(): " + activityName + " (hasInstanceState: " + hasInstanceState + ")");
            
            sendBiometricEvent("lifecycle_event", "Activity", "created", {
                method: "onCreate",
                activity: activityName,
                has_instance_state: hasInstanceState,
                create_timestamp: Date.now()
            });
            
            this.onCreate(savedInstanceState);
        };
        
        console.log("[FINGERPRINT-MONITOR] ✅ Activity lifecycle hooks installed");
    } catch (e) {
        console.log("[FINGERPRINT-MONITOR] ❌ Activity lifecycle hooks failed: " + e);
    }
    
    // ================================
    // SUMMARY AND PERIODIC REPORTING
    // ================================
    
    // Periodic summary of biometric security events
    setInterval(function() {
        if (authEvents.length > 0 || bypassAttempts.length > 0) {
            var summary = {
                type: "biometric_security_summary",
                total_auth_events: authEvents.length,
                total_bypass_attempts: bypassAttempts.length,
                auth_successes: authEvents.filter(e => e.auth_result === "success").length,
                auth_failures: authEvents.filter(e => e.auth_result === "failed").length,
                high_risk_bypasses: bypassAttempts.filter(b => b.risk_level === "HIGH").length,
                deprecated_api_usage: authEvents.filter(e => e.evidence.deprecated_api).length,
                weak_implementations: authEvents.filter(e => !e.evidence.has_crypto_object).length,
                monitoring_duration: Date.now()
            };
            
            console.log("[BIOMETRIC-SUMMARY] " + JSON.stringify(summary));
            send(summary);
        }
    }, 30000); // Every 30 seconds
    
    console.log("[FINGERPRINT-MONITOR] ✅ Biometric authentication monitoring fully initialized");
    console.log("[FINGERPRINT-MONITOR] Monitoring capabilities:");
    console.log("  • androidx.biometric.BiometricPrompt (modern API)");
    console.log("  • android.hardware.fingerprint.FingerprintManager (deprecated)");
    console.log("  • Authentication callbacks and results");
    console.log("  • CryptoObject creation and validation");
    console.log("  • Authentication state management (SharedPreferences)");
    console.log("  • Activity lifecycle bypass detection");
    console.log("  • Weak implementation detection (no CryptoObject)");
    console.log("  • Deprecated API usage detection");
    console.log("[FINGERPRINT-MONITOR] 🔍 Ready to detect biometric authentication vulnerabilities!");
});