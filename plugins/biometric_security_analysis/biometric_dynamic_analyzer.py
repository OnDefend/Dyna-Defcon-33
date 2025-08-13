"""
Biometric Dynamic Analyzer

Provides runtime monitoring of biometric authentication APIs using Frida hooks.
Detects authentication bypass attempts and insecure biometric implementations.
"""

import logging
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from core.apk_ctx import APKContext

logger = logging.getLogger(__name__)

@dataclass
class BiometricRuntimeEvent:
    """Represents a biometric runtime event."""
    event_type: str
    timestamp: float
    api_type: str
    auth_result: str
    security_level: str
    evidence: Dict[str, Any]

class BiometricDynamicAnalyzer:
    """Dynamic analyzer for biometric authentication runtime monitoring."""
    
    def __init__(self):
        """Initialize the dynamic analyzer."""
        self.logger = logger
        self.runtime_events = []
        
        # Authentication bypass patterns
        self.bypass_indicators = {
            "state_manipulation": [
                "auth_bypass",
                "biometric_disabled",
                "force_success",
                "skip_auth"
            ],
            "lifecycle_bypass": [
                "activity_recreation",
                "process_restart",
                "background_foreground"
            ],
            "crypto_bypass": [
                "null_crypto_object",
                "invalid_cipher",
                "missing_validation"
            ],
            "fallback_abuse": [
                "weak_fallback",
                "fallback_bypass",
                "credential_skip"
            ]
        }
    
    def analyze_biometric_runtime(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Perform runtime analysis of biometric authentication.
        
        Args:
            apk_ctx: The APK context for analysis
            
        Returns:
            Dictionary containing dynamic analysis results
        """
        try:
            self.logger.info("Starting biometric dynamic analysis")
            
            results = {
                "runtime_monitoring": {},
                "auth_events": [],
                "bypass_attempts": [],
                "vulnerability_detections": [],
                "monitoring_stats": {
                    "total_events": 0,
                    "auth_successes": 0,
                    "auth_failures": 0,
                    "bypass_attempts": 0
                }
            }
            
            # Start runtime monitoring if Frida manager is available
            if hasattr(apk_ctx, 'frida_manager') and apk_ctx.frida_manager:
                monitoring_results = self._start_biometric_monitoring(apk_ctx.frida_manager)
                results["runtime_monitoring"] = monitoring_results
                
                # Analyze collected events
                analysis = self._analyze_runtime_events()
                results.update(analysis)
            else:
                self.logger.warning("Frida manager not available - skipping dynamic biometric analysis")
                results["runtime_monitoring"] = {"error": "Frida manager not available"}
            
            return results
            
        except Exception as e:
            self.logger.error(f"Biometric dynamic analysis failed: {e}")
            return {
                "error": str(e),
                "runtime_monitoring": {},
                "auth_events": []
            }
    
    def _start_biometric_monitoring(self, frida_manager) -> Dict[str, Any]:
        """Start Frida-based biometric authentication monitoring."""
        try:
            self.logger.info("Starting Frida biometric monitoring")
            
            # Load and execute biometric monitoring script
            biometric_script = self._generate_biometric_monitoring_script()
            
            # Execute the script using Frida manager
            script_result = frida_manager.execute_script(biometric_script, "biometric_monitoring")
            
            if script_result and script_result.get("success"):
                return {
                    "status": "monitoring_active",
                    "script_loaded": True,
                    "monitoring_targets": [
                        "BiometricPrompt",
                        "FingerprintManager",
                        "Authentication callbacks",
                        "CryptoObject validation",
                        "Auth state management"
                    ]
                }
            else:
                return {
                    "status": "monitoring_failed",
                    "script_loaded": False,
                    "error": script_result.get("error", "Unknown error")
                }
                
        except Exception as e:
            self.logger.error(f"Biometric monitoring startup failed: {e}")
            return {
                "status": "monitoring_error",
                "error": str(e)
            }
    
    def _generate_biometric_monitoring_script(self) -> str:
        """Generate Frida script for biometric authentication monitoring."""
        script = """
        Java.perform(function() {
            console.log("[BIOMETRIC-MONITOR] Starting biometric authentication monitoring");
            
            var authEvents = [];
            var bypassAttempts = [];
            
            // Helper function to send biometric event
            function sendBiometricEvent(eventType, apiType, authResult, evidence) {
                var event = {
                    type: "biometric_auth_event",
                    event_type: eventType,
                    timestamp: Date.now(),
                    api_type: apiType,
                    auth_result: authResult,
                    evidence: evidence || {},
                    stack_trace: getCurrentStackTrace()
                };
                
                console.log("[BIOMETRIC-EVENT] " + JSON.stringify(event));
                send(event);
                authEvents.push(event);
            }
            
            // Helper function to detect bypass attempts
            function detectBypassAttempt(method, context, evidence) {
                var bypass = {
                    type: "biometric_bypass_attempt",
                    method: method,
                    context: context,
                    timestamp: Date.now(),
                    evidence: evidence,
                    stack_trace: getCurrentStackTrace()
                };
                
                console.log("[BIOMETRIC-BYPASS] " + JSON.stringify(bypass));
                send(bypass);
                bypassAttempts.push(bypass);
            }
            
            // Get stack trace for evidence
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
            // ANDROIDX BIOMETRIC MONITORING
            // ================================
            
            try {
                console.log("[BIOMETRIC-MONITOR] Setting up androidx.biometric hooks...");
                
                var BiometricPrompt = Java.use("androidx.biometric.BiometricPrompt");
                
                // Hook authenticate methods
                BiometricPrompt.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo').implementation = function(promptInfo) {
                    console.log("[BIOMETRIC] BiometricPrompt.authenticate() called without CryptoObject");
                    
                    sendBiometricEvent("auth_initiated", "BiometricPrompt", "pending", {
                        method: "authenticate(PromptInfo)",
                        has_crypto_object: false,
                        title: promptInfo.getTitle ? promptInfo.getTitle().toString() : "unknown",
                        subtitle: promptInfo.getSubtitle ? promptInfo.getSubtitle().toString() : null
                    });
                    
                    // Check for weak implementation (no CryptoObject)
                    detectBypassAttempt("weak_implementation", "no_crypto_object", {
                        risk: "HIGH",
                        reason: "Biometric authentication without CryptoObject",
                        recommendation: "Use CryptoObject for cryptographic operations"
                    });
                    
                    return this.authenticate(promptInfo);
                };
                
                // Hook authenticate with CryptoObject
                if (BiometricPrompt.authenticate.overload) {
                    BiometricPrompt.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo', 'androidx.biometric.BiometricPrompt$CryptoObject').implementation = function(promptInfo, cryptoObject) {
                        console.log("[BIOMETRIC] BiometricPrompt.authenticate() called with CryptoObject");
                        
                        sendBiometricEvent("auth_initiated", "BiometricPrompt", "pending", {
                            method: "authenticate(PromptInfo, CryptoObject)",
                            has_crypto_object: true,
                            crypto_object_type: cryptoObject ? cryptoObject.getClass().getName() : "null"
                        });
                        
                        // Validate CryptoObject
                        if (!cryptoObject) {
                            detectBypassAttempt("crypto_bypass", "null_crypto_object", {
                                risk: "HIGH",
                                reason: "Null CryptoObject passed to authenticate"
                            });
                        }
                        
                        return this.authenticate(promptInfo, cryptoObject);
                    };
                }
                
                console.log("[BIOMETRIC-MONITOR] ✅ BiometricPrompt hooks installed");
            } catch (e) {
                console.log("[BIOMETRIC-MONITOR] ❌ BiometricPrompt hooks failed: " + e);
            }
            
            try {
                // Hook authentication callbacks
                var AuthenticationCallback = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");
                
                AuthenticationCallback.onAuthenticationSucceeded.implementation = function(result) {
                    console.log("[BIOMETRIC-SUCCESS] Authentication succeeded");
                    
                    sendBiometricEvent("auth_success", "BiometricPrompt", "success", {
                        method: "onAuthenticationSucceeded",
                        crypto_object: result.getCryptoObject() ? "present" : "absent",
                        timestamp: Date.now()
                    });
                    
                    this.onAuthenticationSucceeded(result);
                };
                
                AuthenticationCallback.onAuthenticationFailed.implementation = function() {
                    console.log("[BIOMETRIC-FAILED] Authentication failed");
                    
                    sendBiometricEvent("auth_failure", "BiometricPrompt", "failed", {
                        method: "onAuthenticationFailed"
                    });
                    
                    this.onAuthenticationFailed();
                };
                
                AuthenticationCallback.onAuthenticationError.implementation = function(errorCode, errString) {
                    console.log("[BIOMETRIC-ERROR] Authentication error: " + errorCode + " - " + errString);
                    
                    sendBiometricEvent("auth_error", "BiometricPrompt", "error", {
                        method: "onAuthenticationError",
                        error_code: errorCode,
                        error_string: errString.toString()
                    });
                    
                    this.onAuthenticationError(errorCode, errString);
                };
                
                console.log("[BIOMETRIC-MONITOR] ✅ AuthenticationCallback hooks installed");
            } catch (e) {
                console.log("[BIOMETRIC-MONITOR] ❌ AuthenticationCallback hooks failed: " + e);
            }
            
            // ================================
            // FINGERPRINT MANAGER MONITORING (DEPRECATED)
            // ================================
            
            try {
                console.log("[BIOMETRIC-MONITOR] Setting up FingerprintManager hooks...");
                
                var FingerprintManager = Java.use("android.hardware.fingerprint.FingerprintManager");
                
                FingerprintManager.authenticate.implementation = function(crypto, cancel, flags, callback, handler) {
                    console.log("[FINGERPRINT] FingerprintManager.authenticate() called (DEPRECATED API)");
                    
                    sendBiometricEvent("auth_initiated", "FingerprintManager", "pending", {
                        method: "authenticate(deprecated)",
                        has_crypto_object: crypto !== null,
                        deprecated_api: true,
                        security_risk: "Using deprecated FingerprintManager API"
                    });
                    
                    // Flag deprecated API usage
                    detectBypassAttempt("weak_implementation", "deprecated_api", {
                        risk: "MEDIUM",
                        reason: "Using deprecated FingerprintManager instead of BiometricPrompt",
                        recommendation: "Migrate to androidx.biometric.BiometricPrompt"
                    });
                    
                    return this.authenticate(crypto, cancel, flags, callback, handler);
                };
                
                console.log("[BIOMETRIC-MONITOR] ✅ FingerprintManager hooks installed");
            } catch (e) {
                console.log("[BIOMETRIC-MONITOR] ❌ FingerprintManager hooks failed: " + e);
            }
            
            // ================================
            // AUTH STATE MONITORING
            // ================================
            
            try {
                console.log("[BIOMETRIC-MONITOR] Setting up auth state monitoring...");
                
                var SharedPreferences = Java.use("android.content.SharedPreferences");
                
                // Monitor auth state reads
                SharedPreferences.getBoolean.overload('java.lang.String', 'boolean').implementation = function(key, defValue) {
                    var result = this.getBoolean(key, defValue);
                    
                    if (key.toLowerCase().includes('auth') || key.toLowerCase().includes('biometric') || 
                        key.toLowerCase().includes('fingerprint') || key.toLowerCase().includes('login')) {
                        
                        console.log("[AUTH-STATE] Reading auth state: " + key + " = " + result);
                        
                        sendBiometricEvent("auth_state_read", "SharedPreferences", result ? "authenticated" : "not_authenticated", {
                            method: "getBoolean",
                            key: key,
                            value: result,
                            default_value: defValue
                        });
                        
                        // Check for insecure auth state storage
                        if (result === true) {
                            detectBypassAttempt("state_manipulation", "insecure_storage", {
                                risk: "MEDIUM",
                                reason: "Authentication state stored in SharedPreferences",
                                key: key,
                                recommendation: "Use secure storage for authentication state"
                            });
                        }
                    }
                    
                    return result;
                };
                
                // Monitor auth state writes
                var SharedPreferencesEditor = Java.use("android.content.SharedPreferences$Editor");
                SharedPreferencesEditor.putBoolean.implementation = function(key, value) {
                    if (key.toLowerCase().includes('auth') || key.toLowerCase().includes('biometric') || 
                        key.toLowerCase().includes('fingerprint') || key.toLowerCase().includes('login')) {
                        
                        console.log("[AUTH-STATE] Writing auth state: " + key + " = " + value);
                        
                        sendBiometricEvent("auth_state_write", "SharedPreferences", value ? "authenticated" : "not_authenticated", {
                            method: "putBoolean",
                            key: key,
                            value: value
                        });
                        
                        // Detect potential bypass via state manipulation
                        if (value === true) {
                            detectBypassAttempt("state_manipulation", "direct_auth_write", {
                                risk: "HIGH",
                                reason: "Direct write of authentication success state",
                                key: key,
                                recommendation: "Validate authentication before setting state"
                            });
                        }
                    }
                    
                    return this.putBoolean(key, value);
                };
                
                console.log("[BIOMETRIC-MONITOR] ✅ Auth state monitoring hooks installed");
            } catch (e) {
                console.log("[BIOMETRIC-MONITOR] ❌ Auth state monitoring hooks failed: " + e);
            }
            
            // ================================
            // ACTIVITY LIFECYCLE MONITORING
            // ================================
            
            try {
                console.log("[BIOMETRIC-MONITOR] Setting up activity lifecycle monitoring...");
                
                var Activity = Java.use("android.app.Activity");
                
                Activity.onResume.implementation = function() {
                    console.log("[LIFECYCLE] Activity.onResume() called");
                    
                    sendBiometricEvent("lifecycle_event", "Activity", "resumed", {
                        method: "onResume",
                        activity: this.getClass().getName(),
                        potential_auth_bypass: true
                    });
                    
                    this.onResume();
                };
                
                Activity.onPause.implementation = function() {
                    console.log("[LIFECYCLE] Activity.onPause() called");
                    
                    sendBiometricEvent("lifecycle_event", "Activity", "paused", {
                        method: "onPause",
                        activity: this.getClass().getName()
                    });
                    
                    this.onPause();
                };
                
                console.log("[BIOMETRIC-MONITOR] ✅ Activity lifecycle hooks installed");
            } catch (e) {
                console.log("[BIOMETRIC-MONITOR] ❌ Activity lifecycle hooks failed: " + e);
            }
            
            // ================================
            // SUMMARY AND STATS
            // ================================
            
            // Periodic summary of biometric events
            setInterval(function() {
                if (authEvents.length > 0 || bypassAttempts.length > 0) {
                    var summary = {
                        type: "biometric_monitoring_summary",
                        total_auth_events: authEvents.length,
                        total_bypass_attempts: bypassAttempts.length,
                        auth_successes: authEvents.filter(e => e.auth_result === "success").length,
                        auth_failures: authEvents.filter(e => e.auth_result === "failed").length,
                        monitoring_duration: Date.now()
                    };
                    
                    console.log("[BIOMETRIC-SUMMARY] " + JSON.stringify(summary));
                    send(summary);
                }
            }, 30000); // Every 30 seconds
            
            console.log("[BIOMETRIC-MONITOR] ✅ Biometric authentication monitoring fully initialized");
            console.log("[BIOMETRIC-MONITOR] Monitoring targets:");
            console.log("  • androidx.biometric.BiometricPrompt");
            console.log("  • android.hardware.fingerprint.FingerprintManager (deprecated)");
            console.log("  • Authentication callbacks and results");
            console.log("  • CryptoObject validation");
            console.log("  • Authentication state management");
            console.log("  • Activity lifecycle for bypass detection");
            console.log("[BIOMETRIC-MONITOR] 🔍 Ready to detect biometric security vulnerabilities!");
        });
        """
        
        return script
    
    def _analyze_runtime_events(self) -> Dict[str, Any]:
        """Analyze collected runtime events for vulnerabilities."""
        analysis = {
            "auth_events": [],
            "bypass_attempts": [],
            "vulnerability_detections": [],
            "monitoring_stats": {
                "total_events": len(self.runtime_events),
                "auth_successes": 0,
                "auth_failures": 0,
                "bypass_attempts": 0
            }
        }
        
        auth_successes = 0
        auth_failures = 0
        bypass_count = 0
        
        for event in self.runtime_events:
            analysis["auth_events"].append({
                "type": event.event_type,
                "timestamp": event.timestamp,
                "api_type": event.api_type,
                "auth_result": event.auth_result,
                "security_level": event.security_level
            })
            
            if event.auth_result == "success":
                auth_successes += 1
            elif event.auth_result == "failed":
                auth_failures += 1
            
            # Check for bypass attempts
            if self._is_bypass_attempt(event):
                bypass_count += 1
                analysis["bypass_attempts"].append({
                    "event": event.event_type,
                    "api_type": event.api_type,
                    "bypass_reason": self._get_bypass_reason(event),
                    "timestamp": event.timestamp
                })
                
                # Create vulnerability detection
                vulnerability = self._create_vulnerability_from_event(event)
                if vulnerability:
                    analysis["vulnerability_detections"].append(vulnerability)
        
        analysis["monitoring_stats"]["auth_successes"] = auth_successes
        analysis["monitoring_stats"]["auth_failures"] = auth_failures
        analysis["monitoring_stats"]["bypass_attempts"] = bypass_count
        
        return analysis
    
    def _is_bypass_attempt(self, event: BiometricRuntimeEvent) -> bool:
        """Check if event indicates a bypass attempt."""
        # Check evidence for bypass indicators
        evidence = event.evidence
        
        # Check for state manipulation
        if any(indicator in str(evidence).lower() for indicator in self.bypass_indicators["state_manipulation"]):
            return True
        
        # Check for crypto bypass
        if any(indicator in str(evidence).lower() for indicator in self.bypass_indicators["crypto_bypass"]):
            return True
        
        # Check for deprecated API usage (medium risk)
        if evidence.get("deprecated_api", False):
            return True
        
        # Check for weak implementation
        if not evidence.get("has_crypto_object", True):
            return True
        
        return False
    
    def _get_bypass_reason(self, event: BiometricRuntimeEvent) -> str:
        """Get reason for bypass attempt classification."""
        evidence = event.evidence
        
        if not evidence.get("has_crypto_object", True):
            return "Authentication without CryptoObject"
        elif evidence.get("deprecated_api", False):
            return "Using deprecated FingerprintManager API"
        elif "null_crypto_object" in str(evidence).lower():
            return "Null CryptoObject provided"
        elif "insecure_storage" in str(evidence).lower():
            return "Authentication state stored insecurely"
        else:
            return "Suspicious authentication pattern detected"
    
    def _create_vulnerability_from_event(self, event: BiometricRuntimeEvent) -> Optional[Dict[str, Any]]:
        """Create vulnerability report from runtime event."""
        vulnerability = {
            "type": "biometric_vulnerability",
            "subtype": self._determine_vulnerability_subtype(event),
            "severity": self._determine_severity(event),
            "title": f"Biometric Authentication Vulnerability Detected",
            "description": f"Runtime analysis detected biometric security issue: {self._get_bypass_reason(event)}",
            "evidence": {
                "event_type": event.event_type,
                "api_type": event.api_type,
                "auth_result": event.auth_result,
                "security_level": event.security_level,
                "runtime_evidence": event.evidence,
                "timestamp": event.timestamp
            },
            "cwe_id": "CWE-287",  # Improper Authentication
            "masvs_control": "MASVS-AUTH-2",
            "recommendations": [
                "Use androidx.biometric.BiometricPrompt for modern implementations",
                "Always use CryptoObject for authentication",
                "Implement proper authentication state management",
                "Validate authentication results before granting access"
            ]
        }
        
        return vulnerability
    
    def _determine_vulnerability_subtype(self, event: BiometricRuntimeEvent) -> str:
        """Determine specific vulnerability subtype."""
        evidence = event.evidence
        
        if not evidence.get("has_crypto_object", True):
            return "weak_biometric_implementation"
        elif evidence.get("deprecated_api", False):
            return "deprecated_api_usage"
        elif "insecure_storage" in str(evidence).lower():
            return "auth_state_manipulation"
        else:
            return "biometric_bypass"
    
    def _determine_severity(self, event: BiometricRuntimeEvent) -> str:
        """Determine severity based on event characteristics."""
        evidence = event.evidence
        
        if not evidence.get("has_crypto_object", True):
            return "HIGH"
        elif "null_crypto_object" in str(evidence).lower():
            return "HIGH"
        elif evidence.get("deprecated_api", False):
            return "MEDIUM"
        else:
            return "LOW"