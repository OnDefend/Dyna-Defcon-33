/**
 * Comprehensive Android Logging Hooks for Insecure Logging Detection
 * 
 * Monitors all Android Log methods to detect sensitive data being logged
 * in production applications - a critical security vulnerability.
 * 
 * Features:
 * - Universal Log method hooking (Log.d, Log.v, Log.i, Log.w, Log.e)
 * - Sensitive data pattern detection (passwords, tokens, keys, etc.)
 * - Custom logging framework support (Timber, SLF4J, etc.)
 * - Evidence collection with stack traces and context
 * - Real-time vulnerability classification
 */

Java.perform(function() {
    var Log = Java.use("android.util.Log");
    
    console.log("[LOGGING-HOOKS] 🚀 Comprehensive logging monitoring initialized");
    
    // Sensitive data patterns for universal detection
    var sensitivePatterns = [
        // Authentication & Authorization
        /password/i, /passwd/i, /pwd/i, /passphrase/i,
        /token/i, /jwt/i, /bearer/i, /oauth/i, /auth/i,
        /secret/i, /key/i, /private.*key/i, /api.*key/i,
        /session/i, /cookie/i, /credential/i,
        
        // Financial & PII
        /credit.*card/i, /debit.*card/i, /ssn/i, /social.*security/i,
        /bank.*account/i, /routing.*number/i, /account.*number/i,
        /email/i, /phone/i, /address/i, /birthday/i, /dob/i,
        
        // System & Network
        /database.*url/i, /connection.*string/i, /server.*url/i,
        /endpoint/i, /host/i, /port/i, /ip.*address/i,
        /encryption.*key/i, /certificate/i, /signature/i,
        
        // Mobile Specific
        /device.*id/i, /imei/i, /android.*id/i, /mac.*address/i,
        /location/i, /gps/i, /coordinate/i, /latitude/i, /longitude/i
    ];
    
    /**
     * Check if log message contains sensitive data
     */
    function containsSensitiveData(message) {
        if (!message || typeof message !== 'string') {
            return false;
        }
        
        return sensitivePatterns.some(pattern => pattern.test(message));
    }
    
    /**
     * Get current stack trace for evidence
     */
    function getCurrentStackTrace() {
        try {
            var Exception = Java.use("java.lang.Exception");
            var exception = Exception.$new();
            return exception.getStackTrace().toString();
        } catch (e) {
            return "Stack trace unavailable";
        }
    }
    
    /**
     * Universal log hook function
     */
    function hookLogMethod(logLevel, originalMethod) {
        try {
            originalMethod.overload('java.lang.String', 'java.lang.String').implementation = function(tag, msg) {
                var result = this[logLevel](tag, msg);
                
                // Check for sensitive data
                if (containsSensitiveData(msg) || containsSensitiveData(tag)) {
                    var stackTrace = getCurrentStackTrace();
                    
                    send({
                        type: "insecure_logging_vulnerability",
                        log_level: logLevel.toUpperCase(),
                        tag: tag,
                        message: msg,
                        timestamp: Date.now(),
                        stack_trace: stackTrace,
                        severity: "HIGH",
                        description: "Sensitive data detected in application logs",
                        evidence: {
                            log_method: "Log." + logLevel,
                            contains_sensitive: true,
                            execution_context: {
                                thread: Java.use("java.lang.Thread").currentThread().toString(),
                                process: "runtime_logging_detection"
                            }
                        }
                    });
                    
                    console.log("[INSECURE-LOG-" + logLevel.toUpperCase() + "] 🚨 SENSITIVE DATA: " + tag + ": " + msg);
                }
                
                return result;
            };
            
            // Also hook throwable overloads for exception logging
            try {
                originalMethod.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function(tag, msg, tr) {
                    var result = this[logLevel](tag, msg, tr);
                    
                    if (containsSensitiveData(msg) || containsSensitiveData(tag)) {
                        send({
                            type: "insecure_logging_vulnerability",
                            log_level: logLevel.toUpperCase(),
                            tag: tag,
                            message: msg,
                            throwable: tr ? tr.toString() : null,
                            timestamp: Date.now(),
                            stack_trace: getCurrentStackTrace(),
                            severity: "HIGH",
                            description: "Sensitive data detected in exception logs"
                        });
                    }
                    
                    return result;
                };
            } catch (e) {
                // Some methods might not have throwable overloads
            }
            
            console.log("[LOGGING-HOOKS] ✅ Hooked Log." + logLevel);
            
        } catch (e) {
            console.log("[LOGGING-HOOKS] ❌ Failed to hook Log." + logLevel + ": " + e);
        }
    }
    
    // Hook all standard Android Log levels
    hookLogMethod("d", Log.d);  // Debug
    hookLogMethod("v", Log.v);  // Verbose  
    hookLogMethod("i", Log.i);  // Info
    hookLogMethod("w", Log.w);  // Warning
    hookLogMethod("e", Log.e);  // Error
    
    // Hook println method (often used for debugging)
    try {
        Log.println.overload('int', 'java.lang.String', 'java.lang.String').implementation = function(priority, tag, msg) {
            var result = this.println(priority, tag, msg);
            
            if (containsSensitiveData(msg) || containsSensitiveData(tag)) {
                send({
                    type: "insecure_logging_vulnerability",
                    log_level: "PRINTLN",
                    priority: priority,
                    tag: tag,
                    message: msg,
                    timestamp: Date.now(),
                    stack_trace: getCurrentStackTrace(),
                    severity: "MEDIUM",
                    description: "Sensitive data detected in println logs"
                });
            }
            
            return result;
        };
        console.log("[LOGGING-HOOKS] ✅ Hooked Log.println");
    } catch (e) {
        console.log("[LOGGING-HOOKS] ❌ Failed to hook Log.println: " + e);
    }
    
    // Hook System.out.println for console output detection
    try {
        var System = Java.use("java.lang.System");
        var PrintStream = Java.use("java.io.PrintStream");
        
        PrintStream.println.overload('java.lang.String').implementation = function(msg) {
            var result = this.println(msg);
            
            if (containsSensitiveData(msg)) {
                send({
                    type: "insecure_logging_vulnerability",
                    log_level: "SYSTEM_OUT",
                    message: msg,
                    timestamp: Date.now(),
                    stack_trace: getCurrentStackTrace(),
                    severity: "MEDIUM",
                    description: "Sensitive data detected in System.out.println"
                });
            }
            
            return result;
        };
        console.log("[LOGGING-HOOKS] ✅ Hooked System.out.println");
    } catch (e) {
        console.log("[LOGGING-HOOKS] ❌ Failed to hook System.out.println: " + e);
    }
    
    // Hook popular third-party logging frameworks
    
    // Timber logging framework
    try {
        var Timber = Java.use("timber.log.Timber");
        
        Timber.d.overload('java.lang.String', '[Ljava.lang.Object;').implementation = function(message, args) {
            var result = this.d(message, args);
            
            if (containsSensitiveData(message)) {
                send({
                    type: "insecure_logging_vulnerability",
                    log_level: "TIMBER_DEBUG",
                    message: message,
                    framework: "Timber",
                    timestamp: Date.now(),
                    stack_trace: getCurrentStackTrace(),
                    severity: "HIGH",
                    description: "Sensitive data detected in Timber logging framework"
                });
            }
            
            return result;
        };
        console.log("[LOGGING-HOOKS] ✅ Hooked Timber.d");
    } catch (e) {
        // Timber not present, skip
    }
    
    // Apache Commons Logging
    try {
        var CommonsLog = Java.use("org.apache.commons.logging.Log");
        
        CommonsLog.debug.overload('java.lang.Object').implementation = function(message) {
            var result = this.debug(message);
            
            if (containsSensitiveData(message.toString())) {
                send({
                    type: "insecure_logging_vulnerability",
                    log_level: "COMMONS_DEBUG", 
                    message: message.toString(),
                    framework: "Apache Commons Logging",
                    timestamp: Date.now(),
                    stack_trace: getCurrentStackTrace(),
                    severity: "HIGH",
                    description: "Sensitive data detected in Apache Commons logging"
                });
            }
            
            return result;
        };
        console.log("[LOGGING-HOOKS] ✅ Hooked Apache Commons Log.debug");
    } catch (e) {
        // Apache Commons Logging not present, skip
    }
    
    // Hook custom application logging methods dynamically
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            // Look for custom logger classes
            if (className.toLowerCase().includes('log') && 
                !className.startsWith('android.') && 
                !className.startsWith('java.') &&
                !className.startsWith('javax.')) {
                
                try {
                    var CustomLoggerClass = Java.use(className);
                    
                    // Try to hook common logging method names
                    var commonLogMethods = ['log', 'debug', 'info', 'warn', 'error', 'trace'];
                    
                    commonLogMethods.forEach(function(methodName) {
                        try {
                            if (CustomLoggerClass[methodName]) {
                                // Try to hook if method exists
                                var originalMethod = CustomLoggerClass[methodName];
                                
                                originalMethod.overload('java.lang.String').implementation = function(msg) {
                                    var result = this[methodName](msg);
                                    
                                    if (containsSensitiveData(msg)) {
                                        send({
                                            type: "insecure_logging_vulnerability",
                                            log_level: "CUSTOM_" + methodName.toUpperCase(),
                                            message: msg,
                                            framework: className,
                                            timestamp: Date.now(),
                                            stack_trace: getCurrentStackTrace(),
                                            severity: "HIGH",
                                            description: "Sensitive data detected in custom logging framework: " + className
                                        });
                                    }
                                    
                                    return result;
                                };
                                
                                console.log("[LOGGING-HOOKS] ✅ Hooked custom logger: " + className + "." + methodName);
                            }
                        } catch (e) {
                            // Method might not exist or have different signature
                        }
                    });
                } catch (e) {
                    // Class might not be a logger or accessible
                }
            }
        },
        onComplete: function() {
            console.log("[LOGGING-HOOKS] 🔍 Custom logger enumeration complete");
        }
    });
    
    console.log("[LOGGING-HOOKS] 🛡️ Comprehensive logging monitoring active - detecting insecure logging vulnerabilities");
});