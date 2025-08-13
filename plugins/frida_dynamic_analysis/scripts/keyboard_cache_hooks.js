/**
 * Keyboard Cache Vulnerability Detection Hooks
 * 
 * Monitors Android input field configurations to detect when sensitive
 * data might be cached by soft keyboards, potentially exposing user data.
 * 
 * Features:
 * - EditText input type monitoring
 * - Sensitive field identification
 * - Keyboard cache configuration detection
 * - IME (Input Method Editor) interaction monitoring
 * - Evidence collection with field context
 * 
 * Author: AODS Team
 * Date: January 2025
 */

Java.perform(function() {
    console.log("[KEYBOARD-CACHE] 🚀 Keyboard cache vulnerability monitoring initialized");
    
    try {
        // Sensitive input patterns for universal detection
        var sensitiveInputPatterns = [
            // Authentication
            /password/i, /passwd/i, /pwd/i, /passphrase/i, /pin/i, /code/i,
            /otp/i, /token/i, /auth/i, /login/i, /unlock/i,
            
            // Financial
            /credit.*card/i, /debit.*card/i, /card.*number/i, /cvv/i, /cvc/i,
            /bank.*account/i, /routing/i, /ssn/i, /social.*security/i,
            /account.*number/i, /sort.*code/i,
            
            // Personal & Sensitive
            /secret/i, /private/i, /confidential/i, /sensitive/i,
            /personal/i, /secure/i, /key/i, /license/i
        ];
        
        // Input type constants (Android InputType)
        var INPUT_TYPE_PASSWORD = 0x00000081;  // TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_PASSWORD
        var INPUT_TYPE_WEB_PASSWORD = 0x000000e1;  // TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_WEB_PASSWORD
        var INPUT_TYPE_VISIBLE_PASSWORD = 0x00000091;  // TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
        var INPUT_TYPE_NUMBER_PASSWORD = 0x00000012;  // TYPE_CLASS_NUMBER | TYPE_NUMBER_VARIATION_PASSWORD
        
        /**
         * Check if field name/hint suggests sensitive content
         */
        function isSensitiveField(text) {
            if (!text) return false;
            var textString = text.toString().toLowerCase();
            return sensitiveInputPatterns.some(pattern => pattern.test(textString));
        }
        
        /**
         * Analyze input type for password/sensitive indicators
         */
        function isPasswordInputType(inputType) {
            return (inputType === INPUT_TYPE_PASSWORD ||
                    inputType === INPUT_TYPE_WEB_PASSWORD ||
                    inputType === INPUT_TYPE_VISIBLE_PASSWORD ||
                    inputType === INPUT_TYPE_NUMBER_PASSWORD ||
                    (inputType & 0x000000f0) === 0x00000080);  // Any password variation
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
         * Extract view information for context
         */
        function getViewInfo(view) {
            try {
                var info = {
                    className: view.getClass().getName(),
                    id: null,
                    hint: null,
                    contentDescription: null
                };
                
                // Get view ID
                try {
                    var id = view.getId();
                    if (id !== -1) {
                        var resources = view.getResources();
                        if (resources) {
                            info.id = resources.getResourceEntryName(id);
                        }
                    }
                } catch (e) {
                    // ID extraction failed, continue
                }
                
                // Get hint text
                try {
                    if (view.getHint && view.getHint()) {
                        info.hint = view.getHint().toString();
                    }
                } catch (e) {
                    // Hint extraction failed, continue
                }
                
                // Get content description
                try {
                    if (view.getContentDescription && view.getContentDescription()) {
                        info.contentDescription = view.getContentDescription().toString();
                    }
                } catch (e) {
                    // Content description extraction failed, continue
                }
                
                return info;
            } catch (e) {
                return {className: "Unknown", id: null, hint: null, contentDescription: null};
            }
        }
        
        // Hook EditText.setInputType to monitor input field configurations
        var EditText = Java.use("android.widget.EditText");
        
        EditText.setInputType.implementation = function(type) {
            this.setInputType(type);
            
            var viewInfo = getViewInfo(this);
            var isPasswordType = isPasswordInputType(type);
            var isSensitiveByName = isSensitiveField(viewInfo.hint) || 
                                   isSensitiveField(viewInfo.id) || 
                                   isSensitiveField(viewInfo.contentDescription);
            
            // Check for keyboard cache vulnerability
            var hasKeyboardCacheIssue = false;
            var issueDescription = "";
            var severity = "MEDIUM";
            
            if (isSensitiveByName && !isPasswordType) {
                // Sensitive field without password input type - high risk
                hasKeyboardCacheIssue = true;
                issueDescription = "Sensitive input field allows keyboard caching (missing password input type)";
                severity = "HIGH";
            } else if (isPasswordType) {
                // Password field - verify it's properly configured
                var hasPrivateImeOptions = false;
                try {
                    var imeOptions = this.getImeOptions();
                    var privateImeOptions = this.getPrivateImeOptions();
                    
                    // Check for no suggestions flag
                    var IME_FLAG_NO_PERSONALIZED_LEARNING = 0x1000000;
                    var IME_FLAG_NO_FULLSCREEN = 0x2000000;
                    
                    if (privateImeOptions && privateImeOptions.indexOf("nm") >= 0) {
                        hasPrivateImeOptions = true;  // "nm" = no microphone
                    }
                    
                } catch (e) {
                    // IME options check failed
                }
                
                // Log password field configuration for monitoring
                send({
                    type: "keyboard_cache_info",
                    field_type: "password_field",
                    input_type: type,
                    view_info: viewInfo,
                    properly_configured: true,
                    timestamp: Date.now(),
                    stack_trace: getCurrentStackTrace()
                });
            }
            
            if (hasKeyboardCacheIssue) {
                send({
                    type: "keyboard_cache_vulnerability",
                    vulnerability_type: "sensitive_field_caching",
                    input_type: type,
                    expected_input_type: "password_type_required",
                    view_info: viewInfo,
                    is_sensitive_field: isSensitiveByName,
                    is_password_type: isPasswordType,
                    timestamp: Date.now(),
                    stack_trace: getCurrentStackTrace(),
                    severity: severity,
                    description: issueDescription,
                    evidence: {
                        field_identification: {
                            by_hint: isSensitiveField(viewInfo.hint),
                            by_id: isSensitiveField(viewInfo.id),
                            by_description: isSensitiveField(viewInfo.contentDescription)
                        },
                        input_type_analysis: {
                            current_type: type,
                            is_password: isPasswordType,
                            allows_caching: !isPasswordType
                        }
                    }
                });
                
                console.log("[KEYBOARD-CACHE-VULN] 🚨 SENSITIVE FIELD CACHING: " + 
                           (viewInfo.hint || viewInfo.id || "unknown field") + 
                           " (type: " + type + ")");
            }
            
            // Monitor all input type changes for analysis
            send({
                type: "keyboard_cache_monitoring",
                operation: "setInputType",
                input_type: type,
                view_info: viewInfo,
                is_sensitive: isSensitiveByName,
                is_password_type: isPasswordType,
                timestamp: Date.now()
            });
            
            console.log("[KEYBOARD-CACHE] Input type set: " + type + 
                       " for " + (viewInfo.hint || viewInfo.id || "field"));
        };
        
        // Hook TextView.setTransformationMethod for password visibility monitoring
        var TextView = Java.use("android.widget.TextView");
        
        TextView.setTransformationMethod.implementation = function(method) {
            this.setTransformationMethod(method);
            
            var viewInfo = getViewInfo(this);
            var isPasswordTransformation = false;
            var transformationName = "none";
            
            if (method) {
                transformationName = method.getClass().getName();
                isPasswordTransformation = transformationName.indexOf("Password") >= 0;
            }
            
            send({
                type: "keyboard_cache_monitoring",
                operation: "setTransformationMethod",
                transformation_method: transformationName,
                is_password_transformation: isPasswordTransformation,
                view_info: viewInfo,
                timestamp: Date.now()
            });
            
            console.log("[KEYBOARD-CACHE] Transformation method: " + transformationName + 
                       " for " + (viewInfo.hint || viewInfo.id || "field"));
        };
        
        // Hook InputMethodManager for IME interaction monitoring
        try {
            var InputMethodManager = Java.use("android.view.inputmethod.InputMethodManager");
            
            InputMethodManager.showSoftInput.implementation = function(view, flags) {
                var result = this.showSoftInput(view, flags);
                
                var viewInfo = getViewInfo(view);
                var isSensitiveField = isSensitiveField(viewInfo.hint) || 
                                      isSensitiveField(viewInfo.id) || 
                                      isSensitiveField(viewInfo.contentDescription);
                
                if (isSensitiveField) {
                    // Check if this sensitive field has proper input configuration
                    var inputType = -1;
                    try {
                        if (view.getInputType) {
                            inputType = view.getInputType();
                        }
                    } catch (e) {
                        // Input type check failed
                    }
                    
                    var isPasswordType = isPasswordInputType(inputType);
                    
                    if (!isPasswordType) {
                        send({
                            type: "keyboard_cache_vulnerability",
                            vulnerability_type: "sensitive_ime_exposure",
                            view_info: viewInfo,
                            input_type: inputType,
                            ime_flags: flags,
                            timestamp: Date.now(),
                            stack_trace: getCurrentStackTrace(),
                            severity: "HIGH",
                            description: "Sensitive field exposed to IME without password protection",
                            evidence: {
                                ime_interaction: true,
                                soft_keyboard_shown: true,
                                field_protection: "insufficient"
                            }
                        });
                        
                        console.log("[KEYBOARD-CACHE-VULN] 🚨 SENSITIVE IME EXPOSURE: " + 
                                   (viewInfo.hint || viewInfo.id || "unknown field"));
                    }
                }
                
                send({
                    type: "keyboard_cache_monitoring",
                    operation: "showSoftInput",
                    view_info: viewInfo,
                    ime_flags: flags,
                    is_sensitive: isSensitiveField,
                    timestamp: Date.now()
                });
                
                return result;
            };
            
            console.log("[KEYBOARD-CACHE] ✅ InputMethodManager hooks installed");
            
        } catch (e) {
            console.log("[KEYBOARD-CACHE] ⚠️ InputMethodManager hooks not available: " + e);
        }
        
        // Hook EditText constructor to catch initial configuration
        EditText.$init.overload().implementation = function() {
            this.$init();
            
            // Monitor default configuration
            setTimeout(function() {
                try {
                    var viewInfo = getViewInfo(this);
                    var inputType = this.getInputType ? this.getInputType() : -1;
                    
                    send({
                        type: "keyboard_cache_monitoring",
                        operation: "editTextCreated",
                        input_type: inputType,
                        view_info: viewInfo,
                        timestamp: Date.now()
                    });
                } catch (e) {
                    // Monitoring failed, continue
                }
            }.bind(this), 100);
        };
        
        // Hook for imeOptions setting
        EditText.setImeOptions.implementation = function(imeOptions) {
            this.setImeOptions(imeOptions);
            
            var viewInfo = getViewInfo(this);
            
            send({
                type: "keyboard_cache_monitoring",
                operation: "setImeOptions",
                ime_options: imeOptions,
                view_info: viewInfo,
                timestamp: Date.now()
            });
            
            console.log("[KEYBOARD-CACHE] IME options set: " + imeOptions + 
                       " for " + (viewInfo.hint || viewInfo.id || "field"));
        };
        
        console.log("[KEYBOARD-CACHE] ✅ All keyboard cache hooks installed successfully");
        
    } catch (e) {
        console.log("[KEYBOARD-CACHE] ❌ Failed to install keyboard cache hooks: " + e);
    }
});