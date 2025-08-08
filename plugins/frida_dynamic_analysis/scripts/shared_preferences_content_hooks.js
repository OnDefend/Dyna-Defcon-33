// AODS SharedPreferences Content Monitoring Hooks
// Universal SharedPreferences access monitoring for sensitive data detection
// No hardcoded preference names - discovers and monitors all preferences organically

Java.perform(function() {
    console.log("[AODS-PREFS] SharedPreferences content monitoring hooks initialized");
    
    var sensitiveDataPatterns = [
        // Authentication and security
        /password|passwd|pwd|pin|secret|token|key|credential|auth/gi,
        /bearer|jwt|oauth|session|cookie/gi,
        /fingerprint|biometric|face|touch/gi,
        
        // Personal and financial information
        /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, // Credit card numbers
        /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, // SSN pattern
        /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, // Email addresses
        /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, // Phone numbers
        
        // Location and tracking
        /lat|lon|latitude|longitude|location|gps|coordinates/gi,
        /address|street|city|state|zip|postal/gi,
        
        // Business logic
        /promo|coupon|discount|voucher|code|offer/gi,
        /premium|subscription|payment|billing/gi,
        /admin|root|debug|test|dev/gi
    ];
    
    var suspiciousPreferenceKeys = [
        /user|account|profile|personal/gi,
        /login|auth|credential|security/gi,
        /payment|billing|card|financial/gi,
        /promo|discount|coupon|offer/gi,
        /location|gps|tracking/gi,
        /debug|test|admin|dev/gi
    ];
    
    var monitoredPreferences = new Map();
    var sensitiveFindings = [];
    var preferenceModes = new Map();
    
    // Hook SharedPreferences creation
    try {
        var Context = Java.use("android.content.Context");
        
        Context.getSharedPreferences.overload('java.lang.String', 'int').implementation = function(name, mode) {
            console.log("[AODS-PREFS] SharedPreferences created: " + name + " (mode: " + mode + ")");
            
            // Check for insecure modes
            var modeString = getModeString(mode);
            preferenceModes.set(name, {
                mode: mode,
                modeString: modeString,
                isSecure: isSecureMode(mode)
            });
            
            if (!isSecureMode(mode)) {
                console.log("[AODS-PREFS] INSECURE: SharedPreferences with insecure mode - " + name + " (" + modeString + ")");
                sensitiveFindings.push({
                    type: "insecure_preference_mode",
                    preference_name: name,
                    mode: mode,
                    mode_string: modeString,
                    timestamp: Date.now()
                });
            }
            
            var result = this.getSharedPreferences(name, mode);
            
            // Monitor this preference for future access
            if (!monitoredPreferences.has(name)) {
                monitoredPreferences.set(name, {
                    name: name,
                    mode: mode,
                    access_count: 0,
                    keys_accessed: new Set(),
                    sensitive_keys: new Set()
                });
                
                // Hook the returned SharedPreferences object
                hookSharedPreferencesObject(result, name);
            }
            
            return result;
        };
        
    } catch (e) {
        console.log("[AODS-PREFS] Error hooking Context.getSharedPreferences: " + e);
    }
    
    // Hook SharedPreferences operations
    function hookSharedPreferencesObject(sharedPrefs, prefName) {
        try {
            var SharedPreferences = Java.use("android.content.SharedPreferences");
            
            // Monitor getString operations
            var originalGetString = sharedPrefs.getString;
            sharedPrefs.getString = function(key, defValue) {
                var value = originalGetString.call(this, key, defValue);
                
                console.log("[AODS-PREFS] getString: " + prefName + "." + key);
                recordPreferenceAccess(prefName, key, value, "string");
                
                return value;
            };
            
            // Monitor getInt operations
            var originalGetInt = sharedPrefs.getInt;
            sharedPrefs.getInt = function(key, defValue) {
                var value = originalGetInt.call(this, key, defValue);
                
                console.log("[AODS-PREFS] getInt: " + prefName + "." + key + " = " + value);
                recordPreferenceAccess(prefName, key, value.toString(), "int");
                
                return value;
            };
            
            // Monitor getBoolean operations
            var originalGetBoolean = sharedPrefs.getBoolean;
            sharedPrefs.getBoolean = function(key, defValue) {
                var value = originalGetBoolean.call(this, key, defValue);
                
                console.log("[AODS-PREFS] getBoolean: " + prefName + "." + key + " = " + value);
                recordPreferenceAccess(prefName, key, value.toString(), "boolean");
                
                return value;
            };
            
            // Monitor getLong operations
            var originalGetLong = sharedPrefs.getLong;
            sharedPrefs.getLong = function(key, defValue) {
                var value = originalGetLong.call(this, key, defValue);
                
                console.log("[AODS-PREFS] getLong: " + prefName + "." + key + " = " + value);
                recordPreferenceAccess(prefName, key, value.toString(), "long");
                
                return value;
            };
            
            // Monitor getFloat operations
            var originalGetFloat = sharedPrefs.getFloat;
            sharedPrefs.getFloat = function(key, defValue) {
                var value = originalGetFloat.call(this, key, defValue);
                
                console.log("[AODS-PREFS] getFloat: " + prefName + "." + key + " = " + value);
                recordPreferenceAccess(prefName, key, value.toString(), "float");
                
                return value;
            };
            
            // Monitor getAll operations (bulk access)
            var originalGetAll = sharedPrefs.getAll;
            sharedPrefs.getAll = function() {
                var allPrefs = originalGetAll.call(this);
                
                console.log("[AODS-PREFS] getAll: " + prefName + " (bulk access)");
                
                // Analyze all preferences at once
                var keySet = allPrefs.keySet();
                var iterator = keySet.iterator();
                
                while (iterator.hasNext()) {
                    var key = iterator.next();
                    var value = allPrefs.get(key);
                    
                    if (value) {
                        recordPreferenceAccess(prefName, key, value.toString(), "bulk");
                    }
                }
                
                return allPrefs;
            };
            
        } catch (e) {
            console.log("[AODS-PREFS] Error hooking SharedPreferences object: " + e);
        }
    }
    
    // Hook SharedPreferences.Editor for write operations
    try {
        var SharedPreferencesEditor = Java.use("android.content.SharedPreferences$Editor");
        
        // Monitor putString operations
        SharedPreferencesEditor.putString.implementation = function(key, value) {
            console.log("[AODS-PREFS] putString: " + key + " = " + (value ? value.substring(0, 50) : "null"));
            
            if (value) {
                analyzePreferenceWrite(key, value, "string");
            }
            
            return this.putString(key, value);
        };
        
        // Monitor putInt operations
        SharedPreferencesEditor.putInt.implementation = function(key, value) {
            console.log("[AODS-PREFS] putInt: " + key + " = " + value);
            analyzePreferenceWrite(key, value.toString(), "int");
            
            return this.putInt(key, value);
        };
        
        // Monitor putBoolean operations
        SharedPreferencesEditor.putBoolean.implementation = function(key, value) {
            console.log("[AODS-PREFS] putBoolean: " + key + " = " + value);
            analyzePreferenceWrite(key, value.toString(), "boolean");
            
            return this.putBoolean(key, value);
        };
        
        // Monitor putLong operations
        SharedPreferencesEditor.putLong.implementation = function(key, value) {
            console.log("[AODS-PREFS] putLong: " + key + " = " + value);
            analyzePreferenceWrite(key, value.toString(), "long");
            
            return this.putLong(key, value);
        };
        
        // Monitor putFloat operations
        SharedPreferencesEditor.putFloat.implementation = function(key, value) {
            console.log("[AODS-PREFS] putFloat: " + key + " = " + value);
            analyzePreferenceWrite(key, value.toString(), "float");
            
            return this.putFloat(key, value);
        };
        
    } catch (e) {
        console.log("[AODS-PREFS] Error hooking SharedPreferences.Editor: " + e);
    }
    
    // Record and analyze preference access
    function recordPreferenceAccess(prefName, key, value, dataType) {
        var prefInfo = monitoredPreferences.get(prefName);
        if (prefInfo) {
            prefInfo.access_count++;
            prefInfo.keys_accessed.add(key);
        }
        
        // Analyze key for sensitive content
        var isSensitiveKey = analyzeSensitiveKey(key);
        if (isSensitiveKey) {
            console.log("[AODS-PREFS] SENSITIVE: Sensitive preference key accessed - " + prefName + "." + key);
            if (prefInfo) {
                prefInfo.sensitive_keys.add(key);
            }
            
            sensitiveFindings.push({
                type: "sensitive_preference_key",
                preference_name: prefName,
                key: key,
                data_type: dataType,
                timestamp: Date.now()
            });
        }
        
        // Analyze value for sensitive content
        if (value && value !== "null") {
            var sensitivePatterns = analyzeSensitiveContent(value);
            if (sensitivePatterns.length > 0) {
                console.log("[AODS-PREFS] SENSITIVE: Sensitive data in preference value - " + prefName + "." + key);
                
                sensitiveFindings.push({
                    type: "sensitive_preference_value",
                    preference_name: prefName,
                    key: key,
                    patterns: sensitivePatterns,
                    value_sample: value.substring(0, 50),
                    data_type: dataType,
                    timestamp: Date.now()
                });
            }
        }
    }
    
    // Analyze preference write operations
    function analyzePreferenceWrite(key, value, dataType) {
        console.log("[AODS-PREFS] Analyzing preference write: " + key);
        
        // Check for sensitive key
        var isSensitiveKey = analyzeSensitiveKey(key);
        if (isSensitiveKey) {
            sensitiveFindings.push({
                type: "sensitive_preference_write_key",
                key: key,
                data_type: dataType,
                timestamp: Date.now()
            });
        }
        
        // Check for sensitive value
        if (value) {
            var sensitivePatterns = analyzeSensitiveContent(value);
            if (sensitivePatterns.length > 0) {
                sensitiveFindings.push({
                    type: "sensitive_preference_write_value",
                    key: key,
                    patterns: sensitivePatterns,
                    value_sample: value.substring(0, 50),
                    data_type: dataType,
                    timestamp: Date.now()
                });
            }
        }
    }
    
    // Analyze if a preference key is sensitive
    function analyzeSensitiveKey(key) {
        if (!key) return false;
        
        var keyLower = key.toLowerCase();
        
        for (var pattern of suspiciousPreferenceKeys) {
            if (pattern.test(keyLower)) {
                return true;
            }
        }
        
        return false;
    }
    
    // Analyze content for sensitive patterns
    function analyzeSensitiveContent(content) {
        if (!content) return [];
        
        var foundPatterns = [];
        var contentStr = content.toString();
        
        for (var i = 0; i < sensitiveDataPatterns.length; i++) {
            var pattern = sensitiveDataPatterns[i];
            var matches = null;
            
            if (typeof pattern === 'object' && pattern.test) {
                // RegExp pattern
                matches = contentStr.match(pattern);
            } else if (typeof pattern === 'string') {
                // String pattern (case insensitive)
                if (contentStr.toLowerCase().includes(pattern.toLowerCase())) {
                    matches = [pattern];
                }
            }
            
            if (matches && matches.length > 0) {
                foundPatterns.push(pattern.toString());
            }
        }
        
        return foundPatterns;
    }
    
    // Check if SharedPreferences mode is secure
    function isSecureMode(mode) {
        // MODE_PRIVATE (0) is secure
        // Other modes (MODE_WORLD_READABLE, MODE_WORLD_WRITABLE) are insecure
        return mode === 0;
    }
    
    // Get human-readable mode string
    function getModeString(mode) {
        switch (mode) {
            case 0: return "MODE_PRIVATE";
            case 1: return "MODE_WORLD_READABLE";
            case 2: return "MODE_WORLD_WRITABLE";
            case 3: return "MODE_WORLD_READABLE|MODE_WORLD_WRITABLE";
            default: return "UNKNOWN_MODE_" + mode;
        }
    }
    
    // Export findings for AODS analysis
    function exportFindings() {
        var preferencesArray = Array.from(monitoredPreferences.values()).map(function(pref) {
            return {
                name: pref.name,
                mode: pref.mode,
                access_count: pref.access_count,
                keys_accessed: Array.from(pref.keys_accessed),
                sensitive_keys: Array.from(pref.sensitive_keys)
            };
        });
        
        return {
            preferences_monitored: preferencesArray,
            preference_modes: Object.fromEntries(preferenceModes),
            sensitive_findings: sensitiveFindings,
            total_findings: sensitiveFindings.length
        };
    }
    
    // Make findings available globally
    global.AODSSharedPreferencesFindings = exportFindings;
    
    console.log("[AODS-PREFS] SharedPreferences content monitoring hooks ready");
});