/**
 * Storage Access Hooks
 * 
 * Frida JavaScript code to intercept file system operations
 * and detect insecure data storage during runtime.
 * 
 * Author: AODS Team
 * Date: January 2025
 */

Java.perform(function() {
    console.log("[+] Storage hooks loaded - monitoring file system operations");
    
    try {
        // Hook FileOutputStream for file write monitoring
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload("java.lang.String").implementation = function(name) {
            var result = this.$init(name);
            
            send({
                type: "file_access",
                operation: "write",
                file_path: name,
                timestamp: Date.now(),
                method: "FileOutputStream.init",
                thread: Java.use("java.lang.Thread").currentThread().getName()
            });
            
            console.log("[STORAGE] File write: " + name);
            return result;
        };
        
        FileOutputStream.$init.overload("java.io.File").implementation = function(file) {
            var result = this.$init(file);
            
            var filePath = "";
            try {
                filePath = file.getAbsolutePath();
            } catch (e) {
                filePath = file.toString();
            }
            
            send({
                type: "file_access",
                operation: "write",
                file_path: filePath,
                timestamp: Date.now(),
                method: "FileOutputStream.init(File)"
            });
            
            console.log("[STORAGE] File write: " + filePath);
            return result;
        };
        
        // Hook FileInputStream for file read monitoring
        var FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload("java.lang.String").implementation = function(name) {
            var result = this.$init(name);
            
            send({
                type: "file_access",
                operation: "read",
                file_path: name,
                timestamp: Date.now(),
                method: "FileInputStream.init"
            });
            
            console.log("[STORAGE] File read: " + name);
            return result;
        };
        
        FileInputStream.$init.overload("java.io.File").implementation = function(file) {
            var result = this.$init(file);
            
            var filePath = "";
            try {
                filePath = file.getAbsolutePath();
            } catch (e) {
                filePath = file.toString();
            }
            
            send({
                type: "file_access",
                operation: "read",
                file_path: filePath,
                timestamp: Date.now(),
                method: "FileInputStream.init(File)"
            });
            
            console.log("[STORAGE] File read: " + filePath);
            return result;
        };
        
        // Hook SharedPreferences for preferences monitoring
        var Context = Java.use("android.content.Context");
        Context.getSharedPreferences.implementation = function(name, mode) {
            var result = this.getSharedPreferences(name, mode);
            
            send({
                type: "shared_preferences",
                operation: "get",
                preferences_name: name,
                mode: mode,
                timestamp: Date.now(),
                method: "Context.getSharedPreferences"
            });
            
            console.log("[STORAGE] SharedPreferences access: " + name + " (mode: " + mode + ")");
            return result;
        };
        
        // Hook SharedPreferences.Editor for write operations
        try {
            var SharedPreferencesEditor = Java.use("android.content.SharedPreferences$Editor");
            
            SharedPreferencesEditor.putString.implementation = function(key, value) {
                var result = this.putString(key, value);
                
                send({
                    type: "shared_preferences",
                    operation: "putString",
                    key: key,
                    value_length: value ? value.length : 0,
                    has_sensitive_data: containsSensitiveData(key, value),
                    timestamp: Date.now(),
                    method: "SharedPreferences.Editor.putString"
                });
                
                console.log("[STORAGE] SharedPreferences putString: " + key);
                return result;
            };
            
            SharedPreferencesEditor.putInt.implementation = function(key, value) {
                var result = this.putInt(key, value);
                
                send({
                    type: "shared_preferences",
                    operation: "putInt",
                    key: key,
                    value: value,
                    timestamp: Date.now(),
                    method: "SharedPreferences.Editor.putInt"
                });
                
                console.log("[STORAGE] SharedPreferences putInt: " + key + " = " + value);
                return result;
            };
            
            SharedPreferencesEditor.putBoolean.implementation = function(key, value) {
                var result = this.putBoolean(key, value);
                
                send({
                    type: "shared_preferences",
                    operation: "putBoolean",
                    key: key,
                    value: value,
                    timestamp: Date.now(),
                    method: "SharedPreferences.Editor.putBoolean"
                });
                
                console.log("[STORAGE] SharedPreferences putBoolean: " + key + " = " + value);
                return result;
            };
            
        } catch (e) {
            console.log("[INFO] SharedPreferences.Editor hooks not available: " + e);
        }
        
        // Hook SQLite database operations
        try {
            var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
            
            SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function(sql) {
                var result = this.execSQL(sql);
                
                send({
                    type: "database_access",
                    operation: "execSQL",
                    sql: sql,
                    timestamp: Date.now(),
                    method: "SQLiteDatabase.execSQL"
                });
                
                console.log("[STORAGE] SQLite execSQL: " + sql.substring(0, 100));
                return result;
            };
            
            SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function(sql, selectionArgs) {
                var result = this.rawQuery(sql, selectionArgs);
                
                send({
                    type: "database_access",
                    operation: "rawQuery",
                    sql: sql,
                    has_args: selectionArgs !== null,
                    timestamp: Date.now(),
                    method: "SQLiteDatabase.rawQuery"
                });
                
                console.log("[STORAGE] SQLite rawQuery: " + sql.substring(0, 100));
                return result;
            };
            
        } catch (e) {
            console.log("[INFO] SQLiteDatabase hooks not available: " + e);
        }
        
        // Hook File creation and deletion
        var File = Java.use("java.io.File");
        File.createNewFile.implementation = function() {
            var result = this.createNewFile();
            
            var filePath = "";
            try {
                filePath = this.getAbsolutePath();
            } catch (e) {
                filePath = this.toString();
            }
            
            send({
                type: "file_access",
                operation: "create",
                file_path: filePath,
                timestamp: Date.now(),
                method: "File.createNewFile"
            });
            
            console.log("[STORAGE] File created: " + filePath);
            return result;
        };
        
        File.delete.implementation = function() {
            var filePath = "";
            try {
                filePath = this.getAbsolutePath();
            } catch (e) {
                filePath = this.toString();
            }
            
            var result = this.delete();
            
            send({
                type: "file_access",
                operation: "delete",
                file_path: filePath,
                success: result,
                timestamp: Date.now(),
                method: "File.delete"
            });
            
            console.log("[STORAGE] File delete: " + filePath + " (success: " + result + ")");
            return result;
        };
        
        // Hook internal storage access
        Context.openFileOutput.implementation = function(name, mode) {
            var result = this.openFileOutput(name, mode);
            
            send({
                type: "file_access",
                operation: "openFileOutput",
                filename: name,
                mode: mode,
                timestamp: Date.now(),
                method: "Context.openFileOutput"
            });
            
            console.log("[STORAGE] Internal file output: " + name + " (mode: " + mode + ")");
            return result;
        };
        
        Context.openFileInput.implementation = function(name) {
            var result = this.openFileInput(name);
            
            send({
                type: "file_access",
                operation: "openFileInput",
                filename: name,
                timestamp: Date.now(),
                method: "Context.openFileInput"
            });
            
            console.log("[STORAGE] Internal file input: " + name);
            return result;
        };
        
        // Hook external storage access
        try {
            var Environment = Java.use("android.os.Environment");
            Environment.getExternalStorageDirectory.implementation = function() {
                var result = this.getExternalStorageDirectory();
                
                send({
                    type: "external_storage",
                    operation: "getExternalStorageDirectory",
                    timestamp: Date.now(),
                    method: "Environment.getExternalStorageDirectory"
                });
                
                console.log("[STORAGE] External storage directory accessed");
                return result;
            };
            
        } catch (e) {
            console.log("[INFO] Environment hooks not available: " + e);
        }
        
        console.log("[+] All storage hooks successfully installed");
        
    } catch (e) {
        console.log("[-] Error installing storage hooks: " + e);
        send({
            type: "hook_error",
            error: e.toString(),
            hook_type: "storage",
            timestamp: Date.now()
        });
    }
});

// Utility function to detect sensitive data
function containsSensitiveData(key, value) {
    if (!key && !value) return false;
    
    var sensitiveKeywords = [
        "password", "pass", "pwd", "secret", "token", "key", "auth", 
        "credential", "login", "session", "api_key", "access_token",
        "refresh_token", "jwt", "bearer", "oauth", "pin", "ssn",
        "credit", "card", "cvv", "account", "bank"
    ];
    
    var keyLower = key ? key.toLowerCase() : "";
    var valueLower = value ? value.toLowerCase() : "";
    
    for (var i = 0; i < sensitiveKeywords.length; i++) {
        if (keyLower.indexOf(sensitiveKeywords[i]) !== -1 || 
            valueLower.indexOf(sensitiveKeywords[i]) !== -1) {
            return true;
        }
    }
    
    return false;
}

// Additional monitoring for cache and temporary files
Java.perform(function() {
    try {
        // Hook cache directory access
        var Context = Java.use("android.content.Context");
        Context.getCacheDir.implementation = function() {
            var result = this.getCacheDir();
            
            send({
                type: "cache_access",
                operation: "getCacheDir",
                timestamp: Date.now(),
                method: "Context.getCacheDir"
            });
            
            console.log("[STORAGE] Cache directory accessed");
            return result;
        };
        
        Context.getExternalCacheDir.implementation = function() {
            var result = this.getExternalCacheDir();
            
            send({
                type: "cache_access",
                operation: "getExternalCacheDir",
                timestamp: Date.now(),
                method: "Context.getExternalCacheDir"
            });
            
            console.log("[STORAGE] External cache directory accessed");
            return result;
        };
        
    } catch (e) {
        console.log("[INFO] Cache directory hooks not available: " + e);
    }
    
    // ========================================================================
    // SHARED PREFERENCES MONITORING (TASK 1.1 & 1.2)
    // ========================================================================
    
    console.log("[SHARED-PREFS] 🚀 Initializing comprehensive SharedPreferences monitoring");
    
    try {
        // Sensitive data patterns for universal detection
        var sensitivePatterns = [
            /password/i, /passwd/i, /pwd/i, /passphrase/i,
            /token/i, /jwt/i, /bearer/i, /oauth/i, /auth/i,
            /secret/i, /key/i, /private.*key/i, /api.*key/i,
            /session/i, /cookie/i, /credential/i,
            /credit.*card/i, /debit.*card/i, /ssn/i, /account/i,
            /email/i, /phone/i, /address/i, /pin/i, /code/i
        ];
        
        /**
         * Check if key or value contains sensitive data
         */
        function containsSensitiveData(key, value) {
            if (!key && !value) return false;
            
            var keyString = key ? key.toString() : "";
            var valueString = value ? value.toString() : "";
            
            return sensitivePatterns.some(pattern => 
                pattern.test(keyString) || pattern.test(valueString)
            );
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
        
        // Hook Context.getSharedPreferences to detect preference creation
        var Context = Java.use("android.content.Context");
        Context.getSharedPreferences.implementation = function(name, mode) {
            var result = this.getSharedPreferences(name, mode);
            
            // Check for insecure modes (TASK 1.2: Global/World-readable SharedPreferences)
            var isInsecureMode = false;
            var modeDescription = "PRIVATE";
            
            // MODE_WORLD_READABLE = 1, MODE_WORLD_WRITEABLE = 2
            if (mode === 1) {
                isInsecureMode = true;
                modeDescription = "WORLD_READABLE";
            } else if (mode === 2) {
                isInsecureMode = true;
                modeDescription = "WORLD_WRITEABLE";
            } else if ((mode & 1) !== 0 || (mode & 2) !== 0) {
                isInsecureMode = true;
                modeDescription = "WORLD_ACCESSIBLE";
            }
            
            if (isInsecureMode) {
                send({
                    type: "shared_preferences_vulnerability",
                    vulnerability_type: "insecure_mode",
                    preference_name: name,
                    mode: mode,
                    mode_description: modeDescription,
                    timestamp: Date.now(),
                    stack_trace: getCurrentStackTrace(),
                    severity: "HIGH",
                    description: "SharedPreferences created with world-accessible mode",
                    evidence: {
                        operation: "getSharedPreferences",
                        insecure_mode: true,
                        mode_value: mode
                    }
                });
                
                console.log("[SHARED-PREFS-VULN] 🚨 INSECURE MODE: " + name + " with mode " + modeDescription);
            }
            
            // Log all SharedPreferences access for monitoring
            send({
                type: "shared_preferences",
                operation: "create",
                preference_name: name,
                mode: mode,
                mode_description: modeDescription,
                timestamp: Date.now(),
                stack_trace: getCurrentStackTrace()
            });
            
            console.log("[SHARED-PREFS] Created: " + name + " (mode: " + modeDescription + ")");
            return result;
        };
        
        // Hook SharedPreferences.Editor methods for data storage monitoring
        var SharedPreferencesEditor = Java.use("android.content.SharedPreferences$Editor");
        
        // Hook putString for sensitive string data detection (TASK 1.1)
        SharedPreferencesEditor.putString.implementation = function(key, value) {
            var result = this.putString(key, value);
            
            // Check for sensitive data patterns
            if (containsSensitiveData(key, value)) {
                send({
                    type: "shared_preferences_vulnerability", 
                    vulnerability_type: "sensitive_data_storage",
                    key: key,
                    value: value ? value.substring(0, 100) + "..." : null, // Limit value length
                    timestamp: Date.now(),
                    stack_trace: getCurrentStackTrace(),
                    severity: "HIGH",
                    description: "Sensitive data stored in SharedPreferences without encryption",
                    evidence: {
                        operation: "putString",
                        contains_sensitive_data: true,
                        key_analysis: sensitivePatterns.some(p => p.test(key || "")),
                        value_analysis: sensitivePatterns.some(p => p.test(value || ""))
                    }
                });
                
                console.log("[SHARED-PREFS-VULN] 🚨 SENSITIVE DATA: " + key + " contains sensitive information");
            }
            
            // Log all string storage operations
            send({
                type: "shared_preferences",
                operation: "putString",
                key: key,
                value_length: value ? value.length : 0,
                timestamp: Date.now(),
                stack_trace: getCurrentStackTrace()
            });
            
            console.log("[SHARED-PREFS] putString: " + key);
            return result;
        };
        
        // Hook putInt for sensitive numeric data detection
        SharedPreferencesEditor.putInt.implementation = function(key, value) {
            var result = this.putInt(key, value);
            
            if (containsSensitiveData(key, value)) {
                send({
                    type: "shared_preferences_vulnerability",
                    vulnerability_type: "sensitive_data_storage", 
                    key: key,
                    value: value,
                    timestamp: Date.now(),
                    stack_trace: getCurrentStackTrace(),
                    severity: "MEDIUM",
                    description: "Potentially sensitive numeric data stored in SharedPreferences",
                    evidence: {
                        operation: "putInt",
                        contains_sensitive_data: true
                    }
                });
                
                console.log("[SHARED-PREFS-VULN] 🚨 SENSITIVE INT: " + key);
            }
            
            send({
                type: "shared_preferences",
                operation: "putInt",
                key: key,
                value: value,
                timestamp: Date.now()
            });
            
            return result;
        };
        
        // Hook putLong for sensitive long data detection
        SharedPreferencesEditor.putLong.implementation = function(key, value) {
            var result = this.putLong(key, value);
            
            if (containsSensitiveData(key, value)) {
                send({
                    type: "shared_preferences_vulnerability",
                    vulnerability_type: "sensitive_data_storage",
                    key: key,
                    value: value,
                    timestamp: Date.now(),
                    stack_trace: getCurrentStackTrace(),
                    severity: "MEDIUM", 
                    description: "Potentially sensitive long data stored in SharedPreferences",
                    evidence: {
                        operation: "putLong",
                        contains_sensitive_data: true
                    }
                });
            }
            
            send({
                type: "shared_preferences",
                operation: "putLong",
                key: key,
                value: value,
                timestamp: Date.now()
            });
            
            return result;
        };
        
        // Hook putBoolean for sensitive boolean data detection
        SharedPreferencesEditor.putBoolean.implementation = function(key, value) {
            var result = this.putBoolean(key, value);
            
            if (containsSensitiveData(key, value)) {
                send({
                    type: "shared_preferences_vulnerability",
                    vulnerability_type: "sensitive_data_storage",
                    key: key,
                    value: value,
                    timestamp: Date.now(),
                    stack_trace: getCurrentStackTrace(),
                    severity: "LOW",
                    description: "Potentially sensitive boolean data stored in SharedPreferences",
                    evidence: {
                        operation: "putBoolean",
                        contains_sensitive_data: true
                    }
                });
            }
            
            send({
                type: "shared_preferences",
                operation: "putBoolean",
                key: key,
                value: value,
                timestamp: Date.now()
            });
            
            return result;
        };
        
        // Hook commit() to detect when sensitive data is actually persisted
        SharedPreferencesEditor.commit.implementation = function() {
            var result = this.commit();
            
            send({
                type: "shared_preferences",
                operation: "commit",
                timestamp: Date.now(),
                stack_trace: getCurrentStackTrace(),
                success: result,
                description: "SharedPreferences changes committed to persistent storage"
            });
            
            console.log("[SHARED-PREFS] Changes committed to storage");
            return result;
        };
        
        // Hook apply() to detect asynchronous persistence
        SharedPreferencesEditor.apply.implementation = function() {
            this.apply();
            
            send({
                type: "shared_preferences",
                operation: "apply",
                timestamp: Date.now(),
                stack_trace: getCurrentStackTrace(),
                description: "SharedPreferences changes applied asynchronously"
            });
            
            console.log("[SHARED-PREFS] Changes applied asynchronously");
        };
        
        // Hook getString for sensitive data retrieval monitoring
        var SharedPreferences = Java.use("android.content.SharedPreferences");
        SharedPreferences.getString.implementation = function(key, defValue) {
            var result = this.getString(key, defValue);
            
            if (containsSensitiveData(key, result)) {
                send({
                    type: "shared_preferences",
                    operation: "getString",
                    key: key,
                    has_sensitive_data: true,
                    timestamp: Date.now(),
                    description: "Sensitive data retrieved from SharedPreferences"
                });
                
                console.log("[SHARED-PREFS] 🔍 Sensitive data retrieved: " + key);
            }
            
            return result;
        };
        
        console.log("[SHARED-PREFS] ✅ All SharedPreferences hooks installed successfully");
        
    } catch (e) {
        console.log("[SHARED-PREFS] ❌ Failed to install SharedPreferences hooks: " + e);
    }
});