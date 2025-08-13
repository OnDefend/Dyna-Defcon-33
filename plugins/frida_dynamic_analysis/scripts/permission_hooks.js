/**
 * Permission Analysis Hooks
 * 
 * Monitors Android permission usage and detects potential privilege escalation
 * and permission abuse during runtime analysis.
 * 
 * Author: AODS Team
 * Date: January 2025
 */

// ADAPTIVE_PARAMETERS
// This marker allows adaptive parameter injection

Java.perform(function() {
    console.log("[+] Permission Analysis Hooks loaded");
    
    // Hook PackageManager for permission checking
    var PackageManager = Java.use("android.content.pm.PackageManager");
    
    PackageManager.checkPermission.overload("java.lang.String", "java.lang.String").implementation = function(permission, packageName) {
        var result = this.checkPermission(permission, packageName);
        var resultStr = (result === 0) ? "GRANTED" : "DENIED";
        
        console.log("[PERMISSION_CHECK] " + packageName + " checking " + permission + " → " + resultStr);
        
        send({
            type: "permission_check",
            permission: permission,
            package_name: packageName,
            result: resultStr,
            timestamp: Date.now(),
            evidence: {
                api_call: "PackageManager.checkPermission",
                permission: permission,
                package: packageName,
                result: result
            }
        });
        
        return result;
    };
    
    // Hook ContextWrapper for permission checks
    var ContextWrapper = Java.use("android.content.ContextWrapper");
    
    ContextWrapper.checkSelfPermission.implementation = function(permission) {
        var result = this.checkSelfPermission(permission);
        var resultStr = (result === 0) ? "GRANTED" : "DENIED";
        
        console.log("[SELF_PERMISSION] Checking " + permission + " → " + resultStr);
        
        send({
            type: "self_permission_check",
            permission: permission,
            result: resultStr,
            timestamp: Date.now(),
            evidence: {
                api_call: "ContextWrapper.checkSelfPermission",
                permission: permission,
                result: result
            }
        });
        
        return result;
    };
    
    // Hook ActivityCompat for runtime permission requests
    try {
        var ActivityCompat = Java.use("androidx.core.app.ActivityCompat");
        
        ActivityCompat.requestPermissions.implementation = function(activity, permissions, requestCode) {
            console.log("[PERMISSION_REQUEST] Requesting permissions: " + permissions.toString());
            
            send({
                type: "permission_request",
                permissions: permissions.toString(),
                request_code: requestCode,
                timestamp: Date.now(),
                evidence: {
                    api_call: "ActivityCompat.requestPermissions",
                    permissions: permissions,
                    request_code: requestCode
                }
            });
            
            return this.requestPermissions(activity, permissions, requestCode);
        };
    } catch (e) {
        console.log("[DEBUG] ActivityCompat not available: " + e);
    }
    
    console.log("[+] Permission Analysis Hooks active");
});