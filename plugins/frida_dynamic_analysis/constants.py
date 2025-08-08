"""
Constants and configurations for Frida Dynamic Analysis Plugin.

This module contains all constants, patterns, and configurations used
throughout the Frida dynamic analysis plugin with accurate MASVS/MSTG mappings.
"""

from .data_structures import FridaVulnerabilityPattern, FridaSecurityRecommendation

# MASVS control mappings for vulnerability types
MASVS_MAPPINGS = {
    "ssl_pinning_bypass": {
        "masvs_control": "MSTG-NETWORK-4",
        "masvs_category": "Network Communication",
        "description": "Certificate pinning implementation vulnerability",
        "severity": "HIGH",
        "owasp_category": "M3: Insecure Communication"
    },
    "webview_security": {
        "masvs_control": "MSTG-PLATFORM-2",
        "masvs_category": "Platform Interaction",
        "description": "WebView security configuration vulnerability",
        "severity": "MEDIUM",
        "owasp_category": "M1: Improper Platform Usage"
    },
    "javascript_execution": {
        "masvs_control": "MSTG-PLATFORM-11",
        "masvs_category": "Platform Interaction",
        "description": "JavaScript execution security vulnerability",
        "severity": "MEDIUM",
        "owasp_category": "M1: Improper Platform Usage"
    },
    "anti_debugging": {
        "masvs_control": "MSTG-RESILIENCE-2",
        "masvs_category": "Resilience",
        "description": "Anti-debugging mechanism vulnerability",
        "severity": "MEDIUM",
        "owasp_category": "M10: Extraneous Functionality"
    },
    "anti_tampering": {
        "masvs_control": "MSTG-RESILIENCE-3",
        "masvs_category": "Resilience",
        "description": "Anti-tampering mechanism vulnerability",
        "severity": "MEDIUM",
        "owasp_category": "M10: Extraneous Functionality"
    },
    "runtime_protection": {
        "masvs_control": "MSTG-RESILIENCE-1",
        "masvs_category": "Resilience",
        "description": "Runtime application self-protection vulnerability",
        "severity": "HIGH",
        "owasp_category": "M10: Extraneous Functionality"
    },
    "memory_corruption": {
        "masvs_control": "MSTG-CODE-8",
        "masvs_category": "Code Quality",
        "description": "Memory corruption protection vulnerability",
        "severity": "HIGH",
        "owasp_category": "M7: Client Code Quality"
    },
    "binary_protection": {
        "masvs_control": "MSTG-CODE-9",
        "masvs_category": "Code Quality",
        "description": "Binary protection mechanism vulnerability",
        "severity": "MEDIUM",
        "owasp_category": "M7: Client Code Quality"
    }
}

# Plugin characteristics with accurate MASVS/MSTG mappings
PLUGIN_CHARACTERISTICS = {
    "mode": "deep",  # Frida analysis requires deep mode
    "category": "DYNAMIC_ANALYSIS",
    "masvs_controls": [
        "MSTG-NETWORK-1",   # Network requests over secure channels
        "MSTG-NETWORK-2",   # TLS settings verification
        "MSTG-NETWORK-3",   # Network security configuration
        "MSTG-NETWORK-4",   # Certificate pinning implementation
        "MSTG-PLATFORM-2",  # WebView security configuration
        "MSTG-PLATFORM-11", # JavaScript execution contexts
        "MSTG-RESILIENCE-1", # Runtime application self-protection
        "MSTG-RESILIENCE-2", # Anti-debugging mechanisms
        "MSTG-RESILIENCE-3", # Anti-tampering mechanisms
        "MSTG-RESILIENCE-4", # Reverse engineering resistance
        "MSTG-RESILIENCE-9", # Runtime detection and response
        "MSTG-RESILIENCE-10", # Device binding and attestation
        "MSTG-CODE-6",      # Exception handling
        "MSTG-CODE-8",      # Memory corruption protection
        "MSTG-CODE-9",      # Binary protection mechanisms
    ],
    "owasp_categories": [
        "M1: Improper Platform Usage",
        "M2: Insecure Data Storage", 
        "M3: Insecure Communication",
        "M4: Insecure Authentication",
        "M7: Client Code Quality",
        "M10: Extraneous Functionality"
    ],
    "description": "Enhanced Frida-based dynamic security analysis with comprehensive vulnerability detection",
    "version": "2.0.0",
    "author": "AODS Framework Team"
}

# Vulnerability patterns with accurate MASVS/MSTG mappings
VULNERABILITY_PATTERNS = {
    "ssl_pinning_bypass": FridaVulnerabilityPattern(
        pattern_name="ssl_pinning_bypass",
        indicators=[
            "pinning bypassed",
            "certificate validation disabled",
            "ssl context modified",
            "trust manager replaced",
            "hostname verification disabled",
            "ssl_ctx_set_verify",
            "certificate pinning bypass"
        ],
        severity="HIGH",
        cwe_id="CWE-295",
        masvs_control="MSTG-NETWORK-4",
        owasp_category="M3: Insecure Communication",
        confidence_weight=0.9,
        false_positive_indicators=["test", "debug", "mock", "fake"]
    ),
    
    "webview_xss": FridaVulnerabilityPattern(
        pattern_name="webview_xss",
        indicators=[
            "javascript bridge exposed",
            "webview eval execution",
            "addJavascriptInterface",
            "javascript execution detected",
            "webview xss vulnerability",
            "unsafe javascript bridge",
            "javascript injection possible"
        ],
        severity="HIGH",
        cwe_id="CWE-79",
        masvs_control="MSTG-PLATFORM-2",
        owasp_category="M1: Improper Platform Usage",
        confidence_weight=0.85,
        false_positive_indicators=["secure", "sanitized", "validation"]
    ),
    
    "anti_debug_bypass": FridaVulnerabilityPattern(
        pattern_name="anti_debug_bypass",
        indicators=[
            "debugger detection bypassed",
            "ptrace bypass successful",
            "anti-debug mechanism defeated",
            "debug detection disabled",
            "debugging protection bypassed",
            "tracerpid check bypassed",
            "debug.isdebuggingconnected bypassed"
        ],
        severity="MEDIUM",
        cwe_id="CWE-489",
        masvs_control="MSTG-RESILIENCE-2",
        owasp_category="M10: Extraneous Functionality",
        confidence_weight=0.8,
        false_positive_indicators=["intentional", "expected", "test"]
    ),
    
    "runtime_manipulation": FridaVulnerabilityPattern(
        pattern_name="runtime_manipulation",
        indicators=[
            "method hooking successful",
            "class replacement detected",
            "runtime modification possible",
            "api hooking successful",
            "method interception active",
            "runtime tampering detected",
            "code injection successful"
        ],
        severity="HIGH",
        cwe_id="CWE-913",
        masvs_control="MSTG-RESILIENCE-1",
        owasp_category="M10: Extraneous Functionality",
        confidence_weight=0.9,
        false_positive_indicators=["authorized", "intended", "legitimate"]
    ),
    
    "memory_corruption": FridaVulnerabilityPattern(
        pattern_name="memory_corruption",
        indicators=[
            "buffer overflow detected",
            "memory corruption vulnerability",
            "segmentation fault",
            "heap overflow",
            "stack overflow",
            "memory leak detected",
            "use after free"
        ],
        severity="CRITICAL",
        cwe_id="CWE-120",
        masvs_control="MSTG-CODE-8",
        owasp_category="M7: Client Code Quality",
        confidence_weight=0.95,
        false_positive_indicators=["simulation", "intentional", "test"]
    ),
    
    "root_detection_bypass": FridaVulnerabilityPattern(
        pattern_name="root_detection_bypass",
        indicators=[
            "root detection bypassed",
            "su binary check bypassed",
            "root cloak active",
            "superuser detection defeated",
            "rootbeer bypassed",
            "root hiding successful",
            "device root status masked"
        ],
        severity="MEDIUM",
        cwe_id="CWE-350",
        masvs_control="MSTG-RESILIENCE-1",
        owasp_category="M10: Extraneous Functionality",
        confidence_weight=0.8,
        false_positive_indicators=["emulator", "test", "development"]
    ),
    
    "api_abuse": FridaVulnerabilityPattern(
        pattern_name="api_abuse",
        indicators=[
            "sensitive api hooked",
            "privacy api bypassed",
            "permission check bypassed",
            "api misuse detected",
            "unauthorized api access",
            "api security bypass",
            "system api manipulation"
        ],
        severity="HIGH",
        cwe_id="CWE-284",
        masvs_control="MSTG-PLATFORM-11",
        owasp_category="M1: Improper Platform Usage",
        confidence_weight=0.85,
        false_positive_indicators=["authorized", "legitimate", "expected"]
    )
}

# Security recommendations with deduplication support
SECURITY_RECOMMENDATIONS = {
    "ssl_pinning_bypass": FridaSecurityRecommendation(
        recommendation_id="SSL_PINNING_BYPASS",
        title="Implement Robust SSL Certificate Pinning",
        description="SSL certificate pinning bypass detected during dynamic analysis",
        severity="HIGH",
        masvs_control="MSTG-NETWORK-4",
        fix_description="Implement robust certificate pinning with backup mechanisms and certificate transparency validation",
        code_example="""
// Secure SSL pinning implementation
CertificatePinner certificatePinner = new CertificatePinner.Builder()
    .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
    .build();

OkHttpClient client = new OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .connectionSpecs(Arrays.asList(ConnectionSpec.MODERN_TLS))
    .build();
""",
        references=[
            "https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning",
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md"
        ]
    ),
    
    "webview_xss": FridaSecurityRecommendation(
        recommendation_id="WEBVIEW_XSS",
        title="Secure WebView Configuration",
        description="WebView XSS vulnerability detected during dynamic analysis",
        severity="HIGH",
        masvs_control="MSTG-PLATFORM-2",
        fix_description="Disable JavaScript bridges, implement strict content security policy, and validate all WebView inputs",
        code_example="""
// Secure WebView configuration
webView.getSettings().setJavaScriptEnabled(false);
webView.getSettings().setAllowFileAccess(false);
webView.getSettings().setAllowContentAccess(false);
webView.setWebViewClient(new SecureWebViewClient());

// If JavaScript is required, use secure bridge
@JavascriptInterface
public void secureMethod(String input) {
    // Validate and sanitize all inputs
    if (isValidInput(input)) {
        processSecurely(input);
    }
}
""",
        references=[
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md",
            "https://owasp.org/www-project-mobile-top-10/"
        ]
    ),
    
    "anti_debug_bypass": FridaSecurityRecommendation(
        recommendation_id="ANTI_DEBUG_BYPASS",
        title="Implement Multi-Layer Anti-Debugging Protection",
        description="Anti-debugging mechanism bypass detected during dynamic analysis",
        severity="MEDIUM",
        masvs_control="MSTG-RESILIENCE-2",
        fix_description="Implement multiple layers of anti-debugging protection and runtime integrity checks",
        code_example="""
// Multi-layered anti-debugging
private boolean isDebuggerAttached() {
    return Debug.isDebuggerConnected() || 
           Debug.waitingForDebugger() ||
           checkTracerPid() ||
           checkTimingAttacks();
}

private void enforceIntegrity() {
    if (isDebuggerAttached() || isRuntimeManipulated()) {
        // Graceful degradation or exit
        terminateApplication();
    }
}
""",
        references=[
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md"
        ]
    ),
    
    "runtime_manipulation": FridaSecurityRecommendation(
        recommendation_id="RUNTIME_MANIPULATION",
        title="Implement Runtime Application Self-Protection",
        description="Runtime manipulation vulnerability detected during dynamic analysis",
        severity="HIGH",
        masvs_control="MSTG-RESILIENCE-1",
        fix_description="Implement runtime application self-protection mechanisms with integrity verification",
        code_example="""
// Runtime integrity verification
private boolean verifyRuntimeIntegrity() {
    return checkCodeIntegrity() && 
           checkMethodIntegrity() && 
           checkClassIntegrity() &&
           checkHookingDetection();
}

private void respondToTampering() {
    if (!verifyRuntimeIntegrity()) {
        // Implement response strategy
        terminateOrDegrade();
    }
}
""",
        references=[
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md"
        ]
    )
}

# Frida script templates for different test types
FRIDA_SCRIPT_TEMPLATES = {
    "ssl_pinning_test": """
Java.perform(function() {
    console.log("[+] SSL Pinning Test Started");
    
    // Hook common SSL pinning bypass points
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    
    // Test SSL context modifications
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManager, trustManager, secureRandom) {
        console.log("[+] SSL Context initialization intercepted");
        send({"type": "ssl_context_modified", "evidence": "SSL context initialization detected"});
        return this.init(keyManager, trustManager, secureRandom);
    };
    
    // Test certificate validation bypass
    HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
        console.log("[+] Hostname verifier bypass detected");
        send({"type": "hostname_verification_bypass", "evidence": "Hostname verification bypass detected"});
        return this.setDefaultHostnameVerifier(hostnameVerifier);
    };
});
""",
    
    "webview_test": """
Java.perform(function() {
    console.log("[+] WebView Security Test Started");
    
    var WebView = Java.use("android.webkit.WebView");
    var WebSettings = Java.use("android.webkit.WebSettings");
    
    // Test JavaScript bridge exposure
    WebView.addJavascriptInterface.implementation = function(object, name) {
        console.log("[+] JavaScript interface added: " + name);
        send({"type": "javascript_bridge_exposed", "evidence": "JavaScript interface: " + name});
        return this.addJavascriptInterface(object, name);
    };
    
    // Test WebView security settings
    WebSettings.setJavaScriptEnabled.implementation = function(enabled) {
        console.log("[+] JavaScript enabled: " + enabled);
        send({"type": "javascript_enabled", "evidence": "JavaScript enabled: " + enabled});
        return this.setJavaScriptEnabled(enabled);
    };
});
""",
    
    "anti_tampering_test": """
Java.perform(function() {
    console.log("[+] Anti-Tampering Test Started");
    
    var System = Java.use("java.lang.System");
    var Debug = Java.use("android.os.Debug");
    
    // Test debugger detection bypass
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[+] Debugger detection check bypassed");
        send({"type": "debugger_detection_bypass", "evidence": "Debugger detection bypassed"});
        return false;
    };
    
    // Test process monitoring
    System.getProperty.implementation = function(key) {
        if (key === "ro.debuggable") {
            console.log("[+] Debuggable property check intercepted");
            send({"type": "debuggable_check", "evidence": "Debuggable property accessed"});
        }
        return this.getProperty(key);
    };
});
"""
}

# Test execution timeouts and configurations
TEST_TIMEOUTS = {
    "ssl_pinning": 30,
    "webview_security": 25,
    "anti_tampering": 20,
    "memory_corruption": 45,
    "runtime_manipulation": 35,
    "default": 30
}

# Device requirements and compatibility
DEVICE_REQUIREMENTS = {
    "min_android_version": "5.0",
    "required_tools": ["frida", "adb"],
    "optional_tools": ["frida-server"],
    "root_required": True,
    "usb_debugging_required": True
}

# Error messages and troubleshooting
ERROR_MESSAGES = {
    "frida_not_found": "Frida is not installed or not available in PATH",
    "no_devices": "No Android devices found for Frida analysis",
    "frida_server_not_running": "Frida server is not running on the target device",
    "package_not_found": "Target package not found on device",
    "connection_failed": "Failed to connect to Frida server",
    "spawn_failed": "Failed to spawn target application",
    "script_error": "Frida script execution failed",
    "timeout": "Test execution timed out"
}

# Logging configuration
LOGGING_CONFIG = {
    "log_level": "INFO",
    "log_frida_output": True,
    "log_subprocess_output": True,
    "max_log_size": 10 * 1024 * 1024,  # 10MB
    "log_rotation": True
} 