"""
AODS Plugin Constants - Security Testing Framework Constants

This module provides centralized constants for OWASP MASTG/MASVS compliance,
CWE mappings, GDPR articles, and NIST framework alignment.

Version Compliance:
- OWASP MASTG v2.0 (2024)
- OWASP MASVS v2.0 (2024) 
- CWE Top 25 (2024)
- GDPR (Current)
- NIST Cybersecurity Framework v2.0

Note: MASTG test IDs are mapped to internal test implementations.
For official OWASP MASTG test cases, refer to: https://mas.owasp.org/MASTG/
"""

# MASTG Test ID Mappings (Internal Implementation)
# These map vulnerability types to corresponding test implementations
# Based on OWASP MASTG v2.0 methodology but using internal test case numbers
MASTG_TEST_MAPPINGS = {
    # Authentication & Authorization Tests
    "auth_confirm_credentials": "MASTG-TEST-0017",  # Credential confirmation testing
    "auth_biometric": "MASTG-TEST-0018",           # Biometric authentication testing
    "auth_keystore": "MASTG-TEST-0015",            # Keystore/KeyChain testing
    "auth_tokens": "MASTG-TEST-0212",              # Token-based authentication
    "auth_storage": "MASTG-TEST-0001",             # Authentication data storage
    
    # Code Quality & Injection Tests  
    "sql_injection": "MASTG-TEST-0019",            # SQL injection testing
    "xss_webview": "MASTG-TEST-0020",              # XSS in WebView testing
    "object_injection": "MASTG-TEST-0021",         # Object injection testing
    "code_injection": "MASTG-TEST-0022",           # Code injection testing
    "path_traversal": "MASTG-TEST-0023",           # Path traversal testing
    "command_injection": "MASTG-TEST-0024",        # Command injection testing
    
    # Privacy & Data Protection Tests
    "privacy_controls": "MASTG-TEST-0025",         # User privacy controls
    "data_consent": "MASTG-TEST-0026",             # Data collection consent
    "data_processing": "MASTG-TEST-0027",          # Personal data processing
    "third_party_sharing": "MASTG-TEST-0028",      # Third-party data sharing
    "data_retention": "MASTG-TEST-0029",           # Data retention policies
    "user_data_rights": "MASTG-TEST-0030",         # User data rights implementation
    
    # iOS-Specific Security Tests
    "ios_webview_js_bridge": "MASTG-TEST-0031",    # iOS WebView JS bridge security
    "ios_webview_file_access": "MASTG-TEST-0032",  # iOS WebView file access
    "ios_webview_url_loading": "MASTG-TEST-0033",  # iOS WebView URL loading
    "ios_webview_csp": "MASTG-TEST-0034",          # iOS WebView CSP implementation
    "ios_wkwebview_config": "MASTG-TEST-0035",     # iOS WKWebView configuration
    "ios_biometric_auth": "MASTG-TEST-0064",       # iOS biometric authentication
    "ios_keychain_security": "MASTG-TEST-0065",    # iOS Keychain security
    "ios_ats_config": "MASTG-TEST-0066",           # iOS App Transport Security
    "ios_cert_pinning": "MASTG-TEST-0067",         # iOS certificate pinning
    "ios_runtime_protection": "MASTG-TEST-0068",   # iOS runtime protection
    "ios_code_signing": "MASTG-TEST-0069",         # iOS code signing validation
}

# MASVS Control Mappings (OWASP MASVS v2.0 Compliant)
MASVS_CONTROL_MAPPINGS = {
    "auth": "MASVS-AUTH",           # Authentication and Session Management
    "code": "MASVS-CODE",           # Code Quality and Build Settings
    "privacy": "MASVS-PRIVACY",     # Privacy Controls
    "crypto": "MASVS-CRYPTO",       # Cryptography Requirements
    "network": "MASVS-NETWORK",     # Network Communication Security
    "platform": "MASVS-PLATFORM",  # Platform Integration
    "storage": "MASVS-STORAGE",     # Data Storage and Privacy
    "resilience": "MASVS-RESILIENCE" # Anti-Tampering and Reverse Engineering
}

# CWE Mappings (Based on CWE Top 25 2024)
CWE_MAPPINGS = {
    # Top 10 Most Critical (2024 Rankings)
    "xss": "CWE-79",                    # #1 - Cross-site Scripting
    "buffer_overflow_write": "CWE-787", # #2 - Out-of-bounds Write  
    "sql_injection": "CWE-89",          # #3 - SQL Injection
    "csrf": "CWE-352",                  # #4 - Cross-Site Request Forgery
    "path_traversal": "CWE-22",         # #5 - Path Traversal
    "buffer_overflow_read": "CWE-125",  # #6 - Out-of-bounds Read
    "os_command_injection": "CWE-78",   # #7 - OS Command Injection
    "use_after_free": "CWE-416",        # #8 - Use After Free
    "missing_authorization": "CWE-862", # #9 - Missing Authorization
    "file_upload": "CWE-434",           # #10 - Unrestricted File Upload
    
    # Additional Critical CWEs
    "code_injection": "CWE-94",         # #11 - Code Injection
    "input_validation": "CWE-20",       # #12 - Improper Input Validation
    "command_injection": "CWE-77",      # #13 - Command Injection
    "improper_auth": "CWE-287",         # #14 - Improper Authentication
    "privilege_management": "CWE-269",  # #15 - Improper Privilege Management
    "deserialization": "CWE-502",       # #16 - Deserialization of Untrusted Data
    "info_exposure": "CWE-200",         # #17 - Information Exposure
    "incorrect_authorization": "CWE-863", # #18 - Incorrect Authorization
    "ssrf": "CWE-918",                  # #19 - Server-Side Request Forgery
    "memory_buffer": "CWE-119",         # #20 - Memory Buffer Operations
    
    # Security-Specific CWEs
    "unsafe_reflection": "CWE-470",     # Unsafe Reflection
    "null_pointer": "CWE-476",          # NULL Pointer Dereference
    "hardcoded_credentials": "CWE-798", # Use of Hard-coded Credentials
    "integer_overflow": "CWE-190",      # Integer Overflow
    "resource_consumption": "CWE-400",  # Uncontrolled Resource Consumption
    "missing_auth_critical": "CWE-306", # Missing Authentication for Critical Function
}

# GDPR Article Mappings (Current GDPR Regulation)
GDPR_ARTICLE_MAPPINGS = {
    "data_processing_principles": "Article 5",     # Principles relating to processing
    "lawfulness_processing": "Article 6",          # Lawfulness of processing
    "special_categories": "Article 9",             # Processing of special categories
    "right_erasure": "Article 17",                 # Right to erasure ('right to be forgotten')
    "data_portability": "Article 20",              # Right to data portability
    "data_protection_design": "Article 25",        # Data protection by design and by default
    "security_processing": "Article 32",           # Security of processing
    "data_breach_notification": "Article 33",      # Notification of data breach to supervisory authority
    "data_protection_impact": "Article 35",        # Data protection impact assessment
}

# NIST Cybersecurity Framework v2.0 Mappings
NIST_FRAMEWORK_MAPPINGS = {
    "identify": "NIST.ID",              # Identify function
    "protect": "NIST.PR",               # Protect function  
    "detect": "NIST.DE",                # Detect function
    "respond": "NIST.RS",               # Respond function
    "recover": "NIST.RC",               # Recover function
    "govern": "NIST.GV",                # Govern function (v2.0 addition)
}

# Severity Level Mappings (CVSS v3.1 Aligned)
SEVERITY_MAPPINGS = {
    "critical": 9.0,                    # CVSS 9.0-10.0
    "high": 7.0,                        # CVSS 7.0-8.9
    "medium": 4.0,                      # CVSS 4.0-6.9
    "low": 0.1,                         # CVSS 0.1-3.9
    "info": 0.0                         # CVSS 0.0
}

# Plugin Execution Timeouts (seconds) - Optimized for Production
TIMEOUTS = {
    "default": 300,                     # 5 minutes default
    "static_analysis": 600,             # 10 minutes for static analysis
    "dynamic_analysis": 900,            # 15 minutes for dynamic analysis
    "network_analysis": 180,            # 3 minutes for network tests
    "crypto_analysis": 240,             # 4 minutes for crypto tests
    "quick_scan": 60,                   # 1 minute for quick scans
    "comprehensive": 1800,              # 30 minutes for comprehensive scans
    # Additional timeout categories for specific plugin types
    "ml_analysis": 360,                 # 6 minutes for ML analysis
    "file_processing": 420,             # 7 minutes for file processing
    "device_interaction": 240,          # 4 minutes for device operations
    "external_tool": 180,               # 3 minutes for external tools (APKtool, etc.)
    "frida_analysis": 300,              # 5 minutes for Frida-based analysis
    "webview_analysis": 240,            # 4 minutes for WebView analysis
    "intent_fuzzing": 180,              # 3 minutes for intent fuzzing
    "log_analysis": 120,                # 2 minutes for log analysis
    "anti_debugging": 180,              # 3 minutes for anti-debugging checks
    "root_detection": 120,              # 2 minutes for root detection
}

# Risk Level Classifications
RISK_LEVELS = {
    "critical": {"score": 10, "color": "red", "priority": 1},
    "high": {"score": 8, "color": "orange", "priority": 2},
    "medium": {"score": 6, "color": "yellow", "priority": 3},
    "low": {"score": 4, "color": "blue", "priority": 4},
    "info": {"score": 2, "color": "green", "priority": 5}
}

# Plugin Categories
PLUGIN_CATEGORIES = {
    "authentication": "Authentication & Session Management",
    "authorization": "Authorization & Access Control",
    "crypto": "Cryptography & Key Management",
    "network": "Network Communication Security",
    "storage": "Data Storage & Privacy",
    "code_quality": "Code Quality & Build Settings",
    "platform": "Platform Integration",
    "privacy": "Privacy Controls",
    "resilience": "Anti-Tampering & Reverse Engineering",
    "webview": "WebView Security",
    "dynamic": "Dynamic Analysis",
    "static": "Static Analysis"
}

# Utility Functions
def get_mastg_test(vulnerability_type: str, default: str = "MASTG-TEST-0017") -> str:
    """
    Get MASTG test ID for a vulnerability type.
    
    Args:
        vulnerability_type: Type of vulnerability
        default: Default test ID if not found
        
    Returns:
        MASTG test ID string
    """
    return MASTG_TEST_MAPPINGS.get(vulnerability_type, default)

def get_masvs_control(category: str, default: str = "MASVS-PLATFORM") -> str:
    """
    Get MASVS control for a category.
    
    Args:
        category: Security category
        default: Default control if not found
        
    Returns:
        MASVS control string
    """
    return MASVS_CONTROL_MAPPINGS.get(category, default)

def get_cwe_id(vulnerability_type: str, default: str = "CWE-79") -> str:
    """
    Get CWE ID for a vulnerability type.
    
    Args:
        vulnerability_type: Type of vulnerability
        default: Default CWE if not found
        
    Returns:
        CWE ID string
    """
    return CWE_MAPPINGS.get(vulnerability_type, default)

def get_gdpr_article(data_processing_type: str, default: str = "Article 5") -> str:
    """
    Get GDPR article for a data processing type.
    
    Args:
        data_processing_type: Type of data processing
        default: Default article if not found
        
    Returns:
        GDPR article string
    """
    return GDPR_ARTICLE_MAPPINGS.get(data_processing_type, default)

def get_nist_function(security_function: str, default: str = "NIST.PR") -> str:
    """
    Get NIST framework function.
    
    Args:
        security_function: Security function type
        default: Default function if not found
        
    Returns:
        NIST function string
    """
    return NIST_FRAMEWORK_MAPPINGS.get(security_function, default)

def get_severity_score(severity_level: str, default: float = 4.0) -> float:
    """
    Get CVSS severity score for a level.
    
    Args:
        severity_level: Severity level name
        default: Default score if not found
        
    Returns:
        CVSS severity score
    """
    return SEVERITY_MAPPINGS.get(severity_level.lower(), default)

# Validation Functions
def validate_mastg_test_id(test_id: str) -> bool:
    """Validate MASTG test ID format."""
    return test_id.startswith("MASTG-TEST-") and test_id.split("-")[-1].isdigit()

def validate_masvs_control(control: str) -> bool:
    """Validate MASVS control format."""
    return control.startswith("MASVS-") and control in MASVS_CONTROL_MAPPINGS.values()

def validate_cwe_id(cwe_id: str) -> bool:
    """Validate CWE ID format."""
    return cwe_id.startswith("CWE-") and cwe_id.split("-")[-1].isdigit()

# Export all mappings for external use
__all__ = [
    'MASTG_TEST_MAPPINGS',
    'MASVS_CONTROL_MAPPINGS', 
    'CWE_MAPPINGS',
    'GDPR_ARTICLE_MAPPINGS',
    'NIST_FRAMEWORK_MAPPINGS',
    'SEVERITY_MAPPINGS',
    'get_mastg_test',
    'get_masvs_control',
    'get_cwe_id', 
    'get_gdpr_article',
    'get_nist_function',
    'get_severity_score',
    'validate_mastg_test_id',
    'validate_masvs_control',
    'validate_cwe_id'
] 
# Plugin Execution Timeouts (seconds)
TIMEOUTS = {
    "default": 300,                     # 5 minutes default
    "static_analysis": 600,             # 10 minutes for static analysis
    "dynamic_analysis": 900,            # 15 minutes for dynamic analysis
    "network_analysis": 180,            # 3 minutes for network tests
    "crypto_analysis": 240,             # 4 minutes for crypto tests
    "quick_scan": 60,                   # 1 minute for quick scans
    "comprehensive": 1800               # 30 minutes for comprehensive scans
}

# Risk Level Classifications
RISK_LEVELS = {
    "critical": {"score": 10, "color": "red", "priority": 1},
    "high": {"score": 8, "color": "orange", "priority": 2},
    "medium": {"score": 6, "color": "yellow", "priority": 3},
    "low": {"score": 4, "color": "blue", "priority": 4},
    "info": {"score": 2, "color": "green", "priority": 5}
}

# Plugin Categories
PLUGIN_CATEGORIES = {
    "authentication": "Authentication & Session Management",
    "authorization": "Authorization & Access Control",
    "crypto": "Cryptography & Key Management",
    "network": "Network Communication Security",
    "storage": "Data Storage & Privacy",
    "code_quality": "Code Quality & Build Settings",
    "platform": "Platform Integration",
    "privacy": "Privacy Controls",
    "resilience": "Anti-Tampering & Reverse Engineering",
    "webview": "WebView Security",
    "dynamic": "Dynamic Analysis",
    "static": "Static Analysis"
}
