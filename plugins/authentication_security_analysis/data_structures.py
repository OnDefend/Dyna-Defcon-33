"""
Data structures for authentication security analysis.
Defines authentication vulnerabilities, enums, and constants.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Union

class AuthenticationVulnerabilityType(Enum):
    """Types of authentication vulnerabilities."""
    WEAK_BIOMETRIC_IMPLEMENTATION = "weak_biometric_implementation"
    MISSING_BIOMETRIC_ERROR_HANDLING = "missing_biometric_error_handling"
    MISSING_BIOMETRIC_HARDWARE_REQUIREMENT = "missing_biometric_hardware_requirement"
    IMPROPER_CREDENTIAL_CONFIRMATION_HANDLING = "improper_credential_confirmation_handling"
    INSECURE_SESSION_STORAGE = "insecure_session_storage"
    HARDCODED_AUTH_TOKENS = "hardcoded_auth_tokens"
    HARDCODED_API_KEYS = "hardcoded_api_keys"
    HARDCODED_PASSWORDS = "hardcoded_passwords"
    HARDCODED_JWT_TOKENS = "hardcoded_jwt_tokens"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    KEYSTORE_MISSING_USER_AUTH = "keystore_missing_user_auth"
    KEYSTORE_EXCESSIVE_AUTH_TIMEOUT = "keystore_excessive_auth_timeout"
    BIOMETRIC_WEAK_FALLBACK = "biometric_weak_fallback"
    BIOMETRIC_NO_FALLBACK = "biometric_no_fallback"
    BIOMETRIC_IMPROPER_ERROR_HANDLING = "biometric_improper_error_handling"
    BIOMETRIC_WEAK_PROMPT_CONFIG = "biometric_weak_prompt_config"
    BIOMETRIC_NO_CONFIRMATION_REQUIRED = "biometric_no_confirmation_required"

class AuthenticationSeverity(Enum):
    """Severity levels for authentication vulnerabilities."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class MASTGTestType(Enum):
    """MASTG test categories for authentication."""
    AUTH_CONFIRM_CREDENTIALS = "MASTG-TEST-0017"
    AUTH_BIOMETRIC = "MASTG-TEST-0018"
    AUTH_IOS_BIOMETRIC = "MASTG-TEST-0064"
    AUTH_EVENT_BOUND = "MASTG-TEST-0266"

class MASVSControl(Enum):
    """MASVS controls for authentication."""
    AUTH = "MASVS-AUTH"

class AuthenticationPatternCategory(Enum):
    """Categories of authentication patterns to analyze."""
    BIOMETRIC_APIS = "biometric_apis"
    WEAK_BIOMETRIC_IMPLEMENTATION = "weak_biometric_implementation"
    CREDENTIAL_CONFIRMATION = "credential_confirmation"
    SESSION_MANAGEMENT = "session_management"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    SECRET_PATTERNS = "secret_patterns"

@dataclass
class AuthenticationVulnerability:
    """Detailed authentication vulnerability with exact location and values."""
    
    vuln_type: str
    location: str
    value: str
    decoded_value: Optional[str] = None
    secret_value: Optional[str] = None
    line_number: Optional[int] = None
    severity: str = "HIGH"
    
    def __post_init__(self):
        """Initialize MASTG test ID after object creation."""
        self.mastg_test_id = self._get_mastg_test_id()
    
    def _get_mastg_test_id(self) -> str:
        """Map vulnerability type to MASTG test ID."""
        mastg_mapping = {
            "weak_biometric_implementation": MASTGTestType.AUTH_BIOMETRIC.value,
            "missing_biometric_error_handling": MASTGTestType.AUTH_BIOMETRIC.value,
            "missing_biometric_hardware_requirement": MASTGTestType.AUTH_BIOMETRIC.value,
            "improper_credential_confirmation_handling": MASTGTestType.AUTH_CONFIRM_CREDENTIALS.value,
            "insecure_session_storage": MASTGTestType.AUTH_CONFIRM_CREDENTIALS.value,
            "hardcoded_auth_tokens": MASTGTestType.AUTH_CONFIRM_CREDENTIALS.value,
            "hardcoded_api_keys": MASTGTestType.AUTH_CONFIRM_CREDENTIALS.value,
            "hardcoded_passwords": MASTGTestType.AUTH_CONFIRM_CREDENTIALS.value,
            "hardcoded_jwt_tokens": MASTGTestType.AUTH_CONFIRM_CREDENTIALS.value,
            "authentication_bypass": MASTGTestType.AUTH_CONFIRM_CREDENTIALS.value,
            "keystore_missing_user_auth": MASTGTestType.AUTH_BIOMETRIC.value,
            "keystore_excessive_auth_timeout": MASTGTestType.AUTH_BIOMETRIC.value,
            "biometric_weak_fallback": MASTGTestType.AUTH_BIOMETRIC.value,
            "biometric_no_fallback": MASTGTestType.AUTH_BIOMETRIC.value,
            "biometric_improper_error_handling": MASTGTestType.AUTH_BIOMETRIC.value,
            "biometric_weak_prompt_config": MASTGTestType.AUTH_BIOMETRIC.value,
            "biometric_no_confirmation_required": MASTGTestType.AUTH_BIOMETRIC.value
        }
        return mastg_mapping.get(self.vuln_type, MASTGTestType.AUTH_CONFIRM_CREDENTIALS.value)

@dataclass
class AuthenticationAnalysisResult:
    """Result of authentication security analysis."""
    
    vulnerabilities: List[AuthenticationVulnerability]
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    mastg_compliance: Dict[str, bool]
    
    @classmethod
    def create_from_vulnerabilities(cls, vulnerabilities: List[AuthenticationVulnerability]) -> 'AuthenticationAnalysisResult':
        """Create analysis result from vulnerability list."""
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] += 1
        
        # Check MASTG compliance (fails if any findings exist)
        mastg_compliance = {
            MASTGTestType.AUTH_CONFIRM_CREDENTIALS.value: not any(
                v.mastg_test_id == MASTGTestType.AUTH_CONFIRM_CREDENTIALS.value for v in vulnerabilities
            ),
            MASTGTestType.AUTH_BIOMETRIC.value: not any(
                v.mastg_test_id == MASTGTestType.AUTH_BIOMETRIC.value for v in vulnerabilities
            )
        }
        
        return cls(
            vulnerabilities=vulnerabilities,
            total_findings=len(vulnerabilities),
            critical_findings=severity_counts["CRITICAL"],
            high_findings=severity_counts["HIGH"],
            medium_findings=severity_counts["MEDIUM"],
            low_findings=severity_counts["LOW"],
            mastg_compliance=mastg_compliance
        )

# Authentication patterns configuration
AUTHENTICATION_PATTERNS = {
    AuthenticationPatternCategory.BIOMETRIC_APIS.value: [
        r"BiometricPrompt\.",
        r"FingerprintManager\.",
        r"BiometricManager\.",
        r"androidx\.biometric\.",
        r"android\.hardware\.biometrics\.",
        r"KeyguardManager\.createConfirmDeviceCredentialIntent",
        r"LAContext\.evaluatePolicy",
        r"kSecAccessControlBiometry",
        r"SecAccessControlCreateWithFlags"
    ],
    AuthenticationPatternCategory.WEAK_BIOMETRIC_IMPLEMENTATION.value: [
        r"setAllowedAuthenticators\(BiometricManager\.Authenticators\.DEVICE_CREDENTIAL\)",
        r"setAllowedAuthenticators\(DEVICE_CREDENTIAL\)",
        r"\.setDeviceCredentialAllowed\(true\)",
        r"BiometricPrompt\.AuthenticationCallback\(\)\s*\{\s*\}",
        r"evaluatePolicy.*fallbackTitle:\s*nil",
        r"LAPolicy\.deviceOwnerAuthentication\b"
    ],
    AuthenticationPatternCategory.CREDENTIAL_CONFIRMATION.value: [
        r"KeyguardManager\.createConfirmDeviceCredentialIntent",
        r"DevicePolicyManager\.isActivePasswordSufficient",
        r"KeyguardManager\.isKeyguardSecure",
        r"LAContext\.canEvaluatePolicy",
        r"SecAccessControlCreateWithFlags.*kSecAccessControlUserPresence"
    ],
    AuthenticationPatternCategory.SESSION_MANAGEMENT.value: [
        r"SharedPreferences.*putString.*(?:token|session|auth)",
        r"editor\.putString\([\"'](?:auth_token|session_id|access_token)",
        r"getSharedPreferences.*MODE_PRIVATE.*(?:auth|session)",
        r"getSharedPreferences.*MODE_WORLD_READABLE",
        r"MODE_WORLD_READABLE",
        r"MODE_WORLD_WRITABLE",
        r"NSUserDefaults.*setObject.*(?:token|session|auth)",
        r"Keychain.*kSecAttrAccessible"
    ],
    AuthenticationPatternCategory.AUTHENTICATION_BYPASS.value: [
        r"if\s*\(\s*(?:true|1|\"debug\")\s*\)",
        r"BuildConfig\.DEBUG\s*&&\s*return\s*true",
        r"\/\/\s*TODO:\s*remove.*auth.*debug",
        r"\.setTestMode\(true\)",
        r"BYPASS_AUTH\s*=\s*true"
    ]
}

# Secret detection patterns
SECRET_PATTERNS = {
    "auth_tokens": r'(?i)(?:auth[_-]?token|access[_-]?token|bearer[_-]?token)["\'\s]*[:=]["\'\s]*([a-zA-Z0-9+/=]{20,})',
    "api_keys": r'(?i)(?:api[_-]?key|secret[_-]?key)["\'\s]*[:=]["\'\s]*["\']?([a-zA-Z0-9_\-]{10,})["\']?',
    "passwords": r'(?i)(?:password|passwd|pwd)["\'\s]*[:=]["\'\s]*([^"\'\s]{6,})',
    "jwt_tokens": r'(eyJ[a-zA-Z0-9+/=]+\.eyJ[a-zA-Z0-9+/=]+\.[a-zA-Z0-9+/=]*)',
    "base64_secrets": r'(?i)(?:secret|key|token)["\'\s]*[:=]["\'\s]*([a-zA-Z0-9+/=]{24,})',
    "oauth_secrets": r'(?i)(?:client[_-]?secret|oauth[_-]?secret)["\'\s]*[:=]["\'\s]*([a-zA-Z0-9+/=]{16,})',
    "session_token": r'(?i)putString\s*\(\s*["\'](?:auth_token|session_id|access_token)["\']'
}

# Plugin metadata
PLUGIN_METADATA = {
    "name": "Authentication Security Analysis",
    "category": "Authentication & Authorization",
    "mastg_tests": [
        MASTGTestType.AUTH_CONFIRM_CREDENTIALS.value,
        MASTGTestType.AUTH_BIOMETRIC.value,
        MASTGTestType.AUTH_IOS_BIOMETRIC.value,
        MASTGTestType.AUTH_EVENT_BOUND.value
    ],
    "masvs_controls": [MASVSControl.AUTH.value],
    "version": "2.0.0"
} 