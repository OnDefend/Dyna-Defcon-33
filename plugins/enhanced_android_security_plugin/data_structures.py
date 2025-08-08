#!/usr/bin/env python3
"""
Android Security Data Structures

Clean, generic data structures for Android security analysis without
references to specific test frameworks or implementation details.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Set, Optional, Any
from datetime import datetime

class AndroidVulnerabilityType(Enum):
    """Android security vulnerability categories."""
    
    # Storage vulnerabilities
    INSECURE_SHARED_PREFERENCES = "insecure_shared_preferences"
    INSECURE_FILE_STORAGE = "insecure_file_storage"
    WORLD_READABLE_FILES = "world_readable_files"
    EXTERNAL_STORAGE_MISUSE = "external_storage_misuse"
    TEMP_FILE_EXPOSURE = "temp_file_exposure"
    
    # Logging vulnerabilities
    INSECURE_LOGGING = "insecure_logging"
    SENSITIVE_DATA_LOGGING = "sensitive_data_logging"
    DEBUG_LOGGING_ENABLED = "debug_logging_enabled"
    
    # WebView vulnerabilities
    WEBVIEW_VULNERABILITIES = "webview_vulnerabilities"
    WEBVIEW_FILE_ACCESS = "webview_file_access"
    WEBVIEW_JAVASCRIPT_INJECTION = "webview_javascript_injection"
    WEBVIEW_CONTENT_INJECTION = "webview_content_injection"
    
    # Component vulnerabilities
    EXPORTED_COMPONENTS = "exported_components"
    UNPROTECTED_ACTIVITIES = "unprotected_activities"
    UNPROTECTED_SERVICES = "unprotected_services"
    UNPROTECTED_RECEIVERS = "unprotected_receivers"
    UNPROTECTED_PROVIDERS = "unprotected_providers"
    
    # Manifest vulnerabilities
    DEBUG_ENABLED = "debug_enabled"
    BACKUP_ENABLED = "backup_enabled"
    ALLOW_BACKUP_TRUE = "allow_backup_true"
    DEBUGGABLE_TRUE = "debuggable_true"
    
    # Deep link vulnerabilities
    INSECURE_DEEP_LINKS = "insecure_deep_links"
    UNVALIDATED_INTENT_FILTERS = "unvalidated_intent_filters"
    CUSTOM_SCHEME_HIJACKING = "custom_scheme_hijacking"
    
    # Additional Android security issues
    WEAK_PERMISSIONS = "weak_permissions"
    PERMISSION_BYPASSES = "permission_bypasses"
    INTENT_REDIRECTION = "intent_redirection"
    BROADCAST_INJECTION = "broadcast_injection"

class AndroidSeverityLevel(Enum):
    """Severity levels for Android security vulnerabilities."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AndroidMASVSControl(Enum):
    """MASVS controls relevant to Android security."""
    STORAGE_1 = "MASVS-STORAGE-1"
    STORAGE_2 = "MASVS-STORAGE-2"
    PLATFORM_1 = "MASVS-PLATFORM-1"
    PLATFORM_2 = "MASVS-PLATFORM-2"
    PLATFORM_3 = "MASVS-PLATFORM-3"
    NETWORK_1 = "MASVS-NETWORK-1"
    NETWORK_2 = "MASVS-NETWORK-2"
    CODE_2 = "MASVS-CODE-2"
    CODE_3 = "MASVS-CODE-3"

@dataclass
class AndroidVulnerability:
    """Represents an Android security vulnerability."""
    
    # Core identification
    vulnerability_id: str
    vulnerability_type: AndroidVulnerabilityType
    title: str
    description: str
    
    # Severity and confidence
    severity: AndroidSeverityLevel
    confidence: float
    
    # Location information
    location: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    method_name: Optional[str] = None
    class_name: Optional[str] = None
    
    # Evidence and context
    evidence: str = ""
    code_snippet: str = ""
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)
    
    # Android-specific metadata
    component_type: Optional[str] = None
    permission_required: Optional[str] = None
    exported: Optional[bool] = None
    api_level: Optional[int] = None
    
    # Security impact
    attack_vector: str = ""
    impact_description: str = ""
    remediation_guidance: str = ""
    
    # Compliance mapping
    masvs_controls: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    mstg_test: Optional[str] = None
    
    # Analysis metadata
    detection_method: str = ""
    pattern_matched: str = ""
    analysis_timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class AndroidSecurityConfig:
    """Configuration for Android security analysis."""
    
    # Analysis scope
    analyze_manifest: bool = True
    analyze_components: bool = True
    analyze_storage: bool = True
    analyze_webview: bool = True
    analyze_logging: bool = True
    analyze_deep_links: bool = True
    
    # Detection thresholds
    min_confidence_threshold: float = 0.6
    max_findings_per_category: int = 50
    
    # Analysis options
    include_low_severity: bool = True
    include_framework_noise: bool = False
    detailed_code_analysis: bool = True

@dataclass
class AndroidSecurityAnalysisResult:
    """Results of Android security analysis."""
    
    # Vulnerability findings
    vulnerabilities: List[AndroidVulnerability] = field(default_factory=list)
    storage_issues: List[AndroidVulnerability] = field(default_factory=list)
    webview_issues: List[AndroidVulnerability] = field(default_factory=list)
    component_issues: List[AndroidVulnerability] = field(default_factory=list)
    platform_issues: List[AndroidVulnerability] = field(default_factory=list)
    
    # Analysis statistics
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    
    # Coverage metrics
    coverage_achieved: float = 0.0
    masvs_controls_covered: Set[str] = field(default_factory=set)
    cwe_classes_detected: Set[str] = field(default_factory=set)
    
    # Performance metrics
    analysis_duration: float = 0.0
    files_analyzed: int = 0
    patterns_matched: int = 0
    plugins_executed: int = 0
    
    # Quality indicators
    average_confidence: float = 0.0
    high_confidence_findings: int = 0
    false_positive_risk: str = "LOW"

@dataclass 
class AndroidPatternMatch:
    """Represents a pattern match in Android code analysis."""
    
    pattern_name: str
    pattern_regex: str
    matched_text: str
    file_path: str
    line_number: int
    column_start: int = 0
    column_end: int = 0
    
    # Context
    surrounding_code: str = ""
    method_context: str = ""
    class_context: str = ""
    
    # Analysis metadata
    confidence: float = 0.8
    severity: AndroidSeverityLevel = AndroidSeverityLevel.MEDIUM
    vulnerability_type: Optional[AndroidVulnerabilityType] = None
    
    # Android-specific context
    component_context: Optional[str] = None
    permission_context: Optional[str] = None
    api_level_context: Optional[int] = None

# Android-specific constants
ANDROID_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR", 
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE"
}

ANDROID_SIGNATURE_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_INPUT_METHOD",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_PRINT_SERVICE",
    "android.permission.BIND_WALLPAPER",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS"
}

ANDROID_COMPONENT_TYPES = {
    "activity", "service", "receiver", "provider"
}

# MASVS control mappings for Android vulnerabilities
ANDROID_MASVS_MAPPINGS = {
    AndroidVulnerabilityType.INSECURE_SHARED_PREFERENCES: [AndroidMASVSControl.STORAGE_1.value],
    AndroidVulnerabilityType.INSECURE_FILE_STORAGE: [AndroidMASVSControl.STORAGE_1.value],
    AndroidVulnerabilityType.WORLD_READABLE_FILES: [AndroidMASVSControl.STORAGE_1.value],
    AndroidVulnerabilityType.EXTERNAL_STORAGE_MISUSE: [AndroidMASVSControl.STORAGE_2.value],
    AndroidVulnerabilityType.INSECURE_LOGGING: [AndroidMASVSControl.CODE_2.value],
    AndroidVulnerabilityType.SENSITIVE_DATA_LOGGING: [AndroidMASVSControl.CODE_2.value],
    AndroidVulnerabilityType.WEBVIEW_VULNERABILITIES: [AndroidMASVSControl.PLATFORM_2.value],
    AndroidVulnerabilityType.WEBVIEW_JAVASCRIPT_INJECTION: [AndroidMASVSControl.PLATFORM_2.value],
    AndroidVulnerabilityType.EXPORTED_COMPONENTS: [AndroidMASVSControl.PLATFORM_1.value],
    AndroidVulnerabilityType.UNPROTECTED_ACTIVITIES: [AndroidMASVSControl.PLATFORM_1.value],
    AndroidVulnerabilityType.DEBUG_ENABLED: [AndroidMASVSControl.CODE_2.value],
    AndroidVulnerabilityType.BACKUP_ENABLED: [AndroidMASVSControl.STORAGE_2.value],
    AndroidVulnerabilityType.INSECURE_DEEP_LINKS: [AndroidMASVSControl.PLATFORM_3.value]
}

# CWE mappings for Android vulnerabilities
ANDROID_CWE_MAPPINGS = {
    AndroidVulnerabilityType.INSECURE_SHARED_PREFERENCES: "CWE-200",
    AndroidVulnerabilityType.INSECURE_FILE_STORAGE: "CWE-732",
    AndroidVulnerabilityType.WORLD_READABLE_FILES: "CWE-732",
    AndroidVulnerabilityType.EXTERNAL_STORAGE_MISUSE: "CWE-200",
    AndroidVulnerabilityType.INSECURE_LOGGING: "CWE-532",
    AndroidVulnerabilityType.SENSITIVE_DATA_LOGGING: "CWE-532",
    AndroidVulnerabilityType.WEBVIEW_VULNERABILITIES: "CWE-79",
    AndroidVulnerabilityType.WEBVIEW_JAVASCRIPT_INJECTION: "CWE-79",
    AndroidVulnerabilityType.EXPORTED_COMPONENTS: "CWE-284",
    AndroidVulnerabilityType.UNPROTECTED_ACTIVITIES: "CWE-284",
    AndroidVulnerabilityType.DEBUG_ENABLED: "CWE-489",
    AndroidVulnerabilityType.BACKUP_ENABLED: "CWE-200",
    AndroidVulnerabilityType.INSECURE_DEEP_LINKS: "CWE-601"
} 