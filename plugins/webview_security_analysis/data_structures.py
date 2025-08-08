"""
WebView Security Analysis Data Structures

This module contains all data structures, dataclasses, and enums used
throughout the WebView security analysis plugin components.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import Enum

class WebViewVulnerabilityType(Enum):
    """Types of WebView security vulnerabilities."""
    JAVASCRIPT_INTERFACE_EXPOSURE = "javascript_interface_exposure"
    XSS_VULNERABILITIES = "webview_xss_vulnerabilities" 
    JAVASCRIPT_ENABLED_GLOBALLY = "javascript_enabled_globally"
    FILE_ACCESS_ENABLED = "file_access_enabled"
    UNIVERSAL_ACCESS_ENABLED = "universal_access_enabled"
    MIXED_CONTENT_ALLOWED = "mixed_content_allowed"
    CONFIGURATION_ISSUES = "webview_configuration_issues"
    DANGEROUS_OPERATIONS_EXPOSED = "dangerous_operations_exposed"
    INPUT_VALIDATION_MISSING = "input_validation_missing"
    BRIDGE_SECURITY_ISSUES = "webview_bridge_security"
    DYNAMIC_XSS_TESTING = "dynamic_xss_testing"

class SeverityLevel(Enum):
    """Severity levels for WebView vulnerabilities."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class XSSPayloadType(Enum):
    """Types of XSS payloads for testing."""
    BASIC_SCRIPT = "basic_script"
    EVENT_HANDLER = "event_handler"
    IFRAME_INJECTION = "iframe_injection"
    DATA_URI = "data_uri"
    JAVASCRIPT_URI = "javascript_uri"
    DOM_MANIPULATION = "dom_manipulation"
    COOKIE_THEFT = "cookie_theft"
    POSTMESSAGE = "postmessage"

class WebViewContextType(Enum):
    """Context types for WebView implementations."""
    PRODUCTION_WEBVIEW = "production_webview"
    DEVELOPMENT_WEBVIEW = "development_webview"
    HYBRID_APP = "hybrid_app"
    NATIVE_APP = "native_app"
    CONFIGURATION_FILE = "configuration_file"
    MANIFEST_FILE = "manifest_file"
    JAVASCRIPT_BRIDGE = "javascript_bridge"
    THIRD_PARTY_WEBVIEW = "third_party_webview"
    CUSTOM_WEBVIEW = "custom_webview"
    UNKNOWN_CONTEXT = "unknown_context"

class WebViewConfigurationRisk(Enum):
    """Risk levels for WebView configurations."""
    SAFE = "safe"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    CRITICAL_RISK = "critical_risk"

@dataclass
class WebViewMethodInfo:
    """Information about a WebView method."""
    method_name: str
    class_name: str
    file_path: str
    line_number: int
    parameters: List[str] = field(default_factory=list)
    return_type: str = ""
    security_issues: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'method_name': self.method_name,
            'class_name': self.class_name,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'parameters': self.parameters,
            'return_type': self.return_type,
            'security_issues': self.security_issues
        }

@dataclass
class JavaScriptInterfaceInfo:
    """Information about JavaScript interface exposure."""
    interface_name: str
    class_name: str
    method_name: str
    exposed_methods: List[str]
    file_path: str
    line_number: int
    security_risk: str = "medium"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'interface_name': self.interface_name,
            'class_name': self.class_name,
            'method_name': self.method_name,
            'exposed_methods': self.exposed_methods,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'security_risk': self.security_risk
        }

@dataclass
class XSSTestResult:
    """Result of XSS vulnerability testing."""
    payload: str
    payload_type: str
    success: bool
    response_code: int
    response_body: str
    execution_time: float
    error_message: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'payload': self.payload,
            'payload_type': self.payload_type,
            'success': self.success,
            'response_code': self.response_code,
            'response_body': self.response_body,
            'execution_time': self.execution_time,
            'error_message': self.error_message
        }

@dataclass
class WebViewConfigurationIssue:
    """WebView configuration security issue."""
    setting_name: str
    current_value: str
    recommended_value: str
    risk_level: str
    description: str
    file_path: str
    line_number: int
    remediation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'setting_name': self.setting_name,
            'current_value': self.current_value,
            'recommended_value': self.recommended_value,
            'risk_level': self.risk_level,
            'description': self.description,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'remediation': self.remediation
        }

@dataclass
class WebViewVulnerability:
    """Comprehensive WebView security vulnerability."""
    vulnerability_id: str
    vulnerability_type: str
    severity: str
    confidence: float
    title: str
    description: str
    file_path: str
    line_number: int
    class_name: str
    method_name: str
    code_example: str = ""
    security_impact: str = ""
    remediation: str = ""
    cwe_id: str = ""
    masvs_refs: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'vulnerability_id': self.vulnerability_id,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'title': self.title,
            'description': self.description,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'class_name': self.class_name,
            'method_name': self.method_name,
            'code_example': self.code_example,
            'security_impact': self.security_impact,
            'remediation': self.remediation,
            'cwe_id': self.cwe_id,
            'masvs_refs': self.masvs_refs,
            'references': self.references,
            'evidence': self.evidence
        }

@dataclass
class WebViewSecurityAnalysis:
    """Complete WebView security analysis results."""
    total_webviews: int
    vulnerable_webviews: int
    javascript_interfaces: List[JavaScriptInterfaceInfo]
    xss_test_results: List[XSSTestResult]
    configuration_issues: List[WebViewConfigurationIssue]
    vulnerabilities: List[WebViewVulnerability]
    risk_score: int
    security_recommendations: List[str]
    masvs_compliance: Dict[str, str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'total_webviews': self.total_webviews,
            'vulnerable_webviews': self.vulnerable_webviews,
            'javascript_interfaces': [ji.to_dict() for ji in self.javascript_interfaces],
            'xss_test_results': [xtr.to_dict() for xtr in self.xss_test_results],
            'configuration_issues': [ci.to_dict() for ci in self.configuration_issues],
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'risk_score': self.risk_score,
            'security_recommendations': self.security_recommendations,
            'masvs_compliance': self.masvs_compliance
        }

@dataclass
class WebViewAnalysisContext:
    """Context information for WebView analysis."""
    apk_path: str
    package_name: str
    target_sdk: int = 0
    min_sdk: int = 0
    has_network_permission: bool = False
    has_internet_permission: bool = False
    deep_analysis_mode: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'apk_path': self.apk_path,
            'package_name': self.package_name,
            'target_sdk': self.target_sdk,
            'min_sdk': self.min_sdk,
            'has_network_permission': self.has_network_permission,
            'has_internet_permission': self.has_internet_permission,
            'deep_analysis_mode': self.deep_analysis_mode
        }

class WebViewSecurityPatterns:
    """WebView security pattern types for configuration."""
    JAVASCRIPT_INTERFACE_EXPOSURE = "javascript_interface_exposure"
    XSS_VULNERABILITIES = "webview_xss_vulnerabilities"
    JAVASCRIPT_ENABLED_GLOBALLY = "javascript_enabled_globally"
    FILE_ACCESS_ENABLED = "file_access_enabled"
    UNIVERSAL_ACCESS_ENABLED = "universal_access_enabled"
    MIXED_CONTENT_ALLOWED = "mixed_content_allowed"
    CONFIGURATION_ISSUES = "webview_configuration_issues"
    DANGEROUS_OPERATIONS_EXPOSED = "dangerous_operations_exposed"
    INPUT_VALIDATION_MISSING = "input_validation_missing"
    BRIDGE_SECURITY_ISSUES = "webview_bridge_security"

class MAVSControls:
    """MASVS control mappings for WebView security."""
    PLATFORM_3 = "MASVS-PLATFORM-3"  # WebView security configuration
    CODE_1 = "MASVS-CODE-1"          # Code injection vulnerabilities
    CODE_2 = "MASVS-CODE-2"          # Cross-site scripting (XSS)
    NETWORK_1 = "MASVS-NETWORK-1"    # Secure network communication
    PLATFORM_1 = "MASVS-PLATFORM-1"  # Platform interaction security

class CWECategories:
    """Common Weakness Enumeration categories for WebView vulnerabilities."""
    XSS = "CWE-79"                    # Cross-site Scripting
    CODE_INJECTION = "CWE-94"        # Code Injection
    IMPROPER_INPUT_VALIDATION = "CWE-20"  # Improper Input Validation
    INSECURE_STORAGE = "CWE-922"     # Insecure Storage of Sensitive Information
    IMPROPER_ACCESS_CONTROL = "CWE-284"  # Improper Access Control 