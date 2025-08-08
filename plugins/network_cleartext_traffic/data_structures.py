#!/usr/bin/env python3
"""
Network Cleartext Traffic Analyzer - Data Structures

This module contains all data structures, enums, and type definitions used by the
Network Cleartext Traffic analyzer components.

Classes:
    - NetworkSecurityFinding: Security finding data structure
    - CleartextTrafficAnalysisResult: Analysis result aggregation
    - ManifestAnalysisResult: Manifest analysis specific results
    - NSCAnalysisResult: Network Security Configuration analysis results
    - ResourceAnalysisResult: Resource scanning results
    
Enums:
    - FindingType: Types of network security findings
    - RiskLevel: Security risk severity levels
    - AnalysisStatus: Analysis completion status
    - NSCConfigType: Network Security Configuration types
    - HttpUrlType: HTTP URL classification types
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Set, Any, Union
from xml.etree.ElementTree import Element

class FindingType(Enum):
    """Types of network security findings"""
    CLEARTEXT_ENABLED = "cleartext_enabled"
    CLEARTEXT_DISABLED = "cleartext_disabled"
    TARGET_SDK_INSECURE = "target_sdk_insecure"
    TARGET_SDK_SECURE = "target_sdk_secure"
    NSC_MISCONFIGURED = "nsc_misconfigured"
    NSC_SECURE = "nsc_secure"
    HTTP_URL_FOUND = "http_url_found"
    CERTIFICATE_PINNING = "certificate_pinning"
    TRUST_ANCHOR_ISSUE = "trust_anchor_issue"
    DOMAIN_CONFIG_ISSUE = "domain_config_issue"
    CONFIG_MISSING = "config_missing"
    ANALYSIS_ERROR = "analysis_error"

class RiskLevel(Enum):
    """Security risk severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"

class AnalysisStatus(Enum):
    """Analysis completion status"""
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL = "MANUAL"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"

class NSCConfigType(Enum):
    """Network Security Configuration types"""
    GLOBAL = "global"
    DOMAIN_SPECIFIC = "domain_specific"
    DEBUG_OVERRIDES = "debug_overrides"
    BASE_CONFIG = "base_config"

class HttpUrlType(Enum):
    """HTTP URL classification types"""
    HARDCODED_API = "hardcoded_api"
    CONFIG_URL = "config_url"
    RESOURCE_URL = "resource_url"
    TEST_URL = "test_url"
    EXTERNAL_SERVICE = "external_service"
    ANALYTICS_URL = "analytics_url"
    ADVERTISEMENT_URL = "advertisement_url"
    UNKNOWN = "unknown"

class ManifestAttribute(Enum):
    """Android manifest attribute types"""
    USES_CLEARTEXT_TRAFFIC = "usesCleartextTraffic"
    NETWORK_SECURITY_CONFIG = "networkSecurityConfig"
    TARGET_SDK_VERSION = "targetSdkVersion"
    MIN_SDK_VERSION = "minSdkVersion"
    COMPILE_SDK_VERSION = "compileSdkVersion"

@dataclass
class NetworkSecurityFinding:
    """Network security finding data structure"""
    finding_type: FindingType
    severity: RiskLevel
    title: str
    description: str
    location: str
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    masvs_control: str = ""
    mastg_reference: str = ""
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    detection_method: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary representation"""
        return {
            'finding_type': self.finding_type.value,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'location': self.location,
            'confidence': self.confidence,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'masvs_control': self.masvs_control,
            'mastg_reference': self.mastg_reference,
            'cwe_id': self.cwe_id,
            'cvss_score': self.cvss_score,
            'detection_method': self.detection_method,
            'timestamp': self.timestamp.isoformat()
        }

@dataclass
class HttpUrlDetection:
    """HTTP URL detection details"""
    url: str
    file_path: str
    line_number: Optional[int] = None
    context: str = ""
    url_type: HttpUrlType = HttpUrlType.UNKNOWN
    risk_level: RiskLevel = RiskLevel.MEDIUM
    domain: str = ""
    is_hardcoded: bool = True
    validation_status: str = "not_validated"
    
    def __post_init__(self):
        """Extract domain from URL"""
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(self.url)
            self.domain = parsed.netloc
        except Exception:
            self.domain = ""

@dataclass
class ManifestAnalysisResult:
    """AndroidManifest.xml analysis results"""
    manifest_found: bool = False
    target_sdk: Optional[int] = None
    min_sdk: Optional[int] = None
    uses_cleartext_traffic: Optional[str] = None
    network_security_config: Optional[str] = None
    android_namespace: str = ""
    application_element: Optional[Element] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    
    def get_cleartext_status(self) -> str:
        """Get cleartext traffic status with SDK consideration"""
        if self.uses_cleartext_traffic is not None:
            return self.uses_cleartext_traffic.lower()
        elif self.target_sdk and self.target_sdk >= 28:
            return "false"  # Default for API 28+
        else:
            return "true"   # Default for API < 28

@dataclass
class NSCAnalysisResult:
    """Network Security Configuration analysis results"""
    config_found: bool = False
    config_files: List[str] = field(default_factory=list)
    cleartext_permitted: Optional[bool] = None
    certificate_pinning: bool = False
    trust_anchors_configured: bool = False
    domain_configs: List[Dict[str, Any]] = field(default_factory=list)
    debug_overrides: bool = False
    pin_sets: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    parsed_configs: List[Dict[str, Any]] = field(default_factory=list)
    validation_errors: List[str] = field(default_factory=list)
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    
    def has_secure_configuration(self) -> bool:
        """Check if NSC has secure configuration"""
        return (
            self.config_found and
            self.cleartext_permitted is False and
            self.certificate_pinning
        )

@dataclass
class ResourceAnalysisResult:
    """Resource and code analysis results"""
    directories_scanned: int = 0
    files_scanned: int = 0
    http_urls_found: List[HttpUrlDetection] = field(default_factory=list)
    config_files_analyzed: List[str] = field(default_factory=list)
    suspicious_patterns: List[Dict[str, Any]] = field(default_factory=list)
    encrypted_resources: List[str] = field(default_factory=list)
    analysis_errors: List[str] = field(default_factory=list)
    scan_statistics: Dict[str, int] = field(default_factory=dict)
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    
    def get_unique_domains(self) -> Set[str]:
        """Get unique domains from HTTP URLs"""
        return {detection.domain for detection in self.http_urls_found if detection.domain}
    
    def get_high_risk_urls(self) -> List[HttpUrlDetection]:
        """Get high risk HTTP URLs"""
        return [
            detection for detection in self.http_urls_found
            if detection.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        ]

@dataclass
class SecurityRecommendation:
    """Security recommendation data structure"""
    priority: RiskLevel
    category: str
    title: str
    description: str
    implementation_steps: List[str] = field(default_factory=list)
    code_examples: List[str] = field(default_factory=list)
    verification_steps: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    masvs_control: str = ""
    estimated_effort: str = "MEDIUM"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert recommendation to dictionary"""
        return {
            'priority': self.priority.value,
            'category': self.category,
            'title': self.title,
            'description': self.description,
            'implementation_steps': self.implementation_steps,
            'code_examples': self.code_examples,
            'verification_steps': self.verification_steps,
            'references': self.references,
            'masvs_control': self.masvs_control,
            'estimated_effort': self.estimated_effort
        }

@dataclass
class VerificationCommand:
    """Verification command data structure"""
    category: str
    title: str
    command: str
    description: str
    expected_output: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    requires_device: bool = False
    requires_root: bool = False
    platform_specific: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert command to dictionary"""
        return {
            'category': self.category,
            'title': self.title,
            'command': self.command,
            'description': self.description,
            'expected_output': self.expected_output,
            'risk_level': self.risk_level.value,
            'requires_device': self.requires_device,
            'requires_root': self.requires_root,
            'platform_specific': self.platform_specific
        }

@dataclass
class CleartextTrafficAnalysisResult:
    """Comprehensive cleartext traffic analysis result"""
    overall_status: AnalysisStatus
    risk_level: RiskLevel
    confidence_score: float = 0.0
    findings: List[NetworkSecurityFinding] = field(default_factory=list)
    manifest_analysis: ManifestAnalysisResult = field(default_factory=ManifestAnalysisResult)
    nsc_analysis: NSCAnalysisResult = field(default_factory=NSCAnalysisResult)
    resource_analysis: ResourceAnalysisResult = field(default_factory=ResourceAnalysisResult)
    recommendations: List[SecurityRecommendation] = field(default_factory=list)
    verification_commands: List[VerificationCommand] = field(default_factory=list)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    analysis_duration: float = 0.0
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    
    def get_findings_by_severity(self, severity: RiskLevel) -> List[NetworkSecurityFinding]:
        """Get findings filtered by severity level"""
        return [finding for finding in self.findings if finding.severity == severity]
    
    def get_critical_findings(self) -> List[NetworkSecurityFinding]:
        """Get critical and high severity findings"""
        return [
            finding for finding in self.findings
            if finding.severity in [RiskLevel.CRITICAL, RiskLevel.HIGH]
        ]
    
    def calculate_risk_score(self) -> float:
        """Calculate overall risk score based on findings"""
        if not self.findings:
            return 0.0
        
        severity_weights = {
            RiskLevel.CRITICAL: 10.0,
            RiskLevel.HIGH: 7.5,
            RiskLevel.MEDIUM: 5.0,
            RiskLevel.LOW: 2.5,
            RiskLevel.INFO: 1.0
        }
        
        total_score = sum(
            severity_weights.get(finding.severity, 0.0) * finding.confidence
            for finding in self.findings
        )
        
        return min(total_score / len(self.findings), 10.0)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis result to dictionary"""
        return {
            'overall_status': self.overall_status.value,
            'risk_level': self.risk_level.value,
            'confidence_score': self.confidence_score,
            'findings': [finding.to_dict() for finding in self.findings],
            'recommendations': [rec.to_dict() for rec in self.recommendations],
            'verification_commands': [cmd.to_dict() for cmd in self.verification_commands],
            'analysis_metadata': self.analysis_metadata,
            'analysis_duration': self.analysis_duration,
            'analysis_timestamp': self.analysis_timestamp.isoformat(),
            'risk_score': self.calculate_risk_score(),
            'total_findings': len(self.findings),
            'critical_findings': len(self.get_critical_findings())
        }

# Type aliases for better code readability
PatternDict = Dict[str, Pattern[str]]
ConfigDict = Dict[str, Any]
AnalysisContext = Dict[str, Any]
ManifestElement = Optional[Element]
NSCElement = Optional[Element]

# Constants for analysis thresholds
DEFAULT_CONFIDENCE_THRESHOLD = 0.7
HIGH_CONFIDENCE_THRESHOLD = 0.8
LOW_CONFIDENCE_THRESHOLD = 0.5
MAX_HTTP_URLS_TO_REPORT = 50
MAX_EVIDENCE_ITEMS = 10
DEFAULT_SCAN_TIMEOUT = 300  # 5 minutes

# MASVS control mappings
MASVS_CONTROLS = {
    'network_cleartext': 'MASVS-NETWORK-1',
    'network_config': 'MASVS-NETWORK-2',
    'certificate_pinning': 'MASVS-NETWORK-1',
    'trust_anchors': 'MASVS-NETWORK-2'
}

# MASTG test mappings
MASTG_REFERENCES = {
    'cleartext_traffic': 'MASTG-TEST-0024',
    'network_security_config': 'MASTG-TEST-0025',
    'certificate_validation': 'MASTG-TEST-0023'
} 