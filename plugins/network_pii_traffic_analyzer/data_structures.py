"""
Data structures for network PII traffic analysis.

This module defines the core data structures used throughout the network PII
traffic analyzer for detecting personally identifiable information in network
communications and configurations.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set
from datetime import datetime

class PIIType(Enum):
    """Types of personally identifiable information."""
    DEVICE_IDENTIFIER = "device_identifier"
    LOCATION_DATA = "location_data"
    NETWORK_IDENTIFIER = "network_identifier"
    SYSTEM_IDENTIFIER = "system_identifier"
    PERSONAL_IDENTIFIER = "personal_identifier"
    AUTHENTICATION_DATA = "authentication_data"
    BIOMETRIC_DATA = "biometric_data"
    BEHAVIORAL_DATA = "behavioral_data"
    UNKNOWN = "unknown"

class TransmissionMethod(Enum):
    """Network transmission methods for PII."""
    HTTP = "http"
    HTTPS = "https"
    WEBSOCKET = "websocket"
    FTP = "ftp"
    TCP = "tcp"
    UDP = "udp"
    DNS = "dns"
    EMAIL = "email"
    SMS = "sms"
    BLUETOOTH = "bluetooth"
    NFC = "nfc"
    UNKNOWN = "unknown"

class SeverityLevel(Enum):
    """Severity levels for PII findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FileType(Enum):
    """Types of files being analyzed."""
    SOURCE_CODE = "source_code"
    RESOURCE_FILE = "resource_file"
    MANIFEST = "manifest"
    CONFIG_FILE = "config_file"
    NETWORK_CONFIG = "network_config"
    ASSET = "asset"
    LIBRARY = "library"
    OTHER = "other"

class AnalysisCategory(Enum):
    """Categories of PII analysis."""
    NETWORK_TRANSMISSION = "network_transmission"
    URL_PARAMETER = "url_parameter"
    HARDCODED_ENDPOINT = "hardcoded_endpoint"
    CONFIGURATION = "configuration"
    WEBVIEW_INJECTION = "webview_injection"
    API_COMMUNICATION = "api_communication"
    DATABASE_COMMUNICATION = "database_communication"

@dataclass
class PIIConfiguration:
    """Configuration for the modular PII analyzer."""
    # Analysis behavior
    deep_scan: bool = True
    max_file_size: int = 10 * 1024 * 1024  # 10MB default
    scan_timeout: int = 300  # 5 minutes default
    confidence_threshold: float = 0.1
    
    # File type analysis settings
    analyze_source_files: bool = True
    analyze_resource_files: bool = True
    analyze_manifest: bool = True
    analyze_config_files: bool = True
    
    # Pattern matching settings
    case_sensitive_matching: bool = False
    enable_fuzzy_matching: bool = True
    
    # PII type filters
    detect_device_identifiers: bool = True
    detect_location_data: bool = True
    detect_network_identifiers: bool = True
    detect_personal_identifiers: bool = True
    detect_authentication_data: bool = True
    
    # Transmission method filters
    analyze_http_transmission: bool = True
    analyze_https_transmission: bool = True
    analyze_websocket_transmission: bool = True
    
    # Advanced settings
    extract_network_endpoints: bool = True
    perform_privacy_impact_assessment: bool = True
    generate_compliance_report: bool = True

@dataclass
class PIIContext:
    """Context information for PII analysis."""
    package_name: Optional[str] = None
    apk_path: str = ""
    analysis_mode: str = "basic"  # "basic" or "deep"
    config: Optional[PIIConfiguration] = None
    
    # File analysis context
    file_path: str = ""
    file_type: FileType = FileType.OTHER
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    surrounding_code: str = ""
    method_name: Optional[str] = None
    class_name: Optional[str] = None
    confidence_factors: Dict[str, float] = field(default_factory=dict)

@dataclass
class PIIPattern:
    """Represents a PII detection pattern."""
    name: str
    pattern: str
    description: str
    pii_type: PIIType
    severity: SeverityLevel
    examples: List[str] = field(default_factory=list)
    
    # Pattern metadata
    pattern_id: str = ""
    category: AnalysisCategory = AnalysisCategory.NETWORK_TRANSMISSION
    is_regex: bool = True
    case_sensitive: bool = False
    
    # Validation settings
    min_length: int = 0
    max_length: int = 1000
    validation_rules: List[str] = field(default_factory=list)
    
    # MASVS/OWASP mappings
    masvs_controls: List[str] = field(default_factory=list)
    owasp_categories: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Post-initialization processing."""
        if not self.pattern_id:
            self.pattern_id = f"pii_{self.pii_type.value}_{hash(self.name) % 10000:04d}"

@dataclass
class NetworkEndpoint:
    """Represents a network endpoint that may transmit PII."""
    url: str
    method: str = "GET"
    protocol: str = "HTTPS"
    parameters: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    
    # Security analysis
    uses_tls: bool = True
    certificate_pinning: bool = False
    data_encryption: bool = False
    
    # PII risk assessment
    pii_parameters: Set[str] = field(default_factory=set)
    risk_level: str = "MEDIUM"

@dataclass
class PIINetworkFinding:
    """Represents a PII network transmission finding."""
    finding_id: str
    pii_type: PIIType
    transmission_method: TransmissionMethod
    severity: SeverityLevel
    confidence: float = 0.0
    description: str = ""
    location: str = ""
    evidence: str = ""
    
    # Detection details
    pattern_matched: str = ""
    matched_value: str = ""
    context: Optional[PIIContext] = None
    endpoint: Optional[NetworkEndpoint] = None
    
    # Security analysis
    attack_vectors: List[str] = field(default_factory=list)
    privacy_impact: str = ""
    data_sensitivity: str = "MEDIUM"
    
    # Compliance and remediation
    remediation: str = ""
    masvs_control: str = ""
    mstg_reference: str = ""
    compliance_violations: List[str] = field(default_factory=list)
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_risk_score(self) -> float:
        """Calculate risk score based on severity and confidence."""
        severity_weights = {
            SeverityLevel.CRITICAL: 1.0,
            SeverityLevel.HIGH: 0.8,
            SeverityLevel.MEDIUM: 0.6,
            SeverityLevel.LOW: 0.4,
            SeverityLevel.INFO: 0.2
        }
        
        base_score = severity_weights.get(self.severity, 0.5)
        return base_score * self.confidence

@dataclass
class FileAnalysisResult:
    """Results from analyzing a specific file for PII."""
    file_path: str
    file_type: FileType
    analysis_successful: bool = True
    error_message: Optional[str] = None
    
    # Analysis results
    pii_findings: List[PIINetworkFinding] = field(default_factory=list)
    network_endpoints: List[NetworkEndpoint] = field(default_factory=list)
    
    # Analysis metadata
    analysis_duration: float = 0.0
    patterns_checked: int = 0
    content_size: int = 0
    lines_analyzed: int = 0
    
    def get_findings_by_severity(self) -> Dict[str, int]:
        """Get findings count by severity level."""
        severity_counts = {severity.value: 0 for severity in SeverityLevel}
        
        for finding in self.pii_findings:
            severity_counts[finding.severity.value] += 1
        
        return severity_counts
    
    def get_findings_by_pii_type(self) -> Dict[str, int]:
        """Get findings count by PII type."""
        type_counts = {pii_type.value: 0 for pii_type in PIIType}
        
        for finding in self.pii_findings:
            type_counts[finding.pii_type.value] += 1
        
        return type_counts

@dataclass
class TransmissionRisk:
    """Assessment of transmission risk for specific PII types."""
    pii_type: PIIType
    transmission_method: TransmissionMethod
    risk_level: str
    risk_factors: List[str] = field(default_factory=list)
    mitigation_strategies: List[str] = field(default_factory=list)
    
    # Quantitative risk assessment
    exposure_likelihood: float = 0.5  # 0.0-1.0
    impact_severity: float = 0.5      # 0.0-1.0
    detection_difficulty: float = 0.5 # 0.0-1.0
    
    @property
    def overall_risk_score(self) -> float:
        """Calculate overall risk score."""
        return (self.exposure_likelihood + self.impact_severity + self.detection_difficulty) / 3.0

@dataclass
class PrivacyImpactAssessment:
    """Privacy impact assessment for detected PII."""
    affected_users: str = "ALL_USERS"
    data_collection_purpose: str = "UNKNOWN"
    data_retention_period: str = "UNKNOWN"
    data_sharing: str = "UNKNOWN"
    user_consent: str = "NOT_OBTAINED"
    
    # Regulatory compliance
    gdpr_compliance: str = "NON_COMPLIANT"
    ccpa_compliance: str = "NON_COMPLIANT"
    coppa_compliance: str = "NON_COMPLIANT"
    
    # Risk assessment
    privacy_risks: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)

@dataclass
class ComprehensivePIIAnalysisResult:
    """Complete result of network PII traffic analysis."""
    # Analysis metadata
    package_name: str = ""
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    analysis_duration: float = 0.0
    files_analyzed: int = 0
    
    # File analysis results
    file_results: List[FileAnalysisResult] = field(default_factory=list)
    
    # Consolidated findings
    all_pii_findings: List[PIINetworkFinding] = field(default_factory=list)
    network_endpoints: List[NetworkEndpoint] = field(default_factory=list)
    
    # Risk and privacy assessment
    transmission_risks: List[TransmissionRisk] = field(default_factory=list)
    privacy_impact: Optional[PrivacyImpactAssessment] = None
    
    # Summary statistics
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    
    # Risk metrics
    overall_risk_level: str = "MEDIUM"
    risk_score: float = 0.0
    privacy_risk_percentage: float = 0.0
    
    # Compliance and recommendations
    masvs_controls: List[str] = field(default_factory=list)
    compliance_violations: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def consolidate_findings(self):
        """Consolidate findings from all file results."""
        self.all_pii_findings.clear()
        self.network_endpoints.clear()
        
        for file_result in self.file_results:
            self.all_pii_findings.extend(file_result.pii_findings)
            self.network_endpoints.extend(file_result.network_endpoints)
        
        # Update summary statistics
        self.total_findings = len(self.all_pii_findings)
        
        # Count by severity
        for finding in self.all_pii_findings:
            if finding.severity == SeverityLevel.CRITICAL:
                self.critical_findings += 1
            elif finding.severity == SeverityLevel.HIGH:
                self.high_findings += 1
            elif finding.severity == SeverityLevel.MEDIUM:
                self.medium_findings += 1
            elif finding.severity == SeverityLevel.LOW:
                self.low_findings += 1
        
        # Calculate risk score
        self.risk_score = self._calculate_overall_risk_score()
        
        # Determine risk level
        if self.critical_findings > 0 or self.risk_score > 0.8:
            self.overall_risk_level = "CRITICAL"
        elif self.high_findings > 0 or self.risk_score > 0.6:
            self.overall_risk_level = "HIGH"
        elif self.medium_findings > 0 or self.risk_score > 0.4:
            self.overall_risk_level = "MEDIUM"
        else:
            self.overall_risk_level = "LOW"
    
    def _calculate_overall_risk_score(self) -> float:
        """Calculate overall risk score based on findings."""
        if not self.all_pii_findings:
            return 0.0
        
        total_risk = sum(finding.get_risk_score() for finding in self.all_pii_findings)
        return min(1.0, total_risk / len(self.all_pii_findings))
    
    def get_findings_by_pii_type(self) -> Dict[str, int]:
        """Get findings count by PII type."""
        type_counts = {pii_type.value: 0 for pii_type in PIIType}
        
        for finding in self.all_pii_findings:
            type_counts[finding.pii_type.value] += 1
        
        return type_counts
    
    def get_findings_by_transmission_method(self) -> Dict[str, int]:
        """Get findings count by transmission method."""
        method_counts = {method.value: 0 for method in TransmissionMethod}
        
        for finding in self.all_pii_findings:
            method_counts[finding.transmission_method.value] += 1
        
        return method_counts
    
    def get_high_risk_findings(self) -> List[PIINetworkFinding]:
        """Get findings with high risk scores."""
        return [
            finding for finding in self.all_pii_findings
            if finding.get_risk_score() > 0.7
        ]
    
    def get_privacy_concerns(self) -> List[str]:
        """Get top privacy concerns based on findings."""
        concerns = []
        
        if self.critical_findings > 0:
            concerns.append(f"{self.critical_findings} critical PII transmission issues")
        
        pii_types = self.get_findings_by_pii_type()
        for pii_type, count in pii_types.items():
            if count > 0 and pii_type in ['device_identifier', 'location_data', 'personal_identifier']:
                concerns.append(f"{count} {pii_type.replace('_', ' ')} transmission instances")
        
        transmission_methods = self.get_findings_by_transmission_method()
        if transmission_methods.get('http', 0) > 0:
            concerns.append(f"{transmission_methods['http']} unencrypted HTTP transmissions")
        
        return concerns

@dataclass
class PIIAnalysisConfiguration:
    """Configuration for PII analysis."""
    enable_deep_analysis: bool = True
    analyze_source_files: bool = True
    analyze_resource_files: bool = True
    analyze_manifest: bool = True
    analyze_config_files: bool = True
    
    # Pattern matching settings
    case_sensitive_matching: bool = False
    enable_fuzzy_matching: bool = True
    max_file_size_mb: int = 50
    confidence_threshold: float = 0.7
    
    # PII type filters
    detect_device_identifiers: bool = True
    detect_location_data: bool = True
    detect_network_identifiers: bool = True
    detect_personal_identifiers: bool = True
    detect_authentication_data: bool = True
    
    # Transmission method filters
    analyze_http_transmission: bool = True
    analyze_https_transmission: bool = True
    analyze_websocket_transmission: bool = True
    analyze_database_transmission: bool = True
    
    # Advanced settings
    extract_network_endpoints: bool = True
    perform_privacy_impact_assessment: bool = True
    generate_compliance_report: bool = True

class AnalysisError(Exception):
    """Custom exception for PII analysis errors."""
    
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.context = context or {}

def validate_pii_pattern(pattern: PIIPattern) -> List[str]:
    """Validate a PII pattern for correctness."""
    errors = []
    
    if not pattern.name:
        errors.append("Pattern name is required")
    
    if not pattern.pattern:
        errors.append("Pattern regex is required")
    
    if pattern.is_regex:
        try:
            import re
            re.compile(pattern.pattern)
        except re.error as e:
            errors.append(f"Invalid regex pattern: {e}")
    
    if pattern.min_length < 0:
        errors.append("Minimum length cannot be negative")
    
    if pattern.max_length < pattern.min_length:
        errors.append("Maximum length cannot be less than minimum length")
    
    return errors

def calculate_transmission_risk(pii_type: PIIType, transmission_method: TransmissionMethod) -> float:
    """Calculate transmission risk for PII type and method combination."""
    # Base risk scores for PII types
    pii_risk = {
        PIIType.AUTHENTICATION_DATA: 0.9,
        PIIType.BIOMETRIC_DATA: 0.85,
        PIIType.PERSONAL_IDENTIFIER: 0.8,
        PIIType.DEVICE_IDENTIFIER: 0.6,
        PIIType.LOCATION_DATA: 0.7,
        PIIType.BEHAVIORAL_DATA: 0.5,
        PIIType.NETWORK_IDENTIFIER: 0.4,
        PIIType.SYSTEM_IDENTIFIER: 0.3,
        PIIType.UNKNOWN: 0.5
    }
    
    # Risk modifiers for transmission methods
    transmission_risk = {
        TransmissionMethod.HTTP: 1.0,     # Unencrypted
        TransmissionMethod.SMS: 0.9,      # Often unencrypted
        TransmissionMethod.EMAIL: 0.8,    # May be unencrypted
        TransmissionMethod.FTP: 0.8,      # Often unencrypted
        TransmissionMethod.WEBSOCKET: 0.6, # Depends on implementation
        TransmissionMethod.HTTPS: 0.3,    # Encrypted
        TransmissionMethod.TCP: 0.7,      # Depends on implementation
        TransmissionMethod.UDP: 0.7,      # Depends on implementation
        TransmissionMethod.DNS: 0.5,      # Often cleartext
        TransmissionMethod.BLUETOOTH: 0.6, # Depends on pairing
        TransmissionMethod.NFC: 0.4,      # Short range
        TransmissionMethod.UNKNOWN: 0.6
    }
    
    base_risk = pii_risk.get(pii_type, 0.5)
    transmission_modifier = transmission_risk.get(transmission_method, 0.5)
    
    return min(1.0, base_risk * transmission_modifier) 