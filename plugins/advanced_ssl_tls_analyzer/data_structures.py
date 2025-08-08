#!/usr/bin/env python3
"""
Data Structures for Advanced SSL/TLS Security Analysis

This module defines comprehensive data structures for SSL/TLS security analysis
including vulnerabilities, configurations, and analysis results.

"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Union
import datetime
from pathlib import Path

class DynamicTestType(Enum):
    """Types of dynamic SSL/TLS testing."""
    CERTIFICATE_PINNING = "certificate_pinning"
    SSL_HANDSHAKE = "ssl_handshake"
    CIPHER_SUITE_TESTING = "cipher_suite_testing"
    PROTOCOL_TESTING = "protocol_testing"
    VULNERABILITY_TESTING = "vulnerability_testing"

class SSLTLSSeverity(Enum):
    """SSL/TLS vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class PinningStrength(Enum):
    """Certificate pinning implementation strength levels."""
    NONE = "NONE"
    WEAK = "WEAK"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"

class TLSProtocol(Enum):
    """TLS/SSL protocol versions."""
    TLS_1_3 = "TLSv1.3"
    TLS_1_2 = "TLSv1.2"
    TLS_1_1 = "TLSv1.1"
    TLS_1_0 = "TLSv1.0"
    SSL_3_0 = "SSLv3"
    SSL_2_0 = "SSLv2"

class ValidationStatus(Enum):
    """Certificate validation status."""
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    BYPASSED = "BYPASSED"
    UNKNOWN = "UNKNOWN"

class NetworkSecurityConfigCompliance(Enum):
    """Network Security Configuration compliance levels."""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NOT_CONFIGURED = "NOT_CONFIGURED"

@dataclass
class SSLTLSVulnerability:
    """Represents an SSL/TLS security vulnerability."""
    vulnerability_id: str
    title: str
    severity: SSLTLSSeverity
    confidence: float
    description: str
    location: str
    evidence: str
    attack_vectors: List[str] = field(default_factory=list)
    remediation: str = ""
    cwe_id: str = ""
    references: List[str] = field(default_factory=list)
    impact: str = ""
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    method_name: Optional[str] = None
    class_name: Optional[str] = None
    evidence_data: Dict[str, Any] = field(default_factory=dict)
    masvs_control: Optional[str] = None
    owasp_category: Optional[str] = None
    risk_score: float = 0.0
    detection_method: str = ""
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)

@dataclass
class CertificatePinningImplementation:
    """Represents a certificate pinning implementation."""
    implementation_type: str
    location: str
    strength: PinningStrength
    details: Dict[str, Any] = field(default_factory=dict)
    detection_method: str = ""
    confidence: float = 0.0
    vulnerabilities: List[str] = field(default_factory=list)
    evidence: str = ""
    bypass_detected: bool = False

@dataclass
class CertificateAnalysis:
    """Represents comprehensive certificate analysis results."""
    pinning_detected: bool = False
    pinning_implementations: List[CertificatePinningImplementation] = field(default_factory=list)
    pinning_strength: PinningStrength = PinningStrength.NONE
    custom_trust_managers: List[str] = field(default_factory=list)
    certificate_validation: ValidationStatus = ValidationStatus.UNKNOWN
    hostname_verification: ValidationStatus = ValidationStatus.UNKNOWN
    trust_all_certificates: bool = False
    insecure_trust_managers: List[str] = field(default_factory=list)
    certificate_bypass_methods: List[str] = field(default_factory=list)
    vulnerabilities: List[SSLTLSVulnerability] = field(default_factory=list)
    apk_certificates: Dict[str, Any] = field(default_factory=dict)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TLSConfiguration:
    """Represents TLS configuration details."""
    supported_protocols: List[TLSProtocol] = field(default_factory=list)
    enabled_protocols: List[str] = field(default_factory=list)
    cipher_suites: List[str] = field(default_factory=list)
    weak_protocols: List[str] = field(default_factory=list)
    weak_ciphers: List[str] = field(default_factory=list)
    strong_ciphers: List[str] = field(default_factory=list)
    perfect_forward_secrecy: bool = False
    certificate_transparency: bool = False
    hsts_enabled: bool = False
    configuration_issues: List[str] = field(default_factory=list)

@dataclass
class TLSConfigurationAnalysis:
    """Represents comprehensive TLS configuration analysis results."""
    ssl_contexts: List[Dict[str, Any]] = field(default_factory=list)
    protocol_configurations: List[TLSConfiguration] = field(default_factory=list)
    cipher_configurations: List[str] = field(default_factory=list)
    weak_configurations: List[Dict[str, Any]] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)
    network_security_config: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[SSLTLSVulnerability] = field(default_factory=list)
    protocol_security_score: int = 0
    cipher_security_score: int = 0
    overall_tls_score: int = 0

@dataclass
class NetworkSecurityConfigAnalysis:
    """Represents Network Security Configuration analysis."""
    nsc_file_found: bool = False
    file_path: Optional[str] = None
    base_config: Dict[str, Any] = field(default_factory=dict)
    domain_configs: List[Dict[str, Any]] = field(default_factory=list)
    trust_anchors: List[Dict[str, Any]] = field(default_factory=list)
    certificate_transparency: Dict[str, Any] = field(default_factory=dict)
    cleartext_traffic: Dict[str, Any] = field(default_factory=dict)
    debug_overrides: Dict[str, Any] = field(default_factory=dict)
    pinning_configurations: List[Dict[str, Any]] = field(default_factory=list)
    compliance_issues: List[Dict[str, Any]] = field(default_factory=list)
    security_score: int = 0
    compliance_status: NetworkSecurityConfigCompliance = NetworkSecurityConfigCompliance.NOT_CONFIGURED
    recommendations: List[str] = field(default_factory=list)

@dataclass
class DynamicSSLTestResult:
    """Represents dynamic SSL/TLS testing results."""
    test_name: str
    test_type: str
    success: bool
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: str = ""
    bypass_detected: bool = False
    vulnerabilities_found: List[str] = field(default_factory=list)
    frida_available: bool = False
    test_duration: float = 0.0
    error_message: Optional[str] = None

@dataclass
class DynamicSSLTestingAnalysis:
    """Represents comprehensive dynamic SSL/TLS testing analysis."""
    frida_available: bool = False
    ssl_bypass_tests: List[DynamicSSLTestResult] = field(default_factory=list)
    runtime_analysis_tests: List[DynamicSSLTestResult] = field(default_factory=list)
    pinning_bypass_tests: List[DynamicSSLTestResult] = field(default_factory=list)
    kill_switch_tests: List[DynamicSSLTestResult] = field(default_factory=list)
    testing_capabilities: Dict[str, Any] = field(default_factory=dict)
    overall_bypass_detected: bool = False
    dynamic_vulnerabilities: List[SSLTLSVulnerability] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

@dataclass
class SSLTLSAnalysisResult:
    """Comprehensive SSL/TLS security analysis results."""
    certificate_analysis: CertificateAnalysis = field(default_factory=CertificateAnalysis)
    tls_configuration_analysis: TLSConfigurationAnalysis = field(default_factory=TLSConfigurationAnalysis)
    network_security_config_analysis: NetworkSecurityConfigAnalysis = field(default_factory=NetworkSecurityConfigAnalysis)
    dynamic_ssl_testing_analysis: DynamicSSLTestingAnalysis = field(default_factory=DynamicSSLTestingAnalysis)
    trust_manager_analysis: Dict[str, Any] = field(default_factory=dict)
    ssl_vulnerabilities: List[SSLTLSVulnerability] = field(default_factory=list)
    advanced_protocol_analysis: Dict[str, Any] = field(default_factory=dict)
    gap_resolution_results: Dict[str, Any] = field(default_factory=dict)
    
    # Overall analysis metrics
    overall_risk_score: int = 0
    security_score: int = 0
    vulnerability_count: int = 0
    critical_issues_count: int = 0
    high_issues_count: int = 0
    medium_issues_count: int = 0
    low_issues_count: int = 0
    
    # Analysis metadata
    analysis_stats: Dict[str, Any] = field(default_factory=dict)
    analysis_duration: float = 0.0
    analyzed_files_count: int = 0
    classes_analyzed: int = 0
    methods_analyzed: int = 0
    patterns_matched: int = 0
    detection_gaps: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    
    # Recommendations and reporting
    recommendations: List[str] = field(default_factory=list)
    executive_summary: str = ""
    compliance_status: str = "UNKNOWN"
    next_steps: List[str] = field(default_factory=list)
    
    # Timestamps
    analysis_timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)
    report_generation_timestamp: Optional[datetime.datetime] = None

@dataclass
class SSLTLSAnalysisConfig:
    """Configuration for SSL/TLS security analysis."""
    enable_certificate_analysis: bool = True
    enable_tls_configuration_analysis: bool = True
    enable_network_security_config_analysis: bool = True
    enable_dynamic_testing: bool = True
    enable_trust_manager_analysis: bool = True
    enable_advanced_protocol_analysis: bool = True
    enable_gap_resolution: bool = True
    
    # Analysis depth settings
    deep_certificate_analysis: bool = True
    comprehensive_pinning_detection: bool = True
    advanced_vulnerability_detection: bool = True
    
    # Performance settings
    max_analysis_time: int = 300  # 5 minutes
    max_files_to_analyze: int = 1000
    max_classes_per_file: int = 100
    parallel_analysis: bool = True
    max_workers: int = 4
    
    # Output settings
    include_evidence: bool = True
    include_remediation: bool = True
    include_references: bool = True
    detailed_reporting: bool = True
    
    # Pattern matching settings
    case_sensitive_patterns: bool = False
    regex_timeout: float = 5.0
    pattern_confidence_threshold: float = 0.1
    
    # Dynamic testing settings
    frida_timeout: int = 30
    enable_frida_analysis: bool = True
    dynamic_test_timeout: int = 60
    
    # Confidence calculation settings
    enable_confidence_learning: bool = True
    confidence_threshold: float = 0.5
    evidence_weight_factor: float = 1.0

# Type aliases for better code readability
SSLTLSVulnerabilityList = List[SSLTLSVulnerability]
CertificatePinningList = List[CertificatePinningImplementation]
TLSConfigurationList = List[TLSConfiguration]
DynamicTestResultList = List[DynamicSSLTestResult]
AnalysisMetadata = Dict[str, Any]
SecurityRecommendations = List[str] 