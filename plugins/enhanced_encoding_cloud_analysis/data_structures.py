"""
Data structures for enhanced encoding and cloud analysis.

This module defines the core data structures used throughout the enhanced encoding
and cloud analysis plugin for encoding detection, cloud service validation, and 
comprehensive security analysis.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from datetime import datetime

class EncodingType(Enum):
    """Types of encoding that can be detected."""
    BASE64 = "base64"
    ROT47 = "rot47"
    ROT13 = "rot13"
    HEX = "hex"
    URL_ENCODING = "url_encoding"
    UNICODE_ESCAPE = "unicode_escape"
    HTML_ENTITY = "html_entity"
    MULTI_LAYER = "multi_layer"
    CUSTOM = "custom"
    UNKNOWN = "unknown"

class CloudServiceType(Enum):
    """Types of cloud services that can be detected."""
    FIREBASE = "firebase"
    AWS_S3 = "aws_s3"
    GOOGLE_CLOUD = "google_cloud"
    AZURE = "azure"
    SQLITE_CLOUD = "sqlite_cloud"
    DROPBOX = "dropbox"
    BOX = "box"
    ONEDRIVE = "onedrive"
    GENERIC_API = "generic_api"
    UNKNOWN = "unknown"

class CipherType(Enum):
    """Types of ciphers that can be detected."""
    AES = "aes"
    DES = "des"
    RSA = "rsa"
    BLOWFISH = "blowfish"
    TWOFISH = "twofish"
    RC4 = "rc4"
    CHACHA20 = "chacha20"
    SALSA20 = "salsa20"
    CUSTOM = "custom"
    UNKNOWN = "unknown"

class SeverityLevel(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FileType(Enum):
    """Types of files being analyzed."""
    SOURCE_CODE = "source_code"
    RESOURCE_FILE = "resource_file"
    CONFIG_FILE = "config_file"
    NATIVE_FILE = "native_file"
    STRINGS_XML = "strings_xml"
    MANIFEST = "manifest"
    BINARY = "binary"
    OTHER = "other"

class AnalysisPattern(Enum):
    """Types of analysis patterns for targeting specific vulnerabilities."""
    ANDROID_SECURITY = "android_security"
    FIREBASE_INTEGRATION = "firebase_integration"
    AWS_CREDENTIALS = "aws_credentials"
    ENCODING_CHAINS = "encoding_chains"
    CLOUD_ENDPOINTS = "cloud_endpoints"
    CIPHER_IMPLEMENTATION = "cipher_implementation"
    GENERIC_VULNERABILITY = "generic_vulnerability"

@dataclass
class EncodingContext:
    """Context information for encoding detection."""
    file_path: str
    file_type: FileType
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    surrounding_text: str = ""
    confidence_factors: Dict[str, float] = field(default_factory=dict)

@dataclass
class EncodingFinding:
    """Represents a detected encoding pattern or vulnerability."""
    finding_id: str
    encoding_type: EncodingType
    encoded_content: str
    decoded_content: Optional[str] = None
    location: str = ""
    context: Optional[EncodingContext] = None
    severity: SeverityLevel = SeverityLevel.MEDIUM
    confidence: float = 0.0
    description: str = ""
    
    # Analysis metadata
    pattern_matched: str = ""
    encoding_chain: List[EncodingType] = field(default_factory=list)
    analysis_patterns: List[AnalysisPattern] = field(default_factory=list)
    
    # Security implications
    security_impact: str = ""
    recommendations: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    masvs_control: Optional[str] = None
    
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class CipherFinding:
    """Represents a detected cipher implementation or vulnerability."""
    finding_id: str
    cipher_type: CipherType
    implementation_details: str
    location: str = ""
    context: Optional[EncodingContext] = None
    severity: SeverityLevel = SeverityLevel.HIGH
    confidence: float = 0.0
    description: str = ""
    
    # Cipher-specific details
    key_size: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    iv_usage: Optional[str] = None
    
    # Security analysis
    vulnerabilities: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    compliance_issues: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    masvs_control: Optional[str] = None
    
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class CloudServiceEndpoint:
    """Represents a detected cloud service endpoint."""
    service_type: CloudServiceType
    endpoint_url: str
    service_config: Dict[str, Any] = field(default_factory=dict)
    authentication_method: Optional[str] = None
    encryption_status: Optional[str] = None
    access_permissions: List[str] = field(default_factory=list)

@dataclass
class CloudServiceFinding:
    """Represents a detected cloud service security issue."""
    finding_id: str
    service_type: CloudServiceType
    service_endpoint: Optional[CloudServiceEndpoint] = None
    location: str = ""
    context: Optional[EncodingContext] = None
    severity: SeverityLevel = SeverityLevel.HIGH
    confidence: float = 0.0
    description: str = ""
    
    # Cloud service specific details
    configuration_issues: List[str] = field(default_factory=list)
    credential_exposure: bool = False
    public_access_risk: bool = False
    integration_vulnerabilities: List[str] = field(default_factory=list)
    
    # Security implications
    security_impact: str = ""
    recommendations: List[str] = field(default_factory=list)
    compliance_violations: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    masvs_control: Optional[str] = None
    
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class FileAnalysisResult:
    """Results from analyzing a specific file."""
    file_path: str
    file_type: FileType
    analysis_successful: bool = True
    error_message: Optional[str] = None
    
    # Analysis results
    encoding_findings: List[EncodingFinding] = field(default_factory=list)
    cipher_findings: List[CipherFinding] = field(default_factory=list)
    cloud_findings: List[CloudServiceFinding] = field(default_factory=list)
    
    # Analysis metadata
    analysis_duration: float = 0.0
    patterns_checked: List[AnalysisPattern] = field(default_factory=list)
    content_size: int = 0
    
    def get_total_findings(self) -> int:
        """Get total number of findings in this file."""
        return len(self.encoding_findings) + len(self.cipher_findings) + len(self.cloud_findings)
    
    def get_findings_by_severity(self) -> Dict[str, int]:
        """Get findings count by severity level."""
        severity_counts = {severity.value: 0 for severity in SeverityLevel}
        
        all_findings = self.encoding_findings + self.cipher_findings + self.cloud_findings
        for finding in all_findings:
            severity_counts[finding.severity.value] += 1
        
        return severity_counts

@dataclass
class EncodingChain:
    """Represents a multi-layer encoding chain."""
    chain_id: str
    encoding_layers: List[EncodingType]
    original_content: str
    intermediate_steps: List[str] = field(default_factory=list)
    final_decoded_content: str = ""
    
    # Analysis details
    complexity_score: float = 0.0
    detection_confidence: float = 0.0
    security_implications: List[str] = field(default_factory=list)
    
    # Location information
    locations: List[str] = field(default_factory=list)
    contexts: List[EncodingContext] = field(default_factory=list)

@dataclass
class SecurityPattern:
    """Represents a security pattern detected in analysis."""
    pattern_type: AnalysisPattern
    pattern_name: str
    description: str
    confidence: float = 0.0
    
    # Pattern details
    indicators: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    locations: List[str] = field(default_factory=list)
    
    # Security assessment
    severity: SeverityLevel = SeverityLevel.MEDIUM
    attack_vectors: List[str] = field(default_factory=list)
    impact_assessment: str = ""
    mitigation_strategies: List[str] = field(default_factory=list)

@dataclass
class ComprehensiveAnalysisResult:
    """Complete result of enhanced encoding and cloud analysis."""
    # Analysis metadata
    package_name: str = ""
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    analysis_duration: float = 0.0
    files_analyzed: int = 0
    
    # File analysis results
    file_results: List[FileAnalysisResult] = field(default_factory=list)
    
    # Consolidated findings
    all_encoding_findings: List[EncodingFinding] = field(default_factory=list)
    all_cipher_findings: List[CipherFinding] = field(default_factory=list)
    all_cloud_findings: List[CloudServiceFinding] = field(default_factory=list)
    
    # Advanced analysis results
    encoding_chains: List[EncodingChain] = field(default_factory=list)
    security_patterns: List[SecurityPattern] = field(default_factory=list)
    
    # Risk assessment
    total_findings: int = 0
    risk_score: int = 0
    risk_level: str = "LOW"
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    
    # Compliance and recommendations
    masvs_controls: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    compliance_gaps: List[str] = field(default_factory=list)
    
    def consolidate_findings(self):
        """Consolidate findings from all file results."""
        self.all_encoding_findings.clear()
        self.all_cipher_findings.clear()
        self.all_cloud_findings.clear()
        
        for file_result in self.file_results:
            self.all_encoding_findings.extend(file_result.encoding_findings)
            self.all_cipher_findings.extend(file_result.cipher_findings)
            self.all_cloud_findings.extend(file_result.cloud_findings)
        
        # Update total findings
        self.total_findings = (
            len(self.all_encoding_findings) + 
            len(self.all_cipher_findings) + 
            len(self.all_cloud_findings)
        )
        
        # Update severity counts
        all_findings = self.all_encoding_findings + self.all_cipher_findings + self.all_cloud_findings
        self.critical_issues = sum(1 for f in all_findings if f.severity == SeverityLevel.CRITICAL)
        self.high_issues = sum(1 for f in all_findings if f.severity == SeverityLevel.HIGH)
        self.medium_issues = sum(1 for f in all_findings if f.severity == SeverityLevel.MEDIUM)
        self.low_issues = sum(1 for f in all_findings if f.severity == SeverityLevel.LOW)
        
        # Calculate risk score
        self.risk_score = (
            self.critical_issues * 10 + 
            self.high_issues * 7 + 
            self.medium_issues * 4 + 
            self.low_issues * 1
        )
        
        # Determine risk level
        if self.critical_issues > 0 or self.risk_score > 50:
            self.risk_level = "CRITICAL"
        elif self.high_issues > 0 or self.risk_score > 25:
            self.risk_level = "HIGH"
        elif self.medium_issues > 0 or self.risk_score > 10:
            self.risk_level = "MEDIUM"
        else:
            self.risk_level = "LOW"
    
    def get_findings_by_type(self) -> Dict[str, int]:
        """Get findings count by type."""
        return {
            "encoding_findings": len(self.all_encoding_findings),
            "cipher_findings": len(self.all_cipher_findings),
            "cloud_findings": len(self.all_cloud_findings),
            "encoding_chains": len(self.encoding_chains),
            "security_patterns": len(self.security_patterns)
        }
    
    def get_top_security_concerns(self) -> List[str]:
        """Get top security concerns based on findings."""
        concerns = []
        
        if self.critical_issues > 0:
            concerns.append(f"{self.critical_issues} critical security issues detected")
        
        if len(self.all_cipher_findings) > 0:
            concerns.append("Cipher implementation vulnerabilities found")
        
        if len(self.all_cloud_findings) > 0:
            concerns.append("Cloud service security issues identified")
        
        if len(self.encoding_chains) > 0:
            concerns.append("Multi-layer encoding chains detected")
        
        return concerns

# Analysis context and configuration
@dataclass
class AnalysisConfiguration:
    """Configuration for encoding and cloud analysis."""
    enable_deep_analysis: bool = True
    analyze_binary_files: bool = True
    extract_strings_from_binaries: bool = True
    max_file_size_mb: int = 50
    max_encoding_chain_depth: int = 5
    confidence_threshold: float = 0.7
    
    # File type filters
    analyze_source_files: bool = True
    analyze_resource_files: bool = True
    analyze_config_files: bool = True
    analyze_native_files: bool = True
    
    # Pattern targeting
    target_patterns: List[AnalysisPattern] = field(default_factory=list)
    custom_patterns: Dict[str, str] = field(default_factory=dict)

# Error handling
class EncodingCloudAnalysisError(Exception):
    """Exception raised during encoding and cloud analysis."""
    
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.context = context or {} 