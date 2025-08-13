"""
Data Structures for Enhanced Data Storage Analyzer

This module contains all data structures, enums, and type definitions
used across the enhanced data storage analysis components.

Features:
- PII-focused vulnerability and finding structures
- File permission and security analysis data types
- Path traversal vulnerability definitions
- Storage security assessment structures
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from enum import Enum
from datetime import datetime

class PIIType(Enum):
    """Types of Personally Identifiable Information (PII)."""
    ANDROID_ID = "android_id"
    IMEI = "imei"
    GPS_COORDINATES = "gps_coordinates"
    MAC_ADDRESS = "mac_address"
    PHONE_NUMBER = "phone_number"
    EMAIL_ADDRESS = "email_address"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    IP_ADDRESS = "ip_address"
    DEVICE_ID = "device_id"
    SIM_SERIAL = "sim_serial"
    ADVERTISING_ID = "advertising_id"
    BLUETOOTH_ADDRESS = "bluetooth_address"

class VulnerabilitySeverity(Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class FilePermissionLevel(Enum):
    """File permission security levels."""
    SECURE = "secure"
    MODERATE = "moderate"
    INSECURE = "insecure"
    CRITICAL = "critical"

class StorageSecurityLevel(Enum):
    """Storage security assessment levels."""
    ENCRYPTED = "encrypted"
    PROTECTED = "protected"
    EXPOSED = "exposed"
    VULNERABLE = "vulnerable"

class PathTraversalRisk(Enum):
    """Path traversal vulnerability risk levels."""
    NO_RISK = "no_risk"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    CRITICAL_RISK = "critical_risk"

class AnalysisType(Enum):
    """Types of analysis performed."""
    PII_DETECTION = "pii_detection"
    FILE_PERMISSION = "file_permission"
    STORAGE_SECURITY = "storage_security"
    PATH_TRAVERSAL = "path_traversal"

@dataclass
class PIIFinding:
    """Represents a PII detection finding."""
    
    # Core identification
    pii_type: PIIType
    value: str
    location: str
    file_path: str
    line_number: Optional[int] = None
    
    # Analysis metadata
    confidence: float = 0.0
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    context: str = ""
    pattern_matched: str = ""
    
    # Risk assessment
    exposure_risk: str = ""
    data_sensitivity: str = ""
    compliance_impact: List[str] = field(default_factory=list)
    
    # Remediation
    remediation_advice: str = ""
    false_positive_likelihood: float = 0.0
    
    # Timestamps
    discovered_at: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate PII finding data."""
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")
        
        if not (0.0 <= self.false_positive_likelihood <= 1.0):
            raise ValueError("False positive likelihood must be between 0.0 and 1.0")

@dataclass
class FilePermissionFinding:
    """Represents a file permission security finding."""
    
    # File information
    file_path: str
    permission_mode: str
    owner: str
    group: str
    
    # Security assessment (required fields must come before optional ones)
    permission_level: FilePermissionLevel
    
    # File information (optional)
    size: Optional[int] = None
    
    # Security assessment (continued)
    security_issues: List[str] = field(default_factory=list)
    access_risks: List[str] = field(default_factory=list)
    
    # Analysis metadata
    confidence: float = 0.0
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    location: str = ""
    
    # Compliance and recommendations
    compliance_violations: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)
    
    # Context
    is_system_file: bool = False
    is_app_data: bool = False
    is_external_storage: bool = False
    
    def __post_init__(self):
        """Validate file permission finding data."""
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")

@dataclass
class StorageSecurityFinding:
    """Represents a storage security assessment finding."""
    
    # Storage information
    storage_type: str
    storage_path: str
    encryption_status: str
    access_control: str
    
    # Security assessment
    security_level: StorageSecurityLevel
    encryption_algorithm: Optional[str] = None
    key_management: Optional[str] = None
    
    # Vulnerabilities
    security_issues: List[str] = field(default_factory=list)
    data_leakage_risks: List[str] = field(default_factory=list)
    
    # Analysis metadata
    confidence: float = 0.0
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    location: str = ""
    
    # Context
    contains_sensitive_data: bool = False
    is_backup_location: bool = False
    is_shared_storage: bool = False
    
    # Recommendations
    security_recommendations: List[str] = field(default_factory=list)
    compliance_requirements: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate storage security finding data."""
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")

@dataclass
class PathTraversalFinding:
    """Represents a path traversal vulnerability finding."""
    
    # Vulnerability details (required fields first)
    vulnerable_method: str
    file_path: str
    traversal_risk: PathTraversalRisk
    
    # Vulnerability details (optional fields)
    line_number: Optional[int] = None
    user_input_source: str = ""
    
    # Risk assessment (fields with defaults)
    potential_targets: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    
    # Technical details
    vulnerable_parameter: str = ""
    path_validation: str = ""
    sanitization_present: bool = False
    
    # Analysis metadata
    confidence: float = 0.0
    severity: VulnerabilitySeverity = VulnerabilitySeverity.HIGH
    location: str = ""
    
    # Context
    is_file_operation: bool = False
    is_directory_operation: bool = False
    allows_external_input: bool = False
    
    # Security recommendations
    mitigation_strategies: List[str] = field(default_factory=list)
    code_examples: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate path traversal finding data."""
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")

@dataclass
class EnhancedDataStorageAnalysisConfig:
    """Configuration for enhanced data storage analysis."""
    
    # Analysis scope
    enable_pii_detection: bool = True
    enable_file_permission_analysis: bool = True
    enable_storage_security_analysis: bool = True
    enable_path_traversal_analysis: bool = True
    
    # PII detection settings
    pii_sensitivity_threshold: float = 0.7
    include_low_confidence_pii: bool = False
    pii_context_analysis: bool = True
    
    # File permission settings
    analyze_system_files: bool = False
    analyze_external_storage: bool = True
    permission_depth_limit: int = 3
    
    # Storage security settings
    encryption_analysis_depth: str = "standard"  # basic, standard, deep
    key_management_analysis: bool = True
    backup_security_analysis: bool = True
    
    # Path traversal settings
    traversal_depth_limit: int = 5
    analyze_user_input_sources: bool = True
    include_theoretical_attacks: bool = False
    
    # Performance settings
    max_analysis_time: int = 300  # 5 minutes
    max_files_to_analyze: int = 1000
    parallel_analysis: bool = True
    max_workers: int = 4
    
    # Reporting settings
    detailed_reporting: bool = True
    include_remediation: bool = True
    compliance_mapping: bool = True
    
    def __post_init__(self):
        """Validate configuration."""
        if not (0.0 <= self.pii_sensitivity_threshold <= 1.0):
            raise ValueError("PII sensitivity threshold must be between 0.0 and 1.0")
        
        if self.max_analysis_time <= 0:
            raise ValueError("Max analysis time must be positive")
        
        if self.max_workers <= 0:
            raise ValueError("Max workers must be positive")

@dataclass
class AnalysisStatistics:
    """Statistics from enhanced data storage analysis."""
    
    # Analysis scope
    files_analyzed: int = 0
    directories_scanned: int = 0
    analysis_duration: float = 0.0
    
    # PII detection statistics
    pii_findings_count: int = 0
    pii_types_found: Set[PIIType] = field(default_factory=set)
    high_risk_pii_count: int = 0
    
    # File permission statistics
    files_with_permission_issues: int = 0
    critical_permission_issues: int = 0
    world_readable_files: int = 0
    world_writable_files: int = 0
    
    # Storage security statistics
    encrypted_storage_count: int = 0
    unencrypted_storage_count: int = 0
    storage_vulnerabilities: int = 0
    
    # Path traversal statistics
    path_traversal_vulnerabilities: int = 0
    high_risk_traversal_count: int = 0
    validated_paths_count: int = 0
    
    # Quality metrics
    analysis_coverage: float = 0.0
    confidence_distribution: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

@dataclass
class EnhancedDataStorageAnalysisResult:
    """Comprehensive result of enhanced data storage analysis."""
    
    # Analysis metadata
    analysis_id: str
    package_name: str
    start_time: datetime
    end_time: datetime
    config: EnhancedDataStorageAnalysisConfig
    
    # Analysis results
    pii_findings: List[PIIFinding] = field(default_factory=list)
    file_permission_findings: List[FilePermissionFinding] = field(default_factory=list)
    storage_security_findings: List[StorageSecurityFinding] = field(default_factory=list)
    path_traversal_findings: List[PathTraversalFinding] = field(default_factory=list)
    
    # Statistics and metrics
    statistics: AnalysisStatistics = field(default_factory=AnalysisStatistics)
    
    # Summary data
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    
    # Risk assessment
    overall_risk_score: float = 0.0
    risk_level: str = "UNKNOWN"
    compliance_status: str = "UNKNOWN"
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    priority_actions: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Calculate derived fields."""
        all_findings = (
            self.pii_findings + 
            self.file_permission_findings + 
            self.storage_security_findings + 
            self.path_traversal_findings
        )
        
        self.total_findings = len(all_findings)
        
        # Count findings by severity
        for finding in all_findings:
            if hasattr(finding, 'severity'):
                if finding.severity == VulnerabilitySeverity.CRITICAL:
                    self.critical_findings += 1
                elif finding.severity == VulnerabilitySeverity.HIGH:
                    self.high_findings += 1
                elif finding.severity == VulnerabilitySeverity.MEDIUM:
                    self.medium_findings += 1
                elif finding.severity == VulnerabilitySeverity.LOW:
                    self.low_findings += 1
        
        # Calculate overall risk score if not set
        if not self.overall_risk_score:
            self.overall_risk_score = self._calculate_overall_risk()
        
        # Determine risk level if not set
        if self.risk_level == "UNKNOWN":
            self.risk_level = self._determine_risk_level()
    
    def _calculate_overall_risk(self) -> float:
        """Calculate overall risk score based on findings."""
        if not self.total_findings:
            return 0.0
        
        try:
            # Weight by severity
            severity_weights = {
                VulnerabilitySeverity.CRITICAL: 10.0,
                VulnerabilitySeverity.HIGH: 7.0,
                VulnerabilitySeverity.MEDIUM: 4.0,
                VulnerabilitySeverity.LOW: 1.0
            }
            
            total_weighted_score = 0.0
            all_findings = (
                self.pii_findings + 
                self.file_permission_findings + 
                self.storage_security_findings + 
                self.path_traversal_findings
            )
            
            for finding in all_findings:
                if hasattr(finding, 'severity') and hasattr(finding, 'confidence'):
                    weight = severity_weights.get(finding.severity, 1.0)
                    total_weighted_score += weight * finding.confidence
            
            # Normalize to 0-100 scale
            max_possible_score = len(all_findings) * 10.0
            if max_possible_score > 0:
                return min(100.0, (total_weighted_score / max_possible_score) * 100.0)
            else:
                return 0.0
                
        except Exception:
            return 0.0
    
    def _determine_risk_level(self) -> str:
        """Determine risk level based on overall risk score."""
        if self.overall_risk_score >= 80:
            return "CRITICAL"
        elif self.overall_risk_score >= 60:
            return "HIGH"
        elif self.overall_risk_score >= 40:
            return "MEDIUM"
        elif self.overall_risk_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"

@dataclass
class ConfidenceEvidence:
    """Evidence structure for confidence calculation."""
    
    # Pattern evidence
    pattern_match_quality: float
    pattern_specificity: float
    pattern_reliability: float
    
    # Context evidence
    file_context: str
    location_relevance: float
    data_sensitivity: float
    
    # Validation evidence
    cross_validation: bool
    manual_verification: bool
    false_positive_indicators: List[str] = field(default_factory=list)
    
    # Analysis metadata
    analysis_depth: str = "standard"  # basic, standard, deep
    validation_sources: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate evidence data."""
        float_fields = [
            'pattern_match_quality', 'pattern_specificity', 'pattern_reliability',
            'location_relevance', 'data_sensitivity'
        ]
        
        for field_name in float_fields:
            value = getattr(self, field_name)
            if not (0.0 <= value <= 1.0):
                raise ValueError(f"{field_name} must be between 0.0 and 1.0") 