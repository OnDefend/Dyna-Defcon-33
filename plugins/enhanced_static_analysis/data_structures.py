"""
Enhanced Static Analysis Plugin - Data Structures

This module defines the data structures, enums, and classes used by the enhanced
static analysis plugin for comprehensive security analysis.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from enum import Enum
import datetime

class RiskLevel(Enum):
    """Risk levels for security findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"

class SeverityLevel(Enum):
    """Severity levels for security findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AnalysisType(Enum):
    """Types of analysis performed."""
    STATIC_ANALYSIS = "static_analysis"
    SECRET_DETECTION = "secret_detection"
    MANIFEST_ANALYSIS = "manifest_analysis"
    CODE_QUALITY = "code_quality"
    PATTERN_MATCHING = "pattern_matching"

class FindingCategory(Enum):
    """Categories of security findings."""
    SECURITY_VULNERABILITY = "security_vulnerability"
    CODE_QUALITY_ISSUE = "code_quality_issue"
    PERFORMANCE_ISSUE = "performance_issue"
    COMPLIANCE_ISSUE = "compliance_issue"
    BEST_PRACTICE = "best_practice"
    INFORMATIONAL = "informational"

@dataclass
class AnalysisConfiguration:
    """Configuration for static analysis."""
    enable_secret_detection: bool = True
    enable_manifest_analysis: bool = True
    enable_code_quality: bool = True
    enable_code_quality_metrics: bool = True  # Added missing attribute
    enable_pattern_matching: bool = True
    max_analysis_time: int = 300  # seconds
    max_file_size: int = 10485760  # 10MB
    excluded_file_types: List[str] = field(default_factory=lambda: ['.so', '.jar', '.class'])
    excluded_file_patterns: List[str] = field(default_factory=lambda: ['*/kotlin/jvm/internal/*', '*/org/jetbrains/*', '*/okhttp3/internal/*'])  # Added missing attribute
    custom_patterns: Dict[str, Any] = field(default_factory=dict)
    
    # Secret detection configuration - ADDED MISSING ATTRIBUTES
    secret_confidence_threshold: float = 0.4  # Minimum confidence for secret detection
    entropy_threshold: float = 4.0  # Minimum entropy for high-entropy secret detection
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary representation."""
        return {
            'enable_secret_detection': self.enable_secret_detection,
            'enable_manifest_analysis': self.enable_manifest_analysis,
            'enable_code_quality': self.enable_code_quality,
            'enable_code_quality_metrics': self.enable_code_quality_metrics,  # Added to dict
            'enable_pattern_matching': self.enable_pattern_matching,
            'max_analysis_time': self.max_analysis_time,
            'max_file_size': self.max_file_size,
            'excluded_file_types': self.excluded_file_types,
            'excluded_file_patterns': self.excluded_file_patterns,  # Added to dict
            'custom_patterns': self.custom_patterns,
            # Secret detection configuration - ADDED TO DICT
            'secret_confidence_threshold': self.secret_confidence_threshold,
            'entropy_threshold': self.entropy_threshold
        }

class SecretType(Enum):
    """Types of secrets that can be detected."""
    API_KEY = "api_key"
    DATABASE_URL = "database_url"
    PRIVATE_KEY = "private_key"
    PASSWORD = "password"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    CREDENTIAL = "credential"
    ENCRYPTION_KEY = "encryption_key"
    UNKNOWN = "unknown"

class PatternType(Enum):
    """Types of patterns used for detection."""
    REGEX = "regex"
    ENTROPY = "entropy"
    KEYWORD = "keyword"
    STRUCTURAL = "structural"
    BEHAVIORAL = "behavioral"

class FileType(Enum):
    """Types of files being analyzed."""
    JAVA = "java"
    KOTLIN = "kotlin"
    XML = "xml"
    JSON = "json"
    PROPERTIES = "properties"
    MANIFEST = "manifest"
    RESOURCE = "resource"
    BINARY = "binary"
    UNKNOWN = "unknown"

@dataclass
class SecurityFinding:
    """Represents a security finding from static analysis."""
    id: str
    title: str
    description: str
    severity: SeverityLevel
    category: str
    file_path: str
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    code_snippet: Optional[str] = None
    evidence: Optional[str] = None  # Added missing evidence parameter
    pattern_type: Optional[str] = None  # Added missing pattern_type parameter
    masvs_control: Optional[str] = None  # Added missing masvs_control parameter
    confidence: float = 0.7  # **CONFIDENCE SCORING FIX**: Changed from 0.0 to reasonable default
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    masvs_category: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    detection_method: PatternType = PatternType.REGEX
    false_positive_indicators: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Post-initialization validation."""
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")

@dataclass
class SecretAnalysis:
    """Represents analysis of a potential secret."""
    id: str
    pattern_type: str
    value: str
    entropy: float
    confidence: float
    file_path: str
    line_number: Optional[int] = None
    context: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    secret_type: SecretType = SecretType.UNKNOWN
    detection_method: PatternType = PatternType.ENTROPY
    validation_results: Dict[str, Any] = field(default_factory=dict)
    false_positive_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization validation."""
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")
        if not (0.0 <= self.entropy <= 8.0):
            raise ValueError("Entropy must be between 0.0 and 8.0")

@dataclass
class ManifestAnalysis:
    """Represents analysis of AndroidManifest.xml."""
    package_name: str
    version_code: Optional[int] = None
    version_name: Optional[str] = None
    min_sdk_version: Optional[int] = None
    target_sdk_version: Optional[int] = None
    compile_sdk_version: Optional[int] = None
    permissions: List[Dict[str, Any]] = field(default_factory=list)
    activities: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    receivers: List[Dict[str, Any]] = field(default_factory=list)
    providers: List[Dict[str, Any]] = field(default_factory=list)
    security_features: Dict[str, Any] = field(default_factory=dict)
    exported_components: List[Dict[str, Any]] = field(default_factory=list)
    dangerous_permissions: List[Dict[str, Any]] = field(default_factory=list)
    custom_permissions: List[Dict[str, Any]] = field(default_factory=list)
    intent_filters: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    analysis_errors: List[str] = field(default_factory=list)

@dataclass
class CodeQualityMetrics:
    """Represents code quality metrics."""
    total_files: int = 0
    code_files: int = 0
    lines_of_code: int = 0
    cyclomatic_complexity: float = 0.0
    obfuscation_level: float = 0.0
    dead_code_ratio: float = 0.0
    code_duplication_ratio: float = 0.0
    technical_debt_ratio: float = 0.0
    maintainability_index: float = 0.0
    complexity_distribution: Dict[str, int] = field(default_factory=dict)
    quality_score: float = 0.0
    analysis_timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the metrics to a dictionary for serialization."""
        return {
            'total_files': self.total_files,
            'code_files': self.code_files,
            'lines_of_code': self.lines_of_code,
            'cyclomatic_complexity': self.cyclomatic_complexity,
            'obfuscation_level': self.obfuscation_level,
            'dead_code_ratio': self.dead_code_ratio,
            'code_duplication_ratio': self.code_duplication_ratio,
            'technical_debt_ratio': self.technical_debt_ratio,
            'maintainability_index': self.maintainability_index,
            'complexity_distribution': self.complexity_distribution,
            'quality_score': self.quality_score,
            'analysis_timestamp': self.analysis_timestamp.isoformat() if self.analysis_timestamp else None
        }

@dataclass
class RiskAssessment:
    """Represents overall risk assessment."""
    overall_risk: RiskLevel = RiskLevel.UNKNOWN
    risk_score: float = 0.0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    info_issues: int = 0
    total_issues: int = 0
    risk_factors: List[str] = field(default_factory=list)
    mitigation_strategies: List[str] = field(default_factory=list)
    compliance_status: Dict[str, str] = field(default_factory=dict)
    security_score: float = 0.0
    
    def __post_init__(self):
        """Calculate total issues and validate risk score."""
        self.total_issues = (
            self.critical_issues + self.high_issues + 
            self.medium_issues + self.low_issues + self.info_issues
        )
        if not (0.0 <= self.risk_score <= 1.0):
            raise ValueError("Risk score must be between 0.0 and 1.0")

@dataclass
class AnalysisContext:
    """Context information for analysis."""
    apk_path: str
    package_name: str
    version: str
    target_sdk: int
    min_sdk: int
    analysis_start_time: datetime.datetime = field(default_factory=datetime.datetime.now)
    analysis_end_time: Optional[datetime.datetime] = None
    analyzer_version: str = "2.0.0"
    configuration: Dict[str, Any] = field(default_factory=dict)
    excluded_paths: List[str] = field(default_factory=list)
    included_patterns: List[str] = field(default_factory=list)
    
    @property
    def analysis_duration(self) -> Optional[datetime.timedelta]:
        """Calculate analysis duration."""
        if self.analysis_end_time:
            return self.analysis_end_time - self.analysis_start_time
        return None

@dataclass
class EnhancedStaticAnalysisResult:
    """Comprehensive result of enhanced static analysis."""
    context: AnalysisContext
    security_findings: List[SecurityFinding] = field(default_factory=list)
    secret_analysis: List[SecretAnalysis] = field(default_factory=list)
    manifest_analysis: Optional[ManifestAnalysis] = None
    code_quality_metrics: Optional[CodeQualityMetrics] = None
    risk_assessment: Optional[RiskAssessment] = None
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def get_findings_by_severity(self, severity: SeverityLevel) -> List[SecurityFinding]:
        """Get security findings by severity level."""
        return [f for f in self.security_findings if f.severity == severity]
    
    def get_high_confidence_secrets(self, threshold: float = 0.7) -> List[SecretAnalysis]:
        """Get secrets with high confidence above threshold."""
        return [s for s in self.secret_analysis if s.confidence >= threshold]
    
    def get_critical_issues(self) -> List[SecurityFinding]:
        """Get critical security issues."""
        return self.get_findings_by_severity(SeverityLevel.CRITICAL)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary."""
        return {
            "total_findings": len(self.security_findings),
            "critical_findings": len(self.get_critical_issues()),
            "high_findings": len(self.get_findings_by_severity(SeverityLevel.HIGH)),
            "medium_findings": len(self.get_findings_by_severity(SeverityLevel.MEDIUM)),
            "low_findings": len(self.get_findings_by_severity(SeverityLevel.LOW)),
            "secrets_detected": len(self.secret_analysis),
            "high_confidence_secrets": len(self.get_high_confidence_secrets()),
            "overall_risk": self.risk_assessment.overall_risk.value if self.risk_assessment else "UNKNOWN",
            "risk_score": self.risk_assessment.risk_score if self.risk_assessment else 0.0,
            "total_errors": len(self.errors),
            "total_warnings": len(self.warnings)
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a dictionary for serialization."""
        return {
            "context": {
                "apk_path": self.context.apk_path,
                "package_name": self.context.package_name,
                "version": self.context.version,
                "target_sdk": self.context.target_sdk,
                "min_sdk": self.context.min_sdk,
                "analysis_start_time": self.context.analysis_start_time.isoformat() if self.context.analysis_start_time else None,
                "analysis_end_time": self.context.analysis_end_time.isoformat() if self.context.analysis_end_time else None,
                "analyzer_version": self.context.analyzer_version,
                "configuration": self.context.configuration
            },
            "security_findings": [
                {
                    "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                    "title": getattr(finding, 'title', str(finding)),
                    "description": getattr(finding, 'description', ''),
                    "file_path": getattr(finding, 'file_path', ''),
                    "line_number": getattr(finding, 'line_number', 0)
                } for finding in self.security_findings
            ],
            "secret_analysis": [
                {
                    "pattern_type": secret.pattern_type.value if hasattr(secret.pattern_type, 'value') else str(secret.pattern_type),
                    "confidence": getattr(secret, 'confidence', 0.0),
                    "file_path": getattr(secret, 'file_path', ''),
                    "content": getattr(secret, 'content', '')
                } for secret in self.secret_analysis
            ],
            "manifest_analysis": {
                "package_name": self.manifest_analysis.package_name,
                "target_sdk_version": self.manifest_analysis.target_sdk_version,
                "min_sdk_version": self.manifest_analysis.min_sdk_version,
                "permissions": len(self.manifest_analysis.permissions) if self.manifest_analysis.permissions else 0,
                "activities": len(self.manifest_analysis.activities) if self.manifest_analysis.activities else 0,
                "services": len(self.manifest_analysis.services) if self.manifest_analysis.services else 0
            } if self.manifest_analysis else None,
            "risk_assessment": {
                "overall_risk": self.risk_assessment.overall_risk.value if self.risk_assessment.overall_risk else "UNKNOWN",
                "risk_score": self.risk_assessment.risk_score,
                "critical_issues": self.risk_assessment.critical_issues,
                "high_issues": self.risk_assessment.high_issues,
                "medium_issues": self.risk_assessment.medium_issues,
                "low_issues": self.risk_assessment.low_issues,
                "total_issues": self.risk_assessment.total_issues,
                "security_score": self.risk_assessment.security_score
            } if self.risk_assessment else None,
            "analysis_metadata": self.analysis_metadata,
            "recommendations": self.recommendations,
            "errors": self.errors,
            "warnings": self.warnings,
            "summary": self.get_summary()
        }

@dataclass
class PatternMatch:
    """Represents a pattern match during analysis."""
    pattern_id: str
    pattern_type: PatternType
    matched_text: str
    file_path: str
    line_number: int
    confidence: float
    context: str
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ValidationResult:
    """Represents validation result for a detected secret or finding."""
    is_valid: bool
    confidence: float
    validation_method: str
    details: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None

# Type aliases for better readability
SecurityFindings = List[SecurityFinding]
SecretAnalyses = List[SecretAnalysis]
PatternMatches = List[PatternMatch]
AnalysisResults = Dict[str, Any]

# Alias for backward compatibility
StaticAnalysisResult = EnhancedStaticAnalysisResult 