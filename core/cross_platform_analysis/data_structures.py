"""
Shared Data Structures for Cross-Platform Analysis Engine

This module contains all shared data structures, enums, and type definitions
used across the cross-platform analysis components.

Features:
- finding and result structures
- Framework detection types
- Confidence calculation data types
- Analysis configuration classes
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set
from enum import Enum

class Framework(Enum):
    """Supported cross-platform frameworks."""
    FLUTTER = "flutter"
    REACT_NATIVE = "react_native"
    XAMARIN = "xamarin"
    CORDOVA = "cordova"
    PWA = "pwa"

class VulnerabilityType(Enum):
    """Types of cross-platform vulnerabilities."""
    JAVASCRIPT_INJECTION = "javascript_injection"
    BRIDGE_VULNERABILITIES = "bridge_vulnerabilities"
    INSECURE_STORAGE = "insecure_storage"
    NETWORK_SECURITY = "network_security"
    HARDCODED_SECRETS = "hardcoded_secrets"
    CRYPTO_WEAKNESSES = "crypto_weaknesses"
    THIRD_PARTY_VULNERABILITIES = "third_party_vulnerabilities"
    CONFIGURATION_ISSUES = "configuration_issues"
    IL_CODE_SECURITY = "il_code_security"
    NATIVE_INTEROP = "native_interop"
    SERVICE_WORKER_SECURITY = "service_worker_security"
    MANIFEST_SECURITY = "manifest_security"

class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class DetectionMethod(Enum):
    """Methods used for vulnerability detection."""
    PATTERN_MATCHING = "pattern_matching"
    STATIC_ANALYSIS = "static_analysis"
    DEPENDENCY_ANALYSIS = "dependency_analysis"
    CONFIGURATION_ANALYSIS = "configuration_analysis"
    IL_ANALYSIS = "il_analysis"
    MANIFEST_ANALYSIS = "manifest_analysis"

@dataclass
class CrossPlatformFinding:
    """Represents a detected cross-platform security vulnerability."""
    framework: str
    vulnerability_type: str
    component: str
    original_content: str
    confidence: float
    location: str
    severity: str
    description: str
    remediation: str
    attack_vector: str
    framework_version: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    detection_method: Optional[str] = None
    pattern_category: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)

@dataclass
class FrameworkDetectionResult:
    """Result of framework detection analysis."""
    framework: str
    confidence: float
    version: Optional[str]
    indicators: List[str]
    file_patterns: List[str]
    dependencies: List[str]
    security_features: Dict[str, bool]
    detection_method: str = DetectionMethod.PATTERN_MATCHING.value
    reliability_score: float = 0.0

@dataclass
class AnalysisConfiguration:
    """Configuration for cross-platform analysis."""
    max_analysis_time: int = 300
    enable_parallel_analysis: bool = True
    max_concurrent_analyzers: int = 3
    confidence_threshold: float = 0.3
    enable_deep_analysis: bool = True
    framework_specific_analysis: bool = True
    include_third_party_analysis: bool = True
    cache_results: bool = True
    cache_ttl: int = 600  # 10 minutes
    verbose_logging: bool = False

@dataclass
class LibraryInfo:
    """Information about third-party libraries."""
    name: str
    version: Optional[str]
    framework: str
    vulnerability_score: float
    known_vulnerabilities: List[str] = field(default_factory=list)
    last_updated: Optional[str] = None
    risk_level: str = "unknown"
    remediation_advice: str = ""

@dataclass
class SecurityFeatureAssessment:
    """Assessment of security features in frameworks."""
    feature_name: str
    implementation_status: str  # implemented, missing, partial
    effectiveness_score: float
    description: str
    recommendations: List[str] = field(default_factory=list)

@dataclass
class CrossPlatformAnalysisResult:
    """Complete result of cross-platform analysis."""
    frameworks_detected: List[FrameworkDetectionResult]
    findings: List[CrossPlatformFinding]
    security_assessment: Dict[str, SecurityFeatureAssessment]
    risk_score: float
    risk_level: str
    recommendations: List[str]
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

@dataclass
class ConfidenceEvidence:
    """Evidence structure for confidence calculation."""
    pattern_type: str
    match_quality: float
    context_relevance: float
    framework_specificity: float
    vulnerability_severity: str
    detection_method: str
    code_context: str = ""
    evidence_sources: List[str] = field(default_factory=list)
    validation_methods: List[str] = field(default_factory=list)

@dataclass
class PatternMatchResult:
    """Result of pattern matching operation."""
    pattern_id: str
    match_text: str
    start_position: int
    end_position: int
    confidence: float
    context: str
    pattern_category: str
    vulnerability_type: str
    severity: str
    framework: str

@dataclass
class FrameworkSpecificConfig:
    """Framework-specific analysis configuration."""
    framework: Framework
    enabled_analyzers: List[str]
    pattern_files: List[str]
    confidence_thresholds: Dict[str, float]
    analysis_depth: str  # basic, standard, deep
    custom_patterns: Dict[str, List[str]] = field(default_factory=dict)
    third_party_db_path: Optional[str] = None

@dataclass
class DependencyAnalysisResult:
    """Result of dependency vulnerability analysis."""
    dependency_name: str
    version: str
    vulnerability_id: str
    severity: str
    confidence: float
    description: str
    remediation: str
    affected_versions: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)

@dataclass
class CodeQualityMetrics:
    """Code quality metrics for cross-platform code."""
    complexity_score: float
    maintainability_index: float
    security_hotspots: int
    code_smells: int
    technical_debt_ratio: float
    test_coverage: Optional[float] = None
    documentation_coverage: Optional[float] = None

@dataclass
class PerformanceMetrics:
    """Performance metrics for analysis operations."""
    analysis_duration: float
    files_analyzed: int
    patterns_matched: int
    memory_usage_mb: float
    cpu_usage_percent: float
    cache_hit_ratio: float = 0.0

@dataclass
class ErrorContext:
    """Context information for analysis errors."""
    error_type: str
    component: str
    framework: str
    file_path: str
    line_number: Optional[int] = None
    stack_trace: Optional[str] = None
    recovery_attempted: bool = False
    user_guidance: str = "" 