"""
Enhanced Root Detection Bypass Analyzer Data Structures

This module contains all data structures, dataclasses, and enums used
throughout the enhanced root detection bypass analyzer plugin components.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import Enum
from datetime import datetime

class RootDetectionType(Enum):
    """Types of root detection mechanisms."""
    NATIVE_BINARY = "native_binary"
    FILE_SYSTEM = "file_system"
    PROCESS_EXECUTION = "process_execution"
    SYSTEM_PROPERTY = "system_property"
    PACKAGE_MANAGER = "package_manager"
    RUNTIME_DETECTION = "runtime_detection"
    DEVICE_ATTESTATION = "device_attestation"
    SECURITY_PROVIDER = "security_provider"

class BypassTechnique(Enum):
    """Root detection bypass techniques."""
    HOOKING = "hooking"
    BINARY_PATCHING = "binary_patching"
    ENVIRONMENT_MANIPULATION = "environment_manipulation"
    PROCESS_HIDING = "process_hiding"
    FILE_HIDING = "file_hiding"
    PROPERTY_MASKING = "property_masking"
    LIBRARY_INJECTION = "library_injection"
    SYSTEM_CALL_INTERCEPTION = "system_call_interception"

class SecurityControlType(Enum):
    """Types of security controls."""
    ROOT_DETECTION = "root_detection"
    ANTI_HOOKING = "anti_hooking"
    ANTI_DEBUGGING = "anti_debugging"
    INTEGRITY_CHECK = "integrity_check"
    RUNTIME_PROTECTION = "runtime_protection"
    DEVICE_BINDING = "device_binding"
    ATTESTATION = "attestation"

class EffectivenessLevel(Enum):
    """Security control effectiveness levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"

@dataclass
class RootDetectionFinding:
    """Represents a comprehensive root detection finding with bypass analysis."""
    detection_id: str
    detection_type: str
    severity: str
    confidence: float
    description: str
    location: str
    evidence: List[str]
    pattern_category: str
    bypass_resistance_score: float
    security_control_effectiveness: str
    category: str = "root_detection"
    attack_vectors: List[str] = field(default_factory=list)
    bypass_methods: List[str] = field(default_factory=list)
    remediation: str = ""
    masvs_refs: List[str] = field(default_factory=list)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'detection_id': self.detection_id,
            'detection_type': self.detection_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'description': self.description,
            'location': self.location,
            'evidence': self.evidence,
            'pattern_category': self.pattern_category,
            'category': self.category,
            'bypass_resistance_score': self.bypass_resistance_score,
            'security_control_effectiveness': self.security_control_effectiveness,
            'attack_vectors': self.attack_vectors,
            'bypass_methods': self.bypass_methods,
            'remediation': self.remediation,
            'masvs_refs': self.masvs_refs,
            'analysis_metadata': self.analysis_metadata
        }

@dataclass
class SecurityControlAssessment:
    """Represents comprehensive security control strength assessment."""
    control_type: str
    implementation_strength: str
    effectiveness_score: float
    bypass_resistance: str
    coverage_gaps: List[str]
    strengths: List[str]
    weaknesses: List[str]
    recommendations: List[str]
    risk_level: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'control_type': self.control_type,
            'implementation_strength': self.implementation_strength,
            'effectiveness_score': self.effectiveness_score,
            'bypass_resistance': self.bypass_resistance,
            'coverage_gaps': self.coverage_gaps,
            'strengths': self.strengths,
            'weaknesses': self.weaknesses,
            'recommendations': self.recommendations,
            'risk_level': self.risk_level
        }

@dataclass
class BypassAnalysisResult:
    """Results of bypass effectiveness analysis."""
    bypass_method: str
    effectiveness_score: float
    complexity_level: str
    detection_probability: float
    countermeasures: List[str]
    impact_assessment: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'bypass_method': self.bypass_method,
            'effectiveness_score': self.effectiveness_score,
            'complexity_level': self.complexity_level,
            'detection_probability': self.detection_probability,
            'countermeasures': self.countermeasures,
            'impact_assessment': self.impact_assessment
        }

@dataclass
class RootDetectionAnalysisConfig:
    """Configuration for root detection analysis with performance optimizations."""
    max_analysis_time: int = 45
    enable_parallel_execution: bool = True
    max_concurrent_tests: int = 3
    cache_results: bool = True
    cache_ttl: int = 300  # 5 minutes
    timeout_per_test: int = 15
    enable_dynamic_analysis: bool = True
    verbose_logging: bool = False
    failure_notifications: bool = True
    organic_detection_only: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'max_analysis_time': self.max_analysis_time,
            'enable_parallel_execution': self.enable_parallel_execution,
            'max_concurrent_tests': self.max_concurrent_tests,
            'cache_results': self.cache_results,
            'cache_ttl': self.cache_ttl,
            'timeout_per_test': self.timeout_per_test,
            'enable_dynamic_analysis': self.enable_dynamic_analysis,
            'verbose_logging': self.verbose_logging,
            'failure_notifications': self.failure_notifications,
            'organic_detection_only': self.organic_detection_only
        }

@dataclass
class RootDetectionAnalysisResult:
    """Complete root detection analysis results."""
    detection_findings: List[RootDetectionFinding]
    security_assessments: List[SecurityControlAssessment]
    bypass_analysis: Dict[str, Any]
    dynamic_analysis_results: Dict[str, Any]
    overall_security_score: float
    risk_assessment: str
    recommendations: List[str]
    masvs_compliance: List[str]
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'detection_findings': [finding.to_dict() for finding in self.detection_findings],
            'security_assessments': [assessment.to_dict() for assessment in self.security_assessments],
            'bypass_analysis': self.bypass_analysis,
            'dynamic_analysis_results': self.dynamic_analysis_results,
            'overall_security_score': self.overall_security_score,
            'risk_assessment': self.risk_assessment,
            'recommendations': self.recommendations,
            'masvs_compliance': self.masvs_compliance,
            'analysis_metadata': self.analysis_metadata
        }

class RootDetectionPatterns:
    """Root detection pattern categories for configuration."""
    NATIVE_BINARY = "native_binary_analysis"
    FILE_SYSTEM = "file_system_permission_analysis"
    PROCESS_EXECUTION = "process_execution_analysis"
    SYSTEM_PROPERTY = "system_property_analysis"
    PACKAGE_MANAGER = "package_manager_analysis"
    RUNTIME_DETECTION = "runtime_detection_analysis"

class MAVSRootControls:
    """MASVS control mappings for root detection."""
    RESILIENCE_1 = "MSTG-RESILIENCE-1"  # Anti-tampering protection
    RESILIENCE_2 = "MSTG-RESILIENCE-2"  # Runtime application self-protection
    RESILIENCE_3 = "MSTG-RESILIENCE-3"  # Device binding and attestation
    PLATFORM_11 = "MSTG-PLATFORM-11"    # WebView configuration

class CWERootCategories:
    """Common Weakness Enumeration categories for root detection vulnerabilities."""
    INSUFFICIENT_PROTECTION = "CWE-693"
    MISSING_AUTHENTICATION = "CWE-306"
    INADEQUATE_SECURITY_CONTROL = "CWE-330"
    WEAK_PROTECTION_MECHANISM = "CWE-693"
    BYPASS_PROTECTION = "CWE-807"

@dataclass
class DetectionMethodMetrics:
    """Metrics for detection method effectiveness."""
    method_name: str
    detection_rate: float
    false_positive_rate: float
    bypass_resistance: float
    performance_impact: str
    reliability_score: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'method_name': self.method_name,
            'detection_rate': self.detection_rate,
            'false_positive_rate': self.false_positive_rate,
            'bypass_resistance': self.bypass_resistance,
            'performance_impact': self.performance_impact,
            'reliability_score': self.reliability_score
        }

@dataclass
class ExecutionStatistics:
    """Statistics for analysis execution."""
    total_analysis_time: float
    parallel_execution_time: float
    sequential_execution_time: float
    cache_hits: int
    cache_misses: int
    failed_analyses: int
    successful_analyses: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'total_analysis_time': self.total_analysis_time,
            'parallel_execution_time': self.parallel_execution_time,
            'sequential_execution_time': self.sequential_execution_time,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'failed_analyses': self.failed_analyses,
            'successful_analyses': self.successful_analyses
        } 