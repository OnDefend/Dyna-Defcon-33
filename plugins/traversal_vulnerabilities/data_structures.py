"""
Traversal Vulnerabilities Analysis Plugin Data Structures

This module contains all data structures, dataclasses, and enums used
throughout the traversal vulnerabilities analyzer plugin components.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import Enum

class TraversalType(Enum):
    """Types of traversal vulnerabilities."""
    PATH_TRAVERSAL = "path_traversal"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    FILE_INCLUSION = "file_inclusion"
    CONTENT_PROVIDER = "content_provider"
    INTENT_BASED = "intent_based"
    URI_BASED = "uri_based"
    WEBVIEW_BASED = "webview_based"

class SeverityLevel(Enum):
    """Severity levels for traversal vulnerabilities."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class RiskLevel(Enum):
    """Risk levels for security assessments."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"

@dataclass
class TraversalVulnerability:
    """Represents a path traversal vulnerability finding."""
    vulnerability_id: str
    title: str
    severity: str
    confidence: float
    description: str
    location: str
    evidence: str
    attack_vectors: List[str] = field(default_factory=list)
    remediation: str = ""
    masvs_refs: List[str] = field(default_factory=list)
    cwe_id: str = ""
    risk_score: int = 0
    traversal_type: str = ""
    payload_examples: List[str] = field(default_factory=list)
    mitigation_strategies: List[str] = field(default_factory=list)
    impact_assessment: str = ""
    detection_method: str = ""
    false_positive_likelihood: str = "low"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'vulnerability_id': self.vulnerability_id,
            'title': self.title,
            'severity': self.severity,
            'confidence': self.confidence,
            'description': self.description,
            'location': self.location,
            'evidence': self.evidence,
            'attack_vectors': self.attack_vectors,
            'remediation': self.remediation,
            'masvs_refs': self.masvs_refs,
            'cwe_id': self.cwe_id,
            'risk_score': self.risk_score,
            'traversal_type': self.traversal_type,
            'payload_examples': self.payload_examples,
            'mitigation_strategies': self.mitigation_strategies,
            'impact_assessment': self.impact_assessment,
            'detection_method': self.detection_method,
            'false_positive_likelihood': self.false_positive_likelihood
        }

@dataclass
class ContentProviderAnalysis:
    """Represents content provider security analysis results."""
    provider_name: str
    authority: str
    exported: bool
    permissions: List[str]
    grant_uri_permissions: bool
    path_permissions: List[Dict[str, str]]
    vulnerabilities: List[TraversalVulnerability]
    risk_level: str
    security_score: float = 0.0
    read_permissions: List[str] = field(default_factory=list)
    write_permissions: List[str] = field(default_factory=list)
    uri_matchers: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'provider_name': self.provider_name,
            'authority': self.authority,
            'exported': self.exported,
            'permissions': self.permissions,
            'grant_uri_permissions': self.grant_uri_permissions,
            'path_permissions': self.path_permissions,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'risk_level': self.risk_level,
            'security_score': self.security_score,
            'read_permissions': self.read_permissions,
            'write_permissions': self.write_permissions,
            'uri_matchers': self.uri_matchers
        }

@dataclass
class IntentFilterAnalysis:
    """Represents intent filter security analysis results."""
    component_name: str
    action: str
    data_scheme: str
    data_host: str
    data_path: str
    data_path_pattern: str
    data_path_prefix: str
    exported: bool
    vulnerabilities: List[TraversalVulnerability]
    risk_assessment: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'component_name': self.component_name,
            'action': self.action,
            'data_scheme': self.data_scheme,
            'data_host': self.data_host,
            'data_path': self.data_path,
            'data_path_pattern': self.data_path_pattern,
            'data_path_prefix': self.data_path_prefix,
            'exported': self.exported,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'risk_assessment': self.risk_assessment
        }

@dataclass
class FileOperationAnalysis:
    """Represents file operation security analysis results."""
    operation_type: str
    file_path: str
    validation_present: bool
    sanitization_present: bool
    user_input_source: str
    vulnerabilities: List[TraversalVulnerability]
    security_controls: List[str]
    bypass_techniques: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'operation_type': self.operation_type,
            'file_path': self.file_path,
            'validation_present': self.validation_present,
            'sanitization_present': self.sanitization_present,
            'user_input_source': self.user_input_source,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'security_controls': self.security_controls,
            'bypass_techniques': self.bypass_techniques
        }

@dataclass
class TraversalAnalysisConfig:
    """Configuration for traversal vulnerability analysis."""
    enable_static_analysis: bool = True
    enable_dynamic_analysis: bool = False
    enable_content_provider_analysis: bool = True
    enable_intent_filter_analysis: bool = True
    enable_file_operation_analysis: bool = True
    enable_payload_generation: bool = True
    max_payloads_per_vulnerability: int = 5
    deep_analysis_mode: bool = False
    enable_bypass_detection: bool = True
    confidence_threshold: float = 0.5
    enable_false_positive_filtering: bool = True
    verbose_logging: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'enable_static_analysis': self.enable_static_analysis,
            'enable_dynamic_analysis': self.enable_dynamic_analysis,
            'enable_content_provider_analysis': self.enable_content_provider_analysis,
            'enable_intent_filter_analysis': self.enable_intent_filter_analysis,
            'enable_file_operation_analysis': self.enable_file_operation_analysis,
            'enable_payload_generation': self.enable_payload_generation,
            'max_payloads_per_vulnerability': self.max_payloads_per_vulnerability,
            'deep_analysis_mode': self.deep_analysis_mode,
            'enable_bypass_detection': self.enable_bypass_detection,
            'confidence_threshold': self.confidence_threshold,
            'enable_false_positive_filtering': self.enable_false_positive_filtering,
            'verbose_logging': self.verbose_logging
        }

@dataclass
class TraversalAnalysisResult:
    """Complete traversal vulnerability analysis results."""
    vulnerabilities: List[TraversalVulnerability]
    content_provider_analyses: List[ContentProviderAnalysis]
    intent_filter_analyses: List[IntentFilterAnalysis]
    file_operation_analyses: List[FileOperationAnalysis]
    overall_risk_score: float
    security_assessment: str
    recommendations: List[str]
    masvs_compliance: List[str]
    cwe_mappings: List[str]
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'content_provider_analyses': [cp.to_dict() for cp in self.content_provider_analyses],
            'intent_filter_analyses': [if_a.to_dict() for if_a in self.intent_filter_analyses],
            'file_operation_analyses': [fo.to_dict() for fo in self.file_operation_analyses],
            'overall_risk_score': self.overall_risk_score,
            'security_assessment': self.security_assessment,
            'recommendations': self.recommendations,
            'masvs_compliance': self.masvs_compliance,
            'cwe_mappings': self.cwe_mappings,
            'analysis_metadata': self.analysis_metadata
        }

class TraversalPatterns:
    """Traversal vulnerability pattern categories."""
    PATH_TRAVERSAL = "path_traversal_patterns"
    DIRECTORY_TRAVERSAL = "directory_traversal_patterns"
    FILE_INCLUSION = "file_inclusion_patterns"
    CONTENT_PROVIDER = "content_provider_patterns"
    INTENT_FILTER = "intent_filter_patterns"
    FILE_OPERATION = "file_operation_patterns"
    URI_HANDLING = "uri_handling_patterns"
    WEBVIEW_TRAVERSAL = "webview_traversal_patterns"

class MAVSTraversalControls:
    """MASVS control mappings for traversal vulnerabilities."""
    PLATFORM_11 = "MSTG-PLATFORM-11"  # WebView configuration
    CODE_8 = "MSTG-CODE-8"           # Memory corruption bugs
    PLATFORM_1 = "MSTG-PLATFORM-1"   # Platform interaction
    PLATFORM_2 = "MSTG-PLATFORM-2"   # Platform permissions
    PLATFORM_6 = "MSTG-PLATFORM-6"   # WebView security
    PLATFORM_7 = "MSTG-PLATFORM-7"   # Content provider security
    PLATFORM_9 = "MSTG-PLATFORM-9"   # Custom URL schemes
    PLATFORM_10 = "MSTG-PLATFORM-10" # WebView protocol handlers

class CWETraversalCategories:
    """Common Weakness Enumeration categories for traversal vulnerabilities."""
    PATH_TRAVERSAL = "CWE-22"         # Path traversal
    DIRECTORY_TRAVERSAL = "CWE-23"    # Directory traversal
    FILE_INCLUSION = "CWE-98"         # File inclusion
    INPUT_VALIDATION = "CWE-20"       # Input validation
    RESOURCE_INJECTION = "CWE-99"     # Resource injection
    URI_HANDLING = "CWE-601"          # URL redirection
    AUTHORIZATION = "CWE-285"         # Authorization bypass
    ACCESS_CONTROL = "CWE-284"        # Access control

@dataclass
class TraversalEvidence:
    """Evidence factors for traversal vulnerability confidence calculation."""
    pattern_reliability: float = 0.0      # Pattern match reliability
    context_quality: float = 0.0          # Context analysis quality
    validation_assessment: float = 0.0    # Input validation assessment
    sanitization_assessment: float = 0.0  # Input sanitization assessment
    payload_effectiveness: float = 0.0    # Payload effectiveness score
    bypass_potential: float = 0.0         # Bypass technique potential
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'pattern_reliability': self.pattern_reliability,
            'context_quality': self.context_quality,
            'validation_assessment': self.validation_assessment,
            'sanitization_assessment': self.sanitization_assessment,
            'payload_effectiveness': self.payload_effectiveness,
            'bypass_potential': self.bypass_potential
        }

@dataclass
class PayloadGenerationResult:
    """Results of payload generation for traversal vulnerabilities."""
    vulnerability_id: str
    generated_payloads: List[str]
    payload_types: List[str]
    effectiveness_scores: List[float]
    bypass_techniques: List[str]
    detection_methods: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'vulnerability_id': self.vulnerability_id,
            'generated_payloads': self.generated_payloads,
            'payload_types': self.payload_types,
            'effectiveness_scores': self.effectiveness_scores,
            'bypass_techniques': self.bypass_techniques,
            'detection_methods': self.detection_methods
        }

@dataclass
class SecurityControlAssessment:
    """Assessment of security controls for traversal vulnerabilities."""
    control_name: str
    implemented: bool
    effectiveness: float
    bypass_methods: List[str]
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'control_name': self.control_name,
            'implemented': self.implemented,
            'effectiveness': self.effectiveness,
            'bypass_methods': self.bypass_methods,
            'recommendations': self.recommendations
        } 