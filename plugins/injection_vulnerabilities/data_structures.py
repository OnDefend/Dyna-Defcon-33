"""
Injection Vulnerabilities Plugin - Data Structures

This module provides comprehensive data structures for injection vulnerability analysis
including SQL injection findings, provider analysis, and risk assessment.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import json
import datetime

class VulnerabilityType(Enum):
    """Types of injection vulnerabilities."""
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    XPATH_INJECTION = "xpath_injection"
    LDAP_INJECTION = "ldap_injection"
    GENERIC_INJECTION = "generic_injection"

class SeverityLevel(Enum):
    """Severity levels for injection vulnerabilities."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class RiskLevel(Enum):
    """Risk levels for vulnerability assessment."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

class AnalysisMethod(Enum):
    """Methods used for vulnerability analysis."""
    DYNAMIC_DROZER = "dynamic_drozer"
    STATIC_MANIFEST = "static_manifest"
    STATIC_CODE = "static_code"
    STATIC_PATTERN = "static_pattern"
    HYBRID = "hybrid"

class ProviderSecurityLevel(Enum):
    """Security levels for content providers."""
    SECURE = "secure"
    EXPORTED_PROTECTED = "exported_protected"
    EXPORTED_UNPROTECTED = "exported_unprotected"
    VULNERABLE = "vulnerable"

@dataclass
class InjectionVulnerability:
    """Represents an injection vulnerability finding."""
    vulnerability_type: VulnerabilityType
    title: str
    description: str
    severity: SeverityLevel
    confidence: float
    location: str
    method: AnalysisMethod
    evidence: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    owasp_category: Optional[str] = None
    masvs_control: Optional[str] = None
    detected_at: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization to set detection timestamp."""
        if not self.detected_at:
            self.detected_at = datetime.datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'vulnerability_type': self.vulnerability_type.value,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'location': self.location,
            'method': self.method.value,
            'evidence': self.evidence,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'recommendations': self.recommendations,
            'references': self.references,
            'cwe_ids': self.cwe_ids,
            'owasp_category': self.owasp_category,
            'masvs_control': self.masvs_control,
            'detected_at': self.detected_at
        }

@dataclass
class ContentProviderAnalysis:
    """Represents content provider security analysis."""
    authority: str
    name: str
    exported: bool
    security_level: ProviderSecurityLevel
    permissions: List[str] = field(default_factory=list)
    uri_patterns: List[str] = field(default_factory=list)
    vulnerabilities: List[InjectionVulnerability] = field(default_factory=list)
    grant_uri_permissions: bool = False
    read_permission: Optional[str] = None
    write_permission: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'authority': self.authority,
            'name': self.name,
            'exported': self.exported,
            'security_level': self.security_level.value,
            'permissions': self.permissions,
            'uri_patterns': self.uri_patterns,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'grant_uri_permissions': self.grant_uri_permissions,
            'read_permission': self.read_permission,
            'write_permission': self.write_permission
        }

@dataclass
class SQLPatternAnalysis:
    """Represents SQL pattern analysis results."""
    pattern_type: str
    description: str
    risk_level: RiskLevel
    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'pattern_type': self.pattern_type,
            'description': self.description,
            'risk_level': self.risk_level.value,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'confidence': self.confidence
        }

@dataclass
class DynamicAnalysisResult:
    """Represents dynamic analysis results from Drozer."""
    command_executed: str
    execution_time: float
    success: bool
    raw_output: str
    vulnerabilities_found: List[InjectionVulnerability] = field(default_factory=list)
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'command_executed': self.command_executed,
            'execution_time': self.execution_time,
            'success': self.success,
            'raw_output': self.raw_output,
            'vulnerabilities_found': [v.to_dict() for v in self.vulnerabilities_found],
            'error_message': self.error_message
        }

@dataclass
class StaticAnalysisResult:
    """Represents static analysis results."""
    manifest_analysis: List[ContentProviderAnalysis] = field(default_factory=list)
    code_patterns: List[SQLPatternAnalysis] = field(default_factory=list)
    total_files_analyzed: int = 0
    analysis_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'manifest_analysis': [m.to_dict() for m in self.manifest_analysis],
            'code_patterns': [c.to_dict() for c in self.code_patterns],
            'total_files_analyzed': self.total_files_analyzed,
            'analysis_time': self.analysis_time
        }

@dataclass
class RiskAssessment:
    """Represents overall risk assessment for injection vulnerabilities."""
    overall_risk: RiskLevel
    risk_score: float
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    exported_providers: int = 0
    vulnerable_providers: int = 0
    risk_factors: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Calculate total vulnerabilities after initialization."""
        self.total_vulnerabilities = (
            self.critical_vulnerabilities + self.high_vulnerabilities +
            self.medium_vulnerabilities + self.low_vulnerabilities
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'overall_risk': self.overall_risk.value,
            'risk_score': self.risk_score,
            'total_vulnerabilities': self.total_vulnerabilities,
            'critical_vulnerabilities': self.critical_vulnerabilities,
            'high_vulnerabilities': self.high_vulnerabilities,
            'medium_vulnerabilities': self.medium_vulnerabilities,
            'low_vulnerabilities': self.low_vulnerabilities,
            'exported_providers': self.exported_providers,
            'vulnerable_providers': self.vulnerable_providers,
            'risk_factors': self.risk_factors,
            'mitigations': self.mitigations
        }

@dataclass
class AnalysisContext:
    """Context information for injection vulnerability analysis."""
    apk_path: str
    package_name: str
    drozer_available: bool = False
    analysis_timestamp: Optional[str] = None
    analyzer_version: str = "2.0.0"
    timeout_seconds: int = 30
    max_files_to_analyze: int = 1000
    
    def __post_init__(self):
        """Set default timestamp if not provided."""
        if not self.analysis_timestamp:
            self.analysis_timestamp = datetime.datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'apk_path': self.apk_path,
            'package_name': self.package_name,
            'drozer_available': self.drozer_available,
            'analysis_timestamp': self.analysis_timestamp,
            'analyzer_version': self.analyzer_version,
            'timeout_seconds': self.timeout_seconds,
            'max_files_to_analyze': self.max_files_to_analyze
        }

@dataclass
class InjectionVulnerabilityResult:
    """Comprehensive injection vulnerability analysis result."""
    context: AnalysisContext
    dynamic_analysis: Optional[DynamicAnalysisResult] = None
    static_analysis: Optional[StaticAnalysisResult] = None
    vulnerabilities: List[InjectionVulnerability] = field(default_factory=list)
    risk_assessment: Optional[RiskAssessment] = None
    analysis_summary: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'context': self.context.to_dict(),
            'dynamic_analysis': self.dynamic_analysis.to_dict() if self.dynamic_analysis else None,
            'static_analysis': self.static_analysis.to_dict() if self.static_analysis else None,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'risk_assessment': self.risk_assessment.to_dict() if self.risk_assessment else None,
            'analysis_summary': self.analysis_summary
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

@dataclass
class InjectionAnalysisConfiguration:
    """Configuration for injection vulnerability analysis."""
    enable_dynamic_analysis: bool = True
    enable_static_analysis: bool = True
    enable_manifest_analysis: bool = True
    enable_code_analysis: bool = True
    drozer_timeout_seconds: int = 30
    max_files_to_analyze: int = 1000
    confidence_threshold: float = 0.7
    pattern_sensitivity: str = "medium"  # low, medium, high
    exclude_test_files: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'enable_dynamic_analysis': self.enable_dynamic_analysis,
            'enable_static_analysis': self.enable_static_analysis,
            'enable_manifest_analysis': self.enable_manifest_analysis,
            'enable_code_analysis': self.enable_code_analysis,
            'drozer_timeout_seconds': self.drozer_timeout_seconds,
            'max_files_to_analyze': self.max_files_to_analyze,
            'confidence_threshold': self.confidence_threshold,
            'pattern_sensitivity': self.pattern_sensitivity,
            'exclude_test_files': self.exclude_test_files
        }

# Utility functions
def create_sql_injection_vulnerability(
    description: str,
    severity: SeverityLevel,
    confidence: float,
    location: str,
    method: AnalysisMethod,
    evidence: str,
    **kwargs
) -> InjectionVulnerability:
    """Create a SQL injection vulnerability with standard attributes."""
    return InjectionVulnerability(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        title="SQL Injection Vulnerability",
        description=description,
        severity=severity,
        confidence=confidence,
        location=location,
        method=method,
        evidence=evidence,
        cwe_ids=["CWE-89"],
        owasp_category="A03:2021 - Injection",
        masvs_control="MSTG-PLATFORM-2",
        recommendations=[
            "Use parameterized queries or prepared statements",
            "Validate and sanitize all user inputs",
            "Implement proper access controls for content providers",
            "Use allowlists for acceptable input values"
        ],
        references=[
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cwe.mitre.org/data/definitions/89.html"
        ],
        **kwargs
    )

def create_provider_analysis(
    authority: str,
    name: str,
    exported: bool,
    **kwargs
) -> ContentProviderAnalysis:
    """Create a content provider analysis with standard attributes."""
    if exported:
        if kwargs.get('permissions'):
            security_level = ProviderSecurityLevel.EXPORTED_PROTECTED
        else:
            security_level = ProviderSecurityLevel.EXPORTED_UNPROTECTED
    else:
        security_level = ProviderSecurityLevel.SECURE
    
    return ContentProviderAnalysis(
        authority=authority,
        name=name,
        exported=exported,
        security_level=security_level,
        **kwargs
    ) 