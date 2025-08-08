"""
Enhanced Manifest Analysis - Data Structures

This module provides comprehensive data structures for AndroidManifest.xml analysis
including package information, security flags, components, permissions, and risk assessment.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import json
import datetime

class RiskLevel(Enum):
    """Risk levels for security assessment with orderable values."""
    INFO = 1
    LOW = 2  
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    
    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented
    
    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented
    
    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented
    
    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented
    
    @property
    def name(self):
        """Return the string name for display purposes."""
        names = {1: "INFO", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}
        return names[self.value]

class SecurityStatus(Enum):
    """Overall security status levels."""
    SECURE = "SECURE"
    NEEDS_ATTENTION = "NEEDS_ATTENTION"
    HIGH_RISK = "HIGH_RISK"
    UNKNOWN = "UNKNOWN"

class ComponentType(Enum):
    """Types of Android components."""
    ACTIVITY = "activities"
    SERVICE = "services"
    RECEIVER = "receivers"
    PROVIDER = "providers"

class PermissionProtectionLevel(Enum):
    """Android permission protection levels."""
    NORMAL = "normal"
    DANGEROUS = "dangerous"
    SIGNATURE = "signature"
    SIGNATURE_OR_SYSTEM = "signatureOrSystem"
    UNKNOWN = "unknown"

class AnalysisMethod(Enum):
    """Methods used for manifest analysis."""
    STATIC_MANIFEST = "static_manifest"
    ENHANCED_PARSING = "enhanced_parsing"
    HYBRID = "hybrid"

@dataclass
class PackageInfo:
    """Package information extracted from AndroidManifest.xml."""
    package_name: str
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    target_sdk: Optional[str] = None
    min_sdk: Optional[str] = None
    compile_sdk: Optional[str] = None
    shared_user_id: Optional[str] = None
    install_location: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'package_name': self.package_name,
            'version_name': self.version_name,
            'version_code': self.version_code,
            'target_sdk': self.target_sdk,
            'min_sdk': self.min_sdk,
            'compile_sdk': self.compile_sdk,
            'shared_user_id': self.shared_user_id,
            'install_location': self.install_location
        }

@dataclass
class SecurityFlags:
    """Security-related flags and configurations."""
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext_traffic: Optional[bool] = None
    test_only: bool = False
    extract_native_libs: bool = True
    allow_native_heap_pointer_tagging: bool = False
    network_security_config: Optional[str] = None
    backup_agent: Optional[str] = None
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'debuggable': self.debuggable,
            'allow_backup': self.allow_backup,
            'uses_cleartext_traffic': self.uses_cleartext_traffic,
            'test_only': self.test_only,
            'extract_native_libs': self.extract_native_libs,
            'allow_native_heap_pointer_tagging': self.allow_native_heap_pointer_tagging,
            'network_security_config': self.network_security_config,
            'backup_agent': self.backup_agent,
            'issues': self.issues,
            'recommendations': self.recommendations
        }

@dataclass
class IntentFilter:
    """Intent filter information."""
    actions: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    data_schemes: List[str] = field(default_factory=list)
    data_authorities: List[str] = field(default_factory=list)
    data_paths: List[str] = field(default_factory=list)
    data_mime_types: List[str] = field(default_factory=list)
    priority: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'actions': self.actions,
            'categories': self.categories,
            'data_schemes': self.data_schemes,
            'data_authorities': self.data_authorities,
            'data_paths': self.data_paths,
            'data_mime_types': self.data_mime_types,
            'priority': self.priority
        }

@dataclass
class AndroidComponent:
    """Android component (Activity, Service, Receiver, Provider) information."""
    name: str
    component_type: ComponentType
    exported: bool
    enabled: bool = True
    permission: Optional[str] = None
    read_permission: Optional[str] = None
    write_permission: Optional[str] = None
    grant_uri_permissions: bool = False
    task_affinity: Optional[str] = None
    launch_mode: Optional[str] = None
    intent_filters: List[IntentFilter] = field(default_factory=list)
    meta_data: Dict[str, str] = field(default_factory=dict)
    security_issues: List[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'component_type': self.component_type.value,
            'exported': self.exported,
            'enabled': self.enabled,
            'permission': self.permission,
            'read_permission': self.read_permission,
            'write_permission': self.write_permission,
            'grant_uri_permissions': self.grant_uri_permissions,
            'task_affinity': self.task_affinity,
            'launch_mode': self.launch_mode,
            'intent_filters': [f.to_dict() for f in self.intent_filters],
            'meta_data': self.meta_data,
            'security_issues': self.security_issues,
            'risk_level': self.risk_level.value,
            'confidence': self.confidence
        }

@dataclass
class Permission:
    """Permission information."""
    name: str
    protection_level: PermissionProtectionLevel
    description: Optional[str] = None
    permission_group: Optional[str] = None
    label: Optional[str] = None
    icon: Optional[str] = None
    is_dangerous: bool = False
    is_custom: bool = False
    max_sdk_version: Optional[int] = None
    uses_feature: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'protection_level': self.protection_level.value,
            'description': self.description,
            'permission_group': self.permission_group,
            'label': self.label,
            'icon': self.icon,
            'is_dangerous': self.is_dangerous,
            'is_custom': self.is_custom,
            'max_sdk_version': self.max_sdk_version,
            'uses_feature': self.uses_feature
        }

@dataclass
class PermissionAnalysis:
    """Permission analysis results."""
    requested_permissions: List[Permission] = field(default_factory=list)
    defined_permissions: List[Permission] = field(default_factory=list)
    dangerous_permissions: List[Permission] = field(default_factory=list)
    custom_permissions: List[Permission] = field(default_factory=list)
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'requested_permissions': [p.to_dict() for p in self.requested_permissions],
            'defined_permissions': [p.to_dict() for p in self.defined_permissions],
            'dangerous_permissions': [p.to_dict() for p in self.dangerous_permissions],
            'custom_permissions': [p.to_dict() for p in self.custom_permissions],
            'risk_assessment': self.risk_assessment,
            'recommendations': self.recommendations
        }

@dataclass
class ComponentAnalysis:
    """Component analysis results."""
    activities: List[AndroidComponent] = field(default_factory=list)
    services: List[AndroidComponent] = field(default_factory=list)
    receivers: List[AndroidComponent] = field(default_factory=list)
    providers: List[AndroidComponent] = field(default_factory=list)
    exported_components: List[AndroidComponent] = field(default_factory=list)
    total_components: int = 0
    total_exported: int = 0
    critical_components: int = 0
    high_risk_components: int = 0
    
    def __post_init__(self):
        """Calculate totals after initialization."""
        all_components = self.activities + self.services + self.receivers + self.providers
        self.total_components = len(all_components)
        self.exported_components = [c for c in all_components if c.exported]
        self.total_exported = len(self.exported_components)
        self.critical_components = sum(1 for c in all_components if c.risk_level == RiskLevel.CRITICAL)
        self.high_risk_components = sum(1 for c in all_components if c.risk_level == RiskLevel.HIGH)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'activities': [c.to_dict() for c in self.activities],
            'services': [c.to_dict() for c in self.services],
            'receivers': [c.to_dict() for c in self.receivers],
            'providers': [c.to_dict() for c in self.providers],
            'exported_components': [c.to_dict() for c in self.exported_components],
            'total_components': self.total_components,
            'total_exported': self.total_exported,
            'critical_components': self.critical_components,
            'high_risk_components': self.high_risk_components
        }

@dataclass
class ManifestSecurityFinding:
    """Security finding from manifest analysis."""
    title: str
    description: str
    severity: RiskLevel
    confidence: float
    location: str
    method: AnalysisMethod
    evidence: str
    id: Optional[str] = None  # Added missing id parameter
    component_name: Optional[str] = None
    permission_name: Optional[str] = None
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
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'location': self.location,
            'method': self.method.value,
            'evidence': self.evidence,
            'component_name': self.component_name,
            'permission_name': self.permission_name,
            'recommendations': self.recommendations,
            'references': self.references,
            'cwe_ids': self.cwe_ids,
            'owasp_category': self.owasp_category,
            'masvs_control': self.masvs_control,
            'detected_at': self.detected_at
        }

@dataclass
class ManifestRiskAssessment:
    """Overall risk assessment for manifest analysis."""
    overall_risk: RiskLevel
    security_status: SecurityStatus
    risk_score: float
    risk_factors: List[str] = field(default_factory=list)
    priority_actions: List[str] = field(default_factory=list)
    security_flags_risk: RiskLevel = RiskLevel.LOW
    components_risk: RiskLevel = RiskLevel.LOW
    permissions_risk: RiskLevel = RiskLevel.LOW
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    
    def __post_init__(self):
        """Calculate total findings after initialization."""
        self.total_findings = (
            self.critical_findings + self.high_findings +
            self.medium_findings + self.low_findings
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'overall_risk': self.overall_risk.value,
            'security_status': self.security_status.value,
            'risk_score': self.risk_score,
            'risk_factors': self.risk_factors,
            'priority_actions': self.priority_actions,
            'security_flags_risk': self.security_flags_risk.value,
            'components_risk': self.components_risk.value,
            'permissions_risk': self.permissions_risk.value,
            'total_findings': self.total_findings,
            'critical_findings': self.critical_findings,
            'high_findings': self.high_findings,
            'medium_findings': self.medium_findings,
            'low_findings': self.low_findings
        }

@dataclass
class ManifestAnalysisContext:
    """Context information for manifest analysis."""
    apk_path: str
    manifest_path: str
    package_name: Optional[str] = None
    analysis_timestamp: Optional[str] = None
    analyzer_version: str = "2.0.0"
    
    def __post_init__(self):
        """Set default timestamp if not provided."""
        if not self.analysis_timestamp:
            self.analysis_timestamp = datetime.datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'apk_path': self.apk_path,
            'manifest_path': self.manifest_path,
            'package_name': self.package_name,
            'analysis_timestamp': self.analysis_timestamp,
            'analyzer_version': self.analyzer_version
        }

@dataclass
class ManifestAnalysisResult:
    """Comprehensive manifest analysis result."""
    context: ManifestAnalysisContext
    package_info: Optional[PackageInfo] = None
    security_flags: Optional[SecurityFlags] = None
    component_analysis: Optional[ComponentAnalysis] = None
    permission_analysis: Optional[PermissionAnalysis] = None
    security_findings: List[ManifestSecurityFinding] = field(default_factory=list)
    risk_assessment: Optional[ManifestRiskAssessment] = None
    analysis_summary: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'context': self.context.to_dict(),
            'package_info': self.package_info.to_dict() if self.package_info else None,
            'security_flags': self.security_flags.to_dict() if self.security_flags else None,
            'component_analysis': self.component_analysis.to_dict() if self.component_analysis else None,
            'permission_analysis': self.permission_analysis.to_dict() if self.permission_analysis else None,
            'security_findings': [f.to_dict() for f in self.security_findings],
            'risk_assessment': self.risk_assessment.to_dict() if self.risk_assessment else None,
            'analysis_summary': self.analysis_summary
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

@dataclass
class ManifestAnalysisConfiguration:
    """Configuration for manifest analysis."""
    enable_package_analysis: bool = True
    enable_security_flags_analysis: bool = True
    enable_component_analysis: bool = True
    enable_permission_analysis: bool = True
    enable_risk_assessment: bool = True
    confidence_threshold: float = 0.7
    detailed_component_analysis: bool = True
    analyze_intent_filters: bool = True
    check_dangerous_permissions: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'enable_package_analysis': self.enable_package_analysis,
            'enable_security_flags_analysis': self.enable_security_flags_analysis,
            'enable_component_analysis': self.enable_component_analysis,
            'enable_permission_analysis': self.enable_permission_analysis,
            'enable_risk_assessment': self.enable_risk_assessment,
            'confidence_threshold': self.confidence_threshold,
            'detailed_component_analysis': self.detailed_component_analysis,
            'analyze_intent_filters': self.analyze_intent_filters,
            'check_dangerous_permissions': self.check_dangerous_permissions
        }

# Utility functions for creating standard objects
def create_security_finding(
    title: str,
    description: str,
    severity: RiskLevel,
    confidence: float,
    location: str,
    evidence: str,
    masvs_control: str,
    **kwargs
) -> ManifestSecurityFinding:
    """Create a standard security finding."""
    return ManifestSecurityFinding(
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        location=location,
        method=AnalysisMethod.STATIC_MANIFEST,
        evidence=evidence,
        masvs_control=masvs_control,
        **kwargs
    )

def create_android_component(
    name: str,
    component_type: ComponentType,
    exported: bool,
    **kwargs
) -> AndroidComponent:
    """Create a standard Android component."""
    return AndroidComponent(
        name=name,
        component_type=component_type,
        exported=exported,
        **kwargs
    )

def create_permission(
    name: str,
    protection_level: PermissionProtectionLevel,
    **kwargs
) -> Permission:
    """Create a standard permission."""
    return Permission(
        name=name,
        protection_level=protection_level,
        **kwargs
    ) 