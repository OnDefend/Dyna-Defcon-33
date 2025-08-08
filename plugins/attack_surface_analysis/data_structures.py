"""
Attack Surface Analysis Data Structures

This module contains all data structures, dataclasses, and enums used
throughout the attack surface analysis plugin components.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Set, Optional
from enum import Enum
from datetime import datetime

class ComponentType(Enum):
    """Component types in Android applications."""
    ACTIVITY = "activity"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"

class SeverityLevel(Enum):
    """Severity levels for attack vectors."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ExposureLevel(Enum):
    """Component exposure levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    MINIMAL = "Minimal"

class AttackComplexity(Enum):
    """Attack complexity levels."""
    TRIVIAL = "trivial"
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    VERY_COMPLEX = "very_complex"

class PermissionLevel(Enum):
    """Android permission protection levels."""
    SIGNATURE = "signature"
    DANGEROUS = "dangerous"
    NORMAL = "normal"
    NONE = "none"

class PatternType:
    """Attack surface pattern types for configuration."""
    DANGEROUS_ACTIONS = "dangerous_actions"
    SENSITIVE_SCHEMES = "sensitive_schemes"
    HIGH_RISK_PATTERNS = "high_risk_patterns"
    UNPROTECTED_COMPONENTS = "unprotected_components"
    IPC_VULNERABILITIES = "ipc_vulnerabilities"

@dataclass
class AttackSurfaceVulnerability:
    """Represents an attack surface vulnerability finding."""
    
    # Core identification (required fields)
    vulnerability_id: str
    title: str
    description: str
    severity: SeverityLevel
    confidence: float
    location: str
    evidence: str
    component_type: ComponentType
    component_name: str
    attack_vector: str
    exposure_level: ExposureLevel
    
    # Optional fields with defaults
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    attack_methods: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    cwe_id: str = ""
    masvs_refs: List[str] = field(default_factory=list)
    risk_score: int = 0
    exploitability: AttackComplexity = AttackComplexity.MODERATE
    discovered_at: datetime = field(default_factory=datetime.now)
    tags: Set[str] = field(default_factory=set)
    
    def __post_init__(self):
        """Validate vulnerability data."""
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")
        
        if not (0 <= self.risk_score <= 100):
            self.risk_score = self._calculate_risk_score()
    
    def _calculate_risk_score(self) -> int:
        """Calculate risk score based on severity, confidence, and exposure."""
        severity_scores = {
            SeverityLevel.CRITICAL: 90,
            SeverityLevel.HIGH: 70,
            SeverityLevel.MEDIUM: 50,
            SeverityLevel.LOW: 30,
            SeverityLevel.INFO: 10
        }
        
        exposure_modifiers = {
            ExposureLevel.CRITICAL: 1.2,
            ExposureLevel.HIGH: 1.0,
            ExposureLevel.MEDIUM: 0.8,
            ExposureLevel.LOW: 0.6,
            ExposureLevel.MINIMAL: 0.4
        }
        
        base_score = severity_scores.get(self.severity, 50)
        exposure_modifier = exposure_modifiers.get(self.exposure_level, 1.0)
        confidence_factor = max(0.5, self.confidence)
        
        risk_score = int(base_score * exposure_modifier * confidence_factor)
        return max(0, min(100, risk_score))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'vulnerability_id': self.vulnerability_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'location': self.location,
            'evidence': self.evidence,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'component_type': self.component_type.value,
            'component_name': self.component_name,
            'attack_vector': self.attack_vector,
            'exposure_level': self.exposure_level.value,
            'attack_methods': self.attack_methods,
            'prerequisites': self.prerequisites,
            'impact': self.impact,
            'remediation': self.remediation,
            'cwe_id': self.cwe_id,
            'masvs_refs': self.masvs_refs,
            'risk_score': self.risk_score,
            'exploitability': self.exploitability.value,
            'discovered_at': self.discovered_at.isoformat(),
            'tags': list(self.tags)
        }

@dataclass
class AttackVector:
    """Represents a specific attack vector in the application."""
    vector_id: str
    name: str
    severity: str
    confidence: float
    description: str
    component_type: str
    component_name: str
    entry_point: str
    attack_methods: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    cwe_id: str = ""
    masvs_refs: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'vector_id': self.vector_id,
            'name': self.name,
            'severity': self.severity,
            'confidence': self.confidence,
            'description': self.description,
            'component_type': self.component_type,
            'component_name': self.component_name,
            'entry_point': self.entry_point,
            'attack_methods': self.attack_methods,
            'prerequisites': self.prerequisites,
            'impact': self.impact,
            'remediation': self.remediation,
            'cwe_id': self.cwe_id,
            'masvs_refs': self.masvs_refs
        }

@dataclass
class ComponentSurface:
    """Represents the attack surface of a single component."""
    component_name: str
    component_type: str
    exported: bool
    permissions: List[str]
    intent_filters: List[Dict[str, Any]]
    attack_vectors: List[AttackVector]
    ipc_interfaces: List[str]
    deep_links: List[str]
    risk_score: int
    exposure_level: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'component_name': self.component_name,
            'component_type': self.component_type,
            'exported': self.exported,
            'permissions': self.permissions,
            'intent_filters': self.intent_filters,
            'attack_vectors': [av.to_dict() for av in self.attack_vectors],
            'ipc_interfaces': self.ipc_interfaces,
            'deep_links': self.deep_links,
            'risk_score': self.risk_score,
            'exposure_level': self.exposure_level
        }

@dataclass
class AttackSurfaceAnalysis:
    """Complete attack surface analysis results."""
    total_components: int
    exported_components: int
    high_risk_components: int
    attack_vectors: List[AttackVector]
    component_surfaces: List[ComponentSurface]
    ipc_channels: Dict[str, List[str]]
    deep_link_schemes: Set[str]
    permission_boundaries: Dict[str, List[str]]
    overall_risk_score: int
    attack_complexity: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'total_components': self.total_components,
            'exported_components': self.exported_components,
            'high_risk_components': self.high_risk_components,
            'attack_vectors': [av.to_dict() for av in self.attack_vectors],
            'component_surfaces': [cs.to_dict() for cs in self.component_surfaces],
            'ipc_channels': self.ipc_channels,
            'deep_link_schemes': list(self.deep_link_schemes),
            'permission_boundaries': self.permission_boundaries,
            'overall_risk_score': self.overall_risk_score,
            'attack_complexity': self.attack_complexity
        }

@dataclass
class AnalysisContext:
    """Context information for attack surface analysis."""
    manifest_path: str
    apk_path: str
    package_name: str
    target_sdk: int = 0
    min_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    features: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'manifest_path': self.manifest_path,
            'apk_path': self.apk_path,
            'package_name': self.package_name,
            'target_sdk': self.target_sdk,
            'min_sdk': self.min_sdk,
            'permissions': self.permissions,
            'features': self.features
        }

@dataclass
class DrozerFinding:
    """Represents a finding from Drozer dynamic analysis."""
    command: str
    output: str
    component_type: str
    severity: str
    confidence: float
    description: str
    remediation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'command': self.command,
            'output': self.output,
            'component_type': self.component_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'description': self.description,
            'remediation': self.remediation
        } 