#!/usr/bin/env python3
"""
Data Structures for Improper Platform Usage Analysis Plugin

This module contains all data structures used by the modular improper platform
usage analysis plugin, providing type safety and consistent data handling
across all analysis components.

Features:
- SecurityControlAssessment for security control effectiveness analysis
- RootBypassValidationResult for root detection bypass analysis
- PlatformUsageVulnerability for platform-specific vulnerabilities
- Enhanced type safety and validation
- Rich metadata support for detailed analysis
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Union
from enum import Enum
from datetime import datetime

from core.shared_data_structures.base_vulnerability import (
    BaseVulnerability, 
    VulnerabilityType, 
    VulnerabilitySeverity,
    VulnerabilityContext
)

logger = logging.getLogger(__name__)

class PlatformUsageCategory(Enum):
    """Categories of improper platform usage."""
    EXPORTED_COMPONENTS = "exported_components"
    INTENT_HANDLING = "intent_handling"
    PERMISSION_MISUSE = "permission_misuse"
    CONTENT_PROVIDER_SECURITY = "content_provider_security"
    SERVICE_SECURITY = "service_security"
    BROADCAST_RECEIVER_SECURITY = "broadcast_receiver_security"
    ACTIVITY_SECURITY = "activity_security"
    MANIFEST_CONFIGURATION = "manifest_configuration"

class SecurityControlType(Enum):
    """Types of security controls for platform usage."""
    ROOT_DETECTION = "root_detection"
    ANTI_TAMPERING = "anti_tampering"
    DEBUGGER_DETECTION = "debugger_detection"
    EMULATOR_DETECTION = "emulator_detection"
    HOOK_DETECTION = "hook_detection"
    INTEGRITY_VERIFICATION = "integrity_verification"
    RASP_PROTECTION = "rasp_protection"
    DEVICE_ATTESTATION = "device_attestation"

class ProtectionStrength(Enum):
    """Levels of protection strength."""
    NONE = "none"
    WEAK = "weak"
    MODERATE = "moderate"
    HIGH = "high"  # Added missing HIGH value
    STRONG = "strong"
    VERY_STRONG = "very_strong"
    
    @property
    def score(self) -> float:
        """Convert protection strength to numeric score."""
        strength_scores = {
            ProtectionStrength.NONE: 0.0,
            ProtectionStrength.WEAK: 0.2,
            ProtectionStrength.MODERATE: 0.5,
            ProtectionStrength.HIGH: 0.7,  # Added HIGH score mapping
            ProtectionStrength.STRONG: 0.8,
            ProtectionStrength.VERY_STRONG: 1.0
        }
        return strength_scores[self]

@dataclass
class SecurityControlAssessment:
    """Assessment of security control effectiveness."""
    control_type: str
    effectiveness_score: float
    bypass_resistance: str
    implementation_strength: str
    vulnerability_indicators: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def protection_level(self) -> ProtectionStrength:
        """Determine protection level based on effectiveness score."""
        if self.effectiveness_score >= 0.9:
            return ProtectionStrength.VERY_STRONG
        elif self.effectiveness_score >= 0.7:
            return ProtectionStrength.STRONG
        elif self.effectiveness_score >= 0.5:
            return ProtectionStrength.MODERATE
        elif self.effectiveness_score >= 0.2:
            return ProtectionStrength.WEAK
        else:
            return ProtectionStrength.NONE
    
    @property
    def is_effective(self) -> bool:
        """Check if the security control is considered effective."""
        return self.effectiveness_score >= 0.6

@dataclass
class RootBypassValidationResult:
    """Result of root bypass validation analysis."""
    bypass_detection_strength: str
    anti_tampering_effectiveness: float
    rasp_implementation_quality: str
    integrity_verification_strength: str
    device_attestation_coverage: str
    security_control_assessments: List[SecurityControlAssessment] = field(default_factory=list)
    validation_findings: List[Dict[str, Any]] = field(default_factory=list)
    bypass_techniques_detected: List[str] = field(default_factory=list)  # Added missing field
    overall_protection_score: float = 0.0
    analysis_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    @property
    def effective_controls_count(self) -> int:
        """Get number of effective security controls."""
        return sum(1 for control in self.security_control_assessments if control.is_effective)
    
    @property
    def total_controls_count(self) -> int:
        """Get total number of security controls assessed."""
        return len(self.security_control_assessments)
    
    @property
    def protection_coverage(self) -> float:
        """Calculate protection coverage percentage."""
        if self.total_controls_count == 0:
            return 0.0
        return self.effective_controls_count / self.total_controls_count

@dataclass
class PlatformUsageVulnerability(BaseVulnerability):
    """
    Platform usage vulnerability with enhanced metadata.
    Extends BaseVulnerability with platform-specific fields.
    """
    platform_category: Optional[PlatformUsageCategory] = None
    component_type: str = ""
    exported_status: bool = False
    permission_level: str = ""
    intent_filters: List[str] = field(default_factory=list)
    data_exposure_risk: str = ""
    bypass_techniques: List[str] = field(default_factory=list)
    masvs_controls: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Initialize platform-specific vulnerability data."""
        super().__post_init__()
        
        # Set vulnerability type to platform if not specified
        if self.vulnerability_type == VulnerabilityType.GENERAL_SECURITY:
            self.vulnerability_type = VulnerabilityType.PLATFORM_MISUSE
        
        # Add platform-specific tags
        self.add_tag("platform_usage")
        if self.platform_category:
            self.add_tag(f"category:{self.platform_category.value}")
        if self.component_type:
            self.add_tag(f"component:{self.component_type}")

    @property
    def is_high_risk_component(self) -> bool:
        """Check if this involves a high-risk component type."""
        high_risk_components = {
            "ContentProvider", "Service", "BroadcastReceiver", "Activity"
        }
        return self.component_type in high_risk_components

    @property
    def exposure_risk_score(self) -> float:
        """Calculate exposure risk score based on multiple factors."""
        base_risk = self.risk_score
        
        # Increase risk for exported components
        if self.exported_status:
            base_risk *= 1.4
        
        # Increase risk for high-risk components
        if self.is_high_risk_component:
            base_risk *= 1.3
        
        # Increase risk based on permission level
        if "dangerous" in self.permission_level.lower():
            base_risk *= 1.5
        
        return min(1.0, base_risk)

    def add_intent_filter(self, intent_filter: str) -> None:
        """Add an intent filter to this vulnerability."""
        if intent_filter and intent_filter not in self.intent_filters:
            self.intent_filters.append(intent_filter)

    def add_bypass_technique(self, technique: str) -> None:
        """Add a bypass technique to this vulnerability."""
        if technique and technique not in self.bypass_techniques:
            self.bypass_techniques.append(technique)

    def add_masvs_control(self, control: str) -> None:
        """Add a MASVS control mapping."""
        if control and control not in self.masvs_controls:
            self.masvs_controls.append(control)

class ComponentAnalysisResult:
    """Result of component analysis."""
    
    def __init__(self, component_name: str = None, component_type: str = None, 
                 exported: bool = False, permissions: List[str] = None, 
                 intent_filters: List[str] = None):
        self.component_name = component_name
        self.component_type = component_type
        self.exported = exported
        self.permissions = permissions or []
        self.intent_filters = intent_filters or []
        self.analyzed_components = []
        self.vulnerabilities = []
        self.security_score = 0.0
        self.risk_level = "UNKNOWN"  # Added missing risk_level attribute
        self.analysis_metadata = {}
        
    def add_vulnerability(self, vulnerability):
        """Add a vulnerability to the results."""
        self.vulnerabilities.append(vulnerability)
        # Automatically update risk level when vulnerabilities are added
        self.calculate_risk_level()
        
    def calculate_security_score(self) -> float:
        """Calculate overall security score."""
        if not self.vulnerabilities:
            return 1.0
        
        # Simple scoring based on severity
        critical_count = sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL)
        high_count = sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.HIGH)
        medium_count = sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.MEDIUM)
        
        # Weight-based scoring
        total_weight = critical_count * 1.0 + high_count * 0.7 + medium_count * 0.4
        max_score = 1.0  # Baseline
        
        self.security_score = max(0.0, max_score - (total_weight * 0.1))
        return self.security_score
    
    def calculate_risk_level(self) -> str:
        """Calculate and update risk level based on vulnerabilities."""
        if not self.vulnerabilities:
            self.risk_level = "LOW"
            return self.risk_level
        
        # Check for critical and high severity vulnerabilities
        has_critical = any(v.severity == VulnerabilitySeverity.CRITICAL for v in self.vulnerabilities)
        has_high = any(v.severity == VulnerabilitySeverity.HIGH for v in self.vulnerabilities)
        has_medium = any(v.severity == VulnerabilitySeverity.MEDIUM for v in self.vulnerabilities)
        
        if has_critical:
            self.risk_level = "CRITICAL"
        elif has_high:
            self.risk_level = "HIGH" 
        elif has_medium:
            self.risk_level = "MEDIUM"
        else:
            self.risk_level = "LOW"
            
        return self.risk_level

@dataclass
class PlatformUsageAnalysisResult:
    """Result of comprehensive platform usage analysis."""
    
    # Constructor parameters 
    target_name: str = "Unknown"
    analysis_timestamp: str = ""
    analysis_duration: float = 0.0
    
    # Basic counts
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    
    # Analysis components
    vulnerabilities: List[PlatformUsageVulnerability] = field(default_factory=list)
    component_analysis: Optional[ComponentAnalysisResult] = None
    manifest_analysis: Optional[ManifestAnalysisResult] = None
    
    # Scoring and assessment
    overall_security_score: float = 0.0
    security_grade: str = "UNKNOWN"
    risk_level: str = "UNKNOWN"
    
    # Enhanced analysis results  
    security_assessments: List[SecurityControlAssessment] = field(default_factory=list)
    bypass_analysis: Dict[str, Any] = field(default_factory=dict)
    
    # Compliance and recommendations
    masvs_compliance: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Metadata
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0
    
    def add_vulnerability(self, vulnerability: PlatformUsageVulnerability):
        """Add a vulnerability and update counts."""
        self.vulnerabilities.append(vulnerability)
        self.total_vulnerabilities += 1
        
        # Update severity counts
        if vulnerability.severity == VulnerabilitySeverity.CRITICAL:
            self.critical_vulnerabilities += 1
        elif vulnerability.severity == VulnerabilitySeverity.HIGH:
            self.high_vulnerabilities += 1
        elif vulnerability.severity == VulnerabilitySeverity.MEDIUM:
            self.medium_vulnerabilities += 1
        elif vulnerability.severity == VulnerabilitySeverity.LOW:
            self.low_vulnerabilities += 1
    
    def calculate_security_score(self) -> float:
        """Calculate overall security score based on findings."""
        if self.total_vulnerabilities == 0:
            self.overall_security_score = 1.0
            return self.overall_security_score
        
        # Weight-based scoring
        critical_weight = self.critical_vulnerabilities * 1.0
        high_weight = self.high_vulnerabilities * 0.7
        medium_weight = self.medium_vulnerabilities * 0.4
        low_weight = self.low_vulnerabilities * 0.2
        
        total_weight = critical_weight + high_weight + medium_weight + low_weight
        max_score = 1.0
        
        # Calculate score (higher weight = lower score)
        self.overall_security_score = max(0.0, max_score - (total_weight * 0.1))
        return self.overall_security_score
    
    def calculate_overall_score(self) -> float:
        """Calculate overall security score - alias for calculate_security_score for compatibility."""
        return self.calculate_security_score()

@dataclass
class ManifestAnalysisResult:
    """Result of manifest security analysis."""
    components_analyzed: int = 0
    exported_components: int = 0
    dangerous_permissions: List[str] = field(default_factory=list)
    custom_permissions: List[str] = field(default_factory=list)
    intent_filters_analyzed: int = 0
    security_issues: List[PlatformUsageVulnerability] = field(default_factory=list)
    component_results: List[ComponentAnalysisResult] = field(default_factory=list)
    overall_security_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def export_ratio(self) -> float:
        """Calculate ratio of exported components."""
        if self.components_analyzed == 0:
            return 0.0
        return self.exported_components / self.components_analyzed
    
    @property
    def total_vulnerabilities(self) -> int:
        """Get total number of vulnerabilities found."""
        return len(self.security_issues)
    
    @property
    def high_risk_components(self) -> List[ComponentAnalysisResult]:
        """Get components with high or critical risk."""
        return [
            comp for comp in self.component_results
            if comp.risk_level in ["HIGH", "CRITICAL"]
        ]
    
    @property
    def security_grade(self) -> str:
        """Get overall security grade (A-F) based on security score."""
        if self.overall_security_score >= 0.9:
            return "A"
        elif self.overall_security_score >= 0.8:
            return "B"
        elif self.overall_security_score >= 0.7:
            return "C"
        elif self.overall_security_score >= 0.6:
            return "D"
        else:
            return "F"
    
    def add_security_issue(self, issue: PlatformUsageVulnerability) -> None:
        """Add a vulnerability to the analysis result."""
        self.security_issues.append(issue)
    
    def calculate_overall_score(self) -> None:
        """Calculate the overall security score based on all analysis components."""
        scores = []
        
        # Manifest analysis score
        if self.manifest_analysis:
            scores.append(self.manifest_analysis.overall_security_score)
        
        # Root bypass validation score
        if self.root_bypass_validation:
            scores.append(self.root_bypass_validation.overall_protection_score)
        
        # Calculate weighted average
        if scores:
            self.overall_security_score = sum(scores) / len(scores)
            
            # Apply penalty for critical vulnerabilities
            critical_penalty = self.critical_vulnerabilities * 0.1
            self.overall_security_score = max(0.0, self.overall_security_score - critical_penalty)
        else:
            self.overall_security_score = 0.0 