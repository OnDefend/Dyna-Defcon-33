#!/usr/bin/env python3
"""
Standardized Data Structures for Modularized Anti-Tampering Analysis Plugin

This module provides consistent data structures used across all anti-tampering
analysis modules, ensuring type safety and eliminating duplication of vulnerability
classes throughout the modularized plugin.

Features:
- Standardized anti-tampering vulnerability classes
- Rich metadata support for detailed analysis
- Auto-calculated derived fields and metrics
- MASVS compliance mapping integration
- Type-safe enums for categorization
- confidence integration
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Union
from enum import Enum
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

class AntiTamperingMechanismType(Enum):
    """Types of anti-tampering mechanisms."""
    ROOT_DETECTION = "root_detection"
    DEBUGGER_DETECTION = "debugger_detection"
    CODE_OBFUSCATION = "code_obfuscation"
    ANTI_FRIDA = "anti_frida"
    RASP_MECHANISM = "rasp_mechanism"
    INTEGRITY_CHECK = "integrity_check"
    SIGNATURE_VALIDATION = "signature_validation"
    ENVIRONMENT_CHECK = "environment_check"
    DYNAMIC_ANALYSIS_DETECTION = "dynamic_analysis_detection"
    EMULATOR_DETECTION = "emulator_detection"

class TamperingVulnerabilitySeverity(Enum):
    """Severity levels for anti-tampering vulnerabilities."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class DetectionStrength(Enum):
    """Strength levels for detection mechanisms."""
    NONE = "none"
    WEAK = "weak"
    MODERATE = "moderate"
    HIGH = "high"
    ADVANCED = "advanced"

class BypassResistance(Enum):
    """Resistance levels against bypass attempts."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    EXPERT = "expert"

class AnalysisMethod(Enum):
    """Methods used for anti-tampering analysis."""
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    PATTERN_MATCHING = "pattern_matching"
    BYTECODE_ANALYSIS = "bytecode_analysis"
    MANIFEST_ANALYSIS = "manifest_analysis"
    BINARY_ANALYSIS = "binary_analysis"

@dataclass
class AntiTamperingVulnerability:
    """Represents an anti-tampering security vulnerability finding."""
    
    # Core identification
    vulnerability_id: str
    mechanism_type: AntiTamperingMechanismType
    title: str
    description: str
    
    # Severity and confidence
    severity: TamperingVulnerabilitySeverity
    confidence: float
    
    # Location and evidence
    location: str
    evidence: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    
    # Analysis metadata
    detection_strength: DetectionStrength = DetectionStrength.NONE
    bypass_resistance: BypassResistance = BypassResistance.NONE
    analysis_methods: List[AnalysisMethod] = field(default_factory=list)
    
    # Security context
    attack_vectors: List[str] = field(default_factory=list)
    bypass_techniques: List[str] = field(default_factory=list)
    remediation: str = ""
    
    # Compliance and standards
    masvs_refs: List[str] = field(default_factory=list)
    mstg_refs: List[str] = field(default_factory=list)
    cwe_id: str = ""
    
    # Risk assessment
    risk_score: int = 0
    business_impact: str = ""
    exploitability: str = ""
    
    # Timestamps and metadata
    discovered_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    tags: Set[str] = field(default_factory=set)
    
    def __post_init__(self):
        """Validate vulnerability data and set derived fields."""
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")
        
        if not (0 <= self.risk_score <= 100):
            self.risk_score = self._calculate_risk_score()
        
        # Set default MASVS references based on mechanism type
        if not self.masvs_refs:
            self.masvs_refs = self._get_default_masvs_refs()
    
    def _calculate_risk_score(self) -> int:
        """Calculate risk score based on severity, confidence, and detection strength."""
        severity_scores = {
            TamperingVulnerabilitySeverity.CRITICAL: 90,
            TamperingVulnerabilitySeverity.HIGH: 70,
            TamperingVulnerabilitySeverity.MEDIUM: 50,
            TamperingVulnerabilitySeverity.LOW: 30,
            TamperingVulnerabilitySeverity.INFO: 10
        }
        
        strength_modifiers = {
            DetectionStrength.NONE: 1.5,      # No protection is worse
            DetectionStrength.WEAK: 1.2,
            DetectionStrength.MODERATE: 1.0,
            DetectionStrength.HIGH: 0.8,
            DetectionStrength.ADVANCED: 0.6
        }
        
        base_score = severity_scores.get(self.severity, 50)
        strength_modifier = strength_modifiers.get(self.detection_strength, 1.0)
        confidence_factor = max(0.5, self.confidence)  # Don't penalize too much for low confidence
        
        risk_score = int(base_score * strength_modifier * confidence_factor)
        return max(0, min(100, risk_score))
    
    def _get_default_masvs_refs(self) -> List[str]:
        """Get default MASVS references based on mechanism type."""
        masvs_mapping = {
            AntiTamperingMechanismType.ROOT_DETECTION: ["MSTG-RESILIENCE-1"],
            AntiTamperingMechanismType.DEBUGGER_DETECTION: ["MSTG-RESILIENCE-2"],
            AntiTamperingMechanismType.CODE_OBFUSCATION: ["MSTG-RESILIENCE-9"],
            AntiTamperingMechanismType.ANTI_FRIDA: ["MSTG-RESILIENCE-4"],
            AntiTamperingMechanismType.RASP_MECHANISM: ["MSTG-RESILIENCE-1", "MSTG-RESILIENCE-2"],
            AntiTamperingMechanismType.INTEGRITY_CHECK: ["MSTG-RESILIENCE-3"],
            AntiTamperingMechanismType.SIGNATURE_VALIDATION: ["MSTG-RESILIENCE-3"],
            AntiTamperingMechanismType.ENVIRONMENT_CHECK: ["MSTG-RESILIENCE-1"],
            AntiTamperingMechanismType.DYNAMIC_ANALYSIS_DETECTION: ["MSTG-RESILIENCE-4"],
            AntiTamperingMechanismType.EMULATOR_DETECTION: ["MSTG-RESILIENCE-1"]
        }
        return masvs_mapping.get(self.mechanism_type, [])

@dataclass
class RootDetectionAnalysis:
    """Analysis results for root detection mechanisms."""
    mechanism_count: int = 0
    detection_methods: List[str] = field(default_factory=list)
    strength_assessment: DetectionStrength = DetectionStrength.NONE
    bypass_resistance: BypassResistance = BypassResistance.NONE
    vulnerabilities: List[AntiTamperingVulnerability] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    analysis_coverage: float = 0.0

@dataclass
class DebuggerDetectionAnalysis:
    """Analysis results for debugger detection mechanisms."""
    mechanism_count: int = 0
    detection_methods: List[str] = field(default_factory=list)
    anti_debugging_techniques: List[str] = field(default_factory=list)
    strength_assessment: DetectionStrength = DetectionStrength.NONE
    bypass_resistance: BypassResistance = BypassResistance.NONE
    vulnerabilities: List[AntiTamperingVulnerability] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    analysis_coverage: float = 0.0

@dataclass
class CodeObfuscationAnalysis:
    """Analysis results for code obfuscation mechanisms."""
    obfuscation_level: DetectionStrength = DetectionStrength.NONE
    obfuscation_techniques: List[str] = field(default_factory=list)
    string_obfuscation: bool = False
    control_flow_obfuscation: bool = False
    class_name_obfuscation: bool = False
    method_name_obfuscation: bool = False
    vulnerabilities: List[AntiTamperingVulnerability] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    analysis_coverage: float = 0.0

@dataclass
class AntiFridaAnalysis:
    """Analysis results for anti-Frida mechanisms."""
    mechanism_count: int = 0
    detection_methods: List[str] = field(default_factory=list)
    frida_signature_checks: List[str] = field(default_factory=list)
    strength_assessment: DetectionStrength = DetectionStrength.NONE
    bypass_resistance: BypassResistance = BypassResistance.NONE
    vulnerabilities: List[AntiTamperingVulnerability] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    analysis_coverage: float = 0.0

@dataclass
class RASPAnalysis:
    """Analysis results for Runtime Application Self-Protection mechanisms."""
    rasp_mechanisms: List[str] = field(default_factory=list)
    integrity_checks: List[str] = field(default_factory=list)
    runtime_monitoring: bool = False
    threat_detection: bool = False
    automatic_response: bool = False
    strength_assessment: DetectionStrength = DetectionStrength.NONE
    vulnerabilities: List[AntiTamperingVulnerability] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    analysis_coverage: float = 0.0

@dataclass
class AntiTamperingAnalysisResult:
    """Comprehensive anti-tampering analysis result."""
    
    # Package information
    package_name: str
    analysis_version: str = "2.0.0"
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    
    # Component analysis results
    root_detection: RootDetectionAnalysis = field(default_factory=RootDetectionAnalysis)
    debugger_detection: DebuggerDetectionAnalysis = field(default_factory=DebuggerDetectionAnalysis)
    code_obfuscation: CodeObfuscationAnalysis = field(default_factory=CodeObfuscationAnalysis)
    anti_frida: AntiFridaAnalysis = field(default_factory=AntiFridaAnalysis)
    rasp_analysis: RASPAnalysis = field(default_factory=RASPAnalysis)
    
    # Overall analysis metrics
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    info_vulnerabilities: int = 0
    
    # Resilience scoring
    overall_resilience_score: float = 0.0
    resilience_level: DetectionStrength = DetectionStrength.NONE
    protection_coverage: float = 0.0
    
    # Analysis metadata
    analysis_duration: float = 0.0
    files_analyzed: int = 0
    analysis_methods_used: List[AnalysisMethod] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    
    # Recommendations and compliance
    security_recommendations: List[str] = field(default_factory=list)
    masvs_compliance: Dict[str, bool] = field(default_factory=dict)
    compliance_score: float = 0.0
    
    def __post_init__(self):
        """Calculate derived metrics and validate data."""
        self._calculate_vulnerability_counts()
        self._calculate_resilience_score()
        self._assess_masvs_compliance()
    
    def _calculate_vulnerability_counts(self):
        """Calculate vulnerability counts by severity."""
        all_vulnerabilities = (
            self.root_detection.vulnerabilities +
            self.debugger_detection.vulnerabilities +
            self.code_obfuscation.vulnerabilities +
            self.anti_frida.vulnerabilities +
            self.rasp_analysis.vulnerabilities
        )
        
        self.total_vulnerabilities = len(all_vulnerabilities)
        
        severity_counts = {
            TamperingVulnerabilitySeverity.CRITICAL: 0,
            TamperingVulnerabilitySeverity.HIGH: 0,
            TamperingVulnerabilitySeverity.MEDIUM: 0,
            TamperingVulnerabilitySeverity.LOW: 0,
            TamperingVulnerabilitySeverity.INFO: 0
        }
        
        for vuln in all_vulnerabilities:
            severity_counts[vuln.severity] += 1
        
        self.critical_vulnerabilities = severity_counts[TamperingVulnerabilitySeverity.CRITICAL]
        self.high_vulnerabilities = severity_counts[TamperingVulnerabilitySeverity.HIGH]
        self.medium_vulnerabilities = severity_counts[TamperingVulnerabilitySeverity.MEDIUM]
        self.low_vulnerabilities = severity_counts[TamperingVulnerabilitySeverity.LOW]
        self.info_vulnerabilities = severity_counts[TamperingVulnerabilitySeverity.INFO]
    
    def _calculate_resilience_score(self):
        """Calculate overall resilience score based on all components."""
        component_scores = [
            self.root_detection.confidence_score,
            self.debugger_detection.confidence_score,
            self.code_obfuscation.confidence_score,
            self.anti_frida.confidence_score,
            self.rasp_analysis.confidence_score
        ]
        
        # Weight components based on importance
        weights = [0.25, 0.25, 0.2, 0.15, 0.15]  # Root and debugger detection are most important
        
        weighted_score = sum(score * weight for score, weight in zip(component_scores, weights))
        self.overall_resilience_score = min(100.0, max(0.0, weighted_score))
        
        # Determine resilience level
        if self.overall_resilience_score >= 80:
            self.resilience_level = DetectionStrength.ADVANCED
        elif self.overall_resilience_score >= 60:
            self.resilience_level = DetectionStrength.HIGH
        elif self.overall_resilience_score >= 40:
            self.resilience_level = DetectionStrength.MODERATE
        elif self.overall_resilience_score >= 20:
            self.resilience_level = DetectionStrength.WEAK
        else:
            self.resilience_level = DetectionStrength.NONE
    
    def _assess_masvs_compliance(self):
        """Assess MASVS compliance based on analysis results."""
        masvs_controls = {
            "MSTG-RESILIENCE-1": self.root_detection.confidence_score > 70,
            "MSTG-RESILIENCE-2": self.debugger_detection.confidence_score > 70,
            "MSTG-RESILIENCE-3": len(self.rasp_analysis.integrity_checks) > 0,
            "MSTG-RESILIENCE-4": self.anti_frida.confidence_score > 60,
            "MSTG-RESILIENCE-9": self.code_obfuscation.confidence_score > 50
        }
        
        self.masvs_compliance = masvs_controls
        self.compliance_score = (sum(masvs_controls.values()) / len(masvs_controls)) * 100
    
    def get_all_vulnerabilities(self) -> List[AntiTamperingVulnerability]:
        """Get all vulnerabilities from all components."""
        return (
            self.root_detection.vulnerabilities +
            self.debugger_detection.vulnerabilities +
            self.code_obfuscation.vulnerabilities +
            self.anti_frida.vulnerabilities +
            self.rasp_analysis.vulnerabilities
        )
    
    def get_high_risk_vulnerabilities(self) -> List[AntiTamperingVulnerability]:
        """Get high-risk vulnerabilities (Critical and High severity)."""
        return [
            vuln for vuln in self.get_all_vulnerabilities()
            if vuln.severity in [TamperingVulnerabilitySeverity.CRITICAL, TamperingVulnerabilitySeverity.HIGH]
        ]

@dataclass
class AntiTamperingAnalysisConfig:
    """Configuration for anti-tampering analysis."""
    
    # Analysis scope
    enable_root_detection: bool = True
    enable_debugger_detection: bool = True
    enable_obfuscation_analysis: bool = True
    enable_anti_frida_analysis: bool = True
    enable_rasp_analysis: bool = True
    
    # Performance settings
    max_files_to_analyze: int = 1000
    max_file_size_mb: int = 10
    analysis_timeout_seconds: int = 300
    enable_parallel_processing: bool = True
    max_worker_threads: int = 4
    
    # Detection settings
    pattern_matching_timeout: int = 30
    min_confidence_threshold: float = 0.1
    enable_deep_analysis: bool = True
    enable_dynamic_testing: bool = False
    
    # Output settings
    include_low_confidence_findings: bool = False
    max_vulnerabilities_per_type: int = 50
    include_remediation_guidance: bool = True
    enable_rich_formatting: bool = True
    
    # External configuration
    patterns_config_path: Optional[Path] = None
    custom_patterns: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate configuration parameters."""
        if not (0.0 <= self.min_confidence_threshold <= 1.0):
            raise ValueError("Confidence threshold must be between 0.0 and 1.0")
        
        if self.max_files_to_analyze <= 0:
            raise ValueError("Max files to analyze must be positive")
        
        if self.max_worker_threads <= 0:
            raise ValueError("Max worker threads must be positive")
        
        if self.analysis_timeout_seconds <= 0:
            raise ValueError("Analysis timeout must be positive")

# Export all classes and enums
__all__ = [
    'AntiTamperingMechanismType',
    'TamperingVulnerabilitySeverity', 
    'DetectionStrength',
    'BypassResistance',
    'AnalysisMethod',
    'AntiTamperingVulnerability',
    'RootDetectionAnalysis',
    'DebuggerDetectionAnalysis',
    'CodeObfuscationAnalysis',
    'AntiFridaAnalysis',
    'RASPAnalysis',
    'AntiTamperingAnalysisResult',
    'AntiTamperingAnalysisConfig'
] 