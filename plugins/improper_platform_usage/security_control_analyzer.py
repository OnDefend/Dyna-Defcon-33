#!/usr/bin/env python3
"""
Security Control Analyzer for Improper Platform Usage Plugin

Enhanced security control assessment for Phase 2.5.1 Critical Detection Gap Resolution.
Provides comprehensive root bypass validation, anti-tampering protection strength assessment,
and runtime application self-protection (RASP) analysis.

Phase 2.5.1 Implementation Features:
- Root detection mechanism effectiveness validation
- Anti-tampering protection strength assessment
- Runtime application self-protection (RASP) analysis
- Integrity verification mechanism validation
- Device attestation security analysis
- Bypass resistance scoring and recommendations

MASVS Controls: MSTG-RESILIENCE-1, MSTG-RESILIENCE-2, MSTG-RESILIENCE-3
"""

import logging
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from core.shared_infrastructure.dependency_injection import AnalysisContext
from core.shared_infrastructure.analysis_exceptions import AnalysisError

from .data_structures import (
    SecurityControlAssessment, 
    RootBypassValidationResult,
    SecurityControlType,
    ProtectionStrength,
    PlatformUsageVulnerability,
    VulnerabilitySeverity,
    PlatformUsageCategory
)
from .confidence_calculator import PlatformUsageConfidenceCalculator, EvidenceData

logger = logging.getLogger(__name__)

@dataclass
class SecurityControlPattern:
    """Security control detection pattern with metadata."""
    control_type: SecurityControlType
    pattern: str
    description: str
    strength: ProtectionStrength
    bypass_resistance: float  # 0.0-1.0
    effectiveness_score: float  # 0.0-1.0
    masvs_controls: List[str]
    detection_methods: List[str]

class SecurityControlAnalyzer:
    """
    Enhanced security control analyzer for Phase 2.5.1 requirements.
    
    Provides comprehensive assessment of security controls including root detection,
    anti-tampering protection, RASP mechanisms, and device attestation.
    """
    
    def __init__(self, apk_ctx, confidence_calculator: PlatformUsageConfidenceCalculator):
        """Initialize security control analyzer."""
        self.apk_ctx = apk_ctx
        self.confidence_calculator = confidence_calculator
        self.logger = logging.getLogger(__name__)
        
        # Analysis configuration
        self.max_analysis_time = 180  # 3 minutes timeout
        self.enable_comprehensive_analysis = True
        self.enable_bypass_detection = True
        self.enable_dynamic_correlation = True
        
        # Initialize security control patterns
        self.security_control_patterns = self._initialize_security_control_patterns()
        
        # Analysis statistics
        self.analysis_stats = {
            'controls_detected': 0,
            'bypass_techniques_found': 0,
            'effectiveness_assessments': 0,
            'dynamic_correlations': 0,
            'analysis_time': 0.0
        }
        
        logger.info("Security Control Analyzer initialized for Phase 2.5.1 enhanced analysis")
    
    def _initialize_security_control_patterns(self) -> Dict[SecurityControlType, List[SecurityControlPattern]]:
        """Initialize comprehensive security control patterns for organic detection."""
        return {
            SecurityControlType.ROOT_DETECTION: [
                SecurityControlPattern(
                    control_type=SecurityControlType.ROOT_DETECTION,
                    pattern=r'(?i)(?:su|sudo|doas)\s*(?:binary|executable|process|command)',
                    description='Root binary detection mechanism',
                    strength=ProtectionStrength.MODERATE,
                    bypass_resistance=0.6,
                    effectiveness_score=0.75,
                    masvs_controls=['MSTG-RESILIENCE-1'],
                    detection_methods=['static_analysis', 'pattern_matching']
                ),
                SecurityControlPattern(
                    control_type=SecurityControlType.ROOT_DETECTION,
                    pattern=r'(?i)(?:build\.tags|ro\.build\.tags).*test[\-_]?keys',
                    description='Build tags root detection',
                    strength=ProtectionStrength.WEAK,
                    bypass_resistance=0.3,
                    effectiveness_score=0.5,
                    masvs_controls=['MSTG-RESILIENCE-1'],
                    detection_methods=['property_analysis', 'static_analysis']
                ),
                SecurityControlPattern(
                    control_type=SecurityControlType.ROOT_DETECTION,
                    pattern=r'(?i)(?:packagemanager|package\.manager).*(?:root|su|superuser)',
                    description='Package manager based root detection',
                    strength=ProtectionStrength.MODERATE,
                    bypass_resistance=0.7,
                    effectiveness_score=0.8,
                    masvs_controls=['MSTG-RESILIENCE-1'],
                    detection_methods=['package_analysis', 'runtime_check']
                ),
                SecurityControlPattern(
                    control_type=SecurityControlType.ROOT_DETECTION,
                    pattern=r'(?i)(?:selinux|sepolicy).*(?:enforce|permissive)',
                    description='SELinux policy based root detection',
                    strength=ProtectionStrength.STRONG,
                    bypass_resistance=0.8,
                    effectiveness_score=0.85,
                    masvs_controls=['MSTG-RESILIENCE-1'],
                    detection_methods=['system_property', 'policy_analysis']
                )
            ],
            
            SecurityControlType.ANTI_TAMPERING: [
                SecurityControlPattern(
                    control_type=SecurityControlType.ANTI_TAMPERING,
                    pattern=r'(?i)(?:signature|certificate).*(?:verify|validation|check)',
                    description='Application signature verification',
                    strength=ProtectionStrength.STRONG,
                    bypass_resistance=0.75,
                    effectiveness_score=0.85,
                    masvs_controls=['MSTG-RESILIENCE-9'],
                    detection_methods=['signature_analysis', 'integrity_check']
                ),
                SecurityControlPattern(
                    control_type=SecurityControlType.ANTI_TAMPERING,
                    pattern=r'(?i)(?:installer|installation).*(?:package|source).*(?:verify|check)',
                    description='Installer package verification',
                    strength=ProtectionStrength.MODERATE,
                    bypass_resistance=0.6,
                    effectiveness_score=0.7,
                    masvs_controls=['MSTG-RESILIENCE-9'],
                    detection_methods=['installation_analysis', 'source_verification']
                ),
                SecurityControlPattern(
                    control_type=SecurityControlType.ANTI_TAMPERING,
                    pattern=r'(?i)(?:hash|checksum|digest).*(?:verify|validation|integrity)',
                    description='File integrity verification',
                    strength=ProtectionStrength.STRONG,
                    bypass_resistance=0.8,
                    effectiveness_score=0.9,
                    masvs_controls=['MSTG-RESILIENCE-9'],
                    detection_methods=['hash_verification', 'integrity_analysis']
                )
            ],
            
            SecurityControlType.DEBUGGER_DETECTION: [
                SecurityControlPattern(
                    control_type=SecurityControlType.DEBUGGER_DETECTION,
                    pattern=r'(?i)(?:debug|debugger).*(?:detect|detection|check)',
                    description='Debugger detection mechanism',
                    strength=ProtectionStrength.MODERATE,
                    bypass_resistance=0.55,
                    effectiveness_score=0.7,
                    masvs_controls=['MSTG-RESILIENCE-2'],
                    detection_methods=['debugger_analysis', 'runtime_check']
                ),
                SecurityControlPattern(
                    control_type=SecurityControlType.DEBUGGER_DETECTION,
                    pattern=r'(?i)(?:ptrace|process.*trace).*(?:attach|detect)',
                    description='Process tracing detection',
                    strength=ProtectionStrength.STRONG,
                    bypass_resistance=0.75,
                    effectiveness_score=0.85,
                    masvs_controls=['MSTG-RESILIENCE-2'],
                    detection_methods=['process_analysis', 'system_call_monitor']
                )
            ],
            
            SecurityControlType.RASP_PROTECTION: [
                SecurityControlPattern(
                    control_type=SecurityControlType.RASP_PROTECTION,
                    pattern=r'(?i)(?:runtime|real[\-_]?time).*(?:protection|security|monitor)',
                    description='Runtime application self-protection',
                    strength=ProtectionStrength.STRONG,
                    bypass_resistance=0.85,
                    effectiveness_score=0.9,
                    masvs_controls=['MSTG-RESILIENCE-1', 'MSTG-RESILIENCE-2'],
                    detection_methods=['runtime_analysis', 'behavior_monitor']
                ),
                SecurityControlPattern(
                    control_type=SecurityControlType.RASP_PROTECTION,
                    pattern=r'(?i)(?:security.*manager|permission.*check).*(?:runtime|dynamic)',
                    description='Dynamic security policy enforcement',
                    strength=ProtectionStrength.MODERATE,
                    bypass_resistance=0.7,
                    effectiveness_score=0.75,
                    masvs_controls=['MSTG-RESILIENCE-1'],
                    detection_methods=['permission_analysis', 'policy_enforcement']
                )
            ],
            
            SecurityControlType.DEVICE_ATTESTATION: [
                SecurityControlPattern(
                    control_type=SecurityControlType.DEVICE_ATTESTATION,
                    pattern=r'(?i)(?:attestation|attest).*(?:key|certificate|device)',
                    description='Device attestation mechanism',
                    strength=ProtectionStrength.STRONG,
                    bypass_resistance=0.9,
                    effectiveness_score=0.95,
                    masvs_controls=['MSTG-RESILIENCE-1'],
                    detection_methods=['attestation_analysis', 'certificate_validation']
                ),
                SecurityControlPattern(
                    control_type=SecurityControlType.DEVICE_ATTESTATION,
                    pattern=r'(?i)(?:safetynet|play.*integrity|device.*verify)',
                    description='Platform integrity verification',
                    strength=ProtectionStrength.STRONG,
                    bypass_resistance=0.85,
                    effectiveness_score=0.9,
                    masvs_controls=['MSTG-RESILIENCE-1'],
                    detection_methods=['platform_analysis', 'integrity_verification']
                )
            ]
        }
    
    def analyze_security_controls(self, manifest_content: str, source_content: str = "") -> RootBypassValidationResult:
        """
        Comprehensive security control analysis for Phase 2.5.1 requirements.
        
        Args:
            manifest_content: AndroidManifest.xml content
            source_content: Application source code content
            
        Returns:
            RootBypassValidationResult with comprehensive assessment
        """
        start_time = time.time()
        
        try:
            logger.info(f"Starting comprehensive security control analysis for {self.apk_ctx.package_name}")
            
            # Initialize result
            result = RootBypassValidationResult(
                bypass_detection_strength="Unknown",
                anti_tampering_effectiveness=0.0,
                rasp_implementation_quality="Not Detected", 
                integrity_verification_strength="Unknown",
                device_attestation_coverage="Not Analyzed",
                overall_protection_score=0.0,
                security_control_assessments=[]
            )
            
            # Analyze each security control type
            all_content = f"{manifest_content}\n{source_content}"
            
            for control_type, patterns in self.security_control_patterns.items():
                control_assessments = self._analyze_control_type(
                    control_type, patterns, all_content
                )
                result.security_control_assessments.extend(control_assessments)
            
            # Calculate overall protection score
            result.overall_protection_score = self._calculate_overall_protection_score(
                result.security_control_assessments
            )
            
            # Detect bypass techniques
            result.bypass_techniques_detected = self._detect_bypass_techniques(all_content)
            
            # Generate recommendations
            result.recommendations = self._generate_security_recommendations(result)
            
            # Update statistics
            analysis_time = time.time() - start_time
            self.analysis_stats.update({
                'controls_detected': len(result.security_control_assessments),
                'bypass_techniques_found': len(result.bypass_techniques_detected),
                'effectiveness_assessments': len([a for a in result.security_control_assessments if a.is_effective]),
                'analysis_time': analysis_time
            })
            
            logger.info(f"Security control analysis completed: {len(result.security_control_assessments)} controls analyzed "
                       f"in {analysis_time:.2f}s")
            
            return result
            
        except Exception as e:
            logger.error(f"Security control analysis failed: {e}")
            return RootBypassValidationResult(
                bypass_detection_strength="Error",
                anti_tampering_effectiveness=0.0,
                rasp_implementation_quality="Analysis Failed",
                integrity_verification_strength="Error", 
                device_attestation_coverage="Analysis Failed",
                overall_protection_score=0.0,
                security_control_assessments=[]
            )
    
    def _analyze_control_type(self, control_type: SecurityControlType, patterns: List[SecurityControlPattern], 
                             content: str) -> List[SecurityControlAssessment]:
        """Analyze specific security control type."""
        assessments = []
        
        for pattern in patterns:
            try:
                matches = re.finditer(pattern.pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    # Calculate evidence-based confidence
                    evidence = EvidenceData(
                        pattern_reliability=pattern.effectiveness_score,
                        context_relevance=0.8,  # High for security controls
                        validation_sources=['static_analysis', 'pattern_matching'],
                        cross_validation_count=1,
                        implementation_context='security_control'
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(evidence)
                    
                    # Create security control assessment
                    assessment = SecurityControlAssessment(
                        control_type=control_type,
                        description=pattern.description,
                        strength=pattern.strength,
                        effectiveness_score=pattern.effectiveness_score,
                        bypass_resistance=pattern.bypass_resistance,
                        confidence=confidence,
                        evidence=[match.group()],
                        masvs_controls=pattern.masvs_controls,
                        detection_methods=pattern.detection_methods
                    )
                    
                    assessments.append(assessment)
                    
            except Exception as e:
                logger.warning(f"Error analyzing {control_type.value} pattern: {e}")
                continue
        
        return assessments
    
    def _calculate_overall_protection_score(self, assessments: List[SecurityControlAssessment]) -> float:
        """Calculate overall protection score based on security control assessments."""
        if not assessments:
            return 0.0
        
        # Weight by control type importance
        control_weights = {
            SecurityControlType.ROOT_DETECTION: 0.25,
            SecurityControlType.ANTI_TAMPERING: 0.25,
            SecurityControlType.DEBUGGER_DETECTION: 0.15,
            SecurityControlType.RASP_PROTECTION: 0.20,
            SecurityControlType.DEVICE_ATTESTATION: 0.15
        }
        
        weighted_scores = {}
        control_counts = {}
        
        # Calculate weighted scores by control type
        for assessment in assessments:
            control_type = assessment.control_type
            weight = control_weights.get(control_type, 0.1)
            
            if control_type not in weighted_scores:
                weighted_scores[control_type] = 0.0
                control_counts[control_type] = 0
            
            # Combine effectiveness and bypass resistance
            control_score = (assessment.effectiveness_score * 0.6 + 
                           assessment.bypass_resistance * 0.4) * assessment.confidence
            
            weighted_scores[control_type] += control_score * weight
            control_counts[control_type] += 1
        
        # Average scores by control type
        for control_type in weighted_scores:
            if control_counts[control_type] > 0:
                weighted_scores[control_type] /= control_counts[control_type]
        
        # Calculate overall score
        overall_score = sum(weighted_scores.values())
        return min(overall_score, 1.0)  # Cap at 1.0
    
    def _detect_bypass_techniques(self, content: str) -> List[str]:
        """Detect potential bypass techniques in the application."""
        bypass_patterns = {
            'xposed_hooking': r'(?i)(?:xposed|xposedbrige|xposedhelpers)',
            'frida_injection': r'(?i)(?:frida|frida[\-_]?gadget|frida[\-_]?agent)',
            'substrate_hooking': r'(?i)(?:substrate|mobilesubstrate|cydiasubstrate)',
            'root_cloaking': r'(?i)(?:rootcloak|magisk.*hide|deny.*list)',
            'memory_patching': r'(?i)(?:memory.*patch|runtime.*patch|code.*injection)',
            'ptrace_injection': r'(?i)(?:ptrace.*injection|process.*injection)',
            'library_injection': r'(?i)(?:ld.*preload|library.*injection|so.*injection)',
            'system_manipulation': r'(?i)(?:system.*property.*manipulation|build.*prop.*modification)'
        }
        
        detected_techniques = []
        
        for technique, pattern in bypass_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                detected_techniques.append(technique.replace('_', ' ').title())
        
        return detected_techniques
    
    def _generate_security_recommendations(self, result: RootBypassValidationResult) -> List[str]:
        """Generate comprehensive security recommendations based on analysis."""
        recommendations = []
        
        # Control type specific recommendations
        control_types_found = {assessment.control_type for assessment in result.security_control_assessments}
        
        if SecurityControlType.ROOT_DETECTION not in control_types_found:
            recommendations.append("Implement comprehensive root detection mechanisms using multiple detection methods")
        
        if SecurityControlType.ANTI_TAMPERING not in control_types_found:
            recommendations.append("Deploy anti-tampering protection including signature verification and integrity checks")
        
        if SecurityControlType.DEBUGGER_DETECTION not in control_types_found:
            recommendations.append("Add debugger detection and response mechanisms")
        
        if SecurityControlType.RASP_PROTECTION not in control_types_found:
            recommendations.append("Implement runtime application self-protection (RASP) mechanisms")
        
        if SecurityControlType.DEVICE_ATTESTATION not in control_types_found:
            recommendations.append("Integrate device attestation and platform integrity verification")
        
        # Effectiveness-based recommendations
        weak_controls = [a for a in result.security_control_assessments 
                        if a.effectiveness_score < 0.6 or a.bypass_resistance < 0.5]
        
        if weak_controls:
            recommendations.append(f"Strengthen {len(weak_controls)} weak security controls with higher bypass resistance")
        
        # Bypass technique specific recommendations
        if result.bypass_techniques_detected:
            recommendations.append("Implement countermeasures against detected bypass techniques: " + 
                                 ", ".join(result.bypass_techniques_detected))
        
        # Overall protection recommendations
        if result.overall_protection_score < 0.5:
            recommendations.append("Overall protection is insufficient - implement comprehensive security controls")
        elif result.overall_protection_score < 0.8:
            recommendations.append("Good protection foundation - enhance existing controls for enterprise-grade security")
        
        return recommendations
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics for transparency."""
        return {
            'security_control_analyzer': {
                'controls_detected': self.analysis_stats['controls_detected'],
                'bypass_techniques_found': self.analysis_stats['bypass_techniques_found'],
                'effectiveness_assessments': self.analysis_stats['effectiveness_assessments'],
                'analysis_time': self.analysis_stats['analysis_time'],
                'pattern_categories': len(self.security_control_patterns),
                'total_patterns': sum(len(patterns) for patterns in self.security_control_patterns.values())
            }
        } 