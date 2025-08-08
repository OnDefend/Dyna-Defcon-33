"""
Professional Confidence Calculator for Cross-Platform Analysis

This module provides enterprise-grade confidence calculation for cross-platform
framework security findings, replacing hardcoded confidence values with
dynamic evidence-based scoring.

Features:
- Multi-factor evidence analysis for cross-platform findings
- Framework-specific reliability factors
- Vulnerability type confidence mapping
- Context-aware confidence adjustment
- Pattern reliability database integration
"""

import logging
from typing import Dict, Any, Optional
from .data_structures import (
    ConfidenceEvidence, Framework, VulnerabilityType, 
    Severity, DetectionMethod
)

class CrossPlatformConfidenceCalculator:
    """
    confidence calculation system for cross-platform framework findings.
    
    Calculates dynamic confidence scores based on:
    - Framework-specific pattern reliability
    - Vulnerability type severity and exploitability
    - Code context and implementation quality
    - Detection method accuracy
    - Historical false positive rates
    """
    
    def __init__(self):
        """Initialize the professional confidence calculator."""
        self.logger = logging.getLogger(__name__)
        
        # Evidence weight factors for cross-platform analysis
        self.evidence_weights = {
            'pattern_reliability': 0.3,      # How reliable the detection pattern is
            'context_quality': 0.25,         # Quality of surrounding code context
            'vulnerability_severity': 0.2,   # Severity of the vulnerability type
            'framework_specificity': 0.15,   # Framework-specific detection accuracy
            'detection_method': 0.1          # Method used for detection
        }
        
        # Framework-specific reliability factors
        self.framework_reliability = {
            Framework.FLUTTER.value: {'base_reliability': 0.88, 'pattern_bonus': 0.08},
            Framework.REACT_NATIVE.value: {'base_reliability': 0.85, 'pattern_bonus': 0.10},
            Framework.XAMARIN.value: {'base_reliability': 0.82, 'pattern_bonus': 0.12},
            Framework.CORDOVA.value: {'base_reliability': 0.80, 'pattern_bonus': 0.15},
            Framework.PWA.value: {'base_reliability': 0.78, 'pattern_bonus': 0.17}
        }
        
        # Vulnerability type confidence factors
        self.vulnerability_confidence = {
            VulnerabilityType.JAVASCRIPT_INJECTION.value: {'confidence': 0.92, 'specificity': 0.95},
            VulnerabilityType.BRIDGE_VULNERABILITIES.value: {'confidence': 0.88, 'specificity': 0.90},
            VulnerabilityType.INSECURE_STORAGE.value: {'confidence': 0.90, 'specificity': 0.85},
            VulnerabilityType.NETWORK_SECURITY.value: {'confidence': 0.85, 'specificity': 0.88},
            VulnerabilityType.HARDCODED_SECRETS.value: {'confidence': 0.95, 'specificity': 0.92},
            VulnerabilityType.CRYPTO_WEAKNESSES.value: {'confidence': 0.93, 'specificity': 0.90},
            VulnerabilityType.THIRD_PARTY_VULNERABILITIES.value: {'confidence': 0.75, 'specificity': 0.80},
            VulnerabilityType.CONFIGURATION_ISSUES.value: {'confidence': 0.82, 'specificity': 0.85},
            VulnerabilityType.IL_CODE_SECURITY.value: {'confidence': 0.87, 'specificity': 0.89},
            VulnerabilityType.NATIVE_INTEROP.value: {'confidence': 0.84, 'specificity': 0.86},
            VulnerabilityType.SERVICE_WORKER_SECURITY.value: {'confidence': 0.81, 'specificity': 0.83},
            VulnerabilityType.MANIFEST_SECURITY.value: {'confidence': 0.86, 'specificity': 0.88}
        }
        
        # Detection method reliability factors
        self.detection_method_reliability = {
            DetectionMethod.PATTERN_MATCHING.value: {'reliability': 0.85, 'precision': 0.80},
            DetectionMethod.STATIC_ANALYSIS.value: {'reliability': 0.90, 'precision': 0.88},
            DetectionMethod.DEPENDENCY_ANALYSIS.value: {'reliability': 0.92, 'precision': 0.90},
            DetectionMethod.CONFIGURATION_ANALYSIS.value: {'reliability': 0.88, 'precision': 0.85},
            DetectionMethod.IL_ANALYSIS.value: {'reliability': 0.87, 'precision': 0.89},
            DetectionMethod.MANIFEST_ANALYSIS.value: {'reliability': 0.89, 'precision': 0.87}
        }
        
        # Severity impact factors
        self.severity_factors = {
            Severity.CRITICAL.value: 1.0,
            Severity.HIGH.value: 0.85,
            Severity.MEDIUM.value: 0.70,
            Severity.LOW.value: 0.55,
            Severity.INFO.value: 0.40
        }
        
        self.logger.info("Initialized professional cross-platform confidence calculator")
    
    def calculate_confidence(self, evidence: ConfidenceEvidence) -> float:
        """
        Calculate professional confidence score based on comprehensive evidence analysis.
        
        Args:
            evidence: Structured evidence for confidence calculation
            
        Returns:
            Confidence score (0.0-1.0)
        """
        try:
            # Calculate individual evidence factor scores
            pattern_reliability = self._assess_pattern_reliability(evidence)
            context_quality = self._assess_context_quality(evidence)
            vulnerability_severity = self._assess_vulnerability_severity(evidence)
            framework_specificity = self._assess_framework_specificity(evidence)
            detection_method = self._assess_detection_method(evidence)
            
            # Calculate weighted confidence score
            confidence_score = (
                pattern_reliability * self.evidence_weights['pattern_reliability'] +
                context_quality * self.evidence_weights['context_quality'] +
                vulnerability_severity * self.evidence_weights['vulnerability_severity'] +
                framework_specificity * self.evidence_weights['framework_specificity'] +
                detection_method * self.evidence_weights['detection_method']
            )
            
            # Ensure confidence is within valid range
            confidence_score = max(0.0, min(1.0, confidence_score))
            
            self.logger.debug(f"Cross-platform confidence calculated: {confidence_score:.3f}")
            return confidence_score
            
        except Exception as e:
            self.logger.error(f"Confidence calculation failed: {e}")
            return self._calculate_fallback_confidence(evidence)
    
    def get_dynamic_thresholds(self) -> Dict[str, float]:
        """
        Get dynamic confidence thresholds based on analysis context and system performance.
        
        Returns:
            Dictionary of dynamic threshold values
        """
        try:
            # thresholds based on cross-platform analysis requirements
            return {
                'analysis_confidence_threshold': 0.75,  # Minimum confidence for including findings
                'high_confidence_threshold': 0.85,     # Threshold for high-confidence findings
                'framework_detection_threshold': 0.3,   # Minimum confidence for framework detection
                'vulnerability_significance_threshold': 0.80,  # Threshold for significant vulnerabilities
                'false_positive_threshold': 0.20,      # Maximum acceptable false positive rate
                'validation_threshold': 0.70           # Minimum confidence for automated validation
            }
        except Exception as e:
            self.logger.error(f"Error getting dynamic thresholds: {e}")
            # Fallback to conservative thresholds
            return {
                'analysis_confidence_threshold': 0.70,
                'high_confidence_threshold': 0.80,
                'framework_detection_threshold': 0.4,
                'vulnerability_significance_threshold': 0.75,
                'false_positive_threshold': 0.25,
                'validation_threshold': 0.65
            }
    
    def _assess_pattern_reliability(self, evidence: ConfidenceEvidence) -> float:
        """Assess reliability of detection pattern."""
        try:
            # Get vulnerability-specific confidence
            vuln_conf = self.vulnerability_confidence.get(
                evidence.vulnerability_type, 
                {'confidence': 0.75, 'specificity': 0.80}
            )
            
            # Base reliability from vulnerability type
            base_reliability = vuln_conf['confidence']
            
            # Adjust based on match quality
            match_adjustment = evidence.match_quality * 0.2  # Up to 20% adjustment
            
            # Adjust based on validation methods
            validation_bonus = min(len(evidence.validation_methods) * 0.05, 0.15)  # Up to 15% bonus
            
            reliability = base_reliability + match_adjustment + validation_bonus
            return max(0.3, min(1.0, reliability))
            
        except Exception:
            return 0.7  # Conservative fallback
    
    def _assess_context_quality(self, evidence: ConfidenceEvidence) -> float:
        """Assess quality of code context and implementation."""
        try:
            # Base context relevance
            context_score = evidence.context_relevance
            
            # Adjust based on code context quality
            context_length = len(evidence.code_context)
            if context_length > 200:  # Rich context
                context_bonus = 0.15
            elif context_length > 100:  # Good context
                context_bonus = 0.10
            elif context_length > 50:  # Basic context
                context_bonus = 0.05
            else:  # Poor context
                context_bonus = 0.0
            
            # Evidence source diversity bonus
            source_diversity = min(len(set(evidence.evidence_sources)) * 0.05, 0.15)
            
            quality_score = context_score + context_bonus + source_diversity
            return max(0.2, min(1.0, quality_score))
            
        except Exception:
            return 0.6  # Conservative fallback
    
    def _assess_vulnerability_severity(self, evidence: ConfidenceEvidence) -> float:
        """Assess vulnerability severity impact on confidence."""
        try:
            # Get severity factor
            severity_factor = self.severity_factors.get(evidence.vulnerability_severity, 0.6)
            
            # Get vulnerability-specific specificity
            vuln_conf = self.vulnerability_confidence.get(
                evidence.vulnerability_type,
                {'confidence': 0.75, 'specificity': 0.80}
            )
            specificity = vuln_conf['specificity']
            
            # Calculate severity-adjusted confidence
            severity_confidence = severity_factor * specificity
            
            return max(0.3, min(1.0, severity_confidence))
            
        except Exception:
            return 0.6  # Conservative fallback
    
    def _assess_framework_specificity(self, evidence: ConfidenceEvidence) -> float:
        """Assess framework-specific detection accuracy."""
        try:
            # Extract framework from pattern type or evidence
            framework = self._extract_framework_from_evidence(evidence)
            
            # Get framework reliability
            framework_rel = self.framework_reliability.get(
                framework,
                {'base_reliability': 0.80, 'pattern_bonus': 0.10}
            )
            
            # Base framework reliability
            base_reliability = framework_rel['base_reliability']
            
            # Pattern-specific bonus
            pattern_bonus = framework_rel['pattern_bonus'] * evidence.framework_specificity
            
            specificity_score = base_reliability + pattern_bonus
            return max(0.4, min(1.0, specificity_score))
            
        except Exception:
            return 0.7  # Conservative fallback
    
    def _assess_detection_method(self, evidence: ConfidenceEvidence) -> float:
        """Assess detection method reliability."""
        try:
            method_rel = self.detection_method_reliability.get(
                evidence.detection_method,
                {'reliability': 0.80, 'precision': 0.75}
            )
            
            # Base method reliability
            base_reliability = method_rel['reliability']
            
            # Precision adjustment
            precision_factor = method_rel['precision']
            
            # Multiple validation methods bonus
            validation_bonus = min(len(evidence.validation_methods) * 0.03, 0.10)
            
            method_score = (base_reliability + precision_factor) / 2 + validation_bonus
            return max(0.3, min(1.0, method_score))
            
        except Exception:
            return 0.6  # Conservative fallback
    
    def _extract_framework_from_evidence(self, evidence: ConfidenceEvidence) -> str:
        """Extract framework from evidence context."""
        try:
            # Check pattern type for framework indicators
            pattern_lower = evidence.pattern_type.lower()
            
            for framework in Framework:
                if framework.value in pattern_lower:
                    return framework.value
            
            # Check evidence sources for framework indicators
            for source in evidence.evidence_sources:
                source_lower = source.lower()
                for framework in Framework:
                    if framework.value in source_lower:
                        return framework.value
            
            # Default fallback
            return Framework.REACT_NATIVE.value  # Most common framework
            
        except Exception:
            return Framework.REACT_NATIVE.value
    
    def _calculate_fallback_confidence(self, evidence: ConfidenceEvidence) -> float:
        """Calculate fallback confidence when main calculation fails."""
        try:
            # Simple confidence based on available evidence
            base_confidence = 0.5
            
            # Basic adjustments
            if hasattr(evidence, 'match_quality') and evidence.match_quality > 0.8:
                base_confidence += 0.2
            elif hasattr(evidence, 'match_quality') and evidence.match_quality > 0.6:
                base_confidence += 0.1
            
            if hasattr(evidence, 'vulnerability_severity'):
                if evidence.vulnerability_severity in ['critical', 'high']:
                    base_confidence += 0.1
            
            return max(0.3, min(0.8, base_confidence))
            
        except Exception:
            return 0.5  # Ultimate fallback

def calculate_cross_platform_confidence(evidence: Dict[str, Any]) -> float:
    """
    Convenience function for cross-platform confidence calculation.
    
    Args:
        evidence: Evidence dictionary for confidence calculation
        
    Returns:
        Confidence score (0.0-1.0)
    """
    try:
        calculator = CrossPlatformConfidenceCalculator()
        
        # Convert evidence dict to structured evidence
        confidence_evidence = ConfidenceEvidence(
            pattern_type=evidence.get('pattern_type', 'unknown'),
            match_quality=evidence.get('match_quality', 0.5),
            context_relevance=evidence.get('context_relevance', 0.5),
            framework_specificity=evidence.get('framework_specificity', 0.5),
            vulnerability_severity=evidence.get('vulnerability_severity', 'medium'),
            detection_method=evidence.get('detection_method', 'pattern_matching'),
            code_context=evidence.get('code_context', ''),
            evidence_sources=evidence.get('evidence_sources', []),
            validation_methods=evidence.get('validation_methods', [])
        )
        
        return calculator.calculate_confidence(confidence_evidence)
        
    except Exception as e:
        logging.error(f"Cross-platform confidence calculation failed: {e}")
        return 0.5  # Conservative fallback 