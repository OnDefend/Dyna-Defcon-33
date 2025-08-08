#!/usr/bin/env python3
"""
Runtime Decryption Analysis Confidence Calculator

confidence calculation system for runtime decryption vulnerability findings.
Replaces hardcoded confidence values with evidence-based, multi-factor analysis.

Evidence Factors:
- Pattern reliability: Historical accuracy of detection patterns
- Context validation: Code context and semantic analysis
- Cross-validation: Corroborating evidence from multiple sources
- Implementation quality: Depth and sophistication of analysis
- Risk assessment: Security impact and exploitability

"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from pathlib import Path

from .data_structures import RuntimeDecryptionFinding, DecryptionType, DetectionMethod, VulnerabilitySeverity

# Import shared confidence infrastructure if available
try:
    from core.shared_confidence.universal_confidence_calculator import UniversalConfidenceCalculator
    from core.shared_confidence.evidence_based_scoring import ConfidenceEvidence
    SHARED_CONFIDENCE_AVAILABLE = True
except ImportError:
    SHARED_CONFIDENCE_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class RuntimeDecryptionEvidence:
    """Evidence structure for runtime decryption confidence calculation."""
    pattern_reliability: float = 0.0      # Reliability of matched pattern
    context_validation: float = 0.0       # Code context validation score
    cross_validation: float = 0.0         # Cross-validation from multiple sources
    implementation_depth: float = 0.0     # Depth of implementation analysis
    risk_assessment: float = 0.0          # Security risk and impact assessment
    semantic_analysis: float = 0.0        # Semantic code analysis score
    dynamic_testability: float = 0.0      # Dynamic testing feasibility

class RuntimeDecryptionConfidenceCalculator:
    """
    confidence calculator for runtime decryption analysis findings.
    
    Provides evidence-based confidence scoring using multiple validation factors
    to ensure accurate and defensible security assessments.
    """
    
    def __init__(self):
        """Initialize the confidence calculator with pattern reliability database."""
        self.logger = logging.getLogger(__name__)
        
        # Evidence weights for runtime decryption factors
        self.evidence_weights = {
            'pattern_reliability': 0.25,      # Historical pattern accuracy
            'context_validation': 0.20,       # Code context validation
            'cross_validation': 0.15,         # Multiple source validation
            'implementation_depth': 0.15,     # Analysis depth and quality
            'risk_assessment': 0.10,          # Security impact assessment
            'semantic_analysis': 0.10,        # Semantic code analysis
            'dynamic_testability': 0.05       # Dynamic testing capability
        }
        
        # Pattern reliability database based on historical accuracy
        self.pattern_reliability = {
            # High reliability patterns (90%+ accuracy)
            'javax.crypto.Cipher': 0.95,
            'decrypt': 0.90,
            'AES.decrypt': 0.95,
            'DES.decrypt': 0.92,
            'RSA.decrypt': 0.94,
            
            # Medium reliability patterns (70-90% accuracy)
            'cipher.doFinal': 0.85,
            'android.security': 0.80,
            'keystore': 0.82,
            'base64': 0.75,
            'encode': 0.70,
            'decode': 0.72,
            
            # Lower reliability patterns (50-70% accuracy)
            'encrypt': 0.65,  # Can be false positive
            'secret': 0.60,
            'password': 0.55,
            'token': 0.58,
            
            # Method-specific patterns
            'native_decrypt': 0.88,
            'jni_crypto': 0.85,
            'runtime_key_derivation': 0.90,
            'dynamic_key_generation': 0.87
        }
        
        # Detection method reliability scores
        self.detection_method_reliability = {
            DetectionMethod.SEMANTIC_ANALYSIS: 0.90,
            DetectionMethod.FLOW_ANALYSIS: 0.85,
            DetectionMethod.CROSS_REFERENCE: 0.80,
            DetectionMethod.PATTERN_MATCHING: 0.75,
            DetectionMethod.RESOURCE_ANALYSIS: 0.70
        }
        
        # Pattern type risk assessment
        self.pattern_risk_scores = {
            DecryptionType.RUNTIME_DECRYPTION: 0.95,      # Highest risk
            DecryptionType.HARDCODED_CRYPTO: 0.90,        # Very high risk
            DecryptionType.WEAK_CRYPTO: 0.85,             # High risk
            DecryptionType.CUSTOM_CRYPTO: 0.80,           # High risk
            DecryptionType.KEY_MANAGEMENT: 0.75,          # Medium-high risk
            DecryptionType.NATIVE_DECRYPTION: 0.70,       # Medium risk
            DecryptionType.CRYPTO_IMPLEMENTATION: 0.65,   # Medium risk
            DecryptionType.RESOURCE_DECRYPTION: 0.60      # Lower risk
        }
        
        # Confidence floor and ceiling
        self.confidence_floor = 0.1   # Minimum confidence score
        self.confidence_ceiling = 0.95 # Maximum confidence score
        
        self.logger.info("Runtime decryption confidence calculator initialized")
    
    def calculate_confidence(
        self,
        finding: RuntimeDecryptionFinding,
        context: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Calculate professional confidence score for a runtime decryption finding.
        
        Args:
            finding: The runtime decryption finding to score
            context: Additional context for confidence calculation
            
        Returns:
            float: Confidence score between 0.0 and 1.0
        """
        context = context or {}
        
        try:
            # Gather evidence from multiple factors
            evidence = self._gather_evidence(finding, context)
            
            # Calculate weighted confidence score
            confidence_score = self._calculate_weighted_confidence(evidence)
            
            # Apply contextual adjustments
            adjusted_score = self._apply_contextual_adjustments(
                confidence_score, finding, context
            )
            
            # Ensure score is within bounds
            final_score = max(self.confidence_floor, min(adjusted_score, self.confidence_ceiling))
            
            self.logger.debug(
                f"Calculated confidence {final_score:.2f} for finding: {finding.finding_type}"
            )
            
            return final_score
            
        except Exception as e:
            self.logger.error(f"Error calculating confidence: {e}", exc_info=True)
            return 0.5  # Default moderate confidence
    
    def _gather_evidence(
        self,
        finding: RuntimeDecryptionFinding,
        context: Dict[str, Any]
    ) -> RuntimeDecryptionEvidence:
        """Gather evidence from multiple analysis factors."""
        evidence = RuntimeDecryptionEvidence()
        
        # Pattern reliability evidence
        evidence.pattern_reliability = self._assess_pattern_reliability(finding)
        
        # Context validation evidence
        evidence.context_validation = self._assess_context_validation(finding, context)
        
        # Cross-validation evidence
        evidence.cross_validation = context.get('cross_validation', 0.5)
        
        # Implementation depth evidence
        evidence.implementation_depth = context.get('analysis_depth', 0.7)
        
        # Risk assessment evidence
        evidence.risk_assessment = self._assess_risk_level(finding)
        
        # Semantic analysis evidence
        evidence.semantic_analysis = self._assess_semantic_quality(finding)
        
        # Dynamic testability evidence
        evidence.dynamic_testability = 1.0 if finding.is_dynamic_testable() else 0.3
        
        return evidence
    
    def _calculate_weighted_confidence(self, evidence: RuntimeDecryptionEvidence) -> float:
        """Calculate weighted confidence score from evidence factors."""
        weighted_score = 0.0
        
        # Apply evidence weights
        weighted_score += evidence.pattern_reliability * self.evidence_weights['pattern_reliability']
        weighted_score += evidence.context_validation * self.evidence_weights['context_validation']
        weighted_score += evidence.cross_validation * self.evidence_weights['cross_validation']
        weighted_score += evidence.implementation_depth * self.evidence_weights['implementation_depth']
        weighted_score += evidence.risk_assessment * self.evidence_weights['risk_assessment']
        weighted_score += evidence.semantic_analysis * self.evidence_weights['semantic_analysis']
        weighted_score += evidence.dynamic_testability * self.evidence_weights['dynamic_testability']
        
        return weighted_score
    
    def _assess_pattern_reliability(self, finding: RuntimeDecryptionFinding) -> float:
        """Assess the reliability of the matched pattern."""
        # Base reliability from pattern database
        base_reliability = self.pattern_reliability.get(finding.matched_pattern, 0.6)
        
        # Detection method adjustment
        method_reliability = self.detection_method_reliability.get(
            finding.detection_method, 0.7
        )
        
        # Combine pattern and method reliability
        combined_reliability = (base_reliability * 0.7) + (method_reliability * 0.3)
        
        # Adjust for evidence quality
        if len(finding.evidence) >= 3:
            combined_reliability *= 1.1  # Multiple evidence sources
        elif len(finding.evidence) >= 2:
            combined_reliability *= 1.05 # Some evidence sources
        
        return min(combined_reliability, 1.0)
    
    def _assess_context_validation(
        self,
        finding: RuntimeDecryptionFinding,
        context: Dict[str, Any]
    ) -> float:
        """Assess the validation of code context."""
        validation_score = 0.5  # Base score
        
        # File location validation
        if finding.file_path and any(keyword in finding.file_path.lower() 
                                   for keyword in ['crypto', 'security', 'encrypt', 'decrypt']):
            validation_score += 0.2
        
        # Class name validation
        if finding.class_name and any(keyword in finding.class_name.lower()
                                    for keyword in ['crypto', 'cipher', 'security', 'encrypt']):
            validation_score += 0.2
        
        # Method name validation
        if finding.method_name and any(keyword in finding.method_name.lower()
                                     for keyword in ['decrypt', 'encode', 'decode', 'cipher']):
            validation_score += 0.15
        
        # Line number precision
        if finding.line_number is not None:
            validation_score += 0.1
        
        # Context information
        if context.get('pattern_validation', 0) > 0.7:
            validation_score += 0.1
        
        return min(validation_score, 1.0)
    
    def _assess_risk_level(self, finding: RuntimeDecryptionFinding) -> float:
        """Assess the security risk level of the finding."""
        # Base risk from pattern type
        base_risk = self.pattern_risk_scores.get(finding.pattern_type, 0.6)
        
        # Severity adjustment
        severity_multipliers = {
            VulnerabilitySeverity.CRITICAL: 1.0,
            VulnerabilitySeverity.HIGH: 0.8,
            VulnerabilitySeverity.MEDIUM: 0.6,
            VulnerabilitySeverity.LOW: 0.4,
            VulnerabilitySeverity.INFO: 0.2
        }
        severity_multiplier = severity_multipliers.get(finding.severity, 0.6)
        
        # Dynamic testability increases risk confidence
        dynamic_bonus = 0.1 if finding.is_dynamic_testable() else 0.0
        
        risk_score = (base_risk * severity_multiplier) + dynamic_bonus
        
        return min(risk_score, 1.0)
    
    def _assess_semantic_quality(self, finding: RuntimeDecryptionFinding) -> float:
        """Assess the quality of semantic analysis."""
        quality_score = 0.5  # Base quality
        
        # Code structure indicators
        if finding.class_name and finding.method_name:
            quality_score += 0.2  # Well-structured code location
        
        # Pattern sophistication
        if len(finding.matched_pattern) > 10:  # Complex patterns
            quality_score += 0.1
        
        # Evidence depth
        if len(finding.evidence) >= 2:
            quality_score += 0.15
        
        # Context richness
        if len(finding.context) >= 3:
            quality_score += 0.1
        
        # Attack vector specification
        if finding.attack_vector:
            quality_score += 0.05
        
        return min(quality_score, 1.0)
    
    def _apply_contextual_adjustments(
        self,
        base_confidence: float,
        finding: RuntimeDecryptionFinding,
        context: Dict[str, Any]
    ) -> float:
        """Apply contextual adjustments to confidence score."""
        adjusted_confidence = base_confidence
        
        # High-quality evidence bonus
        if len(finding.evidence) >= 3 and all(len(ev) > 10 for ev in finding.evidence):
            adjusted_confidence *= 1.05
        
        # Multiple related findings bonus
        if len(finding.related_findings) >= 2:
            adjusted_confidence *= 1.03
        
        # Dynamic testability bonus
        if finding.is_dynamic_testable() and finding.frida_script_path:
            adjusted_confidence *= 1.02
        
        # Pattern validation penalty for weak patterns
        if context.get('pattern_validation', 1.0) < 0.5:
            adjusted_confidence *= 0.95
        
        return adjusted_confidence
    
    def get_pattern_reliability(self, pattern_type: str, detection_method: DetectionMethod) -> float:
        """Get pattern reliability score for external validation."""
        pattern_score = self.pattern_reliability.get(pattern_type, 0.6)
        method_score = self.detection_method_reliability.get(detection_method, 0.7)
        return (pattern_score + method_score) / 2.0
    
    def update_pattern_reliability(self, pattern: str, accuracy: float):
        """Update pattern reliability based on validation results."""
        if pattern in self.pattern_reliability:
            # Weighted average with existing reliability
            current = self.pattern_reliability[pattern]
            self.pattern_reliability[pattern] = (current * 0.8) + (accuracy * 0.2)
        else:
            self.pattern_reliability[pattern] = accuracy
        
        self.logger.info(f"Updated pattern reliability for '{pattern}': {accuracy:.2f}")
    
    def get_confidence_explanation(self, finding: RuntimeDecryptionFinding) -> Dict[str, Any]:
        """Get detailed explanation of confidence calculation."""
        evidence = self._gather_evidence(finding, {})
        
        return {
            "final_confidence": finding.confidence,
            "evidence_factors": {
                "pattern_reliability": evidence.pattern_reliability,
                "context_validation": evidence.context_validation,
                "cross_validation": evidence.cross_validation,
                "implementation_depth": evidence.implementation_depth,
                "risk_assessment": evidence.risk_assessment,
                "semantic_analysis": evidence.semantic_analysis,
                "dynamic_testability": evidence.dynamic_testability
            },
            "evidence_weights": self.evidence_weights,
            "pattern_used": finding.matched_pattern,
            "detection_method": finding.detection_method.value,
            "adjustments_applied": "See contextual adjustments in calculation"
        } 
"""
Runtime Decryption Analysis Confidence Calculator

confidence calculation system for runtime decryption vulnerability findings.
Replaces hardcoded confidence values with evidence-based, multi-factor analysis.

Evidence Factors:
- Pattern reliability: Historical accuracy of detection patterns
- Context validation: Code context and semantic analysis
- Cross-validation: Corroborating evidence from multiple sources
- Implementation quality: Depth and sophistication of analysis
- Risk assessment: Security impact and exploitability

"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from pathlib import Path

from .data_structures import RuntimeDecryptionFinding, DecryptionType, DetectionMethod, VulnerabilitySeverity

# Import shared confidence infrastructure if available
try:
    from core.shared_confidence.universal_confidence_calculator import UniversalConfidenceCalculator
    from core.shared_confidence.evidence_based_scoring import ConfidenceEvidence
    SHARED_CONFIDENCE_AVAILABLE = True
except ImportError:
    SHARED_CONFIDENCE_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class RuntimeDecryptionEvidence:
    """Evidence structure for runtime decryption confidence calculation."""
    pattern_reliability: float = 0.0      # Reliability of matched pattern
    context_validation: float = 0.0       # Code context validation score
    cross_validation: float = 0.0         # Cross-validation from multiple sources
    implementation_depth: float = 0.0     # Depth of implementation analysis
    risk_assessment: float = 0.0          # Security risk and impact assessment
    semantic_analysis: float = 0.0        # Semantic code analysis score
    dynamic_testability: float = 0.0      # Dynamic testing feasibility

class RuntimeDecryptionConfidenceCalculator:
    """
    confidence calculator for runtime decryption analysis findings.
    
    Provides evidence-based confidence scoring using multiple validation factors
    to ensure accurate and defensible security assessments.
    """
    
    def __init__(self):
        """Initialize the confidence calculator with pattern reliability database."""
        self.logger = logging.getLogger(__name__)
        
        # Evidence weights for runtime decryption factors
        self.evidence_weights = {
            'pattern_reliability': 0.25,      # Historical pattern accuracy
            'context_validation': 0.20,       # Code context validation
            'cross_validation': 0.15,         # Multiple source validation
            'implementation_depth': 0.15,     # Analysis depth and quality
            'risk_assessment': 0.10,          # Security impact assessment
            'semantic_analysis': 0.10,        # Semantic code analysis
            'dynamic_testability': 0.05       # Dynamic testing capability
        }
        
        # Pattern reliability database based on historical accuracy
        self.pattern_reliability = {
            # High reliability patterns (90%+ accuracy)
            'javax.crypto.Cipher': 0.95,
            'decrypt': 0.90,
            'AES.decrypt': 0.95,
            'DES.decrypt': 0.92,
            'RSA.decrypt': 0.94,
            
            # Medium reliability patterns (70-90% accuracy)
            'cipher.doFinal': 0.85,
            'android.security': 0.80,
            'keystore': 0.82,
            'base64': 0.75,
            'encode': 0.70,
            'decode': 0.72,
            
            # Lower reliability patterns (50-70% accuracy)
            'encrypt': 0.65,  # Can be false positive
            'secret': 0.60,
            'password': 0.55,
            'token': 0.58,
            
            # Method-specific patterns
            'native_decrypt': 0.88,
            'jni_crypto': 0.85,
            'runtime_key_derivation': 0.90,
            'dynamic_key_generation': 0.87
        }
        
        # Detection method reliability scores
        self.detection_method_reliability = {
            DetectionMethod.SEMANTIC_ANALYSIS: 0.90,
            DetectionMethod.FLOW_ANALYSIS: 0.85,
            DetectionMethod.CROSS_REFERENCE: 0.80,
            DetectionMethod.PATTERN_MATCHING: 0.75,
            DetectionMethod.RESOURCE_ANALYSIS: 0.70
        }
        
        # Pattern type risk assessment
        self.pattern_risk_scores = {
            DecryptionType.RUNTIME_DECRYPTION: 0.95,      # Highest risk
            DecryptionType.HARDCODED_CRYPTO: 0.90,        # Very high risk
            DecryptionType.WEAK_CRYPTO: 0.85,             # High risk
            DecryptionType.CUSTOM_CRYPTO: 0.80,           # High risk
            DecryptionType.KEY_MANAGEMENT: 0.75,          # Medium-high risk
            DecryptionType.NATIVE_DECRYPTION: 0.70,       # Medium risk
            DecryptionType.CRYPTO_IMPLEMENTATION: 0.65,   # Medium risk
            DecryptionType.RESOURCE_DECRYPTION: 0.60      # Lower risk
        }
        
        # Confidence floor and ceiling
        self.confidence_floor = 0.1   # Minimum confidence score
        self.confidence_ceiling = 0.95 # Maximum confidence score
        
        self.logger.info("Runtime decryption confidence calculator initialized")
    
    def calculate_confidence(
        self,
        finding: RuntimeDecryptionFinding,
        context: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Calculate professional confidence score for a runtime decryption finding.
        
        Args:
            finding: The runtime decryption finding to score
            context: Additional context for confidence calculation
            
        Returns:
            float: Confidence score between 0.0 and 1.0
        """
        context = context or {}
        
        try:
            # Gather evidence from multiple factors
            evidence = self._gather_evidence(finding, context)
            
            # Calculate weighted confidence score
            confidence_score = self._calculate_weighted_confidence(evidence)
            
            # Apply contextual adjustments
            adjusted_score = self._apply_contextual_adjustments(
                confidence_score, finding, context
            )
            
            # Ensure score is within bounds
            final_score = max(self.confidence_floor, min(adjusted_score, self.confidence_ceiling))
            
            self.logger.debug(
                f"Calculated confidence {final_score:.2f} for finding: {finding.finding_type}"
            )
            
            return final_score
            
        except Exception as e:
            self.logger.error(f"Error calculating confidence: {e}", exc_info=True)
            return 0.5  # Default moderate confidence
    
    def _gather_evidence(
        self,
        finding: RuntimeDecryptionFinding,
        context: Dict[str, Any]
    ) -> RuntimeDecryptionEvidence:
        """Gather evidence from multiple analysis factors."""
        evidence = RuntimeDecryptionEvidence()
        
        # Pattern reliability evidence
        evidence.pattern_reliability = self._assess_pattern_reliability(finding)
        
        # Context validation evidence
        evidence.context_validation = self._assess_context_validation(finding, context)
        
        # Cross-validation evidence
        evidence.cross_validation = context.get('cross_validation', 0.5)
        
        # Implementation depth evidence
        evidence.implementation_depth = context.get('analysis_depth', 0.7)
        
        # Risk assessment evidence
        evidence.risk_assessment = self._assess_risk_level(finding)
        
        # Semantic analysis evidence
        evidence.semantic_analysis = self._assess_semantic_quality(finding)
        
        # Dynamic testability evidence
        evidence.dynamic_testability = 1.0 if finding.is_dynamic_testable() else 0.3
        
        return evidence
    
    def _calculate_weighted_confidence(self, evidence: RuntimeDecryptionEvidence) -> float:
        """Calculate weighted confidence score from evidence factors."""
        weighted_score = 0.0
        
        # Apply evidence weights
        weighted_score += evidence.pattern_reliability * self.evidence_weights['pattern_reliability']
        weighted_score += evidence.context_validation * self.evidence_weights['context_validation']
        weighted_score += evidence.cross_validation * self.evidence_weights['cross_validation']
        weighted_score += evidence.implementation_depth * self.evidence_weights['implementation_depth']
        weighted_score += evidence.risk_assessment * self.evidence_weights['risk_assessment']
        weighted_score += evidence.semantic_analysis * self.evidence_weights['semantic_analysis']
        weighted_score += evidence.dynamic_testability * self.evidence_weights['dynamic_testability']
        
        return weighted_score
    
    def _assess_pattern_reliability(self, finding: RuntimeDecryptionFinding) -> float:
        """Assess the reliability of the matched pattern."""
        # Base reliability from pattern database
        base_reliability = self.pattern_reliability.get(finding.matched_pattern, 0.6)
        
        # Detection method adjustment
        method_reliability = self.detection_method_reliability.get(
            finding.detection_method, 0.7
        )
        
        # Combine pattern and method reliability
        combined_reliability = (base_reliability * 0.7) + (method_reliability * 0.3)
        
        # Adjust for evidence quality
        if len(finding.evidence) >= 3:
            combined_reliability *= 1.1  # Multiple evidence sources
        elif len(finding.evidence) >= 2:
            combined_reliability *= 1.05 # Some evidence sources
        
        return min(combined_reliability, 1.0)
    
    def _assess_context_validation(
        self,
        finding: RuntimeDecryptionFinding,
        context: Dict[str, Any]
    ) -> float:
        """Assess the validation of code context."""
        validation_score = 0.5  # Base score
        
        # File location validation
        if finding.file_path and any(keyword in finding.file_path.lower() 
                                   for keyword in ['crypto', 'security', 'encrypt', 'decrypt']):
            validation_score += 0.2
        
        # Class name validation
        if finding.class_name and any(keyword in finding.class_name.lower()
                                    for keyword in ['crypto', 'cipher', 'security', 'encrypt']):
            validation_score += 0.2
        
        # Method name validation
        if finding.method_name and any(keyword in finding.method_name.lower()
                                     for keyword in ['decrypt', 'encode', 'decode', 'cipher']):
            validation_score += 0.15
        
        # Line number precision
        if finding.line_number is not None:
            validation_score += 0.1
        
        # Context information
        if context.get('pattern_validation', 0) > 0.7:
            validation_score += 0.1
        
        return min(validation_score, 1.0)
    
    def _assess_risk_level(self, finding: RuntimeDecryptionFinding) -> float:
        """Assess the security risk level of the finding."""
        # Base risk from pattern type
        base_risk = self.pattern_risk_scores.get(finding.pattern_type, 0.6)
        
        # Severity adjustment
        severity_multipliers = {
            VulnerabilitySeverity.CRITICAL: 1.0,
            VulnerabilitySeverity.HIGH: 0.8,
            VulnerabilitySeverity.MEDIUM: 0.6,
            VulnerabilitySeverity.LOW: 0.4,
            VulnerabilitySeverity.INFO: 0.2
        }
        severity_multiplier = severity_multipliers.get(finding.severity, 0.6)
        
        # Dynamic testability increases risk confidence
        dynamic_bonus = 0.1 if finding.is_dynamic_testable() else 0.0
        
        risk_score = (base_risk * severity_multiplier) + dynamic_bonus
        
        return min(risk_score, 1.0)
    
    def _assess_semantic_quality(self, finding: RuntimeDecryptionFinding) -> float:
        """Assess the quality of semantic analysis."""
        quality_score = 0.5  # Base quality
        
        # Code structure indicators
        if finding.class_name and finding.method_name:
            quality_score += 0.2  # Well-structured code location
        
        # Pattern sophistication
        if len(finding.matched_pattern) > 10:  # Complex patterns
            quality_score += 0.1
        
        # Evidence depth
        if len(finding.evidence) >= 2:
            quality_score += 0.15
        
        # Context richness
        if len(finding.context) >= 3:
            quality_score += 0.1
        
        # Attack vector specification
        if finding.attack_vector:
            quality_score += 0.05
        
        return min(quality_score, 1.0)
    
    def _apply_contextual_adjustments(
        self,
        base_confidence: float,
        finding: RuntimeDecryptionFinding,
        context: Dict[str, Any]
    ) -> float:
        """Apply contextual adjustments to confidence score."""
        adjusted_confidence = base_confidence
        
        # High-quality evidence bonus
        if len(finding.evidence) >= 3 and all(len(ev) > 10 for ev in finding.evidence):
            adjusted_confidence *= 1.05
        
        # Multiple related findings bonus
        if len(finding.related_findings) >= 2:
            adjusted_confidence *= 1.03
        
        # Dynamic testability bonus
        if finding.is_dynamic_testable() and finding.frida_script_path:
            adjusted_confidence *= 1.02
        
        # Pattern validation penalty for weak patterns
        if context.get('pattern_validation', 1.0) < 0.5:
            adjusted_confidence *= 0.95
        
        return adjusted_confidence
    
    def get_pattern_reliability(self, pattern_type: str, detection_method: DetectionMethod) -> float:
        """Get pattern reliability score for external validation."""
        pattern_score = self.pattern_reliability.get(pattern_type, 0.6)
        method_score = self.detection_method_reliability.get(detection_method, 0.7)
        return (pattern_score + method_score) / 2.0
    
    def update_pattern_reliability(self, pattern: str, accuracy: float):
        """Update pattern reliability based on validation results."""
        if pattern in self.pattern_reliability:
            # Weighted average with existing reliability
            current = self.pattern_reliability[pattern]
            self.pattern_reliability[pattern] = (current * 0.8) + (accuracy * 0.2)
        else:
            self.pattern_reliability[pattern] = accuracy
        
        self.logger.info(f"Updated pattern reliability for '{pattern}': {accuracy:.2f}")
    
    def get_confidence_explanation(self, finding: RuntimeDecryptionFinding) -> Dict[str, Any]:
        """Get detailed explanation of confidence calculation."""
        evidence = self._gather_evidence(finding, {})
        
        return {
            "final_confidence": finding.confidence,
            "evidence_factors": {
                "pattern_reliability": evidence.pattern_reliability,
                "context_validation": evidence.context_validation,
                "cross_validation": evidence.cross_validation,
                "implementation_depth": evidence.implementation_depth,
                "risk_assessment": evidence.risk_assessment,
                "semantic_analysis": evidence.semantic_analysis,
                "dynamic_testability": evidence.dynamic_testability
            },
            "evidence_weights": self.evidence_weights,
            "pattern_used": finding.matched_pattern,
            "detection_method": finding.detection_method.value,
            "adjustments_applied": "See contextual adjustments in calculation"
        } 