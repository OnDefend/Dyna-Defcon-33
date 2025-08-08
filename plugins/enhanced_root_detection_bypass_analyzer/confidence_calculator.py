"""
Enhanced Root Detection Bypass Analyzer Confidence Calculator

confidence calculation system for root detection analysis findings.
Uses evidence-based scoring with pattern reliability data and context-aware adjustments.
"""

from typing import Dict, Any, List, Optional
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class RootDetectionEvidence:
    """Evidence factors for root detection confidence calculation."""
    pattern_reliability: float = 0.0      # Pattern match reliability
    detection_context: float = 0.0        # Detection context quality
    implementation_quality: float = 0.0   # Implementation analysis quality
    bypass_resistance: float = 0.0        # Bypass resistance assessment
    validation_coverage: float = 0.0      # Validation method coverage
    analysis_depth: float = 0.0           # Analysis depth factor

class EnhancedRootDetectionConfidenceCalculator:
    """
    confidence calculation system for root detection analysis.
    
    Implements evidence-based confidence scoring with context-aware adjustments
    and pattern reliability assessment for enhanced accuracy.
    """
    
    def __init__(self):
        """Initialize confidence calculator with evidence weights and pattern reliability."""
        # Evidence weight factors for root detection analysis
        self.evidence_weights = {
            'pattern_reliability': 0.25,      # 25% - Pattern match reliability
            'detection_context': 0.20,        # 20% - Detection context
            'implementation_quality': 0.20,   # 20% - Implementation quality
            'bypass_resistance': 0.15,        # 15% - Bypass resistance
            'validation_coverage': 0.10,      # 10% - Validation coverage
            'analysis_depth': 0.10            # 10% - Analysis depth
        }
        
        # Pattern reliability database with historical false positive rates
        self.pattern_reliability_data = {
            'native_binary_analysis': {'reliability': 0.92, 'fp_rate': 0.08},
            'file_system_permission_analysis': {'reliability': 0.88, 'fp_rate': 0.12},
            'process_execution_analysis': {'reliability': 0.85, 'fp_rate': 0.15},
            'system_property_analysis': {'reliability': 0.90, 'fp_rate': 0.10},
            'package_manager_analysis': {'reliability': 0.87, 'fp_rate': 0.13},
            'runtime_detection_analysis': {'reliability': 0.94, 'fp_rate': 0.06},
            'device_attestation_analysis': {'reliability': 0.96, 'fp_rate': 0.04},
            'security_provider_analysis': {'reliability': 0.89, 'fp_rate': 0.11}
        }
        
        # Context factors for confidence adjustment
        self.context_factors = {
            'implementation_file': 1.0,       # High relevance
            'native_library': 0.95,          # High relevance
            'config_file': 0.8,              # Medium-high relevance
            'resource_file': 0.6,            # Medium relevance
            'test_file': 0.3,                # Lower relevance
            'library_code': 0.4              # Lower relevance
        }
        
        # Detection method effectiveness scores
        self.detection_effectiveness = {
            'static_analysis': 0.75,
            'dynamic_analysis': 0.90,
            'hybrid_analysis': 0.95,
            'runtime_validation': 0.88,
            'behavioral_analysis': 0.85
        }
    
    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence for root detection analysis finding.
        
        Args:
            evidence: Evidence data for confidence calculation
            
        Returns:
            float: Confidence score between 0.0 and 1.0
        """
        try:
            # Ensure evidence is a dictionary before processing
            if not isinstance(evidence, dict):
                logger.warning(f"Evidence must be a dictionary, got {type(evidence)}. Using default confidence.")
                return 0.5  # Default confidence for invalid evidence
            # Extract evidence factors
            evidence_factors = self._extract_evidence(evidence)
            
            # Calculate weighted evidence score
            evidence_score = self._calculate_evidence_score(evidence_factors)
            
            # Apply pattern reliability adjustment
            pattern_adjustment = self._calculate_pattern_reliability(evidence)
            
            # Apply context-based adjustments
            context_adjustment = self._calculate_context_adjustment(evidence)
            
            # Apply detection method adjustment
            method_adjustment = self._calculate_method_adjustment(evidence)
            
            # Calculate final confidence
            base_confidence = evidence_score * pattern_adjustment * context_adjustment * method_adjustment
            
            # Apply final calibration
            final_confidence = self._apply_calibration(base_confidence, evidence)
            
            logger.debug(f"Root detection confidence calculation - "
                        f"Evidence: {evidence_score:.3f}, "
                        f"Pattern: {pattern_adjustment:.3f}, "
                        f"Context: {context_adjustment:.3f}, "
                        f"Method: {method_adjustment:.3f}, "
                        f"Final: {final_confidence:.3f}")
            
            return max(0.1, min(1.0, final_confidence))
            
        except Exception as e:
            logger.error(f"Error calculating root detection confidence: {e}")
            return 0.5  # Conservative default
    
    def _extract_evidence(self, evidence: Dict[str, Any]) -> RootDetectionEvidence:
        """Extract evidence factors from analysis data."""
        factors = RootDetectionEvidence()
        
        # Ensure evidence is a dictionary before processing
        if not isinstance(evidence, dict):
            logger.warning(f"Evidence must be a dictionary for factor extraction, got {type(evidence)}")
            return factors  # Return default factors
        
        # Pattern reliability
        pattern_type = evidence.get('pattern_category', '')
        if pattern_type in self.pattern_reliability_data:
            factors.pattern_reliability = self.pattern_reliability_data[pattern_type]['reliability']
        else:
            factors.pattern_reliability = 0.5  # Default
        
        # Detection context quality
        detection_type = evidence.get('detection_type', '')
        if detection_type in ['native_binary', 'runtime_detection', 'device_attestation']:
            factors.detection_context = 0.9
        elif detection_type in ['file_system', 'system_property']:
            factors.detection_context = 0.7
        else:
            factors.detection_context = 0.5
        
        # Implementation quality assessment
        location = evidence.get('location', '')
        if 'native' in location.lower() or '.so' in location.lower():
            factors.implementation_quality = 0.95
        elif '.java' in location.lower() or '.kt' in location.lower():
            factors.implementation_quality = 0.85
        else:
            factors.implementation_quality = 0.6
        
        # Bypass resistance scoring
        bypass_resistance = evidence.get('bypass_resistance_score', 0.5)
        factors.bypass_resistance = min(1.0, bypass_resistance)
        
        # Validation coverage
        analysis_methods = evidence.get('analysis_methods', [])
        if len(analysis_methods) >= 3:
            factors.validation_coverage = 1.0
        elif len(analysis_methods) == 2:
            factors.validation_coverage = 0.7
        elif len(analysis_methods) == 1:
            factors.validation_coverage = 0.5
        else:
            factors.validation_coverage = 0.3
        
        # Analysis depth
        evidence_strength = evidence.get('evidence', '')
        if len(evidence_strength) > 200:  # Detailed evidence
            factors.analysis_depth = 0.9
        elif len(evidence_strength) > 100:  # Moderate evidence
            factors.analysis_depth = 0.7
        else:  # Basic evidence
            factors.analysis_depth = 0.5
        
        return factors
    
    def _calculate_evidence_score(self, evidence: RootDetectionEvidence) -> float:
        """Calculate weighted evidence score."""
        return (
            evidence.pattern_reliability * self.evidence_weights['pattern_reliability'] +
            evidence.detection_context * self.evidence_weights['detection_context'] +
            evidence.implementation_quality * self.evidence_weights['implementation_quality'] +
            evidence.bypass_resistance * self.evidence_weights['bypass_resistance'] +
            evidence.validation_coverage * self.evidence_weights['validation_coverage'] +
            evidence.analysis_depth * self.evidence_weights['analysis_depth']
        )
    
    def _calculate_pattern_reliability(self, evidence: Dict[str, Any]) -> float:
        """Calculate pattern reliability adjustment factor."""
        pattern_type = evidence.get('pattern_category', '')
        
        if pattern_type in self.pattern_reliability_data:
            reliability_data = self.pattern_reliability_data[pattern_type]
            return reliability_data['reliability']
        
        return 0.5  # Conservative default
    
    def _calculate_context_adjustment(self, evidence: Dict[str, Any]) -> float:
        """Calculate context-based confidence adjustment."""
        location = evidence.get('location', '')
        
        # Determine context factor
        context_factor = 1.0
        
        if 'test' in location.lower():
            context_factor = self.context_factors['test_file']
        elif any(native in location.lower() for native in ['lib', '.so', 'jni']):
            context_factor = self.context_factors['native_library']
        elif any(config in location.lower() for config in ['config', 'properties', 'xml']):
            context_factor = self.context_factors['config_file']
        elif any(lib in location.lower() for lib in ['vendor', 'third_party']):
            context_factor = self.context_factors['library_code']
        else:
            context_factor = self.context_factors['implementation_file']
        
        # Security criticality adjustment
        severity = evidence.get('severity', 'medium')
        if severity == 'critical':
            context_factor *= 1.1
        elif severity == 'high':
            context_factor *= 1.05
        
        return min(1.0, context_factor)
    
    def _calculate_method_adjustment(self, evidence: Dict[str, Any]) -> float:
        """Calculate detection method effectiveness adjustment."""
        analysis_methods = evidence.get('analysis_methods', [])
        
        if not analysis_methods:
            return 0.5  # No specific method information
        
        # Calculate average effectiveness of used methods
        method_scores = []
        for method in analysis_methods:
            method_lower = method.lower()
            if 'dynamic' in method_lower:
                method_scores.append(self.detection_effectiveness['dynamic_analysis'])
            elif 'static' in method_lower:
                method_scores.append(self.detection_effectiveness['static_analysis'])
            elif 'runtime' in method_lower:
                method_scores.append(self.detection_effectiveness['runtime_validation'])
            elif 'behavioral' in method_lower:
                method_scores.append(self.detection_effectiveness['behavioral_analysis'])
            else:
                method_scores.append(0.6)  # Generic method
        
        if method_scores:
            avg_effectiveness = sum(method_scores) / len(method_scores)
            
            # Bonus for hybrid analysis (multiple methods)
            if len(method_scores) > 1:
                avg_effectiveness = min(1.0, avg_effectiveness * 1.1)
            
            return avg_effectiveness
        
        return 0.6  # Default method effectiveness
    
    def _apply_calibration(self, confidence: float, evidence: Dict[str, Any]) -> float:
        """Apply final calibration based on analysis characteristics."""
        # Conservative adjustment for low evidence
        if confidence < 0.4:
            confidence *= 0.9
        
        # Boost confidence for strong evidence
        bypass_resistance = evidence.get('bypass_resistance_score', 0.5)
        if bypass_resistance > 0.8:
            confidence = min(1.0, confidence * 1.05)
        
        # Adjust for detection type reliability
        detection_type = evidence.get('detection_type', '')
        if detection_type in ['device_attestation', 'runtime_detection']:
            confidence = min(1.0, confidence * 1.03)
        elif detection_type in ['process_execution', 'file_system']:
            confidence *= 0.95
        
        return confidence
    
    def get_confidence_factors(self, evidence: Dict[str, Any]) -> Dict[str, float]:
        """Get detailed confidence factors for transparency."""
        evidence_factors = self._extract_evidence(evidence)
        
        return {
            'pattern_reliability': evidence_factors.pattern_reliability,
            'detection_context': evidence_factors.detection_context,
            'implementation_quality': evidence_factors.implementation_quality,
            'bypass_resistance': evidence_factors.bypass_resistance,
            'validation_coverage': evidence_factors.validation_coverage,
            'analysis_depth': evidence_factors.analysis_depth,
            'evidence_weights': self.evidence_weights.copy(),
            'pattern_adjustment': self._calculate_pattern_reliability(evidence),
            'context_adjustment': self._calculate_context_adjustment(evidence),
            'method_adjustment': self._calculate_method_adjustment(evidence)
        }
    
    def get_pattern_reliability(self, pattern_type: str) -> float:
        """Get pattern reliability score for specific pattern type."""
        return self.pattern_reliability_data.get(pattern_type, {}).get('reliability', 0.5)
    
    def update_pattern_reliability(self, pattern_type: str, accuracy_data: Dict[str, float]):
        """Update pattern reliability based on validation results."""
        if pattern_type in self.pattern_reliability_data:
            # Update reliability based on new accuracy data
            current_reliability = self.pattern_reliability_data[pattern_type]['reliability']
            new_accuracy = accuracy_data.get('accuracy', current_reliability)
            
            # Weighted average with historical data
            updated_reliability = (current_reliability * 0.8) + (new_accuracy * 0.2)
            
            self.pattern_reliability_data[pattern_type]['reliability'] = updated_reliability
            self.pattern_reliability_data[pattern_type]['fp_rate'] = 1.0 - updated_reliability
            
            logger.info(f"Updated pattern reliability for {pattern_type}: {updated_reliability:.3f}")
    
    def calculate_bypass_resistance_confidence(self, bypass_methods: List[str], 
                                             countermeasures: List[str]) -> float:
        """Calculate confidence for bypass resistance assessment."""
        if not bypass_methods:
            return 0.3  # No bypass methods identified
        
        # Base confidence from number of identified bypass methods
        base_confidence = min(0.8, 0.4 + (len(bypass_methods) * 0.1))
        
        # Adjust based on countermeasures
        if countermeasures:
            countermeasure_factor = min(1.2, 1.0 + (len(countermeasures) * 0.05))
            base_confidence *= countermeasure_factor
        
        return min(1.0, base_confidence) 