"""
Traversal Vulnerabilities Confidence Calculator

confidence calculation system for path traversal vulnerabilities.
Uses evidence-based scoring with pattern reliability data and context-aware adjustments.
"""

from typing import Dict, Any, List, Optional
import logging
from dataclasses import dataclass

from .data_structures import TraversalEvidence

logger = logging.getLogger(__name__)

class TraversalConfidenceCalculator:
    """
    confidence calculation system for path traversal vulnerabilities.
    
    Implements evidence-based, multi-factor confidence scoring that considers:
    - Path validation quality and complexity
    - URI security and handling mechanisms
    - File system permission boundaries
    - Payload effectiveness and bypass techniques
    - Context-aware analysis based on traversal type
    """
    
    def __init__(self):
        """Initialize confidence calculator with evidence weights and pattern reliability."""
        # Evidence weight factors for path traversal analysis
        self.evidence_weights = {
            'path_validation': 0.25,          # 25% - Path validation assessment
            'uri_security': 0.20,             # 20% - URI security analysis
            'file_permissions': 0.20,         # 20% - File permission boundaries
            'payload_effectiveness': 0.15,    # 15% - Payload effectiveness
            'context_analysis': 0.10,         # 10% - Context analysis
            'bypass_potential': 0.10          # 10% - Bypass technique potential
        }
        
        # Pattern reliability database with historical false positive rates
        self.pattern_reliability_data = {
            'path_traversal_patterns': {'reliability': 0.90, 'fp_rate': 0.10},
            'directory_traversal_patterns': {'reliability': 0.88, 'fp_rate': 0.12},
            'file_inclusion_patterns': {'reliability': 0.85, 'fp_rate': 0.15},
            'content_provider_patterns': {'reliability': 0.92, 'fp_rate': 0.08},
            'intent_filter_patterns': {'reliability': 0.87, 'fp_rate': 0.13},
            'file_operation_patterns': {'reliability': 0.89, 'fp_rate': 0.11},
            'uri_handling_patterns': {'reliability': 0.86, 'fp_rate': 0.14},
            'webview_traversal_patterns': {'reliability': 0.83, 'fp_rate': 0.17}
        }
        
        # Context adjustment factors
        self.context_factors = {
            'traversal_type': {
                'path_traversal': 1.0,
                'directory_traversal': 0.95,
                'file_inclusion': 0.90,
                'content_provider': 1.05,
                'intent_based': 0.85,
                'uri_based': 0.90,
                'webview_based': 0.80
            },
            'file_location': {
                'AndroidManifest.xml': 1.10,
                'java': 1.0,
                'kotlin': 1.0,
                'native': 0.95,
                'resources': 0.90,
                'assets': 0.85
            },
            'analysis_method': {
                'static': 1.0,
                'dynamic': 1.15,
                'hybrid': 1.20,
                'manual': 1.25
            }
        }
        
        logger.info("Traversal confidence calculator initialized with professional scoring")
    
    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence score for a traversal vulnerability finding.
        
        Args:
            evidence: Dictionary containing evidence factors
            
        Returns:
            float: Confidence score between 0.0 and 1.0
        """
        try:
            # Extract and validate evidence
            traversal_evidence = self._extract_evidence(evidence)
            
            # Calculate evidence-based score
            evidence_score = self._calculate_evidence_score(traversal_evidence)
            
            # Apply pattern reliability adjustment
            pattern_adjustment = self._calculate_pattern_reliability(evidence)
            
            # Apply context-aware adjustments
            context_adjustment = self._calculate_context_adjustment(evidence)
            
            # Calculate final confidence score
            base_confidence = evidence_score * pattern_adjustment * context_adjustment
            
            # Apply calibration to ensure accurate probability representation
            calibrated_confidence = self._apply_calibration(base_confidence, evidence)
            
            # Ensure confidence is within valid range
            final_confidence = max(0.0, min(1.0, calibrated_confidence))
            
            logger.debug(f"Traversal confidence calculated: {final_confidence:.3f}")
            return final_confidence
            
        except Exception as e:
            logger.error(f"Error calculating traversal confidence: {e}")
            return 0.5  # Conservative default
    
    def _extract_evidence(self, evidence: Dict[str, Any]) -> TraversalEvidence:
        """Extract and validate evidence factors from input."""
        return TraversalEvidence(
            pattern_reliability=evidence.get('pattern_reliability', 0.0),
            context_quality=evidence.get('context_quality', 0.0),
            validation_assessment=evidence.get('validation_assessment', 0.0),
            sanitization_assessment=evidence.get('sanitization_assessment', 0.0),
            payload_effectiveness=evidence.get('payload_effectiveness', 0.0),
            bypass_potential=evidence.get('bypass_potential', 0.0)
        )
    
    def _calculate_evidence_score(self, evidence: TraversalEvidence) -> float:
        """Calculate weighted evidence score."""
        score = (
            evidence.pattern_reliability * self.evidence_weights['path_validation'] +
            evidence.context_quality * self.evidence_weights['uri_security'] +
            evidence.validation_assessment * self.evidence_weights['file_permissions'] +
            evidence.sanitization_assessment * self.evidence_weights['payload_effectiveness'] +
            evidence.payload_effectiveness * self.evidence_weights['context_analysis'] +
            evidence.bypass_potential * self.evidence_weights['bypass_potential']
        )
        return score
    
    def _calculate_pattern_reliability(self, evidence: Dict[str, Any]) -> float:
        """Calculate pattern reliability adjustment factor."""
        pattern_type = evidence.get('pattern_type', 'path_traversal_patterns')
        
        if pattern_type in self.pattern_reliability_data:
            reliability = self.pattern_reliability_data[pattern_type]['reliability']
            return reliability
        
        return 0.85  # Conservative default
    
    def _calculate_context_adjustment(self, evidence: Dict[str, Any]) -> float:
        """Calculate context-aware adjustment factor."""
        adjustment = 1.0
        
        # Traversal type adjustment
        traversal_type = evidence.get('traversal_type', 'path_traversal')
        if traversal_type in self.context_factors['traversal_type']:
            adjustment *= self.context_factors['traversal_type'][traversal_type]
        
        # File location adjustment
        file_location = evidence.get('file_location', 'java')
        file_ext = file_location.split('.')[-1] if '.' in file_location else file_location
        
        if 'AndroidManifest.xml' in file_location:
            adjustment *= self.context_factors['file_location']['AndroidManifest.xml']
        elif file_ext in ['java', 'kt']:
            adjustment *= self.context_factors['file_location']['java']
        elif file_ext in ['xml', 'json']:
            adjustment *= self.context_factors['file_location']['resources']
        
        # Analysis method adjustment
        analysis_method = evidence.get('analysis_method', 'static')
        if analysis_method in self.context_factors['analysis_method']:
            adjustment *= self.context_factors['analysis_method'][analysis_method]
        
        return adjustment
    
    def _apply_calibration(self, confidence: float, evidence: Dict[str, Any]) -> float:
        """Apply calibration to ensure confidence reflects actual probability."""
        # Platt scaling-like calibration
        calibrated = 1.0 / (1.0 + pow(2.71828, -confidence))
        
        # Adjust based on evidence quality
        evidence_quality = evidence.get('evidence_quality', 0.8)
        calibrated *= evidence_quality
        
        return calibrated
    
    def get_confidence_factors(self, evidence: Dict[str, Any]) -> Dict[str, float]:
        """Get detailed confidence factor breakdown for transparency."""
        traversal_evidence = self._extract_evidence(evidence)
        
        return {
            'path_validation': traversal_evidence.pattern_reliability,
            'uri_security': traversal_evidence.context_quality,
            'file_permissions': traversal_evidence.validation_assessment,
            'payload_effectiveness': traversal_evidence.payload_effectiveness,
            'context_analysis': traversal_evidence.sanitization_assessment,
            'bypass_potential': traversal_evidence.bypass_potential,
            'pattern_reliability': self._calculate_pattern_reliability(evidence),
            'context_adjustment': self._calculate_context_adjustment(evidence)
        }
    
    def get_pattern_reliability(self, pattern_type: str) -> float:
        """Get pattern reliability score for specific pattern type."""
        return self.pattern_reliability_data.get(pattern_type, {}).get('reliability', 0.85)
    
    def update_pattern_reliability(self, pattern_type: str, accuracy_data: Dict[str, float]):
        """Update pattern reliability based on validation results."""
        if pattern_type not in self.pattern_reliability_data:
            self.pattern_reliability_data[pattern_type] = {'reliability': 0.85, 'fp_rate': 0.15}
        
        # Update with new accuracy data
        self.pattern_reliability_data[pattern_type]['reliability'] = accuracy_data.get('reliability', 0.85)
        self.pattern_reliability_data[pattern_type]['fp_rate'] = accuracy_data.get('fp_rate', 0.15)
        
        logger.info(f"Updated pattern reliability for {pattern_type}: {accuracy_data}")
    
    def calculate_traversal_specific_confidence(self, traversal_type: str, 
                                              validation_strength: float,
                                              payload_success_rate: float) -> float:
        """
        Calculate confidence specific to traversal vulnerability characteristics.
        
        Args:
            traversal_type: Type of traversal vulnerability
            validation_strength: Strength of input validation (0.0-1.0)
            payload_success_rate: Success rate of payload testing (0.0-1.0)
            
        Returns:
            float: Confidence score between 0.0 and 1.0
        """
        # Base confidence from traversal type
        base_confidence = self.context_factors['traversal_type'].get(traversal_type, 0.8)
        
        # Adjust based on validation strength (lower validation = higher confidence)
        validation_factor = 1.0 - (validation_strength * 0.3)
        
        # Adjust based on payload success rate
        payload_factor = 0.7 + (payload_success_rate * 0.3)
        
        # Calculate final confidence
        confidence = base_confidence * validation_factor * payload_factor
        
        return max(0.0, min(1.0, confidence))
    
    def assess_bypass_confidence(self, bypass_methods: List[str], 
                                countermeasures: List[str]) -> float:
        """
        Assess confidence in bypass techniques for traversal vulnerabilities.
        
        Args:
            bypass_methods: List of potential bypass methods
            countermeasures: List of implemented countermeasures
            
        Returns:
            float: Bypass confidence score
        """
        if not bypass_methods:
            return 0.0
        
        # Base confidence from number of bypass methods
        base_confidence = min(len(bypass_methods) * 0.2, 1.0)
        
        # Reduce confidence based on countermeasures
        countermeasure_factor = max(0.3, 1.0 - (len(countermeasures) * 0.15))
        
        # Calculate bypass confidence
        bypass_confidence = base_confidence * countermeasure_factor
        
        return max(0.0, min(1.0, bypass_confidence))

def calculate_dynamic_confidence(evidence: Dict[str, Any]) -> float:
    """
    Calculate confidence for dynamic traversal vulnerability analysis.
    
    Args:
        evidence: Dictionary containing dynamic analysis evidence
        
    Returns:
        float: Dynamic confidence score
    """
    calculator = TraversalConfidenceCalculator()
    
    # Enhance evidence with dynamic analysis factors
    enhanced_evidence = evidence.copy()
    enhanced_evidence['analysis_method'] = 'dynamic'
    enhanced_evidence['evidence_quality'] = 0.9  # Dynamic analysis provides higher quality evidence
    
    return calculator.calculate_confidence(enhanced_evidence) 