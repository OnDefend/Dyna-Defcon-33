"""
Confidence calculation system with evidence-based methodology
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class ConfidenceLevel(Enum):
    """Confidence levels for vulnerability findings."""
    VERY_HIGH = "VERY_HIGH"  # 90-100%
    HIGH = "HIGH"           # 75-90%
    MEDIUM = "MEDIUM"       # 50-75%
    LOW = "LOW"             # 25-50%
    VERY_LOW = "VERY_LOW"   # 0-25%

@dataclass
class ConfidenceEvidence:
    """Evidence structure for confidence calculation."""
    pattern_type: str
    pattern_strength: str  # 'high', 'medium', 'low'
    context_relevance: str
    validation_sources: List[str]
    attack_vector_clarity: str  # 'direct', 'indirect', 'theoretical'
    false_positive_indicators: List[str]

class ConfidenceCalculator:
    """
    Universal confidence calculator for AODS security findings.
    
    This class provides consistent, evidence-based confidence scoring
    across all AODS plugins and analysis types.
    """
    
    def __init__(self):
        """Initialize the confidence calculator."""
        self.evidence_weights = {
            'pattern_reliability': 0.30,
            'context_relevance': 0.25,
            'validation_coverage': 0.20,
            'attack_vector_clarity': 0.15,
            'false_positive_adjustment': 0.10
        }
        
        # Pattern reliability database with historical false positive rates
        self.pattern_reliability = {
            # High reliability patterns (< 5% FP rate)
            'explicit_vulnerability': 0.98,
            'confirmed_exploitation': 0.96,
            'verified_bypass': 0.94,
            'working_proof_of_concept': 0.95,
            
            # Medium reliability patterns (5-15% FP rate)
            'suspicious_pattern': 0.87,
            'potential_vulnerability': 0.82,
            'insecure_configuration': 0.85,
            'weak_implementation': 0.80,
            
            # Lower reliability patterns (15-30% FP rate)
            'generic_pattern': 0.75,
            'heuristic_detection': 0.70,
            'framework_analysis': 0.72,
            'automated_finding': 0.68
        }
        
        # Context relevance adjustments
        self.context_factors = {
            'implementation_file': 1.0,
            'configuration_file': 0.85,
            'test_file': 0.60,
            'documentation_file': 0.40,
            'build_artifact': 0.30
        }
        
        # Attack vector clarity scoring
        self.attack_vector_scoring = {
            'direct': 1.0,      # Direct exploitation path
            'indirect': 0.75,   # Requires additional steps
            'theoretical': 0.50, # Theoretical vulnerability
            'speculative': 0.25  # Highly speculative
        }
    
    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence score based on evidence.
        
        Args:
            evidence: Dictionary containing evidence factors
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        try:
            # Extract evidence components
            pattern_type = evidence.get('pattern_type', 'generic_pattern')
            pattern_strength = evidence.get('pattern_strength', 'medium')
            context_relevance = evidence.get('context_relevance', 'implementation_file')
            validation_sources = evidence.get('validation_sources', [])
            attack_vector_clarity = evidence.get('attack_vector_clarity', 'indirect')
            false_positive_indicators = evidence.get('false_positive_indicators', [])
            
            # Calculate individual factor scores
            pattern_score = self._calculate_pattern_score(pattern_type, pattern_strength)
            context_score = self._calculate_context_score(context_relevance)
            validation_score = self._calculate_validation_score(validation_sources)
            attack_vector_score = self._calculate_attack_vector_score(attack_vector_clarity)
            fp_adjustment = self._calculate_false_positive_adjustment(false_positive_indicators)
            
            # Weighted confidence calculation
            confidence = (
                pattern_score * self.evidence_weights['pattern_reliability'] +
                context_score * self.evidence_weights['context_relevance'] +
                validation_score * self.evidence_weights['validation_coverage'] +
                attack_vector_score * self.evidence_weights['attack_vector_clarity'] +
                fp_adjustment * self.evidence_weights['false_positive_adjustment']
            )
            
            # Ensure confidence is within valid range
            confidence = max(0.0, min(1.0, confidence))
            
            logger.debug(f"Confidence calculated: {confidence:.3f} for pattern: {pattern_type}")
            return confidence
            
        except Exception as e:
            logger.warning(f"Error calculating confidence: {e}")
            return 0.5  # Default medium confidence
    
    def _calculate_pattern_score(self, pattern_type: str, pattern_strength: str) -> float:
        """Calculate pattern reliability score."""
        base_reliability = self.pattern_reliability.get(pattern_type, 0.70)
        
        # Adjust based on pattern strength
        strength_multipliers = {
            'high': 1.0,
            'medium': 0.85,
            'low': 0.70
        }
        
        multiplier = strength_multipliers.get(pattern_strength, 0.85)
        return base_reliability * multiplier
    
    def _calculate_context_score(self, context_relevance: str) -> float:
        """Calculate context relevance score."""
        return self.context_factors.get(context_relevance, 0.70)
    
    def _calculate_validation_score(self, validation_sources: List[str]) -> float:
        """Calculate validation coverage score."""
        if not validation_sources:
            return 0.30
        
        # Score based on number and diversity of validation sources
        source_count = len(validation_sources)
        
        if source_count >= 3:
            return 0.95  # Triple validation
        elif source_count == 2:
            return 0.80  # Dual validation
        else:
            return 0.60  # Single validation
    
    def _calculate_attack_vector_score(self, attack_vector_clarity: str) -> float:
        """Calculate attack vector clarity score."""
        return self.attack_vector_scoring.get(attack_vector_clarity, 0.75)
    
    def _calculate_false_positive_adjustment(self, fp_indicators: List[str]) -> float:
        """Calculate false positive risk adjustment."""
        if not fp_indicators:
            return 1.0  # No false positive indicators
        
        # Reduce confidence based on number of FP indicators
        fp_count = len(fp_indicators)
        
        if fp_count >= 3:
            return 0.50  # High FP risk
        elif fp_count == 2:
            return 0.70  # Medium FP risk
        else:
            return 0.85  # Low FP risk
    
    def get_confidence_level(self, confidence_score: float) -> ConfidenceLevel:
        """Convert confidence score to confidence level."""
        if confidence_score >= 0.90:
            return ConfidenceLevel.VERY_HIGH
        elif confidence_score >= 0.75:
            return ConfidenceLevel.HIGH
        elif confidence_score >= 0.50:
            return ConfidenceLevel.MEDIUM
        elif confidence_score >= 0.25:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW
    
    def create_confidence_evidence(self, 
                                 pattern_type: str,
                                 pattern_strength: str = 'medium',
                                 context_relevance: str = 'implementation_file',
                                 validation_sources: Optional[List[str]] = None,
                                 attack_vector_clarity: str = 'indirect',
                                 false_positive_indicators: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Helper method to create properly structured evidence dictionary.
        
        Args:
            pattern_type: Type of vulnerability pattern detected
            pattern_strength: Strength of the pattern ('high', 'medium', 'low')
            context_relevance: Relevance of the context where found
            validation_sources: List of validation methods used
            attack_vector_clarity: Clarity of attack vector
            false_positive_indicators: List of false positive indicators
            
        Returns:
            Structured evidence dictionary
        """
        return {
            'pattern_type': pattern_type,
            'pattern_strength': pattern_strength,
            'context_relevance': context_relevance,
            'validation_sources': validation_sources or [],
            'attack_vector_clarity': attack_vector_clarity,
            'false_positive_indicators': false_positive_indicators or []
        }

# Convenience function for quick confidence calculation
def calculate_confidence(pattern_type: str, 
                        pattern_strength: str = 'medium',
                        context_relevance: str = 'implementation_file',
                        validation_sources: Optional[List[str]] = None,
                        attack_vector_clarity: str = 'indirect',
                        false_positive_indicators: Optional[List[str]] = None) -> float:
    """
    Quick confidence calculation function.
    
    Returns confidence score between 0.0 and 1.0.
    """
    calculator = ConfidenceCalculator()
    evidence = calculator.create_confidence_evidence(
        pattern_type=pattern_type,
        pattern_strength=pattern_strength,
        context_relevance=context_relevance,
        validation_sources=validation_sources,
        attack_vector_clarity=attack_vector_clarity,
        false_positive_indicators=false_positive_indicators
    )
    return calculator.calculate_confidence(evidence) 