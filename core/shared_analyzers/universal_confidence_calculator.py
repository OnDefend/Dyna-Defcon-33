#!/usr/bin/env python3
"""
Universal Confidence Calculator for AODS Plugin Modularization

This module provides standardized confidence calculation methodology across
all plugins, eliminating hardcoded confidence values and implementing
evidence-based confidence scoring.

Features:
- Multi-factor evidence analysis
- Pattern reliability database with historical accuracy
- Context-aware confidence adjustments
- Cross-validation assessment capabilities
- Plugin-specific confidence factors
- Statistical confidence calibration
- Comprehensive error handling and logging
"""

import logging
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum

logger = logging.getLogger(__name__)

class ConfidenceFactorType(Enum):
    """Types of confidence factors."""
    EVIDENCE_QUALITY = "evidence_quality"
    PATTERN_RELIABILITY = "pattern_reliability"
    CONTEXT_RELEVANCE = "context_relevance"
    VALIDATION_SOURCES = "validation_sources"
    IMPLEMENTATION_CONTEXT = "implementation_context"

@dataclass
class ConfidenceEvidence:
    """Represents evidence for confidence calculation."""
    factor_type: ConfidenceFactorType
    factor_name: str
    value: float
    weight: float
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate evidence values."""
        if not 0.0 <= self.value <= 1.0:
            raise ValueError(f"Evidence value must be between 0.0 and 1.0, got {self.value}")
        if not 0.0 <= self.weight <= 1.0:
            raise ValueError(f"Evidence weight must be between 0.0 and 1.0, got {self.weight}")

@dataclass
class PatternReliability:
    """Pattern reliability data based on historical accuracy."""
    pattern_id: str
    pattern_name: str
    total_validations: int
    correct_predictions: int
    false_positive_rate: float
    false_negative_rate: float
    confidence_adjustment: float
    last_updated: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def accuracy(self) -> float:
        """Calculate pattern accuracy."""
        if self.total_validations == 0:
            return 0.5  # Default neutral accuracy
        return self.correct_predictions / self.total_validations
    
    @property
    def reliability_score(self) -> float:
        """Calculate reliability score (0.0 to 1.0)."""
        if self.total_validations < 10:
            # Insufficient data, conservative scoring
            return 0.5 + (self.accuracy - 0.5) * 0.5
        return self.accuracy

@dataclass
class ConfidenceConfiguration:
    """Configuration for confidence calculation."""
    plugin_type: str
    evidence_weights: Dict[ConfidenceFactorType, float]
    context_factors: Dict[str, float]
    reliability_database: Dict[str, PatternReliability]
    minimum_confidence: float = 0.1
    maximum_confidence: float = 0.95
    default_pattern_reliability: float = 0.8
    cross_validation_bonus: float = 0.1
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate configuration."""
        # Validate evidence weights sum to 1.0
        total_weight = sum(self.evidence_weights.values())
        if not 0.95 <= total_weight <= 1.05:  # Allow small floating point errors
            logger.warning(f"Evidence weights sum to {total_weight}, should be close to 1.0")
        
        # Validate confidence bounds
        if not 0.0 <= self.minimum_confidence < self.maximum_confidence <= 1.0:
            raise ValueError("Invalid confidence bounds")

class UniversalConfidenceCalculator:
    """
    Universal confidence calculator providing standardized confidence
    scoring methodology across all AODS plugins.
    """

    def __init__(self, config: ConfidenceConfiguration):
        """
        Initialize the universal confidence calculator.

        Args:
            config: Configuration for confidence calculation
        """
        self.config = config
        self.calculation_history: List[Dict[str, Any]] = []
        
        # Default evidence weights if not specified
        self.default_weights = {
            ConfidenceFactorType.EVIDENCE_QUALITY: 0.25,
            ConfidenceFactorType.PATTERN_RELIABILITY: 0.25,
            ConfidenceFactorType.CONTEXT_RELEVANCE: 0.20,
            ConfidenceFactorType.VALIDATION_SOURCES: 0.20,
            ConfidenceFactorType.IMPLEMENTATION_CONTEXT: 0.10
        }
        
        logger.info(f"UniversalConfidenceCalculator initialized for {config.plugin_type}")

    def calculate_confidence(self, 
                           evidence_list: List[ConfidenceEvidence],
                           pattern_id: Optional[str] = None,
                           context: Optional[Dict[str, Any]] = None) -> float:
        """
        Calculate confidence score based on evidence and context.

        Args:
            evidence_list: List of confidence evidence
            pattern_id: Pattern identifier for reliability lookup
            context: Additional context for confidence calculation

        Returns:
            Confidence score between minimum_confidence and maximum_confidence
        """
        if not evidence_list:
            logger.warning("No evidence provided for confidence calculation")
            return self.config.minimum_confidence
        
        try:
            # Calculate base confidence from evidence
            base_confidence = self._calculate_evidence_based_confidence(evidence_list)
            
            # Apply pattern reliability adjustment
            reliability_adjusted = self._apply_pattern_reliability(base_confidence, pattern_id)
            
            # Apply context adjustments
            context_adjusted = self._apply_context_adjustments(reliability_adjusted, context)
            
            # Apply cross-validation bonus if applicable
            final_confidence = self._apply_cross_validation_bonus(context_adjusted, context)
            
            # Ensure confidence is within bounds
            bounded_confidence = max(
                self.config.minimum_confidence,
                min(self.config.maximum_confidence, final_confidence)
            )
            
            # Record calculation for analysis
            self._record_calculation(evidence_list, pattern_id, context, bounded_confidence)
            
            return bounded_confidence
            
        except Exception as e:
            logger.error(f"Error in confidence calculation: {e}")
            return self.config.minimum_confidence

    def _calculate_evidence_based_confidence(self, evidence_list: List[ConfidenceEvidence]) -> float:
        """Calculate base confidence from evidence factors."""
        total_weighted_score = 0.0
        total_weight = 0.0
        
        # Group evidence by factor type
        evidence_by_type: Dict[ConfidenceFactorType, List[ConfidenceEvidence]] = {}
        for evidence in evidence_list:
            if evidence.factor_type not in evidence_by_type:
                evidence_by_type[evidence.factor_type] = []
            evidence_by_type[evidence.factor_type].append(evidence)
        
        # Calculate weighted average for each factor type
        for factor_type, evidences in evidence_by_type.items():
            factor_weight = self.config.evidence_weights.get(
                factor_type, 
                self.default_weights.get(factor_type, 0.2)
            )
            
            # Calculate average value for this factor type
            if evidences:
                factor_value = sum(e.value * e.weight for e in evidences) / sum(e.weight for e in evidences)
                total_weighted_score += factor_value * factor_weight
                total_weight += factor_weight
        
        # Calculate base confidence
        if total_weight > 0:
            base_confidence = total_weighted_score / total_weight
        else:
            base_confidence = 0.5  # Neutral confidence
        
        return base_confidence

    def _apply_pattern_reliability(self, base_confidence: float, pattern_id: Optional[str]) -> float:
        """Apply pattern reliability adjustment."""
        if pattern_id is None:
            return base_confidence
        
        reliability = self.config.reliability_database.get(pattern_id)
        if reliability is None:
            # Use default pattern reliability
            reliability_score = self.config.default_pattern_reliability
        else:
            reliability_score = reliability.reliability_score
            
        # Apply reliability adjustment
        # High reliability patterns get a bonus, low reliability get penalty
        reliability_factor = 0.5 + (reliability_score - 0.5) * 0.4  # Scale to 0.3-0.7 range
        adjusted_confidence = base_confidence * reliability_factor
        
        return adjusted_confidence

    def _apply_context_adjustments(self, confidence: float, context: Optional[Dict[str, Any]]) -> float:
        """Apply context-specific confidence adjustments."""
        if context is None:
            return confidence
        
        adjusted_confidence = confidence
        
        # Apply context factors
        for context_key, context_value in context.items():
            if context_key in self.config.context_factors:
                factor = self.config.context_factors[context_key]
                
                # Apply context adjustment based on value type
                if isinstance(context_value, bool):
                    if context_value:
                        adjusted_confidence *= (1.0 + factor * 0.1)
                    else:
                        adjusted_confidence *= (1.0 - factor * 0.1)
                elif isinstance(context_value, (int, float)):
                    # Normalize numeric values and apply adjustment
                    normalized_value = max(0.0, min(1.0, float(context_value)))
                    adjustment = (normalized_value - 0.5) * factor * 0.2
                    adjusted_confidence *= (1.0 + adjustment)
        
        return adjusted_confidence

    def _apply_cross_validation_bonus(self, confidence: float, context: Optional[Dict[str, Any]]) -> float:
        """Apply bonus for cross-validation from multiple sources."""
        if context is None:
            return confidence
        
        validation_sources = context.get('validation_sources', [])
        if isinstance(validation_sources, list) and len(validation_sources) > 1:
            # Apply bonus based on number of validation sources
            validation_bonus = min(
                self.config.cross_validation_bonus,
                (len(validation_sources) - 1) * 0.05
            )
            return confidence * (1.0 + validation_bonus)
        
        return confidence

    def _record_calculation(self, 
                          evidence_list: List[ConfidenceEvidence],
                          pattern_id: Optional[str],
                          context: Optional[Dict[str, Any]],
                          final_confidence: float) -> None:
        """Record confidence calculation for analysis."""
        calculation_record = {
            'timestamp': __import__('time').time(),
            'plugin_type': self.config.plugin_type,
            'evidence_count': len(evidence_list),
            'pattern_id': pattern_id,
            'context_keys': list(context.keys()) if context else [],
            'final_confidence': final_confidence,
            'evidence_types': [e.factor_type.value for e in evidence_list]
        }
        
        self.calculation_history.append(calculation_record)
        
        # Keep only recent calculations (last 1000)
        if len(self.calculation_history) > 1000:
            self.calculation_history = self.calculation_history[-1000:]

    def create_evidence(self, 
                       factor_type: ConfidenceFactorType,
                       factor_name: str,
                       value: float,
                       weight: float = 1.0,
                       description: str = "",
                       metadata: Optional[Dict[str, Any]] = None) -> ConfidenceEvidence:
        """
        Create confidence evidence with validation.

        Args:
            factor_type: Type of confidence factor
            factor_name: Name of the specific factor
            value: Evidence value (0.0 to 1.0)
            weight: Evidence weight (0.0 to 1.0)
            description: Human-readable description
            metadata: Additional metadata

        Returns:
            Validated confidence evidence
        """
        return ConfidenceEvidence(
            factor_type=factor_type,
            factor_name=factor_name,
            value=value,
            weight=weight,
            description=description,
            metadata=metadata or {}
        )

    def update_pattern_reliability(self, 
                                 pattern_id: str,
                                 was_correct: bool,
                                 metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Update pattern reliability based on validation result.

        Args:
            pattern_id: Pattern identifier
            was_correct: Whether the pattern prediction was correct
            metadata: Additional metadata for the validation
        """
        if pattern_id not in self.config.reliability_database:
            # Initialize new pattern reliability
            self.config.reliability_database[pattern_id] = PatternReliability(
                pattern_id=pattern_id,
                pattern_name=pattern_id,
                total_validations=0,
                correct_predictions=0,
                false_positive_rate=0.0,
                false_negative_rate=0.0,
                confidence_adjustment=1.0,
                last_updated=__import__('datetime').datetime.now().isoformat(),
                metadata=metadata or {}
            )
        
        reliability = self.config.reliability_database[pattern_id]
        
        # Update statistics
        reliability.total_validations += 1
        if was_correct:
            reliability.correct_predictions += 1
        
        # Recalculate rates
        if reliability.total_validations > 0:
            accuracy = reliability.correct_predictions / reliability.total_validations
            reliability.false_positive_rate = max(0.0, 1.0 - accuracy) / 2.0
            reliability.false_negative_rate = max(0.0, 1.0 - accuracy) / 2.0
        
        reliability.last_updated = __import__('datetime').datetime.now().isoformat()
        
        logger.debug(f"Updated pattern {pattern_id} reliability: {reliability.accuracy:.3f} accuracy")

    def _calculate_weighted_confidence(self, evidence_data: Dict[str, float]) -> float:
        """
        Calculate weighted confidence score based on multiple evidence factors.
        
        This method provides compatibility for legacy code that expects this interface
        while leveraging the UniversalConfidenceCalculator's evidence-based approach.
        
        Args:
            evidence_data: Dictionary of evidence factors and their scores
            
        Returns:
            Weighted confidence score between 0.0 and 1.0
        """
        try:
            if not evidence_data:
                return 0.5  # Default confidence when no evidence
            
            # Convert evidence_data to ConfidenceEvidence objects
            evidence_list = []
            
            # Map common evidence keys to confidence factors
            evidence_mapping = {
                'pattern_match': ConfidenceFactorType.PATTERN_RELIABILITY,
                'pattern_reliability': ConfidenceFactorType.PATTERN_RELIABILITY,
                'context_relevance': ConfidenceFactorType.CONTEXT_RELEVANCE,
                'evidence_quality': ConfidenceFactorType.EVIDENCE_QUALITY,
                'validation_sources': ConfidenceFactorType.VALIDATION_SOURCES,
                'implementation_context': ConfidenceFactorType.IMPLEMENTATION_CONTEXT,
                'location_specificity': ConfidenceFactorType.CONTEXT_RELEVANCE
            }
            
            # Default weights if not configured
            default_weights = {
                ConfidenceFactorType.PATTERN_RELIABILITY: 0.30,
                ConfidenceFactorType.CONTEXT_RELEVANCE: 0.25,
                ConfidenceFactorType.EVIDENCE_QUALITY: 0.20,
                ConfidenceFactorType.VALIDATION_SOURCES: 0.15,
                ConfidenceFactorType.IMPLEMENTATION_CONTEXT: 0.10
            }
            
            for factor_name, score in evidence_data.items():
                # Map factor name to confidence factor type
                factor_type = evidence_mapping.get(factor_name, ConfidenceFactorType.EVIDENCE_QUALITY)
                
                # Get weight from config or use default
                weight = self.config.evidence_weights.get(factor_type, default_weights.get(factor_type, 0.1))
                
                # Create evidence object
                evidence = ConfidenceEvidence(
                    factor_type=factor_type,
                    factor_name=factor_name,
                    value=max(0.0, min(1.0, float(score))),  # Clamp to valid range
                    weight=weight,
                    description=f"Legacy evidence factor: {factor_name}"
                )
                evidence_list.append(evidence)
            
            # Use the main calculate_confidence method
            return self.calculate_confidence(evidence_list)
            
        except Exception as e:
            logger.warning(f"Weighted confidence calculation failed: {e}")
            return 0.5  # Default confidence on error

    def get_statistics(self) -> Dict[str, Any]:
        """Get confidence calculation statistics."""
        if not self.calculation_history:
            return {'total_calculations': 0}
        
        confidences = [calc['final_confidence'] for calc in self.calculation_history]
        
        return {
            'total_calculations': len(self.calculation_history),
            'avg_confidence': sum(confidences) / len(confidences),
            'min_confidence': min(confidences),
            'max_confidence': max(confidences),
            'confidence_std': self._calculate_std(confidences),
            'pattern_reliability_count': len(self.config.reliability_database),
            'plugin_type': self.config.plugin_type
        }

    def _calculate_std(self, values: List[float]) -> float:
        """Calculate standard deviation."""
        if len(values) < 2:
            return 0.0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return math.sqrt(variance) 