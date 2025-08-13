"""
Enhanced Static Analysis - Confidence Calculator Component

This module provides confidence calculation capabilities for static analysis findings.
"""

import logging
from typing import Dict, List, Optional, Any
from .data_structures import (
    SecurityFinding, RiskLevel, SeverityLevel, AnalysisConfiguration
)

class StaticAnalysisConfidenceCalculator:
    """Confidence calculator for static analysis findings."""
    
    def __init__(self, config: Optional[AnalysisConfiguration] = None):
        """Initialize the confidence calculator."""
        self.config = config or AnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
        
        # Pattern reliability scores
        self.pattern_reliability = {
            'high_confidence': 0.95,
            'medium_confidence': 0.75,
            'low_confidence': 0.55,
            'heuristic': 0.35
        }
        
        # Severity-based confidence adjustments
        self.severity_confidence = {
            SeverityLevel.CRITICAL: 0.1,
            SeverityLevel.HIGH: 0.05,
            SeverityLevel.MEDIUM: 0.0,
            SeverityLevel.LOW: -0.05,
            SeverityLevel.INFO: -0.1
        }
    
    def calculate_confidence(self, finding: SecurityFinding, context: Optional[Dict[str, Any]] = None) -> float:
        """
        Calculate confidence score for a security finding.
        
        Args:
            finding: SecurityFinding to calculate confidence for
            context: Optional context information
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        try:
            # Base confidence from pattern reliability
            base_confidence = self.pattern_reliability.get('medium_confidence', 0.75)
            
            # Adjust based on severity
            severity = getattr(finding, 'severity', SeverityLevel.MEDIUM)
            severity_adjustment = self.severity_confidence.get(severity, 0.0)
            
            # Adjust based on evidence quality
            evidence_adjustment = self._calculate_evidence_adjustment(finding)
            
            # Combine adjustments
            final_confidence = base_confidence + severity_adjustment + evidence_adjustment
            
            # Ensure confidence is within valid range
            return max(0.0, min(1.0, final_confidence))
            
        except Exception as e:
            self.logger.warning(f"Confidence calculation failed: {e}")
            return 0.5  # Default confidence
    
    def _calculate_evidence_adjustment(self, finding: SecurityFinding) -> float:
        """Calculate confidence adjustment based on evidence quality."""
        adjustment = 0.0
        
        # Check if evidence is provided
        evidence = getattr(finding, 'evidence', None)
        if evidence:
            if len(str(evidence)) > 100:  # Substantial evidence
                adjustment += 0.1
            elif len(str(evidence)) > 50:  # Some evidence
                adjustment += 0.05
        
        # Check for location information
        location = getattr(finding, 'location', None)
        if location:
            adjustment += 0.05
        
        # Check for additional context
        description = getattr(finding, 'description', '')
        if len(description) > 50:  # Detailed description
            adjustment += 0.05
        
        return adjustment
    
    def _calculate_weighted_confidence(self, evidence_data: Dict[str, float]) -> float:
        """
        Calculate weighted confidence score based on multiple evidence factors.
        
        Args:
            evidence_data: Dictionary of evidence factors and their scores
            
        Returns:
            Weighted confidence score between 0.0 and 1.0
        """
        try:
            if not evidence_data:
                return 0.5  # Default confidence when no evidence
            
            # Evidence weights for static analysis
            evidence_weights = {
                'pattern_match': 0.30,      # How well the pattern matches
                'context_relevance': 0.25,  # How relevant in the code context
                'evidence_quality': 0.20,   # Quality of supporting evidence
                'location_specificity': 0.15, # How specific the location is
                'validation_sources': 0.10   # Number of validation sources
            }
            
            # Calculate weighted score
            total_score = 0.0
            total_weight = 0.0
            
            for factor, score in evidence_data.items():
                if factor in evidence_weights:
                    weight = evidence_weights[factor]
                    total_score += score * weight
                    total_weight += weight
                else:
                    # Handle unknown factors with lower weight
                    weight = 0.05
                    total_score += score * weight
                    total_weight += weight
            
            # Normalize by total weight
            if total_weight > 0:
                weighted_confidence = total_score / total_weight
            else:
                weighted_confidence = 0.5  # Default if no valid factors
            
            # Apply static analysis specific adjustments
            weighted_confidence = self._apply_static_analysis_adjustments(weighted_confidence, evidence_data)
            
            # Ensure confidence is within valid range
            return max(0.0, min(1.0, weighted_confidence))
            
        except Exception as e:
            self.logger.warning(f"Weighted confidence calculation failed: {e}")
            return 0.5  # Default confidence on error
    
    def _apply_static_analysis_adjustments(self, base_confidence: float, evidence_data: Dict[str, float]) -> float:
        """Apply static analysis specific adjustments to confidence score."""
        adjusted_confidence = base_confidence
        
        # Boost confidence for high-quality patterns
        pattern_match = evidence_data.get('pattern_match', 0.5)
        if pattern_match > 0.8:
            adjusted_confidence += 0.1
        elif pattern_match < 0.3:
            adjusted_confidence -= 0.1
        
        # Adjust based on context relevance
        context_relevance = evidence_data.get('context_relevance', 0.5)
        if context_relevance > 0.9:
            adjusted_confidence += 0.05
        elif context_relevance < 0.2:
            adjusted_confidence -= 0.1
        
        # Boost confidence for multiple validation sources
        validation_sources = evidence_data.get('validation_sources', 0.0)
        if validation_sources > 0.7:
            adjusted_confidence += 0.05
        
        return adjusted_confidence 