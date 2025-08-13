"""
Enhanced Confidence Scoring System
Replaces broken 0.0 confidence scores with evidence-based scoring
"""

import re
import math
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1

class EvidenceType(Enum):
    """Types of evidence for confidence scoring."""
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    PATTERN_MATCH = "pattern_match"
    HEURISTIC = "heuristic"
    ML_PREDICTION = "ml_prediction"
    EXPERT_RULE = "expert_rule"

@dataclass
class Evidence:
    """Evidence for vulnerability confidence scoring."""
    evidence_type: EvidenceType
    confidence: float
    description: str
    weight: float = 1.0
    source: str = ""

class EnhancedConfidenceScorer:
    """Advanced confidence scoring system with evidence-based calculation."""
    
    def __init__(self):
        self.evidence_weights = self._get_evidence_weights()
        self.pattern_confidences = self._get_pattern_confidences()
        self.scoring_history = []
    
    def _get_evidence_weights(self) -> Dict[EvidenceType, float]:
        """Get weights for different types of evidence."""
        return {
            EvidenceType.EXPERT_RULE: 0.95,
            EvidenceType.DYNAMIC_ANALYSIS: 0.90,
            EvidenceType.ML_PREDICTION: 0.85,
            EvidenceType.STATIC_ANALYSIS: 0.80,
            EvidenceType.PATTERN_MATCH: 0.75,
            EvidenceType.HEURISTIC: 0.60
        }
    
    def _get_pattern_confidences(self) -> Dict[str, float]:
        """Get confidence scores for specific vulnerability patterns."""
        return {
            # High confidence patterns
            "hardcoded_password": 0.90,
            "sql_injection": 0.85,
            "path_traversal": 0.80,
            "command_injection": 0.85,
            "cryptographic_weakness": 0.75,
            
            # Medium confidence patterns  
            "insecure_random": 0.70,
            "weak_crypto": 0.65,
            "exported_component": 0.60,
            "debug_enabled": 0.55,
            
            # Lower confidence patterns
            "potential_leak": 0.45,
            "suspicious_permission": 0.40,
            "code_quality": 0.35,
            "best_practice": 0.30
        }
    
    def calculate_base_confidence(self, vulnerability_type: str, severity: SeverityLevel) -> float:
        """Calculate base confidence score based on vulnerability type and severity."""
        
        # Get pattern-specific confidence
        pattern_confidence = self.pattern_confidences.get(vulnerability_type.lower(), 0.5)
        
        # Severity multiplier
        severity_multipliers = {
            SeverityLevel.CRITICAL: 1.0,
            SeverityLevel.HIGH: 0.9,
            SeverityLevel.MEDIUM: 0.8,
            SeverityLevel.LOW: 0.7
        }
        
        severity_multiplier = severity_multipliers.get(severity, 0.8)
        
        return pattern_confidence * severity_multiplier
    
    def calculate_evidence_score(self, evidence_list: List[Evidence]) -> float:
        """Calculate evidence-based confidence score."""
        if not evidence_list:
            return 0.5  # Default medium confidence
        
        weighted_scores = []
        total_weight = 0
        
        for evidence in evidence_list:
            evidence_weight = self.evidence_weights.get(evidence.evidence_type, 0.5)
            weighted_score = evidence.confidence * evidence_weight * evidence.weight
            weighted_scores.append(weighted_score)
            total_weight += evidence_weight * evidence.weight
        
        if total_weight == 0:
            return 0.5
        
        # Calculate weighted average
        evidence_score = sum(weighted_scores) / total_weight
        
        # Apply evidence count bonus (more evidence = higher confidence)
        evidence_count_bonus = min(0.1, len(evidence_list) * 0.02)
        evidence_score = min(1.0, evidence_score + evidence_count_bonus)
        
        return evidence_score
    
    def calculate_context_adjustments(self, context: Dict[str, Any]) -> float:
        """Calculate context-based confidence adjustments."""
        adjustment = 0.0
        
        # File location adjustment
        file_path = context.get("file_path", "")
        if file_path:
            if any(pattern in file_path.lower() for pattern in ['test', 'example', 'demo']):
                adjustment -= 0.2  # Lower confidence for test/demo code
            elif any(pattern in file_path.lower() for pattern in ['security', 'auth', 'crypto']):
                adjustment += 0.1  # Higher confidence for security-related files
        
        # Code context adjustment
        surrounding_code = context.get("surrounding_code", "")
        if surrounding_code:
            # Check for security-related context
            security_indicators = ['security', 'auth', 'crypto', 'password', 'key', 'token']
            if any(indicator in surrounding_code.lower() for indicator in security_indicators):
                adjustment += 0.05
            
            # Check for test/debug context
            test_indicators = ['test', 'debug', 'mock', 'fake', 'dummy']
            if any(indicator in surrounding_code.lower() for indicator in test_indicators):
                adjustment -= 0.15
        
        # Framework/library adjustment
        is_framework_code = context.get("is_framework_code", False)
        if is_framework_code:
            adjustment -= 0.3  # Much lower confidence for framework code
        
        return adjustment
    
    def calculate_ml_enhancement(self, ml_prediction: Optional[float], 
                                ml_confidence: Optional[float]) -> float:
        """Calculate ML-based confidence enhancement."""
        if ml_prediction is None or ml_confidence is None:
            return 0.0
        
        # ML enhancement based on prediction confidence
        if ml_confidence > 0.8:
            return 0.1  # High ML confidence boost
        elif ml_confidence > 0.6:
            return 0.05  # Medium ML confidence boost
        else:
            return 0.0  # Low ML confidence - no boost
    
    def score_vulnerability(self, vulnerability_type: str, severity: SeverityLevel,
                           evidence_list: List[Evidence], context: Dict[str, Any] = None,
                           ml_prediction: Optional[float] = None,
                           ml_confidence: Optional[float] = None) -> Dict[str, Any]:
        """Comprehensive vulnerability confidence scoring."""
        
        context = context or {}
        
        # Calculate base confidence
        base_confidence = self.calculate_base_confidence(vulnerability_type, severity)
        
        # Calculate evidence-based score
        evidence_score = self.calculate_evidence_score(evidence_list)
        
        # Calculate context adjustments
        context_adjustment = self.calculate_context_adjustments(context)
        
        # Calculate ML enhancement
        ml_enhancement = self.calculate_ml_enhancement(ml_prediction, ml_confidence)
        
        # Combine all factors
        raw_confidence = (base_confidence * 0.4 + evidence_score * 0.5 + 
                         context_adjustment + ml_enhancement)
        
        # Ensure confidence is within bounds [0.1, 1.0]
        final_confidence = max(0.1, min(1.0, raw_confidence))
        
        # Create detailed scoring breakdown
        scoring_details = {
            "final_confidence": final_confidence,
            "base_confidence": base_confidence,
            "evidence_score": evidence_score,
            "context_adjustment": context_adjustment,
            "ml_enhancement": ml_enhancement,
            "evidence_count": len(evidence_list),
            "vulnerability_type": vulnerability_type,
            "severity": severity.name,
            "scoring_factors": {
                "pattern_recognition": base_confidence,
                "evidence_quality": evidence_score,
                "contextual_relevance": context_adjustment,
                "ml_validation": ml_enhancement
            }
        }
        
        # Log scoring details for transparency
        logger.debug(f"Confidence scoring for {vulnerability_type}:")
        logger.debug(f"  Final confidence: {final_confidence:.3f}")
        logger.debug(f"  Base: {base_confidence:.3f}, Evidence: {evidence_score:.3f}")
        logger.debug(f"  Context: {context_adjustment:+.3f}, ML: {ml_enhancement:+.3f}")
        
        # Store in history for learning
        self.scoring_history.append(scoring_details)
        
        return scoring_details
    
    def create_evidence(self, evidence_type: EvidenceType, confidence: float,
                       description: str, weight: float = 1.0, source: str = "") -> Evidence:
        """Helper method to create evidence objects."""
        return Evidence(
            evidence_type=evidence_type,
            confidence=confidence,
            description=description,
            weight=weight,
            source=source
        )
    
    def score_simple_finding(self, vulnerability_type: str, severity_str: str = "medium",
                           description: str = "", source: str = "") -> float:
        """Simple confidence scoring for basic findings."""
        
        # Convert severity string to enum
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW
        }
        severity = severity_map.get(severity_str.lower(), SeverityLevel.MEDIUM)
        
        # Create basic evidence
        evidence = [
            self.create_evidence(
                EvidenceType.PATTERN_MATCH,
                0.7,
                description or f"Pattern match for {vulnerability_type}",
                source=source
            )
        ]
        
        # Score the vulnerability
        scoring_result = self.score_vulnerability(vulnerability_type, severity, evidence)
        return scoring_result["final_confidence"]
    
    def get_scoring_statistics(self) -> Dict[str, Any]:
        """Get confidence scoring statistics."""
        if not self.scoring_history:
            return {"message": "No scoring history available"}
        
        confidences = [score["final_confidence"] for score in self.scoring_history]
        
        return {
            "total_scores": len(confidences),
            "average_confidence": sum(confidences) / len(confidences),
            "min_confidence": min(confidences),
            "max_confidence": max(confidences),
            "confidence_distribution": {
                "high (>0.8)": sum(1 for c in confidences if c > 0.8),
                "medium (0.5-0.8)": sum(1 for c in confidences if 0.5 <= c <= 0.8),
                "low (<0.5)": sum(1 for c in confidences if c < 0.5)
            }
        }

# Global enhanced confidence scorer instance
enhanced_confidence_scorer = EnhancedConfidenceScorer()

def score_finding_confidence(vulnerability_type: str, severity: str = "medium",
                           description: str = "", source: str = "") -> float:
    """Global function for simple confidence scoring."""
    return enhanced_confidence_scorer.score_simple_finding(
        vulnerability_type, severity, description, source
    ) 