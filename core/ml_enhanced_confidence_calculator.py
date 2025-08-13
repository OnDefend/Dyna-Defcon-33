#!/usr/bin/env python3
"""
ML-Enhanced Confidence Calculator for AODS

Integrates machine learning models with traditional pattern-based confidence scoring
to provide more accurate vulnerability assessment and reduce false positives.

Features:
- ML-enhanced confidence scoring using existing ML models
- Integration with MLSecurityAnalyzer for code snippet analysis
- Contextual analysis using IntelligentVulnerabilityDetector
- False positive reduction using MLFalsePositiveReducer
- Fallback to traditional scoring when ML is unavailable
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

try:
    from core.ml_security_analyzer import MLSecurityAnalyzer, MLVulnerabilityScore
    from core.ai_ml.intelligent_vulnerability_detector import IntelligentVulnerabilityDetector, DetectionResult
    from core.ai_ml.ml_false_positive_reducer import MLFalsePositiveReducer, FPReductionResult
    ML_COMPONENTS_AVAILABLE = True
except ImportError:
    ML_COMPONENTS_AVAILABLE = False
    MLSecurityAnalyzer = None
    IntelligentVulnerabilityDetector = None
    MLFalsePositiveReducer = None

logger = logging.getLogger(__name__)

@dataclass
class MLConfidenceResult:
    """Result from ML-enhanced confidence calculation."""
    
    final_confidence: float
    pattern_confidence: float
    ml_confidence: float
    false_positive_probability: float
    confidence_factors: Dict[str, float]
    ml_analysis_used: bool
    reasoning: str

class MLEnhancedConfidenceCalculator:
    """
    ML-Enhanced confidence calculator that combines traditional pattern matching
    with machine learning analysis for improved accuracy.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Initialize ML components if available
        self.ml_security_analyzer = None
        self.intelligent_detector = None
        self.false_positive_reducer = None
        self.ml_components_available = ML_COMPONENTS_AVAILABLE
        
        if self.ml_components_available:
            try:
                self.ml_security_analyzer = MLSecurityAnalyzer()
                self.intelligent_detector = IntelligentVulnerabilityDetector()
                self.false_positive_reducer = MLFalsePositiveReducer()
                self.logger.info("ML-enhanced confidence calculator initialized with full ML components")
            except Exception as e:
                self.logger.warning(f"Failed to initialize ML components: {e}")
                self.ml_components_available = False
        else:
            self.logger.info("ML-enhanced confidence calculator initialized in fallback mode")
        
        # Configuration
        self.config = {
            'ml_weight': 0.4,  # Weight for ML confidence (40%)
            'pattern_weight': 0.6,  # Weight for pattern confidence (60%)
            'fp_threshold': 0.7,  # False positive reduction threshold
            'min_confidence': 0.1,  # Minimum confidence score
            'max_confidence': 0.95,  # Maximum confidence score
        }
        
        self.statistics = {
            'total_calculations': 0,
            'ml_enhanced_calculations': 0,
            'fallback_calculations': 0,
            'false_positives_detected': 0
        }
    
    def calculate_confidence(self, finding, context: Dict[str, Any] = None) -> float:
        """
        Calculate ML-enhanced confidence score for a security finding.
        
        Args:
            finding: SecurityFinding object with code snippet and metadata
            context: Additional context for confidence calculation
            
        Returns:
            Enhanced confidence score (0.0 to 1.0)
        """
        self.statistics['total_calculations'] += 1
        context = context or {}
        
        try:
            # Get base pattern confidence
            pattern_confidence = self._calculate_pattern_confidence(finding, context)
            
            # If ML components are available, enhance with ML analysis
            if self.ml_components_available and hasattr(finding, 'code_snippet') and finding.code_snippet:
                ml_result = self._calculate_ml_enhanced_confidence(finding, pattern_confidence, context)
                self.statistics['ml_enhanced_calculations'] += 1
                
                if ml_result.false_positive_probability > self.config['fp_threshold']:
                    self.statistics['false_positives_detected'] += 1
                
                return ml_result.final_confidence
            else:
                # Fallback to pattern-only confidence
                self.statistics['fallback_calculations'] += 1
                return self._apply_confidence_bounds(pattern_confidence)
                
        except Exception as e:
            self.logger.warning(f"Confidence calculation failed: {e}")
            self.statistics['fallback_calculations'] += 1
            return 0.5  # Safe fallback
    
    def _calculate_pattern_confidence(self, finding, context: Dict[str, Any]) -> float:
        """Calculate traditional pattern-based confidence."""
        base_confidence = 0.7
        
        # Adjust based on pattern category
        pattern_category = context.get('pattern_category', '')
        file_path = getattr(finding, 'file_path', '')
        match_value = context.get('match_value', '')
        
        # File type adjustments
        if file_path.endswith(('.java', '.kt')):
            base_confidence += 0.1
        elif file_path.endswith('.xml'):
            base_confidence += 0.05
        elif file_path.endswith('.properties'):
            base_confidence += 0.15
        
        # Pattern-specific adjustments
        if 'hardcoded' in pattern_category.lower():
            # Higher confidence for longer matches
            if len(match_value) > 20:
                base_confidence += 0.1
            # Lower confidence for test files
            if 'test' in file_path.lower():
                base_confidence -= 0.3
        elif 'crypto' in pattern_category.lower():
            # Higher confidence for actual algorithm usage
            if 'getInstance' in match_value:
                base_confidence += 0.1
        elif 'network' in pattern_category.lower():
            # Higher confidence for production code
            if 'debug' not in file_path.lower():
                base_confidence += 0.1
        
        return base_confidence
    
    def _calculate_ml_enhanced_confidence(self, finding, pattern_confidence: float, context: Dict[str, Any]) -> MLConfidenceResult:
        """Calculate ML-enhanced confidence using available ML models."""
        
        # Initialize result
        ml_confidence = pattern_confidence
        false_positive_probability = 0.0
        confidence_factors = {}
        reasoning = "Pattern-based analysis"
        
        try:
            code_snippet = finding.code_snippet
            file_path = getattr(finding, 'file_path', '')
            line_number = getattr(finding, 'line_number', 1)
            vulnerability_type = context.get('pattern_category', getattr(finding, 'title', 'unknown'))
            
            # 1. ML Security Analyzer - Enhanced confidence scoring
            if self.ml_security_analyzer:
                try:
                    ml_score = self.ml_security_analyzer.analyze_vulnerability_confidence(
                        vulnerability_type=vulnerability_type,
                        code_snippet=code_snippet,
                        file_path=file_path,
                        line_number=line_number,
                        base_confidence=pattern_confidence
                    )
                    
                    if hasattr(ml_score, 'combined_confidence'):
                        ml_confidence = ml_score.combined_confidence
                        confidence_factors['ml_complexity'] = getattr(ml_score, 'complexity_score', 0.0)
                        confidence_factors['ml_pattern_strength'] = getattr(ml_score, 'pattern_strength', 0.0)
                        confidence_factors['ml_context_relevance'] = getattr(ml_score, 'context_relevance', 0.0)
                        reasoning += " + ML security analysis"
                    
                except Exception as e:
                    self.logger.debug(f"ML security analyzer failed: {e}")
            
            # 2. Intelligent Vulnerability Detector - Contextual analysis
            if self.intelligent_detector:
                try:
                    detection_result = self.intelligent_detector.detect_vulnerabilities(
                        content=code_snippet,
                        title=getattr(finding, 'title', ''),
                        file_path=file_path,
                        context=context
                    )
                    
                    if hasattr(detection_result, 'confidence_score') and detection_result.confidence_score > 0:
                        # Blend with existing ML confidence
                        ml_confidence = (ml_confidence + detection_result.confidence_score) / 2
                        confidence_factors['intelligent_detection'] = detection_result.confidence_score
                        reasoning += " + contextual AI analysis"
                    
                except Exception as e:
                    self.logger.debug(f"Intelligent detector failed: {e}")
            
            # 3. False Positive Reducer - Reduce false positives
            if self.false_positive_reducer:
                try:
                    vulnerability_info = {
                        'type': vulnerability_type,
                        'severity': getattr(finding, 'severity', 'MEDIUM'),
                        'pattern': context.get('match_value', '')
                    }
                    
                    fp_result = self.false_positive_reducer.analyze_for_false_positive(
                        content=code_snippet,
                        title=getattr(finding, 'title', ''),
                        vulnerability_info=vulnerability_info,
                        context=context
                    )
                    
                    false_positive_probability = getattr(fp_result, 'confidence', 0.0)
                    
                    # Reduce confidence if high false positive probability
                    if false_positive_probability > 0.5:
                        reduction_factor = false_positive_probability * 0.5
                        ml_confidence = max(0.1, ml_confidence - reduction_factor)
                        confidence_factors['false_positive_reduction'] = -reduction_factor
                        reasoning += " + false positive filtering"
                    
                except Exception as e:
                    self.logger.debug(f"False positive reducer failed: {e}")
            
            # Combine pattern and ML confidence
            final_confidence = (
                self.config['pattern_weight'] * pattern_confidence +
                self.config['ml_weight'] * ml_confidence
            )
            
            return MLConfidenceResult(
                final_confidence=self._apply_confidence_bounds(final_confidence),
                pattern_confidence=pattern_confidence,
                ml_confidence=ml_confidence,
                false_positive_probability=false_positive_probability,
                confidence_factors=confidence_factors,
                ml_analysis_used=True,
                reasoning=reasoning
            )
            
        except Exception as e:
            self.logger.warning(f"ML confidence calculation failed: {e}")
            return MLConfidenceResult(
                final_confidence=self._apply_confidence_bounds(pattern_confidence),
                pattern_confidence=pattern_confidence,
                ml_confidence=pattern_confidence,
                false_positive_probability=0.0,
                confidence_factors={},
                ml_analysis_used=False,
                reasoning="Fallback to pattern analysis"
            )
    
    def _apply_confidence_bounds(self, confidence: float) -> float:
        """Apply minimum and maximum confidence bounds."""
        return max(self.config['min_confidence'], min(self.config['max_confidence'], confidence))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get calculator statistics for monitoring."""
        total = self.statistics['total_calculations']
        if total > 0:
            return {
                **self.statistics,
                'ml_usage_rate': self.statistics['ml_enhanced_calculations'] / total,
                'false_positive_rate': self.statistics['false_positives_detected'] / total,
                'ml_available': self.ml_components_available
            }
        return {**self.statistics, 'ml_available': self.ml_components_available}

# Global instance for easy access
_ml_confidence_calculator = None

def get_ml_confidence_calculator() -> MLEnhancedConfidenceCalculator:
    """Get global ML confidence calculator instance."""
    global _ml_confidence_calculator
    if _ml_confidence_calculator is None:
        _ml_confidence_calculator = MLEnhancedConfidenceCalculator()
    return _ml_confidence_calculator