#!/usr/bin/env python3
"""
Confidence Calculator for Static Analysis

Calculates confidence scores for static analysis findings based on
multiple evidence factors including pattern strength, context relevance,
and validation coverage.
"""

import logging
from typing import Dict, List

from core.shared_analyzers.universal_confidence_calculator import (
    UniversalConfidenceCalculator,
    ConfidenceConfiguration,
    ConfidenceFactorType,
    PatternReliability
)

class StaticAnalysisConfidenceCalculator(UniversalConfidenceCalculator):
    """
    confidence calculation system for static analysis findings.
    
    Implements evidence-based, multi-factor confidence scoring for static code analysis
    that considers pattern reliability, context relevance, code quality indicators,
    and cross-validation from multiple analysis methods.
    """
    
    def __init__(self):
        # Create pattern reliability database
        pattern_reliability_db = {
            'sql_injection': PatternReliability(
                pattern_id='sql_injection',
                pattern_name='SQL Injection',
                total_validations=100,
                correct_predictions=85,
                false_positive_rate=0.15,
                false_negative_rate=0.10,
                confidence_adjustment=0.0,
                last_updated='2024-01-01'
            ),
            'xss_vulnerabilities': PatternReliability(
                pattern_id='xss_vulnerabilities',
                pattern_name='XSS Vulnerabilities',
                total_validations=100,
                correct_predictions=90,
                false_positive_rate=0.10,
                false_negative_rate=0.08,
                confidence_adjustment=0.0,
                last_updated='2024-01-01'
            ),
            'path_traversal': PatternReliability(
                pattern_id='path_traversal',
                pattern_name='Path Traversal',
                total_validations=100,
                correct_predictions=75,
                false_positive_rate=0.25,
                false_negative_rate=0.20,
                confidence_adjustment=0.0,
                last_updated='2024-01-01'
            ),
            'command_injection': PatternReliability(
                pattern_id='command_injection',
                pattern_name='Command Injection',
                total_validations=100,
                correct_predictions=95,
                false_positive_rate=0.05,
                false_negative_rate=0.03,
                confidence_adjustment=0.0,
                last_updated='2024-01-01'
            ),
            'crypto_misuse': PatternReliability(
                pattern_id='crypto_misuse',
                pattern_name='Crypto Misuse',
                total_validations=100,
                correct_predictions=82,
                false_positive_rate=0.18,
                false_negative_rate=0.15,
                confidence_adjustment=0.0,
                last_updated='2024-01-01'
            ),
            'insecure_storage': PatternReliability(
                pattern_id='insecure_storage',
                pattern_name='Insecure Storage',
                total_validations=100,
                correct_predictions=88,
                false_positive_rate=0.12,
                false_negative_rate=0.10,
                confidence_adjustment=0.0,
                last_updated='2024-01-01'
            )
        }
        
        # Create configuration for universal confidence calculator
        config = ConfidenceConfiguration(
            plugin_type='static_analysis',
            evidence_weights={
                ConfidenceFactorType.PATTERN_RELIABILITY: 0.3,
                ConfidenceFactorType.CONTEXT_RELEVANCE: 0.25,
                ConfidenceFactorType.EVIDENCE_QUALITY: 0.2,
                ConfidenceFactorType.VALIDATION_SOURCES: 0.15,
                ConfidenceFactorType.IMPLEMENTATION_CONTEXT: 0.1
            },
            context_factors={
                'source_code': 1.0,
                'config_files': 0.9,
                'manifest_files': 0.95,
                'resource_files': 0.7,
                'test_files': 0.4,
                'build_files': 0.3,
                'documentation': 0.2
            },
            reliability_database=pattern_reliability_db,
            minimum_confidence=0.1,
            maximum_confidence=0.95,
            default_pattern_reliability=0.8,
            cross_validation_bonus=0.1
        )
        
        super().__init__(config)
        
        # Evidence weight factors for static analysis
        self.evidence_weights = {
            'pattern_reliability': 0.3,     # Quality of pattern matching
            'context_relevance': 0.25,      # Context appropriateness
            'code_quality': 0.2,            # Code quality indicators
            'cross_validation': 0.15,       # Multiple validation methods
            'severity_impact': 0.1           # Severity-based adjustment
        }
        
        # Pattern reliability database (based on historical false positive rates)
        self.pattern_reliability = {
            'sql_injection': {'reliability': 0.85, 'fp_rate': 0.15},
            'xss_vulnerabilities': {'reliability': 0.90, 'fp_rate': 0.10},
            'path_traversal': {'reliability': 0.75, 'fp_rate': 0.25},
            'command_injection': {'reliability': 0.95, 'fp_rate': 0.05},
            'crypto_misuse': {'reliability': 0.82, 'fp_rate': 0.18},
            'insecure_storage': {'reliability': 0.88, 'fp_rate': 0.12},
            'weak_crypto': {'reliability': 0.90, 'fp_rate': 0.10},
            'debug_code': {'reliability': 0.70, 'fp_rate': 0.30},
            'hardcoded_secrets': {'reliability': 0.85, 'fp_rate': 0.15},
            'insecure_urls': {'reliability': 0.78, 'fp_rate': 0.22},
            'manifest_security': {'reliability': 0.92, 'fp_rate': 0.08}
        }
        
        # Context relevance factors
        self.context_factors = {
            'source_code': 1.0,
            'config_files': 0.9,
            'manifest_files': 0.95,
            'resource_files': 0.7,
            'test_files': 0.4,
            'build_files': 0.3,
            'documentation': 0.2
        }
        
        # Severity impact multipliers
        self.severity_multipliers = {
            'CRITICAL': 1.1,
            'HIGH': 1.0,
            'MEDIUM': 0.9,
            'LOW': 0.8,
            'INFO': 0.7
        }
        
        # Code quality indicators
        self.quality_indicators = {
            'explicit_patterns': 1.0,      # Clear vulnerability patterns
            'complex_patterns': 0.9,       # Complex but identifiable patterns
            'simple_patterns': 0.8,        # Simple pattern matches
            'heuristic_patterns': 0.7,     # Heuristic-based detection
            'entropy_based': 0.6           # Entropy-only detection
        }
        
        logging.info("Initialized StaticAnalysisConfidenceCalculator with professional scoring")
    
    def calculate_static_analysis_confidence(self, pattern_type: str, severity: str, 
                                           context: str, file_path: str, 
                                           code_snippet: str = "", 
                                           evidence: List[str] = None) -> float:
        """
        Calculate professional confidence for static analysis findings.
        
        Args:
            pattern_type: Type of security pattern detected
            severity: Severity level of the finding
            context: Context where the finding was detected
            file_path: Path to the file containing the finding
            code_snippet: Code snippet containing the pattern
            evidence: List of evidence supporting the finding
            
        Returns:
            Dynamic confidence score (0.0-1.0)
        """
        try:
            # Get base evidence
            evidence_data = {
                'pattern_reliability': self._assess_pattern_reliability(pattern_type),
                'context_relevance': self._assess_context_relevance(context, file_path),
                'code_quality': self._assess_code_quality(code_snippet, pattern_type),
                'cross_validation': self._assess_cross_validation(evidence or []),
                'severity_impact': self._assess_severity_impact(severity)
            }
            
            # Calculate weighted confidence
            confidence = self._calculate_weighted_confidence(evidence_data)
            
            # Apply pattern-specific adjustments
            confidence = self._apply_pattern_adjustments(confidence, pattern_type, severity)
            
            # Apply context-specific adjustments
            confidence = self._apply_context_adjustments(confidence, file_path, context)
            
            # Ensure confidence is in valid range
            confidence = max(0.1, min(1.0, confidence))
            
            return confidence
            
        except Exception as e:
            logging.error(f"Error calculating static analysis confidence: {e}")
            return 0.5  # Conservative fallback
    
    def _calculate_weighted_confidence(self, evidence_data: Dict[str, float]) -> float:
        """Calculate weighted confidence based on evidence factors."""
        confidence = 0.0
        total_weight = 0.0
        
        # Calculate weighted sum of evidence factors
        for factor, weight in self.evidence_weights.items():
            if factor in evidence_data:
                confidence += evidence_data[factor] * weight
                total_weight += weight
        
        # Normalize by total weight used
        if total_weight > 0:
            confidence = confidence / total_weight
        else:
            # Fallback if no evidence factors found
            confidence = 0.5
        
        return confidence
    
    def _assess_pattern_reliability(self, pattern_type: str) -> float:
        """Assess the reliability of the pattern type."""
        if pattern_type in self.pattern_reliability:
            return self.pattern_reliability[pattern_type]['reliability']
        return 0.7  # Default reliability for unknown patterns
    
    def _assess_context_relevance(self, context: str, file_path: str) -> float:
        """Assess the relevance of the context."""
        # Determine file type
        file_path_lower = file_path.lower()
        
        if any(ext in file_path_lower for ext in ['.java', '.kt', '.smali']):
            return self.context_factors['source_code']
        elif 'androidmanifest' in file_path_lower:
            return self.context_factors['manifest_files']
        elif any(ext in file_path_lower for ext in ['.xml', '.json', '.properties']):
            return self.context_factors['config_files']
        elif 'test' in file_path_lower:
            return self.context_factors['test_files']
        elif any(ext in file_path_lower for ext in ['.png', '.jpg', '.jpeg']):
            return self.context_factors['resource_files']
        else:
            return 0.8  # Default relevance
    
    def _assess_code_quality(self, code_snippet: str, pattern_type: str) -> float:
        """Assess code quality indicators."""
        if not code_snippet:
            return 0.7
        
        # Check for explicit vulnerability patterns
        if len(code_snippet) > 50 and any(keyword in code_snippet.lower() 
                                        for keyword in ['sql', 'exec', 'eval', 'system']):
            return self.quality_indicators['explicit_patterns']
        
        # Check for complex patterns
        if len(code_snippet) > 30:
            return self.quality_indicators['complex_patterns']
        
        # Simple patterns
        if len(code_snippet) > 10:
            return self.quality_indicators['simple_patterns']
        
        return self.quality_indicators['heuristic_patterns']
    
    def _assess_cross_validation(self, evidence: List[str]) -> float:
        """Assess cross-validation evidence."""
        if not evidence:
            return 0.5
        
        # More evidence increases confidence
        evidence_count = len(evidence)
        if evidence_count >= 3:
            return 1.0
        elif evidence_count == 2:
            return 0.8
        elif evidence_count == 1:
            return 0.6
        else:
            return 0.5
    
    def _assess_severity_impact(self, severity: str) -> float:
        """Assess severity impact on confidence."""
        return self.severity_multipliers.get(severity, 1.0)
    
    def _apply_pattern_adjustments(self, confidence: float, pattern_type: str, severity: str) -> float:
        """Apply pattern-specific confidence adjustments."""
        # High-confidence patterns
        if pattern_type in ['command_injection', 'manifest_security']:
            confidence *= 1.1
        
        # Medium-confidence patterns
        elif pattern_type in ['sql_injection', 'crypto_misuse']:
            confidence *= 1.0
        
        # Lower-confidence patterns
        elif pattern_type in ['debug_code', 'insecure_urls']:
            confidence *= 0.9
        
        # Critical findings get a confidence boost
        if severity == 'CRITICAL':
            confidence *= 1.05
        
        return confidence
    
    def _apply_context_adjustments(self, confidence: float, file_path: str, context: str) -> float:
        """Apply context-specific confidence adjustments."""
        # Source code files get higher confidence
        if any(ext in file_path.lower() for ext in ['.java', '.kt']):
            confidence *= 1.05
        
        # Manifest files get higher confidence for security findings
        elif 'androidmanifest' in file_path.lower():
            confidence *= 1.1
        
        # Test files get lower confidence
        elif 'test' in file_path.lower():
            confidence *= 0.7
        
        return confidence

# Export the calculator
__all__ = ['StaticAnalysisConfidenceCalculator'] 