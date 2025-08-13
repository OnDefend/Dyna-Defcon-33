"""
Professional Confidence Calculator for Token Replay Analysis

This module provides enterprise-grade confidence calculation for token security
analysis findings based on multiple evidence factors, pattern reliability, and
contextual analysis.
"""

from typing import Dict, Any
from .data_structures import TokenType, TokenVulnerabilityType, TokenStrength

class TokenSecurityConfidenceCalculator:
    """
    confidence calculation system for token security analysis findings.
    
    Calculates dynamic confidence scores based on:
    - Pattern reliability and accuracy in token security detection
    - Evidence strength from multiple token analysis methods
    - Context awareness based on token usage and implementation
    - Cross-validation from multiple token detection techniques
    - Analysis depth and comprehensive coverage of token security patterns
    """
    
    def __init__(self):
        # Evidence weight factors for token security analysis
        self.evidence_weights = {
            'pattern_reliability': 0.3,      # Reliability of token security patterns
            'evidence_strength': 0.25,       # Strength of evidence from analysis
            'context_awareness': 0.2,        # Context of token usage
            'cross_validation': 0.15,        # Multiple detection method validation
            'analysis_depth': 0.1           # Depth of token security analysis
        }
        
        # Pattern reliability data for token security findings (based on false positive rates)
        self.pattern_reliability = {
            'jwt_none_algorithm': {'reliability': 0.98, 'fp_rate': 0.02},
            'weak_token_entropy': {'reliability': 0.85, 'fp_rate': 0.15},
            'predictable_token': {'reliability': 0.90, 'fp_rate': 0.10},
            'no_token_expiry': {'reliability': 0.95, 'fp_rate': 0.05},
            'excessive_token_expiry': {'reliability': 0.80, 'fp_rate': 0.20},
            'session_fixation': {'reliability': 0.88, 'fp_rate': 0.12},
            'token_replay_vulnerable': {'reliability': 0.75, 'fp_rate': 0.25},
            'insecure_token_storage': {'reliability': 0.92, 'fp_rate': 0.08},
            'hardcoded_token_secret': {'reliability': 0.97, 'fp_rate': 0.03},
            'weak_jwt_algorithm': {'reliability': 0.93, 'fp_rate': 0.07},
            'missing_jwt_signature': {'reliability': 0.99, 'fp_rate': 0.01},
            'token_in_url': {'reliability': 0.89, 'fp_rate': 0.11}
        }
        
        # Context factor mapping for token security analysis
        self.context_factors = {
            'production_app': 0.9,          # Production application context
            'development_app': 0.7,         # Development application context
            'test_app': 0.4,                # Test application context
            'jwt_token': 0.9,               # JWT token context
            'session_token': 0.85,          # Session token context
            'api_key': 0.8,                 # API key context
            'oauth_token': 0.85,            # OAuth token context
            'bearer_token': 0.8,            # Bearer token context
            'custom_token': 0.6,            # Custom token implementation
            'network_traffic': 0.8,         # Network traffic analysis
            'static_analysis': 0.7,         # Static code analysis
            'dynamic_analysis': 0.9,        # Dynamic runtime analysis
            'unknown_context': 0.6          # Unknown context
        }
    
    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate dynamic confidence score for token security findings.
        
        Args:
            evidence: Dictionary containing evidence factors
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        confidence_score = 0.0
        total_weight = 0.0
        
        # Factor 1: Pattern reliability assessment
        reliability_score = self._assess_pattern_reliability(evidence)
        confidence_score += reliability_score * self.evidence_weights['pattern_reliability']
        total_weight += self.evidence_weights['pattern_reliability']
        
        # Factor 2: Evidence strength evaluation
        evidence_score = self._assess_evidence_strength(evidence)
        confidence_score += evidence_score * self.evidence_weights['evidence_strength']
        total_weight += self.evidence_weights['evidence_strength']
        
        # Factor 3: Context awareness analysis
        context_score = self._assess_context_awareness(evidence)
        confidence_score += context_score * self.evidence_weights['context_awareness']
        total_weight += self.evidence_weights['context_awareness']
        
        # Factor 4: Cross-validation assessment
        validation_score = self._assess_cross_validation(evidence)
        confidence_score += validation_score * self.evidence_weights['cross_validation']
        total_weight += self.evidence_weights['cross_validation']
        
        # Factor 5: Analysis depth evaluation
        depth_score = self._assess_analysis_depth(evidence)
        confidence_score += depth_score * self.evidence_weights['analysis_depth']
        total_weight += self.evidence_weights['analysis_depth']
        
        # Normalize confidence score
        if total_weight > 0:
            confidence_score = confidence_score / total_weight
        
        # Apply pattern-specific reliability adjustment
        pattern_type = evidence.get('pattern_type', 'unknown')
        if pattern_type in self.pattern_reliability:
            pattern_data = self.pattern_reliability[pattern_type]
            confidence_score *= pattern_data['reliability']
        
        # Ensure confidence score is within valid range
        return max(0.0, min(1.0, confidence_score))
    
    def _assess_pattern_reliability(self, evidence: Dict[str, Any]) -> float:
        """Assess reliability of token security patterns."""
        pattern_type = evidence.get('pattern_type', 'unknown')
        
        if pattern_type in self.pattern_reliability:
            return self.pattern_reliability[pattern_type]['reliability']
        
        # Default reliability for unknown patterns
        return 0.7
    
    def _assess_evidence_strength(self, evidence: Dict[str, Any]) -> float:
        """Assess strength of evidence from token security analysis."""
        strength_indicators = 0
        max_indicators = 6
        
        # Check for various evidence strength indicators
        if evidence.get('token_discovered', False):
            strength_indicators += 1
        
        if evidence.get('jwt_decoded', False):
            strength_indicators += 1
        
        if evidence.get('replay_test_performed', False):
            strength_indicators += 1
        
        if evidence.get('entropy_calculated', False):
            strength_indicators += 1
        
        if evidence.get('expiry_analyzed', False):
            strength_indicators += 1
        
        if evidence.get('weakness_patterns_found', 0) > 0:
            strength_indicators += 1
        
        return strength_indicators / max_indicators
    
    def _assess_context_awareness(self, evidence: Dict[str, Any]) -> float:
        """Assess context awareness of token security finding."""
        token_type = evidence.get('token_type', '')
        analysis_source = evidence.get('analysis_source', '')
        app_context = evidence.get('app_context', '')
        
        # Determine context based on token type
        context_score = 0.6  # Default
        
        if token_type in ['jwt', 'bearer', 'oauth']:
            context_score = self.context_factors.get(f'{token_type}_token', 0.8)
        elif analysis_source in ['network_traffic', 'static_analysis', 'dynamic_analysis']:
            context_score = self.context_factors.get(analysis_source, 0.7)
        elif app_context in ['production_app', 'development_app', 'test_app']:
            context_score = self.context_factors.get(app_context, 0.6)
        
        return context_score
    
    def _assess_cross_validation(self, evidence: Dict[str, Any]) -> float:
        """Assess cross-validation from multiple analysis methods."""
        validation_methods = evidence.get('validation_methods', [])
        
        # Define validation method quality scores
        validation_quality_scores = {
            'static_code_analysis': 0.7,
            'network_traffic_analysis': 0.9,
            'jwt_decoding': 0.85,
            'entropy_analysis': 0.8,
            'pattern_matching': 0.75,
            'replay_testing': 0.95,
            'expiry_validation': 0.8,
            'storage_analysis': 0.7,
            'algorithm_analysis': 0.85
        }
        
        validation_score = 0.0
        if validation_methods:
            # Calculate average quality of validation methods
            quality_scores = [
                validation_quality_scores.get(method, 0.5) 
                for method in validation_methods
            ]
            validation_score = sum(quality_scores) / len(quality_scores)
            
            # Bonus for multiple validation methods
            if len(validation_methods) > 1:
                validation_score *= min(1.2, 1.0 + (len(validation_methods) - 1) * 0.1)
        
        return min(1.0, validation_score)
    
    def _assess_analysis_depth(self, evidence: Dict[str, Any]) -> float:
        """Assess depth of token security analysis."""
        depth_indicators = 0
        max_indicators = 8
        
        # Check for analysis depth indicators
        if evidence.get('tokens_discovered', 0) > 0:
            depth_indicators += 1
        
        if evidence.get('jwt_tokens_analyzed', 0) > 0:
            depth_indicators += 1
        
        if evidence.get('session_tokens_analyzed', 0) > 0:
            depth_indicators += 1
        
        if evidence.get('replay_tests_performed', 0) > 0:
            depth_indicators += 1
        
        if evidence.get('entropy_tests_performed', 0) > 0:
            depth_indicators += 1
        
        if evidence.get('expiry_tests_performed', 0) > 0:
            depth_indicators += 1
        
        if evidence.get('weakness_patterns_tested', 0) > 5:
            depth_indicators += 1
        
        if evidence.get('classes_analyzed', 0) > 10:
            depth_indicators += 1
        
        return depth_indicators / max_indicators
    
    def map_vulnerability_to_pattern_type(self, vulnerability_type: str) -> str:
        """Map vulnerability type to pattern type for reliability lookup."""
        vulnerability_pattern_mapping = {
            'JWT None Algorithm': 'jwt_none_algorithm',
            'Weak Token Entropy': 'weak_token_entropy',
            'Predictable Token': 'predictable_token',
            'No Token Expiry': 'no_token_expiry',
            'Excessive Token Expiry': 'excessive_token_expiry',
            'Session Fixation': 'session_fixation',
            'Token Replay Vulnerable': 'token_replay_vulnerable',
            'Insecure Token Storage': 'insecure_token_storage',
            'Hardcoded Token Secret': 'hardcoded_token_secret',
            'Weak JWT Algorithm': 'weak_jwt_algorithm',
            'Missing JWT Signature': 'missing_jwt_signature',
            'Token in URL': 'token_in_url'
        }
        
        return vulnerability_pattern_mapping.get(vulnerability_type, 'unknown')

def calculate_token_security_confidence(evidence: Dict[str, Any]) -> float:
    """
    Convenience function for calculating token security confidence.
    
    Args:
        evidence: Dictionary containing evidence factors
        
    Returns:
        Confidence score between 0.0 and 1.0
    """
    calculator = TokenSecurityConfidenceCalculator()
    return calculator.calculate_confidence(evidence) 