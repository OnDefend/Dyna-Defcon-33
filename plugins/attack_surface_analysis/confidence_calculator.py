"""
Professional Confidence Calculator for Attack Surface Analysis

This module provides enterprise-grade confidence calculation for attack surface
analysis findings based on multiple evidence factors, pattern reliability, and
contextual analysis.
"""

from typing import Dict, Any
from .data_structures import PermissionLevel, AttackComplexity

class AttackSurfaceConfidenceCalculator:
    """
    confidence calculation system for attack surface analysis findings.
    
    Calculates dynamic confidence scores based on:
    - Component exposure patterns and complexity
    - Permission protection levels and effectiveness
    - Attack vector complexity and exploitability
    - Cross-validation from multiple analysis methods
    - Context relevance and implementation quality
    """
    
    def __init__(self):
        # Evidence weight factors for attack surface analysis
        self.evidence_weights = {
            'component_exposure': 0.3,      # How exposed the component is
            'permission_protection': 0.25,  # Level of permission protection
            'attack_complexity': 0.2,       # Complexity of potential attack
            'validation_methods': 0.15,     # Number of validation methods
            'context_relevance': 0.1        # Relevance in app context
        }
        
        # Pattern reliability data (based on false positive rates)
        self.pattern_reliability = {
            'exported_activities': {'reliability': 0.90, 'fp_rate': 0.10},
            'unprotected_broadcasts': {'reliability': 0.95, 'fp_rate': 0.05},
            'content_providers': {'reliability': 0.85, 'fp_rate': 0.15},
            'ipc_vulnerabilities': {'reliability': 0.80, 'fp_rate': 0.20},
            'intent_filters': {'reliability': 0.88, 'fp_rate': 0.12},
            'deep_links': {'reliability': 0.83, 'fp_rate': 0.17},
            'dangerous_actions': {'reliability': 0.92, 'fp_rate': 0.08},
            'sensitive_schemes': {'reliability': 0.87, 'fp_rate': 0.13},
            'high_risk_patterns': {'reliability': 0.75, 'fp_rate': 0.25},
            'unprotected_components': {'reliability': 0.85, 'fp_rate': 0.15},
            'drozer_findings': {'reliability': 0.70, 'fp_rate': 0.30}
        }
        
        # Context scoring factors
        self.context_factors = {
            'manifest_analysis': 0.9,       # Manifest-based findings
            'static_analysis': 0.8,         # Static code analysis
            'drozer_analysis': 0.7,         # Drozer dynamic analysis
            'pattern_matching': 0.6,        # Pattern-based detection
            'heuristic_analysis': 0.5       # Heuristic-based findings
        }
        
        # Component exposure levels
        self.exposure_levels = {
            'exported_unprotected': 1.0,    # Exported with no permission
            'exported_protected': 0.7,      # Exported with permissions
            'implicit_export': 0.8,         # Exported via intent filters
            'internal_only': 0.2            # Not exported
        }
        
        # Attack complexity factors
        self.attack_complexity = {
            'trivial': 1.0,                 # No authentication required
            'simple': 0.8,                  # Basic requirements
            'moderate': 0.6,                # Some complexity
            'complex': 0.4,                 # High complexity
            'very_complex': 0.2             # Very difficult to exploit
        }
    
    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate dynamic confidence score for attack surface findings.
        
        Args:
            evidence: Dictionary containing evidence factors
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        confidence_score = 0.0
        total_weight = 0.0
        
        # Factor 1: Component exposure assessment
        exposure_score = self._assess_component_exposure(evidence)
        confidence_score += exposure_score * self.evidence_weights['component_exposure']
        total_weight += self.evidence_weights['component_exposure']
        
        # Factor 2: Permission protection evaluation
        protection_score = self._assess_permission_protection(evidence)
        confidence_score += protection_score * self.evidence_weights['permission_protection']
        total_weight += self.evidence_weights['permission_protection']
        
        # Factor 3: Attack complexity analysis
        complexity_score = self._assess_attack_complexity(evidence)
        confidence_score += complexity_score * self.evidence_weights['attack_complexity']
        total_weight += self.evidence_weights['attack_complexity']
        
        # Factor 4: Validation methods cross-check
        validation_score = self._assess_validation_methods(evidence)
        confidence_score += validation_score * self.evidence_weights['validation_methods']
        total_weight += self.evidence_weights['validation_methods']
        
        # Factor 5: Context relevance assessment
        context_score = self._assess_context_relevance(evidence)
        confidence_score += context_score * self.evidence_weights['context_relevance']
        total_weight += self.evidence_weights['context_relevance']
        
        # Normalize confidence score
        if total_weight > 0:
            confidence_score = confidence_score / total_weight
        
        # Apply pattern-specific reliability adjustment
        pattern_type = evidence.get('pattern_type', 'generic')
        reliability_adjustment = self._get_pattern_reliability(pattern_type)
        confidence_score *= reliability_adjustment
        
        # Ensure confidence is within valid range
        return max(0.0, min(1.0, confidence_score))
    
    def _assess_component_exposure(self, evidence: Dict[str, Any]) -> float:
        """Assess the level of component exposure."""
        exported = evidence.get('exported', False)
        has_intent_filters = evidence.get('has_intent_filters', False)
        component_type = evidence.get('component_type', '')
        
        if exported and not evidence.get('permissions', []):
            return self.exposure_levels['exported_unprotected']
        elif exported and evidence.get('permissions', []):
            return self.exposure_levels['exported_protected'] 
        elif has_intent_filters:
            return self.exposure_levels['implicit_export']
        else:
            return self.exposure_levels['internal_only']
    
    def _assess_permission_protection(self, evidence: Dict[str, Any]) -> float:
        """Assess the effectiveness of permission protection."""
        permissions = evidence.get('permissions', [])
        permission_level = evidence.get('permission_level', 'none')
        
        if not permissions:
            return 1.0  # High confidence in vulnerability if no protection
        
        # Map permission levels to confidence scores
        protection_levels = {
            'signature': 0.3,           # Strong protection
            'signatureOrSystem': 0.2,   # Very strong protection
            'dangerous': 0.5,           # Moderate protection (runtime)
            'normal': 0.7,              # Weak protection
            'none': 1.0                 # No protection
        }
        
        return protection_levels.get(permission_level, 0.7)
    
    def _assess_attack_complexity(self, evidence: Dict[str, Any]) -> float:
        """Assess the complexity of the potential attack."""
        attack_methods = evidence.get('attack_methods', [])
        prerequisites = evidence.get('prerequisites', [])
        component_type = evidence.get('component_type', '')
        
        # Base complexity assessment
        complexity_factors = 0.0
        
        # Number of prerequisites indicates complexity
        if len(prerequisites) == 0:
            complexity_factors += 0.3  # No prerequisites = higher confidence
        elif len(prerequisites) <= 2:
            complexity_factors += 0.2
        else:
            complexity_factors += 0.1
        
        # Attack method complexity
        simple_methods = ['direct component access', 'intent manipulation']
        if any(method.lower() in evidence.get('attack_description', '').lower() 
               for method in simple_methods):
            complexity_factors += 0.3
        
        # Component type specific factors
        if component_type == 'activity':
            complexity_factors += 0.2  # Activities are easier to attack
        elif component_type == 'provider':
            complexity_factors += 0.3  # Providers are high-value targets
        
        return min(1.0, complexity_factors)
    
    def _assess_validation_methods(self, evidence: Dict[str, Any]) -> float:
        """Assess the reliability based on validation methods used."""
        validation_sources = evidence.get('validation_sources', [])
        
        # Higher confidence with multiple validation sources
        if len(validation_sources) >= 3:
            return 0.9  # Triple validation
        elif len(validation_sources) == 2:
            return 0.7  # Dual validation
        elif len(validation_sources) == 1:
            return 0.5  # Single validation
        else:
            return 0.3  # No explicit validation
    
    def _assess_context_relevance(self, evidence: Dict[str, Any]) -> float:
        """Assess the relevance of findings in the application context."""
        analysis_source = evidence.get('analysis_source', 'heuristic')
        return self.context_factors.get(analysis_source, 0.5)
    
    def _get_pattern_reliability(self, pattern_type: str) -> float:
        """Get pattern-specific reliability adjustment."""
        pattern_data = self.pattern_reliability.get(pattern_type, 
                                                   {'reliability': 0.7})
        return pattern_data['reliability']

def calculate_attack_surface_confidence(evidence: Dict[str, Any]) -> float:
    """
    Convenience function for calculating attack surface confidence.
    
    Args:
        evidence: Dictionary containing evidence factors
        
    Returns:
        Confidence score between 0.0 and 1.0
    """
    calculator = AttackSurfaceConfidenceCalculator()
    return calculator.calculate_confidence(evidence) 