"""
Evidence-Based Confidence Calculator for Enhanced Network Security Analysis

This module provides enterprise-grade confidence calculation for network security
analysis findings based on multiple evidence factors, pattern reliability, and
contextual analysis.
"""

from typing import Dict, Any
from .data_structures import NetworkVulnerabilityType, NetworkContextType

class NetworkSecurityConfidenceCalculator:
    """
    Evidence-based confidence calculation system for network security analysis findings.
    
    Calculates dynamic confidence scores based on:
    - Pattern reliability and accuracy in network security detection
    - Evidence strength from multiple network security analysis methods
    - Context awareness based on network configuration and implementation
    - Cross-validation from multiple network security detection techniques
    - Analysis depth and comprehensive coverage of network security patterns
    """
    
    def __init__(self):
        # Evidence weight factors for network security analysis
        self.evidence_weights = {
            'pattern_reliability': 0.3,      # Reliability of network security patterns
            'evidence_strength': 0.25,       # Strength of evidence from analysis
            'context_awareness': 0.2,        # Context of network configuration
            'cross_validation': 0.15,        # Multiple detection method validation
            'analysis_depth': 0.1           # Depth of network security analysis
        }
        
        # Pattern reliability data for network security findings (based on false positive rates)
        self.pattern_reliability = {
            'insecure_http': {'reliability': 0.95, 'fp_rate': 0.05},
            'weak_ssl_context': {'reliability': 0.90, 'fp_rate': 0.10},
            'trust_all_certs': {'reliability': 0.98, 'fp_rate': 0.02},
            'hostname_verification_disabled': {'reliability': 0.92, 'fp_rate': 0.08},
            'plaintext_credentials': {'reliability': 0.85, 'fp_rate': 0.15},
            'ssl_config_issues': {'reliability': 0.88, 'fp_rate': 0.12},
            'certificate_validation_bypass': {'reliability': 0.93, 'fp_rate': 0.07},
            'network_config_issues': {'reliability': 0.87, 'fp_rate': 0.13},
            'credential_handling_issues': {'reliability': 0.80, 'fp_rate': 0.20},
            'tls_version_issues': {'reliability': 0.94, 'fp_rate': 0.06},
            'cipher_suite_issues': {'reliability': 0.89, 'fp_rate': 0.11}
        }
        
        # Context factor mapping for network security analysis
        self.context_factors = {
            'production_app': 0.9,          # Production application context
            'development_app': 0.7,         # Development application context
            'framework_code': 0.6,          # Framework/library code context
            'test_code': 0.4,               # Test code context
            'configuration_file': 0.8,      # Configuration file context
            'manifest_file': 0.85,          # Manifest file context
            'native_code': 0.75,            # Native code context
            'third_party_lib': 0.65,        # Third-party library context
            'generated_code': 0.5,          # Generated code context
            'unknown_context': 0.6          # Unknown context
        }
    
    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate dynamic confidence score for network security findings.
        
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
        """Assess reliability of network security patterns."""
        pattern_type = evidence.get('pattern_type', 'unknown')
        
        if pattern_type in self.pattern_reliability:
            return self.pattern_reliability[pattern_type]['reliability']
        
        # Default reliability for unknown patterns
        return 0.7
    
    def _assess_evidence_strength(self, evidence: Dict[str, Any]) -> float:
        """Assess strength of evidence from network security analysis."""
        strength_indicators = 0
        max_indicators = 5
        
        # Check for various evidence strength indicators
        if evidence.get('pattern_matches', 0) > 0:
            strength_indicators += 1
        
        if evidence.get('code_examples'):
            strength_indicators += 1
        
        if evidence.get('method_name') and evidence.get('method_name') != 'unknown_method':
            strength_indicators += 1
        
        if evidence.get('line_number', 0) > 0:
            strength_indicators += 1
        
        if evidence.get('severity') in ['HIGH', 'CRITICAL']:
            strength_indicators += 1
        
        return strength_indicators / max_indicators
    
    def _assess_context_awareness(self, evidence: Dict[str, Any]) -> float:
        """Assess context awareness of network security finding."""
        file_path = evidence.get('file_path', '')
        class_name = evidence.get('class_name', '')
        
        # Determine context based on file path and class name
        if 'test' in file_path.lower() or 'test' in class_name.lower():
            return self.context_factors['test_code']
        elif 'config' in file_path.lower() or 'properties' in file_path.lower():
            return self.context_factors['configuration_file']
        elif 'manifest' in file_path.lower():
            return self.context_factors['manifest_file']
        elif 'generated' in file_path.lower() or 'gen/' in file_path:
            return self.context_factors['generated_code']
        elif any(lib in file_path.lower() for lib in ['library', 'lib', 'third', 'vendor']):
            return self.context_factors['third_party_lib']
        elif 'native' in file_path.lower() or '.so' in file_path:
            return self.context_factors['native_code']
        else:
            return self.context_factors['production_app']
    
    def _assess_cross_validation(self, evidence: Dict[str, Any]) -> float:
        """Assess cross-validation from multiple analysis methods."""
        validation_methods = evidence.get('validation_methods', [])
        
        # Define validation method quality scores
        validation_quality_scores = {
            'static_analysis': 0.8,
            'manifest_analysis': 0.75,
            'code_pattern_matching': 0.7,
            'ssl_configuration_analysis': 0.85,
            'certificate_validation_analysis': 0.9,
            'network_configuration_analysis': 0.8,
            'credential_analysis': 0.75,
            'dynamic_testing': 0.95,
            'network_traffic_analysis': 0.9
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
        """Assess depth of network security analysis."""
        depth_indicators = 0
        max_indicators = 6
        
        # Check for analysis depth indicators
        if evidence.get('classes_analyzed', 0) > 10:
            depth_indicators += 1
        
        if evidence.get('methods_analyzed', 0) > 20:
            depth_indicators += 1
        
        if evidence.get('ssl_patterns_checked', 0) > 5:
            depth_indicators += 1
        
        if evidence.get('certificate_patterns_checked', 0) > 3:
            depth_indicators += 1
        
        if evidence.get('network_config_patterns_checked', 0) > 4:
            depth_indicators += 1
        
        if evidence.get('credential_patterns_checked', 0) > 3:
            depth_indicators += 1
        
        return depth_indicators / max_indicators
    
    def map_vulnerability_to_pattern_type(self, vulnerability_type: str) -> str:
        """Map vulnerability type to pattern type for reliability lookup."""
        vulnerability_pattern_mapping = {
            'Insecure HTTP Usage': 'insecure_http',
            'Weak SSL Context': 'weak_ssl_context',
            'Trust All Certificates': 'trust_all_certs',
            'Hostname Verification Disabled': 'hostname_verification_disabled',
            'Plaintext Credentials': 'plaintext_credentials',
            'SSL Configuration Issues': 'ssl_config_issues',
            'Certificate Validation Bypass': 'certificate_validation_bypass',
            'Network Configuration Issues': 'network_config_issues',
            'Credential Handling Issues': 'credential_handling_issues',
            'TLS Version Issues': 'tls_version_issues',
            'Cipher Suite Issues': 'cipher_suite_issues'
        }
        
        return vulnerability_pattern_mapping.get(vulnerability_type, 'unknown')

def calculate_network_security_confidence(evidence: Dict[str, Any]) -> float:
    """
    Convenience function for calculating network security confidence.
    
    Args:
        evidence: Dictionary containing evidence factors
        
    Returns:
        Confidence score between 0.0 and 1.0
    """
    calculator = NetworkSecurityConfidenceCalculator()
    return calculator.calculate_confidence(evidence)