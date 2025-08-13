"""
Professional Confidence Calculator for WebView Security Analysis

This module provides enterprise-grade confidence calculation for WebView security
analysis findings based on multiple evidence factors, pattern reliability, and
contextual analysis.
"""

from typing import Dict, Any, List
from .data_structures import WebViewVulnerabilityType, WebViewContextType

class WebViewSecurityConfidenceCalculator:
    """
    confidence calculation system for WebView security analysis findings.
    
    Calculates dynamic confidence scores based on:
    - Security vulnerability patterns and their reliability
    - Evidence strength from multiple WebView analysis methods
    - Context awareness based on WebView implementation and configuration
    - Cross-validation from multiple security analysis techniques
    - Analysis depth and comprehensive coverage of WebView security issues
    """
    
    def __init__(self):
        # Evidence weight factors for WebView security analysis
        self.evidence_weights = {
            'pattern_reliability': 0.3,      # Reliability of WebView security patterns
            'evidence_strength': 0.25,       # Strength of evidence from analysis
            'context_awareness': 0.2,        # Context of WebView implementation
            'cross_validation': 0.15,        # Multiple detection method validation
            'analysis_depth': 0.1           # Depth of WebView security analysis
        }
        
        # Pattern reliability data for WebView security findings (based on false positive rates)
        self.pattern_reliability = {
            'javascript_interface_exposure': {'reliability': 0.95, 'fp_rate': 0.05},
            'webview_xss_vulnerabilities': {'reliability': 0.92, 'fp_rate': 0.08},
            'javascript_enabled_globally': {'reliability': 0.85, 'fp_rate': 0.15},
            'file_access_enabled': {'reliability': 0.88, 'fp_rate': 0.12},
            'universal_access_enabled': {'reliability': 0.98, 'fp_rate': 0.02},
            'mixed_content_allowed': {'reliability': 0.90, 'fp_rate': 0.10},
            'webview_configuration_issues': {'reliability': 0.87, 'fp_rate': 0.13},
            'dangerous_operations_exposed': {'reliability': 0.93, 'fp_rate': 0.07},
            'input_validation_missing': {'reliability': 0.80, 'fp_rate': 0.20},
            'webview_bridge_security': {'reliability': 0.86, 'fp_rate': 0.14},
            'dynamic_xss_testing': {'reliability': 0.95, 'fp_rate': 0.05}
        }
        
        # Context factor mapping for WebView security analysis
        self.context_factors = {
            'production_webview': 0.9,      # Production WebView implementation
            'development_webview': 0.7,     # Development WebView implementation
            'hybrid_app': 0.8,              # Hybrid application context
            'native_app': 0.6,              # Native app with WebView context
            'configuration_file': 0.85,     # Configuration file context
            'manifest_file': 0.80,          # Manifest file context
            'javascript_bridge': 0.95,      # JavaScript bridge context
            'third_party_webview': 0.75,    # Third-party WebView library context
            'custom_webview': 0.70,         # Custom WebView implementation context
            'unknown_context': 0.65         # Unknown context
        }
        
        # WebView security vulnerability types and their impact levels
        self.vulnerability_types = {
            'javascript_interface_exposure': 0.95,  # High impact - code execution
            'webview_xss_vulnerabilities': 0.90,    # High impact - content injection
            'universal_access_enabled': 0.98,       # Critical impact - file access
            'file_access_enabled': 0.85,            # Medium-high impact - local files
            'mixed_content_allowed': 0.88,          # Medium-high impact - MITM
            'javascript_enabled_globally': 0.70,    # Medium impact - depends on usage
            'dangerous_operations_exposed': 0.93,   # High impact - system access
            'input_validation_missing': 0.75,       # Medium impact - depends on exposure
            'webview_configuration_issues': 0.80,   # Medium impact - configuration
            'webview_bridge_security': 0.85,        # Medium-high impact - bridge issues
            'dynamic_xss_testing': 0.95             # High impact - confirmed XSS
        }
    
    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate dynamic confidence score for WebView security findings.
        
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
        
        # Apply vulnerability-specific adjustments
        vulnerability_type = evidence.get('vulnerability_type', 'unknown')
        if vulnerability_type in self.vulnerability_types:
            impact_factor = self.vulnerability_types[vulnerability_type]
            confidence_score *= impact_factor
        
        # Ensure confidence score is within valid range
        return max(0.0, min(1.0, confidence_score))
    
    def _assess_pattern_reliability(self, evidence: Dict[str, Any]) -> float:
        """Assess reliability of WebView security patterns."""
        pattern_type = evidence.get('pattern_type', 'unknown')
        
        if pattern_type in self.pattern_reliability:
            return self.pattern_reliability[pattern_type]['reliability']
        else:
            return 0.5  # Default reliability for unknown patterns
    
    def _assess_evidence_strength(self, evidence: Dict[str, Any]) -> float:
        """Assess strength of evidence from WebView analysis."""
        strength_score = 0.0
        
        # Multiple evidence sources increase confidence
        evidence_sources = evidence.get('evidence_sources', [])
        if len(evidence_sources) >= 3:
            strength_score += 0.3
        elif len(evidence_sources) >= 2:
            strength_score += 0.2
        elif len(evidence_sources) >= 1:
            strength_score += 0.1
        
        # Code examples and patterns increase confidence
        if evidence.get('code_examples'):
            strength_score += 0.2
        
        # Pattern matches increase confidence
        pattern_matches = evidence.get('pattern_matches', 0)
        if pattern_matches > 0:
            strength_score += min(0.3, pattern_matches * 0.1)
        
        # Dynamic testing results increase confidence
        if evidence.get('dynamic_test_results'):
            strength_score += 0.25
        
        # Method analysis depth
        methods_analyzed = evidence.get('methods_analyzed', 0)
        if methods_analyzed > 5:
            strength_score += 0.15
        elif methods_analyzed > 1:
            strength_score += 0.1
        
        return min(1.0, strength_score)
    
    def _assess_context_awareness(self, evidence: Dict[str, Any]) -> float:
        """Assess context awareness for WebView security analysis."""
        context_type = evidence.get('context_type', 'unknown_context')
        return self.context_factors.get(context_type, 0.5)
    
    def _assess_cross_validation(self, evidence: Dict[str, Any]) -> float:
        """Assess cross-validation from multiple analysis methods."""
        validation_methods = evidence.get('validation_methods', [])
        
        # Define validation method quality scores
        validation_quality_scores = {
            'static_analysis': 0.7,
            'dynamic_testing': 0.9,
            'configuration_analysis': 0.8,
            'javascript_bridge_analysis': 0.85,
            'manifest_analysis': 0.75,
            'code_pattern_matching': 0.65,
            'runtime_testing': 0.95,
            'penetration_testing': 1.0
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
    
    def _assess_validation_quality(self, validation_methods: List[str]) -> float:
        """Assess the quality of validation methods used."""
        if not validation_methods:
            return 0.3
        
        # High-quality validation methods
        high_quality = ['dynamic_testing', 'runtime_testing', 'penetration_testing']
        medium_quality = ['static_analysis', 'configuration_analysis', 'javascript_bridge_analysis']
        low_quality = ['code_pattern_matching', 'manifest_analysis']
        
        quality_score = 0.0
        for method in validation_methods:
            if method in high_quality:
                quality_score += 0.3
            elif method in medium_quality:
                quality_score += 0.2
            elif method in low_quality:
                quality_score += 0.1
        
        # Normalize by number of methods
        if validation_methods:
            quality_score = quality_score / len(validation_methods)
        
        return min(1.0, quality_score)
    
    def _assess_analysis_depth(self, evidence: Dict[str, Any]) -> float:
        """Assess depth of WebView security analysis."""
        depth_score = 0.0
        
        # Number of files analyzed
        files_analyzed = evidence.get('files_analyzed', 0)
        if files_analyzed > 10:
            depth_score += 0.3
        elif files_analyzed > 5:
            depth_score += 0.2
        elif files_analyzed > 1:
            depth_score += 0.1
        
        # Number of classes analyzed
        classes_analyzed = evidence.get('classes_analyzed', 0)
        if classes_analyzed > 20:
            depth_score += 0.25
        elif classes_analyzed > 10:
            depth_score += 0.15
        elif classes_analyzed > 1:
            depth_score += 0.1
        
        # WebView methods analyzed
        webview_methods = evidence.get('webview_methods_analyzed', 0)
        if webview_methods > 15:
            depth_score += 0.2
        elif webview_methods > 5:
            depth_score += 0.15
        elif webview_methods > 1:
            depth_score += 0.1
        
        # JavaScript interfaces analyzed
        js_interfaces = evidence.get('javascript_interfaces_analyzed', 0)
        if js_interfaces > 5:
            depth_score += 0.15
        elif js_interfaces > 1:
            depth_score += 0.1
        
        # XSS payloads tested
        xss_payloads = evidence.get('xss_payloads_tested', 0)
        if xss_payloads > 10:
            depth_score += 0.1
        elif xss_payloads > 5:
            depth_score += 0.05
        
        return min(1.0, depth_score)
    
    def _map_vulnerability_to_pattern_type(self, vulnerability_type: str) -> str:
        """Map vulnerability type to pattern type for reliability lookup."""
        vulnerability_pattern_mapping = {
            'XSS': 'webview_xss_vulnerabilities',
            'JavaScript Interface': 'javascript_interface_exposure',
            'File Access': 'file_access_enabled',
            'Universal Access': 'universal_access_enabled',
            'Mixed Content': 'mixed_content_allowed',
            'Configuration': 'webview_configuration_issues',
            'Bridge Security': 'webview_bridge_security',
            'Input Validation': 'input_validation_missing'
        }
        
        return vulnerability_pattern_mapping.get(vulnerability_type, 'unknown')

def calculate_webview_confidence(evidence: Dict[str, Any]) -> float:
    """
    Convenience function for calculating WebView security confidence.
    
    Args:
        evidence: Dictionary containing evidence factors
        
    Returns:
        Confidence score between 0.0 and 1.0
    """
    calculator = WebViewSecurityConfidenceCalculator()
    return calculator.calculate_confidence(evidence) 