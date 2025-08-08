#!/usr/bin/env python3
"""
Evidence-Based SSL/TLS Confidence Calculator

This module provides sophisticated confidence calculation for SSL/TLS security findings
using evidence-based scoring, pattern reliability assessment, and contextual analysis.

"""

import logging
import yaml
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import statistics
import math

from core.shared_infrastructure.dependency_injection import AnalysisContext
from .data_structures import SSLTLSVulnerability, SSLTLSSeverity, ValidationStatus

class SSLTLSConfidenceCalculator:
    """
    Evidence-based confidence calculator for SSL/TLS security findings.
    
    Implements evidence-based confidence scoring with multi-factor analysis,
    pattern reliability assessment, and contextual adjustments.
    """
    
    def __init__(self, context: AnalysisContext):
        """Initialize SSL/TLS confidence calculator with dependency injection."""
        self.context = context
        self.logger = context.logger
        self.pattern_reliability_db = context.pattern_reliability_db
        self.learning_system = context.learning_system
        
        # Load SSL/TLS specific configuration
        self.ssl_patterns_config = self._load_ssl_patterns_config()
        
        # Evidence weight factors (must sum to 1.0)
        self.evidence_weights = {
            'ssl_implementation_depth': 0.25,      # Implementation vs config vs test files
            'pattern_reliability': 0.20,          # Historical pattern accuracy
            'evidence_quality': 0.20,             # Multiple evidence sources
            'context_relevance': 0.15,            # SSL/TLS context specificity
            'cross_validation': 0.20               # Multiple detection methods
        }
        
        # Context factor mappings
        self.context_factors = self._initialize_context_factors()
        
        # Pattern reliability cache
        self._pattern_reliability_cache = {}
        
        self.logger.info("SSL/TLS evidence-based confidence calculator initialized")
    
    def calculate_ssl_confidence(self, 
                                vulnerability: SSLTLSVulnerability,
                                ssl_context: Optional[Dict[str, Any]] = None,
                                evidence: Optional[Dict[str, Any]] = None) -> float:
        """
        Calculate evidence-based confidence score for SSL/TLS findings.
        
        Args:
            vulnerability: SSL/TLS vulnerability finding
            ssl_context: SSL/TLS specific context information
            evidence: Evidence data for the finding
            
        Returns:
            Evidence-based confidence score (0.0 - 1.0)
        """
        try:
            if not vulnerability or not hasattr(vulnerability, 'vulnerability_id'):
                self.logger.warning("Invalid vulnerability provided for confidence calculation")
                return 0.1  # Conservative default
            
            # Extract or initialize evidence data
            evidence_data = evidence or getattr(vulnerability, 'evidence_data', {})
            ssl_context = ssl_context or {}
            
            # Calculate individual evidence factors
            implementation_score = self._calculate_implementation_depth_score(
                vulnerability, ssl_context, evidence_data
            )
            
            pattern_reliability_score = self._calculate_pattern_reliability_score(
                vulnerability, evidence_data
            )
            
            evidence_quality_score = self._calculate_evidence_quality_score(
                vulnerability, evidence_data
            )
            
            context_relevance_score = self._calculate_context_relevance_score(
                vulnerability, ssl_context, evidence_data
            )
            
            cross_validation_score = self._calculate_cross_validation_score(
                vulnerability, evidence_data
            )
            
            # Calculate weighted confidence score
            confidence = (
                implementation_score * self.evidence_weights['ssl_implementation_depth'] +
                pattern_reliability_score * self.evidence_weights['pattern_reliability'] +
                evidence_quality_score * self.evidence_weights['evidence_quality'] +
                context_relevance_score * self.evidence_weights['context_relevance'] +
                cross_validation_score * self.evidence_weights['cross_validation']
            )
            
            # Apply SSL/TLS specific adjustments
            confidence = self._apply_ssl_specific_adjustments(
                confidence, vulnerability, ssl_context, evidence_data
            )
            
            # Ensure confidence is within valid range
            confidence = max(0.0, min(1.0, confidence))
            
            # Log confidence calculation details
            self.logger.debug(
                f"SSL/TLS confidence calculated: {confidence:.3f} for {vulnerability.vulnerability_id}"
            )
            
            return confidence
            
        except Exception as e:
            self.logger.error(f"Error calculating SSL/TLS confidence: {e}")
            return 0.3  # Conservative fallback
    
    def _calculate_implementation_depth_score(self, 
                                           vulnerability: SSLTLSVulnerability,
                                           ssl_context: Dict[str, Any],
                                           evidence: Dict[str, Any]) -> float:
        """Calculate score based on SSL/TLS implementation depth and context."""
        score = 0.5  # Base score
        
        # SSL/TLS implementation context factors
        location = getattr(vulnerability, 'location', '')
        file_path = getattr(vulnerability, 'file_path', '')
        class_name = getattr(vulnerability, 'class_name', '')
        method_name = getattr(vulnerability, 'method_name', '')
        
        # File type analysis
        if file_path:
            if any(ssl_term in file_path.lower() for ssl_term in 
                   ['ssl', 'tls', 'certificate', 'trust', 'network', 'security']):
                score += 0.3  # SSL/TLS specific file
            elif file_path.endswith(('.java', '.kt')):
                score += 0.2  # Main source file
            elif 'test' in file_path.lower():
                score += 0.1  # Test file (lower confidence)
        
        # Class context analysis
        if class_name:
            ssl_class_indicators = [
                'ssl', 'tls', 'certificate', 'trust', 'pinning', 'security',
                'network', 'https', 'socket', 'factory'
            ]
            if any(indicator in class_name.lower() for indicator in ssl_class_indicators):
                score += 0.2  # SSL/TLS related class
        
        # Method context analysis
        if method_name:
            ssl_method_indicators = [
                'ssl', 'tls', 'certificate', 'trust', 'verify', 'validate',
                'pin', 'check', 'secure', 'encrypt'
            ]
            if any(indicator in method_name.lower() for indicator in ssl_method_indicators):
                score += 0.2  # SSL/TLS related method
        
        # SSL/TLS context analysis
        if ssl_context:
            if ssl_context.get('is_network_class', False):
                score += 0.1
            if ssl_context.get('has_ssl_imports', False):
                score += 0.1
            if ssl_context.get('certificate_related', False):
                score += 0.1
        
        return min(1.0, score)
    
    def _calculate_pattern_reliability_score(self,
                                          vulnerability: SSLTLSVulnerability,
                                          evidence: Dict[str, Any]) -> float:
        """Calculate score based on pattern reliability from historical data."""
        pattern_id = getattr(vulnerability, 'detection_method', 'unknown')
        
        # Check cache first
        if pattern_id in self._pattern_reliability_cache:
            return self._pattern_reliability_cache[pattern_id]
        
        # Get pattern reliability from database
        if self.pattern_reliability_db:
            reliability = self.pattern_reliability_db.get_pattern_reliability(pattern_id)
            if reliability:
                score = reliability.reliability_score
                self._pattern_reliability_cache[pattern_id] = score
                return score
        
        # Fallback to configuration-based reliability
        if self.ssl_patterns_config and 'pattern_reliability' in self.ssl_patterns_config:
            pattern_data = self.ssl_patterns_config['pattern_reliability'].get(pattern_id, {})
            if pattern_data:
                reliability_score = pattern_data.get('reliability_score', 0.5)
                self._pattern_reliability_cache[pattern_id] = reliability_score
                return reliability_score
        
        # Conservative default for unknown patterns
        return 0.5
    
    def _calculate_evidence_quality_score(self,
                                       vulnerability: SSLTLSVulnerability,
                                       evidence: Dict[str, Any]) -> float:
        """Calculate score based on evidence quality and completeness."""
        score = 0.3  # Base score
        
        # Evidence completeness factors
        evidence_factors = [
            ('source_code_match', 0.2),
            ('method_signature', 0.15),
            ('import_statements', 0.1),
            ('class_hierarchy', 0.1),
            ('configuration_files', 0.15),
            ('manifest_references', 0.1),
            ('certificate_data', 0.2)
        ]
        
        for factor, weight in evidence_factors:
            if evidence.get(factor):
                score += weight
        
        # Evidence strength assessment
        evidence_strength = evidence.get('evidence_strength', 'weak')
        strength_multipliers = {
            'very_strong': 1.0,
            'strong': 0.9,
            'medium': 0.7,
            'weak': 0.5,
            'very_weak': 0.3
        }
        score *= strength_multipliers.get(evidence_strength, 0.5)
        
        # Multiple evidence sources bonus
        evidence_sources = evidence.get('sources', [])
        if isinstance(evidence_sources, list) and len(evidence_sources) > 1:
            source_bonus = min(0.2, len(evidence_sources) * 0.05)
            score += source_bonus
        
        return min(1.0, score)
    
    def _calculate_context_relevance_score(self,
                                        vulnerability: SSLTLSVulnerability,
                                        ssl_context: Dict[str, Any],
                                        evidence: Dict[str, Any]) -> float:
        """Calculate score based on SSL/TLS context relevance."""
        score = 0.4  # Base score
        
        # SSL/TLS context indicators
        context_indicators = {
            'ssl_related_class': 0.2,
            'certificate_operations': 0.2,
            'network_security_context': 0.15,
            'trust_manager_context': 0.2,
            'pinning_context': 0.15,
            'protocol_configuration': 0.1
        }
        
        for indicator, weight in context_indicators.items():
            if ssl_context.get(indicator, False):
                score += weight
        
        # Vulnerability type specific adjustments
        vuln_type = getattr(vulnerability, 'title', '').lower()
        if 'certificate' in vuln_type or 'trust' in vuln_type:
            score += 0.1
        if 'pinning' in vuln_type:
            score += 0.1
        if 'tls' in vuln_type or 'ssl' in vuln_type:
            score += 0.1
        
        return min(1.0, score)
    
    def _calculate_cross_validation_score(self,
                                       vulnerability: SSLTLSVulnerability,
                                       evidence: Dict[str, Any]) -> float:
        """Calculate score based on cross-validation from multiple methods."""
        base_score = 0.3
        
        # Count validation sources
        validation_sources = evidence.get('validation_sources', [])
        if not isinstance(validation_sources, list):
            return base_score
        
        # Validation source types and their weights
        validation_weights = {
            'static_analysis': 0.2,
            'manifest_analysis': 0.15,
            'configuration_analysis': 0.15,
            'certificate_analysis': 0.2,
            'dynamic_analysis': 0.3,  # Highest weight for dynamic validation
            'pattern_matching': 0.1,
            'bytecode_analysis': 0.2
        }
        
        score = base_score
        for source in validation_sources:
            if source in validation_weights:
                score += validation_weights[source]
        
        # Bonus for multiple independent validations
        if len(validation_sources) >= 3:
            score += 0.1  # Triple validation bonus
        elif len(validation_sources) >= 2:
            score += 0.05  # Dual validation bonus
        
        return min(1.0, score)
    
    def _apply_ssl_specific_adjustments(self,
                                      base_confidence: float,
                                      vulnerability: SSLTLSVulnerability,
                                      ssl_context: Dict[str, Any],
                                      evidence: Dict[str, Any]) -> float:
        """Apply SSL/TLS specific confidence adjustments."""
        confidence = base_confidence
        
        # Severity-based adjustments
        severity = getattr(vulnerability, 'severity', SSLTLSSeverity.MEDIUM)
        if severity == SSLTLSSeverity.CRITICAL:
            confidence *= 1.1  # Slight boost for critical findings
        elif severity == SSLTLSSeverity.LOW:
            confidence *= 0.9  # Slight reduction for low severity
        
        # SSL/TLS specific pattern adjustments
        vuln_id = getattr(vulnerability, 'vulnerability_id', '')
        if 'trust_all' in vuln_id.lower():
            confidence *= 1.05  # High confidence pattern
        elif 'pinning' in vuln_id.lower():
            confidence *= 0.95  # Pinning can be complex to detect accurately
        
        # Context-specific adjustments
        if ssl_context.get('is_test_environment', False):
            confidence *= 0.8  # Reduce confidence for test code
        
        if ssl_context.get('has_fallback_logic', False):
            confidence *= 0.9  # Reduce confidence when fallback logic exists
        
        # Evidence quality adjustments
        if evidence.get('dynamic_validation', False):
            confidence *= 1.1  # Boost for dynamic validation
        
        if evidence.get('multiple_instances', 0) > 1:
            confidence *= 1.05  # Boost for multiple instances
        
        return confidence
    
    def _load_ssl_patterns_config(self) -> Dict[str, Any]:
        """Load SSL/TLS patterns configuration."""
        try:
            config_path = Path(__file__).parent / 'ssl_patterns_config.yaml'
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f)
        except Exception as e:
            self.logger.warning(f"Could not load SSL patterns config: {e}")
        
        return {}
    
    def _initialize_context_factors(self) -> Dict[str, float]:
        """Initialize context factor mappings."""
        return {
            'java_source': 1.0,
            'kotlin_source': 1.0,
            'smali_source': 0.9,
            'xml_config': 0.8,
            'manifest_file': 0.9,
            'test_file': 0.6,
            'third_party': 0.7,
            'generated_code': 0.5,
            'ssl_specific_file': 1.2,
            'certificate_file': 1.1,
            'network_config': 1.0
        }
    
    def get_confidence_explanation(self, 
                                 vulnerability: SSLTLSVulnerability,
                                 ssl_context: Optional[Dict[str, Any]] = None,
                                 evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Get detailed explanation of confidence calculation."""
        ssl_context = ssl_context or {}
        evidence = evidence or {}
        
        explanation = {
            'overall_confidence': self.calculate_ssl_confidence(vulnerability, ssl_context, evidence),
            'evidence_factors': {
                'ssl_implementation_depth': self._calculate_implementation_depth_score(vulnerability, ssl_context, evidence),
                'pattern_reliability': self._calculate_pattern_reliability_score(vulnerability, evidence),
                'evidence_quality': self._calculate_evidence_quality_score(vulnerability, evidence),
                'context_relevance': self._calculate_context_relevance_score(vulnerability, ssl_context, evidence),
                'cross_validation': self._calculate_cross_validation_score(vulnerability, evidence)
            },
            'evidence_weights': self.evidence_weights,
            'adjustments_applied': 'SSL/TLS specific adjustments based on severity and context',
            'methodology': 'Multi-factor evidence-based confidence calculation'
        }
        
        return explanation