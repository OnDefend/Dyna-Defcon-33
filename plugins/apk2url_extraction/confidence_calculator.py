#!/usr/bin/env python3
"""
APK2URL Extraction Plugin - Professional Confidence Calculator

Evidence-based confidence calculation system for endpoint discovery findings.
Implements sophisticated confidence scoring that considers pattern reliability,
context relevance, extraction method quality, and validation coverage.
"""

import logging
import yaml
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass
from .data_structures import (
    EndpointFinding, EndpointType, ExtractionMethod, SecurityRisk,
    ProtocolType, DomainCategory, PatternMatch, ExtractionResults
)

logger = logging.getLogger(__name__)

@dataclass
class ConfidenceEvidence:
    """Evidence factors for confidence calculation."""
    pattern_reliability: float = 0.0
    context_relevance: float = 0.0
    validation_coverage: float = 0.0
    extraction_method_quality: float = 0.0
    noise_filtering_effectiveness: float = 0.0
    structural_validation: float = 0.0

class APK2URLConfidenceCalculator:
    """
    confidence calculation system for APK2URL endpoint discovery.
    
    Implements evidence-based confidence scoring with multi-factor analysis
    considering pattern reliability, context relevance, and extraction quality.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize confidence calculator with configuration."""
        if config_path is None:
            config_path = Path(__file__).parent / "extraction_patterns_config.yaml"
        
        self.config = self._load_configuration(config_path)
        
        # Evidence weight factors for endpoint discovery
        self.evidence_weights = {
            'pattern_reliability': 0.25,        # 25% - Pattern match reliability
            'context_relevance': 0.20,          # 20% - Context relevance
            'validation_coverage': 0.20,        # 20% - Validation coverage
            'extraction_method_quality': 0.15,  # 15% - Extraction method quality
            'noise_filtering_effectiveness': 0.10, # 10% - Noise filtering
            'structural_validation': 0.10       # 10% - Structural validation
        }
        
        # Pattern reliability database from configuration
        self.pattern_reliability_data = self._extract_pattern_reliability()
        
        # Context relevance factors
        self.context_factors = {
            'manifest_file': 1.0,        # Highest relevance
            'config_file': 0.9,          # High relevance
            'resource_file': 0.8,        # Medium-high relevance
            'dex_code': 0.7,             # Medium relevance
            'native_library': 0.6,       # Lower relevance
            'binary_data': 0.5,          # Lowest relevance
            'certificate': 0.8           # High relevance for certs
        }
        
        # Extraction method quality scores
        self.extraction_method_quality = {
            ExtractionMethod.MANIFEST_ANALYSIS: 0.95,
            ExtractionMethod.CONFIG_ANALYSIS: 0.90,
            ExtractionMethod.JSON_ANALYSIS: 0.85,
            ExtractionMethod.RESOURCE_ANALYSIS: 0.80,
            ExtractionMethod.DEX_ANALYSIS: 0.75,
            ExtractionMethod.CERTIFICATE_ANALYSIS: 0.85,
            ExtractionMethod.NATIVE_LIB_ANALYSIS: 0.70,
            ExtractionMethod.BINARY_PATTERN_MATCHING: 0.60
        }
        
        # Endpoint type risk multipliers
        self.endpoint_risk_multipliers = {
            EndpointType.SECRET: 1.2,
            EndpointType.API_ENDPOINT: 1.1,
            EndpointType.URL: 1.0,
            EndpointType.IP_ADDRESS: 1.0,
            EndpointType.DOMAIN: 0.9,
            EndpointType.DEEP_LINK: 0.9,
            EndpointType.FILE_URL: 0.8,
            EndpointType.CERTIFICATE: 0.8
        }
        
        # Protocol security factors
        self.protocol_security_factors = {
            ProtocolType.HTTPS: 1.0,
            ProtocolType.WEBSOCKET_SECURE: 1.0,
            ProtocolType.HTTP: 0.7,      # Lower confidence due to security risk
            ProtocolType.WEBSOCKET: 0.7, # Lower confidence due to security risk
            ProtocolType.FTP: 0.6,       # Lower confidence due to cleartext
            ProtocolType.CUSTOM: 0.8     # Unknown security implications
        }
        
        logger.info("Initialized APK2URLConfidenceCalculator")
    
    def calculate_finding_confidence(self, finding: EndpointFinding, 
                                   evidence: Dict[str, Any]) -> float:
        """
        Calculate evidence-based confidence for an endpoint finding.
        
        Args:
            finding: Endpoint finding
            evidence: Evidence data for confidence calculation
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        try:
            # Extract evidence factors
            evidence_factors = self._extract_evidence_factors(finding, evidence)
            
            # Calculate weighted confidence score
            confidence = (
                evidence_factors.pattern_reliability * self.evidence_weights['pattern_reliability'] +
                evidence_factors.context_relevance * self.evidence_weights['context_relevance'] +
                evidence_factors.validation_coverage * self.evidence_weights['validation_coverage'] +
                evidence_factors.extraction_method_quality * self.evidence_weights['extraction_method_quality'] +
                evidence_factors.noise_filtering_effectiveness * self.evidence_weights['noise_filtering_effectiveness'] +
                evidence_factors.structural_validation * self.evidence_weights['structural_validation']
            )
            
            # Apply endpoint type multiplier
            type_multiplier = self.endpoint_risk_multipliers.get(finding.endpoint_type, 1.0)
            confidence *= type_multiplier
            
            # Apply protocol security factor
            if finding.protocol:
                protocol_factor = self.protocol_security_factors.get(finding.protocol, 0.8)
                confidence *= protocol_factor
            
            # Apply risk level adjustment
            confidence = self._apply_risk_level_adjustment(confidence, finding.risk_level)
            
            # Ensure confidence is within valid bounds
            confidence = max(0.0, min(1.0, confidence))
            
            logger.debug(f"Calculated confidence {confidence:.3f} for finding {finding.value}")
            return confidence
            
        except Exception as e:
            logger.error(f"Error calculating finding confidence: {e}")
            return 0.5  # Conservative default
    
    def calculate_extraction_confidence(self, results: ExtractionResults,
                                      evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence for overall extraction results.
        
        Args:
            results: Complete extraction results
            evidence: Evidence data for confidence calculation
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        try:
            # Factor 1: Extraction completeness
            completeness = self._assess_extraction_completeness(results, evidence)
            
            # Factor 2: Processing coverage
            coverage = self._assess_processing_coverage(results, evidence)
            
            # Factor 3: Noise filtering effectiveness
            noise_filtering = self._assess_noise_filtering_effectiveness(results, evidence)
            
            # Factor 4: Validation consistency
            validation_consistency = self._assess_validation_consistency(evidence)
            
            # Calculate weighted confidence
            confidence = (
                completeness * 0.3 +
                coverage * 0.25 +
                noise_filtering * 0.25 +
                validation_consistency * 0.2
            )
            
            return max(0.0, min(1.0, confidence))
            
        except Exception as e:
            logger.error(f"Error calculating extraction confidence: {e}")
            return 0.5  # Conservative default
    
    def _extract_evidence_factors(self, finding: EndpointFinding,
                                evidence: Dict[str, Any]) -> ConfidenceEvidence:
        """Extract evidence factors for confidence calculation."""
        # Pattern reliability based on pattern type
        pattern_type = evidence.get('pattern_type', 'generic')
        pattern_reliability = self.pattern_reliability_data.get(pattern_type, 0.7)
        
        # Context relevance based on source file type
        context_type = self._determine_context_type(finding.source_file)
        context_relevance = self.context_factors.get(context_type, 0.5)
        
        # Validation coverage based on validation methods
        validation_methods = evidence.get('validation_methods', [])
        validation_coverage = min(1.0, len(validation_methods) * 0.25)
        
        # Extraction method quality
        extraction_quality = self.extraction_method_quality.get(
            finding.extraction_method, 0.6
        )
        
        # Noise filtering effectiveness
        noise_filtering = self._assess_noise_filtering_quality(finding, evidence)
        
        # Structural validation
        structural_validation = self._assess_structural_validation(finding, evidence)
        
        return ConfidenceEvidence(
            pattern_reliability=pattern_reliability,
            context_relevance=context_relevance,
            validation_coverage=validation_coverage,
            extraction_method_quality=extraction_quality,
            noise_filtering_effectiveness=noise_filtering,
            structural_validation=structural_validation
        )
    
    def _determine_context_type(self, source_file: str) -> str:
        """Determine context type from source file path."""
        source_lower = source_file.lower()
        
        if 'androidmanifest.xml' in source_lower:
            return 'manifest_file'
        elif source_lower.endswith('.xml') and '/res/' in source_lower:
            return 'resource_file'
        elif source_lower.endswith('.json'):
            return 'config_file'
        elif source_lower.endswith('.dex') or 'classes' in source_lower:
            return 'dex_code'
        elif source_lower.endswith('.so') or '/lib/' in source_lower:
            return 'native_library'
        elif 'certificate' in source_lower or source_lower.endswith('.crt'):
            return 'certificate'
        else:
            return 'binary_data'
    
    def _assess_noise_filtering_quality(self, finding: EndpointFinding,
                                      evidence: Dict[str, Any]) -> float:
        """Assess quality of noise filtering for the finding."""
        noise_score = 0.5  # Base score
        
        # Check if noise filtering was applied
        if evidence.get('noise_filtered', False):
            noise_score += 0.3
        
        # Check if finding passed framework noise checks
        if evidence.get('passed_framework_check', False):
            noise_score += 0.2
        
        # Penalty for findings in excluded paths
        if any(pattern in finding.source_file.lower() 
               for pattern in ['flutter_assets', 'node_modules', 'react-native']):
            noise_score -= 0.3
        
        return max(0.0, min(1.0, noise_score))
    
    def _assess_structural_validation(self, finding: EndpointFinding,
                                    evidence: Dict[str, Any]) -> float:
        """Assess structural validation of the finding."""
        validation_score = 0.0
        
        # URL structural validation
        if finding.endpoint_type == EndpointType.URL:
            if evidence.get('valid_url_structure', False):
                validation_score += 0.4
            if evidence.get('valid_domain', False):
                validation_score += 0.3
            if evidence.get('valid_scheme', False):
                validation_score += 0.3
        
        # IP address validation
        elif finding.endpoint_type == EndpointType.IP_ADDRESS:
            if evidence.get('valid_ip_format', False):
                validation_score += 0.5
            if evidence.get('not_reserved_ip', False):
                validation_score += 0.3
            if evidence.get('not_version_number', False):
                validation_score += 0.2
        
        # Domain validation
        elif finding.endpoint_type == EndpointType.DOMAIN:
            if evidence.get('valid_tld', False):
                validation_score += 0.4
            if evidence.get('valid_domain_format', False):
                validation_score += 0.3
            if evidence.get('not_framework_reference', False):
                validation_score += 0.3
        
        # API endpoint validation
        elif finding.endpoint_type == EndpointType.API_ENDPOINT:
            if evidence.get('valid_api_pattern', False):
                validation_score += 0.5
            if evidence.get('reasonable_path_structure', False):
                validation_score += 0.3
            if evidence.get('not_ui_reference', False):
                validation_score += 0.2
        
        else:
            # Generic validation for other types
            validation_score = 0.6
        
        return max(0.0, min(1.0, validation_score))
    
    def _apply_risk_level_adjustment(self, confidence: float, risk_level: SecurityRisk) -> float:
        """Apply risk level adjustment to confidence."""
        risk_adjustments = {
            SecurityRisk.CRITICAL: 1.1,
            SecurityRisk.HIGH: 1.05,
            SecurityRisk.MEDIUM: 1.0,
            SecurityRisk.LOW: 0.95,
            SecurityRisk.INFO: 0.9
        }
        
        adjustment = risk_adjustments.get(risk_level, 1.0)
        return confidence * adjustment
    
    def _assess_extraction_completeness(self, results: ExtractionResults,
                                      evidence: Dict[str, Any]) -> float:
        """Assess completeness of extraction process."""
        completeness_score = 0.5
        
        # Check various extraction aspects
        if evidence.get('manifest_processed'):
            completeness_score += 0.15
        if evidence.get('resources_processed'):
            completeness_score += 0.1
        if evidence.get('dex_processed'):
            completeness_score += 0.1
        if evidence.get('configs_processed'):
            completeness_score += 0.1
        if evidence.get('certificates_processed'):
            completeness_score += 0.05
        
        return min(1.0, completeness_score)
    
    def _assess_processing_coverage(self, results: ExtractionResults,
                                  evidence: Dict[str, Any]) -> float:
        """Assess processing coverage for confidence calculation."""
        total_files = evidence.get('total_files_in_apk', 1)
        processed_files = evidence.get('files_processed', 0)
        
        if total_files == 0:
            return 0.5
        
        coverage_ratio = processed_files / total_files
        return min(1.0, coverage_ratio)
    
    def _assess_noise_filtering_effectiveness(self, results: ExtractionResults,
                                            evidence: Dict[str, Any]) -> float:
        """Assess noise filtering effectiveness."""
        if results.noise_filter_result:
            return results.noise_filter_result.filter_efficiency
        
        # Fallback assessment
        original_count = evidence.get('pre_filter_count', 0)
        final_count = sum(len(category) for category in [
            results.urls, results.ips, results.domains, results.api_endpoints,
            results.deep_links, results.file_urls, results.certificates, results.secrets
        ])
        
        if original_count == 0:
            return 0.8  # No noise to filter
        
        filter_ratio = 1.0 - (final_count / original_count)
        return max(0.3, min(1.0, filter_ratio))  # At least 30% effectiveness
    
    def _assess_validation_consistency(self, evidence: Dict[str, Any]) -> float:
        """Assess validation consistency across findings."""
        validation_results = evidence.get('validation_results', {})
        
        if not validation_results:
            return 0.5
        
        # Calculate consistency across validation methods
        consistency_scores = []
        for method, results in validation_results.items():
            if isinstance(results, dict) and 'success_rate' in results:
                consistency_scores.append(results['success_rate'])
        
        if not consistency_scores:
            return 0.5
        
        # Calculate average consistency
        avg_consistency = sum(consistency_scores) / len(consistency_scores)
        return avg_consistency
    
    def _extract_pattern_reliability(self) -> Dict[str, float]:
        """Extract pattern reliability data from configuration."""
        reliability_data = {}
        
        # URL patterns
        url_patterns = self.config.get('url_patterns', {})
        for pattern_name, pattern_config in url_patterns.items():
            confidence = pattern_config.get('confidence', 0.7)
            reliability_data[pattern_name] = confidence
        
        # IP patterns
        ip_patterns = self.config.get('ip_patterns', {})
        for pattern_name, pattern_config in ip_patterns.items():
            confidence = pattern_config.get('confidence', 0.7)
            reliability_data[pattern_name] = confidence
        
        # Domain patterns
        domain_patterns = self.config.get('domain_patterns', {})
        for pattern_name, pattern_config in domain_patterns.items():
            confidence = pattern_config.get('confidence', 0.7)
            reliability_data[pattern_name] = confidence
        
        # API patterns
        api_patterns = self.config.get('api_patterns', {})
        for pattern_name, pattern_config in api_patterns.items():
            confidence = pattern_config.get('confidence', 0.7)
            reliability_data[pattern_name] = confidence
        
        return reliability_data
    
    def _load_configuration(self, config_path: Path) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded APK2URL extraction configuration from {config_path}")
            return config
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return {}
    
    def calculate_pattern_confidence(self, pattern_match: PatternMatch,
                                   evidence: Dict[str, Any]) -> float:
        """Calculate confidence for a specific pattern match."""
        try:
            # Base confidence from pattern reliability
            pattern_confidence = self.pattern_reliability_data.get(
                pattern_match.pattern_name, 0.7
            )
            
            # Adjust for context quality
            context_quality = self._assess_context_quality(pattern_match)
            
            # Adjust for noise probability
            noise_probability = 1.0 - (0.1 if pattern_match.is_noise else 0.0)
            
            # Calculate overall confidence
            confidence = pattern_confidence * context_quality * noise_probability
            
            return max(0.0, min(1.0, confidence))
            
        except Exception as e:
            logger.error(f"Error calculating pattern confidence: {e}")
            return 0.5  # Conservative default
    
    def _assess_context_quality(self, pattern_match: PatternMatch) -> float:
        """Assess quality of context around pattern match."""
        context_score = 0.5
        
        # Check for meaningful context before and after
        if pattern_match.context_before and len(pattern_match.context_before.strip()) > 5:
            context_score += 0.2
        
        if pattern_match.context_after and len(pattern_match.context_after.strip()) > 5:
            context_score += 0.2
        
        # Penalty for very long contexts (likely noise)
        if (len(pattern_match.context_before) > 100 or 
            len(pattern_match.context_after) > 100):
            context_score -= 0.1
        
        return max(0.0, min(1.0, context_score)) 