#!/usr/bin/env python3
"""
Confidence Calculator for Production APK Validation

This module provides confidence calculation for production APK
validation with evidence-based scoring and dynamic threshold determination.

Features:
- Evidence-based confidence calculation for security findings
- Dynamic threshold calculation based on APK characteristics
- Context-aware confidence adjustments
- Quality assessment and false positive estimation
- Production readiness assessment

"""

import logging
import math
import statistics
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import yaml

@dataclass
class ProductionValidationEvidence:
    """Evidence structure for production APK validation confidence calculation."""
    apk_characteristics: Dict[str, Any]
    finding_analysis: Dict[str, Any]
    security_assessment: Dict[str, Any]
    configuration_analysis: Dict[str, Any]
    validation_context: Dict[str, Any]

class ProductionAPKConfidenceCalculator:
    """
    Confidence calculation system for production APK validation.
    
    Provides evidence-based confidence scoring for security findings
    and dynamic threshold calculation for production environments.
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize the production APK confidence calculator."""
        self.logger = logging.getLogger(__name__)
        
        # Evidence weight factors for production validation confidence
        self.evidence_weights = {
            'finding_reliability': 0.30,     # Reliability of security findings
            'apk_characteristics': 0.25,     # APK size, complexity, type
            'security_assessment': 0.20,     # Security analysis quality
            'configuration_analysis': 0.15,  # Configuration validation depth
            'validation_context': 0.10      # Validation environment context
        }
        
        # Pattern reliability data for production validation (based on historical accuracy)
        self.pattern_reliability = {
            'critical_security_finding': {'reliability': 0.95, 'fp_rate': 0.05},
            'high_severity_finding': {'reliability': 0.92, 'fp_rate': 0.08},
            'medium_severity_finding': {'reliability': 0.85, 'fp_rate': 0.15},
            'low_severity_finding': {'reliability': 0.78, 'fp_rate': 0.22},
            'configuration_issue': {'reliability': 0.88, 'fp_rate': 0.12},
            'debug_configuration': {'reliability': 0.94, 'fp_rate': 0.06},
            'backup_configuration': {'reliability': 0.90, 'fp_rate': 0.10},
            'production_hardening': {'reliability': 0.87, 'fp_rate': 0.13},
            'vulnerability_preservation': {'reliability': 0.93, 'fp_rate': 0.07},
            'false_positive_indicator': {'reliability': 0.82, 'fp_rate': 0.18}
        }
        
        # Context factor mapping for production validation
        self.context_factors = {
            'apk_size': {'small': 0.8, 'medium': 0.9, 'large': 1.0, 'very_large': 1.1},
            'apk_complexity': {'low': 0.7, 'medium': 0.9, 'high': 1.0, 'very_high': 1.1},
            'target_environment': {'development': 0.6, 'testing': 0.8, 'staging': 0.9, 'production': 1.0},
            'validation_method': {'automated': 0.8, 'hybrid': 0.9, 'manual': 1.0},
            'analysis_depth': {'basic': 0.7, 'standard': 0.9, 'comprehensive': 1.0, 'exhaustive': 1.1}
        }
        
        # Load custom configuration if provided
        self.config = self._load_confidence_config(config_path)
        
        self.logger.info("Production APK Confidence Calculator initialized")
    
    def _load_confidence_config(self, config_path: Optional[Path]) -> Dict[str, Any]:
        """Load confidence calculation configuration from file."""
        default_config = {
            'production_ready_base_threshold': 0.70,
            'high_confidence_base_threshold': 0.80,
            'critical_finding_weight': 1.2,
            'security_hardening_bonus': 0.1,
            'debug_configuration_penalty': 0.15
        }
        
        if config_path and config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    config_data = yaml.safe_load(f)
                    return {**default_config, **config_data.get('confidence_calculation', {})}
            except Exception as e:
                self.logger.warning(f"Failed to load confidence config: {e}")
        
        return default_config
    
    def calculate_production_readiness_confidence(self, evidence: ProductionValidationEvidence) -> float:
        """
        Calculate production readiness confidence based on comprehensive evidence analysis.
        
        Args:
            evidence: Structured evidence for confidence calculation
            
        Returns:
            Confidence score (0.0-1.0) for production readiness assessment
        """
        try:
            # Calculate individual evidence factor scores
            finding_reliability = self._assess_finding_reliability(evidence.finding_analysis)
            apk_characteristics = self._assess_apk_characteristics(evidence.apk_characteristics)
            security_assessment = self._assess_security_assessment(evidence.security_assessment)
            configuration_analysis = self._assess_configuration_analysis(evidence.configuration_analysis)
            validation_context = self._assess_validation_context(evidence.validation_context)
            
            # Calculate weighted confidence score
            confidence_score = (
                finding_reliability * self.evidence_weights['finding_reliability'] +
                apk_characteristics * self.evidence_weights['apk_characteristics'] +
                security_assessment * self.evidence_weights['security_assessment'] +
                configuration_analysis * self.evidence_weights['configuration_analysis'] +
                validation_context * self.evidence_weights['validation_context']
            )
            
            # Apply production-specific adjustments
            confidence_score = self._apply_production_adjustments(confidence_score, evidence)
            
            # Ensure confidence is within valid range
            confidence_score = max(0.0, min(1.0, confidence_score))
            
            self.logger.debug(f"Production readiness confidence calculated: {confidence_score:.3f}")
            return confidence_score
            
        except Exception as e:
            self.logger.error(f"Confidence calculation failed: {e}")
            return 0.5  # Conservative fallback
    
    def calculate_finding_confidence(self, finding: Dict[str, Any], apk_context: Dict[str, Any]) -> float:
        """
        Calculate confidence for individual security finding.
        
        Args:
            finding: Security finding data
            apk_context: APK context information
            
        Returns:
            Confidence score (0.0-1.0) for the finding
        """
        try:
            # Extract finding characteristics
            severity = finding.get('severity', 'medium').lower()
            finding_type = finding.get('type', 'unknown').lower()
            evidence_strength = finding.get('evidence', {})
            
            # Base confidence from pattern reliability
            pattern_key = f"{severity}_severity_finding"
            base_confidence = self.pattern_reliability.get(pattern_key, {'reliability': 0.8})['reliability']
            
            # Adjust based on evidence strength
            evidence_factor = self._assess_evidence_strength(evidence_strength)
            
            # Adjust based on APK context
            context_factor = self._assess_finding_context(finding, apk_context)
            
            # Calculate final confidence
            finding_confidence = base_confidence * evidence_factor * context_factor
            
            # Ensure within valid range
            finding_confidence = max(0.1, min(1.0, finding_confidence))
            
            return finding_confidence
            
        except Exception as e:
            self.logger.error(f"Finding confidence calculation failed: {e}")
            return 0.5  # Conservative fallback
    
    def get_dynamic_thresholds(self, apk_context: Dict[str, Any]) -> Dict[str, float]:
        """
        Generate dynamic thresholds based on APK context and analysis requirements.
        
        Args:
            apk_context: APK context information
            
        Returns:
            Dictionary of dynamic thresholds for validation
        """
        try:
            # Base thresholds from configuration
            base_thresholds = {
                'production_ready_threshold': self.config['production_ready_base_threshold'],
                'high_confidence_threshold': self.config['high_confidence_base_threshold'],
                'critical_severity_threshold': 0.70,
                'high_severity_threshold': 0.80,
                'critical_types_threshold': 0.60
            }
            
            # Adjust thresholds based on APK characteristics
            apk_size = apk_context.get('size_category', 'medium')
            apk_complexity = apk_context.get('complexity', 'medium')
            target_environment = apk_context.get('target_environment', 'production')
            
            # Apply context-based adjustments
            adjustments = {
                'apk_size_adjustment': self.context_factors['apk_size'].get(apk_size, 1.0),
                'complexity_adjustment': self.context_factors['apk_complexity'].get(apk_complexity, 1.0),
                'environment_adjustment': self.context_factors['target_environment'].get(target_environment, 1.0)
            }
            
            # Calculate adjustment factor
            overall_adjustment = sum(adjustments.values()) / len(adjustments)
            
            # Apply adjustments to thresholds
            dynamic_thresholds = {}
            for threshold_name, base_value in base_thresholds.items():
                adjusted_value = base_value * overall_adjustment
                # Keep thresholds within reasonable bounds
                dynamic_thresholds[threshold_name] = max(0.3, min(0.95, adjusted_value))
            
            self.logger.debug(f"Dynamic thresholds generated: {dynamic_thresholds}")
            return dynamic_thresholds
            
        except Exception as e:
            self.logger.error(f"Dynamic threshold calculation failed: {e}")
            # Return conservative default thresholds
            return {
                'production_ready_threshold': 0.70,
                'high_confidence_threshold': 0.80,
                'critical_severity_threshold': 0.70,
                'high_severity_threshold': 0.80,
                'critical_types_threshold': 0.60
            }
    
    def _assess_finding_reliability(self, finding_analysis: Dict[str, Any]) -> float:
        """Assess reliability of security findings."""
        try:
            total_findings = finding_analysis.get('total_findings', 1)
            critical_findings = finding_analysis.get('critical_findings', 0)
            high_confidence_findings = finding_analysis.get('high_confidence_findings', 0)
            false_positive_indicators = finding_analysis.get('false_positive_indicators', 0)
            
            # Calculate base reliability
            if total_findings == 0:
                return 0.5
            
            # High confidence finding ratio
            high_confidence_ratio = high_confidence_findings / total_findings
            
            # Critical finding significance
            critical_significance = min(critical_findings / max(total_findings, 1), 0.3)
            
            # False positive penalty
            fp_penalty = min(false_positive_indicators / max(total_findings, 1), 0.2)
            
            # Calculate reliability score
            reliability = 0.7 + (high_confidence_ratio * 0.2) + critical_significance - fp_penalty
            
            return max(0.2, min(1.0, reliability))
            
        except Exception:
            return 0.6  # Conservative default
    
    def _assess_apk_characteristics(self, apk_characteristics: Dict[str, Any]) -> float:
        """Assess APK characteristics impact on confidence."""
        try:
            size_category = apk_characteristics.get('size_category', 'medium')
            complexity = apk_characteristics.get('complexity', 'medium')
            library_count = apk_characteristics.get('library_count', 0)
            
            # Size factor
            size_factor = self.context_factors['apk_size'].get(size_category, 0.9)
            
            # Complexity factor
            complexity_factor = self.context_factors['apk_complexity'].get(complexity, 0.9)
            
            # Library complexity (more libraries = more analysis surface)
            library_factor = min(1.0 + (library_count / 100), 1.2)  # Up to 20% bonus
            
            # Calculate characteristics score
            characteristics_score = (size_factor + complexity_factor + library_factor) / 3
            
            return max(0.3, min(1.2, characteristics_score))
            
        except Exception:
            return 0.8  # Conservative default
    
    def _assess_security_assessment(self, security_assessment: Dict[str, Any]) -> float:
        """Assess quality of security assessment."""
        try:
            analysis_depth = security_assessment.get('analysis_depth', 'standard')
            plugin_coverage = security_assessment.get('plugin_coverage', 0.8)
            validation_methods = security_assessment.get('validation_methods', 1)
            
            # Analysis depth factor
            depth_factor = self.context_factors['analysis_depth'].get(analysis_depth, 0.9)
            
            # Plugin coverage factor
            coverage_factor = min(plugin_coverage + 0.2, 1.0)  # Bonus for high coverage
            
            # Validation methods factor
            validation_factor = min(1.0 + (validation_methods - 1) * 0.1, 1.2)  # Bonus for multiple methods
            
            # Calculate assessment score
            assessment_score = (depth_factor + coverage_factor + validation_factor) / 3
            
            return max(0.4, min(1.2, assessment_score))
            
        except Exception:
            return 0.8  # Conservative default
    
    def _assess_configuration_analysis(self, configuration_analysis: Dict[str, Any]) -> float:
        """Assess configuration analysis completeness."""
        try:
            debug_analysis = configuration_analysis.get('debug_analysis', False)
            backup_analysis = configuration_analysis.get('backup_analysis', False)
            hardening_analysis = configuration_analysis.get('hardening_analysis', False)
            manifest_analysis = configuration_analysis.get('manifest_analysis', False)
            
            # Count completed analysis types
            completed_analyses = sum([debug_analysis, backup_analysis, hardening_analysis, manifest_analysis])
            total_analyses = 4
            
            # Base score from completion ratio
            completion_ratio = completed_analyses / total_analyses
            
            # Bonus for critical configurations
            critical_bonus = 0.0
            if debug_analysis and backup_analysis:
                critical_bonus = 0.1  # Bonus for covering critical production configs
            
            # Calculate configuration score
            config_score = completion_ratio + critical_bonus
            
            return max(0.3, min(1.1, config_score))
            
        except Exception:
            return 0.7  # Conservative default
    
    def _assess_validation_context(self, validation_context: Dict[str, Any]) -> float:
        """Assess validation environment context."""
        try:
            validation_method = validation_context.get('method', 'automated')
            environment = validation_context.get('environment', 'testing')
            tool_reliability = validation_context.get('tool_reliability', 0.8)
            
            # Method factor
            method_factor = self.context_factors['validation_method'].get(validation_method, 0.8)
            
            # Environment factor
            env_factor = self.context_factors['target_environment'].get(environment, 0.8)
            
            # Tool reliability factor
            tool_factor = min(tool_reliability + 0.1, 1.0)  # Slight bonus for high reliability
            
            # Calculate context score
            context_score = (method_factor + env_factor + tool_factor) / 3
            
            return max(0.4, min(1.0, context_score))
            
        except Exception:
            return 0.7  # Conservative default
    
    def _apply_production_adjustments(self, base_confidence: float, evidence: ProductionValidationEvidence) -> float:
        """Apply production-specific confidence adjustments."""
        try:
            adjusted_confidence = base_confidence
            
            # Debug configuration penalty
            if evidence.configuration_analysis.get('debug_enabled', False):
                adjusted_confidence -= self.config['debug_configuration_penalty']
            
            # Security hardening bonus
            if evidence.security_assessment.get('hardening_score', 0) > 0.8:
                adjusted_confidence += self.config['security_hardening_bonus']
            
            # Critical finding weight
            critical_findings = evidence.finding_analysis.get('critical_findings', 0)
            if critical_findings > 0:
                critical_factor = min(critical_findings * 0.1, 0.3)  # Max 30% adjustment
                adjusted_confidence *= (1 + critical_factor * self.config['critical_finding_weight'])
            
            return adjusted_confidence
            
        except Exception:
            return base_confidence
    
    def _assess_evidence_strength(self, evidence: Dict[str, Any]) -> float:
        """Assess strength of evidence for a finding."""
        evidence_sources = evidence.get('sources', [])
        evidence_quality = evidence.get('quality', 'medium')
        validation_count = len(evidence_sources)
        
        # Base factor from evidence quality
        quality_factors = {'low': 0.6, 'medium': 0.8, 'high': 1.0, 'very_high': 1.2}
        quality_factor = quality_factors.get(evidence_quality, 0.8)
        
        # Validation count bonus
        validation_bonus = min(validation_count * 0.1, 0.3)  # Max 30% bonus
        
        return min(quality_factor + validation_bonus, 1.3)
    
    def _assess_finding_context(self, finding: Dict[str, Any], apk_context: Dict[str, Any]) -> float:
        """Assess finding relevance in APK context."""
        finding_type = finding.get('type', '').lower()
        apk_type = apk_context.get('type', '').lower()
        
        # Context relevance factors
        relevance_factor = 1.0
        
        # Adjust based on APK type
        if 'banking' in apk_type and 'crypto' in finding_type:
            relevance_factor += 0.2  # Crypto issues more relevant in banking apps
        elif 'game' in apk_type and 'performance' in finding_type:
            relevance_factor -= 0.1  # Performance issues less critical in games
        
        return max(0.5, min(1.3, relevance_factor))

def calculate_production_confidence(evidence: Dict[str, Any]) -> float:
    """
    Convenience function for production confidence calculation.
    
    Args:
        evidence: Evidence dictionary for confidence calculation
        
    Returns:
        Confidence score (0.0-1.0)
    """
    calculator = ProductionAPKConfidenceCalculator()
    
    # Convert evidence dict to structured evidence
    validation_evidence = ProductionValidationEvidence(
        apk_characteristics=evidence.get('apk_characteristics', {}),
        finding_analysis=evidence.get('finding_analysis', {}),
        security_assessment=evidence.get('security_assessment', {}),
        configuration_analysis=evidence.get('configuration_analysis', {}),
        validation_context=evidence.get('validation_context', {})
    )
    
    return calculator.calculate_production_readiness_confidence(validation_evidence) 