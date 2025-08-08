"""
External Service Analysis Confidence Calculator

confidence calculation system for external service analysis findings.
Uses evidence-based scoring with pattern reliability data for cloud services,
credentials, network security, and configuration analysis.
"""

from typing import Dict, Any, List, Optional
import logging
from dataclasses import dataclass

from .data_structures import (
    ServiceType, CredentialType, SeverityLevel, AnalysisContext,
    ExternalServiceVulnerability, CredentialExposure, NetworkSecurityIssue,
    ConfigurationIssue
)

logger = logging.getLogger(__name__)

@dataclass
class ExternalServiceEvidence:
    """Evidence factors for external service analysis confidence calculation."""
    service_detection_quality: float = 0.0      # Quality of service pattern detection
    credential_validation: float = 0.0          # Credential exposure validation
    network_security_analysis: float = 0.0      # Network security assessment quality
    configuration_validation: float = 0.0       # Configuration analysis strength
    pattern_reliability: float = 0.0            # Pattern match reliability
    context_relevance: float = 0.0              # Context and implementation relevance
    cross_validation: float = 0.0               # Multiple validation sources

class ExternalServiceConfidenceCalculator:
    """confidence calculator for external service analysis."""
    
    def __init__(self):
        """Initialize confidence calculator with evidence weights and pattern reliability."""
        self.evidence_weights = {
            'service_detection_quality': 0.20,    # 20% - Service pattern detection quality
            'credential_validation': 0.20,        # 20% - Credential exposure validation
            'network_security_analysis': 0.15,    # 15% - Network security assessment
            'configuration_validation': 0.15,     # 15% - Configuration analysis
            'pattern_reliability': 0.15,          # 15% - Pattern match reliability
            'context_relevance': 0.10,            # 10% - Context relevance
            'cross_validation': 0.05              # 5% - Multiple validation sources
        }
        
        # Pattern reliability database with historical false positive rates
        self.pattern_reliability_db = {
            # Cloud service patterns
            'aws_s3_detection': {'reliability': 0.92, 'fp_rate': 0.08},
            'firebase_detection': {'reliability': 0.88, 'fp_rate': 0.12},
            'google_cloud_detection': {'reliability': 0.85, 'fp_rate': 0.15},
            'azure_detection': {'reliability': 0.87, 'fp_rate': 0.13},
            'dropbox_detection': {'reliability': 0.83, 'fp_rate': 0.17},
            'payment_gateway_detection': {'reliability': 0.95, 'fp_rate': 0.05},
            'social_media_detection': {'reliability': 0.80, 'fp_rate': 0.20},
            'analytics_detection': {'reliability': 0.75, 'fp_rate': 0.25},
            
            # Credential exposure patterns
            'api_key_exposure': {'reliability': 0.85, 'fp_rate': 0.15},
            'secret_key_exposure': {'reliability': 0.90, 'fp_rate': 0.10},
            'access_token_exposure': {'reliability': 0.88, 'fp_rate': 0.12},
            'password_exposure': {'reliability': 0.80, 'fp_rate': 0.20},
            'private_key_exposure': {'reliability': 0.95, 'fp_rate': 0.05},
            'connection_string_exposure': {'reliability': 0.92, 'fp_rate': 0.08},
            'jwt_token_exposure': {'reliability': 0.90, 'fp_rate': 0.10},
            'oauth_token_exposure': {'reliability': 0.85, 'fp_rate': 0.15},
            
            # Network security patterns
            'insecure_protocol': {'reliability': 0.95, 'fp_rate': 0.05},
            'weak_ssl_config': {'reliability': 0.90, 'fp_rate': 0.10},
            'certificate_bypass': {'reliability': 0.95, 'fp_rate': 0.05},
            'cleartext_traffic': {'reliability': 0.85, 'fp_rate': 0.15},
            'weak_cipher': {'reliability': 0.88, 'fp_rate': 0.12},
            'nsc_misconfiguration': {'reliability': 0.82, 'fp_rate': 0.18},
            
            # Configuration patterns
            'manifest_service_config': {'reliability': 0.80, 'fp_rate': 0.20},
            'resource_config_issue': {'reliability': 0.75, 'fp_rate': 0.25},
            'permission_misconfiguration': {'reliability': 0.85, 'fp_rate': 0.15}
        }
        
        # Context factor weights
        self.context_factors = {
            'production_indicators': 0.3,      # Production vs test environment indicators
            'file_type_relevance': 0.2,        # File type relevance to finding
            'implementation_depth': 0.2,       # Code vs config vs manifest
            'security_context': 0.2,           # Security-specific context
            'framework_context': 0.1           # Framework/library context
        }
    
    def calculate_service_confidence(self, 
                                   vulnerability: ExternalServiceVulnerability,
                                   evidence: Optional[ExternalServiceEvidence] = None,
                                   context: Optional[AnalysisContext] = None) -> float:
        """
        Calculate confidence score for external service vulnerability.
        
        Args:
            vulnerability: External service vulnerability to score
            evidence: Evidence factors (auto-generated if not provided)
            context: Analysis context information
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        try:
            # Extract evidence if not provided
            if evidence is None:
                evidence = self._extract_service_evidence(vulnerability, context)
            
            # Calculate evidence-based score
            evidence_score = self._calculate_evidence_score(evidence)
            
            # Apply pattern reliability adjustment
            pattern_adjustment = self._get_pattern_reliability_adjustment(vulnerability)
            
            # Apply context adjustments
            context_adjustment = self._calculate_context_adjustment(vulnerability, context)
            
            # Calculate base confidence
            base_confidence = evidence_score * (1.0 + pattern_adjustment + context_adjustment)
            
            # Apply calibration
            calibrated_confidence = self._apply_calibration(base_confidence, vulnerability, context)
            
            # Ensure confidence is within bounds
            final_confidence = max(0.1, min(1.0, calibrated_confidence))
            
            logger.debug(f"Confidence calculation - Evidence: {evidence_score:.3f}, "
                        f"Pattern: {pattern_adjustment:.3f}, Context: {context_adjustment:.3f}, "
                        f"Final: {final_confidence:.3f}")
            
            return final_confidence
            
        except Exception as e:
            logger.error(f"Error calculating service confidence: {e}")
            return 0.5  # Return moderate confidence on error
    
    def calculate_credential_confidence(self,
                                      credential: CredentialExposure,
                                      context: Optional[AnalysisContext] = None) -> float:
        """Calculate confidence score for credential exposure."""
        try:
            # Base confidence from credential type
            base_confidence = self._get_credential_base_confidence(credential.credential_type)
            
            # Pattern reliability adjustment
            pattern_key = f"{credential.credential_type.value}_exposure"
            pattern_reliability = self.pattern_reliability_db.get(pattern_key, {}).get('reliability', 0.8)
            
            # Context adjustments
            context_adjustment = 0.0
            if context:
                # File type adjustments
                if context.file_type in ['properties', 'config', 'xml']:
                    context_adjustment += 0.1
                elif context.file_type in ['test', 'spec']:
                    context_adjustment -= 0.2
                
                # Analysis depth adjustments
                if context.analysis_depth == 'deep':
                    context_adjustment += 0.05
            
            # Check for test/demo indicators in context
            if credential.context and credential.context.lower():
                test_indicators = ['test', 'demo', 'example', 'sample', 'fake', 'dummy']
                if any(indicator in credential.context.lower() for indicator in test_indicators):
                    context_adjustment -= 0.3
            
            # Calculate final confidence
            final_confidence = base_confidence * pattern_reliability + context_adjustment
            
            return max(0.1, min(1.0, final_confidence))
            
        except Exception as e:
            logger.error(f"Error calculating credential confidence: {e}")
            return 0.7
    
    def calculate_network_security_confidence(self,
                                            issue: NetworkSecurityIssue,
                                            context: Optional[AnalysisContext] = None) -> float:
        """Calculate confidence score for network security issue."""
        try:
            # Base confidence from issue type
            base_confidence = self._get_network_issue_base_confidence(issue.issue_type)
            
            # Pattern reliability adjustment
            pattern_reliability = self.pattern_reliability_db.get(issue.issue_type, {}).get('reliability', 0.8)
            
            # Severity adjustment
            severity_adjustment = {
                SeverityLevel.CRITICAL: 0.1,
                SeverityLevel.HIGH: 0.05,
                SeverityLevel.MEDIUM: 0.0,
                SeverityLevel.LOW: -0.05,
                SeverityLevel.INFO: -0.1
            }.get(issue.severity, 0.0)
            
            # Context adjustments
            context_adjustment = 0.0
            if context and context.file_type == 'xml':  # NSC files
                context_adjustment += 0.05
            
            final_confidence = base_confidence * pattern_reliability + severity_adjustment + context_adjustment
            
            return max(0.1, min(1.0, final_confidence))
            
        except Exception as e:
            logger.error(f"Error calculating network security confidence: {e}")
            return 0.8
    
    def _extract_service_evidence(self, vulnerability: ExternalServiceVulnerability,
                                context: Optional[AnalysisContext] = None) -> ExternalServiceEvidence:
        """Extract evidence factors from vulnerability data."""
        evidence = ExternalServiceEvidence()
        
        # Service detection quality
        service_patterns = {
            ServiceType.AWS_S3: 0.92,
            ServiceType.FIREBASE: 0.88,
            ServiceType.GOOGLE_CLOUD: 0.85,
            ServiceType.AZURE: 0.87,
            ServiceType.PAYMENT_GATEWAY: 0.95,
            ServiceType.SOCIAL_MEDIA: 0.80,
            ServiceType.ANALYTICS: 0.75,
        }
        evidence.service_detection_quality = service_patterns.get(vulnerability.service_type, 0.75)
        
        # Pattern reliability
        if vulnerability.evidence.get('pattern'):
            pattern_key = f"{vulnerability.service_type.value}_detection"
            evidence.pattern_reliability = self.pattern_reliability_db.get(
                pattern_key, {}).get('reliability', 0.8)
        
        # Context relevance
        if context:
            if context.file_type in ['java', 'kotlin']:
                evidence.context_relevance = 0.9
            elif context.file_type in ['xml', 'json']:
                evidence.context_relevance = 0.7
            else:
                evidence.context_relevance = 0.5
            
            # Cross-validation
            evidence.cross_validation = min(1.0, context.cross_references * 0.2)
        
        # Configuration validation (from evidence)
        if vulnerability.evidence.get('risk_factors'):
            evidence.configuration_validation = 0.8
        
        return evidence
    
    def _calculate_evidence_score(self, evidence: ExternalServiceEvidence) -> float:
        """Calculate weighted evidence score."""
        total_score = (
            evidence.service_detection_quality * self.evidence_weights['service_detection_quality'] +
            evidence.credential_validation * self.evidence_weights['credential_validation'] +
            evidence.network_security_analysis * self.evidence_weights['network_security_analysis'] +
            evidence.configuration_validation * self.evidence_weights['configuration_validation'] +
            evidence.pattern_reliability * self.evidence_weights['pattern_reliability'] +
            evidence.context_relevance * self.evidence_weights['context_relevance'] +
            evidence.cross_validation * self.evidence_weights['cross_validation']
        )
        
        return total_score
    
    def _get_pattern_reliability_adjustment(self, vulnerability: ExternalServiceVulnerability) -> float:
        """Get pattern reliability adjustment factor."""
        pattern_key = f"{vulnerability.service_type.value}_detection"
        pattern_data = self.pattern_reliability_db.get(pattern_key, {})
        
        reliability = pattern_data.get('reliability', 0.8)
        fp_rate = pattern_data.get('fp_rate', 0.2)
        
        # Convert reliability to adjustment factor
        return (reliability - 0.8) * 0.5  # Normalize around 0.8 baseline
    
    def _calculate_context_adjustment(self, vulnerability: ExternalServiceVulnerability,
                                   context: Optional[AnalysisContext] = None) -> float:
        """Calculate context-based confidence adjustments."""
        if not context:
            return 0.0
        
        adjustment = 0.0
        
        # File type adjustments
        file_type_adjustments = {
            'java': 0.1, 'kotlin': 0.1, 'xml': 0.05, 'json': 0.03,
            'properties': 0.05, 'config': 0.05, 'test': -0.1, 'spec': -0.1
        }
        adjustment += file_type_adjustments.get(context.file_type, 0.0)
        
        # Analysis depth adjustments
        depth_adjustments = {'basic': -0.05, 'medium': 0.0, 'deep': 0.05}
        adjustment += depth_adjustments.get(context.analysis_depth, 0.0)
        
        # Validation sources adjustment
        if len(context.validation_sources) > 1:
            adjustment += min(0.1, len(context.validation_sources) * 0.03)
        
        return adjustment
    
    def _apply_calibration(self, confidence: float, vulnerability: ExternalServiceVulnerability,
                         context: Optional[AnalysisContext] = None) -> float:
        """Apply calibration to confidence score."""
        # Severity-based calibration
        severity_calibration = {
            SeverityLevel.CRITICAL: 1.05,
            SeverityLevel.HIGH: 1.02,
            SeverityLevel.MEDIUM: 1.0,
            SeverityLevel.LOW: 0.98,
            SeverityLevel.INFO: 0.95
        }
        
        calibration_factor = severity_calibration.get(vulnerability.severity, 1.0)
        
        # Service type calibration
        service_calibration = {
            ServiceType.PAYMENT_GATEWAY: 1.05,  # Higher stakes
            ServiceType.AWS_S3: 1.02,
            ServiceType.FIREBASE: 1.02,
            ServiceType.ANALYTICS: 0.98,        # Lower stakes
            ServiceType.ADVERTISING: 0.95
        }
        
        calibration_factor *= service_calibration.get(vulnerability.service_type, 1.0)
        
        return confidence * calibration_factor
    
    def _get_credential_base_confidence(self, cred_type: CredentialType) -> float:
        """Get base confidence for credential type."""
        base_confidences = {
            CredentialType.PRIVATE_KEY: 0.95,
            CredentialType.SECRET_KEY: 0.90,
            CredentialType.CONNECTION_STRING: 0.92,
            CredentialType.API_KEY: 0.85,
            CredentialType.ACCESS_TOKEN: 0.88,
            CredentialType.JWT_TOKEN: 0.90,
            CredentialType.OAUTH_TOKEN: 0.85,
            CredentialType.PASSWORD: 0.80,
            CredentialType.CERTIFICATE: 0.85
        }
        return base_confidences.get(cred_type, 0.75)
    
    def _get_network_issue_base_confidence(self, issue_type: str) -> float:
        """Get base confidence for network security issue type."""
        base_confidences = {
            'certificate_validation_bypass': 0.95,
            'insecure_protocol': 0.90,
            'weak_ssl_config': 0.88,
            'cleartext_traffic_allowed': 0.85,
            'weak_cipher': 0.85,
            'nsc_cleartext_permitted': 0.90,
            'nsc_system_ca_override': 0.85,
            'nsc_user_ca_trusted': 0.80,
            'nsc_expired_pin': 0.95,
            'nsc_debug_overrides': 0.85
        }
        return base_confidences.get(issue_type, 0.75)
    
    def get_confidence_factors(self, vulnerability: ExternalServiceVulnerability,
                             context: Optional[AnalysisContext] = None) -> Dict[str, float]:
        """Get detailed confidence factors for analysis."""
        evidence = self._extract_service_evidence(vulnerability, context)
        
        return {
            'service_detection_quality': evidence.service_detection_quality,
            'credential_validation': evidence.credential_validation,
            'network_security_analysis': evidence.network_security_analysis,
            'configuration_validation': evidence.configuration_validation,
            'pattern_reliability': evidence.pattern_reliability,
            'context_relevance': evidence.context_relevance,
            'cross_validation': evidence.cross_validation,
            'evidence_score': self._calculate_evidence_score(evidence),
            'pattern_adjustment': self._get_pattern_reliability_adjustment(vulnerability),
            'context_adjustment': self._calculate_context_adjustment(vulnerability, context)
        } 