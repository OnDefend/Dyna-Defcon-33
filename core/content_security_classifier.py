#!/usr/bin/env python3
"""
Content Security & Classification Module for AODS
================================================

This module provides comprehensive content security and classification capabilities
for decoded Base64 content in security reports. It implements safe handling of
potentially sensitive information with configurable redaction options and
security warnings for high-risk content.

Features:
- Advanced content type classification with confidence scoring
- Configurable redaction policies for sensitive data protection
- Security risk assessment with immediate action recommendations
- Safe content handling with sanitization capabilities
- Compliance-ready redaction for regulatory requirements
- Context-aware security warnings and alerts

"""

import hashlib
import json
import logging
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityClassificationLevel(Enum):
    """Security classification levels for content."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    TOP_SECRET = "TOP_SECRET"

class RedactionPolicy(Enum):
    """Redaction policy options for sensitive content."""
    NONE = "NONE"
    PARTIAL = "PARTIAL"
    FULL = "FULL"
    HASH_REPLACEMENT = "HASH_REPLACEMENT"
    PLACEHOLDER_REPLACEMENT = "PLACEHOLDER_REPLACEMENT"

class ContentSensitivityLevel(Enum):
    """Content sensitivity levels for classification."""
    MINIMAL = 1
    LOW = 2
    MODERATE = 3
    HIGH = 4
    CRITICAL = 5

@dataclass
class SecurityClassificationResult:
    """Result of content security classification."""
    
    content_type: str
    sensitivity_level: ContentSensitivityLevel
    security_classification: SecurityClassificationLevel
    confidence_score: float
    risk_indicators: List[str]
    redaction_recommended: bool
    redaction_policy: RedactionPolicy
    security_warnings: List[str]
    compliance_flags: List[str]
    immediate_action_required: bool
    classification_metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class RedactionConfiguration:
    """Configuration for content redaction policies."""
    
    enable_redaction: bool = True
    default_redaction_policy: RedactionPolicy = RedactionPolicy.PARTIAL
    preserve_content_structure: bool = True
    redaction_placeholder: str = "[REDACTED]"
    hash_algorithm: str = "sha256"
    partial_redaction_percentage: float = 0.7
    sensitive_pattern_redaction: Dict[str, RedactionPolicy] = field(default_factory=dict)
    compliance_mode: bool = False

@dataclass
class SecurityConfiguration:
    """Configuration for security classification behavior."""
    
    enable_security_warnings: bool = True
    enable_compliance_checking: bool = True
    minimum_confidence_threshold: float = 0.6
    escalation_sensitivity_threshold: ContentSensitivityLevel = ContentSensitivityLevel.HIGH
    enable_immediate_action_alerts: bool = True
    security_context_analysis: bool = True
    enable_content_sanitization: bool = True

class ContentSecurityClassifier:
    """
    Advanced Content Security & Classification System.
    
    This class provides comprehensive security classification and safe handling
    of decoded content with configurable redaction policies and security controls.
    """
    
    def __init__(self, 
                 redaction_config: Optional[RedactionConfiguration] = None,
                 security_config: Optional[SecurityConfiguration] = None):
        """
        Initialize the Content Security Classifier.
        
        Args:
            redaction_config: Configuration for redaction policies
            security_config: Configuration for security classification
        """
        self.redaction_config = redaction_config or RedactionConfiguration()
        self.security_config = security_config or SecurityConfiguration()
        
        # Initialize classification patterns with enhanced security focus
        self.security_classification_patterns = self._initialize_security_patterns()
        
        # Initialize compliance patterns for regulatory requirements
        self.compliance_patterns = self._initialize_compliance_patterns()
        
        # Initialize redaction patterns for sensitive data
        self.redaction_patterns = self._initialize_redaction_patterns()
        
        # Classification statistics
        self.classification_statistics = {
            'total_classifications': 0,
            'high_risk_content_detected': 0,
            'redactions_applied': 0,
            'security_warnings_generated': 0,
            'compliance_flags_raised': 0,
            'immediate_actions_required': 0
        }
        
        logger.info("Content Security Classifier initialized with comprehensive security controls")
    
    def _initialize_security_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize security classification patterns."""
        return {
            'authentication_credentials': {
                'patterns': [
                    r'(?i)password\s*[:=]\s*["\']?([^"\'\s]{4,})["\']?',
                    r'(?i)username\s*[:=]\s*["\']?([^"\'\s]{3,})["\']?',
                    r'(?i)login\s*[:=]\s*["\']?([^"\'\s]{3,})["\']?',
                    r'(?i)auth\s*[:=]\s*["\']?([^"\'\s]{8,})["\']?',
                    r'(?i)credential[s]?\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?',
                    r'(?i)passwd\s*[:=]\s*["\']?([^"\'\s]{4,})["\']?',
                    r'(?i)pwd\s*[:=]\s*["\']?([^"\'\s]{4,})["\']?',
                    r'(?i)user.*pass\s*[:=]\s*["\']?([^"\'\s]{4,})["\']?',
                    r'(?i)admin.*pass\s*[:=]\s*["\']?([^"\'\s]{4,})["\']?'
                ],
                'sensitivity_level': ContentSensitivityLevel.CRITICAL,
                'security_classification': SecurityClassificationLevel.RESTRICTED,
                'confidence_weight': 0.95,
                'redaction_policy': RedactionPolicy.FULL,
                'immediate_action': True,
                'compliance_flags': ['PCI_DSS', 'GDPR', 'SOX']
            },
            'api_authentication_keys': {
                'patterns': [
                    r'(?i)api[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9+/]{16,})["\']?',
                    r'(?i)access[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9+/]{16,})["\']?',
                    r'(?i)secret[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9+/]{16,})["\']?',
                    r'(?i)private[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9+/]{16,})["\']?',
                    r'AKIA[0-9A-Z]{16}',  # AWS Access Key
                    r'AIza[0-9A-Za-z_-]{35}',  # Google API Key
                    r'sk-[a-zA-Z0-9]{48}',  # OpenAI API Key
                    r'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}',  # Slack Bot Token
                    r'ghp_[a-zA-Z0-9]{36}',  # GitHub Personal Access Token
                    r'gho_[a-zA-Z0-9]{36}',  # GitHub OAuth Token
                ],
                'sensitivity_level': ContentSensitivityLevel.CRITICAL,
                'security_classification': SecurityClassificationLevel.RESTRICTED,
                'confidence_weight': 0.98,
                'redaction_policy': RedactionPolicy.HASH_REPLACEMENT,
                'immediate_action': True,
                'compliance_flags': ['SOC2', 'ISO27001', 'NIST']
            },
            'digital_certificates': {
                'patterns': [
                    r'-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----',
                    r'(?i)certificate\s*[:=]\s*["\']?([A-Za-z0-9+/=]{100,})["\']?',
                    r'(?i)private[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9+/=]{100,})["\']?',
                    r'(?i)public[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9+/=]{100,})["\']?',
                    r'(?i)rsa[_-]?private[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9+/=]{100,})["\']?',
                ],
                'sensitivity_level': ContentSensitivityLevel.CRITICAL,
                'security_classification': SecurityClassificationLevel.RESTRICTED,
                'confidence_weight': 0.97,
                'redaction_policy': RedactionPolicy.FULL,
                'immediate_action': True,
                'compliance_flags': ['PKI', 'TLS', 'SSL']
            },
            'network_endpoints': {
                'patterns': [
                    r'https?://[^\s<>"\']+',
                    r'ftp://[^\s<>"\']+',
                    r'(?i)endpoint\s*[:=]\s*["\']?([^\s<>"\']+)["\']?',
                    r'(?i)server\s*[:=]\s*["\']?([^\s<>"\']+)["\']?',
                    r'(?i)host\s*[:=]\s*["\']?([^\s<>"\']+)["\']?',
                    r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\']*)?',
                    r'(?i)url\s*[:=]\s*["\']?([^\s<>"\']+)["\']?',
                ],
                'sensitivity_level': ContentSensitivityLevel.MODERATE,
                'security_classification': SecurityClassificationLevel.CONFIDENTIAL,
                'confidence_weight': 0.8,
                'redaction_policy': RedactionPolicy.PARTIAL,
                'immediate_action': False,
                'compliance_flags': ['NETWORK_SECURITY']
            },
            'structured_configuration_data': {
                'patterns': [
                    r'(?i)config\s*[:=]\s*["\']?([^"\'\s]{10,})["\']?',
                    r'(?i)setting[s]?\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?',
                    r'(?i)property\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?',
                    r'(?i)option[s]?\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?',
                    r'(?i)param[s]?\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?',
                    r'\{[^}]{20,}\}',  # JSON-like configuration
                    r'<[^>]+>[^<]{10,}</[^>]+>',  # XML-like configuration
                ],
                'sensitivity_level': ContentSensitivityLevel.LOW,
                'security_classification': SecurityClassificationLevel.INTERNAL,
                'confidence_weight': 0.6,
                'redaction_policy': RedactionPolicy.NONE,
                'immediate_action': False,
                'compliance_flags': []
            },
            'application_secrets': {
                'patterns': [
                    r'(?i)secret\s*[:=]\s*["\']?([A-Za-z0-9+/]{16,})["\']?',
                    r'(?i)token\s*[:=]\s*["\']?([A-Za-z0-9+/._-]{20,})["\']?',
                    r'(?i)bearer\s+([A-Za-z0-9+/._-]{20,})',
                    r'(?i)jwt\s*[:=]?\s*["\']?([A-Za-z0-9+/._-]{50,})["\']?',
                    r'[A-Za-z0-9]{32,64}',  # Long hex/base64 strings (potential secrets)
                    r'(?i)session[_-]?id\s*[:=]\s*["\']?([A-Za-z0-9+/]{16,})["\']?',
                ],
                'sensitivity_level': ContentSensitivityLevel.HIGH,
                'security_classification': SecurityClassificationLevel.CONFIDENTIAL,
                'confidence_weight': 0.85,
                'redaction_policy': RedactionPolicy.HASH_REPLACEMENT,
                'immediate_action': True,
                'compliance_flags': ['SESSION_MANAGEMENT', 'TOKEN_SECURITY']
            },
            'application_flags': {
                'patterns': [
                    r'(?i)flag\{[^}]+\}',
                    r'(?i)FLAG\{[^}]+\}',
                    r'(?i)ctf\{[^}]+\}',
                    r'(?i)[Ff]lag[_-]?\d+\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                    r'(?i)[Ff]lag[_-]?[a-zA-Z0-9]+\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                    r'\{[^}]*flag[^}]*\}',
                ],
                'sensitivity_level': ContentSensitivityLevel.HIGH,
                'security_classification': SecurityClassificationLevel.CONFIDENTIAL,
                'confidence_weight': 0.9,
                'redaction_policy': RedactionPolicy.PARTIAL,
                'immediate_action': False,
                'compliance_flags': ['CTF', 'CHALLENGE']
            }
        }
    
    def _initialize_compliance_patterns(self) -> Dict[str, List[str]]:
        """Initialize compliance-specific patterns."""
        return {
            'PCI_DSS': [
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card numbers
                r'(?i)card[_-]?number',
                r'(?i)cvv',
                r'(?i)expir[ey]'
            ],
            'GDPR': [
                r'(?i)personal[_-]?data',
                r'(?i)pii',
                r'(?i)personally[_-]?identifiable',
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  # Email addresses
            ],
            'HIPAA': [
                r'(?i)health[_-]?record',
                r'(?i)medical[_-]?data',
                r'(?i)patient[_-]?info'
            ],
            'SOX': [
                r'(?i)financial[_-]?data',
                r'(?i)audit[_-]?trail',
                r'(?i)accounting[_-]?record'
            ]
        }
    
    def _initialize_redaction_patterns(self) -> Dict[str, str]:
        """Initialize patterns for content redaction."""
        return {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'mac_address': r'\b[0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}\b'
        }
    
    def classify_content_security(self, content: str, context: Optional[Dict[str, Any]] = None) -> SecurityClassificationResult:
        """
        Perform comprehensive security classification of content.
        
        Args:
            content: Content to classify
            context: Optional context information for enhanced classification
            
        Returns:
            SecurityClassificationResult with comprehensive security analysis
        """
        self.classification_statistics['total_classifications'] += 1
        
        if not content or not content.strip():
            return self._create_minimal_classification_result()
        
        # Perform pattern-based classification
        classification_results = self._analyze_security_patterns(content)
        
        # Determine best classification match
        best_classification = self._determine_best_classification(classification_results)
        
        # Perform compliance analysis
        compliance_flags = self._analyze_compliance_requirements(content)
        
        # Generate security warnings
        security_warnings = self._generate_security_warnings(content, best_classification)
        
        # Determine redaction policy
        redaction_policy = self._determine_redaction_policy(best_classification)
        
        # Create comprehensive result
        result = SecurityClassificationResult(
            content_type=best_classification['content_type'],
            sensitivity_level=best_classification['sensitivity_level'],
            security_classification=best_classification['security_classification'],
            confidence_score=best_classification['confidence_score'],
            risk_indicators=best_classification['risk_indicators'],
            redaction_recommended=best_classification['redaction_recommended'],
            redaction_policy=redaction_policy,
            security_warnings=security_warnings,
            compliance_flags=compliance_flags,
            immediate_action_required=best_classification['immediate_action_required'],
            classification_metadata={
                'classification_timestamp': datetime.now().isoformat(),
                'content_length': len(content),
                'context': context or {},
                'classifier_version': '1.0.0'
            }
        )
        
        # Update statistics
        self._update_classification_statistics(result)
        
        logger.info(f"Content classified as {result.content_type} with {result.sensitivity_level.name} sensitivity")
        
        return result
    
    def apply_content_redaction(self, content: str, classification_result: SecurityClassificationResult) -> str:
        """
        Apply redaction to content based on classification result.
        
        Args:
            content: Original content to redact
            classification_result: Security classification result
            
        Returns:
            Redacted content string
        """
        if not self.redaction_config.enable_redaction:
            return content
        
        if classification_result.redaction_policy == RedactionPolicy.NONE:
            return content
        
        redacted_content = content
        
        if classification_result.redaction_policy == RedactionPolicy.FULL:
            redacted_content = self._apply_full_redaction(content)
        elif classification_result.redaction_policy == RedactionPolicy.PARTIAL:
            redacted_content = self._apply_partial_redaction(content)
        elif classification_result.redaction_policy == RedactionPolicy.HASH_REPLACEMENT:
            redacted_content = self._apply_hash_replacement(content)
        elif classification_result.redaction_policy == RedactionPolicy.PLACEHOLDER_REPLACEMENT:
            redacted_content = self._apply_placeholder_replacement(content, classification_result.content_type)
        
        # Apply pattern-specific redaction
        redacted_content = self._apply_pattern_redaction(redacted_content)
        
        self.classification_statistics['redactions_applied'] += 1
        
        return redacted_content
    
    def generate_security_report(self, content: str, classification_result: SecurityClassificationResult) -> Dict[str, Any]:
        """
        Generate comprehensive security report for classified content.
        
        Args:
            content: Original content
            classification_result: Security classification result
            
        Returns:
            Comprehensive security report dictionary
        """
        return {
            'security_analysis': {
                'content_type': classification_result.content_type,
                'sensitivity_level': classification_result.sensitivity_level.name,
                'security_classification': classification_result.security_classification.value,
                'confidence_score': classification_result.confidence_score,
                'risk_assessment': {
                    'risk_indicators': classification_result.risk_indicators,
                    'immediate_action_required': classification_result.immediate_action_required,
                    'security_warnings': classification_result.security_warnings
                }
            },
            'redaction_analysis': {
                'redaction_recommended': classification_result.redaction_recommended,
                'redaction_policy': classification_result.redaction_policy.value,
                'redacted_content': self.apply_content_redaction(content, classification_result) if classification_result.redaction_recommended else None
            },
            'compliance_analysis': {
                'compliance_flags': classification_result.compliance_flags,
                'regulatory_requirements': self._get_regulatory_requirements(classification_result.compliance_flags)
            },
            'recommendations': self._generate_security_recommendations(classification_result),
            'metadata': classification_result.classification_metadata
        }
    
    def _analyze_security_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Analyze content against security patterns."""
        results = []
        
        for content_type, pattern_config in self.security_classification_patterns.items():
            matches = []
            confidence_score = 0.0
            
            for pattern in pattern_config['patterns']:
                pattern_matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if pattern_matches:
                    matches.extend(pattern_matches)
                    # Calculate confidence based on match quality and quantity
                    match_confidence = min(len(pattern_matches) * 0.2, 1.0)
                    confidence_score = max(confidence_score, match_confidence)
            
            if matches:
                final_confidence = confidence_score * pattern_config['confidence_weight']
                
                results.append({
                    'content_type': content_type,
                    'sensitivity_level': pattern_config['sensitivity_level'],
                    'security_classification': pattern_config['security_classification'],
                    'confidence_score': final_confidence,
                    'risk_indicators': matches[:5],  # Limit indicators
                    'redaction_recommended': pattern_config['redaction_policy'] != RedactionPolicy.NONE,
                    'immediate_action_required': pattern_config['immediate_action'],
                    'compliance_flags': pattern_config['compliance_flags']
                })
        
        return results
    
    def _determine_best_classification(self, classification_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Determine the best classification from multiple results."""
        if not classification_results:
            return {
                'content_type': 'unknown',
                'sensitivity_level': ContentSensitivityLevel.MINIMAL,
                'security_classification': SecurityClassificationLevel.PUBLIC,
                'confidence_score': 0.0,
                'risk_indicators': [],
                'redaction_recommended': False,
                'immediate_action_required': False,
                'compliance_flags': []
            }
        
        # Sort by confidence score and sensitivity level
        sorted_results = sorted(
            classification_results,
            key=lambda x: (x['confidence_score'], x['sensitivity_level'].value),
            reverse=True
        )
        
        return sorted_results[0]
    
    def _analyze_compliance_requirements(self, content: str) -> List[str]:
        """Analyze content for compliance requirements."""
        compliance_flags = []
        
        for compliance_type, patterns in self.compliance_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    compliance_flags.append(compliance_type)
                    break
        
        return list(set(compliance_flags))
    
    def _generate_security_warnings(self, content: str, classification: Dict[str, Any]) -> List[str]:
        """Generate security warnings based on classification."""
        warnings = []
        
        if not self.security_config.enable_security_warnings:
            return warnings
        
        if classification['sensitivity_level'].value >= ContentSensitivityLevel.HIGH.value:
            warnings.append("High sensitivity content detected - review access controls")
        
        if classification['immediate_action_required']:
            warnings.append("Immediate security action required - potential credential exposure")
        
        if classification['confidence_score'] >= 0.9:
            warnings.append("High confidence security classification - validate findings")
        
        if len(classification['risk_indicators']) > 3:
            warnings.append("Multiple security risk indicators detected")
        
        return warnings
    
    def _determine_redaction_policy(self, classification: Dict[str, Any]) -> RedactionPolicy:
        """Determine appropriate redaction policy."""
        if not self.redaction_config.enable_redaction:
            return RedactionPolicy.NONE
        
        if classification['sensitivity_level'].value >= ContentSensitivityLevel.CRITICAL.value:
            return RedactionPolicy.FULL
        elif classification['sensitivity_level'].value >= ContentSensitivityLevel.HIGH.value:
            return RedactionPolicy.HASH_REPLACEMENT
        elif classification['sensitivity_level'].value >= ContentSensitivityLevel.MODERATE.value:
            return RedactionPolicy.PARTIAL
        else:
            return RedactionPolicy.NONE
    
    def _apply_full_redaction(self, content: str) -> str:
        """Apply full redaction to content."""
        if self.redaction_config.preserve_content_structure:
            # Preserve structure but redact all content
            redacted = re.sub(r'[A-Za-z0-9]', 'X', content)
            return f"{self.redaction_config.redaction_placeholder} ({len(content)} chars)"
        else:
            return self.redaction_config.redaction_placeholder
    
    def _apply_partial_redaction(self, content: str) -> str:
        """Apply partial redaction to content."""
        if len(content) <= 10:
            return self.redaction_config.redaction_placeholder
        
        redaction_length = int(len(content) * self.redaction_config.partial_redaction_percentage)
        visible_length = len(content) - redaction_length
        
        if visible_length < 3:
            visible_length = 3
            redaction_length = len(content) - visible_length
        
        visible_part = content[:visible_length//2] + content[-(visible_length//2):]
        redacted_part = 'X' * redaction_length
        
        return f"{content[:visible_length//2]}...{redacted_part}...{content[-(visible_length//2):]}"
    
    def _apply_hash_replacement(self, content: str) -> str:
        """Apply hash replacement redaction."""
        hash_obj = hashlib.new(self.redaction_config.hash_algorithm)
        hash_obj.update(content.encode('utf-8'))
        content_hash = hash_obj.hexdigest()[:16]  # Truncate for readability
        
        return f"{self.redaction_config.redaction_placeholder}_HASH_{content_hash}"
    
    def _apply_placeholder_replacement(self, content: str, content_type: str) -> str:
        """Apply content-type specific placeholder replacement."""
        placeholders = {
            'authentication_credentials': '[CREDENTIAL_REDACTED]',
            'api_authentication_keys': '[API_KEY_REDACTED]',
            'digital_certificates': '[CERTIFICATE_REDACTED]',
            'network_endpoints': '[ENDPOINT_REDACTED]',
            'application_secrets': '[SECRET_REDACTED]',
            'application_flags': '[FLAG_REDACTED]'
        }
        
        return placeholders.get(content_type, self.redaction_config.redaction_placeholder)
    
    def _apply_pattern_redaction(self, content: str) -> str:
        """Apply pattern-specific redaction."""
        redacted_content = content
        
        for pattern_name, pattern in self.redaction_patterns.items():
            if pattern_name in ['email', 'phone', 'ssn', 'credit_card']:
                redacted_content = re.sub(pattern, f'[{pattern_name.upper()}_REDACTED]', redacted_content)
        
        return redacted_content
    
    def _get_regulatory_requirements(self, compliance_flags: List[str]) -> List[str]:
        """Get regulatory requirements based on compliance flags."""
        requirements = []
        
        for flag in compliance_flags:
            if flag == 'PCI_DSS':
                requirements.append('PCI DSS compliance required for payment card data')
            elif flag == 'GDPR':
                requirements.append('GDPR compliance required for personal data')
            elif flag == 'HIPAA':
                requirements.append('HIPAA compliance required for health information')
            elif flag == 'SOX':
                requirements.append('SOX compliance required for financial data')
        
        return requirements
    
    def _generate_security_recommendations(self, classification_result: SecurityClassificationResult) -> List[str]:
        """Generate security recommendations based on classification."""
        recommendations = []
        
        if classification_result.immediate_action_required:
            recommendations.append('Immediately rotate or revoke exposed credentials')
            recommendations.append('Review access logs for potential unauthorized access')
        
        if classification_result.sensitivity_level.value >= ContentSensitivityLevel.HIGH.value:
            recommendations.append('Implement additional access controls for sensitive content')
            recommendations.append('Enable audit logging for content access')
        
        if classification_result.redaction_recommended:
            recommendations.append('Apply appropriate redaction before sharing reports')
            recommendations.append('Implement data loss prevention (DLP) controls')
        
        if classification_result.compliance_flags:
            recommendations.append('Ensure compliance with applicable regulatory requirements')
            recommendations.append('Document security controls for audit purposes')
        
        return recommendations
    
    def _create_minimal_classification_result(self) -> SecurityClassificationResult:
        """Create minimal classification result for empty content."""
        return SecurityClassificationResult(
            content_type='empty',
            sensitivity_level=ContentSensitivityLevel.MINIMAL,
            security_classification=SecurityClassificationLevel.PUBLIC,
            confidence_score=0.0,
            risk_indicators=[],
            redaction_recommended=False,
            redaction_policy=RedactionPolicy.NONE,
            security_warnings=[],
            compliance_flags=[],
            immediate_action_required=False
        )
    
    def _update_classification_statistics(self, result: SecurityClassificationResult) -> None:
        """Update classification statistics."""
        if result.sensitivity_level.value >= ContentSensitivityLevel.HIGH.value:
            self.classification_statistics['high_risk_content_detected'] += 1
        
        if result.security_warnings:
            self.classification_statistics['security_warnings_generated'] += 1
        
        if result.compliance_flags:
            self.classification_statistics['compliance_flags_raised'] += 1
        
        if result.immediate_action_required:
            self.classification_statistics['immediate_actions_required'] += 1
    
    def get_classification_statistics(self) -> Dict[str, Any]:
        """Get comprehensive classification statistics."""
        return {
            'classification_statistics': self.classification_statistics.copy(),
            'configuration_summary': {
                'redaction_enabled': self.redaction_config.enable_redaction,
                'security_warnings_enabled': self.security_config.enable_security_warnings,
                'compliance_checking_enabled': self.security_config.enable_compliance_checking,
                'minimum_confidence_threshold': self.security_config.minimum_confidence_threshold
            },
            'supported_content_types': list(self.security_classification_patterns.keys()),
            'supported_compliance_frameworks': list(self.compliance_patterns.keys())
        }

def main():
    """Main function for testing Content Security Classifier."""
    # Initialize classifier with default configuration
    classifier = ContentSecurityClassifier()
    
    # Test cases for different content types
    test_cases = [
        "password=admin123",
        "api_key=AIzaSyDxVlAaGH-7OLlNjkqJ6MjHjK8qY2QwXyZ",
        "https://api.example.com/v1/users",
        '{"username": "admin", "password": "secret123"}',
        "flag{this_is_a_test_flag}",
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC..."
    ]
    
    print("🔒 Content Security & Classification Test")
    print("=" * 50)
    
    for i, test_content in enumerate(test_cases, 1):
        print(f"\n🧪 Test Case {i}: {test_content[:50]}...")
        
        # Classify content
        result = classifier.classify_content_security(test_content)
        
        print(f"   Content Type: {result.content_type}")
        print(f"   Sensitivity: {result.sensitivity_level.name}")
        print(f"   Classification: {result.security_classification.value}")
        print(f"   Confidence: {result.confidence_score:.2f}")
        print(f"   Redaction Policy: {result.redaction_policy.value}")
        print(f"   Immediate Action: {result.immediate_action_required}")
        
        if result.redaction_recommended:
            redacted = classifier.apply_content_redaction(test_content, result)
            print(f"   Redacted: {redacted}")
        
        if result.security_warnings:
            print(f"   Warnings: {', '.join(result.security_warnings)}")
    
    # Print statistics
    stats = classifier.get_classification_statistics()
    print(f"\n📊 Classification Statistics:")
    for key, value in stats['classification_statistics'].items():
        print(f"   {key}: {value}")
    
    print("\n✅ Content Security & Classification test completed successfully!")

if __name__ == "__main__":
    main() 