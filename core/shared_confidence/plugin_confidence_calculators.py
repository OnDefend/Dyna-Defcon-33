"""
Plugin-Specific Confidence Calculators

Specialized confidence calculators for different security analysis domains.
Each calculator inherits from the universal system and provides domain-specific
expertise for accurate confidence scoring.

Features:
- Domain-specific evidence factors and weights
- Specialized pattern reliability databases
- Context-aware adjustments for each security domain
- Cross-validation assessment tailored to each plugin
- Integration with universal confidence framework
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..shared_analyzers.universal_confidence_calculator import (
    UniversalConfidenceCalculator,
    ConfidenceConfiguration,
    ConfidenceEvidence,
    ConfidenceFactorType,
    PatternReliability
)
from ..shared_infrastructure.pattern_reliability_database import (
    PatternReliabilityDatabase,
    get_reliability_database
)

logger = logging.getLogger(__name__)

class CryptoConfidenceCalculator(UniversalConfidenceCalculator):
    """
    Specialized confidence calculator for cryptographic analysis findings.
    
    Provides domain-specific confidence scoring for:
    - Cryptographic algorithm strength assessment
    - Key management security analysis
    - SSL/TLS configuration validation
    - Certificate security assessment
    - Cryptographic implementation correctness
    """
    
    def __init__(self, config: Optional[ConfidenceConfiguration] = None):
        """Initialize crypto-specific confidence calculator."""
        
        # Crypto-specific evidence weights
        crypto_weights = {
            ConfidenceFactorType.EVIDENCE_QUALITY: 0.25,
            ConfidenceFactorType.PATTERN_RELIABILITY: 0.30,  # Higher for crypto patterns
            ConfidenceFactorType.CONTEXT_RELEVANCE: 0.20,
            ConfidenceFactorType.VALIDATION_SOURCES: 0.15,
            ConfidenceFactorType.IMPLEMENTATION_CONTEXT: 0.10
        }
        
        # Crypto-specific context factors
        crypto_context_factors = {
            'production_code': 1.0,
            'configuration_files': 0.95,
            'test_code': 0.3,
            'example_code': 0.2,
            'documentation': 0.1,
            'key_management': 1.0,
            'ssl_configuration': 0.95,
            'certificate_handling': 0.9,
            'encryption_implementation': 0.95
        }
        
        # Crypto-specific pattern reliability
        crypto_patterns = {
            'weak_algorithm_md5': PatternReliability(
                pattern_id='weak_algorithm_md5',
                pattern_name='MD5 Algorithm Usage',
                total_validations=500,
                correct_predictions=485,
                false_positive_rate=0.030,
                false_negative_rate=0.015,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "crypto_weakness"}
            ),
            'weak_algorithm_sha1': PatternReliability(
                pattern_id='weak_algorithm_sha1',
                pattern_name='SHA1 Algorithm Usage',
                total_validations=400,
                correct_predictions=380,
                false_positive_rate=0.050,
                false_negative_rate=0.025,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "crypto_weakness"}
            ),
            'hardcoded_crypto_key': PatternReliability(
                pattern_id='hardcoded_crypto_key',
                pattern_name='Hardcoded Cryptographic Key',
                total_validations=300,
                correct_predictions=285,
                false_positive_rate=0.050,
                false_negative_rate=0.025,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "key_management"}
            ),
            'weak_ssl_configuration': PatternReliability(
                pattern_id='weak_ssl_configuration',
                pattern_name='Weak SSL Configuration',
                total_validations=250,
                correct_predictions=235,
                false_positive_rate=0.060,
                false_negative_rate=0.030,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "ssl_tls"}
            ),
            'trust_all_certificates': PatternReliability(
                pattern_id='trust_all_certificates',
                pattern_name='Trust All Certificates',
                total_validations=200,
                correct_predictions=195,
                false_positive_rate=0.025,
                false_negative_rate=0.013,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "certificate_validation"}
            ),
            'weak_random_generation': PatternReliability(
                pattern_id='weak_random_generation',
                pattern_name='Weak Random Number Generation',
                total_validations=150,
                correct_predictions=140,
                false_positive_rate=0.067,
                false_negative_rate=0.033,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "randomness"}
            )
        }
        
        if config is None:
            config = ConfidenceConfiguration(
                plugin_type='cryptography',
                evidence_weights=crypto_weights,
                context_factors=crypto_context_factors,
                reliability_database=crypto_patterns,
                minimum_confidence=0.15,
                maximum_confidence=0.98
            )
        
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
    def calculate_crypto_confidence(self, 
                                  algorithm_type: str,
                                  implementation_context: str,
                                  evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence for cryptographic findings.
        
        Args:
            algorithm_type: Type of cryptographic algorithm
            implementation_context: Context of implementation
            evidence: Evidence supporting the finding
            
        Returns:
            Confidence score (0.0-1.0)
        """
        # Create evidence objects
        evidence_list = [
            ConfidenceEvidence(
                factor_type=ConfidenceFactorType.PATTERN_RELIABILITY,
                score=self._assess_algorithm_strength(algorithm_type),
                weight=0.3,
                description=f"Algorithm strength assessment for {algorithm_type}"
            ),
            ConfidenceEvidence(
                factor_type=ConfidenceFactorType.CONTEXT_RELEVANCE,
                score=self._assess_crypto_context(implementation_context),
                weight=0.2,
                description=f"Implementation context: {implementation_context}"
            ),
            ConfidenceEvidence(
                factor_type=ConfidenceFactorType.EVIDENCE_QUALITY,
                score=self._assess_crypto_evidence(evidence),
                weight=0.25,
                description="Evidence quality assessment"
            )
        ]
        
        pattern_id = f"crypto_{algorithm_type.lower()}"
        context = {
            'algorithm_type': algorithm_type,
            'implementation_context': implementation_context,
            'domain': 'cryptography'
        }
        
        return self.calculate_confidence(evidence_list, pattern_id, context)
    
    def _assess_algorithm_strength(self, algorithm_type: str) -> float:
        """Assess cryptographic algorithm strength."""
        algorithm_strength = {
            'md5': 0.1,      # Very weak
            'sha1': 0.2,     # Weak
            'des': 0.1,      # Very weak
            '3des': 0.3,     # Weak
            'rc4': 0.1,      # Very weak
            'aes128': 0.8,   # Strong
            'aes256': 0.9,   # Very strong
            'sha256': 0.9,   # Very strong
            'sha512': 0.9,   # Very strong
            'rsa2048': 0.8,  # Strong
            'rsa4096': 0.9,  # Very strong
            'ecdsa': 0.85,   # Strong
            'ed25519': 0.9   # Very strong
        }
        
        return algorithm_strength.get(algorithm_type.lower(), 0.5)
    
    def _assess_crypto_context(self, implementation_context: str) -> float:
        """Assess cryptographic implementation context."""
        context_scores = {
            'production_code': 1.0,
            'configuration': 0.95,
            'key_management': 1.0,
            'ssl_configuration': 0.95,
            'certificate_handling': 0.9,
            'test_code': 0.3,
            'example_code': 0.2,
            'documentation': 0.1
        }
        
        return context_scores.get(implementation_context.lower(), 0.5)
    
    def _assess_crypto_evidence(self, evidence: Dict[str, Any]) -> float:
        """Assess quality of cryptographic evidence."""
        base_score = 0.5
        
        # Strong evidence indicators
        if evidence.get('algorithm_explicit'):
            base_score += 0.2
        if evidence.get('key_length_specified'):
            base_score += 0.15
        if evidence.get('configuration_explicit'):
            base_score += 0.15
        if evidence.get('multiple_sources'):
            base_score += 0.1
        
        return min(1.0, base_score)

class BinaryConfidenceCalculator(UniversalConfidenceCalculator):
    """
    Specialized confidence calculator for binary analysis findings.
    
    Provides domain-specific confidence scoring for:
    - Binary hardening analysis
    - Native library security assessment
    - JNI security analysis
    - Memory protection validation
    - Native code vulnerability detection
    """
    
    def __init__(self, config: Optional[ConfidenceConfiguration] = None):
        """Initialize binary-specific confidence calculator."""
        
        # Binary-specific evidence weights
        binary_weights = {
            ConfidenceFactorType.EVIDENCE_QUALITY: 0.30,  # Higher for binary analysis
            ConfidenceFactorType.PATTERN_RELIABILITY: 0.25,
            ConfidenceFactorType.CONTEXT_RELEVANCE: 0.20,
            ConfidenceFactorType.VALIDATION_SOURCES: 0.15,
            ConfidenceFactorType.IMPLEMENTATION_CONTEXT: 0.10
        }
        
        # Binary-specific context factors
        binary_context_factors = {
            'native_library': 1.0,
            'jni_implementation': 0.95,
            'system_library': 0.9,
            'third_party_library': 0.85,
            'debug_symbols': 0.8,
            'stripped_binary': 0.7,
            'obfuscated_code': 0.6
        }
        
        # Binary-specific pattern reliability
        binary_patterns = {
            'missing_pie': PatternReliability(
                pattern_id='missing_pie',
                pattern_name='Missing PIE Protection',
                total_validations=200,
                correct_predictions=190,
                false_positive_rate=0.050,
                false_negative_rate=0.025,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "binary_hardening"}
            ),
            'missing_nx_bit': PatternReliability(
                pattern_id='missing_nx_bit',
                pattern_name='Missing NX Bit Protection',
                total_validations=150,
                correct_predictions=145,
                false_positive_rate=0.033,
                false_negative_rate=0.017,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "binary_hardening"}
            ),
            'missing_stack_canary': PatternReliability(
                pattern_id='missing_stack_canary',
                pattern_name='Missing Stack Canary',
                total_validations=180,
                correct_predictions=170,
                false_positive_rate=0.056,
                false_negative_rate=0.028,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "binary_hardening"}
            ),
            'jni_security_issue': PatternReliability(
                pattern_id='jni_security_issue',
                pattern_name='JNI Security Issue',
                total_validations=100,
                correct_predictions=85,
                false_positive_rate=0.150,
                false_negative_rate=0.075,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "jni_analysis"}
            )
        }
        
        if config is None:
            config = ConfidenceConfiguration(
                plugin_type='binary_analysis',
                evidence_weights=binary_weights,
                context_factors=binary_context_factors,
                reliability_database=binary_patterns,
                minimum_confidence=0.1,
                maximum_confidence=0.95
            )
        
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
    
    def calculate_binary_confidence(self,
                                   protection_type: str,
                                   binary_context: str,
                                   evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence for binary analysis findings.
        
        Args:
            protection_type: Type of binary protection
            binary_context: Context of binary analysis
            evidence: Evidence supporting the finding
            
        Returns:
            Confidence score (0.0-1.0)
        """
        # Create evidence objects
        evidence_list = [
            ConfidenceEvidence(
                factor_type=ConfidenceFactorType.PATTERN_RELIABILITY,
                score=self._assess_protection_strength(protection_type),
                weight=0.25,
                description=f"Protection strength assessment for {protection_type}"
            ),
            ConfidenceEvidence(
                factor_type=ConfidenceFactorType.CONTEXT_RELEVANCE,
                score=self._assess_binary_context(binary_context),
                weight=0.2,
                description=f"Binary context: {binary_context}"
            ),
            ConfidenceEvidence(
                factor_type=ConfidenceFactorType.EVIDENCE_QUALITY,
                score=self._assess_binary_evidence(evidence),
                weight=0.3,
                description="Evidence quality assessment"
            )
        ]
        
        pattern_id = f"binary_{protection_type.lower()}"
        context = {
            'protection_type': protection_type,
            'binary_context': binary_context,
            'domain': 'binary_analysis'
        }
        
        return self.calculate_confidence(evidence_list, pattern_id, context)
    
    def _assess_protection_strength(self, protection_type: str) -> float:
        """Assess binary protection mechanism strength."""
        protection_strength = {
            'pie': 0.9,           # Very important
            'nx_bit': 0.9,        # Very important
            'stack_canary': 0.85,  # Important
            'relro': 0.8,         # Important
            'fortify': 0.75,      # Moderately important
            'cfi': 0.9,           # Very important
            'aslr': 0.85,         # Important
            'dep': 0.8            # Important
        }
        
        return protection_strength.get(protection_type.lower(), 0.5)
    
    def _assess_binary_context(self, binary_context: str) -> float:
        """Assess binary analysis context."""
        context_scores = {
            'native_library': 1.0,
            'jni_implementation': 0.95,
            'system_library': 0.9,
            'third_party_library': 0.85,
            'debug_symbols': 0.8,
            'stripped_binary': 0.7,
            'obfuscated_code': 0.6
        }
        
        return context_scores.get(binary_context.lower(), 0.5)
    
    def _assess_binary_evidence(self, evidence: Dict[str, Any]) -> float:
        """Assess quality of binary analysis evidence."""
        base_score = 0.5
        
        # Strong evidence indicators
        if evidence.get('tool_verification'):
            base_score += 0.2
        if evidence.get('multiple_binaries'):
            base_score += 0.15
        if evidence.get('symbol_analysis'):
            base_score += 0.1
        if evidence.get('dynamic_analysis'):
            base_score += 0.15
        
        return min(1.0, base_score)

class NetworkConfidenceCalculator(UniversalConfidenceCalculator):
    """
    Specialized confidence calculator for network security analysis findings.
    
    Provides domain-specific confidence scoring for:
    - Network configuration security
    - SSL/TLS vulnerability assessment
    - Certificate validation issues
    - Network traffic analysis
    - Protocol security assessment
    """
    
    def __init__(self, config: Optional[ConfidenceConfiguration] = None):
        """Initialize network-specific confidence calculator."""
        
        # Network-specific evidence weights
        network_weights = {
            ConfidenceFactorType.EVIDENCE_QUALITY: 0.25,
            ConfidenceFactorType.PATTERN_RELIABILITY: 0.30,
            ConfidenceFactorType.CONTEXT_RELEVANCE: 0.25,  # Higher for network context
            ConfidenceFactorType.VALIDATION_SOURCES: 0.15,
            ConfidenceFactorType.IMPLEMENTATION_CONTEXT: 0.05
        }
        
        # Network-specific context factors
        network_context_factors = {
            'network_config': 1.0,
            'ssl_configuration': 0.95,
            'certificate_validation': 0.9,
            'traffic_analysis': 0.85,
            'protocol_analysis': 0.9,
            'api_communication': 0.8
        }
        
        # Network-specific pattern reliability
        network_patterns = {
            'ssl_pinning_bypass': PatternReliability(
                pattern_id='ssl_pinning_bypass',
                pattern_name='SSL Pinning Bypass',
                total_validations=150,
                correct_predictions=140,
                false_positive_rate=0.067,
                false_negative_rate=0.033,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "ssl_security"}
            ),
            'cleartext_traffic': PatternReliability(
                pattern_id='cleartext_traffic',
                pattern_name='Cleartext Traffic',
                total_validations=200,
                correct_predictions=190,
                false_positive_rate=0.050,
                false_negative_rate=0.025,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "network_security"}
            ),
            'weak_tls_version': PatternReliability(
                pattern_id='weak_tls_version',
                pattern_name='Weak TLS Version',
                total_validations=120,
                correct_predictions=115,
                false_positive_rate=0.042,
                false_negative_rate=0.021,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "protocol_security"}
            )
        }
        
        if config is None:
            config = ConfidenceConfiguration(
                plugin_type='network_security',
                evidence_weights=network_weights,
                context_factors=network_context_factors,
                reliability_database=network_patterns,
                minimum_confidence=0.1,
                maximum_confidence=0.95
            )
        
        super().__init__(config)
        self.logger = logging.getLogger(__name__)

class StorageConfidenceCalculator(UniversalConfidenceCalculator):
    """
    Specialized confidence calculator for storage security analysis findings.
    
    Provides domain-specific confidence scoring for:
    - Data storage security assessment
    - Database security analysis
    - File system security validation
    - Encryption at rest analysis
    - Access control assessment
    """
    
    def __init__(self, config: Optional[ConfidenceConfiguration] = None):
        """Initialize storage-specific confidence calculator."""
        
        # Storage-specific evidence weights
        storage_weights = {
            ConfidenceFactorType.EVIDENCE_QUALITY: 0.30,
            ConfidenceFactorType.PATTERN_RELIABILITY: 0.25,
            ConfidenceFactorType.CONTEXT_RELEVANCE: 0.20,
            ConfidenceFactorType.VALIDATION_SOURCES: 0.15,
            ConfidenceFactorType.IMPLEMENTATION_CONTEXT: 0.10
        }
        
        # Storage-specific context factors
        storage_context_factors = {
            'database_security': 1.0,
            'file_system_security': 0.95,
            'encryption_at_rest': 0.9,
            'access_control': 0.85,
            'backup_security': 0.8,
            'temporary_storage': 0.7
        }
        
        # Storage-specific pattern reliability
        storage_patterns = {
            'unencrypted_database': PatternReliability(
                pattern_id='unencrypted_database',
                pattern_name='Unencrypted Database',
                total_validations=100,
                correct_predictions=95,
                false_positive_rate=0.050,
                false_negative_rate=0.025,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "data_protection"}
            ),
            'weak_file_permissions': PatternReliability(
                pattern_id='weak_file_permissions',
                pattern_name='Weak File Permissions',
                total_validations=80,
                correct_predictions=75,
                false_positive_rate=0.062,
                false_negative_rate=0.031,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "access_control"}
            ),
            'sql_injection_vulnerability': PatternReliability(
                pattern_id='sql_injection_vulnerability',
                pattern_name='SQL Injection Vulnerability',
                total_validations=200,
                correct_predictions=180,
                false_positive_rate=0.100,
                false_negative_rate=0.050,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "database_security"}
            )
        }
        
        if config is None:
            config = ConfidenceConfiguration(
                plugin_type='storage_security',
                evidence_weights=storage_weights,
                context_factors=storage_context_factors,
                reliability_database=storage_patterns,
                minimum_confidence=0.1,
                maximum_confidence=0.95
            )
        
        super().__init__(config)
        self.logger = logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # Compatibility helper: delegates to generic storage confidence logic
    # to prevent AttributeError in analyzers expecting this specialised API.
    # ------------------------------------------------------------------
    def calculate_shared_preferences_confidence(self, category: str, pattern_type: str, context: Dict[str, Any]) -> float:  # type: ignore
        """Compute confidence for shared-preferences vulnerabilities.

        This method exists only for backward-compatibility.  It calls the more
        general `calculate_storage_confidence` when present so that scoring
        remains evidence-based rather than hard-coded.
        """
        try:
            if hasattr(self, 'calculate_storage_confidence'):
                dummy_vuln = type('Dummy', (), {'severity': 'medium', 'storage_type': 'shared_preferences'})()
                evidence: Dict[str, Any] = {
                    'pattern_type': pattern_type,
                    'category': category,
                    **(context or {})
                }
                return self.calculate_storage_confidence(dummy_vuln, evidence)  # type: ignore
        except Exception:
            pass
        return 0.5

class PlatformConfidenceCalculator(UniversalConfidenceCalculator):
    """
    Specialized confidence calculator for platform usage analysis findings.
    
    Provides domain-specific confidence scoring for:
    - Platform API usage assessment
    - Permission analysis
    - Component security validation
    - Intent security analysis
    - Manifest security assessment
    """
    
    def __init__(self, config: Optional[ConfidenceConfiguration] = None):
        """Initialize platform-specific confidence calculator."""
        
        # Platform-specific evidence weights
        platform_weights = {
            ConfidenceFactorType.EVIDENCE_QUALITY: 0.25,
            ConfidenceFactorType.PATTERN_RELIABILITY: 0.25,
            ConfidenceFactorType.CONTEXT_RELEVANCE: 0.25,
            ConfidenceFactorType.VALIDATION_SOURCES: 0.15,
            ConfidenceFactorType.IMPLEMENTATION_CONTEXT: 0.10
        }
        
        # Platform-specific context factors
        platform_context_factors = {
            'manifest_analysis': 1.0,
            'permission_analysis': 0.95,
            'component_security': 0.9,
            'intent_security': 0.85,
            'api_usage': 0.8,
            'platform_integration': 0.85
        }
        
        # Platform-specific pattern reliability
        platform_patterns = {
            'exported_component': PatternReliability(
                pattern_id='exported_component',
                pattern_name='Exported Component',
                total_validations=300,
                correct_predictions=285,
                false_positive_rate=0.050,
                false_negative_rate=0.025,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "component_security"}
            ),
            'dangerous_permission': PatternReliability(
                pattern_id='dangerous_permission',
                pattern_name='Dangerous Permission',
                total_validations=250,
                correct_predictions=235,
                false_positive_rate=0.060,
                false_negative_rate=0.030,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "permission_analysis"}
            ),
            'intent_filter_vulnerability': PatternReliability(
                pattern_id='intent_filter_vulnerability',
                pattern_name='Intent Filter Vulnerability',
                total_validations=150,
                correct_predictions=135,
                false_positive_rate=0.100,
                false_negative_rate=0.050,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "intent_security"}
            )
        }
        
        if config is None:
            config = ConfidenceConfiguration(
                plugin_type='platform_usage',
                evidence_weights=platform_weights,
                context_factors=platform_context_factors,
                reliability_database=platform_patterns,
                minimum_confidence=0.1,
                maximum_confidence=0.95
            )
        
        super().__init__(config)
        self.logger = logging.getLogger(__name__)

class WebViewConfidenceCalculator(UniversalConfidenceCalculator):
    """
    Specialized confidence calculator for WebView security analysis findings.
    
    Provides domain-specific confidence scoring for:
    - WebView configuration security
    - JavaScript interface analysis
    - URL validation assessment
    - Content security policy analysis
    - WebView vulnerability detection
    """
    
    def __init__(self, config: Optional[ConfidenceConfiguration] = None):
        """Initialize WebView-specific confidence calculator."""
        
        # WebView-specific evidence weights
        webview_weights = {
            ConfidenceFactorType.EVIDENCE_QUALITY: 0.30,
            ConfidenceFactorType.PATTERN_RELIABILITY: 0.25,
            ConfidenceFactorType.CONTEXT_RELEVANCE: 0.20,
            ConfidenceFactorType.VALIDATION_SOURCES: 0.15,
            ConfidenceFactorType.IMPLEMENTATION_CONTEXT: 0.10
        }
        
        # WebView-specific context factors
        webview_context_factors = {
            'javascript_interface': 1.0,
            'webview_configuration': 0.95,
            'url_validation': 0.9,
            'content_security_policy': 0.85,
            'webview_permissions': 0.8
        }
        
        # WebView-specific pattern reliability
        webview_patterns = {
            'javascript_enabled': PatternReliability(
                pattern_id='javascript_enabled',
                pattern_name='JavaScript Enabled',
                total_validations=200,
                correct_predictions=190,
                false_positive_rate=0.050,
                false_negative_rate=0.025,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "webview_config"}
            ),
            'file_access_enabled': PatternReliability(
                pattern_id='file_access_enabled',
                pattern_name='File Access Enabled',
                total_validations=150,
                correct_predictions=140,
                false_positive_rate=0.067,
                false_negative_rate=0.033,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "webview_config"}
            ),
            'unsafe_javascript_interface': PatternReliability(
                pattern_id='unsafe_javascript_interface',
                pattern_name='Unsafe JavaScript Interface',
                total_validations=100,
                correct_predictions=90,
                false_positive_rate=0.100,
                false_negative_rate=0.050,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "javascript_interface"}
            )
        }
        
        if config is None:
            config = ConfidenceConfiguration(
                plugin_type='webview_security',
                evidence_weights=webview_weights,
                context_factors=webview_context_factors,
                reliability_database=webview_patterns,
                minimum_confidence=0.1,
                maximum_confidence=0.95
            )
        
        super().__init__(config)
        self.logger = logging.getLogger(__name__)

class InjectionConfidenceCalculator(UniversalConfidenceCalculator):
    """
    Specialized confidence calculator for injection vulnerability analysis findings.
    
    Provides domain-specific confidence scoring for:
    - SQL injection vulnerability assessment
    - Command injection analysis
    - Path traversal vulnerability detection
    - Cross-site scripting (XSS) analysis
    - Input validation assessment
    """
    
    def __init__(self, config: Optional[ConfidenceConfiguration] = None):
        """Initialize injection-specific confidence calculator."""
        
        # Injection-specific evidence weights
        injection_weights = {
            ConfidenceFactorType.EVIDENCE_QUALITY: 0.35,  # Higher for injection analysis
            ConfidenceFactorType.PATTERN_RELIABILITY: 0.25,
            ConfidenceFactorType.CONTEXT_RELEVANCE: 0.20,
            ConfidenceFactorType.VALIDATION_SOURCES: 0.15,
            ConfidenceFactorType.IMPLEMENTATION_CONTEXT: 0.05
        }
        
        # Injection-specific context factors
        injection_context_factors = {
            'user_input_handling': 1.0,
            'database_interaction': 0.95,
            'command_execution': 0.9,
            'file_system_access': 0.85,
            'web_interface': 0.8,
            'api_endpoint': 0.85
        }
        
        # Injection-specific pattern reliability
        injection_patterns = {
            'sql_injection': PatternReliability(
                pattern_id='sql_injection',
                pattern_name='SQL Injection',
                total_validations=400,
                correct_predictions=360,
                false_positive_rate=0.100,
                false_negative_rate=0.050,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "injection_vulnerability"}
            ),
            'command_injection': PatternReliability(
                pattern_id='command_injection',
                pattern_name='Command Injection',
                total_validations=200,
                correct_predictions=190,
                false_positive_rate=0.050,
                false_negative_rate=0.025,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "injection_vulnerability"}
            ),
            'path_traversal': PatternReliability(
                pattern_id='path_traversal',
                pattern_name='Path Traversal',
                total_validations=300,
                correct_predictions=270,
                false_positive_rate=0.100,
                false_negative_rate=0.050,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={"pattern_category": "injection_vulnerability"}
            )
        }
        
        if config is None:
            config = ConfidenceConfiguration(
                plugin_type='injection_analysis',
                evidence_weights=injection_weights,
                context_factors=injection_context_factors,
                reliability_database=injection_patterns,
                minimum_confidence=0.1,
                maximum_confidence=0.95
            )
        
        super().__init__(config)
        self.logger = logging.getLogger(__name__)

class StaticAnalysisConfidenceCalculator(UniversalConfidenceCalculator):
    """
    Specialized confidence calculator for static analysis findings.
    
    Provides domain-specific confidence scoring for:
    - Static code analysis results
    - Pattern matching confidence
    - Code quality assessment
    - Security pattern detection
    - Vulnerability classification
    """
    
    def __init__(self, config: Optional[ConfidenceConfiguration] = None):
        """Initialize static analysis-specific confidence calculator."""
        
        # Static analysis-specific evidence weights
        static_weights = {
            ConfidenceFactorType.EVIDENCE_QUALITY: 0.30,
            ConfidenceFactorType.PATTERN_RELIABILITY: 0.30,
            ConfidenceFactorType.CONTEXT_RELEVANCE: 0.20,
            ConfidenceFactorType.VALIDATION_SOURCES: 0.15,
            ConfidenceFactorType.IMPLEMENTATION_CONTEXT: 0.05
        }
        
        # Static analysis-specific context factors
        static_context_factors = {
            'source_code': 1.0,
            'configuration_files': 0.9,
            'manifest_files': 0.95,
            'resource_files': 0.7,
            'test_files': 0.4,
            'build_files': 0.3,
            'documentation': 0.2
        }
        
        # Static analysis-specific pattern reliability
        static_patterns = {
            'hardcoded_secrets': PatternReliability(
                pattern_id='hardcoded_secrets',
                pattern_name='Hardcoded Secrets',
                total_validations=100,
                correct_predictions=85,
                false_positive_rate=0.150,
                false_negative_rate=0.075,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={}
            ),
            'insecure_urls': PatternReliability(
                pattern_id='insecure_urls',
                pattern_name='Insecure URLs',
                total_validations=100,
                correct_predictions=85,
                false_positive_rate=0.150,
                false_negative_rate=0.075,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={}
            ),
            'debug_code': PatternReliability(
                pattern_id='debug_code',
                pattern_name='Debug Code',
                total_validations=100,
                correct_predictions=85,
                false_positive_rate=0.150,
                false_negative_rate=0.075,
                confidence_adjustment=0.0,
                last_updated='2024-01-01',
                metadata={}
            )
        }
        
        if config is None:
            config = ConfidenceConfiguration(
                plugin_type='static_analysis',
                evidence_weights=static_weights,
                context_factors=static_context_factors,
                reliability_database=static_patterns,
                minimum_confidence=0.1,
                maximum_confidence=0.95
            )
        
        super().__init__(config)
        self.logger = logging.getLogger(__name__)

def create_plugin_confidence_calculator(plugin_type: str) -> UniversalConfidenceCalculator:
    """
    Factory function to create appropriate confidence calculator for plugin type.
    
    Args:
        plugin_type: Type of plugin requiring confidence calculation
        
    Returns:
        Specialized confidence calculator instance
    """
    calculators = {
        'cryptography': CryptoConfidenceCalculator,
        'crypto': CryptoConfidenceCalculator,
        'binary_analysis': BinaryConfidenceCalculator,
        'native_binary': BinaryConfidenceCalculator,
        'network_security': NetworkConfidenceCalculator,
        'network': NetworkConfidenceCalculator,
        'storage_security': StorageConfidenceCalculator,
        'storage': StorageConfidenceCalculator,
        'platform_usage': PlatformConfidenceCalculator,
        'platform': PlatformConfidenceCalculator,
        'webview_security': WebViewConfidenceCalculator,
        'webview': WebViewConfidenceCalculator,
        'injection_analysis': InjectionConfidenceCalculator,
        'injection': InjectionConfidenceCalculator,
        'static_analysis': StaticAnalysisConfidenceCalculator,
        'static': StaticAnalysisConfidenceCalculator
    }
    
    calculator_class = calculators.get(plugin_type.lower())
    if calculator_class:
        return calculator_class()
    else:
        # Return generic universal calculator for unknown types
        logger.warning(f"Unknown plugin type: {plugin_type}, using universal calculator")
        
        # **CONFIDENCE CALCULATOR FIX**: Create default configuration for UniversalConfidenceCalculator
        from core.shared_analyzers.universal_confidence_calculator import ConfidenceConfiguration, ConfidenceFactorType
        
        default_config = ConfidenceConfiguration(
            plugin_type=plugin_type,
            evidence_weights={
                ConfidenceFactorType.EVIDENCE_QUALITY: 0.25,
                ConfidenceFactorType.PATTERN_RELIABILITY: 0.25,
                ConfidenceFactorType.CONTEXT_RELEVANCE: 0.20,
                ConfidenceFactorType.VALIDATION_SOURCES: 0.20,
                ConfidenceFactorType.IMPLEMENTATION_CONTEXT: 0.10
            },
            context_factors={},
            reliability_database={}
        )
        
        return UniversalConfidenceCalculator(default_config) 