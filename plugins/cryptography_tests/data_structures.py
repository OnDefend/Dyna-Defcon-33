#!/usr/bin/env python3
"""
Standardized Data Structures for Modularized Cryptography Tests Plugin

This module provides consistent data structures used across all crypto analysis
modules, ensuring type safety and eliminating duplication of vulnerability
classes throughout the modularized plugin.

Features:
- Standardized cryptographic vulnerability classes
- Rich metadata support for detailed analysis
- Auto-calculated derived fields and metrics
- MASVS compliance mapping integration
- Type-safe enums for categorization
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Union
from enum import Enum
from datetime import datetime

from core.shared_data_structures.base_vulnerability import (
    BaseVulnerability, 
    VulnerabilityType, 
    VulnerabilitySeverity,
    VulnerabilityContext
)

logger = logging.getLogger(__name__)

class CryptographicAlgorithmType(Enum):
    """Types of cryptographic algorithms."""
    SYMMETRIC_CIPHER = "symmetric_cipher"
    ASYMMETRIC_CIPHER = "asymmetric_cipher"
    HASH_FUNCTION = "hash_function"
    KEY_DERIVATION = "key_derivation"
    DIGITAL_SIGNATURE = "digital_signature"
    MAC = "message_authentication_code"
    RANDOM_GENERATOR = "random_generator"
    STREAM_CIPHER = "stream_cipher"
    BLOCK_CIPHER = "block_cipher"

class CryptographicStrength(Enum):
    """Cryptographic strength levels."""
    VERY_WEAK = "very_weak"
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    VERY_STRONG = "very_strong"
    
    @property
    def score(self) -> int:
        """Get numeric score for strength (1-5)."""
        strength_scores = {
            CryptographicStrength.VERY_WEAK: 1,
            CryptographicStrength.WEAK: 2,
            CryptographicStrength.MODERATE: 3,
            CryptographicStrength.STRONG: 4,
            CryptographicStrength.VERY_STRONG: 5
        }
        return strength_scores.get(self, 1)

class ComplianceStandard(Enum):
    """Cryptographic compliance standards."""
    FIPS_140_2 = "FIPS 140-2"
    COMMON_CRITERIA = "Common Criteria"
    NIST_SP_800_53 = "NIST SP 800-53"
    NIST_SP_800_57 = "NIST SP 800-57"
    NIST_SP_800_90 = "NIST SP 800-90"
    NIST_SP_800_131 = "NIST SP 800-131"
    ISO_27001 = "ISO 27001"
    PCI_DSS = "PCI DSS"
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    SOX = "SOX"

@dataclass
class CryptographicAlgorithm:
    """Represents a cryptographic algorithm with its characteristics."""
    name: str
    algorithm_type: CryptographicAlgorithmType
    key_size: int
    strength: CryptographicStrength
    mode: str = ""
    padding: str = ""
    is_deprecated: bool = False
    deprecation_reason: str = ""
    recommended_replacement: str = ""
    compliance_status: Dict[ComplianceStandard, bool] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_secure(self) -> bool:
        """Determine if algorithm is considered secure."""
        return not self.is_deprecated and self.strength.score >= 3
    
    @property
    def security_level(self) -> str:
        """Get human-readable security level."""
        if self.is_deprecated:
            return "Deprecated"
        elif self.strength.score >= 4:
            return "High Security"
        elif self.strength.score >= 3:
            return "Moderate Security"
        else:
            return "Low Security"

@dataclass
class CryptographicImplementation:
    """Represents a cryptographic implementation found in the application."""
    implementation_id: str
    algorithm: CryptographicAlgorithm
    location: str
    usage_context: str
    implementation_details: Dict[str, Any] = field(default_factory=dict)
    security_issues: List[str] = field(default_factory=list)
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    compliance_analysis: Dict[ComplianceStandard, Dict[str, Any]] = field(default_factory=dict)
    vulnerabilities: List['CryptographicVulnerability'] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    analysis_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def vulnerability_count(self) -> int:
        """Get number of vulnerabilities in this implementation."""
        return len(self.vulnerabilities)
    
    @property
    def critical_vulnerability_count(self) -> int:
        """Get number of critical vulnerabilities."""
        return sum(1 for vuln in self.vulnerabilities if vuln.severity == VulnerabilitySeverity.CRITICAL)
    
    @property
    def overall_security_score(self) -> float:
        """Calculate overall security score (0.0 to 1.0)."""
        base_score = self.algorithm.strength.score / 5.0
        
        # Penalize for vulnerabilities
        if self.vulnerabilities:
            vulnerability_penalty = sum(
                (6 - vuln.severity.score) * 0.1 for vuln in self.vulnerabilities
            ) / len(self.vulnerabilities)
            base_score -= min(vulnerability_penalty, 0.8)  # Max penalty 80%
        
        # Bonus for compliance
        compliance_bonus = sum(self.compliance_analysis.values()) * 0.05
        base_score += min(compliance_bonus, 0.2)  # Max bonus 20%
        
        return max(0.0, min(1.0, base_score))

@dataclass
class CryptographicVulnerability(BaseVulnerability):
    """
    Specialized vulnerability class for cryptographic security issues.
    Extends BaseVulnerability with crypto-specific fields.
    """
    algorithm_name: str = ""
    algorithm_type: Optional[CryptographicAlgorithmType] = None
    key_size: int = 0
    cryptographic_weakness: str = ""
    attack_vectors: List[str] = field(default_factory=list)
    cryptographic_impact: str = ""
    algorithm_recommendations: List[str] = field(default_factory=list)
    compliance_violations: List[ComplianceStandard] = field(default_factory=list)
    
    def __post_init__(self):
        """Initialize crypto-specific vulnerability data."""
        super().__post_init__()
        
        # Set vulnerability type to crypto if not specified
        if self.vulnerability_type == VulnerabilityType.GENERAL_SECURITY:
            self.vulnerability_type = VulnerabilityType.WEAK_CRYPTOGRAPHY
        
        # Add crypto-specific tags
        self.add_tag("cryptography")
        if self.algorithm_name:
            self.add_tag(f"algorithm:{self.algorithm_name}")
        if self.algorithm_type:
            self.add_tag(f"type:{self.algorithm_type.value}")

    @property
    def is_algorithm_deprecated(self) -> bool:
        """Check if the algorithm is deprecated."""
        deprecated_algorithms = {
            "DES", "3DES", "RC4", "MD5", "SHA1", "RSA-1024"
        }
        return self.algorithm_name.upper() in deprecated_algorithms

    @property
    def cryptographic_risk_score(self) -> float:
        """Calculate crypto-specific risk score."""
        base_risk = self.risk_score
        
        # Increase risk for deprecated algorithms
        if self.is_algorithm_deprecated:
            base_risk *= 1.5
        
        # Increase risk for weak key sizes
        if self.key_size > 0:
            if self.key_size < 128:  # Very weak
                base_risk *= 1.8
            elif self.key_size < 256:  # Weak
                base_risk *= 1.3
        
        return min(1.0, base_risk)

    def add_attack_vector(self, attack_vector: str) -> None:
        """Add an attack vector to this vulnerability."""
        if attack_vector and attack_vector not in self.attack_vectors:
            self.attack_vectors.append(attack_vector)

    def add_compliance_violation(self, standard: ComplianceStandard) -> None:
        """Add a compliance standard violation."""
        if standard not in self.compliance_violations:
            self.compliance_violations.append(standard)

    def add_algorithm_recommendation(self, recommendation: str) -> None:
        """Add an algorithm-specific recommendation."""
        if recommendation and recommendation not in self.algorithm_recommendations:
            self.algorithm_recommendations.append(recommendation)

@dataclass
class KeyManagementAnalysis:
    """Analysis results for key management practices."""
    key_generation_methods: List[Dict[str, Any]] = field(default_factory=list)
    key_storage_methods: List[Dict[str, Any]] = field(default_factory=list)
    key_derivation_functions: List[Dict[str, Any]] = field(default_factory=list)
    hardware_security_modules: List[Dict[str, Any]] = field(default_factory=list)
    android_keystore_usage: Dict[str, Any] = field(default_factory=dict)
    key_rotation_policies: List[Dict[str, Any]] = field(default_factory=list)
    key_escrow_mechanisms: List[Dict[str, Any]] = field(default_factory=list)
    biometric_key_protection: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[CryptographicVulnerability] = field(default_factory=list)
    overall_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    compliance_status: Dict[ComplianceStandard, bool] = field(default_factory=dict)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def uses_hardware_security(self) -> bool:
        """Check if hardware security modules are used."""
        return len(self.hardware_security_modules) > 0 or bool(self.android_keystore_usage)
    
    @property
    def key_management_score(self) -> float:
        """Calculate key management security score."""
        score = 0.0
        
        # Base score for secure key generation
        if any(method.get('is_secure', False) for method in self.key_generation_methods):
            score += 0.3
        
        # Score for hardware-backed storage
        if self.uses_hardware_security:
            score += 0.4
        
        # Score for key rotation
        if self.key_rotation_policies:
            score += 0.2
        
        # Score for biometric protection
        if self.biometric_key_protection:
            score += 0.1
        
        # Penalize for vulnerabilities
        if self.vulnerabilities:
            penalty = len(self.vulnerabilities) * 0.1
            score -= min(penalty, 0.5)
        
        return max(0.0, min(1.0, score))

@dataclass
class CertificateAnalysis:
    """Analysis results for certificate and PKI security."""
    certificates: List[Dict[str, Any]] = field(default_factory=list)
    certificate_chains: List[Dict[str, Any]] = field(default_factory=list)
    pinning_implementations: List[Dict[str, Any]] = field(default_factory=list)
    trust_managers: List[Dict[str, Any]] = field(default_factory=list)
    certificate_validation: List[Dict[str, Any]] = field(default_factory=list)
    ocsp_validation: List[Dict[str, Any]] = field(default_factory=list)
    certificate_transparency: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[CryptographicVulnerability] = field(default_factory=list)
    overall_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    compliance_status: Dict[ComplianceStandard, bool] = field(default_factory=dict)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SSLTLSAnalysis:
    """Analysis results for SSL/TLS configuration."""
    protocol_versions: List[Dict[str, Any]] = field(default_factory=list)
    cipher_suites: List[Dict[str, Any]] = field(default_factory=list)
    certificate_validation: List[Dict[str, Any]] = field(default_factory=list)
    hostname_verification: List[Dict[str, Any]] = field(default_factory=list)
    perfect_forward_secrecy: List[Dict[str, Any]] = field(default_factory=list)
    network_security_config: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[CryptographicVulnerability] = field(default_factory=list)
    overall_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    compliance_status: Dict[ComplianceStandard, bool] = field(default_factory=dict)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CryptographicStorageAnalysis:
    """Analysis results for cryptographic storage security."""
    encrypted_storage_implementations: List[Dict[str, Any]] = field(default_factory=list)
    key_derivation_for_storage: List[Dict[str, Any]] = field(default_factory=list)
    storage_integrity_protection: List[Dict[str, Any]] = field(default_factory=list)
    secure_deletion_mechanisms: List[Dict[str, Any]] = field(default_factory=list)
    cold_storage_protection: List[Dict[str, Any]] = field(default_factory=list)
    database_encryption: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[CryptographicVulnerability] = field(default_factory=list)
    overall_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    compliance_status: Dict[ComplianceStandard, bool] = field(default_factory=dict)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class NISTComplianceAnalysis:
    """Analysis results for NIST and FIPS compliance."""
    nist_sp_800_53_compliance: Dict[str, Any] = field(default_factory=dict)
    nist_sp_800_57_compliance: Dict[str, Any] = field(default_factory=dict)
    nist_sp_800_90_compliance: Dict[str, Any] = field(default_factory=dict)
    nist_sp_800_131_compliance: Dict[str, Any] = field(default_factory=dict)
    nist_sp_800_175_compliance: Dict[str, Any] = field(default_factory=dict)
    fips_140_2_compliance: Dict[str, Any] = field(default_factory=dict)
    common_criteria_compliance: Dict[str, Any] = field(default_factory=dict)
    regulatory_compliance: Dict[str, Any] = field(default_factory=dict)
    compliance_gaps: List[Dict[str, Any]] = field(default_factory=list)
    compliance_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CryptographicAnalysis:
    """Complete cryptographic security analysis results."""
    target_name: str
    analysis_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    analysis_duration: float = 0.0
    
    # Core analysis components
    implementations: List[CryptographicImplementation] = field(default_factory=list)
    key_management: Optional[KeyManagementAnalysis] = None
    certificate_analysis: Optional[CertificateAnalysis] = None
    ssl_tls_analysis: Optional[SSLTLSAnalysis] = None
    storage_analysis: Optional[CryptographicStorageAnalysis] = None
    compliance_analysis: Optional[NISTComplianceAnalysis] = None
    
    # Aggregated results
    vulnerabilities: List[CryptographicVulnerability] = field(default_factory=list)
    overall_security_score: float = 0.0
    compliance_status: str = ""
    
    # Recommendations and metadata
    recommendations: List[str] = field(default_factory=list)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def total_implementations(self) -> int:
        """Get total number of crypto implementations found."""
        return len(self.implementations)
    
    @property
    def total_vulnerabilities(self) -> int:
        """Get total number of vulnerabilities found."""
        return len(self.vulnerabilities)
    
    @property
    def critical_vulnerabilities(self) -> int:
        """Get number of critical vulnerabilities."""
        return sum(1 for vuln in self.vulnerabilities if vuln.severity == VulnerabilitySeverity.CRITICAL)
    
    @property
    def high_vulnerabilities(self) -> int:
        """Get number of high severity vulnerabilities."""
        return sum(1 for vuln in self.vulnerabilities if vuln.severity == VulnerabilitySeverity.HIGH)
    
    @property
    def security_grade(self) -> str:
        """Get overall security grade (A-F)."""
        if self.overall_security_score >= 0.9:
            return "A"
        elif self.overall_security_score >= 0.8:
            return "B"
        elif self.overall_security_score >= 0.7:
            return "C"
        elif self.overall_security_score >= 0.6:
            return "D"
        else:
            return "F"
    
    def add_implementation(self, implementation: CryptographicImplementation) -> None:
        """Add a cryptographic implementation to the analysis."""
        self.implementations.append(implementation)
        # Add implementation vulnerabilities to overall list
        self.vulnerabilities.extend(implementation.vulnerabilities)
    
    def add_vulnerability(self, vulnerability: CryptographicVulnerability) -> None:
        """Add a vulnerability to the analysis."""
        self.vulnerabilities.append(vulnerability)
    
    def calculate_overall_score(self) -> None:
        """Calculate the overall security score based on all analysis components."""
        scores = []
        
        # Implementation scores
        if self.implementations:
            impl_scores = [impl.overall_security_score for impl in self.implementations]
            scores.append(sum(impl_scores) / len(impl_scores))
        
        # Component scores
        if self.key_management:
            scores.append(self.key_management.key_management_score)
        if self.certificate_analysis:
            scores.append(self.certificate_analysis.overall_score)
        if self.ssl_tls_analysis:
            scores.append(self.ssl_tls_analysis.overall_score)
        if self.storage_analysis:
            scores.append(self.storage_analysis.overall_score)
        if self.compliance_analysis:
            scores.append(self.compliance_analysis.compliance_score)
        
        # Calculate weighted average
        if scores:
            self.overall_security_score = sum(scores) / len(scores)
            
            # Apply penalty for critical vulnerabilities
            critical_penalty = self.critical_vulnerabilities * 0.1
            self.overall_security_score = max(0.0, self.overall_security_score - critical_penalty)
        else:
            self.overall_security_score = 0.0 