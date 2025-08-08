"""
APK Signing Certificate Analyzer Data Structures

This module contains all data structures, dataclasses, and enums used
throughout the APK signing certificate analyzer plugin components.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import Enum
from datetime import datetime, timezone

class SignatureScheme(Enum):
    """Android APK signature schemes."""
    V1_JAR = "v1_jar"
    V2_APK = "v2_apk"
    V3_KEY_ROTATION = "v3_key_rotation"
    V4_INCREMENTAL = "v4_incremental"

class CertificateSecurityLevel(Enum):
    """Certificate security assessment levels with orderable values."""
    INFO = 1       # Informational level (lowest severity)
    LOW = 2        # Low severity issues
    MEDIUM = 3     # Medium severity issues  
    HIGH = 4       # High severity issues
    CRITICAL = 5   # Critical severity issues (highest severity)
    
    def __lt__(self, other):
        """Enable comparison of security levels."""
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented
    
    def __le__(self, other):
        """Enable less than or equal comparison."""
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented
    
    def __gt__(self, other):
        """Enable greater than comparison."""
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented
    
    def __ge__(self, other):
        """Enable greater than or equal comparison.""" 
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented
    
    @property
    def display_name(self):
        """Get the display name of the security level."""
        return self.name

class SignatureAlgorithm(Enum):
    """Supported signature algorithms."""
    RSA_PKCS1_SHA1 = "RSA_PKCS1_SHA1"
    RSA_PKCS1_SHA256 = "RSA_PKCS1_SHA256"
    RSA_PKCS1_SHA512 = "RSA_PKCS1_SHA512"
    RSA_PSS_SHA256 = "RSA_PSS_SHA256"
    RSA_PSS_SHA512 = "RSA_PSS_SHA512"
    ECDSA_SHA256 = "ECDSA_SHA256"
    ECDSA_SHA512 = "ECDSA_SHA512"
    DSA_SHA256 = "DSA_SHA256"

class ComplianceStandard(Enum):
    """Compliance standards for certificate validation."""
    ANDROID_SIGNING = "android_signing"
    NIST_SP_800_57 = "nist_sp_800_57"
    FIPS_186_4 = "fips_186_4"
    COMMON_CRITERIA = "common_criteria"
    PKCS_1 = "pkcs_1"
    X509_RFC_5280 = "x509_rfc_5280"

@dataclass
class CertificateExtension:
    """Represents a certificate extension."""
    oid: str
    critical: bool
    value: str
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'oid': self.oid,
            'critical': self.critical,
            'value': self.value,
            'description': self.description
        }

@dataclass
class SigningCertificate:
    """Represents a signing certificate with security analysis."""
    subject: str
    issuer: str
    serial_number: str
    valid_from: datetime
    valid_to: datetime
    key_algorithm: str
    key_size: int
    signature_algorithm: str
    fingerprint_sha256: str
    fingerprint_sha1: str
    is_self_signed: bool
    certificate_pem: str
    certificate_der: bytes
    extensions: List[CertificateExtension] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)
    security_level: CertificateSecurityLevel = CertificateSecurityLevel.INFO
    public_key_pem: str = ""
    subject_alt_names: List[str] = field(default_factory=list)
    key_usage: List[str] = field(default_factory=list)
    extended_key_usage: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'subject': self.subject,
            'issuer': self.issuer,
            'serial_number': self.serial_number,
            'valid_from': self.valid_from.isoformat() if self.valid_from else None,
            'valid_to': self.valid_to.isoformat() if self.valid_to else None,
            'key_algorithm': self.key_algorithm,
            'key_size': self.key_size,
            'signature_algorithm': self.signature_algorithm,
            'fingerprint_sha256': self.fingerprint_sha256,
            'fingerprint_sha1': self.fingerprint_sha1,
            'is_self_signed': self.is_self_signed,
            'extensions': [ext.to_dict() for ext in self.extensions],
            'security_issues': self.security_issues,
            'security_level': self.security_level.name,
            'subject_alt_names': self.subject_alt_names,
            'key_usage': self.key_usage,
            'extended_key_usage': self.extended_key_usage
        }
    
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        from datetime import timezone
        # Use UTC timezone-aware datetime for comparison
        now_utc = datetime.now(timezone.utc)
        return now_utc > self.valid_to
    
    def days_until_expiry(self) -> int:
        """Calculate days until certificate expiry."""
        if self.is_expired():
            return 0
        from datetime import timezone
        # Use UTC timezone-aware datetime for comparison
        now_utc = datetime.now(timezone.utc)
        return (self.valid_to - now_utc).days

@dataclass
class SignatureVerification:
    """Results of signature verification."""
    is_valid: bool
    algorithm: str
    hash_algorithm: str
    verification_method: str
    error_message: str = ""
    trust_chain_valid: bool = False
    timestamp_valid: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'is_valid': self.is_valid,
            'algorithm': self.algorithm,
            'hash_algorithm': self.hash_algorithm,
            'verification_method': self.verification_method,
            'error_message': self.error_message,
            'trust_chain_valid': self.trust_chain_valid,
            'timestamp_valid': self.timestamp_valid
        }

@dataclass
class APKSignature:
    """Represents an APK signature with verification details."""
    scheme: SignatureScheme
    algorithm: str
    digest_algorithm: str
    signature_data: bytes
    certificates: List[SigningCertificate] = field(default_factory=list)
    verification: Optional[SignatureVerification] = None
    security_issues: List[str] = field(default_factory=list)
    timestamp: Optional[datetime] = None
    signature_block_size: int = 0
    additional_attributes: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def signature_algorithm(self) -> str:
        """
        Backward compatibility property for signature_algorithm.
        Returns the algorithm attribute.
        """
        return self.algorithm
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'scheme': self.scheme.value,
            'algorithm': self.algorithm,
            'digest_algorithm': self.digest_algorithm,
            'certificates': [cert.to_dict() for cert in self.certificates],
            'verification': self.verification.to_dict() if self.verification else None,
            'security_issues': self.security_issues,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'signature_block_size': self.signature_block_size,
            'additional_attributes': self.additional_attributes
        }
    
    @property
    def is_valid(self) -> bool:
        """Check if signature is valid."""
        return self.verification.is_valid if self.verification else False

@dataclass
class ComplianceAssessment:
    """Results of compliance standard assessment."""
    standard: ComplianceStandard
    compliant: bool
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    score: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'standard': self.standard.value,
            'compliant': self.compliant,
            'issues': self.issues,
            'recommendations': self.recommendations,
            'score': self.score,
            'details': self.details
        }

@dataclass
class SecurityAssessment:
    """Comprehensive security assessment results."""
    overall_score: float
    security_level: CertificateSecurityLevel
    critical_issues: List[str] = field(default_factory=list)
    high_issues: List[str] = field(default_factory=list)
    medium_issues: List[str] = field(default_factory=list)
    low_issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'overall_score': self.overall_score,
            'security_level': self.security_level.name,
            'critical_issues': self.critical_issues,
            'high_issues': self.high_issues,
            'medium_issues': self.medium_issues,
            'low_issues': self.low_issues,
            'recommendations': self.recommendations,
            'risk_factors': self.risk_factors
        }

@dataclass
class APKSigningAnalysisResult:
    """Comprehensive APK signing certificate analysis result."""
    apk_path: str
    package_name: str
    signatures: List[APKSignature] = field(default_factory=list)
    signature_schemes_found: List[SignatureScheme] = field(default_factory=list)
    certificate_chain_valid: bool = False
    digital_signature_valid: bool = False
    security_assessment: Optional[SecurityAssessment] = None
    compliance_assessments: List[ComplianceAssessment] = field(default_factory=list)
    analysis_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    detailed_findings: List[Dict[str, Any]] = field(default_factory=list)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'apk_path': self.apk_path,
            'package_name': self.package_name,
            'signatures': [sig.to_dict() for sig in self.signatures],
            'signature_schemes_found': [scheme.value for scheme in self.signature_schemes_found],
            'certificate_chain_valid': self.certificate_chain_valid,
            'digital_signature_valid': self.digital_signature_valid,
            'security_assessment': self.security_assessment.to_dict() if self.security_assessment else None,
            'compliance_assessments': [comp.to_dict() for comp in self.compliance_assessments],
            'analysis_timestamp': self.analysis_timestamp.isoformat(),
            'detailed_findings': self.detailed_findings,
            'analysis_metadata': self.analysis_metadata
        }
    
    @property
    def overall_security_score(self) -> float:
        """Get overall security score."""
        return self.security_assessment.overall_score if self.security_assessment else 0.0
    
    @property
    def has_critical_issues(self) -> bool:
        """Check if there are critical security issues."""
        if not self.security_assessment:
            return False
        return len(self.security_assessment.critical_issues) > 0
    
    @property
    def total_certificates(self) -> int:
        """Get total number of certificates."""
        total = 0
        for signature in self.signatures:
            total += len(signature.certificates)
        return total

@dataclass
class CertificateAnalysisConfig:
    """Configuration for certificate analysis."""
    verify_certificate_chain: bool = True
    check_revocation_status: bool = True
    validate_trust_anchors: bool = True
    perform_compliance_checks: bool = True
    include_certificate_transparency: bool = True
    enable_ocsp_checking: bool = True
    enable_crl_checking: bool = True
    require_valid_timestamps: bool = True
    minimum_key_size_rsa: int = 2048
    minimum_key_size_ec: int = 256
    allowed_signature_algorithms: List[str] = field(default_factory=lambda: [
        "RSA_PKCS1_SHA256", "RSA_PKCS1_SHA512", "RSA_PSS_SHA256", 
        "RSA_PSS_SHA512", "ECDSA_SHA256", "ECDSA_SHA512"
    ])
    max_certificate_chain_length: int = 5
    certificate_validity_period_days: int = 365
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'verify_certificate_chain': self.verify_certificate_chain,
            'check_revocation_status': self.check_revocation_status,
            'validate_trust_anchors': self.validate_trust_anchors,
            'perform_compliance_checks': self.perform_compliance_checks,
            'include_certificate_transparency': self.include_certificate_transparency,
            'enable_ocsp_checking': self.enable_ocsp_checking,
            'enable_crl_checking': self.enable_crl_checking,
            'require_valid_timestamps': self.require_valid_timestamps,
            'minimum_key_size_rsa': self.minimum_key_size_rsa,
            'minimum_key_size_ec': self.minimum_key_size_ec,
            'allowed_signature_algorithms': self.allowed_signature_algorithms,
            'max_certificate_chain_length': self.max_certificate_chain_length,
            'certificate_validity_period_days': self.certificate_validity_period_days
        }

class CertificateConstants:
    """Constants for certificate analysis."""
    
    # Signature scheme IDs
    APK_SIGNATURE_SCHEME_V2_ID = 0x7109871a
    APK_SIGNATURE_SCHEME_V3_ID = 0xf05368c0
    APK_SIGNATURE_SCHEME_V4_ID = 0x42726577
    
    # Minimum secure key sizes
    MIN_RSA_KEY_SIZE = 2048
    MIN_EC_KEY_SIZE = 256
    MIN_DSA_KEY_SIZE = 2048
    
    # Certificate validity periods
    MAX_CERTIFICATE_VALIDITY_YEARS = 25
    RECOMMENDED_CERTIFICATE_VALIDITY_YEARS = 1
    
    # Hash algorithms
    SECURE_HASH_ALGORITHMS = ['SHA256', 'SHA384', 'SHA512', 'SHA3-256', 'SHA3-384', 'SHA3-512']
    DEPRECATED_HASH_ALGORITHMS = ['MD5', 'SHA1']
    
    # Certificate extensions
    CRITICAL_EXTENSIONS = ['keyUsage', 'basicConstraints', 'certificatePolicies']
    RECOMMENDED_EXTENSIONS = ['subjectKeyIdentifier', 'authorityKeyIdentifier']

class SecurityMetrics:
    """Security metrics and thresholds."""
    
    # Security score weights
    SIGNATURE_VALIDITY_WEIGHT = 0.25
    CERTIFICATE_VALIDITY_WEIGHT = 0.20
    KEY_STRENGTH_WEIGHT = 0.20
    ALGORITHM_STRENGTH_WEIGHT = 0.15
    COMPLIANCE_WEIGHT = 0.10
    TRUST_CHAIN_WEIGHT = 0.10
    
    # Security level thresholds
    CRITICAL_THRESHOLD = 0.3
    HIGH_THRESHOLD = 0.5
    MEDIUM_THRESHOLD = 0.7
    LOW_THRESHOLD = 0.85
    
    # Risk factors
    EXPIRED_CERTIFICATE_RISK = 0.9
    WEAK_KEY_RISK = 0.8
    DEPRECATED_ALGORITHM_RISK = 0.7
    UNTRUSTED_CA_RISK = 0.6
    REVOKED_CERTIFICATE_RISK = 0.95 