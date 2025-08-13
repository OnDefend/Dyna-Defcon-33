"""
APK Signing Certificate Security Assessor

Module for performing comprehensive security assessment of APK signing
certificates and digital signatures.
"""

import logging
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict

from .data_structures import (
    SigningCertificate, APKSignature, SecurityAssessment, ComplianceAssessment,
    CertificateSecurityLevel, ComplianceStandard, CertificateAnalysisConfig,
    SecurityMetrics, CertificateConstants
)

logger = logging.getLogger(__name__)

class SecurityAssessor:
    """
    Comprehensive security assessor for APK signing certificates and signatures.
    
    Evaluates security posture based on multiple factors:
    - Certificate validity and strength
    - Key algorithm and size
    - Signature algorithm strength
    - Certificate chain trust
    - Compliance with security standards
    """
    
    def __init__(self, config: Optional[CertificateAnalysisConfig] = None):
        """Initialize the security assessor."""
        self.config = config or CertificateAnalysisConfig()
        
        logger.debug("Security assessor initialized")
    
    def assess_signature_security(self, signature: APKSignature) -> SecurityAssessment:
        """
        Perform comprehensive security assessment of an APK signature.
        
        Args:
            signature: APK signature to assess
            
        Returns:
            SecurityAssessment with detailed findings
        """
        try:
            # Initialize assessment
            assessment = SecurityAssessment(
                overall_score=0.0,
                security_level=CertificateSecurityLevel.INFO
            )
            
            # Assess signature algorithm strength
            sig_score = self._assess_signature_algorithm(signature, assessment)
            
            # Assess certificates if present
            cert_score = 1.0
            if signature.certificates:
                cert_score = self._assess_certificates(signature.certificates, assessment)
            
            # Assess signature verification status
            verification_score = self._assess_verification_status(signature, assessment)
            
            # Calculate overall score using weighted factors
            assessment.overall_score = (
                sig_score * SecurityMetrics.ALGORITHM_STRENGTH_WEIGHT +
                cert_score * SecurityMetrics.CERTIFICATE_VALIDITY_WEIGHT +
                verification_score * SecurityMetrics.SIGNATURE_VALIDITY_WEIGHT
            )
            
            # Determine security level based on score
            assessment.security_level = self._determine_security_level(assessment.overall_score)
            
            # Generate recommendations
            self._generate_security_recommendations(assessment)
            
            logger.debug(f"Signature security assessment completed: {assessment.overall_score:.3f}")
            return assessment
            
        except Exception as e:
            logger.error(f"Security assessment failed: {e}")
            return SecurityAssessment(
                overall_score=0.0,
                security_level=CertificateSecurityLevel.CRITICAL,
                critical_issues=[f"Security assessment failed: {e}"]
            )
    
    def assess_certificate_security(self, certificate: SigningCertificate) -> SecurityAssessment:
        """
        Perform security assessment of a single certificate.
        
        Args:
            certificate: Certificate to assess
            
        Returns:
            SecurityAssessment with detailed findings
        """
        try:
            assessment = SecurityAssessment(
                overall_score=0.0,
                security_level=CertificateSecurityLevel.INFO
            )
            
            # Check certificate validity
            validity_score = self._assess_certificate_validity(certificate, assessment)
            
            # Check key strength
            key_score = self._assess_key_strength(certificate, assessment)
            
            # Check signature algorithm
            sig_algo_score = self._assess_certificate_signature_algorithm(certificate, assessment)
            
            # Check certificate extensions
            extension_score = self._assess_certificate_extensions(certificate, assessment)
            
            # Calculate overall score
            assessment.overall_score = (
                validity_score * 0.3 +
                key_score * 0.3 +
                sig_algo_score * 0.2 +
                extension_score * 0.2
            )
            
            # Determine security level
            assessment.security_level = self._determine_security_level(assessment.overall_score)
            
            # Generate recommendations
            self._generate_certificate_recommendations(certificate, assessment)
            
            logger.debug(f"Certificate security assessment completed: {assessment.overall_score:.3f}")
            return assessment
            
        except Exception as e:
            logger.error(f"Certificate security assessment failed: {e}")
            return SecurityAssessment(
                overall_score=0.0,
                security_level=CertificateSecurityLevel.CRITICAL,
                critical_issues=[f"Certificate assessment failed: {e}"]
            )
    
    def assess_compliance(self, signatures: List[APKSignature]) -> List[ComplianceAssessment]:
        """
        Assess compliance with various security standards.
        
        Args:
            signatures: List of APK signatures to assess
            
        Returns:
            List of compliance assessments
        """
        compliance_assessments = []
        
        try:
            # Android signing requirements
            android_compliance = self._assess_android_compliance(signatures)
            compliance_assessments.append(android_compliance)
            
            # NIST SP 800-57 compliance
            nist_compliance = self._assess_nist_compliance(signatures)
            compliance_assessments.append(nist_compliance)
            
            # FIPS 186-4 compliance
            fips_compliance = self._assess_fips_compliance(signatures)
            compliance_assessments.append(fips_compliance)
            
            # X.509 RFC 5280 compliance
            x509_compliance = self._assess_x509_compliance(signatures)
            compliance_assessments.append(x509_compliance)
            
            logger.debug(f"Compliance assessment completed: {len(compliance_assessments)} standards")
            return compliance_assessments
            
        except Exception as e:
            logger.error(f"Compliance assessment failed: {e}")
            return [ComplianceAssessment(
                standard=ComplianceStandard.ANDROID_SIGNING,
                compliant=False,
                issues=[f"Compliance assessment failed: {e}"]
            )]
    
    def _assess_signature_algorithm(self, signature: APKSignature, assessment: SecurityAssessment) -> float:
        """Assess signature algorithm strength."""
        score = 1.0
        
        # Check algorithm strength
        algorithm = signature.algorithm.upper()
        
        # Deprecated algorithms
        if 'MD5' in algorithm:
            assessment.critical_issues.append("MD5 signature algorithm is cryptographically broken")
            score = 0.0
        elif 'SHA1' in algorithm:
            assessment.high_issues.append("SHA-1 signature algorithm is deprecated")
            score = 0.3
        
        # Weak algorithms
        elif 'SHA224' in algorithm:
            assessment.medium_issues.append("SHA-224 provides limited security margin")
            score = 0.6
        
        # Strong algorithms
        elif any(strong in algorithm for strong in ['SHA256', 'SHA384', 'SHA512', 'SHA3']):
            score = 1.0
        else:
            assessment.medium_issues.append(f"Unknown signature algorithm: {algorithm}")
            score = 0.5
        
        # Check digest algorithm separately
        digest_algo = signature.digest_algorithm.upper()
        if 'MD5' in digest_algo:
            assessment.critical_issues.append("MD5 digest algorithm is cryptographically broken")
            score = min(score, 0.0)
        elif 'SHA1' in digest_algo:
            assessment.high_issues.append("SHA-1 digest algorithm is deprecated")
            score = min(score, 0.3)
        
        return score
    
    def _assess_certificates(self, certificates: List[SigningCertificate], assessment: SecurityAssessment) -> float:
        """Assess certificate security."""
        if not certificates:
            assessment.critical_issues.append("No certificates found in signature")
            return 0.0
        
        scores = []
        
        for cert in certificates:
            cert_assessment = self.assess_certificate_security(cert)
            scores.append(cert_assessment.overall_score)
            
            # Merge issues
            assessment.critical_issues.extend(cert_assessment.critical_issues)
            assessment.high_issues.extend(cert_assessment.high_issues)
            assessment.medium_issues.extend(cert_assessment.medium_issues)
            assessment.low_issues.extend(cert_assessment.low_issues)
        
        # Return average score of all certificates
        return sum(scores) / len(scores) if scores else 0.0
    
    def _assess_verification_status(self, signature: APKSignature, assessment: SecurityAssessment) -> float:
        """Assess signature verification status."""
        if not signature.verification:
            assessment.critical_issues.append("Signature verification not performed")
            return 0.0
        
        if not signature.verification.is_valid:
            assessment.critical_issues.append(f"Signature verification failed: {signature.verification.error_message}")
            return 0.0
        
        score = 1.0
        
        # Check trust chain
        if not signature.verification.trust_chain_valid:
            assessment.high_issues.append("Certificate trust chain validation failed")
            score *= 0.7
        
        # Check timestamp
        if signature.verification.timestamp_valid is False:
            assessment.medium_issues.append("Timestamp verification failed")
            score *= 0.9
        
        return score
    
    def _assess_certificate_validity(self, certificate: SigningCertificate, assessment: SecurityAssessment) -> float:
        """Assess certificate validity period."""
        score = 1.0
        
        # Check if expired
        if certificate.is_expired():
            assessment.critical_issues.append(f"Certificate expired on {certificate.valid_to}")
            return 0.0
        
        # Check validity period length
        validity_days = (certificate.valid_to - certificate.valid_from).days
        max_validity = CertificateConstants.MAX_CERTIFICATE_VALIDITY_YEARS * 365
        
        if validity_days > max_validity:
            assessment.medium_issues.append(f"Certificate validity period ({validity_days} days) exceeds recommended maximum")
            score *= 0.8
        
        # Check how soon it expires
        days_until_expiry = certificate.days_until_expiry()
        if days_until_expiry < 30:
            assessment.high_issues.append(f"Certificate expires in {days_until_expiry} days")
            score *= 0.7
        elif days_until_expiry < 90:
            assessment.medium_issues.append(f"Certificate expires in {days_until_expiry} days")
            score *= 0.9
        
        return score
    
    def _assess_key_strength(self, certificate: SigningCertificate, assessment: SecurityAssessment) -> float:
        """Assess cryptographic key strength."""
        score = 1.0
        
        algorithm = certificate.key_algorithm.upper()
        key_size = certificate.key_size
        
        if algorithm == "RSA":
            if key_size < 1024:
                assessment.critical_issues.append(f"RSA key size {key_size} is critically weak")
                score = 0.0
            elif key_size < 2048:
                assessment.high_issues.append(f"RSA key size {key_size} is below current recommendations")
                score = 0.4
            elif key_size < 3072:
                assessment.low_issues.append(f"RSA key size {key_size} meets minimum requirements")
                score = 0.8
            else:
                score = 1.0
                
        elif algorithm == "EC":
            if key_size < 160:
                assessment.critical_issues.append(f"EC key size {key_size} is critically weak")
                score = 0.0
            elif key_size < 256:
                assessment.high_issues.append(f"EC key size {key_size} is below current recommendations")
                score = 0.4
            elif key_size < 384:
                score = 0.8
            else:
                score = 1.0
                
        elif algorithm == "DSA":
            if key_size < 1024:
                assessment.critical_issues.append(f"DSA key size {key_size} is critically weak")
                score = 0.0
            elif key_size < 2048:
                assessment.high_issues.append(f"DSA key size {key_size} is below current recommendations")
                score = 0.4
            else:
                score = 0.8  # DSA is generally less preferred than RSA/EC
        else:
            assessment.medium_issues.append(f"Unknown key algorithm: {algorithm}")
            score = 0.5
        
        return score
    
    def _assess_certificate_signature_algorithm(self, certificate: SigningCertificate, assessment: SecurityAssessment) -> float:
        """Assess certificate's signature algorithm."""
        algorithm = certificate.signature_algorithm.upper()
        
        # Map common algorithm names
        if 'MD5' in algorithm:
            assessment.critical_issues.append("Certificate signed with MD5 (cryptographically broken)")
            return 0.0
        elif 'SHA1' in algorithm:
            assessment.high_issues.append("Certificate signed with SHA-1 (deprecated)")
            return 0.3
        elif any(secure in algorithm for secure in ['SHA256', 'SHA384', 'SHA512']):
            return 1.0
        else:
            assessment.medium_issues.append(f"Unknown certificate signature algorithm: {algorithm}")
            return 0.5
    
    def _assess_certificate_extensions(self, certificate: SigningCertificate, assessment: SecurityAssessment) -> float:
        """Assess certificate extensions."""
        score = 1.0
        
        # Check for critical extensions
        extension_oids = [ext.oid for ext in certificate.extensions]
        
        # Basic constraints should be present for CA certificates
        if certificate.is_self_signed:
            basic_constraints_present = any('basicConstraints' in ext.description for ext in certificate.extensions)
            if not basic_constraints_present:
                assessment.medium_issues.append("Self-signed certificate missing basic constraints extension")
                score *= 0.9
        
        # Key usage should be present
        if not certificate.key_usage:
            assessment.low_issues.append("Certificate missing key usage extension")
            score *= 0.95
        
        # Check for appropriate key usage
        if 'Digital Signature' not in certificate.key_usage:
            assessment.medium_issues.append("Certificate not authorized for digital signatures")
            score *= 0.8
        
        return score
    
    def _determine_security_level(self, score: float) -> CertificateSecurityLevel:
        """Determine security level based on score."""
        if score <= SecurityMetrics.CRITICAL_THRESHOLD:
            return CertificateSecurityLevel.CRITICAL
        elif score <= SecurityMetrics.HIGH_THRESHOLD:
            return CertificateSecurityLevel.HIGH
        elif score <= SecurityMetrics.MEDIUM_THRESHOLD:
            return CertificateSecurityLevel.MEDIUM
        elif score <= SecurityMetrics.LOW_THRESHOLD:
            return CertificateSecurityLevel.LOW
        else:
            return CertificateSecurityLevel.INFO
    
    def _generate_security_recommendations(self, assessment: SecurityAssessment) -> None:
        """Generate security recommendations based on assessment."""
        recommendations = []
        
        # Critical issues
        if assessment.critical_issues:
            recommendations.append("URGENT: Address critical security issues immediately")
            recommendations.append("Consider re-signing the APK with stronger cryptographic methods")
        
        # High priority issues
        if assessment.high_issues:
            recommendations.append("Update to stronger cryptographic algorithms")
            recommendations.append("Replace deprecated signature methods")
        
        # Medium priority issues
        if assessment.medium_issues:
            recommendations.append("Consider upgrading certificate parameters")
            recommendations.append("Review certificate validity periods")
        
        # General recommendations
        if assessment.overall_score < 0.8:
            recommendations.append("Implement comprehensive certificate management practices")
            recommendations.append("Regular security audits of signing infrastructure")
        
        assessment.recommendations = recommendations
    
    def _generate_certificate_recommendations(self, certificate: SigningCertificate, assessment: SecurityAssessment) -> None:
        """Generate certificate-specific recommendations."""
        recommendations = []
        
        # Expiry recommendations
        if certificate.is_expired():
            recommendations.append("Replace expired certificate immediately")
        elif certificate.days_until_expiry() < 90:
            recommendations.append("Renew certificate before expiration")
        
        # Key strength recommendations
        if certificate.key_algorithm == "RSA" and certificate.key_size < 2048:
            recommendations.append("Upgrade to RSA-2048 or higher")
        elif certificate.key_algorithm == "EC" and certificate.key_size < 256:
            recommendations.append("Upgrade to P-256 curve or higher")
        
        # Algorithm recommendations
        if any(weak in certificate.signature_algorithm.upper() for weak in ['MD5', 'SHA1']):
            recommendations.append("Use SHA-256 or stronger signature algorithms")
        
        # Extension recommendations
        if not certificate.key_usage:
            recommendations.append("Include appropriate key usage extensions")
        
        assessment.recommendations = recommendations
    
    def _assess_android_compliance(self, signatures: List[APKSignature]) -> ComplianceAssessment:
        """Assess compliance with Android signing requirements."""
        assessment = ComplianceAssessment(
            standard=ComplianceStandard.ANDROID_SIGNING,
            compliant=True,
            score=1.0
        )
        
        try:
            if not signatures:
                assessment.compliant = False
                assessment.issues.append("No signatures found")
                assessment.score = 0.0
                return assessment
            
            # Check signature scheme requirements
            has_v1 = any(sig.scheme.value == "v1_jar" for sig in signatures)
            has_v2_or_higher = any(sig.scheme.value in ["v2_apk", "v3_key_rotation", "v4_incremental"] for sig in signatures)
            
            if not has_v2_or_higher:
                assessment.issues.append("Missing v2+ signature scheme for enhanced security")
                assessment.score *= 0.8
            
            # Check certificate requirements
            for signature in signatures:
                if not signature.certificates:
                    assessment.compliant = False
                    assessment.issues.append("Signature missing certificates")
                    assessment.score = 0.0
                    break
                
                # Check certificate validity
                for cert in signature.certificates:
                    if cert.is_expired():
                        assessment.compliant = False
                        assessment.issues.append("Certificate is expired")
                        assessment.score = 0.0
                        break
            
            # Generate recommendations
            if not assessment.compliant:
                assessment.recommendations.append("Ensure all signatures have valid certificates")
            if not has_v2_or_higher:
                assessment.recommendations.append("Add v2 or higher signature scheme")
            
            return assessment
            
        except Exception as e:
            logger.error(f"Android compliance assessment failed: {e}")
            assessment.compliant = False
            assessment.issues.append(f"Assessment failed: {e}")
            assessment.score = 0.0
            return assessment
    
    def _assess_nist_compliance(self, signatures: List[APKSignature]) -> ComplianceAssessment:
        """Assess compliance with NIST SP 800-57."""
        assessment = ComplianceAssessment(
            standard=ComplianceStandard.NIST_SP_800_57,
            compliant=True,
            score=1.0
        )
        
        try:
            for signature in signatures:
                for cert in signature.certificates:
                    # Check key sizes per NIST recommendations
                    if cert.key_algorithm == "RSA" and cert.key_size < 2048:
                        assessment.compliant = False
                        assessment.issues.append(f"RSA key size {cert.key_size} below NIST minimum")
                        assessment.score *= 0.5
                    elif cert.key_algorithm == "EC" and cert.key_size < 224:
                        assessment.compliant = False
                        assessment.issues.append(f"EC key size {cert.key_size} below NIST minimum")
                        assessment.score *= 0.5
                    
                    # Check signature algorithms
                    if any(weak in cert.signature_algorithm.upper() for weak in ['MD5', 'SHA1']):
                        assessment.compliant = False
                        assessment.issues.append("Weak signature algorithm not NIST compliant")
                        assessment.score *= 0.3
            
            return assessment
            
        except Exception as e:
            logger.error(f"NIST compliance assessment failed: {e}")
            assessment.compliant = False
            assessment.issues.append(f"Assessment failed: {e}")
            return assessment
    
    def _assess_fips_compliance(self, signatures: List[APKSignature]) -> ComplianceAssessment:
        """Assess compliance with FIPS 186-4."""
        assessment = ComplianceAssessment(
            standard=ComplianceStandard.FIPS_186_4,
            compliant=True,
            score=1.0
        )
        
        try:
            # FIPS 186-4 specifies approved signature algorithms
            approved_algorithms = ['RSA', 'ECDSA', 'DSA']
            approved_hashes = ['SHA-224', 'SHA-256', 'SHA-384', 'SHA-512']
            
            for signature in signatures:
                # Check signature algorithm
                algo_approved = any(approved in signature.algorithm.upper() for approved in approved_algorithms)
                if not algo_approved:
                    assessment.compliant = False
                    assessment.issues.append(f"Signature algorithm {signature.algorithm} not FIPS approved")
                    assessment.score *= 0.5
                
                # Check hash algorithm
                hash_approved = any(approved in signature.digest_algorithm.upper() for approved in approved_hashes)
                if not hash_approved:
                    assessment.compliant = False
                    assessment.issues.append(f"Hash algorithm {signature.digest_algorithm} not FIPS approved")
                    assessment.score *= 0.5
            
            return assessment
            
        except Exception as e:
            logger.error(f"FIPS compliance assessment failed: {e}")
            assessment.compliant = False
            assessment.issues.append(f"Assessment failed: {e}")
            return assessment
    
    def _assess_x509_compliance(self, signatures: List[APKSignature]) -> ComplianceAssessment:
        """Assess compliance with X.509 RFC 5280."""
        assessment = ComplianceAssessment(
            standard=ComplianceStandard.X509_RFC_5280,
            compliant=True,
            score=1.0
        )
        
        try:
            for signature in signatures:
                for cert in signature.certificates:
                    # Check required certificate fields
                    if not cert.subject or not cert.issuer:
                        assessment.compliant = False
                        assessment.issues.append("Certificate missing required subject/issuer")
                        assessment.score *= 0.7
                    
                    if not cert.serial_number:
                        assessment.compliant = False
                        assessment.issues.append("Certificate missing serial number")
                        assessment.score *= 0.8
                    
                    # Check validity period format
                    if not cert.valid_from or not cert.valid_to:
                        assessment.compliant = False
                        assessment.issues.append("Certificate missing validity period")
                        assessment.score *= 0.7
                    
                    # Check for recommended extensions
                    has_key_usage = bool(cert.key_usage)
                    if not has_key_usage:
                        assessment.issues.append("Certificate missing key usage extension")
                        assessment.score *= 0.9
            
            return assessment
            
        except Exception as e:
            logger.error(f"X.509 compliance assessment failed: {e}")
            assessment.compliant = False
            assessment.issues.append(f"Assessment failed: {e}")
            return assessment 