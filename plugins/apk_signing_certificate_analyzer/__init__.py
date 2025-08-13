"""
APK Signing Certificate Analyzer - Main Orchestration Module

This module coordinates all components of the APK signing certificate analyzer
to provide comprehensive analysis of APK signing certificates and digital signatures.
"""

import logging
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any

from rich.text import Text

from .data_structures import (
    APKSigningAnalysisResult, APKSignature, SigningCertificate,
    SecurityAssessment, ComplianceAssessment, CertificateAnalysisConfig,
    SignatureScheme, CertificateSecurityLevel
)
from .certificate_parser import CertificateParser
from .signature_verifier import SignatureVerifier
from .security_assessor import SecurityAssessor
from .formatter import CertificateAnalysisFormatter

# Import unified deduplication framework
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)

logger = logging.getLogger(__name__)

# Plugin metadata
PLUGIN_METADATA = {
    "name": "APK Signing Certificate Analyzer",
    "description": "Comprehensive analysis of APK signing certificates and digital signatures with security assessment",
    "version": "2.0.0",
    "author": "AODS Development Team",
    "category": "CERTIFICATE_ANALYSIS",
    "priority": "HIGH",
    "timeout": 90,
    "mode": "comprehensive",
    "requires_device": False,
    "requires_network": False,
    "invasive": False,
    "execution_time_estimate": 60,
    "dependencies": ["openssl"],
    "modular_architecture": True,
    "components": [
        "certificate_parser",
        "signature_verifier",
        "security_assessor",
        "formatter"
    ],
    "security_controls": ["MASVS-CRYPTO-1", "MASVS-CRYPTO-2"],
    "owasp_categories": ["M5", "M10"]
}

class APKSigningCertificateAnalyzer:
    """
    Main analyzer class that orchestrates comprehensive APK signing certificate analysis.
    
    This class coordinates all analysis components to provide:
    - Certificate extraction from all signature schemes (v1-v4)
    - Digital signature verification
    - Certificate chain validation
    - Security assessment and scoring
    - Compliance checking against standards
    - reporting
    """
    
    def __init__(self, apk_ctx, config: Optional[CertificateAnalysisConfig] = None):
        """
        Initialize the APK signing certificate analyzer.
        
        Args:
            apk_ctx: APK context with file path and package information
            config: Optional analysis configuration
        """
        self.apk_ctx = apk_ctx
        self.config = config or CertificateAnalysisConfig()
        
        # Initialize analysis components
        self.certificate_parser = CertificateParser()
        self.signature_verifier = SignatureVerifier(self.config)
        self.security_assessor = SecurityAssessor(self.config)
        self.formatter = CertificateAnalysisFormatter()
        
        # Temporary directory for analysis
        self.temp_dir = None
        
        logger.debug(f"APK signing certificate analyzer initialized for {apk_ctx.apk_path}")
    
    def analyze_apk_signing_certificates(self) -> APKSigningAnalysisResult:
        """
        Perform comprehensive APK signing certificate analysis.
        
        Returns:
            Complete analysis result with certificates, signatures, and assessments
        """
        try:
            # Initialize result
            result = APKSigningAnalysisResult(
                apk_path=self.apk_ctx.apk_path,
                package_name=getattr(self.apk_ctx, 'package_name', 'unknown')
            )
            
            # Create temporary working directory
            self._create_temp_dir()
            
            logger.debug("Starting APK signing certificate analysis")
            
            # Step 1: Extract certificates from all signature schemes
            signatures = self._extract_all_signatures()
            result.signatures = signatures
            result.signature_schemes_found = [sig.scheme for sig in signatures]
            
            if not signatures:
                logger.warning("No signatures found in APK")
                result.detailed_findings.append({
                    'type': 'warning',
                    'message': 'No digital signatures found in APK',
                    'impact': 'APK authenticity and integrity cannot be verified'
                })
                return result
            
            # Step 2: Verify digital signatures
            self._verify_signatures(signatures, result)
            
            # Step 3: Validate certificate chains
            self._validate_certificate_chains(signatures, result)
            
            # Step 4: Perform security assessment
            if signatures:
                result.security_assessment = self._perform_security_assessment(signatures)
            
            # Step 5: Assess compliance with standards
            if self.config.perform_compliance_checks:
                result.compliance_assessments = self._assess_compliance(signatures)
            
            # Step 6: Generate detailed findings
            self._generate_detailed_findings(result)
            
            # Step 7: Calculate overall scores and status
            self._calculate_overall_status(result)
            
            logger.debug(f"APK signing certificate analysis completed. Overall security score: {result.overall_security_score:.3f}")
            
            return result
            
        except Exception as e:
            logger.error(f"APK signing certificate analysis failed: {e}")
            
            # Return error result
            error_result = APKSigningAnalysisResult(
                apk_path=self.apk_ctx.apk_path,
                package_name=getattr(self.apk_ctx, 'package_name', 'unknown')
            )
            error_result.detailed_findings.append({
                'type': 'error',
                'message': f'Analysis failed: {e}',
                'impact': 'Unable to assess APK signing security'
            })
            
            return error_result
            
        finally:
            # Cleanup temporary directory
            self._cleanup_temp_dir()
    
    def _extract_all_signatures(self) -> List[APKSignature]:
        """Extract signatures from all supported schemes."""
        signatures = []
        
        try:
            # Extract v1 (JAR) signatures
            v1_certificates = self.certificate_parser.extract_v1_jar_certificates(self.apk_ctx.apk_path)
            if v1_certificates:
                v1_signature = APKSignature(
                    scheme=SignatureScheme.V1_JAR,
                    algorithm="PKCS#7",
                    digest_algorithm="SHA-1",  # Default for v1
                    signature_data=b"",  # Placeholder
                    certificates=v1_certificates
                )
                signatures.append(v1_signature)
                logger.debug(f"Found v1 signature with {len(v1_certificates)} certificates")
            
            # Extract v2/v3/v4 signatures
            scheme_certificates = self.certificate_parser.extract_v2_v3_v4_certificates(self.apk_ctx.apk_path)
            for scheme, certificates in scheme_certificates.items():
                if certificates:
                    signature = APKSignature(
                        scheme=scheme,
                        algorithm=self._determine_signature_algorithm(scheme),
                        digest_algorithm="SHA-256",  # Default for v2+
                        signature_data=b"",  # Placeholder
                        certificates=certificates
                    )
                    signatures.append(signature)
                    logger.debug(f"Found {scheme.value} signature with {len(certificates)} certificates")
            
            logger.debug(f"Extracted {len(signatures)} signatures from APK")
            return signatures
            
        except Exception as e:
            logger.error(f"Failed to extract signatures: {e}")
            return []
    
    def _verify_signatures(self, signatures: List[APKSignature], result: APKSigningAnalysisResult) -> None:
        """Verify all digital signatures."""
        try:
            # Read APK data for verification
            with open(self.apk_ctx.apk_path, 'rb') as f:
                apk_data = f.read()
            
            valid_signatures = 0
            
            for signature in signatures:
                logger.debug(f"Verifying {signature.scheme.value} signature")
                
                # Verify signature
                verification = self.signature_verifier.verify_apk_signature(signature, apk_data)
                signature.verification = verification
                
                if verification.is_valid:
                    valid_signatures += 1
                    logger.debug(f"{signature.scheme.value} signature verified successfully")
                else:
                    logger.warning(f"{signature.scheme.value} signature verification failed: {verification.error_message}")
            
            # Update overall signature validity
            result.digital_signature_valid = valid_signatures > 0
            
            result.analysis_metadata['total_signatures'] = len(signatures)
            result.analysis_metadata['valid_signatures'] = valid_signatures
            
            logger.debug(f"Signature verification completed: {valid_signatures}/{len(signatures)} valid")
            
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            result.digital_signature_valid = False
    
    def _validate_certificate_chains(self, signatures: List[APKSignature], result: APKSigningAnalysisResult) -> None:
        """Validate certificate chains for all signatures."""
        try:
            valid_chains = 0
            total_chains = 0
            
            for signature in signatures:
                if signature.certificates:
                    total_chains += 1
                    
                    # Validate certificate chain
                    chain_valid = self.signature_verifier.verify_certificate_chain(signature.certificates)
                    
                    if chain_valid:
                        valid_chains += 1
                        logger.debug(f"Certificate chain valid for {signature.scheme.value}")
                    else:
                        logger.info(f"Certificate chain validation skipped for {signature.scheme.value} (common for debug/test APKs)")
                    
                    # Check individual certificate revocation status
                    if self.config.check_revocation_status:
                        for cert in signature.certificates:
                            revoked = not self.signature_verifier.check_certificate_revocation(cert)
                            if revoked:
                                cert.security_issues.append("Certificate may be revoked")
                                logger.warning(f"Certificate {cert.serial_number} may be revoked")
            
            # Update overall chain validity
            result.certificate_chain_valid = valid_chains > 0 and valid_chains == total_chains
            
            result.analysis_metadata['total_certificate_chains'] = total_chains
            result.analysis_metadata['valid_certificate_chains'] = valid_chains
            
            logger.debug(f"Certificate chain validation completed: {valid_chains}/{total_chains} valid")
            
        except Exception as e:
            logger.error(f"Certificate chain validation failed: {e}")
            result.certificate_chain_valid = False
    
    def _perform_security_assessment(self, signatures: List[APKSignature]) -> SecurityAssessment:
        """Perform comprehensive security assessment."""
        try:
            # Assess security for all signatures
            all_assessments = []
            
            for signature in signatures:
                assessment = self.security_assessor.assess_signature_security(signature)
                all_assessments.append(assessment)
                logger.debug(f"Security assessment for {signature.scheme.value}: {assessment.overall_score:.3f}")
            
            # Combine assessments into overall security assessment
            if all_assessments:
                overall_assessment = self._combine_security_assessments(all_assessments)
                logger.debug(f"Overall security assessment completed: {overall_assessment.overall_score:.3f}")
                return overall_assessment
            else:
                return SecurityAssessment(
                    overall_score=0.0,
                    security_level=CertificateSecurityLevel.CRITICAL,
                    critical_issues=["No signatures found for security assessment"]
                )
                
        except Exception as e:
            logger.error(f"Security assessment failed: {e}")
            return SecurityAssessment(
                overall_score=0.0,
                security_level=CertificateSecurityLevel.CRITICAL,
                critical_issues=[f"Security assessment failed: {e}"]
            )
    
    def _assess_compliance(self, signatures: List[APKSignature]) -> List[ComplianceAssessment]:
        """Assess compliance with security standards."""
        try:
            compliance_assessments = self.security_assessor.assess_compliance(signatures)
            
            compliance_summary = {}
            for assessment in compliance_assessments:
                compliance_summary[assessment.standard.value] = assessment.compliant
            
            logger.debug(f"Compliance assessment completed: {compliance_summary}")
            return compliance_assessments
            
        except Exception as e:
            logger.error(f"Compliance assessment failed: {e}")
            return []
    
    def _generate_detailed_findings(self, result: APKSigningAnalysisResult) -> None:
        """Generate detailed findings for the analysis."""
        try:
            findings = []
            
            # Signature findings
            for i, signature in enumerate(result.signatures):
                finding = {
                    'type': 'signature',
                    'id': f'signature_{i+1}',
                    'scheme': signature.scheme.value,
                    'algorithm': signature.algorithm,
                    'valid': signature.is_valid,
                    'certificate_count': len(signature.certificates),
                    'issues': signature.security_issues
                }
                findings.append(finding)
                
                # Certificate findings
                for j, cert in enumerate(signature.certificates):
                    cert_finding = {
                        'type': 'certificate',
                        'id': f'certificate_{i+1}_{j+1}',
                        'subject': cert.subject,
                        'issuer': cert.issuer,
                        'expired': cert.is_expired(),
                        'key_algorithm': cert.key_algorithm,
                        'key_size': cert.key_size,
                        'security_level': cert.security_level.name,
                        'issues': cert.security_issues
                    }
                    findings.append(cert_finding)
            
            # Security assessment findings
            if result.security_assessment:
                security_finding = {
                    'type': 'security_assessment',
                    'overall_score': result.security_assessment.overall_score,
                    'security_level': result.security_assessment.security_level.name,
                    'critical_issues': len(result.security_assessment.critical_issues),
                    'high_issues': len(result.security_assessment.high_issues),
                    'medium_issues': len(result.security_assessment.medium_issues),
                    'low_issues': len(result.security_assessment.low_issues)
                }
                findings.append(security_finding)
            
            # Compliance findings
            for assessment in result.compliance_assessments:
                compliance_finding = {
                    'type': 'compliance',
                    'standard': assessment.standard.value,
                    'compliant': assessment.compliant,
                    'score': assessment.score,
                    'issues': len(assessment.issues)
                }
                findings.append(compliance_finding)
            
            result.detailed_findings = findings
            logger.debug(f"Generated {len(findings)} detailed findings")
            
        except Exception as e:
            logger.error(f"Failed to generate detailed findings: {e}")
    
    def _calculate_overall_status(self, result: APKSigningAnalysisResult) -> None:
        """Calculate overall analysis status and metadata."""
        try:
            # Update analysis metadata
            result.analysis_metadata.update({
                'analyzer_version': '1.0.0',
                'analysis_configuration': self.config.to_dict(),
                'total_signatures': len(result.signatures),
                'signature_schemes': [scheme.value for scheme in result.signature_schemes_found],
                'total_certificates': result.total_certificates,
                'has_critical_issues': result.has_critical_issues
            })
            
            logger.debug("Overall status calculation completed")
            
        except Exception as e:
            logger.error(f"Failed to calculate overall status: {e}")
    
    def _combine_security_assessments(self, assessments: List[SecurityAssessment]) -> SecurityAssessment:
        """Combine multiple security assessments into one overall assessment."""
        if not assessments:
            return SecurityAssessment(
                overall_score=0.0,
                security_level=CertificateSecurityLevel.CRITICAL
            )
        
        # Calculate weighted average score
        total_score = sum(assessment.overall_score for assessment in assessments)
        overall_score = total_score / len(assessments)
        
        # Combine all issues
        combined_assessment = SecurityAssessment(
            overall_score=overall_score,
            security_level=CertificateSecurityLevel.INFO
        )
        
        for assessment in assessments:
            combined_assessment.critical_issues.extend(assessment.critical_issues)
            combined_assessment.high_issues.extend(assessment.high_issues)
            combined_assessment.medium_issues.extend(assessment.medium_issues)
            combined_assessment.low_issues.extend(assessment.low_issues)
            combined_assessment.recommendations.extend(assessment.recommendations)
            combined_assessment.risk_factors.extend(assessment.risk_factors)
        
        # Remove duplicates
        combined_assessment.critical_issues = list(set(combined_assessment.critical_issues))
        combined_assessment.high_issues = list(set(combined_assessment.high_issues))
        combined_assessment.medium_issues = list(set(combined_assessment.medium_issues))
        combined_assessment.low_issues = list(set(combined_assessment.low_issues))
        combined_assessment.recommendations = list(set(combined_assessment.recommendations))
        combined_assessment.risk_factors = list(set(combined_assessment.risk_factors))
        
        # Determine overall security level based on worst issues
        if combined_assessment.critical_issues:
            combined_assessment.security_level = CertificateSecurityLevel.CRITICAL
        elif combined_assessment.high_issues:
            combined_assessment.security_level = CertificateSecurityLevel.HIGH
        elif combined_assessment.medium_issues:
            combined_assessment.security_level = CertificateSecurityLevel.MEDIUM
        elif combined_assessment.low_issues:
            combined_assessment.security_level = CertificateSecurityLevel.LOW
        else:
            combined_assessment.security_level = CertificateSecurityLevel.INFO
        
        return combined_assessment
    
    def _determine_signature_algorithm(self, scheme: SignatureScheme) -> str:
        """Determine signature algorithm based on scheme."""
        algorithm_map = {
            SignatureScheme.V1_JAR: "PKCS#7",
            SignatureScheme.V2_APK: "RSA-PSS",
            SignatureScheme.V3_KEY_ROTATION: "RSA-PSS",
            SignatureScheme.V4_INCREMENTAL: "RSA-PSS"
        }
        return algorithm_map.get(scheme, "Unknown")
    
    def _create_temp_dir(self) -> None:
        """Create temporary directory for analysis."""
        try:
            self.temp_dir = tempfile.mkdtemp(prefix="apk_signing_analysis_")
            logger.debug(f"Created temporary directory: {self.temp_dir}")
        except Exception as e:
            logger.warning(f"Failed to create temporary directory: {e}")
            self.temp_dir = None
    
    def _cleanup_temp_dir(self) -> None:
        """Clean up temporary directory."""
        if self.temp_dir and Path(self.temp_dir).exists():
            try:
                shutil.rmtree(self.temp_dir)
                logger.debug(f"Cleaned up temporary directory: {self.temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup temporary directory: {e}")

def run(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Main entry point for the APK signing certificate analyzer plugin.
    
    Args:
        apk_ctx: APK context with file path and package information
        
    Returns:
        Tuple of (analysis_type, formatted_results)
    """
    try:
        logger.debug(f"Starting APK signing certificate analysis for {apk_ctx.apk_path}")
        
        # Create analyzer with default configuration
        analyzer = APKSigningCertificateAnalyzer(apk_ctx)
        
        # Perform analysis
        result = analyzer.analyze_apk_signing_certificates()
        
        # Format results
        formatted_output = analyzer.formatter.format_analysis_result(result)
        
        logger.debug("APK signing certificate analysis completed successfully")
        return "APK Signing Certificate Analysis", formatted_output
        
    except Exception as e:
        logger.error(f"APK signing certificate analysis failed: {e}")
        error_text = Text()
        error_text.append(f"APK Signing Certificate Analysis Failed: {e}", style="red")
        return "APK Signing Certificate Analysis", error_text

def run_plugin(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """Plugin interface wrapper."""
    return run(apk_ctx) 