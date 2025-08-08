#!/usr/bin/env python3

"""
Advanced Certificate and PKI Analyzer for Cryptography Tests

This module provides comprehensive analysis of certificate handling, PKI implementation,
and advanced certificate security features in Android applications.

Features:
- Certificate chain validation analysis
- Certificate pinning implementation assessment
- OCSP (Online Certificate Status Protocol) validation
- Certificate transparency log verification
- Public key infrastructure security assessment
- Certificate authority trust validation
- Certificate lifecycle management
- Advanced PKI security analysis
"""

import re
import logging
import base64
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class CertificateChainAssessment:
    """Certificate chain validation assessment."""
    chain_validation_implemented: bool = False
    chain_validation_bypassed: bool = False
    custom_ca_validation: bool = False
    root_ca_validation: bool = False
    intermediate_ca_handling: bool = False
    chain_validation_vulnerabilities: List[str] = field(default_factory=list)
    chain_depth_verification: bool = False
    certificate_path_constraints: bool = False

@dataclass
class CertificatePinningAssessment:
    """Certificate pinning implementation assessment."""
    pinning_implemented: bool = False
    pinning_methods: List[str] = field(default_factory=list)
    pinning_scope: str = "NONE"  # NONE, PARTIAL, COMPREHENSIVE
    backup_pins: bool = False
    pin_failure_handling: str = "UNKNOWN"
    dynamic_pinning: bool = False
    pinning_vulnerabilities: List[str] = field(default_factory=list)
    leaf_certificate_pinning: bool = False
    intermediate_certificate_pinning: bool = False
    public_key_pinning: bool = False

@dataclass
class OCSPAssessment:
    """OCSP (Online Certificate Status Protocol) assessment."""
    ocsp_implemented: bool = False
    ocsp_stapling: bool = False
    ocsp_checking_enforced: bool = False
    ocsp_failure_handling: str = "UNKNOWN"
    ocsp_vulnerabilities: List[str] = field(default_factory=list)
    soft_fail_detected: bool = False
    hard_fail_implemented: bool = False

@dataclass
class CertificateTransparencyAssessment:
    """Certificate Transparency log verification assessment."""
    ct_verification: bool = False
    ct_log_monitoring: bool = False
    sct_validation: bool = False  # Signed Certificate Timestamp
    ct_policy_enforcement: bool = False
    ct_vulnerabilities: List[str] = field(default_factory=list)
    ct_log_sources: List[str] = field(default_factory=list)

@dataclass
class PKISecurityAssessment:
    """Public Key Infrastructure security assessment."""
    pki_implementation: bool = False
    custom_pki: bool = False
    ca_trust_store: bool = False
    certificate_validation_logic: bool = False
    key_usage_validation: bool = False
    extended_key_usage_validation: bool = False
    critical_extension_handling: bool = False
    pki_vulnerabilities: List[str] = field(default_factory=list)

@dataclass
class CertificateAuthorityAssessment:
    """Certificate Authority trust validation assessment."""
    ca_validation: bool = False
    custom_ca_handling: bool = False
    ca_trust_decisions: List[str] = field(default_factory=list)
    ca_pinning: bool = False
    ca_vulnerabilities: List[str] = field(default_factory=list)
    root_ca_trust_store: bool = False
    ca_certificate_verification: bool = False

class CertificatePKIAnalyzer:
    """Advanced analyzer for certificate and PKI security."""
    
    def __init__(self):
        self.certificate_patterns = self._initialize_certificate_patterns()
        self.pki_patterns = self._initialize_pki_patterns()
        self.ocsp_patterns = self._initialize_ocsp_patterns()
        self.ct_patterns = self._initialize_ct_patterns()
        self.ca_patterns = self._initialize_ca_patterns()
    
    def _initialize_certificate_patterns(self) -> Dict[str, List[str]]:
        """Initialize certificate analysis patterns."""
        return {
            "chain_validation": [
                r"CertPathValidator\.getInstance\(",
                r"CertPath\.validate\(",
                r"CertificateFactory\.generateCertPath\(",
                r"PKIXParameters\(",
                r"TrustAnchor\(",
                r"CertPathBuilder\.getInstance\(",
                r"CertPathBuilderParameters",
                r"validateCertificateChain\(",
                r"verifyCertificateChain\(",
                r"buildCertificatePath\(",
                r"X509Certificate\[\].*validate",
                r"CertificateChainValidator"
            ],
            "pinning_implementation": [
                r"CertificatePinner\.Builder\(\)",
                r"HttpsURLConnection\.setDefaultHostnameVerifier\(",
                r"OkHttpClient\.Builder\(\)\.certificatePinner\(",
                r"pin.*sha256",
                r"Retrofit\.Builder\(\)\.client\(",
                r"TrustManagerFactory\.getInstance\(",
                r"X509TrustManager.*pin",
                r"CertificateFactory\.generateCertificate\(",
                r"MessageDigest\.getInstance\([\"']SHA-256[\"']\)",
                r"PublicKey.*equals\(",
                r"Certificate.*getPublicKey\(\)",
                r"pinning.*policy",
                r"backup.*pin",
                r"certificate.*fingerprint"
            ],
            "validation_bypass": [
                r"X509TrustManager.*\{\s*\}",
                r"HostnameVerifier.*return\s+true",
                r"SSLSocketFactory.*getInsecure",
                r"trustAllCerts|trustAllHosts",
                r"TrustAllX509TrustManager",
                r"AcceptAllTrustManager",
                r"NullTrustManager",
                r"checkServerTrusted\(\).*\{\s*\}",
                r"checkClientTrusted\(\).*\{\s*\}",
                r"getAcceptedIssuers\(\).*return\s+null",
                r"verify\(\).*return\s+true",
                r"allowAllHostnames\(true\)",
                r"ALLOW_ALL_HOSTNAME_VERIFIER"
            ]
        }
    
    def _initialize_pki_patterns(self) -> Dict[str, List[str]]:
        """Initialize PKI analysis patterns."""
        return {
            "pki_implementation": [
                r"KeyStore\.getInstance\([\"']PKCS12[\"']\)",
                r"KeyStore\.getInstance\([\"']JKS[\"']\)",
                r"CertificateFactory\.getInstance\([\"']X\.509[\"']\)",
                r"X509Certificate\.getInstance\(",
                r"PKIXCertPathValidator",
                r"CertPathValidator\.validate\(",
                r"PKIXBuilderParameters",
                r"PKIXRevocationChecker",
                r"AlgorithmConstraints",
                r"BasicConstraints",
                r"KeyUsage",
                r"ExtendedKeyUsage",
                r"SubjectAlternativeName",
                r"AuthorityKeyIdentifier",
                r"SubjectKeyIdentifier"
            ],
            "key_usage_validation": [
                r"KeyUsage\.getInstance\(",
                r"getKeyUsage\(\)",
                r"hasKeyUsage\(",
                r"checkKeyUsage\(",
                r"ExtendedKeyUsage\.getInstance\(",
                r"getExtendedKeyUsage\(\)",
                r"hasExtendedKeyUsage\(",
                r"validateKeyUsage\(",
                r"KEY_USAGE_.*",
                r"EKU_.*",
                r"id-kp-.*"
            ],
            "certificate_extensions": [
                r"Extension\.getInstance\(",
                r"getExtension\(",
                r"getCriticalExtensionOIDs\(\)",
                r"getNonCriticalExtensionOIDs\(\)",
                r"hasUnsupportedCriticalExtension\(\)",
                r"BasicConstraints\.getInstance\(",
                r"PolicyConstraints\.getInstance\(",
                r"NameConstraints\.getInstance\(",
                r"AuthorityInformationAccess",
                r"CRLDistributionPoints",
                r"FreshestCRL"
            ]
        }
    
    def _initialize_ocsp_patterns(self) -> Dict[str, List[str]]:
        """Initialize OCSP analysis patterns."""
        return {
            "ocsp_implementation": [
                r"OCSPReq\.getInstance\(",
                r"OCSPResp\.getInstance\(",
                r"OCSPChecker",
                r"RevocationChecker",
                r"PKIXRevocationChecker",
                r"CertPathChecker",
                r"ocsp\..*\.url",
                r"OCSP.*Response",
                r"OCSP.*Request",
                r"revocation.*check",
                r"certificate.*status",
                r"CertificateStatus",
                r"RevokedStatus",
                r"GoodStatus",
                r"UnknownStatus"
            ],
            "ocsp_stapling": [
                r"SSLParameters\.setServerNames\(",
                r"ExtendedSSLSession",
                r"SNIServerName",
                r"status_request.*extension",
                r"certificate_status.*extension",
                r"OCSPStapling",
                r"status.*request",
                r"multiple_certificate_status"
            ]
        }
    
    def _initialize_ct_patterns(self) -> Dict[str, List[str]]:
        """Initialize Certificate Transparency patterns."""
        return {
            "ct_verification": [
                r"SCT.*verification",
                r"SignedCertificateTimestamp",
                r"CertificateTransparency",
                r"CTLog.*verification",
                r"ct\.googleapis\.com",
                r"certificate.*transparency",
                r"sct.*validation",
                r"ct.*policy",
                r"TransparencyLog",
                r"LogEntry.*verification",
                r"CTVerifier",
                r"SCTVerifier"
            ],
            "ct_monitoring": [
                r"CTMonitor",
                r"certificate.*monitoring",
                r"log.*monitoring",
                r"transparency.*monitoring",
                r"ct.*alert",
                r"certificate.*watch",
                r"LogMonitor",
                r"CertificateWatcher"
            ]
        }
    
    def _initialize_ca_patterns(self) -> Dict[str, List[str]]:
        """Initialize Certificate Authority patterns."""
        return {
            "ca_validation": [
                r"TrustAnchor\(",
                r"CertificateAuthority",
                r"RootCA",
                r"IntermediateCA",
                r"TrustedCertificateStore",
                r"CAManager",
                r"TrustStore\.getInstance\(",
                r"X509TrustManager.*getAcceptedIssuers\(\)",
                r"validateCertificateAuthority\(",
                r"checkCAConstraints\(",
                r"issuedBy\(",
                r"verifyIssuer\(",
                r"CACertificate",
                r"AuthorityCertIssuer"
            ],
            "ca_pinning": [
                r"pin.*ca|ca.*pin",
                r"root.*ca.*pin",
                r"intermediate.*ca.*pin",
                r"authority.*pin",
                r"issuer.*pin",
                r"CAPinner",
                r"AuthorityPinner",
                r"IssuerPinner"
            ]
        }
    
    def analyze_certificate_chain_validation(self, content: str, file_path: str) -> CertificateChainAssessment:
        """Analyze certificate chain validation implementation."""
        assessment = CertificateChainAssessment()
        
        try:
            # Check for chain validation implementation
            for pattern in self.certificate_patterns["chain_validation"]:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    assessment.chain_validation_implemented = True
                    context = self._extract_context(match, content, 150)
                    
                    # Analyze specific validation features
                    if 'certpathvalidator' in match.group().lower():
                        assessment.custom_ca_validation = True
                    elif 'trustanchor' in match.group().lower():
                        assessment.root_ca_validation = True
                    elif 'certpath' in match.group().lower():
                        assessment.intermediate_ca_handling = True
                    
                    # Check for proper depth verification
                    if any(keyword in context.lower() for keyword in ['depth', 'maxpathlength', 'pathlen']):
                        assessment.chain_depth_verification = True
            
            # Check for validation bypass
            for pattern in self.certificate_patterns["validation_bypass"]:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    assessment.chain_validation_bypassed = True
                    assessment.chain_validation_vulnerabilities.append(
                        f"Certificate validation bypass detected: {match.group()}"
                    )
            
            # Assess overall chain validation security
            if assessment.chain_validation_implemented:
                if not assessment.root_ca_validation:
                    assessment.chain_validation_vulnerabilities.append("Root CA validation not implemented")
                if not assessment.chain_depth_verification:
                    assessment.chain_validation_vulnerabilities.append("Certificate chain depth verification missing")
                    
        except Exception as e:
            logger.error(f"Error analyzing certificate chain validation: {e}")
            assessment.chain_validation_vulnerabilities.append(f"Analysis error: {e}")
        
        return assessment
    
    def analyze_certificate_pinning_implementation(self, content: str, file_path: str) -> CertificatePinningAssessment:
        """Analyze certificate pinning implementation."""
        assessment = CertificatePinningAssessment()
        
        try:
            pinning_methods = set()
            
            for pattern in self.certificate_patterns["pinning_implementation"]:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    assessment.pinning_implemented = True
                    context = self._extract_context(match, content, 200)
                    match_text = match.group().lower()
                    
                    # Identify pinning method
                    if 'certificatepinner' in match_text:
                        pinning_methods.add("OkHttp CertificatePinner")
                    elif 'hostnameVerifier' in match_text:
                        pinning_methods.add("Custom HostnameVerifier")
                    elif 'trustmanager' in match_text:
                        pinning_methods.add("Custom TrustManager")
                    elif 'sha256' in match_text:
                        pinning_methods.add("SHA-256 Pin")
                        assessment.public_key_pinning = True
                    elif 'publickey' in match_text:
                        assessment.public_key_pinning = True
                        pinning_methods.add("Public Key Pinning")
                    elif 'certificate' in match_text:
                        assessment.leaf_certificate_pinning = True
                        pinning_methods.add("Certificate Pinning")
                    
                    # Check for backup pins
                    if any(keyword in context.lower() for keyword in ['backup', 'secondary', 'fallback']):
                        assessment.backup_pins = True
                    
                    # Check for failure handling
                    if any(keyword in context.lower() for keyword in ['fail', 'exception', 'error']):
                        if 'hard' in context.lower() or 'strict' in context.lower():
                            assessment.pin_failure_handling = "HARD_FAIL"
                        elif 'soft' in context.lower() or 'warn' in context.lower():
                            assessment.pin_failure_handling = "SOFT_FAIL"
            
            assessment.pinning_methods = list(pinning_methods)
            
            # Assess pinning scope
            if len(pinning_methods) >= 3:
                assessment.pinning_scope = "COMPREHENSIVE"
            elif len(pinning_methods) >= 1:
                assessment.pinning_scope = "PARTIAL"
            
            # Assess pinning vulnerabilities
            if assessment.pinning_implemented:
                if not assessment.backup_pins:
                    assessment.pinning_vulnerabilities.append("No backup pins configured")
                if assessment.pin_failure_handling == "SOFT_FAIL":
                    assessment.pinning_vulnerabilities.append("Soft failure handling reduces security")
                if not assessment.public_key_pinning and not assessment.leaf_certificate_pinning:
                    assessment.pinning_vulnerabilities.append("Pinning method unclear or insecure")
                    
        except Exception as e:
            logger.error(f"Error analyzing certificate pinning: {e}")
            assessment.pinning_vulnerabilities.append(f"Analysis error: {e}")
        
        return assessment
    
    def analyze_ocsp_implementation(self, content: str, file_path: str) -> OCSPAssessment:
        """Analyze OCSP implementation."""
        assessment = OCSPAssessment()
        
        try:
            for pattern in self.ocsp_patterns["ocsp_implementation"]:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    assessment.ocsp_implemented = True
                    context = self._extract_context(match, content, 150)
                    match_text = match.group().lower()
                    
                    # Check for specific OCSP features
                    if 'revocationchecker' in match_text:
                        assessment.ocsp_checking_enforced = True
                    
                    # Analyze failure handling
                    if any(keyword in context.lower() for keyword in ['fail', 'error', 'exception']):
                        if 'soft' in context.lower():
                            assessment.soft_fail_detected = True
                            assessment.ocsp_failure_handling = "SOFT_FAIL"
                        elif 'hard' in context.lower():
                            assessment.hard_fail_implemented = True
                            assessment.ocsp_failure_handling = "HARD_FAIL"
            
            # Check for OCSP stapling
            for pattern in self.ocsp_patterns["ocsp_stapling"]:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    assessment.ocsp_stapling = True
            
            # Assess OCSP vulnerabilities
            if assessment.ocsp_implemented:
                if assessment.soft_fail_detected:
                    assessment.ocsp_vulnerabilities.append("OCSP soft-fail reduces security")
                if not assessment.ocsp_checking_enforced:
                    assessment.ocsp_vulnerabilities.append("OCSP checking not properly enforced")
                    
        except Exception as e:
            logger.error(f"Error analyzing OCSP implementation: {e}")
            assessment.ocsp_vulnerabilities.append(f"Analysis error: {e}")
        
        return assessment
    
    def analyze_certificate_transparency(self, content: str, file_path: str) -> CertificateTransparencyAssessment:
        """Analyze Certificate Transparency implementation."""
        assessment = CertificateTransparencyAssessment()
        
        try:
            for pattern in self.ct_patterns["ct_verification"]:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    assessment.ct_verification = True
                    context = self._extract_context(match, content, 150)
                    match_text = match.group().lower()
                    
                    # Check for specific CT features
                    if 'sct' in match_text or 'signedcertificatetimestamp' in match_text:
                        assessment.sct_validation = True
                    elif 'policy' in match_text:
                        assessment.ct_policy_enforcement = True
                    
                    # Extract CT log sources
                    if 'googleapis.com' in context or 'ctlog' in context:
                        assessment.ct_log_sources.append("Google CT Logs")
            
            # Check for CT monitoring
            for pattern in self.ct_patterns["ct_monitoring"]:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    assessment.ct_log_monitoring = True
            
            # Assess CT vulnerabilities
            if assessment.ct_verification:
                if not assessment.sct_validation:
                    assessment.ct_vulnerabilities.append("SCT validation not implemented")
                if not assessment.ct_policy_enforcement:
                    assessment.ct_vulnerabilities.append("CT policy enforcement missing")
                    
        except Exception as e:
            logger.error(f"Error analyzing Certificate Transparency: {e}")
            assessment.ct_vulnerabilities.append(f"Analysis error: {e}")
        
        return assessment
    
    def analyze_pki_security(self, content: str, file_path: str) -> PKISecurityAssessment:
        """Analyze PKI security implementation."""
        assessment = PKISecurityAssessment()
        
        try:
            for pattern in self.pki_patterns["pki_implementation"]:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    assessment.pki_implementation = True
                    match_text = match.group().lower()
                    
                    # Check for custom PKI
                    if any(keyword in match_text for keyword in ['custom', 'proprietary', 'internal']):
                        assessment.custom_pki = True
                    elif 'keystore' in match_text:
                        assessment.ca_trust_store = True
                    elif 'certpathvalidator' in match_text:
                        assessment.certificate_validation_logic = True
            
            # Check for key usage validation
            for pattern in self.pki_patterns["key_usage_validation"]:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    match_text = match.group().lower()
                    
                    if 'keyusage' in match_text:
                        assessment.key_usage_validation = True
                    elif 'extendedkeyusage' in match_text:
                        assessment.extended_key_usage_validation = True
            
            # Check for certificate extension handling
            for pattern in self.pki_patterns["certificate_extensions"]:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    match_text = match.group().lower()
                    
                    if 'criticalextension' in match_text:
                        assessment.critical_extension_handling = True
            
            # Assess PKI vulnerabilities
            if assessment.pki_implementation:
                if not assessment.key_usage_validation:
                    assessment.pki_vulnerabilities.append("Key usage validation not implemented")
                if not assessment.critical_extension_handling:
                    assessment.pki_vulnerabilities.append("Critical extension handling missing")
                    
        except Exception as e:
            logger.error(f"Error analyzing PKI security: {e}")
            assessment.pki_vulnerabilities.append(f"Analysis error: {e}")
        
        return assessment
    
    def analyze_ca_trust_validation(self, content: str, file_path: str) -> CertificateAuthorityAssessment:
        """Analyze Certificate Authority trust validation."""
        assessment = CertificateAuthorityAssessment()
        
        try:
            for pattern in self.ca_patterns["ca_validation"]:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    assessment.ca_validation = True
                    context = self._extract_context(match, content, 150)
                    match_text = match.group().lower()
                    
                    # Check for specific CA features
                    if 'trustanchor' in match_text:
                        assessment.root_ca_trust_store = True
                    elif 'getacceptedissuers' in match_text:
                        assessment.ca_certificate_verification = True
                    elif any(keyword in match_text for keyword in ['custom', 'internal']):
                        assessment.custom_ca_handling = True
            
            # Check for CA pinning
            for pattern in self.ca_patterns["ca_pinning"]:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    assessment.ca_pinning = True
            
            # Assess CA vulnerabilities
            if assessment.ca_validation:
                if not assessment.root_ca_trust_store:
                    assessment.ca_vulnerabilities.append("Root CA trust store validation missing")
                if not assessment.ca_certificate_verification:
                    assessment.ca_vulnerabilities.append("CA certificate verification not implemented")
                    
        except Exception as e:
            logger.error(f"Error analyzing CA trust validation: {e}")
            assessment.ca_vulnerabilities.append(f"Analysis error: {e}")
        
        return assessment
    
    def _extract_context(self, match: re.Match, content: str, context_size: int = 200) -> str:
        """Extract context around a match."""
        start = max(0, match.start() - context_size // 2)
        end = min(len(content), match.end() + context_size // 2)
        return content[start:end]
    
    def analyze_comprehensive_certificate_pki(self, content: str, file_path: str) -> Dict[str, Any]:
        """Perform comprehensive certificate and PKI analysis."""
        try:
            analysis_results = {
                "certificate_chain": self.analyze_certificate_chain_validation(content, file_path),
                "certificate_pinning": self.analyze_certificate_pinning_implementation(content, file_path),
                "ocsp": self.analyze_ocsp_implementation(content, file_path),
                "certificate_transparency": self.analyze_certificate_transparency(content, file_path),
                "pki_security": self.analyze_pki_security(content, file_path),
                "ca_trust": self.analyze_ca_trust_validation(content, file_path)
            }
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"Error in comprehensive certificate/PKI analysis: {e}")
            return {"error": str(e)} 