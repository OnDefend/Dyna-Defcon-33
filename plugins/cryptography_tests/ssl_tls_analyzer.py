#!/usr/bin/env python3
"""
SSL/TLS Security Analyzer

This module provides comprehensive SSL/TLS security analysis for Android
applications, including certificate validation, cipher suite analysis,
protocol version assessment, and network security configuration evaluation.

Key Features:
- SSL/TLS protocol version analysis
- Cipher suite security assessment
- Certificate validation bypass detection
- Hostname verification analysis
- Network Security Configuration parsing
- Perfect Forward Secrecy evaluation
- SSL/TLS vulnerability detection
"""

import logging
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from pathlib import Path
import base64
import json

from .data_structures import (
    CryptographicVulnerability,
    SSLTLSAnalysis,
    CryptographicAlgorithmType,
    ComplianceStandard
)
from .confidence_calculator import CryptoConfidenceCalculator

logger = logging.getLogger(__name__)

@dataclass
class SSLTLSConfiguration:
    """SSL/TLS configuration details."""
    protocols: List[str] = field(default_factory=list)
    cipher_suites: List[str] = field(default_factory=list)
    certificate_validation: bool = True
    hostname_verification: bool = True
    certificate_pinning: bool = False
    trust_all_certificates: bool = False
    custom_trust_manager: bool = False
    network_security_config: Optional[Dict[str, Any]] = None
    perfect_forward_secrecy: bool = False
    vulnerabilities: List[str] = field(default_factory=list)

class SSLTLSAnalyzer:
    """
    Comprehensive SSL/TLS security analyzer.
    
    Analyzes SSL/TLS configurations, certificate handling, and network
    security settings to identify potential vulnerabilities and misconfigurations.
    """
    
    def __init__(self, apk_ctx):
        """Initialize the SSL/TLS analyzer."""
        self.apk_ctx = apk_ctx
        self.confidence_calculator = CryptoConfidenceCalculator()
        
        # SSL/TLS security patterns
        self.ssl_patterns = self._initialize_ssl_patterns()
        
        # Weak cipher suites
        self.weak_cipher_suites = {
            "NULL": "No encryption",
            "EXPORT": "Export-grade encryption (weak)",
            "DES": "DES encryption (deprecated)",
            "3DES": "3DES encryption (deprecated)",
            "RC4": "RC4 stream cipher (broken)",
            "MD5": "MD5 hash (weak)",
            "SHA1": "SHA1 hash (weak for signatures)",
            "DHE_RSA_WITH_DES": "DES with DHE (weak)",
            "RSA_WITH_RC4": "RC4 with RSA (broken)",
            "RSA_WITH_NULL": "No encryption with RSA",
            "ECDHE_RSA_WITH_RC4": "RC4 with ECDHE (broken)",
            "SSL_RSA_WITH_DES": "SSL with DES (deprecated)",
            "TLS_RSA_WITH_RC4": "TLS with RC4 (broken)"
        }
        
        # Strong cipher suites
        self.strong_cipher_suites = {
            "TLS_AES_256_GCM_SHA384": "AES-256-GCM with SHA-384",
            "TLS_AES_128_GCM_SHA256": "AES-128-GCM with SHA-256",
            "TLS_CHACHA20_POLY1305_SHA256": "ChaCha20-Poly1305",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": "ECDHE-RSA-AES256-GCM-SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "ECDHE-RSA-AES128-GCM-SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "ECDHE-ECDSA-AES256-GCM-SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "ECDHE-ECDSA-AES128-GCM-SHA256"
        }
        
        # Deprecated SSL/TLS versions
        self.deprecated_versions = {
            "SSLv2": "SSL 2.0 (deprecated)",
            "SSLv3": "SSL 3.0 (deprecated)",
            "TLSv1": "TLS 1.0 (deprecated)",
            "TLSv1.1": "TLS 1.1 (deprecated)"
        }
        
        # Secure SSL/TLS versions
        self.secure_versions = {
            "TLSv1.2": "TLS 1.2 (secure)",
            "TLSv1.3": "TLS 1.3 (most secure)"
        }
        
        logger.info("Initialized SSLTLSAnalyzer")
    
    def _initialize_ssl_patterns(self) -> Dict[str, List[str]]:
        """Initialize SSL/TLS detection patterns."""
        return {
            "certificate_validation_bypass": [
                r"TrustManager\[\]\s*\{\s*public\s+void\s+checkClientTrusted",
                r"TrustManager\[\]\s*\{\s*public\s+void\s+checkServerTrusted",
                r"X509TrustManager.*checkServerTrusted.*\{\s*\}",
                r"X509TrustManager.*checkClientTrusted.*\{\s*\}",
                r"HostnameVerifier.*verify.*return\s+true",
                r"setHostnameVerifier.*ALLOW_ALL_HOSTNAME_VERIFIER",
                r"HttpsURLConnection\.setDefaultHostnameVerifier",
                r"trustAllCerts|trustAllHosts|allowAllHostnames",
                r"TrustAllX509TrustManager",
                r"NullHostnameVerifier",
            ],
            "ssl_context_creation": [
                r"SSLContext\.getInstance\([\"']([^\"']+)[\"']",
                r"SSLSocketFactory\.createSocket",
                r"HttpsURLConnection\.setSSLSocketFactory",
                r"OkHttpClient\.Builder\(\)\.sslSocketFactory",
                r"ConnectionSpec\.Builder\(\)",
                r"TrustManagerFactory\.getInstance"
            ],
            "network_security_config": [
                r"android:networkSecurityConfig",
                r"<network-security-config",
                r"<trust-anchors",
                r"<certificates",
                r"<pin-set",
                r"<domain-config",
                r"cleartextTrafficPermitted",
                r"<debug-overrides"
            ],
            "certificate_pinning": [
                r"CertificatePinner\.Builder\(\)",
                r"\.pin\([\"']([^\"']+)[\"']",
                r"PinningTrustManager",
                r"certificate.*pin|pin.*certificate",
                r"public.*key.*pin|pin.*public.*key",
                r"sha256/[A-Za-z0-9+/=]{43}",
                r"sha1/[A-Za-z0-9+/=]{27}"
            ],
            "weak_ssl_configuration": [
                r"Protocol.*SSLv[23]",
                r"Protocol.*TLSv1\.0",
                r"Protocol.*TLSv1\.1",
                r"setEnabledProtocols.*SSLv[23]",
                r"setEnabledProtocols.*TLSv1\.0",
                r"setEnabledCipherSuites.*NULL",
                r"setEnabledCipherSuites.*EXPORT",
                r"setEnabledCipherSuites.*DES",
                r"setEnabledCipherSuites.*RC4"
            ]
        }
    
    def analyze_ssl_tls_security(self, file_contents: Dict[str, str]) -> SSLTLSAnalysis:
        """
        Perform comprehensive SSL/TLS security analysis.
        
        Args:
            file_contents: Dictionary of file paths to their contents
            
        Returns:
            SSL/TLS security analysis results
        """
        analysis = SSLTLSAnalysis()
        
        try:
            # Analyze each file for SSL/TLS patterns
            for file_path, content in file_contents.items():
                if self._is_relevant_file(file_path):
                    self._analyze_file_ssl_tls(file_path, content, analysis)
            
            # Analyze Network Security Configuration
            self._analyze_network_security_config(file_contents, analysis)
            
            # Analyze manifest for SSL/TLS settings
            self._analyze_manifest_ssl_settings(file_contents, analysis)
            
            # Calculate overall SSL/TLS security score
            analysis.overall_score = self._calculate_ssl_tls_score(analysis)
            
            # Generate recommendations
            analysis.recommendations = self._generate_ssl_tls_recommendations(analysis)
            
            # Set compliance status
            analysis.compliance_status = self._assess_compliance(analysis)
            
            logger.info(f"SSL/TLS analysis completed: {len(analysis.vulnerabilities)} vulnerabilities found")
            
        except Exception as e:
            logger.error(f"Error during SSL/TLS analysis: {e}")
            analysis.vulnerabilities.append(
                self._create_analysis_error_vulnerability(str(e))
            )
        
        return analysis
    
    def _is_relevant_file(self, file_path: str) -> bool:
        """Check if file is relevant for SSL/TLS analysis."""
        relevant_extensions = ['.java', '.kt', '.xml', '.json', '.properties']
        relevant_keywords = [
            'ssl', 'tls', 'https', 'network', 'security', 'trust',
            'certificate', 'crypto', 'okhttp', 'retrofit', 'volley'
        ]
        
        file_path_lower = file_path.lower()
        
        # Check extension
        if any(file_path_lower.endswith(ext) for ext in relevant_extensions):
            return True
        
        # Check for relevant keywords in path
        if any(keyword in file_path_lower for keyword in relevant_keywords):
            return True
        
        return False
    
    def _analyze_file_ssl_tls(self, file_path: str, content: str, analysis: SSLTLSAnalysis) -> None:
        """Analyze a single file for SSL/TLS security patterns."""
        
        # Check for certificate validation bypass
        self._check_certificate_validation_bypass(file_path, content, analysis)
        
        # Check for weak SSL/TLS configurations
        self._check_weak_ssl_configurations(file_path, content, analysis)
        
        # Check for SSL context creation
        self._check_ssl_context_creation(file_path, content, analysis)
        
        # Check for certificate pinning
        self._check_certificate_pinning(file_path, content, analysis)
        
        # Check for hostname verification
        self._check_hostname_verification(file_path, content, analysis)
    
    def _check_certificate_validation_bypass(self, file_path: str, content: str, analysis: SSLTLSAnalysis) -> None:
        """Check for certificate validation bypass patterns."""
        patterns = self.ssl_patterns["certificate_validation_bypass"]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                # Create vulnerability
                vulnerability = CryptographicVulnerability(
                    vulnerability_id=f"ssl_cert_bypass_{hash(file_path + pattern + str(line_num))}",
                    title="SSL Certificate Validation Bypass",
                    description=f"Certificate validation bypass detected: {match.group(0)[:100]}...",
                    severity=VulnerabilitySeverity.HIGH,
                    location=f"{file_path}:{line_num}",
                    algorithm_name="SSL/TLS",
                    algorithm_type=CryptographicAlgorithmType.ASYMMETRIC_CIPHER,
                    cryptographic_weakness="Certificate validation bypass",
                    attack_vectors=[
                        "Man-in-the-middle attacks",
                        "Certificate spoofing",
                        "Rogue certificate acceptance"
                    ],
                    algorithm_recommendations=[
                        "Remove custom TrustManager implementations",
                        "Use default certificate validation",
                        "Implement proper certificate pinning"
                    ]
                )
                
                analysis.vulnerabilities.append(vulnerability)
                analysis.certificate_validation.append({
                    "type": "bypass_detected",
                    "location": f"{file_path}:{line_num}",
                    "pattern": pattern,
                    "code_snippet": match.group(0)[:200],
                    "severity": "HIGH"
                })
    
    def _check_weak_ssl_configurations(self, file_path: str, content: str, analysis: SSLTLSAnalysis) -> None:
        """Check for weak SSL/TLS configurations."""
        patterns = self.ssl_patterns["weak_ssl_configuration"]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                # Determine specific weakness
                matched_text = match.group(0).upper()
                weakness_type = "unknown"
                
                if any(weak_version in matched_text for weak_version in ["SSLV2", "SSLV3", "TLSV1.0", "TLSV1.1"]):
                    weakness_type = "weak_protocol_version"
                elif any(weak_cipher in matched_text for weak_cipher in ["NULL", "EXPORT", "DES", "RC4"]):
                    weakness_type = "weak_cipher_suite"
                
                # Create vulnerability
                vulnerability = CryptographicVulnerability(
                    vulnerability_id=f"ssl_weak_config_{hash(file_path + pattern + str(line_num))}",
                    title="Weak SSL/TLS Configuration",
                    description=f"Weak SSL/TLS configuration detected: {match.group(0)[:100]}",
                    severity=VulnerabilitySeverity.MEDIUM,
                    location=f"{file_path}:{line_num}",
                    algorithm_name="SSL/TLS",
                    algorithm_type=CryptographicAlgorithmType.ASYMMETRIC_CIPHER,
                    cryptographic_weakness=weakness_type,
                    attack_vectors=[
                        "Protocol downgrade attacks",
                        "Cipher suite downgrade attacks",
                        "Cryptographic attacks on weak algorithms"
                    ],
                    algorithm_recommendations=[
                        "Use TLS 1.2 or higher",
                        "Enable only strong cipher suites",
                        "Disable weak protocols and ciphers"
                    ]
                )
                
                analysis.vulnerabilities.append(vulnerability)
                
                # Add to appropriate analysis category
                if weakness_type == "weak_protocol_version":
                    analysis.protocol_versions.append({
                        "version": matched_text,
                        "location": f"{file_path}:{line_num}",
                        "security_level": "WEAK",
                        "recommendation": "Upgrade to TLS 1.2+"
                    })
                elif weakness_type == "weak_cipher_suite":
                    analysis.cipher_suites.append({
                        "cipher_suite": matched_text,
                        "location": f"{file_path}:{line_num}",
                        "security_level": "WEAK",
                        "recommendation": "Use strong cipher suites"
                    })
    
    def _check_ssl_context_creation(self, file_path: str, content: str, analysis: SSLTLSAnalysis) -> None:
        """Check SSL context creation patterns."""
        patterns = self.ssl_patterns["ssl_context_creation"]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                # Extract SSL context details
                if match.groups():
                    ssl_protocol = match.group(1)
                    
                    # Check if protocol is weak
                    if ssl_protocol.upper() in self.deprecated_versions:
                        vulnerability = CryptographicVulnerability(
                            vulnerability_id=f"ssl_weak_protocol_{hash(file_path + ssl_protocol + str(line_num))}",
                            title="Weak SSL/TLS Protocol Version",
                            description=f"Deprecated SSL/TLS protocol version: {ssl_protocol}",
                            severity=VulnerabilitySeverity.MEDIUM,
                            location=f"{file_path}:{line_num}",
                            algorithm_name=ssl_protocol,
                            algorithm_type=CryptographicAlgorithmType.ASYMMETRIC_CIPHER,
                            cryptographic_weakness="Deprecated protocol version",
                            attack_vectors=[
                                "Protocol downgrade attacks",
                                "Known protocol vulnerabilities"
                            ],
                            algorithm_recommendations=[
                                f"Replace {ssl_protocol} with TLS 1.2 or higher"
                            ]
                        )
                        analysis.vulnerabilities.append(vulnerability)
                    
                    # Record protocol version
                    analysis.protocol_versions.append({
                        "version": ssl_protocol,
                        "location": f"{file_path}:{line_num}",
                        "security_level": "WEAK" if ssl_protocol.upper() in self.deprecated_versions else "SECURE",
                        "context": "ssl_context_creation"
                    })
    
    def _check_certificate_pinning(self, file_path: str, content: str, analysis: SSLTLSAnalysis) -> None:
        """Check for certificate pinning implementations."""
        patterns = self.ssl_patterns["certificate_pinning"]
        
        has_pinning = False
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                has_pinning = True
                
                # Extract pin details if available
                pin_value = ""
                if match.groups():
                    pin_value = match.group(1)
                
                analysis.certificate_validation.append({
                    "type": "certificate_pinning",
                    "location": f"{file_path}:{line_num}",
                    "pin_value": pin_value,
                    "implementation": "detected",
                    "security_level": "HIGH"
                })
        
        # If no pinning found, note it as a potential security enhancement
        if not has_pinning and any(keyword in content.lower() for keyword in ["https", "ssl", "tls"]):
            analysis.recommendations.append(
                "Consider implementing certificate pinning for enhanced security"
            )
    
    def _check_hostname_verification(self, file_path: str, content: str, analysis: SSLTLSAnalysis) -> None:
        """Check hostname verification settings."""
        # Patterns for hostname verification bypass
        bypass_patterns = [
            r"setHostnameVerifier.*ALLOW_ALL_HOSTNAME_VERIFIER",
            r"HostnameVerifier.*verify.*return\s+true",
            r"setDefaultHostnameVerifier",
            r"NullHostnameVerifier"
        ]
        
        for pattern in bypass_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerability = CryptographicVulnerability(
                    vulnerability_id=f"ssl_hostname_bypass_{hash(file_path + pattern + str(line_num))}",
                    title="Hostname Verification Bypass",
                    description=f"Hostname verification bypass detected: {match.group(0)[:100]}",
                    severity=VulnerabilitySeverity.HIGH,
                    location=f"{file_path}:{line_num}",
                    algorithm_name="SSL/TLS",
                    algorithm_type=CryptographicAlgorithmType.ASYMMETRIC_CIPHER,
                    cryptographic_weakness="Hostname verification bypass",
                    attack_vectors=[
                        "Man-in-the-middle attacks",
                        "DNS spoofing attacks",
                        "Rogue server impersonation"
                    ],
                    algorithm_recommendations=[
                        "Remove hostname verification bypass",
                        "Use default hostname verification",
                        "Implement proper hostname validation"
                    ]
                )
                
                analysis.vulnerabilities.append(vulnerability)
                analysis.hostname_verification.append({
                    "type": "bypass_detected",
                    "location": f"{file_path}:{line_num}",
                    "pattern": pattern,
                    "severity": "HIGH"
                })
    
    def _analyze_network_security_config(self, file_contents: Dict[str, str], analysis: SSLTLSAnalysis) -> None:
        """Analyze Android Network Security Configuration."""
        # Look for network security config file
        nsc_files = [
            path for path in file_contents.keys()
            if 'network_security_config' in path.lower() or 'network-security-config' in path.lower()
        ]
        
        for nsc_file in nsc_files:
            try:
                content = file_contents[nsc_file]
                self._parse_network_security_config(nsc_file, content, analysis)
            except Exception as e:
                logger.error(f"Error parsing network security config {nsc_file}: {e}")
    
    def _parse_network_security_config(self, file_path: str, content: str, analysis: SSLTLSAnalysis) -> None:
        """Parse Android Network Security Configuration XML."""
        try:
            root = ET.fromstring(content)
            
            # Check for cleartext traffic permission
            if root.attrib.get('cleartextTrafficPermitted', '').lower() == 'true':
                vulnerability = CryptographicVulnerability(
                    vulnerability_id=f"nsc_cleartext_{hash(file_path)}",
                    title="Cleartext Traffic Permitted",
                    description="Network Security Configuration allows cleartext traffic",
                    severity=VulnerabilitySeverity.MEDIUM,
                    location=file_path,
                    algorithm_name="Network Security",
                    cryptographic_weakness="Cleartext traffic allowed",
                    attack_vectors=[
                        "Network traffic interception",
                        "Man-in-the-middle attacks",
                        "Data exposure over unencrypted connections"
                    ],
                    algorithm_recommendations=[
                        "Set cleartextTrafficPermitted to false",
                        "Use HTTPS for all network communications"
                    ]
                )
                analysis.vulnerabilities.append(vulnerability)
            
            # Parse domain configurations
            for domain_config in root.findall('.//domain-config'):
                self._parse_domain_config(domain_config, file_path, analysis)
            
            # Parse debug overrides
            debug_overrides = root.find('.//debug-overrides')
            if debug_overrides is not None:
                analysis.network_security_config["debug_overrides"] = True
                analysis.recommendations.append(
                    "Remove debug overrides from production builds"
                )
        
        except ET.ParseError as e:
            logger.error(f"XML parsing error in {file_path}: {e}")
    
    def _parse_domain_config(self, domain_config, file_path: str, analysis: SSLTLSAnalysis) -> None:
        """Parse domain configuration from Network Security Config."""
        # Check for cleartext traffic permission at domain level
        if domain_config.attrib.get('cleartextTrafficPermitted', '').lower() == 'true':
            domains = [d.text for d in domain_config.findall('.//domain')]
            
            vulnerability = CryptographicVulnerability(
                vulnerability_id=f"nsc_domain_cleartext_{hash(file_path + str(domains))}",
                title="Domain-Specific Cleartext Traffic",
                description=f"Cleartext traffic permitted for domains: {', '.join(domains)}",
                severity=VulnerabilitySeverity.MEDIUM,
                location=file_path,
                algorithm_name="Network Security",
                cryptographic_weakness="Domain-specific cleartext traffic",
                attack_vectors=[
                    "Network interception for specific domains",
                    "Targeted man-in-the-middle attacks"
                ],
                algorithm_recommendations=[
                    "Remove cleartext permission for production domains",
                    "Use HTTPS for all domain communications"
                ]
            )
            analysis.vulnerabilities.append(vulnerability)
        
        # Check for certificate pinning
        pin_set = domain_config.find('.//pin-set')
        if pin_set is not None:
            pins = [pin.text for pin in pin_set.findall('.//pin')]
            analysis.certificate_validation.append({
                "type": "certificate_pinning_nsc",
                "location": file_path,
                "pins": pins,
                "security_level": "HIGH"
            })
    
    def _analyze_manifest_ssl_settings(self, file_contents: Dict[str, str], analysis: SSLTLSAnalysis) -> None:
        """Analyze AndroidManifest.xml for SSL/TLS settings."""
        manifest_files = [
            path for path in file_contents.keys()
            if 'androidmanifest.xml' in path.lower()
        ]
        
        for manifest_file in manifest_files:
            try:
                content = file_contents[manifest_file]
                self._parse_manifest_ssl_settings(manifest_file, content, analysis)
            except Exception as e:
                logger.error(f"Error parsing manifest {manifest_file}: {e}")
    
    def _parse_manifest_ssl_settings(self, file_path: str, content: str, analysis: SSLTLSAnalysis) -> None:
        """Parse SSL/TLS settings from AndroidManifest.xml."""
        try:
            root = ET.fromstring(content)
            
            # Check for network security config reference
            application = root.find('.//application')
            if application is not None:
                nsc_attr = application.attrib.get(
                    '{http://schemas.android.com/apk/res/android}networkSecurityConfig'
                )
                if nsc_attr:
                    analysis.network_security_config["reference"] = nsc_attr
                    analysis.network_security_config["defined"] = True
                else:
                    analysis.network_security_config["defined"] = False
                    analysis.recommendations.append(
                        "Consider defining Network Security Configuration for enhanced security"
                    )
            
            # Check for uses-cleartext-traffic
            uses_cleartext = root.find('.//uses-cleartext-traffic')
            if uses_cleartext is not None:
                if uses_cleartext.attrib.get('android:required', '').lower() == 'true':
                    vulnerability = CryptographicVulnerability(
                        vulnerability_id=f"manifest_cleartext_{hash(file_path)}",
                        title="Cleartext Traffic Required",
                        description="AndroidManifest.xml requires cleartext traffic",
                        severity=VulnerabilitySeverity.MEDIUM,
                        location=file_path,
                        algorithm_name="Network Security",
                        cryptographic_weakness="Cleartext traffic required",
                        attack_vectors=[
                            "Network traffic interception",
                            "Unencrypted data transmission"
                        ],
                        algorithm_recommendations=[
                            "Remove uses-cleartext-traffic requirement",
                            "Use HTTPS for all network communications"
                        ]
                    )
                    analysis.vulnerabilities.append(vulnerability)
        
        except ET.ParseError as e:
            logger.error(f"XML parsing error in manifest {file_path}: {e}")
    
    def _calculate_ssl_tls_score(self, analysis: SSLTLSAnalysis) -> float:
        """Calculate overall SSL/TLS security score."""
        score = 1.0
        
        # Penalize for vulnerabilities
        critical_vulns = sum(1 for v in analysis.vulnerabilities if v.severity.value == "CRITICAL")
        high_vulns = sum(1 for v in analysis.vulnerabilities if v.severity.value == "HIGH")
        medium_vulns = sum(1 for v in analysis.vulnerabilities if v.severity.value == "MEDIUM")
        
        score -= critical_vulns * 0.3
        score -= high_vulns * 0.2
        score -= medium_vulns * 0.1
        
        # Bonus for security features
        if any(cert.get("type") == "certificate_pinning" for cert in analysis.certificate_validation):
            score += 0.1
        
        if analysis.network_security_config.get("defined", False):
            score += 0.05
        
        return max(0.0, min(1.0, score))
    
    def _generate_ssl_tls_recommendations(self, analysis: SSLTLSAnalysis) -> List[str]:
        """Generate SSL/TLS security recommendations."""
        recommendations = []
        
        # Certificate validation recommendations
        if any(cert.get("type") == "bypass_detected" for cert in analysis.certificate_validation):
            recommendations.append("Remove certificate validation bypasses")
        
        # Protocol version recommendations
        weak_protocols = [
            pv for pv in analysis.protocol_versions
            if pv.get("security_level") == "WEAK"
        ]
        if weak_protocols:
            recommendations.append("Upgrade to TLS 1.2 or higher")
        
        # Cipher suite recommendations
        weak_ciphers = [
            cs for cs in analysis.cipher_suites
            if cs.get("security_level") == "WEAK"
        ]
        if weak_ciphers:
            recommendations.append("Use strong cipher suites (AES-GCM, ChaCha20-Poly1305)")
        
        # Certificate pinning recommendations
        if not any(cert.get("type") == "certificate_pinning" for cert in analysis.certificate_validation):
            recommendations.append("Consider implementing certificate pinning")
        
        # Network Security Configuration recommendations
        if not analysis.network_security_config.get("defined", False):
            recommendations.append("Define Network Security Configuration")
        
        return recommendations
    
    def _assess_compliance(self, analysis: SSLTLSAnalysis) -> Dict[ComplianceStandard, bool]:
        """Assess SSL/TLS compliance with various standards."""
        compliance = {}
        
        # NIST compliance
        has_strong_protocols = any(
            pv.get("security_level") == "SECURE" for pv in analysis.protocol_versions
        )
        has_strong_ciphers = any(
            cs.get("security_level") == "SECURE" for cs in analysis.cipher_suites
        )
        no_cert_bypass = not any(
            cert.get("type") == "bypass_detected" for cert in analysis.certificate_validation
        )
        
        compliance[ComplianceStandard.NIST_SP_800_53] = (
            has_strong_protocols and has_strong_ciphers and no_cert_bypass
        )
        
        # PCI DSS compliance
        compliance[ComplianceStandard.PCI_DSS] = (
            has_strong_protocols and has_strong_ciphers and no_cert_bypass
        )
        
        return compliance
    
    def _create_analysis_error_vulnerability(self, error_message: str) -> CryptographicVulnerability:
        """Create a vulnerability for analysis errors."""
        return CryptographicVulnerability(
            vulnerability_id=f"ssl_analysis_error_{hash(error_message)}",
            title="SSL/TLS Analysis Error",
            description=f"Error during SSL/TLS analysis: {error_message}",
            severity=VulnerabilitySeverity.LOW,
            location="analysis_engine",
            algorithm_name="SSL/TLS",
            cryptographic_weakness="Analysis limitation",
            algorithm_recommendations=["Manual review recommended"]
        ) 