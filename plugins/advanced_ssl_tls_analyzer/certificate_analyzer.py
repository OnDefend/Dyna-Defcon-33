#!/usr/bin/env python3
"""
Certificate Analyzer Module

This module provides comprehensive certificate validation and pinning analysis
for Android applications, including detection of certificate validation bypasses,
trust manager issues, and certificate pinning implementations.

"""

import re
import logging
import hashlib
import base64
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import xml.etree.ElementTree as ET

from core.shared_infrastructure.dependency_injection import AnalysisContext
from core.shared_infrastructure.analysis_exceptions import CertificateAnalysisError, safe_execute, ErrorContext
from .data_structures import (
    CertificateAnalysis, CertificatePinningImplementation, SSLTLSVulnerability,
    SSLTLSSeverity, PinningStrength, ValidationStatus
)
from .confidence_calculator import SSLTLSConfidenceCalculator

class CertificateAnalyzer:
    """
    Comprehensive certificate validation and pinning analyzer.
    
    Provides enterprise-grade analysis of certificate handling including:
    - Certificate validation bypass detection
    - Trust manager security analysis
    - Certificate pinning implementation detection
    - APK certificate analysis
    """
    
    def __init__(self, context: AnalysisContext, confidence_calculator: SSLTLSConfidenceCalculator, logger: logging.Logger):
        """Initialize certificate analyzer with dependency injection."""
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = logger
        self.apk_ctx = context.apk_ctx
        
        # Initialize certificate analysis patterns
        self.certificate_patterns = self._load_certificate_patterns()
        self.pinning_patterns = self._load_pinning_patterns()
        self.trust_manager_patterns = self._load_trust_manager_patterns()
        
        # Analysis statistics
        self.stats = {
            'certificates_analyzed': 0,
            'pinning_implementations_found': 0,
            'trust_managers_analyzed': 0,
            'validation_bypasses_found': 0
        }
    
    def analyze_certificates(self) -> CertificateAnalysis:
        """
        Perform comprehensive certificate analysis.
        
        Returns:
            CertificateAnalysis containing complete certificate security assessment
        """
        self.logger.info("Starting comprehensive certificate analysis...")
        
        analysis = CertificateAnalysis()
        
        try:
            # Analyze certificate validation implementations
            validation_analysis = safe_execute(
                lambda: self._analyze_certificate_validation(),
                ErrorContext(component_name="certificate_analyzer", operation="certificate_validation_analysis")
            )
            if validation_analysis:
                analysis.certificate_validation = validation_analysis.get('status', ValidationStatus.UNKNOWN)
                analysis.vulnerabilities.extend(validation_analysis.get('vulnerabilities', []))
            
            # Analyze trust manager implementations
            trust_manager_analysis = safe_execute(
                lambda: self._analyze_trust_managers(),
                ErrorContext(component_name="certificate_analyzer", operation="trust_manager_analysis")
            )
            if trust_manager_analysis:
                analysis.custom_trust_managers = trust_manager_analysis.get('custom_managers', [])
                analysis.insecure_trust_managers = trust_manager_analysis.get('insecure_managers', [])
                analysis.trust_all_certificates = trust_manager_analysis.get('trust_all_detected', False)
                analysis.vulnerabilities.extend(trust_manager_analysis.get('vulnerabilities', []))
            
            # Analyze certificate pinning implementations
            pinning_analysis = safe_execute(
                lambda: self._analyze_certificate_pinning(),
                ErrorContext(component_name="certificate_analyzer", operation="certificate_pinning_analysis")
            )
            if pinning_analysis:
                analysis.pinning_detected = pinning_analysis.get('pinning_detected', False)
                analysis.pinning_implementations = pinning_analysis.get('implementations', [])
                analysis.pinning_strength = pinning_analysis.get('overall_strength', PinningStrength.NONE)
                analysis.vulnerabilities.extend(pinning_analysis.get('vulnerabilities', []))
            
            # Analyze hostname verification
            hostname_analysis = safe_execute(
                lambda: self._analyze_hostname_verification(),
                ErrorContext(component_name="certificate_analyzer", operation="hostname_verification_analysis")
            )
            if hostname_analysis:
                analysis.hostname_verification = hostname_analysis.get('status', ValidationStatus.UNKNOWN)
                analysis.vulnerabilities.extend(hostname_analysis.get('vulnerabilities', []))
            
            # Analyze APK certificates
            apk_cert_analysis = safe_execute(
                lambda: self._analyze_apk_certificates(),
                ErrorContext(component_name="certificate_analyzer", operation="apk_certificate_analysis")
            )
            if apk_cert_analysis:
                analysis.apk_certificates = apk_cert_analysis
            
            # Set analysis metadata
            analysis.analysis_metadata = {
                'certificates_analyzed': self.stats['certificates_analyzed'],
                'pinning_implementations_found': self.stats['pinning_implementations_found'],
                'trust_managers_analyzed': self.stats['trust_managers_analyzed'],
                'validation_bypasses_found': self.stats['validation_bypasses_found'],
                'analysis_methods_used': [
                    'certificate_validation_analysis',
                    'trust_manager_analysis', 
                    'certificate_pinning_analysis',
                    'hostname_verification_analysis',
                    'apk_certificate_analysis'
                ]
            }
            
            self.logger.info(f"Certificate analysis completed: {len(analysis.vulnerabilities)} vulnerabilities found")
            
        except Exception as e:
            self.logger.error(f"Error during certificate analysis: {e}")
            # Create error vulnerability
            error_vuln = self._create_analysis_error_vulnerability(str(e))
            analysis.vulnerabilities.append(error_vuln)
        
        return analysis
    
    def _analyze_certificate_validation(self) -> Dict[str, Any]:
        """Analyze certificate validation implementations."""
        self.logger.info("Analyzing certificate validation implementations...")
        
        validation_analysis = {
            'status': ValidationStatus.UNKNOWN,
            'vulnerabilities': [],
            'validation_methods': [],
            'bypass_detected': False
        }
        
        try:
            if hasattr(self.apk_ctx, 'analyzer') and self.apk_ctx.analyzer:
                classes = self._get_classes_safely()
                
                for class_item in classes:
                    try:
                        class_info = self._extract_class_info(class_item)
                        if not class_info:
                            continue
                        
                        if class_info['type'] == 'androguard' and hasattr(class_item, 'get_source'):
                            source_code = class_item.get_source()
                            self._analyze_certificate_validation_code(
                                source_code, class_info['name'], validation_analysis
                            )
                            self.stats['certificates_analyzed'] += 1
                            
                    except Exception as e:
                        self.logger.debug(f"Error analyzing certificate validation in class: {e}")
                        continue
            
            # Determine overall validation status
            if validation_analysis['bypass_detected']:
                validation_analysis['status'] = ValidationStatus.BYPASSED
            elif validation_analysis['validation_methods']:
                validation_analysis['status'] = ValidationStatus.ENABLED
            else:
                validation_analysis['status'] = ValidationStatus.UNKNOWN
                
        except Exception as e:
            self.logger.error(f"Certificate validation analysis failed: {e}")
            validation_analysis['error'] = str(e)
        
        return validation_analysis
    
    def _analyze_certificate_validation_code(self, source_code: str, class_name: str, analysis: Dict[str, Any]) -> None:
        """Analyze source code for certificate validation patterns."""
        
        # Check for certificate validation bypass patterns
        bypass_patterns = [
            (r'checkServerTrusted.*\{\s*\}', 'Empty checkServerTrusted implementation'),
            (r'checkServerTrusted.*\{\s*return\s*;\s*\}', 'checkServerTrusted with early return'),
            (r'getAcceptedIssuers.*\{\s*return\s+null', 'getAcceptedIssuers returns null'),
            (r'getAcceptedIssuers.*\{\s*return\s+new\s+X509Certificate\[0\]', 'getAcceptedIssuers returns empty array'),
            (r'X509Certificate.*verify.*\{\s*return\s*true', 'Certificate verify always returns true'),
            (r'checkValidity.*\{\s*\}', 'Empty checkValidity implementation')
        ]
        
        for pattern, description in bypass_patterns:
            if re.search(pattern, source_code, re.IGNORECASE | re.DOTALL):
                analysis['bypass_detected'] = True
                self.stats['validation_bypasses_found'] += 1
                
                # Create vulnerability
                vulnerability = self._create_certificate_vulnerability(
                    vuln_id=f"CERT_BYPASS_{len(analysis['vulnerabilities'])+1:03d}",
                    title="Certificate Validation Bypass",
                    severity=SSLTLSSeverity.CRITICAL,
                    description=f"Certificate validation bypass detected: {description}",
                    location=class_name,
                    evidence=self._extract_evidence(source_code, pattern.split('.*')[0]),
                    cwe_id="CWE-295",
                    detection_method="certificate_validation_analysis"
                )
                analysis['vulnerabilities'].append(vulnerability)
        
        # Check for proper certificate validation methods
        validation_patterns = [
            (r'checkServerTrusted.*X509Certificate.*String', 'Custom checkServerTrusted implementation'),
            (r'CertPathValidator\.getInstance', 'CertPathValidator usage'),
            (r'CertificateFactory\.getInstance', 'CertificateFactory usage'),
            (r'X509Certificate.*verify\(', 'Certificate verification call')
        ]
        
        for pattern, description in validation_patterns:
            if re.search(pattern, source_code, re.IGNORECASE):
                analysis['validation_methods'].append({
                    'method': description,
                    'location': class_name,
                    'pattern': pattern
                })
    
    def _analyze_trust_managers(self) -> Dict[str, Any]:
        """Analyze trust manager implementations."""
        self.logger.info("Analyzing trust manager implementations...")
        
        trust_analysis = {
            'custom_managers': [],
            'insecure_managers': [],
            'trust_all_detected': False,
            'vulnerabilities': []
        }
        
        try:
            if hasattr(self.apk_ctx, 'analyzer') and self.apk_ctx.analyzer:
                classes = self._get_classes_safely()
                
                for class_item in classes:
                    try:
                        class_info = self._extract_class_info(class_item)
                        if not class_info:
                            continue
                        
                        if class_info['type'] == 'androguard' and hasattr(class_item, 'get_source'):
                            source_code = class_item.get_source()
                            self._analyze_trust_manager_code(
                                source_code, class_info['name'], trust_analysis
                            )
                            self.stats['trust_managers_analyzed'] += 1
                            
                    except Exception as e:
                        self.logger.debug(f"Error analyzing trust manager in class: {e}")
                        continue
                        
        except Exception as e:
            self.logger.error(f"Trust manager analysis failed: {e}")
            trust_analysis['error'] = str(e)
        
        return trust_analysis
    
    def _analyze_trust_manager_code(self, source_code: str, class_name: str, analysis: Dict[str, Any]) -> None:
        """Analyze source code for trust manager patterns."""
        
        # Check for custom trust manager implementations
        if re.search(r'implements\s+X509TrustManager|extends\s+X509TrustManager', source_code, re.IGNORECASE):
            analysis['custom_managers'].append(class_name)
            
            # Check if it's an insecure implementation
            insecure_patterns = [
                (r'checkServerTrusted.*\{\s*\}', 'Empty checkServerTrusted'),
                (r'checkClientTrusted.*\{\s*\}', 'Empty checkClientTrusted'),
                (r'getAcceptedIssuers.*\{\s*return\s+null', 'Returns null for accepted issuers'),
                (r'getAcceptedIssuers.*\{\s*return\s+new\s+X509Certificate\[0\]', 'Returns empty array for accepted issuers')
            ]
            
            for pattern, description in insecure_patterns:
                if re.search(pattern, source_code, re.IGNORECASE | re.DOTALL):
                    analysis['insecure_managers'].append({
                        'class': class_name,
                        'issue': description,
                        'pattern': pattern
                    })
                    analysis['trust_all_detected'] = True
                    
                    # Create vulnerability
                    vulnerability = self._create_certificate_vulnerability(
                        vuln_id=f"TRUST_MGR_{len(analysis['vulnerabilities'])+1:03d}",
                        title="Insecure Trust Manager",
                        severity=SSLTLSSeverity.CRITICAL,
                        description=f"Insecure trust manager implementation: {description}",
                        location=class_name,
                        evidence=self._extract_evidence(source_code, pattern.split('.*')[0]),
                        cwe_id="CWE-295",
                        detection_method="trust_manager_analysis"
                    )
                    analysis['vulnerabilities'].append(vulnerability)
        
        # Check for trust-all patterns in SSL context initialization
        trust_all_patterns = [
            (r'sslContext\.init\s*\(\s*null\s*,\s*trustAllCerts', 'SSL context initialized with trust-all certificates'),
            (r'new\s+TrustManager\[\]\s*\{\s*new\s+X509TrustManager\s*\(\s*\)\s*\{', 'Anonymous trust-all manager'),
            (r'TrustManager.*checkServerTrusted.*\{\s*\}', 'Trust manager with empty validation')
        ]
        
        for pattern, description in trust_all_patterns:
            if re.search(pattern, source_code, re.IGNORECASE | re.DOTALL):
                analysis['trust_all_detected'] = True
                
                vulnerability = self._create_certificate_vulnerability(
                    vuln_id=f"TRUST_ALL_{len(analysis['vulnerabilities'])+1:03d}",
                    title="Trust-All Certificate Manager",
                    severity=SSLTLSSeverity.CRITICAL,
                    description=f"Trust-all certificate manager detected: {description}",
                    location=class_name,
                    evidence=self._extract_evidence(source_code, pattern.split('.*')[0]),
                    cwe_id="CWE-295",
                    detection_method="trust_manager_analysis"
                )
                analysis['vulnerabilities'].append(vulnerability)
    
    def _analyze_certificate_pinning(self) -> Dict[str, Any]:
        """Analyze certificate pinning implementations using multiple detection methods."""
        self.logger.info("Analyzing certificate pinning with comprehensive detection methods...")
        
        pinning_analysis = {
            'pinning_detected': False,
            'implementations': [],
            'overall_strength': PinningStrength.NONE,
            'detection_methods': {},
            'vulnerabilities': []
        }
        
        try:
            # Method 1: Network Security Config XML parsing
            nsc_findings = self._analyze_nsc_pinning()
            pinning_analysis['detection_methods']['NSC_XML'] = len(nsc_findings)
            pinning_analysis['implementations'].extend(nsc_findings)
            
            # Method 2: Known 3rd-party libraries detection
            library_findings = self._analyze_third_party_pinning()
            pinning_analysis['detection_methods']['THIRD_PARTY'] = len(library_findings)
            pinning_analysis['implementations'].extend(library_findings)
            
            # Method 3: Custom pinning implementation detection
            custom_findings = self._analyze_custom_pinning()
            pinning_analysis['detection_methods']['CUSTOM'] = len(custom_findings)
            pinning_analysis['implementations'].extend(custom_findings)
            
            # Method 4: JNI/Native pinning detection
            jni_findings = self._analyze_jni_pinning()
            pinning_analysis['detection_methods']['JNI'] = len(jni_findings)
            pinning_analysis['implementations'].extend(jni_findings)
            
            # Determine overall pinning status
            if pinning_analysis['implementations']:
                pinning_analysis['pinning_detected'] = True
                self.stats['pinning_implementations_found'] = len(pinning_analysis['implementations'])
                
                # Calculate overall strength
                pinning_analysis['overall_strength'] = self._calculate_overall_pinning_strength(
                    pinning_analysis['implementations']
                )
            
        except Exception as e:
            self.logger.error(f"Certificate pinning analysis failed: {e}")
            pinning_analysis['error'] = str(e)
        
        return pinning_analysis
    
    def _analyze_hostname_verification(self) -> Dict[str, Any]:
        """Analyze hostname verification implementations."""
        self.logger.info("Analyzing hostname verification...")
        
        hostname_analysis = {
            'status': ValidationStatus.UNKNOWN,
            'vulnerabilities': [],
            'verification_disabled': False
        }
        
        try:
            if hasattr(self.apk_ctx, 'analyzer') and self.apk_ctx.analyzer:
                classes = self._get_classes_safely()
                
                for class_item in classes:
                    try:
                        class_info = self._extract_class_info(class_item)
                        if not class_info:
                            continue
                        
                        if class_info['type'] == 'androguard' and hasattr(class_item, 'get_source'):
                            source_code = class_item.get_source()
                            self._analyze_hostname_verification_code(
                                source_code, class_info['name'], hostname_analysis
                            )
                            
                    except Exception as e:
                        self.logger.debug(f"Error analyzing hostname verification in class: {e}")
                        continue
            
            # Determine overall status
            if hostname_analysis['verification_disabled']:
                hostname_analysis['status'] = ValidationStatus.DISABLED
            else:
                hostname_analysis['status'] = ValidationStatus.ENABLED
                
        except Exception as e:
            self.logger.error(f"Hostname verification analysis failed: {e}")
            hostname_analysis['error'] = str(e)
        
        return hostname_analysis
    
    def _analyze_hostname_verification_code(self, source_code: str, class_name: str, analysis: Dict[str, Any]) -> None:
        """Analyze source code for hostname verification patterns."""
        
        # Patterns that disable hostname verification
        disabled_patterns = [
            (r'ALLOW_ALL_HOSTNAME_VERIFIER', 'ALLOW_ALL_HOSTNAME_VERIFIER used'),
            (r'setHostnameVerifier.*ALLOW_ALL', 'setHostnameVerifier with ALLOW_ALL'),
            (r'HostnameVerifier.*verify.*return\s+true', 'HostnameVerifier always returns true'),
            (r'setDefaultHostnameVerifier.*ALLOW_ALL', 'setDefaultHostnameVerifier with ALLOW_ALL'),
            (r'verify.*\{\s*return\s+true\s*;\s*\}', 'verify method always returns true')
        ]
        
        for pattern, description in disabled_patterns:
            if re.search(pattern, source_code, re.IGNORECASE | re.DOTALL):
                analysis['verification_disabled'] = True
                
                vulnerability = self._create_certificate_vulnerability(
                    vuln_id=f"HOSTNAME_{len(analysis['vulnerabilities'])+1:03d}",
                    title="Hostname Verification Disabled",
                    severity=SSLTLSSeverity.HIGH,
                    description=f"Hostname verification disabled: {description}",
                    location=class_name,
                    evidence=self._extract_evidence(source_code, pattern.split('.*')[0]),
                    cwe_id="CWE-295",
                    detection_method="hostname_verification_analysis"
                )
                analysis['vulnerabilities'].append(vulnerability)
    
    def _analyze_apk_certificates(self) -> Dict[str, Any]:
        """Analyze APK signing certificates."""
        self.logger.info("Analyzing APK signing certificates...")
        
        cert_analysis = {
            'signing_certificates': [],
            'certificate_details': {},
            'security_issues': []
        }
        
        try:
            # This would typically analyze the APK's signing certificates
            # Implementation depends on the APK analysis framework being used
            if hasattr(self.apk_ctx, 'get_certificates'):
                certificates = self.apk_ctx.get_certificates()
                cert_analysis['signing_certificates'] = certificates
                
                # Analyze certificate details
                for cert in certificates:
                    cert_details = self._analyze_certificate_details(cert)
                    cert_analysis['certificate_details'][cert.get('serial', 'unknown')] = cert_details
                    
        except Exception as e:
            self.logger.debug(f"APK certificate analysis not available: {e}")
            cert_analysis['error'] = str(e)
        
        return cert_analysis
    
    # Helper methods for pinning detection
    def _analyze_nsc_pinning(self) -> List[CertificatePinningImplementation]:
        """Analyze Network Security Config for certificate pinning."""
        implementations = []
        
        try:
            # Look for network security configuration files
            nsc_files = self._find_network_security_config_files()
            
            for nsc_file in nsc_files:
                try:
                    content = self._read_file_safely(nsc_file)
                    if not content:
                        continue
                    
                    # Parse XML for pin-set configurations
                    pin_sets = self._extract_pin_sets_from_xml(content)
                    
                    for pin_set in pin_sets:
                        implementation = CertificatePinningImplementation(
                            method='Network Security Config',
                            location=nsc_file,
                            strength=PinningStrength.HIGH,
                            details={
                                'domain': pin_set.get('domain', []),
                                'pins': pin_set.get('pins', []),
                                'backup_pins': pin_set.get('backup_pins', []),
                                'expiration': pin_set.get('expiration'),
                                'include_subdomains': pin_set.get('include_subdomains', False)
                            },
                            confidence=0.95  # High confidence for XML parsing
                        )
                        implementations.append(implementation)
                        
                        # Log successful detection
                        self.logger.info(f"NSC pinning detected: {len(pin_set.get('pins', []))} pins for domains {pin_set.get('domain', [])}")
                        
                except Exception as e:
                    self.logger.warning(f"Error parsing NSC file {nsc_file}: {e}")
                    
        except Exception as e:
            self.logger.debug(f"NSC pinning analysis failed: {e}")
        
        return implementations
    
    def _analyze_third_party_pinning(self) -> List[CertificatePinningImplementation]:
        """Analyze third-party library pinning implementations."""
        implementations = []
        
        try:
            # Get Java files for analysis
            java_files = []
            if hasattr(self.apk_ctx, 'get_java_files'):
                java_files = self.apk_ctx.get_java_files()
            
            # Enhanced third-party library patterns with confidence scoring
            pinning_patterns = {
                'okhttp_certificate_pinner': {
                    'patterns': [
                        r'CertificatePinner\.Builder\(\)',
                        r'\.pin\s*\(\s*["\'][^"\']+["\']',
                        r'certificatePinner\s*\(\s*new\s+CertificatePinner',
                        r'CertificatePinner\.pin\s*\('
                    ],
                    'library': 'OkHttp CertificatePinner',
                    'strength': PinningStrength.HIGH,
                    'base_confidence': 0.90
                },
                'trustkit': {
                    'patterns': [
                        r'TrustKit\.initialize',
                        r'TSKPinningValidator',
                        r'kTSKPublicKeyHashes',
                        r'TrustKit.*Configuration'
                    ],
                    'library': 'TrustKit',
                    'strength': PinningStrength.HIGH,
                    'base_confidence': 0.85
                },
                'conscrypt': {
                    'patterns': [
                        r'Conscrypt\.isConscrypt',
                        r'ConscryptSocketFactory',
                        r'Conscrypt.*TrustManager'
                    ],
                    'library': 'Conscrypt',
                    'strength': PinningStrength.MEDIUM,
                    'base_confidence': 0.75
                },
                'retrofit_pinning': {
                    'patterns': [
                        r'Retrofit\.Builder\(\).*certificatePinner',
                        r'OkHttpClient\.Builder\(\).*certificatePinner',
                        r'Retrofit.*sslSocketFactory'
                    ],
                    'library': 'Retrofit with pinning',
                    'strength': PinningStrength.MEDIUM,
                    'base_confidence': 0.70
                },
                'volley_pinning': {
                    'patterns': [
                        r'HurlStack.*SSLSocketFactory',
                        r'Volley.*RequestQueue.*ssl',
                        r'StringRequest.*ssl.*pinning'
                    ],
                    'library': 'Volley with SSL pinning',
                    'strength': PinningStrength.LOW,
                    'base_confidence': 0.65
                }
            }
            
            # Analyze each Java file for pinning patterns
            for file_path in java_files[:200]:  # Limit for performance
                try:
                    content = self._read_file_safely(file_path)
                    if not content:
                        continue
                    
                    # Check each pinning pattern
                    for pattern_key, pattern_info in pinning_patterns.items():
                        for pattern in pattern_info['patterns']:
                            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                            
                            for match in matches:
                                # Calculate enhanced confidence based on context
                                context = self._extract_context_around_match(content, match, 300)
                                confidence = self._calculate_pinning_confidence(
                                    pattern_info['base_confidence'], 
                                    context, 
                                    pattern
                                )
                                
                                # Extract pinning details from context
                                pin_details = self._extract_pinning_details(context, pattern_key)
                                
                                implementation = CertificatePinningImplementation(
                                    method=pattern_info['library'],
                                    location=file_path,
                                    strength=pattern_info['strength'],
                                    details={
                                        'pattern_matched': pattern,
                                        'line_number': content[:match.start()].count('\n') + 1,
                                        'context_snippet': context[:100] + '...',
                                        'pin_count': pin_details.get('pin_count', 0),
                                        'domains': pin_details.get('domains', []),
                                        'backup_pins': pin_details.get('has_backup', False)
                                    },
                                    confidence=confidence
                                )
                                implementations.append(implementation)
                                
                                self.logger.info(f"Third-party pinning detected: {pattern_info['library']} in {file_path}")
                                
                except Exception as e:
                    self.logger.debug(f"Error analyzing file {file_path}: {e}")
                    
        except Exception as e:
            self.logger.debug(f"Third-party pinning analysis failed: {e}")
        
        return implementations
    
    def _analyze_custom_pinning(self) -> List[CertificatePinningImplementation]:
        """Analyze custom certificate pinning implementations."""
        implementations = []
        
        try:
            # Get Java files for analysis
            java_files = []
            if hasattr(self.apk_ctx, 'get_java_files'):
                java_files = self.apk_ctx.get_java_files()
            
            # Custom pinning detection patterns
            custom_patterns = {
                'trust_manager_pinning': {
                    'patterns': [
                        r'class\s+\w+\s+implements\s+X509TrustManager.*checkServerTrusted',
                        r'new\s+X509TrustManager\s*\(\s*\)\s*\{.*checkServerTrusted',
                        r'X509TrustManager.*\{.*certificate.*pin.*\}'
                    ],
                    'strength': PinningStrength.MEDIUM,
                    'base_confidence': 0.80
                },
                'hostname_verifier_pinning': {
                    'patterns': [
                        r'HostnameVerifier.*\{.*certificate.*verify',
                        r'new\s+HostnameVerifier\s*\(\s*\)\s*\{.*verify',
                        r'setDefaultHostnameVerifier.*certificate.*pin'
                    ],
                    'strength': PinningStrength.MEDIUM,
                    'base_confidence': 0.75
                },
                'manual_certificate_validation': {
                    'patterns': [
                        r'PublicKey.*equals\(',
                        r'certificate\.getPublicKey\(\)',
                        r'MessageDigest\.getInstance.*SHA.*',
                        r'certificate.*fingerprint.*equals'
                    ],
                    'strength': PinningStrength.LOW,
                    'base_confidence': 0.70
                },
                'ssl_context_pinning': {
                    'patterns': [
                        r'SSLContext\.init.*TrustManager.*pin',
                        r'SSLSocketFactory.*certificate.*validation',
                        r'HttpsURLConnection.*setSSLSocketFactory.*pin'
                    ],
                    'strength': PinningStrength.MEDIUM,
                    'base_confidence': 0.75
                }
            }
            
            # Analyze each Java file for custom pinning patterns
            for file_path in java_files[:150]:  # Limit for performance
                try:
                    content = self._read_file_safely(file_path)
                    if not content:
                        continue
                    
                    # Check each custom pattern
                    for pattern_key, pattern_info in custom_patterns.items():
                        for pattern in pattern_info['patterns']:
                            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                            
                            for match in matches:
                                # Enhanced context analysis for custom implementations
                                context = self._extract_context_around_match(content, match, 500)
                                
                                # Validate it's actually pinning and not bypass
                                if self._is_pinning_bypass(context):
                                    continue
                                
                                # Calculate confidence based on implementation quality
                                confidence = self._calculate_custom_pinning_confidence(
                                    pattern_info['base_confidence'],
                                    context,
                                    pattern_key
                                )
                                
                                implementation = CertificatePinningImplementation(
                                    method=f'Custom {pattern_key.replace("_", " ").title()}',
                                    location=file_path,
                                    strength=pattern_info['strength'],
                                    details={
                                        'pattern_type': pattern_key,
                                        'pattern_matched': pattern,
                                        'line_number': content[:match.start()].count('\n') + 1,
                                        'implementation_quality': self._assess_implementation_quality(context),
                                        'has_error_handling': 'catch' in context.lower(),
                                        'has_logging': any(log in context.lower() for log in ['log', 'debug', 'error'])
                                    },
                                    confidence=confidence
                                )
                                implementations.append(implementation)
                                
                                self.logger.info(f"Custom pinning detected: {pattern_key} in {file_path}")
                                
                except Exception as e:
                    self.logger.debug(f"Error analyzing custom pinning in {file_path}: {e}")
                    
        except Exception as e:
            self.logger.debug(f"Custom pinning analysis failed: {e}")
        
        return implementations
    
    def _analyze_jni_pinning(self) -> List[CertificatePinningImplementation]:
        """Analyze JNI/Native certificate pinning implementations."""
        implementations = []
        
        try:
            # Look for native libraries
            native_libs = self._find_native_libraries()
            
            # JNI pinning indicators
            jni_patterns = {
                'native_ssl_functions': [
                    'SSL_CTX_set_verify',
                    'SSL_set_verify_callback',
                    'X509_verify_cert',
                    'SSL_get_peer_certificate',
                    'X509_digest'
                ],
                'java_native_methods': [
                    r'native.*ssl.*verify',
                    r'native.*certificate.*pin',
                    r'native.*trust.*manager'
                ]
            }
            
            # Check Java code for JNI method declarations
            if hasattr(self.apk_ctx, 'get_java_files'):
                java_files = self.apk_ctx.get_java_files()
                
                for file_path in java_files[:100]:  # Limit for performance
                    try:
                        content = self._read_file_safely(file_path)
                        if not content:
                            continue
                        
                        # Check for native method declarations related to SSL
                        for pattern in jni_patterns['java_native_methods']:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            
                            for match in matches:
                                context = self._extract_context_around_match(content, match, 200)
                                
                                # Verify it's actually pinning-related
                                if any(keyword in context.lower() for keyword in ['pin', 'certificate', 'ssl', 'tls']):
                                    implementation = CertificatePinningImplementation(
                                        method='JNI/Native SSL Implementation',
                                        location=file_path,
                                        strength=PinningStrength.HIGH,
                                        details={
                                            'native_method': match.group(),
                                            'line_number': content[:match.start()].count('\n') + 1,
                                            'native_libraries': len(native_libs),
                                            'context_snippet': context[:100] + '...'
                                        },
                                        confidence=0.85  # High confidence for native implementations
                                    )
                                    implementations.append(implementation)
                                    
                                    self.logger.info(f"JNI pinning detected: {match.group()} in {file_path}")
                                    
                    except Exception as e:
                        self.logger.debug(f"Error analyzing JNI pinning in {file_path}: {e}")
            
            # Additional analysis of native libraries (if available)
            for lib_path in native_libs:
                try:
                    # This would require binary analysis tools
                    # For now, just note the presence of native libraries
                    if any(ssl_lib in lib_path.lower() for ssl_lib in ['ssl', 'crypto', 'tls']):
                        implementation = CertificatePinningImplementation(
                            method='Native SSL Library',
                            location=lib_path,
                            strength=PinningStrength.MEDIUM,
                            details={
                                'library_type': 'native',
                                'potential_ssl_implementation': True
                            },
                            confidence=0.60  # Lower confidence without binary analysis
                        )
                        implementations.append(implementation)
                        
                        self.logger.info(f"Native SSL library detected: {lib_path}")
                        
                except Exception as e:
                    self.logger.debug(f"Error analyzing native library {lib_path}: {e}")
                    
        except Exception as e:
            self.logger.debug(f"JNI pinning analysis failed: {e}")
        
        return implementations
    
    # Utility methods
    def _load_certificate_patterns(self) -> Dict[str, Any]:
        """Load certificate analysis patterns from configuration."""
        # Load from ssl_patterns_config.yaml
        return {}
    
    def _load_pinning_patterns(self) -> Dict[str, Any]:
        """Load pinning detection patterns from configuration."""
        # Load from ssl_patterns_config.yaml
        return {}
    
    def _load_trust_manager_patterns(self) -> Dict[str, Any]:
        """Load trust manager patterns from configuration."""
        # Load from ssl_patterns_config.yaml
        return {}
    
    def _get_classes_safely(self):
        """Safely get classes from APK analyzer."""
        try:
            if hasattr(self.apk_ctx, 'analyzer') and self.apk_ctx.analyzer:
                return self.apk_ctx.analyzer.get_classes()
            return []
        except Exception as e:
            self.logger.debug(f"Error getting classes: {e}")
            return []
    
    # Enhanced helper methods for SSL pinning detection accuracy
    
    def _find_network_security_config_files(self) -> List[str]:
        """Find Network Security Configuration files in the APK."""
        nsc_files = []
        
        try:
            # Look for common NSC file locations
            if hasattr(self.apk_ctx, 'get_xml_files'):
                xml_files = self.apk_ctx.get_xml_files()
                
                for xml_file in xml_files:
                    if any(nsc_name in xml_file.lower() for nsc_name in [
                        'network_security_config', 'network_config', 'nsc_config'
                    ]):
                        nsc_files.append(xml_file)
            
            # Also check AndroidManifest.xml for networkSecurityConfig reference
            if hasattr(self.apk_ctx, 'get_file_content'):
                manifest_content = self.apk_ctx.get_file_content('AndroidManifest.xml')
                if manifest_content and 'networkSecurityConfig' in manifest_content:
                    # Extract the referenced config file
                    import re
                    match = re.search(r'android:networkSecurityConfig="@xml/([^"]+)"', manifest_content)
                    if match:
                        config_name = match.group(1)
                        config_files = [f for f in xml_files if config_name in f]
                        nsc_files.extend(config_files)
                        
        except Exception as e:
            self.logger.debug(f"Error finding NSC files: {e}")
        
        return list(set(nsc_files))  # Remove duplicates
    
    def _extract_pin_sets_from_xml(self, xml_content: str) -> List[Dict[str, Any]]:
        """Extract pin-set configurations from Network Security Config XML."""
        pin_sets = []
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_content)
            
            # Find all pin-set elements
            for pin_set in root.findall('.//pin-set'):
                pin_set_data = {
                    'domain': [],
                    'pins': [],
                    'backup_pins': [],
                    'expiration': None,
                    'include_subdomains': False
                }
                
                # Extract expiration
                expiration = pin_set.get('expiration')
                if expiration:
                    pin_set_data['expiration'] = expiration
                
                # Find domain configurations
                for domain_config in pin_set.findall('.//domain-config'):
                    for domain in domain_config.findall('.//domain'):
                        domain_name = domain.text
                        if domain_name:
                            pin_set_data['domain'].append(domain_name)
                        
                        # Check for includeSubdomains
                        if domain.get('includeSubdomains') == 'true':
                            pin_set_data['include_subdomains'] = True
                
                # Find pin elements
                for pin in pin_set.findall('.//pin'):
                    digest = pin.get('digest')
                    pin_value = pin.text
                    
                    if digest and pin_value:
                        pin_data = {'digest': digest, 'value': pin_value}
                        
                        # Determine if it's a backup pin
                        if pin.get('backup') == 'true':
                            pin_set_data['backup_pins'].append(pin_data)
                        else:
                            pin_set_data['pins'].append(pin_data)
                
                if pin_set_data['pins'] or pin_set_data['backup_pins']:
                    pin_sets.append(pin_set_data)
                    
        except Exception as e:
            self.logger.debug(f"Error parsing NSC XML: {e}")
            # Fallback to regex parsing
            pin_sets.extend(self._extract_pins_with_regex(xml_content))
        
        return pin_sets
    
    def _extract_pins_with_regex(self, xml_content: str) -> List[Dict[str, Any]]:
        """Fallback method to extract pins using regex when XML parsing fails."""
        pin_sets = []
        
        try:
            import re
            
            # Find pin elements with regex
            pin_pattern = r'<pin\s+digest="([^"]+)">([^<]+)</pin>'
            domain_pattern = r'<domain[^>]*>([^<]+)</domain>'
            
            pins = re.findall(pin_pattern, xml_content)
            domains = re.findall(domain_pattern, xml_content)
            
            if pins:
                pin_set_data = {
                    'domain': domains,
                    'pins': [{'digest': digest, 'value': value} for digest, value in pins],
                    'backup_pins': [],
                    'expiration': None,
                    'include_subdomains': 'includeSubdomains="true"' in xml_content
                }
                pin_sets.append(pin_set_data)
                
        except Exception as e:
            self.logger.debug(f"Error in regex pin extraction: {e}")
        
        return pin_sets
    
    def _read_file_safely(self, file_path: str) -> Optional[str]:
        """Safely read file content with error handling."""
        try:
            if hasattr(self.apk_ctx, 'get_file_content'):
                return self.apk_ctx.get_file_content(file_path)
            else:
                # Fallback to direct file reading
                from pathlib import Path
                file_obj = Path(file_path)
                if file_obj.exists():
                    return file_obj.read_text(encoding='utf-8', errors='ignore')
            return None
        except Exception as e:
            self.logger.debug(f"Error reading file {file_path}: {e}")
            return None
    
    def _extract_context_around_match(self, content: str, match, context_size: int = 300) -> str:
        """Extract context around a regex match for better analysis."""
        start = max(0, match.start() - context_size // 2)
        end = min(len(content), match.end() + context_size // 2)
        return content[start:end]
    
    def _calculate_pinning_confidence(self, base_confidence: float, context: str, pattern: str) -> float:
        """Calculate enhanced confidence for pinning detection based on context analysis."""
        confidence = base_confidence
        
        # Boost confidence for specific high-quality indicators
        high_quality_indicators = [
            'sha256', 'sha1', 'pin-set', 'backup', 'CertificatePinner',
            'TrustKit', 'publickey', 'certificate'
        ]
        
        quality_boost = sum(0.02 for indicator in high_quality_indicators if indicator.lower() in context.lower())
        confidence += min(quality_boost, 0.10)  # Max 10% boost
        
        # Reduce confidence for potential false positives
        false_positive_indicators = [
            'comment', '//', '/*', 'test', 'example', 'demo', 'disabled', 'false'
        ]
        
        fp_penalty = sum(0.03 for indicator in false_positive_indicators if indicator.lower() in context.lower())
        confidence -= min(fp_penalty, 0.15)  # Max 15% penalty
        
        # Boost confidence for proper implementation patterns
        if 'builder' in context.lower() and 'pin' in context.lower():
            confidence += 0.05
        
        if 'backup' in context.lower() and 'pin' in context.lower():
            confidence += 0.03
        
        return max(0.5, min(1.0, confidence))  # Keep within reasonable bounds
    
    def _extract_pinning_details(self, context: str, pattern_key: str) -> Dict[str, Any]:
        """Extract detailed information about pinning implementation from context."""
        details = {
            'pin_count': 0,
            'domains': [],
            'has_backup': False
        }
        
        try:
            import re
            
            # Count pin occurrences
            pin_patterns = [r'\.pin\s*\(', r'sha256', r'sha1', r'pin-set']
            details['pin_count'] = sum(len(re.findall(pattern, context, re.IGNORECASE)) for pattern in pin_patterns)
            
            # Extract domains
            domain_patterns = [
                r'["\']([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']',
                r'hostname.*["\']([^"\']+)["\']'
            ]
            
            for pattern in domain_patterns:
                matches = re.findall(pattern, context)
                for match in matches:
                    if '.' in match and len(match) > 3:  # Basic domain validation
                        details['domains'].append(match)
            
            # Check for backup pins
            details['has_backup'] = any(backup in context.lower() for backup in ['backup', 'fallback', 'secondary'])
            
        except Exception as e:
            self.logger.debug(f"Error extracting pinning details: {e}")
        
        return details
    
    def _is_pinning_bypass(self, context: str) -> bool:
        """Check if the context indicates a pinning bypass rather than implementation."""
        bypass_indicators = [
            'disable', 'bypass', 'ignore', 'skip', 'allow_all', 'trust_all',
            'return true', 'return null', '// todo', '// fixme', 'debug',
            'development', 'testing'
        ]
        
        return any(indicator in context.lower() for indicator in bypass_indicators)
    
    def _calculate_custom_pinning_confidence(self, base_confidence: float, context: str, pattern_key: str) -> float:
        """Calculate confidence for custom pinning implementations."""
        confidence = base_confidence
        
        # Analyze implementation quality
        quality_indicators = {
            'proper_error_handling': ['try', 'catch', 'exception'],
            'certificate_validation': ['certificate', 'chain', 'validate'],
            'public_key_pinning': ['publickey', 'getpublickey', 'keystore'],
            'hash_verification': ['sha256', 'sha1', 'digest', 'hash'],
            'proper_logging': ['log', 'logger', 'debug', 'info']
        }
        
        for quality_type, indicators in quality_indicators.items():
            if any(indicator in context.lower() for indicator in indicators):
                confidence += 0.02
        
        # Penalty for poor practices
        poor_practices = [
            'return true', 'return null', 'empty', '// todo', '// hack'
        ]
        
        for practice in poor_practices:
            if practice in context.lower():
                confidence -= 0.05
        
        return max(0.5, min(1.0, confidence))
    
    def _assess_implementation_quality(self, context: str) -> str:
        """Assess the quality of a custom pinning implementation."""
        quality_score = 0
        
        # Positive indicators
        if any(indicator in context.lower() for indicator in ['try', 'catch', 'exception']):
            quality_score += 2
        
        if any(indicator in context.lower() for indicator in ['validate', 'verify', 'check']):
            quality_score += 2
        
        if any(indicator in context.lower() for indicator in ['log', 'debug', 'error']):
            quality_score += 1
        
        if any(indicator in context.lower() for indicator in ['backup', 'fallback']):
            quality_score += 1
        
        # Negative indicators
        if any(indicator in context.lower() for indicator in ['return true', 'return null']):
            quality_score -= 3
        
        if any(indicator in context.lower() for indicator in ['todo', 'fixme', 'hack']):
            quality_score -= 2
        
        if quality_score >= 4:
            return 'high'
        elif quality_score >= 2:
            return 'medium'
        elif quality_score >= 0:
            return 'low'
        else:
            return 'poor'
    
    def _find_native_libraries(self) -> List[str]:
        """Find native libraries (.so files) in the APK."""
        native_libs = []
        
        try:
            if hasattr(self.apk_ctx, 'get_files'):
                all_files = self.apk_ctx.get_files('*.so')
                native_libs.extend(all_files)
            
            # Also look in common native library directories
            lib_dirs = ['lib/', 'libs/', 'jni/']
            for lib_dir in lib_dirs:
                if hasattr(self.apk_ctx, 'get_files'):
                    dir_files = self.apk_ctx.get_files(f'{lib_dir}*')
                    native_libs.extend([f for f in dir_files if f.endswith('.so')])
                    
        except Exception as e:
            self.logger.debug(f"Error finding native libraries: {e}")
        
        return list(set(native_libs))  # Remove duplicates
    
    def _calculate_overall_pinning_strength(self, implementations: List) -> PinningStrength:
        """Calculate overall pinning strength based on all implementations found."""
        if not implementations:
            return PinningStrength.NONE
        
        # Count implementations by strength
        strength_counts = {
            PinningStrength.HIGH: 0,
            PinningStrength.MEDIUM: 0,
            PinningStrength.LOW: 0
        }
        
        for impl in implementations:
            if hasattr(impl, 'strength'):
                strength_counts[impl.strength] += 1
        
        # Determine overall strength
        if strength_counts[PinningStrength.HIGH] >= 2:
            return PinningStrength.HIGH
        elif strength_counts[PinningStrength.HIGH] >= 1 or strength_counts[PinningStrength.MEDIUM] >= 2:
            return PinningStrength.MEDIUM
        elif strength_counts[PinningStrength.MEDIUM] >= 1 or strength_counts[PinningStrength.LOW] >= 2:
            return PinningStrength.LOW
        else:
            return PinningStrength.LOW
    
    def _create_certificate_vulnerability(self, vuln_id: str, title: str, severity: SSLTLSSeverity,
                                        description: str, location: str, evidence: str,
                                        cwe_id: str = "", detection_method: str = "", **kwargs) -> SSLTLSVulnerability:
        """Create a certificate-related vulnerability."""
        
        # Calculate professional confidence
        ssl_context = kwargs.get('ssl_context', {})
        evidence_data = kwargs.get('evidence_data', {})
        confidence = self.confidence_calculator.calculate_ssl_confidence(
            None, ssl_context, evidence_data
        )
        
        vulnerability = SSLTLSVulnerability(
            vulnerability_id=vuln_id,
            title=title,
            severity=severity,
            confidence=confidence,
            description=description,
            location=location,
            evidence=evidence,
            cwe_id=cwe_id,
            detection_method=detection_method,
            masvs_control="MSTG-NETWORK-3",
            **kwargs
        )
        
        return vulnerability
    
    def _create_analysis_error_vulnerability(self, error_message: str) -> SSLTLSVulnerability:
        """Create vulnerability for analysis errors."""
        return SSLTLSVulnerability(
            vulnerability_id="CERT_ANALYSIS_ERROR",
            title="Certificate Analysis Error",
            severity=SSLTLSSeverity.INFO,
            confidence=0.1,
            description=f"Error during certificate analysis: {error_message}",
            location="Certificate Analyzer",
            evidence=error_message,
            cwe_id="",
            detection_method="error_handling"
        )
    
    def _extract_evidence(self, source_code: str, pattern: str) -> str:
        """Extract evidence snippet from source code."""
        try:
            lines = source_code.split('\n')
            for i, line in enumerate(lines):
                if pattern.lower() in line.lower():
                    start = max(0, i - 2)
                    end = min(len(lines), i + 3)
                    return '\n'.join(lines[start:end])
        except Exception:
            pass
        return f"Pattern match: {pattern}"
    
    def _extract_class_info(self, class_item) -> Optional[Dict[str, str]]:
        """Extract class information safely."""
        try:
            if hasattr(class_item, 'get_name'):
                return {
                    'name': class_item.get_name(),
                    'type': 'androguard'
                }
        except Exception as e:
            self.logger.debug(f"Could not extract class info: {e}")
        return None
    
    def _analyze_certificate_details(self, certificate: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze individual certificate details."""
        return {
            'analyzed': True,
            'details': certificate
        } 