#!/usr/bin/env python3
"""
TLS Configuration Analyzer Module

This module provides comprehensive TLS/SSL protocol and cipher suite analysis
for Android applications, including protocol version assessment, cipher strength
evaluation, and security configuration validation.

"""

import re
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from enum import Enum

from core.shared_infrastructure.dependency_injection import AnalysisContext
from core.shared_infrastructure.analysis_exceptions import TLSAnalysisError, safe_execute, ErrorContext
from .data_structures import (
    TLSConfigurationAnalysis, TLSConfiguration, SSLTLSVulnerability,
    SSLTLSSeverity, TLSProtocol
)
from .confidence_calculator import SSLTLSConfidenceCalculator

class CipherStrength(Enum):
    """Cipher suite strength levels."""
    VERY_STRONG = "VERY_STRONG"
    STRONG = "STRONG"
    MEDIUM = "MEDIUM"
    WEAK = "WEAK"
    BROKEN = "BROKEN"

class TLSConfigurationAnalyzer:
    """
    Comprehensive TLS/SSL configuration analyzer.
    
    Provides enterprise-grade analysis of TLS configurations including:
    - TLS/SSL protocol version analysis
    - Cipher suite strength assessment
    - Perfect Forward Secrecy evaluation
    - Security configuration validation
    """
    
    def __init__(self, context: AnalysisContext, confidence_calculator: SSLTLSConfidenceCalculator, logger: logging.Logger):
        """Initialize TLS configuration analyzer with dependency injection."""
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = logger
        self.apk_ctx = context.apk_ctx
        
        # Initialize TLS analysis patterns and data
        self.protocol_patterns = self._initialize_protocol_patterns()
        self.cipher_patterns = self._initialize_cipher_patterns()
        self.weak_cipher_suites = self._initialize_weak_ciphers()
        self.strong_cipher_suites = self._initialize_strong_ciphers()
        
        # Analysis statistics
        self.stats = {
            'tls_configs_analyzed': 0,
            'protocols_detected': 0,
            'ciphers_detected': 0,
            'security_issues_found': 0
        }
    
    def analyze_tls_configuration(self) -> TLSConfigurationAnalysis:
        """
        Perform comprehensive TLS configuration analysis.
        
        Returns:
            TLSConfigurationAnalysis containing complete TLS security assessment
        """
        self.logger.info("Starting comprehensive TLS configuration analysis...")
        
        analysis = TLSConfigurationAnalysis()
        
        try:
            # Analyze TLS/SSL protocol configurations
            protocol_analysis = safe_execute(
                lambda: self._analyze_protocol_configurations(),
                ErrorContext(component_name="tls_configuration_analyzer", operation="protocol_analysis")
            )
            if protocol_analysis:
                analysis.protocol_configurations = protocol_analysis.get('configurations', [])
                analysis.vulnerabilities.extend(protocol_analysis.get('vulnerabilities', []))
            
            # Analyze cipher suite configurations
            cipher_analysis = safe_execute(
                lambda: self._analyze_cipher_configurations(),
                ErrorContext(component_name="tls_configuration_analyzer", operation="cipher_analysis")
            )
            if cipher_analysis:
                analysis.cipher_configurations = cipher_analysis.get('cipher_suites', [])
                analysis.vulnerabilities.extend(cipher_analysis.get('vulnerabilities', []))
            
            # Analyze SSL context configurations
            ssl_context_analysis = safe_execute(
                lambda: self._analyze_ssl_contexts(),
                ErrorContext(component_name="tls_configuration_analyzer", operation="ssl_context_analysis")
            )
            if ssl_context_analysis:
                analysis.ssl_contexts = ssl_context_analysis.get('contexts', [])
                analysis.weak_configurations = ssl_context_analysis.get('weak_configs', [])
                analysis.vulnerabilities.extend(ssl_context_analysis.get('vulnerabilities', []))
            
            # Analyze Perfect Forward Secrecy
            pfs_analysis = safe_execute(
                lambda: self._analyze_perfect_forward_secrecy(),
                ErrorContext(component_name="tls_configuration_analyzer", operation="pfs_analysis")
            )
            if pfs_analysis:
                for config in analysis.protocol_configurations:
                    if hasattr(config, 'perfect_forward_secrecy'):
                        config.perfect_forward_secrecy = pfs_analysis.get('pfs_enabled', False)
                analysis.vulnerabilities.extend(pfs_analysis.get('vulnerabilities', []))
            
            # Calculate security scores
            analysis.protocol_security_score = self._calculate_protocol_security_score(analysis)
            analysis.cipher_security_score = self._calculate_cipher_security_score(analysis)
            analysis.overall_tls_score = self._calculate_overall_tls_score(analysis)
            
            self.logger.info(f"TLS configuration analysis completed: {len(analysis.vulnerabilities)} issues found")
            
        except Exception as e:
            self.logger.error(f"Error during TLS configuration analysis: {e}")
            # Create error vulnerability
            error_vuln = self._create_analysis_error_vulnerability(str(e))
            analysis.vulnerabilities.append(error_vuln)
        
        return analysis
    
    def _analyze_protocol_configurations(self) -> Dict[str, Any]:
        """Analyze TLS/SSL protocol configurations."""
        self.logger.info("Analyzing TLS/SSL protocol configurations...")
        
        protocol_analysis = {
            'configurations': [],
            'vulnerabilities': [],
            'protocols_found': set(),
            'weak_protocols': []
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
                            self._analyze_protocol_code(
                                source_code, class_info['name'], protocol_analysis
                            )
                            self.stats['tls_configs_analyzed'] += 1
                            
                    except Exception as e:
                        self.logger.debug(f"Error analyzing TLS protocol in class: {e}")
                        continue
            
            # Create TLS configurations from findings
            for protocol in protocol_analysis['protocols_found']:
                config = TLSConfiguration()
                config.enabled_protocols = [protocol]
                config.weak_protocols = [p for p in [protocol] if p in protocol_analysis['weak_protocols']]
                protocol_analysis['configurations'].append(config)
                
        except Exception as e:
            self.logger.error(f"Protocol configuration analysis failed: {e}")
            protocol_analysis['error'] = str(e)
        
        return protocol_analysis
    
    def _analyze_protocol_code(self, source_code: str, class_name: str, analysis: Dict[str, Any]) -> None:
        """Analyze source code for TLS protocol patterns."""
        
        # TLS/SSL protocol version patterns
        protocol_patterns = [
            (r'TLSv1\.3', TLSProtocol.TLS_1_3, 'strong'),
            (r'TLSv1\.2', TLSProtocol.TLS_1_2, 'strong'),
            (r'TLSv1\.1', TLSProtocol.TLS_1_1, 'weak'),
            (r'TLSv1\.0', TLSProtocol.TLS_1_0, 'weak'),
            (r'SSLv3', TLSProtocol.SSL_3_0, 'broken'),
            (r'SSLv2', TLSProtocol.SSL_2_0, 'broken')
        ]
        
        for pattern, protocol, strength in protocol_patterns:
            if re.search(pattern, source_code, re.IGNORECASE):
                analysis['protocols_found'].add(protocol.value)
                self.stats['protocols_detected'] += 1
                
                if strength in ['weak', 'broken']:
                    analysis['weak_protocols'].append(protocol.value)
                    
                    # Create vulnerability for weak protocols
                    severity = SSLTLSSeverity.HIGH if strength == 'weak' else SSLTLSSeverity.CRITICAL
                    vulnerability = self._create_tls_vulnerability(
                        vuln_id=f"TLS_PROTO_{len(analysis['vulnerabilities'])+1:03d}",
                        title=f"Weak TLS/SSL Protocol: {protocol.value}",
                        severity=severity,
                        description=f"Application uses {strength} TLS/SSL protocol version: {protocol.value}",
                        location=class_name,
                        evidence=self._extract_evidence(source_code, pattern),
                        cwe_id="CWE-326",
                        detection_method="protocol_analysis"
                    )
                    analysis['vulnerabilities'].append(vulnerability)
        
        # Check for protocol configuration methods
        config_patterns = [
            (r'setEnabledProtocols\s*\(', 'setEnabledProtocols method call'),
            (r'SSLContext\.getInstance\s*\(', 'SSLContext getInstance call'),
            (r'SSLSocketFactory.*protocols', 'SSLSocketFactory protocol configuration'),
            (r'HttpsURLConnection.*protocols', 'HttpsURLConnection protocol setting')
        ]
        
        for pattern, description in config_patterns:
            if re.search(pattern, source_code, re.IGNORECASE):
                self.logger.debug(f"Found TLS configuration pattern: {description} in {class_name}")
    
    def _analyze_cipher_configurations(self) -> Dict[str, Any]:
        """Analyze cipher suite configurations."""
        self.logger.info("Analyzing cipher suite configurations...")
        
        cipher_analysis = {
            'cipher_suites': [],
            'vulnerabilities': [],
            'weak_ciphers': [],
            'strong_ciphers': []
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
                            self._analyze_cipher_code(
                                source_code, class_info['name'], cipher_analysis
                            )
                            
                    except Exception as e:
                        self.logger.debug(f"Error analyzing ciphers in class: {e}")
                        continue
                        
        except Exception as e:
            self.logger.error(f"Cipher configuration analysis failed: {e}")
            cipher_analysis['error'] = str(e)
        
        return cipher_analysis
    
    def _analyze_cipher_code(self, source_code: str, class_name: str, analysis: Dict[str, Any]) -> None:
        """Analyze source code for cipher suite patterns."""
        
        # Check for weak cipher suites
        for cipher_name, cipher_info in self.weak_cipher_suites.items():
            pattern = cipher_info.get('pattern', cipher_name)
            if re.search(pattern, source_code, re.IGNORECASE):
                analysis['weak_ciphers'].append(cipher_name)
                analysis['cipher_suites'].append(cipher_name)
                self.stats['ciphers_detected'] += 1
                self.stats['security_issues_found'] += 1
                
                # Create vulnerability
                vulnerability = self._create_tls_vulnerability(
                    vuln_id=f"WEAK_CIPHER_{len(analysis['vulnerabilities'])+1:03d}",
                    title=f"Weak Cipher Suite: {cipher_name}",
                    severity=SSLTLSSeverity.HIGH,
                    description=f"Weak or broken cipher suite detected: {cipher_info.get('description', cipher_name)}",
                    location=class_name,
                    evidence=self._extract_evidence(source_code, pattern),
                    cwe_id="CWE-326",
                    detection_method="cipher_analysis"
                )
                analysis['vulnerabilities'].append(vulnerability)
        
        # Check for strong cipher suites
        for cipher_name, cipher_info in self.strong_cipher_suites.items():
            pattern = cipher_info.get('pattern', cipher_name)
            if re.search(pattern, source_code, re.IGNORECASE):
                analysis['strong_ciphers'].append(cipher_name)
                analysis['cipher_suites'].append(cipher_name)
                self.stats['ciphers_detected'] += 1
        
        # Check for cipher configuration methods
        cipher_config_patterns = [
            (r'setEnabledCipherSuites\s*\(', 'setEnabledCipherSuites method'),
            (r'getSupportedCipherSuites\s*\(', 'getSupportedCipherSuites method'),
            (r'CipherSuite\.' , 'CipherSuite reference'),
            (r'cipher.*suites?', 'General cipher suite reference')
        ]
        
        for pattern, description in cipher_config_patterns:
            if re.search(pattern, source_code, re.IGNORECASE):
                self.logger.debug(f"Found cipher configuration: {description} in {class_name}")
    
    def _analyze_ssl_contexts(self) -> Dict[str, Any]:
        """Analyze SSL context configurations."""
        self.logger.info("Analyzing SSL context configurations...")
        
        ssl_analysis = {
            'contexts': [],
            'weak_configs': [],
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
                            self._analyze_ssl_context_code(
                                source_code, class_info['name'], ssl_analysis
                            )
                            
                    except Exception as e:
                        self.logger.debug(f"Error analyzing SSL context in class: {e}")
                        continue
                        
        except Exception as e:
            self.logger.error(f"SSL context analysis failed: {e}")
            ssl_analysis['error'] = str(e)
        
        return ssl_analysis
    
    def _analyze_ssl_context_code(self, source_code: str, class_name: str, analysis: Dict[str, Any]) -> None:
        """Analyze source code for SSL context patterns."""
        
        # Check for weak SSL context configurations
        weak_ssl_patterns = [
            (r'SSLContext\.getInstance\s*\(\s*["\']SSL["\']', 'Generic SSL context (weak)'),
            (r'SSLContext\.getInstance\s*\(\s*["\']SSLv3["\']', 'SSLv3 context (broken)'),
            (r'SSLContext\.getInstance\s*\(\s*["\']SSLv2["\']', 'SSLv2 context (broken)'),
            (r'sslContext\.init\s*\(\s*null\s*,.*null', 'SSL context with null parameters'),
            (r'SSLSocketFactory.*getInsecure', 'Insecure SSL socket factory')
        ]
        
        for pattern, description in weak_ssl_patterns:
            if re.search(pattern, source_code, re.IGNORECASE | re.DOTALL):
                analysis['weak_configs'].append({
                    'type': 'Weak SSL Context',
                    'location': class_name,
                    'description': description,
                    'pattern': pattern
                })
                
                # Create vulnerability
                severity = SSLTLSSeverity.CRITICAL if 'broken' in description else SSLTLSSeverity.HIGH
                vulnerability = self._create_tls_vulnerability(
                    vuln_id=f"SSL_CTX_{len(analysis['vulnerabilities'])+1:03d}",
                    title="Weak SSL Context Configuration",
                    severity=severity,
                    description=f"Weak SSL context configuration: {description}",
                    location=class_name,
                    evidence=self._extract_evidence(source_code, pattern.split('\\s')[0]),
                    cwe_id="CWE-326",
                    detection_method="ssl_context_analysis"
                )
                analysis['vulnerabilities'].append(vulnerability)
        
        # Check for proper SSL context configurations
        strong_ssl_patterns = [
            (r'SSLContext\.getInstance\s*\(\s*["\']TLSv1\.3["\']', 'TLS 1.3 context'),
            (r'SSLContext\.getInstance\s*\(\s*["\']TLSv1\.2["\']', 'TLS 1.2 context'),
            (r'SSLContext\.getInstance\s*\(\s*["\']TLS["\']', 'Modern TLS context')
        ]
        
        for pattern, description in strong_ssl_patterns:
            if re.search(pattern, source_code, re.IGNORECASE):
                analysis['contexts'].append({
                    'type': 'Secure SSL Context',
                    'location': class_name,
                    'description': description
                })
    
    def _analyze_perfect_forward_secrecy(self) -> Dict[str, Any]:
        """Analyze Perfect Forward Secrecy support."""
        self.logger.info("Analyzing Perfect Forward Secrecy support...")
        
        pfs_analysis = {
            'pfs_enabled': False,
            'pfs_ciphers': [],
            'vulnerabilities': []
        }
        
        try:
            # PFS-enabled cipher patterns
            pfs_patterns = [
                (r'ECDHE', 'ECDHE key exchange'),
                (r'DHE', 'DHE key exchange'),
                (r'TLS_ECDHE.*', 'ECDHE cipher suite'),
                (r'TLS_DHE.*', 'DHE cipher suite')
            ]
            
            if hasattr(self.apk_ctx, 'analyzer') and self.apk_ctx.analyzer:
                classes = self._get_classes_safely()
                
                for class_item in classes:
                    try:
                        class_info = self._extract_class_info(class_item)
                        if not class_info:
                            continue
                        
                        if class_info['type'] == 'androguard' and hasattr(class_item, 'get_source'):
                            source_code = class_item.get_source()
                            
                            for pattern, description in pfs_patterns:
                                if re.search(pattern, source_code, re.IGNORECASE):
                                    pfs_analysis['pfs_enabled'] = True
                                    pfs_analysis['pfs_ciphers'].append({
                                        'cipher': description,
                                        'location': class_info['name']
                                    })
                            
                    except Exception as e:
                        self.logger.debug(f"Error analyzing PFS in class: {e}")
                        continue
            
            # If no PFS support found, create informational finding
            if not pfs_analysis['pfs_enabled']:
                vulnerability = self._create_tls_vulnerability(
                    vuln_id="PFS_NOT_ENFORCED",
                    title="Perfect Forward Secrecy Not Enforced",
                    severity=SSLTLSSeverity.MEDIUM,
                    description="No Perfect Forward Secrecy support detected in TLS configuration",
                    location="TLS Configuration",
                    evidence="No ECDHE or DHE cipher suites found",
                    cwe_id="CWE-326",
                    detection_method="pfs_analysis"
                )
                pfs_analysis['vulnerabilities'].append(vulnerability)
                
        except Exception as e:
            self.logger.error(f"PFS analysis failed: {e}")
            pfs_analysis['error'] = str(e)
        
        return pfs_analysis
    
    def _calculate_protocol_security_score(self, analysis: TLSConfigurationAnalysis) -> int:
        """Calculate protocol security score."""
        score = 100
        
        # Deduct points for each vulnerability
        for vuln in analysis.vulnerabilities:
            if 'protocol' in vuln.title.lower():
                if vuln.severity == SSLTLSSeverity.CRITICAL:
                    score -= 40
                elif vuln.severity == SSLTLSSeverity.HIGH:
                    score -= 20
                elif vuln.severity == SSLTLSSeverity.MEDIUM:
                    score -= 10
        
        return max(0, score)
    
    def _calculate_cipher_security_score(self, analysis: TLSConfigurationAnalysis) -> int:
        """Calculate cipher security score."""
        score = 100
        
        # Deduct points for weak ciphers
        for vuln in analysis.vulnerabilities:
            if 'cipher' in vuln.title.lower():
                if vuln.severity == SSLTLSSeverity.CRITICAL:
                    score -= 30
                elif vuln.severity == SSLTLSSeverity.HIGH:
                    score -= 15
                elif vuln.severity == SSLTLSSeverity.MEDIUM:
                    score -= 8
        
        return max(0, score)
    
    def _calculate_overall_tls_score(self, analysis: TLSConfigurationAnalysis) -> int:
        """Calculate overall TLS security score."""
        protocol_score = analysis.protocol_security_score
        cipher_score = analysis.cipher_security_score
        
        # Weighted average
        overall_score = int((protocol_score * 0.6) + (cipher_score * 0.4))
        
        return overall_score
    
    # Initialize pattern data
    def _initialize_protocol_patterns(self) -> Dict[str, Any]:
        """Initialize TLS protocol patterns."""
        return {
            'weak_protocols': [
                'TLSv1.0', 'TLSv1.1', 'SSLv2', 'SSLv3', 'SSL'
            ],
            'strong_protocols': [
                'TLSv1.2', 'TLSv1.3'
            ]
        }
    
    def _initialize_cipher_patterns(self) -> Dict[str, Any]:
        """Initialize cipher pattern data."""
        return {
            'weak_indicators': ['NULL', 'EXPORT', 'DES', 'RC4', 'MD5'],
            'strong_indicators': ['AES.*GCM', 'ChaCha20', 'ECDHE', 'SHA256', 'SHA384']
        }
    
    def _initialize_weak_ciphers(self) -> Dict[str, Dict[str, str]]:
        """Initialize weak cipher suite database."""
        return {
            "NULL": {
                "pattern": r"NULL",
                "description": "No encryption",
                "strength": "BROKEN"
            },
            "EXPORT": {
                "pattern": r"EXPORT",
                "description": "Export-grade encryption (weak)",
                "strength": "BROKEN"
            },
            "DES": {
                "pattern": r"\bDES\b",
                "description": "DES encryption (deprecated)",
                "strength": "BROKEN"
            },
            "3DES": {
                "pattern": r"3DES",
                "description": "3DES encryption (deprecated)",
                "strength": "WEAK"
            },
            "RC4": {
                "pattern": r"RC4",
                "description": "RC4 stream cipher (broken)",
                "strength": "BROKEN"
            },
            "MD5": {
                "pattern": r"MD5",
                "description": "MD5 hash (weak)",
                "strength": "WEAK"
            }
        }
    
    def _initialize_strong_ciphers(self) -> Dict[str, Dict[str, str]]:
        """Initialize strong cipher suite database."""
        return {
            "TLS_AES_256_GCM_SHA384": {
                "pattern": r"TLS_AES_256_GCM_SHA384",
                "description": "AES-256-GCM with SHA-384",
                "strength": "VERY_STRONG"
            },
            "TLS_AES_128_GCM_SHA256": {
                "pattern": r"TLS_AES_128_GCM_SHA256", 
                "description": "AES-128-GCM with SHA-256",
                "strength": "STRONG"
            },
            "TLS_CHACHA20_POLY1305_SHA256": {
                "pattern": r"TLS_CHACHA20_POLY1305_SHA256",
                "description": "ChaCha20-Poly1305",
                "strength": "VERY_STRONG"
            },
            "ECDHE_RSA_AES_GCM": {
                "pattern": r"ECDHE.*RSA.*AES.*GCM",
                "description": "ECDHE-RSA with AES-GCM",
                "strength": "STRONG"
            }
        }
    
    # Utility methods
    def _get_classes_safely(self):
        """Safely get classes from APK analyzer."""
        try:
            if hasattr(self.apk_ctx, 'analyzer') and self.apk_ctx.analyzer:
                return self.apk_ctx.analyzer.get_classes()
        except Exception as e:
            self.logger.debug(f"Could not get classes: {e}")
        return []
    
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
    
    def _create_tls_vulnerability(self, vuln_id: str, title: str, severity: SSLTLSSeverity,
                                description: str, location: str, evidence: str,
                                cwe_id: str = "", detection_method: str = "", **kwargs) -> SSLTLSVulnerability:
        """Create a TLS-related vulnerability."""
        
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
            masvs_control="MSTG-NETWORK-1",
            **kwargs
        )
        
        return vulnerability
    
    def _create_analysis_error_vulnerability(self, error_message: str) -> SSLTLSVulnerability:
        """Create vulnerability for analysis errors."""
        return SSLTLSVulnerability(
            vulnerability_id="TLS_ANALYSIS_ERROR",
            title="TLS Configuration Analysis Error",
            severity=SSLTLSSeverity.INFO,
            confidence=0.1,
            description=f"Error during TLS configuration analysis: {error_message}",
            location="TLS Configuration Analyzer",
            evidence=error_message,
            cwe_id="",
            detection_method="error_handling"
        ) 