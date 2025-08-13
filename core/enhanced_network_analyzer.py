#!/usr/bin/env python3
"""
Enhanced Network Security Analyzer for AODS - Advanced Implementation

This analyzer provides comprehensive network security analysis with enhanced
coverage for mobile application network security testing.

Advanced Network Coverage:
- Network communication security patterns
- TLS/SSL security analysis
- Certificate validation testing
- API security analysis
- Data transmission security validation
- Network protocol security testing

"""

import re
import logging
import json
import xml.etree.ElementTree as ET
import hashlib
import os
import tempfile
import zipfile
import ssl
import socket
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse
from datetime import datetime

logger = logging.getLogger(__name__)

class NetworkSeverityLevel(Enum):
    """Network vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH" 
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class NetworkTestCategory(Enum):
    """Network test categories for MASTG coverage"""
    HTTPS_TRAFFIC = "https_traffic"
    CERTIFICATE_PINNING = "certificate_pinning"
    PROTOCOL_SECURITY = "protocol_security"
    TLS_CONFIGURATION = "tls_configuration"
    API_SECURITY = "api_security"
    AUTHENTICATION = "authentication"
    NETWORK_CONFIG = "network_config"
    WEBSOCKET_SECURITY = "websocket_security"
    PROXY_SECURITY = "proxy_security"
    DNS_SECURITY = "dns_security"
    MONITORING_PREVENTION = "monitoring_prevention"
    NETWORK_HEADERS = "network_headers"

@dataclass
class NetworkFinding:
    """Network security finding with MASTG mapping"""
    test_id: str
    title: str
    description: str
    severity: NetworkSeverityLevel
    category: NetworkTestCategory
    file_path: str
    line_number: int = 0
    evidence: List[str] = None
    recommendations: List[str] = None
    masvs_controls: List[str] = None
    cwe_ids: List[str] = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []
        if self.recommendations is None:
            self.recommendations = []
        if self.masvs_controls is None:
            self.masvs_controls = []
        if self.cwe_ids is None:
            self.cwe_ids = []

class EnhancedNetworkAnalyzer:
    """
    Enhanced network security analyzer implementing advanced network security requirements.
    
    This analyzer provides comprehensive security analysis for mobile network communications
    including TLS/SSL, certificate validation, and API security testing.
    """
    
    def __init__(self):
        """Initialize the enhanced network analyzer with advanced test patterns."""
        self.findings: List[NetworkFinding] = []
        self.analysis_stats = {
            'files_analyzed': 0,
            'network_configs_found': 0,
            'api_endpoints_found': 0,
            'certificate_pins_found': 0,
            'tls_configs_found': 0,
            'websocket_usage': 0,
            'total_analysis_time': 0.0
        }
        
        # Initialize test patterns for comprehensive coverage
        self._initialize_mastg_patterns()
        
        logger.debug("Enhanced Network Analyzer initialized for comprehensive network security analysis (MASTG-TEST-0031 to 0060)")
    
    def _initialize_mastg_patterns(self):
        """Initialize patterns for MASTG-TEST-0031 through MASTG-TEST-0060."""
        
        # MASTG-TEST-0031-0035: HTTPS and Certificate Pinning Patterns
        self.https_patterns = {
            'insecure_http': [
                r'http://(?!localhost|127\.0\.0\.1)',
                r'HttpURLConnection.*http://',
                r'OkHttpClient.*http://',
                r'Retrofit.*http://',
                r'Volley.*http://'
            ],
            'certificate_pinning': [
                r'CertificatePinner',
                r'TrustManager',
                r'X509TrustManager',
                r'PinningTrustManager',
                r'SSLContext\.getInstance',
                r'trustManager'
            ],
            'pinning_bypass': [
                r'checkServerTrusted.*\{\s*\}',
                r'X509TrustManager.*\{\s*return;\s*\}',
                r'TrustAllCerts',
                r'NullTrustManager',
                r'AcceptAllCertificates'
            ]
        }
        
        # MASTG-TEST-0036-0040: Protocol and API Security Patterns
        self.protocol_patterns = {
            'tls_configuration': [
                r'SSLContext\.getInstance\("TLS"\)',
                r'SSLContext\.getInstance\("SSL"\)',
                r'setEnabledProtocols',
                r'setEnabledCipherSuites',
                r'SSLv3|TLSv1\.0|TLSv1\.1'  # Weak protocols
            ],
            'api_security': [
                r'Authorization:\s*Bearer',
                r'X-API-Key',
                r'apikey\s*=',
                r'token\s*=',
                r'access_token'
            ],
            'insecure_api': [
                r'api.*http://',
                r'endpoint.*http://',
                r'service.*http://',
                r'rest.*http://'
            ]
        }
        
        # MASTG-TEST-0041-0045: WebSocket and Network Request Patterns
        self.websocket_patterns = {
            'websocket_usage': [
                r'WebSocket',
                r'ws://',
                r'wss://',
                r'SocketIO',
                r'WebSocketClient'
            ],
            'insecure_websocket': [
                r'ws://(?!localhost|127\.0\.0\.1)',
                r'WebSocket.*ws://',
                r'allowAllHostnameVerifier'
            ]
        }
        
        # MASTG-TEST-0046-0050: Network Configuration Patterns
        self.network_config_patterns = {
            'timeout_config': [
                r'connectTimeout',
                r'readTimeout',
                r'writeTimeout',
                r'setConnectTimeout',
                r'setReadTimeout'
            ],
            'proxy_config': [
                r'Proxy\.Type',
                r'ProxySelector',
                r'setProxy',
                r'HTTP_PROXY',
                r'HTTPS_PROXY'
            ],
            'dns_config': [
                r'InetAddress\.getByName',
                r'DNS.*lookup',
                r'DnsLookup',
                r'resolver'
            ]
        }
        
        # MASTG-TEST-0051-0055: SSL/TLS and Security Headers Patterns
        self.security_headers_patterns = {
            'ssl_tls_config': [
                r'TLSv1\.3',
                r'TLSv1\.2',
                r'SSLv3',  # Weak
                r'TLSv1\.0',  # Weak
                r'TLSv1\.1'   # Weak
            ],
            'cipher_suites': [
                r'TLS_AES_256_GCM_SHA384',
                r'TLS_CHACHA20_POLY1305_SHA256',
                r'TLS_AES_128_GCM_SHA256',
                r'DES',  # Weak
                r'RC4',  # Weak
                r'MD5'   # Weak
            ],
            'security_headers': [
                r'Strict-Transport-Security',
                r'Content-Security-Policy',
                r'X-Content-Type-Options',
                r'X-Frame-Options',
                r'X-XSS-Protection'
            ]
        }
        
        # MASTG-TEST-0056-0060: Advanced Network Security Patterns
        self.advanced_network_patterns = {
            'rate_limiting': [
                r'RateLimiter',
                r'Throttle',
                r'rate.*limit',
                r'RequestsPerSecond',
                r'ApiRateLimit'
            ],
            'cors_config': [
                r'Access-Control-Allow-Origin',
                r'CORS',
                r'CrossOrigin',
                r'AllowedOrigins'
            ],
            'network_monitoring': [
                r'NetworkInterceptor',
                r'LoggingInterceptor',
                r'HttpLoggingInterceptor',
                r'NetworkSecurityConfig'
            ]
        }

    def analyze_network_security(self, apk_path: str, source_code_path: str = None) -> List[NetworkFinding]:
        """
        Comprehensive network security analysis for enhanced security coverage.
        
        This method performs thorough analysis of network security features and identifies
        potential vulnerabilities in network communications.
        """
        
        logger.debug("Starting comprehensive network security analysis...")
        self.findings.clear()
        
        try:
            # Analyze APK structure and network-related files
            self._analyze_apk_network_structure(apk_path)
            
            # Analyze source code if available
            if source_code_path and os.path.exists(source_code_path):
                self._analyze_network_source_code(source_code_path)
            
            # Analyze network security configuration
            self._analyze_network_security_config(apk_path)
            
            # Perform specialized network tests
            self._perform_https_traffic_tests(apk_path)
            self._perform_certificate_pinning_tests(apk_path)
            self._perform_protocol_security_tests(apk_path)
            self._perform_api_security_tests(apk_path)
            self._perform_websocket_security_tests(apk_path)
            self._perform_network_config_tests(apk_path)
            self._perform_security_headers_tests(apk_path)
            
            logger.debug(f"Network analysis completed. Found {len(self.findings)} findings.")
            
        except Exception as e:
            logger.error(f"Error during network security analysis: {e}")
            self._add_finding(
                "MASTG-TEST-ERROR",
                "Network Analysis Error",
                f"Failed to complete network analysis: {e}",
                NetworkSeverityLevel.HIGH,
                NetworkTestCategory.NETWORK_CONFIG,
                apk_path
            )
        
        return self.findings
    
    def _analyze_apk_network_structure(self, apk_path: str):
        """Analyze APK file structure for network-related configurations."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                file_list = apk_zip.namelist()
                
                # Check for network security config files
                network_config_files = [f for f in file_list if 'network_security_config' in f or 'network-security-config' in f]
                if network_config_files:
                    for config_file in network_config_files:
                        self._analyze_network_config_file(apk_zip, config_file)
                
                # Check for certificate files
                cert_files = [f for f in file_list if f.endswith(('.pem', '.crt', '.cer', '.p7b', '.p7c'))]
                if cert_files:
                    self._add_finding(
                        "MASTG-TEST-0033",
                        "Certificate Files Found in APK",
                        f"Found certificate files in APK: {cert_files}",
                        NetworkSeverityLevel.MEDIUM,
                        NetworkTestCategory.CERTIFICATE_PINNING,
                        apk_path,
                        evidence=cert_files,
                        recommendations=["Review certificate pinning implementation", "Ensure certificates are properly validated"],
                        cwe_ids=["CWE-295"]
                    )
                
                # Check for network library configurations
                lib_files = [f for f in file_list if any(lib in f.lower() for lib in ['okhttp', 'retrofit', 'volley', 'picasso'])]
                self.analysis_stats['network_configs_found'] = len(network_config_files)
                
        except Exception as e:
            logger.error(f"Error analyzing APK network structure: {e}")
    
    def _analyze_network_config_file(self, apk_zip: zipfile.ZipFile, config_file: str):
        """Analyze network security configuration file."""
        try:
            config_content = apk_zip.read(config_file).decode('utf-8', errors='ignore')
            
            # Check for cleartext traffic allowance
            if 'cleartextTrafficPermitted="true"' in config_content:
                self._add_finding(
                    "MASTG-TEST-0031",
                    "Cleartext Traffic Permitted",
                    f"Network security config allows cleartext traffic in {config_file}",
                    NetworkSeverityLevel.HIGH,
                    NetworkTestCategory.HTTPS_TRAFFIC,
                    config_file,
                    evidence=["cleartextTrafficPermitted=\"true\""],
                    recommendations=["Disable cleartext traffic", "Use HTTPS for all network communication"],
                    masvs_controls=["MASVS-NETWORK-1"],
                    cwe_ids=["CWE-319"]
                )
            
            # Check for trust anchor overrides
            if 'trust-anchors' in config_content and 'system' not in config_content:
                self._add_finding(
                    "MASTG-TEST-0034",
                    "Custom Trust Anchors Without System CAs",
                    f"Custom trust anchors configured without system CAs in {config_file}",
                    NetworkSeverityLevel.MEDIUM,
                    NetworkTestCategory.CERTIFICATE_PINNING,
                    config_file,
                    recommendations=["Include system trust anchors", "Review custom certificate validation logic"],
                    cwe_ids=["CWE-295"]
                )
                
        except Exception as e:
            logger.debug(f"Error analyzing network config file {config_file}: {e}")
    
    def _analyze_network_source_code(self, source_path: str):
        """Analyze source code for network security patterns."""
        try:
            for root, dirs, files in os.walk(source_path):
                for file in files:
                    if file.endswith(('.java', '.kt', '.xml', '.json')):
                        file_path = os.path.join(root, file)
                        self._analyze_network_source_file(file_path)
                        self.analysis_stats['files_analyzed'] += 1
        except Exception as e:
            logger.error(f"Error analyzing network source code: {e}")
    
    def _analyze_network_source_file(self, file_path: str):
        """Analyze individual source file for network security patterns."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Check different network security patterns
            self._check_https_patterns(content, file_path)
            self._check_certificate_pinning_patterns(content, file_path)
            self._check_protocol_security_patterns(content, file_path)
            self._check_api_security_patterns(content, file_path)
            self._check_websocket_patterns(content, file_path)
            self._check_network_config_patterns(content, file_path)
            self._check_security_headers_patterns(content, file_path)
            
        except Exception as e:
            logger.debug(f"Error analyzing network source file {file_path}: {e}")
    
    def _check_https_patterns(self, content: str, file_path: str):
        """Check for HTTPS traffic and certificate pinning patterns."""
        # Check for insecure HTTP usage
        for pattern in self.https_patterns['insecure_http']:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                self._add_finding(
                    "MASTG-TEST-0031",
                    "Insecure HTTP Usage Detected",
                    f"Insecure HTTP communication found: {pattern}",
                    NetworkSeverityLevel.HIGH,
                    NetworkTestCategory.HTTPS_TRAFFIC,
                    file_path,
                    evidence=matches[:3],
                    recommendations=["Use HTTPS instead of HTTP", "Implement certificate pinning"],
                    masvs_controls=["MASVS-NETWORK-1"],
                    cwe_ids=["CWE-319"]
                )
        
        # Check for certificate pinning bypass
        for pattern in self.https_patterns['pinning_bypass']:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                self._add_finding(
                    "MASTG-TEST-0033",
                    "Certificate Pinning Bypass Detected",
                    f"Certificate validation bypass pattern found: {pattern}",
                    NetworkSeverityLevel.CRITICAL,
                    NetworkTestCategory.CERTIFICATE_PINNING,
                    file_path,
                    evidence=matches[:3],
                    recommendations=["Remove certificate pinning bypass", "Implement proper certificate validation"],
                    masvs_controls=["MASVS-NETWORK-1"],
                    cwe_ids=["CWE-295"]
                )
    
    def _check_certificate_pinning_patterns(self, content: str, file_path: str):
        """Check for certificate pinning implementation patterns."""
        pinning_found = False
        for pattern in self.https_patterns['certificate_pinning']:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                pinning_found = True
                self.analysis_stats['certificate_pins_found'] += len(matches)
        
        # If network requests are found but no pinning implementation
        if any(term in content.lower() for term in ['httpurlconnection', 'okhttpclient', 'retrofit']) and not pinning_found:
            self._add_finding(
                "MASTG-TEST-0032",
                "Missing Certificate Pinning Implementation",
                "Network requests found without certificate pinning implementation",
                NetworkSeverityLevel.MEDIUM,
                NetworkTestCategory.CERTIFICATE_PINNING,
                file_path,
                recommendations=["Implement certificate pinning for all HTTPS connections"],
                masvs_controls=["MASVS-NETWORK-1"],
                cwe_ids=["CWE-295"]
            )
    
    def _check_protocol_security_patterns(self, content: str, file_path: str):
        """Check for protocol security configuration patterns."""
        # Check for weak TLS protocols
        weak_protocols = ['SSLv3', 'TLSv1.0', 'TLSv1.1']
        for protocol in weak_protocols:
            if protocol in content:
                self._add_finding(
                    "MASTG-TEST-0037",
                    f"Weak TLS Protocol Usage: {protocol}",
                    f"Weak TLS protocol {protocol} found in network configuration",
                    NetworkSeverityLevel.HIGH,
                    NetworkTestCategory.TLS_CONFIGURATION,
                    file_path,
                    evidence=[protocol],
                    recommendations=[f"Remove {protocol} support", "Use TLS 1.2 or higher"],
                    masvs_controls=["MASVS-NETWORK-1"],
                    cwe_ids=["CWE-326"]
                )
    
    def _check_api_security_patterns(self, content: str, file_path: str):
        """Check for API security patterns."""
        # Check for API endpoints
        api_patterns = [r'https?://[^/]+/api/', r'endpoint\s*=\s*["\'][^"\']+["\']']
        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self.analysis_stats['api_endpoints_found'] += len(matches)
        
        # Check for insecure API usage
        for pattern in self.protocol_patterns['insecure_api']:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self._add_finding(
                    "MASTG-TEST-0039",
                    "Insecure API Endpoint Usage",
                    f"Insecure API endpoint found: {pattern}",
                    NetworkSeverityLevel.HIGH,
                    NetworkTestCategory.API_SECURITY,
                    file_path,
                    evidence=matches[:3],
                    recommendations=["Use HTTPS for all API endpoints", "Implement proper API authentication"],
                    masvs_controls=["MASVS-NETWORK-1"],
                    cwe_ids=["CWE-319"]
                )
    
    def _check_websocket_patterns(self, content: str, file_path: str):
        """Check for WebSocket security patterns."""
        # Check for WebSocket usage
        for pattern in self.websocket_patterns['websocket_usage']:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self.analysis_stats['websocket_usage'] += len(matches)
        
        # Check for insecure WebSocket usage
        for pattern in self.websocket_patterns['insecure_websocket']:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self._add_finding(
                    "MASTG-TEST-0042",
                    "Insecure WebSocket Usage",
                    f"Insecure WebSocket connection found: {pattern}",
                    NetworkSeverityLevel.HIGH,
                    NetworkTestCategory.WEBSOCKET_SECURITY,
                    file_path,
                    evidence=matches[:3],
                    recommendations=["Use WSS instead of WS", "Implement WebSocket authentication"],
                    masvs_controls=["MASVS-NETWORK-1"],
                    cwe_ids=["CWE-319"]
                )
    
    def _check_network_config_patterns(self, content: str, file_path: str):
        """Check for network configuration patterns."""
        # Check timeout configurations
        timeout_patterns = self.network_config_patterns['timeout_config']
        for pattern in timeout_patterns:
            matches = re.findall(f'{pattern}\\s*\\(\\s*(\\d+)', content, re.IGNORECASE)
            for match in matches:
                timeout_value = int(match)
                if timeout_value > 30000:  # > 30 seconds
                    self._add_finding(
                        "MASTG-TEST-0046",
                        "Excessive Network Timeout Configuration",
                        f"Network timeout set to {timeout_value}ms which may be excessive",
                        NetworkSeverityLevel.LOW,
                        NetworkTestCategory.NETWORK_CONFIG,
                        file_path,
                        evidence=[f"{pattern}({timeout_value})"],
                        recommendations=["Review and optimize network timeout values"]
                    )
    
    def _check_security_headers_patterns(self, content: str, file_path: str):
        """Check for security headers patterns."""
        # Check for weak cipher suites
        weak_ciphers = ['DES', 'RC4', 'MD5']
        for cipher in weak_ciphers:
            if cipher in content and 'cipher' in content.lower():
                self._add_finding(
                    "MASTG-TEST-0052",
                    f"Weak Cipher Suite Usage: {cipher}",
                    f"Weak cipher suite {cipher} found in network configuration",
                    NetworkSeverityLevel.HIGH,
                    NetworkTestCategory.TLS_CONFIGURATION,
                    file_path,
                    evidence=[cipher],
                    recommendations=[f"Remove {cipher} cipher support", "Use strong cipher suites"],
                    masvs_controls=["MASVS-NETWORK-1"],
                    cwe_ids=["CWE-327"]
                )
    
    def _analyze_network_security_config(self, apk_path: str):
        """Analyze network security configuration in manifest."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    manifest_content = apk_zip.read('AndroidManifest.xml')
                    # Basic manifest analysis for network config
                    self._check_manifest_network_config(manifest_content.decode('utf-8', errors='ignore'))
        except Exception as e:
            logger.debug(f"Error analyzing network security config: {e}")
    
    def _check_manifest_network_config(self, manifest_content: str):
        """Check manifest for network security configuration."""
        if 'android:usesCleartextTraffic="true"' in manifest_content:
            self._add_finding(
                "MASTG-TEST-0035",
                "Cleartext Traffic Enabled in Manifest",
                "Application manifest allows cleartext traffic",
                NetworkSeverityLevel.HIGH,
                NetworkTestCategory.NETWORK_CONFIG,
                "AndroidManifest.xml",
                evidence=["android:usesCleartextTraffic=\"true\""],
                recommendations=["Disable cleartext traffic in manifest", "Use HTTPS for all communications"],
                masvs_controls=["MASVS-NETWORK-1"],
                cwe_ids=["CWE-319"]
            )
    
    # Specialized test methods for different MASTG test categories
    def _perform_https_traffic_tests(self, apk_path: str):
        """Perform HTTPS traffic security tests (MASTG-TEST-0031)."""
        logger.debug("Performing HTTPS traffic tests (MASTG-TEST-0031)...")
        
        try:
            # Check APK for HTTPS usage patterns
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Check for proper HTTPS implementations
                for file_info in apk_zip.namelist():
                    if file_info.endswith('.xml') or file_info.endswith('.properties'):
                        try:
                            content = apk_zip.read(file_info).decode('utf-8', errors='ignore')
                            self._analyze_https_configurations(content, file_info)
                        except Exception as e:
                            logger.debug(f"Error analyzing {file_info}: {e}")
                            
        except Exception as e:
            logger.error(f"Error in HTTPS traffic tests: {e}")
    
    def _analyze_https_configurations(self, content: str, file_path: str):
        """Analyze HTTPS configurations in file content."""
        # Check for insecure HTTP usage
        http_patterns = [
            r'http://(?!schemas\.android\.com)',  # Exclude Android schema URLs
            r'HttpURLConnection.*http://',
            r'OkHttpClient.*http://'
        ]
        
        for pattern in http_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self._add_finding(
                    "MASTG-TEST-0031",
                    "Insecure HTTP Usage Detected",
                    f"HTTP connections found where HTTPS should be used: {pattern}",
                    NetworkSeverityLevel.HIGH,
                    NetworkTestCategory.HTTPS_TRAFFIC,
                    file_path,
                    evidence=matches[:3],
                    recommendations=["Replace HTTP with HTTPS", "Implement secure communication protocols"],
                    masvs_controls=["MASVS-NETWORK-1"],
                    cwe_ids=["CWE-319"]
                )
    
    def _perform_certificate_pinning_tests(self, apk_path: str):
        """Perform certificate pinning tests (MASTG-TEST-0032, 0033)."""
        logger.debug("Performing certificate pinning tests (MASTG-TEST-0032, 0033)...")
        
        try:
            # Check for certificate pinning implementations
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                pinning_found = False
                
                for file_info in apk_zip.namelist():
                    if file_info.endswith('.xml') or file_info.endswith('.properties'):
                        try:
                            content = apk_zip.read(file_info).decode('utf-8', errors='ignore')
                            if self._check_certificate_pinning_implementation(content, file_info):
                                pinning_found = True
                        except Exception as e:
                            logger.debug(f"Error analyzing {file_info}: {e}")
                
                # If no pinning found, add warning
                if not pinning_found:
                    self._add_finding(
                        "MASTG-TEST-0032",
                        "Certificate Pinning Not Implemented",
                        "No certificate pinning implementation detected",
                        NetworkSeverityLevel.MEDIUM,
                        NetworkTestCategory.CERTIFICATE_PINNING,
                        "APK Analysis",
                        evidence=["No pinning configuration found"],
                        recommendations=["Implement certificate pinning", "Use Network Security Configuration"],
                        masvs_controls=["MASVS-NETWORK-1"],
                        cwe_ids=["CWE-295"]
                    )
                    
        except Exception as e:
            logger.error(f"Error in certificate pinning tests: {e}")
    
    def _check_certificate_pinning_implementation(self, content: str, file_path: str) -> bool:
        """Check for certificate pinning implementation."""
        pinning_patterns = [
            r'<pin-set>',
            r'certificatePinner',
            r'TrustManager',
            r'X509TrustManager'
        ]
        
        for pattern in pinning_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self._add_finding(
                    "MASTG-TEST-0033",
                    "Certificate Pinning Implementation Found",
                    f"Certificate pinning implementation detected: {pattern}",
                    NetworkSeverityLevel.INFO,
                    NetworkTestCategory.CERTIFICATE_PINNING,
                    file_path,
                    evidence=[pattern],
                    recommendations=["Verify pinning configuration", "Test pinning bypass protection"],
                    masvs_controls=["MASVS-NETWORK-1"]
                )
                return True
        return False
    
    def _perform_protocol_security_tests(self, apk_path: str):
        """Perform protocol security tests (MASTG-TEST-0036, 0037)."""
        logger.debug("Performing protocol security tests (MASTG-TEST-0036, 0037)...")
        
        try:
            # Check for secure protocol configurations
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                for file_info in apk_zip.namelist():
                    if file_info.endswith('.xml') or file_info.endswith('.properties'):
                        try:
                            content = apk_zip.read(file_info).decode('utf-8', errors='ignore')
                            self._analyze_protocol_security(content, file_path)
                        except Exception as e:
                            logger.debug(f"Error analyzing {file_info}: {e}")
                            
        except Exception as e:
            logger.error(f"Error in protocol security tests: {e}")
    
    def _analyze_protocol_security(self, content: str, file_path: str):
        """Analyze protocol security configurations."""
        # Check for weak TLS versions
        weak_tls_patterns = [
            r'SSLv[23]',
            r'TLSv1\.0',
            r'TLSv1\.1',
            r'SSL_.*_WITH_.*_NULL_'
        ]
        
        for pattern in weak_tls_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self._add_finding(
                    "MASTG-TEST-0036",
                    "Weak TLS/SSL Protocol Configuration",
                    f"Weak TLS/SSL protocol detected: {pattern}",
                    NetworkSeverityLevel.HIGH,
                    NetworkTestCategory.PROTOCOL_SECURITY,
                    file_path,
                    evidence=matches[:3],
                    recommendations=["Use TLS 1.2 or higher", "Disable weak cipher suites"],
                    masvs_controls=["MASVS-NETWORK-1"],
                    cwe_ids=["CWE-327"]
                )
    
    def _perform_api_security_tests(self, apk_path: str):
        """Perform API security tests (MASTG-TEST-0039, 0040)."""
        logger.debug("Performing API security tests (MASTG-TEST-0039, 0040)...")
        
        try:
            # Check for API security implementations
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                for file_info in apk_zip.namelist():
                    if file_info.endswith('.xml') or file_info.endswith('.properties'):
                        try:
                            content = apk_zip.read(file_info).decode('utf-8', errors='ignore')
                            self._analyze_api_security(content, file_path)
                        except Exception as e:
                            logger.debug(f"Error analyzing {file_info}: {e}")
                            
        except Exception as e:
            logger.error(f"Error in API security tests: {e}")
    
    def _analyze_api_security(self, content: str, file_path: str):
        """Analyze API security configurations."""
        # Check for hardcoded API keys
        api_key_patterns = [
            r'api[_-]?key[\s]*[:=][\s]*["\']?[A-Za-z0-9]{20,}["\']?',
            r'secret[_-]?key[\s]*[:=][\s]*["\']?[A-Za-z0-9]{20,}["\']?',
            r'access[_-]?token[\s]*[:=][\s]*["\']?[A-Za-z0-9]{20,}["\']?'
        ]
        
        for pattern in api_key_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self._add_finding(
                    "MASTG-TEST-0039",
                    "Hardcoded API Credentials Detected",
                    f"Hardcoded API credentials found: {pattern}",
                    NetworkSeverityLevel.CRITICAL,
                    NetworkTestCategory.API_SECURITY,
                    file_path,
                    evidence=["[REDACTED - API Key Pattern]"],
                    recommendations=["Remove hardcoded credentials", "Use secure credential storage"],
                    masvs_controls=["MASVS-NETWORK-1"],
                    cwe_ids=["CWE-798"]
                )
    
    def _perform_websocket_security_tests(self, apk_path: str):
        """Perform WebSocket security tests (MASTG-TEST-0042)."""
        logger.debug("Performing WebSocket security tests (MASTG-TEST-0042)...")
        
        try:
            # Check for WebSocket security configurations
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                for file_info in apk_zip.namelist():
                    if file_info.endswith('.xml') or file_info.endswith('.properties'):
                        try:
                            content = apk_zip.read(file_info).decode('utf-8', errors='ignore')
                            self._analyze_websocket_security(content, file_path)
                        except Exception as e:
                            logger.debug(f"Error analyzing {file_info}: {e}")
                            
        except Exception as e:
            logger.error(f"Error in WebSocket security tests: {e}")
    
    def _analyze_websocket_security(self, content: str, file_path: str):
        """Analyze WebSocket security configurations."""
        # Check for insecure WebSocket usage
        insecure_ws_patterns = [
            r'ws://(?!localhost|127\.0\.0\.1)',  # Exclude localhost
            r'WebSocket.*ws://',
            r'SocketIOClient.*ws://'
        ]
        
        for pattern in insecure_ws_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self._add_finding(
                    "MASTG-TEST-0042",
                    "Insecure WebSocket Connection",
                    f"Insecure WebSocket (WS) connection found: {pattern}",
                    NetworkSeverityLevel.HIGH,
                    NetworkTestCategory.WEBSOCKET_SECURITY,
                    file_path,
                    evidence=matches[:3],
                    recommendations=["Use WSS instead of WS", "Implement WebSocket authentication"],
                    masvs_controls=["MASVS-NETWORK-1"],
                    cwe_ids=["CWE-319"]
                )
    
    def _perform_network_config_tests(self, apk_path: str):
        """Perform network configuration tests (MASTG-TEST-0046, 0047)."""
        logger.debug("Performing network configuration tests (MASTG-TEST-0046, 0047)...")
        
        try:
            # Check for network configuration security
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Check for network security configuration files
                nsc_files = [f for f in apk_zip.namelist() if 'network_security_config' in f]
                
                if not nsc_files:
                    self._add_finding(
                        "MASTG-TEST-0046",
                        "Network Security Configuration Missing",
                        "No Network Security Configuration file found",
                        NetworkSeverityLevel.MEDIUM,
                        NetworkTestCategory.NETWORK_CONFIG,
                        "APK Analysis",
                        evidence=["No network_security_config.xml"],
                        recommendations=["Implement Network Security Configuration", "Define security policies"],
                        masvs_controls=["MASVS-NETWORK-1"],
                        cwe_ids=["CWE-16"]
                    )
                else:
                    # Analyze existing NSC files
                    for nsc_file in nsc_files:
                        try:
                            content = apk_zip.read(nsc_file).decode('utf-8', errors='ignore')
                            self._analyze_network_security_config(content, nsc_file)
                        except Exception as e:
                            logger.debug(f"Error analyzing {nsc_file}: {e}")
                            
        except Exception as e:
            logger.error(f"Error in network configuration tests: {e}")
    
    def _analyze_network_security_config(self, content: str, file_path: str):
        """Analyze Network Security Configuration content."""
        # Check for permissive configurations
        permissive_patterns = [
            r'cleartextTrafficPermitted="true"',
            r'<trust-anchors>.*<certificates\s+src="user"/>',
            r'<pin-set.*expiration="[^"]*2019[^"]*"'  # Expired pins
        ]
        
        for pattern in permissive_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            if matches:
                self._add_finding(
                    "MASTG-TEST-0047",
                    "Permissive Network Security Configuration",
                    f"Permissive network configuration detected: {pattern}",
                    NetworkSeverityLevel.HIGH,
                    NetworkTestCategory.NETWORK_CONFIG,
                    file_path,
                    evidence=matches[:3],
                    recommendations=["Restrict network security configuration", "Disable cleartext traffic"],
                    masvs_controls=["MASVS-NETWORK-1"],
                    cwe_ids=["CWE-16"]
                )
    
    def _perform_security_headers_tests(self, apk_path: str):
        """Perform security headers tests (MASTG-TEST-0058, 0059)."""
        logger.debug("Performing security headers tests (MASTG-TEST-0058, 0059)...")
        
        try:
            # Check for security headers implementations
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                for file_info in apk_zip.namelist():
                    if file_info.endswith('.xml') or file_info.endswith('.properties'):
                        try:
                            content = apk_zip.read(file_info).decode('utf-8', errors='ignore')
                            self._analyze_security_headers(content, file_path)
                        except Exception as e:
                            logger.debug(f"Error analyzing {file_info}: {e}")
                            
        except Exception as e:
            logger.error(f"Error in security headers tests: {e}")
    
    def _analyze_security_headers(self, content: str, file_path: str):
        """Analyze security headers configurations."""
        # Check for missing security headers
        security_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]
        
        headers_found = []
        for header in security_headers:
            if header in content:
                headers_found.append(header)
        
        missing_headers = [h for h in security_headers if h not in headers_found]
        
        if missing_headers:
            self._add_finding(
                "MASTG-TEST-0058",
                "Missing Security Headers",
                f"Missing security headers: {', '.join(missing_headers)}",
                NetworkSeverityLevel.MEDIUM,
                NetworkTestCategory.NETWORK_HEADERS,
                file_path,
                evidence=missing_headers,
                recommendations=["Implement missing security headers", "Configure web server security headers"],
                masvs_controls=["MASVS-NETWORK-1"],
                cwe_ids=["CWE-16"]
            )
    
    def _add_finding(self, test_id: str, title: str, description: str, severity: NetworkSeverityLevel,
                    category: NetworkTestCategory, file_path: str, line_number: int = 0,
                    evidence: List[str] = None, recommendations: List[str] = None,
                    masvs_controls: List[str] = None, cwe_ids: List[str] = None):
        """Add a network security finding to the results."""
        finding = NetworkFinding(
            test_id=test_id,
            title=title,
            description=description,
            severity=severity,
            category=category,
            file_path=file_path,
            line_number=line_number,
            evidence=evidence or [],
            recommendations=recommendations or [],
            masvs_controls=masvs_controls or [],
            cwe_ids=cwe_ids or []
        )
        self.findings.append(finding)
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get comprehensive analysis summary."""
        severity_counts = {}
        category_counts = {}
        
        for finding in self.findings:
            severity = finding.severity.value
            category = finding.category.value
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
        
        return {
            "total_findings": len(self.findings),
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
            "analysis_statistics": self.analysis_stats,
            "mastg_coverage": {
                "tests_covered": list(set(f.test_id for f in self.findings)),
                "coverage_percentage": len(set(f.test_id for f in self.findings)) / 30 * 100  # 30 tests in comprehensive analysis
            },
            "metadata": {
                "analyzer_version": "4.0.0",
                "analysis_type": "comprehensive",
                "phase": "Advanced Network Security Analysis",
                "analysis_timestamp": datetime.now().isoformat()
            }
        }
    
    def export_findings_json(self) -> Dict[str, Any]:
        """Export findings in JSON format."""
        return {
            "phase": "Advanced Network Security Analysis",
            "analyzer": "EnhancedNetworkAnalyzer",
            "findings": [
                {
                    "test_id": f.test_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "evidence": f.evidence,
                    "recommendations": f.recommendations,
                    "masvs_controls": f.masvs_controls,
                    "cwe_ids": f.cwe_ids
                }
                for f in self.findings
            ],
            "summary": self.get_analysis_summary()
        } 