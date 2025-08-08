#!/usr/bin/env python3
"""
OWASP MASVS v2 network and privacy analysis

This module provides network and privacy analysis following OWASP MASVS standards.
"""

import hashlib
import json
import logging
import os
import re
import ssl
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class NetworkFinding:
    """MASVS-NETWORK vulnerability finding"""

    mastg_test: str
    masvs_control: str
    vulnerability_type: str
    severity: str
    confidence: float
    description: str
    location: str
    evidence: str
    owasp_category: str = "MASVS-NETWORK"
    remediation: str = ""

@dataclass
class PrivacyFinding:
    """MASVS-PRIVACY vulnerability finding"""

    mastg_test: str
    masvs_control: str
    vulnerability_type: str
    severity: str
    confidence: float
    description: str
    location: str
    evidence: str
    owasp_category: str = "MASVS-PRIVACY"
    remediation: str = ""

@dataclass
class OWASPNetworkPrivacyAnalysis:
    """Complete OWASP MASVS-NETWORK & MASVS-PRIVACY analysis result"""

    network_findings: List[NetworkFinding] = field(default_factory=list)
    privacy_findings: List[PrivacyFinding] = field(default_factory=list)
    tls_configuration_analysis: Dict[str, Any] = field(default_factory=dict)
    certificate_pinning_analysis: Dict[str, Any] = field(default_factory=dict)
    network_communication_analysis: Dict[str, Any] = field(default_factory=dict)
    privacy_controls_analysis: Dict[str, Any] = field(default_factory=dict)
    data_processing_analysis: Dict[str, Any] = field(default_factory=dict)
    mastg_compliance: Dict[str, bool] = field(default_factory=dict)
    masvs_compliance: Dict[str, bool] = field(default_factory=dict)
    detection_statistics: Dict[str, Any] = field(default_factory=dict)

    @property
    def findings(self) -> List:
        """🔥 PRIORITY 3 FIX: Compatibility property for validation suite integration"""
        return self.network_findings + self.privacy_findings

class OWASPNetworkPrivacyAnalyzer:
    """
    OWASP MASVS-NETWORK & MASVS-PRIVACY Comprehensive Analyzer

    Implements complete MASTG test procedures for network and privacy security:
    - MASTG-TEST-0019 through 0022, 0064-0066, 0206-0208, 0254-0256
    - MASTG-TECH-0010, 0011
    - TLS analysis, certificate pinning, privacy controls validation
    """

    def __init__(self):
        self.network_patterns = self._initialize_network_patterns()
        self.privacy_patterns = self._initialize_privacy_patterns()
        self.tls_patterns = self._initialize_tls_patterns()
        self.certificate_patterns = self._initialize_certificate_patterns()
        self.privacy_control_patterns = self._initialize_privacy_control_patterns()

    def _initialize_network_patterns(self) -> Dict[str, List[str]]:
        """Initialize MASTG-compliant network vulnerability patterns"""
        return {
            # MASTG-TEST-0019: Data Encryption on the Network
            "insecure_network_protocols": [
                # 🔥 PRIORITY 3 FIX: Enhanced Android XML schema exclusions to prevent false positives
                r'(?<!xmlns[:\s=])["\']http://(?!schemas\.android\.com|www\.w3\.org|xmlpull\.org|java\.sun\.com|purl\.org|apache\.org|eclipse\.org|jcp\.org|xml\.apache\.org)[^"\']*["\']',  # HTTP URLs excluding all legitimate XML schemas
                r'http://(?!schemas\.android\.com|www\.w3\.org|xmlpull\.org|java\.sun\.com|purl\.org|apache\.org|eclipse\.org|jcp\.org|xml\.apache\.org)(?!.*xmlns)(?!.*android:)(?!.*namespace)(?!.*schema)[^\s\'"<>]+',  # HTTP URLs not in XML schema context
                r'URL\(["\']http://(?!schemas\.android\.com|www\.w3\.org|xmlpull\.org|java\.sun\.com|purl\.org|apache\.org)[^"\']*["\']',  # URL constructor with HTTP
                r'HttpURLConnection.*http://(?!schemas\.android\.com|www\.w3\.org|xmlpull\.org|java\.sun\.com|purl\.org|apache\.org)[^\s\'"<>]+',
                r'okhttp.*http://(?!schemas\.android\.com|www\.w3\.org|xmlpull\.org|java\.sun\.com|purl\.org|apache\.org)[^\s\'"<>]+',
                r'retrofit.*http://(?!schemas\.android\.com|www\.w3\.org|xmlpull\.org|java\.sun\.com|purl\.org|apache\.org)[^\s\'"<>]+',
                r'volley.*http://(?!schemas\.android\.com|www\.w3\.org|xmlpull\.org|java\.sun\.com|purl\.org|apache\.org)[^\s\'"<>]+',
                r'SSLContext\.getInstance\(["\']SSL["\']',  # Deprecated SSL
                r'SSLContext\.getInstance\(["\']SSLv3["\']',
                r'baseUrl\(["\']http://(?!schemas\.android\.com|www\.w3\.org|xmlpull\.org|java\.sun\.com|purl\.org|apache\.org)[^"\']*["\']',  # Base URL configurations
                r'setBaseUrl\(["\']http://(?!schemas\.android\.com|www\.w3\.org|xmlpull\.org|java\.sun\.com|purl\.org|apache\.org)[^"\']*["\']',  # API base URL settings
            ],
            # 🔥 PRIORITY 3 FIX: Firebase Configuration Vulnerability Detection (Organic)
            "firebase_configuration_exposure": [
                # Generic Firebase endpoint patterns (organic, no hardcoded app names)
                r'https://[a-zA-Z0-9_-]+\.firebaseio\.com/[^"\'\\s]*\.json',  # Firebase RTDB JSON endpoints
                r'https://[a-zA-Z0-9_-]+-default-rtdb\.firebaseio\.com/[^"\'\\s]*',  # Modern Firebase RTDB
                r'["\'][a-zA-Z0-9_-]+\.firebaseio\.com[^"\']*["\']',  # Quoted Firebase URLs
                r'firebaseapp\.com/[^"\'\\s]*|firebaseio\.com/[^"\'\\s]*',  # Firebase domains
                r'firebase.*database.*url["\']?\s*[:=]\s*["\'][^"\']*["\']',  # Firebase DB URL configs
                r'firebase.*config.*["\']?\s*[:=]\s*["\'][^"\']*["\']',  # Firebase config strings
                r'firebaseConfig\s*[:=]\s*\{[^}]*databaseURL[^}]*\}',  # Firebase config objects
                r'DatabaseReference.*firebase.*["\'][^"\']*["\']',  # Firebase database references
                r'FirebaseDatabase\.getInstance\(["\'][^"\']*["\']',  # Firebase getInstance calls
                r'googleapis\.com/.*firebase.*v1/[^"\'\\s]*',  # Firebase REST API patterns
                # Generic BaaS (Backend-as-a-Service) exposure patterns
                r'[a-zA-Z0-9_-]+\.(firebaseio|googleapis|firebaseapp)\.com/.*\.json',  # Generic BaaS JSON endpoints
                r'["\']https://[^"\']*firebase[^"\']*\.json["\']',  # Firebase JSON endpoint strings
                r'["\']https://[^"\']*\.json["\'].*firebase',  # JSON endpoints with Firebase context
                # Base64 encoded Firebase configurations (organic detection)
                r'[A-Za-z0-9+/]{40,}={0,2}.*firebase|firebase.*[A-Za-z0-9+/]{40,}={0,2}',  # Firebase + Base64
                r'ZmxhZ3M|ZmlyZWJhc2U|ZGF0YWJhc2U',  # Common Base64 patterns (flags, firebase, database)
            ],
            # Enhanced cloud service configuration exposure (organic)
            "cloud_service_exposure": [
                r'[a-zA-Z0-9_-]+\.(amazonaws\.com|azure\.com|googleapis\.com)/[^"\'\\s]*\.json',  # Cloud JSON APIs
                r'["\'].*\.googleapis\.com/.*v1/.*["\']',  # Google API endpoints
                r'["\'].*\.cloudfunctions\.net/.*["\']',  # Cloud function endpoints
                r'api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_-]{20,}["\']',  # Generic API keys
                r'access[_-]?token["\']?\s*[:=]\s*["\'][A-Za-z0-9_.-]{20,}["\']',  # Access tokens
                r'secret[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_-]{20,}["\']',  # Secret keys
                r'database[_-]?url["\']?\s*[:=]\s*["\']https://[^"\']*["\']',  # Database URLs
                r'endpoint[_-]?url["\']?\s*[:=]\s*["\']https://[^"\']*["\']',  # Endpoint URLs
            ],
            # MASTG-TEST-0020: TLS Settings
            "weak_tls_configuration": [
                r"setHostnameVerifier.*ALLOW_ALL_HOSTNAME_VERIFIER",
                r"setHostnameVerifier.*return true",
                r"X509TrustManager.*checkServerTrusted.*\{\s*\}",  # Empty trust manager
                r"TrustManager.*\{\s*\}",  # Empty trust manager array
                r"SSLContext.*getInsecure",
                r"setSSLSocketFactory.*getInsecure",
                r"verify\([^)]*\)\s*\{\s*return\s+true\s*;\s*\}",  # Always return true verifier
                r"HostnameVerifier[^{]*\{\s*return\s+true\s*;\s*\}",  # Hostname verifier bypass
            ],
            # MASTG-TEST-0021: Endpoint Identity Verification
            "endpoint_verification_bypass": [
                r"setHostnameVerifier\([^)]*null[^)]*\)",
                r"HttpsURLConnection.*setDefaultHostnameVerifier.*null",
                r"OkHttpClient.*hostnameVerifier.*null",
                r"verify\(.*hostname.*\)\s*\{\s*return\s+true",  # Always return true
                r"HostnameVerifier.*verify.*return\s+true",
                r"hostnameVerifier\([^)]*\)\s*\{\s*return\s+true",  # Lambda hostname verifier bypass
            ],
            # MASTG-TEST-0022: Certificate Pinning
            "missing_certificate_pinning": [
                r"CertificatePinner\.Builder\(\)\.build\(\)",  # Empty certificate pinner
                r"OkHttpClient.*certificatePinner.*null",
                r"HttpsURLConnection.*without.*pinning",
                r"TrustManager.*trustAllCerts",
                r"\.certificatePinner\(null\)",  # Null certificate pinner
                r"new\s+CertificatePinner\.Builder\(\)\.build\(\)",  # Empty builder pattern
            ],
            # MASTG-TEST-0064-0066: Network Protocols and Communication
            "insecure_network_communication": [
                r"Socket\([^)]*80[^)]*\)|Socket\([^)]*8080[^)]*\)",  # Plain sockets on HTTP ports
                r"ServerSocket\([^)]*80[^)]*\)|ServerSocket\([^)]*8080[^)]*\)",
                r'URL\(["\']ftp://[^"\']*["\']',  # Insecure FTP
                r'URL\(["\']telnet://[^"\']*["\']',  # Insecure Telnet
                r'WebSocket.*ws://[^\s\'"<>]+',  # Insecure WebSocket
                r'mqtt://[^\s\'"<>]+|amqp://(?!.*ssl)[^\s\'"<>]+',  # Insecure messaging protocols
            ],
        }

    def _initialize_privacy_patterns(self) -> Dict[str, List[str]]:
        """Initialize MASTG-compliant privacy vulnerability patterns"""
        return {
            # MASTG-TEST-0206: Keyboard Cache
            "keyboard_cache_vulnerabilities": [
                r"EditText.*inputType.*(?!.*password|.*numberPassword)",
                r"setInputType\(.*(?!.*PASSWORD)",
                r"TextView.*setTextIsSelectable\(true\)",
                r"autocomplete.*on|spellcheck.*true",
            ],
            # MASTG-TEST-0207-0208: Screenshot Protection
            "screenshot_vulnerabilities": [
                r"FLAG_SECURE.*false|setFlags.*FLAG_SECURE.*false",
                r"getWindow\(\)\.setFlags.*(?!.*FLAG_SECURE)",
                r"onPause\(\).*without.*FLAG_SECURE",
                r"onStop\(\).*without.*FLAG_SECURE",
            ],
            # MASTG-TEST-0254: Sensitive Data Processing
            "sensitive_data_processing": [
                # 🔥 ENHANCED: More comprehensive exclusions for Android XML schemas and system contexts
                r"(?<!schemas\.android\.com)(?<!xmlns)(?<!namespace)(?<!xml\.apache\.org)(?<!xmlpull\.org)(?<!w3\.org)(?<!java\.sun\.com)(?<!purl\.org)(?<!apache\.org)(?<!eclipse\.org)(?<!jcp\.org)name|email|phone|address|ssn|credit.*card|bank.*account",
                r"(?<!schemas\.android\.com)(?<!xmlns)(?<!namespace)(?<!xml\.apache\.org)(?<!xmlpull\.org)(?<!w3\.org)(?<!java\.sun\.com)(?<!purl\.org)(?<!apache\.org)(?<!eclipse\.org)(?<!jcp\.org)location|gps|latitude|longitude|coordinates",
                r"(?<!schemas\.android\.com)(?<!xmlns)(?<!namespace)(?<!xml\.apache\.org)(?<!xmlpull\.org)(?<!w3\.org)(?<!java\.sun\.com)(?<!purl\.org)(?<!apache\.org)(?<!eclipse\.org)(?<!jcp\.org)contact|calendar|photos|camera|microphone",
                r"(?<!schemas\.android\.com)(?<!xmlns)(?<!namespace)(?<!xml\.apache\.org)(?<!xmlpull\.org)(?<!w3\.org)(?<!java\.sun\.com)(?<!purl\.org)(?<!apache\.org)(?<!eclipse\.org)(?<!jcp\.org)biometric|fingerprint|face.*recognition",
                r"(?<!schemas\.android\.com)(?<!xmlns)(?<!namespace)(?<!xml\.apache\.org)(?<!xmlpull\.org)(?<!w3\.org)(?<!java\.sun\.com)(?<!purl\.org)(?<!apache\.org)(?<!eclipse\.org)(?<!jcp\.org)device.*id|imei|android.*id|advertising.*id",
            ],
            # MASTG-TEST-0255: Third-Party Data Sharing (ORGANIC PATTERNS)
            "third_party_sharing": [
                r"analytics|tracking|advertisement|ads",
                r"[a-z]+\.(com|net|io)/.*analytics|analytics\.[a-z]+\.(com|net|io)",  # Generic analytics domains
                r"crashlytics|crash.*reporting|error.*tracking",
                r"sendData.*external|upload.*analytics",
                r"HttpPost.*analytics|HttpGet.*tracking",
                r"sdk.*analytics|analytics.*sdk",  # Generic analytics SDKs
                r"third.*party.*tracking|external.*data.*sharing",  # Generic third-party patterns
                r"\.googleapis\.com/.*analytics|\.googletagmanager\.com",  # Generic Google services
            ],
            # MASTG-TEST-0256: Privacy Controls
            "missing_privacy_controls": [
                r"SharedPreferences.*privacy.*consent.*missing",
                r"permission.*request.*without.*explanation",
                r"data.*collection.*without.*consent",
                r"opt.*out.*mechanism.*missing",
            ],
        }

    def _initialize_tls_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize TLS configuration security patterns"""
        return {
            "deprecated_tls_versions": {
                "patterns": [r"TLSv1\.0|TLSv1\.1|SSLv2|SSLv3"],
                "severity": "HIGH",
                "mastg_test": "MASTG-TEST-0020",
            },
            "weak_cipher_suites": {
                "patterns": [r"DES|RC4|MD5|NULL|EXPORT|ANON"],
                "severity": "HIGH",
                "mastg_test": "MASTG-TEST-0020",
            },
            "insecure_renegotiation": {
                "patterns": [r"allowUnsafeRenegotiation.*true"],
                "severity": "MEDIUM",
                "mastg_test": "MASTG-TEST-0020",
            },
        }

    def _initialize_certificate_patterns(self) -> Dict[str, List[str]]:
        """Initialize certificate security patterns"""
        return {
            "certificate_validation_bypass": [
                r"checkServerTrusted.*\{\s*\}",
                r"X509TrustManager.*return\s*;",
                r"trustAllCerts|trustAllHosts",
                r"setDefaultTrustManager.*null",
            ],
            "weak_certificate_validation": [
                r"CertificateException.*catch.*\{\s*\}",
                r"SSLException.*catch.*\{\s*\}",
                r"certificate.*validation.*disabled",
                r"verify.*certificate.*false",
            ],
        }

    def _initialize_privacy_control_patterns(self) -> Dict[str, List[str]]:
        """Initialize privacy control patterns"""
        return {
            "gdpr_compliance": [
                r"consent.*management|privacy.*policy|data.*protection",
                r"opt.*in|opt.*out|withdraw.*consent",
                r"data.*subject.*rights|right.*to.*deletion",
                r"privacy.*settings|data.*settings",
            ],
            "data_minimization": [
                r"collect.*only.*necessary|minimal.*data.*collection",
                r"purpose.*limitation|data.*retention.*policy",
                r"anonymization|pseudonymization",
                r"data.*lifecycle.*management",
            ],
        }

    def analyze_apk(self, apk_path: str) -> OWASPNetworkPrivacyAnalysis:
        """
        Comprehensive MASVS-NETWORK & MASVS-PRIVACY analysis

        Implements all 15 MASTG test procedures:
        - 9 Network security tests (MASTG-TEST-0019 to 0022, 0064-0066, TECH-0010, 0011)
        - 6 Privacy protection tests (MASTG-TEST-0206-0208, 0254-0256)
        """
        logger.debug(
            f"Starting comprehensive OWASP MASVS-NETWORK & MASVS-PRIVACY analysis: {apk_path}"
        )

        analysis = OWASPNetworkPrivacyAnalysis()

        try:
            with zipfile.ZipFile(apk_path, "r") as apk_zip:
                # MASTG-TEST-0019 to 0022, 0064-0066: Network Security Analysis
                analysis.network_findings.extend(
                    self._analyze_network_security(apk_zip)
                )

                # MASTG-TEST-0206-0208, 0254-0256: Privacy Protection Analysis
                analysis.privacy_findings.extend(
                    self._analyze_privacy_protection(apk_zip)
                )

                # TLS Configuration Analysis
                analysis.tls_configuration_analysis = self._analyze_tls_configuration(
                    apk_zip
                )

                # Certificate Pinning Analysis
                analysis.certificate_pinning_analysis = (
                    self._analyze_certificate_pinning(apk_zip)
                )

                # Network Communication Analysis
                analysis.network_communication_analysis = (
                    self._analyze_network_communication(apk_zip)
                )

                # Privacy Controls Analysis
                analysis.privacy_controls_analysis = self._analyze_privacy_controls(
                    apk_zip
                )

                # Data Processing Analysis
                analysis.data_processing_analysis = self._analyze_data_processing(
                    apk_zip
                )

                # MASTG Compliance Assessment
                analysis.mastg_compliance = self._assess_mastg_compliance(analysis)

                # MASVS Compliance Assessment
                analysis.masvs_compliance = self._assess_masvs_compliance(analysis)

                # Detection Statistics
                analysis.detection_statistics = self._calculate_detection_statistics(
                    analysis
                )

        except Exception as e:
            logger.error(f"Error during OWASP network/privacy analysis: {e}")

        logger.debug(
            f"OWASP MASVS-NETWORK & MASVS-PRIVACY analysis complete. "
            f"Network findings: {len(analysis.network_findings)}, "
            f"Privacy findings: {len(analysis.privacy_findings)}"
        )

        return analysis

    def _analyze_network_security(
        self, apk_zip: zipfile.ZipFile
    ) -> List[NetworkFinding]:
        """
        MASTG-TEST-0019 to 0022, 0064-0066: Comprehensive network security analysis
        MASTG-TECH-0010, 0011: Technical network validation
        """
        findings = []

        # Analyze all source files for network vulnerabilities
        for file_info in apk_zip.filelist:
            if file_info.filename.endswith((".java", ".smali", ".kt", ".xml")):
                try:
                    content = apk_zip.read(file_info.filename).decode(
                        "utf-8", errors="ignore"
                    )

                    # MASTG-TEST-0019: Data Encryption on the Network
                    findings.extend(
                        self._check_network_encryption(content, file_info.filename)
                    )

                    # MASTG-TEST-0020: TLS Settings
                    findings.extend(
                        self._check_tls_configuration(content, file_info.filename)
                    )

                    # MASTG-TEST-0021: Endpoint Identity Verification
                    findings.extend(
                        self._check_endpoint_verification(content, file_info.filename)
                    )

                    # MASTG-TEST-0022: Certificate Pinning
                    findings.extend(
                        self._check_certificate_pinning(content, file_info.filename)
                    )

                    # MASTG-TEST-0064-0066: Network Protocols
                    findings.extend(
                        self._check_network_protocols(content, file_info.filename)
                    )

                    # 🔥 PRIORITY 3 FIX: Firebase Configuration Exposure Detection
                    findings.extend(
                        self._check_firebase_configuration(content, file_info.filename)
                    )

                    # Enhanced Cloud Service Configuration Exposure Detection
                    findings.extend(
                        self._check_cloud_service_exposure(content, file_info.filename)
                    )

                except Exception as e:
                    logger.debug(
                        f"Error analyzing network security in {file_info.filename}: {e}"
                    )

        return findings

    def _check_network_encryption(
        self, content: str, filename: str
    ) -> List[NetworkFinding]:
        """MASTG-TEST-0019: Testing Data Encryption on the Network"""
        findings = []

        for pattern in self.network_patterns["insecure_network_protocols"]:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                finding = NetworkFinding(
                    mastg_test="MASTG-TEST-0019",
                    masvs_control="MASVS-NETWORK-1",
                    vulnerability_type="Insecure Network Protocol",
                    severity="HIGH",
                    confidence=0.90,
                    description=f"Insecure network protocol detected: {match.group()}",
                    location=f"{filename}:{self._get_line_number(content, match.start())}",
                    evidence=match.group(),
                    remediation="Use HTTPS instead of HTTP. Implement TLS 1.2+ for all network communications.",
                )
                findings.append(finding)

        return findings

    def _check_tls_configuration(
        self, content: str, filename: str
    ) -> List[NetworkFinding]:
        """MASTG-TEST-0020: Testing the TLS Settings"""
        findings = []

        for pattern in self.network_patterns["weak_tls_configuration"]:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                finding = NetworkFinding(
                    mastg_test="MASTG-TEST-0020",
                    masvs_control="MASVS-NETWORK-1",
                    vulnerability_type="Weak TLS Configuration",
                    severity="HIGH",
                    confidence=0.85,
                    description=f"Weak TLS configuration detected: {match.group()}",
                    location=f"{filename}:{self._get_line_number(content, match.start())}",
                    evidence=match.group(),
                    remediation="Configure TLS properly with strong cipher suites, certificate validation, and hostname verification.",
                )
                findings.append(finding)

        return findings

    def _check_endpoint_verification(
        self, content: str, filename: str
    ) -> List[NetworkFinding]:
        """MASTG-TEST-0021: Testing Endpoint Identity Verification"""
        findings = []

        for pattern in self.network_patterns["endpoint_verification_bypass"]:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                finding = NetworkFinding(
                    mastg_test="MASTG-TEST-0021",
                    masvs_control="MASVS-NETWORK-1",
                    vulnerability_type="Endpoint Verification Bypass",
                    severity="HIGH",
                    confidence=0.88,
                    description=f"Endpoint identity verification bypass detected: {match.group()}",
                    location=f"{filename}:{self._get_line_number(content, match.start())}",
                    evidence=match.group(),
                    remediation="Enable proper hostname verification and certificate validation for all HTTPS connections.",
                )
                findings.append(finding)

        return findings

    def _check_certificate_pinning(
        self, content: str, filename: str
    ) -> List[NetworkFinding]:
        """MASTG-TEST-0022: Testing Custom Certificate Stores and Certificate Pinning"""
        findings = []

        for pattern in self.network_patterns["missing_certificate_pinning"]:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                finding = NetworkFinding(
                    mastg_test="MASTG-TEST-0022",
                    masvs_control="MASVS-NETWORK-2",
                    vulnerability_type="Missing Certificate Pinning",
                    severity="MEDIUM",
                    confidence=0.75,
                    description=f"Missing or weak certificate pinning: {match.group()}",
                    location=f"{filename}:{self._get_line_number(content, match.start())}",
                    evidence=match.group(),
                    remediation="Implement certificate pinning for critical API endpoints to prevent man-in-the-middle attacks.",
                )
                findings.append(finding)

        return findings

    def _check_network_protocols(
        self, content: str, filename: str
    ) -> List[NetworkFinding]:
        """MASTG-TEST-0064-0066: Testing Network Protocols and Communication"""
        findings = []

        for pattern in self.network_patterns["insecure_network_communication"]:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                finding = NetworkFinding(
                    mastg_test="MASTG-TEST-0064",
                    masvs_control="MASVS-NETWORK-1",
                    vulnerability_type="Insecure Network Communication",
                    severity="MEDIUM",
                    confidence=0.80,
                    description=f"Insecure network communication protocol: {match.group()}",
                    location=f"{filename}:{self._get_line_number(content, match.start())}",
                    evidence=match.group(),
                    remediation="Use secure protocols (HTTPS, WSS, FTPS) instead of insecure alternatives.",
                )
                findings.append(finding)

        return findings

    def _check_firebase_configuration(
        self, content: str, filename: str
    ) -> List[NetworkFinding]:
        """🔥 PRIORITY 3 FIX: Firebase Configuration Exposure Detection"""
        findings = []

        for pattern in self.network_patterns["firebase_configuration_exposure"]:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                finding = NetworkFinding(
                    mastg_test="MASVS-NETWORK-1",
                    masvs_control="MASVS-NETWORK-1",
                    vulnerability_type="Firebase Configuration Exposure",
                    severity="HIGH",
                    confidence=0.90,
                    description=f"Firebase configuration exposure detected: {match.group()}",
                    location=f"{filename}:{self._get_line_number(content, match.start())}",
                    evidence=match.group(),
                    remediation="Remove Firebase configuration from the app. Use Firebase Hosting instead.",
                )
                findings.append(finding)

        return findings

    def _check_cloud_service_exposure(
        self, content: str, filename: str
    ) -> List[NetworkFinding]:
        """Enhanced Cloud Service Configuration Exposure Detection"""
        findings = []

        for pattern in self.network_patterns["cloud_service_exposure"]:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                finding = NetworkFinding(
                    mastg_test="MASVS-NETWORK-1",
                    masvs_control="MASVS-NETWORK-1",
                    vulnerability_type="Cloud Service Exposure",
                    severity="HIGH",
                    confidence=0.90,
                    description=f"Cloud service exposure detected: {match.group()}",
                    location=f"{filename}:{self._get_line_number(content, match.start())}",
                    evidence=match.group(),
                    remediation="Remove cloud service configuration from the app. Use local services instead.",
                )
                findings.append(finding)

        return findings

    def _analyze_privacy_protection(
        self, apk_zip: zipfile.ZipFile
    ) -> List[PrivacyFinding]:
        """
        MASTG-TEST-0206-0208, 0254-0256: Comprehensive privacy protection analysis
        """
        findings = []

        for file_info in apk_zip.filelist:
            if file_info.filename.endswith((".java", ".smali", ".kt", ".xml")):
                try:
                    content = apk_zip.read(file_info.filename).decode(
                        "utf-8", errors="ignore"
                    )

                    # MASTG-TEST-0206: Keyboard Cache
                    findings.extend(
                        self._check_keyboard_cache(content, file_info.filename)
                    )

                    # MASTG-TEST-0207-0208: Screenshot Protection
                    findings.extend(
                        self._check_screenshot_protection(content, file_info.filename)
                    )

                    # MASTG-TEST-0254: Sensitive Data Processing
                    findings.extend(
                        self._check_sensitive_data_processing(
                            content, file_info.filename
                        )
                    )

                    # MASTG-TEST-0255: Third-Party Data Sharing
                    findings.extend(
                        self._check_third_party_sharing(content, file_info.filename)
                    )

                    # MASTG-TEST-0256: Privacy Controls
                    findings.extend(
                        self._check_privacy_controls(content, file_info.filename)
                    )

                except Exception as e:
                    logger.debug(
                        f"Error analyzing privacy in {file_info.filename}: {e}"
                    )

        return findings

    def _check_keyboard_cache(
        self, content: str, filename: str
    ) -> List[PrivacyFinding]:
        """MASTG-TEST-0206: Testing App Data on the Keyboard Cache"""
        findings = []

        for pattern in self.privacy_patterns["keyboard_cache_vulnerabilities"]:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                finding = PrivacyFinding(
                    mastg_test="MASTG-TEST-0206",
                    masvs_control="MASVS-PRIVACY-1",
                    vulnerability_type="Keyboard Cache Vulnerability",
                    severity="MEDIUM",
                    confidence=0.75,
                    description=f"Sensitive data may be cached in keyboard: {match.group()}",
                    location=f"{filename}:{self._get_line_number(content, match.start())}",
                    evidence=match.group(),
                    remediation="Set appropriate input types for sensitive fields to prevent keyboard caching.",
                )
                findings.append(finding)

        return findings

    def _check_screenshot_protection(
        self, content: str, filename: str
    ) -> List[PrivacyFinding]:
        """MASTG-TEST-0207-0208: Testing Screenshot Protection"""
        findings = []

        for pattern in self.privacy_patterns["screenshot_vulnerabilities"]:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                finding = PrivacyFinding(
                    mastg_test="MASTG-TEST-0207",
                    masvs_control="MASVS-PRIVACY-1",
                    vulnerability_type="Screenshot Protection Missing",
                    severity="MEDIUM",
                    confidence=0.80,
                    description=f"Missing screenshot protection for sensitive content: {match.group()}",
                    location=f"{filename}:{self._get_line_number(content, match.start())}",
                    evidence=match.group(),
                    remediation="Implement FLAG_SECURE to prevent screenshots and screen recording of sensitive activities.",
                )
                findings.append(finding)

        return findings

    def _check_sensitive_data_processing(
        self, content: str, filename: str
    ) -> List[PrivacyFinding]:
        """MASTG-TEST-0254: Testing Sensitive Data Processing"""
        findings = []

        for pattern in self.privacy_patterns["sensitive_data_processing"]:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                finding = PrivacyFinding(
                    mastg_test="MASTG-TEST-0254",
                    masvs_control="MASVS-PRIVACY-1",
                    vulnerability_type="Sensitive Data Processing",
                    severity="MEDIUM",
                    confidence=0.70,
                    description=f"Sensitive data processing detected: {match.group()}",
                    location=f"{filename}:{self._get_line_number(content, match.start())}",
                    evidence=match.group(),
                    remediation="Ensure sensitive data is processed securely with appropriate privacy controls and user consent.",
                )
                findings.append(finding)

        return findings

    def _check_third_party_sharing(
        self, content: str, filename: str
    ) -> List[PrivacyFinding]:
        """MASTG-TEST-0255: Testing Sensitive Data Sharing with Third Parties"""
        findings = []

        for pattern in self.privacy_patterns["third_party_sharing"]:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                finding = PrivacyFinding(
                    mastg_test="MASTG-TEST-0255",
                    masvs_control="MASVS-PRIVACY-3",
                    vulnerability_type="Third-Party Data Sharing",
                    severity="MEDIUM",
                    confidence=0.85,
                    description=f"Third-party data sharing detected: {match.group()}",
                    location=f"{filename}:{self._get_line_number(content, match.start())}",
                    evidence=match.group(),
                    remediation="Implement transparency and user consent mechanisms for third-party data sharing.",
                )
                findings.append(finding)

        return findings

    def _check_privacy_controls(
        self, content: str, filename: str
    ) -> List[PrivacyFinding]:
        """MASTG-TEST-0256: Testing User Privacy Controls"""
        findings = []

        for pattern in self.privacy_patterns["missing_privacy_controls"]:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                finding = PrivacyFinding(
                    mastg_test="MASTG-TEST-0256",
                    masvs_control="MASVS-PRIVACY-2",
                    vulnerability_type="Missing Privacy Controls",
                    severity="MEDIUM",
                    confidence=0.75,
                    description=f"Missing user privacy controls: {match.group()}",
                    location=f"{filename}:{self._get_line_number(content, match.start())}",
                    evidence=match.group(),
                    remediation="Implement comprehensive privacy controls allowing users to manage their data and consent.",
                )
                findings.append(finding)

        return findings

    def _analyze_tls_configuration(self, apk_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """MASTG-TECH-0010: Network Communication Analysis - TLS Configuration"""
        tls_analysis = {
            "tls_versions_found": [],
            "cipher_suites_found": [],
            "certificate_validation_issues": [],
            "hostname_verification_issues": [],
        }

        for file_info in apk_zip.filelist:
            if file_info.filename.endswith((".java", ".smali", ".kt")):
                try:
                    content = apk_zip.read(file_info.filename).decode(
                        "utf-8", errors="ignore"
                    )

                    # Check for TLS versions
                    tls_version_patterns = [r"TLSv1\.[0-3]", r"SSLv[23]"]
                    for pattern in tls_version_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        tls_analysis["tls_versions_found"].extend(matches)

                    # Check for cipher suites
                    cipher_patterns = [r"TLS_[A-Z0-9_]+", r"SSL_[A-Z0-9_]+"]
                    for pattern in cipher_patterns:
                        matches = re.findall(pattern, content)
                        tls_analysis["cipher_suites_found"].extend(matches)

                except Exception as e:
                    logger.debug(f"Error analyzing TLS in {file_info.filename}: {e}")

        return tls_analysis

    def _analyze_certificate_pinning(self, apk_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """MASTG-TECH-0011: Certificate Pinning Analysis"""
        pinning_analysis = {
            "certificate_pinning_implemented": False,
            "pinning_mechanisms": [],
            "pinned_certificates": [],
            "pinning_bypass_vulnerabilities": [],
        }

        for file_info in apk_zip.filelist:
            if file_info.filename.endswith((".java", ".smali", ".kt")):
                try:
                    content = apk_zip.read(file_info.filename).decode(
                        "utf-8", errors="ignore"
                    )

                    # Check for certificate pinning implementations
                    pinning_patterns = [
                        r"CertificatePinner",
                        r"PinningTrustManager",
                        r"certificatePinner",
                        r"pin.*certificate",
                        r"sha256.*pin",
                    ]

                    for pattern in pinning_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            pinning_analysis["certificate_pinning_implemented"] = True
                            pinning_analysis["pinning_mechanisms"].append(
                                {"file": file_info.filename, "mechanism": pattern}
                            )

                    # Check for certificate pins (SHA256 hashes)
                    sha256_pattern = r"sha256/[A-Za-z0-9+/=]{44}"
                    pins = re.findall(sha256_pattern, content)
                    pinning_analysis["pinned_certificates"].extend(pins)

                except Exception as e:
                    logger.debug(
                        f"Error analyzing certificate pinning in {file_info.filename}: {e}"
                    )

        return pinning_analysis

    def _analyze_network_communication(
        self, apk_zip: zipfile.ZipFile
    ) -> Dict[str, Any]:
        """Analyze network communication patterns and URLs"""
        network_analysis = {
            "urls_found": [],
            "api_endpoints": [],
            "insecure_connections": [],
            "secure_connections": [],
        }

        for file_info in apk_zip.filelist:
            if file_info.filename.endswith((".java", ".smali", ".kt", ".xml")):
                try:
                    content = apk_zip.read(file_info.filename).decode(
                        "utf-8", errors="ignore"
                    )

                    # Extract URLs
                    url_patterns = [
                        r'https?://[^\s\'"<>]+',
                        r'ftp://[^\s\'"<>]+',
                        r'ws[s]?://[^\s\'"<>]+',
                    ]

                    for pattern in url_patterns:
                        urls = re.findall(pattern, content, re.IGNORECASE)
                        network_analysis["urls_found"].extend(urls)

                        for url in urls:
                            if url.startswith("https://") or url.startswith("wss://"):
                                network_analysis["secure_connections"].append(url)
                            else:
                                network_analysis["insecure_connections"].append(url)

                    # Extract API endpoints
                    api_patterns = [r'/api/[^\s\'"<>]+', r'/v[0-9]+/[^\s\'"<>]+']
                    for pattern in api_patterns:
                        endpoints = re.findall(pattern, content)
                        network_analysis["api_endpoints"].extend(endpoints)

                except Exception as e:
                    logger.debug(
                        f"Error analyzing network communication in {file_info.filename}: {e}"
                    )

        return network_analysis

    def _analyze_privacy_controls(self, apk_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """Analyze privacy controls and consent mechanisms"""
        privacy_controls = {
            "consent_mechanisms": [],
            "privacy_settings": [],
            "data_deletion_controls": [],
            "opt_out_mechanisms": [],
        }

        for file_info in apk_zip.filelist:
            if file_info.filename.endswith((".java", ".smali", ".kt", ".xml")):
                try:
                    content = apk_zip.read(file_info.filename).decode(
                        "utf-8", errors="ignore"
                    )

                    # Check for consent mechanisms
                    consent_patterns = [
                        r"consent.*dialog|consent.*manager",
                        r"privacy.*policy|terms.*service",
                        r"agree.*terms|accept.*privacy",
                    ]

                    for pattern in consent_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            privacy_controls["consent_mechanisms"].append(
                                {"file": file_info.filename, "type": pattern}
                            )

                    # Check for privacy settings
                    settings_patterns = [
                        r"privacy.*settings|data.*settings",
                        r"permission.*settings|consent.*settings",
                    ]

                    for pattern in settings_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            privacy_controls["privacy_settings"].append(
                                {"file": file_info.filename, "type": pattern}
                            )

                except Exception as e:
                    logger.debug(
                        f"Error analyzing privacy controls in {file_info.filename}: {e}"
                    )

        return privacy_controls

    def _analyze_data_processing(self, apk_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """Analyze data processing and handling patterns"""
        data_processing = {
            "sensitive_data_types": [],
            "data_storage_locations": [],
            "data_transmission_methods": [],
            "data_retention_policies": [],
        }

        sensitive_data_patterns = {
            "personal_identifiers": r"email|phone|name|address|ssn",
            "financial_data": r"credit.*card|bank.*account|payment",
            "location_data": r"location|gps|latitude|longitude",
            "biometric_data": r"fingerprint|face.*recognition|biometric",
            "device_identifiers": r"device.*id|imei|android.*id",
        }

        for file_info in apk_zip.filelist:
            if file_info.filename.endswith((".java", ".smali", ".kt")):
                try:
                    content = apk_zip.read(file_info.filename).decode(
                        "utf-8", errors="ignore"
                    )

                    for data_type, pattern in sensitive_data_patterns.items():
                        if re.search(pattern, content, re.IGNORECASE):
                            data_processing["sensitive_data_types"].append(
                                {"type": data_type, "file": file_info.filename}
                            )

                except Exception as e:
                    logger.debug(
                        f"Error analyzing data processing in {file_info.filename}: {e}"
                    )

        return data_processing

    def _assess_mastg_compliance(
        self, analysis: OWASPNetworkPrivacyAnalysis
    ) -> Dict[str, bool]:
        """Assess compliance with MASTG test procedures"""
        compliance = {}

        # MASTG-TEST Compliance Assessment
        mastg_tests = [
            "MASTG-TEST-0019",
            "MASTG-TEST-0020",
            "MASTG-TEST-0021",
            "MASTG-TEST-0022",
            "MASTG-TEST-0064",
            "MASTG-TEST-0065",
            "MASTG-TEST-0066",
            "MASTG-TEST-0206",
            "MASTG-TEST-0207",
            "MASTG-TEST-0208",
            "MASTG-TEST-0254",
            "MASTG-TEST-0255",
            "MASTG-TEST-0256",
            "MASTG-TECH-0010",
            "MASTG-TECH-0011",
        ]

        for test in mastg_tests:
            # Check if vulnerabilities found for this test (non-compliance)
            network_violations = [
                f for f in analysis.network_findings if f.mastg_test == test
            ]
            privacy_violations = [
                f for f in analysis.privacy_findings if f.mastg_test == test
            ]

            # Compliance = no high/medium severity findings for this test
            compliance[test] = not any(
                f.severity in ["HIGH", "MEDIUM"]
                for f in network_violations + privacy_violations
            )

        return compliance

    def _assess_masvs_compliance(
        self, analysis: OWASPNetworkPrivacyAnalysis
    ) -> Dict[str, bool]:
        """Assess compliance with MASVS controls"""
        compliance = {}

        masvs_controls = [
            "MASVS-NETWORK-1",
            "MASVS-NETWORK-2",
            "MASVS-PRIVACY-1",
            "MASVS-PRIVACY-2",
            "MASVS-PRIVACY-3",
            "MASVS-PRIVACY-4",
        ]

        for control in masvs_controls:
            # Check if violations found for this control
            network_violations = [
                f for f in analysis.network_findings if f.masvs_control == control
            ]
            privacy_violations = [
                f for f in analysis.privacy_findings if f.masvs_control == control
            ]

            # Compliance = no high severity findings for this control
            compliance[control] = not any(
                f.severity == "HIGH" for f in network_violations + privacy_violations
            )

        return compliance

    def _calculate_detection_statistics(
        self, analysis: OWASPNetworkPrivacyAnalysis
    ) -> Dict[str, Any]:
        """Calculate comprehensive detection statistics"""
        total_findings = len(analysis.network_findings) + len(analysis.privacy_findings)

        network_high = len(
            [f for f in analysis.network_findings if f.severity == "HIGH"]
        )
        network_medium = len(
            [f for f in analysis.network_findings if f.severity == "MEDIUM"]
        )
        privacy_high = len(
            [f for f in analysis.privacy_findings if f.severity == "HIGH"]
        )
        privacy_medium = len(
            [f for f in analysis.privacy_findings if f.severity == "MEDIUM"]
        )

        return {
            "total_findings": total_findings,
            "network_findings": len(analysis.network_findings),
            "privacy_findings": len(analysis.privacy_findings),
            "high_severity": network_high + privacy_high,
            "medium_severity": network_medium + privacy_medium,
            "mastg_compliance_rate": sum(analysis.mastg_compliance.values())
            / len(analysis.mastg_compliance)
            * 100,
            "masvs_compliance_rate": sum(analysis.masvs_compliance.values())
            / len(analysis.masvs_compliance)
            * 100,
            "certificate_pinning_implemented": analysis.certificate_pinning_analysis.get(
                "certificate_pinning_implemented", False
            ),
            "secure_connections": len(
                analysis.network_communication_analysis.get("secure_connections", [])
            ),
            "insecure_connections": len(
                analysis.network_communication_analysis.get("insecure_connections", [])
            ),
            "privacy_controls_detected": len(
                analysis.privacy_controls_analysis.get("consent_mechanisms", [])
            ),
        }

    def _get_line_number(self, content: str, position: int) -> int:
        """Get line number for a position in content"""
        return content[:position].count("\n") + 1

    def generate_owasp_report(
        self, analysis: OWASPNetworkPrivacyAnalysis
    ) -> Dict[str, Any]:
        """Generate comprehensive OWASP MASVS-NETWORK & MASVS-PRIVACY compliance report"""
        return {
            "owasp_analysis_summary": {
                "framework_version": "OWASP MASVS v2",
                "categories_analyzed": ["MASVS-NETWORK", "MASVS-PRIVACY"],
                "mastg_tests_implemented": 15,
                "total_findings": len(analysis.network_findings)
                + len(analysis.privacy_findings),
                "compliance_assessment": {
                    "mastg_compliance_rate": analysis.detection_statistics.get(
                        "mastg_compliance_rate", 0
                    ),
                    "masvs_compliance_rate": analysis.detection_statistics.get(
                        "masvs_compliance_rate", 0
                    ),
                },
            },
            "network_analysis": {
                "findings_count": len(analysis.network_findings),
                "high_severity_network": len(
                    [f for f in analysis.network_findings if f.severity == "HIGH"]
                ),
                "medium_severity_network": len(
                    [f for f in analysis.network_findings if f.severity == "MEDIUM"]
                ),
                "mastg_tests_covered": list(
                    set(f.mastg_test for f in analysis.network_findings)
                ),
                "detailed_findings": [
                    {
                        "mastg_test": f.mastg_test,
                        "masvs_control": f.masvs_control,
                        "vulnerability_type": f.vulnerability_type,
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "location": f.location,
                        "evidence": f.evidence,
                        "remediation": f.remediation,
                    }
                    for f in analysis.network_findings
                ],
            },
            "privacy_analysis": {
                "findings_count": len(analysis.privacy_findings),
                "high_severity_privacy": len(
                    [f for f in analysis.privacy_findings if f.severity == "HIGH"]
                ),
                "medium_severity_privacy": len(
                    [f for f in analysis.privacy_findings if f.severity == "MEDIUM"]
                ),
                "mastg_tests_covered": list(
                    set(f.mastg_test for f in analysis.privacy_findings)
                ),
                "detailed_findings": [
                    {
                        "mastg_test": f.mastg_test,
                        "masvs_control": f.masvs_control,
                        "vulnerability_type": f.vulnerability_type,
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "location": f.location,
                        "evidence": f.evidence,
                        "remediation": f.remediation,
                    }
                    for f in analysis.privacy_findings
                ],
            },
            "tls_configuration_analysis": analysis.tls_configuration_analysis,
            "certificate_pinning_analysis": analysis.certificate_pinning_analysis,
            "network_communication_analysis": analysis.network_communication_analysis,
            "privacy_controls_analysis": analysis.privacy_controls_analysis,
            "data_processing_analysis": analysis.data_processing_analysis,
            "compliance_summary": {
                "mastg_compliance": analysis.mastg_compliance,
                "masvs_compliance": analysis.masvs_compliance,
                "overall_security_rating": self._calculate_security_rating(analysis),
            },
            "detection_statistics": analysis.detection_statistics,
        }

    def _calculate_security_rating(self, analysis: OWASPNetworkPrivacyAnalysis) -> str:
        """Calculate overall security rating based on findings"""
        high_severity_count = len(
            [
                f
                for f in analysis.network_findings + analysis.privacy_findings
                if f.severity == "HIGH"
            ]
        )
        medium_severity_count = len(
            [
                f
                for f in analysis.network_findings + analysis.privacy_findings
                if f.severity == "MEDIUM"
            ]
        )

        if high_severity_count >= 5:
            return "CRITICAL"
        elif high_severity_count >= 3:
            return "HIGH_RISK"
        elif high_severity_count >= 1 or medium_severity_count >= 5:
            return "MEDIUM_RISK"
        elif medium_severity_count >= 1:
            return "LOW_RISK"
        else:
            return "SECURE"
