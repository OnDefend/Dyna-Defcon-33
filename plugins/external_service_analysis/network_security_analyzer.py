"""
Network Security Analysis Module for External Service Analysis

This module handles the analysis of network security configurations,
SSL/TLS settings, protocol security, and insecure communication patterns.
"""

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
import xml.etree.ElementTree as ET

from .data_structures import (
    NetworkSecurityIssue, NetworkSecurityLevel, SeverityLevel,
    ExternalServiceVulnerability, ServiceEndpoint, AnalysisContext
)

logger = logging.getLogger(__name__)

class NetworkSecurityAnalyzer:
    """Analyzes network security configurations and patterns."""
    
    def __init__(self):
        """Initialize network security analyzer."""
        self._init_patterns()
        self._detected_cache: Set[Tuple[str, str, str]] = set()
    
    def _init_patterns(self):
        """Initialize network security detection patterns."""
        # Insecure protocol patterns
        self.insecure_protocol_patterns = [
            re.compile(r'http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.).*', re.IGNORECASE),
            re.compile(r'ftp://.*', re.IGNORECASE),
            re.compile(r'telnet://.*', re.IGNORECASE),
        ]
        
        # Weak SSL/TLS configuration patterns
        self.weak_ssl_patterns = [
            re.compile(r'TLSv1\.0', re.IGNORECASE),
            re.compile(r'TLSv1\.1', re.IGNORECASE),
            re.compile(r'SSLv3', re.IGNORECASE),
            re.compile(r'NULL.*Cipher', re.IGNORECASE),
            re.compile(r'EXPORT.*Cipher', re.IGNORECASE),
        ]
        
        # Certificate validation bypass patterns
        self.cert_bypass_patterns = [
            re.compile(r'trustAllCerts', re.IGNORECASE),
            re.compile(r'allowAllHostnameVerifier', re.IGNORECASE),
            re.compile(r'setHostnameVerifier.*ALLOW_ALL', re.IGNORECASE),
            re.compile(r'checkServerTrusted.*return', re.IGNORECASE),
            re.compile(r'X509TrustManager.*\{\s*\}', re.IGNORECASE | re.DOTALL),
        ]
        
        # Cleartext traffic patterns
        self.cleartext_patterns = [
            re.compile(r'usesCleartextTraffic\s*=\s*["\']?true', re.IGNORECASE),
            re.compile(r'android:usesCleartextTraffic\s*=\s*["\']?true', re.IGNORECASE),
        ]
        
        # Network security config issues
        self.nsc_issue_patterns = [
            re.compile(r'trust-anchors.*system.*false', re.IGNORECASE | re.DOTALL),
            re.compile(r'trust-anchors.*user.*true', re.IGNORECASE | re.DOTALL),
            re.compile(r'pin-set.*expiration.*["\'][^"\']*2020', re.IGNORECASE),  # Expired pins
            re.compile(r'cleartextTrafficPermitted\s*=\s*["\']?true', re.IGNORECASE),
        ]
        
        # Weak cipher patterns
        self.weak_cipher_patterns = [
            re.compile(r'DES_CBC', re.IGNORECASE),
            re.compile(r'RC4', re.IGNORECASE),
            re.compile(r'MD5', re.IGNORECASE),
            re.compile(r'SHA1(?!_)', re.IGNORECASE),  # SHA1 but not SHA1_ variants
        ]
    
    def analyze_network_security(self, content: str, file_path: str,
                                context: Optional[AnalysisContext] = None) -> List[NetworkSecurityIssue]:
        """
        Analyze content for network security issues.
        
        Args:
            content: File content to analyze
            file_path: Path to the file being analyzed
            context: Analysis context for confidence calculation
            
        Returns:
            List of detected network security issues
        """
        issues = []
        
        if not content or not content.strip():
            return issues
        
        # Analyze different types of network security issues
        issues.extend(self._analyze_insecure_protocols(content, file_path, context))
        issues.extend(self._analyze_weak_ssl_config(content, file_path, context))
        issues.extend(self._analyze_certificate_bypass(content, file_path, context))
        issues.extend(self._analyze_cleartext_traffic(content, file_path, context))
        issues.extend(self._analyze_weak_ciphers(content, file_path, context))
        
        # Special handling for XML files (network security config)
        if file_path.endswith('.xml'):
            issues.extend(self._analyze_network_security_config(content, file_path, context))
        
        return issues
    
    def _analyze_insecure_protocols(self, content: str, file_path: str,
                                  context: Optional[AnalysisContext] = None) -> List[NetworkSecurityIssue]:
        """Analyze for insecure protocol usage."""
        issues = []
        
        for pattern in self.insecure_protocol_patterns:
            for match in pattern.finditer(content):
                matched_url = match.group(0)
                
                cache_key = ("insecure_protocol", matched_url, file_path)
                if cache_key in self._detected_cache:
                    continue
                
                self._detected_cache.add(cache_key)
                
                issue = NetworkSecurityIssue(
                    issue_type="insecure_protocol",
                    description=f"Insecure protocol detected: {matched_url}",
                    endpoint=matched_url,
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Use HTTPS instead of HTTP for external communications",
                    cwe="CWE-319",
                    masvs_control="MSTG-NETWORK-01",
                    confidence=self._calculate_network_confidence("insecure_protocol", content, context)
                )
                
                issues.append(issue)
        
        return issues
    
    def _analyze_weak_ssl_config(self, content: str, file_path: str,
                                context: Optional[AnalysisContext] = None) -> List[NetworkSecurityIssue]:
        """Analyze for weak SSL/TLS configurations."""
        issues = []
        
        for pattern in self.weak_ssl_patterns:
            for match in pattern.finditer(content):
                matched_text = match.group(0)
                
                cache_key = ("weak_ssl", matched_text, file_path)
                if cache_key in self._detected_cache:
                    continue
                
                self._detected_cache.add(cache_key)
                
                issue = NetworkSecurityIssue(
                    issue_type="weak_ssl_config",
                    description=f"Weak SSL/TLS configuration: {matched_text}",
                    endpoint=matched_text,
                    severity=SeverityLevel.HIGH,
                    recommendation="Use TLS 1.2 or higher with strong cipher suites",
                    cwe="CWE-326",
                    masvs_control="MSTG-NETWORK-02",
                    confidence=self._calculate_network_confidence("weak_ssl", content, context)
                )
                
                issues.append(issue)
        
        return issues
    
    def _analyze_certificate_bypass(self, content: str, file_path: str,
                                  context: Optional[AnalysisContext] = None) -> List[NetworkSecurityIssue]:
        """Analyze for certificate validation bypass."""
        issues = []
        
        for pattern in self.cert_bypass_patterns:
            for match in pattern.finditer(content):
                matched_text = match.group(0)
                
                cache_key = ("cert_bypass", matched_text, file_path)
                if cache_key in self._detected_cache:
                    continue
                
                self._detected_cache.add(cache_key)
                
                issue = NetworkSecurityIssue(
                    issue_type="certificate_validation_bypass",
                    description=f"Certificate validation bypass detected: {matched_text}",
                    endpoint="N/A",
                    severity=SeverityLevel.CRITICAL,
                    recommendation="Remove certificate validation bypass and implement proper certificate validation",
                    cwe="CWE-295",
                    masvs_control="MSTG-NETWORK-03",
                    confidence=self._calculate_network_confidence("cert_bypass", content, context)
                )
                
                issues.append(issue)
        
        return issues
    
    def _analyze_cleartext_traffic(self, content: str, file_path: str,
                                 context: Optional[AnalysisContext] = None) -> List[NetworkSecurityIssue]:
        """Analyze for cleartext traffic configuration."""
        issues = []
        
        for pattern in self.cleartext_patterns:
            for match in pattern.finditer(content):
                matched_text = match.group(0)
                
                cache_key = ("cleartext_traffic", matched_text, file_path)
                if cache_key in self._detected_cache:
                    continue
                
                self._detected_cache.add(cache_key)
                
                issue = NetworkSecurityIssue(
                    issue_type="cleartext_traffic_allowed",
                    description=f"Cleartext traffic allowed: {matched_text}",
                    endpoint="N/A",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Disable cleartext traffic and use HTTPS for all external communications",
                    cwe="CWE-319",
                    masvs_control="MSTG-NETWORK-01",
                    confidence=self._calculate_network_confidence("cleartext", content, context)
                )
                
                issues.append(issue)
        
        return issues
    
    def _analyze_weak_ciphers(self, content: str, file_path: str,
                            context: Optional[AnalysisContext] = None) -> List[NetworkSecurityIssue]:
        """Analyze for weak cipher usage."""
        issues = []
        
        for pattern in self.weak_cipher_patterns:
            for match in pattern.finditer(content):
                matched_text = match.group(0)
                
                cache_key = ("weak_cipher", matched_text, file_path)
                if cache_key in self._detected_cache:
                    continue
                
                self._detected_cache.add(cache_key)
                
                issue = NetworkSecurityIssue(
                    issue_type="weak_cipher",
                    description=f"Weak cipher algorithm detected: {matched_text}",
                    endpoint="N/A",
                    severity=SeverityLevel.HIGH,
                    recommendation="Use strong cipher algorithms and avoid deprecated cryptographic methods",
                    cwe="CWE-327",
                    masvs_control="MSTG-CRYPTO-01",
                    confidence=self._calculate_network_confidence("weak_cipher", content, context)
                )
                
                issues.append(issue)
        
        return issues
    
    def _analyze_network_security_config(self, content: str, file_path: str,
                                       context: Optional[AnalysisContext] = None) -> List[NetworkSecurityIssue]:
        """Analyze Android Network Security Configuration."""
        issues = []
        
        try:
            # Parse XML content
            root = ET.fromstring(content)
            
            # Check for common NSC misconfigurations
            issues.extend(self._check_nsc_cleartext_permitted(root, file_path, context))
            issues.extend(self._check_nsc_trust_anchors(root, file_path, context))
            issues.extend(self._check_nsc_certificate_pinning(root, file_path, context))
            issues.extend(self._check_nsc_debug_overrides(root, file_path, context))
            
        except ET.ParseError:
            # If not valid XML, fall back to pattern matching
            for pattern in self.nsc_issue_patterns:
                for match in pattern.finditer(content):
                    matched_text = match.group(0)
                    
                    cache_key = ("nsc_issue", matched_text, file_path)
                    if cache_key in self._detected_cache:
                        continue
                    
                    self._detected_cache.add(cache_key)
                    
                    issue = NetworkSecurityIssue(
                        issue_type="network_security_config_issue",
                        description=f"Network Security Config issue: {matched_text}",
                        endpoint="N/A",
                        severity=SeverityLevel.MEDIUM,
                        recommendation="Review and fix Network Security Configuration",
                        cwe="CWE-295",
                        masvs_control="MSTG-NETWORK-02",
                        confidence=self._calculate_network_confidence("nsc_issue", content, context)
                    )
                    
                    issues.append(issue)
        
        return issues
    
    def _check_nsc_cleartext_permitted(self, root: ET.Element, file_path: str,
                                     context: Optional[AnalysisContext] = None) -> List[NetworkSecurityIssue]:
        """Check for cleartext traffic permissions in NSC."""
        issues = []
        
        # Look for cleartextTrafficPermitted="true"
        for elem in root.iter():
            if 'cleartextTrafficPermitted' in elem.attrib:
                if elem.attrib['cleartextTrafficPermitted'].lower() == 'true':
                    issue = NetworkSecurityIssue(
                        issue_type="nsc_cleartext_permitted",
                        description="Network Security Config allows cleartext traffic",
                        endpoint="N/A",
                        severity=SeverityLevel.MEDIUM,
                        recommendation="Set cleartextTrafficPermitted to false",
                        cwe="CWE-319",
                        masvs_control="MSTG-NETWORK-01",
                        confidence=0.90
                    )
                    issues.append(issue)
        
        return issues
    
    def _check_nsc_trust_anchors(self, root: ET.Element, file_path: str,
                               context: Optional[AnalysisContext] = None) -> List[NetworkSecurityIssue]:
        """Check for trust anchor misconfigurations."""
        issues = []
        
        for trust_anchors in root.iter('trust-anchors'):
            # Check if system CAs are disabled
            for certificates in trust_anchors.iter('certificates'):
                if certificates.attrib.get('src') == 'system' and \
                   certificates.attrib.get('overridePins', '').lower() == 'true':
                    
                    issue = NetworkSecurityIssue(
                        issue_type="nsc_system_ca_override",
                        description="System certificate authorities can be overridden",
                        endpoint="N/A",
                        severity=SeverityLevel.HIGH,
                        recommendation="Remove overridePins=true for system certificates",
                        cwe="CWE-295",
                        masvs_control="MSTG-NETWORK-03",
                        confidence=0.85
                    )
                    issues.append(issue)
            
            # Check if user CAs are trusted
            for certificates in trust_anchors.iter('certificates'):
                if certificates.attrib.get('src') == 'user':
                    issue = NetworkSecurityIssue(
                        issue_type="nsc_user_ca_trusted",
                        description="User-added certificate authorities are trusted",
                        endpoint="N/A",
                        severity=SeverityLevel.MEDIUM,
                        recommendation="Consider removing user CA trust for production apps",
                        cwe="CWE-295",
                        masvs_control="MSTG-NETWORK-03",
                        confidence=0.80
                    )
                    issues.append(issue)
        
        return issues
    
    def _check_nsc_certificate_pinning(self, root: ET.Element, file_path: str,
                                     context: Optional[AnalysisContext] = None) -> List[NetworkSecurityIssue]:
        """Check certificate pinning configuration."""
        issues = []
        
        for pin_set in root.iter('pin-set'):
            expiration = pin_set.attrib.get('expiration')
            if expiration:
                # Check for expired or soon-to-expire pins
                import datetime
                try:
                    exp_date = datetime.datetime.strptime(expiration, '%Y-%m-%d')
                    if exp_date < datetime.datetime.now():
                        issue = NetworkSecurityIssue(
                            issue_type="nsc_expired_pin",
                            description=f"Certificate pin has expired: {expiration}",
                            endpoint="N/A",
                            severity=SeverityLevel.HIGH,
                            recommendation="Update certificate pins before expiration",
                            cwe="CWE-295",
                            masvs_control="MSTG-NETWORK-04",
                            confidence=0.95
                        )
                        issues.append(issue)
                except ValueError:
                    pass  # Invalid date format
        
        return issues
    
    def _check_nsc_debug_overrides(self, root: ET.Element, file_path: str,
                                 context: Optional[AnalysisContext] = None) -> List[NetworkSecurityIssue]:
        """Check for debug overrides in NSC."""
        issues = []
        
        for debug_overrides in root.iter('debug-overrides'):
            issue = NetworkSecurityIssue(
                issue_type="nsc_debug_overrides",
                description="Debug overrides found in Network Security Config",
                endpoint="N/A",
                severity=SeverityLevel.MEDIUM,
                recommendation="Remove debug overrides from production builds",
                cwe="CWE-489",
                masvs_control="MSTG-CODE-08",
                confidence=0.85
            )
            issues.append(issue)
        
        return issues
    
    def analyze_endpoint_security(self, endpoints: List[ServiceEndpoint]) -> List[NetworkSecurityIssue]:
        """
        Analyze security of detected service endpoints.
        
        Args:
            endpoints: List of service endpoints to analyze
            
        Returns:
            List of network security issues found in endpoints
        """
        issues = []
        
        for endpoint in endpoints:
            # Check protocol security
            if endpoint.url.startswith('http://'):
                issue = NetworkSecurityIssue(
                    issue_type="insecure_endpoint",
                    description=f"Insecure HTTP endpoint: {endpoint.url}",
                    endpoint=endpoint.url,
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Use HTTPS instead of HTTP",
                    cwe="CWE-319",
                    masvs_control="MSTG-NETWORK-01",
                    confidence=0.95
                )
                issues.append(issue)
            
            # Check authentication security
            if endpoint.authentication == "basic_auth":
                issue = NetworkSecurityIssue(
                    issue_type="weak_authentication",
                    description=f"Basic authentication detected for endpoint: {endpoint.url}",
                    endpoint=endpoint.url,
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Use stronger authentication mechanisms like OAuth 2.0",
                    cwe="CWE-287",
                    masvs_control="MSTG-AUTH-01",
                    confidence=0.80
                )
                issues.append(issue)
            
            # Check encryption
            if endpoint.encryption == "None":
                issue = NetworkSecurityIssue(
                    issue_type="no_encryption",
                    description=f"No encryption detected for endpoint: {endpoint.url}",
                    endpoint=endpoint.url,
                    severity=SeverityLevel.HIGH,
                    recommendation="Enable TLS encryption for all external communications",
                    cwe="CWE-311",
                    masvs_control="MSTG-NETWORK-01",
                    confidence=0.90
                )
                issues.append(issue)
        
        return issues
    
    def _calculate_network_confidence(self, issue_type: str, content: str,
                                    context: Optional[AnalysisContext] = None) -> float:
        """Calculate confidence score for network security issues."""
        base_confidence = {
            'insecure_protocol': 0.85,
            'weak_ssl': 0.90,
            'cert_bypass': 0.95,
            'cleartext': 0.80,
            'weak_cipher': 0.85,
            'nsc_issue': 0.75
        }
        
        confidence = base_confidence.get(issue_type, 0.75)
        
        # Adjust based on context
        if context:
            # File type adjustments
            if context.file_type in ['java', 'kotlin']:
                confidence += 0.05
            elif context.file_type == 'xml':
                confidence += 0.02
            
            # Cross-reference adjustments
            if context.cross_references > 1:
                confidence += min(0.1, context.cross_references * 0.02)
        
        return max(0.1, min(1.0, confidence))
    
    def create_vulnerabilities_from_issues(self, issues: List[NetworkSecurityIssue]) -> List[ExternalServiceVulnerability]:
        """Create vulnerability objects from network security issues."""
        vulnerabilities = []
        
        for issue in issues:
            vulnerability = ExternalServiceVulnerability(
                vulnerability_id=f"NET_SEC_{issue.issue_type.upper()}_{hash(issue.endpoint) % 10000:04d}",
                title=f"Network Security Issue: {issue.issue_type.replace('_', ' ').title()}",
                description=issue.description,
                severity=issue.severity,
                service_type=self._get_service_type_for_issue(issue.issue_type),
                location=issue.endpoint,
                evidence={
                    'issue_type': issue.issue_type,
                    'endpoint': issue.endpoint,
                    'recommendation': issue.recommendation
                },
                recommendations=[issue.recommendation],
                cwe=issue.cwe,
                masvs_control=issue.masvs_control,
                confidence=issue.confidence
            )
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _get_service_type_for_issue(self, issue_type: str):
        """Get appropriate service type for network security issue."""
        from .data_structures import ServiceType
        
        # Most network security issues are related to general network communications
        return ServiceType.UNKNOWN
    
    def get_network_security_statistics(self) -> Dict[str, int]:
        """Get statistics about network security analysis."""
        issue_counts = {}
        
        for cache_entry in self._detected_cache:
            issue_type = cache_entry[0]
            issue_counts[issue_type] = issue_counts.get(issue_type, 0) + 1
        
        return {
            'total_issues': len(self._detected_cache),
            'issue_breakdown': issue_counts,
            'unique_types': len(issue_counts)
        } 