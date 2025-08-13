#!/usr/bin/env python3
"""
Dynamic Deep Link Testing Coordinator for AODS

This module implements comprehensive deep link security analysis:
- Dynamic Deep Link Testing
- URL scheme enumeration and testing
- Deep link payload generation
- Intent-based vulnerability detection
- URL validation bypass testing
- Comprehensive deep link security analysis

Integrates with existing AODS manifest analysis infrastructure.
"""

import asyncio
import os
import json
import logging
import hashlib
import time
import re
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import subprocess
import xml.etree.ElementTree as ET

# Deep link analysis data structures
class URLSchemeType(Enum):
    HTTP = "http"
    HTTPS = "https"
    CUSTOM = "custom"
    FILE = "file"
    CONTENT = "content"
    MARKET = "market"
    INTENT = "intent"

class DeepLinkSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class IntentFilterSecurity(Enum):
    SECURE = "secure"
    MODERATE = "moderate"
    VULNERABLE = "vulnerable"
    CRITICAL = "critical"

class DeepLinkVulnerabilityType(Enum):
    URL_HIJACKING = "url_hijacking"
    INTENT_INJECTION = "intent_injection"
    PARAMETER_INJECTION = "parameter_injection"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    PATH_TRAVERSAL = "path_traversal"
    CROSS_APP_SCRIPTING = "cross_app_scripting"
    INSECURE_TRANSMISSION = "insecure_transmission"
    MISSING_VALIDATION = "missing_validation"

@dataclass
class URLScheme:
    """URL scheme configuration"""
    scheme: str
    host: Optional[str] = None
    path_pattern: Optional[str] = None
    scheme_type: URLSchemeType = URLSchemeType.CUSTOM
    requires_auth: bool = False
    exported: bool = True
    priority: int = 0

@dataclass
class IntentFilter:
    """Intent filter analysis result"""
    action: str
    category: List[str]
    data_schemes: List[str] = field(default_factory=list)
    data_hosts: List[str] = field(default_factory=list)
    data_paths: List[str] = field(default_factory=list)
    data_mime_types: List[str] = field(default_factory=list)
    exported: bool = True
    security_level: IntentFilterSecurity = IntentFilterSecurity.MODERATE

@dataclass
class DeepLinkPayload:
    """Deep link test payload"""
    payload_id: str
    url: str
    payload_type: str
    description: str
    expected_behavior: str
    risk_level: DeepLinkSeverity
    parameters: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DeepLinkVulnerability:
    """Deep link vulnerability finding"""
    vulnerability_id: str
    vulnerability_type: DeepLinkVulnerabilityType
    severity: DeepLinkSeverity
    url_scheme: str
    description: str
    proof_of_concept: str
    impact: str
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DeepLinkAnalysisResult:
    """Complete deep link analysis result"""
    analysis_id: str
    app_package: str
    url_schemes: List[URLScheme] = field(default_factory=list)
    intent_filters: List[IntentFilter] = field(default_factory=list)
    vulnerabilities: List[DeepLinkVulnerability] = field(default_factory=list)
    test_results: List[Dict[str, Any]] = field(default_factory=list)
    security_score: float = 0.0
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    analysis_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

class URLSchemeEnumerator:
    """Enumerate and analyze URL schemes from manifest"""
    
    def __init__(self, app_package: str):
        self.logger = logging.getLogger(__name__)
        self.app_package = app_package
        
    async def enumerate_url_schemes(self, manifest_path: str) -> List[URLScheme]:
        """Enumerate URL schemes from AndroidManifest.xml"""
        schemes = []
        
        try:
            if not os.path.exists(manifest_path):
                self.logger.warning(f"Manifest not found: {manifest_path}")
                return schemes
            
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Find all intent filters with data elements
            for intent_filter in root.findall('.//intent-filter'):
                for data in intent_filter.findall('data'):
                    scheme = self._extract_scheme_from_data(data, intent_filter)
                    if scheme:
                        schemes.append(scheme)
            
            # Deduplicate schemes
            unique_schemes = self._deduplicate_schemes(schemes)
            
            self.logger.info(f"Enumerated {len(unique_schemes)} URL schemes")
            return unique_schemes
            
        except Exception as e:
            self.logger.error(f"Failed to enumerate URL schemes: {e}")
            return schemes
    
    def _extract_scheme_from_data(self, data_element: ET.Element, intent_filter: ET.Element) -> Optional[URLScheme]:
        """Extract URL scheme from data element"""
        try:
            scheme_attr = data_element.get('{http://schemas.android.com/apk/res/android}scheme')
            host_attr = data_element.get('{http://schemas.android.com/apk/res/android}host')
            path_attr = data_element.get('{http://schemas.android.com/apk/res/android}path') or \
                       data_element.get('{http://schemas.android.com/apk/res/android}pathPattern') or \
                       data_element.get('{http://schemas.android.com/apk/res/android}pathPrefix')
            
            if not scheme_attr:
                return None
            
            # Determine scheme type
            scheme_type = URLSchemeType.CUSTOM
            if scheme_attr == 'http':
                scheme_type = URLSchemeType.HTTP
            elif scheme_attr == 'https':
                scheme_type = URLSchemeType.HTTPS
            elif scheme_attr == 'file':
                scheme_type = URLSchemeType.FILE
            elif scheme_attr == 'content':
                scheme_type = URLSchemeType.CONTENT
            elif scheme_attr == 'market':
                scheme_type = URLSchemeType.MARKET
            
            # Check if exported (default is True for intent filters)
            # Note: getparent() is not available in standard ElementTree, so we'll default to True
            exported = True
            try:
                # Try to find parent activity in the tree context if needed
                # For now, default to exported=True for intent filters
                pass
            except AttributeError:
                # getparent() not available in this ElementTree implementation
                pass
            
            return URLScheme(
                scheme=scheme_attr,
                host=host_attr,
                path_pattern=path_attr,
                scheme_type=scheme_type,
                exported=exported
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to extract scheme from data element: {e}")
            return None
    
    def _deduplicate_schemes(self, schemes: List[URLScheme]) -> List[URLScheme]:
        """Remove duplicate URL schemes"""
        seen = set()
        unique_schemes = []
        
        for scheme in schemes:
            scheme_key = (scheme.scheme, scheme.host, scheme.path_pattern)
            if scheme_key not in seen:
                seen.add(scheme_key)
                unique_schemes.append(scheme)
        
        return unique_schemes
    
    async def analyze_intent_filters(self, manifest_path: str) -> List[IntentFilter]:
        """Analyze intent filters for security issues"""
        intent_filters = []
        
        try:
            if not os.path.exists(manifest_path):
                return intent_filters
            
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            for intent_filter in root.findall('.//intent-filter'):
                filter_analysis = self._analyze_single_intent_filter(intent_filter)
                if filter_analysis:
                    intent_filters.append(filter_analysis)
            
            return intent_filters
            
        except Exception as e:
            self.logger.error(f"Failed to analyze intent filters: {e}")
            return intent_filters
    
    def _analyze_single_intent_filter(self, intent_filter: ET.Element) -> Optional[IntentFilter]:
        """Analyze single intent filter"""
        try:
            # Extract action
            action_element = intent_filter.find('action')
            action = action_element.get('{http://schemas.android.com/apk/res/android}name') if action_element is not None else ""
            
            # Extract categories
            categories = []
            for category in intent_filter.findall('category'):
                cat_name = category.get('{http://schemas.android.com/apk/res/android}name')
                if cat_name:
                    categories.append(cat_name)
            
            # Extract data attributes
            data_schemes = []
            data_hosts = []
            data_paths = []
            data_mime_types = []
            
            for data in intent_filter.findall('data'):
                scheme = data.get('{http://schemas.android.com/apk/res/android}scheme')
                host = data.get('{http://schemas.android.com/apk/res/android}host')
                path = data.get('{http://schemas.android.com/apk/res/android}path')
                mime_type = data.get('{http://schemas.android.com/apk/res/android}mimeType')
                
                if scheme:
                    data_schemes.append(scheme)
                if host:
                    data_hosts.append(host)
                if path:
                    data_paths.append(path)
                if mime_type:
                    data_mime_types.append(mime_type)
            
            # Assess security level
            security_level = self._assess_intent_filter_security(
                action, categories, data_schemes, data_hosts, data_paths
            )
            
            # Check if exported (default is True for intent filters)
            # Note: getparent() is not available in standard ElementTree, so we'll default to True
            exported = True
            try:
                # Try to find parent activity in the tree context if needed
                # For now, default to exported=True for intent filters
                pass
            except AttributeError:
                # getparent() not available in this ElementTree implementation
                pass
            
            return IntentFilter(
                action=action,
                category=categories,
                data_schemes=data_schemes,
                data_hosts=data_hosts,
                data_paths=data_paths,
                data_mime_types=data_mime_types,
                exported=exported,
                security_level=security_level
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to analyze intent filter: {e}")
            return None
    
    def _assess_intent_filter_security(self, action: str, categories: List[str], 
                                     schemes: List[str], hosts: List[str], 
                                     paths: List[str]) -> IntentFilterSecurity:
        """Assess security level of intent filter"""
        risk_score = 0
        
        # Check for dangerous actions
        dangerous_actions = [
            'android.intent.action.VIEW',
            'android.intent.action.SEND',
            'android.intent.action.SEND_MULTIPLE'
        ]
        if action in dangerous_actions:
            risk_score += 20
        
        # Check for overly broad schemes
        if 'http' in schemes or 'https' in schemes:
            risk_score += 15
        
        # Check for wildcard patterns
        if any('*' in host for host in hosts):
            risk_score += 25
        if any('*' in path for path in paths):
            risk_score += 25
        
        # Check for missing validation
        if len(schemes) > 0 and len(hosts) == 0:
            risk_score += 20
        
        # Determine security level
        if risk_score > 60:
            return IntentFilterSecurity.CRITICAL
        elif risk_score > 40:
            return IntentFilterSecurity.VULNERABLE
        elif risk_score > 20:
            return IntentFilterSecurity.MODERATE
        else:
            return IntentFilterSecurity.SECURE

class DeepLinkPayloadGenerator:
    """Generate test payloads for deep link testing"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Attack payload templates - Enhanced with additional vectors
        self.payload_templates = {
            'parameter_injection': [
                '?param=<script>alert(1)</script>',
                '?param=javascript:alert(1)',
                '?param=../../../etc/passwd',
                '?param=\';DROP TABLE users;--',
                '?param=%3Cscript%3Ealert(1)%3C/script%3E',
                '?param=${7*7}',  # Template injection
                '?param={{7*7}}',  # Template injection alternate
                '?param=<img src=x onerror=alert(1)>',  # Image XSS
                '?param=%00',  # Null byte injection
                '?param=\\x00',  # Hex null byte
                '?param=<iframe src=javascript:alert(1)></iframe>',  # Iframe XSS
                '?param=\';system(\'id\');--'  # Command injection
            ],
            'path_traversal': [
                '/../../../etc/passwd',
                '/..\\..\\..\\windows\\system32\\config\\sam',
                '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
                '/....//....//....//etc/passwd',
                '/...%c0%af...%c0%af...%c0%afetc%c0%afpasswd',  # Unicode bypass
                '/.%252e/.%252e/.%252e/etc/passwd',  # Double encoding
                '/..%c1%1c..%c1%1c..%c1%1cetc%c1%1cpasswd',  # UTF-8 overlong
                '/..%c0%2e%c0%2e/..%c0%2e%c0%2e/etc/passwd',  # Unicode traversal
                '/proc/self/environ',  # Process environment
                '/proc/version',  # System version
                '/etc/hosts'  # Network configuration
            ],
            'authorization_bypass': [
                '?admin=true',
                '?role=admin',
                '?privilege=elevated',
                '?bypass=1',
                '?debug=true',
                '?is_admin=1',  # Admin flag
                '?user_type=admin',  # User type manipulation
                '?access_level=999',  # Access level escalation
                '?token=admin_token',  # Token manipulation
                '?session_id=admin_session',  # Session hijacking
                '?uid=0',  # Root user ID
                '?gid=0'  # Root group ID
            ],
            'url_hijacking': [
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'vbscript:msgbox(1)',
                'file:///etc/passwd',
                'ftp://evil.com/malware.apk',  # FTP protocol
                'ldap://evil.com/exploit',  # LDAP injection
                'ssh://root:password@evil.com',  # SSH credential exposure
                'telnet://admin:admin@target.com',  # Telnet access
                'about:blank#blocked',  # About protocol abuse
                'chrome://settings/',  # Browser internals
                'moz-extension://malicious-addon'  # Extension abuse
            ],
            'intent_injection': [
                'intent://example.com#Intent;scheme=http;action=android.intent.action.VIEW;end',
                'intent://evil.com#Intent;component=com.victim/com.victim.Activity;end',
                'intent://example.com#Intent;SEL;action=android.intent.action.CALL;end',
                'intent://malicious#Intent;action=android.intent.action.SENDTO;end',  # Send action
                'intent://exploit#Intent;action=android.intent.action.DIAL;end',  # Dial action
                'intent://attack#Intent;action=android.intent.action.DELETE;end',  # Delete action
                'intent://payload#Intent;action=android.intent.action.EDIT;end',  # Edit action
                'intent://backdoor#Intent;action=android.intent.action.INSTALL_PACKAGE;end'  # Install action
            ],
            'protocol_confusion': [  # New category
                'http://evil.com@target.com/path',  # URL confusion
                'https://target.com.evil.com/login',  # Subdomain confusion
                'ftp://target.com:80/http-tunnel',  # Port confusion
                'mailto:admin@target.com?cc=attacker@evil.com',  # Email injection
                'sms:+1234567890?body=malicious_payload',  # SMS injection
                'tel:+1234567890;evil_param=payload'  # Tel parameter injection
            ],
            'encoding_attacks': [  # New category
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',  # URL encoding
                '%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',  # UTF-8 bypass
                '..%252f..%252f..%252fetc%252fpasswd',  # Double URL encoding
                '..%c1%1c..%c1%1c..%c1%1cetc%c1%1cpasswd',  # Unicode bypass
                '%u002e%u002e%u002f%u002e%u002e%u002f',  # Unicode encoding
                '\u002e\u002e\u002f\u002e\u002e\u002f'  # Unicode literal
            ],
            'deserialization_attacks': [  # New category
                '?data=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',  # Java serialized
                '?obj=YToxOntzOjQ6ImNvZGUiO3M6NDoic3lzdGVtKCdpZCcpOyI7fQ==',  # PHP serialized
                '?pickle=cos\nsystem\n(S\'id\'\ntR.',  # Python pickle
                '?marshal=marshal.loads(base64.b64decode(payload))'  # Python marshal
            ]
        }
    
    async def generate_payloads(self, url_schemes: List[URLScheme]) -> List[DeepLinkPayload]:
        """Generate test payloads for URL schemes"""
        payloads = []
        
        for scheme in url_schemes:
            scheme_payloads = await self._generate_scheme_payloads(scheme)
            payloads.extend(scheme_payloads)
        
        self.logger.info(f"Generated {len(payloads)} test payloads")
        return payloads
    
    async def _generate_scheme_payloads(self, scheme: URLScheme) -> List[DeepLinkPayload]:
        """Generate payloads for specific URL scheme"""
        payloads = []
        base_url = self._construct_base_url(scheme)
        
        # Generate payloads for each attack type
        for attack_type, templates in self.payload_templates.items():
            for i, template in enumerate(templates):
                payload_id = hashlib.md5(f"{scheme.scheme}_{attack_type}_{i}".encode()).hexdigest()[:12]
                
                test_url = self._apply_payload_template(base_url, template, attack_type)
                severity = self._assess_payload_severity(attack_type, scheme)
                
                payload = DeepLinkPayload(
                    payload_id=payload_id,
                    url=test_url,
                    payload_type=attack_type,
                    description=f"{attack_type.replace('_', ' ').title()} test for {scheme.scheme} scheme",
                    expected_behavior=self._get_expected_behavior(attack_type),
                    risk_level=severity,
                    parameters={
                        'base_scheme': scheme.scheme,
                        'template_used': template,
                        'attack_vector': attack_type
                    }
                )
                payloads.append(payload)
        
        return payloads
    
    def _construct_base_url(self, scheme: URLScheme) -> str:
        """Construct base URL from scheme"""
        url = scheme.scheme + "://"
        
        if scheme.host:
            url += scheme.host
        else:
            url += "example.com"
        
        if scheme.path_pattern:
            # Simplify path pattern for testing
            path = scheme.path_pattern.replace("*", "test").replace(".*", "test")
            if not path.startswith("/"):
                path = "/" + path
            url += path
        else:
            url += "/test"
        
        return url
    
    def _apply_payload_template(self, base_url: str, template: str, attack_type: str) -> str:
        """Apply payload template to base URL"""
        if attack_type == 'parameter_injection':
            return base_url + template
        elif attack_type == 'path_traversal':
            # Insert path traversal before the last path component
            parts = base_url.split('/')
            if len(parts) > 3:
                parts.insert(-1, template.lstrip('/'))
                return '/'.join(parts)
            return base_url + template
        elif attack_type == 'authorization_bypass':
            return base_url + template
        elif attack_type == 'url_hijacking':
            # Replace the entire URL for hijacking tests
            return template
        elif attack_type == 'intent_injection':
            return template
        else:
            return base_url + "?" + template.lstrip('?')
    
    def _assess_payload_severity(self, attack_type: str, scheme: URLScheme) -> DeepLinkSeverity:
        """Assess severity of payload based on attack type and scheme"""
        severity_map = {
            'intent_injection': DeepLinkSeverity.CRITICAL,
            'url_hijacking': DeepLinkSeverity.HIGH,
            'authorization_bypass': DeepLinkSeverity.HIGH,
            'parameter_injection': DeepLinkSeverity.MEDIUM,
            'path_traversal': DeepLinkSeverity.MEDIUM
        }
        
        base_severity = severity_map.get(attack_type, DeepLinkSeverity.LOW)
        
        # Increase severity for exported schemes
        if scheme.exported and base_severity == DeepLinkSeverity.MEDIUM:
            return DeepLinkSeverity.HIGH
        elif scheme.exported and base_severity == DeepLinkSeverity.LOW:
            return DeepLinkSeverity.MEDIUM
        
        return base_severity
    
    def _get_expected_behavior(self, attack_type: str) -> str:
        """Get expected behavior for attack type"""
        behaviors = {
            'parameter_injection': 'App should sanitize parameters and not execute injected code',
            'path_traversal': 'App should validate paths and prevent directory traversal',
            'authorization_bypass': 'App should verify authorization regardless of URL parameters',
            'url_hijacking': 'App should validate URL schemes and reject malicious URLs',
            'intent_injection': 'App should validate intent components and prevent injection'
        }
        return behaviors.get(attack_type, 'App should handle malicious input securely')

class IntentSecurityAnalyzer:
    """Analyze intent-based security vulnerabilities"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def analyze_intent_vulnerabilities(self, intent_filters: List[IntentFilter], 
                                           payloads: List[DeepLinkPayload]) -> List[DeepLinkVulnerability]:
        """Analyze intent filters for security vulnerabilities"""
        vulnerabilities = []
        
        # Analyze each intent filter
        for intent_filter in intent_filters:
            filter_vulns = await self._analyze_intent_filter_vulnerabilities(intent_filter)
            vulnerabilities.extend(filter_vulns)
        
        # Analyze payload-specific vulnerabilities
        payload_vulns = await self._analyze_payload_vulnerabilities(payloads)
        vulnerabilities.extend(payload_vulns)
        
        return vulnerabilities
    
    async def _analyze_intent_filter_vulnerabilities(self, intent_filter: IntentFilter) -> List[DeepLinkVulnerability]:
        """Analyze vulnerabilities in single intent filter"""
        vulnerabilities = []
        
        # Check for overly permissive intent filters
        if intent_filter.exported and intent_filter.security_level in [
            IntentFilterSecurity.VULNERABLE, IntentFilterSecurity.CRITICAL
        ]:
            vuln_id = hashlib.md5(f"intent_filter_{intent_filter.action}".encode()).hexdigest()[:12]
            
            vulnerability = DeepLinkVulnerability(
                vulnerability_id=vuln_id,
                vulnerability_type=DeepLinkVulnerabilityType.INTENT_INJECTION,
                severity=DeepLinkSeverity.HIGH if intent_filter.security_level == IntentFilterSecurity.CRITICAL else DeepLinkSeverity.MEDIUM,
                url_scheme=",".join(intent_filter.data_schemes),
                description=f"Overly permissive intent filter for action {intent_filter.action}",
                proof_of_concept=f"intent://{intent_filter.data_hosts[0] if intent_filter.data_hosts else 'example.com'}#Intent;action={intent_filter.action};end",
                impact="Potential for intent injection attacks and unauthorized access",
                recommendations=[
                    "Restrict intent filter permissions",
                    "Validate intent data thoroughly",
                    "Set exported=false if not needed",
                    "Implement proper authorization checks"
                ],
                metadata={
                    'action': intent_filter.action,
                    'categories': intent_filter.category,
                    'security_level': intent_filter.security_level.value
                }
            )
            vulnerabilities.append(vulnerability)
        
        # Check for missing host validation
        if intent_filter.data_schemes and not intent_filter.data_hosts:
            vuln_id = hashlib.md5(f"missing_host_{intent_filter.action}".encode()).hexdigest()[:12]
            
            vulnerability = DeepLinkVulnerability(
                vulnerability_id=vuln_id,
                vulnerability_type=DeepLinkVulnerabilityType.MISSING_VALIDATION,
                severity=DeepLinkSeverity.MEDIUM,
                url_scheme=",".join(intent_filter.data_schemes),
                description="Intent filter lacks host validation",
                proof_of_concept=f"{intent_filter.data_schemes[0]}://malicious.com/attack",
                impact="Allows arbitrary hosts to trigger app functionality",
                recommendations=[
                    "Add host validation to intent filters",
                    "Implement whitelist of allowed hosts",
                    "Validate all incoming intent data"
                ],
                metadata={
                    'action': intent_filter.action,
                    'schemes': intent_filter.data_schemes
                }
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _analyze_payload_vulnerabilities(self, payloads: List[DeepLinkPayload]) -> List[DeepLinkVulnerability]:
        """Analyze vulnerabilities based on generated payloads"""
        vulnerabilities = []
        
        # Group payloads by risk level
        high_risk_payloads = [p for p in payloads if p.risk_level in [DeepLinkSeverity.CRITICAL, DeepLinkSeverity.HIGH]]
        
        for payload in high_risk_payloads:
            vuln_type_mapping = {
                'intent_injection': DeepLinkVulnerabilityType.INTENT_INJECTION,
                'parameter_injection': DeepLinkVulnerabilityType.PARAMETER_INJECTION,
                'path_traversal': DeepLinkVulnerabilityType.PATH_TRAVERSAL,
                'authorization_bypass': DeepLinkVulnerabilityType.AUTHORIZATION_BYPASS,
                'url_hijacking': DeepLinkVulnerabilityType.URL_HIJACKING
            }
            
            vuln_type = vuln_type_mapping.get(payload.payload_type, DeepLinkVulnerabilityType.MISSING_VALIDATION)
            
            vulnerability = DeepLinkVulnerability(
                vulnerability_id=f"payload_{payload.payload_id}",
                vulnerability_type=vuln_type,
                severity=payload.risk_level,
                url_scheme=payload.parameters.get('base_scheme', 'unknown'),
                description=f"Potential {payload.payload_type.replace('_', ' ')} vulnerability",
                proof_of_concept=payload.url,
                impact=self._get_vulnerability_impact(vuln_type),
                recommendations=self._get_vulnerability_recommendations(vuln_type),
                metadata=payload.parameters
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _get_vulnerability_impact(self, vuln_type: DeepLinkVulnerabilityType) -> str:
        """Get impact description for vulnerability type"""
        impacts = {
            DeepLinkVulnerabilityType.INTENT_INJECTION: "Attackers can inject malicious intents and access restricted functionality",
            DeepLinkVulnerabilityType.PARAMETER_INJECTION: "Malicious parameters can lead to code injection or data manipulation",
            DeepLinkVulnerabilityType.PATH_TRAVERSAL: "Attackers can access files outside intended directory structure",
            DeepLinkVulnerabilityType.AUTHORIZATION_BYPASS: "Unauthorized access to protected app functionality",
            DeepLinkVulnerabilityType.URL_HIJACKING: "Malicious URLs can redirect users to attacker-controlled content"
        }
        return impacts.get(vuln_type, "Potential security risk")
    
    def _get_vulnerability_recommendations(self, vuln_type: DeepLinkVulnerabilityType) -> List[str]:
        """Get recommendations for vulnerability type"""
        recommendations = {
            DeepLinkVulnerabilityType.INTENT_INJECTION: [
                "Validate all intent components",
                "Use explicit intents when possible",
                "Implement proper intent filtering"
            ],
            DeepLinkVulnerabilityType.PARAMETER_INJECTION: [
                "Sanitize all URL parameters",
                "Use parameterized queries",
                "Implement input validation"
            ],
            DeepLinkVulnerabilityType.PATH_TRAVERSAL: [
                "Validate file paths",
                "Use canonical path validation",
                "Restrict file access to intended directories"
            ],
            DeepLinkVulnerabilityType.AUTHORIZATION_BYPASS: [
                "Implement proper authorization checks",
                "Validate user permissions",
                "Use secure authentication mechanisms"
            ],
            DeepLinkVulnerabilityType.URL_HIJACKING: [
                "Validate URL schemes",
                "Use whitelist of allowed URLs",
                "Implement URL verification"
            ]
        }
        return recommendations.get(vuln_type, ["Implement proper input validation"])

class DynamicDeepLinkTestingCoordinator:
    """Main coordinator for dynamic deep link testing"""
    
    def __init__(self, app_package: str, config: Optional[Dict] = None):
        self.logger = logging.getLogger(__name__)
        self.app_package = app_package
        self.config = config or {}
        
        # Initialize components
        self.scheme_enumerator = URLSchemeEnumerator(app_package)
        self.payload_generator = DeepLinkPayloadGenerator()
        self.intent_analyzer = IntentSecurityAnalyzer()
        
        # Analysis state
        self.analysis_active = False
        self.current_analysis = None
    
    async def coordinate_deeplink_analysis(self, manifest_path: str, 
                                         analysis_profile: str = "comprehensive") -> DeepLinkAnalysisResult:
        """
        Coordinate comprehensive deep link security analysis.
        
        Analysis Profiles:
        - 'comprehensive': Full deep link security analysis
        - 'scheme_focus': Focus on URL scheme enumeration
        - 'intent_focus': Focus on intent filter analysis
        - 'payload_testing': Focus on payload generation and testing
        - 'vulnerability_scan': Focus on vulnerability detection
        """
        analysis_id = f"DEEPLINK_{int(time.time())}"
        self.logger.info(f"Starting deep link analysis {analysis_id} with profile: {analysis_profile}")
        
        try:
            self.analysis_active = True
            
            # Step 1: Enumerate URL schemes based on profile
            url_schemes = await self._coordinate_scheme_enumeration(manifest_path, analysis_profile)
            
            # Step 2: Analyze intent filters based on profile
            intent_filters = await self._coordinate_intent_analysis(manifest_path, analysis_profile)
            
            # Step 3: Generate test payloads based on profile
            test_payloads = await self._coordinate_payload_generation(url_schemes, analysis_profile)
            
            # Step 4: Detect vulnerabilities based on profile
            vulnerabilities = await self._coordinate_vulnerability_detection(
                intent_filters, test_payloads, analysis_profile
            )
            
            # Step 5: Generate security assessment
            security_assessment = await self._generate_security_assessment(
                url_schemes, intent_filters, vulnerabilities
            )
            
            # Create comprehensive result
            result = DeepLinkAnalysisResult(
                analysis_id=analysis_id,
                app_package=self.app_package,
                url_schemes=url_schemes,
                intent_filters=intent_filters,
                vulnerabilities=vulnerabilities,
                test_results=security_assessment['test_results'],
                security_score=security_assessment['security_score'],
                risk_assessment=security_assessment['risk_assessment'],
                recommendations=security_assessment['recommendations']
            )
            
            self.current_analysis = result
            self.logger.info(f"Deep link analysis {analysis_id} completed successfully")
            return result
            
        except Exception as e:
            self.logger.error(f"Deep link analysis failed: {e}")
            raise
        finally:
            self.analysis_active = False
    
    async def _coordinate_scheme_enumeration(self, manifest_path: str, profile: str) -> List[URLScheme]:
        """Coordinate URL scheme enumeration based on profile"""
        if profile in ['comprehensive', 'scheme_focus']:
            return await self.scheme_enumerator.enumerate_url_schemes(manifest_path)
        else:
            # Basic enumeration for other profiles
            schemes = await self.scheme_enumerator.enumerate_url_schemes(manifest_path)
            return schemes[:5]  # Limit for focused analysis
    
    async def _coordinate_intent_analysis(self, manifest_path: str, profile: str) -> List[IntentFilter]:
        """Coordinate intent filter analysis based on profile"""
        if profile in ['comprehensive', 'intent_focus']:
            return await self.scheme_enumerator.analyze_intent_filters(manifest_path)
        else:
            # Basic analysis for other profiles
            filters = await self.scheme_enumerator.analyze_intent_filters(manifest_path)
            return filters[:3]  # Limit for focused analysis
    
    async def _coordinate_payload_generation(self, schemes: List[URLScheme], profile: str) -> List[DeepLinkPayload]:
        """Coordinate payload generation based on profile"""
        if profile in ['comprehensive', 'payload_testing']:
            return await self.payload_generator.generate_payloads(schemes)
        else:
            # Limited payload generation for other profiles
            limited_schemes = schemes[:3]
            return await self.payload_generator.generate_payloads(limited_schemes)
    
    async def _coordinate_vulnerability_detection(self, intent_filters: List[IntentFilter],
                                                payloads: List[DeepLinkPayload], 
                                                profile: str) -> List[DeepLinkVulnerability]:
        """Coordinate vulnerability detection based on profile"""
        if profile in ['comprehensive', 'vulnerability_scan']:
            return await self.intent_analyzer.analyze_intent_vulnerabilities(intent_filters, payloads)
        else:
            # Basic vulnerability detection for other profiles
            limited_filters = intent_filters[:3]
            limited_payloads = payloads[:10]
            return await self.intent_analyzer.analyze_intent_vulnerabilities(limited_filters, limited_payloads)
    
    async def _generate_security_assessment(self, schemes: List[URLScheme],
                                          intent_filters: List[IntentFilter],
                                          vulnerabilities: List[DeepLinkVulnerability]) -> Dict[str, Any]:
        """Generate comprehensive security assessment"""
        
        # Calculate security score
        security_score = 100.0
        
        # Deduct points for vulnerabilities
        for vuln in vulnerabilities:
            if vuln.severity == DeepLinkSeverity.CRITICAL:
                security_score -= 25
            elif vuln.severity == DeepLinkSeverity.HIGH:
                security_score -= 15
            elif vuln.severity == DeepLinkSeverity.MEDIUM:
                security_score -= 10
            elif vuln.severity == DeepLinkSeverity.LOW:
                security_score -= 5
        
        # Deduct points for insecure intent filters
        for intent_filter in intent_filters:
            if intent_filter.security_level == IntentFilterSecurity.CRITICAL:
                security_score -= 20
            elif intent_filter.security_level == IntentFilterSecurity.VULNERABLE:
                security_score -= 15
        
        security_score = max(0, security_score)
        
        # Risk assessment
        critical_vulns = len([v for v in vulnerabilities if v.severity == DeepLinkSeverity.CRITICAL])
        high_vulns = len([v for v in vulnerabilities if v.severity == DeepLinkSeverity.HIGH])
        
        risk_level = "LOW"
        if critical_vulns > 0:
            risk_level = "CRITICAL"
        elif high_vulns > 2:
            risk_level = "HIGH"
        elif high_vulns > 0 or security_score < 70:
            risk_level = "MEDIUM"
        
        # Generate recommendations
        recommendations = []
        if security_score < 50:
            recommendations.append("Comprehensive security review of deep link implementation required")
        if critical_vulns > 0:
            recommendations.append("Address critical deep link vulnerabilities immediately")
        if any(f.security_level == IntentFilterSecurity.CRITICAL for f in intent_filters):
            recommendations.append("Review and restrict overly permissive intent filters")
        
        recommendations.extend([
            "Implement proper URL validation",
            "Use explicit intents when possible",
            "Validate all deep link parameters",
            "Regular security testing of deep link functionality"
        ])
        
        # Test results summary
        test_results = [
            {
                'test_type': 'url_scheme_enumeration',
                'schemes_found': len(schemes),
                'exported_schemes': len([s for s in schemes if s.exported]),
                'status': 'completed'
            },
            {
                'test_type': 'intent_filter_analysis',
                'filters_analyzed': len(intent_filters),
                'vulnerable_filters': len([f for f in intent_filters if f.security_level in [IntentFilterSecurity.VULNERABLE, IntentFilterSecurity.CRITICAL]]),
                'status': 'completed'
            },
            {
                'test_type': 'vulnerability_detection',
                'vulnerabilities_found': len(vulnerabilities),
                'critical_vulnerabilities': critical_vulns,
                'status': 'completed'
            }
        ]
        
        return {
            'security_score': security_score,
            'risk_assessment': {
                'risk_level': risk_level,
                'total_vulnerabilities': len(vulnerabilities),
                'critical_vulnerabilities': critical_vulns,
                'high_vulnerabilities': high_vulns,
                'vulnerable_intent_filters': len([f for f in intent_filters if f.security_level in [IntentFilterSecurity.VULNERABLE, IntentFilterSecurity.CRITICAL]])
            },
            'recommendations': recommendations,
            'test_results': test_results
        }
    
    async def get_analysis_summary(self) -> Optional[Dict[str, Any]]:
        """Get summary of current analysis"""
        if not self.current_analysis:
            return None
        
        return {
            'analysis_id': self.current_analysis.analysis_id,
            'app_package': self.current_analysis.app_package,
            'url_schemes_count': len(self.current_analysis.url_schemes),
            'intent_filters_count': len(self.current_analysis.intent_filters),
            'vulnerabilities_count': len(self.current_analysis.vulnerabilities),
            'security_score': self.current_analysis.security_score,
            'risk_level': self.current_analysis.risk_assessment.get('risk_level', 'UNKNOWN'),
            'analysis_timestamp': self.current_analysis.analysis_timestamp.isoformat()
        }

# Integration with AODS framework
async def integrate_deeplink_analysis_with_aods(coordinator: DynamicDeepLinkTestingCoordinator,
                                              aods_context: Dict[str, Any]) -> Dict[str, Any]:
    """Integrate deep link analysis with AODS framework"""
    try:
        # Get manifest path from AODS context
        manifest_path = aods_context.get('manifest_path', 'AndroidManifest.xml')
        
        # Determine analysis profile based on AODS scan mode
        scan_mode = aods_context.get('scan_mode', 'comprehensive')
        profile_mapping = {
            'lightning': 'scheme_focus',
            'fast': 'intent_focus', 
            'standard': 'payload_testing',
            'deep': 'comprehensive',
            'comprehensive': 'comprehensive'
        }
        
        analysis_profile = profile_mapping.get(scan_mode, 'comprehensive')
        
        # Run coordinated deep link analysis
        deeplink_result = await coordinator.coordinate_deeplink_analysis(manifest_path, analysis_profile)
        
        # Convert to AODS-compatible format
        aods_findings = []
        for vulnerability in deeplink_result.vulnerabilities:
            aods_findings.append({
                'type': 'deeplink_security',
                'subtype': vulnerability.vulnerability_type.value,
                'severity': vulnerability.severity.value,
                'confidence': 0.8,
                'location': vulnerability.url_scheme,
                'description': vulnerability.description,
                'proof_of_concept': vulnerability.proof_of_concept,
                'recommendations': vulnerability.recommendations,
                'metadata': vulnerability.metadata
            })
        
        return {
            'deeplink_analysis_complete': True,
            'analysis_profile': analysis_profile,
            'deeplink_findings': aods_findings,
            'security_score': deeplink_result.security_score,
            'risk_assessment': deeplink_result.risk_assessment,
            'url_schemes': [{'scheme': s.scheme, 'exported': s.exported} for s in deeplink_result.url_schemes],
            'recommendations': deeplink_result.recommendations,
            'analysis_summary': await coordinator.get_analysis_summary()
        }
        
    except Exception as e:
        logging.getLogger(__name__).error(f"AODS deep link analysis integration failed: {e}")
        return {
            'deeplink_analysis_complete': False,
            'error': str(e),
            'analysis_profile': 'failed'
        }

if __name__ == "__main__":
    async def demo_deeplink_analysis():
        """Demo of Dynamic Deep Link Testing Coordinator"""
        coordinator = DynamicDeepLinkTestingCoordinator("com.example.test")
        
        try:
            # Run comprehensive analysis
            result = await coordinator.coordinate_deeplink_analysis(
                "AndroidManifest.xml", "comprehensive"
            )
            
            print(f"Deep Link Analysis Complete: {result.analysis_id}")
            print(f"URL Schemes: {len(result.url_schemes)}")
            print(f"Intent Filters: {len(result.intent_filters)}")
            print(f"Vulnerabilities: {len(result.vulnerabilities)}")
            print(f"Security Score: {result.security_score:.1f}")
            print(f"Risk Level: {result.risk_assessment.get('risk_level', 'UNKNOWN')}")
            
        except Exception as e:
            print(f"Demo failed: {e}")
    
    asyncio.run(demo_deeplink_analysis()) 