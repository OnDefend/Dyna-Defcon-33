#!/usr/bin/env python3
"""
Enhanced Runtime Vulnerability Detector

Advanced detection engine for analyzing findings from enhanced Frida hooks including:
- Database content analysis
- SharedPreferences security analysis  
- SSL pinning bypass testing
- WebView redirection detection

Author: AODS Team
Date: January 2025
"""

import json
import logging
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Import base detection components
try:
    from .runtime_detector import RuntimeVulnerabilityDetector, RuntimeVulnerability
    BASE_DETECTOR_AVAILABLE = True
except ImportError:
    logging.warning("Base runtime detector not available")
    BASE_DETECTOR_AVAILABLE = False


class EnhancedVulnerabilityType(Enum):
    """Enhanced vulnerability types for new detection capabilities."""
    DATABASE_CONTENT_EXPOSURE = "database_content_exposure"
    SHARED_PREFERENCES_INSECURE = "shared_preferences_insecure"
    SSL_PINNING_BYPASSABLE = "ssl_pinning_bypassable"
    WEBVIEW_URL_REDIRECTION = "webview_url_redirection"
    SENSITIVE_DATA_UNENCRYPTED = "sensitive_data_unencrypted"
    INSECURE_STORAGE_MODE = "insecure_storage_mode"
    CERTIFICATE_VALIDATION_BYPASS = "certificate_validation_bypass"
    JAVASCRIPT_INJECTION = "javascript_injection"


@dataclass
class EnhancedVulnerability:
    """Enhanced vulnerability with detailed evidence."""
    vulnerability_type: EnhancedVulnerabilityType
    title: str
    description: str
    severity: str
    confidence: float
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    masvs_control: Optional[str] = None
    timestamp: Optional[float] = None


class EnhancedRuntimeVulnerabilityDetector:
    """
    Enhanced detector for analyzing advanced runtime findings.
    
    Analyzes findings from:
    - Database content monitoring hooks
    - SharedPreferences content analysis hooks
    - SSL pinning bypass testing hooks
    - WebView redirection detection hooks
    """
    
    def __init__(self):
        """Initialize enhanced runtime vulnerability detector."""
        self.logger = logging.getLogger(__name__)
        self.detected_vulnerabilities = []
        
        # Sensitive data patterns for analysis
        self.sensitive_patterns = {
            'credit_card': re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
            'ssn': re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),
            'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
            'password': re.compile(r'password|passwd|pwd|secret|token|key|credential', re.IGNORECASE),
            'financial': re.compile(r'\$\d+\.?\d*|balance|account|routing', re.IGNORECASE)
        }
        
        # Severity mappings
        self.severity_mappings = {
            'database_content_exposure': 'HIGH',
            'shared_preferences_insecure': 'MEDIUM',
            'ssl_pinning_bypassable': 'HIGH',
            'webview_url_redirection': 'HIGH',
            'sensitive_data_unencrypted': 'HIGH',
            'insecure_storage_mode': 'MEDIUM',
            'certificate_validation_bypass': 'CRITICAL',
            'javascript_injection': 'HIGH'
        }
        
        self.logger.info("Enhanced runtime vulnerability detector initialized")
    
    def analyze_all_enhanced_findings(self, runtime_results: List[Dict[str, Any]]) -> List[EnhancedVulnerability]:
        """
        Analyze all enhanced runtime findings and detect vulnerabilities.
        
        Args:
            runtime_results: List of runtime hook results
            
        Returns:
            List of detected enhanced vulnerabilities
        """
        try:
            self.logger.info("Starting enhanced vulnerability analysis")
            vulnerabilities = []
            
            for result in runtime_results:
                hook_name = result.get('hook_name', 'unknown')
                
                if hook_name == 'database_content_hooks':
                    db_vulns = self.analyze_database_findings(result)
                    vulnerabilities.extend(db_vulns)
                elif hook_name == 'shared_preferences_content_hooks':
                    prefs_vulns = self.analyze_shared_preferences_findings(result)
                    vulnerabilities.extend(prefs_vulns)
                elif hook_name == 'ssl_pinning_bypass_tester':
                    ssl_vulns = self.analyze_ssl_findings(result)
                    vulnerabilities.extend(ssl_vulns)
                elif hook_name == 'webview_redirection_detector':
                    webview_vulns = self.analyze_webview_findings(result)
                    vulnerabilities.extend(webview_vulns)
            
            self.detected_vulnerabilities.extend(vulnerabilities)
            self.logger.info(f"Enhanced analysis complete: {len(vulnerabilities)} vulnerabilities detected")
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error in enhanced vulnerability analysis: {e}")
            return []
    
    def analyze_database_findings(self, result: Dict[str, Any]) -> List[EnhancedVulnerability]:
        """Analyze database content monitoring findings."""
        vulnerabilities = []
        
        try:
            # Extract database findings from Frida script global
            runtime_events = result.get('runtime_events', [])
            
            for event in runtime_events:
                payload = event.get('payload', {})
                
                if 'AODSDatabaseFindings' in str(payload):
                    # Parse database findings
                    db_findings = self._extract_database_findings(payload)
                    
                    for finding in db_findings:
                        vuln = self._create_database_vulnerability(finding)
                        if vuln:
                            vulnerabilities.append(vuln)
            
            self.logger.info(f"Database analysis: {len(vulnerabilities)} vulnerabilities found")
            
        except Exception as e:
            self.logger.error(f"Error analyzing database findings: {e}")
        
        return vulnerabilities
    
    def analyze_shared_preferences_findings(self, result: Dict[str, Any]) -> List[EnhancedVulnerability]:
        """Analyze SharedPreferences content monitoring findings."""
        vulnerabilities = []
        
        try:
            runtime_events = result.get('runtime_events', [])
            
            for event in runtime_events:
                payload = event.get('payload', {})
                
                if 'AODSSharedPreferencesFindings' in str(payload):
                    # Parse SharedPreferences findings
                    prefs_findings = self._extract_shared_preferences_findings(payload)
                    
                    for finding in prefs_findings:
                        vuln = self._create_shared_preferences_vulnerability(finding)
                        if vuln:
                            vulnerabilities.append(vuln)
            
            self.logger.info(f"SharedPreferences analysis: {len(vulnerabilities)} vulnerabilities found")
            
        except Exception as e:
            self.logger.error(f"Error analyzing SharedPreferences findings: {e}")
        
        return vulnerabilities
    
    def analyze_ssl_findings(self, result: Dict[str, Any]) -> List[EnhancedVulnerability]:
        """Analyze SSL pinning bypass testing findings."""
        vulnerabilities = []
        
        try:
            runtime_events = result.get('runtime_events', [])
            
            for event in runtime_events:
                payload = event.get('payload', {})
                
                if 'AODSSSLTestResults' in str(payload):
                    # Parse SSL test findings
                    ssl_findings = self._extract_ssl_findings(payload)
                    
                    for finding in ssl_findings:
                        vuln = self._create_ssl_vulnerability(finding)
                        if vuln:
                            vulnerabilities.append(vuln)
            
            self.logger.info(f"SSL analysis: {len(vulnerabilities)} vulnerabilities found")
            
        except Exception as e:
            self.logger.error(f"Error analyzing SSL findings: {e}")
        
        return vulnerabilities
    
    def analyze_webview_findings(self, result: Dict[str, Any]) -> List[EnhancedVulnerability]:
        """Analyze WebView redirection detection findings."""
        vulnerabilities = []
        
        try:
            runtime_events = result.get('runtime_events', [])
            
            for event in runtime_events:
                payload = event.get('payload', {})
                
                if 'AODSWebViewFindings' in str(payload):
                    # Parse WebView findings
                    webview_findings = self._extract_webview_findings(payload)
                    
                    for finding in webview_findings:
                        vuln = self._create_webview_vulnerability(finding)
                        if vuln:
                            vulnerabilities.append(vuln)
            
            self.logger.info(f"WebView analysis: {len(vulnerabilities)} vulnerabilities found")
            
        except Exception as e:
            self.logger.error(f"Error analyzing WebView findings: {e}")
        
        return vulnerabilities
    
    def _extract_database_findings(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract database findings from payload."""
        findings = []
        
        try:
            # The findings would be in the payload from the Frida script
            # This is a simplified extraction - real implementation would parse the actual data
            if isinstance(payload, dict):
                sensitive_findings = payload.get('sensitive_findings', [])
                findings.extend(sensitive_findings)
            
        except Exception as e:
            self.logger.error(f"Error extracting database findings: {e}")
        
        return findings
    
    def _extract_shared_preferences_findings(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract SharedPreferences findings from payload."""
        findings = []
        
        try:
            if isinstance(payload, dict):
                sensitive_findings = payload.get('sensitive_findings', [])
                findings.extend(sensitive_findings)
            
        except Exception as e:
            self.logger.error(f"Error extracting SharedPreferences findings: {e}")
        
        return findings
    
    def _extract_ssl_findings(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract SSL test findings from payload."""
        findings = []
        
        try:
            if isinstance(payload, dict):
                ssl_test_results = payload.get('ssl_test_results', [])
                findings.extend(ssl_test_results)
            
        except Exception as e:
            self.logger.error(f"Error extracting SSL findings: {e}")
        
        return findings
    
    def _extract_webview_findings(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract WebView findings from payload."""
        findings = []
        
        try:
            if isinstance(payload, dict):
                webview_findings = payload.get('webview_findings', [])
                findings.extend(webview_findings)
            
        except Exception as e:
            self.logger.error(f"Error extracting WebView findings: {e}")
        
        return findings
    
    def _create_database_vulnerability(self, finding: Dict[str, Any]) -> Optional[EnhancedVulnerability]:
        """Create vulnerability from database finding."""
        try:
            finding_type = finding.get('type', '')
            
            if finding_type == 'sensitive_data_found':
                return EnhancedVulnerability(
                    vulnerability_type=EnhancedVulnerabilityType.DATABASE_CONTENT_EXPOSURE,
                    title="Sensitive Data in Database",
                    description=f"Sensitive data detected in database context: {finding.get('context', 'unknown')}. "
                              f"Pattern matched: {finding.get('pattern', 'unknown')}",
                    severity="HIGH",
                    confidence=0.85,
                    evidence={
                        'context': finding.get('context'),
                        'pattern': finding.get('pattern'),
                        'sample': finding.get('sample', '')[:50],
                        'timestamp': finding.get('timestamp')
                    },
                    remediation=[
                        "Encrypt sensitive data before storing in database",
                        "Use parameterized queries to prevent injection",
                        "Implement proper access controls for database files",
                        "Consider using Android Keystore for sensitive data"
                    ],
                    cwe_id="CWE-200",
                    masvs_control="MASVS-STORAGE-1"
                )
            
            elif finding_type == 'sensitive_data_modification':
                return EnhancedVulnerability(
                    vulnerability_type=EnhancedVulnerabilityType.SENSITIVE_DATA_UNENCRYPTED,
                    title="Unencrypted Sensitive Data Storage",
                    description=f"Sensitive data being stored unencrypted: {finding.get('sql', 'unknown operation')}",
                    severity="HIGH",
                    confidence=0.80,
                    evidence={
                        'sql': finding.get('sql'),
                        'timestamp': finding.get('timestamp')
                    },
                    remediation=[
                        "Encrypt sensitive data before database storage",
                        "Use Android Keystore for encryption keys",
                        "Implement data classification policies"
                    ],
                    cwe_id="CWE-311",
                    masvs_control="MASVS-STORAGE-1"
                )
            
        except Exception as e:
            self.logger.error(f"Error creating database vulnerability: {e}")
        
        return None
    
    def _create_shared_preferences_vulnerability(self, finding: Dict[str, Any]) -> Optional[EnhancedVulnerability]:
        """Create vulnerability from SharedPreferences finding."""
        try:
            finding_type = finding.get('type', '')
            
            if finding_type == 'insecure_preference_mode':
                return EnhancedVulnerability(
                    vulnerability_type=EnhancedVulnerabilityType.INSECURE_STORAGE_MODE,
                    title="Insecure SharedPreferences Mode",
                    description=f"SharedPreferences created with insecure mode: {finding.get('mode_string', 'unknown')} "
                              f"for preference: {finding.get('preference_name', 'unknown')}",
                    severity="MEDIUM",
                    confidence=0.90,
                    evidence={
                        'preference_name': finding.get('preference_name'),
                        'mode': finding.get('mode'),
                        'mode_string': finding.get('mode_string'),
                        'timestamp': finding.get('timestamp')
                    },
                    remediation=[
                        "Use MODE_PRIVATE for all SharedPreferences",
                        "Avoid MODE_WORLD_READABLE and MODE_WORLD_WRITABLE",
                        "Consider using EncryptedSharedPreferences for sensitive data"
                    ],
                    cwe_id="CWE-732",
                    masvs_control="MASVS-STORAGE-1"
                )
            
            elif finding_type == 'sensitive_preference_value':
                return EnhancedVulnerability(
                    vulnerability_type=EnhancedVulnerabilityType.SHARED_PREFERENCES_INSECURE,
                    title="Sensitive Data in SharedPreferences",
                    description=f"Sensitive data stored in SharedPreferences: {finding.get('key', 'unknown key')}. "
                              f"Patterns detected: {', '.join(finding.get('patterns', []))}",
                    severity="HIGH",
                    confidence=0.80,
                    evidence={
                        'preference_name': finding.get('preference_name'),
                        'key': finding.get('key'),
                        'patterns': finding.get('patterns'),
                        'value_sample': finding.get('value_sample', '')[:50],
                        'data_type': finding.get('data_type'),
                        'timestamp': finding.get('timestamp')
                    },
                    remediation=[
                        "Use EncryptedSharedPreferences for sensitive data",
                        "Implement proper data classification",
                        "Consider using Android Keystore for credentials",
                        "Avoid storing passwords or tokens in preferences"
                    ],
                    cwe_id="CWE-200",
                    masvs_control="MASVS-STORAGE-1"
                )
            
        except Exception as e:
            self.logger.error(f"Error creating SharedPreferences vulnerability: {e}")
        
        return None
    
    def _create_ssl_vulnerability(self, finding: Dict[str, Any]) -> Optional[EnhancedVulnerability]:
        """Create vulnerability from SSL finding."""
        try:
            finding_type = finding.get('type', '')
            
            if finding_type == 'insecure_trust_manager':
                return EnhancedVulnerability(
                    vulnerability_type=EnhancedVulnerabilityType.CERTIFICATE_VALIDATION_BYPASS,
                    title="Insecure SSL Trust Manager",
                    description=f"Insecure trust manager detected: {finding.get('class_name', 'unknown')}. "
                              f"This may allow certificate validation bypass.",
                    severity="CRITICAL",
                    confidence=0.95,
                    evidence={
                        'class_name': finding.get('class_name'),
                        'timestamp': finding.get('timestamp')
                    },
                    remediation=[
                        "Use default Android trust managers",
                        "Implement proper certificate validation",
                        "Add certificate pinning for critical connections",
                        "Remove custom trust managers that bypass validation"
                    ],
                    cwe_id="CWE-295",
                    masvs_control="MASVS-NETWORK-1"
                )
            
            elif finding_type == 'pinning_bypass_possible':
                return EnhancedVulnerability(
                    vulnerability_type=EnhancedVulnerabilityType.SSL_PINNING_BYPASSABLE,
                    title="SSL Pinning Bypass Possible",
                    description=f"SSL certificate pinning implementation may be bypassable. "
                              f"Pinner class: {finding.get('pinner_class', 'unknown')}",
                    severity="HIGH",
                    confidence=0.75,
                    evidence={
                        'pinner_class': finding.get('pinner_class'),
                        'timestamp': finding.get('timestamp')
                    },
                    remediation=[
                        "Strengthen certificate pinning implementation",
                        "Add runtime application self-protection (RASP)",
                        "Implement anti-hooking measures",
                        "Use multiple pinning methods"
                    ],
                    cwe_id="CWE-295",
                    masvs_control="MASVS-NETWORK-2"
                )
            
            elif finding_type == 'hostname_verification_bypassed':
                return EnhancedVulnerability(
                    vulnerability_type=EnhancedVulnerabilityType.CERTIFICATE_VALIDATION_BYPASS,
                    title="Hostname Verification Bypassed",
                    description=f"Hostname verification is bypassed by: {finding.get('verifier_class', 'unknown')}",
                    severity="HIGH",
                    confidence=0.90,
                    evidence={
                        'verifier_class': finding.get('verifier_class'),
                        'timestamp': finding.get('timestamp')
                    },
                    remediation=[
                        "Enable proper hostname verification",
                        "Use default hostname verifiers",
                        "Implement strict SSL policy",
                        "Remove hostname verification bypass code"
                    ],
                    cwe_id="CWE-295",
                    masvs_control="MASVS-NETWORK-1"
                )
            
        except Exception as e:
            self.logger.error(f"Error creating SSL vulnerability: {e}")
        
        return None
    
    def _create_webview_vulnerability(self, finding: Dict[str, Any]) -> Optional[EnhancedVulnerability]:
        """Create vulnerability from WebView finding."""
        try:
            finding_type = finding.get('type', '')
            
            if finding_type == 'url_redirection_vulnerability':
                return EnhancedVulnerability(
                    vulnerability_type=EnhancedVulnerabilityType.WEBVIEW_URL_REDIRECTION,
                    title="WebView URL Redirection Vulnerability",
                    description=f"WebView is vulnerable to URL redirection attacks. "
                              f"Test URL: {finding.get('test_url', 'unknown')}",
                    severity="HIGH",
                    confidence=0.80,
                    evidence={
                        'test_url': finding.get('test_url'),
                        'timestamp': finding.get('timestamp')
                    },
                    remediation=[
                        "Implement URL validation before loading",
                        "Use URL allowlists for trusted domains",
                        "Disable JavaScript if not needed",
                        "Implement shouldOverrideUrlLoading properly"
                    ],
                    cwe_id="CWE-601",
                    masvs_control="MASVS-PLATFORM-1"
                )
            
            elif finding_type == 'javascript_injection_possible':
                return EnhancedVulnerability(
                    vulnerability_type=EnhancedVulnerabilityType.JAVASCRIPT_INJECTION,
                    title="WebView JavaScript Injection Possible",
                    description=f"WebView allows JavaScript injection for URL: {finding.get('url', 'unknown')}",
                    severity="HIGH",
                    confidence=0.75,
                    evidence={
                        'url': finding.get('url'),
                        'timestamp': finding.get('timestamp')
                    },
                    remediation=[
                        "Disable JavaScript if not required",
                        "Implement Content Security Policy",
                        "Validate all injected JavaScript",
                        "Use addJavascriptInterface carefully"
                    ],
                    cwe_id="CWE-79",
                    masvs_control="MASVS-PLATFORM-1"
                )
            
            elif finding_type == 'file_access_vulnerability':
                return EnhancedVulnerability(
                    vulnerability_type=EnhancedVulnerabilityType.WEBVIEW_URL_REDIRECTION,
                    title="WebView File Access Vulnerability",
                    description=f"WebView allows file access which could lead to data exposure. URL: {finding.get('url', 'unknown')}",
                    severity="HIGH",
                    confidence=0.85,
                    evidence={
                        'url': finding.get('url'),
                        'timestamp': finding.get('timestamp')
                    },
                    remediation=[
                        "Disable file access with setAllowFileAccess(false)",
                        "Disable universal access from file URLs",
                        "Use content providers for file access",
                        "Implement proper access controls"
                    ],
                    cwe_id="CWE-200",
                    masvs_control="MASVS-PLATFORM-1"
                )
            
        except Exception as e:
            self.logger.error(f"Error creating WebView vulnerability: {e}")
        
        return None
    
    def get_vulnerabilities_summary(self) -> Dict[str, Any]:
        """Get summary of detected vulnerabilities."""
        try:
            summary = {
                'total_vulnerabilities': len(self.detected_vulnerabilities),
                'by_type': {},
                'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                'high_confidence': 0,
                'remediation_required': 0
            }
            
            for vuln in self.detected_vulnerabilities:
                # Count by type
                vuln_type = vuln.vulnerability_type.value
                summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
                
                # Count by severity
                severity = vuln.severity
                if severity in summary['by_severity']:
                    summary['by_severity'][severity] += 1
                
                # Count high confidence
                if vuln.confidence >= 0.8:
                    summary['high_confidence'] += 1
                
                # Count those requiring remediation
                if vuln.remediation:
                    summary['remediation_required'] += 1
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error generating vulnerability summary: {e}")
            return {}
    
    def export_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Export vulnerabilities in standard format."""
        try:
            exported = []
            
            for vuln in self.detected_vulnerabilities:
                exported.append({
                    'vulnerability_type': vuln.vulnerability_type.value,
                    'title': vuln.title,
                    'description': vuln.description,
                    'severity': vuln.severity,
                    'confidence': vuln.confidence,
                    'evidence': vuln.evidence,
                    'remediation': vuln.remediation,
                    'cwe_id': vuln.cwe_id,
                    'masvs_control': vuln.masvs_control,
                    'timestamp': vuln.timestamp
                })
            
            return exported
            
        except Exception as e:
            self.logger.error(f"Error exporting vulnerabilities: {e}")
            return []