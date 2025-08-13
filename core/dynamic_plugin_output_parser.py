#!/usr/bin/env python3
"""
Dynamic Plugin Output Parser
===========================

This module parses dynamic plugin text outputs and converts them into structured
SecurityFinding objects using the same approach as static analysis plugins.

This ensures dynamic analysis results have the same quality CWE/MASVS mappings
and structured data as static analysis.
"""

import re
import json
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

# Import the same data structures used by static analysis
try:
    from plugins.enhanced_static_analysis.data_structures import (
        SecurityFinding, SeverityLevel, FindingCategory, RiskLevel, PatternType
    )
except ImportError:
    # Fallback if import fails
    from dataclasses import dataclass
    from enum import Enum
    
    class SeverityLevel(Enum):
        CRITICAL = "CRITICAL"
        HIGH = "HIGH"
        MEDIUM = "MEDIUM"
        LOW = "LOW"
    
    class FindingCategory(Enum):
        SECURITY_VULNERABILITY = "SECURITY_VULNERABILITY"
        CRYPTOGRAPHIC_WEAKNESS = "CRYPTOGRAPHIC_WEAKNESS"
        DATA_STORAGE = "DATA_STORAGE"
        NETWORK_SECURITY = "NETWORK_SECURITY"
    
    @dataclass
    class SecurityFinding:
        title: str
        description: str
        severity: SeverityLevel
        category: str
        file_path: str = ""
        line_number: Optional[int] = None
        code_snippet: Optional[str] = None
        evidence: Optional[str] = None
        masvs_control: Optional[str] = None
        cwe_id: Optional[str] = None
        detection_method: str = "dynamic_analysis"
        source: str = "dynamic_analysis"
        confidence: float = 0.7
        recommendations: List[str] = field(default_factory=list)
        metadata: Dict[str, Any] = field(default_factory=dict)


class DynamicPluginOutputParser:
    """
    Parses dynamic plugin text outputs and creates structured SecurityFinding objects
    using the same CWE/MASVS mapping approach as static analysis.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Plugin-specific parsing patterns
        self.plugin_parsers = {
            'enhanced_data_storage_analyzer': self._parse_data_storage_output,
            'insecure_logging_detection': self._parse_logging_output,
            'injection_vulnerabilities': self._parse_injection_output,
            'network_communication_tests': self._parse_network_output,
            'intent_fuzzing_analysis': self._parse_intent_output,
            'advanced_vulnerability_detection': self._parse_advanced_vuln_output,
            'enhanced_platform_usage_analyzer': self._parse_platform_output,
            'traversal_vulnerabilities': self._parse_traversal_output,
            'apk2url_extraction': self._parse_url_output,
            'authentication_security_analysis': self._parse_auth_output,
            'network_cleartext_traffic': self._parse_cleartext_output,
            'apk_signing_certificate_analyzer': self._parse_cert_output,
            'component_exploitation_plugin': self._parse_component_output,
            'mastg_integration': self._parse_mastg_output,
            'library_vulnerability_scanner': self._parse_library_output
        }
    
    def parse_dynamic_vulnerability(self, vuln_dict: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Parse a dynamic vulnerability dictionary and extract structured findings.
        
        Args:
            vuln_dict: Raw vulnerability dictionary from dynamic scan
            
        Returns:
            List of structured SecurityFinding objects
        """
        plugin_name = vuln_dict.get('plugin_name', '')
        description = vuln_dict.get('description', '')
        title = vuln_dict.get('title', '').replace(' Security Analysis', '')
        
        # Use plugin-specific parser if available
        if plugin_name in self.plugin_parsers:
            return self.plugin_parsers[plugin_name](vuln_dict, title, description)
        else:
            # Generic parsing fallback
            return self._parse_generic_output(vuln_dict, title, description)
    
    def _parse_data_storage_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Parse Enhanced Data Storage Analysis output."""
        findings = []
        
        # Extract findings from description text
        if 'CRITICAL' in description and ('external storage' in description.lower() or 'shared preferences' in description.lower()):
            import uuid
            finding = SecurityFinding(
                id=f"dynamic_{uuid.uuid4().hex[:8]}",
                title="Insecure Data Storage in External Storage",
                description="Application stores sensitive data in external storage accessible to other applications",
                severity=SeverityLevel.CRITICAL,
                category=FindingCategory.DATA_STORAGE.value,
                file_path="Runtime Analysis",
                cwe_id="CWE-312",
                masvs_control="MASVS-STORAGE-1",
                confidence=0.8,
                detection_method="dynamic_storage_analysis",
                source="dynamic_analysis",
                recommendations=[
                    "Use internal storage for sensitive data",
                    "Encrypt sensitive data before storage",
                    "Implement proper access controls"
                ]
            )
            findings.append(finding)
        
        if 'shared preferences' in description.lower() and 'insecure' in description.lower():
            import uuid
            finding = SecurityFinding(
                id=f"dynamic_{uuid.uuid4().hex[:8]}",
                title="Insecure Shared Preferences Storage",
                description="Application stores sensitive data in shared preferences without encryption",
                severity=SeverityLevel.HIGH,
                category=FindingCategory.DATA_STORAGE.value,
                file_path="Runtime Analysis",
                cwe_id="CWE-312",
                masvs_control="MASVS-STORAGE-1",
                confidence=0.7,
                detection_method="dynamic_storage_analysis",
                source="dynamic_analysis",
                recommendations=[
                    "Encrypt shared preferences data",
                    "Use Android Keystore for key management",
                    "Validate data access patterns"
                ]
            )
            findings.append(finding)
        
        return findings if findings else [self._create_default_finding(title, description, "MASVS-STORAGE-1", "CWE-312")]
    
    def _parse_logging_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Parse Insecure Logging Detection output."""
        findings = []
        
        if 'sensitive' in description.lower() and 'log' in description.lower():
            finding = SecurityFinding(
                title="Sensitive Data in Application Logs",
                description="Application logs contain sensitive information that could be accessed by other applications",
                severity=SeverityLevel.HIGH,
                category=FindingCategory.SECURITY_VULNERABILITY.value,
                cwe_id="CWE-532",
                masvs_control="MASVS-PRIVACY-1",
                confidence=0.8,
                detection_method="dynamic_logging_analysis",
                source="dynamic_analysis",
                recommendations=[
                    "Remove sensitive data from log statements",
                    "Implement log sanitization",
                    "Use conditional logging for production builds"
                ]
            )
            findings.append(finding)
        
        return findings if findings else [self._create_default_finding(title, description, "MASVS-PRIVACY-1", "CWE-532")]
    
    def _parse_injection_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Parse SQL Injection Vulnerabilities output."""
        findings = []
        
        if 'sql' in description.lower() and 'injection' in description.lower():
            finding = SecurityFinding(
                title="SQL Injection Vulnerability",
                description="Application constructs SQL queries using unsanitized user input",
                severity=SeverityLevel.CRITICAL,
                category=FindingCategory.SECURITY_VULNERABILITY.value,
                cwe_id="CWE-89",
                masvs_control="MASVS-CODE-1",
                confidence=0.9,
                detection_method="dynamic_injection_testing",
                source="dynamic_analysis",
                recommendations=[
                    "Use parameterized queries or prepared statements",
                    "Implement input validation and sanitization",
                    "Apply principle of least privilege for database access"
                ]
            )
            findings.append(finding)
        
        return findings if findings else [self._create_default_finding(title, description, "MASVS-CODE-1", "CWE-89")]
    
    def _parse_network_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Parse Network Communication Security output."""
        findings = []
        
        if 'cleartext' in description.lower() or 'http' in description.lower():
            finding = SecurityFinding(
                title="Cleartext Network Communication",
                description="Application transmits sensitive data over unencrypted connections",
                severity=SeverityLevel.HIGH,
                category=FindingCategory.NETWORK_SECURITY.value,
                cwe_id="CWE-319",
                masvs_control="MASVS-NETWORK-1",
                confidence=0.8,
                detection_method="dynamic_network_analysis",
                source="dynamic_analysis",
                recommendations=[
                    "Use HTTPS for all network communications",
                    "Implement certificate pinning",
                    "Validate TLS configuration"
                ]
            )
            findings.append(finding)
        
        return findings if findings else [self._create_default_finding(title, description, "MASVS-NETWORK-1", "CWE-319")]
    
    def _parse_intent_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Parse Intent Fuzzing Analysis output."""
        findings = []
        
        if 'intent' in description.lower() and ('exported' in description.lower() or 'unprotected' in description.lower()):
            finding = SecurityFinding(
                title="Unprotected Exported Component",
                description="Application exposes components that can be accessed by other applications without proper protection",
                severity=SeverityLevel.MEDIUM,
                category=FindingCategory.SECURITY_VULNERABILITY.value,
                cwe_id="CWE-926",
                masvs_control="MASVS-PLATFORM-1",
                confidence=0.7,
                detection_method="dynamic_component_testing",
                source="dynamic_analysis",
                recommendations=[
                    "Set exported=false for internal components",
                    "Implement permission checks for exported components",
                    "Validate intent data and sources"
                ]
            )
            findings.append(finding)
        
        return findings if findings else [self._create_default_finding(title, description, "MASVS-PLATFORM-1", "CWE-926")]
    
    def _parse_advanced_vuln_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Parse Advanced Vulnerability Detection output."""
        return [self._create_default_finding(title, description, "MASVS-GENERAL", "CWE-200")]
    
    def _parse_platform_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Parse Enhanced Improper Platform Usage Analysis output."""
        return [self._create_default_finding(title, description, "MASVS-PLATFORM-1", "CWE-693")]
    
    def _parse_traversal_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Parse Traversal Vulnerability Analysis output."""
        findings = []
        
        if 'traversal' in description.lower() or '../' in description:
            finding = SecurityFinding(
                title="Path Traversal Vulnerability",
                description="Application allows access to files outside intended directory structure",
                severity=SeverityLevel.HIGH,
                category=FindingCategory.SECURITY_VULNERABILITY.value,
                cwe_id="CWE-22",
                masvs_control="MASVS-CODE-1",
                confidence=0.8,
                detection_method="dynamic_traversal_testing",
                source="dynamic_analysis",
                recommendations=[
                    "Validate and sanitize file paths",
                    "Use absolute paths and avoid user-controlled paths",
                    "Implement proper access controls"
                ]
            )
            findings.append(finding)
        
        return findings if findings else [self._create_default_finding(title, description, "MASVS-CODE-1", "CWE-22")]
    
    def _parse_url_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Parse APK2URL Endpoint Discovery output."""
        return [self._create_default_finding(title, description, "MASVS-NETWORK-1", "CWE-200")]
    
    def _parse_auth_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Parse Authentication Security Analysis output."""
        return [self._create_default_finding(title, description, "MASVS-AUTH-1", "CWE-287")]
    
    def _parse_cleartext_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Parse Network Cleartext Traffic Analysis output."""
        return [self._create_default_finding(title, description, "MASVS-NETWORK-1", "CWE-319")]
    
    def _parse_cert_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Parse APK Signing Certificate Analysis output."""
        return [self._create_default_finding(title, description, "MASVS-RESILIENCE-1", "CWE-295")]
    
    def _parse_component_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Parse Component Exploitation Plugin output."""
        return [self._create_default_finding(title, description, "MASVS-PLATFORM-1", "CWE-926")]
    
    def _parse_mastg_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Parse MASTG Compliance Analysis output."""
        return [self._create_default_finding(title, description, "MASVS-GENERAL", "CWE-200")]
    
    def _parse_library_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Parse Library Vulnerability Scanner output."""
        return [self._create_default_finding(title, description, "MASVS-CODE-1", "CWE-1104")]
    
    def _parse_generic_output(self, vuln_dict: Dict, title: str, description: str) -> List[SecurityFinding]:
        """Generic parser for unknown plugin outputs."""
        return [self._create_default_finding(title, description, "MASVS-GENERAL", "CWE-200")]
    
    def _create_default_finding(self, title: str, description: str, masvs_control: str, cwe_id: str) -> SecurityFinding:
        """Create a default SecurityFinding with basic information."""
        
        # Clean up title
        clean_title = title.replace(' Security Analysis', '').strip()
        
        # Determine severity based on CWE
        severity = self._determine_severity_from_cwe(cwe_id)
        
        # Create proper description
        clean_description = self._clean_description(description)
        
        # Generate unique ID
        import uuid
        finding_id = f"dynamic_{uuid.uuid4().hex[:8]}"
        
        return SecurityFinding(
            id=finding_id,
            title=clean_title,
            description=clean_description,
            severity=severity,
            category=FindingCategory.SECURITY_VULNERABILITY.value,
            file_path="Runtime Analysis",  # Dynamic analysis doesn't have specific file paths
            cwe_id=cwe_id,
            masvs_control=masvs_control,
            confidence=0.7,
            detection_method="dynamic_analysis",
            source="dynamic_analysis",
            recommendations=self._get_recommendations_for_cwe(cwe_id),
            metadata={'original_plugin_output': description[:200]}
        )
    
    def _determine_severity_from_cwe(self, cwe_id: str) -> SeverityLevel:
        """Determine severity level based on CWE ID."""
        critical_cwes = ['CWE-89', 'CWE-78', 'CWE-79', 'CWE-327']
        high_cwes = ['CWE-22', 'CWE-319', 'CWE-532', 'CWE-312']
        medium_cwes = ['CWE-926', 'CWE-693', 'CWE-295', 'CWE-287']
        
        if cwe_id in critical_cwes:
            return SeverityLevel.CRITICAL
        elif cwe_id in high_cwes:
            return SeverityLevel.HIGH
        elif cwe_id in medium_cwes:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def _clean_description(self, description: str) -> str:
        """Clean up description text for professional presentation."""
        if not description or len(description.strip()) < 20:
            return "Security vulnerability detected during dynamic analysis."
        
        # Take first meaningful sentence
        sentences = description.split('. ')
        if sentences:
            clean_desc = sentences[0].strip()
            # Remove formatting characters
            clean_desc = re.sub(r'[=\-_*#]+', '', clean_desc)
            clean_desc = clean_desc.replace('ANALYSIS REPORT', '').replace('SECURITY ANALYSIS', '').strip()
            return clean_desc + '.' if not clean_desc.endswith('.') else clean_desc
        
        return description[:200] + '...' if len(description) > 200 else description
    
    def _get_recommendations_for_cwe(self, cwe_id: str) -> List[str]:
        """Get specific recommendations based on CWE ID."""
        recommendations_map = {
            'CWE-89': [
                "Use parameterized queries or prepared statements",
                "Implement input validation and sanitization",
                "Apply principle of least privilege for database access"
            ],
            'CWE-78': [
                "Avoid executing system commands with user input",
                "Use safe APIs instead of shell commands",
                "Implement input validation and sanitization"
            ],
            'CWE-79': [
                "Implement proper input encoding",
                "Use Content Security Policy (CSP)",
                "Validate and sanitize all user inputs"
            ],
            'CWE-327': [
                "Replace weak cryptographic algorithms with stronger ones",
                "Use AES-256 or other approved encryption standards",
                "Implement proper key management"
            ],
            'CWE-22': [
                "Validate and sanitize file paths",
                "Use absolute paths and avoid user-controlled paths",
                "Implement proper access controls"
            ],
            'CWE-319': [
                "Use HTTPS for all network communications",
                "Implement certificate pinning",
                "Validate TLS configuration"
            ],
            'CWE-532': [
                "Remove sensitive data from log statements",
                "Implement log sanitization",
                "Use conditional logging for production builds"
            ],
            'CWE-312': [
                "Use internal storage for sensitive data",
                "Encrypt sensitive data at rest",
                "Implement proper access controls"
            ]
        }
        
        return recommendations_map.get(cwe_id, [
            "Review security implementation",
            "Follow OWASP security guidelines",
            "Implement defense-in-depth measures"
        ])


def parse_dynamic_scan_results(scan_data: Dict[str, Any]) -> List[SecurityFinding]:
    """
    Parse dynamic scan results and return structured SecurityFinding objects.
    
    Args:
        scan_data: The complete dynamic scan data dictionary
        
    Returns:
        List of structured SecurityFinding objects
    """
    parser = DynamicPluginOutputParser()
    structured_findings = []
    
    vulnerabilities = scan_data.get('vulnerabilities', [])
    
    for vuln_dict in vulnerabilities:
        # Skip the JADX static analysis findings (they're already structured)
        if vuln_dict.get('plugin_name') == 'jadx_static_analysis':
            continue
            
        # Parse dynamic plugin outputs
        plugin_findings = parser.parse_dynamic_vulnerability(vuln_dict)
        structured_findings.extend(plugin_findings)
    
    return structured_findings