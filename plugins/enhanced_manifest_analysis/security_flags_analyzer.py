"""
Enhanced Manifest Analysis - Security Flags Analyzer Component

This module provides comprehensive security flags analysis from AndroidManifest.xml
including debuggable, allowBackup, cleartext traffic, and other security configurations.
"""

import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any

from .data_structures import (
    SecurityFlags, ManifestSecurityFinding, RiskLevel, AnalysisMethod,
    ManifestAnalysisConfiguration, create_security_finding
)

class SecurityFlagsAnalyzer:
    """Analyzer for security-related flags from AndroidManifest.xml."""
    
    def __init__(self, config: Optional[ManifestAnalysisConfiguration] = None):
        """Initialize the security flags analyzer."""
        self.config = config or ManifestAnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
        self.namespace = '{http://schemas.android.com/apk/res/android}'
    
    def analyze_security_flags(self, manifest_root: ET.Element) -> SecurityFlags:
        """Analyze security flags from manifest."""
        try:
            # Find application element
            application = manifest_root.find('application')
            if application is None:
                self.logger.warning("No application element found in manifest")
                return SecurityFlags()
            
            # Extract security flags
            debuggable = self._get_boolean_attribute(application, 'debuggable', False)
            allow_backup = self._get_boolean_attribute(application, 'allowBackup', True)
            uses_cleartext_traffic = self._get_cleartext_traffic_setting(application)
            test_only = self._get_boolean_attribute(application, 'testOnly', False)
            extract_native_libs = self._get_boolean_attribute(application, 'extractNativeLibs', True)
            allow_native_heap_pointer_tagging = self._get_boolean_attribute(
                application, 'allowNativeHeapPointerTagging', False
            )
            
            # Get other security-related attributes
            network_security_config = application.get(f'{self.namespace}networkSecurityConfig')
            backup_agent = application.get(f'{self.namespace}backupAgent')
            
            # Create security flags object
            security_flags = SecurityFlags(
                debuggable=debuggable,
                allow_backup=allow_backup,
                uses_cleartext_traffic=uses_cleartext_traffic,
                test_only=test_only,
                extract_native_libs=extract_native_libs,
                allow_native_heap_pointer_tagging=allow_native_heap_pointer_tagging,
                network_security_config=network_security_config,
                backup_agent=backup_agent
            )
            
            # Analyze security implications
            self._analyze_security_implications(security_flags)
            
            return security_flags
            
        except Exception as e:
            self.logger.error(f"Failed to analyze security flags: {e}")
            return SecurityFlags()
    
    def analyze_security_flags_findings(self, security_flags: SecurityFlags) -> List[ManifestSecurityFinding]:
        """Analyze security flags for security findings."""
        findings = []
        
        try:
            # Check debuggable flag
            if security_flags.debuggable:
                findings.append(self._create_debuggable_finding())
            
            # Check allow backup flag
            if security_flags.allow_backup:
                findings.append(self._create_allow_backup_finding(security_flags.backup_agent))
            
            # Check cleartext traffic
            if security_flags.uses_cleartext_traffic is True:
                findings.append(self._create_cleartext_traffic_finding())
            
            # Check test only flag
            if security_flags.test_only:
                findings.append(self._create_test_only_finding())
            
            # Check extract native libs (potential security implication)
            if not security_flags.extract_native_libs:
                findings.append(self._create_extract_native_libs_finding())
            
            # Check network security config
            if security_flags.network_security_config:
                findings.append(self._create_network_security_config_finding(
                    security_flags.network_security_config
                ))
            
        except Exception as e:
            self.logger.error(f"Failed to analyze security flags findings: {e}")
        
        return findings
    
    def _get_boolean_attribute(self, element: ET.Element, attr_name: str, default: bool) -> bool:
        """Get boolean attribute value with proper Android namespace handling."""
        value = element.get(f'{self.namespace}{attr_name}')
        if value is None:
            return default
        return value.lower() == 'true'
    
    def _get_cleartext_traffic_setting(self, application: ET.Element) -> Optional[bool]:
        """Get cleartext traffic setting with proper handling of different Android versions."""
        # Check usesCleartextTraffic attribute
        cleartext_value = application.get(f'{self.namespace}usesCleartextTraffic')
        if cleartext_value is not None:
            return cleartext_value.lower() == 'true'
        
        # Check network security config for cleartext traffic policy
        network_config = application.get(f'{self.namespace}networkSecurityConfig')
        if network_config:
            # If network security config is present, cleartext traffic is likely disabled
            return False
        
        # Default varies by target SDK version, return None to indicate default behavior
        return None
    
    def _analyze_security_implications(self, security_flags: SecurityFlags) -> None:
        """Analyze security implications and populate issues and recommendations."""
        # Check for critical security issues
        if security_flags.debuggable:
            security_flags.issues.append("Debuggable flag is enabled - allows runtime debugging")
        
        if security_flags.uses_cleartext_traffic is True:
            security_flags.issues.append("Cleartext traffic is enabled - allows unencrypted HTTP connections")
        
        if security_flags.test_only:
            security_flags.issues.append("Test-only flag is enabled - application is marked for testing")
        
        if security_flags.allow_backup and not security_flags.backup_agent:
            security_flags.issues.append("Backup is enabled without custom backup agent - may expose sensitive data")
        
        # Generate recommendations
        if security_flags.debuggable:
            security_flags.recommendations.append("Disable debuggable flag in production builds")
        
        if security_flags.allow_backup:
            security_flags.recommendations.append("Consider disabling backup or implementing custom backup agent")
        
        if security_flags.uses_cleartext_traffic is True:
            security_flags.recommendations.append("Disable cleartext traffic and use HTTPS only")
        
        if security_flags.test_only:
            security_flags.recommendations.append("Remove test-only flag from production builds")
        
        if not security_flags.network_security_config:
            security_flags.recommendations.append("Consider implementing network security configuration")
    
    def _create_debuggable_finding(self) -> ManifestSecurityFinding:
        """Create finding for debuggable flag."""
        return create_security_finding(
            title="Debuggable Flag Enabled",
            description="Application has debuggable flag enabled, allowing runtime debugging and code inspection",
            severity=RiskLevel.HIGH,
            confidence=0.95,
            location="AndroidManifest.xml - application",
            evidence="android:debuggable=\"true\"",
            masvs_control="MSTG-CODE-01",
            recommendations=[
                "Disable debuggable flag in production builds",
                "Use build variants to control debug settings",
                "Implement proper build configuration management"
            ],
            references=[
                "https://developer.android.com/guide/topics/manifest/application-element#debug",
                "https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage"
            ],
            cwe_ids=["CWE-489"]
        )
    
    def _create_allow_backup_finding(self, backup_agent: Optional[str]) -> ManifestSecurityFinding:
        """Create finding for allow backup flag with calibrated severity."""
        if backup_agent:
            # **PRECISION FIX**: Custom backup agent present - lower risk
            severity = RiskLevel.LOW  # Changed from MEDIUM
            description = "Application allows backup with custom backup agent - verify data filtering implementation"
            recommendations = [
                "Review custom backup agent implementation for sensitive data handling",
                "Ensure sensitive data is properly excluded from backups",
                "Test backup/restore functionality with security focus"
            ]
        else:
            # **PRECISION FIX**: Default backup behavior - not inherently critical
            severity = RiskLevel.MEDIUM  # Changed from HIGH to reduce false positives
            description = "Application allows backup without custom backup agent - potential sensitive data exposure"
            recommendations = [
                "Review if application handles sensitive data requiring backup protection",
                "Consider implementing custom backup agent if sensitive data is present",
                "Use backup rules to exclude sensitive files (databases, shared preferences)",
                "Disable backup (android:allowBackup=\"false\") for highly sensitive applications"
            ]
        
        return create_security_finding(
            title="Backup Enabled",
            description=description,
            severity=severity,
            confidence=0.8,
            location="AndroidManifest.xml - application",
            evidence="android:allowBackup=\"true\"",
            masvs_control="MSTG-PLATFORM-01",
            recommendations=recommendations,
            references=[
                "https://developer.android.com/guide/topics/manifest/application-element#allowbackup",
                "https://developer.android.com/guide/topics/data/autobackup"
            ],
            cwe_ids=["CWE-200"]
        )
    
    def _create_cleartext_traffic_finding(self) -> ManifestSecurityFinding:
        """Create finding for cleartext traffic setting."""
        return create_security_finding(
            title="Cleartext Traffic Enabled",
            description="Application allows cleartext HTTP traffic, potentially exposing data in transit",
            severity=RiskLevel.HIGH,
            confidence=0.9,
            location="AndroidManifest.xml - application",
            evidence="android:usesCleartextTraffic=\"true\"",
            masvs_control="MSTG-NETWORK-01",
            recommendations=[
                "Disable cleartext traffic and use HTTPS only",
                "Implement network security configuration",
                "Use certificate pinning for additional security"
            ],
            references=[
                "https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic",
                "https://developer.android.com/training/articles/security-config"
            ],
            cwe_ids=["CWE-319"]
        )
    
    def _create_test_only_finding(self) -> ManifestSecurityFinding:
        """Create finding for test only flag."""
        return create_security_finding(
            title="Test-Only Flag Enabled",
            description="Application is marked as test-only, indicating it's not intended for production use",
            severity=RiskLevel.MEDIUM,
            confidence=0.95,
            location="AndroidManifest.xml - application",
            evidence="android:testOnly=\"true\"",
            masvs_control="MSTG-CODE-01",
            recommendations=[
                "Remove test-only flag from production builds",
                "Use proper build configuration for different environments",
                "Implement CI/CD pipeline checks to prevent test builds in production"
            ],
            references=[
                "https://developer.android.com/guide/topics/manifest/application-element#testOnly"
            ],
            cwe_ids=["CWE-489"]
        )
    
    def _create_extract_native_libs_finding(self) -> ManifestSecurityFinding:
        """Create finding for extract native libs setting."""
        return create_security_finding(
            title="Native Libraries Not Extracted",
            description="Application has extractNativeLibs set to false - may impact security analysis",
            severity=RiskLevel.LOW,
            confidence=0.7,
            location="AndroidManifest.xml - application",
            evidence="android:extractNativeLibs=\"false\"",
            masvs_control="MSTG-PLATFORM-01",
            recommendations=[
                "Ensure this setting is intentional and necessary",
                "Review impact on security analysis tools",
                "Consider security implications of compressed native libraries"
            ],
            references=[
                "https://developer.android.com/guide/topics/manifest/application-element#extractNativeLibs"
            ],
            cwe_ids=["CWE-1188"]
        )
    
    def _create_network_security_config_finding(self, config_resource: str) -> ManifestSecurityFinding:
        """Create finding for network security configuration."""
        return create_security_finding(
            title="Network Security Configuration Present",
            description=f"Application uses network security configuration: {config_resource}",
            severity=RiskLevel.INFO,
            confidence=0.9,
            location="AndroidManifest.xml - application",
            evidence=f"android:networkSecurityConfig=\"{config_resource}\"",
            masvs_control="MSTG-NETWORK-01",
            recommendations=[
                "Review network security configuration for proper settings",
                "Ensure certificate pinning is implemented if required",
                "Verify cleartext traffic is properly restricted"
            ],
            references=[
                "https://developer.android.com/training/articles/security-config",
                "https://developer.android.com/guide/topics/manifest/application-element#networksecurityconfig"
            ],
            cwe_ids=["CWE-16"]
        )
    
    def get_security_flags_summary(self, security_flags: SecurityFlags, findings: List[ManifestSecurityFinding]) -> Dict[str, Any]:
        """Generate security flags summary."""
        return {
            'flags_status': {
                'debuggable': security_flags.debuggable,
                'allow_backup': security_flags.allow_backup,
                'uses_cleartext_traffic': security_flags.uses_cleartext_traffic,
                'test_only': security_flags.test_only,
                'extract_native_libs': security_flags.extract_native_libs
            },
            'security_configurations': {
                'network_security_config': security_flags.network_security_config is not None,
                'backup_agent': security_flags.backup_agent is not None
            },
            'security_score': self._calculate_security_score(security_flags),
            'findings_count': len(findings),
            'issues_count': len(security_flags.issues),
            'recommendations_count': len(security_flags.recommendations),
            'highest_severity': self._get_highest_severity(findings)
        }
    
    def _calculate_security_score(self, security_flags: SecurityFlags) -> float:
        """Calculate security score based on flags (0.0 to 1.0, higher is better)."""
        score = 1.0
        
        # Deduct points for security issues
        if security_flags.debuggable:
            score -= 0.3
        
        if security_flags.uses_cleartext_traffic is True:
            score -= 0.25
        
        if security_flags.test_only:
            score -= 0.15
        
        if security_flags.allow_backup and not security_flags.backup_agent:
            score -= 0.2
        
        # Add points for security enhancements
        if security_flags.network_security_config:
            score += 0.1
        
        if security_flags.backup_agent:
            score += 0.05
        
        return max(0.0, min(1.0, score))
    
    def _get_highest_severity(self, findings: List[ManifestSecurityFinding]) -> str:
        """Safely get highest severity from findings list."""
        if not findings:
            return RiskLevel.LOW.name
        
        # **SAFETY FIX**: Safe severity comparison with explicit ranking
        _SEVERITY_RANK = {
            RiskLevel.INFO: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }
        
        try:
            highest_finding = max(findings, key=lambda f: _SEVERITY_RANK.get(f.severity, -1))
            return highest_finding.severity.name
        except (ValueError, AttributeError) as e:
            self.logger.warning(f"Error determining highest severity: {e}")
            return RiskLevel.LOW.name 