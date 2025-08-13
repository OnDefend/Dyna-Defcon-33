"""
Enhanced Manifest Analysis - Package Analyzer Component

This module provides comprehensive package information analysis from AndroidManifest.xml
including version information, SDK levels, and package configuration.
"""

import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any

from .data_structures import (
    PackageInfo, ManifestSecurityFinding, RiskLevel, AnalysisMethod,
    ManifestAnalysisConfiguration, create_security_finding
)

class PackageAnalyzer:
    """Analyzer for package information from AndroidManifest.xml."""
    
    def __init__(self, config: Optional[ManifestAnalysisConfiguration] = None):
        """Initialize the package analyzer."""
        self.config = config or ManifestAnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
        self.namespace = '{http://schemas.android.com/apk/res/android}'
    
    def analyze_package_info(self, manifest_root: ET.Element) -> PackageInfo:
        """Analyze package information from manifest root element."""
        try:
            # Extract basic package information
            package_name = manifest_root.get('package', '')
            
            # Get version information
            version_name = manifest_root.get(f'{self.namespace}versionName')
            version_code = manifest_root.get(f'{self.namespace}versionCode')
            
            # Get SDK information
            uses_sdk = manifest_root.find('uses-sdk')
            target_sdk = None
            min_sdk = None
            
            if uses_sdk is not None:
                target_sdk = uses_sdk.get(f'{self.namespace}targetSdkVersion')
                min_sdk = uses_sdk.get(f'{self.namespace}minSdkVersion')
            
            # Get other package attributes
            shared_user_id = manifest_root.get(f'{self.namespace}sharedUserId')
            install_location = manifest_root.get(f'{self.namespace}installLocation')
            
            # Create package info object
            package_info = PackageInfo(
                package_name=package_name,
                version_name=version_name,
                version_code=version_code,
                target_sdk=target_sdk,
                min_sdk=min_sdk,
                shared_user_id=shared_user_id,
                install_location=install_location
            )
            
            self.logger.info(f"Extracted package info for {package_name}")
            return package_info
            
        except Exception as e:
            self.logger.error(f"Failed to analyze package info: {e}")
            return PackageInfo(package_name="unknown")
    
    def analyze_package_security(self, package_info: PackageInfo) -> List[ManifestSecurityFinding]:
        """Analyze package information for security issues."""
        findings = []
        
        try:
            # Check target SDK version
            if package_info.target_sdk:
                target_sdk_int = self._parse_sdk_version(package_info.target_sdk)
                if target_sdk_int is not None:
                    findings.extend(self._analyze_target_sdk_security(target_sdk_int))
            
            # Check minimum SDK version
            if package_info.min_sdk:
                min_sdk_int = self._parse_sdk_version(package_info.min_sdk)
                if min_sdk_int is not None:
                    findings.extend(self._analyze_min_sdk_security(min_sdk_int))
            
            # Check shared user ID
            if package_info.shared_user_id:
                findings.extend(self._analyze_shared_user_id_security(package_info.shared_user_id))
            
            # Check install location
            if package_info.install_location:
                findings.extend(self._analyze_install_location_security(package_info.install_location))
            
            # Check version information
            findings.extend(self._analyze_version_security(package_info))
            
        except Exception as e:
            self.logger.error(f"Failed to analyze package security: {e}")
        
        return findings
    
    def _parse_sdk_version(self, sdk_version: str) -> Optional[int]:
        """Parse SDK version string to integer."""
        try:
            return int(sdk_version)
        except (ValueError, TypeError):
            return None
    
    def _analyze_target_sdk_security(self, target_sdk: int) -> List[ManifestSecurityFinding]:
        """Analyze target SDK version for security implications."""
        findings = []
        
        # Current recommended minimum target SDK
        RECOMMENDED_MIN_TARGET_SDK = 30
        CURRENT_TARGET_SDK = 34
        
        if target_sdk < 23:
            findings.append(create_security_finding(
                title="Very Low Target SDK Version",
                description=f"Target SDK version {target_sdk} is extremely outdated and lacks modern security features",
                severity=RiskLevel.CRITICAL,
                confidence=0.95,
                location="AndroidManifest.xml - uses-sdk",
                evidence=f"targetSdkVersion=\"{target_sdk}\"",
                masvs_control="MSTG-PLATFORM-01",
                recommendations=[
                    "Update target SDK to latest version (34+)",
                    "Test application thoroughly after SDK update",
                    "Review runtime permissions implementation"
                ],
                references=[
                    "https://developer.android.com/guide/topics/manifest/uses-sdk-element",
                    "https://developer.android.com/about/versions"
                ],
                cwe_ids=["CWE-1104"]
            ))
        
        elif target_sdk < 28:
            findings.append(create_security_finding(
                title="Low Target SDK Version",
                description=f"Target SDK version {target_sdk} is outdated and may lack important security enhancements",
                severity=RiskLevel.HIGH,
                confidence=0.9,
                location="AndroidManifest.xml - uses-sdk",
                evidence=f"targetSdkVersion=\"{target_sdk}\"",
                masvs_control="MSTG-PLATFORM-01",
                recommendations=[
                    "Update target SDK to version 30 or higher",
                    "Review application behavior changes",
                    "Implement scoped storage if targeting API 30+"
                ],
                references=[
                    "https://developer.android.com/guide/topics/manifest/uses-sdk-element"
                ],
                cwe_ids=["CWE-1104"]
            ))
        
        elif target_sdk < RECOMMENDED_MIN_TARGET_SDK:
            findings.append(create_security_finding(
                title="Below Recommended Target SDK",
                description=f"Target SDK version {target_sdk} is below the recommended minimum of {RECOMMENDED_MIN_TARGET_SDK}",
                severity=RiskLevel.MEDIUM,
                confidence=0.8,
                location="AndroidManifest.xml - uses-sdk",
                evidence=f"targetSdkVersion=\"{target_sdk}\"",
                masvs_control="MSTG-PLATFORM-01",
                recommendations=[
                    f"Consider updating to target SDK {CURRENT_TARGET_SDK}",
                    "Review new security features and requirements",
                    "Test application compatibility"
                ],
                references=[
                    "https://developer.android.com/guide/topics/manifest/uses-sdk-element"
                ],
                cwe_ids=["CWE-1104"]
            ))
        
        return findings
    
    def _analyze_min_sdk_security(self, min_sdk: int) -> List[ManifestSecurityFinding]:
        """Analyze minimum SDK version for security implications."""
        findings = []
        
        # Very old SDK versions with security concerns
        if min_sdk < 21:
            findings.append(create_security_finding(
                title="Very Low Minimum SDK Version",
                description=f"Minimum SDK version {min_sdk} supports very old Android versions with known security vulnerabilities",
                severity=RiskLevel.HIGH,
                confidence=0.85,
                location="AndroidManifest.xml - uses-sdk",
                evidence=f"minSdkVersion=\"{min_sdk}\"",
                masvs_control="MSTG-PLATFORM-01",
                recommendations=[
                    "Consider raising minimum SDK to 21 or higher",
                    "Implement additional security measures for older devices",
                    "Document security limitations for older versions"
                ],
                references=[
                    "https://developer.android.com/guide/topics/manifest/uses-sdk-element"
                ],
                cwe_ids=["CWE-1104"]
            ))
        
        elif min_sdk < 23:
            findings.append(create_security_finding(
                title="Low Minimum SDK Version",
                description=f"Minimum SDK version {min_sdk} supports Android versions without runtime permissions",
                severity=RiskLevel.MEDIUM,
                confidence=0.75,
                location="AndroidManifest.xml - uses-sdk",
                evidence=f"minSdkVersion=\"{min_sdk}\"",
                masvs_control="MSTG-PLATFORM-01",
                recommendations=[
                    "Consider raising minimum SDK to 23 for runtime permissions",
                    "Implement proper permission handling for older versions",
                    "Test security features on older Android versions"
                ],
                references=[
                    "https://developer.android.com/guide/topics/manifest/uses-sdk-element"
                ],
                cwe_ids=["CWE-1104"]
            ))
        
        return findings
    
    def _analyze_shared_user_id_security(self, shared_user_id: str) -> List[ManifestSecurityFinding]:
        """Analyze shared user ID for security implications."""
        findings = []
        
        # Shared user ID is generally a security concern
        findings.append(create_security_finding(
            title="Shared User ID Detected",
            description=f"Application uses shared user ID '{shared_user_id}' which can lead to security vulnerabilities",
            severity=RiskLevel.HIGH,
            confidence=0.9,
            location="AndroidManifest.xml - manifest",
            evidence=f"android:sharedUserId=\"{shared_user_id}\"",
            masvs_control="MSTG-PLATFORM-02",
            recommendations=[
                "Remove shared user ID if not absolutely necessary",
                "Ensure all apps sharing the user ID are signed with the same certificate",
                "Review data access permissions between shared apps",
                "Consider alternative architectures to avoid shared user ID"
            ],
            references=[
                "https://developer.android.com/guide/topics/manifest/manifest-element#uid",
                "https://developer.android.com/guide/components/processes-and-threads"
            ],
            cwe_ids=["CWE-269"]
        ))
        
        return findings
    
    def _analyze_install_location_security(self, install_location: str) -> List[ManifestSecurityFinding]:
        """Analyze install location for security implications."""
        findings = []
        
        if install_location == "preferExternal" or install_location == "auto":
            findings.append(create_security_finding(
                title="External Storage Installation Allowed",
                description=f"Application allows installation on external storage ({install_location})",
                severity=RiskLevel.MEDIUM,
                confidence=0.8,
                location="AndroidManifest.xml - manifest",
                evidence=f"android:installLocation=\"{install_location}\"",
                masvs_control="MSTG-PLATFORM-01",
                recommendations=[
                    "Consider setting installLocation to 'internalOnly' for sensitive apps",
                    "Review security implications of external storage installation",
                    "Implement additional security measures if external installation is required"
                ],
                references=[
                    "https://developer.android.com/guide/topics/manifest/manifest-element#install"
                ],
                cwe_ids=["CWE-922"]
            ))
        
        return findings
    
    def _analyze_version_security(self, package_info: PackageInfo) -> List[ManifestSecurityFinding]:
        """Analyze version information for security implications."""
        findings = []
        
        # Check for debug version indicators
        if package_info.version_name:
            version_name_lower = package_info.version_name.lower()
            debug_indicators = ['debug', 'dev', 'test', 'beta', 'alpha']
            
            for indicator in debug_indicators:
                if indicator in version_name_lower:
                    findings.append(create_security_finding(
                        title="Debug Version Indicator",
                        description=f"Version name contains debug indicator '{indicator}' which may indicate a development build",
                        severity=RiskLevel.MEDIUM,
                        confidence=0.7,
                        location="AndroidManifest.xml - manifest",
                        evidence=f"android:versionName=\"{package_info.version_name}\"",
                        masvs_control="MSTG-CODE-01",
                        recommendations=[
                            "Ensure production builds use proper version names",
                            "Remove debug indicators from production releases",
                            "Review build configuration for production deployment"
                        ],
                        references=[
                            "https://developer.android.com/guide/topics/manifest/manifest-element#vname"
                        ],
                        cwe_ids=["CWE-489"]
                    ))
                    break
        
        return findings
    
    def get_package_security_summary(self, package_info: PackageInfo, findings: List[ManifestSecurityFinding]) -> Dict[str, Any]:
        """Generate package security summary."""
        return {
            'package_name': package_info.package_name,
            'version_info': {
                'version_name': package_info.version_name,
                'version_code': package_info.version_code
            },
            'sdk_info': {
                'target_sdk': package_info.target_sdk,
                'min_sdk': package_info.min_sdk,
                'target_sdk_current': self._is_target_sdk_current(package_info.target_sdk),
                'min_sdk_secure': self._is_min_sdk_secure(package_info.min_sdk)
            },
            'security_concerns': {
                'shared_user_id': package_info.shared_user_id is not None,
                'external_install_allowed': package_info.install_location in ['preferExternal', 'auto']
            },
            'findings_count': len(findings),
            'highest_severity': max([f.severity for f in findings], default=RiskLevel.LOW).name
        }
    
    def _is_target_sdk_current(self, target_sdk: Optional[str]) -> bool:
        """Check if target SDK is current."""
        if not target_sdk:
            return False
        
        try:
            target_sdk_int = int(target_sdk)
            return target_sdk_int >= 30
        except (ValueError, TypeError):
            return False
    
    def _is_min_sdk_secure(self, min_sdk: Optional[str]) -> bool:
        """Check if minimum SDK is secure."""
        if not min_sdk:
            return False
        
        try:
            min_sdk_int = int(min_sdk)
            return min_sdk_int >= 23
        except (ValueError, TypeError):
            return False 