"""
Enhanced Manifest Analysis - Permissions Analyzer

This module provides comprehensive permissions analysis functionality for AndroidManifest.xml.
Full implementation with extensive security analysis capabilities.
"""

import logging
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional, Set
import re

from .data_structures import (
    PermissionAnalysis, Permission, PermissionProtectionLevel,
    ManifestSecurityFinding, ManifestAnalysisConfiguration,
    RiskLevel, AnalysisMethod
)

class PermissionsAnalyzer:
    """Comprehensive Android permissions analyzer with security analysis capabilities."""
    
    def __init__(self, config: Optional[ManifestAnalysisConfiguration] = None):
        """Initialize the permissions analyzer with configuration."""
        self.config = config or ManifestAnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
        
        # Initialize permission patterns and data
        self.dangerous_permissions = self._initialize_dangerous_permissions()
        self.signature_permissions = self._initialize_signature_permissions()
        self.custom_permission_patterns = self._initialize_custom_permission_patterns()
        self.permission_groups = self._initialize_permission_groups()
        
        # Analysis statistics
        self.analysis_stats = {
            'total_permissions': 0,
            'dangerous_permissions': 0,
            'custom_permissions': 0,
            'findings': 0
        }
    
    def analyze_permissions(self, manifest_root: ET.Element) -> PermissionAnalysis:
        """Analyze permissions from manifest with comprehensive security analysis."""
        try:
            self.logger.info("Starting comprehensive permissions analysis")
            
            analysis = PermissionAnalysis(
                requested_permissions=[],
                defined_permissions=[],
                dangerous_permissions=[],
                custom_permissions=[]
            )
            
            # Analyze requested permissions (uses-permission)
            requested_perms = self._analyze_requested_permissions(manifest_root)
            analysis.requested_permissions = requested_perms
            
            # Analyze declared permissions (permission)
            declared_perms = self._analyze_declared_permissions(manifest_root)
            analysis.defined_permissions = declared_perms
            
            # Analyze permission groups
            perm_groups = self._analyze_permission_groups(manifest_root)
            analysis.permission_groups = perm_groups
            
            # Identify dangerous permissions
            dangerous_perms = self._identify_dangerous_permissions(requested_perms)
            analysis.dangerous_permissions = dangerous_perms
            
            # Identify custom permissions
            custom_perms = self._identify_custom_permissions(requested_perms + declared_perms)
            analysis.custom_permissions = custom_perms
            
            # Update statistics
            self.analysis_stats['total_permissions'] = len(requested_perms) + len(declared_perms)
            self.analysis_stats['dangerous_permissions'] = len(dangerous_perms)
            self.analysis_stats['custom_permissions'] = len(custom_perms)
            
            self.logger.info(f"Permissions analysis completed: {self.analysis_stats['total_permissions']} permissions analyzed")
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Permissions analysis failed: {e}")
            return PermissionAnalysis()
    
    def get_permission_findings(self, permission_analysis: PermissionAnalysis) -> List[ManifestSecurityFinding]:
        """Generate security findings from permission analysis."""
        findings = []
        
        try:
            # Check for dangerous permissions
            findings.extend(self._check_dangerous_permissions(permission_analysis))
            
            # Check for excessive permissions
            findings.extend(self._check_excessive_permissions(permission_analysis))
            
            # Check for custom permissions security
            findings.extend(self._check_custom_permissions_security(permission_analysis))
            
            # Check for permission combinations
            findings.extend(self._check_permission_combinations(permission_analysis))
            
            # Check for deprecated permissions
            findings.extend(self._check_deprecated_permissions(permission_analysis))
            
            # Check for permission protection levels
            findings.extend(self._check_permission_protection_levels(permission_analysis))
            
            self.analysis_stats['findings'] = len(findings)
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Permission findings generation failed: {e}")
            return []
    
    def get_permission_summary(self, permission_analysis: PermissionAnalysis) -> Dict[str, Any]:
        """Generate comprehensive permission analysis summary."""
        try:
            summary = {
                            'total_permissions': len(permission_analysis.requested_permissions) + len(permission_analysis.defined_permissions),
            'requested_permissions': len(permission_analysis.requested_permissions),
            'declared_permissions': len(permission_analysis.defined_permissions),
                'dangerous_permissions': len(permission_analysis.dangerous_permissions),
                'custom_permissions': len(permission_analysis.custom_permissions),
                'permission_groups': len(permission_analysis.permission_groups),
                'findings': self.analysis_stats['findings'],
                'permission_breakdown': self._get_permission_breakdown(permission_analysis),
                'security_analysis': self._get_security_analysis_summary(permission_analysis)
            }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Permission summary generation failed: {e}")
            return {
                'total_permissions': 0,
                'dangerous_permissions': 0,
                'findings': 0,
                'error': str(e)
            }
    
    def _analyze_requested_permissions(self, manifest_root: ET.Element) -> List[Permission]:
        """Analyze requested permissions (uses-permission elements)."""
        permissions = []
        
        try:
            uses_permissions = manifest_root.findall('.//uses-permission')
            
            for uses_perm in uses_permissions:
                name = uses_perm.get('{http://schemas.android.com/apk/res/android}name')
                if name:
                    permission = Permission(
                        name=name,
                        protection_level=self._get_permission_protection_level(name),
                        is_dangerous=self._is_dangerous_permission(name),
                        is_custom=self._is_custom_permission(name),
                        description=self._get_permission_description(name),
                        permission_group=self._get_permission_group(name)
                    )
                    permissions.append(permission)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing requested permissions: {e}")
        
        return permissions
    
    def _analyze_declared_permissions(self, manifest_root: ET.Element) -> List[Permission]:
        """Analyze declared permissions (permission elements)."""
        permissions = []
        
        try:
            declared_permissions = manifest_root.findall('.//permission')
            
            for decl_perm in declared_permissions:
                name = decl_perm.get('{http://schemas.android.com/apk/res/android}name')
                protection_level = decl_perm.get('{http://schemas.android.com/apk/res/android}protectionLevel')
                label = decl_perm.get('{http://schemas.android.com/apk/res/android}label')
                description = decl_perm.get('{http://schemas.android.com/apk/res/android}description')
                
                if name:
                    permission = Permission(
                        name=name,
                        protection_level=self._parse_protection_level(protection_level),
                        is_dangerous=protection_level == 'dangerous',
                        is_custom=True,  # All declared permissions are custom
                        description=description or label or '',
                        permission_group=self._get_permission_group(name)
                    )
                    permissions.append(permission)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing declared permissions: {e}")
        
        return permissions
    
    def _analyze_permission_groups(self, manifest_root: ET.Element) -> List[str]:
        """Analyze permission groups."""
        groups = []
        
        try:
            permission_groups = manifest_root.findall('.//permission-group')
            
            for group in permission_groups:
                name = group.get('{http://schemas.android.com/apk/res/android}name')
                if name:
                    groups.append(name)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing permission groups: {e}")
        
        return groups
    
    def _identify_dangerous_permissions(self, permissions: List[Permission]) -> List[Permission]:
        """Identify dangerous permissions from the list."""
        dangerous = []
        
        for perm in permissions:
            if perm.is_dangerous or perm.name in self.dangerous_permissions:
                dangerous.append(perm)
        
        return dangerous
    
    def _identify_custom_permissions(self, permissions: List[Permission]) -> List[Permission]:
        """Identify custom permissions from the list."""
        custom = []
        
        for perm in permissions:
            if perm.is_custom or not perm.name.startswith('android.permission.'):
                custom.append(perm)
        
        return custom
    
    def _check_dangerous_permissions(self, analysis: PermissionAnalysis) -> List[ManifestSecurityFinding]:
        """Check for dangerous permissions and generate findings."""
        findings = []
        
        for perm in analysis.dangerous_permissions:
            finding = ManifestSecurityFinding(
                title=f"Dangerous Permission: {perm.name}",
                description=f"App requests dangerous permission: {perm.name}",
                severity=RiskLevel.HIGH,
                confidence=0.9,
                location="AndroidManifest.xml - uses-permission",
                method=AnalysisMethod.STATIC_MANIFEST,
                evidence=f"<uses-permission android:name=\"{perm.name}\" />",
                masvs_control='MSTG-PLATFORM-1',
                recommendations=[f"Ensure {perm.name} is necessary and properly justified"]
            )
            findings.append(finding)
        
        return findings
    
    def _check_excessive_permissions(self, analysis: PermissionAnalysis) -> List[ManifestSecurityFinding]:
        """Check for excessive permissions."""
        findings = []
        
        # Check for too many permissions
        total_perms = len(analysis.requested_permissions)
        if total_perms > 20:
            finding = ManifestSecurityFinding(
                id="excessive_permissions",
                title="Excessive Permissions",
                description=f"App requests {total_perms} permissions, which may be excessive",
                severity=RiskLevel.MEDIUM,
                location="AndroidManifest.xml - uses-permission",
                method=AnalysisMethod.STATIC_MANIFEST,
                masvs_control='MSTG-PLATFORM-1',
                evidence=f"Total permissions: {total_perms}",
                recommendations=["Review and remove unnecessary permissions"],
                confidence=0.7
            )
            findings.append(finding)
        
        # Check for specific excessive permission patterns
        excessive_patterns = [
            ('android.permission.READ_EXTERNAL_STORAGE', 'android.permission.WRITE_EXTERNAL_STORAGE'),
            ('android.permission.READ_CONTACTS', 'android.permission.WRITE_CONTACTS'),
            ('android.permission.READ_CALENDAR', 'android.permission.WRITE_CALENDAR'),
            ('android.permission.READ_CALL_LOG', 'android.permission.WRITE_CALL_LOG')
        ]
        
        requested_names = [p.name for p in analysis.requested_permissions]
        
        for read_perm, write_perm in excessive_patterns:
            if read_perm in requested_names and write_perm in requested_names:
                finding = ManifestSecurityFinding(
                    title=f"Excessive Read/Write Permissions",
                    description=f"App requests both read and write permissions for {read_perm.split('.')[-1]}",
                    severity=RiskLevel.MEDIUM,
                    confidence=0.8,
                    location="AndroidManifest.xml - uses-permission",
                    method=AnalysisMethod.STATIC_MANIFEST,
                    evidence=f"Both {read_perm} and {write_perm} requested",
                    masvs_control='MSTG-PLATFORM-1',
                    recommendations=["Consider if both read and write access are necessary"]
                )
                findings.append(finding)
        
        return findings
    
    def _check_custom_permissions_security(self, analysis: PermissionAnalysis) -> List[ManifestSecurityFinding]:
        """Check custom permissions for security issues."""
        findings = []
        
        for perm in analysis.custom_permissions:
            # Check for weak protection levels
            if perm.protection_level == PermissionProtectionLevel.NORMAL:
                finding = ManifestSecurityFinding(
                    title=f"Weak Custom Permission Protection",
                    description=f"Custom permission {perm.name} has weak protection level",
                    severity=RiskLevel.MEDIUM,
                    confidence=0.8,
                    location="AndroidManifest.xml - permission",
                    method=AnalysisMethod.STATIC_MANIFEST,
                    evidence=f"Custom permission with normal protection level",
                    permission_name=perm.name,
                    masvs_control='MSTG-PLATFORM-1',
                    recommendations=["Use signature or signatureOrSystem protection level for sensitive permissions"]
                )
                findings.append(finding)
            
            # Check for poorly named custom permissions
            if self._is_poorly_named_permission(perm.name):
                finding = ManifestSecurityFinding(
                    title=f"Poorly Named Custom Permission",
                    description=f"Custom permission {perm.name} has poor naming",
                    severity=RiskLevel.LOW,
                    confidence=0.6,
                    location="AndroidManifest.xml - permission",
                    method=AnalysisMethod.STATIC_MANIFEST,
                    evidence=f"Permission name: {perm.name}",
                    permission_name=perm.name,
                    masvs_control='MSTG-PLATFORM-1',
                    recommendations=["Use descriptive, namespace-prefixed permission names"]
                )
                findings.append(finding)
        
        return findings
    
    def _check_permission_combinations(self, analysis: PermissionAnalysis) -> List[ManifestSecurityFinding]:
        """Check for dangerous permission combinations."""
        findings = []
        
        requested_names = [p.name for p in analysis.requested_permissions]
        
        # Check for root/admin combinations
        admin_permissions = [
            'android.permission.DEVICE_ADMIN',
            'android.permission.BIND_DEVICE_ADMIN'
        ]
        
        system_permissions = [
            'android.permission.WRITE_SECURE_SETTINGS',
            'android.permission.WRITE_SETTINGS',
            'android.permission.INSTALL_PACKAGES',
            'android.permission.DELETE_PACKAGES'
        ]
        
        if any(perm in requested_names for perm in admin_permissions):
            if any(perm in requested_names for perm in system_permissions):
                finding = ManifestSecurityFinding(
                    id="dangerous_admin_combination",
                    title="Dangerous Admin Permission Combination",
                    description="App combines device admin with system modification permissions",
                    severity=RiskLevel.CRITICAL,
                    location="AndroidManifest.xml - uses-permission",
                    method=AnalysisMethod.STATIC_MANIFEST,
                    masvs_control='MSTG-PLATFORM-1',
                    evidence="Device admin + system permissions",
                    recommendations=["Carefully review the necessity of admin permissions"],
                    confidence=0.9
                )
                findings.append(finding)
        
        # Check for location + network combination
        location_perms = [
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.ACCESS_BACKGROUND_LOCATION'
        ]
        
        network_perms = [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE'
        ]
        
        if (any(perm in requested_names for perm in location_perms) and 
            any(perm in requested_names for perm in network_perms)):
            finding = ManifestSecurityFinding(
                id="location_network_combination",
                title="Location and Network Permission Combination",
                description="App can access location and send data over network",
                severity=RiskLevel.HIGH,
                location="AndroidManifest.xml - uses-permission",
                method=AnalysisMethod.STATIC_MANIFEST,
                masvs_control='MSTG-PLATFORM-1',
                evidence="Location + network permissions",
                recommendations=["Ensure location data is properly protected during network transmission"],
                confidence=0.8
            )
            findings.append(finding)
        
        return findings
    
    def _check_deprecated_permissions(self, analysis: PermissionAnalysis) -> List[ManifestSecurityFinding]:
        """Check for deprecated permissions."""
        findings = []
        
        deprecated_permissions = {
            'android.permission.WRITE_EXTERNAL_STORAGE': 'Use scoped storage instead',
            'android.permission.READ_EXTERNAL_STORAGE': 'Use scoped storage instead',
            'android.permission.WRITE_SETTINGS': 'Use Settings.ACTION_MANAGE_WRITE_SETTINGS intent',
            'android.permission.PERSISTENT_ACTIVITY': 'Deprecated in API level 9',
            'android.permission.RESTART_PACKAGES': 'Deprecated in API level 8',
            'android.permission.GET_TASKS': 'Deprecated in API level 21'
        }
        
        for perm in analysis.requested_permissions:
            if perm.name in deprecated_permissions:
                finding = ManifestSecurityFinding(
                    title=f"Deprecated Permission: {perm.name}",
                    description=f"App uses deprecated permission: {perm.name}",
                    severity=RiskLevel.MEDIUM,
                    confidence=0.95,
                    location="AndroidManifest.xml - uses-permission",
                    method=AnalysisMethod.STATIC_MANIFEST,
                    evidence=f"Deprecated permission: {perm.name}",
                    permission_name=perm.name,
                    masvs_control='MSTG-PLATFORM-1',
                    recommendations=[deprecated_permissions[perm.name]]
                )
                findings.append(finding)
        
        return findings
    
    def _check_permission_protection_levels(self, analysis: PermissionAnalysis) -> List[ManifestSecurityFinding]:
        """Check permission protection levels for security issues."""
        findings = []
        
        for perm in analysis.defined_permissions:
            # Check for signature permissions with poor naming
            if (perm.protection_level == PermissionProtectionLevel.SIGNATURE and
                not perm.name.startswith(('com.', 'org.', 'net.'))):
                finding = ManifestSecurityFinding(
                    title=f"Signature Permission Naming Issue",
                    description=f"Signature permission {perm.name} should use proper namespace",
                    severity=RiskLevel.LOW,
                    confidence=0.7,
                    location="AndroidManifest.xml - permission",
                    method=AnalysisMethod.STATIC_MANIFEST,
                    evidence=f"Signature permission: {perm.name}",
                    permission_name=perm.name,
                    masvs_control='MSTG-PLATFORM-1',
                    recommendations=["Use proper namespace for signature permissions"]
                )
                findings.append(finding)
        
        return findings
    
    def _get_permission_protection_level(self, permission_name: str) -> PermissionProtectionLevel:
        """Get the protection level for a permission."""
        if permission_name in self.dangerous_permissions:
            return PermissionProtectionLevel.DANGEROUS
        elif permission_name in self.signature_permissions:
            return PermissionProtectionLevel.SIGNATURE
        elif permission_name.startswith('android.permission.'):
            return PermissionProtectionLevel.NORMAL
        else:
            return PermissionProtectionLevel.NORMAL
    
    def _parse_protection_level(self, protection_level: str) -> PermissionProtectionLevel:
        """Parse protection level string to enum."""
        if not protection_level:
            return PermissionProtectionLevel.NORMAL
        
        level_map = {
            'normal': PermissionProtectionLevel.NORMAL,
            'dangerous': PermissionProtectionLevel.DANGEROUS,
            'signature': PermissionProtectionLevel.SIGNATURE,
            'signatureOrSystem': PermissionProtectionLevel.SIGNATURE_OR_SYSTEM
        }
        
        return level_map.get(protection_level.lower(), PermissionProtectionLevel.NORMAL)
    
    def _is_dangerous_permission(self, permission_name: str) -> bool:
        """Check if a permission is dangerous."""
        return permission_name in self.dangerous_permissions
    
    def _is_custom_permission(self, permission_name: str) -> bool:
        """Check if a permission is custom (not Android system permission)."""
        return not permission_name.startswith('android.permission.')
    
    def _is_poorly_named_permission(self, permission_name: str) -> bool:
        """Check if a custom permission has poor naming."""
        # Check for various naming issues
        if len(permission_name) < 10:
            return True
        
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_.]*$', permission_name):
            return True
        
        if permission_name.count('.') < 2:
            return True
        
        poor_patterns = [
            r'^[A-Z_]+$',  # All caps
            r'permission$',  # Ends with 'permission'
            r'test',  # Contains 'test'
            r'debug',  # Contains 'debug'
            r'temp'  # Contains 'temp'
        ]
        
        return any(re.search(pattern, permission_name, re.IGNORECASE) for pattern in poor_patterns)
    
    def _get_permission_description(self, permission_name: str) -> str:
        """Get description for a permission."""
        descriptions = {
            'android.permission.CAMERA': 'Access device camera',
            'android.permission.RECORD_AUDIO': 'Record audio',
            'android.permission.ACCESS_FINE_LOCATION': 'Access precise location',
            'android.permission.ACCESS_COARSE_LOCATION': 'Access approximate location',
            'android.permission.READ_CONTACTS': 'Read contacts',
            'android.permission.WRITE_CONTACTS': 'Write contacts',
            'android.permission.READ_CALENDAR': 'Read calendar',
            'android.permission.WRITE_CALENDAR': 'Write calendar',
            'android.permission.READ_SMS': 'Read SMS messages',
            'android.permission.SEND_SMS': 'Send SMS messages',
            'android.permission.READ_PHONE_STATE': 'Read phone state',
            'android.permission.CALL_PHONE': 'Make phone calls',
            'android.permission.READ_CALL_LOG': 'Read call log',
            'android.permission.WRITE_CALL_LOG': 'Write call log',
            'android.permission.READ_EXTERNAL_STORAGE': 'Read external storage',
            'android.permission.WRITE_EXTERNAL_STORAGE': 'Write external storage',
            'android.permission.INTERNET': 'Access internet',
            'android.permission.ACCESS_NETWORK_STATE': 'Access network state'
        }
        
        return descriptions.get(permission_name, f"Permission: {permission_name}")
    
    def _get_permission_group(self, permission_name: str) -> str:
        """Get the permission group for a permission."""
        for group, permissions in self.permission_groups.items():
            if permission_name in permissions:
                return group
        return 'OTHER'
    
    def _get_permission_breakdown(self, analysis: PermissionAnalysis) -> Dict[str, int]:
        """Get permission breakdown by category."""
        breakdown = {
            'NORMAL': 0,
            'DANGEROUS': 0,
            'SIGNATURE': 0,
            'CUSTOM': 0
        }
        
        for perm in analysis.requested_permissions + analysis.defined_permissions:
            if perm.is_custom:
                breakdown['CUSTOM'] += 1
            elif perm.protection_level == PermissionProtectionLevel.DANGEROUS:
                breakdown['DANGEROUS'] += 1
            elif perm.protection_level == PermissionProtectionLevel.SIGNATURE:
                breakdown['SIGNATURE'] += 1
            else:
                breakdown['NORMAL'] += 1
        
        return breakdown
    
    def _get_security_analysis_summary(self, analysis: PermissionAnalysis) -> Dict[str, Any]:
        """Get security analysis summary."""
        dangerous_count = len(analysis.dangerous_permissions)
        total_count = len(analysis.requested_permissions)
        
        risk_level = 'LOW'
        if dangerous_count > 10:
            risk_level = 'CRITICAL'
        elif dangerous_count > 5:
            risk_level = 'HIGH'
        elif dangerous_count > 2:
            risk_level = 'MEDIUM'
        
        return {
            'risk_level': risk_level,
            'dangerous_permission_ratio': dangerous_count / max(total_count, 1),
            'has_admin_permissions': any(
                'DEVICE_ADMIN' in p.name or 'BIND_DEVICE_ADMIN' in p.name 
                for p in analysis.requested_permissions
            ),
            'has_location_permissions': any(
                'LOCATION' in p.name for p in analysis.requested_permissions
            ),
            'has_network_permissions': any(
                p.name in ['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE']
                for p in analysis.requested_permissions
            ),
            'custom_permissions_count': len(analysis.custom_permissions)
        }
    
    def _initialize_dangerous_permissions(self) -> Set[str]:
        """Initialize the set of dangerous permissions."""
        return {
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.ACCESS_BACKGROUND_LOCATION',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.GET_ACCOUNTS',
            'android.permission.READ_CALENDAR',
            'android.permission.WRITE_CALENDAR',
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_PHONE_STATE',
            'android.permission.READ_PHONE_NUMBERS',
            'android.permission.CALL_PHONE',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG',
            'android.permission.ADD_VOICEMAIL',
            'android.permission.USE_SIP',
            'android.permission.PROCESS_OUTGOING_CALLS',
            'android.permission.BODY_SENSORS',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.ACTIVITY_RECOGNITION'
        }
    
    def _initialize_signature_permissions(self) -> Set[str]:
        """Initialize the set of signature permissions."""
        return {
            'android.permission.BIND_DEVICE_ADMIN',
            'android.permission.BIND_INPUT_METHOD',
            'android.permission.BIND_ACCESSIBILITY_SERVICE',
            'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE',
            'android.permission.BIND_WALLPAPER',
            'android.permission.BIND_VPN_SERVICE',
            'android.permission.WRITE_SECURE_SETTINGS',
            'android.permission.INSTALL_PACKAGES',
            'android.permission.DELETE_PACKAGES',
            'android.permission.CLEAR_APP_CACHE',
            'android.permission.CLEAR_APP_USER_DATA',
            'android.permission.FORCE_STOP_PACKAGES',
            'android.permission.GET_PACKAGE_SIZE'
        }
    
    def _initialize_custom_permission_patterns(self) -> List[str]:
        """Initialize patterns for custom permissions."""
        return [
            r'^com\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\.permission\.[A-Z_]+$',
            r'^[a-zA-Z][a-zA-Z0-9_]*\.[a-zA-Z][a-zA-Z0-9_]*\.permission\.[A-Z_]+$'
        ]
    
    def _initialize_permission_groups(self) -> Dict[str, Set[str]]:
        """Initialize permission groups."""
        return {
            'CAMERA': {
                'android.permission.CAMERA'
            },
            'MICROPHONE': {
                'android.permission.RECORD_AUDIO'
            },
            'LOCATION': {
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.ACCESS_COARSE_LOCATION',
                'android.permission.ACCESS_BACKGROUND_LOCATION'
            },
            'CONTACTS': {
                'android.permission.READ_CONTACTS',
                'android.permission.WRITE_CONTACTS',
                'android.permission.GET_ACCOUNTS'
            },
            'CALENDAR': {
                'android.permission.READ_CALENDAR',
                'android.permission.WRITE_CALENDAR'
            },
            'SMS': {
                'android.permission.READ_SMS',
                'android.permission.SEND_SMS',
                'android.permission.RECEIVE_SMS'
            },
            'PHONE': {
                'android.permission.READ_PHONE_STATE',
                'android.permission.READ_PHONE_NUMBERS',
                'android.permission.CALL_PHONE',
                'android.permission.READ_CALL_LOG',
                'android.permission.WRITE_CALL_LOG',
                'android.permission.ADD_VOICEMAIL',
                'android.permission.USE_SIP',
                'android.permission.PROCESS_OUTGOING_CALLS'
            },
            'SENSORS': {
                'android.permission.BODY_SENSORS'
            },
            'STORAGE': {
                'android.permission.READ_EXTERNAL_STORAGE',
                'android.permission.WRITE_EXTERNAL_STORAGE'
            },
            'ACTIVITY': {
                'android.permission.ACTIVITY_RECOGNITION'
            },
            'NETWORK': {
                'android.permission.INTERNET',
                'android.permission.ACCESS_NETWORK_STATE',
                'android.permission.ACCESS_WIFI_STATE',
                'android.permission.CHANGE_WIFI_STATE'
            }
        } 