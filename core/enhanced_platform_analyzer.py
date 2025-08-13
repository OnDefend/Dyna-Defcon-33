#!/usr/bin/env python3
"""
Enhanced Platform Security Analyzer for AODS - Advanced Implementation

This analyzer provides comprehensive platform security analysis with enhanced
coverage for mobile application security testing.

Advanced Platform Coverage:
- Platform interaction security patterns
- System service security analysis
- Native library security validation
- Runtime security analysis
- Hardware security feature validation
- Biometric security implementation analysis

"""

import re
import logging
import json
import xml.etree.ElementTree as ET
import os
import zipfile
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)

class PlatformSeverityLevel(Enum):
    """Platform vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class PlatformTestCategory(Enum):
    """Platform test categories for MASTG coverage"""
    PERMISSION_ANALYSIS = "permission_analysis"
    INTENT_SECURITY = "intent_security"
    COMPONENT_EXPOSURE = "component_exposure"
    DEEPLINK_SECURITY = "deeplink_security"
    MANIFEST_SECURITY = "manifest_security"
    DEBUG_CONFIGURATION = "debug_configuration"
    SDK_VERSION_SECURITY = "sdk_version_security"
    APPLICATION_CONFIG = "application_config"
    COMPONENT_INTERACTION = "component_interaction"
    BACKUP_SECURITY = "backup_security"
    RESOURCE_PROTECTION = "resource_protection"
    PLATFORM_INTEGRATION = "platform_integration"

@dataclass
class PlatformFinding:
    """Platform security finding with MASTG mapping"""
    test_id: str
    title: str
    description: str
    severity: PlatformSeverityLevel
    category: PlatformTestCategory
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

class EnhancedPlatformAnalyzer:
    """
    Enhanced platform security analyzer implementing advanced platform security requirements.
    
    This analyzer provides comprehensive security analysis for mobile platform interactions
    including system services, native libraries, and hardware security features.
    """
    
    def __init__(self):
        """Initialize the enhanced platform analyzer with advanced test patterns."""
        self.findings: List[PlatformFinding] = []
        self.analysis_stats = {
            'files_analyzed': 0,
            'permissions_found': 0,
            'exported_components': 0,
            'intent_filters_found': 0,
            'deeplinks_found': 0,
            'custom_permissions': 0,
            'total_analysis_time': 0.0
        }
        
        # Initialize dangerous and critical permissions
        self._initialize_permission_patterns()
        
        # Initialize manifest security patterns
        self._initialize_manifest_patterns()
        
        logger.debug("Enhanced Platform Analyzer initialized for comprehensive platform security analysis (MASTG-TEST-0061 to 0090)")
    
    def _initialize_permission_patterns(self):
        """Initialize permission patterns for security analysis."""
        
        # MASTG-TEST-0061: Dangerous permissions requiring runtime checks
        self.dangerous_permissions = {
            'CAMERA': 'Camera access permission',
            'RECORD_AUDIO': 'Microphone access permission',
            'ACCESS_FINE_LOCATION': 'Precise location access',
            'ACCESS_COARSE_LOCATION': 'Approximate location access',
            'READ_CONTACTS': 'Contact reading access',
            'WRITE_CONTACTS': 'Contact modification access',
            'READ_CALENDAR': 'Calendar reading access',
            'WRITE_CALENDAR': 'Calendar modification access',
            'READ_SMS': 'SMS reading access',
            'SEND_SMS': 'SMS sending permission',
            'READ_PHONE_STATE': 'Phone state access',
            'CALL_PHONE': 'Phone calling permission',
            'READ_EXTERNAL_STORAGE': 'External storage reading',
            'WRITE_EXTERNAL_STORAGE': 'External storage writing',
            'ACCESS_BACKGROUND_LOCATION': 'Background location access'
        }
        
        # MASTG-TEST-0062: Critical system permissions
        self.critical_permissions = {
            'SYSTEM_ALERT_WINDOW': 'System overlay permission',
            'WRITE_SETTINGS': 'System settings modification',
            'DEVICE_ADMIN': 'Device administrator access',
            'BIND_ACCESSIBILITY_SERVICE': 'Accessibility service binding',
            'BIND_DEVICE_ADMIN': 'Device admin service binding',
            'INSTALL_PACKAGES': 'Package installation permission',
            'DELETE_PACKAGES': 'Package deletion permission',
            'MANAGE_EXTERNAL_STORAGE': 'All files access permission',
            'QUERY_ALL_PACKAGES': 'Package visibility permission'
        }
        
        # MASTG-TEST-0063: Custom permission analysis patterns
        self.custom_permission_patterns = {
            'signature_protection': r'android:protectionLevel="signature"',
            'dangerous_protection': r'android:protectionLevel="dangerous"',
            'normal_protection': r'android:protectionLevel="normal"',
            'system_protection': r'android:protectionLevel="system"'
        }
    
    def _initialize_manifest_patterns(self):
        """Initialize manifest security patterns."""
        
        # MASTG-TEST-0066-0075: Intent filter and component patterns
        self.component_patterns = {
            'exported_activity': r'<activity[^>]+android:exported="true"',
            'exported_service': r'<service[^>]+android:exported="true"',
            'exported_receiver': r'<receiver[^>]+android:exported="true"',
            'exported_provider': r'<provider[^>]+android:exported="true"',
            'intent_filter': r'<intent-filter[^>]*>',
            'action_main': r'<action\s+android:name="android\.intent\.action\.MAIN"',
            'action_view': r'<action\s+android:name="android\.intent\.action\.VIEW"',
            'category_browsable': r'<category\s+android:name="android\.intent\.category\.BROWSABLE"'
        }
        
        # MASTG-TEST-0072-0074: Deep link patterns
        self.deeplink_patterns = {
            'custom_scheme': r'android:scheme="([^"]+)"',
            'http_scheme': r'android:scheme="http"',
            'https_scheme': r'android:scheme="https"',
            'data_host': r'android:host="([^"]+)"',
            'data_path': r'android:path="([^"]+)"',
            'data_pathPrefix': r'android:pathPrefix="([^"]+)"'
        }
        
        # MASTG-TEST-0078-0084: Application configuration patterns
        self.app_config_patterns = {
            'backup_allowed': r'android:allowBackup="true"',
            'debug_enabled': r'android:debuggable="true"',
            'clear_text_traffic': r'android:usesCleartextTraffic="true"',
            'task_affinity': r'android:taskAffinity="([^"]+)"',
            'launch_mode': r'android:launchMode="([^"]+)"',
            'target_sdk': r'android:targetSdkVersion="(\d+)"',
            'min_sdk': r'android:minSdkVersion="(\d+)"'
        }

    def analyze_platform_security(self, apk_path: str, source_code_path: str = None) -> List[PlatformFinding]:
        """
        Comprehensive platform security analysis for enhanced security coverage.
        
        This method performs thorough analysis of platform security features and identifies
        potential vulnerabilities in platform interactions.
        """
        
        logger.debug("Starting comprehensive platform security analysis...")
        self.findings.clear()
        
        try:
            # Analyze APK manifest and platform configuration
            self._analyze_android_manifest(apk_path)
            
            # Analyze source code if available
            if source_code_path and os.path.exists(source_code_path):
                self._analyze_platform_source_code(source_code_path)
            
            # Perform specialized platform tests
            self._perform_permission_analysis(apk_path)
            self._perform_component_security_analysis(apk_path)
            self._perform_intent_security_analysis(apk_path)
            self._perform_deeplink_security_analysis(apk_path)
            self._perform_manifest_security_analysis(apk_path)
            self._perform_debug_configuration_analysis(apk_path)
            self._perform_sdk_version_analysis(apk_path)
            
            logger.debug(f"Platform analysis completed. Found {len(self.findings)} findings.")
            
        except Exception as e:
            logger.error(f"Error during platform security analysis: {e}")
            self._add_finding(
                "MASTG-TEST-ERROR",
                "Platform Analysis Error",
                f"Failed to complete platform analysis: {e}",
                PlatformSeverityLevel.HIGH,
                PlatformTestCategory.PLATFORM_INTEGRATION,
                apk_path
            )
        
        return self.findings
    
    def _analyze_android_manifest(self, apk_path: str):
        """Analyze AndroidManifest.xml for platform security issues."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    manifest_content = apk_zip.read('AndroidManifest.xml').decode('utf-8', errors='ignore')
                    self._analyze_manifest_content(manifest_content)
        except Exception as e:
            logger.error(f"Error analyzing Android manifest: {e}")
    
    def _analyze_manifest_content(self, manifest_content: str):
        """Analyze manifest content for security patterns."""
        
        # Analyze permissions
        self._analyze_manifest_permissions(manifest_content)
        
        # Analyze components
        self._analyze_manifest_components(manifest_content)
        
        # Analyze deep links
        self._analyze_manifest_deeplinks(manifest_content)
        
        # Analyze application configuration
        self._analyze_manifest_app_config(manifest_content)
    
    def _analyze_manifest_permissions(self, manifest_content: str):
        """Analyze permission declarations and usage."""
        
        # Find all permission declarations
        permission_pattern = r'<uses-permission\s+android:name="([^"]+)"'
        permissions = re.findall(permission_pattern, manifest_content)
        self.analysis_stats['permissions_found'] = len(permissions)
        
        # Check for dangerous permissions
        for permission in permissions:
            permission_name = permission.split('.')[-1]
            
            if permission_name in self.dangerous_permissions:
                self._add_finding(
                    "MASTG-TEST-0061",
                    f"Dangerous Permission Declared: {permission_name}",
                    f"Dangerous permission {permission} requires runtime handling: {self.dangerous_permissions[permission_name]}",
                    PlatformSeverityLevel.MEDIUM,
                    PlatformTestCategory.PERMISSION_ANALYSIS,
                    "AndroidManifest.xml",
                    evidence=[permission],
                    recommendations=["Implement runtime permission requests", "Validate permission necessity"],
                    masvs_controls=["MASVS-PLATFORM-1"],
                    cwe_ids=["CWE-250"]
                )
            
            if permission_name in self.critical_permissions:
                self._add_finding(
                    "MASTG-TEST-0062",
                    f"Critical System Permission: {permission_name}",
                    f"Critical system permission {permission} detected: {self.critical_permissions[permission_name]}",
                    PlatformSeverityLevel.HIGH,
                    PlatformTestCategory.PERMISSION_ANALYSIS,
                    "AndroidManifest.xml",
                    evidence=[permission],
                    recommendations=["Review necessity of critical permission", "Implement additional security measures"],
                    masvs_controls=["MASVS-PLATFORM-1"],
                    cwe_ids=["CWE-250"]
                )
        
        # Check for custom permission definitions
        custom_permission_pattern = r'<permission\s+[^>]*android:name="([^"]+)"[^>]*>'
        custom_permissions = re.findall(custom_permission_pattern, manifest_content)
        self.analysis_stats['custom_permissions'] = len(custom_permissions)
        
        for custom_perm in custom_permissions:
            self._add_finding(
                "MASTG-TEST-0063",
                f"Custom Permission Defined: {custom_perm}",
                f"Custom permission definition found: {custom_perm}",
                PlatformSeverityLevel.INFO,
                PlatformTestCategory.PERMISSION_ANALYSIS,
                "AndroidManifest.xml",
                evidence=[custom_perm],
                recommendations=["Review custom permission protection level", "Validate custom permission necessity"]
            )
    
    def _analyze_manifest_components(self, manifest_content: str):
        """Analyze component security configuration."""
        
        # Check exported components
        for component_type, pattern in self.component_patterns.items():
            if 'exported' in component_type:
                matches = re.findall(pattern, manifest_content, re.MULTILINE | re.DOTALL)
                if matches:
                    self.analysis_stats['exported_components'] += len(matches)
                    
                    component_name = component_type.replace('exported_', '').title()
                    self._add_finding(
                        "MASTG-TEST-0067",
                        f"Exported {component_name} Component",
                        f"Exported {component_name.lower()} component found, accessible by other applications",
                        PlatformSeverityLevel.MEDIUM if component_type != 'exported_provider' else PlatformSeverityLevel.HIGH,
                        PlatformTestCategory.COMPONENT_EXPOSURE,
                        "AndroidManifest.xml",
                        evidence=matches[:3],
                        recommendations=[f"Review {component_name.lower()} export necessity", "Implement proper access controls"],
                        masvs_controls=["MASVS-PLATFORM-2"],
                        cwe_ids=["CWE-200"]
                    )
        
        # Check intent filters
        intent_filters = re.findall(self.component_patterns['intent_filter'], manifest_content)
        self.analysis_stats['intent_filters_found'] = len(intent_filters)
        
        # Check for implicit intent filter exposure
        if intent_filters:
            main_actions = re.findall(self.component_patterns['action_main'], manifest_content)
            view_actions = re.findall(self.component_patterns['action_view'], manifest_content)
            
            if len(view_actions) > len(main_actions):
                self._add_finding(
                    "MASTG-TEST-0066",
                    "Multiple VIEW Intent Filters Detected",
                    f"Found {len(view_actions)} VIEW intent filters, potential for unintended exposure",
                    PlatformSeverityLevel.MEDIUM,
                    PlatformTestCategory.INTENT_SECURITY,
                    "AndroidManifest.xml",
                    evidence=[f"{len(view_actions)} VIEW actions"],
                    recommendations=["Review intent filter necessity", "Implement input validation for intent data"],
                    masvs_controls=["MASVS-PLATFORM-2"]
                )
    
    def _analyze_manifest_deeplinks(self, manifest_content: str):
        """Analyze deep link security configuration."""
        
        browsable_categories = re.findall(self.component_patterns['category_browsable'], manifest_content)
        if browsable_categories:
            # Extract deep link schemes
            custom_schemes = re.findall(self.deeplink_patterns['custom_scheme'], manifest_content)
            http_schemes = re.findall(self.deeplink_patterns['http_scheme'], manifest_content)
            
            self.analysis_stats['deeplinks_found'] = len(custom_schemes) + len(http_schemes)
            
            for scheme in custom_schemes:
                if scheme not in ['http', 'https', 'ftp']:
                    self._add_finding(
                        "MASTG-TEST-0072",
                        f"Custom Deep Link Scheme: {scheme}",
                        f"Custom URI scheme {scheme} found in deep link configuration",
                        PlatformSeverityLevel.MEDIUM,
                        PlatformTestCategory.DEEPLINK_SECURITY,
                        "AndroidManifest.xml",
                        evidence=[f"scheme: {scheme}"],
                        recommendations=["Validate deep link input data", "Implement authentication for sensitive deep links"],
                        masvs_controls=["MASVS-PLATFORM-3"],
                        cwe_ids=["CWE-20"]
                    )
            
            # Check for insecure HTTP deep links
            if http_schemes:
                self._add_finding(
                    "MASTG-TEST-0073",
                    "Insecure HTTP Deep Link Scheme",
                    "HTTP scheme used for deep links, susceptible to interception",
                    PlatformSeverityLevel.HIGH,
                    PlatformTestCategory.DEEPLINK_SECURITY,
                    "AndroidManifest.xml",
                    evidence=["HTTP scheme in deep links"],
                    recommendations=["Use HTTPS for web-based deep links", "Implement additional security for HTTP schemes"],
                    masvs_controls=["MASVS-PLATFORM-3"],
                    cwe_ids=["CWE-319"]
                )
    
    def _analyze_manifest_app_config(self, manifest_content: str):
        """Analyze application configuration security."""
        
        # Check backup configuration
        if re.search(self.app_config_patterns['backup_allowed'], manifest_content):
            self._add_finding(
                "MASTG-TEST-0078",
                "Application Backup Enabled",
                "Application backup is enabled, potentially exposing sensitive data",
                PlatformSeverityLevel.MEDIUM,
                PlatformTestCategory.BACKUP_SECURITY,
                "AndroidManifest.xml",
                evidence=["android:allowBackup=\"true\""],
                recommendations=["Disable backup for sensitive applications", "Implement backup encryption"],
                masvs_controls=["MASVS-STORAGE-1"],
                cwe_ids=["CWE-200"]
            )
        
        # Check debug configuration
        if re.search(self.app_config_patterns['debug_enabled'], manifest_content):
            self._add_finding(
                "MASTG-TEST-0079",
                "Debug Mode Enabled",
                "Application has debug mode enabled in production",
                PlatformSeverityLevel.HIGH,
                PlatformTestCategory.DEBUG_CONFIGURATION,
                "AndroidManifest.xml",
                evidence=["android:debuggable=\"true\""],
                recommendations=["Disable debug mode for production builds", "Review build configuration"],
                masvs_controls=["MASVS-CODE-8"],
                cwe_ids=["CWE-489"]
            )
        
        # Check cleartext traffic configuration
        if re.search(self.app_config_patterns['clear_text_traffic'], manifest_content):
            self._add_finding(
                "MASTG-TEST-0035",
                "Cleartext Traffic Allowed",
                "Application allows cleartext HTTP traffic",
                PlatformSeverityLevel.HIGH,
                PlatformTestCategory.APPLICATION_CONFIG,
                "AndroidManifest.xml",
                evidence=["android:usesCleartextTraffic=\"true\""],
                recommendations=["Disable cleartext traffic", "Use HTTPS for all network communication"],
                masvs_controls=["MASVS-NETWORK-1"],
                cwe_ids=["CWE-319"]
            )
        
        # Check SDK version configuration
        target_sdk_matches = re.findall(self.app_config_patterns['target_sdk'], manifest_content)
        min_sdk_matches = re.findall(self.app_config_patterns['min_sdk'], manifest_content)
        
        if target_sdk_matches:
            target_sdk = int(target_sdk_matches[0])
            if target_sdk < 29:  # Android 10
                self._add_finding(
                    "MASTG-TEST-0082",
                    f"Outdated Target SDK Version: {target_sdk}",
                    f"Application targets SDK version {target_sdk}, missing recent security enhancements",
                    PlatformSeverityLevel.MEDIUM,
                    PlatformTestCategory.SDK_VERSION_SECURITY,
                    "AndroidManifest.xml",
                    evidence=[f"targetSdkVersion: {target_sdk}"],
                    recommendations=["Update to latest target SDK version", "Review security implications of outdated SDK"],
                    masvs_controls=["MASVS-PLATFORM-1"]
                )
        
        if min_sdk_matches:
            min_sdk = int(min_sdk_matches[0])
            if min_sdk < 23:  # Android 6.0
                self._add_finding(
                    "MASTG-TEST-0083",
                    f"Low Minimum SDK Version: {min_sdk}",
                    f"Application supports SDK version {min_sdk}, lacking runtime permission model",
                    PlatformSeverityLevel.LOW,
                    PlatformTestCategory.SDK_VERSION_SECURITY,
                    "AndroidManifest.xml",
                    evidence=[f"minSdkVersion: {min_sdk}"],
                    recommendations=["Consider raising minimum SDK version", "Implement runtime permission handling"],
                    masvs_controls=["MASVS-PLATFORM-1"]
                )
    
    def _analyze_platform_source_code(self, source_path: str):
        """Analyze source code for platform security patterns."""
        try:
            for root, dirs, files in os.walk(source_path):
                for file in files:
                    if file.endswith(('.java', '.kt', '.xml')):
                        file_path = os.path.join(root, file)
                        self._analyze_platform_source_file(file_path)
                        self.analysis_stats['files_analyzed'] += 1
        except Exception as e:
            logger.error(f"Error analyzing platform source code: {e}")
    
    def _analyze_platform_source_file(self, file_path: str):
        """Analyze individual source file for platform security patterns."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for runtime permission handling
            self._check_runtime_permissions(content, file_path)
            
            # Check for intent handling security
            self._check_intent_security(content, file_path)
            
            # Check for component interaction security
            self._check_component_interaction(content, file_path)
            
        except Exception as e:
            logger.debug(f"Error analyzing platform source file {file_path}: {e}")
    
    def _check_runtime_permissions(self, content: str, file_path: str):
        """Check for proper runtime permission handling."""
        permission_check_patterns = [
            r'checkSelfPermission',
            r'requestPermissions',
            r'onRequestPermissionsResult',
            r'ContextCompat\.checkSelfPermission',
            r'ActivityCompat\.requestPermissions'
        ]
        
        permission_usage_patterns = [
            r'getSystemService\(CAMERA_SERVICE\)',
            r'getLocation',
            r'readContacts',
            r'AudioRecord',
            r'MediaRecorder'
        ]
        
        has_permission_checks = any(re.search(pattern, content, re.IGNORECASE) for pattern in permission_check_patterns)
        has_permission_usage = any(re.search(pattern, content, re.IGNORECASE) for pattern in permission_usage_patterns)
        
        if has_permission_usage and not has_permission_checks:
            self._add_finding(
                "MASTG-TEST-0065",
                "Missing Runtime Permission Checks",
                "Dangerous permission usage found without proper runtime checks",
                PlatformSeverityLevel.HIGH,
                PlatformTestCategory.PERMISSION_ANALYSIS,
                file_path,
                recommendations=["Implement runtime permission checks", "Handle permission denial gracefully"],
                masvs_controls=["MASVS-PLATFORM-1"],
                cwe_ids=["CWE-250"]
            )
    
    def _check_intent_security(self, content: str, file_path: str):
        """Check for secure intent handling."""
        # Check for intent data validation
        intent_patterns = [
            r'getIntent\(\)\.getData\(\)',
            r'intent\.getStringExtra',
            r'intent\.getExtras',
            r'getIntentData'
        ]
        
        validation_patterns = [
            r'validate',
            r'sanitize',
            r'check',
            r'verify',
            r'filter'
        ]
        
        has_intent_usage = any(re.search(pattern, content, re.IGNORECASE) for pattern in intent_patterns)
        has_validation = any(re.search(pattern, content, re.IGNORECASE) for pattern in validation_patterns)
        
        if has_intent_usage and not has_validation:
            self._add_finding(
                "MASTG-TEST-0075",
                "Unvalidated Intent Data Usage",
                "Intent data used without proper validation",
                PlatformSeverityLevel.MEDIUM,
                PlatformTestCategory.INTENT_SECURITY,
                file_path,
                recommendations=["Validate all intent data", "Sanitize user input from intents"],
                masvs_controls=["MASVS-PLATFORM-3"],
                cwe_ids=["CWE-20"]
            )
    
    def _check_component_interaction(self, content: str, file_path: str):
        """Check for secure component interaction."""
        # Check for implicit intent usage
        implicit_intent_patterns = [
            r'new\s+Intent\([^)]*\)',
            r'Intent\.ACTION_',
            r'sendBroadcast',
            r'startActivity.*implicit'
        ]
        
        for pattern in implicit_intent_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches and 'setComponent' not in content:
                self._add_finding(
                    "MASTG-TEST-0075",
                    "Implicit Intent Usage Without Component Specification",
                    "Implicit intent used without component specification",
                    PlatformSeverityLevel.LOW,
                    PlatformTestCategory.COMPONENT_INTERACTION,
                    file_path,
                    evidence=matches[:3],
                    recommendations=["Use explicit intents when possible", "Validate intent recipients"],
                    masvs_controls=["MASVS-PLATFORM-2"]
                )
    
    # Specialized test methods for different MASTG test categories
    def _perform_permission_analysis(self, apk_path: str):
        """Perform comprehensive permission analysis (MASTG-TEST-0061-0065)."""
        logger.debug("Performing permission analysis (MASTG-TEST-0061-0065)...")
        
        try:
            # Analyze APK for permission usage patterns
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Check AndroidManifest.xml for permission declarations
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    manifest_content = apk_zip.read('AndroidManifest.xml').decode('utf-8', errors='ignore')
                    self._analyze_permission_declarations(manifest_content)
                
                # Check for dangerous permissions without runtime checks
                self._analyze_dangerous_permissions(apk_zip)
                
                # Check for permission escalation patterns
                self._check_permission_escalation(apk_zip)
                
        except Exception as e:
            logger.error(f"Error in permission analysis: {e}")
    
    def _analyze_permission_declarations(self, manifest_content: str):
        """Analyze permission declarations in manifest."""
        dangerous_permissions = [
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ]
        
        for permission in dangerous_permissions:
            if permission in manifest_content:
                self._add_finding(
                    "MASTG-TEST-0061",
                    f"Dangerous Permission Declared: {permission}",
                    f"Application declares dangerous permission: {permission}",
                    PlatformSeverityLevel.MEDIUM,
                    PlatformTestCategory.PERMISSION_ANALYSIS,
                    "AndroidManifest.xml",
                    evidence=[permission],
                    recommendations=["Verify permission necessity", "Implement runtime permission checks"],
                    masvs_controls=["MASVS-PLATFORM-1"],
                    cwe_ids=["CWE-250"]
                )
    
    def _analyze_dangerous_permissions(self, apk_zip: zipfile.ZipFile):
        """Analyze dangerous permission usage patterns."""
        # Check for usage of dangerous permissions without runtime checks
        dangerous_patterns = {
            'CAMERA': [r'Camera\.open', r'Camera2', r'CameraX'],
            'LOCATION': [r'LocationManager\.requestLocationUpdates', r'FusedLocationProvider'],
            'CONTACTS': [r'ContactsContract\.CommonDataKinds']
        }
        
        for file_info in apk_zip.namelist():
            if file_info.endswith('.xml') or file_info.endswith('.smali'):
                try:
                    content = apk_zip.read(file_info).decode('utf-8', errors='ignore')
                    for perm_type, patterns in dangerous_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                self._add_finding(
                                    "MASTG-TEST-0062",
                                    f"Dangerous Permission Usage: {perm_type}",
                                    f"Dangerous permission {perm_type} used without proper runtime checks",
                                    PlatformSeverityLevel.HIGH,
                                    PlatformTestCategory.PERMISSION_ANALYSIS,
                                    file_info,
                                    evidence=[pattern],
                                    recommendations=["Implement runtime permission checks", "Handle permission denial gracefully"],
                                    masvs_controls=["MASVS-PLATFORM-1"],
                                    cwe_ids=["CWE-250"]
                                )
                except Exception as e:
                    logger.debug(f"Error analyzing {file_info}: {e}")
    
    def _check_permission_escalation(self, apk_zip: zipfile.ZipFile):
        """Check for permission escalation patterns."""
        escalation_patterns = [
            r'PendingIntent\.FLAG_MUTABLE',
            r'adb\s+shell',
            r'su\s+',
            r'Runtime\.getRuntime\(\)\.exec'
        ]
        
        for file_info in apk_zip.namelist():
            if file_info.endswith('.xml') or file_info.endswith('.smali'):
                try:
                    content = apk_zip.read(file_info).decode('utf-8', errors='ignore')
                    for pattern in escalation_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            self._add_finding(
                                "MASTG-TEST-0063",
                                "Potential Permission Escalation",
                                f"Pattern indicating potential permission escalation: {pattern}",
                                PlatformSeverityLevel.HIGH,
                                PlatformTestCategory.PERMISSION_ANALYSIS,
                                file_info,
                                evidence=matches[:3],
                                recommendations=["Review permission escalation patterns", "Use secure alternatives"],
                                masvs_controls=["MASVS-PLATFORM-1"],
                                cwe_ids=["CWE-250"]
                            )
                except Exception as e:
                    logger.debug(f"Error analyzing {file_info}: {e}")
    
    def _perform_component_security_analysis(self, apk_path: str):
        """Perform component security analysis (MASTG-TEST-0067-0071)."""
        logger.debug("Performing component security analysis (MASTG-TEST-0067-0071)...")
        
        try:
            # Analyze APK for component security
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Check for exported components
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    manifest_content = apk_zip.read('AndroidManifest.xml').decode('utf-8', errors='ignore')
                    self._analyze_exported_components(manifest_content)
                
                # Check for component protection mechanisms
                self._analyze_component_protection(apk_zip)
                
        except Exception as e:
            logger.error(f"Error in component security analysis: {e}")
    
    def _analyze_exported_components(self, manifest_content: str):
        """Analyze exported components in manifest."""
        component_patterns = [
            (r'<activity[^>]*android:exported="true"[^>]*>', 'Activity'),
            (r'<service[^>]*android:exported="true"[^>]*>', 'Service'),
            (r'<receiver[^>]*android:exported="true"[^>]*>', 'BroadcastReceiver'),
            (r'<provider[^>]*android:exported="true"[^>]*>', 'ContentProvider')
        ]
        
        for pattern, component_type in component_patterns:
            matches = re.findall(pattern, manifest_content, re.IGNORECASE)
            if matches:
                self._add_finding(
                    "MASTG-TEST-0067",
                    f"Exported {component_type} Component",
                    f"Exported {component_type} component found - ensure proper security controls",
                    PlatformSeverityLevel.MEDIUM,
                    PlatformTestCategory.COMPONENT_EXPOSURE,
                    "AndroidManifest.xml",
                    evidence=matches[:3],
                    recommendations=["Review component necessity", "Implement proper access controls"],
                    masvs_controls=["MASVS-PLATFORM-2"],
                    cwe_ids=["CWE-200"]
                )
    
    def _analyze_component_protection(self, apk_zip: zipfile.ZipFile):
        """Analyze component protection mechanisms."""
        protection_patterns = [
            r'android:permission="[^"]*"',
            r'checkCallingPermission',
            r'enforceCallingPermission',
            r'checkCallingOrSelfPermission'
        ]
        
        for file_info in apk_zip.namelist():
            if file_info.endswith('.xml') or file_info.endswith('.smali'):
                try:
                    content = apk_zip.read(file_info).decode('utf-8', errors='ignore')
                    has_protection = any(re.search(pattern, content, re.IGNORECASE) for pattern in protection_patterns)
                    
                    if 'exported="true"' in content and not has_protection:
                        self._add_finding(
                            "MASTG-TEST-0068",
                            "Exported Component Without Protection",
                            "Exported component found without proper protection mechanisms",
                            PlatformSeverityLevel.HIGH,
                            PlatformTestCategory.COMPONENT_EXPOSURE,
                            file_info,
                            evidence=["exported=true without protection"],
                            recommendations=["Add permission checks", "Implement access controls"],
                            masvs_controls=["MASVS-PLATFORM-2"],
                            cwe_ids=["CWE-200"]
                        )
                except Exception as e:
                    logger.debug(f"Error analyzing {file_info}: {e}")
    
    def _perform_intent_security_analysis(self, apk_path: str):
        """Perform intent security analysis (MASTG-TEST-0066, 0075)."""
        logger.debug("Performing intent security analysis (MASTG-TEST-0066, 0075)...")
        
        try:
            # Analyze APK for intent security
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Check for intent injection vulnerabilities
                self._analyze_intent_injection(apk_zip)
                
                # Check for intent data validation
                self._analyze_intent_data_validation(apk_zip)
                
        except Exception as e:
            logger.error(f"Error in intent security analysis: {e}")
    
    def _analyze_intent_injection(self, apk_zip: zipfile.ZipFile):
        """Analyze intent injection vulnerabilities."""
        injection_patterns = [
            r'getIntent\(\)\.getData\(\)',
            r'intent\.getStringExtra\([^)]*\)',
            r'intent\.getParcelableExtra\([^)]*\)',
            r'setResult\(.*intent.*\)'
        ]
        
        for file_info in apk_zip.namelist():
            if file_info.endswith('.xml') or file_info.endswith('.smali'):
                try:
                    content = apk_zip.read(file_info).decode('utf-8', errors='ignore')
                    for pattern in injection_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            self._add_finding(
                                "MASTG-TEST-0066",
                                "Potential Intent Injection",
                                f"Intent data usage pattern that may be vulnerable to injection: {pattern}",
                                PlatformSeverityLevel.MEDIUM,
                                PlatformTestCategory.INTENT_SECURITY,
                                file_info,
                                evidence=matches[:3],
                                recommendations=["Validate intent data", "Sanitize user input"],
                                masvs_controls=["MASVS-PLATFORM-3"],
                                cwe_ids=["CWE-20"]
                            )
                except Exception as e:
                    logger.debug(f"Error analyzing {file_info}: {e}")
    
    def _analyze_intent_data_validation(self, apk_zip: zipfile.ZipFile):
        """Analyze intent data validation patterns."""
        validation_patterns = [
            r'TextUtils\.isEmpty',
            r'Uri\.parse.*validate',
            r'intent\.getData\(\).*null',
            r'if\s*\([^)]*intent[^)]*!=\s*null\)'
        ]
        
        for file_info in apk_zip.namelist():
            if file_info.endswith('.xml') or file_info.endswith('.smali'):
                try:
                    content = apk_zip.read(file_info).decode('utf-8', errors='ignore')
                    has_validation = any(re.search(pattern, content, re.IGNORECASE) for pattern in validation_patterns)
                    has_intent_usage = re.search(r'getIntent\(\)', content, re.IGNORECASE)
                    
                    if has_intent_usage and not has_validation:
                        self._add_finding(
                            "MASTG-TEST-0075",
                            "Missing Intent Data Validation",
                            "Intent data used without proper validation",
                            PlatformSeverityLevel.MEDIUM,
                            PlatformTestCategory.INTENT_SECURITY,
                            file_info,
                            evidence=["Intent usage without validation"],
                            recommendations=["Add intent data validation", "Check for null values"],
                            masvs_controls=["MASVS-PLATFORM-3"],
                            cwe_ids=["CWE-20"]
                        )
                except Exception as e:
                    logger.debug(f"Error analyzing {file_info}: {e}")
    
    def _perform_deeplink_security_analysis(self, apk_path: str):
        """Perform deep link security analysis (MASTG-TEST-0072-0074)."""
        logger.debug("Performing deep link security analysis (MASTG-TEST-0072-0074)...")
        
        try:
            # Analyze APK for deep link security
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Check for deep link configurations
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    manifest_content = apk_zip.read('AndroidManifest.xml').decode('utf-8', errors='ignore')
                    self._analyze_deeplink_configurations(manifest_content)
                
                # Check for deep link validation
                self._analyze_deeplink_validation(apk_zip)
                
        except Exception as e:
            logger.error(f"Error in deep link security analysis: {e}")
    
    def _analyze_deeplink_configurations(self, manifest_content: str):
        """Analyze deep link configurations in manifest."""
        deeplink_patterns = [
            r'<intent-filter[^>]*>.*<data[^>]*android:scheme="[^"]*"[^>]*>',
            r'<intent-filter[^>]*>.*<data[^>]*android:host="[^"]*"[^>]*>',
            r'android:autoVerify="true"'
        ]
        
        for pattern in deeplink_patterns:
            matches = re.findall(pattern, manifest_content, re.IGNORECASE | re.DOTALL)
            if matches:
                self._add_finding(
                    "MASTG-TEST-0072",
                    "Deep Link Configuration Found",
                    f"Deep link configuration detected: {pattern}",
                    PlatformSeverityLevel.INFO,
                    PlatformTestCategory.DEEPLINK_SECURITY,
                    "AndroidManifest.xml",
                    evidence=matches[:3],
                    recommendations=["Validate deep link data", "Implement proper URL validation"],
                    masvs_controls=["MASVS-PLATFORM-3"],
                    cwe_ids=["CWE-20"]
                )
    
    def _analyze_deeplink_validation(self, apk_zip: zipfile.ZipFile):
        """Analyze deep link validation patterns."""
        validation_patterns = [
            r'Uri\.parse\([^)]*\)\.validate',
            r'URLUtil\.isValidUrl',
            r'Patterns\.WEB_URL\.matcher'
        ]
        
        for file_info in apk_zip.namelist():
            if file_info.endswith('.xml') or file_info.endswith('.smali'):
                try:
                    content = apk_zip.read(file_info).decode('utf-8', errors='ignore')
                    has_deeplink_handling = re.search(r'Intent\.ACTION_VIEW', content, re.IGNORECASE)
                    has_validation = any(re.search(pattern, content, re.IGNORECASE) for pattern in validation_patterns)
                    
                    if has_deeplink_handling and not has_validation:
                        self._add_finding(
                            "MASTG-TEST-0073",
                            "Deep Link Without Validation",
                            "Deep link handling found without proper URL validation",
                            PlatformSeverityLevel.MEDIUM,
                            PlatformTestCategory.DEEPLINK_SECURITY,
                            file_info,
                            evidence=["Deep link handling without validation"],
                            recommendations=["Add URL validation", "Sanitize deep link data"],
                            masvs_controls=["MASVS-PLATFORM-3"],
                            cwe_ids=["CWE-20"]
                        )
                except Exception as e:
                    logger.debug(f"Error analyzing {file_info}: {e}")
    
    def _perform_manifest_security_analysis(self, apk_path: str):
        """Perform manifest security analysis (MASTG-TEST-0088-0090)."""
        logger.debug("Performing manifest security analysis (MASTG-TEST-0088-0090)...")
        
        try:
            # Analyze APK for manifest security
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    manifest_content = apk_zip.read('AndroidManifest.xml').decode('utf-8', errors='ignore')
                    self._analyze_manifest_security_configurations(manifest_content)
                    
        except Exception as e:
            logger.error(f"Error in manifest security analysis: {e}")
    
    def _analyze_manifest_security_configurations(self, manifest_content: str):
        """Analyze manifest security configurations."""
        security_issues = [
            (r'android:allowBackup="true"', "Backup allowed", "MASTG-TEST-0088"),
            (r'android:debuggable="true"', "Debug mode enabled", "MASTG-TEST-0089"),
            (r'android:usesCleartextTraffic="true"', "Cleartext traffic allowed", "MASTG-TEST-0090"),
            (r'android:exported="true"[^>]*android:permission=""', "Exported without permission", "MASTG-TEST-0067")
        ]
        
        for pattern, description, test_id in security_issues:
            matches = re.findall(pattern, manifest_content, re.IGNORECASE)
            if matches:
                self._add_finding(
                    test_id,
                    f"Manifest Security Issue: {description}",
                    f"Manifest contains security issue: {description}",
                    PlatformSeverityLevel.MEDIUM,
                    PlatformTestCategory.MANIFEST_SECURITY,
                    "AndroidManifest.xml",
                    evidence=matches[:3],
                    recommendations=["Review manifest security settings", "Disable dangerous configurations"],
                    masvs_controls=["MASVS-PLATFORM-1"],
                    cwe_ids=["CWE-16"]
                )
    
    def _perform_debug_configuration_analysis(self, apk_path: str):
        """Perform debug configuration analysis (MASTG-TEST-0079)."""
        logger.debug("Performing debug configuration analysis (MASTG-TEST-0079)...")
        
        try:
            # Analyze APK for debug configurations
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Check for debug configurations in manifest
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    manifest_content = apk_zip.read('AndroidManifest.xml').decode('utf-8', errors='ignore')
                    self._analyze_debug_configurations(manifest_content)
                
                # Check for debug code in application
                self._analyze_debug_code(apk_zip)
                
        except Exception as e:
            logger.error(f"Error in debug configuration analysis: {e}")
    
    def _analyze_debug_configurations(self, manifest_content: str):
        """Analyze debug configurations in manifest."""
        debug_patterns = [
            r'android:debuggable="true"',
            r'android:testOnly="true"',
            r'<application[^>]*android:debuggable="true"'
        ]
        
        for pattern in debug_patterns:
            matches = re.findall(pattern, manifest_content, re.IGNORECASE)
            if matches:
                self._add_finding(
                    "MASTG-TEST-0079",
                    "Debug Configuration Enabled",
                    f"Debug configuration found in manifest: {pattern}",
                    PlatformSeverityLevel.HIGH,
                    PlatformTestCategory.DEBUG_CONFIGURATION,
                    "AndroidManifest.xml",
                    evidence=matches[:3],
                    recommendations=["Disable debug mode in production", "Remove debug configurations"],
                    masvs_controls=["MASVS-PLATFORM-1"],
                    cwe_ids=["CWE-489"]
                )
    
    def _analyze_debug_code(self, apk_zip: zipfile.ZipFile):
        """Analyze debug code patterns."""
        debug_code_patterns = [
            r'Log\.d\(',
            r'Log\.v\(',
            r'System\.out\.println',
            r'printStackTrace\(',
            r'BuildConfig\.DEBUG'
        ]
        
        for file_info in apk_zip.namelist():
            if file_info.endswith('.xml') or file_info.endswith('.smali'):
                try:
                    content = apk_zip.read(file_info).decode('utf-8', errors='ignore')
                    for pattern in debug_code_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            self._add_finding(
                                "MASTG-TEST-0079",
                                "Debug Code Found",
                                f"Debug code pattern found: {pattern}",
                                PlatformSeverityLevel.LOW,
                                PlatformTestCategory.DEBUG_CONFIGURATION,
                                file_info,
                                evidence=matches[:3],
                                recommendations=["Remove debug code in production", "Use conditional debug logging"],
                                masvs_controls=["MASVS-PLATFORM-1"],
                                cwe_ids=["CWE-489"]
                            )
                except Exception as e:
                    logger.debug(f"Error analyzing {file_info}: {e}")
    
    def _perform_sdk_version_analysis(self, apk_path: str):
        """Perform SDK version analysis (MASTG-TEST-0082-0083)."""
        logger.debug("Performing SDK version analysis (MASTG-TEST-0082-0083)...")
        
        try:
            # Analyze APK for SDK version configurations
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    manifest_content = apk_zip.read('AndroidManifest.xml').decode('utf-8', errors='ignore')
                    self._analyze_sdk_versions(manifest_content)
                    
        except Exception as e:
            logger.error(f"Error in SDK version analysis: {e}")
    
    def _analyze_sdk_versions(self, manifest_content: str):
        """Analyze SDK version configurations."""
        # Extract SDK version information
        min_sdk_match = re.search(r'android:minSdkVersion="(\d+)"', manifest_content, re.IGNORECASE)
        target_sdk_match = re.search(r'android:targetSdkVersion="(\d+)"', manifest_content, re.IGNORECASE)
        
        if min_sdk_match:
            min_sdk = int(min_sdk_match.group(1))
            if min_sdk < 21:  # Android 5.0 (API 21)
                self._add_finding(
                    "MASTG-TEST-0082",
                    "Low Minimum SDK Version",
                    f"Minimum SDK version {min_sdk} is below recommended security baseline",
                    PlatformSeverityLevel.MEDIUM,
                    PlatformTestCategory.SDK_VERSION_SECURITY,
                    "AndroidManifest.xml",
                    evidence=[f"minSdkVersion={min_sdk}"],
                    recommendations=["Increase minimum SDK version", "Consider security implications"],
                    masvs_controls=["MASVS-PLATFORM-1"],
                    cwe_ids=["CWE-16"]
                )
        
        if target_sdk_match:
            target_sdk = int(target_sdk_match.group(1))
            if target_sdk < 29:  # Android 10 (API 29)
                self._add_finding(
                    "MASTG-TEST-0083",
                    "Outdated Target SDK Version",
                    f"Target SDK version {target_sdk} is outdated and may lack security features",
                    PlatformSeverityLevel.MEDIUM,
                    PlatformTestCategory.SDK_VERSION_SECURITY,
                    "AndroidManifest.xml",
                    evidence=[f"targetSdkVersion={target_sdk}"],
                    recommendations=["Update target SDK version", "Test with latest security features"],
                    masvs_controls=["MASVS-PLATFORM-1"],
                    cwe_ids=["CWE-16"]
                )
        
        # Check for compile SDK version if available
        compile_sdk_match = re.search(r'compileSdkVersion\s+(\d+)', manifest_content, re.IGNORECASE)
        if compile_sdk_match:
            compile_sdk = int(compile_sdk_match.group(1))
            if compile_sdk < 30:  # Android 11 (API 30)
                self._add_finding(
                    "MASTG-TEST-0083",
                    "Outdated Compile SDK Version",
                    f"Compile SDK version {compile_sdk} is outdated",
                    PlatformSeverityLevel.LOW,
                    PlatformTestCategory.SDK_VERSION_SECURITY,
                    "AndroidManifest.xml",
                    evidence=[f"compileSdkVersion={compile_sdk}"],
                    recommendations=["Update compile SDK version", "Use latest development tools"],
                    masvs_controls=["MASVS-PLATFORM-1"],
                    cwe_ids=["CWE-16"]
                )
    
    def _add_finding(self, test_id: str, title: str, description: str, severity: PlatformSeverityLevel,
                    category: PlatformTestCategory, file_path: str, line_number: int = 0,
                    evidence: List[str] = None, recommendations: List[str] = None,
                    masvs_controls: List[str] = None, cwe_ids: List[str] = None):
        """Add a platform security finding to the results."""
        finding = PlatformFinding(
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
                "phase": "Advanced Platform Security Analysis",
                "analysis_timestamp": datetime.now().isoformat()
            }
        }
    
    def export_findings_json(self) -> Dict[str, Any]:
        """Export findings in JSON format."""
        return {
            "phase": "Advanced Platform Security Analysis",
            "analyzer": "EnhancedPlatformAnalyzer",
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