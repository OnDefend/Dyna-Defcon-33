#!/usr/bin/env python3
"""
Network Cleartext Traffic Analyzer - AndroidManifest.xml Analyzer

This module provides comprehensive analysis of AndroidManifest.xml for cleartext traffic
configuration, target SDK versions, and network security settings.

Features:
- AndroidManifest.xml parsing and validation
- Target SDK version analysis and risk assessment
- usesCleartextTraffic attribute detection
- Network Security Configuration reference extraction
- Permission analysis for network-related permissions
- Component analysis for network-exposed components

Classes:
    ManifestAnalyzer: Main AndroidManifest.xml analysis engine
"""

import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

from .data_structures import (
    ManifestAnalysisResult, NetworkSecurityFinding, FindingType, RiskLevel,
    ManifestAttribute
)
from .confidence_calculator import NetworkCleartextConfidenceCalculator

class ManifestAnalyzer:
    """
    AndroidManifest.xml analyzer for network cleartext traffic configuration.
    
    Provides comprehensive analysis of manifest settings related to network security
    including cleartext traffic configuration, target SDK version assessment,
    and Network Security Configuration references.
    """
    
    def __init__(self, confidence_calculator: NetworkCleartextConfidenceCalculator):
        """
        Initialize manifest analyzer.
        
        Args:
            confidence_calculator: Confidence calculation engine
        """
        self.logger = logging.getLogger(__name__)
        self.confidence_calculator = confidence_calculator
        self.android_ns = "{http://schemas.android.com/apk/res/android}"
        
        # Network-related permissions to analyze
        self.network_permissions = {
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.CHANGE_NETWORK_STATE',
            'android.permission.CHANGE_WIFI_STATE'
        }
        
        # Components that may handle network traffic
        self.network_components = {
            'activity', 'service', 'receiver', 'provider'
        }
    
    def analyze_manifest(self, manifest_path: Path) -> ManifestAnalysisResult:
        """
        Perform comprehensive AndroidManifest.xml analysis.
        
        Args:
            manifest_path: Path to AndroidManifest.xml file
            
        Returns:
            ManifestAnalysisResult with analysis findings and data
        """
        result = ManifestAnalysisResult()
        
        try:
            if not manifest_path.exists():
                self.logger.warning(f"AndroidManifest.xml not found at {manifest_path}")
                return result
            
            result.manifest_found = True
            
            # Parse AndroidManifest.xml
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Extract Android namespace
            self._extract_android_namespace(root)
            result.android_namespace = self.android_ns
            
            # Analyze uses-sdk configuration
            self._analyze_uses_sdk(root, result)
            
            # Analyze application element
            app_element = root.find("application")
            if app_element is not None:
                result.application_element = app_element
                self._analyze_application_element(app_element, result)
            
            # Analyze permissions
            self._analyze_permissions(root, result)
            
            # Analyze components
            self._analyze_components(root, result)
            
            # Generate findings based on analysis
            findings = self._generate_manifest_findings(result)
            result.findings.extend(findings)
            
            self.logger.info(f"Manifest analysis completed with {len(result.findings)} findings")
            
        except ET.ParseError as e:
            self.logger.error(f"XML parsing error in AndroidManifest.xml: {e}")
            result.findings.append({
                'type': 'MANIFEST_PARSE_ERROR',
                'message': f'Failed to parse AndroidManifest.xml: {e}',
                'severity': 'HIGH'
            })
        except Exception as e:
            self.logger.error(f"Error analyzing AndroidManifest.xml: {e}")
            result.findings.append({
                'type': 'MANIFEST_ANALYSIS_ERROR',
                'message': f'Analysis error: {e}',
                'severity': 'MEDIUM'
            })
        
        return result
    
    def _extract_android_namespace(self, root: ET.Element):
        """Extract Android namespace from manifest root element"""
        # Look for android namespace in root attributes
        for key, value in root.attrib.items():
            if value == "http://schemas.android.com/apk/res/android":
                # Extract namespace prefix
                if key.startswith("{"):
                    # Namespace is already in Clark notation
                    self.android_ns = "{http://schemas.android.com/apk/res/android}"
                else:
                    # Extract prefix (e.g., "xmlns:android" -> "android:")
                    prefix = key.split(":")[-1] if ":" in key else "android"
                    self.android_ns = f"{{{value}}}"
                break
    
    def _analyze_uses_sdk(self, root: ET.Element, result: ManifestAnalysisResult):
        """Analyze uses-sdk element for SDK version information"""
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            # Target SDK version
            target_sdk_attr = f"{self.android_ns}targetSdkVersion"
            target_sdk_str = uses_sdk.get(target_sdk_attr)
            if target_sdk_str:
                try:
                    result.target_sdk = int(target_sdk_str)
                except ValueError:
                    self.logger.warning(f"Invalid targetSdkVersion: {target_sdk_str}")
            
            # Min SDK version
            min_sdk_attr = f"{self.android_ns}minSdkVersion"
            min_sdk_str = uses_sdk.get(min_sdk_attr)
            if min_sdk_str:
                try:
                    result.min_sdk = int(min_sdk_str)
                except ValueError:
                    self.logger.warning(f"Invalid minSdkVersion: {min_sdk_str}")
        
        # Also check manifest element for target SDK (alternative location)
        if result.target_sdk is None:
            target_sdk_attr = f"{self.android_ns}targetSdkVersion"
            target_sdk_str = root.get(target_sdk_attr)
            if target_sdk_str:
                try:
                    result.target_sdk = int(target_sdk_str)
                except ValueError:
                    pass
    
    def _analyze_application_element(self, app_element: ET.Element, result: ManifestAnalysisResult):
        """Analyze application element for network security configuration"""
        # Check usesCleartextTraffic attribute
        cleartext_attr = f"{self.android_ns}usesCleartextTraffic"
        cleartext_value = app_element.get(cleartext_attr)
        if cleartext_value is not None:
            result.uses_cleartext_traffic = cleartext_value.lower()
        
        # Check networkSecurityConfig attribute
        nsc_attr = f"{self.android_ns}networkSecurityConfig"
        nsc_value = app_element.get(nsc_attr)
        if nsc_value is not None:
            result.network_security_config = nsc_value
    
    def _analyze_permissions(self, root: ET.Element, result: ManifestAnalysisResult):
        """Analyze uses-permission elements for network-related permissions"""
        permission_elements = root.findall("uses-permission")
        
        for perm_element in permission_elements:
            name_attr = f"{self.android_ns}name"
            permission_name = perm_element.get(name_attr)
            
            if permission_name:
                result.permissions.append(permission_name)
    
    def _analyze_components(self, root: ET.Element, result: ManifestAnalysisResult):
        """Analyze application components for network exposure"""
        app_element = root.find("application")
        if app_element is None:
            return
        
        # Analyze activities
        for activity in app_element.findall("activity"):
            name_attr = f"{self.android_ns}name"
            activity_name = activity.get(name_attr, "")
            if activity_name:
                result.activities.append(activity_name)
        
        # Analyze services
        for service in app_element.findall("service"):
            name_attr = f"{self.android_ns}name"
            service_name = service.get(name_attr, "")
            if service_name:
                result.services.append(service_name)
        
        # Analyze receivers
        for receiver in app_element.findall("receiver"):
            name_attr = f"{self.android_ns}name"
            receiver_name = receiver.get(name_attr, "")
            if receiver_name:
                result.receivers.append(receiver_name)
        
        # Analyze providers
        for provider in app_element.findall("provider"):
            name_attr = f"{self.android_ns}name"
            provider_name = provider.get(name_attr, "")
            if provider_name:
                result.providers.append(provider_name)
    
    def _generate_manifest_findings(self, result: ManifestAnalysisResult) -> List[Dict[str, Any]]:
        """Generate security findings based on manifest analysis"""
        findings = []
        
        # Target SDK version assessment
        if result.target_sdk is not None:
            if result.target_sdk >= 28:
                findings.append({
                    'type': 'TARGET_SDK_SECURE',
                    'message': f'Target SDK {result.target_sdk} - Cleartext traffic disabled by default',
                    'severity': 'INFO',
                    'evidence': [f'targetSdkVersion="{result.target_sdk}"'],
                    'location': 'AndroidManifest.xml'
                })
            else:
                findings.append({
                    'type': 'TARGET_SDK_INSECURE',
                    'message': f'Target SDK {result.target_sdk} - Cleartext traffic enabled by default',
                    'severity': 'MEDIUM',
                    'evidence': [f'targetSdkVersion="{result.target_sdk}"'],
                    'location': 'AndroidManifest.xml',
                    'remediation': [
                        'Upgrade target SDK to 28 or higher',
                        'Explicitly disable cleartext traffic if upgrading is not possible'
                    ]
                })
        
        # Cleartext traffic configuration assessment
        if result.uses_cleartext_traffic is not None:
            if result.uses_cleartext_traffic == "true":
                severity = 'HIGH'
                if result.target_sdk and result.target_sdk >= 28:
                    severity = 'CRITICAL'  # More severe on API 28+ where it's disabled by default
                
                findings.append({
                    'type': 'CLEARTEXT_ENABLED',
                    'message': 'android:usesCleartextTraffic="true" - Cleartext traffic explicitly enabled',
                    'severity': severity,
                    'evidence': [f'usesCleartextTraffic="{result.uses_cleartext_traffic}"'],
                    'location': 'AndroidManifest.xml/application',
                    'remediation': [
                        'Set android:usesCleartextTraffic="false"',
                        'Use HTTPS for all network communications',
                        'Implement Network Security Configuration for fine-grained control'
                    ]
                })
            elif result.uses_cleartext_traffic == "false":
                findings.append({
                    'type': 'CLEARTEXT_DISABLED',
                    'message': 'android:usesCleartextTraffic="false" - Cleartext traffic disabled',
                    'severity': 'INFO',
                    'evidence': [f'usesCleartextTraffic="{result.uses_cleartext_traffic}"'],
                    'location': 'AndroidManifest.xml/application'
                })
        
        # Network Security Configuration reference
        if result.network_security_config:
            findings.append({
                'type': 'NSC_CONFIGURED',
                'message': f'Network Security Configuration referenced: {result.network_security_config}',
                'severity': 'INFO',
                'evidence': [f'networkSecurityConfig="{result.network_security_config}"'],
                'location': 'AndroidManifest.xml/application'
            })
        elif result.target_sdk and result.target_sdk >= 24:
            # NSC is available for API 24+, recommend using it
            findings.append({
                'type': 'NSC_MISSING',
                'message': 'Network Security Configuration not configured',
                'severity': 'MEDIUM',
                'evidence': ['No networkSecurityConfig attribute found'],
                'location': 'AndroidManifest.xml/application',
                'remediation': [
                    'Implement Network Security Configuration',
                    'Create res/xml/network_security_config.xml',
                    'Reference NSC in android:networkSecurityConfig attribute'
                ]
            })
        
        # Internet permission assessment
        if 'android.permission.INTERNET' not in result.permissions:
            findings.append({
                'type': 'NO_INTERNET_PERMISSION',
                'message': 'No INTERNET permission declared',
                'severity': 'INFO',
                'evidence': ['INTERNET permission not found in uses-permission elements'],
                'location': 'AndroidManifest.xml'
            })
        
        # Network state permissions
        network_state_perms = [
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.ACCESS_WIFI_STATE'
        ]
        
        declared_network_perms = [p for p in network_state_perms if p in result.permissions]
        if declared_network_perms:
            findings.append({
                'type': 'NETWORK_STATE_PERMISSIONS',
                'message': f'Network state permissions declared: {len(declared_network_perms)}',
                'severity': 'INFO',
                'evidence': declared_network_perms,
                'location': 'AndroidManifest.xml'
            })
        
        return findings
    
    def generate_security_findings(self, result: ManifestAnalysisResult) -> List[NetworkSecurityFinding]:
        """
        Generate NetworkSecurityFinding objects from manifest analysis.
        
        Args:
            result: Manifest analysis result
            
        Returns:
            List of NetworkSecurityFinding objects with calculated confidence
        """
        security_findings = []
        
        for finding_data in result.findings:
            try:
                # Map finding type
                finding_type = self._map_finding_type(finding_data['type'])
                
                # Map severity
                severity = self._map_severity(finding_data['severity'])
                
                # Create security finding
                finding = NetworkSecurityFinding(
                    finding_type=finding_type,
                    severity=severity,
                    title=self._generate_finding_title(finding_data),
                    description=finding_data['message'],
                    location=finding_data.get('location', 'AndroidManifest.xml'),
                    evidence=finding_data.get('evidence', []),
                    remediation=finding_data.get('remediation', []),
                    masvs_control="MASVS-NETWORK-1",
                    mastg_reference="MASTG-TEST-0024",
                    detection_method="manifest_analysis"
                )
                
                # Calculate confidence
                finding.confidence = self.confidence_calculator.calculate_cleartext_confidence(
                    finding,
                    manifest_analysis=result,
                    context={'file_type': 'manifest', 'analysis_source': 'manifest_analyzer'}
                )
                
                security_findings.append(finding)
                
            except Exception as e:
                self.logger.error(f"Error creating security finding: {e}")
                continue
        
        return security_findings
    
    def _map_finding_type(self, finding_type_str: str) -> FindingType:
        """Map string finding type to FindingType enum"""
        mapping = {
            'TARGET_SDK_SECURE': FindingType.TARGET_SDK_SECURE,
            'TARGET_SDK_INSECURE': FindingType.TARGET_SDK_INSECURE,
            'CLEARTEXT_ENABLED': FindingType.CLEARTEXT_ENABLED,
            'CLEARTEXT_DISABLED': FindingType.CLEARTEXT_DISABLED,
            'NSC_CONFIGURED': FindingType.NSC_SECURE,
            'NSC_MISSING': FindingType.CONFIG_MISSING,
            'NO_INTERNET_PERMISSION': FindingType.CONFIG_MISSING,
            'NETWORK_STATE_PERMISSIONS': FindingType.CONFIG_MISSING,
            'MANIFEST_PARSE_ERROR': FindingType.ANALYSIS_ERROR,
            'MANIFEST_ANALYSIS_ERROR': FindingType.ANALYSIS_ERROR
        }
        
        return mapping.get(finding_type_str, FindingType.ANALYSIS_ERROR)
    
    def _map_severity(self, severity_str: str) -> RiskLevel:
        """Map string severity to RiskLevel enum"""
        mapping = {
            'CRITICAL': RiskLevel.CRITICAL,
            'HIGH': RiskLevel.HIGH,
            'MEDIUM': RiskLevel.MEDIUM,
            'LOW': RiskLevel.LOW,
            'INFO': RiskLevel.INFO
        }
        
        return mapping.get(severity_str.upper(), RiskLevel.MEDIUM)
    
    def _generate_finding_title(self, finding_data: Dict[str, Any]) -> str:
        """Generate appropriate title for finding"""
        finding_type = finding_data['type']
        
        titles = {
            'TARGET_SDK_SECURE': 'Secure Target SDK Version',
            'TARGET_SDK_INSECURE': 'Insecure Target SDK Version',
            'CLEARTEXT_ENABLED': 'Cleartext Traffic Enabled',
            'CLEARTEXT_DISABLED': 'Cleartext Traffic Disabled',
            'NSC_CONFIGURED': 'Network Security Configuration Found',
            'NSC_MISSING': 'Network Security Configuration Missing',
            'NO_INTERNET_PERMISSION': 'No Internet Permission',
            'NETWORK_STATE_PERMISSIONS': 'Network State Permissions',
            'MANIFEST_PARSE_ERROR': 'Manifest Parse Error',
            'MANIFEST_ANALYSIS_ERROR': 'Manifest Analysis Error'
        }
        
        return titles.get(finding_type, 'Manifest Security Finding')
    
    def get_cleartext_status_summary(self, result: ManifestAnalysisResult) -> Dict[str, Any]:
        """
        Get summary of cleartext traffic configuration status.
        
        Args:
            result: Manifest analysis result
            
        Returns:
            Dictionary with cleartext status summary
        """
        status = result.get_cleartext_status()
        
        # Determine effective cleartext policy
        if result.uses_cleartext_traffic is not None:
            policy_source = "explicit_manifest"
            policy_value = result.uses_cleartext_traffic
        elif result.target_sdk and result.target_sdk >= 28:
            policy_source = "default_api28plus"
            policy_value = "false"
        else:
            policy_source = "default_legacy"
            policy_value = "true"
        
        # Risk assessment
        if policy_value == "true":
            if result.target_sdk and result.target_sdk >= 28:
                risk_level = "CRITICAL"
                risk_reason = "Cleartext enabled on API 28+ (disabled by default)"
            else:
                risk_level = "HIGH"
                risk_reason = "Cleartext enabled on legacy API"
        else:
            risk_level = "LOW"
            risk_reason = "Cleartext traffic disabled"
        
        return {
            'cleartext_enabled': policy_value == "true",
            'policy_source': policy_source,
            'policy_value': policy_value,
            'target_sdk': result.target_sdk,
            'risk_level': risk_level,
            'risk_reason': risk_reason,
            'has_nsc': result.network_security_config is not None,
            'nsc_reference': result.network_security_config
        } 