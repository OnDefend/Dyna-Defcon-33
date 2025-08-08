"""
Enhanced Manifest Analysis - Components Analyzer

This module provides comprehensive component analysis functionality for AndroidManifest.xml.
Full implementation with extensive security analysis capabilities.
"""

import logging
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional, Set
import re

from .data_structures import (
    ComponentAnalysis, AndroidComponent, ComponentType, RiskLevel,
    ManifestSecurityFinding, ManifestAnalysisConfiguration, AnalysisMethod
)

class ComponentsAnalyzer:
    """Comprehensive Android components analyzer with security analysis capabilities."""
    
    def __init__(self, config: Optional[ManifestAnalysisConfiguration] = None):
        """Initialize the components analyzer with configuration."""
        self.config = config or ManifestAnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
        
        # Initialize component analysis patterns
        self.dangerous_actions = self._initialize_dangerous_actions()
        self.dangerous_categories = self._initialize_dangerous_categories()
        self.sensitive_schemes = self._initialize_sensitive_schemes()
        self.component_patterns = self._initialize_component_patterns()
        
        # Analysis statistics
        self.analysis_stats = {
            'total_components': 0,
            'exported_components': 0,
            'protected_components': 0,
            'findings': 0
        }
    
    def analyze_components(self, manifest_root: ET.Element) -> ComponentAnalysis:
        """Analyze components from manifest with comprehensive security analysis."""
        try:
            self.logger.info("Starting comprehensive components analysis")
            
            analysis = ComponentAnalysis(
                activities=[],
                services=[],
                receivers=[],
                providers=[],
                exported_components=[]
            )
            
            # Analyze activities
            activities = self._analyze_activities(manifest_root)
            analysis.activities = activities
            
            # Analyze services
            services = self._analyze_services(manifest_root)
            analysis.services = services
            
            # Analyze broadcast receivers
            receivers = self._analyze_receivers(manifest_root)
            analysis.receivers = receivers
            
            # Analyze content providers
            providers = self._analyze_providers(manifest_root)
            analysis.providers = providers
            
            # Identify exported components
            all_components = activities + services + receivers + providers
            exported_components = [comp for comp in all_components if comp.exported]
            analysis.exported_components = exported_components
            
            # Identify protected components
            protected_components = [comp for comp in all_components if comp.permission]
            analysis.protected_components = protected_components
            
            # Update statistics
            self.analysis_stats['total_components'] = len(all_components)
            self.analysis_stats['exported_components'] = len(exported_components)
            self.analysis_stats['protected_components'] = len(protected_components)
            
            self.logger.info(f"Components analysis completed: {self.analysis_stats['total_components']} components analyzed")
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Components analysis failed: {e}")
            return ComponentAnalysis()
    
    def get_component_findings(self, component_analysis: ComponentAnalysis) -> List[ManifestSecurityFinding]:
        """Generate security findings from component analysis."""
        findings = []
        
        try:
            # Check for exported components without protection
            findings.extend(self._check_exported_components(component_analysis))
            
            # Check for dangerous intent filters
            findings.extend(self._check_dangerous_intent_filters(component_analysis))
            
            # Check for content provider security
            findings.extend(self._check_content_provider_security(component_analysis))
            
            # Check for service security
            findings.extend(self._check_service_security(component_analysis))
            
            # Check for receiver security
            findings.extend(self._check_receiver_security(component_analysis))
            
            # Check for activity security
            findings.extend(self._check_activity_security(component_analysis))
            
            # Check for component naming issues
            findings.extend(self._check_component_naming(component_analysis))
            
            self.analysis_stats['findings'] = len(findings)
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Component findings generation failed: {e}")
            return []
    
    def get_component_summary(self, component_analysis: ComponentAnalysis) -> Dict[str, Any]:
        """Generate comprehensive component analysis summary."""
        try:
            all_components = (component_analysis.activities + 
                            component_analysis.services + 
                            component_analysis.receivers + 
                            component_analysis.providers)
            
            summary = {
                'total_components': len(all_components),
                'activities': len(component_analysis.activities),
                'services': len(component_analysis.services),
                'receivers': len(component_analysis.receivers),
                'providers': len(component_analysis.providers),
                'exported_components': len(component_analysis.exported_components),
                'protected_components': len(component_analysis.protected_components),
                'findings': self.analysis_stats['findings'],
                'component_breakdown': self._get_component_breakdown(component_analysis),
                'security_analysis': self._get_security_analysis_summary(component_analysis)
            }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Component summary generation failed: {e}")
            return {
                'total_components': 0,
                'exported_components': 0,
                'findings': 0,
                'error': str(e)
            }
    
    def _analyze_activities(self, manifest_root: ET.Element) -> List[AndroidComponent]:
        """Analyze activity components."""
        components = []
        
        try:
            activities = manifest_root.findall('.//activity')
            
            for activity in activities:
                component = self._parse_component(activity, ComponentType.ACTIVITY)
                if component:
                    components.append(component)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing activities: {e}")
        
        return components
    
    def _analyze_services(self, manifest_root: ET.Element) -> List[AndroidComponent]:
        """Analyze service components."""
        components = []
        
        try:
            services = manifest_root.findall('.//service')
            
            for service in services:
                component = self._parse_component(service, ComponentType.SERVICE)
                if component:
                    components.append(component)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing services: {e}")
        
        return components
    
    def _analyze_receivers(self, manifest_root: ET.Element) -> List[AndroidComponent]:
        """Analyze broadcast receiver components."""
        components = []
        
        try:
            receivers = manifest_root.findall('.//receiver')
            
            for receiver in receivers:
                component = self._parse_component(receiver, ComponentType.RECEIVER)
                if component:
                    components.append(component)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing receivers: {e}")
        
        return components
    
    def _analyze_providers(self, manifest_root: ET.Element) -> List[AndroidComponent]:
        """Analyze content provider components."""
        components = []
        
        try:
            providers = manifest_root.findall('.//provider')
            
            for provider in providers:
                component = self._parse_component(provider, ComponentType.PROVIDER)
                if component:
                    components.append(component)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing providers: {e}")
        
        return components
    
    def _parse_component(self, element: ET.Element, component_type: ComponentType) -> Optional[AndroidComponent]:
        """Parse a component element into AndroidComponent object."""
        try:
            name = element.get('{http://schemas.android.com/apk/res/android}name')
            if not name:
                return None
            
            # Determine if component is exported
            exported = self._is_component_exported(element)
            
            # Get permission
            permission = element.get('{http://schemas.android.com/apk/res/android}permission')
            
            # Get enabled status
            enabled = element.get('{http://schemas.android.com/apk/res/android}enabled')
            is_enabled = enabled != 'false'
            
            # Parse intent filters
            intent_filters = self._parse_intent_filters(element)
            
            # Determine risk level
            risk_level = self._calculate_component_risk(element, exported, permission, intent_filters)
            
            # Additional attributes for specific component types
            additional_attrs = {}
            if component_type == ComponentType.PROVIDER:
                additional_attrs.update({
                    'authorities': element.get('{http://schemas.android.com/apk/res/android}authorities'),
                    'read_permission': element.get('{http://schemas.android.com/apk/res/android}readPermission'),
                    'write_permission': element.get('{http://schemas.android.com/apk/res/android}writePermission'),
                    'grant_uri_permissions': element.get('{http://schemas.android.com/apk/res/android}grantUriPermissions') == 'true'
                })
            elif component_type == ComponentType.SERVICE:
                additional_attrs.update({
                    'isolated_process': element.get('{http://schemas.android.com/apk/res/android}isolatedProcess') == 'true',
                    'external_service': element.get('{http://schemas.android.com/apk/res/android}externalService') == 'true'
                })
            elif component_type == ComponentType.ACTIVITY:
                additional_attrs.update({
                    'launch_mode': element.get('{http://schemas.android.com/apk/res/android}launchMode'),
                    'task_affinity': element.get('{http://schemas.android.com/apk/res/android}taskAffinity'),
                    'allow_task_reparenting': element.get('{http://schemas.android.com/apk/res/android}allowTaskReparenting') == 'true'
                })
            
            component = AndroidComponent(
                name=name,
                component_type=component_type,
                exported=exported,
                enabled=is_enabled,
                permission=permission,
                intent_filters=intent_filters,
                risk_level=risk_level,
                read_permission=additional_attrs.get('read_permission'),
                write_permission=additional_attrs.get('write_permission'),
                grant_uri_permissions=additional_attrs.get('grant_uri_permissions', False),
                task_affinity=additional_attrs.get('task_affinity'),
                launch_mode=additional_attrs.get('launch_mode'),
                meta_data={k: v for k, v in additional_attrs.items() 
                          if k not in ['read_permission', 'write_permission', 'grant_uri_permissions', 
                                     'task_affinity', 'launch_mode']}
            )
            
            return component
            
        except Exception as e:
            self.logger.error(f"Error parsing component: {e}")
            return None
    
    def _is_component_exported(self, element: ET.Element) -> bool:
        """Determine if a component is exported."""
        exported_attr = element.get('{http://schemas.android.com/apk/res/android}exported')
        
        if exported_attr is not None:
            return exported_attr.lower() == 'true'
        
        # If no explicit exported attribute, check for intent filters
        intent_filters = element.findall('.//intent-filter')
        return len(intent_filters) > 0
    
    def _parse_intent_filters(self, element: ET.Element) -> List[Dict[str, Any]]:
        """Parse intent filters for a component."""
        intent_filters = []
        
        try:
            filters = element.findall('.//intent-filter')
            
            for filter_elem in filters:
                intent_filter = {
                    'actions': [],
                    'categories': [],
                    'data_schemes': [],
                    'data_authorities': [],
                    'data_paths': [],
                    'data_types': [],
                    'data_path_patterns': [] # Added for path patterns
                }
                
                # Parse actions
                actions = filter_elem.findall('.//action')
                for action in actions:
                    action_name = action.get('{http://schemas.android.com/apk/res/android}name')
                    if action_name:
                        intent_filter['actions'].append(action_name)
                
                # Parse categories
                categories = filter_elem.findall('.//category')
                for category in categories:
                    category_name = category.get('{http://schemas.android.com/apk/res/android}name')
                    if category_name:
                        intent_filter['categories'].append(category_name)
                
                # Parse data elements
                data_elements = filter_elem.findall('.//data')
                for data in data_elements:
                    scheme = data.get('{http://schemas.android.com/apk/res/android}scheme')
                    if scheme:
                        intent_filter['data_schemes'].append(scheme)
                    
                    host = data.get('{http://schemas.android.com/apk/res/android}host')
                    if host:
                        intent_filter['data_authorities'].append(host)
                    
                    path = data.get('{http://schemas.android.com/apk/res/android}path')
                    if path:
                        intent_filter['data_paths'].append(path)
                    
                    mime_type = data.get('{http://schemas.android.com/apk/res/android}mimeType')
                    if mime_type:
                        intent_filter['data_types'].append(mime_type)
                
                # Parse path patterns
                path_patterns = filter_elem.findall('.//path-pattern')
                for path_pattern_elem in path_patterns:
                    path_pattern = path_pattern_elem.get('{http://schemas.android.com/apk/res/android}pattern')
                    if path_pattern:
                        intent_filter['data_path_patterns'].append(path_pattern)
                
                intent_filters.append(intent_filter)
                
        except Exception as e:
            self.logger.error(f"Error parsing intent filters: {e}")
        
        return intent_filters
    
    def _calculate_component_risk(self, element: ET.Element, exported: bool, permission: str, intent_filters: List[Dict[str, Any]]) -> RiskLevel:
        """Calculate risk level for a component."""
        risk_score = 0
        
        # Base risk for exported components
        if exported:
            risk_score += 30
        
        # Risk reduction for protected components
        if permission:
            risk_score -= 15
        
        # Risk increase for dangerous intent filters
        for intent_filter in intent_filters:
            for action in intent_filter['actions']:
                if action in self.dangerous_actions:
                    risk_score += 25
            
            for category in intent_filter['categories']:
                if category in self.dangerous_categories:
                    risk_score += 20
            
            for scheme in intent_filter['data_schemes']:
                if scheme in self.sensitive_schemes:
                    risk_score += 15
        
        # Convert score to risk level
        if risk_score >= 60:
            return RiskLevel.CRITICAL
        elif risk_score >= 40:
            return RiskLevel.HIGH
        elif risk_score >= 20:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _check_exported_components(self, analysis: ComponentAnalysis) -> List[ManifestSecurityFinding]:
        """Check for exported components without proper protection."""
        findings = []
        
        for component in analysis.exported_components:
            if not component.permission:
                severity = 'HIGH' if component.component_type in [ComponentType.SERVICE, ComponentType.PROVIDER] else 'MEDIUM'
                
                finding = ManifestSecurityFinding(
                    title=f"Exported {component.component_type.value} Without Permission",
                    description=f"Component {component.name} is exported without permission protection",
                    severity=RiskLevel.HIGH,
                    confidence=0.9,
                    location=f"AndroidManifest.xml - {component.name}",
                    method=AnalysisMethod.STATIC_MANIFEST,
                    evidence=f"Exported {component.component_type.value}: {component.name}",
                    component_name=component.name,
                    masvs_control='MSTG-PLATFORM-11',
                    recommendations=["Add permission protection or set exported=\"false\""]
                )
                findings.append(finding)
        
        return findings
    
    def _check_dangerous_intent_filters(self, analysis: ComponentAnalysis) -> List[ManifestSecurityFinding]:
        """Check for dangerous intent filters."""
        findings = []
        
        all_components = (analysis.activities + analysis.services + 
                         analysis.receivers + analysis.providers)
        
        for component in all_components:
            for intent_filter in component.intent_filters:
                # Check for dangerous actions
                for action in intent_filter['actions']:
                    if action in self.dangerous_actions:
                        finding = ManifestSecurityFinding(
                            title=f"Dangerous Intent Action: {action}",
                            description=f"Component {component.name} handles dangerous action: {action}",
                            severity=RiskLevel.HIGH,
                            confidence=0.8,
                            location=f"AndroidManifest.xml - {component.name}",
                            method=AnalysisMethod.STATIC_MANIFEST,
                            evidence=f"Intent action: {action}",
                            component_name=component.name,
                            masvs_control='MSTG-PLATFORM-11',
                            recommendations=["Ensure proper validation of intent data"]
                        )
                        findings.append(finding)
                
                # Check for sensitive schemes
                for scheme in intent_filter['data_schemes']:
                    if scheme in self.sensitive_schemes:
                        finding = ManifestSecurityFinding(
                            title=f"Sensitive URI Scheme: {scheme}",
                            description=f"Component {component.name} handles sensitive URI scheme: {scheme}",
                            severity=RiskLevel.MEDIUM,
                            confidence=0.7,
                            location=f"AndroidManifest.xml - {component.name}",
                            method=AnalysisMethod.STATIC_MANIFEST,
                            evidence=f"URI scheme: {scheme}",
                            component_name=component.name,
                            masvs_control='MSTG-PLATFORM-11',
                            recommendations=["Validate and sanitize URI scheme data"]
                        )
                        findings.append(finding)
                
                # Check for path patterns that might be exploitable
                for path_pattern in intent_filter['data_path_patterns']:
                    if self._is_exploitable_path_pattern(path_pattern):
                        finding = ManifestSecurityFinding(
                            title=f"Exploitable Path Pattern",
                            description=f"Component {component.name} has potentially exploitable path pattern: {path_pattern}",
                            severity=RiskLevel.MEDIUM,
                            confidence=0.6,
                            location=f"AndroidManifest.xml - {component.name}",
                            method=AnalysisMethod.STATIC_MANIFEST,
                            evidence=f"Path pattern: {path_pattern}",
                            component_name=component.name,
                            masvs_control='MSTG-PLATFORM-11',
                            recommendations=["Review and restrict path patterns to prevent exploitation"]
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_content_provider_security(self, analysis: ComponentAnalysis) -> List[ManifestSecurityFinding]:
        """Check content provider security."""
        findings = []
        
        for provider in analysis.providers:
            # Check for world-readable/writable providers
            if provider.exported and not provider.permission:
                attrs = provider.meta_data
                
                if not attrs.get('read_permission') and not attrs.get('write_permission'):
                    finding = ManifestSecurityFinding(
                        title=f"World-Accessible Content Provider",
                        description=f"Provider {provider.name} is world-accessible",
                        severity=RiskLevel.CRITICAL,
                        confidence=0.95,
                        location=f"AndroidManifest.xml - {provider.name}",
                        method=AnalysisMethod.STATIC_MANIFEST,
                        evidence=f"Exported provider without permissions: {provider.name}",
                        component_name=provider.name,
                        masvs_control='MSTG-PLATFORM-11',
                        recommendations=["Add read/write permissions or set exported=\"false\""]
                    )
                    findings.append(finding)
            
            # Check for grant URI permissions
            if provider.grant_uri_permissions:
                finding = ManifestSecurityFinding(
                    title=f"Grant URI Permissions Enabled",
                    description=f"Provider {provider.name} allows granting URI permissions",
                    severity=RiskLevel.MEDIUM,
                    confidence=0.7,
                    location=f"AndroidManifest.xml - {provider.name}",
                    method=AnalysisMethod.STATIC_MANIFEST,
                    evidence=f"grantUriPermissions=\"true\"",
                    component_name=provider.name,
                    masvs_control='MSTG-PLATFORM-11',
                    recommendations=["Ensure URI permissions are properly validated"]
                )
                findings.append(finding)
        
        return findings
    
    def _check_service_security(self, analysis: ComponentAnalysis) -> List[ManifestSecurityFinding]:
        """Check service security."""
        findings = []
        
        for service in analysis.services:
            # Check for external services
            if service.meta_data.get('external_service'):
                finding = ManifestSecurityFinding(
                    title=f"External Service",
                    description=f"Service {service.name} is marked as external",
                    severity=RiskLevel.MEDIUM,
                    confidence=0.8,
                    location=f"AndroidManifest.xml - {service.name}",
                    method=AnalysisMethod.STATIC_MANIFEST,
                    evidence=f"externalService=\"true\"",
                    component_name=service.name,
                    masvs_control='MSTG-PLATFORM-11',
                    recommendations=["Ensure external services are properly secured"]
                )
                findings.append(finding)
            
            # Check for isolated process
            if not service.meta_data.get('isolated_process') and service.exported:
                finding = ManifestSecurityFinding(
                    title=f"Non-Isolated Exported Service",
                    description=f"Exported service {service.name} doesn't run in isolated process",
                    severity=RiskLevel.LOW,
                    confidence=0.6,
                    location=f"AndroidManifest.xml - {service.name}",
                    method=AnalysisMethod.STATIC_MANIFEST,
                    evidence=f"Exported service without isolation",
                    component_name=service.name,
                    masvs_control='MSTG-PLATFORM-11',
                    recommendations=["Consider using isolatedProcess=\"true\" for security"]
                )
                findings.append(finding)
        
        return findings
    
    def _check_receiver_security(self, analysis: ComponentAnalysis) -> List[ManifestSecurityFinding]:
        """Check broadcast receiver security."""
        findings = []
        
        for receiver in analysis.receivers:
            # Check for system broadcast receivers
            for intent_filter in receiver.intent_filters:
                system_actions = [
                    'android.intent.action.BOOT_COMPLETED',
                    'android.intent.action.PACKAGE_REPLACED',
                    'android.intent.action.PACKAGE_INSTALL',
                    'android.net.conn.CONNECTIVITY_CHANGE'
                ]
                
                for action in intent_filter['actions']:
                    if action in system_actions and not receiver.permission:
                        finding = ManifestSecurityFinding(
                            title=f"Unprotected System Broadcast Receiver",
                            description=f"Receiver {receiver.name} handles system broadcast without permission",
                            severity=RiskLevel.MEDIUM,
                            confidence=0.8,
                            location=f"AndroidManifest.xml - {receiver.name}",
                            method=AnalysisMethod.STATIC_MANIFEST,
                            evidence=f"System action: {action}",
                            component_name=receiver.name,
                            masvs_control='MSTG-PLATFORM-11',
                            recommendations=["Add permission protection for system broadcasts"]
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_activity_security(self, analysis: ComponentAnalysis) -> List[ManifestSecurityFinding]:
        """Check activity security."""
        findings = []
        
        for activity in analysis.activities:
            # Check for task reparenting
            if activity.meta_data.get('allow_task_reparenting'):
                finding = ManifestSecurityFinding(
                    title=f"Task Reparenting Enabled",
                    description=f"Activity {activity.name} allows task reparenting",
                    severity=RiskLevel.LOW,
                    confidence=0.6,
                    location=f"AndroidManifest.xml - {activity.name}",
                    method=AnalysisMethod.STATIC_MANIFEST,
                    evidence=f"allowTaskReparenting=\"true\"",
                    component_name=activity.name,
                    masvs_control='MSTG-PLATFORM-11',
                    recommendations=["Consider security implications of task reparenting"]
                )
                findings.append(finding)
            
            # Check for custom task affinity
            task_affinity = activity.task_affinity
            if task_affinity and task_affinity != activity.name:
                finding = ManifestSecurityFinding(
                    title=f"Custom Task Affinity",
                    description=f"Activity {activity.name} has custom task affinity: {task_affinity}",
                    severity=RiskLevel.LOW,
                    confidence=0.5,
                    location=f"AndroidManifest.xml - {activity.name}",
                    method=AnalysisMethod.STATIC_MANIFEST,
                    evidence=f"taskAffinity=\"{task_affinity}\"",
                    component_name=activity.name,
                    masvs_control='MSTG-PLATFORM-11',
                    recommendations=["Review task affinity for security implications"]
                )
                findings.append(finding)
        
        return findings
    
    def _check_component_naming(self, analysis: ComponentAnalysis) -> List[ManifestSecurityFinding]:
        """Check component naming for security issues."""
        findings = []
        
        all_components = (analysis.activities + analysis.services + 
                         analysis.receivers + analysis.providers)
        
        for component in all_components:
            # Check for debug/test components
            if any(keyword in component.name.lower() for keyword in ['debug', 'test', 'dev']):
                finding = ManifestSecurityFinding(
                    title=f"Debug/Test Component",
                    description=f"Component {component.name} appears to be for debugging/testing",
                    severity=RiskLevel.MEDIUM,
                    confidence=0.7,
                    location=f"AndroidManifest.xml - {component.name}",
                    method=AnalysisMethod.STATIC_MANIFEST,
                    evidence=f"Debug/test component: {component.name}",
                    component_name=component.name,
                    masvs_control='MSTG-PLATFORM-11',
                    recommendations=["Remove debug/test components from production builds"]
                )
                findings.append(finding)
        
        return findings
    
    def _get_component_breakdown(self, analysis: ComponentAnalysis) -> Dict[str, int]:
        """Get component breakdown by type and risk."""
        breakdown = {
            'activities': len(analysis.activities),
            'services': len(analysis.services),
            'receivers': len(analysis.receivers),
            'providers': len(analysis.providers),
            'exported': len(analysis.exported_components),
            'protected': len(analysis.protected_components),
            'high_risk': 0,
            'medium_risk': 0,
            'low_risk': 0
        }
        
        all_components = (analysis.activities + analysis.services + 
                         analysis.receivers + analysis.providers)
        
        for component in all_components:
            if component.risk_level == RiskLevel.HIGH or component.risk_level == RiskLevel.CRITICAL:
                breakdown['high_risk'] += 1
            elif component.risk_level == RiskLevel.MEDIUM:
                breakdown['medium_risk'] += 1
            else:
                breakdown['low_risk'] += 1
        
        return breakdown
    
    def _get_security_analysis_summary(self, analysis: ComponentAnalysis) -> Dict[str, Any]:
        """Get security analysis summary."""
        all_components = (analysis.activities + analysis.services + 
                         analysis.receivers + analysis.providers)
        
        exported_count = len(analysis.exported_components)
        protected_count = len(analysis.protected_components)
        total_count = len(all_components)
        
        unprotected_exported = exported_count - protected_count
        
        risk_level = 'LOW'
        if unprotected_exported > 5:
            risk_level = 'CRITICAL'
        elif unprotected_exported > 3:
            risk_level = 'HIGH'
        elif unprotected_exported > 1:
            risk_level = 'MEDIUM'
        
        return {
            'risk_level': risk_level,
            'exported_ratio': exported_count / max(total_count, 1),
            'protected_ratio': protected_count / max(exported_count, 1),
            'unprotected_exported_count': unprotected_exported,
            'has_content_providers': len(analysis.providers) > 0,
            'has_system_receivers': any(
                any('android.intent.action.BOOT_COMPLETED' in action for intent_filter in receiver.intent_filters for action in intent_filter['actions'])
                for receiver in analysis.receivers
            ),
            'component_diversity': len(set(comp.component_type for comp in all_components))
        }
    
    def _initialize_dangerous_actions(self) -> Set[str]:
        """Initialize set of dangerous intent actions."""
        return {
            'android.intent.action.BOOT_COMPLETED',
            'android.intent.action.PACKAGE_REPLACED',
            'android.intent.action.PACKAGE_INSTALL',
            'android.intent.action.PACKAGE_REMOVED',
            'android.intent.action.SEND',
            'android.intent.action.SENDTO',
            'android.intent.action.VIEW',
            'android.intent.action.EDIT',
            'android.intent.action.DELETE',
            'android.intent.action.INSERT',
            'android.intent.action.PROCESS_TEXT',
            'android.net.conn.CONNECTIVITY_CHANGE',
            'android.provider.Telephony.SMS_RECEIVED',
            'android.provider.Telephony.WAP_PUSH_RECEIVED'
        }
    
    def _initialize_dangerous_categories(self) -> Set[str]:
        """Initialize set of dangerous intent categories."""
        return {
            'android.intent.category.LAUNCHER',
            'android.intent.category.DEFAULT',
            'android.intent.category.BROWSABLE',
            'android.intent.category.HOME'
        }
    
    def _initialize_sensitive_schemes(self) -> Set[str]:
        """Initialize set of sensitive URI schemes."""
        return {
            'file',
            'content',
            'android_asset',
            'android_res',
            'data',
            'javascript',
            'tel',
            'sms',
            'mailto',
            'geo'
        }
    
    def _initialize_component_patterns(self) -> Dict[str, List[str]]:
        """Initialize component analysis patterns."""
        return {
            'debug_patterns': [
                'debug',
                'test',
                'dev',
                'staging',
                'mock'
            ],
            'suspicious_patterns': [
                'admin',
                'root',
                'system',
                'hidden',
                'secret'
            ]
        } 

    def _is_exploitable_path_pattern(self, path_pattern: str) -> bool:
        """Check if a path pattern might be exploitable."""
        # Simple check for common exploitable patterns
        exploitable_patterns = [
            '../',   # Directory traversal
            '.*',    # Wildcard patterns
            '/..',   # Parent directory
            '%2e%2e', # URL-encoded directory traversal
            '*',     # Wildcard
        ]
        
        return any(pattern in path_pattern.lower() for pattern in exploitable_patterns) 