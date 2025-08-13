#!/usr/bin/env python3
"""
Component Security Analyzer for AODS - Enhanced Security Analysis Framework

This analyzer identifies security vulnerabilities in Android application components including:
- Exported Activity security issues
- Intent Filter vulnerabilities 
- Service security problems
- Broadcast Receiver exposure issues
- Component permission misconfigurations

"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import logging

from .base_security_analyzer import BaseSecurityAnalyzer
from .enhanced_config_manager import EnhancedConfigManager

class ComponentSecurityAnalyzer(BaseSecurityAnalyzer):
    """
    Advanced component security analyzer for Android applications.
    
    Analyzes Android components for security vulnerabilities with focus on:
    - Component exposure through exports
    - Intent filter security issues
    - Permission misconfigurations
    - Inter-component communication vulnerabilities
    """
    
    def __init__(self, config_manager: Optional[EnhancedConfigManager] = None):
        """
        Initialize the Component Security Analyzer.
        
        Args:
            config_manager: Configuration manager for pattern loading
        """
        super().__init__("Component Security Analyzer")
        
        # Add analyzer_name for compatibility with tests
        self.analyzer_name = "Component Security Analyzer"
        
        self.config_manager = config_manager or EnhancedConfigManager()
        self.component_patterns = self._initialize_component_patterns()
        self.manifest_namespace = {'android': 'http://schemas.android.com/apk/res/android'}
        
        # Component analysis metrics
        self.component_metrics = {
            'activities_analyzed': 0,
            'services_analyzed': 0,
            'receivers_analyzed': 0,
            'providers_analyzed': 0,
            'exported_components': 0,
            'vulnerable_intents': 0,
            'permission_issues': 0
        }
        
        self.logger.debug("Component Security Analyzer v1.0 initialized successfully")
    
    def _initialize_component_patterns(self) -> Dict[str, Any]:
        """Initialize component security patterns from configuration."""
        patterns = {
            'exported_activity_patterns': {
                'dangerous_exported_activities': [
                    r'<activity[^>]*android:exported\s*=\s*["\']true["\'][^>]*>.*?<intent-filter',
                    r'<activity[^>]*>.*?<intent-filter[^>]*>.*?<action[^>]*android:name\s*=\s*["\']android\.intent\.action\.MAIN["\']',
                    r'<activity[^>]*android:exported\s*=\s*["\']true["\'][^>]*>.*?android:permission\s*=\s*["\']["\']'
                ],
                'intent_filter_vulnerabilities': [
                    r'<intent-filter[^>]*>.*?<data[^>]*android:scheme\s*=\s*["\']http["\']',
                    r'<intent-filter[^>]*>.*?<data[^>]*android:pathPattern\s*=\s*["\'][^"\']*\*[^"\']*["\']',
                    r'<intent-filter[^>]*>.*?<category[^>]*android:name\s*=\s*["\']android\.intent\.category\.BROWSABLE["\']'
                ]
            },
            'service_security_patterns': {
                'exported_service_vulnerabilities': [
                    r'<service[^>]*android:exported\s*=\s*["\']true["\'][^>]*(?!.*android:permission)',
                    r'<service[^>]*android:exported\s*=\s*["\']true["\'][^>]*android:permission\s*=\s*["\']["\']',
                    r'<service[^>]*>.*?<intent-filter[^>]*>(?!.*android:permission)'
                ],
                'service_permission_issues': [
                    r'<service[^>]*android:exported\s*=\s*["\']true["\'][^>]*android:permission\s*=\s*["\']android\.permission\.BIND_[^"\']*["\']',
                    r'<service[^>]*>.*?android:process\s*=\s*["\'][^"\']*:[^"\']*["\']'
                ]
            },
            'receiver_security_patterns': {
                'broadcast_receiver_vulnerabilities': [
                    r'<receiver[^>]*android:exported\s*=\s*["\']true["\'][^>]*(?!.*android:permission)',
                    r'<receiver[^>]*>.*?<intent-filter[^>]*>.*?<action[^>]*android:name\s*=\s*["\'][^"\']*BOOT_COMPLETED["\']',
                    r'<receiver[^>]*>.*?<intent-filter[^>]*>.*?<action[^>]*android:name\s*=\s*["\'][^"\']*SMS_RECEIVED["\']'
                ],
                'receiver_permission_bypass': [
                    r'<receiver[^>]*android:exported\s*=\s*["\']true["\'][^>]*android:permission\s*=\s*["\']["\']',
                    r'<receiver[^>]*>.*?<intent-filter[^>]*android:priority\s*=\s*["\'][0-9]+["\']'
                ]
            },
            'provider_security_patterns': {
                'content_provider_vulnerabilities': [
                    r'<provider[^>]*android:exported\s*=\s*["\']true["\'][^>]*(?!.*android:permission)',
                    r'<provider[^>]*android:grantUriPermissions\s*=\s*["\']true["\']',
                    r'<provider[^>]*>.*?<path-permission[^>]*android:readPermission\s*=\s*["\']["\']'
                ],
                'provider_data_exposure': [
                    r'<provider[^>]*android:authorities\s*=\s*["\'][^"\']*\.[^"\']*["\'].*android:exported\s*=\s*["\']true["\']',
                    r'<provider[^>]*>.*?<grant-uri-permission[^>]*android:pathPattern\s*=\s*["\'][^"\']*\*[^"\']*["\']'
                ]
            }
        }
        
        # Load additional patterns from configuration if available
        try:
            if hasattr(self.config_manager, 'get_patterns'):
                config_patterns = self.config_manager.get_patterns('component_patterns')
                if config_patterns:
                    patterns.update(config_patterns)
                    self.logger.debug("Loaded component patterns from configuration")
        except Exception as e:
            self.logger.warning(f"Could not load component patterns from config: {e}")
        
        return patterns
    
    def analyze(self, target: Union[str, Path], **kwargs) -> List[Dict[str, Any]]:
        """
        Analyze target for component security vulnerabilities.
        
        Args:
            target: AndroidManifest.xml content or file path
            **kwargs: Additional analysis parameters
            
        Returns:
            List of security findings
        """
        self.start_analysis()
        
        try:
            # Determine if target is content or file path
            is_content = False
            
            if isinstance(target, (str, Path)):
                target_str = str(target)
                # Check if it's XML content or a file path
                if target_str.strip().startswith('<?xml') or '<manifest' in target_str:
                    is_content = True
                else:
                    # Check if file exists
                    try:
                        target_path = Path(target_str)
                        is_content = not target_path.exists()
                    except (OSError, ValueError):
                        is_content = True
            else:
                is_content = True
            
            if is_content:
                # Treat as AndroidManifest.xml content
                self._analyze_manifest_content(str(target), kwargs.get('file_path', 'AndroidManifest.xml'))
            else:
                # Treat as file path
                target_path = Path(target)
                if target_path.is_file() and target_path.name == 'AndroidManifest.xml':
                    self._analyze_manifest_file(target_path)
                elif target_path.is_dir():
                    self._analyze_directory(target_path)
                else:
                    self.logger.warning(f"Target not found or invalid: {target}")
            
            stats = self.end_analysis()
            self.logger.debug(f"Component analysis completed: {len(self.findings)} findings in {stats['performance_stats']['analysis_time']:.3f}s")
            
            return self.findings
            
        except Exception as e:
            self.logger.error(f"Error in component analysis: {e}")
            self.analysis_stats['errors_encountered'] += 1
            return self.findings
    
    def _analyze_directory(self, directory: Path):
        """Recursively analyze directory for AndroidManifest.xml files."""
        for manifest_file in directory.rglob('AndroidManifest.xml'):
            if manifest_file.is_file():
                self._analyze_manifest_file(manifest_file)
    
    def _analyze_manifest_file(self, manifest_path: Path):
        """Analyze AndroidManifest.xml file."""
        try:
            content, success = self._safe_file_read(manifest_path)
            if success and content:
                self._analyze_manifest_content(content, str(manifest_path))
        except Exception as e:
            self.logger.error(f"Error reading manifest file {manifest_path}: {e}")
    
    def _analyze_manifest_content(self, content: str, file_path: str):
        """Analyze AndroidManifest.xml content for component vulnerabilities."""
        # Analyze using both regex patterns and XML parsing
        self._analyze_with_regex_patterns(content, file_path)
        self._analyze_with_xml_parsing(content, file_path)
    
    def _analyze_with_regex_patterns(self, content: str, file_path: str):
        """Analyze manifest content using regex patterns."""
        # Analyze exported activities
        self._detect_activity_vulnerabilities(content, file_path)
        
        # Analyze service security
        self._detect_service_vulnerabilities(content, file_path)
        
        # Analyze broadcast receivers
        self._detect_receiver_vulnerabilities(content, file_path)
        
        # Analyze content providers
        self._detect_provider_vulnerabilities(content, file_path)
    
    def _analyze_with_xml_parsing(self, content: str, file_path: str):
        """Analyze manifest using XML parsing for more accurate component analysis."""
        try:
            # Parse XML content
            root = ET.fromstring(content)
            
            # Register namespace
            ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
            
            # Analyze application components
            app_element = root.find('application')
            if app_element is not None:
                self._analyze_activities_xml(app_element, file_path)
                self._analyze_services_xml(app_element, file_path)
                self._analyze_receivers_xml(app_element, file_path)
                self._analyze_providers_xml(app_element, file_path)
        
        except ET.ParseError as e:
            self.logger.warning(f"XML parsing failed for {file_path}: {e}, falling back to regex analysis")
        except Exception as e:
            self.logger.error(f"Error in XML analysis for {file_path}: {e}")
    
    def _detect_activity_vulnerabilities(self, content: str, file_path: str):
        """Detect activity security vulnerabilities using regex patterns."""
        patterns = self.component_patterns.get('exported_activity_patterns', {})
        
        # Check for dangerous exported activities
        for pattern in patterns.get('dangerous_exported_activities', []):
            for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                vulnerability = self._analyze_exported_activity_risk(match, content)
                if vulnerability:
                    line_num = self._get_line_number(content, match.start())
                    context = self._extract_context(content, match.start(), match.end())
                    
                    finding = self._create_finding(
                        type='EXPORTED_ACTIVITY_VULNERABILITY',
                        severity=vulnerability['severity'],
                        title=vulnerability['title'],
                        description=vulnerability['description'],
                        reason=vulnerability['reason'],
                        recommendation=vulnerability['recommendation'],
                        location=f"{file_path}:{line_num}",
                        file_path=file_path,
                        line_number=line_num,
                        evidence=match.group(0)[:200] + '...' if len(match.group(0)) > 200 else match.group(0),
                        context=context,
                        pattern_matched=pattern,
                        cwe_id='CWE-926',
                        confidence=vulnerability['confidence'],
                        tags=['component-security', 'exported-activity', 'android'],
                        custom_fields={
                            'component_type': 'activity',
                            'export_status': 'true'
                        }
                    )
                    
                    self.add_finding(finding)
                    self.component_metrics['exported_components'] += 1
        
        # Check for intent filter vulnerabilities
        for pattern in patterns.get('intent_filter_vulnerabilities', []):
            for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                vulnerability = self._analyze_intent_filter_risk(match, content)
                if vulnerability:
                    line_num = self._get_line_number(content, match.start())
                    context = self._extract_context(content, match.start(), match.end())
                    
                    finding = self._create_finding(
                        type='INTENT_FILTER_VULNERABILITY',
                        severity=vulnerability['severity'],
                        title=vulnerability['title'],
                        description=vulnerability['description'],
                        reason=vulnerability['reason'],
                        recommendation=vulnerability['recommendation'],
                        location=f"{file_path}:{line_num}",
                        file_path=file_path,
                        line_number=line_num,
                        evidence=match.group(0)[:200] + '...' if len(match.group(0)) > 200 else match.group(0),
                        context=context,
                        pattern_matched=pattern,
                        cwe_id='CWE-925',
                        confidence=vulnerability['confidence'],
                        tags=['component-security', 'intent-filter', 'android'],
                        custom_fields={
                            'vulnerability_type': 'intent_filter',
                            'component_type': 'activity'
                        }
                    )
                    
                    self.add_finding(finding)
                    self.component_metrics['vulnerable_intents'] += 1
    
    def _detect_service_vulnerabilities(self, content: str, file_path: str):
        """Detect service security vulnerabilities."""
        patterns = self.component_patterns.get('service_security_patterns', {})
        
        # Check for exported service vulnerabilities
        for pattern in patterns.get('exported_service_vulnerabilities', []):
            for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                vulnerability = self._analyze_service_security_risk(match, content)
                if vulnerability:
                    line_num = self._get_line_number(content, match.start())
                    context = self._extract_context(content, match.start(), match.end())
                    
                    finding = self._create_finding(
                        type='EXPORTED_SERVICE_VULNERABILITY',
                        severity=vulnerability['severity'],
                        title=vulnerability['title'],
                        description=vulnerability['description'],
                        reason=vulnerability['reason'],
                        recommendation=vulnerability['recommendation'],
                        location=f"{file_path}:{line_num}",
                        file_path=file_path,
                        line_number=line_num,
                        evidence=match.group(0)[:200] + '...' if len(match.group(0)) > 200 else match.group(0),
                        context=context,
                        pattern_matched=pattern,
                        cwe_id='CWE-926',
                        confidence=vulnerability['confidence'],
                        tags=['component-security', 'exported-service', 'android'],
                        custom_fields={
                            'component_type': 'service',
                            'export_status': 'true'
                        }
                    )
                    
                    self.add_finding(finding)
                    self.component_metrics['exported_components'] += 1
    
    def _detect_receiver_vulnerabilities(self, content: str, file_path: str):
        """Detect broadcast receiver security vulnerabilities."""
        patterns = self.component_patterns.get('receiver_security_patterns', {})
        
        # Check for broadcast receiver vulnerabilities
        for pattern in patterns.get('broadcast_receiver_vulnerabilities', []):
            for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                vulnerability = self._analyze_receiver_security_risk(match, content)
                if vulnerability:
                    line_num = self._get_line_number(content, match.start())
                    context = self._extract_context(content, match.start(), match.end())
                    
                    finding = self._create_finding(
                        type='BROADCAST_RECEIVER_VULNERABILITY',
                        severity=vulnerability['severity'],
                        title=vulnerability['title'],
                        description=vulnerability['description'],
                        reason=vulnerability['reason'],
                        recommendation=vulnerability['recommendation'],
                        location=f"{file_path}:{line_num}",
                        file_path=file_path,
                        line_number=line_num,
                        evidence=match.group(0)[:200] + '...' if len(match.group(0)) > 200 else match.group(0),
                        context=context,
                        pattern_matched=pattern,
                        cwe_id='CWE-926',
                        confidence=vulnerability['confidence'],
                        tags=['component-security', 'broadcast-receiver', 'android'],
                        custom_fields={
                            'component_type': 'receiver',
                            'export_status': 'true'
                        }
                    )
                    
                    self.add_finding(finding)
                    self.component_metrics['exported_components'] += 1
    
    def _detect_provider_vulnerabilities(self, content: str, file_path: str):
        """Detect content provider security vulnerabilities."""
        patterns = self.component_patterns.get('provider_security_patterns', {})
        
        # Check for content provider vulnerabilities
        for pattern in patterns.get('content_provider_vulnerabilities', []):
            for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                vulnerability = self._analyze_provider_security_risk(match, content)
                if vulnerability:
                    line_num = self._get_line_number(content, match.start())
                    context = self._extract_context(content, match.start(), match.end())
                    
                    finding = self._create_finding(
                        type='CONTENT_PROVIDER_VULNERABILITY',
                        severity=vulnerability['severity'],
                        title=vulnerability['title'],
                        description=vulnerability['description'],
                        reason=vulnerability['reason'],
                        recommendation=vulnerability['recommendation'],
                        location=f"{file_path}:{line_num}",
                        file_path=file_path,
                        line_number=line_num,
                        evidence=match.group(0)[:200] + '...' if len(match.group(0)) > 200 else match.group(0),
                        context=context,
                        pattern_matched=pattern,
                        cwe_id='CWE-200',
                        confidence=vulnerability['confidence'],
                        tags=['component-security', 'content-provider', 'android'],
                        custom_fields={
                            'component_type': 'provider',
                            'export_status': 'true'
                        }
                    )
                    
                    self.add_finding(finding)
                    self.component_metrics['exported_components'] += 1
    
    def _analyze_activities_xml(self, app_element: ET.Element, file_path: str):
        """Analyze activities using XML parsing."""
        activities = app_element.findall('activity')
        for activity in activities:
            self.component_metrics['activities_analyzed'] += 1
            self._check_activity_security_xml(activity, file_path)
    
    def _analyze_services_xml(self, app_element: ET.Element, file_path: str):
        """Analyze services using XML parsing."""
        services = app_element.findall('service')
        for service in services:
            self.component_metrics['services_analyzed'] += 1
            self._check_service_security_xml(service, file_path)
    
    def _analyze_receivers_xml(self, app_element: ET.Element, file_path: str):
        """Analyze broadcast receivers using XML parsing."""
        receivers = app_element.findall('receiver')
        for receiver in receivers:
            self.component_metrics['receivers_analyzed'] += 1
            self._check_receiver_security_xml(receiver, file_path)
    
    def _analyze_providers_xml(self, app_element: ET.Element, file_path: str):
        """Analyze content providers using XML parsing."""
        providers = app_element.findall('provider')
        for provider in providers:
            self.component_metrics['providers_analyzed'] += 1
            self._check_provider_security_xml(provider, file_path)
    
    def _check_activity_security_xml(self, activity: ET.Element, file_path: str):
        """Check individual activity for security issues."""
        exported = activity.get('{http://schemas.android.com/apk/res/android}exported')
        permission = activity.get('{http://schemas.android.com/apk/res/android}permission')
        name = activity.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
        
        # Check for exported activity without permission
        if exported == 'true' and not permission:
            intent_filters = activity.findall('intent-filter')
            if intent_filters:
                finding = self._create_finding(
                    type='EXPORTED_ACTIVITY_NO_PERMISSION',
                    severity='HIGH',
                    title=f'Exported Activity Without Permission: {name}',
                    description='Activity is exported without requiring any permission, making it accessible to other applications',
                    reason='Exported activities without permissions can be invoked by malicious applications',
                    recommendation='Add android:permission attribute or set android:exported="false"',
                    location=f"{file_path}:activity[{name}]",
                    file_path=file_path,
                    evidence=f'<activity android:name="{name}" android:exported="true">',
                    cwe_id='CWE-926',
                    confidence=0.90,
                    tags=['component-security', 'exported-activity', 'android', 'high-risk'],
                    custom_fields={
                        'component_name': name,
                        'component_type': 'activity',
                        'export_status': 'true',
                        'has_permission': False,
                        'intent_filter_count': len(intent_filters)
                    }
                )
                self.add_finding(finding)
    
    def _check_service_security_xml(self, service: ET.Element, file_path: str):
        """Check individual service for security issues."""
        exported = service.get('{http://schemas.android.com/apk/res/android}exported')
        permission = service.get('{http://schemas.android.com/apk/res/android}permission')
        name = service.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
        
        # Check for exported service without permission
        if exported == 'true' and not permission:
            finding = self._create_finding(
                type='EXPORTED_SERVICE_NO_PERMISSION',
                severity='HIGH',
                title=f'Exported Service Without Permission: {name}',
                description='Service is exported without requiring any permission, making it accessible to other applications',
                reason='Exported services without permissions can be bound or started by malicious applications',
                recommendation='Add android:permission attribute or set android:exported="false"',
                location=f"{file_path}:service[{name}]",
                file_path=file_path,
                evidence=f'<service android:name="{name}" android:exported="true">',
                cwe_id='CWE-926',
                confidence=0.90,
                tags=['component-security', 'exported-service', 'android', 'high-risk'],
                custom_fields={
                    'component_name': name,
                    'component_type': 'service',
                    'export_status': 'true',
                    'has_permission': False
                }
            )
            self.add_finding(finding)
    
    def _check_receiver_security_xml(self, receiver: ET.Element, file_path: str):
        """Check individual broadcast receiver for security issues."""
        exported = receiver.get('{http://schemas.android.com/apk/res/android}exported')
        permission = receiver.get('{http://schemas.android.com/apk/res/android}permission')
        name = receiver.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
        
        # Check for exported receiver without permission
        if exported == 'true' and not permission:
            intent_filters = receiver.findall('intent-filter')
            if intent_filters:
                # Determine if this is a high-risk receiver based on actions
                severity = 'HIGH' if self._is_high_risk_receiver(receiver) else 'MEDIUM'
                title_suffix = self._get_receiver_risk_description(receiver)
                
                finding = self._create_finding(
                    type='EXPORTED_RECEIVER_NO_PERMISSION',
                    severity=severity,
                    title=f'Exported {title_suffix} Receiver Without Permission: {name}',
                    description='Broadcast receiver is exported without requiring any permission',
                    reason='Exported receivers without permissions can receive broadcasts from malicious applications',
                    recommendation='Add android:permission attribute or set android:exported="false"',
                    location=f"{file_path}:receiver[{name}]",
                    file_path=file_path,
                    evidence=f'<receiver android:name="{name}" android:exported="true">',
                    cwe_id='CWE-926',
                    confidence=0.85,
                    tags=['component-security', 'broadcast-receiver', 'android'],
                    custom_fields={
                        'component_name': name,
                        'component_type': 'receiver',
                        'export_status': 'true',
                        'has_permission': False,
                        'intent_filter_count': len(intent_filters)
                    }
                )
                self.add_finding(finding)
    
    def _check_provider_security_xml(self, provider: ET.Element, file_path: str):
        """Check individual content provider for security issues."""
        exported = provider.get('{http://schemas.android.com/apk/res/android}exported')
        permission = provider.get('{http://schemas.android.com/apk/res/android}permission')
        name = provider.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
        authorities = provider.get('{http://schemas.android.com/apk/res/android}authorities', 'Unknown')
        
        # Check for exported provider without permission
        if exported == 'true' and not permission:
            finding = self._create_finding(
                type='EXPORTED_PROVIDER_NO_PERMISSION',
                severity='HIGH',
                title=f'Exported Content Provider Without Permission: {name}',
                description='Content provider is exported without requiring any permission',
                reason='Exported content providers without permissions can be accessed by malicious applications',
                recommendation='Add android:permission attribute or set android:exported="false"',
                location=f"{file_path}:provider[{name}]",
                file_path=file_path,
                evidence=f'<provider android:name="{name}" android:authorities="{authorities}" android:exported="true">',
                cwe_id='CWE-200',
                confidence=0.90,
                tags=['component-security', 'content-provider', 'android', 'high-risk'],
                custom_fields={
                    'component_name': name,
                    'component_type': 'provider',
                    'export_status': 'true',
                    'has_permission': False,
                    'authorities': authorities
                }
            )
            self.add_finding(finding)
    
    def _is_high_risk_receiver(self, receiver: ET.Element) -> bool:
        """Determine if a receiver handles high-risk actions."""
        high_risk_actions = [
            'BOOT_COMPLETED', 'SMS_RECEIVED', 'PHONE_STATE', 'NEW_OUTGOING_CALL',
            'PACKAGE_ADDED', 'PACKAGE_REMOVED', 'SCREEN_ON', 'SCREEN_OFF'
        ]
        
        actions = receiver.findall('.//action')
        for action in actions:
            action_name = action.get('{http://schemas.android.com/apk/res/android}name', '')
            for risk_action in high_risk_actions:
                if risk_action in action_name:
                    return True
        return False
    
    def _get_receiver_risk_description(self, receiver: ET.Element) -> str:
        """Get a description of the receiver's risk type."""
        actions = receiver.findall('.//action')
        for action in actions:
            action_name = action.get('{http://schemas.android.com/apk/res/android}name', '')
            if 'BOOT_COMPLETED' in action_name:
                return 'Boot'
            elif 'SMS_RECEIVED' in action_name:
                return 'SMS'
            elif 'PHONE_STATE' in action_name:
                return 'Phone State'
        return 'Broadcast'
    
    def _analyze_exported_activity_risk(self, match: re.Match, content: str) -> Optional[Dict[str, Any]]:
        """Analyze the risk level of an exported activity."""
        matched_text = match.group(0).lower()
        
        # Determine severity based on patterns
        if 'permission=""' in matched_text or 'permission=\'\'' in matched_text:
            severity = 'HIGH'
            confidence = 0.95
            title = 'Exported Activity with Empty Permission'
            reason = 'Activity is exported with an empty permission, effectively making it unprotected'
        elif 'android:permission' not in matched_text:
            severity = 'HIGH'
            confidence = 0.90
            title = 'Exported Activity Without Permission Protection'
            reason = 'Activity is exported without any permission requirement'
        elif 'intent.action.main' in matched_text:
            severity = 'MEDIUM'
            confidence = 0.75
            title = 'Main Activity Exported'
            reason = 'Main activity is exported, which may expose application entry points'
        else:
            severity = 'MEDIUM'
            confidence = 0.70
            title = 'Exported Activity Detected'
            reason = 'Activity is exported and may be accessible to other applications'
        
        return {
            'severity': severity,
            'confidence': confidence,
            'title': title,
            'description': 'Exported Android activity that may be vulnerable to external access',
            'reason': reason,
            'recommendation': 'Review activity exports and add appropriate permission requirements'
        }
    
    def _analyze_intent_filter_risk(self, match: re.Match, content: str) -> Optional[Dict[str, Any]]:
        """Analyze the risk level of intent filter configurations."""
        matched_text = match.group(0).lower()
        
        if 'scheme="http"' in matched_text:
            severity = 'HIGH'
            confidence = 0.90
            title = 'HTTP Scheme Intent Filter'
            reason = 'Intent filter accepts HTTP URLs, potentially exposing the app to malicious links'
        elif 'pathpattern' in matched_text and '*' in matched_text:
            severity = 'MEDIUM'
            confidence = 0.80
            title = 'Wildcard Path Pattern in Intent Filter'
            reason = 'Intent filter uses wildcard patterns that may be too permissive'
        elif 'browsable' in matched_text:
            severity = 'MEDIUM'
            confidence = 0.75
            title = 'Browsable Intent Filter'
            reason = 'Intent filter allows the activity to be launched from web browsers'
        else:
            return None
        
        return {
            'severity': severity,
            'confidence': confidence,
            'title': title,
            'description': 'Intent filter configuration that may introduce security risks',
            'reason': reason,
            'recommendation': 'Review intent filter patterns and restrict to necessary URL schemes only'
        }
    
    def _analyze_service_security_risk(self, match: re.Match, content: str) -> Optional[Dict[str, Any]]:
        """Analyze the risk level of service security issues."""
        matched_text = match.group(0).lower()
        
        if 'exported="true"' in matched_text and 'permission' not in matched_text:
            severity = 'HIGH'
            confidence = 0.90
            title = 'Exported Service Without Permission'
            reason = 'Service is exported without any permission protection'
        elif 'permission=""' in matched_text:
            severity = 'HIGH'
            confidence = 0.95
            title = 'Service with Empty Permission'
            reason = 'Service has an empty permission, making it effectively unprotected'
        else:
            severity = 'MEDIUM'
            confidence = 0.75
            title = 'Service Security Issue'
            reason = 'Service may have security configuration issues'
        
        return {
            'severity': severity,
            'confidence': confidence,
            'title': title,
            'description': 'Service component that may be vulnerable to unauthorized access',
            'reason': reason,
            'recommendation': 'Add appropriate permission requirements to protect the service'
        }
    
    def _analyze_receiver_security_risk(self, match: re.Match, content: str) -> Optional[Dict[str, Any]]:
        """Analyze the risk level of broadcast receiver security issues."""
        matched_text = match.group(0).lower()
        
        if 'boot_completed' in matched_text:
            severity = 'HIGH'
            confidence = 0.85
            title = 'Boot Receiver Without Permission'
            reason = 'Broadcast receiver listens for boot events without proper permission protection'
        elif 'sms_received' in matched_text:
            severity = 'HIGH'
            confidence = 0.90
            title = 'SMS Receiver Without Permission'
            reason = 'Broadcast receiver listens for SMS events without proper permission protection'
        elif 'exported="true"' in matched_text and 'permission' not in matched_text:
            severity = 'MEDIUM'
            confidence = 0.80
            title = 'Exported Receiver Without Permission'
            reason = 'Broadcast receiver is exported without permission protection'
        else:
            severity = 'MEDIUM'
            confidence = 0.70
            title = 'Receiver Security Issue'
            reason = 'Broadcast receiver may have security configuration issues'
        
        return {
            'severity': severity,
            'confidence': confidence,
            'title': title,
            'description': 'Broadcast receiver that may be vulnerable to unauthorized broadcasts',
            'reason': reason,
            'recommendation': 'Add appropriate permission requirements to protect the receiver'
        }
    
    def _analyze_provider_security_risk(self, match: re.Match, content: str) -> Optional[Dict[str, Any]]:
        """Analyze the risk level of content provider security issues."""
        matched_text = match.group(0).lower()
        
        if 'exported="true"' in matched_text and 'permission' not in matched_text:
            severity = 'HIGH'
            confidence = 0.90
            title = 'Exported Content Provider Without Permission'
            reason = 'Content provider is exported without any permission protection'
        elif 'granturipermissions="true"' in matched_text:
            severity = 'MEDIUM'
            confidence = 0.80
            title = 'Content Provider Grants URI Permissions'
            reason = 'Content provider grants URI permissions which may expose data'
        elif 'path-permission' in matched_text and 'readpermission=""' in matched_text:
            severity = 'HIGH'
            confidence = 0.85
            title = 'Content Provider with Empty Read Permission'
            reason = 'Content provider has empty read permission, making data accessible'
        else:
            severity = 'MEDIUM'
            confidence = 0.75
            title = 'Content Provider Security Issue'
            reason = 'Content provider may have security configuration issues'
        
        return {
            'severity': severity,
            'confidence': confidence,
            'title': title,
            'description': 'Content provider that may expose application data',
            'reason': reason,
            'recommendation': 'Add appropriate permission requirements to protect provider data'
        }
    
    def get_component_metrics(self) -> Dict[str, Any]:
        """Get component analysis metrics."""
        return {
            **self.component_metrics,
            'total_findings': len(self.findings),
            'analysis_time': self.analysis_stats.get('analysis_time', 0),
            'files_processed': self.analysis_stats.get('files_processed', 0)
        } 