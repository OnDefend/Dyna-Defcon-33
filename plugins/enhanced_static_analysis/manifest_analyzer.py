"""
Enhanced Static Analysis - Manifest Analyzer Component

This module provides comprehensive AndroidManifest.xml analysis capabilities
including security configuration assessment, permission analysis, and component analysis.
"""

import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
import os

from core.apk_ctx import APKContext
from .data_structures import ManifestAnalysis, AnalysisConfiguration

class ManifestAnalyzer:
    """Advanced AndroidManifest.xml analyzer."""
    
    def __init__(self, config: Optional[AnalysisConfiguration] = None):
        """Initialize the manifest analyzer."""
        self.config = config or AnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
    
    def analyze_manifest(self, apk_ctx: APKContext) -> Optional[ManifestAnalysis]:
        """Analyze AndroidManifest.xml for security issues."""
        try:
            manifest_path = self._get_manifest_path(apk_ctx)
            if not manifest_path or not os.path.exists(manifest_path):
                self.logger.warning("AndroidManifest.xml not found")
                return None
            
            # Parse manifest
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Extract basic information
            package_name = root.get('package', 'unknown')
            
            # Analyze components
            activities = self._analyze_activities(root)
            services = self._analyze_services(root)
            receivers = self._analyze_receivers(root)
            providers = self._analyze_providers(root)
            
            # Analyze permissions
            permissions = self._analyze_permissions(root)
            dangerous_permissions = self._identify_dangerous_permissions(permissions)
            
            # Analyze security features
            security_features = self._analyze_security_features(root)
            
            # Identify exported components
            exported_components = self._identify_exported_components(
                activities, services, receivers, providers
            )
            
            # Get SDK versions
            target_sdk = self._get_target_sdk(root)
            min_sdk = self._get_min_sdk(root)
            
            return ManifestAnalysis(
                package_name=package_name,
                target_sdk_version=target_sdk,  # Fixed parameter name
                min_sdk_version=min_sdk,        # Fixed parameter name
                permissions=permissions,
                activities=activities,
                services=services,
                receivers=receivers,
                providers=providers,
                security_features=security_features,
                exported_components=exported_components,
                dangerous_permissions=dangerous_permissions
            )
            
        except ET.ParseError as e:
            self.logger.error(f"Failed to parse AndroidManifest.xml: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Manifest analysis failed: {e}")
            return None
    
    def _get_manifest_path(self, apk_ctx: APKContext) -> Optional[str]:
        """Get path to AndroidManifest.xml."""
        # Try to get from APK context
        if hasattr(apk_ctx, 'manifest_path'):
            return apk_ctx.manifest_path
        
        # Try to construct from extraction path
        extraction_path = self._get_extraction_path(apk_ctx)
        if extraction_path:
            manifest_path = os.path.join(extraction_path, 'AndroidManifest.xml')
            if os.path.exists(manifest_path):
                return manifest_path
        
        return None
    
    def _get_extraction_path(self, apk_ctx: APKContext) -> Optional[str]:
        """Get APK extraction path."""
        if hasattr(apk_ctx, 'extraction_path'):
            return apk_ctx.extraction_path
        
        # Try to construct from APK path
        if apk_ctx.apk_path:
            apk_name = os.path.basename(apk_ctx.apk_path).replace('.apk', '')
            extraction_path = os.path.join(os.path.dirname(apk_ctx.apk_path), f"{apk_name}_extracted")
            if os.path.exists(extraction_path):
                return extraction_path
        
        return None
    
    def _analyze_activities(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Analyze activity components."""
        activities = []
        
        for activity in root.findall('.//activity'):
            activity_info = {
                'name': activity.get('{http://schemas.android.com/apk/res/android}name', 'unknown'),
                'exported': self._is_exported(activity),
                'permissions': self._get_component_permissions(activity),
                'intent_filters': self._get_intent_filters(activity),
                'launch_mode': activity.get('{http://schemas.android.com/apk/res/android}launchMode'),
                'task_affinity': activity.get('{http://schemas.android.com/apk/res/android}taskAffinity')
            }
            activities.append(activity_info)
        
        return activities
    
    def _analyze_services(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Analyze service components."""
        services = []
        
        for service in root.findall('.//service'):
            service_info = {
                'name': service.get('{http://schemas.android.com/apk/res/android}name', 'unknown'),
                'exported': self._is_exported(service),
                'permissions': self._get_component_permissions(service),
                'intent_filters': self._get_intent_filters(service),
                'process': service.get('{http://schemas.android.com/apk/res/android}process'),
                'isolated': service.get('{http://schemas.android.com/apk/res/android}isolatedProcess') == 'true'
            }
            services.append(service_info)
        
        return services
    
    def _analyze_receivers(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Analyze broadcast receiver components."""
        receivers = []
        
        for receiver in root.findall('.//receiver'):
            receiver_info = {
                'name': receiver.get('{http://schemas.android.com/apk/res/android}name', 'unknown'),
                'exported': self._is_exported(receiver),
                'permissions': self._get_component_permissions(receiver),
                'intent_filters': self._get_intent_filters(receiver),
                'priority': receiver.get('{http://schemas.android.com/apk/res/android}priority')
            }
            receivers.append(receiver_info)
        
        return receivers
    
    def _analyze_providers(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Analyze content provider components."""
        providers = []
        
        for provider in root.findall('.//provider'):
            provider_info = {
                'name': provider.get('{http://schemas.android.com/apk/res/android}name', 'unknown'),
                'exported': self._is_exported(provider),
                'permissions': self._get_component_permissions(provider),
                'authorities': provider.get('{http://schemas.android.com/apk/res/android}authorities'),
                'grant_uri_permissions': provider.get('{http://schemas.android.com/apk/res/android}grantUriPermissions') == 'true'
            }
            providers.append(provider_info)
        
        return providers
    
    def _analyze_permissions(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Analyze declared permissions."""
        permissions = []
        
        for permission in root.findall('.//uses-permission'):
            perm_info = {
                'name': permission.get('{http://schemas.android.com/apk/res/android}name', 'unknown'),
                'max_sdk_version': permission.get('{http://schemas.android.com/apk/res/android}maxSdkVersion'),
                'type': 'uses-permission'
            }
            permissions.append(perm_info)
        
        # Also check for permission definitions
        for permission in root.findall('.//permission'):
            perm_info = {
                'name': permission.get('{http://schemas.android.com/apk/res/android}name', 'unknown'),
                'protection_level': permission.get('{http://schemas.android.com/apk/res/android}protectionLevel'),
                'label': permission.get('{http://schemas.android.com/apk/res/android}label'),
                'description': permission.get('{http://schemas.android.com/apk/res/android}description'),
                'type': 'permission'
            }
            permissions.append(perm_info)
        
        return permissions
    
    def _analyze_security_features(self, root: ET.Element) -> Dict[str, Any]:
        """Analyze security-related features."""
        security_features = {}
        
        # Check application attributes
        app_element = root.find('.//application')
        if app_element is not None:
            security_features['debuggable'] = app_element.get(
                '{http://schemas.android.com/apk/res/android}debuggable'
            ) == 'true'
            
            security_features['allow_backup'] = app_element.get(
                '{http://schemas.android.com/apk/res/android}allowBackup'
            ) != 'false'
            
            security_features['uses_cleartext_traffic'] = app_element.get(
                '{http://schemas.android.com/apk/res/android}usesCleartextTraffic'
            ) == 'true'
            
            security_features['network_security_config'] = app_element.get(
                '{http://schemas.android.com/apk/res/android}networkSecurityConfig'
            )
        
        # Check SDK versions
        uses_sdk = root.find('.//uses-sdk')
        if uses_sdk is not None:
            security_features['target_sdk'] = uses_sdk.get(
                '{http://schemas.android.com/apk/res/android}targetSdkVersion'
            )
            security_features['min_sdk'] = uses_sdk.get(
                '{http://schemas.android.com/apk/res/android}minSdkVersion'
            )
        
        return security_features
    
    def _is_exported(self, component: ET.Element) -> bool:
        """Check if component is exported."""
        exported = component.get('{http://schemas.android.com/apk/res/android}exported')
        
        if exported is not None:
            return exported == 'true'
        
        # If not explicitly set, check for intent filters
        intent_filters = component.findall('.//intent-filter')
        return len(intent_filters) > 0
    
    def _get_component_permissions(self, component: ET.Element) -> List[str]:
        """Get permissions required for component."""
        permissions = []
        
        permission = component.get('{http://schemas.android.com/apk/res/android}permission')
        if permission:
            permissions.append(permission)
        
        return permissions
    
    def _get_intent_filters(self, component: ET.Element) -> List[Dict[str, Any]]:
        """Get intent filters for component."""
        filters = []
        
        for intent_filter in component.findall('.//intent-filter'):
            filter_info = {
                'actions': [action.get('{http://schemas.android.com/apk/res/android}name') 
                           for action in intent_filter.findall('.//action')],
                'categories': [category.get('{http://schemas.android.com/apk/res/android}name') 
                              for category in intent_filter.findall('.//category')],
                'data': [self._get_data_info(data) for data in intent_filter.findall('.//data')]
            }
            filters.append(filter_info)
        
        return filters
    
    def _get_data_info(self, data: ET.Element) -> Dict[str, Any]:
        """Get data information from intent filter."""
        return {
            'scheme': data.get('{http://schemas.android.com/apk/res/android}scheme'),
            'host': data.get('{http://schemas.android.com/apk/res/android}host'),
            'path': data.get('{http://schemas.android.com/apk/res/android}path'),
            'mime_type': data.get('{http://schemas.android.com/apk/res/android}mimeType')
        }
    
    def _identify_dangerous_permissions(self, permissions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify dangerous permissions."""
        dangerous_permission_patterns = [
            'CAMERA', 'LOCATION', 'RECORD_AUDIO', 'READ_SMS', 'SEND_SMS',
            'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_PHONE_STATE',
            'CALL_PHONE', 'READ_CALL_LOG', 'WRITE_CALL_LOG',
            'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
            'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
            'RECORD_AUDIO', 'READ_CALENDAR', 'WRITE_CALENDAR'
        ]
        
        dangerous_permissions = []
        for perm in permissions:
            perm_name = perm.get('name', '')
            if any(pattern in perm_name for pattern in dangerous_permission_patterns):
                dangerous_permissions.append(perm)
        
        return dangerous_permissions
    
    def _identify_exported_components(self, activities: List[Dict[str, Any]], 
                                    services: List[Dict[str, Any]], 
                                    receivers: List[Dict[str, Any]], 
                                    providers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify exported components."""
        exported_components = []
        
        for activity in activities:
            if activity.get('exported', False):
                exported_components.append({
                    'name': activity['name'],
                    'type': 'activity',
                    'permissions': activity.get('permissions', []),
                    'intent_filters': activity.get('intent_filters', [])
                })
        
        for service in services:
            if service.get('exported', False):
                exported_components.append({
                    'name': service['name'],
                    'type': 'service',
                    'permissions': service.get('permissions', []),
                    'intent_filters': service.get('intent_filters', [])
                })
        
        for receiver in receivers:
            if receiver.get('exported', False):
                exported_components.append({
                    'name': receiver['name'],
                    'type': 'receiver',
                    'permissions': receiver.get('permissions', []),
                    'intent_filters': receiver.get('intent_filters', [])
                })
        
        for provider in providers:
            if provider.get('exported', False):
                exported_components.append({
                    'name': provider['name'],
                    'type': 'provider',
                    'permissions': provider.get('permissions', []),
                    'authorities': provider.get('authorities')
                })
        
        return exported_components
    
    def _get_target_sdk(self, root: ET.Element) -> Optional[int]:
        """Get target SDK version."""
        uses_sdk = root.find('.//uses-sdk')
        if uses_sdk is not None:
            target_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion')
            if target_sdk:
                try:
                    return int(target_sdk)
                except ValueError:
                    pass
        return None
    
    def _get_min_sdk(self, root: ET.Element) -> Optional[int]:
        """Get minimum SDK version."""
        uses_sdk = root.find('.//uses-sdk')
        if uses_sdk is not None:
            min_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion')
            if min_sdk:
                try:
                    return int(min_sdk)
                except ValueError:
                    pass
        return None 