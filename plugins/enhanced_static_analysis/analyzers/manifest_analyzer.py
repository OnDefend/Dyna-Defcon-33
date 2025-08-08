"""
Manifest Analysis Engine

This module handles processing and analysis of AndroidManifest.xml analysis results.
"""

import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class ManifestAnalysisEngine:
    """
    Engine for processing AndroidManifest.xml analysis results.
    
    Provides enhanced processing, risk assessment, and security analysis of manifest data.
    """
    
    def __init__(self):
        """Initialize the manifest analysis engine."""
        self.dangerous_permissions = {
            'android.permission.CAMERA': 'HIGH',
            'android.permission.RECORD_AUDIO': 'HIGH',
            'android.permission.ACCESS_FINE_LOCATION': 'HIGH',
            'android.permission.ACCESS_COARSE_LOCATION': 'MEDIUM',
            'android.permission.READ_CONTACTS': 'HIGH',
            'android.permission.WRITE_CONTACTS': 'HIGH',
            'android.permission.READ_SMS': 'HIGH',
            'android.permission.SEND_SMS': 'HIGH',
            'android.permission.READ_PHONE_STATE': 'MEDIUM',
            'android.permission.CALL_PHONE': 'MEDIUM',
            'android.permission.WRITE_EXTERNAL_STORAGE': 'MEDIUM',
            'android.permission.READ_EXTERNAL_STORAGE': 'MEDIUM',
            'android.permission.SYSTEM_ALERT_WINDOW': 'HIGH',
            'android.permission.WRITE_SETTINGS': 'MEDIUM',
            'android.permission.INSTALL_PACKAGES': 'CRITICAL',
            'android.permission.DELETE_PACKAGES': 'CRITICAL',
            'android.permission.BIND_DEVICE_ADMIN': 'HIGH',
            'android.permission.BIND_ACCESSIBILITY_SERVICE': 'HIGH'
        }
        
        self.security_flags = {
            'debuggable': 'Enable debugging in production builds',
            'allow_backup': 'Allow application data backup',
            'uses_cleartext_traffic': 'Allow cleartext network traffic',
            'test_only': 'Application marked as test-only',
            'extract_native_libs': 'Extract native libraries'
        }
    
    def process_manifest_analysis(self, manifest_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process manifest analysis results with enhanced security assessment.
        
        Args:
            manifest_data: Raw manifest analysis results
            
        Returns:
            Dict[str, Any]: Processed manifest analysis results
        """
        if not manifest_data or 'error' in manifest_data:
            logger.warning("Manifest analysis data is empty or contains errors")
            return manifest_data
        
        logger.info("Processing AndroidManifest.xml analysis results")
        
        # Enhanced manifest analysis
        enhanced_manifest = {
            'original_data': manifest_data,
            'security_assessment': self._perform_security_assessment(manifest_data),
            'permission_analysis': self._analyze_permissions(manifest_data),
            'component_analysis': self._analyze_components(manifest_data),
            'security_features': self._analyze_security_features(manifest_data),
            'risk_assessment': {},
            'recommendations': []
        }
        
        # Calculate overall risk assessment
        enhanced_manifest['risk_assessment'] = self._calculate_manifest_risk(enhanced_manifest)
        
        # Generate security recommendations
        enhanced_manifest['recommendations'] = self._generate_security_recommendations(enhanced_manifest)
        
        logger.info("Manifest analysis processing completed successfully")
        return enhanced_manifest
    
    def _perform_security_assessment(self, manifest_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive security assessment of manifest.
        
        Args:
            manifest_data: Manifest analysis data
            
        Returns:
            Dict[str, Any]: Security assessment results
        """
        assessment = {
            'security_score': 0.0,
            'critical_issues': [],
            'high_issues': [],
            'medium_issues': [],
            'low_issues': [],
            'positive_findings': []
        }
        
        # Check security features
        security_features = manifest_data.get('security_features', {})
        
        # Check for debuggable flag
        if security_features.get('debuggable', False):
            assessment['critical_issues'].append({
                'type': 'debuggable_enabled',
                'description': 'Application is debuggable in production',
                'risk_level': 'CRITICAL',
                'impact': 'Allows attackers to debug and reverse engineer the application'
            })
        else:
            assessment['positive_findings'].append('Application is not debuggable')
        
        # Check backup settings
        if security_features.get('allow_backup', True):
            assessment['medium_issues'].append({
                'type': 'backup_enabled',
                'description': 'Application allows backup of data',
                'risk_level': 'MEDIUM',
                'impact': 'Sensitive data may be exposed through backup mechanisms'
            })
        else:
            assessment['positive_findings'].append('Application backup is disabled')
        
        # Check cleartext traffic
        cleartext_traffic = security_features.get('uses_cleartext_traffic')
        if cleartext_traffic is True:
            assessment['high_issues'].append({
                'type': 'cleartext_traffic',
                'description': 'Application explicitly allows cleartext traffic',
                'risk_level': 'HIGH',
                'impact': 'Network communications may be intercepted'
            })
        elif cleartext_traffic is False:
            assessment['positive_findings'].append('Cleartext traffic is disabled')
        
        # Check target SDK version
        target_sdk = security_features.get('target_sdk')
        if target_sdk:
            if target_sdk < 23:
                assessment['high_issues'].append({
                    'type': 'outdated_target_sdk',
                    'description': f'Target SDK version {target_sdk} is outdated',
                    'risk_level': 'HIGH',
                    'impact': 'Missing modern security features and protections'
                })
            elif target_sdk < 28:
                assessment['medium_issues'].append({
                    'type': 'older_target_sdk',
                    'description': f'Target SDK version {target_sdk} is older',
                    'risk_level': 'MEDIUM',
                    'impact': 'Some security features may not be available'
                })
            else:
                assessment['positive_findings'].append(f'Target SDK version {target_sdk} is modern')
        
        # Calculate security score
        assessment['security_score'] = self._calculate_security_score(assessment)
        
        return assessment
    
    def _analyze_permissions(self, manifest_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze application permissions for security risks.
        
        Args:
            manifest_data: Manifest analysis data
            
        Returns:
            Dict[str, Any]: Permission analysis results
        """
        permissions = manifest_data.get('permissions', [])
        
        analysis = {
            'total_permissions': len(permissions),
            'dangerous_permissions': [],
            'normal_permissions': [],
            'signature_permissions': [],
            'unknown_permissions': [],
            'permission_risk_score': 0.0,
            'overprivileged_assessment': {}
        }
        
        for permission in permissions:
            perm_name = permission.get('name', '')
            perm_level = permission.get('protection_level', 'normal')
            
            # Categorize permission
            if perm_name in self.dangerous_permissions:
                risk_level = self.dangerous_permissions[perm_name]
                analysis['dangerous_permissions'].append({
                    'name': perm_name,
                    'risk_level': risk_level,
                    'description': self._get_permission_description(perm_name),
                    'justification_needed': True
                })
            elif perm_level == 'dangerous':
                analysis['dangerous_permissions'].append({
                    'name': perm_name,
                    'risk_level': 'MEDIUM',
                    'description': self._get_permission_description(perm_name),
                    'justification_needed': True
                })
            elif perm_level == 'signature':
                analysis['signature_permissions'].append({
                    'name': perm_name,
                    'risk_level': 'LOW',
                    'description': self._get_permission_description(perm_name)
                })
            elif perm_level == 'normal':
                analysis['normal_permissions'].append({
                    'name': perm_name,
                    'risk_level': 'LOW',
                    'description': self._get_permission_description(perm_name)
                })
            else:
                analysis['unknown_permissions'].append({
                    'name': perm_name,
                    'risk_level': 'UNKNOWN',
                    'description': 'Unknown permission'
                })
        
        # Calculate permission risk score
        analysis['permission_risk_score'] = self._calculate_permission_risk_score(analysis)
        
        # Assess overprivileged status
        analysis['overprivileged_assessment'] = self._assess_overprivileged(analysis)
        
        return analysis
    
    def _analyze_components(self, manifest_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze application components for security risks.
        
        Args:
            manifest_data: Manifest analysis data
            
        Returns:
            Dict[str, Any]: Component analysis results
        """
        analysis = {
            'activities': self._analyze_component_type(manifest_data.get('activities', []), 'activity'),
            'services': self._analyze_component_type(manifest_data.get('services', []), 'service'),
            'receivers': self._analyze_component_type(manifest_data.get('receivers', []), 'receiver'),
            'providers': self._analyze_component_type(manifest_data.get('providers', []), 'provider'),
            'exported_components': [],
            'vulnerable_components': [],
            'component_risk_score': 0.0
        }
        
        # Find exported components
        for component_type in ['activities', 'services', 'receivers', 'providers']:
            components = manifest_data.get(component_type, [])
            for component in components:
                if component.get('exported', False):
                    analysis['exported_components'].append({
                        'type': component_type[:-1],  # Remove 's' from plural
                        'name': component.get('name', 'Unknown'),
                        'risk_level': self._assess_component_export_risk(component, component_type),
                        'has_intent_filter': bool(component.get('intent_filters', [])),
                        'permissions': component.get('permissions', [])
                    })
        
        # Assess vulnerable components
        analysis['vulnerable_components'] = self._find_vulnerable_components(analysis)
        
        # Calculate component risk score
        analysis['component_risk_score'] = self._calculate_component_risk_score(analysis)
        
        return analysis
    
    def _analyze_security_features(self, manifest_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security features and configurations.
        
        Args:
            manifest_data: Manifest analysis data
            
        Returns:
            Dict[str, Any]: Security features analysis
        """
        security_features = manifest_data.get('security_features', {})
        
        analysis = {
            'security_config': {},
            'network_security': {},
            'app_security': {},
            'development_features': {},
            'recommendations': []
        }
        
        # Analyze security configuration
        analysis['security_config'] = {
            'debuggable': security_features.get('debuggable', False),
            'allow_backup': security_features.get('allow_backup', True),
            'uses_cleartext_traffic': security_features.get('uses_cleartext_traffic'),
            'test_only': security_features.get('test_only', False),
            'extract_native_libs': security_features.get('extract_native_libs', True)
        }
        
        # Analyze network security
        network_config = security_features.get('network_security_config', {})
        analysis['network_security'] = {
            'has_network_security_config': bool(network_config),
            'cleartext_traffic_permitted': network_config.get('cleartextTrafficPermitted', True),
            'certificate_pinning': network_config.get('certificatePinning', False),
            'trust_anchors': network_config.get('trustAnchors', [])
        }
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_security_feature_recommendations(analysis)
        
        return analysis
    
    def _calculate_manifest_risk(self, enhanced_manifest: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate overall manifest risk assessment.
        
        Args:
            enhanced_manifest: Enhanced manifest analysis data
            
        Returns:
            Dict[str, Any]: Risk assessment results
        """
        security_assessment = enhanced_manifest.get('security_assessment', {})
        permission_analysis = enhanced_manifest.get('permission_analysis', {})
        component_analysis = enhanced_manifest.get('component_analysis', {})
        
        # Count issues by severity
        critical_count = len(security_assessment.get('critical_issues', []))
        high_count = len(security_assessment.get('high_issues', []))
        medium_count = len(security_assessment.get('medium_issues', []))
        low_count = len(security_assessment.get('low_issues', []))
        
        # Factor in permissions and components
        dangerous_perms = len(permission_analysis.get('dangerous_permissions', []))
        exported_components = len(component_analysis.get('exported_components', []))
        
        # Calculate risk score
        risk_score = (
            critical_count * 0.4 +
            high_count * 0.3 +
            medium_count * 0.2 +
            low_count * 0.1 +
            dangerous_perms * 0.1 +
            exported_components * 0.05
        )
        
        # Normalize risk score
        risk_score = min(1.0, risk_score / 5.0)
        
        # Determine risk level
        if risk_score >= 0.8 or critical_count > 0:
            risk_level = 'CRITICAL'
        elif risk_score >= 0.6 or high_count > 2:
            risk_level = 'HIGH'
        elif risk_score >= 0.4 or medium_count > 3:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'critical_issues': critical_count,
            'high_issues': high_count,
            'medium_issues': medium_count,
            'low_issues': low_count,
            'dangerous_permissions': dangerous_perms,
            'exported_components': exported_components,
            'total_issues': critical_count + high_count + medium_count + low_count
        }
    
    def _generate_security_recommendations(self, enhanced_manifest: Dict[str, Any]) -> List[str]:
        """
        Generate security recommendations based on manifest analysis.
        
        Args:
            enhanced_manifest: Enhanced manifest analysis data
            
        Returns:
            List[str]: Security recommendations
        """
        recommendations = []
        
        security_assessment = enhanced_manifest.get('security_assessment', {})
        permission_analysis = enhanced_manifest.get('permission_analysis', {})
        component_analysis = enhanced_manifest.get('component_analysis', {})
        
        # Security configuration recommendations
        for issue in security_assessment.get('critical_issues', []):
            if issue['type'] == 'debuggable_enabled':
                recommendations.append("Disable debuggable flag for production builds")
        
        for issue in security_assessment.get('high_issues', []):
            if issue['type'] == 'cleartext_traffic':
                recommendations.append("Disable cleartext traffic and use HTTPS only")
            elif issue['type'] == 'outdated_target_sdk':
                recommendations.append("Update target SDK to latest version")
        
        # Permission recommendations
        dangerous_perms = permission_analysis.get('dangerous_permissions', [])
        if dangerous_perms:
            recommendations.append(f"Review and justify {len(dangerous_perms)} dangerous permissions")
        
        # Component recommendations
        exported_components = component_analysis.get('exported_components', [])
        if exported_components:
            recommendations.append(f"Review {len(exported_components)} exported components for security risks")
        
        # General recommendations
        recommendations.extend([
            "Implement proper input validation for all components",
            "Use secure coding practices for all development",
            "Regularly update security configurations",
            "Implement proper error handling and logging",
            "Use obfuscation and anti-tampering measures"
        ])
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    # Helper methods
    def _calculate_security_score(self, assessment: Dict[str, Any]) -> float:
        """Calculate security score based on assessment."""
        critical_count = len(assessment.get('critical_issues', []))
        high_count = len(assessment.get('high_issues', []))
        medium_count = len(assessment.get('medium_issues', []))
        positive_count = len(assessment.get('positive_findings', []))
        
        # Calculate score (0.0 to 1.0, higher is better)
        penalty = critical_count * 0.4 + high_count * 0.2 + medium_count * 0.1
        bonus = positive_count * 0.1
        
        score = max(0.0, 1.0 - penalty + bonus)
        return min(1.0, score)
    
    def _get_permission_description(self, permission_name: str) -> str:
        """Get description for a permission."""
        descriptions = {
            'android.permission.CAMERA': 'Access camera hardware',
            'android.permission.RECORD_AUDIO': 'Record audio',
            'android.permission.ACCESS_FINE_LOCATION': 'Access precise location',
            'android.permission.ACCESS_COARSE_LOCATION': 'Access approximate location',
            'android.permission.READ_CONTACTS': 'Read contact data',
            'android.permission.WRITE_CONTACTS': 'Write contact data',
            'android.permission.READ_SMS': 'Read SMS messages',
            'android.permission.SEND_SMS': 'Send SMS messages',
            'android.permission.READ_PHONE_STATE': 'Read phone state',
            'android.permission.CALL_PHONE': 'Make phone calls',
            'android.permission.WRITE_EXTERNAL_STORAGE': 'Write external storage',
            'android.permission.READ_EXTERNAL_STORAGE': 'Read external storage',
            'android.permission.SYSTEM_ALERT_WINDOW': 'Display system alert windows',
            'android.permission.WRITE_SETTINGS': 'Write system settings',
            'android.permission.INSTALL_PACKAGES': 'Install packages',
            'android.permission.DELETE_PACKAGES': 'Delete packages',
            'android.permission.BIND_DEVICE_ADMIN': 'Bind device admin',
            'android.permission.BIND_ACCESSIBILITY_SERVICE': 'Bind accessibility service'
        }
        return descriptions.get(permission_name, 'Unknown permission')
    
    def _calculate_permission_risk_score(self, analysis: Dict[str, Any]) -> float:
        """Calculate risk score based on permissions."""
        dangerous_count = len(analysis.get('dangerous_permissions', []))
        total_count = analysis.get('total_permissions', 1)
        
        # Calculate risk ratio
        risk_ratio = dangerous_count / total_count
        
        # Apply weighting based on specific dangerous permissions
        weight_factor = 1.0
        for perm in analysis.get('dangerous_permissions', []):
            if perm['risk_level'] == 'CRITICAL':
                weight_factor += 0.5
            elif perm['risk_level'] == 'HIGH':
                weight_factor += 0.3
        
        return min(1.0, risk_ratio * weight_factor)
    
    def _assess_overprivileged(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Assess if application is overprivileged."""
        dangerous_count = len(analysis.get('dangerous_permissions', []))
        
        if dangerous_count > 10:
            return {
                'status': 'HIGH_RISK',
                'reason': f'Application requests {dangerous_count} dangerous permissions',
                'recommendation': 'Review and reduce permission requests'
            }
        elif dangerous_count > 5:
            return {
                'status': 'MEDIUM_RISK',
                'reason': f'Application requests {dangerous_count} dangerous permissions',
                'recommendation': 'Consider reducing permission requests'
            }
        else:
            return {
                'status': 'LOW_RISK',
                'reason': f'Application requests {dangerous_count} dangerous permissions',
                'recommendation': 'Permission usage appears reasonable'
            }
    
    def _analyze_component_type(self, components: List[Dict], component_type: str) -> Dict[str, Any]:
        """Analyze a specific component type."""
        analysis = {
            'total_count': len(components),
            'exported_count': 0,
            'with_intent_filters': 0,
            'with_permissions': 0,
            'components': []
        }
        
        for component in components:
            comp_analysis = {
                'name': component.get('name', 'Unknown'),
                'exported': component.get('exported', False),
                'has_intent_filters': bool(component.get('intent_filters', [])),
                'permissions': component.get('permissions', []),
                'risk_level': 'LOW'
            }
            
            if comp_analysis['exported']:
                analysis['exported_count'] += 1
                comp_analysis['risk_level'] = 'MEDIUM'
            
            if comp_analysis['has_intent_filters']:
                analysis['with_intent_filters'] += 1
            
            if comp_analysis['permissions']:
                analysis['with_permissions'] += 1
            
            analysis['components'].append(comp_analysis)
        
        return analysis
    
    def _assess_component_export_risk(self, component: Dict, component_type: str) -> str:
        """Assess risk level for exported component."""
        has_intent_filters = bool(component.get('intent_filters', []))
        has_permissions = bool(component.get('permissions', []))
        
        if component_type == 'providers' and not has_permissions:
            return 'HIGH'
        elif component_type == 'services' and has_intent_filters:
            return 'HIGH'
        elif has_intent_filters and not has_permissions:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _find_vulnerable_components(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find potentially vulnerable components."""
        vulnerable = []
        
        # Check exported components without proper protection
        for comp in analysis.get('exported_components', []):
            if comp['risk_level'] == 'HIGH':
                vulnerable.append({
                    'component': comp,
                    'vulnerability': 'Exported component without proper protection',
                    'risk_level': 'HIGH'
                })
        
        return vulnerable
    
    def _calculate_component_risk_score(self, analysis: Dict[str, Any]) -> float:
        """Calculate risk score for components."""
        exported_count = len(analysis.get('exported_components', []))
        vulnerable_count = len(analysis.get('vulnerable_components', []))
        
        # Calculate risk based on exported and vulnerable components
        risk_score = (exported_count * 0.1) + (vulnerable_count * 0.3)
        
        return min(1.0, risk_score)
    
    def _generate_security_feature_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations for security features."""
        recommendations = []
        
        security_config = analysis.get('security_config', {})
        network_security = analysis.get('network_security', {})
        
        if security_config.get('debuggable', False):
            recommendations.append("Disable debuggable flag for production")
        
        if security_config.get('allow_backup', True):
            recommendations.append("Consider disabling backup for sensitive apps")
        
        if security_config.get('uses_cleartext_traffic', True):
            recommendations.append("Disable cleartext traffic")
        
        if not network_security.get('has_network_security_config', False):
            recommendations.append("Implement network security configuration")
        
        return recommendations 