#!/usr/bin/env python3
"""
Manifest Analyzer for Improper Platform Usage Analysis

This module provides comprehensive AndroidManifest.xml parsing and security analysis
for the improper platform usage plugin.

Features:
- Complete XML parsing and validation
- Component extraction and analysis
- Permission analysis
- Security flag assessment
- Deep link extraction
- error handling

"""

import logging
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import yaml

from core.shared_infrastructure.analysis_exceptions import AnalysisError
from core.shared_infrastructure.dependency_injection import AnalysisContext
from .data_structures import (
    ManifestSecurityAnalysis, ComponentAnalysis, PermissionAnalysis, 
    DeepLinkAnalysis, ComponentType, ProtectionLevel, RiskLevel,
    IntentFilterAnalysis, VulnerabilitySeverity
)
from .confidence_calculator import PlatformUsageConfidenceCalculator

logger = logging.getLogger(__name__)

class ManifestAnalyzer:
    """
    Comprehensive AndroidManifest.xml analyzer for security assessment.
    
    Provides enterprise-grade manifest parsing and security analysis including
    component extraction, permission analysis, and security configuration assessment.
    """
    
    def __init__(self, context: AnalysisContext, confidence_calculator: PlatformUsageConfidenceCalculator):
        """
        Initialize manifest analyzer.
        
        Args:
            context: Analysis context with dependency injection
            confidence_calculator: confidence calculator
        """
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = context.logger if hasattr(context, 'logger') else logger
        
        # Load configuration
        self.config = self._load_configuration()
        
        # Dangerous permissions from configuration
        self.dangerous_permissions = {
            perm['name']: perm for perm in self.config.get('dangerous_permissions', [])
        }
        
        # High-risk intent actions
        self.high_risk_actions = {
            action['action']: action for action in self.config.get('high_risk_intent_actions', [])
        }
        
        # Sensitive schemes
        self.sensitive_schemes = {
            scheme['scheme']: scheme for scheme in self.config.get('sensitive_schemes', [])
        }
        
        self.logger.info("Manifest analyzer initialized")
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load configuration from external YAML file."""
        try:
            config_path = Path(__file__).parent / 'platform_patterns_config.yaml'
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f)
            else:
                self.logger.warning(f"Configuration file not found: {config_path}")
                return {}
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            return {}
    
    def analyze_manifest(self, apk_ctx) -> ManifestSecurityAnalysis:
        """
        Perform comprehensive manifest security analysis.
        
        Args:
            apk_ctx: APK context containing manifest information
            
        Returns:
            Complete manifest security analysis results
        """
        try:
            self.logger.info("Starting comprehensive manifest analysis")
            
            # Get manifest path
            manifest_path = self._get_manifest_path(apk_ctx)
            if not manifest_path:
                raise AnalysisError("AndroidManifest.xml not found or accessible")
            
            # Parse XML
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Extract basic information
            target_sdk = self._extract_target_sdk(root)
            min_sdk = self._extract_min_sdk(root)
            compile_sdk = self._extract_compile_sdk(root)
            
            # Extract and analyze permissions
            permissions_declared = self._analyze_permissions(root)
            custom_permissions = self._extract_custom_permissions(root)
            
            # Extract and analyze components
            components = self._analyze_components(root)
            
            # Extract security flags
            security_flags = self._extract_security_flags(root)
            
            # Extract and analyze deep links
            deep_links = self._analyze_deep_links(root, components)
            
            # Calculate overall risk level
            overall_risk_level = self._calculate_overall_risk(components, permissions_declared, deep_links)
            
            # Create analysis result
            analysis = ManifestSecurityAnalysis(
                target_sdk=target_sdk,
                min_sdk=min_sdk,
                compile_sdk=compile_sdk,
                permissions_declared=permissions_declared,
                custom_permissions=custom_permissions,
                components=components,
                security_flags=security_flags,
                deep_links=deep_links,
                vulnerabilities=[],  # Will be populated by vulnerability analyzers
                overall_risk_level=overall_risk_level,
                analysis_metadata={
                    "manifest_path": str(manifest_path),
                    "xml_valid": True,
                    "parsing_method": "ElementTree"
                }
            )
            
            self.logger.info(f"Manifest analysis completed. Found {len(components)} components, "
                           f"{len(permissions_declared)} permissions, {len(deep_links)} deep links")
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Manifest analysis failed: {e}")
            raise AnalysisError(f"Manifest analysis failed: {e}") from e
    
    def _get_manifest_path(self, apk_ctx) -> Optional[Path]:
        """Get path to AndroidManifest.xml."""
        try:
            # Try to get from APK context
            if hasattr(apk_ctx, 'manifest_path') and apk_ctx.manifest_path:
                manifest_path = Path(apk_ctx.manifest_path)
                if manifest_path.exists():
                    return manifest_path
            
            # Try to extract from APK
            if hasattr(apk_ctx, 'apk_path'):
                return self._extract_manifest_from_apk(apk_ctx.apk_path)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get manifest path: {e}")
            return None
    
    def _extract_manifest_from_apk(self, apk_path: str) -> Optional[Path]:
        """Extract AndroidManifest.xml from APK file."""
        try:
            apk_path = Path(apk_path)
            if not apk_path.exists():
                return None
            
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Check if AndroidManifest.xml exists
                if 'AndroidManifest.xml' not in apk_zip.namelist():
                    return None
                
                # Extract to temporary location
                temp_dir = apk_path.parent / f"{apk_path.stem}_temp"
                temp_dir.mkdir(exist_ok=True)
                
                manifest_path = temp_dir / "AndroidManifest.xml"
                with apk_zip.open('AndroidManifest.xml') as manifest_file:
                    with open(manifest_path, 'wb') as output_file:
                        output_file.write(manifest_file.read())
                
                return manifest_path
                
        except Exception as e:
            self.logger.error(f"Failed to extract manifest from APK: {e}")
            return None
    
    def _extract_target_sdk(self, root: ET.Element) -> int:
        """Extract target SDK version."""
        try:
            uses_sdk = root.find('.//uses-sdk')
            if uses_sdk is not None:
                target_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion')
                if target_sdk:
                    return int(target_sdk)
            
            # Try alternative locations
            application = root.find('.//application')
            if application is not None:
                target_sdk = application.get('{http://schemas.android.com/apk/res/android}targetSdkVersion')
                if target_sdk:
                    return int(target_sdk)
            
            return 0  # Unknown
            
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Failed to extract target SDK: {e}")
            return 0
    
    def _extract_min_sdk(self, root: ET.Element) -> int:
        """Extract minimum SDK version."""
        try:
            uses_sdk = root.find('.//uses-sdk')
            if uses_sdk is not None:
                min_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion')
                if min_sdk:
                    return int(min_sdk)
            
            return 0  # Unknown
            
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Failed to extract min SDK: {e}")
            return 0
    
    def _extract_compile_sdk(self, root: ET.Element) -> int:
        """Extract compile SDK version."""
        try:
            compile_sdk = root.get('{http://schemas.android.com/apk/res/android}compileSdkVersion')
            if compile_sdk:
                return int(compile_sdk)
            
            return 0  # Unknown
            
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Failed to extract compile SDK: {e}")
            return 0
    
    def _analyze_permissions(self, root: ET.Element) -> List[PermissionAnalysis]:
        """Analyze declared permissions."""
        permissions = []
        
        try:
            for uses_permission in root.findall('.//uses-permission'):
                permission_name = uses_permission.get('{http://schemas.android.com/apk/res/android}name')
                if not permission_name:
                    continue
                
                # Analyze permission
                perm_config = self.dangerous_permissions.get(permission_name, {})
                is_dangerous = bool(perm_config)
                protection_level = perm_config.get('risk_level', 'NORMAL')
                common_misuse = perm_config.get('common_misuse', [])
                
                permission_analysis = PermissionAnalysis(
                    permission_name=permission_name,
                    protection_level=protection_level,
                    is_dangerous=is_dangerous,
                    is_custom=not permission_name.startswith('android.permission.'),
                    potential_misuse=common_misuse,
                    recommendations=self._get_permission_recommendations(permission_name, is_dangerous)
                )
                
                permissions.append(permission_analysis)
            
            self.logger.debug(f"Analyzed {len(permissions)} permissions")
            return permissions
            
        except Exception as e:
            self.logger.error(f"Permission analysis failed: {e}")
            return []
    
    def _get_permission_recommendations(self, permission_name: str, is_dangerous: bool) -> List[str]:
        """Get security recommendations for permission usage."""
        recommendations = []
        
        if is_dangerous:
            recommendations.append("Implement runtime permission requests for Android 6.0+")
            recommendations.append("Provide clear justification to users")
            recommendations.append("Use least privilege principle")
        
        if permission_name in ['android.permission.READ_EXTERNAL_STORAGE', 'android.permission.WRITE_EXTERNAL_STORAGE']:
            recommendations.append("Consider using scoped storage for Android 10+")
        
        if permission_name == 'android.permission.SYSTEM_ALERT_WINDOW':
            recommendations.append("Implement proper overlay validation")
            recommendations.append("Avoid using for malicious purposes")
        
        return recommendations
    
    def _extract_custom_permissions(self, root: ET.Element) -> List[Dict[str, str]]:
        """Extract custom permission definitions."""
        custom_permissions = []
        
        try:
            for permission in root.findall('.//permission'):
                name = permission.get('{http://schemas.android.com/apk/res/android}name')
                protection_level = permission.get('{http://schemas.android.com/apk/res/android}protectionLevel', 'normal')
                label = permission.get('{http://schemas.android.com/apk/res/android}label', '')
                description = permission.get('{http://schemas.android.com/apk/res/android}description', '')
                
                if name:
                    custom_permissions.append({
                        'name': name,
                        'protection_level': protection_level,
                        'label': label,
                        'description': description
                    })
            
            self.logger.debug(f"Found {len(custom_permissions)} custom permissions")
            return custom_permissions
            
        except Exception as e:
            self.logger.error(f"Custom permission extraction failed: {e}")
            return []
    
    def _analyze_components(self, root: ET.Element) -> List[ComponentAnalysis]:
        """Analyze all Android components."""
        components = []
        
        try:
            # Analyze activities
            for activity in root.findall('.//activity'):
                component = self._analyze_component_element(activity, ComponentType.ACTIVITY)
                if component:
                    components.append(component)
            
            # Analyze services
            for service in root.findall('.//service'):
                component = self._analyze_component_element(service, ComponentType.SERVICE)
                if component:
                    components.append(component)
            
            # Analyze receivers
            for receiver in root.findall('.//receiver'):
                component = self._analyze_component_element(receiver, ComponentType.RECEIVER)
                if component:
                    components.append(component)
            
            # Analyze providers
            for provider in root.findall('.//provider'):
                component = self._analyze_component_element(provider, ComponentType.PROVIDER)
                if component:
                    components.append(component)
            
            self.logger.debug(f"Analyzed {len(components)} components")
            return components
            
        except Exception as e:
            self.logger.error(f"Component analysis failed: {e}")
            return []
    
    def _analyze_component_element(self, element: ET.Element, component_type: ComponentType) -> Optional[ComponentAnalysis]:
        """Analyze individual component element."""
        try:
            component_name = element.get('{http://schemas.android.com/apk/res/android}name')
            if not component_name:
                return None
            
            # Check if component is exported
            exported = self._is_component_exported(element)
            
            # Extract permissions
            permissions = self._extract_component_permissions(element)
            
            # Extract intent filters
            intent_filters = self._extract_intent_filters(element)
            
            # Assess protection level
            protection_level = self._assess_component_protection_level(permissions, exported)
            
            # Calculate risk level
            risk_level = self._calculate_component_risk(exported, permissions, intent_filters, component_type)
            
            # Calculate security score
            security_score = self._calculate_component_security_score(exported, permissions, intent_filters, component_type)
            
            return ComponentAnalysis(
                component_name=component_name,
                component_type=component_type,
                exported=exported,
                permissions=permissions,
                intent_filters=intent_filters,
                vulnerabilities=[],  # Will be populated by vulnerability analyzers
                risk_level=risk_level,
                protection_level=protection_level,
                security_score=security_score,
                analysis_metadata={
                    "has_intent_filters": bool(intent_filters),
                    "permission_protected": bool(permissions),
                    "high_risk_actions": self._count_high_risk_actions(intent_filters)
                }
            )
            
        except Exception as e:
            self.logger.error(f"Component element analysis failed: {e}")
            return None
    
    def _is_component_exported(self, element: ET.Element) -> bool:
        """Check if component is exported."""
        exported_attr = element.get('{http://schemas.android.com/apk/res/android}exported')
        
        if exported_attr is not None:
            return exported_attr.lower() == 'true'
        
        # If not explicitly set, check for intent filters
        intent_filters = element.findall('.//intent-filter')
        return len(intent_filters) > 0
    
    def _extract_component_permissions(self, element: ET.Element) -> List[str]:
        """Extract permissions required by component."""
        permissions = []
        
        # Direct permission
        permission = element.get('{http://schemas.android.com/apk/res/android}permission')
        if permission:
            permissions.append(permission)
        
        # Read permission (for providers)
        read_permission = element.get('{http://schemas.android.com/apk/res/android}readPermission')
        if read_permission:
            permissions.append(read_permission)
        
        # Write permission (for providers)
        write_permission = element.get('{http://schemas.android.com/apk/res/android}writePermission')
        if write_permission:
            permissions.append(write_permission)
        
        return permissions
    
    def _extract_intent_filters(self, element: ET.Element) -> List[IntentFilterAnalysis]:
        """Extract and analyze intent filters."""
        intent_filters = []
        
        try:
            for intent_filter in element.findall('.//intent-filter'):
                # Extract actions
                actions = [
                    action.get('{http://schemas.android.com/apk/res/android}name', '')
                    for action in intent_filter.findall('.//action')
                ]
                
                # Extract categories
                categories = [
                    category.get('{http://schemas.android.com/apk/res/android}name', '')
                    for category in intent_filter.findall('.//category')
                ]
                
                # Extract data elements
                data_schemes = []
                data_hosts = []
                data_paths = []
                data_mime_types = []
                
                for data in intent_filter.findall('.//data'):
                    scheme = data.get('{http://schemas.android.com/apk/res/android}scheme')
                    if scheme:
                        data_schemes.append(scheme)
                    
                    host = data.get('{http://schemas.android.com/apk/res/android}host')
                    if host:
                        data_hosts.append(host)
                    
                    path = data.get('{http://schemas.android.com/apk/res/android}path')
                    path_prefix = data.get('{http://schemas.android.com/apk/res/android}pathPrefix')
                    path_pattern = data.get('{http://schemas.android.com/apk/res/android}pathPattern')
                    
                    for p in [path, path_prefix, path_pattern]:
                        if p:
                            data_paths.append(p)
                    
                    mime_type = data.get('{http://schemas.android.com/apk/res/android}mimeType')
                    if mime_type:
                        data_mime_types.append(mime_type)
                
                # Analyze security issues
                has_wildcards = any('*' in item for item in data_hosts + data_paths)
                has_sensitive_schemes = any(scheme in self.sensitive_schemes for scheme in data_schemes)
                
                security_issues = []
                if has_wildcards:
                    security_issues.append("Uses wildcard patterns")
                if has_sensitive_schemes:
                    security_issues.append("Uses security-sensitive schemes")
                
                # Check for high-risk actions
                for action in actions:
                    if action in self.high_risk_actions:
                        security_issues.append(f"High-risk action: {action}")
                
                # Calculate risk level
                risk_level = self._calculate_intent_filter_risk(actions, data_schemes, has_wildcards, has_sensitive_schemes)
                
                intent_filter_analysis = IntentFilterAnalysis(
                    actions=actions,
                    categories=categories,
                    data_schemes=data_schemes,
                    data_hosts=data_hosts,
                    data_paths=data_paths,
                    data_mime_types=data_mime_types,
                    has_wildcards=has_wildcards,
                    has_sensitive_schemes=has_sensitive_schemes,
                    risk_level=risk_level,
                    security_issues=security_issues
                )
                
                intent_filters.append(intent_filter_analysis)
            
            return intent_filters
            
        except Exception as e:
            self.logger.error(f"Intent filter extraction failed: {e}")
            return []
    
    def _calculate_intent_filter_risk(self, actions: List[str], schemes: List[str], 
                                    has_wildcards: bool, has_sensitive_schemes: bool) -> RiskLevel:
        """Calculate risk level for intent filter."""
        risk_score = 0
        
        # High-risk actions
        for action in actions:
            if action in self.high_risk_actions:
                action_risk = self.high_risk_actions[action].get('risk_level', 'LOW')
                if action_risk == 'CRITICAL':
                    risk_score += 40
                elif action_risk == 'HIGH':
                    risk_score += 30
                elif action_risk == 'MEDIUM':
                    risk_score += 20
                else:
                    risk_score += 10
        
        # Sensitive schemes
        if has_sensitive_schemes:
            risk_score += 25
        
        # Wildcards
        if has_wildcards:
            risk_score += 20
        
        # Determine risk level
        if risk_score >= 70:
            return RiskLevel.CRITICAL
        elif risk_score >= 50:
            return RiskLevel.HIGH
        elif risk_score >= 30:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _assess_component_protection_level(self, permissions: List[str], exported: bool) -> ProtectionLevel:
        """Assess component protection level."""
        if not exported:
            return ProtectionLevel.PROTECTED
        elif permissions:
            # Check if any permissions are signature-level
            for permission in permissions:
                if 'signature' in permission.lower():
                    return ProtectionLevel.SIGNATURE_PROTECTED
            return ProtectionLevel.PERMISSION_PROTECTED
        else:
            return ProtectionLevel.UNPROTECTED
    
    def _calculate_component_risk(self, exported: bool, permissions: List[str], 
                                 intent_filters: List[IntentFilterAnalysis], 
                                 component_type: ComponentType) -> RiskLevel:
        """Calculate component risk level."""
        risk_score = 0
        
        # Base risk for component type
        if component_type == ComponentType.PROVIDER:
            risk_score += 20  # Providers are inherently higher risk
        elif component_type == ComponentType.SERVICE:
            risk_score += 15
        elif component_type == ComponentType.RECEIVER:
            risk_score += 10
        else:  # Activity
            risk_score += 5
        
        # Export status
        if exported:
            risk_score += 30
            if not permissions:
                risk_score += 40  # Unprotected exported component
        
        # Intent filter risks
        for intent_filter in intent_filters:
            if intent_filter.risk_level == RiskLevel.CRITICAL:
                risk_score += 30
            elif intent_filter.risk_level == RiskLevel.HIGH:
                risk_score += 20
            elif intent_filter.risk_level == RiskLevel.MEDIUM:
                risk_score += 10
        
        # Determine risk level
        if risk_score >= 80:
            return RiskLevel.CRITICAL
        elif risk_score >= 60:
            return RiskLevel.HIGH
        elif risk_score >= 40:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_component_security_score(self, exported: bool, permissions: List[str],
                                          intent_filters: List[IntentFilterAnalysis],
                                          component_type: ComponentType) -> int:
        """Calculate component security score (0-100)."""
        score = 100
        
        # Deduct for being exported without protection
        if exported and not permissions:
            score -= 40
        elif exported:
            score -= 20
        
        # Deduct for high-risk intent filters
        for intent_filter in intent_filters:
            if intent_filter.risk_level == RiskLevel.CRITICAL:
                score -= 25
            elif intent_filter.risk_level == RiskLevel.HIGH:
                score -= 15
            elif intent_filter.risk_level == RiskLevel.MEDIUM:
                score -= 10
        
        return max(0, score)
    
    def _count_high_risk_actions(self, intent_filters: List[IntentFilterAnalysis]) -> int:
        """Count high-risk actions in intent filters."""
        count = 0
        for intent_filter in intent_filters:
            for action in intent_filter.actions:
                if action in self.high_risk_actions:
                    count += 1
        return count
    
    def _extract_security_flags(self, root: ET.Element) -> Dict[str, Any]:
        """Extract security-related flags and configurations."""
        security_flags = {}
        
        try:
            application = root.find('.//application')
            if application is not None:
                # Extract common security flags
                security_flags['allowBackup'] = application.get(
                    '{http://schemas.android.com/apk/res/android}allowBackup', 'true'
                ).lower() == 'true'
                
                security_flags['debuggable'] = application.get(
                    '{http://schemas.android.com/apk/res/android}debuggable', 'false'
                ).lower() == 'true'
                
                security_flags['usesCleartextTraffic'] = application.get(
                    '{http://schemas.android.com/apk/res/android}usesCleartextTraffic', 'true'
                ).lower() == 'true'
                
                security_flags['requestLegacyExternalStorage'] = application.get(
                    '{http://schemas.android.com/apk/res/android}requestLegacyExternalStorage', 'false'
                ).lower() == 'true'
                
                security_flags['extractNativeLibs'] = application.get(
                    '{http://schemas.android.com/apk/res/android}extractNativeLibs', 'true'
                ).lower() == 'true'
            
            self.logger.debug(f"Extracted {len(security_flags)} security flags")
            return security_flags
            
        except Exception as e:
            self.logger.error(f"Security flag extraction failed: {e}")
            return {}
    
    def _analyze_deep_links(self, root: ET.Element, components: List[ComponentAnalysis]) -> List[DeepLinkAnalysis]:
        """Analyze deep link configurations."""
        deep_links = []
        
        try:
            for component in components:
                if component.component_type != ComponentType.ACTIVITY:
                    continue
                
                for intent_filter in component.intent_filters:
                    if not intent_filter.data_schemes:
                        continue
                    
                    for scheme in intent_filter.data_schemes:
                        for host in intent_filter.data_hosts or ['']:
                            for path in intent_filter.data_paths or ['']:
                                # Analyze deep link security
                                has_validation = self._check_deep_link_validation(
                                    component.component_name, scheme, host, path
                                )
                                
                                security_issues = []
                                attack_vectors = []
                                
                                # Check for security issues
                                if scheme in ['http']:
                                    security_issues.append("Uses insecure HTTP scheme")
                                    attack_vectors.append("Man-in-the-middle attacks")
                                
                                if '*' in host:
                                    security_issues.append("Uses wildcard host pattern")
                                    attack_vectors.append("Domain hijacking")
                                
                                if '*' in path:
                                    security_issues.append("Uses wildcard path pattern")
                                    attack_vectors.append("Path traversal")
                                
                                if not has_validation:
                                    security_issues.append("Lacks input validation")
                                    attack_vectors.append("Parameter injection")
                                
                                # Calculate risk level
                                risk_level = self._calculate_deep_link_risk(
                                    scheme, host, path, security_issues
                                )
                                
                                deep_link = DeepLinkAnalysis(
                                    scheme=scheme,
                                    host=host,
                                    path_prefix=path,
                                    component_name=component.component_name,
                                    component_type=component.component_type,
                                    has_validation=has_validation,
                                    security_issues=security_issues,
                                    attack_vectors=attack_vectors,
                                    risk_level=risk_level
                                )
                                
                                deep_links.append(deep_link)
            
            self.logger.debug(f"Analyzed {len(deep_links)} deep links")
            return deep_links
            
        except Exception as e:
            self.logger.error(f"Deep link analysis failed: {e}")
            return []
    
    def _check_deep_link_validation(self, component_name: str, scheme: str, host: str, path: str) -> bool:
        """Check if deep link has proper validation (simplified heuristic)."""
        # This is a simplified check - in reality would require code analysis
        # For now, assume HTTPS links have better validation
        return scheme == 'https' and '*' not in host and '*' not in path
    
    def _calculate_deep_link_risk(self, scheme: str, host: str, path: str, 
                                 security_issues: List[str]) -> RiskLevel:
        """Calculate deep link risk level."""
        risk_score = 0
        
        # Scheme risks
        if scheme == 'http':
            risk_score += 30
        elif scheme in self.sensitive_schemes:
            risk_score += 25
        
        # Host risks
        if '*' in host:
            risk_score += 35
        
        # Path risks
        if '*' in path or path == '/':
            risk_score += 30
        
        # Security issues
        risk_score += len(security_issues) * 10
        
        # Determine risk level
        if risk_score >= 70:
            return RiskLevel.CRITICAL
        elif risk_score >= 50:
            return RiskLevel.HIGH
        elif risk_score >= 30:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_overall_risk(self, components: List[ComponentAnalysis], 
                               permissions: List[PermissionAnalysis],
                               deep_links: List[DeepLinkAnalysis]) -> RiskLevel:
        """Calculate overall manifest risk level."""
        risk_score = 0
        
        # Component risks
        for component in components:
            if component.risk_level == RiskLevel.CRITICAL:
                risk_score += 25
            elif component.risk_level == RiskLevel.HIGH:
                risk_score += 15
            elif component.risk_level == RiskLevel.MEDIUM:
                risk_score += 8
        
        # Permission risks
        dangerous_perms = len([p for p in permissions if p.is_dangerous])
        risk_score += dangerous_perms * 5
        
        # Deep link risks
        for deep_link in deep_links:
            if deep_link.risk_level == RiskLevel.CRITICAL:
                risk_score += 20
            elif deep_link.risk_level == RiskLevel.HIGH:
                risk_score += 12
            elif deep_link.risk_level == RiskLevel.MEDIUM:
                risk_score += 6
        
        # Determine overall risk level
        if risk_score >= 80:
            return RiskLevel.CRITICAL
        elif risk_score >= 60:
            return RiskLevel.HIGH
        elif risk_score >= 40:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

def create_manifest_analyzer(context: AnalysisContext, 
                           confidence_calculator: PlatformUsageConfidenceCalculator) -> ManifestAnalyzer:
    """
    Factory function to create manifest analyzer with dependency injection.
    
    Args:
        context: Analysis context
        confidence_calculator: confidence calculator
        
    Returns:
        Configured manifest analyzer
    """
    return ManifestAnalyzer(context, confidence_calculator) 