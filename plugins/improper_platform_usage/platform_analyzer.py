#!/usr/bin/env python3
"""
Core Platform Usage Analyzer

This module contains the main analysis logic for detecting improper platform
usage patterns in Android applications, extracted from the monolithic plugin
for improved maintainability and testability.

Features:
- Manifest analysis and component security assessment
- Intent filter security validation
- Permission usage analysis
- Component export security evaluation
- confidence calculation integration
"""

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass

# Import base vulnerability classes
from core.shared_data_structures.base_vulnerability import VulnerabilitySeverity, VulnerabilityType

from .data_structures import (
    PlatformUsageVulnerability, ComponentAnalysisResult, ManifestAnalysisResult,
    PlatformUsageCategory, SecurityControlType, ProtectionStrength
)
from .confidence_calculator import PlatformUsageConfidenceCalculator, EvidenceData

logger = logging.getLogger(__name__)

class PlatformUsageAnalyzer:
    """Core analyzer for improper platform usage detection."""
    
    def __init__(self, apk_ctx, confidence_calculator: Optional[PlatformUsageConfidenceCalculator] = None):
        """Initialize the platform usage analyzer."""
        self.apk_ctx = apk_ctx
        self.confidence_calculator = confidence_calculator or PlatformUsageConfidenceCalculator()
        self.manifest_path = self._get_manifest_path()
        self.manifest_root = self._parse_manifest()
        
    def _get_manifest_path(self) -> Optional[Path]:
        """Get the path to the AndroidManifest.xml file."""
        try:
            # Use APKContext's manifest_path if available
            if hasattr(self.apk_ctx, 'manifest_path') and self.apk_ctx.manifest_path:
                if self.apk_ctx.manifest_path.exists():
                    return self.apk_ctx.manifest_path
            
            # Use decompiled_apk_dir if available  
            if hasattr(self.apk_ctx, 'decompiled_apk_dir') and self.apk_ctx.decompiled_apk_dir:
                manifest_path = self.apk_ctx.decompiled_apk_dir / "AndroidManifest.xml"
                if manifest_path.exists():
                    return manifest_path
            
            # Fallback paths
            possible_paths = [
                Path(self.apk_ctx.apk_path).parent / "AndroidManifest.xml",
                Path.cwd() / "temp" / "AndroidManifest.xml"
            ]
            
            for path in possible_paths:
                if path.exists():
                    return path
                    
        except Exception as e:
            logger.warning(f"Error finding manifest path: {e}")
        
        return None
    
    def _parse_manifest(self) -> Optional[ET.Element]:
        """Parse the AndroidManifest.xml file."""
        if not self.manifest_path:
            logger.warning("AndroidManifest.xml not found")
            return None
        
        try:
            tree = ET.parse(self.manifest_path)
            return tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Error parsing AndroidManifest.xml: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error parsing manifest: {e}")
            return None
    
    def analyze_platform_usage(self) -> ManifestAnalysisResult:
        """Perform comprehensive platform usage analysis."""
        result = ManifestAnalysisResult()
        
        if not self.manifest_root:
            logger.warning("Cannot analyze platform usage without manifest")
            return result
        
        try:
            # Analyze components
            result.component_results = self._analyze_components()
            result.components_analyzed = len(result.component_results)
            result.exported_components = sum(1 for comp in result.component_results if comp.exported)
            
            # Analyze permissions
            result.dangerous_permissions = self._extract_dangerous_permissions()
            result.custom_permissions = self._extract_custom_permissions()
            
            # Analyze intent filters
            result.intent_filters_analyzed = self._count_intent_filters()
            
            # Collect vulnerabilities from component analysis
            for comp_result in result.component_results:
                result.security_issues.extend(comp_result.vulnerabilities)
            
            # Calculate overall security score
            result.overall_security_score = self._calculate_overall_security_score(result)
            
            # Generate recommendations
            result.recommendations = self._generate_recommendations(result)
            
            # Add analysis metadata
            result.analysis_metadata = {
                "analyzer_version": "2.0.0",
                "analysis_timestamp": "2024-01-15",
                "manifest_path": str(self.manifest_path),
                "total_components": result.components_analyzed,
                "exported_ratio": result.export_ratio
            }
            
        except Exception as e:
            logger.error(f"Error during platform usage analysis: {e}")
        
        return result
    
    def _analyze_components(self) -> List[ComponentAnalysisResult]:
        """Analyze all components in the manifest."""
        components = []
        
        # Component types to analyze
        component_types = {
            "activity": "Activity",
            "service": "Service", 
            "receiver": "BroadcastReceiver",
            "provider": "ContentProvider"
        }
        
        for xml_tag, component_type in component_types.items():
            elements = self.manifest_root.findall(f".//application/{xml_tag}")
            for element in elements:
                result = self._analyze_component(element, component_type)
                if result:
                    components.append(result)
        
        return components
    
    def _analyze_component(self, element: ET.Element, component_type: str) -> Optional[ComponentAnalysisResult]:
        """Analyze a single component."""
        try:
            # Extract component information
            name = element.get("{http://schemas.android.com/apk/res/android}name", "")
            exported = self._is_component_exported(element)
            permissions = self._extract_component_permissions(element)
            intent_filters = self._extract_intent_filters(element)
            
            # Create component result
            result = ComponentAnalysisResult(
                component_name=name,
                component_type=component_type,
                exported=exported,
                permissions=permissions,
                intent_filters=intent_filters
            )
            
            # Analyze component security
            result.vulnerabilities = self._analyze_component_security(result)
            result.security_score = self._calculate_component_security_score(result)
            result.recommendations = self._generate_component_recommendations(result)
            
            # Add analysis metadata
            result.analysis_metadata = {
                "analysis_method": "manifest_analysis",
                "component_xml_tag": element.tag,
                "has_intent_filters": len(intent_filters) > 0,
                "permission_protected": len(permissions) > 0
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing component {element.get('name', 'unknown')}: {e}")
            return None
    
    def _is_component_exported(self, element: ET.Element) -> bool:
        """Check if a component is exported."""
        # Check explicit android:exported attribute
        exported_attr = element.get("{http://schemas.android.com/apk/res/android}exported")
        if exported_attr:
            return exported_attr.lower() == "true"
        
        # Check for intent filters (implies exported if not explicitly set)
        intent_filters = element.findall("intent-filter")
        return len(intent_filters) > 0
    
    def _extract_component_permissions(self, element: ET.Element) -> List[str]:
        """Extract permissions associated with a component."""
        permissions = []
        
        # Component-level permission
        permission = element.get("{http://schemas.android.com/apk/res/android}permission")
        if permission:
            permissions.append(permission)
        
        # Read/write permissions for content providers
        read_permission = element.get("{http://schemas.android.com/apk/res/android}readPermission")
        if read_permission:
            permissions.append(read_permission)
            
        write_permission = element.get("{http://schemas.android.com/apk/res/android}writePermission")
        if write_permission:
            permissions.append(write_permission)
        
        return permissions
    
    def _extract_intent_filters(self, element: ET.Element) -> List[str]:
        """Extract intent filters from a component."""
        intent_filters = []
        
        for intent_filter in element.findall("intent-filter"):
            actions = []
            categories = []
            data_schemes = []
            
            # Extract actions
            for action in intent_filter.findall("action"):
                action_name = action.get("{http://schemas.android.com/apk/res/android}name")
                if action_name:
                    actions.append(action_name)
            
            # Extract categories
            for category in intent_filter.findall("category"):
                category_name = category.get("{http://schemas.android.com/apk/res/android}name")
                if category_name:
                    categories.append(category_name)
            
            # Extract data schemes
            for data in intent_filter.findall("data"):
                scheme = data.get("{http://schemas.android.com/apk/res/android}scheme")
                if scheme:
                    data_schemes.append(scheme)
            
            # Create intent filter description
            filter_desc = f"Actions: {', '.join(actions)}"
            if categories:
                filter_desc += f" | Categories: {', '.join(categories)}"
            if data_schemes:
                filter_desc += f" | Schemes: {', '.join(data_schemes)}"
            
            intent_filters.append(filter_desc)
        
        return intent_filters
    
    def _analyze_component_security(self, component: ComponentAnalysisResult) -> List[PlatformUsageVulnerability]:
        """Analyze security vulnerabilities for a component."""
        vulnerabilities = []
        
        # Check for exported component without protection
        if component.exported and not component.permissions:
            vuln = self._create_exported_component_vulnerability(component)
            vulnerabilities.append(vuln)
        
        # Check for content provider specific issues
        if component.component_type == "ContentProvider":
            content_provider_vulns = self._analyze_content_provider_security(component)
            vulnerabilities.extend(content_provider_vulns)
        
        # Check for deep link handling issues
        if component.intent_filters:
            deep_link_vulns = self._analyze_deep_link_security(component)
            vulnerabilities.extend(deep_link_vulns)
        
        return vulnerabilities
    
    def _create_exported_component_vulnerability(self, component: ComponentAnalysisResult) -> PlatformUsageVulnerability:
        """Create vulnerability for exported component without proper protection."""
        
        # Calculate confidence using the proper EvidenceData parameters
        evidence_data = EvidenceData(
            manifest_complexity=0.6,  # Basic component analysis
            permission_usage=0.0 if not component.permissions else 0.5,
            component_isolation=0.0 if component.exported else 1.0,
            validation_coverage=0.8,  # Manifest analysis provides good coverage
            implementation_quality=0.5,  # Default since we can't assess implementation quality from manifest
            pattern_matches=1,
            cross_validation_sources=1,
            context_relevance=0.8
        )
        
        confidence = self.confidence_calculator.calculate_platform_confidence(
            vulnerability_type="exported_component",
            evidence=evidence_data,
            pattern_id="exported_component_pattern",
            analysis_source="manifest_analysis"
        )
        
        # Determine severity based on component type and protection
        severity = VulnerabilitySeverity.HIGH if component.component_type in ["ContentProvider", "Service"] else VulnerabilitySeverity.MEDIUM
        if not component.permissions and component.exported:
            severity = VulnerabilitySeverity.HIGH
        
        # Create vulnerability with proper context
        vulnerability = PlatformUsageVulnerability(
            vulnerability_id=f"exported_component_{component.component_name}",
            vulnerability_type=VulnerabilityType.EXPORTED_COMPONENTS,
            title=f"Exported {component.component_type} Without Protection",
            description=f"The {component.component_type} '{component.component_name}' is exported but lacks proper permission protection, potentially allowing unauthorized access.",
            severity=severity,
            confidence=confidence,
            evidence=f"Component exported: {component.exported}, Permissions: {len(component.permissions)}",
            platform_category=PlatformUsageCategory.EXPORTED_COMPONENTS,
            component_type=component.component_type,
            exported_status=component.exported,
            permission_level="none" if not component.permissions else "protected",
            intent_filters=component.intent_filters,
            masvs_controls=["MSTG-PLATFORM-11"],
            remediation="Add appropriate permission protection to exported components or set android:exported='false' if external access is not required.",
            security_impact="Unauthorized applications may access this component, potentially leading to data exposure or privilege escalation."
        )
        
        # Set context information
        vulnerability.context.file_path = "AndroidManifest.xml"
        vulnerability.context.component_type = component.component_type
        vulnerability.context.analysis_source = "manifest_analysis"
        
        # Add pattern match with location information
        vulnerability.add_match(
            pattern_id="exported_component_pattern",
            pattern_name="Exported Component Detection",
            match_text=f"{component.component_type}: {component.component_name}",
            confidence=confidence,
            location=f"AndroidManifest.xml: {component.component_name}"
        )
        
        return vulnerability
    
    def _analyze_content_provider_security(self, component: ComponentAnalysisResult) -> List[PlatformUsageVulnerability]:
        """Analyze content provider specific security issues."""
        vulnerabilities = []
        
        if component.component_type != "ContentProvider":
            return vulnerabilities
        
        # Check for exported content provider without proper permissions
        if component.exported and not component.permissions:
            evidence_data = EvidenceData(
                manifest_complexity=0.7,  # Content providers are more complex
                permission_usage=0.0,  # No permissions used
                component_isolation=0.0,  # Exported without protection
                validation_coverage=0.8,
                implementation_quality=0.5,
                pattern_matches=1,
                cross_validation_sources=1,
                context_relevance=0.9
            )
            
            confidence = self.confidence_calculator.calculate_platform_confidence(
                vulnerability_type="content_provider",
                evidence=evidence_data,
                pattern_id="content_provider_pattern",
                analysis_source="manifest_analysis"
            )
            
            vulnerability = PlatformUsageVulnerability(
                vulnerability_id=f"content_provider_exposed_{component.component_name}",
                vulnerability_type=VulnerabilityType.CONTENT_PROVIDER,
                title="Exported Content Provider Without Permission Protection",
                description=f"Content Provider '{component.component_name}' is exported without proper permission protection, allowing unauthorized data access.",
                severity=VulnerabilitySeverity.HIGH,
                confidence=confidence,
                evidence=f"Exported: {component.exported}, Permissions: {len(component.permissions)}",
                platform_category=PlatformUsageCategory.CONTENT_PROVIDER_SECURITY,
                component_type=component.component_type,
                exported_status=component.exported,
                permission_level="none",
                masvs_controls=["MSTG-PLATFORM-11"],
                remediation="Add appropriate read/write permissions to the content provider or set android:exported='false'.",
                security_impact="Unauthorized applications may access sensitive data through this content provider."
            )
            
            # Set context
            vulnerability.context.file_path = "AndroidManifest.xml"
            vulnerability.context.component_type = component.component_type
            vulnerability.context.analysis_source = "manifest_analysis"
            
            # Add match
            vulnerability.add_match(
                pattern_id="content_provider_pattern",
                pattern_name="Content Provider Security",
                match_text=f"ContentProvider: {component.component_name}",
                confidence=confidence,
                location=f"AndroidManifest.xml: {component.component_name}"
            )
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    def _analyze_deep_link_security(self, component: ComponentAnalysisResult) -> List[PlatformUsageVulnerability]:
        """Analyze deep link security issues."""
        vulnerabilities = []
        
        # Check for sensitive schemes in intent filters
        sensitive_schemes = ["http", "https"]
        for intent_filter in component.intent_filters:
            if any(scheme in intent_filter.lower() for scheme in sensitive_schemes):
                evidence_data = EvidenceData(
                    manifest_complexity=0.6,
                    permission_usage=0.5 if component.permissions else 0.0,
                    component_isolation=0.3,  # Intent filters increase exposure
                    validation_coverage=0.7,
                    implementation_quality=0.5,
                    pattern_matches=1,
                    cross_validation_sources=1,
                    context_relevance=0.7
                )
                
                confidence = self.confidence_calculator.calculate_platform_confidence(
                    vulnerability_type="deep_link",
                    evidence=evidence_data,
                    pattern_id="deep_link_pattern",
                    analysis_source="manifest_analysis"
                )
                
                vulnerability = PlatformUsageVulnerability(
                    vulnerability_id=f"deep_link_security_{component.component_name}",
                    vulnerability_type=VulnerabilityType.INTENT_SECURITY,
                    title="Insecure Deep Link Configuration",
                    description=f"Component '{component.component_name}' accepts deep links that may be vulnerable to intent-based attacks.",
                    severity=VulnerabilitySeverity.MEDIUM,
                    confidence=confidence,
                    evidence=f"Intent filters: {len(component.intent_filters)}, Scheme detected: {intent_filter}",
                    platform_category=PlatformUsageCategory.INTENT_HANDLING,
                    component_type=component.component_type,
                    exported_status=component.exported,
                    intent_filters=component.intent_filters,
                    masvs_controls=["MSTG-PLATFORM-11"],
                    remediation="Validate all deep link inputs and implement proper intent verification.",
                    security_impact="Malicious applications may exploit deep links to perform unauthorized actions."
                )
                
                # Set context
                vulnerability.context.file_path = "AndroidManifest.xml"
                vulnerability.context.component_type = component.component_type
                vulnerability.context.analysis_source = "manifest_analysis"
                
                # Add match
                vulnerability.add_match(
                    pattern_id="deep_link_pattern",
                    pattern_name="Deep Link Security",
                    match_text=intent_filter,
                    confidence=confidence,
                    location=f"AndroidManifest.xml: {component.component_name}"
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _extract_dangerous_permissions(self) -> List[str]:
        """Extract dangerous permissions from manifest."""
        dangerous_permissions = []
        
        dangerous_permission_patterns = [
            "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
            "READ_CONTACTS", "WRITE_CONTACTS", "READ_SMS", "SEND_SMS",
            "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_PHONE_STATE"
        ]
        
        # Find all permission elements
        for permission in self.manifest_root.findall(".//uses-permission"):
            perm_name = permission.get("{http://schemas.android.com/apk/res/android}name", "")
            
            # Check if it's a dangerous permission
            for dangerous in dangerous_permission_patterns:
                if dangerous in perm_name:
                    dangerous_permissions.append(perm_name)
                    break
        
        return dangerous_permissions
    
    def _extract_custom_permissions(self) -> List[str]:
        """Extract custom permission definitions from manifest."""
        custom_permissions = []
        
        for permission in self.manifest_root.findall(".//permission"):
            perm_name = permission.get("{http://schemas.android.com/apk/res/android}name", "")
            if perm_name:
                custom_permissions.append(perm_name)
        
        return custom_permissions
    
    def _count_intent_filters(self) -> int:
        """Count total intent filters in the application."""
        return len(self.manifest_root.findall(".//intent-filter"))
    
    def _calculate_component_security_score(self, component: ComponentAnalysisResult) -> float:
        """Calculate security score for a component."""
        base_score = 1.0
        
        # Penalties for security issues
        if component.exported and not component.permissions:
            base_score -= 0.4  # Major penalty for unprotected export
        
        if component.component_type == "ContentProvider" and component.exported:
            base_score -= 0.3  # Additional penalty for content provider
        
        if component.intent_filters and not component.permissions:
            base_score -= 0.2  # Penalty for unprotected intent handling
        
        # Apply vulnerability penalty
        vulnerability_penalty = len(component.vulnerabilities) * 0.1
        base_score -= vulnerability_penalty
        
        return max(0.0, min(1.0, base_score))
    
    def _calculate_overall_security_score(self, result: ManifestAnalysisResult) -> float:
        """Calculate overall security score for the application."""
        if result.components_analyzed == 0:
            return 0.0
        
        # Average component scores
        component_scores = [comp.security_score for comp in result.component_results]
        average_score = sum(component_scores) / len(component_scores)
        
        # Apply penalties for dangerous patterns
        penalty = 0.0
        
        # Penalty for high export ratio
        if result.export_ratio > 0.5:
            penalty += 0.1
        
        # Penalty for dangerous permissions
        if len(result.dangerous_permissions) > 5:
            penalty += 0.1
        
        # Penalty for critical vulnerabilities
        penalty += len([v for v in result.security_issues if v.severity == "CRITICAL"]) * 0.05
        
        final_score = max(0.0, average_score - penalty)
        return final_score
    
    def _generate_component_recommendations(self, component: ComponentAnalysisResult) -> List[str]:
        """Generate security recommendations for a component."""
        recommendations = []
        
        if component.exported and not component.permissions:
            recommendations.append(f"Add proper permission protection to exported {component.component_type}")
        
        if component.component_type == "ContentProvider":
            recommendations.append("Implement proper access controls for ContentProvider data")
            
        if component.intent_filters:
            recommendations.append("Validate all input data from intents to prevent injection attacks")
        
        return recommendations
    
    def _generate_recommendations(self, result: ManifestAnalysisResult) -> List[str]:
        """Generate overall security recommendations."""
        recommendations = []
        
        if result.export_ratio > 0.3:
            recommendations.append("Review exported components and add proper permission protection")
        
        if len(result.dangerous_permissions) > 5:
            recommendations.append("Review dangerous permission usage and implement runtime permission checks")
        
        if result.high_risk_components:
            recommendations.append("Address high-risk component configurations immediately")
        
        recommendations.append("Implement component-level security controls and input validation")
        recommendations.append("Follow OWASP MASVS guidelines for platform security")
        
        return recommendations 