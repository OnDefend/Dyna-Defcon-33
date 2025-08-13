#!/usr/bin/env python3
"""
Manifest Security Analyzer for AODS

Advanced Android manifest analysis with comprehensive security assessment
capabilities. Provides critical detection restoration and enhancement.

Critical Detection Framework - Manifest Security Analysis Engine
"""

import logging
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    # Correct pyaxmlparser import
    from pyaxmlparser import APK

    PYAXMLPARSER_AVAILABLE = True
except ImportError:
    APK = None
    PYAXMLPARSER_AVAILABLE = False
    logging.warning(
        "pyaxmlparser not available - using fallback AndroidManifest parsing"
    )

@dataclass
class ComponentInfo:
    """Information about an Android component."""

    name: str
    component_type: str  # activity, service, receiver, provider
    exported: bool
    intent_filters: List[Dict[str, Any]]
    permissions: List[str]
    protection_level: str = "normal"
    risk_score: int = 0

@dataclass
class PermissionInfo:
    """Information about an Android permission."""

    name: str
    protection_level: str
    dangerous: bool
    description: str
    risk_score: int

@dataclass
class SecurityFlag:
    """Security configuration flag information."""

    name: str
    value: str
    secure: bool
    description: str
    risk_score: int

class AndroidManifestSecurityAnalyzer:
    """
    Comprehensive AndroidManifest.xml security analyzer.

    Uses pyaxmlparser for accurate binary XML parsing to detect:
    - Exported components (activities, services, receivers, providers)
    - Dangerous permissions and permission analysis
    - Security flags (allowBackup, debuggable, usesCleartextTraffic)
    - Intent filter security issues
    - Deep link vulnerabilities
    """

    # Dangerous permissions that require special attention
    DANGEROUS_PERMISSIONS = {
        "android.permission.CAMERA": {"risk": 7, "description": "Access camera"},
        "android.permission.RECORD_AUDIO": {"risk": 8, "description": "Record audio"},
        "android.permission.ACCESS_FINE_LOCATION": {
            "risk": 9,
            "description": "Access precise location",
        },
        "android.permission.ACCESS_COARSE_LOCATION": {
            "risk": 6,
            "description": "Access approximate location",
        },
        "android.permission.READ_CONTACTS": {
            "risk": 8,
            "description": "Read contact information",
        },
        "android.permission.WRITE_CONTACTS": {
            "risk": 7,
            "description": "Modify contact information",
        },
        "android.permission.READ_SMS": {"risk": 9, "description": "Read SMS messages"},
        "android.permission.SEND_SMS": {"risk": 8, "description": "Send SMS messages"},
        "android.permission.READ_PHONE_STATE": {
            "risk": 7,
            "description": "Read phone state and identity",
        },
        "android.permission.CALL_PHONE": {
            "risk": 6,
            "description": "Directly call phone numbers",
        },
        "android.permission.READ_EXTERNAL_STORAGE": {
            "risk": 6,
            "description": "Read external storage",
        },
        "android.permission.WRITE_EXTERNAL_STORAGE": {
            "risk": 7,
            "description": "Write to external storage",
        },
        "android.permission.ACCESS_NETWORK_STATE": {
            "risk": 3,
            "description": "View network connections",
        },
        "android.permission.INTERNET": {
            "risk": 4,
            "description": "Network communication",
        },
        "android.permission.WAKE_LOCK": {
            "risk": 3,
            "description": "Prevent device from sleeping",
        },
        "android.permission.SYSTEM_ALERT_WINDOW": {
            "risk": 8,
            "description": "Display system-level alerts",
        },
        "android.permission.WRITE_SETTINGS": {
            "risk": 7,
            "description": "Modify system settings",
        },
    }

    # Security flags and their secure values
    SECURITY_FLAGS = {
        "android:allowBackup": {
            "secure_value": "false",
            "risk": 6,
            "description": "Backup configuration",
        },
        "android:debuggable": {
            "secure_value": "false",
            "risk": 9,
            "description": "Debug mode",
        },
        "android:usesCleartextTraffic": {
            "secure_value": "false",
            "risk": 8,
            "description": "Cleartext traffic",
        },
        "android:requestLegacyExternalStorage": {
            "secure_value": "false",
            "risk": 5,
            "description": "Legacy storage",
        },
        "android:allowClearUserData": {
            "secure_value": "false",
            "risk": 6,
            "description": "Clear user data",
        },
    }

    def __init__(self):
        """Initialize the AndroidManifest security analyzer."""
        self.logger = logging.getLogger(__name__)
        self.components: List[ComponentInfo] = []
        self.permissions: List[PermissionInfo] = []
        self.security_flags: List[SecurityFlag] = []
        self.deep_links: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []

    def analyze_manifest(self, apk_path: str) -> Dict[str, Any]:
        """
        Analyze AndroidManifest.xml from APK file.

        Args:
            apk_path: Path to the APK file

        Returns:
            Comprehensive analysis results
        """
        try:
            self.logger.debug(f"Starting AndroidManifest.xml analysis for: {apk_path}")

            # Parse AndroidManifest.xml using pyaxmlparser or fallback
            manifest_data = self._parse_manifest_with_pyaxmlparser(apk_path)

            if not manifest_data:
                # Fallback to text-based parsing with apktool
                manifest_data = self._parse_manifest_fallback(apk_path)

            if not manifest_data:
                return {"error": "Failed to parse AndroidManifest.xml"}

            # Analyze different aspects
            self._analyze_components(manifest_data)
            self._analyze_permissions(manifest_data)
            self._analyze_security_flags(manifest_data)
            self._analyze_deep_links()
            self._assess_security_risks()

            return self._generate_analysis_report()

        except Exception as e:
            self.logger.error(f"AndroidManifest analysis failed: {e}")
            return {"error": f"Analysis failed: {str(e)}"}

    def _parse_manifest_with_pyaxmlparser(self, apk_path: str) -> Optional[ET.Element]:
        """Parse AndroidManifest.xml using pyaxmlparser for binary XML."""
        if not PYAXMLPARSER_AVAILABLE:
            return None

        try:
            # Use pyaxmlparser APK class to parse
            apk = APK(apk_path)
            manifest_xml = apk.get_manifest()

            if manifest_xml:
                return ET.fromstring(manifest_xml)

        except Exception as e:
            self.logger.warning(f"pyaxmlparser failed: {e}")

        return None

    def _parse_manifest_fallback(self, apk_path: str) -> Optional[ET.Element]:
        """Fallback text-based AndroidManifest.xml parsing using apktool."""
        try:
            import subprocess
            import tempfile

            self.logger.debug("Using apktool fallback for AndroidManifest.xml parsing")

            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract using apktool
                result = subprocess.run(
                    ["apktool", "d", apk_path, "-o", temp_dir, "-f"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                if result.returncode == 0:
                    manifest_path = os.path.join(temp_dir, "AndroidManifest.xml")
                    if os.path.exists(manifest_path):
                        return ET.parse(manifest_path).getroot()
                else:
                    self.logger.error(f"apktool extraction failed: {result.stderr}")

        except Exception as e:
            self.logger.warning(f"Fallback manifest parsing failed: {e}")

        return None

    def _analyze_components(self, manifest_root: ET.Element) -> None:
        """Analyze Android components for security issues."""
        # Find application element
        app_element = manifest_root.find("application")
        if app_element is None:
            return

        # Analyze different component types
        component_types = [
            ("activity", "android:name"),
            ("service", "android:name"),
            ("receiver", "android:name"),
            ("provider", "android:name"),
        ]

        for component_type, name_attr in component_types:
            components = app_element.findall(component_type)
            for component in components:
                self._analyze_component(component, component_type)

    def _analyze_component(self, component: ET.Element, component_type: str) -> None:
        """Analyze individual component for security issues."""
        # Get component name with proper namespace handling
        name = (
            component.get("android:name")
            or component.get("{http://schemas.android.com/apk/res/android}name")
            or "Unknown"
        )

        exported = self._is_component_exported(component)
        intent_filters = self._extract_intent_filters(component)
        permissions = self._extract_component_permissions(component)

        # Calculate risk score
        risk_score = self._calculate_component_risk(
            exported, intent_filters, permissions
        )

        component_info = ComponentInfo(
            name=name,
            component_type=component_type,
            exported=exported,
            intent_filters=intent_filters,
            permissions=permissions,
            risk_score=risk_score,
        )

        self.components.append(component_info)

        # Check for vulnerabilities
        if exported and component_type in ["activity", "service"]:
            self._check_exported_component_vulnerability(component_info)

    def _is_component_exported(self, component: ET.Element) -> bool:
        """Determine if a component is exported."""
        # Check explicit exported attribute with namespace handling
        exported_attr = component.get("android:exported") or component.get(
            "{http://schemas.android.com/apk/res/android}exported"
        )

        if exported_attr is not None:
            return exported_attr.lower() == "true"

        # Check for intent filters (implicit export)
        intent_filters = component.findall("intent-filter")
        return len(intent_filters) > 0

    def _extract_intent_filters(self, component: ET.Element) -> List[Dict[str, Any]]:
        """Extract intent filter information."""
        intent_filters = []

        for intent_filter in component.findall("intent-filter"):
            filter_info = {"actions": [], "categories": [], "data": []}

            # Extract actions
            for action in intent_filter.findall("action"):
                action_name = action.get("android:name") or action.get(
                    "{http://schemas.android.com/apk/res/android}name"
                )
                if action_name:
                    filter_info["actions"].append(action_name)

            # Extract categories
            for category in intent_filter.findall("category"):
                cat_name = category.get("android:name") or category.get(
                    "{http://schemas.android.com/apk/res/android}name"
                )
                if cat_name:
                    filter_info["categories"].append(cat_name)

            # Extract data elements for deep link analysis
            for data in intent_filter.findall("data"):
                data_info = {}
                for attr in [
                    "android:scheme",
                    "android:host",
                    "android:port",
                    "android:path",
                    "android:pathPrefix",
                    "android:pathPattern",
                    "android:mimeType",
                ]:
                    value = data.get(attr) or data.get(
                        "{http://schemas.android.com/apk/res/android}"
                        + attr.split(":")[-1]
                    )
                    if value:
                        data_info[attr.replace("android:", "")] = value

                if data_info:
                    filter_info["data"].append(data_info)

            intent_filters.append(filter_info)

        return intent_filters

    def _extract_component_permissions(self, component: ET.Element) -> List[str]:
        """Extract permissions associated with component."""
        permissions = []

        # Check permission attribute with namespace handling
        permission = component.get("android:permission") or component.get(
            "{http://schemas.android.com/apk/res/android}permission"
        )
        if permission:
            permissions.append(permission)

        return permissions

    def _calculate_component_risk(
        self, exported: bool, intent_filters: List[Dict], permissions: List[str]
    ) -> int:
        """Calculate risk score for component."""
        risk_score = 0

        if exported:
            risk_score += 5

        # Higher risk for exported components with intent filters
        if exported and intent_filters:
            risk_score += 3

        # Check for dangerous actions
        for intent_filter in intent_filters:
            for action in intent_filter.get("actions", []):
                if action in [
                    "android.intent.action.VIEW",
                    "android.intent.action.MAIN",
                ]:
                    risk_score += 2

        # Reduce risk if protected by permissions
        if permissions:
            risk_score = max(0, risk_score - 2)

        return risk_score

    def _analyze_permissions(self, manifest_root: ET.Element) -> None:
        """Analyze requested permissions."""
        permission_elements = manifest_root.findall("uses-permission")

        for perm_element in permission_elements:
            perm_name = perm_element.get("android:name") or perm_element.get(
                "{http://schemas.android.com/apk/res/android}name"
            )
            if perm_name:
                perm_info = self._analyze_permission(perm_name)
                self.permissions.append(perm_info)

    def _analyze_permission(self, permission_name: str) -> PermissionInfo:
        """Analyze individual permission."""
        dangerous_info = self.DANGEROUS_PERMISSIONS.get(permission_name, {})

        return PermissionInfo(
            name=permission_name,
            protection_level=dangerous_info.get("protection_level", "normal"),
            dangerous=permission_name in self.DANGEROUS_PERMISSIONS,
            description=dangerous_info.get("description", "Standard permission"),
            risk_score=dangerous_info.get("risk", 1),
        )

    def _analyze_security_flags(self, manifest_root: ET.Element) -> None:
        """Analyze security configuration flags."""
        app_element = manifest_root.find("application")
        if app_element is None:
            return

        for flag_name, flag_info in self.SECURITY_FLAGS.items():
            value = app_element.get(flag_name) or app_element.get(
                "{http://schemas.android.com/apk/res/android}"
                + flag_name.split(":")[-1]
            )

            if value is not None:
                secure = value.lower() == flag_info["secure_value"]

                security_flag = SecurityFlag(
                    name=flag_name,
                    value=value,
                    secure=secure,
                    description=flag_info["description"],
                    risk_score=0 if secure else flag_info["risk"],
                )

                self.security_flags.append(security_flag)

                # Add vulnerability if insecure
                if not secure:
                    self._add_security_flag_vulnerability(security_flag)

    def _analyze_deep_links(self) -> None:
        """Analyze deep link configurations for vulnerabilities."""
        for component in self.components:
            if component.exported and component.component_type == "activity":
                for intent_filter in component.intent_filters:
                    for data in intent_filter.get("data", []):
                        if "scheme" in data:
                            deep_link = {
                                "component": component.name,
                                "scheme": data.get("scheme"),
                                "host": data.get("host"),
                                "path": data.get(
                                    "path",
                                    data.get("pathPrefix", data.get("pathPattern")),
                                ),
                                "risk_score": self._calculate_deep_link_risk(data),
                            }
                            self.deep_links.append(deep_link)

    def _calculate_deep_link_risk(self, data: Dict[str, str]) -> int:
        """Calculate risk score for deep link."""
        risk_score = 5  # Base risk for deep links

        scheme = data.get("scheme", "")
        if scheme in ["http", "https"]:
            risk_score += 3  # Web-based deep links are riskier

        if not data.get("host"):
            risk_score += 2  # No host restriction increases risk

        return risk_score

    def _check_exported_component_vulnerability(self, component: ComponentInfo) -> None:
        """Check for exported component vulnerabilities based on security characteristics."""

        # Base vulnerability for any exported component
        vuln = {
            "type": "Exported Component",
            "component": component.name,
            "component_type": component.component_type,
            "description": f"Exported {component.component_type} without proper protection",
            "risk_score": component.risk_score,
            "recommendation": "Add permission protection or make component non-exported",
            "security_impact": self._assess_security_impact(component),
        }

        # Enhance description based on security characteristics
        if component.risk_score >= 8:
            vuln["description"] = (
                f"High-risk exported {component.component_type}: {component.name}"
            )
            vuln["severity"] = "HIGH"
        elif component.risk_score >= 5:
            vuln["description"] = (
                f"Medium-risk exported {component.component_type}: {component.name}"
            )
            vuln["severity"] = "MEDIUM"
        else:
            vuln["description"] = (
                f"Low-risk exported {component.component_type}: {component.name}"
            )
            vuln["severity"] = "LOW"

        # Add context about why this is risky
        risk_factors = []
        if component.exported and not component.permissions:
            risk_factors.append("no permission protection")
        if component.intent_filters:
            risk_factors.append(f"{len(component.intent_filters)} intent filter(s)")
        if component.component_type in ["activity", "service"]:
            risk_factors.append("potentially sensitive component type")

        if risk_factors:
            vuln["risk_factors"] = risk_factors
            vuln["description"] += f" - Risk factors: {', '.join(risk_factors)}"

        self.vulnerabilities.append(vuln)

    def _assess_security_impact(self, component: ComponentInfo) -> str:
        """Assess the security impact of an exported component."""
        if component.component_type == "activity":
            if component.intent_filters:
                return "Potential unauthorized access to application functionality"
            return "Direct activity invocation possible"
        elif component.component_type == "service":
            return "Background service accessible to other applications"
        elif component.component_type == "receiver":
            return "Broadcast receiver can be triggered by other applications"
        elif component.component_type == "provider":
            return "Data provider accessible to other applications"
        else:
            return "Component accessible to other applications"

    def _add_security_flag_vulnerability(self, flag: SecurityFlag) -> None:
        """Add vulnerability for insecure security flag."""
        vuln = {
            "type": "Security Configuration",
            "flag": flag.name,
            "value": flag.value,
            "description": f"Insecure {flag.description} configuration",
            "risk_score": flag.risk_score,
            "recommendation": f"Set {flag.name} to secure value",
            "security_impact": self._assess_flag_security_impact(flag),
        }

        self.vulnerabilities.append(vuln)

    def _assess_flag_security_impact(self, flag: SecurityFlag) -> str:
        """Assess the security impact of an insecure flag."""
        flag_impacts = {
            "android:allowBackup": "Application data can be backed up and potentially extracted",
            "android:debuggable": "Application can be debugged, exposing internal data and logic",
            "android:usesCleartextTraffic": "Network traffic sent in cleartext, vulnerable to interception",
            "android:requestLegacyExternalStorage": "Uses legacy storage access, potentially insecure",
            "android:allowClearUserData": "User data can be cleared by other applications",
        }
        return flag_impacts.get(
            flag.name, "Security configuration may create vulnerabilities"
        )

    def _assess_security_risks(self) -> None:
        """Assess overall security risks."""
        # Additional risk assessment logic can be added here
        pass

    def _generate_analysis_report(self) -> Dict[str, Any]:
        """Generate comprehensive analysis report."""
        return {
            "analysis_type": "AndroidManifest Security Analysis",
            "timestamp": "2025-05-31",
            "summary": {
                "total_components": len(self.components),
                "exported_components": len([c for c in self.components if c.exported]),
                "dangerous_permissions": len(
                    [p for p in self.permissions if p.dangerous]
                ),
                "security_issues": len(self.vulnerabilities),
                "deep_links": len(self.deep_links),
            },
            "components": [
                {
                    "name": c.name,
                    "type": c.component_type,
                    "exported": c.exported,
                    "risk_score": c.risk_score,
                    "intent_filters": len(c.intent_filters),
                    "permissions": c.permissions,
                }
                for c in self.components
            ],
            "permissions": [
                {
                    "name": p.name,
                    "dangerous": p.dangerous,
                    "risk_score": p.risk_score,
                    "description": p.description,
                }
                for p in self.permissions
            ],
            "security_flags": [
                {
                    "name": f.name,
                    "value": f.value,
                    "secure": f.secure,
                    "risk_score": f.risk_score,
                    "description": f.description,
                }
                for f in self.security_flags
            ],
            "deep_links": self.deep_links,
            "vulnerabilities": self.vulnerabilities,
            "recommendations": self._generate_recommendations(),
        }

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations."""
        recommendations = []

        exported_count = len([c for c in self.components if c.exported])
        if exported_count > 0:
            recommendations.append(
                f"Review {exported_count} exported components for necessary protection"
            )

        dangerous_perms = [p for p in self.permissions if p.dangerous]
        if dangerous_perms:
            recommendations.append(
                f"Audit {len(dangerous_perms)} dangerous permissions for necessity"
            )

        insecure_flags = [f for f in self.security_flags if not f.secure]
        if insecure_flags:
            recommendations.append(
                f"Fix {len(insecure_flags)} insecure security configuration flags"
            )

        if self.deep_links:
            recommendations.append(
                f"Secure {len(self.deep_links)} deep link configurations"
            )

        return recommendations

def analyze_android_manifest(apk_path: str) -> Dict[str, Any]:
    """
    Convenience function to analyze AndroidManifest.xml.

    Args:
        apk_path: Path to the APK file

    Returns:
        Analysis results dictionary
    """
    analyzer = AndroidManifestSecurityAnalyzer()
    return analyzer.analyze_manifest(apk_path)
