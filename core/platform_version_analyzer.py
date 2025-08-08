#!/usr/bin/env python3
"""
Platform Version Analyzer for AODS

This module implements comprehensive platform version analysis for MASVS-CODE-3 compliance.
It analyzes target SDK versions, minimum SDK requirements, deprecated API usage, and 
platform security implications.

MASVS Controls Covered:
- MASVS-CODE-3: The app targets a recent platform version

Security Analysis Features:
- SDK version analysis (targetSdkVersion, minSdkVersion, compileSdkVersion)
- Deprecated API usage detection with security impact assessment
- Platform version compatibility analysis
- Security implication assessment for version choices
- Platform upgrade recommendations with security benefits

"""

import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from datetime import datetime

# Import detailed vulnerability framework
try:
    from core.detailed_vulnerability_framework import (
        DetailedVulnerability,
        VulnerabilityLocation,
        RemediationGuidance,
        VulnerabilityEvidence,
        create_detailed_vulnerability,
        DetailedVulnerabilityReporter
    )
    DETAILED_FRAMEWORK_AVAILABLE = True
except ImportError:
    DETAILED_FRAMEWORK_AVAILABLE = False
    logging.warning("Detailed vulnerability framework not available, using fallback reporting")

logger = logging.getLogger(__name__)

class PlatformVersionFinding:
    """Data class for platform version findings."""
    
    def __init__(self, finding_type: str, location: str, severity: str, 
                 description: str, evidence: str = "", remediation: str = "",
                 sdk_version: str = "", line_number: int = 0):
        self.finding_type = finding_type
        self.location = location
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.remediation = remediation
        self.sdk_version = sdk_version
        self.line_number = line_number
        self.masvs_control = "MASVS-CODE-3"
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return {
            "finding_type": self.finding_type,
            "location": self.location,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "sdk_version": self.sdk_version,
            "line_number": self.line_number,
            "masvs_control": self.masvs_control
        }

class PlatformVersionAnalyzer:
    """Comprehensive platform version analyzer for Android applications."""
    
    def __init__(self, apk_ctx):
        """Initialize the platform version analyzer.
        
        Args:
            apk_ctx: APK context object containing app information and analysis data
        """
        self.apk_ctx = apk_ctx
        self.package_name = apk_ctx.package_name
        self.findings: List[PlatformVersionFinding] = []
        self.detailed_vulnerabilities: List[DetailedVulnerability] = []
        self.detailed_reporter = DetailedVulnerabilityReporter() if DETAILED_FRAMEWORK_AVAILABLE else None
        
        # Current recommended SDK versions (as of 2024)
        self.current_recommendations = {
            "target_sdk": 34,  # Android 14 (API level 34)
            "min_target_sdk": 33,  # Android 13 (API level 33) minimum recommended
            "compile_sdk": 34,  # Android 14 (API level 34)
            "min_sdk": 21,  # Android 5.0 (API level 21) minimum for security
            "deprecation_threshold": 28  # Android 9 (API level 28) - below this is concerning
        }
        
        # SDK version security implications
        self.security_implications = {
            "below_21": {
                "severity": "CRITICAL",
                "issues": [
                    "No runtime permissions model",
                    "Weak TLS/SSL implementation",
                    "Limited security provider updates",
                    "No app backup encryption",
                    "Vulnerable WebView implementation"
                ],
                "cves": ["CVE-2014-6041", "CVE-2014-7911", "CVE-2015-1538"]
            },
            "21_to_23": {
                "severity": "HIGH",
                "issues": [
                    "Basic runtime permissions only",
                    "Limited network security config",
                    "Weak crypto defaults",
                    "No backup encryption by default"
                ],
                "cves": ["CVE-2016-2460", "CVE-2016-3861"]
            },
            "24_to_26": {
                "severity": "MEDIUM",
                "issues": [
                    "Limited security provider updates",
                    "Weak default TLS configuration",
                    "No automatic backup encryption"
                ],
                "cves": ["CVE-2017-0561", "CVE-2017-13156"]
            },
            "27_to_29": {
                "severity": "LOW",
                "issues": [
                    "Some security features not enabled by default",
                    "Limited background restrictions"
                ],
                "cves": ["CVE-2019-2215"]
            },
            "30_plus": {
                "severity": "INFO",
                "issues": [],
                "benefits": [
                    "Strong runtime permissions",
                    "Network security config enforced",
                    "Scoped storage protection",
                    "Background restrictions",
                    "Strong crypto defaults"
                ]
            }
        }
        
        # Deprecated API patterns with security implications
        self.deprecated_apis = {
            "network": {
                "patterns": [
                    r"HttpClient",
                    r"DefaultHttpClient",
                    r"BasicHttpParams",
                    r"org\.apache\.http"
                ],
                "replacement": "HttpURLConnection or OkHttp",
                "security_impact": "Weak TLS/SSL implementation, vulnerable to MITM attacks",
                "deprecated_in": 23,
                "removed_in": 28
            },
            "crypto": {
                "patterns": [
                    r"Cipher\.getInstance\(\"AES\"\)",
                    r"Cipher\.getInstance\(\"DES\"\)",
                    r"MessageDigest\.getInstance\(\"MD5\"\)",
                    r"MessageDigest\.getInstance\(\"SHA1\"\)"
                ],
                "replacement": "Use AES-256-GCM, SHA-256 or higher",
                "security_impact": "Weak cryptographic algorithms vulnerable to attacks",
                "deprecated_in": 21,
                "removed_in": None
            },
            "storage": {
                "patterns": [
                    r"getExternalStorageDirectory\(\)",
                    r"Environment\.getExternalStorageDirectory",
                    r"MODE_WORLD_READABLE",
                    r"MODE_WORLD_WRITEABLE"
                ],
                "replacement": "Scoped storage, internal storage, or EncryptedSharedPreferences",
                "security_impact": "Data exposure through external storage or world-accessible files",
                "deprecated_in": 29,
                "removed_in": 30
            },
            "permissions": {
                "patterns": [
                    r"requestPermissions.*WRITE_EXTERNAL_STORAGE",
                    r"checkSelfPermission.*WRITE_EXTERNAL_STORAGE"
                ],
                "replacement": "Scoped storage for Android 10+",
                "security_impact": "Broad storage access permissions unnecessary in modern Android",
                "deprecated_in": 29,
                "removed_in": None
            },
            "webview": {
                "patterns": [
                    r"WebView.*setPluginsEnabled",
                    r"WebSettings.*setPluginsEnabled",
                    r"WebView.*setPictureListener"
                ],
                "replacement": "Modern WebView security configurations",
                "security_impact": "Deprecated WebView features with security vulnerabilities",
                "deprecated_in": 18,
                "removed_in": 24
            }
        }

    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive platform version analysis.
        
        Returns:
            Dict containing analysis results, findings, and MASVS compliance status
        """
        logger.debug("Starting platform version analysis...")
        
        results = {
            "sdk_versions": {},
            "deprecated_apis": [],
            "security_assessment": {},
            "compliance_status": "UNKNOWN",
            "risk_score": 0,
            "recommendations": [],
            "masvs_controls": []
        }
        
        try:
            # Analyze SDK versions from manifest
            self._analyze_sdk_versions(results)
            
            # Analyze deprecated API usage
            self._analyze_deprecated_apis(results)
            
            # Assess security implications
            self._assess_security_implications(results)
            
            # Calculate compliance and risk score
            self._calculate_compliance_status(results)
            self._calculate_risk_score(results)
            
            # Generate recommendations
            self._generate_recommendations(results)
            
            # Map to MASVS controls
            self._map_masvs_controls(results)
            
            logger.debug(f"Platform version analysis completed. Found {len(self.findings)} findings.")
            
        except Exception as e:
            logger.error(f"Error during platform version analysis: {e}")
            results["error"] = str(e)
            
        return results

    def _analyze_sdk_versions(self, results: Dict[str, Any]) -> None:
        """Analyze SDK versions from AndroidManifest.xml."""
        sdk_info = {
            "target_sdk": None,
            "min_sdk": None,
            "compile_sdk": None,
            "max_sdk": None
        }
        
        try:
            # Get manifest XML
            if hasattr(self.apk_ctx, 'get_android_manifest_xml'):
                manifest_xml = self.apk_ctx.get_android_manifest_xml()
                if manifest_xml:
                    self._parse_manifest_sdk_versions(manifest_xml, sdk_info)
            
            # Try alternative methods if manifest not available
            if not any(sdk_info.values()):
                self._extract_sdk_from_apk_info(sdk_info)
            
            results["sdk_versions"] = sdk_info
            
            # Create findings for SDK version issues
            self._analyze_sdk_version_security(sdk_info)
            
        except Exception as e:
            logger.debug(f"Error analyzing SDK versions: {e}")

    def _parse_manifest_sdk_versions(self, manifest_xml: str, sdk_info: Dict) -> None:
        """Parse SDK versions from manifest XML."""
        try:
            # Parse XML
            root = ET.fromstring(manifest_xml)
            
            # Find uses-sdk element
            uses_sdk = root.find('uses-sdk')
            if uses_sdk is not None:
                # Extract SDK versions
                sdk_info["min_sdk"] = self._extract_sdk_level(uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion'))
                sdk_info["target_sdk"] = self._extract_sdk_level(uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion'))
                sdk_info["max_sdk"] = self._extract_sdk_level(uses_sdk.get('{http://schemas.android.com/apk/res/android}maxSdkVersion'))
            
            # Check for compileSdkVersion in build files if available
            if hasattr(self.apk_ctx, 'get_files'):
                for file_path, content in self.apk_ctx.get_files().items():
                    if 'build.gradle' in file_path or 'gradle.properties' in file_path:
                        compile_sdk = self._extract_compile_sdk_from_gradle(content)
                        if compile_sdk:
                            sdk_info["compile_sdk"] = compile_sdk
                            break
            
        except ET.ParseError as e:
            logger.debug(f"Error parsing manifest XML: {e}")
        except Exception as e:
            logger.debug(f"Error extracting SDK versions: {e}")

    def _extract_sdk_level(self, sdk_value: Optional[str]) -> Optional[int]:
        """Extract numeric SDK level from string value."""
        if not sdk_value:
            return None
        
        try:
            # Handle numeric values
            if sdk_value.isdigit():
                return int(sdk_value)
            
            # Handle named API levels (if any)
            api_name_mapping = {
                "L": 21,
                "M": 23,
                "N": 24,
                "O": 26,
                "P": 28,
                "Q": 29,
                "R": 30,
                "S": 31,
                "T": 33,
                "U": 34
            }
            
            return api_name_mapping.get(sdk_value.upper())
            
        except (ValueError, AttributeError):
            return None

    def _extract_compile_sdk_from_gradle(self, gradle_content: str) -> Optional[int]:
        """Extract compileSdkVersion from Gradle build file."""
        patterns = [
            r'compileSdkVersion\s+(\d+)',
            r'compileSdk\s+(\d+)',
            r'compileSdkVersion\s*=\s*(\d+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, gradle_content)
            if match:
                try:
                    return int(match.group(1))
                except ValueError:
                    continue
        
        return None

    def _extract_sdk_from_apk_info(self, sdk_info: Dict) -> None:
        """Extract SDK info from APK context if available."""
        try:
            if hasattr(self.apk_ctx, 'get_target_sdk'):
                sdk_info["target_sdk"] = self.apk_ctx.get_target_sdk()
            
            if hasattr(self.apk_ctx, 'get_min_sdk'):
                sdk_info["min_sdk"] = self.apk_ctx.get_min_sdk()
                
            if hasattr(self.apk_ctx, 'get_effective_target_sdk'):
                target_sdk = self.apk_ctx.get_effective_target_sdk()
                if target_sdk and not sdk_info["target_sdk"]:
                    sdk_info["target_sdk"] = target_sdk
                    
        except Exception as e:
            logger.debug(f"Error extracting SDK from APK context: {e}")

    def _analyze_sdk_version_security(self, sdk_info: Dict) -> None:
        """Analyze SDK versions for security implications."""
        target_sdk = sdk_info.get("target_sdk")
        min_sdk = sdk_info.get("min_sdk")
        compile_sdk = sdk_info.get("compile_sdk")
        
        # Analyze target SDK version
        if target_sdk:
            if target_sdk < self.current_recommendations["min_target_sdk"]:
                severity = "HIGH" if target_sdk < self.current_recommendations["deprecation_threshold"] else "MEDIUM"
                self._create_finding(
                    "outdated_target_sdk",
                    "AndroidManifest.xml",
                    severity,
                    f"Target SDK version {target_sdk} is outdated",
                    f"targetSdkVersion: {target_sdk}",
                    f"Update targetSdkVersion to {self.current_recommendations['target_sdk']} or higher",
                    str(target_sdk),
                    0
                )
            
            # Check security implications
            security_category = self._get_security_category_for_sdk(target_sdk)
            if security_category and security_category["severity"] in ["CRITICAL", "HIGH"]:
                for issue in security_category["issues"]:
                    self._create_finding(
                        "sdk_security_issue",
                        "AndroidManifest.xml",
                        security_category["severity"],
                        f"Security issue with target SDK {target_sdk}: {issue}",
                        f"targetSdkVersion: {target_sdk}",
                        f"Update to API level {self.current_recommendations['target_sdk']} to address security issues",
                        str(target_sdk),
                        0
                    )
        
        # Analyze minimum SDK version
        if min_sdk and min_sdk < self.current_recommendations["min_sdk"]:
            self._create_finding(
                "low_min_sdk",
                "AndroidManifest.xml",
                "MEDIUM",
                f"Minimum SDK version {min_sdk} is very low",
                f"minSdkVersion: {min_sdk}",
                f"Consider raising minSdkVersion to {self.current_recommendations['min_sdk']} for better security",
                str(min_sdk),
                0
            )
        
        # Analyze compile SDK version
        if compile_sdk and compile_sdk < self.current_recommendations["compile_sdk"]:
            self._create_finding(
                "outdated_compile_sdk",
                "build.gradle",
                "MEDIUM",
                f"Compile SDK version {compile_sdk} is outdated", 
                f"compileSdkVersion: {compile_sdk}",
                f"Update compileSdkVersion to {self.current_recommendations['compile_sdk']}",
                str(compile_sdk),
                0
            )

    def _get_security_category_for_sdk(self, sdk_version: int) -> Optional[Dict]:
        """Get security category for SDK version."""
        if sdk_version < 21:
            return self.security_implications["below_21"]
        elif 21 <= sdk_version <= 23:
            return self.security_implications["21_to_23"]
        elif 24 <= sdk_version <= 26:
            return self.security_implications["24_to_26"]
        elif 27 <= sdk_version <= 29:
            return self.security_implications["27_to_29"]
        elif sdk_version >= 30:
            return self.security_implications["30_plus"]
        
        return None

    def _analyze_deprecated_apis(self, results: Dict[str, Any]) -> None:
        """Analyze deprecated API usage."""
        deprecated_apis = []
        
        # Analyze source files for deprecated API usage
        if hasattr(self.apk_ctx, 'get_java_files'):
            java_files = self.apk_ctx.get_java_files()
            for file_path, content in java_files.items():
                apis = self._find_deprecated_apis_in_file(file_path, content)
                deprecated_apis.extend(apis)
        
        # Analyze DEX files if available
        if hasattr(self.apk_ctx, 'get_classes'):
            classes = self.apk_ctx.get_classes()
            for class_item in classes:
                apis = self._analyze_class_for_deprecated_apis(class_item)
                deprecated_apis.extend(apis)
        
        results["deprecated_apis"] = deprecated_apis

    def _find_deprecated_apis_in_file(self, file_path: str, content: str) -> List[Dict]:
        """Find deprecated APIs in a Java file."""
        deprecated_apis = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for category, api_info in self.deprecated_apis.items():
                for pattern in api_info["patterns"]:
                    if re.search(pattern, line):
                        deprecated_apis.append({
                            "category": category,
                            "file": file_path,
                            "line": line_num,
                            "code": line.strip(),
                            "pattern": pattern,
                            "replacement": api_info["replacement"],
                            "security_impact": api_info["security_impact"],
                            "deprecated_in": api_info["deprecated_in"],
                            "removed_in": api_info["removed_in"]
                        })
                        
                        # Create finding
                        severity = "HIGH" if api_info.get("removed_in") else "MEDIUM"
                        self._create_finding(
                            "deprecated_api_usage",
                            f"{file_path}:{line_num}",
                            severity,
                            f"Deprecated {category} API detected: {api_info['security_impact']}",
                            line.strip(),
                            f"Replace with {api_info['replacement']}",
                            pattern,
                            line_num
                        )
        
        return deprecated_apis

    def _analyze_class_for_deprecated_apis(self, class_item) -> List[Dict]:
        """Analyze a DEX class for deprecated API usage."""
        deprecated_apis = []
        
        try:
            class_name = class_item.get_name() if hasattr(class_item, 'get_name') else str(class_item)
            
            # Check for deprecated API usage in method calls
            if hasattr(class_item, 'get_methods'):
                for method in class_item.get_methods():
                    apis = self._analyze_method_for_deprecated_apis(method, class_name)
                    deprecated_apis.extend(apis)
                    
        except Exception as e:
            logger.debug(f"Error analyzing class for deprecated APIs: {e}")
        
        return deprecated_apis

    def _analyze_method_for_deprecated_apis(self, method, class_name: str) -> List[Dict]:
        """Analyze a method for deprecated API calls."""
        deprecated_apis = []
        
        try:
            method_name = method.get_name() if hasattr(method, 'get_name') else str(method)
            
            if hasattr(method, 'get_code'):
                code = method.get_code()
                if code:
                    # Check for specific deprecated API calls
                    deprecated_calls = [
                        "HttpClient", "DefaultHttpClient", "getExternalStorageDirectory",
                        "MODE_WORLD_READABLE", "MODE_WORLD_WRITEABLE"
                    ]
                    
                    for instruction in code.get_bc().get_instructions():
                        instruction_str = str(instruction)
                        for deprecated_call in deprecated_calls:
                            if deprecated_call in instruction_str:
                                deprecated_apis.append({
                                    "category": "method_call",
                                    "class": class_name,
                                    "method": method_name,
                                    "call": deprecated_call,
                                    "instruction": instruction_str
                                })
                                
                                self._create_finding(
                                    "deprecated_method_call",
                                    f"{class_name}::{method_name}",
                                    "MEDIUM",
                                    f"Deprecated API call: {deprecated_call}",
                                    instruction_str,
                                    "Replace with modern alternative API",
                                    deprecated_call,
                                    0
                                )
                                
        except Exception as e:
            logger.debug(f"Error analyzing method for deprecated APIs: {e}")
        
        return deprecated_apis

    def _assess_security_implications(self, results: Dict[str, Any]) -> None:
        """Assess security implications of platform version choices."""
        sdk_versions = results.get("sdk_versions", {})
        deprecated_apis = results.get("deprecated_apis", [])
        
        assessment = {
            "target_sdk_security": {},
            "min_sdk_security": {},
            "deprecated_api_risks": [],
            "overall_risk_level": "UNKNOWN"
        }
        
        # Assess target SDK security
        target_sdk = sdk_versions.get("target_sdk")
        if target_sdk:
            security_category = self._get_security_category_for_sdk(target_sdk)
            if security_category:
                assessment["target_sdk_security"] = {
                    "version": target_sdk,
                    "severity": security_category["severity"],
                    "issues": security_category["issues"],
                    "benefits": security_category.get("benefits", []),
                    "cves": security_category.get("cves", [])
                }
        
        # Assess minimum SDK security
        min_sdk = sdk_versions.get("min_sdk")
        if min_sdk:
            min_security_category = self._get_security_category_for_sdk(min_sdk)
            if min_security_category:
                assessment["min_sdk_security"] = {
                    "version": min_sdk,
                    "severity": min_security_category["severity"],
                    "issues": min_security_category["issues"],
                    "impact": f"App can run on devices with security vulnerabilities from API level {min_sdk}"
                }
        
        # Assess deprecated API risks
        for api in deprecated_apis:
            assessment["deprecated_api_risks"].append({
                "category": api["category"],
                "security_impact": api["security_impact"],
                "removed_in": api.get("removed_in"),
                "deprecated_in": api.get("deprecated_in")
            })
        
        # Determine overall risk level
        if target_sdk and target_sdk < 24:
            assessment["overall_risk_level"] = "CRITICAL"
        elif target_sdk and target_sdk < 28:
            assessment["overall_risk_level"] = "HIGH"
        elif target_sdk and target_sdk < 31:
            assessment["overall_risk_level"] = "MEDIUM"
        elif deprecated_apis:
            assessment["overall_risk_level"] = "MEDIUM"
        else:
            assessment["overall_risk_level"] = "LOW"
        
        results["security_assessment"] = assessment

    def _calculate_compliance_status(self, results: Dict[str, Any]) -> None:
        """Calculate MASVS-CODE-3 compliance status."""
        sdk_versions = results.get("sdk_versions", {})
        security_assessment = results.get("security_assessment", {})
        deprecated_apis = results.get("deprecated_apis", [])
        
        target_sdk = sdk_versions.get("target_sdk")
        overall_risk = security_assessment.get("overall_risk_level", "UNKNOWN")
        
        # Determine compliance status
        if not target_sdk:
            results["compliance_status"] = "UNKNOWN"
        elif target_sdk >= self.current_recommendations["target_sdk"]:
            results["compliance_status"] = "COMPLIANT"
        elif target_sdk >= self.current_recommendations["min_target_sdk"]:
            if overall_risk in ["LOW", "MEDIUM"]:
                results["compliance_status"] = "PARTIALLY_COMPLIANT"
            else:
                results["compliance_status"] = "NON_COMPLIANT"
        else:
            results["compliance_status"] = "NON_COMPLIANT"

    def _calculate_risk_score(self, results: Dict[str, Any]) -> None:
        """Calculate risk score based on platform version analysis."""
        base_score = 100  # Start with perfect score
        
        sdk_versions = results.get("sdk_versions", {})
        deprecated_apis = results.get("deprecated_apis", [])
        security_assessment = results.get("security_assessment", {})
        
        # Deduct points for outdated target SDK
        target_sdk = sdk_versions.get("target_sdk")
        if target_sdk:
            recommended_target = self.current_recommendations["target_sdk"]
            if target_sdk < recommended_target:
                deduction = (recommended_target - target_sdk) * 5
                base_score -= min(deduction, 50)  # Max 50 points deduction
        
        # Deduct points for deprecated APIs
        for api in deprecated_apis:
            if api.get("removed_in"):
                base_score -= 15  # Removed APIs are more serious
            else:
                base_score -= 10  # Deprecated APIs
        
        # Deduct points based on security assessment
        overall_risk = security_assessment.get("overall_risk_level", "LOW")
        risk_deductions = {
            "CRITICAL": 40,
            "HIGH": 30,
            "MEDIUM": 20,
            "LOW": 5
        }
        base_score -= risk_deductions.get(overall_risk, 0)
        
        # Normalize score to 0-100 range
        risk_score = max(0, min(100, base_score))
        results["risk_score"] = risk_score

    def _generate_recommendations(self, results: Dict[str, Any]) -> None:
        """Generate platform version recommendations."""
        recommendations = []
        
        sdk_versions = results.get("sdk_versions", {})
        deprecated_apis = results.get("deprecated_apis", [])
        compliance_status = results.get("compliance_status", "UNKNOWN")
        
        # SDK version recommendations
        target_sdk = sdk_versions.get("target_sdk")
        if target_sdk and target_sdk < self.current_recommendations["target_sdk"]:
            recommendations.append({
                "category": "Platform Version",
                "title": "Update Target SDK Version",
                "description": f"Update targetSdkVersion from {target_sdk} to {self.current_recommendations['target_sdk']}",
                "priority": "HIGH" if target_sdk < self.current_recommendations["min_target_sdk"] else "MEDIUM",
                "benefits": [
                    "Access to latest security features",
                    "Better runtime permissions",
                    "Improved app performance",
                    "Required for Play Store submissions"
                ]
            })
        
        min_sdk = sdk_versions.get("min_sdk")
        if min_sdk and min_sdk < self.current_recommendations["min_sdk"]:
            recommendations.append({
                "category": "Platform Version",
                "title": "Consider Raising Minimum SDK Version",
                "description": f"Consider raising minSdkVersion from {min_sdk} to {self.current_recommendations['min_sdk']}",
                "priority": "MEDIUM",
                "benefits": [
                    "Better security baseline",
                    "Access to modern security APIs",
                    "Reduced security vulnerabilities"
                ],
                "considerations": [
                    "May reduce device compatibility",
                    "Analyze user base before implementing"
                ]
            })
        
        # Deprecated API recommendations
        if deprecated_apis:
            categories = set(api["category"] for api in deprecated_apis)
            for category in categories:
                category_apis = [api for api in deprecated_apis if api["category"] == category]
                recommendations.append({
                    "category": "Deprecated APIs",
                    "title": f"Replace Deprecated {category.title()} APIs",
                    "description": f"Replace {len(category_apis)} deprecated {category} API(s)",
                    "priority": "HIGH" if any(api.get("removed_in") for api in category_apis) else "MEDIUM",
                    "details": [
                        {
                            "api": api["pattern"],
                            "replacement": api["replacement"],
                            "security_impact": api["security_impact"]
                        }
                        for api in category_apis[:3]  # Show top 3
                    ]
                })
        
        # General recommendations
        recommendations.extend([
            {
                "category": "Security",
                "title": "Regular Platform Updates",
                "description": "Establish a process for regular platform version updates",
                "priority": "LOW",
                "actions": [
                    "Monitor Android security bulletins",
                    "Test app with new API levels",
                    "Update target SDK annually"
                ]
            },
            {
                "category": "Development",
                "title": "API Deprecation Monitoring",
                "description": "Implement monitoring for deprecated API usage",
                "priority": "LOW",
                "actions": [
                    "Use lint checks for deprecated APIs",
                    "Review API usage during code reviews",
                    "Set up automated detection in CI/CD"
                ]
            }
        ])
        
        results["recommendations"] = recommendations

    def _map_masvs_controls(self, results: Dict[str, Any]) -> None:
        """Map findings to MASVS controls."""
        compliance_status = results.get("compliance_status", "UNKNOWN")
        sdk_versions = results.get("sdk_versions", {})
        deprecated_apis = results.get("deprecated_apis", [])
        
        # Map to MASVS-CODE-3
        status = "PASS"
        if compliance_status == "NON_COMPLIANT":
            status = "FAIL"
        elif compliance_status == "PARTIALLY_COMPLIANT":
            status = "PARTIAL"
        elif compliance_status == "UNKNOWN":
            status = "UNKNOWN"
        
        masvs_control = {
            "control_id": "MASVS-CODE-3",
            "control_name": "Platform Version Targeting",
            "status": status,
            "findings": len(deprecated_apis),
            "compliance_status": compliance_status,
            "description": "The app targets a recent platform version",
            "details": {
                "target_sdk": sdk_versions.get("target_sdk"),
                "min_sdk": sdk_versions.get("min_sdk"),
                "compile_sdk": sdk_versions.get("compile_sdk"),
                "deprecated_api_count": len(deprecated_apis)
            }
        }
        
        results["masvs_controls"] = [masvs_control]

    def _create_finding(self, finding_type: str, location: str, severity: str,
                       description: str, evidence: str, remediation: str,
                       sdk_version: str, line_number: int) -> None:
        """Create a platform version finding."""
        finding = PlatformVersionFinding(
            finding_type=finding_type,
            location=location,
            severity=severity,
            description=description,
            evidence=evidence,
            remediation=remediation,
            sdk_version=sdk_version,
            line_number=line_number
        )
        
        self.findings.append(finding)
        
        # Create detailed vulnerability if framework available
        if DETAILED_FRAMEWORK_AVAILABLE:
            vulnerability = create_detailed_vulnerability(
                vulnerability_type=finding_type,
                severity=severity,
                cwe_id=self._get_cwe_for_finding_type(finding_type),
                masvs_control="MASVS-CODE-3",
                location=VulnerabilityLocation(
                    file_path=location.split(':')[0] if ':' in location else location,
                    line_number=line_number if line_number > 0 else None,
                    component_type="Platform Version Configuration"
                ),
                security_impact=description,
                remediation=RemediationGuidance(
                    fix_description=remediation,
                    code_example=self._get_code_example_for_finding(finding_type)
                ),
                evidence=VulnerabilityEvidence(
                    matched_pattern=evidence,
                    detection_method="Platform Version Analysis",
                    confidence_score=self._get_confidence_for_finding_type(finding_type)
                )
            )
            self.detailed_vulnerabilities.append(vulnerability)

    def _get_cwe_for_finding_type(self, finding_type: str) -> str:
        """Get CWE ID for finding type."""
        cwe_mapping = {
            "outdated_target_sdk": "CWE-1104",  # Use of Unmaintained Third Party Components
            "low_min_sdk": "CWE-1104",  # Use of Unmaintained Third Party Components
            "outdated_compile_sdk": "CWE-1104",  # Use of Unmaintained Third Party Components
            "deprecated_api_usage": "CWE-477",  # Use of Obsolete Function
            "deprecated_method_call": "CWE-477",  # Use of Obsolete Function
            "sdk_security_issue": "CWE-1188"  # Deprecated Functionality
        }
        return cwe_mapping.get(finding_type, "CWE-1104")

    def _get_confidence_for_finding_type(self, finding_type: str) -> float:
        """Get confidence score for finding type."""
        confidence_mapping = {
            "outdated_target_sdk": 0.95,
            "low_min_sdk": 0.90,
            "outdated_compile_sdk": 0.85,
            "deprecated_api_usage": 0.80,
            "deprecated_method_call": 0.75,
            "sdk_security_issue": 0.85
        }
        return confidence_mapping.get(finding_type, 0.80)

    def _get_code_example_for_finding(self, finding_type: str) -> str:
        """Get code example for finding remediation."""
        examples = {
            "outdated_target_sdk": """
// Update AndroidManifest.xml or build.gradle
android {
    compileSdkVersion 34
    targetSdkVersion 34
}
            """,
            "deprecated_api_usage": """
// Replace deprecated HttpClient with modern alternative
// OLD: HttpClient client = new DefaultHttpClient();
// NEW: Use OkHttp or HttpURLConnection
OkHttpClient client = new OkHttpClient();
            """,
            "low_min_sdk": """
// Consider raising minimum SDK version
android {
    minSdkVersion 21  // Android 5.0 for better security
    targetSdkVersion 34
}
            """
        }
        return examples.get(finding_type, "// Update to use modern platform features")

    def get_findings(self) -> List[PlatformVersionFinding]:
        """Get all platform version findings."""
        return self.findings

    def get_detailed_vulnerabilities(self) -> List[DetailedVulnerability]:
        """Get detailed vulnerabilities if framework available."""
        return self.detailed_vulnerabilities if DETAILED_FRAMEWORK_AVAILABLE else []

def analyze_platform_version(apk_ctx) -> Dict[str, Any]:
    """
    Main function to analyze platform version targeting.
    
    Args:
        apk_ctx: APK context object
        
    Returns:
        Dict containing comprehensive platform version analysis results
    """
    analyzer = PlatformVersionAnalyzer(apk_ctx)
    return analyzer.analyze()

# Plugin integration functions
def run_plugin(apk_ctx, deep_mode: bool = False) -> Dict[str, Any]:
    """
    Execute platform version analysis plugin.
    
    Args:
        apk_ctx: APK context object
        deep_mode: Whether to run deep analysis (currently not used)
        
    Returns:
        Dict containing plugin results
    """
    try:
        # Run the analysis
        analyzer = PlatformVersionAnalyzer(apk_ctx)
        results = analyzer.analyze()
        
        # Format results for plugin framework
        plugin_results = {
            "plugin_name": "Platform Version Analysis",
            "version": "1.0.0",
            "masvs_controls": results.get("masvs_controls", []),
            "compliance_status": results.get("compliance_status", "UNKNOWN"),
            "risk_score": results.get("risk_score", 0),
            "findings": {
                "sdk_versions": results.get("sdk_versions", {}),
                "deprecated_apis": results.get("deprecated_apis", []),
                "security_assessment": results.get("security_assessment", {})
            },
            "recommendations": results.get("recommendations", []),
            "summary": _generate_summary(results),
            "detailed_vulnerabilities_count": len(analyzer.get_detailed_vulnerabilities())
        }
        
        return plugin_results
        
    except Exception as e:
        logger.error(f"Platform version analysis plugin failed: {e}")
        return {
            "plugin_name": "Platform Version Analysis",
            "error": str(e),
            "status": "FAILED"
        }

def _generate_summary(results: Dict[str, Any]) -> str:
    """Generate summary of platform version analysis."""
    compliance_status = results.get("compliance_status", "UNKNOWN")
    risk_score = results.get("risk_score", 0)
    sdk_versions = results.get("sdk_versions", {})
    deprecated_apis = results.get("deprecated_apis", [])
    
    target_sdk = sdk_versions.get("target_sdk", "Unknown")
    api_count = len(deprecated_apis)
    
    summary = f"Platform version analysis completed. "
    summary += f"Compliance: {compliance_status}, Risk Score: {risk_score}/100. "
    summary += f"Target SDK: {target_sdk}, Found {api_count} deprecated APIs."
    
    return summary

# Plugin characteristics for AODS framework integration
PLUGIN_CHARACTERISTICS = {
    "name": "Platform Version Analysis",
    "description": "Comprehensive platform version analysis for MASVS-CODE-3 compliance",
    "version": "1.0.0",
    "author": "AODS Framework",
    "category": "CODE_ANALYSIS",
    "mode": "comprehensive",
    "masvs_controls": ["MASVS-CODE-3"],
    "requires_device": False,
    "requires_network": False,
    "invasive": False,
    "execution_time_estimate": 20,
    "dependencies": []
} 