#!/usr/bin/env python3
"""
Platform Authentication Analyzer for AODS

This module implements comprehensive platform authentication analysis for MASVS-PLATFORM-2 compliance.
It detects usage of platform-provided authentication APIs, validates proper implementation,
and identifies security misconfigurations.

MASVS Controls Covered:
- MASVS-PLATFORM-2: The app uses platform-provided authentication APIs

Security Analysis Features:
- BiometricManager and FingerprintManager API usage detection
- Biometric authentication flow validation
- Custom authentication bypass detection
- Authentication token handling analysis
- Multi-factor authentication compliance validation

"""

import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union

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

class PlatformAuthFinding:
    """Data class for platform authentication findings."""
    
    def __init__(self, finding_type: str, location: str, severity: str, 
                 description: str, evidence: str = "", remediation: str = "",
                 api_name: str = "", line_number: int = 0):
        self.finding_type = finding_type
        self.location = location
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.remediation = remediation
        self.api_name = api_name
        self.line_number = line_number
        self.masvs_control = "MASVS-PLATFORM-2"
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return {
            "finding_type": self.finding_type,
            "location": self.location,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "api_name": self.api_name,
            "line_number": self.line_number,
            "masvs_control": self.masvs_control
        }

class PlatformAuthenticationAnalyzer:
    """Comprehensive platform authentication analyzer for Android applications."""
    
    def __init__(self, apk_ctx):
        """Initialize the platform authentication analyzer.
        
        Args:
            apk_ctx: APK context object containing app information and analysis data
        """
        self.apk_ctx = apk_ctx
        self.package_name = apk_ctx.package_name
        self.findings: List[PlatformAuthFinding] = []
        self.detailed_vulnerabilities: List[DetailedVulnerability] = []
        self.detailed_reporter = DetailedVulnerabilityReporter() if DETAILED_FRAMEWORK_AVAILABLE else None
        
        # Platform authentication API patterns
        self.platform_auth_apis = {
            "BiometricManager": {
                "import_patterns": [
                    r"import\s+androidx\.biometric\.BiometricManager",
                    r"import\s+androidx\.biometric\.\*"
                ],
                "usage_patterns": [
                    r"BiometricManager\.from\(",
                    r"BiometricManager\.canAuthenticate\(",
                    r"BIOMETRIC_SUCCESS",
                    r"BIOMETRIC_ERROR_",
                    r"BIOMETRIC_STATUS_"
                ],
                "methods": [
                    "canAuthenticate", "from", "isHardwareDetected"
                ]
            },
            "BiometricPrompt": {
                "import_patterns": [
                    r"import\s+androidx\.biometric\.BiometricPrompt",
                    r"import\s+androidx\.biometric\.\*"
                ],
                "usage_patterns": [
                    r"BiometricPrompt\(",
                    r"BiometricPrompt\.Builder\(",
                    r"authenticate\(",
                    r"AuthenticationCallback",
                    r"AuthenticationResult"
                ],
                "methods": [
                    "authenticate", "Builder", "AuthenticationCallback"
                ]
            },
            "FingerprintManager": {
                "import_patterns": [
                    r"import\s+android\.hardware\.fingerprint\.FingerprintManager",
                    r"import\s+android\.support\.v4\.hardware\.fingerprint\.FingerprintManagerCompat"
                ],
                "usage_patterns": [
                    r"FingerprintManager\.from\(",
                    r"FingerprintManagerCompat\.from\(",
                    r"authenticate\(",
                    r"isHardwareDetected\(",
                    r"hasEnrolledFingerprints\("
                ],
                "methods": [
                    "authenticate", "isHardwareDetected", "hasEnrolledFingerprints"
                ],
                "deprecated": True
            },
            "KeyguardManager": {
                "import_patterns": [
                    r"import\s+android\.app\.KeyguardManager"
                ],
                "usage_patterns": [
                    r"KeyguardManager",
                    r"isKeyguardSecure\(",
                    r"isDeviceSecure\(",
                    r"createConfirmDeviceCredentialIntent\("
                ],
                "methods": [
                    "isKeyguardSecure", "isDeviceSecure", "createConfirmDeviceCredentialIntent"
                ]
            }
        }
        
        # Security patterns to detect
        self.security_patterns = {
            "insecure_storage": [
                r"SharedPreferences.*putString.*auth",
                r"SharedPreferences.*putString.*token",
                r"SharedPreferences.*putString.*biometric",
                r"\.edit\(\)\.putString\(.*auth.*\)",
                r"preferences\.putString\(.*token.*\)"
            ],
            "custom_auth_bypass": [
                r"if\s*\(\s*DEBUG\s*\)",
                r"if\s*\(\s*BuildConfig\.DEBUG\s*\)",
                r"bypass.*auth",
                r"skip.*authentication",
                r"disable.*biometric"
            ],
            "hardcoded_credentials": [
                r"password\s*=\s*[\"'][^\"']+[\"']",
                r"secret\s*=\s*[\"'][^\"']+[\"']",
                r"api_key\s*=\s*[\"'][^\"']+[\"']",
                r"token\s*=\s*[\"'][^\"']+[\"']"
            ],
            "weak_crypto": [
                r"MD5\(",
                r"SHA1\(",
                r"DES\(",
                r"ECB",
                r"Cipher\.getInstance\(\"AES\"\)"
            ]
        }

    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive platform authentication analysis.
        
        Returns:
            Dict containing analysis results, findings, and MASVS compliance status
        """
        logger.debug("Starting platform authentication analysis...")
        
        results = {
            "platform_auth_usage": {},
            "authentication_flows": [],
            "security_issues": [],
            "compliance_status": "UNKNOWN",
            "risk_score": 0,
            "recommendations": [],
            "masvs_controls": []
        }
        
        try:
            # Analyze platform authentication API usage
            self._analyze_platform_auth_apis(results)
            
            # Analyze authentication flows
            self._analyze_authentication_flows(results)
            
            # Check for security issues
            self._analyze_security_issues(results)
            
            # Analyze manifest permissions
            self._analyze_manifest_permissions(results)
            
            # Calculate compliance and risk score
            self._calculate_compliance_status(results)
            self._calculate_risk_score(results)
            
            # Generate recommendations
            self._generate_recommendations(results)
            
            # Map to MASVS controls
            self._map_masvs_controls(results)
            
            logger.debug(f"Platform authentication analysis completed. Found {len(self.findings)} findings.")
            
        except Exception as e:
            logger.error(f"Error during platform authentication analysis: {e}")
            results["error"] = str(e)
            
        return results

    def _analyze_platform_auth_apis(self, results: Dict[str, Any]) -> None:
        """Analyze usage of platform authentication APIs."""
        platform_usage = {}
        
        # Analyze source files for API usage
        if hasattr(self.apk_ctx, 'get_java_files'):
            java_files = self.apk_ctx.get_java_files()
            for file_path, content in java_files.items():
                self._analyze_file_for_auth_apis(file_path, content, platform_usage)
        
        # Analyze DEX files if available
        if hasattr(self.apk_ctx, 'get_classes'):
            classes = self.apk_ctx.get_classes()
            for class_item in classes:
                self._analyze_class_for_auth_apis(class_item, platform_usage)
        
        results["platform_auth_usage"] = platform_usage
        
    def _analyze_file_for_auth_apis(self, file_path: str, content: str, platform_usage: Dict) -> None:
        """Analyze a Java file for platform authentication API usage."""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for api_name, api_info in self.platform_auth_apis.items():
                # Check for imports
                for import_pattern in api_info["import_patterns"]:
                    if re.search(import_pattern, line):
                        if api_name not in platform_usage:
                            platform_usage[api_name] = {
                                "imports": [],
                                "usage": [],
                                "deprecated": api_info.get("deprecated", False)
                            }
                        
                        platform_usage[api_name]["imports"].append({
                            "file": file_path,
                            "line": line_num,
                            "code": line.strip()
                        })
                        
                        # Create finding for deprecated API usage
                        if api_info.get("deprecated", False):
                            self._create_finding(
                                "deprecated_api_usage",
                                f"{file_path}:{line_num}",
                                "MEDIUM",
                                f"Deprecated authentication API {api_name} detected",
                                line.strip(),
                                f"Replace {api_name} with androidx.biometric.BiometricPrompt or BiometricManager",
                                api_name,
                                line_num
                            )
                
                # Check for API usage
                for usage_pattern in api_info["usage_patterns"]:
                    if re.search(usage_pattern, line):
                        if api_name not in platform_usage:
                            platform_usage[api_name] = {
                                "imports": [],
                                "usage": [],
                                "deprecated": api_info.get("deprecated", False)
                            }
                        
                        platform_usage[api_name]["usage"].append({
                            "file": file_path,
                            "line": line_num,
                            "code": line.strip(),
                            "method": self._extract_method_name(line, api_info["methods"])
                        })
                        
                        # Create finding for platform API usage
                        self._create_finding(
                            "platform_auth_api_usage",
                            f"{file_path}:{line_num}",
                            "INFO",
                            f"Platform authentication API {api_name} usage detected",
                            line.strip(),
                            "Ensure proper error handling and fallback mechanisms",
                            api_name,
                            line_num
                        )

    def _analyze_class_for_auth_apis(self, class_item, platform_usage: Dict) -> None:
        """Analyze a DEX class for platform authentication API usage."""
        try:
            class_name = class_item.get_name() if hasattr(class_item, 'get_name') else str(class_item)
            
            # Check if this is an authentication-related class
            auth_keywords = ['auth', 'biometric', 'fingerprint', 'login', 'credential']
            if any(keyword in class_name.lower() for keyword in auth_keywords):
                
                # Analyze methods for authentication API calls
                if hasattr(class_item, 'get_methods'):
                    for method in class_item.get_methods():
                        self._analyze_method_for_auth_apis(method, class_name, platform_usage)
                        
        except Exception as e:
            logger.debug(f"Error analyzing class for auth APIs: {e}")

    def _analyze_method_for_auth_apis(self, method, class_name: str, platform_usage: Dict) -> None:
        """Analyze a method for platform authentication API calls."""
        try:
            method_name = method.get_name() if hasattr(method, 'get_name') else str(method)
            
            # Check method body for API calls
            if hasattr(method, 'get_code'):
                code = method.get_code()
                if code:
                    # Look for authentication-related method calls
                    auth_calls = [
                        "canAuthenticate",
                        "authenticate", 
                        "isHardwareDetected",
                        "hasEnrolledFingerprints",
                        "isDeviceSecure"
                    ]
                    
                    for instruction in code.get_bc().get_instructions():
                        instruction_str = str(instruction)
                        for auth_call in auth_calls:
                            if auth_call in instruction_str:
                                self._create_finding(
                                    "platform_auth_method_call",
                                    f"{class_name}::{method_name}",
                                    "INFO",
                                    f"Platform authentication method call: {auth_call}",
                                    instruction_str,
                                    "Verify proper implementation and error handling",
                                    auth_call,
                                    0
                                )
                                
        except Exception as e:
            logger.debug(f"Error analyzing method for auth APIs: {e}")

    def _analyze_authentication_flows(self, results: Dict[str, Any]) -> None:
        """Analyze authentication flows for security issues."""
        auth_flows = []
        
        # Look for authentication flow implementations
        if hasattr(self.apk_ctx, 'get_java_files'):
            java_files = self.apk_ctx.get_java_files()
            for file_path, content in java_files.items():
                flow_info = self._analyze_auth_flow_in_file(file_path, content)
                if flow_info:
                    auth_flows.append(flow_info)
        
        results["authentication_flows"] = auth_flows

    def _analyze_auth_flow_in_file(self, file_path: str, content: str) -> Optional[Dict]:
        """Analyze authentication flow implementation in a file."""
        lines = content.split('\n')
        flow_info = None
        
        # Look for BiometricPrompt.AuthenticationCallback implementation
        callback_pattern = r"AuthenticationCallback|onAuthenticationSucceeded|onAuthenticationError"
        biometric_prompt_pattern = r"BiometricPrompt.*authenticate"
        
        has_callback = False
        has_prompt = False
        error_handling = False
        success_handling = False
        
        for line_num, line in enumerate(lines, 1):
            if re.search(callback_pattern, line):
                has_callback = True
                
                # Check for proper error handling
                if "onAuthenticationError" in line:
                    error_handling = True
                    
                # Check for proper success handling
                if "onAuthenticationSucceeded" in line:
                    success_handling = True
                    
            if re.search(biometric_prompt_pattern, line):
                has_prompt = True
        
        if has_callback or has_prompt:
            flow_info = {
                "file": file_path,
                "has_callback": has_callback,
                "has_prompt": has_prompt,
                "error_handling": error_handling,
                "success_handling": success_handling,
                "secure": error_handling and success_handling
            }
            
            # Create findings for incomplete implementations
            if has_prompt and not error_handling:
                self._create_finding(
                    "missing_error_handling",
                    file_path,
                    "HIGH",
                    "Biometric authentication missing proper error handling",
                    "BiometricPrompt without onAuthenticationError handling",
                    "Implement onAuthenticationError in AuthenticationCallback",
                    "BiometricPrompt",
                    0
                )
                
            if has_prompt and not success_handling:
                self._create_finding(
                    "missing_success_handling",
                    file_path,
                    "MEDIUM",
                    "Biometric authentication missing proper success handling",
                    "BiometricPrompt without onAuthenticationSucceeded handling",
                    "Implement onAuthenticationSucceeded in AuthenticationCallback",
                    "BiometricPrompt",
                    0
                )
        
        return flow_info

    def _analyze_security_issues(self, results: Dict[str, Any]) -> None:
        """Analyze for common authentication security issues."""
        security_issues = []
        
        if hasattr(self.apk_ctx, 'get_java_files'):
            java_files = self.apk_ctx.get_java_files()
            for file_path, content in java_files.items():
                issues = self._find_security_issues_in_file(file_path, content)
                security_issues.extend(issues)
        
        results["security_issues"] = security_issues

    def _find_security_issues_in_file(self, file_path: str, content: str) -> List[Dict]:
        """Find security issues in a file."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for insecure storage patterns
            for pattern in self.security_patterns["insecure_storage"]:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append({
                        "type": "insecure_auth_storage",
                        "file": file_path,
                        "line": line_num,
                        "code": line.strip(),
                        "severity": "HIGH"
                    })
                    
                    self._create_finding(
                        "insecure_auth_storage",
                        f"{file_path}:{line_num}",
                        "HIGH",
                        "Authentication data stored insecurely",
                        line.strip(),
                        "Use Android Keystore or EncryptedSharedPreferences for authentication data",
                        "SharedPreferences",
                        line_num
                    )
            
            # Check for custom authentication bypass
            for pattern in self.security_patterns["custom_auth_bypass"]:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append({
                        "type": "auth_bypass",
                        "file": file_path,
                        "line": line_num,
                        "code": line.strip(),
                        "severity": "CRITICAL"
                    })
                    
                    self._create_finding(
                        "auth_bypass_detected",
                        f"{file_path}:{line_num}",
                        "CRITICAL",
                        "Authentication bypass mechanism detected",
                        line.strip(),
                        "Remove debug authentication bypasses from production code",
                        "DEBUG",
                        line_num
                    )
            
            # Check for hardcoded credentials
            for pattern in self.security_patterns["hardcoded_credentials"]:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append({
                        "type": "hardcoded_credentials",
                        "file": file_path,
                        "line": line_num,
                        "code": line.strip(),
                        "severity": "HIGH"
                    })
                    
                    self._create_finding(
                        "hardcoded_credentials",
                        f"{file_path}:{line_num}",
                        "HIGH",
                        "Hardcoded authentication credentials detected",
                        line.strip(),
                        "Remove hardcoded credentials and use secure credential storage",
                        "CREDENTIALS",
                        line_num
                    )
            
            # Check for weak cryptography
            for pattern in self.security_patterns["weak_crypto"]:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append({
                        "type": "weak_crypto",
                        "file": file_path,
                        "line": line_num,
                        "code": line.strip(),
                        "severity": "MEDIUM"
                    })
                    
                    self._create_finding(
                        "weak_crypto_in_auth",
                        f"{file_path}:{line_num}",
                        "MEDIUM",
                        "Weak cryptography detected in authentication context",
                        line.strip(),
                        "Use strong cryptographic algorithms (AES-256, SHA-256+)",
                        "CRYPTO",
                        line_num
                    )
        
        return issues

    def _analyze_manifest_permissions(self, results: Dict[str, Any]) -> None:
        """Analyze manifest permissions related to authentication."""
        if not hasattr(self.apk_ctx, 'get_android_manifest_xml'):
            return
        
        try:
            manifest_xml = self.apk_ctx.get_android_manifest_xml()
            if manifest_xml:
                auth_permissions = [
                    "android.permission.USE_FINGERPRINT",
                    "android.permission.USE_BIOMETRIC", 
                    "android.permission.WRITE_SECURE_SETTINGS",
                    "android.permission.DEVICE_POWER"
                ]
                
                permissions_found = []
                for permission in auth_permissions:
                    if permission in manifest_xml:
                        permissions_found.append(permission)
                        
                        # Check for deprecated permissions
                        if permission == "android.permission.USE_FINGERPRINT":
                            self._create_finding(
                                "deprecated_permission",
                                "AndroidManifest.xml",
                                "MEDIUM",
                                "Deprecated USE_FINGERPRINT permission detected",
                                permission,
                                "Replace with USE_BIOMETRIC permission",
                                "PERMISSION",
                                0
                            )
                
                results["auth_permissions"] = permissions_found
                
        except Exception as e:
            logger.debug(f"Error analyzing manifest permissions: {e}")

    def _calculate_compliance_status(self, results: Dict[str, Any]) -> None:
        """Calculate MASVS-PLATFORM-2 compliance status."""
        platform_usage = results.get("platform_auth_usage", {})
        security_issues = results.get("security_issues", [])
        auth_flows = results.get("authentication_flows", [])
        
        # Check if platform authentication APIs are used
        modern_apis_used = any(
            api in platform_usage and not info.get("deprecated", False)
            for api, info in self.platform_auth_apis.items()
            if api in platform_usage
        )
        
        # Check for critical security issues
        critical_issues = [
            issue for issue in security_issues 
            if issue.get("severity") == "CRITICAL"
        ]
        
        # Check for proper authentication flow implementation
        secure_flows = [
            flow for flow in auth_flows 
            if flow.get("secure", False)
        ]
        
        if critical_issues:
            results["compliance_status"] = "NON_COMPLIANT"
        elif not modern_apis_used and not auth_flows:
            results["compliance_status"] = "NOT_APPLICABLE"
        elif modern_apis_used and secure_flows:
            results["compliance_status"] = "COMPLIANT"
        elif modern_apis_used:
            results["compliance_status"] = "PARTIALLY_COMPLIANT"
        else:
            results["compliance_status"] = "NON_COMPLIANT"

    def _calculate_risk_score(self, results: Dict[str, Any]) -> None:
        """Calculate risk score based on findings."""
        base_score = 0
        
        # Platform API usage (positive points)
        platform_usage = results.get("platform_auth_usage", {})
        modern_apis = [
            api for api, info in platform_usage.items()
            if not self.platform_auth_apis.get(api, {}).get("deprecated", False)
        ]
        base_score += len(modern_apis) * 10
        
        # Security issues (negative points)
        security_issues = results.get("security_issues", [])
        for issue in security_issues:
            severity = issue.get("severity", "LOW")
            if severity == "CRITICAL":
                base_score -= 30
            elif severity == "HIGH":
                base_score -= 20
            elif severity == "MEDIUM":
                base_score -= 10
            elif severity == "LOW":
                base_score -= 5
        
        # Authentication flows (positive points)
        auth_flows = results.get("authentication_flows", [])
        secure_flows = [flow for flow in auth_flows if flow.get("secure", False)]
        base_score += len(secure_flows) * 15
        
        # Normalize score to 0-100 range
        risk_score = max(0, min(100, base_score))
        results["risk_score"] = risk_score

    def _generate_recommendations(self, results: Dict[str, Any]) -> None:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        platform_usage = results.get("platform_auth_usage", {})
        security_issues = results.get("security_issues", [])
        compliance_status = results.get("compliance_status", "UNKNOWN")
        
        # Recommendations based on compliance status
        if compliance_status == "NON_COMPLIANT":
            recommendations.append({
                "category": "Critical",
                "title": "Implement Platform Authentication APIs",
                "description": "Use androidx.biometric.BiometricPrompt or BiometricManager for authentication",
                "priority": "HIGH"
            })
        
        # Recommendations for deprecated APIs
        deprecated_apis = [
            api for api, info in platform_usage.items()
            if info.get("deprecated", False)
        ]
        if deprecated_apis:
            recommendations.append({
                "category": "Migration",
                "title": "Migrate from Deprecated Authentication APIs",
                "description": f"Replace deprecated APIs ({', '.join(deprecated_apis)}) with modern alternatives",
                "priority": "MEDIUM"
            })
        
        # Recommendations for security issues
        critical_issues = [i for i in security_issues if i.get("severity") == "CRITICAL"]
        if critical_issues:
            recommendations.append({
                "category": "Security",
                "title": "Fix Critical Authentication Security Issues",
                "description": "Address authentication bypass mechanisms and insecure implementations",
                "priority": "CRITICAL"
            })
        
        # General recommendations
        recommendations.extend([
            {
                "category": "Implementation",
                "title": "Implement Proper Error Handling",
                "description": "Ensure all authentication flows have comprehensive error handling",
                "priority": "MEDIUM"
            },
            {
                "category": "Security",
                "title": "Use Android Keystore",
                "description": "Store authentication tokens and sensitive data in Android Keystore",
                "priority": "MEDIUM"
            },
            {
                "category": "Testing",
                "title": "Implement Authentication Testing",
                "description": "Add comprehensive unit and integration tests for authentication flows",
                "priority": "LOW"
            }
        ])
        
        results["recommendations"] = recommendations

    def _map_masvs_controls(self, results: Dict[str, Any]) -> None:
        """Map findings to MASVS controls."""
        compliance_status = results.get("compliance_status", "UNKNOWN")
        security_issues = results.get("security_issues", [])
        
        # Map to MASVS-PLATFORM-2
        status = "PASS"
        if compliance_status == "NON_COMPLIANT":
            status = "FAIL"
        elif compliance_status == "PARTIALLY_COMPLIANT":
            status = "PARTIAL"
        elif compliance_status == "NOT_APPLICABLE":
            status = "N/A"
        
        masvs_control = {
            "control_id": "MASVS-PLATFORM-2",
            "control_name": "Platform Authentication APIs",
            "status": status,
            "findings": len(security_issues),
            "compliance_status": compliance_status,
            "description": "The app uses platform-provided authentication APIs"
        }
        
        results["masvs_controls"] = [masvs_control]

    def _create_finding(self, finding_type: str, location: str, severity: str,
                       description: str, evidence: str, remediation: str,
                       api_name: str, line_number: int) -> None:
        """Create a platform authentication finding."""
        finding = PlatformAuthFinding(
            finding_type=finding_type,
            location=location,
            severity=severity,
            description=description,
            evidence=evidence,
            remediation=remediation,
            api_name=api_name,
            line_number=line_number
        )
        
        self.findings.append(finding)
        
        # Create detailed vulnerability if framework available
        if DETAILED_FRAMEWORK_AVAILABLE:
            vulnerability = create_detailed_vulnerability(
                vulnerability_type=finding_type,
                severity=severity,
                cwe_id=self._get_cwe_for_finding_type(finding_type),
                masvs_control="MASVS-PLATFORM-2",
                location=VulnerabilityLocation(
                    file_path=location.split(':')[0] if ':' in location else location,
                    line_number=line_number if line_number > 0 else None,
                    component_type="Authentication Implementation"
                ),
                security_impact=description,
                remediation=RemediationGuidance(
                    fix_description=remediation,
                    code_example=self._get_code_example_for_finding(finding_type)
                ),
                evidence=VulnerabilityEvidence(
                    matched_pattern=evidence,
                    detection_method="Platform Authentication Analysis",
                    confidence_score=self._get_confidence_for_finding_type(finding_type)
                )
            )
            self.detailed_vulnerabilities.append(vulnerability)

    def _get_cwe_for_finding_type(self, finding_type: str) -> str:
        """Get CWE ID for finding type."""
        cwe_mapping = {
            "deprecated_api_usage": "CWE-1188",  # Deprecated Function
            "platform_auth_api_usage": "CWE-287",  # Improper Authentication
            "missing_error_handling": "CWE-754",  # Improper Check for Unusual Conditions
            "insecure_auth_storage": "CWE-312",  # Cleartext Storage of Sensitive Information
            "auth_bypass_detected": "CWE-287",  # Improper Authentication
            "hardcoded_credentials": "CWE-798",  # Use of Hard-coded Credentials
            "weak_crypto_in_auth": "CWE-327",  # Use of a Broken Cryptographic Algorithm
            "deprecated_permission": "CWE-1188"  # Deprecated Function
        }
        return cwe_mapping.get(finding_type, "CWE-287")

    def _get_confidence_for_finding_type(self, finding_type: str) -> float:
        """Get confidence score for finding type."""
        confidence_mapping = {
            "platform_auth_api_usage": 0.95,
            "deprecated_api_usage": 0.90,
            "auth_bypass_detected": 0.85,
            "hardcoded_credentials": 0.80,
            "insecure_auth_storage": 0.75,
            "missing_error_handling": 0.70,
            "weak_crypto_in_auth": 0.65
        }
        return confidence_mapping.get(finding_type, 0.70)

    def _get_code_example_for_finding(self, finding_type: str) -> str:
        """Get code example for finding remediation."""
        examples = {
            "deprecated_api_usage": """
// Replace FingerprintManager with BiometricPrompt
BiometricPrompt biometricPrompt = new BiometricPrompt(fragmentActivity, 
    ContextCompat.getMainExecutor(context), authenticationCallback);
            """,
            "missing_error_handling": """
// Implement proper error handling
AuthenticationCallback callback = new AuthenticationCallback() {
    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        // Handle authentication errors appropriately
        Log.e(TAG, "Authentication error: " + errString);
    }
};
            """,
            "insecure_auth_storage": """
// Use EncryptedSharedPreferences for authentication data
EncryptedSharedPreferences.create(
    "auth_prefs",
    masterKeyAlias,
    context,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
);
            """
        }
        return examples.get(finding_type, "// Implement secure authentication practices")

    def _extract_method_name(self, line: str, methods: List[str]) -> str:
        """Extract method name from code line."""
        for method in methods:
            if method in line:
                return method
        return "unknown"

    def get_findings(self) -> List[PlatformAuthFinding]:
        """Get all platform authentication findings."""
        return self.findings

    def get_detailed_vulnerabilities(self) -> List[DetailedVulnerability]:
        """Get detailed vulnerabilities if framework available."""
        return self.detailed_vulnerabilities if DETAILED_FRAMEWORK_AVAILABLE else []

def analyze_platform_authentication(apk_ctx) -> Dict[str, Any]:
    """
    Main function to analyze platform authentication implementation.
    
    Args:
        apk_ctx: APK context object
        
    Returns:
        Dict containing comprehensive platform authentication analysis results
    """
    analyzer = PlatformAuthenticationAnalyzer(apk_ctx)
    return analyzer.analyze()

# Plugin integration functions
def run_plugin(apk_ctx, deep_mode: bool = False) -> Dict[str, Any]:
    """
    Execute platform authentication analysis plugin.
    
    Args:
        apk_ctx: APK context object
        deep_mode: Whether to run deep analysis (currently not used)
        
    Returns:
        Dict containing plugin results
    """
    try:
        # Run the analysis
        analyzer = PlatformAuthenticationAnalyzer(apk_ctx)
        results = analyzer.analyze()
        
        # Format results for plugin framework
        plugin_results = {
            "plugin_name": "Platform Authentication Analysis",
            "version": "1.0.0",
            "masvs_controls": results.get("masvs_controls", []),
            "compliance_status": results.get("compliance_status", "UNKNOWN"),
            "risk_score": results.get("risk_score", 0),
            "findings": {
                "platform_auth_usage": results.get("platform_auth_usage", {}),
                "authentication_flows": results.get("authentication_flows", []),
                "security_issues": results.get("security_issues", [])
            },
            "recommendations": results.get("recommendations", []),
            "summary": _generate_summary(results),
            "detailed_vulnerabilities_count": len(analyzer.get_detailed_vulnerabilities())
        }
        
        return plugin_results
        
    except Exception as e:
        logger.error(f"Platform authentication analysis plugin failed: {e}")
        return {
            "plugin_name": "Platform Authentication Analysis",
            "error": str(e),
            "status": "FAILED"
        }

def _generate_summary(results: Dict[str, Any]) -> str:
    """Generate summary of platform authentication analysis."""
    compliance_status = results.get("compliance_status", "UNKNOWN")
    risk_score = results.get("risk_score", 0)
    platform_usage = results.get("platform_auth_usage", {})
    security_issues = results.get("security_issues", [])
    
    apis_count = len(platform_usage)
    issues_count = len(security_issues)
    
    summary = f"Platform authentication analysis completed. "
    summary += f"Compliance: {compliance_status}, Risk Score: {risk_score}/100. "
    summary += f"Found {apis_count} platform authentication APIs and {issues_count} security issues."
    
    return summary

# Plugin characteristics for AODS framework integration
PLUGIN_CHARACTERISTICS = {
    "name": "Platform Authentication Analysis",
    "description": "Comprehensive platform authentication analysis for MASVS-PLATFORM-2 compliance",
    "version": "1.0.0",
    "author": "AODS Framework",
    "category": "PLATFORM_ANALYSIS",
    "mode": "comprehensive",
    "masvs_controls": ["MASVS-PLATFORM-2"],
    "requires_device": False,
    "requires_network": False,
    "invasive": False,
    "execution_time_estimate": 30,
    "dependencies": []
} 