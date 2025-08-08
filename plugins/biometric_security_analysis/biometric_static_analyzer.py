"""
Biometric Static Analyzer

Analyzes APKs for biometric authentication APIs, permissions, and implementation patterns.
Detects potential security issues in biometric implementations through static analysis.
"""

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from core.apk_ctx import APKContext

logger = logging.getLogger(__name__)

@dataclass
class BiometricAPIInfo:
    """Information about detected biometric API usage."""
    api_type: str
    class_name: str
    methods_used: List[str]
    security_features: List[str] = None
    deprecated: bool = False
    security_level: str = "UNKNOWN"

class BiometricStaticAnalyzer:
    """Static analyzer for biometric authentication security."""
    
    def __init__(self):
        """Initialize the static analyzer."""
        self.logger = logger
        
        # Biometric API patterns
        self.biometric_apis = {
            "androidx_biometric": {
                "classes": [
                    "androidx.biometric.BiometricPrompt",
                    "androidx.biometric.BiometricManager",
                    "androidx.biometric.BiometricPrompt$PromptInfo",
                    "androidx.biometric.BiometricPrompt$AuthenticationCallback",
                    "androidx.biometric.BiometricPrompt$CryptoObject"
                ],
                "methods": [
                    "authenticate", "canAuthenticate", "from",
                    "setTitle", "setSubtitle", "setDescription",
                    "setNegativeButtonText", "build",
                    "onAuthenticationSucceeded", "onAuthenticationFailed"
                ],
                "security_level": "HIGH",
                "deprecated": False
            },
            "fingerprint_manager": {
                "classes": [
                    "android.hardware.fingerprint.FingerprintManager",
                    "android.support.v4.hardware.fingerprint.FingerprintManagerCompat",
                    "androidx.core.hardware.fingerprint.FingerprintManagerCompat"
                ],
                "methods": [
                    "authenticate", "isHardwareDetected", "hasEnrolledFingerprints",
                    "from", "getErrorString"
                ],
                "security_level": "MEDIUM",
                "deprecated": True
            },
            "keyguard_manager": {
                "classes": [
                    "android.app.KeyguardManager"
                ],
                "methods": [
                    "isKeyguardSecure", "isDeviceSecure",
                    "createConfirmDeviceCredentialIntent"
                ],
                "security_level": "LOW",
                "deprecated": False
            }
        }
        
        # Security patterns to detect
        self.security_patterns = {
            "crypto_object_usage": [
                r"BiometricPrompt\.CryptoObject",
                r"FingerprintManager\.CryptoObject",
                r"new\s+CryptoObject\s*\(",
                r"authenticate\s*\([^)]*CryptoObject"
            ],
            "weak_implementation": [
                r"authenticate\s*\([^)]*null[^)]*\)",
                r"BiometricPrompt\s*\([^)]*null",
                r"setNegativeButtonText\s*\(\s*null\s*\)"
            ],
            "auth_state_storage": [
                r"SharedPreferences.*auth",
                r"putBoolean\s*\([^)]*auth[^)]*true\s*\)",
                r"getBoolean\s*\([^)]*auth[^)]*\)"
            ],
            "fallback_auth": [
                r"DeviceCredential",
                r"PIN.*password",
                r"fallback.*auth",
                r"backup.*auth"
            ],
            "insecure_storage": [
                r"PreferenceManager.*auth",
                r"SQLite.*auth.*state",
                r"File.*auth.*state"
            ]
        }
    
    def analyze_biometric_apis(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Analyze APK for biometric authentication APIs and security issues.
        
        Args:
            apk_ctx: The APK context for analysis
            
        Returns:
            Dictionary containing static analysis results
        """
        try:
            self.logger.info("Starting biometric static analysis")
            
            results = {
                "apis_detected": [],
                "apis_found": 0,
                "biometric_permissions": [],
                "has_biometric_permission": False,
                "uses_crypto_object": False,
                "security_patterns": [],
                "code_analysis": {
                    "files_analyzed": 0,
                    "patterns_detected": 0
                },
                "security_assessment": {}
            }
            
            # Analyze manifest for biometric permissions
            manifest_analysis = self._analyze_manifest(apk_ctx)
            results.update(manifest_analysis)
            
            # Detect biometric APIs
            api_analysis = self._detect_biometric_apis(apk_ctx)
            results["apis_detected"] = api_analysis
            results["apis_found"] = len(api_analysis)
            
            # Analyze source code for security patterns
            code_analysis = self._analyze_source_code(apk_ctx)
            results["security_patterns"] = code_analysis["patterns"]
            results["code_analysis"] = code_analysis["stats"]
            results["uses_crypto_object"] = code_analysis["uses_crypto_object"]
            
            # Generate security assessment
            security_assessment = self._generate_security_assessment(results)
            results["security_assessment"] = security_assessment
            
            self.logger.info(f"Biometric static analysis completed: {results['apis_found']} APIs detected")
            return results
            
        except Exception as e:
            self.logger.error(f"Biometric static analysis failed: {e}")
            return {
                "error": str(e),
                "apis_detected": [],
                "apis_found": 0
            }
    
    def _analyze_manifest(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """Analyze AndroidManifest.xml for biometric permissions."""
        manifest_results = {
            "biometric_permissions": [],
            "has_biometric_permission": False
        }
        
        try:
            # Get manifest path
            manifest_path = self._get_manifest_path(apk_ctx)
            if not manifest_path or not manifest_path.exists():
                self.logger.warning("AndroidManifest.xml not found")
                return manifest_results
            
            # Parse manifest
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Check for biometric permissions
            biometric_permissions = [
                "android.permission.USE_BIOMETRIC",
                "android.permission.USE_FINGERPRINT",
                "android.permission.USE_BIOMETRIC_STRONG",
                "android.permission.USE_BIOMETRIC_WEAK"
            ]
            
            permissions = root.findall(".//uses-permission")
            for permission in permissions:
                name = permission.get('{http://schemas.android.com/apk/res/android}name', '')
                if name in biometric_permissions:
                    manifest_results["biometric_permissions"].append(name)
                    manifest_results["has_biometric_permission"] = True
            
        except Exception as e:
            self.logger.error(f"Manifest analysis failed: {e}")
        
        return manifest_results
    
    def _detect_biometric_apis(self, apk_ctx: APKContext) -> List[BiometricAPIInfo]:
        """Detect biometric APIs in the APK."""
        detected_apis = []
        
        try:
            # Search in decompiled source code
            source_paths = self._get_source_paths(apk_ctx)
            
            for api_name, api_info in self.biometric_apis.items():
                api_detected = False
                methods_found = []
                security_features = []
                
                # Check for API usage
                for source_path in source_paths:
                    if not source_path.exists():
                        continue
                    
                    for java_file in source_path.rglob("*.java"):
                        try:
                            with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            
                            # Check for class imports/usage
                            for class_name in api_info["classes"]:
                                if class_name in content:
                                    api_detected = True
                                    
                                    # Check for method usage
                                    for method in api_info["methods"]:
                                        if f".{method}(" in content or f"{method}(" in content:
                                            methods_found.append(method)
                                    
                                    # Check for security features
                                    if "CryptoObject" in content:
                                        security_features.append("CryptoObject")
                                    if "setAllowedAuthenticators" in content:
                                        security_features.append("AuthenticatorTypes")
                                    if "BiometricManager.Authenticators" in content:
                                        security_features.append("AuthenticatorValidation")
                        
                        except Exception as e:
                            self.logger.debug(f"Error reading {java_file}: {e}")
                            continue
                
                if api_detected:
                    api = BiometricAPIInfo(
                        api_type=api_name,
                        class_name=api_info["classes"][0],
                        methods_used=list(set(methods_found)),
                        security_features=security_features,
                        deprecated=api_info["deprecated"],
                        security_level=api_info["security_level"]
                    )
                    detected_apis.append(api)
                    self.logger.info(f"Detected biometric API: {api_name}")
        
        except Exception as e:
            self.logger.error(f"API detection failed: {e}")
        
        return detected_apis
    
    def _analyze_source_code(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """Analyze source code for biometric security patterns."""
        analysis_results = {
            "patterns": [],
            "uses_crypto_object": False,
            "stats": {
                "files_analyzed": 0,
                "patterns_detected": 0
            }
        }
        
        try:
            source_paths = self._get_source_paths(apk_ctx)
            
            for source_path in source_paths:
                if not source_path.exists():
                    continue
                
                for java_file in source_path.rglob("*.java"):
                    try:
                        with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        analysis_results["stats"]["files_analyzed"] += 1
                        
                        # Check for security patterns
                        for pattern_type, patterns in self.security_patterns.items():
                            for pattern in patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                                for match in matches:
                                    analysis_results["patterns"].append({
                                        "type": pattern_type,
                                        "pattern": pattern,
                                        "file": str(java_file.relative_to(source_path)),
                                        "match": match.group(0),
                                        "line": content[:match.start()].count('\n') + 1
                                    })
                                    analysis_results["stats"]["patterns_detected"] += 1
                                    
                                    # Check for CryptoObject usage
                                    if pattern_type == "crypto_object_usage":
                                        analysis_results["uses_crypto_object"] = True
                    
                    except Exception as e:
                        self.logger.debug(f"Error analyzing {java_file}: {e}")
                        continue
        
        except Exception as e:
            self.logger.error(f"Source code analysis failed: {e}")
        
        return analysis_results
    
    def _generate_security_assessment(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate security assessment based on static analysis results."""
        assessment = {
            "has_biometric_functionality": results["apis_found"] > 0,
            "biometric_permission_granted": results["has_biometric_permission"],
            "uses_modern_apis": False,
            "uses_deprecated_apis": False,
            "potential_vulnerabilities": len(results.get("security_patterns", [])),
            "risk_factors": []
        }
        
        # Check for modern vs deprecated APIs
        apis = results.get("apis_detected", [])
        for api in apis:
            if hasattr(api, 'deprecated'):
                if api.deprecated:
                    assessment["uses_deprecated_apis"] = True
                else:
                    assessment["uses_modern_apis"] = True
        
        # Identify risk factors
        if assessment["has_biometric_functionality"] and not assessment["biometric_permission_granted"]:
            assessment["risk_factors"].append("Biometric APIs without proper permissions")
        
        if assessment["uses_deprecated_apis"]:
            assessment["risk_factors"].append("Using deprecated FingerprintManager API")
        
        if not results.get("uses_crypto_object", False) and assessment["has_biometric_functionality"]:
            assessment["risk_factors"].append("Biometric authentication without CryptoObject")
        
        if assessment["potential_vulnerabilities"] > 3:
            assessment["risk_factors"].append("Multiple potential security issues detected")
        
        # Determine overall risk level
        risk_score = 0
        if assessment["uses_deprecated_apis"]:
            risk_score += 2
        if not results.get("uses_crypto_object", False):
            risk_score += 3
        if assessment["potential_vulnerabilities"] > 0:
            risk_score += assessment["potential_vulnerabilities"]
        if len(assessment["risk_factors"]) > 0:
            risk_score += len(assessment["risk_factors"])
        
        if risk_score >= 6:
            assessment["risk_level"] = "HIGH"
        elif risk_score >= 3:
            assessment["risk_level"] = "MEDIUM"
        else:
            assessment["risk_level"] = "LOW"
        
        return assessment
    
    def _get_manifest_path(self, apk_ctx: APKContext) -> Optional[Path]:
        """Get path to AndroidManifest.xml."""
        if hasattr(apk_ctx, 'get_decompiled_path'):
            decompiled_path = apk_ctx.get_decompiled_path()
            if decompiled_path:
                return Path(decompiled_path) / "AndroidManifest.xml"
        
        # Fallback to workspace
        if hasattr(apk_ctx, 'workspace_dir'):
            return Path(apk_ctx.workspace_dir) / "AndroidManifest.xml"
        
        return None
    
    def _get_source_paths(self, apk_ctx: APKContext) -> List[Path]:
        """Get paths to source code directories."""
        source_paths = []
        
        if hasattr(apk_ctx, 'get_decompiled_path'):
            decompiled_path = apk_ctx.get_decompiled_path()
            if decompiled_path:
                source_paths.append(Path(decompiled_path) / "sources")
                source_paths.append(Path(decompiled_path) / "smali")
        
        if hasattr(apk_ctx, 'workspace_dir'):
            workspace_path = Path(apk_ctx.workspace_dir)
            source_paths.append(workspace_path)
            source_paths.append(workspace_path / "sources")
        
        return [p for p in source_paths if p.exists()]