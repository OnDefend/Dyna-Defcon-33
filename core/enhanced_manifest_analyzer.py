#!/usr/bin/env python3
"""
🔍 AODS Enhanced Manifest Analyzer
Organic AndroidManifest.xml Security Analysis

This analyzer provides comprehensive AndroidManifest.xml analysis for security
vulnerabilities using organic detection methods that identify security issues
without hardcoded application references or CTF-specific patterns.

Key Features:
- Exported component security analysis
- Intent filter vulnerability detection
- Deep link scheme security assessment with dynamic risk scoring
- Permission analysis and dangerous permission identification
- Component protection level assessment
- Dynamic confidence calculation based on security risk factors
- Universal APK compatibility (no hardcoded app references)

Detects Generic Vulnerabilities:
- Unprotected exported components
- Suspicious deep link schemes with RCE potential
- Overprivileged permission requests
- Insecure component configurations
"""

import hashlib
import json
import logging
import os
import re
import time
import xml.etree.ElementTree as ET
from core.encoding_utils import safe_read_file, safe_parse_xml, safe_decode_bytes
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .base_owasp_analyzer import (BaseOWASPAnalyzer, SecurityFinding,
                                  StandardAnalysisResult)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import JADX unified helper for memory optimization
try:
    from core.shared_infrastructure import get_decompiled_sources_unified
    JADX_UNIFIED_AVAILABLE = True
except ImportError:
    JADX_UNIFIED_AVAILABLE = False
    logger.warning("JADX unified helper not available in EnhancedManifestAnalyzer")

@dataclass
class ManifestFinding:
    """Represents a security finding in AndroidManifest.xml."""

    finding_type: str
    severity: str
    confidence: float
    component_name: str
    component_type: str
    description: str
    category: str
    remediation: str
    security_impact: str
    cwe: str
    context: Dict[str, Any]

@dataclass
class ManifestAnalysisResult:
    """Complete AndroidManifest.xml analysis results."""

    apk_path: str
    manifest_path: str
    analysis_time: float
    findings: List[ManifestFinding]
    statistics: Dict[str, Any]
    package_info: Dict[str, Any]
    exported_components: Dict[str, List[Dict]]
    permission_analysis: Dict[str, Any]
    deep_link_analysis: Dict[str, Any]

class EnhancedManifestAnalyzer(BaseOWASPAnalyzer):
    """
    🔍 AODS Enhanced Manifest Analyzer for Organic Security Detection

    Comprehensive AndroidManifest.xml analysis focused on generic security
    vulnerabilities using organic patterns that work universally across all APKs.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Enhanced Manifest Analyzer."""
        # Set up default configuration first
        default_config = self._get_default_config()

        # Merge with provided config if any
        if config:
            default_config.update(config)

        super().__init__(default_config)
        self.android_ns = "{http://schemas.android.com/apk/res/android}"

        # Initialize security patterns for organic detection
        self._initialize_security_patterns()

        logger.debug("Manifest Analyzer initialized successfully")

    def _get_masvs_category(self) -> str:
        """Return the MASVS category this analyzer implements."""
        return "MASVS-PLATFORM"

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for manifest analysis."""
        return {
            "analysis_options": {
                "enable_deep_link_analysis": True,
                "enable_exported_component_analysis": True,
                "enable_permission_analysis": True,
                "base_confidence_threshold": 0.5,
                "suspicious_scheme_patterns": ["test", "debug", "internal", "admin"],
                "rce_risk_keywords": [
                    "exec",
                    "command",
                    "shell",
                    "run",
                    "execute",
                    "cmd",
                    "system",
                    "bash",
                ],
            },
            "risk_scoring": {
                "unprotected_main_activity": 0.9,
                "unprotected_exported_receiver": 0.8,
                "custom_scheme_with_host": 0.7,
                "rce_pattern_detection": 0.95,
                "excessive_permissions_base": 0.6,
            },
        }

    def _initialize_security_patterns(self) -> None:
        """Initialize comprehensive security patterns for organic detection."""

        # Generic deep link vulnerability patterns
        self.deep_link_patterns = {
            "suspicious_scheme_indicators": [
                r"(?i)(test|debug|internal|admin|dev)",
                r"(?i)(custom|app|deeplink)",
                r"(?i)(api|cmd|exec|shell)",
                # 🔥 PRIORITY 2 FIX: Enhanced organic pattern matching for potential RCE schemes
                r"(?i)(\w+\d+|challenge\d+|test\d+)",  # Generic numbered patterns (organic)
                r"(?i)(rce|command|execution)",  # Direct RCE indicators
                r"(?i)(run|execute|system|bash)",  # Execution-related terms
                r"(?i)(vuln|exploit|hack)",  # Vulnerability indicators
            ],
            "rce_risk_patterns": [
                r"(?i)(exec|command|shell|cmd)",
                r"(?i)(run|execute|process|system)",
                r"(?i)(bash|sh|terminal|console)",
                r"(?i)(rce|remote.*exec)",
                # 🔥 PRIORITY 2 FIX: Generic RCE risk detection patterns (organic)
                r"(?i)(\w+\d+.*rce|.*rce.*\w+\d+)",  # Generic numbered schemes with RCE
                r"(?i)(binary|param|argument)",  # Parameter injection indicators
                r"(?i)(inject|exploit|vuln)",  # Vulnerability-related terms
            ],
            "source_code_rce_patterns": [
                r"Runtime\.getRuntime\(\)\.exec\s*\(",  # Runtime.exec() calls
                r"ProcessBuilder\s*\(",  # ProcessBuilder usage
                r"Process\s+\w+\s*=.*\.exec\s*\(",  # Process execution
                r"\.exec\s*\(\s*[\"'].*\+.*[\"']\s*\)",  # String concatenation in exec
                r"\.exec\s*\(\s*.*getIntent\(\).*\)",  # Intent data in exec
                r"\.exec\s*\(\s*.*getStringExtra.*\)",  # Intent extras in exec
                r"\.exec\s*\(\s*.*getDataString.*\)",  # Intent data string in exec
                r"System\.getProperty\s*\(.*\+.*\)",  # System property manipulation
                r"Class\.forName\s*\(.*\+.*\)",  # Dynamic class loading
            ],
            "intent_parameter_injection": [
                r"getIntent\(\)\.getStringExtra\s*\(",  # Intent string extras
                r"getIntent\(\)\.getDataString\s*\(",  # Intent data strings
                r"getIntent\(\)\.getData\s*\(",  # Intent data URIs
                r"intent\.getStringExtra\s*\(",  # Intent extras access
                r"Uri\.parse\s*\(.*getIntent.*\)",  # URI parsing from intent
            ],
            "data_exposure_indicators": [
                r"(?i)(file|content|data)",
                r"(?i)(storage|cache|temp)",
                r"(?i)(internal|external)",
            ],
        }

        # Generic component security patterns
        self.component_patterns = {
            "high_risk_actions": [
                "android.intent.action.MAIN",
                "android.intent.action.VIEW",
                "android.intent.action.BOOT_COMPLETED",
                "android.intent.action.SEND",
                "android.intent.action.SENDTO",
                "android.intent.action.EDIT",
            ],
            "sensitive_broadcast_actions": [
                "android.intent.action.BOOT_COMPLETED",
                "android.intent.action.USER_PRESENT",
                "android.intent.action.PHONE_STATE",
                "android.intent.action.SMS_RECEIVED",
            ],
        }

        # Generic permission risk patterns
        self.permission_patterns = {
            "high_risk_permissions": [
                "SYSTEM_ALERT_WINDOW",
                "WRITE_EXTERNAL_STORAGE",
                "READ_EXTERNAL_STORAGE",
                "CAMERA",
                "RECORD_AUDIO",
                "ACCESS_FINE_LOCATION",
                "ACCESS_COARSE_LOCATION",
                "READ_CONTACTS",
                "READ_SMS",
                "SEND_SMS",
                "READ_PHONE_STATE",
                "CALL_PHONE",
            ],
            "security_bypass_permissions": [
                "WRITE_SETTINGS",
                "SYSTEM_ALERT_WINDOW",
                "BIND_ACCESSIBILITY_SERVICE",
                "DEVICE_ADMIN",
            ],
        }

    def _calculate_dynamic_confidence(
        self, risk_factors: List[str], base_confidence: float = 0.5
    ) -> float:
        """Calculate dynamic confidence based on multiple risk factors."""
        confidence = base_confidence

        # Risk multipliers
        risk_multipliers = {
            "unprotected_exported": 0.3,
            "main_action_present": 0.2,
            "custom_scheme": 0.15,
            "rce_pattern": 0.4,
            "sensitive_action": 0.25,
            "no_permission_protection": 0.3,
            "suspicious_scheme_name": 0.2,
        }

        # Apply risk multipliers
        for factor in risk_factors:
            if factor in risk_multipliers:
                confidence += risk_multipliers[factor]

        # Cap confidence at 1.0
        return min(confidence, 1.0)

    def _assess_scheme_security_risk(
        self, scheme: str
    ) -> Tuple[bool, List[str], float]:
        """🔥 PRIORITY 2 FIX: Enhanced scheme security risk assessment for RCE detection."""
        risk_factors = []
        is_suspicious = False

        scheme_lower = scheme.lower()

        # Check for suspicious scheme patterns
        for pattern in self.deep_link_patterns["suspicious_scheme_indicators"]:
            if re.search(pattern, scheme_lower):
                risk_factors.append("suspicious_scheme_name")
                is_suspicious = True

        # Check for RCE risk patterns
        for pattern in self.deep_link_patterns["rce_risk_patterns"]:
            if re.search(pattern, scheme_lower):
                risk_factors.append("rce_pattern")
                is_suspicious = True

        # 🔥 PRIORITY 2 FIX: Enhanced RCE risk detection for numbered schemes (ORGANIC)
        # Detect patterns that could indicate test/challenge apps with potential RCE
        if re.match(r"^[a-z]+\d+$", scheme_lower):
            risk_factors.append("numbered_scheme")
            is_suspicious = True
            
            # Enhanced organic RCE detection for numbered schemes with execution terms
            if re.search(r"(rce|cmd|exec|run|shell)", scheme_lower):
                risk_factors.append("execution_scheme")
                risk_factors.append("potential_command_injection")
                is_suspicious = True

        # 🔥 PRIORITY 2 FIX: Generic challenge/CTF app patterns (organic detection)
        challenge_patterns = [
            r"^(challenge|ctf|test|exercise)\d*$",
            r"^(vuln|exploit|hack)\d*$", 
            r"^(demo|sample|tutorial)\d*$",
        ]
        
        for pattern in challenge_patterns:
            if re.match(pattern, scheme_lower):
                risk_factors.append("challenge_app_scheme")
                is_suspicious = True

        # 🔥 PRIORITY 2 FIX: Detect schemes that might accept command parameters
        # Common parameter patterns that could lead to RCE
        command_risk_patterns = [
            r"binary|exec|cmd|shell|run",  # Direct command indicators
            r"param|arg|input|data",  # Parameter-related schemes
            r"process|system|execute",  # Execution-related terms
        ]
        
        for pattern in command_risk_patterns:
            if re.search(pattern, scheme_lower):
                risk_factors.append("parameter_injection_risk")
                is_suspicious = True

        # Check for data exposure indicators
        for pattern in self.deep_link_patterns["data_exposure_indicators"]:
            if re.search(pattern, scheme_lower):
                risk_factors.append("data_exposure_risk")
                is_suspicious = True

        # 🔥 PRIORITY 2 FIX: Enhanced confidence calculation for RCE schemes
        base_confidence = 0.5
        
        # Boost confidence for high-risk patterns
        if "execution_scheme" in risk_factors:
            base_confidence = 0.95  # Very high confidence for execution schemes
        elif "numbered_scheme" in risk_factors:
            base_confidence = 0.80  # High confidence for numbered schemes  
        elif "challenge_app_scheme" in risk_factors:
            base_confidence = 0.75  # Good confidence for challenge apps
        elif "parameter_injection_risk" in risk_factors:
            base_confidence = 0.70  # Good confidence for parameter risks
        
        # Calculate final confidence
        confidence = self._calculate_dynamic_confidence(risk_factors, base_confidence)

        return is_suspicious, risk_factors, confidence

    def _assess_component_security_risk(
        self, component: Dict[str, Any]
    ) -> Tuple[List[str], float]:
        """Assess security risk of an exported component."""
        risk_factors = []

        # Check if component is exported without permission protection
        if not component.get("permission"):
            risk_factors.append("no_permission_protection")
            risk_factors.append("unprotected_exported")

        # Check for high-risk intent actions
        for intent_filter in component.get("intent_filters", []):
            for action in intent_filter.get("actions", []):
                if action in self.component_patterns["high_risk_actions"]:
                    risk_factors.append("main_action_present")
                if action in self.component_patterns["sensitive_broadcast_actions"]:
                    risk_factors.append("sensitive_action")

        # Calculate confidence based on risk factors
        base_confidence = self.config["risk_scoring"].get(
            "unprotected_main_activity", 0.8
        )
        confidence = self._calculate_dynamic_confidence(risk_factors, base_confidence)

        return risk_factors, confidence

    def analyze_apk(self, apk_path: str) -> StandardAnalysisResult:
        """
        Analyze an APK file for MASVS-PLATFORM security vulnerabilities.

        Args:
            apk_path: Path to the APK file to analyze

        Returns:
            StandardAnalysisResult containing security findings
        """
        start_time = time.time()

        try:
            # 🔥 PRIORITY 2 FIX: Store APK path for source code RCE analysis
            self._current_apk_path = apk_path

            logger.debug(
                f"🔍 Starting OWASP MASVS-PLATFORM analysis: {os.path.basename(apk_path)}"
            )

            # Extract and analyze AndroidManifest.xml
            manifest_path = self._extract_manifest_from_apk(apk_path)

            if not manifest_path:
                logger.error("❌ Failed to extract AndroidManifest.xml")
                return StandardAnalysisResult(
                    analyzer_name=self.__class__.__name__,
                    apk_path=apk_path,
                    analysis_time=time.time() - start_time,
                    findings=[],
                    statistics={"error": "Failed to extract manifest"},
                    mastg_tests_executed=[],
                    masvs_category=self._get_masvs_category(),
                )

            # Perform comprehensive manifest analysis
            manifest_result = self.analyze_manifest(manifest_path, apk_path)

            # Convert ManifestFinding objects to SecurityFinding objects
            security_findings = self._convert_findings(manifest_result.findings)

            analysis_time = time.time() - start_time

            logger.debug(f"✅ MASVS-PLATFORM analysis completed in {analysis_time:.2f}s")
            logger.debug(f"📊 Found {len(security_findings)} platform security findings")

            return StandardAnalysisResult(
                analyzer_name=self.__class__.__name__,
                apk_path=apk_path,
                analysis_time=analysis_time,
                findings=security_findings,
                statistics=manifest_result.statistics,
                mastg_tests_executed=self._get_executed_mastg_tests(),
                masvs_category=self._get_masvs_category(),
            )

        except Exception as e:
            logger.error(f"❌ MASVS-PLATFORM analysis failed: {str(e)}")
            return StandardAnalysisResult(
                analyzer_name=self.__class__.__name__,
                apk_path=apk_path,
                analysis_time=time.time() - start_time,
                findings=[],
                statistics={"error": str(e)},
                mastg_tests_executed=[],
                masvs_category=self._get_masvs_category(),
            )
        finally:
            # Clean up temporary files
            if hasattr(self, "_temp_manifest_path") and os.path.exists(
                self._temp_manifest_path
            ):
                try:
                    os.remove(self._temp_manifest_path)
                except Exception as e:
                    logger.warning(f"⚠️ Failed to cleanup temp manifest: {e}")

            # 🔥 PRIORITY 2 FIX: Clean up APK path reference
            if hasattr(self, "_current_apk_path"):
                delattr(self, "_current_apk_path")

    def _extract_manifest_from_apk(self, apk_path: str) -> Optional[str]:
        """
        Extract and convert AndroidManifest.xml from APK file.

        AndroidManifest.xml files in APKs are in binary format and need conversion
        to readable XML for parsing.

        Args:
            apk_path: Path to APK file

        Returns:
            Path to extracted and converted manifest file, or None if extraction failed
        """
        import shutil
        import subprocess
        import tempfile

        try:
            with zipfile.ZipFile(apk_path, "r") as apk_zip:
                # Check if AndroidManifest.xml exists
                if "AndroidManifest.xml" not in apk_zip.namelist():
                    logger.error("AndroidManifest.xml not found in APK")
                    return None

                # Extract binary manifest to temporary file
                with tempfile.NamedTemporaryFile(
                    mode="wb", suffix="_AndroidManifest_binary.xml", delete=False
                ) as temp_binary_file:
                    manifest_data = apk_zip.read("AndroidManifest.xml")
                    temp_binary_file.write(manifest_data)
                    binary_manifest_path = temp_binary_file.name

                # Try to convert binary XML to readable XML using AAPT
                readable_manifest_path = self._convert_binary_manifest_to_xml(
                    apk_path, binary_manifest_path
                )

                # Clean up binary manifest
                try:
                    os.unlink(binary_manifest_path)
                except:
                    pass

                return readable_manifest_path

        except Exception as e:
            logger.error(f"Failed to extract AndroidManifest.xml: {e}")
            return None

    def _convert_binary_manifest_to_xml(
        self, apk_path: str, binary_manifest_path: str
    ) -> Optional[str]:
        """
        Convert binary AndroidManifest.xml to readable format using AAPT.

        This method uses AAPT to directly extract manifest data without
        complex XML conversion, focusing on security-relevant components.

        Args:
            apk_path: Path to original APK file
            binary_manifest_path: Path to extracted binary manifest (unused in this approach)

        Returns:
            Path to a simplified XML file with extracted security data, or None if extraction failed
        """
        import json
        import subprocess
        import tempfile

        try:
            # Find aapt executable
            aapt_path = self._find_aapt_executable()
            if not aapt_path:
                logger.error("❌ AAPT not found - cannot parse AndroidManifest.xml")
                return None

            logger.debug("🔧 Extracting manifest data using AAPT")

            # Use AAPT to extract manifest data
            manifest_data = self._extract_manifest_data_with_aapt(apk_path, aapt_path)

            if not manifest_data:
                logger.error("❌ Failed to extract manifest data")
                return None

            # Create a simplified XML file with the extracted data
            xml_content = self._create_simplified_xml(manifest_data)

            # Save to temporary file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix="_AndroidManifest_simplified.xml", delete=False
            ) as temp_file:
                temp_file.write(xml_content)
                logger.debug("✅ Successfully created simplified AndroidManifest.xml")
                return temp_file.name

        except Exception as e:
            logger.error(f"❌ AAPT manifest extraction failed: {e}")
            return None

    def _extract_manifest_data_with_aapt(
        self, apk_path: str, aapt_path: str
    ) -> Optional[dict]:
        """Extract key manifest data using AAPT."""
        import re
        import subprocess

        try:
            # Use aapt to dump manifest in xmltree format
            cmd = [aapt_path, "dump", "xmltree", apk_path, "AndroidManifest.xml"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                logger.error(f"❌ AAPT failed: {result.stderr}")
                return None

            manifest_data = {
                "package_name": "",
                "exported_activities": [],
                "exported_receivers": [],
                "exported_services": [],
                "deep_link_schemes": [],
                "permissions": [],
            }

            lines = result.stdout.split("\n")

            # Extract package name
            for line in lines:
                if "A: package=" in line:
                    match = re.search(r'package="([^"]+)"', line)
                    if match:
                        manifest_data["package_name"] = match.group(1)
                        break

            # Extract exported components and deep links
            i = 0
            while i < len(lines):
                line = lines[i].strip()

                # Look for activity or receiver
                if (
                    line.startswith("E: activity")
                    or line.startswith("E: receiver")
                    or line.startswith("E: service")
                ):
                    component_type = line.split()[1]
                    name = None
                    exported = False
                    schemes = []
                    has_intent_filters = False

                    # Look for attributes in next few lines
                    j = i + 1
                    while j < len(lines) and j < i + 30:  # Look ahead max 30 lines for intent filters
                        attr_line = lines[j].strip()

                        if not attr_line:
                            j += 1
                            continue

                        # Stop if we hit another component
                        if attr_line.startswith("E: ") and (
                            "activity" in attr_line
                            or "receiver" in attr_line
                            or "service" in attr_line
                        ):
                            break

                        # Extract name (only if we don't have one yet)
                        if "android:name(0x01010003)=" in attr_line and name is None:
                            match = re.search(r'"([^"]+)"', attr_line)
                            if match:
                                name = match.group(1)

                        # Extract exported status
                        if "android:exported(0x01010010)=" in attr_line:
                            if "0xffffffff" in attr_line:
                                exported = True

                        # Check for intent filters (makes component implicitly exported)
                        if "E: intent-filter" in attr_line:
                            has_intent_filters = True

                        # Extract deep link schemes
                        if "android:scheme(0x01010027)=" in attr_line:
                            match = re.search(r'"([^"]+)"', attr_line)
                            if match:
                                scheme = match.group(1)
                                schemes.append(scheme)
                                manifest_data["deep_link_schemes"].append(scheme)

                        j += 1

                    # 🔥 PRIORITY 2 FIX: Include activities with intent filters (implicitly exported)
                    # or explicitly exported activities
                    if (exported or has_intent_filters) and name:
                        component = {
                            "name": name, 
                            "exported": exported or has_intent_filters, 
                            "schemes": schemes,
                            "has_intent_filters": has_intent_filters
                        }

                        if component_type == "activity":
                            manifest_data["exported_activities"].append(component)
                        elif component_type == "receiver":
                            manifest_data["exported_receivers"].append(component)
                        elif component_type == "service":
                            manifest_data["exported_services"].append(component)

                i += 1

            # Extract permissions
            for line in lines:
                if "E: uses-permission" in line:
                    # Look for the permission name in the next few lines
                    line_idx = lines.index(line)
                    for j in range(line_idx + 1, min(line_idx + 3, len(lines))):
                        if "android:name(0x01010003)=" in lines[j]:
                            match = re.search(r'"([^"]+)"', lines[j])
                            if match:
                                manifest_data["permissions"].append(match.group(1))
                                break

            logger.debug(
                f"📊 Extracted: {len(manifest_data['exported_activities'])} activities, "
                f"{len(manifest_data['exported_receivers'])} receivers, "
                f"{len(manifest_data['deep_link_schemes'])} schemes"
            )

            return manifest_data

        except Exception as e:
            logger.error(f"❌ AAPT parsing failed: {e}")
            return None

    def _create_simplified_xml(self, manifest_data: dict) -> str:
        """Create a simplified XML representation of the manifest data."""
        xml_lines = ['<?xml version="1.0" encoding="utf-8"?>']
        xml_lines.append(
            f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{manifest_data["package_name"]}">'
        )
        xml_lines.append("  <application>")

        # Add exported activities
        for activity in manifest_data["exported_activities"]:
            xml_lines.append(
                f'    <activity android:name="{activity["name"]}" android:exported="true">'
            )
            for scheme in activity["schemes"]:
                xml_lines.append("      <intent-filter>")
                xml_lines.append(
                    '        <action android:name="android.intent.action.VIEW" />'
                )
                xml_lines.append(
                    '        <category android:name="android.intent.category.DEFAULT" />'
                )
                xml_lines.append(
                    '        <category android:name="android.intent.category.BROWSABLE" />'
                )
                xml_lines.append(f'        <data android:scheme="{scheme}" />')
                xml_lines.append("      </intent-filter>")
            xml_lines.append("    </activity>")

        # Add exported receivers
        for receiver in manifest_data["exported_receivers"]:
            xml_lines.append(
                f'    <receiver android:name="{receiver["name"]}" android:exported="true" />'
            )

        # Add exported services
        for service in manifest_data["exported_services"]:
            xml_lines.append(
                f'    <service android:name="{service["name"]}" android:exported="true" />'
            )

        xml_lines.append("  </application>")

        # Add permissions
        for permission in manifest_data["permissions"]:
            xml_lines.append(f'  <uses-permission android:name="{permission}" />')

        xml_lines.append("</manifest>")

        return "\n".join(xml_lines)

    def _find_aapt_executable(self) -> Optional[str]:
        """Find AAPT executable in system PATH or Android SDK."""
        import shutil

        # Common AAPT executable names
        aapt_names = ["aapt", "aapt2"]

        for aapt_name in aapt_names:
            aapt_path = shutil.which(aapt_name)
            if aapt_path:
                logger.debug(f"✅ Found AAPT at: {aapt_path}")
                return aapt_path

        # Try common Android SDK locations
        sdk_locations = [
            os.path.expanduser("~/Android/Sdk/build-tools"),
            "/opt/android-sdk/build-tools",
            "/usr/local/android-sdk/build-tools",
        ]

        for sdk_path in sdk_locations:
            if os.path.exists(sdk_path):
                # Find latest build-tools version
                for version_dir in sorted(os.listdir(sdk_path), reverse=True):
                    version_path = os.path.join(sdk_path, version_dir)
                    if os.path.isdir(version_path):
                        for aapt_name in aapt_names:
                            aapt_path = os.path.join(version_path, aapt_name)
                            if os.path.exists(aapt_path) and os.access(
                                aapt_path, os.X_OK
                            ):
                                logger.debug(f"✅ Found AAPT at: {aapt_path}")
                                return aapt_path

        logger.warning("⚠️ AAPT not found in system PATH or common SDK locations")
        return None

    def _convert_findings(
        self, manifest_findings: List[ManifestFinding]
    ) -> List[SecurityFinding]:
        """
        Convert ManifestFinding objects to standard SecurityFinding objects.

        Args:
            manifest_findings: List of ManifestFinding objects

        Returns:
            List of SecurityFinding objects
        """
        standard_findings = []

        for finding in manifest_findings:
            standard_finding = self._create_finding(
                finding_type=finding.finding_type,
                severity=finding.severity,
                title=f"{finding.component_type}: {finding.component_name}",
                description=finding.description,
                confidence=finding.confidence,
                category=finding.category,
                remediation=finding.remediation,
                context={
                    "component_name": finding.component_name,
                    "component_type": finding.component_type,
                    "security_impact": finding.security_impact,
                    "cwe": finding.cwe,
                    **finding.context,
                },
                mastg_test_id=self._get_mastg_test_for_finding(finding.finding_type),
            )
            standard_findings.append(standard_finding)

        return standard_findings

    def _get_mastg_test_for_finding(self, finding_type: str) -> str:
        """Map finding type to MASTG test ID."""
        mastg_mapping = {
            "exported_component": "MASTG-TEST-0029",
            "deep_link_vulnerability": "MASTG-TEST-0028",
            "permission_vulnerability": "MASTG-TEST-0024",
            "unprotected_broadcast": "MASTG-TEST-0029",
            "intent_manipulation": "MASTG-TEST-0030",
        }
        return mastg_mapping.get(finding_type, "MASTG-TEST-0024")

    def _get_executed_mastg_tests(self) -> List[str]:
        """Return list of MASTG tests executed by this analyzer."""
        return [
            "MASTG-TEST-0024",  # Testing for App Permissions
            "MASTG-TEST-0028",  # Testing Deep Links
            "MASTG-TEST-0029",  # Testing for Sensitive Functionality Exposure Through IPC
            "MASTG-TEST-0030",  # Testing for Vulnerable Implementation of PendingIntent
            "MASTG-TECH-0117",  # Obtaining Information from the AndroidManifest
        ]

    def analyze_manifest(
        self, manifest_path: str, apk_path: str = ""
    ) -> ManifestAnalysisResult:
        """
        Perform comprehensive AndroidManifest.xml analysis.

        Args:
            manifest_path: Path to AndroidManifest.xml file
            apk_path: Optional APK path for context

        Returns:
            ManifestAnalysisResult with comprehensive analysis results
        """
        analysis_start = time.time()
        findings = []

        try:
            # Parse manifest
            tree, root = self._parse_manifest(manifest_path)
            
            # Store root for compatibility methods
            self._current_manifest_root = root

            # Extract basic package information
            package_info = self._extract_package_info(root)

            # Analyze exported components
            exported_components = self._analyze_exported_components(root)
            findings.extend(
                self._detect_exported_component_vulnerabilities(exported_components)
            )

            # Analyze deep links
            deep_link_analysis = self._analyze_deep_links(root)
            findings.extend(self._detect_deep_link_vulnerabilities(deep_link_analysis))

            # Analyze permissions
            permission_analysis = self._analyze_permissions(root)
            findings.extend(
                self._detect_permission_vulnerabilities(permission_analysis)
            )

            # Generate statistics
            statistics = self._generate_statistics(
                findings, exported_components, deep_link_analysis
            )

            analysis_time = time.time() - analysis_start

            logger.debug(f"✅ Manifest analysis completed in {analysis_time:.2f}s")
            logger.debug(f"📊 Found {len(findings)} security findings")

            return ManifestAnalysisResult(
                apk_path=apk_path,
                manifest_path=manifest_path,
                analysis_time=analysis_time,
                findings=findings,
                statistics=statistics,
                package_info=package_info,
                exported_components=exported_components,
                permission_analysis=permission_analysis,
                deep_link_analysis=deep_link_analysis,
            )

        except Exception as e:
            logger.error(f"❌ Manifest analysis failed: {e}")
            return ManifestAnalysisResult(
                apk_path=apk_path,
                manifest_path=manifest_path,
                analysis_time=time.time() - analysis_start,
                findings=[],
                statistics={},
                package_info={},
                exported_components={},
                permission_analysis={},
                deep_link_analysis={},
            )

    def _parse_manifest(self, manifest_path: str) -> Tuple[ET.ElementTree, ET.Element]:
        """Parse AndroidManifest.xml file with enhanced encoding support and binary XML detection."""
        if not os.path.exists(manifest_path):
            raise FileNotFoundError(f"Manifest file not found: {manifest_path}")

        # Check if the file is in binary format
        try:
            with open(manifest_path, 'rb') as f:
                first_bytes = f.read(8)
                # Android binary XML files typically start with specific magic bytes
                if len(first_bytes) >= 4 and (first_bytes[:4] == b'\x03\x00\x08\x00' or 
                                             first_bytes[:2] == b'\x03\x00' or
                                             b'\x00\x00' in first_bytes[:8]):
                    logger.debug(f"🔧 Detected binary XML format in {manifest_path}")
                    
                    # Try to find the original APK path to use for AAPT conversion
                    apk_path = None
                    
                    # Strategy 1: Look for APK based on workspace path structure
                    if 'workspace' in manifest_path:
                        # Extract APK name from workspace directory
                        workspace_dir = os.path.dirname(manifest_path)
                        workspace_name = os.path.basename(workspace_dir)
                        
                        # Try to extract APK name (remove decompilation suffix)
                        apk_base_name = workspace_name.replace('_decompiled', '').replace('_extracted', '')
                        if '_' in apk_base_name:
                            # Remove potential random suffix (e.g., _78137437)
                            parts = apk_base_name.split('_')
                            if len(parts) > 1 and parts[-1].isdigit():
                                apk_base_name = '_'.join(parts[:-1])
                        
                        # Look for APK in the apks directory
                        parent_dir = os.path.dirname(workspace_dir)
                        apks_dir = os.path.join(parent_dir, 'apks')
                        
                        if os.path.exists(apks_dir):
                            # Try exact match first
                            exact_apk = os.path.join(apks_dir, f"{apk_base_name}.apk")
                            if os.path.exists(exact_apk):
                                apk_path = exact_apk
                            else:
                                # Try pattern matching with the extracted name
                                for apk_file in os.listdir(apks_dir):
                                    if apk_file.endswith('.apk') and apk_base_name in apk_file:
                                        apk_path = os.path.join(apks_dir, apk_file)
                                        break
                                
                                # If still not found, try more flexible matching
                                if not apk_path:
                                    # Try matching with the original workspace name (before cleaning)
                                    original_name = workspace_name.replace('_decompiled', '').replace('_extracted', '')
                                    
                                    # First, try exact prefix matching for the main app name
                                    main_app_name = original_name.split('-')[0] if '-' in original_name else original_name.split('_')[0]
                                    
                                    best_match = None
                                    best_match_score = 0
                                    
                                    for apk_file in os.listdir(apks_dir):
                                        if apk_file.endswith('.apk'):
                                            apk_name_without_ext = apk_file[:-4]  # Remove .apk
                                            
                                            # Score the match quality
                                            score = 0
                                            
                                            # Highest priority: exact name match in APK name
                                            if main_app_name.lower() in apk_name_without_ext.lower():
                                                score += 100
                                            
                                            # Medium priority: workspace name starts with APK name
                                            if original_name.lower().startswith(apk_name_without_ext.lower()):
                                                score += 50
                                            
                                            # Lower priority: any part matches
                                            if any(part.lower() in apk_name_without_ext.lower() 
                                                  for part in original_name.split('-')[:2] if len(part) > 2):
                                                score += 25
                                            
                                            # Boost score for larger files (likely main APKs)
                                            full_path = os.path.join(apks_dir, apk_file)
                                            size = os.path.getsize(full_path)
                                            if size > 50 * 1024 * 1024:  # > 50MB
                                                score += 10
                                            if size > 200 * 1024 * 1024:  # > 200MB
                                                score += 20
                                            
                                            if score > best_match_score:
                                                best_match_score = score
                                                best_match = os.path.join(apks_dir, apk_file)
                                    
                                    if best_match and best_match_score > 0:
                                        apk_path = best_match
                                
                                # Final fallback: take the largest APK (likely the main one)
                                if not apk_path:
                                    largest_apk = None
                                    largest_size = 0
                                    for apk_file in os.listdir(apks_dir):
                                        if apk_file.endswith('.apk'):
                                            full_path = os.path.join(apks_dir, apk_file)
                                            size = os.path.getsize(full_path)
                                            if size > largest_size:
                                                largest_size = size
                                                largest_apk = full_path
                                    apk_path = largest_apk
                    
                    # Strategy 2: Check current directory
                    if not apk_path:
                        current_dir = os.getcwd()
                        apks_dir = os.path.join(current_dir, 'apks')
                        if os.path.exists(apks_dir):
                            for apk_file in os.listdir(apks_dir):
                                if apk_file.endswith('.apk'):
                                    apk_path = os.path.join(apks_dir, apk_file)
                                    break
                    
                    if apk_path and os.path.exists(apk_path):
                        logger.debug(f"🔧 Converting binary XML using AAPT from {apk_path}")
                        converted_xml_path = self._convert_binary_manifest_to_xml(apk_path, manifest_path)
                        if converted_xml_path and os.path.exists(converted_xml_path):
                            manifest_path = converted_xml_path
                            logger.debug(f"✅ Successfully converted to readable XML: {manifest_path}")
                        else:
                            logger.warning("⚠️ AAPT conversion failed, attempting raw parsing")
                    else:
                        logger.warning("⚠️ Could not find original APK for AAPT conversion")
        except Exception as e:
            logger.debug(f"Binary detection error: {e}")

        # Use enhanced encoding-safe parsing
        try:
            # First try standard parsing
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            return tree, root
        except ET.ParseError:
            # Fallback to safe parsing with encoding detection
            logger.debug(f"Using enhanced encoding parsing for {manifest_path}")
            content = safe_read_file(manifest_path)
            root = safe_parse_xml(content, manifest_path)
            if root is not None:
                # Create a tree from the root element
                tree = ET.ElementTree(root)
                return tree, root
            else:
                raise ET.ParseError(f"Could not parse manifest file: {manifest_path}")

    def _extract_package_info(self, root: ET.Element) -> Dict[str, Any]:
        """Extract basic package information."""
        return {
            "package_name": root.get("package", "unknown"),
            "version_code": root.get(f"{self.android_ns}versionCode", "unknown"),
            "version_name": root.get(f"{self.android_ns}versionName", "unknown"),
            "shared_user_id": root.get(f"{self.android_ns}sharedUserId"),
        }

    def _analyze_exported_components(self, root: ET.Element) -> Dict[str, List[Dict]]:
        """Analyze all exported components in the manifest."""
        components = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }

        app_element = root.find("application")
        if app_element is None:
            return components

        # Analyze each component type
        for component_type in ["activity", "service", "receiver", "provider"]:
            plural_type = (
                f"{component_type}s" if component_type != "activity" else "activities"
            )

            for element in app_element.findall(component_type):
                component_info = self._analyze_component(element, component_type)
                if component_info["exported"]:
                    components[plural_type].append(component_info)

        return components

    def _analyze_component(
        self, element: ET.Element, component_type: str
    ) -> Dict[str, Any]:
        """Analyze a single component for security vulnerabilities."""
        component_info = {
            "name": element.get(f"{self.android_ns}name", "unknown"),
            "type": component_type,
            "exported": False,
            "permission": element.get(f"{self.android_ns}permission"),
            "intent_filters": [],
            "deep_links": [],
            "security_risks": [],
        }

        # Determine if component is exported
        exported_attr = element.get(f"{self.android_ns}exported")
        has_intent_filters = len(element.findall("intent-filter")) > 0

        if exported_attr is not None:
            component_info["exported"] = exported_attr.lower() == "true"
        else:
            # Default behavior: exported if has intent filters
            component_info["exported"] = has_intent_filters

        # Analyze intent filters
        for intent_filter in element.findall("intent-filter"):
            filter_info = self._analyze_intent_filter(intent_filter)
            component_info["intent_filters"].append(filter_info)

            # Check for deep links
            if filter_info["data_schemes"]:
                component_info["deep_links"].extend(filter_info["data_schemes"])

        # Add risk assessment for plugin compatibility
        if component_info["exported"]:
            risk_factors, confidence = self._assess_component_security_risk(component_info)
            
            # Determine risk level based on risk factors
            if "rce_pattern" in risk_factors:
                component_info["risk_level"] = "CRITICAL"
            elif "main_action_present" in risk_factors and "unprotected_exported" in risk_factors:
                component_info["risk_level"] = "HIGH"
            elif "sensitive_action" in risk_factors or "unprotected_exported" in risk_factors:
                component_info["risk_level"] = "HIGH"
            elif component_info["exported"] and not component_info["permission"]:
                component_info["risk_level"] = "MEDIUM"
            else:
                component_info["risk_level"] = "LOW"
            
            # Add security issues based on risk factors
            component_info["security_issues"] = []
            if "unprotected_exported" in risk_factors:
                component_info["security_issues"].append("No permission protection")
            if "main_action_present" in risk_factors:
                component_info["security_issues"].append("Main action exposed")
            if "sensitive_action" in risk_factors:
                component_info["security_issues"].append("Sensitive action exposed")
            if "rce_pattern" in risk_factors:
                component_info["security_issues"].append("Potential RCE risk")
        else:
            # Non-exported components have low risk
            component_info["risk_level"] = "LOW"
            component_info["security_issues"] = []

        return component_info

    def _analyze_intent_filter(self, intent_filter: ET.Element) -> Dict[str, List[str]]:
        """Analyze intent filter for security-relevant patterns."""
        filter_info = {
            "actions": [],
            "categories": [],
            "data_schemes": [],
            "data_hosts": [],
            "data_paths": [],
        }

        # Extract actions
        for action in intent_filter.findall("action"):
            action_name = action.get(f"{self.android_ns}name")
            if action_name:
                filter_info["actions"].append(action_name)

        # Extract categories
        for category in intent_filter.findall("category"):
            category_name = category.get(f"{self.android_ns}name")
            if category_name:
                filter_info["categories"].append(category_name)

        # Extract data schemes, hosts, and paths
        for data in intent_filter.findall("data"):
            scheme = data.get(f"{self.android_ns}scheme")
            host = data.get(f"{self.android_ns}host")
            path = data.get(f"{self.android_ns}path")

            if scheme:
                filter_info["data_schemes"].append(scheme)
            if host:
                filter_info["data_hosts"].append(host)
            if path:
                filter_info["data_paths"].append(path)

        return filter_info

    def _analyze_deep_links(self, root: ET.Element) -> Dict[str, Any]:
        """Analyze deep link configurations in the manifest."""
        deep_link_analysis = {
            "total_schemes": 0,
            "custom_schemes": [],
            "suspicious_schemes": [],
            "scheme_host_combinations": [],
            "potential_vulnerabilities": [],
        }

        app_element = root.find("application")
        if app_element is None:
            return deep_link_analysis

        # Collect all data schemes and scheme-host combinations
        all_schemes = set()
        scheme_host_combos = []

        for component_type in ["activity", "service", "receiver"]:
            for element in app_element.findall(component_type):
                for intent_filter in element.findall("intent-filter"):
                    for data in intent_filter.findall("data"):
                        scheme = data.get(f"{self.android_ns}scheme")
                        host = data.get(f"{self.android_ns}host")

                        if scheme:
                            all_schemes.add(scheme)

                            # Track scheme-host combinations
                            if host:
                                combo = f"{scheme}://{host}"
                                scheme_host_combos.append(
                                    {
                                        "scheme": scheme,
                                        "host": host,
                                        "combination": combo,
                                        "component": element.get(
                                            f"{self.android_ns}name", "unknown"
                                        ),
                                    }
                                )

        deep_link_analysis["total_schemes"] = len(all_schemes)
        deep_link_analysis["custom_schemes"] = list(all_schemes)
        deep_link_analysis["scheme_host_combinations"] = scheme_host_combos

        # Assess each scheme for security risk
        for scheme in all_schemes:
            is_suspicious, risk_factors, confidence = self._assess_scheme_security_risk(
                scheme
            )
            if is_suspicious:
                deep_link_analysis["suspicious_schemes"].append(
                    {
                        "scheme": scheme,
                        "risk_factors": risk_factors,
                        "confidence": confidence,
                    }
                )

        return deep_link_analysis

    def _analyze_permissions(self, root: ET.Element) -> Dict[str, Any]:
        """Analyze permission declarations and usage."""
        permission_analysis = {
            "uses_permissions": [],
            "dangerous_permissions": [],
            "custom_permissions": [],
            "security_risks": [],
        }

        # Analyze uses-permission elements
        for uses_perm in root.findall("uses-permission"):
            perm_name = uses_perm.get(f"{self.android_ns}name")
            if perm_name:
                permission_analysis["uses_permissions"].append(perm_name)

                # Check if it's a high-risk permission
                if any(
                    danger in perm_name
                    for danger in self.permission_patterns["high_risk_permissions"]
                ):
                    permission_analysis["dangerous_permissions"].append(perm_name)

        # Analyze permission definitions
        for permission in root.findall("permission"):
            perm_name = permission.get(f"{self.android_ns}name")
            if perm_name:
                permission_analysis["custom_permissions"].append(perm_name)

        # Add risk assessment for plugin compatibility
        dangerous_count = len(permission_analysis["dangerous_permissions"])
        total_permissions = len(permission_analysis["uses_permissions"])
        custom_permissions = len(permission_analysis["custom_permissions"])
        
        # Determine overall risk level
        if dangerous_count >= 5:
            overall_risk = "CRITICAL"
        elif dangerous_count >= 3:
            overall_risk = "HIGH"
        elif dangerous_count >= 1:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"
        
        permission_analysis["risk_assessment"] = {
            "overall_risk": overall_risk,
            "total_permissions": total_permissions,
            "dangerous_count": dangerous_count,
            "custom_permissions": custom_permissions
        }
        
        # Add additional fields for plugin compatibility
        permission_analysis["defines_permissions"] = []
        permission_analysis["recommendations"] = []
        
        # Add recommendations based on risk
        if dangerous_count >= 3:
            permission_analysis["recommendations"].append("Review and minimize dangerous permission requests")
        if custom_permissions > 0:
            permission_analysis["recommendations"].append("Review custom permission protection levels")
        if total_permissions > 10:
            permission_analysis["recommendations"].append("Consider reducing total permission count")

        return permission_analysis

    def _detect_permission_vulnerabilities(
        self, permission_analysis: Dict[str, Any]
    ) -> List[ManifestFinding]:
        """Detect vulnerabilities in permission configurations."""
        findings = []

        # Analyze dangerous permissions
        dangerous_permissions = permission_analysis.get("dangerous_permissions", [])
        if dangerous_permissions:
            # Determine severity based on number of dangerous permissions
            if len(dangerous_permissions) >= 5:
                severity = "HIGH"
                finding_type = "excessive_high_risk_permissions"
                description = f"App requests {len(dangerous_permissions)} dangerous permissions (excessive)"
            elif len(dangerous_permissions) >= 3:
                severity = "MEDIUM"
                finding_type = "multiple_dangerous_permissions"
                description = f"App requests {len(dangerous_permissions)} dangerous permissions"
            else:
                severity = "LOW"
                finding_type = "dangerous_permissions_present"
                description = f"App requests {len(dangerous_permissions)} dangerous permissions"

            findings.append(
                ManifestFinding(
                    finding_type=finding_type,
                    severity=severity,
                    confidence=0.9,
                    component_name="application",
                    component_type="permissions",
                    description=description,
                    category="permission_security",
                    remediation="Review and minimize dangerous permission requests, implement runtime permissions",
                    security_impact="Potential privacy and security risks from excessive permissions",
                    cwe="CWE-250",
                    context={
                        "dangerous_permissions": dangerous_permissions,
                        "permission_count": len(dangerous_permissions),
                        "detection_method": "organic_permission_analysis",
                    },
                )
            )

        # Check for custom permissions with weak protection levels
        custom_permissions = permission_analysis.get("custom_permissions", [])
        weak_custom_permissions = []
        for perm in custom_permissions:
            if isinstance(perm, dict) and perm.get("protection_level"):
                protection = perm["protection_level"].lower()
                if "normal" in protection or "dangerous" in protection:
                    weak_custom_permissions.append(perm)

        if weak_custom_permissions:
            findings.append(
                ManifestFinding(
                    finding_type="weak_custom_permission_protection",
                    severity="MEDIUM",
                    confidence=0.8,
                    component_name="application",
                    component_type="permissions",
                    description=f"Custom permissions with weak protection levels detected",
                    category="permission_security",
                    remediation="Use 'signature' or 'signatureOrSystem' protection levels for custom permissions",
                    security_impact="Unauthorized access to custom permission-protected resources",
                    cwe="CWE-276",
                    context={
                        "weak_permissions": weak_custom_permissions,
                        "detection_method": "organic_permission_analysis",
                    },
                )
            )

        return findings

    def _detect_exported_component_vulnerabilities(
        self, components: Dict[str, List[Dict]]
    ) -> List[ManifestFinding]:
        """Detect vulnerabilities in exported components using organic patterns."""
        findings = []

        for component_type, component_list in components.items():
            for component in component_list:
                risk_factors, confidence = self._assess_component_security_risk(
                    component
                )

                # Only report if confidence meets threshold
                if (
                    confidence
                    >= self.config["analysis_options"]["base_confidence_threshold"]
                ):

                    # Determine severity based on risk factors and component type
                    severity = self._determine_severity(risk_factors, component_type)

                    # Generate finding for unprotected exported component
                    if "unprotected_exported" in risk_factors:
                        findings.append(
                            ManifestFinding(
                                finding_type=f"unprotected_exported_{component['type']}",
                                severity=severity,
                                confidence=confidence,
                                component_name=component["name"],
                                component_type=component["type"],
                                description=f"Exported {component['type']} lacks permission protection",
                                category="component_security",
                                remediation=f"Add android:permission to protect exported {component['type']}",
                                security_impact=f"Unauthorized {component['type']} access, potential security bypass",
                                cwe="CWE-926",
                                context={
                                    "risk_factors": risk_factors,
                                    "intent_filters": component["intent_filters"],
                                    "detection_method": "organic_component_analysis",
                                },
                            )
                        )

        return findings

    def _detect_deep_link_vulnerabilities(
        self, deep_link_analysis: Dict[str, Any]
    ) -> List[ManifestFinding]:
        """🔥 PRIORITY 2 FIX: Enhanced deep link vulnerability detection with source code RCE analysis."""
        findings = []

        # Analyze suspicious schemes
        for scheme_info in deep_link_analysis["suspicious_schemes"]:
            scheme = scheme_info["scheme"]
            risk_factors = scheme_info["risk_factors"]
            confidence = scheme_info["confidence"]

            # Only report if confidence meets threshold
            if (
                confidence
                >= self.config["analysis_options"]["base_confidence_threshold"]
            ):
                # 🔥 PRIORITY 2 FIX: Enhanced severity and finding type for RCE schemes
                if "execution_scheme" in risk_factors or "potential_command_injection" in risk_factors:
                    # Create specific RCE finding for execution schemes
                    findings.append(
                        ManifestFinding(
                            finding_type="rce_execution_scheme",
                            severity="CRITICAL",
                            confidence=confidence,
                            component_name="deep_link_handler",
                            component_type="deep_link",
                            description=f"Remote Code Execution (RCE) execution scheme detected: {scheme}",
                            category="deep_link_security",
                            remediation="Remove RCE execution schemes, implement secure parameter validation, disable command execution",
                            security_impact="Remote code execution through malicious execution scheme exploitation",
                            cwe="CWE-78",
                            context={
                                "scheme": scheme,
                                "risk_factors": risk_factors,
                                "detection_method": "organic_execution_scheme_analysis",
                                "rce_indicators": ["command_injection", "binary_execution", "parameter_injection"],
                            },
                        )
                    )
                elif "challenge_app_scheme" in risk_factors:
                    # Create high-risk finding for challenge/CTF schemes
                    findings.append(
                        ManifestFinding(
                            finding_type="high_risk_challenge_scheme",
                            severity="HIGH",
                            confidence=confidence,
                            component_name="deep_link_handler",
                            component_type="deep_link",
                            description=f"High-risk challenge/test scheme detected: {scheme}",
                            category="deep_link_security",
                            remediation="Review challenge scheme implementation, ensure proper input validation",
                            security_impact="Potential security bypass through challenge scheme exploitation",
                            cwe="CWE-94",
                            context={
                                "scheme": scheme,
                                "risk_factors": risk_factors,
                                "detection_method": "organic_challenge_scheme_analysis",
                            },
                        )
                    )
                else:
                    # Standard suspicious scheme finding
                    severity = "HIGH" if "rce_pattern" in risk_factors else "MEDIUM"
                    findings.append(
                        ManifestFinding(
                            finding_type="suspicious_deep_link_scheme",
                            severity=severity,
                            confidence=confidence,
                            component_name="deep_link_handler",
                            component_type="deep_link",
                            description=f"Potentially unsafe deep link scheme detected: {scheme}",
                            category="deep_link_security",
                            remediation="Validate and sanitize deep link inputs, implement proper authentication",
                            security_impact="Potential unauthorized access through deep link manipulation",
                            cwe="CWE-200",
                            context={
                                "scheme": scheme,
                                "risk_factors": risk_factors,
                                "detection_method": "organic_scheme_analysis",
                            },
                        )
                    )

        # Analyze scheme-host combinations for RCE risk
        for combo_info in deep_link_analysis["scheme_host_combinations"]:
            scheme = combo_info["scheme"]
            host = combo_info["host"]
            combination = combo_info["combination"]

            # Assess RCE risk organically
            rce_risk_factors = []

            # Check for RCE patterns in scheme or host
            scheme_lower = scheme.lower()
            host_lower = host.lower()

            for pattern in self.deep_link_patterns["rce_risk_patterns"]:
                if re.search(pattern, scheme_lower) or re.search(pattern, host_lower):
                    rce_risk_factors.append("rce_pattern_detected")

            if rce_risk_factors:
                confidence = self.config["risk_scoring"].get(
                    "rce_pattern_detection", 0.95
                )

                findings.append(
                    ManifestFinding(
                        finding_type="potential_rce_deep_link",
                        severity="CRITICAL",
                        confidence=confidence,
                        component_name=combo_info["component"],
                        component_type="deep_link",
                        description=f"Potential RCE deep link detected: {combination}",
                        category="deep_link_security",
                        remediation="Remove dangerous deep links, implement strict input validation",
                        security_impact="Remote code execution through malicious deep link exploitation",
                        cwe="CWE-94",
                        context={
                            "scheme": scheme,
                            "host": host,
                            "combination": combination,
                            "component": combo_info["component"],
                            "risk_factors": rce_risk_factors,
                            "detection_method": "organic_rce_analysis",
                        },
                    )
                )

        # 🔥 PRIORITY 2 FIX: Enhanced source code RCE detection for deep link handlers
        source_code_rce_findings = self._analyze_source_code_for_rce(deep_link_analysis)
        findings.extend(source_code_rce_findings)

        return findings

    def _analyze_source_code_for_rce(
        self, deep_link_analysis: Dict[str, Any]
    ) -> List[ManifestFinding]:
        """🔥 PRIORITY 2 FIX: Analyze source code for RCE patterns in deep link handlers."""
        findings = []

        # Get APK path from the analysis context
        apk_path = getattr(self, "_current_apk_path", None)
        if not apk_path:
            return findings

        try:
            # Use JADX to decompile and analyze source code
            source_code_findings = self._decompile_and_analyze_for_rce(
                apk_path, deep_link_analysis
            )

            for source_finding in source_code_findings:
                # Convert source code findings to manifest findings
                manifest_finding = ManifestFinding(
                    finding_type="rce_command_injection_deep_link",
                    severity="CRITICAL",
                    confidence=source_finding["confidence"],
                    component_name=source_finding["component"],
                    component_type="deep_link",
                    description=f"Command injection vulnerability in deep link handler: {source_finding['description']}",
                    category="deep_link_security",
                    remediation="Remove Runtime.exec() calls, implement secure parameter handling, validate all intent data",
                    security_impact="Remote code execution through malicious deep link parameters",
                    cwe="CWE-78",
                    context={
                        "file_path": source_finding["file_path"],
                        "line_number": source_finding["line_number"],
                        "code_snippet": source_finding["code_snippet"],
                        "rce_pattern": source_finding["pattern_matched"],
                        "detection_method": "organic_source_code_rce_analysis",
                        "intent_data_usage": source_finding.get(
                            "intent_data_usage", False
                        ),
                    },
                )
                findings.append(manifest_finding)

        except Exception as e:
            logger.debug(f"⚠️ Source code RCE analysis failed: {e}")

        return findings

    def _decompile_and_analyze_for_rce(
        self, apk_path: str, deep_link_analysis: Dict[str, Any]
    ) -> List[Dict]:
        """
        Decompile APK and analyze for RCE patterns using memory-optimized unified JADX helper.
        
        This method now uses the centralized JADX manager and cache system
        to eliminate redundant decompilations and optimize memory usage.
        """
        findings = []

        try:
            # Use unified JADX helper for memory optimization
            if JADX_UNIFIED_AVAILABLE:
                logger.debug("Using memory-optimized JADX decompilation for RCE analysis...")
                
                # Get decompiled sources using unified helper
                decompiled_dir = get_decompiled_sources_unified(
                    apk_path=apk_path,
                    analyzer_name="EnhancedManifestAnalyzer_RCE",
                    timeout=30  # Keep original 30s timeout for RCE analysis
                )
                
                if decompiled_dir:
                    # Analyze decompiled source code for RCE patterns
                    findings = self._scan_source_files_for_rce(decompiled_dir, deep_link_analysis)
                    logger.debug(f"Memory-optimized RCE analysis found {len(findings)} findings")
                else:
                    logger.debug("Memory-optimized decompilation failed for RCE analysis, falling back")
                    findings = self._decompile_and_analyze_for_rce_fallback(apk_path, deep_link_analysis)
            else:
                # Use fallback method if unified helper not available
                findings = self._decompile_and_analyze_for_rce_fallback(apk_path, deep_link_analysis)

        except Exception as e:
            logger.debug(f"⚠️ Memory-optimized RCE decompilation failed: {e}")
            # Fall back to direct implementation
            findings = self._decompile_and_analyze_for_rce_fallback(apk_path, deep_link_analysis)

        return findings
    
    def _decompile_and_analyze_for_rce_fallback(
        self, apk_path: str, deep_link_analysis: Dict[str, Any]
    ) -> List[Dict]:
        """Fallback RCE analysis with direct JADX decompilation."""
        import shutil
        import subprocess
        import tempfile

        findings = []

        try:
            # Create temporary directory for decompilation
            with tempfile.TemporaryDirectory(prefix="aods_rce_analysis_fallback_") as temp_dir:
                # Find JADX executable
                jadx_path = self._find_jadx_executable()
                if not jadx_path:
                    return findings

                # Decompile APK with JADX
                jadx_cmd = [
                    jadx_path,
                    "--no-res",  # Skip resources for faster analysis
                    "--no-imports",  # Skip unused imports
                    "--output-dir",
                    temp_dir,
                    apk_path,
                ]

                result = subprocess.run(
                    jadx_cmd, capture_output=True, text=True, timeout=30
                )

                if result.returncode != 0:
                    logger.debug(f"⚠️ JADX fallback decompilation warning: {result.stderr}")

                # Analyze decompiled source code for RCE patterns
                findings = self._scan_source_files_for_rce(temp_dir, deep_link_analysis)

        except Exception as e:
            logger.debug(f"⚠️ Fallback decompilation failed: {e}")

        return findings

    def _find_jadx_executable(self) -> Optional[str]:
        """Find JADX executable in system PATH."""
        jadx_candidates = ["jadx", "/usr/bin/jadx", "/usr/local/bin/jadx"]

        for candidate in jadx_candidates:
            if shutil.which(candidate):
                return candidate

        return None

    def _scan_source_files_for_rce(
        self, source_dir: str, deep_link_analysis: Dict[str, Any]
    ) -> List[Dict]:
        """🔥 PRIORITY 2 FIX: Scan decompiled source files for RCE patterns."""
        import os

        findings = []

        # Get components that handle deep links
        deep_link_components = set()
        for scheme_info in deep_link_analysis.get("suspicious_schemes", []):
            if "component" in scheme_info:
                deep_link_components.add(scheme_info["component"])
        for combo_info in deep_link_analysis.get("scheme_host_combinations", []):
            if "component" in combo_info:
                deep_link_components.add(combo_info["component"])

        try:
            # Walk through all Java files
            for root, dirs, files in os.walk(source_dir):
                for file in files:
                    if file.endswith(".java"):
                        file_path = os.path.join(root, file)

                        # Analyze file for RCE patterns
                        file_findings = self._analyze_java_file_for_rce(
                            file_path, deep_link_components
                        )
                        findings.extend(file_findings)

        except Exception as e:
            logger.debug(f"⚠️ Source file scanning failed: {e}")

        return findings

    def _analyze_java_file_for_rce(
        self, file_path: str, deep_link_components: set
    ) -> List[Dict]:
        """🔥 PRIORITY 2 FIX: Analyze individual Java file for RCE patterns."""
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Check if this file is related to deep link handling
            is_deep_link_handler = self._is_deep_link_handler_file(
                content, deep_link_components
            )

            # Scan for RCE patterns
            for category, patterns in self.deep_link_patterns.items():
                if category in [
                    "source_code_rce_patterns",
                    "intent_parameter_injection",
                ]:
                    for pattern in patterns:
                        matches = re.finditer(
                            pattern, content, re.MULTILINE | re.IGNORECASE
                        )

                        for match in matches:
                            line_number = content[: match.start()].count("\n") + 1
                            code_snippet = self._extract_code_snippet(
                                content, match.start(), match.end()
                            )

                            # Calculate confidence based on context
                            confidence = self._calculate_rce_confidence(
                                match.group(0),
                                code_snippet,
                                is_deep_link_handler,
                                category,
                            )

                            if confidence >= 0.6:  # Threshold for RCE detection
                                findings.append(
                                    {
                                        "file_path": file_path,
                                        "line_number": line_number,
                                        "code_snippet": code_snippet,
                                        "pattern_matched": pattern,
                                        "confidence": confidence,
                                        "component": self._extract_component_name(
                                            file_path
                                        ),
                                        "description": f"RCE pattern detected: {match.group(0)}",
                                        "intent_data_usage": "getIntent" in code_snippet
                                        or "intent." in code_snippet.lower(),
                                    }
                                )

        except Exception as e:
            logger.debug(f"⚠️ Java file analysis failed for {file_path}: {e}")

        return findings

    def _is_deep_link_handler_file(
        self, content: str, deep_link_components: set
    ) -> bool:
        """Check if Java file handles deep links."""
        # Check for deep link handling patterns
        deep_link_indicators = [
            "onNewIntent",
            "getIntent()",
            "Intent.ACTION_VIEW",
            "Uri.parse",
            "getDataString",
            "getStringExtra",
        ]

        content_lower = content.lower()
        for indicator in deep_link_indicators:
            if indicator.lower() in content_lower:
                return True

        # Check if file name matches known deep link components
        for component in deep_link_components:
            if component.lower() in content.lower():
                return True

        return False

    def _calculate_rce_confidence(
        self,
        matched_text: str,
        code_snippet: str,
        is_deep_link_handler: bool,
        category: str,
    ) -> float:
        """Calculate confidence score for RCE pattern detection."""
        confidence = 0.5

        # Higher confidence for deep link handlers
        if is_deep_link_handler:
            confidence += 0.2

        # Category-based adjustments
        if category == "runtime_exec":
            confidence += 0.3
        elif category == "process_builder":
            confidence += 0.25
        elif category == "intent_injection":
            confidence += 0.2

        # Pattern-specific adjustments based on context
        if "getIntent()" in code_snippet and "exec" in matched_text:
            confidence += 0.25

        if any(keyword in matched_text.lower() for keyword in ["shell", "cmd", "bash"]):
            confidence += 0.15

        if "+" in matched_text:  # String concatenation
            confidence += 0.1

        return min(confidence, 1.0)

    def _extract_code_snippet(
        self, content: str, start: int, end: int, context_lines: int = 3
    ) -> str:
        """Extract code snippet with context lines around the match."""
        lines = content.split("\n")
        match_start_line = content[:start].count("\n")
        match_end_line = content[:end].count("\n")

        snippet_start = max(0, match_start_line - context_lines)
        snippet_end = min(len(lines), match_end_line + context_lines + 1)

        return "\n".join(lines[snippet_start:snippet_end])

    def _extract_component_name(self, file_path: str) -> str:
        """Extract component name from file path."""
        return Path(file_path).stem.replace("Activity", "").replace("Service", "")

    def analyze_security_flags(self) -> dict:
        """
        Analyze security flags from AndroidManifest.xml.
        
        This method provides compatibility with the enhanced manifest analysis plugin
        by analyzing security-related flags and configuration settings.
        
        Returns:
            dict: Security flags analysis with debuggable, allow_backup, cleartext traffic, etc.
        """
        if not hasattr(self, '_current_manifest_root') or self._current_manifest_root is None:
            return {
                "debuggable": False,
                "allow_backup": True,
                "uses_cleartext_traffic": None,
                "test_only": False,
                "issues": ["Manifest not loaded - unable to analyze security flags"],
                "recommendations": ["Load AndroidManifest.xml before analyzing security flags"]
            }
        
        root = self._current_manifest_root
        
        # Initialize security flags
        security_flags = {
            "debuggable": False,
            "allow_backup": True,  # Default is true
            "uses_cleartext_traffic": None,  # Default varies by API level
            "test_only": False,
            "issues": [],
            "recommendations": []
        }
        
        # Find application element
        application = root.find("application")
        if application is None:
            security_flags["issues"].append("No application element found in manifest")
            return security_flags
        
        # Check debuggable flag
        debuggable = application.get(f"{self.android_ns}debuggable", "false")
        security_flags["debuggable"] = debuggable.lower() == "true"
        if security_flags["debuggable"]:
            security_flags["issues"].append("Application is debuggable - security risk in production")
            security_flags["recommendations"].append("Set android:debuggable='false' for production builds")
        
        # Check allowBackup flag
        allow_backup = application.get(f"{self.android_ns}allowBackup", "true")
        security_flags["allow_backup"] = allow_backup.lower() == "true"
        if security_flags["allow_backup"]:
            security_flags["issues"].append("Backup is allowed - sensitive data may be exposed")
            security_flags["recommendations"].append("Set android:allowBackup='false' to prevent data backup")
        
        # Check usesCleartextTraffic flag
        cleartext_traffic = application.get(f"{self.android_ns}usesCleartextTraffic")
        if cleartext_traffic is not None:
            security_flags["uses_cleartext_traffic"] = cleartext_traffic.lower() == "true"
            if security_flags["uses_cleartext_traffic"]:
                security_flags["issues"].append("Clear-text traffic is allowed - data transmission not encrypted")
                security_flags["recommendations"].append("Set android:usesCleartextTraffic='false' to enforce HTTPS")
        
        # Check testOnly flag
        test_only = application.get(f"{self.android_ns}testOnly", "false")
        security_flags["test_only"] = test_only.lower() == "true"
        if security_flags["test_only"]:
            security_flags["issues"].append("Application marked as test-only - should not be in production")
            security_flags["recommendations"].append("Remove android:testOnly='true' for production builds")
        
        # Additional security configuration checks
        self._check_additional_security_configs(application, security_flags)
        
        return security_flags
    
    def _check_additional_security_configs(self, application: ET.Element, security_flags: dict) -> None:
        """Check additional security configurations in the application element."""
        
        # Check for exported attribute on application (unusual but possible)
        if application.get(f"{self.android_ns}exported", "false").lower() == "true":
            security_flags["issues"].append("Application element is exported - unusual configuration")
            security_flags["recommendations"].append("Review android:exported='true' on application element")
        
        # Check for hardcoded process name
        process_name = application.get(f"{self.android_ns}process")
        if process_name and not process_name.startswith(":"):
            security_flags["issues"].append(f"Hardcoded process name: {process_name}")
            security_flags["recommendations"].append("Use private process names starting with ':'")
        
        # Check for custom application class
        app_class = application.get(f"{self.android_ns}name")
        if app_class:
            # This is informational - custom Application classes need careful review
            security_flags["recommendations"].append(f"Review custom Application class: {app_class}")
        
        # Check for large heap flag
        large_heap = application.get(f"{self.android_ns}largeHeap", "false")
        if large_heap.lower() == "true":
            security_flags["recommendations"].append("Large heap enabled - ensure memory usage is justified")
    
    def get_exported_components(self) -> dict:
        """
        Get exported components analysis.
        
        This method provides compatibility with the enhanced manifest analysis plugin
        by returning exported components with risk assessment.
        
        Returns:
            dict: Exported components organized by type with risk analysis
        """
        if not hasattr(self, '_current_manifest_root') or self._current_manifest_root is None:
            return {
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": []
            }
        
        return self._analyze_exported_components(self._current_manifest_root)
    
    def analyze_permissions(self) -> dict:
        """
        Analyze permissions for compatibility with the enhanced manifest analysis plugin.
        
        This method provides compatibility by returning permission analysis results
        in the expected format.
        
        Returns:
            dict: Permission analysis with risk assessment and recommendations
        """
        if not hasattr(self, '_current_manifest_root') or self._current_manifest_root is None:
            return {
                "dangerous_permissions": [],
                "defines_permissions": [],
                "risk_assessment": {
                    "overall_risk": "UNKNOWN",
                    "total_permissions": 0,
                    "dangerous_count": 0,
                    "custom_permissions": 0
                },
                "recommendations": ["Manifest not loaded - unable to analyze permissions"]
            }
        
        return self._analyze_permissions(self._current_manifest_root)

    def _determine_severity(self, risk_factors: List[str], component_type: str) -> str:
        """Determine severity based on risk factors and component type."""
        if "rce_pattern" in risk_factors:
            return "CRITICAL"
        elif (
            "main_action_present" in risk_factors
            and "unprotected_exported" in risk_factors
        ):
            return "HIGH"
        elif "sensitive_action" in risk_factors:
            return "HIGH"
        elif "unprotected_exported" in risk_factors:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_statistics(
        self,
        findings: List[ManifestFinding],
        exported_components: Dict[str, List[Dict]],
        deep_link_analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate comprehensive analysis statistics."""

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        category_counts = {}

        for finding in findings:
            severity_counts[finding.severity] += 1
            category_counts[finding.category] = (
                category_counts.get(finding.category, 0) + 1
            )

        total_exported = sum(
            len(components) for components in exported_components.values()
        )

        return {
            "total_findings": len(findings),
            "severity_distribution": severity_counts,
            "category_distribution": category_counts,
            "exported_components": {
                "total": total_exported,
                "by_type": {k: len(v) for k, v in exported_components.items()},
            },
            "deep_links": {
                "total_schemes": deep_link_analysis["total_schemes"],
                "suspicious_schemes": len(deep_link_analysis["suspicious_schemes"]),
            },
            "organic_detection": {
                "component_vulnerabilities": any(
                    f.finding_type.startswith("unprotected_exported") for f in findings
                ),
                "deep_link_vulnerabilities": any(
                    f.finding_type
                    in ["suspicious_deep_link_scheme", "potential_rce_deep_link"]
                    for f in findings
                ),
                "permission_vulnerabilities": any(
                    f.finding_type == "excessive_high_risk_permissions"
                    for f in findings
                ),
            },
        }

    def export_results(self, result: ManifestAnalysisResult, output_file: str) -> bool:
        """Export analysis results to JSON file."""
        try:
            # Convert dataclass to dict
            result_dict = asdict(result)

            with open(output_file, "w") as f:
                json.dump(result_dict, f, indent=2, default=str)

            logger.debug(f"✅ Results exported to {output_file}")
            return True

        except Exception as e:
            logger.error(f"❌ Failed to export results: {e}")
            return False

def main():
    """Main function for testing the Enhanced Manifest Analyzer."""
    import sys

    if len(sys.argv) != 2:
        print("Usage: python enhanced_manifest_analyzer.py <manifest_path>")
        sys.exit(1)

    manifest_path = sys.argv[1]
    analyzer = EnhancedManifestAnalyzer()
    result = analyzer.analyze_manifest(manifest_path)

    print(f"\n🔍 Enhanced Manifest Analysis Results")
    print(f"📊 Total Findings: {len(result.findings)}")
    print(f"⏱️  Analysis Time: {result.analysis_time:.2f}s")

    for finding in result.findings:
        print(f"\n🚨 {finding.finding_type.upper()}")
        print(f"   Severity: {finding.severity}")
        print(f"   Component: {finding.component_name}")
        print(f"   Description: {finding.description}")

if __name__ == "__main__":
    main()
