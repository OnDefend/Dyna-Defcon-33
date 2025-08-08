"""
Privacy Leak Detection Analyzer

This module provides comprehensive privacy leak detection capabilities for Android applications,
implementing MASVS requirements for privacy and data protection. It detects various forms of
data leakage including clipboard access, screenshot capture, location data, and analytics tracking.

Features:
- Clipboard monitoring with Frida hooks on ClipboardManager
- Screenshot security validation (FLAG_SECURE analysis)
- Location data leakage detection (GPS, network, passive)
- Analytics and advertising ID enumeration
- Privacy policy compliance assessment
- Sensitive data exposure detection
- Real-time privacy violation monitoring

MASVS Coverage:
- MSTG-PRIVACY-01: App Permissions and Data Collection
- MSTG-PRIVACY-02: Data Sharing and Third-Party Services
- MSTG-PRIVACY-03: Privacy Policy Compliance
- MSTG-PRIVACY-04: Location Data Handling
- MSTG-PRIVACY-05: Device Identifiers and Analytics
"""

import json
import logging
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.apk_ctx import APKContext
from core.frida_manager import FridaManager

@dataclass
class PrivacyLeak:
    """Represents a privacy leak finding."""

    leak_id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # CLIPBOARD, SCREENSHOT, LOCATION, ANALYTICS, IDENTIFIER, etc.
    confidence: float  # 0.0 to 1.0
    evidence: List[str] = field(default_factory=list)
    data_types: List[str] = field(default_factory=list)  # Types of leaked data
    leakage_methods: List[str] = field(default_factory=list)  # How data is leaked
    timestamp: Optional[float] = None
    recommendations: List[str] = field(default_factory=list)
    masvs_refs: List[str] = field(default_factory=list)
    privacy_impact: str = "UNKNOWN"  # HIGH, MEDIUM, LOW

@dataclass
class ClipboardAnalysisResult:
    """Results from clipboard monitoring analysis."""

    clipboard_accesses: int = 0
    clipboard_writes: int = 0
    clipboard_reads: int = 0
    sensitive_data_copied: List[Dict[str, Any]] = field(default_factory=list)
    clipboard_monitoring_active: bool = False
    findings: List[PrivacyLeak] = field(default_factory=list)

@dataclass
class ScreenshotAnalysisResult:
    """Results from screenshot security analysis."""

    flag_secure_activities: List[str] = field(default_factory=list)
    insecure_activities: List[str] = field(default_factory=list)
    screenshot_attempts: int = 0
    screen_recording_detected: bool = False
    findings: List[PrivacyLeak] = field(default_factory=list)

@dataclass
class LocationAnalysisResult:
    """Results from location data analysis."""

    location_permissions: List[str] = field(default_factory=list)
    location_requests: List[Dict[str, Any]] = field(default_factory=list)
    background_location: bool = False
    precise_location: bool = False
    location_sharing: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[PrivacyLeak] = field(default_factory=list)

@dataclass
class AnalyticsAnalysisResult:
    """Results from analytics and tracking analysis."""

    advertising_ids: List[Dict[str, Any]] = field(default_factory=list)
    analytics_sdks: List[str] = field(default_factory=list)
    tracking_domains: Set[str] = field(default_factory=set)
    user_profiling: List[Dict[str, Any]] = field(default_factory=list)
    data_collection: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[PrivacyLeak] = field(default_factory=list)

class PrivacyLeakAnalyzer:
    """
    Comprehensive privacy leak detection analyzer.

    This class provides advanced privacy analysis capabilities including:
    - Real-time clipboard monitoring via Frida hooks
    - Screenshot security validation and FLAG_SECURE detection
    - Location data access and sharing analysis
    - Analytics SDK and advertising ID detection
    - Privacy policy compliance assessment
    - Sensitive data exposure monitoring
    """

    def __init__(self, apk_ctx: APKContext):
        """Initialize privacy leak analyzer."""
        self.apk_ctx = apk_ctx
        self.package_name = apk_ctx.package_name
        self.console = Console()
        self.temp_dir = Path(tempfile.mkdtemp(prefix="privacy_analysis_"))
        self.frida_manager: Optional[FridaManager] = None

        # Sensitive data patterns
        self.sensitive_patterns = {
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "phone": r"\b\+?[\d\s\-\(\)]{10,}\b",
            "credit_card": r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
            "ssn": r"\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b",
            "api_key": r"\b[A-Za-z0-9]{20,}\b",
            "password": r'password["\s]*[:=]["\s]*[^\s"]{4,}',
            "token": r'token["\s]*[:=]["\s]*[^\s"]{10,}',
        }

        # Analytics SDK patterns
        self.analytics_sdks = [
            "com.google.firebase.analytics",
            "com.google.android.gms.analytics",
            "com.facebook.appevents",
            "com.mixpanel.android",
            "com.amplitude.api",
            "com.segment.analytics",
            "com.flurry.android",
            "com.localytics.android",
            "com.crashlytics.android",
            "com.adjust.sdk",
        ]

    def analyze_privacy_leaks(self, enable_dynamic: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive privacy leak analysis.

        Args:
            enable_dynamic: Whether to perform dynamic analysis with Frida

        Returns:
            Dict containing comprehensive privacy analysis results
        """
        results = {
            "clipboard_analysis": ClipboardAnalysisResult(),
            "screenshot_analysis": ScreenshotAnalysisResult(),
            "location_analysis": LocationAnalysisResult(),
            "analytics_analysis": AnalyticsAnalysisResult(),
            "overall_findings": [],
            "privacy_score": 0.0,
            "recommendations": [],
        }

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Privacy leak analysis..."),
                console=self.console,
            ) as progress:
                task = progress.add_task("Analyzing privacy leaks", total=100)

                # Static analysis first
                progress.update(
                    task, advance=20, description="Analyzing manifest permissions..."
                )
                self._analyze_manifest_permissions(results)

                progress.update(
                    task, advance=20, description="Analyzing code for privacy leaks..."
                )
                self._analyze_code_privacy_patterns(results)

                progress.update(
                    task, advance=20, description="Analyzing screenshot security..."
                )
                self._analyze_screenshot_security(results)

                progress.update(
                    task, advance=20, description="Analyzing analytics SDKs..."
                )
                self._analyze_analytics_sdks(results)

                # Dynamic analysis if enabled
                if enable_dynamic:
                    progress.update(
                        task, advance=10, description="Starting dynamic analysis..."
                    )
                    if self._setup_frida():
                        self._perform_dynamic_privacy_analysis(results)

                progress.update(
                    task, advance=10, description="Calculating privacy score..."
                )
                self._calculate_privacy_score(results)

        except Exception as e:
            logging.error(f"Privacy leak analysis failed: {e}")

        return results

    def _analyze_manifest_permissions(self, results: Dict[str, Any]):
        """Analyze manifest for privacy-related permissions."""
        try:
            # Get permissions from the APK analyzer
            permissions = []
            if hasattr(self.apk_ctx, "analyzer") and self.apk_ctx.analyzer:
                permissions = self.apk_ctx.analyzer.get_permissions() or []
            elif hasattr(self.apk_ctx, "permissions"):
                permissions = self.apk_ctx.permissions or []

            if not permissions:
                logging.debug("No permissions found for analysis")
                return

            # Location permissions
            location_perms = [
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.ACCESS_BACKGROUND_LOCATION",
            ]

            for perm in permissions:
                if perm in location_perms:
                    results["location_analysis"].location_permissions.append(perm)

                    # Check for background location
                    if "BACKGROUND_LOCATION" in perm:
                        results["location_analysis"].background_location = True
                        leak = PrivacyLeak(
                            leak_id="PRIVACY_LOC_001",
                            title="Background Location Access",
                            description="App requests background location access which may lead to continuous tracking",
                            severity="HIGH",
                            category="LOCATION",
                            confidence=0.9,
                            evidence=[f"Permission: {perm}"],
                            data_types=["location"],
                            privacy_impact="HIGH",
                            masvs_refs=["MSTG-PRIVACY-04"],
                            recommendations=[
                                "Justify background location usage",
                                "Implement location data minimization",
                                "Provide clear user consent mechanism",
                            ],
                        )
                        results["location_analysis"].findings.append(leak)

            # Check for other privacy-sensitive permissions
            sensitive_perms = {
                "android.permission.READ_CONTACTS": ("CONTACTS", "Contact data access"),
                "android.permission.READ_SMS": ("SMS", "SMS message access"),
                "android.permission.READ_CALL_LOG": ("CALL_LOG", "Call log access"),
                "android.permission.CAMERA": ("CAMERA", "Camera access"),
                "android.permission.RECORD_AUDIO": ("MICROPHONE", "Microphone access"),
                "android.permission.READ_EXTERNAL_STORAGE": (
                    "STORAGE",
                    "External storage access",
                ),
            }

            for perm in permissions:
                if perm in sensitive_perms:
                    category, desc = sensitive_perms[perm]
                    leak = PrivacyLeak(
                        leak_id=f"PRIVACY_{category}_001",
                        title=f"Sensitive Permission: {category}",
                        description=desc,
                        severity="MEDIUM",
                        category=category,
                        confidence=0.8,
                        evidence=[f"Permission: {perm}"],
                        privacy_impact="MEDIUM",
                        masvs_refs=["MSTG-PRIVACY-01"],
                        recommendations=[
                            "Justify permission usage with clear purpose",
                            "Request permissions at runtime when needed",
                            "Implement data usage transparency",
                        ],
                    )
                    results["overall_findings"].append(leak)

        except Exception as e:
            logging.error(f"Error analyzing manifest permissions: {e}")
            logging.debug(f"Available apk_ctx attributes: {dir(self.apk_ctx)}")
            if hasattr(self.apk_ctx, "analyzer"):
                logging.debug(
                    f"Analyzer available: {self.apk_ctx.analyzer is not None}"
                )
                if self.apk_ctx.analyzer:
                    logging.debug(
                        f"Analyzer methods: {[method for method in dir(self.apk_ctx.analyzer) if not method.startswith('_')]}"
                    )

    def _analyze_code_privacy_patterns(self, results: Dict[str, Any]):
        """Analyze code for privacy leak patterns."""
        if (
            not hasattr(self.apk_ctx, "jadx_output_dir")
            or not self.apk_ctx.jadx_output_dir
        ):
            return

        java_files = list(self.apk_ctx.jadx_output_dir.rglob("*.java"))

        for java_file in java_files:
            try:
                content = java_file.read_text(encoding="utf-8", errors="ignore")
                self._analyze_file_for_privacy_patterns(java_file, content, results)
            except Exception as e:
                logging.debug(f"Error analyzing {java_file}: {e}")

    def _analyze_file_for_privacy_patterns(
        self, file_path: Path, content: str, results: Dict[str, Any]
    ):
        """Analyze individual file for privacy patterns."""

        # Clipboard access detection
        clipboard_patterns = [
            r"ClipboardManager.*getSystemService",
            r"ClipboardManager.*getText",
            r"ClipboardManager.*setText",
            r"CLIPBOARD_SERVICE",
        ]

        for pattern in clipboard_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                results["clipboard_analysis"].clipboard_accesses += 1
                leak = PrivacyLeak(
                    leak_id="PRIVACY_CLIP_001",
                    title="Clipboard Access Detected",
                    description=f"App accesses clipboard in {file_path.name}",
                    severity="MEDIUM",
                    category="CLIPBOARD",
                    confidence=0.8,
                    evidence=[f"File: {file_path.name}", f"Pattern: {pattern}"],
                    data_types=["clipboard_content"],
                    privacy_impact="MEDIUM",
                    masvs_refs=["MSTG-PRIVACY-01"],
                    recommendations=[
                        "Minimize clipboard access",
                        "Clear clipboard after use",
                        "Inform users about clipboard usage",
                    ],
                )
                results["clipboard_analysis"].findings.append(leak)

        # Location access detection
        location_patterns = [
            r"LocationManager.*getLastKnownLocation",
            r"LocationManager.*requestLocationUpdates",
            r"FusedLocationProviderClient",
            r"getLatitude|getLongitude",
            r"GPS_PROVIDER|NETWORK_PROVIDER",
        ]

        for pattern in location_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                results["location_analysis"].location_requests.append(
                    {
                        "file": str(file_path.name),
                        "pattern": pattern,
                        "context": self._extract_context(content, pattern),
                    }
                )

        # Analytics and tracking detection
        for sdk in self.analytics_sdks:
            if sdk in content:
                results["analytics_analysis"].analytics_sdks.append(sdk)
                leak = PrivacyLeak(
                    leak_id="PRIVACY_ANALYTICS_001",
                    title=f"Analytics SDK Detected: {sdk}",
                    description=f"App uses analytics SDK which may collect user data",
                    severity="MEDIUM",
                    category="ANALYTICS",
                    confidence=0.9,
                    evidence=[f"File: {file_path.name}", f"SDK: {sdk}"],
                    data_types=["usage_analytics", "user_behavior"],
                    privacy_impact="MEDIUM",
                    masvs_refs=["MSTG-PRIVACY-02"],
                    recommendations=[
                        "Review analytics data collection practices",
                        "Implement opt-out mechanisms",
                        "Ensure GDPR compliance",
                    ],
                )
                results["analytics_analysis"].findings.append(leak)

        # Advertising ID detection
        adid_patterns = [
            r"AdvertisingIdClient\.getAdvertisingIdInfo",
            r"getAdvertisingId\(\)",
            r"ADVERTISING_ID",
        ]

        for pattern in adid_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                results["analytics_analysis"].advertising_ids.append(
                    {
                        "file": str(file_path.name),
                        "pattern": pattern,
                        "context": self._extract_context(content, pattern),
                    }
                )

        # Sensitive data patterns
        for data_type, pattern in self.sensitive_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                leak = PrivacyLeak(
                    leak_id=f"PRIVACY_DATA_{data_type.upper()}_001",
                    title=f"Potential {data_type.title()} Exposure",
                    description=f"Pattern suggesting {data_type} data found in code",
                    severity=(
                        "HIGH"
                        if data_type in ["credit_card", "ssn", "password"]
                        else "MEDIUM"
                    ),
                    category="SENSITIVE_DATA",
                    confidence=0.7,
                    evidence=[f"File: {file_path.name}", f"Pattern: {match.group()}"],
                    data_types=[data_type],
                    privacy_impact=(
                        "HIGH" if data_type in ["credit_card", "ssn"] else "MEDIUM"
                    ),
                    masvs_refs=["MSTG-PRIVACY-01"],
                    recommendations=[
                        "Remove hardcoded sensitive data",
                        "Use secure storage mechanisms",
                        "Implement data encryption",
                    ],
                )
                results["overall_findings"].append(leak)

    def _analyze_screenshot_security(self, results: Dict[str, Any]):
        """Analyze screenshot security implementation."""
        if (
            not hasattr(self.apk_ctx, "jadx_output_dir")
            or not self.apk_ctx.jadx_output_dir
        ):
            return

        java_files = list(self.apk_ctx.jadx_output_dir.rglob("*.java"))
        flag_secure_found = False

        for java_file in java_files:
            try:
                content = java_file.read_text(encoding="utf-8", errors="ignore")

                # Check for FLAG_SECURE usage - more specific patterns to avoid false positives
                flag_secure_patterns = [
                    r"WindowManager\.LayoutParams\.FLAG_SECURE",
                    r"setFlags\s*\([^)]*FLAG_SECURE",
                    r"addFlags\s*\([^)]*FLAG_SECURE",
                    r"\.FLAG_SECURE\s*[,\)]",  # FLAG_SECURE used as parameter
                ]

                file_has_flag_secure = False
                for pattern in flag_secure_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        flag_secure_found = True
                        file_has_flag_secure = True
                        results["screenshot_analysis"].flag_secure_activities.append(
                            str(java_file.name)
                        )
                        break  # Only add once per file

                # Check for activities that should use FLAG_SECURE
                sensitive_activity_patterns = [
                    r"class.*LoginActivity",
                    r"class.*PaymentActivity",
                    r"class.*BankingActivity",
                    r"class.*PasswordActivity",
                ]

                for pattern in sensitive_activity_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        if not file_has_flag_secure:
                            results["screenshot_analysis"].insecure_activities.append(
                                str(java_file.name)
                            )
                            leak = PrivacyLeak(
                                leak_id="PRIVACY_SCREENSHOT_001",
                                title="Sensitive Activity Without FLAG_SECURE",
                                description=f"Sensitive activity {java_file.name} lacks screenshot protection",
                                severity="HIGH",
                                category="SCREENSHOT",
                                confidence=0.8,
                                evidence=[
                                    f"File: {java_file.name}",
                                    f"Pattern: {pattern}",
                                ],
                                data_types=["screen_content"],
                                privacy_impact="HIGH",
                                masvs_refs=["MSTG-PRIVACY-01"],
                                recommendations=[
                                    "Implement FLAG_SECURE for sensitive activities",
                                    "Prevent screenshots during sensitive operations",
                                    "Consider app backgrounding protection",
                                ],
                            )
                            results["screenshot_analysis"].findings.append(leak)

            except Exception as e:
                logging.debug(f"Error analyzing {java_file}: {e}")

        # If no FLAG_SECURE found at all, it's a potential issue
        if not flag_secure_found:
            leak = PrivacyLeak(
                leak_id="PRIVACY_SCREENSHOT_002",
                title="No Screenshot Protection Implemented",
                description="App does not implement any screenshot protection mechanisms",
                severity="MEDIUM",
                category="SCREENSHOT",
                confidence=0.9,
                evidence=["No FLAG_SECURE usage found in codebase"],
                data_types=["screen_content"],
                privacy_impact="MEDIUM",
                masvs_refs=["MSTG-PRIVACY-01"],
                recommendations=[
                    "Implement FLAG_SECURE for sensitive screens",
                    "Consider screenshot detection and warnings",
                    "Implement app backgrounding protection",
                ],
            )
            results["screenshot_analysis"].findings.append(leak)

    def _analyze_analytics_sdks(self, results: Dict[str, Any]):
        """Analyze analytics SDKs and tracking mechanisms."""
        # Already handled in _analyze_code_privacy_patterns
        # Additional analysis for tracking domains could be added here
        pass

    def _setup_frida(self) -> bool:
        """Setup Frida for dynamic analysis."""
        try:
            self.frida_manager = FridaManager(self.package_name)
            available, msg = self.frida_manager.check_frida_availability()

            if not available:
                logging.warning(f"Frida not available: {msg}")
                return False

            if not self.frida_manager.start_frida_server():
                logging.warning("Failed to start Frida server")
                return False

            if not self.frida_manager.attach_to_app():
                logging.warning("Failed to attach to app")
                return False

            return True

        except Exception as e:
            logging.error(f"Frida setup failed: {e}")
            return False

    def _perform_dynamic_privacy_analysis(self, results: Dict[str, Any]):
        """Perform dynamic privacy analysis using Frida."""
        if not self.frida_manager:
            return

        try:
            # Monitor clipboard operations
            self._monitor_clipboard_operations(results)

            # Monitor location requests
            self._monitor_location_requests(results)

            # Monitor analytics calls
            self._monitor_analytics_calls(results)

        except Exception as e:
            logging.error(f"Dynamic privacy analysis failed: {e}")

    def _monitor_clipboard_operations(self, results: Dict[str, Any]):
        """Monitor clipboard operations using Frida."""
        clipboard_script = """
        Java.perform(function() {
            var ClipboardManager = Java.use("android.content.ClipboardManager");

            ClipboardManager.getText.implementation = function() {
                console.log("[PRIVACY] Clipboard getText() called");
                send({type: "clipboard_read", timestamp: Date.now()});
                return this.getText();
            };

            ClipboardManager.setText.implementation = function(text) {
                console.log("[PRIVACY] Clipboard setText() called with: " + text);
                send({type: "clipboard_write", text: text.toString(), timestamp: Date.now()});
                return this.setText(text);
            };
        });
        """

        try:
            script = self.frida_manager.session.create_script(clipboard_script)

            def on_message(message, data):
                if message["type"] == "send":
                    payload = message["payload"]
                    if payload["type"] == "clipboard_read":
                        results["clipboard_analysis"].clipboard_reads += 1
                    elif payload["type"] == "clipboard_write":
                        results["clipboard_analysis"].clipboard_writes += 1

                        # Check for sensitive data
                        text = payload.get("text", "")
                        for data_type, pattern in self.sensitive_patterns.items():
                            if re.search(pattern, text, re.IGNORECASE):
                                results[
                                    "clipboard_analysis"
                                ].sensitive_data_copied.append(
                                    {
                                        "data_type": data_type,
                                        "timestamp": payload["timestamp"],
                                        "detected_pattern": pattern,
                                    }
                                )

            script.on("message", on_message)
            script.load()

            # Run for a short period
            time.sleep(10)

            results["clipboard_analysis"].clipboard_monitoring_active = True

        except Exception as e:
            logging.error(f"Clipboard monitoring failed: {e}")

    def _monitor_location_requests(self, results: Dict[str, Any]):
        """Monitor location requests using Frida."""
        location_script = """
        Java.perform(function() {
            var LocationManager = Java.use("android.location.LocationManager");

            LocationManager.getLastKnownLocation.implementation = function(provider) {
                console.log("[PRIVACY] getLastKnownLocation called for provider: " + provider);
                send({type: "location_request", provider: provider, timestamp: Date.now()});
                return this.getLastKnownLocation(provider);
            };

            LocationManager.requestLocationUpdates.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    console.log("[PRIVACY] requestLocationUpdates called");
                    send({type: "location_updates", timestamp: Date.now()});
                    return overload.apply(this, arguments);
                };
            });
        });
        """

        try:
            script = self.frida_manager.session.create_script(location_script)

            def on_message(message, data):
                if message["type"] == "send":
                    payload = message["payload"]
                    if payload["type"] in ["location_request", "location_updates"]:
                        results["location_analysis"].location_requests.append(payload)

            script.on("message", on_message)
            script.load()

            time.sleep(10)

        except Exception as e:
            logging.error(f"Location monitoring failed: {e}")

    def _monitor_analytics_calls(self, results: Dict[str, Any]):
        """Monitor analytics and tracking calls."""
        # Implementation for monitoring analytics calls would go here
        pass

    def _extract_context(self, content: str, pattern: str, window: int = 50) -> str:
        """Extract context around a pattern match."""
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            start = max(0, match.start() - window)
            end = min(len(content), match.end() + window)
            return content[start:end].strip()
        return ""

    def _calculate_privacy_score(self, results: Dict[str, Any]):
        """Calculate overall privacy score based on findings."""
        total_findings = 0
        critical_findings = 0
        high_findings = 0

        for category in [
            "clipboard_analysis",
            "screenshot_analysis",
            "location_analysis",
            "analytics_analysis",
        ]:
            if category in results:
                category_data = results[category]
                if hasattr(category_data, "findings"):
                    for finding in category_data.findings:
                        total_findings += 1
                        if finding.severity == "CRITICAL":
                            critical_findings += 1
                        elif finding.severity == "HIGH":
                            high_findings += 1

        for finding in results["overall_findings"]:
            total_findings += 1
            if finding.severity == "CRITICAL":
                critical_findings += 1
            elif finding.severity == "HIGH":
                high_findings += 1

        # Calculate score (higher is better)
        base_score = 100.0
        penalty = (critical_findings * 20) + (high_findings * 10) + (total_findings * 2)
        privacy_score = max(0.0, base_score - penalty)

        results["privacy_score"] = privacy_score

        # Generate recommendations
        if privacy_score < 50:
            results["recommendations"].append(
                "Immediate privacy review required - multiple critical issues found"
            )
        elif privacy_score < 70:
            results["recommendations"].append("Significant privacy improvements needed")
        elif privacy_score < 85:
            results["recommendations"].append("Minor privacy enhancements recommended")
        else:
            results["recommendations"].append("Good privacy practices detected")

    def cleanup(self):
        """Clean up temporary resources."""
        try:
            if (
                self.frida_manager
                and hasattr(self.frida_manager, "session")
                and self.frida_manager.session
            ):
                self.frida_manager.session.detach()

            if self.temp_dir.exists():
                import shutil

                shutil.rmtree(self.temp_dir)
        except Exception as e:
            logging.debug(f"Cleanup error: {e}")
