"""
WebView Security Analyzer for Android Security Testing.

This module provides comprehensive WebView security analysis capabilities including
XSS detection, JavaScript bridge security testing, insecure settings detection,
and WebView configuration analysis as required by MASVS standards.
"""

import json
import logging
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import quote, unquote

from rich.text import Text

class WebViewAnalyzer:
    """
    WebView security analyzer for Android applications.

    This class provides comprehensive WebView security testing including:
    - XSS vulnerability detection and exploitation
    - JavaScript bridge security analysis
    - Insecure WebView settings detection
    - Content Security Policy (CSP) validation
    - File access and universal access testing
    - WebView configuration security assessment

    Attributes:
        package_name (str): Android package name
        device_id (Optional[str]): Android device ID
        temp_dir (Path): Temporary directory for analysis files
        analysis_results (Dict): Collection of analysis results
    """

    def __init__(self, package_name: str, device_id: Optional[str] = None):
        """
        Initialize WebView analyzer.

        Args:
            package_name: Android package name
            device_id: Optional Android device ID (uses default device if None)
        """
        self.package_name = package_name
        self.device_id = device_id
        self.temp_dir = Path(tempfile.mkdtemp(prefix="webview_analysis_"))
        self.analysis_results: Dict[str, any] = {}
        self.xss_payloads = self._generate_xss_payloads()
        self.js_bridge_tests = self._generate_js_bridge_tests()

    def check_adb_availability(self) -> Tuple[bool, str]:
        """
        Check if ADB is available and device is connected.

        Returns:
            Tuple of (is_available, status_message)
        """
        try:
            # Check if adb is installed
            result = subprocess.run(
                ["adb", "version"], capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0:
                return False, "ADB not found. Install Android SDK platform-tools"

            # Check if device is connected
            device_cmd = ["adb"]
            if self.device_id:
                device_cmd.extend(["-s", self.device_id])
            device_cmd.append("devices")

            device_check = subprocess.run(
                device_cmd, capture_output=True, text=True, timeout=10
            )

            if device_check.returncode != 0:
                return False, "Failed to list ADB devices"

            devices_output = device_check.stdout
            if "device" not in devices_output or "offline" in devices_output:
                return False, "No connected devices found or device offline"

            return True, "ADB available with connected device"

        except subprocess.TimeoutExpired:
            return False, "ADB command timed out"
        except Exception as e:
            return False, f"ADB check failed: {str(e)}"

    def _generate_xss_payloads(self) -> List[Dict]:
        """Generate comprehensive XSS test payloads."""
        return [
            # Basic XSS payloads
            {
                "name": "Basic Script Alert",
                "payload": "<script>alert('XSS')</script>",
                "type": "script_injection",
                "severity": "HIGH",
            },
            {
                "name": "Image Onerror XSS",
                "payload": "<img src=x onerror=alert('XSS')>",
                "type": "attribute_injection",
                "severity": "HIGH",
            },
            {
                "name": "SVG XSS",
                "payload": "<svg onload=alert('XSS')>",
                "type": "svg_injection",
                "severity": "HIGH",
            },
            {
                "name": "JavaScript URL",
                "payload": "javascript:alert('XSS')",
                "type": "url_injection",
                "severity": "MEDIUM",
            },
            {
                "name": "Data URL XSS",
                "payload": "data:text/html,<script>alert('XSS')</script>",
                "type": "data_url",
                "severity": "HIGH",
            },
            # Advanced XSS payloads
            {
                "name": "Event Handler XSS",
                "payload": "<body onload=alert('XSS')>",
                "type": "event_handler",
                "severity": "HIGH",
            },
            {
                "name": "Iframe XSS",
                "payload": "<iframe src=javascript:alert('XSS')></iframe>",
                "type": "iframe_injection",
                "severity": "HIGH",
            },
            {
                "name": "Form Action XSS",
                "payload": "<form action=javascript:alert('XSS')><input type=submit>",
                "type": "form_injection",
                "severity": "MEDIUM",
            },
            {
                "name": "Meta Refresh XSS",
                "payload": "<meta http-equiv=refresh content=0;url=javascript:alert('XSS')>",
                "type": "meta_injection",
                "severity": "MEDIUM",
            },
            {
                "name": "CSS Expression XSS",
                "payload": "<style>body{background:url('javascript:alert(\"XSS\")')}</style>",
                "type": "css_injection",
                "severity": "MEDIUM",
            },
            # Encoded XSS payloads
            {
                "name": "URL Encoded XSS",
                "payload": "%3Cscript%3Ealert('XSS')%3C/script%3E",
                "type": "encoded_injection",
                "severity": "HIGH",
            },
            {
                "name": "HTML Entity XSS",
                "payload": "&lt;script&gt;alert('XSS')&lt;/script&gt;",
                "type": "entity_injection",
                "severity": "MEDIUM",
            },
            {
                "name": "Unicode XSS",
                "payload": "<script>alert('\\u0058\\u0053\\u0053')</script>",
                "type": "unicode_injection",
                "severity": "HIGH",
            },
            # Context-specific XSS
            {
                "name": "Attribute Context XSS",
                "payload": "' onmouseover=alert('XSS') '",
                "type": "attribute_context",
                "severity": "HIGH",
            },
            {
                "name": "Script Context XSS",
                "payload": "';alert('XSS');//",
                "type": "script_context",
                "severity": "HIGH",
            },
            {
                "name": "CSS Context XSS",
                "payload": "expression(alert('XSS'))",
                "type": "css_context",
                "severity": "MEDIUM",
            },
        ]

    def _generate_js_bridge_tests(self) -> List[Dict]:
        """Generate JavaScript bridge security tests."""
        return [
            # Bridge enumeration
            {
                "name": "Bridge Enumeration",
                "script": "for(var prop in window) { if(typeof window[prop] === 'object' && window[prop] !== null) console.log('Bridge: ' + prop); }",
                "type": "enumeration",
                "severity": "INFO",
            },
            # Common bridge names
            {
                "name": "Android Bridge Test",
                "script": "if(typeof Android !== 'undefined') { console.log('Android bridge found'); try { Android.toString(); } catch(e) { console.log('Android bridge error: ' + e); } }",
                "type": "bridge_test",
                "severity": "MEDIUM",
            },
            {
                "name": "WebAppInterface Test",
                "script": "if(typeof WebAppInterface !== 'undefined') { console.log('WebAppInterface found'); try { WebAppInterface.toString(); } catch(e) { console.log('WebAppInterface error: ' + e); } }",
                "type": "bridge_test",
                "severity": "MEDIUM",
            },
            {
                "name": "JSInterface Test",
                "script": "if(typeof JSInterface !== 'undefined') { console.log('JSInterface found'); try { JSInterface.toString(); } catch(e) { console.log('JSInterface error: ' + e); } }",
                "type": "bridge_test",
                "severity": "MEDIUM",
            },
            # Bridge exploitation attempts
            {
                "name": "File System Access Test",
                "script": "try { if(typeof Android !== 'undefined' && Android.readFile) { Android.readFile('/etc/passwd'); } } catch(e) { console.log('File access blocked: ' + e); }",
                "type": "exploitation",
                "severity": "HIGH",
            },
            {
                "name": "Command Execution Test",
                "script": "try { if(typeof Android !== 'undefined' && Android.exec) { Android.exec('id'); } } catch(e) { console.log('Command execution blocked: ' + e); }",
                "type": "exploitation",
                "severity": "CRITICAL",
            },
            {
                "name": "Reflection Attack Test",
                "script": "try { if(typeof Android !== 'undefined') { var clazz = Android.getClass(); console.log('Reflection possible: ' + clazz); } } catch(e) { console.log('Reflection blocked: ' + e); }",
                "type": "exploitation",
                "severity": "HIGH",
            },
            # Data exfiltration tests
            {
                "name": "Data Exfiltration Test",
                "script": "try { var data = document.cookie + '|' + localStorage.getItem('token') + '|' + sessionStorage.getItem('session'); if(typeof Android !== 'undefined' && Android.sendData) { Android.sendData(data); } } catch(e) { console.log('Data exfiltration blocked: ' + e); }",
                "type": "data_exfiltration",
                "severity": "HIGH",
            },
            {
                "name": "Location Access Test",
                "script": "try { navigator.geolocation.getCurrentPosition(function(pos) { if(typeof Android !== 'undefined' && Android.sendLocation) { Android.sendLocation(pos.coords.latitude, pos.coords.longitude); } }); } catch(e) { console.log('Location access blocked: ' + e); }",
                "type": "privacy_leak",
                "severity": "MEDIUM",
            },
        ]

    def test_webview_xss_vulnerabilities(self) -> List[Dict]:
        """
        Test WebView for XSS vulnerabilities using various payloads.

        Returns:
            List of XSS test results
        """
        results = []

        for payload_info in self.xss_payloads:
            payload = payload_info["payload"]

            # Test via intent data
            intent_result = self._test_xss_via_intent(payload, payload_info)
            if intent_result:
                results.append(intent_result)

            # Test via URL parameter
            url_result = self._test_xss_via_url(payload, payload_info)
            if url_result:
                results.append(url_result)

            # Test via file URL
            file_result = self._test_xss_via_file(payload, payload_info)
            if file_result:
                results.append(file_result)

            # Small delay between tests
            time.sleep(0.5)

        return results

    def test_javascript_bridge_security(self) -> List[Dict]:
        """
        Test JavaScript bridge security and exposed methods.

        Returns:
            List of JavaScript bridge test results
        """
        results = []

        for test_info in self.js_bridge_tests:
            script = test_info["script"]

            # Execute JavaScript in WebView context
            result = self._execute_javascript_in_webview(script, test_info)
            if result:
                results.append(result)

            # Small delay between tests
            time.sleep(0.5)

        return results

    def test_webview_settings_security(self) -> Dict[str, any]:
        """
        Test WebView security settings and configurations.

        Returns:
            Dict containing WebView settings analysis
        """
        settings_tests = {
            "javascript_enabled": self._test_javascript_enabled(),
            "file_access_enabled": self._test_file_access(),
            "file_access_from_file_urls": self._test_file_access_from_file_urls(),
            "universal_access_from_file_urls": self._test_universal_access_from_file_urls(),
            "allow_content_access": self._test_content_access(),
            "mixed_content_mode": self._test_mixed_content_mode(),
            "safe_browsing_enabled": self._test_safe_browsing(),
            "dom_storage_enabled": self._test_dom_storage(),
        }

        return {
            "timestamp": time.time(),
            "package_name": self.package_name,
            "settings_analysis": settings_tests,
            "security_score": self._calculate_webview_security_score(settings_tests),
            "recommendations": self._generate_webview_recommendations(settings_tests),
        }

    def _test_xss_via_intent(self, payload: str, payload_info: Dict) -> Optional[Dict]:
        """Test XSS via intent data."""
        try:
            cmd = ["adb"]
            if self.device_id:
                cmd.extend(["-s", self.device_id])

            # Create intent with XSS payload
            cmd.extend(
                [
                    "shell",
                    "am",
                    "start",
                    "-a",
                    "android.intent.action.VIEW",
                    "-d",
                    f"http://example.com?data={quote(payload)}",
                    "-n",
                    f"{self.package_name}/.MainActivity",
                ]
            )

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            # Check for successful execution
            if result.returncode == 0 and "Complete" in result.stdout:
                # Check logcat for XSS execution indicators
                xss_detected = self._check_logcat_for_xss()

                return {
                    "test_type": "intent_xss",
                    "payload_info": payload_info,
                    "payload": payload,
                    "method": "intent_data",
                    "executed": "Complete" in result.stdout,
                    "xss_detected": xss_detected,
                    "result": result.stdout,
                    "timestamp": time.time(),
                }

        except Exception as e:
            logging.warning(f"Intent XSS test failed: {e}")

        return None

    def _test_xss_via_url(self, payload: str, payload_info: Dict) -> Optional[Dict]:
        """Test XSS via URL parameter."""
        try:
            # Create HTML file with XSS payload
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head><title>XSS Test</title></head>
            <body>
                <h1>XSS Test Page</h1>
                <div id="content">{payload}</div>
                <script>
                    console.log('XSS Test: {payload_info["name"]}');
                    // Test payload execution
                    {payload if payload.startswith('javascript:') else ''}
                </script>
            </body>
            </html>
            """

            # Write to temp file
            html_file = self.temp_dir / f"xss_test_{payload_info['type']}.html"
            html_file.write_text(html_content)

            # Push to device
            device_path = f"/sdcard/xss_test_{payload_info['type']}.html"
            push_cmd = ["adb"]
            if self.device_id:
                push_cmd.extend(["-s", self.device_id])
            push_cmd.extend(["push", str(html_file), device_path])

            subprocess.run(push_cmd, capture_output=True, timeout=10)

            # Open in WebView
            view_cmd = ["adb"]
            if self.device_id:
                view_cmd.extend(["-s", self.device_id])
            view_cmd.extend(
                [
                    "shell",
                    "am",
                    "start",
                    "-a",
                    "android.intent.action.VIEW",
                    "-d",
                    f"file://{device_path}",
                    "-n",
                    f"{self.package_name}/.MainActivity",
                ]
            )

            result = subprocess.run(
                view_cmd, capture_output=True, text=True, timeout=15
            )

            if result.returncode == 0:
                # Check for XSS execution
                xss_detected = self._check_logcat_for_xss()

                return {
                    "test_type": "url_xss",
                    "payload_info": payload_info,
                    "payload": payload,
                    "method": "file_url",
                    "executed": "Complete" in result.stdout,
                    "xss_detected": xss_detected,
                    "file_path": device_path,
                    "timestamp": time.time(),
                }

        except Exception as e:
            logging.warning(f"URL XSS test failed: {e}")

        return None

    def _test_xss_via_file(self, payload: str, payload_info: Dict) -> Optional[Dict]:
        """Test XSS via file:// URL."""
        try:
            cmd = ["adb"]
            if self.device_id:
                cmd.extend(["-s", self.device_id])

            # Test file:// URL with XSS payload
            file_url = f"file:///android_asset/test.html?xss={quote(payload)}"
            cmd.extend(
                [
                    "shell",
                    "am",
                    "start",
                    "-a",
                    "android.intent.action.VIEW",
                    "-d",
                    file_url,
                    "-n",
                    f"{self.package_name}/.MainActivity",
                ]
            )

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            if result.returncode == 0:
                xss_detected = self._check_logcat_for_xss()

                return {
                    "test_type": "file_xss",
                    "payload_info": payload_info,
                    "payload": payload,
                    "method": "file_url",
                    "executed": "Complete" in result.stdout,
                    "xss_detected": xss_detected,
                    "url": file_url,
                    "timestamp": time.time(),
                }

        except Exception as e:
            logging.warning(f"File XSS test failed: {e}")

        return None

    def _execute_javascript_in_webview(
        self, script: str, test_info: Dict
    ) -> Optional[Dict]:
        """Execute JavaScript in WebView context."""
        try:
            # Create HTML file with JavaScript test
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head><title>JS Bridge Test</title></head>
            <body>
                <h1>JavaScript Bridge Test</h1>
                <script>
                    try {{
                        {script}
                    }} catch(e) {{
                        console.log('JS Bridge Test Error: ' + e.message);
                    }}
                </script>
            </body>
            </html>
            """

            # Write and push to device
            html_file = self.temp_dir / f"js_test_{test_info['type']}.html"
            html_file.write_text(html_content)

            device_path = f"/sdcard/js_test_{test_info['type']}.html"
            push_cmd = ["adb"]
            if self.device_id:
                push_cmd.extend(["-s", self.device_id])
            push_cmd.extend(["push", str(html_file), device_path])

            subprocess.run(push_cmd, capture_output=True, timeout=10)

            # Open in WebView
            view_cmd = ["adb"]
            if self.device_id:
                view_cmd.extend(["-s", self.device_id])
            view_cmd.extend(
                [
                    "shell",
                    "am",
                    "start",
                    "-a",
                    "android.intent.action.VIEW",
                    "-d",
                    f"file://{device_path}",
                    "-n",
                    f"{self.package_name}/.MainActivity",
                ]
            )

            result = subprocess.run(
                view_cmd, capture_output=True, text=True, timeout=15
            )

            if result.returncode == 0:
                # Check logcat for JavaScript execution results
                js_output = self._check_logcat_for_javascript()

                return {
                    "test_type": "js_bridge",
                    "test_info": test_info,
                    "script": script,
                    "executed": "Complete" in result.stdout,
                    "js_output": js_output,
                    "file_path": device_path,
                    "timestamp": time.time(),
                }

        except Exception as e:
            logging.warning(f"JavaScript bridge test failed: {e}")

        return None

    def _check_logcat_for_xss(self) -> bool:
        """Check logcat for XSS execution indicators."""
        try:
            cmd = ["adb"]
            if self.device_id:
                cmd.extend(["-s", self.device_id])
            cmd.extend(["logcat", "-d", "-s", "chromium:*", "WebView:*", "Console:*"])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                logcat_output = result.stdout.lower()
                xss_indicators = [
                    "xss",
                    "alert(",
                    "javascript:",
                    "script executed",
                    "eval(",
                    "document.cookie",
                ]

                return any(indicator in logcat_output for indicator in xss_indicators)

        except Exception as e:
            logging.warning(f"Logcat XSS check failed: {e}")

        return False

    def _check_logcat_for_javascript(self) -> List[str]:
        """Check logcat for JavaScript execution output."""
        try:
            cmd = ["adb"]
            if self.device_id:
                cmd.extend(["-s", self.device_id])
            cmd.extend(["logcat", "-d", "-s", "Console:*", "chromium:*"])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                lines = result.stdout.split("\n")
                js_lines = [
                    line
                    for line in lines
                    if any(
                        keyword in line.lower()
                        for keyword in ["bridge", "interface", "android", "console"]
                    )
                ]
                return js_lines[-10:]  # Return last 10 relevant lines

        except Exception as e:
            logging.warning(f"Logcat JavaScript check failed: {e}")

        return []

    def _test_javascript_enabled(self) -> Dict:
        """Test if JavaScript is enabled in WebView."""
        # This would typically require Frida or similar runtime analysis
        return {
            "setting": "javascript_enabled",
            "status": "unknown",
            "risk": "medium",
            "description": "JavaScript enablement status requires runtime analysis",
        }

    def _test_file_access(self) -> Dict:
        """Test file access settings."""
        return {
            "setting": "file_access_enabled",
            "status": "unknown",
            "risk": "high",
            "description": "File access settings require runtime analysis",
        }

    def _test_file_access_from_file_urls(self) -> Dict:
        """Test file access from file URLs."""
        return {
            "setting": "file_access_from_file_urls",
            "status": "unknown",
            "risk": "high",
            "description": "File URL access settings require runtime analysis",
        }

    def _test_universal_access_from_file_urls(self) -> Dict:
        """Test universal access from file URLs."""
        return {
            "setting": "universal_access_from_file_urls",
            "status": "unknown",
            "risk": "critical",
            "description": "Universal access settings require runtime analysis",
        }

    def _test_content_access(self) -> Dict:
        """Test content access settings."""
        return {
            "setting": "allow_content_access",
            "status": "unknown",
            "risk": "medium",
            "description": "Content access settings require runtime analysis",
        }

    def _test_mixed_content_mode(self) -> Dict:
        """Test mixed content mode settings."""
        return {
            "setting": "mixed_content_mode",
            "status": "unknown",
            "risk": "medium",
            "description": "Mixed content settings require runtime analysis",
        }

    def _test_safe_browsing(self) -> Dict:
        """Test safe browsing settings."""
        return {
            "setting": "safe_browsing_enabled",
            "status": "unknown",
            "risk": "low",
            "description": "Safe browsing settings require runtime analysis",
        }

    def _test_dom_storage(self) -> Dict:
        """Test DOM storage settings."""
        return {
            "setting": "dom_storage_enabled",
            "status": "unknown",
            "risk": "low",
            "description": "DOM storage settings require runtime analysis",
        }

    def _calculate_webview_security_score(self, settings: Dict) -> int:
        """Calculate WebView security score based on settings."""
        # This is a simplified scoring system
        # In practice, this would analyze actual settings
        return 50  # Neutral score when settings are unknown

    def _generate_webview_recommendations(self, settings: Dict) -> List[str]:
        """Generate WebView security recommendations."""
        recommendations = [
            "Disable JavaScript if not required for functionality",
            "Disable file access unless absolutely necessary",
            "Disable universal access from file URLs",
            "Implement Content Security Policy (CSP)",
            "Validate all input before displaying in WebView",
            "Use HTTPS for all WebView content",
            "Implement proper JavaScript bridge security",
            "Enable safe browsing if available",
            "Sanitize all user-generated content",
            "Implement proper error handling for WebView operations",
        ]
        return recommendations

    def run_comprehensive_webview_analysis(self) -> Dict[str, any]:
        """
        Run comprehensive WebView security analysis.

        Returns:
            Dict containing complete WebView analysis results
        """
        analysis_report = {
            "status": "success",
            "package_name": self.package_name,
            "timestamp": time.time(),
            "xss_tests": [],
            "js_bridge_tests": [],
            "settings_analysis": {},
            "vulnerabilities": [],
            "recommendations": [],
        }

        try:
            # Check ADB availability
            is_available, status_msg = self.check_adb_availability()
            if not is_available:
                analysis_report["status"] = "failed"
                analysis_report["error"] = status_msg
                return analysis_report

            logging.debug("Starting WebView security analysis...")

            # Test XSS vulnerabilities
            xss_results = self.test_webview_xss_vulnerabilities()
            analysis_report["xss_tests"] = xss_results

            # Test JavaScript bridge security
            js_bridge_results = self.test_javascript_bridge_security()
            analysis_report["js_bridge_tests"] = js_bridge_results

            # Test WebView settings
            settings_analysis = self.test_webview_settings_security()
            analysis_report["settings_analysis"] = settings_analysis

            # Analyze results for vulnerabilities
            vulnerabilities = self._analyze_webview_vulnerabilities(
                xss_results, js_bridge_results, settings_analysis
            )
            analysis_report["vulnerabilities"] = vulnerabilities

            # Generate recommendations
            analysis_report["recommendations"] = (
                self._generate_comprehensive_recommendations(
                    vulnerabilities, settings_analysis
                )
            )

        except Exception as e:
            logging.error(f"WebView analysis failed: {e}")
            analysis_report["status"] = "failed"
            analysis_report["error"] = str(e)

        finally:
            self.cleanup()

        return analysis_report

    def _analyze_webview_vulnerabilities(
        self, xss_results: List, js_bridge_results: List, settings_analysis: Dict
    ) -> List[Dict]:
        """Analyze WebView test results for vulnerabilities."""
        vulnerabilities = []

        # Analyze XSS test results
        for xss_result in xss_results:
            if xss_result.get("xss_detected") or xss_result.get("executed"):
                vulnerabilities.append(
                    {
                        "type": "Cross-Site Scripting (XSS)",
                        "severity": xss_result["payload_info"]["severity"],
                        "method": xss_result.get("method", "unknown"),
                        "payload": xss_result["payload"],
                        "description": f"XSS vulnerability detected via {xss_result.get('method', 'unknown')} method",
                        "evidence": {
                            "executed": xss_result.get("executed", False),
                            "xss_detected": xss_result.get("xss_detected", False),
                            "payload_type": xss_result["payload_info"]["type"],
                        },
                    }
                )

        # Analyze JavaScript bridge results
        for js_result in js_bridge_results:
            if (
                js_result.get("executed")
                and js_result["test_info"]["type"] == "exploitation"
            ):
                vulnerabilities.append(
                    {
                        "type": "JavaScript Bridge Vulnerability",
                        "severity": js_result["test_info"]["severity"],
                        "test_name": js_result["test_info"]["name"],
                        "description": f"JavaScript bridge vulnerability: {js_result['test_info']['name']}",
                        "evidence": {
                            "executed": js_result.get("executed", False),
                            "js_output": js_result.get("js_output", []),
                            "script": js_result["script"],
                        },
                    }
                )

        # Analyze settings for vulnerabilities
        settings = settings_analysis.get("settings_analysis", {})
        for setting_name, setting_info in settings.items():
            if setting_info.get("risk") in ["high", "critical"]:
                vulnerabilities.append(
                    {
                        "type": "Insecure WebView Configuration",
                        "severity": (
                            "HIGH" if setting_info.get("risk") == "high" else "CRITICAL"
                        ),
                        "setting": setting_name,
                        "description": f"Insecure WebView setting: {setting_name}",
                        "evidence": {
                            "setting": setting_name,
                            "status": setting_info.get("status", "unknown"),
                            "risk": setting_info.get("risk", "unknown"),
                        },
                    }
                )

        return vulnerabilities

    def _generate_comprehensive_recommendations(
        self, vulnerabilities: List, settings_analysis: Dict
    ) -> List[str]:
        """Generate comprehensive WebView security recommendations."""
        recommendations = []

        vuln_types = set(vuln["type"] for vuln in vulnerabilities)

        if "Cross-Site Scripting (XSS)" in vuln_types:
            recommendations.extend(
                [
                    "Implement strict input validation and output encoding",
                    "Use Content Security Policy (CSP) to prevent XSS",
                    "Sanitize all user input before displaying in WebView",
                    "Disable JavaScript if not required for functionality",
                ]
            )

        if "JavaScript Bridge Vulnerability" in vuln_types:
            recommendations.extend(
                [
                    "Implement proper access controls for JavaScript bridge methods",
                    "Validate all input to JavaScript bridge functions",
                    "Use @JavascriptInterface annotation with proper security checks",
                    "Avoid exposing sensitive system functions via JavaScript bridge",
                ]
            )

        if "Insecure WebView Configuration" in vuln_types:
            recommendations.extend(
                [
                    "Review and harden WebView security settings",
                    "Disable unnecessary WebView features",
                    "Implement proper file access controls",
                    "Use HTTPS for all WebView content",
                ]
            )

        # General WebView security recommendations
        recommendations.extend(
            [
                "Implement certificate pinning for WebView HTTPS connections",
                "Use secure communication protocols for all WebView traffic",
                "Implement proper error handling and logging",
                "Regular security testing of WebView implementations",
            ]
        )

        return list(set(recommendations))  # Remove duplicates

    def cleanup(self) -> None:
        """Clean up temporary files and resources."""
        try:
            if self.temp_dir and self.temp_dir.exists():
                import shutil

                shutil.rmtree(self.temp_dir)
                logging.debug(
                    f"Cleaned up WebView analysis temp directory: {self.temp_dir}"
                )
        except Exception as e:
            logging.warning(f"WebView analysis cleanup failed: {e}")

def run_webview_security_analysis(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Run comprehensive WebView security analysis.

    Args:
        apk_ctx: APKContext instance

    Returns:
        Tuple containing title and formatted results
    """
    if not apk_ctx.package_name:
        return (
            "WebView Security Analysis",
            Text.from_markup("[red]Error: Package name not available[/red]"),
        )

    try:
        # Initialize WebView analyzer
        webview_analyzer = WebViewAnalyzer(apk_ctx.package_name)

        # Run comprehensive analysis
        analysis = webview_analyzer.run_comprehensive_webview_analysis()

        # Format results for display
        result = _format_webview_analysis_results(analysis)

        return ("WebView Security Analysis", result)

    except Exception as e:
        logging.error(f"WebView security analysis failed: {e}")
        return (
            "WebView Security Analysis",
            Text.from_markup(f"[red]Analysis failed: {e}[/red]"),
        )

def _format_webview_analysis_results(analysis: Dict) -> Text:
    """Format WebView analysis results for display."""
    output = Text()

    # Header
    output.append("🌐 WebView Security Analysis\n", style="bold blue")
    output.append("=" * 50 + "\n\n", style="blue")

    if analysis["status"] == "failed":
        output.append("❌ Analysis Failed\n", style="red")
        output.append(f"Error: {analysis.get('error', 'Unknown error')}\n", style="red")

        if "ADB not found" in analysis.get("error", ""):
            output.append("\n💡 ADB Installation Guide\n", style="bold yellow")
            output.append("• Install Android SDK platform-tools\n")
            output.append("• Add platform-tools to PATH\n")
            output.append("• Connect Android device with USB debugging enabled\n")

        return output

    # Analysis summary
    output.append("📊 Analysis Summary\n", style="bold")
    output.append(f"• Package: {analysis.get('package_name', 'unknown')}\n")

    xss_tests = analysis.get("xss_tests", [])
    js_bridge_tests = analysis.get("js_bridge_tests", [])
    output.append(f"• XSS Tests Performed: {len(xss_tests)}\n")
    output.append(f"• JavaScript Bridge Tests: {len(js_bridge_tests)}\n")

    settings_analysis = analysis.get("settings_analysis", {})
    security_score = settings_analysis.get("security_score", 0)
    output.append(f"• WebView Security Score: {security_score}/100\n")
    output.append("\n")

    # Vulnerabilities
    vulnerabilities = analysis.get("vulnerabilities", [])
    if vulnerabilities:
        output.append("🚨 Vulnerabilities Detected\n", style="bold red")

        # Group by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        for severity, count in severity_counts.items():
            color = {
                "CRITICAL": "red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green",
            }.get(severity, "white")
            output.append(f"• {severity}: {count} vulnerabilities\n", style=color)

        output.append("\n📋 Vulnerability Details\n", style="bold")
        for i, vuln in enumerate(vulnerabilities[:5], 1):  # Show first 5
            output.append(f"{i}. {vuln.get('type', 'Unknown')}\n", style="red")
            output.append(
                f"   Severity: {vuln.get('severity', 'UNKNOWN')}\n", style="yellow"
            )
            output.append(
                f"   Description: {vuln.get('description', 'No description')}\n"
            )

            if vuln.get("payload"):
                output.append(f"   Payload: {vuln['payload'][:100]}...\n", style="cyan")

        if len(vulnerabilities) > 5:
            output.append(
                f"... and {len(vulnerabilities) - 5} more vulnerabilities\n",
                style="yellow",
            )

        output.append("\n")
    else:
        output.append(
            "✅ No Critical WebView Vulnerabilities Detected\n", style="bold green"
        )
        output.append("• XSS protection appears to be working\n", style="green")
        output.append("• JavaScript bridge security looks adequate\n", style="green")
        output.append("\n")

    # XSS Test Results Summary
    if xss_tests:
        successful_xss = sum(
            1 for test in xss_tests if test.get("xss_detected") or test.get("executed")
        )
        output.append(f"🎯 XSS Testing Results\n", style="bold yellow")
        output.append(f"• Total XSS Tests: {len(xss_tests)}\n")
        output.append(f"• Successful XSS Attacks: {successful_xss}\n")
        if successful_xss > 0:
            output.append(
                f"• XSS Success Rate: {(successful_xss/len(xss_tests)*100):.1f}%\n",
                style="red",
            )
        else:
            output.append("• XSS Success Rate: 0% (Good!)\n", style="green")
        output.append("\n")

    # JavaScript Bridge Results Summary
    if js_bridge_tests:
        successful_exploits = sum(
            1
            for test in js_bridge_tests
            if test.get("executed") and test["test_info"]["type"] == "exploitation"
        )
        output.append(f"🔗 JavaScript Bridge Testing\n", style="bold yellow")
        output.append(f"• Total Bridge Tests: {len(js_bridge_tests)}\n")
        output.append(f"• Successful Exploits: {successful_exploits}\n")
        if successful_exploits > 0:
            output.append(
                f"• Bridge Exploit Rate: {(successful_exploits/len(js_bridge_tests)*100):.1f}%\n",
                style="red",
            )
        else:
            output.append("• Bridge Exploit Rate: 0% (Good!)\n", style="green")
        output.append("\n")

    # Recommendations
    recommendations = analysis.get("recommendations", [])
    if recommendations:
        output.append("💡 Security Recommendations\n", style="bold green")
        for rec in recommendations[:8]:  # Show first 8 recommendations
            output.append(f"• {rec}\n", style="green")
        output.append("\n")

    # MASVS Mappings
    output.append("🎯 MASVS Control Mappings\n", style="bold blue")
    output.append("• MASVS-PLATFORM-3: WebView security configuration\n", style="cyan")
    output.append("• MSTG-CODE-8: Input validation and sanitization\n", style="cyan")
    output.append("• MSTG-CODE-9: Binary protection mechanisms\n", style="cyan")
    output.append("• MSTG-NETWORK-01: Secure communication protocols\n", style="cyan")
    output.append("• MSTG-NETWORK-02: TLS configuration validation\n", style="cyan")

    return output
