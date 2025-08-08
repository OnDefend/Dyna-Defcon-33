"""
Intent Fuzzing Framework for Android Security Testing.

This module provides comprehensive intent fuzzing capabilities for Android applications,
including intent injection, URI manipulation, deep link testing, and insecure intent
handling detection as required by MASVS standards.
"""

import json
import logging
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, urlparse

from rich.text import Text

class IntentFuzzer:
    """
    Intent fuzzing manager for Android security testing.

    This class provides comprehensive intent fuzzing including:
    - Intent injection and manipulation
    - Deep link and URI scheme testing
    - Component exposure analysis
    - Intent filter bypass testing
    - Insecure intent handling detection

    Attributes:
        package_name (str): Android package name
        device_id (Optional[str]): Android device ID
        temp_dir (Path): Temporary directory for analysis files
        fuzzing_results (Dict): Collection of fuzzing results
    """

    def __init__(
        self, package_name: str, device_id: Optional[str] = None, apk_ctx=None
    ):
        """
        Initialize Intent fuzzer.

        Args:
            package_name: Android package name
            device_id: Optional Android device ID (uses default device if None)
            apk_ctx: APK analysis context for accessing manifest and analyzer
        """
        self.package_name = package_name
        self.device_id = device_id
        self.apk_ctx = apk_ctx  # Store APK context for component discovery
        self.temp_dir = Path(tempfile.mkdtemp(prefix="intent_fuzzing_"))
        self.fuzzing_results: Dict[str, any] = {}
        self.exported_components: Dict[str, List[str]] = {}

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

    def extract_exported_components(
        self, manifest_data: Optional[Dict] = None
    ) -> Dict[str, List[str]]:
        """
        Extract exported components from the application using AndroidManifest.xml.

        Args:
            manifest_data: Optional pre-parsed manifest data

        Returns:
            Dict containing exported components by type with real component names
        """
        try:
            components = {
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": [],
            }

            # First try to parse AndroidManifest.xml directly if available
            if hasattr(self, "apk_ctx") and self.apk_ctx:
                try:
                    manifest_path = self.apk_ctx.manifest_path
                    if manifest_path.exists():
                        components = self._parse_manifest_for_components(manifest_path)
                        if components and any(components.values()):
                            self.exported_components = components
                            return components
                except Exception as e:
                    logging.debug(f"Direct manifest parsing failed: {e}")

            # Fallback to APKAnalyzer if available
            if hasattr(self, "apk_ctx") and self.apk_ctx and self.apk_ctx.analyzer:
                try:
                    exported_components = (
                        self.apk_ctx.analyzer.get_exported_components()
                    )
                    if exported_components and any(exported_components.values()):
                        self.exported_components = exported_components
                        return exported_components
                except Exception as e:
                    logging.debug(f"APKAnalyzer component extraction failed: {e}")

            # Original fallback to dumpsys for runtime detection
            if not manifest_data:
                # Use dumpsys to get component information
                cmd = ["adb"]
                if self.device_id:
                    cmd.extend(["-s", self.device_id])
                cmd.extend(["shell", "dumpsys", "package", self.package_name])

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                if result.returncode != 0:
                    logging.warning(
                        f"Failed to get package info for {self.package_name}"
                    )
                    return components  # Return empty but structured dict

                # Parse dumpsys output for exported components
                output = result.stdout
                components = self._parse_dumpsys_output(output)

            else:
                # Use provided manifest data
                components = self._parse_manifest_data(manifest_data)

            self.exported_components = components
            return components

        except Exception as e:
            logging.error(f"Component extraction failed: {e}")
            return {
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": [],
            }

    def _parse_manifest_for_components(self, manifest_path) -> Dict[str, List[str]]:
        """Parse AndroidManifest.xml directly for component information."""
        components = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }

        try:
            # Use safe XML parsing to handle binary AndroidManifest.xml
            from core.encoding_utils import safe_read_file, safe_parse_xml
            
            # Read the manifest file safely
            manifest_content = safe_read_file(str(manifest_path))
            if not manifest_content:
                logging.warning(f"Could not read manifest file: {manifest_path}")
                return components
            
            # Parse XML safely with timeout protection
            root = safe_parse_xml(manifest_content, str(manifest_path), timeout=10)
            if root is None:
                logging.warning(f"Could not parse manifest XML: {manifest_path}")
                return components

            # Find all exported activities
            for activity in root.findall(".//activity"):
                exported_attr = activity.get(
                    "{http://schemas.android.com/apk/res/android}exported"
                )
                name = activity.get("{http://schemas.android.com/apk/res/android}name")

                # Check if exported explicitly or has intent-filter (implicitly exported)
                if (
                    exported_attr == "true"
                    or activity.find("intent-filter") is not None
                ) and name:
                    # Convert relative names to full names
                    if name.startswith("."):
                        name = self.package_name + name
                    elif not name.startswith(self.package_name) and "." not in name:
                        name = f"{self.package_name}.{name}"

                    components["activities"].append(
                        {
                            "name": name,
                            "intent_filters": self._extract_intent_filters(activity),
                            "permissions": self._extract_permissions(activity),
                            "exported": exported_attr == "true"
                            or activity.find("intent-filter") is not None,
                        }
                    )

            # Find all exported services
            for service in root.findall(".//service"):
                exported_attr = service.get(
                    "{http://schemas.android.com/apk/res/android}exported"
                )
                name = service.get("{http://schemas.android.com/apk/res/android}name")

                if (
                    exported_attr == "true" or service.find("intent-filter") is not None
                ) and name:
                    if name.startswith("."):
                        name = self.package_name + name
                    elif not name.startswith(self.package_name) and "." not in name:
                        name = f"{self.package_name}.{name}"

                    components["services"].append(
                        {
                            "name": name,
                            "intent_filters": self._extract_intent_filters(service),
                            "permissions": self._extract_permissions(service),
                            "exported": exported_attr == "true"
                            or service.find("intent-filter") is not None,
                        }
                    )

            # Find all exported receivers
            for receiver in root.findall(".//receiver"):
                exported_attr = receiver.get(
                    "{http://schemas.android.com/apk/res/android}exported"
                )
                name = receiver.get("{http://schemas.android.com/apk/res/android}name")

                if (
                    exported_attr == "true"
                    or receiver.find("intent-filter") is not None
                ) and name:
                    if name.startswith("."):
                        name = self.package_name + name
                    elif not name.startswith(self.package_name) and "." not in name:
                        name = f"{self.package_name}.{name}"

                    components["receivers"].append(
                        {
                            "name": name,
                            "intent_filters": self._extract_intent_filters(receiver),
                            "permissions": self._extract_permissions(receiver),
                            "exported": exported_attr == "true"
                            or receiver.find("intent-filter") is not None,
                        }
                    )

            # Find all exported providers
            for provider in root.findall(".//provider"):
                exported_attr = provider.get(
                    "{http://schemas.android.com/apk/res/android}exported"
                )
                name = provider.get("{http://schemas.android.com/apk/res/android}name")

                if exported_attr == "true" and name:
                    if name.startswith("."):
                        name = self.package_name + name
                    elif not name.startswith(self.package_name) and "." not in name:
                        name = f"{self.package_name}.{name}"

                    components["providers"].append(
                        {
                            "name": name,
                            "authorities": provider.get(
                                "{http://schemas.android.com/apk/res/android}authorities",
                                "",
                            ),
                            "permissions": self._extract_permissions(provider),
                            "exported": True,
                        }
                    )

            logging.info(
                f"Extracted {sum(len(comp_list) for comp_list in components.values())} exported components from manifest"
            )
            return components

        except Exception as e:
            logging.error(f"Manifest parsing failed: {e}")
            return components

    def _extract_intent_filters(self, component) -> List[Dict]:
        """Extract intent filter information from a component."""
        filters = []

        for intent_filter in component.findall("intent-filter"):
            filter_info = {"actions": [], "categories": [], "data": []}

            # Extract actions
            for action in intent_filter.findall("action"):
                action_name = action.get(
                    "{http://schemas.android.com/apk/res/android}name"
                )
                if action_name:
                    filter_info["actions"].append(action_name)

            # Extract categories
            for category in intent_filter.findall("category"):
                category_name = category.get(
                    "{http://schemas.android.com/apk/res/android}name"
                )
                if category_name:
                    filter_info["categories"].append(category_name)

            # Extract data specifications
            for data in intent_filter.findall("data"):
                data_info = {}
                for attr in [
                    "scheme",
                    "host",
                    "port",
                    "path",
                    "pathPattern",
                    "pathPrefix",
                    "mimeType",
                ]:
                    value = data.get(
                        f"{{http://schemas.android.com/apk/res/android}}{attr}"
                    )
                    if value:
                        data_info[attr] = value
                if data_info:
                    filter_info["data"].append(data_info)

            filters.append(filter_info)

        return filters

    def _extract_permissions(self, component) -> List[str]:
        """Extract permission requirements from a component."""
        permissions = []

        permission = component.get(
            "{http://schemas.android.com/apk/res/android}permission"
        )
        if permission:
            permissions.append(permission)

        readPermission = component.get(
            "{http://schemas.android.com/apk/res/android}readPermission"
        )
        if readPermission:
            permissions.append(readPermission)

        writePermission = component.get(
            "{http://schemas.android.com/apk/res/android}writePermission"
        )
        if writePermission:
            permissions.append(writePermission)

        return permissions

    def _parse_dumpsys_output(self, output: str) -> Dict[str, List[str]]:
        """Parse dumpsys output for component information (fallback method)."""
        components = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }

        # Extract activities
        if "Activity Resolver Table:" in output:
            activity_section = output.split("Activity Resolver Table:")[1].split(
                "Service Resolver Table:"
            )[0]
            for line in activity_section.split("\n"):
                if self.package_name in line and "/" in line:
                    component = line.strip().split()[-1]
                    if component.startswith(self.package_name):
                        components["activities"].append(
                            {
                                "name": component,
                                "intent_filters": [],
                                "permissions": [],
                                "exported": True,
                            }
                        )

        # Extract services
        if "Service Resolver Table:" in output:
            service_section = output.split("Service Resolver Table:")[1].split(
                "Receiver Resolver Table:"
            )[0]
            for line in service_section.split("\n"):
                if self.package_name in line and "/" in line:
                    component = line.strip().split()[-1]
                    if component.startswith(self.package_name):
                        components["services"].append(
                            {
                                "name": component,
                                "intent_filters": [],
                                "permissions": [],
                                "exported": True,
                            }
                        )

        # Extract receivers
        if "Receiver Resolver Table:" in output:
            receiver_section = output.split("Receiver Resolver Table:")[1].split(
                "ContentProvider Resolver Table:"
            )[0]
            for line in receiver_section.split("\n"):
                if self.package_name in line and "/" in line:
                    component = line.strip().split()[-1]
                    if component.startswith(self.package_name):
                        components["receivers"].append(
                            {
                                "name": component,
                                "intent_filters": [],
                                "permissions": [],
                                "exported": True,
                            }
                        )

        return components

    def _parse_manifest_data(self, manifest_data: Dict) -> Dict[str, List[str]]:
        """Parse provided manifest data structure (legacy support)."""
        components = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }

        # Extract from manifest data if available
        if "application" in manifest_data:
            app_data = manifest_data["application"]

            # Activities
            for activity in app_data.get("activity", []):
                if activity.get("exported", False):
                    components["activities"].append(
                        {
                            "name": activity.get("name", ""),
                            "intent_filters": [],
                            "permissions": [],
                            "exported": True,
                        }
                    )

            # Services
            for service in app_data.get("service", []):
                if service.get("exported", False):
                    components["services"].append(
                        {
                            "name": service.get("name", ""),
                            "intent_filters": [],
                            "permissions": [],
                            "exported": True,
                        }
                    )

            # Receivers
            for receiver in app_data.get("receiver", []):
                if receiver.get("exported", False):
                    components["receivers"].append(
                        {
                            "name": receiver.get("name", ""),
                            "intent_filters": [],
                            "permissions": [],
                            "exported": True,
                        }
                    )

            # Providers
            for provider in app_data.get("provider", []):
                if provider.get("exported", False):
                    components["providers"].append(
                        {
                            "name": provider.get("name", ""),
                            "authorities": provider.get("authorities", ""),
                            "permissions": [],
                            "exported": True,
                        }
                    )

        return components

    def fuzz_activity_intents(self) -> List[Dict]:
        """
        Fuzz exported activities with various intent payloads with timeout protection.

        Returns:
            List of fuzzing results
        """
        import time
        
        results = []
        activities = self.exported_components.get("activities", [])

        if not activities:
            logging.warning("No exported activities found for fuzzing")
            return results
        
        start_time = time.time()
        max_fuzzing_time = 15  # 15 seconds max for activity fuzzing
        max_activities = 10  # Limit number of activities to prevent hanging

        # Intent fuzzing payloads
        fuzzing_payloads = [
            # Basic intent fuzzing
            {"action": "android.intent.action.VIEW"},
            {"action": "android.intent.action.EDIT"},
            {"action": "android.intent.action.SEND"},
            # Data URI fuzzing
            {"action": "android.intent.action.VIEW", "data": "file:///etc/passwd"},
            {
                "action": "android.intent.action.VIEW",
                "data": "content://settings/secure",
            },
            {"action": "android.intent.action.VIEW", "data": "javascript:alert('XSS')"},
            {
                "action": "android.intent.action.VIEW",
                "data": "data:text/html,<script>alert('XSS')</script>",
            },
            # Extra data fuzzing
            {
                "action": "android.intent.action.SEND",
                "extras": {"android.intent.extra.TEXT": "../../../etc/passwd"},
            },
            {
                "action": "android.intent.action.SEND",
                "extras": {
                    "android.intent.extra.TEXT": "<script>alert('XSS')</script>"
                },
            },
            {
                "action": "android.intent.action.SEND",
                "extras": {"android.intent.extra.TEXT": "' OR 1=1 --"},
            },
            # Deep link fuzzing
            {
                "action": "android.intent.action.VIEW",
                "data": f"{self.package_name}://admin/delete?id=../../../sensitive",
            },
            {
                "action": "android.intent.action.VIEW",
                "data": f"{self.package_name}://user/profile?id=<script>alert('XSS')</script>",
            },
            # Component fuzzing
            {"action": "android.intent.action.MAIN"},
            {"action": "android.intent.action.CREATE_SHORTCUT"},
        ]

        # Limit activities to prevent hanging
        limited_activities = activities[:max_activities] if len(activities) > max_activities else activities
        
        for i, activity in enumerate(limited_activities):
            # Check timeout
            if time.time() - start_time > max_fuzzing_time:
                logging.warning(f"Activity fuzzing timed out after {max_fuzzing_time}s, processed {i}/{len(limited_activities)} activities")
                break
                
            logging.info(f"Fuzzing activity: {activity}")

            # Limit payloads per activity
            limited_payloads = fuzzing_payloads[:3]  # Only test first 3 payloads per activity
            
            for payload in limited_payloads:
                # Check timeout for each payload
                if time.time() - start_time > max_fuzzing_time:
                    break
                    
                try:
                    result = self._send_intent_to_activity(activity, payload)
                    if result:
                        results.append(
                            {
                                "component": activity,
                                "component_type": "activity",
                                "payload": payload,
                                "result": result,
                                "timestamp": time.time(),
                            }
                        )

                except Exception as e:
                    logging.warning(
                        f"Failed to fuzz activity {activity} with payload {payload}: {e}"
                    )
                    results.append(
                        {
                            "component": activity,
                            "component_type": "activity",
                            "payload": payload,
                            "result": {"error": str(e)},
                            "timestamp": time.time(),
                        }
                    )

        return results

    def fuzz_service_intents(self) -> List[Dict]:
        """
        Fuzz exported services with various intent payloads with timeout protection.

        Returns:
            List of fuzzing results
        """
        import time
        
        results = []
        services = self.exported_components.get("services", [])

        if not services:
            logging.warning("No exported services found for fuzzing")
            return results
        
        start_time = time.time()
        max_fuzzing_time = 10  # 10 seconds max for service fuzzing
        max_services = 8  # Limit number of services

        # Service-specific fuzzing payloads
        service_payloads = [
            {"action": "android.intent.action.BOOT_COMPLETED"},
            {"action": "android.intent.action.USER_PRESENT"},
            {"action": "android.intent.action.SCREEN_ON"},
            {"action": "android.intent.action.SCREEN_OFF"},
            {"action": "custom.action.ADMIN"},
            {"action": "custom.action.DEBUG"},
            {"extras": {"command": "rm -rf /"}},
            {"extras": {"sql": "DROP TABLE users;"}},
            {"extras": {"path": "../../../etc/passwd"}},
        ]

        # Limit services to prevent hanging
        limited_services = services[:max_services] if len(services) > max_services else services
        
        for i, service in enumerate(limited_services):
            # Check timeout
            if time.time() - start_time > max_fuzzing_time:
                logging.warning(f"Service fuzzing timed out after {max_fuzzing_time}s, processed {i}/{len(limited_services)} services")
                break
                
            logging.info(f"Fuzzing service: {service}")

            # Limit payloads per service
            limited_payloads = service_payloads[:2]  # Only test first 2 payloads per service
            
            for payload in limited_payloads:
                # Check timeout for each payload
                if time.time() - start_time > max_fuzzing_time:
                    break
                    
                try:
                    result = self._send_intent_to_service(service, payload)
                    if result:
                        results.append(
                            {
                                "component": service,
                                "component_type": "service",
                                "payload": payload,
                                "result": result,
                                "timestamp": time.time(),
                            }
                        )

                except Exception as e:
                    logging.warning(
                        f"Failed to fuzz service {service} with payload {payload}: {e}"
                    )
                    results.append(
                        {
                            "component": service,
                            "component_type": "service",
                            "payload": payload,
                            "result": {"error": str(e)},
                            "timestamp": time.time(),
                        }
                    )

        return results

    def fuzz_broadcast_receivers(self) -> List[Dict]:
        """
        Fuzz exported broadcast receivers with various intent payloads with timeout protection.

        Returns:
            List of fuzzing results
        """
        import time
        
        results = []
        receivers = self.exported_components.get("receivers", [])

        if not receivers:
            logging.warning("No exported receivers found for fuzzing")
            return results
        
        start_time = time.time()
        max_fuzzing_time = 10  # 10 seconds max for receiver fuzzing
        max_receivers = 8  # Limit number of receivers

        # Broadcast-specific fuzzing payloads
        broadcast_payloads = [
            {"action": "android.intent.action.BOOT_COMPLETED"},
            {"action": "android.intent.action.PACKAGE_ADDED"},
            {"action": "android.intent.action.PACKAGE_REMOVED"},
            {"action": "android.intent.action.USER_PRESENT"},
            {"action": "android.net.conn.CONNECTIVITY_CHANGE"},
            {"action": "android.intent.action.SMS_RECEIVED"},
            {"action": "custom.broadcast.ADMIN"},
            {"action": "custom.broadcast.DEBUG"},
            {"extras": {"malicious_data": "../../sensitive_file"}},
            {"extras": {"injection": "<script>alert('XSS')</script>"}},
        ]

        # Limit receivers to prevent hanging
        limited_receivers = receivers[:max_receivers] if len(receivers) > max_receivers else receivers
        
        for i, receiver in enumerate(limited_receivers):
            # Check timeout
            if time.time() - start_time > max_fuzzing_time:
                logging.warning(f"Receiver fuzzing timed out after {max_fuzzing_time}s, processed {i}/{len(limited_receivers)} receivers")
                break
                
            logging.info(f"Fuzzing receiver: {receiver}")

            # Limit payloads per receiver
            limited_payloads = broadcast_payloads[:2]  # Only test first 2 payloads per receiver
            
            for payload in limited_payloads:
                # Check timeout for each payload
                if time.time() - start_time > max_fuzzing_time:
                    break
                    
                try:
                    result = self._send_broadcast_intent(receiver, payload)
                    if result:
                        results.append(
                            {
                                "component": receiver,
                                "component_type": "receiver",
                                "payload": payload,
                                "result": result,
                                "timestamp": time.time(),
                            }
                        )

                except Exception as e:
                    logging.warning(
                        f"Failed to fuzz receiver {receiver} with payload {payload}: {e}"
                    )
                    results.append(
                        {
                            "component": receiver,
                            "component_type": "receiver",
                            "payload": payload,
                            "result": {"error": str(e)},
                            "timestamp": time.time(),
                        }
                    )

        return results

    def test_deep_links(self) -> List[Dict]:
        """
        Test deep link handling and URI scheme vulnerabilities.

        Returns:
            List of deep link test results
        """
        results = []

        # Common deep link schemes to test
        schemes = [
            f"{self.package_name}",
            "http",
            "https",
            "file",
            "content",
            "android-app",
            "market",
            "intent",
        ]

        # Deep link fuzzing payloads
        deep_link_payloads = [
            # Path traversal
            "://admin/../../../etc/passwd",
            "://user/profile/../../admin/delete",
            "://data/../config/sensitive.xml",
            # XSS attempts
            "://search?q=<script>alert('XSS')</script>",
            "://user?name=<img src=x onerror=alert('XSS')>",
            "://redirect?url=javascript:alert('XSS')",
            # SQL injection
            "://user?id=1' OR 1=1 --",
            "://search?q='; DROP TABLE users; --",
            "://login?user=admin'/**/OR/**/1=1#",
            # Command injection
            "://exec?cmd=rm -rf /",
            "://run?command=cat /etc/passwd",
            "://shell?exec=id; whoami",
            # Protocol confusion
            "://redirect?url=file:///etc/passwd",
            "://open?uri=content://settings/secure",
            "://load?src=android-app://com.malicious.app",
        ]

        for scheme in schemes:
            for payload in deep_link_payloads:
                uri = scheme + payload

                try:
                    result = self._test_deep_link(uri)
                    results.append(
                        {
                            "uri": uri,
                            "scheme": scheme,
                            "payload": payload,
                            "result": result,
                            "timestamp": time.time(),
                        }
                    )

                except Exception as e:
                    logging.warning(f"Failed to test deep link {uri}: {e}")
                    results.append(
                        {
                            "uri": uri,
                            "scheme": scheme,
                            "payload": payload,
                            "result": {"error": str(e)},
                            "timestamp": time.time(),
                        }
                    )

        return results

    def _send_intent_to_activity(self, activity: str, payload: Dict) -> Optional[Dict]:
        """Send intent to activity and capture result."""
        cmd = ["adb"]
        if self.device_id:
            cmd.extend(["-s", self.device_id])

        cmd.extend(["shell", "am", "start"])

        # Add intent parameters
        if "action" in payload:
            cmd.extend(["-a", payload["action"]])

        if "data" in payload:
            cmd.extend(["-d", payload["data"]])

        if "extras" in payload:
            for key, value in payload["extras"].items():
                cmd.extend(["--es", key, str(value)])

        cmd.extend(["-n", activity])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": " ".join(cmd),
            }

        except subprocess.TimeoutExpired:
            return {"error": "Command timed out"}
        except Exception as e:
            return {"error": str(e)}

    def _send_intent_to_service(self, service: str, payload: Dict) -> Optional[Dict]:
        """Send intent to service and capture result."""
        cmd = ["adb"]
        if self.device_id:
            cmd.extend(["-s", self.device_id])

        cmd.extend(["shell", "am", "startservice"])

        # Add intent parameters
        if "action" in payload:
            cmd.extend(["-a", payload["action"]])

        if "extras" in payload:
            for key, value in payload["extras"].items():
                cmd.extend(["--es", key, str(value)])

        cmd.extend(["-n", service])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": " ".join(cmd),
            }

        except subprocess.TimeoutExpired:
            return {"error": "Command timed out"}
        except Exception as e:
            return {"error": str(e)}

    def _send_broadcast_intent(self, receiver: str, payload: Dict) -> Optional[Dict]:
        """Send broadcast intent to receiver and capture result."""
        cmd = ["adb"]
        if self.device_id:
            cmd.extend(["-s", self.device_id])

        cmd.extend(["shell", "am", "broadcast"])

        # Add intent parameters
        if "action" in payload:
            cmd.extend(["-a", payload["action"]])

        if "extras" in payload:
            for key, value in payload["extras"].items():
                cmd.extend(["--es", key, str(value)])

        cmd.extend(["-n", receiver])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": " ".join(cmd),
            }

        except subprocess.TimeoutExpired:
            return {"error": "Command timed out"}
        except Exception as e:
            return {"error": str(e)}

    def _test_deep_link(self, uri: str) -> Dict:
        """Test deep link URI and capture result."""
        cmd = ["adb"]
        if self.device_id:
            cmd.extend(["-s", self.device_id])

        cmd.extend(
            [
                "shell",
                "am",
                "start",
                "-W",
                "-a",
                "android.intent.action.VIEW",
                "-d",
                uri,
            ]
        )

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": " ".join(cmd),
                "handled": "Complete" in result.stdout,
            }

        except subprocess.TimeoutExpired:
            return {"error": "Command timed out"}
        except Exception as e:
            return {"error": str(e)}

    def run_comprehensive_fuzzing(self) -> Dict[str, any]:
        """
        Run comprehensive intent fuzzing analysis with timeout protection.

        Returns:
            Dict containing fuzzing results and analysis
        """
        import time
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
        
        analysis_report = {
            "status": "success",
            "package_name": self.package_name,
            "timestamp": time.time(),
            "exported_components": {},
            "fuzzing_results": {},
            "vulnerabilities": [],
            "recommendations": [],
        }

        start_time = time.time()
        max_analysis_time = 90  # OPTIMIZATION: Increased from 45s to 90s for better coverage (aligns with plugin manager timeout)

        try:
            # Check ADB availability with timeout
            is_available, status_msg = self.check_adb_availability()
            if not is_available:
                analysis_report["status"] = "failed"
                analysis_report["error"] = status_msg
                return analysis_report

            # Extract exported components with timeout
            if time.time() - start_time > max_analysis_time:
                analysis_report["status"] = "timeout"
                analysis_report["error"] = "Component extraction timed out"
                return analysis_report

            components = self.extract_exported_components()
            analysis_report["exported_components"] = components

            if not any(components.values()):
                analysis_report["status"] = "warning"
                analysis_report["message"] = "No exported components found for fuzzing"
                return analysis_report

            # Run fuzzing tests with timeout protection
            logging.info("Starting intent fuzzing analysis with timeout protection...")

            def run_fuzzing_with_timeout():
                results = {}
                
                # Limit fuzzing to prevent hanging
                if time.time() - start_time < max_analysis_time * 0.3:  # 30% of time for activities
                    activity_results = self.fuzz_activity_intents()
                    results["activities"] = activity_results
                else:
                    results["activities"] = []
                    logging.warning("Skipping activity fuzzing due to time constraints")

                if time.time() - start_time < max_analysis_time * 0.6:  # 60% of time for services
                    service_results = self.fuzz_service_intents()
                    results["services"] = service_results
                else:
                    results["services"] = []
                    logging.warning("Skipping service fuzzing due to time constraints")

                if time.time() - start_time < max_analysis_time * 0.8:  # 80% of time for receivers
                    receiver_results = self.fuzz_broadcast_receivers()
                    results["receivers"] = receiver_results
                else:
                    results["receivers"] = []
                    logging.warning("Skipping receiver fuzzing due to time constraints")

                if time.time() - start_time < max_analysis_time * 0.9:  # 90% of time for deep links
                    deep_link_results = self.test_deep_links()
                    results["deep_links"] = deep_link_results
                else:
                    results["deep_links"] = []
                    logging.warning("Skipping deep link testing due to time constraints")
                
                return results

            # Execute fuzzing with timeout
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(run_fuzzing_with_timeout)
                try:
                    remaining_time = max_analysis_time - (time.time() - start_time)
                    if remaining_time <= 0:
                        analysis_report["status"] = "timeout"
                        analysis_report["error"] = "Analysis timed out before fuzzing could start"
                        return analysis_report
                    
                    fuzzing_results = future.result(timeout=remaining_time)
                    analysis_report["fuzzing_results"] = fuzzing_results
                    
                except FutureTimeoutError:
                    future.cancel()
                    analysis_report["status"] = "timeout"
                    analysis_report["error"] = f"Intent fuzzing timed out after {max_analysis_time}s"
                    analysis_report["fuzzing_results"] = {"activities": [], "services": [], "receivers": [], "deep_links": []}
                    logging.warning(f"Intent fuzzing timed out after {max_analysis_time}s")

            # Quick analysis of results for vulnerabilities
            if analysis_report["fuzzing_results"]:
                vulnerabilities = self._analyze_fuzzing_results(
                    analysis_report["fuzzing_results"]
                )
                analysis_report["vulnerabilities"] = vulnerabilities

                # Generate recommendations
                analysis_report["recommendations"] = self._generate_fuzzing_recommendations(
                    vulnerabilities
                )

        except Exception as e:
            logging.error(f"Intent fuzzing analysis failed: {e}")
            analysis_report["status"] = "failed"
            analysis_report["error"] = str(e)

        finally:
            self.cleanup()
            elapsed_time = time.time() - start_time
            logging.info(f"Intent fuzzing analysis completed in {elapsed_time:.2f}s")

        return analysis_report

    def _analyze_fuzzing_results(self, results: Dict) -> List[Dict]:
        """Analyze fuzzing results for potential vulnerabilities."""
        vulnerabilities = []

        # Analyze all fuzzing results
        for category, category_results in results.items():
            for result in category_results:
                if "result" in result and isinstance(result["result"], dict):
                    result_data = result["result"]

                    # Check for successful exploitation indicators
                    if result_data.get("returncode") == 0:
                        stdout = result_data.get("stdout", "")
                        stderr = result_data.get("stderr", "")

                        # Look for vulnerability indicators
                        vuln_indicators = [
                            ("Path Traversal", ["etc/passwd", "../../", "../"]),
                            ("XSS", ["<script>", "javascript:", "alert("]),
                            ("SQL Injection", ["DROP TABLE", "OR 1=1", "' OR"]),
                            ("Command Injection", ["rm -rf", "cat /etc", "whoami"]),
                            ("Insecure Deep Link", ["file://", "content://settings"]),
                        ]

                        for vuln_type, indicators in vuln_indicators:
                            for indicator in indicators:
                                if indicator in str(
                                    result.get("payload", "")
                                ).lower() and (
                                    "Complete" in stdout or "Starting" in stdout
                                ):

                                    # Get actual component name from exported components
                                    component_name = (
                                        self._get_component_name_from_result(result)
                                    )
                                    component_type = result.get(
                                        "component_type", "unknown"
                                    )

                                    vulnerabilities.append(
                                        {
                                            "type": vuln_type,
                                            "severity": self._assess_vulnerability_severity(
                                                vuln_type
                                            ),
                                            "component": component_name,
                                            "component_type": component_type,
                                            "payload": result.get("payload", {}),
                                            "evidence": {
                                                "stdout": stdout,
                                                "stderr": stderr,
                                                "returncode": result_data.get(
                                                    "returncode"
                                                ),
                                            },
                                            "description": f"{vuln_type} vulnerability detected in {component_name}",
                                        }
                                    )

        return vulnerabilities

    def _assess_vulnerability_severity(self, vuln_type: str) -> str:
        """Assess vulnerability severity based on type."""
        severity_map = {
            "Path Traversal": "HIGH",
            "XSS": "MEDIUM",
            "SQL Injection": "HIGH",
            "Command Injection": "CRITICAL",
            "Insecure Deep Link": "MEDIUM",
        }
        return severity_map.get(vuln_type, "LOW")

    def _generate_fuzzing_recommendations(
        self, vulnerabilities: List[Dict]
    ) -> List[str]:
        """Generate security recommendations based on fuzzing results."""
        recommendations = []

        vuln_types = set(vuln["type"] for vuln in vulnerabilities)

        if "Path Traversal" in vuln_types:
            recommendations.append(
                "Implement proper input validation and sanitization for file paths"
            )
            recommendations.append(
                "Use canonical path validation to prevent directory traversal"
            )

        if "XSS" in vuln_types:
            recommendations.append(
                "Sanitize and validate all user input in WebViews and UI components"
            )
            recommendations.append(
                "Implement Content Security Policy (CSP) for WebViews"
            )

        if "SQL Injection" in vuln_types:
            recommendations.append("Use parameterized queries and prepared statements")
            recommendations.append(
                "Implement proper input validation for database operations"
            )

        if "Command Injection" in vuln_types:
            recommendations.append("Avoid executing system commands with user input")
            recommendations.append("Use safe APIs instead of shell command execution")

        if "Insecure Deep Link" in vuln_types:
            recommendations.append(
                "Implement proper deep link validation and authorization"
            )
            recommendations.append("Use intent filters with specific schemes and hosts")

        # General recommendations
        recommendations.extend(
            [
                "Set android:exported='false' for components that don't need external access",
                "Implement proper intent validation in all exported components",
                "Use permission-based access control for sensitive components",
                "Implement runtime security checks for intent handling",
            ]
        )

        return recommendations

    def cleanup(self) -> None:
        """Clean up temporary files and resources."""
        try:
            if self.temp_dir and self.temp_dir.exists():
                import shutil

                shutil.rmtree(self.temp_dir)
                logging.info(
                    f"Cleaned up intent fuzzing temp directory: {self.temp_dir}"
                )
        except Exception as e:
            logging.warning(f"Intent fuzzing cleanup failed: {e}")

    def _get_component_name_from_result(self, result: Dict) -> str:
        """Get actual component name from fuzzing result."""
        if "component" in result:
            return result["component"]
        elif "name" in result:
            return result["name"]
        else:
            return "unknown"

def run_intent_fuzzing_analysis(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Run comprehensive intent fuzzing analysis.

    Args:
        apk_ctx: APKContext instance

    Returns:
        Tuple containing title and formatted results
    """
    if not apk_ctx.package_name:
        return (
            "Intent Fuzzing Analysis",
            Text.from_markup("[red]Error: Package name not available[/red]"),
        )

    try:
        # Initialize intent fuzzer with APK context for real component discovery
        intent_fuzzer = IntentFuzzer(apk_ctx.package_name, apk_ctx=apk_ctx)

        # Run comprehensive fuzzing
        analysis = intent_fuzzer.run_comprehensive_fuzzing()

        # Format results for display
        result = _format_intent_fuzzing_results(analysis)

        return ("Intent Fuzzing Analysis", result)

    except Exception as e:
        logging.error(f"Intent fuzzing analysis failed: {e}")
        return (
            "Intent Fuzzing Analysis",
            Text.from_markup(f"[red]Analysis failed: {e}[/red]"),
        )

def _format_intent_fuzzing_results(analysis: Dict) -> Text:
    """Format intent fuzzing analysis results for display."""
    output = Text()

    # Header
    output.append("🎯 Intent Fuzzing Security Analysis\n", style="bold blue")
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

    components = analysis.get("exported_components", {})
    total_components = sum(len(comp_list) for comp_list in components.values())
    output.append(f"• Exported Components: {total_components}\n")

    for comp_type, comp_list in components.items():
        if comp_list:
            output.append(f"  - {comp_type.title()}: {len(comp_list)}\n", style="cyan")

    # Fuzzing results summary
    fuzzing_results = analysis.get("fuzzing_results", {})
    total_tests = sum(len(results) for results in fuzzing_results.values())
    output.append(f"• Total Fuzzing Tests: {total_tests}\n")
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
            output.append(
                f"{i}. {vuln.get('type', 'Unknown')} in {vuln.get('component', 'unknown')}\n",
                style="red",
            )
            output.append(
                f"   Severity: {vuln.get('severity', 'UNKNOWN')}\n", style="yellow"
            )
            output.append(
                f"   Description: {vuln.get('description', 'No description')}\n"
            )

        if len(vulnerabilities) > 5:
            output.append(
                f"... and {len(vulnerabilities) - 5} more vulnerabilities\n",
                style="yellow",
            )

        output.append("\n")
    else:
        output.append("✅ No Critical Vulnerabilities Detected\n", style="bold green")
        output.append("• Intent handling appears to be secure\n", style="green")
        output.append("• No obvious injection vulnerabilities found\n", style="green")
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
    output.append("• MSTG-PLATFORM-01: App component security\n", style="cyan")
    output.append(
        "• MSTG-PLATFORM-02: Inter-app communication security\n", style="cyan"
    )
    output.append("• MSTG-PLATFORM-03: Intent handling security\n", style="cyan")
    output.append("• MSTG-PLATFORM-04: Deep link validation\n", style="cyan")
    output.append("• MSTG-CODE-8: Input validation and sanitization\n", style="cyan")

    return output
