#!/usr/bin/env python3
"""
Enhanced Device Detection for AODS

This module provides robust device detection and connection management
with comprehensive edge case handling to ensure AODS maintains stable
connections throughout security scans.

Key Features:
- Multiple device detection strategies
- Network stability monitoring
- Automatic reconnection handling
- Cross-platform compatibility
- Comprehensive error handling
"""

import logging
import re
import subprocess
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

class DeviceStatus(Enum):
    """Device connection status"""
    CONNECTED = "device"
    UNAUTHORIZED = "unauthorized"
    OFFLINE = "offline"
    BOOTLOADER = "bootloader"
    RECOVERY = "recovery"
    UNKNOWN = "unknown"

@dataclass
class DetectedDevice:
    """Information about a detected device"""
    device_id: str
    status: DeviceStatus
    is_emulator: bool = False
    is_wifi: bool = False
    api_level: Optional[int] = None
    model: Optional[str] = None
    manufacturer: Optional[str] = None
    connection_quality: float = 1.0

class EnhancedDeviceDetection:
    """Enhanced device detection with robust error handling"""

    def __init__(self):
        self.logger = logging.getLogger("enhanced_device_detection")
        self.last_scan_time = 0
        self.cached_devices: Dict[str, DetectedDevice] = {}
        self.scan_cache_duration = 5  # Cache results for 5 seconds

    def detect_devices(self, force_rescan: bool = False) -> List[DetectedDevice]:
        """
        Detect all available Android devices with comprehensive scanning
        
        Args:
            force_rescan: Force a new scan even if cache is valid
            
        Returns:
            List[DetectedDevice]: List of detected devices
        """
        # Use cache if recent and not forcing rescan
        if not force_rescan and self._is_cache_valid():
            return list(self.cached_devices.values())

        self.logger.info("🔍 Starting enhanced device detection...")
        devices = []

        try:
            # Primary detection: Standard ADB devices
            adb_devices = self._detect_adb_devices()
            devices.extend(adb_devices)

            # Secondary detection: Network devices
            network_devices = self._detect_network_devices()
            devices.extend(network_devices)

            # Tertiary detection: Emulator processes
            emulator_devices = self._detect_emulator_devices()
            devices.extend(emulator_devices)

            # Update cache
            self.cached_devices = {device.device_id: device for device in devices}
            self.last_scan_time = time.time()

            self.logger.info(f"📱 Detected {len(devices)} device(s)")
            for device in devices:
                self.logger.info(
                    f"  • {device.device_id} ({device.status.value}) "
                    f"{'[Emulator]' if device.is_emulator else ''}"
                    f"{'[WiFi]' if device.is_wifi else ''}"
                )

        except Exception as e:
            self.logger.error(f"❌ Device detection failed: {e}")

        return devices

    def _detect_adb_devices(self) -> List[DetectedDevice]:
        """Detect devices using ADB with enhanced parsing"""
        devices = []

        try:
            # Use ADB with detailed listing
            result = subprocess.run(
                ["adb", "devices", "-l"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                devices = self._parse_enhanced_adb_output(result.stdout)
            else:
                self.logger.warning(f"⚠️ ADB command failed: {result.stderr}")

        except subprocess.TimeoutExpired:
            self.logger.warning("⚠️ ADB device detection timed out")
        except FileNotFoundError:
            self.logger.warning("⚠️ ADB not found - ensure Android SDK is installed")
        except Exception as e:
            self.logger.warning(f"⚠️ ADB detection error: {e}")

        return devices

    def _parse_enhanced_adb_output(self, output: str) -> List[DetectedDevice]:
        """Parse ADB output with comprehensive device information extraction"""
        devices = []
        lines = output.strip().split('\n')

        # Skip the header line
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue

            device = self._parse_adb_device_line(line)
            if device:
                devices.append(device)

        return devices

    def _parse_adb_device_line(self, line: str) -> Optional[DetectedDevice]:
        """Parse a single ADB device line with robust pattern matching"""
        # Enhanced pattern matching for different ADB output formats
        patterns = [
            # Standard format: device_id status [device properties]
            r'^(\S+)\s+(device|unauthorized|offline|bootloader|recovery)(?:\s+(.*))?$',
            # Alternative format: device_id \t status [properties]
            r'^(\S+)\s*\t\s*(device|unauthorized|offline|bootloader|recovery)(?:\s+(.*))?$',
            # Legacy format: device_id status
            r'^(\S+)\s+(device|unauthorized|offline|bootloader|recovery)$'
        ]

        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                device_id = match.group(1)
                status_str = match.group(2)
                properties = match.group(3) if len(match.groups()) >= 3 else ""

                # Convert status string to enum
                try:
                    status = DeviceStatus(status_str)
                except ValueError:
                    status = DeviceStatus.UNKNOWN

                # Create device object
                device = DetectedDevice(
                    device_id=device_id,
                    status=status
                )

                # Analyze device characteristics
                self._analyze_device_characteristics(device, properties)

                return device

        # If no pattern matched, log for debugging
        self.logger.debug(f"Unrecognized ADB device line format: {line}")
        return None

    def _analyze_device_characteristics(self, device: DetectedDevice, properties: str) -> None:
        """Analyze device characteristics from ADB properties"""
        # Determine if device is an emulator
        device.is_emulator = self._is_emulator_device(device.device_id, properties)

        # Determine if device is connected via WiFi
        device.is_wifi = self._is_wifi_device(device.device_id, properties)

        # Extract model information
        device.model = self._extract_model(properties)

        # Extract manufacturer information
        device.manufacturer = self._extract_manufacturer(properties)

        # Get additional device information if accessible
        if device.status == DeviceStatus.CONNECTED:
            device.api_level = self._get_device_api_level(device.device_id)

    def _is_emulator_device(self, device_id: str, properties: str) -> bool:
        """Determine if device is an emulator"""
        emulator_indicators = [
            'emulator-',
            'emu-',
            'genymotion',
            'bluestacks',
            'simulator'
        ]

        device_id_lower = device_id.lower()
        properties_lower = properties.lower()

        return any(
            indicator in device_id_lower or indicator in properties_lower
            for indicator in emulator_indicators
        )

    def _is_wifi_device(self, device_id: str, properties: str) -> bool:
        """Determine if device is connected via WiFi"""
        # WiFi devices typically have IP addresses in device ID
        wifi_patterns = [
            r'\d+\.\d+\.\d+\.\d+:\d+',  # IP:port format
            r'.*:\d+$'  # Any string ending with :port
        ]

        return any(re.match(pattern, device_id) for pattern in wifi_patterns)

    def _extract_model(self, properties: str) -> Optional[str]:
        """Extract device model from properties"""
        model_patterns = [
            r'model:([^\s]+)',
            r'device:([^\s]+)',
            r'product:([^\s]+)'
        ]

        for pattern in model_patterns:
            match = re.search(pattern, properties)
            if match:
                return match.group(1)

        return None

    def _extract_manufacturer(self, properties: str) -> Optional[str]:
        """Extract manufacturer from properties"""
        # Try to extract from product field
        product_match = re.search(r'product:([^\s]+)', properties)
        if product_match:
            product = product_match.group(1)
            # Manufacturer is often the first part before underscore
            return product.split('_')[0]

        return None

    def _get_device_api_level(self, device_id: str) -> Optional[int]:
        """Get Android API level for a connected device"""
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "getprop", "ro.build.version.sdk"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                api_str = result.stdout.strip()
                if api_str.isdigit():
                    return int(api_str)

        except Exception as e:
            self.logger.debug(f"Could not get API level for {device_id}: {e}")

        return None

    def _detect_network_devices(self) -> List[DetectedDevice]:
        """Detect network-connected devices (future enhancement)"""
        # This could be enhanced to scan for devices on the network
        # For now, rely on ADB's network device detection
        return []

    def _detect_emulator_devices(self) -> List[DetectedDevice]:
        """Detect devices by scanning for emulator processes"""
        devices = []

        try:
            import psutil

            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_info = proc.info
                    if 'emulator' in proc_info['name'].lower():
                        # Extract emulator device ID from command line
                        cmdline = ' '.join(proc_info['cmdline'])
                        
                        # Look for port specification
                        port_match = re.search(r'-port\s+(\d+)', cmdline)
                        if port_match:
                            port = port_match.group(1)
                            device_id = f"emulator-{port}"

                            # Check if this emulator is already detected by ADB
                            if device_id not in self.cached_devices:
                                device = DetectedDevice(
                                    device_id=device_id,
                                    status=DeviceStatus.CONNECTED,
                                    is_emulator=True
                                )
                                devices.append(device)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except ImportError:
            self.logger.debug("psutil not available for emulator detection")
        except Exception as e:
            self.logger.debug(f"Emulator detection failed: {e}")

        return devices

    def _is_cache_valid(self) -> bool:
        """Check if cached device list is still valid"""
        return (
            self.cached_devices and 
            time.time() - self.last_scan_time < self.scan_cache_duration
        )

    def get_best_device(self, prefer_real_device: bool = True) -> Optional[DetectedDevice]:
        """
        Get the best available device for testing
        
        Args:
            prefer_real_device: Prefer real devices over emulators
            
        Returns:
            DetectedDevice: Best available device or None
        """
        devices = self.detect_devices()
        
        # Filter to only connected devices
        connected_devices = [
            device for device in devices 
            if device.status == DeviceStatus.CONNECTED
        ]

        if not connected_devices:
            return None

        # Scoring function for device selection
        def score_device(device: DetectedDevice) -> float:
            score = 0.0

            # Base score for being connected
            score += 10.0

            # Prefer real devices over emulators
            if prefer_real_device and not device.is_emulator:
                score += 5.0
            elif device.is_emulator:
                score += 2.0

            # Prefer USB over WiFi for stability
            if not device.is_wifi:
                score += 3.0

            # Prefer higher API levels
            if device.api_level:
                score += min(device.api_level / 30.0, 2.0)

            # Factor in connection quality
            score += device.connection_quality

            return score

        return max(connected_devices, key=score_device)

    def test_device_connectivity(self, device_id: str) -> Dict[str, any]:
        """
        Test comprehensive connectivity to a specific device
        
        Args:
            device_id: Device ID to test
            
        Returns:
            Dict: Connectivity test results
        """
        result = {
            "device_id": device_id,
            "adb_responsive": False,
            "shell_access": False,
            "port_forwarding": False,
            "drozer_ready": False,
            "connection_quality": 0.0,
            "latency": None,
            "errors": []
        }

        try:
            # Test 1: Basic ADB responsiveness
            start_time = time.time()
            adb_result = subprocess.run(
                ["adb", "-s", device_id, "get-state"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if adb_result.returncode == 0:
                result["adb_responsive"] = True
                result["latency"] = time.time() - start_time

            # Test 2: Shell access
            shell_result = subprocess.run(
                ["adb", "-s", device_id, "shell", "echo", "test"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if shell_result.returncode == 0 and "test" in shell_result.stdout:
                result["shell_access"] = True

            # Test 3: Port forwarding capability
            forward_result = subprocess.run(
                ["adb", "-s", device_id, "forward", "tcp:31415", "tcp:31415"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if forward_result.returncode == 0:
                result["port_forwarding"] = True
                
                # Clean up test port forwarding
                subprocess.run(
                    ["adb", "-s", device_id, "forward", "--remove", "tcp:31415"],
                    capture_output=True,
                    timeout=5
                )

            # Test 4: Drozer readiness (if available)
            try:
                drozer_result = subprocess.run(
                    ["drozer", "console", "connect", "--command", "list"],
                    capture_output=True,
                    timeout=10
                )
                
                if drozer_result.returncode == 0:
                    result["drozer_ready"] = True
                    
            except FileNotFoundError:
                result["errors"].append("Drozer not found")

            # Calculate overall connection quality
            quality_score = 0.0
            if result["adb_responsive"]:
                quality_score += 0.3
            if result["shell_access"]:
                quality_score += 0.3
            if result["port_forwarding"]:
                quality_score += 0.3
            if result["drozer_ready"]:
                quality_score += 0.1

            result["connection_quality"] = quality_score

        except Exception as e:
            result["errors"].append(str(e))

        return result

    def monitor_device_stability(self, device_id: str, duration: int = 30) -> Dict[str, any]:
        """
        Monitor device connection stability over time
        
        Args:
            device_id: Device to monitor
            duration: Monitoring duration in seconds
            
        Returns:
            Dict: Stability monitoring results
        """
        self.logger.info(f"🔍 Monitoring device {device_id} stability for {duration}s...")
        
        results = {
            "device_id": device_id,
            "monitoring_duration": duration,
            "total_checks": 0,
            "successful_checks": 0,
            "failed_checks": 0,
            "stability_score": 0.0,
            "disconnection_events": 0,
            "average_latency": 0.0,
            "max_latency": 0.0,
            "min_latency": float('inf')
        }

        check_interval = 2  # Check every 2 seconds
        total_latency = 0.0
        
        start_time = time.time()
        while time.time() - start_time < duration:
            results["total_checks"] += 1
            
            try:
                # Quick connectivity check
                check_start = time.time()
                check_result = subprocess.run(
                    ["adb", "-s", device_id, "shell", "echo", "ping"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                
                check_latency = time.time() - check_start
                
                if check_result.returncode == 0 and "ping" in check_result.stdout:
                    results["successful_checks"] += 1
                    total_latency += check_latency
                    results["max_latency"] = max(results["max_latency"], check_latency)
                    results["min_latency"] = min(results["min_latency"], check_latency)
                else:
                    results["failed_checks"] += 1
                    results["disconnection_events"] += 1
                    
            except Exception:
                results["failed_checks"] += 1
                results["disconnection_events"] += 1
            
            time.sleep(check_interval)

        # Calculate final metrics
        if results["successful_checks"] > 0:
            results["average_latency"] = total_latency / results["successful_checks"]
            results["stability_score"] = results["successful_checks"] / results["total_checks"]
        
        if results["min_latency"] == float('inf'):
            results["min_latency"] = 0.0

        self.logger.info(
            f"📊 Stability monitoring complete: "
            f"{results['stability_score']:.2%} success rate, "
            f"{results['average_latency']:.3f}s avg latency"
        )

        return results

# Factory function for easy integration
def create_device_detector() -> EnhancedDeviceDetection:
    """Create an enhanced device detection instance"""
    return EnhancedDeviceDetection() 