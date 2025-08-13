#!/usr/bin/env python3
"""
Robust Connection Manager for AODS

This module provides comprehensive device detection, connection establishment, 
and connection maintenance capabilities to ensure AODS can reliably connect 
to and maintain connections with Android devices/emulators throughout scans.

Key Features:
- Multi-strategy device detection (USB, WiFi, emulator)
- Network stability monitoring and recovery
- Connection health checks with automatic recovery
- Graceful degradation handling
- Cross-platform compatibility
- Comprehensive edge case handling
"""

import asyncio
import logging
import os
import re
import subprocess
import sys
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Callable
import socket
import psutil
import signal

class DeviceType(Enum):
    """Device connection types"""
    USB = "usb"
    WIFI = "wifi"
    EMULATOR = "emulator"
    UNKNOWN = "unknown"

class ConnectionState(Enum):
    """Enhanced connection states"""
    UNKNOWN = "unknown"
    SCANNING = "scanning"
    DETECTED = "detected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    AUTHENTICATED = "authenticated"
    MONITORING = "monitoring"
    RECOVERING = "recovering"
    DISCONNECTED = "disconnected"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    STABLE = "stable"
    UNSTABLE = "unstable"

@dataclass
class Device:
    """Device information"""
    device_id: str
    device_type: DeviceType
    status: str
    api_level: Optional[int] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    connection_quality: float = 0.0
    last_seen: float = field(default_factory=time.time)
    stability_score: float = 1.0
    ping_latency: Optional[float] = None

@dataclass
class ConnectionConfig:
    """Robust connection configuration"""
    # Detection settings
    device_scan_timeout: int = 10
    device_scan_interval: int = 2
    max_detection_attempts: int = 5
    
    # Connection settings
    connection_timeout: int = 30
    max_connection_attempts: int = 3
    connection_retry_delay: int = 2
    
    # Monitoring settings
    health_check_interval: int = 10
    stability_threshold: float = 0.7
    max_consecutive_failures: int = 3
    
    # Recovery settings
    auto_recovery_enabled: bool = True
    recovery_max_attempts: int = 5
    recovery_delay_base: int = 2  # Exponential backoff base
    
    # Quality settings
    min_connection_quality: float = 0.5
    ping_timeout: int = 3
    performance_monitoring: bool = True

class RobustConnectionManager:
    """
    Comprehensive connection manager for Android devices with robust error handling
    and automatic recovery capabilities.
    """

    def __init__(self, config: Optional[ConnectionConfig] = None):
        """Initialize the robust connection manager"""
        self.config = config or ConnectionConfig()
        self.logger = logging.getLogger("robust_connection_manager")
        
        # State management
        self.state = ConnectionState.UNKNOWN
        self.devices: Dict[str, Device] = {}
        self.primary_device: Optional[Device] = None
        self.connection_history: List[Dict] = []
        
        # Monitoring
        self.monitoring_thread: Optional[threading.Thread] = None
        self.monitoring_active = False
        self.health_check_callbacks: List[Callable] = []
        
        # Performance tracking
        self.performance_metrics = {
            "connection_attempts": 0,
            "successful_connections": 0,
            "recovery_attempts": 0,
            "successful_recoveries": 0,
            "average_connection_time": 0.0,
            "stability_events": []
        }
        
        # Lock for thread safety
        self._lock = threading.Lock()
        
        self._setup_logging()

    def _ensure_drozer_agent_startup(self) -> bool:
        """Enhanced drozer agent startup with comprehensive initialization"""
        try:
            import subprocess
            import time
            
            # Identify drozer package
            drozer_packages = ["com.withsecure.dz", "com.mwr.dz", "com.boops.boops"]
            drozer_package = None
            
            for pkg in drozer_packages:
                result = subprocess.run(
                    ["adb", "shell", f"pm list packages | grep {pkg}"],
                    capture_output=True, timeout=10
                )
                if result.returncode == 0:
                    drozer_package = pkg
                    break
            
            if not drozer_package:
                return False
            
            # Start drozer agent
            subprocess.run(
                ["adb", "shell", f"am start {drozer_package}/com.WithSecure.dz.activities.MainActivity"],
                capture_output=True, timeout=10
            )
            time.sleep(2)
            
            # Send broadcast
            subprocess.run(
                ["adb", "shell", f"am broadcast -a com.withsecure.dz.START --ei com.withsecure.dz.port 31415"],
                capture_output=True, timeout=10
            )
            time.sleep(3)
            
            return True
            
        except Exception:
            return False

    def _setup_logging(self) -> None:
        """Setup enhanced logging"""
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def scan_devices(self, force_rescan: bool = False) -> List[Device]:
        """
        Comprehensive device scanning with multiple detection strategies
        
        Args:
            force_rescan: Force a complete rescan even if devices are cached
            
        Returns:
            List[Device]: List of detected devices
        """
        if not force_rescan and self.devices and self._devices_recently_scanned():
            return list(self.devices.values())
        
        self.logger.info("🔍 Starting comprehensive device scan...")
        self.state = ConnectionState.SCANNING
        
        detected_devices = []
        
        # Strategy 1: Standard ADB device detection
        detected_devices.extend(self._scan_adb_devices())
        
        # Strategy 2: Network device discovery
        detected_devices.extend(self._scan_network_devices())
        
        # Strategy 3: Emulator detection
        detected_devices.extend(self._scan_emulators())
        
        # Strategy 4: USB device detection
        detected_devices.extend(self._scan_usb_devices())
        
        # Update device registry
        with self._lock:
            self.devices.clear()
            for device in detected_devices:
                self.devices[device.device_id] = device
        
        self.logger.info(f"📱 Detected {len(detected_devices)} device(s)")
        self.state = ConnectionState.DETECTED if detected_devices else ConnectionState.UNAVAILABLE
        
        return detected_devices

    def _scan_adb_devices(self) -> List[Device]:
        """Scan for devices using ADB"""
        devices = []
        
        try:
            result = subprocess.run(
                ["adb", "devices", "-l"],
                capture_output=True,
                text=True,
                timeout=self.config.device_scan_timeout
            )
            
            if result.returncode == 0:
                devices = self._parse_adb_output(result.stdout)
                
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.warning(f"⚠️ ADB device scan failed: {e}")
        
        return devices

    def _parse_adb_output(self, output: str) -> List[Device]:
        """Parse ADB devices output with enhanced device info extraction"""
        devices = []
        lines = output.strip().split('\n')[1:]  # Skip header
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Parse device line: device_id status [additional_info]
            parts = line.split()
            if len(parts) >= 2:
                device_id = parts[0]
                status = parts[1]
                
                # Only include properly connected devices
                if status in ['device', 'unauthorized', 'offline']:
                    device_type = self._determine_device_type(device_id, line)
                    
                    device = Device(
                        device_id=device_id,
                        device_type=device_type,
                        status=status
                    )
                    
                    # Extract additional device info if available
                    self._enrich_device_info(device, line)
                    devices.append(device)
        
        return devices

    def _determine_device_type(self, device_id: str, info_line: str) -> DeviceType:
        """Determine device type from device ID and info"""
        device_id_lower = device_id.lower()
        info_lower = info_line.lower()
        
        # Check for emulator patterns
        if any(pattern in device_id_lower for pattern in ['emulator-', 'emu-', 'genymotion']):
            return DeviceType.EMULATOR
        
        # Check for network/WiFi patterns
        if ':' in device_id and ('.' in device_id or 'wifi' in info_lower):
            return DeviceType.WIFI
        
        # Check for USB patterns
        if any(pattern in info_lower for pattern in ['usb:', 'product:', 'model:']):
            return DeviceType.USB
        
        return DeviceType.UNKNOWN

    def _enrich_device_info(self, device: Device, info_line: str) -> None:
        """Extract additional device information from ADB output"""
        try:
            # Extract model info
            model_match = re.search(r'model:([^\s]+)', info_line)
            if model_match:
                device.model = model_match.group(1)
            
            # Extract product info (can indicate manufacturer)
            product_match = re.search(r'product:([^\s]+)', info_line)
            if product_match:
                device.manufacturer = product_match.group(1).split('_')[0]
            
            # Get API level if device is accessible
            if device.status == 'device':
                api_level = self._get_device_api_level(device.device_id)
                if api_level:
                    device.api_level = api_level
                    
        except Exception as e:
            self.logger.debug(f"Could not enrich device info for {device.device_id}: {e}")

    def _get_device_api_level(self, device_id: str) -> Optional[int]:
        """Get Android API level for a device"""
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "getprop", "ro.build.version.sdk"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip().isdigit():
                return int(result.stdout.strip())
                
        except Exception:
            pass
        
        return None

    def _scan_network_devices(self) -> List[Device]:
        """Scan for network-connected Android devices"""
        devices = []
        
        # This would typically scan common ADB wireless ports
        # For now, rely on ADB's network device detection
        # Future enhancement: implement network discovery
        
        return devices

    def _scan_emulators(self) -> List[Device]:
        """Scan for running Android emulators"""
        devices = []
        
        try:
            # Check for running emulator processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if 'emulator' in proc.info['name'].lower():
                        # Extract emulator port from command line
                        cmdline = ' '.join(proc.info['cmdline'])
                        port_match = re.search(r'-port\s+(\d+)', cmdline)
                        if port_match:
                            port = port_match.group(1)
                            device_id = f"emulator-{port}"
                            
                            device = Device(
                                device_id=device_id,
                                device_type=DeviceType.EMULATOR,
                                status="device"
                            )
                            devices.append(device)
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.debug(f"Emulator scan failed: {e}")
        
        return devices

    def _scan_usb_devices(self) -> List[Device]:
        """Scan for USB-connected Android devices"""
        devices = []
        
        # USB device detection is typically handled by ADB
        # This could be enhanced with direct USB scanning in the future
        
        return devices

    def establish_connection(self, device_id: Optional[str] = None) -> bool:
        """
        Establish robust connection to a device with comprehensive error handling
        
        Args:
            device_id: Specific device to connect to, or None for best available
            
        Returns:
            bool: True if connection established successfully
        """
        self.logger.info("🔧 Establishing robust device connection...")
        self.state = ConnectionState.CONNECTING
        self.performance_metrics["connection_attempts"] += 1
        
        start_time = time.time()
        
        try:
            # Select target device
            target_device = self._select_target_device(device_id)
            if not target_device:
                self.logger.error("❌ No suitable device found for connection")
                self.state = ConnectionState.UNAVAILABLE
                return False
            
            self.logger.info(f"📱 Connecting to {target_device.device_id} ({target_device.device_type.value})")
            
            # Establish connection with retries
            success = self._connect_with_retries(target_device)
            
            if success:
                self.primary_device = target_device
                self.state = ConnectionState.CONNECTED
                self.performance_metrics["successful_connections"] += 1
                
                # Start connection monitoring
                self._start_monitoring()
                
                connection_time = time.time() - start_time
                self._update_average_connection_time(connection_time)
                
                self.logger.info(f"✅ Connection established successfully in {connection_time:.2f}s")
                return True
            else:
                self.state = ConnectionState.FAILED
                self.logger.error("❌ Failed to establish connection after all attempts")
                return False
                
        except Exception as e:
            self.state = ConnectionState.FAILED
            self.logger.error(f"❌ Connection establishment failed: {e}")
            return False

    def _select_target_device(self, device_id: Optional[str] = None) -> Optional[Device]:
        """Select the best device for connection"""
        if device_id:
            return self.devices.get(device_id)
        
        # Auto-select best device based on criteria
        candidates = [d for d in self.devices.values() if d.status == 'device']
        
        if not candidates:
            return None
        
        # Scoring system for device selection
        def score_device(device: Device) -> float:
            score = 0.0
            
            # Prefer USB over WiFi over emulator for stability
            if device.device_type == DeviceType.USB:
                score += 3.0
            elif device.device_type == DeviceType.WIFI:
                score += 2.0
            elif device.device_type == DeviceType.EMULATOR:
                score += 1.0
            
            # Consider stability score
            score += device.stability_score
            
            # Consider connection quality
            score += device.connection_quality
            
            # Prefer higher API levels
            if device.api_level:
                score += min(device.api_level / 30.0, 1.0)
            
            return score
        
        return max(candidates, key=score_device)

    def _connect_with_retries(self, device: Device) -> bool:
        """Attempt connection with retry logic"""
        for attempt in range(self.config.max_connection_attempts):
            self.logger.info(f"🔄 Connection attempt {attempt + 1}/{self.config.max_connection_attempts}")
            
            if self._attempt_single_connection(device):
                return True
            
            if attempt < self.config.max_connection_attempts - 1:
                delay = self.config.connection_retry_delay * (attempt + 1)
                self.logger.info(f"⏳ Retrying in {delay} seconds...")
                time.sleep(delay)
        
        return False

    def _attempt_single_connection(self, device: Device) -> bool:
        """Attempt a single connection to the device"""
        try:
            # Test basic ADB connectivity
            result = subprocess.run(
                ["adb", "-s", device.device_id, "shell", "echo", "test"],
                capture_output=True,
                text=True,
                timeout=self.config.connection_timeout
            )
            
            if result.returncode == 0 and "test" in result.stdout:
                # Test drozer port forwarding
                if self._setup_port_forwarding(device.device_id):
                    # Verify drozer connectivity
                    if self._verify_drozer_connectivity(device.device_id):
                        device.connection_quality = 1.0
                        return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Connection attempt failed: {e}")
            return False

    def _setup_port_forwarding(self, device_id: str) -> bool:
        """Setup ADB port forwarding for drozer"""
        try:
            # Clean up existing forwarding
            subprocess.run(
                ["adb", "-s", device_id, "forward", "--remove", "tcp:31415"],
                capture_output=True,
                timeout=10
            )
            
            # Setup new forwarding
            result = subprocess.run(
                ["adb", "-s", device_id, "forward", "tcp:31415", "tcp:31415"],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            return result.returncode == 0
            
        except Exception as e:
            self.logger.debug(f"Port forwarding failed: {e}")
            return False

    def _verify_drozer_connectivity(self, device_id: str) -> bool:
        """Verify drozer agent connectivity"""
        try:
            # Simple drozer connectivity test
            result = subprocess.run(
                ["drozer", "console", "connect", "--command", "list"],
                capture_output=True,
                text=True,
                timeout=45
            )
            
            return result.returncode == 0
            
        except Exception as e:
            self.logger.debug(f"Drozer connectivity test failed: {e}")
            return False

    def _start_monitoring(self) -> None:
        """Start connection health monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True,
            name="connection_monitor"
        )
        self.monitoring_thread.start()
        self.logger.info("🔍 Connection monitoring started")

    def _monitoring_loop(self) -> None:
        """Main monitoring loop"""
        consecutive_failures = 0
        
        while self.monitoring_active and self.primary_device:
            try:
                # Perform health check
                health_ok = self._perform_health_check()
                
                if health_ok:
                    consecutive_failures = 0
                    self.state = ConnectionState.STABLE
                    
                    # Update device stability score
                    self.primary_device.stability_score = min(
                        self.primary_device.stability_score + 0.1, 1.0
                    )
                else:
                    consecutive_failures += 1
                    self.state = ConnectionState.UNSTABLE
                    
                    # Decrease stability score
                    self.primary_device.stability_score = max(
                        self.primary_device.stability_score - 0.2, 0.0
                    )
                    
                    self.logger.warning(f"⚠️ Health check failed ({consecutive_failures}/{self.config.max_consecutive_failures})")
                    
                    # Attempt recovery if threshold exceeded
                    if consecutive_failures >= self.config.max_consecutive_failures:
                        if self.config.auto_recovery_enabled:
                            self._attempt_recovery()
                            consecutive_failures = 0  # Reset after recovery attempt
                        else:
                            self.logger.error("❌ Connection unstable, auto-recovery disabled")
                            break
                
                # Call health check callbacks
                for callback in self.health_check_callbacks:
                    try:
                        callback(health_ok, self.primary_device)
                    except Exception as e:
                        self.logger.debug(f"Health check callback failed: {e}")
                
                time.sleep(self.config.health_check_interval)
                
            except Exception as e:
                self.logger.error(f"❌ Monitoring loop error: {e}")
                time.sleep(self.config.health_check_interval)

    def _perform_health_check(self) -> bool:
        """Perform comprehensive health check"""
        if not self.primary_device:
            return False
        
        try:
            # Test 1: Basic ADB connectivity
            result = subprocess.run(
                ["adb", "-s", self.primary_device.device_id, "shell", "echo", "ping"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0 or "ping" not in result.stdout:
                return False
            
            # Test 2: Port forwarding status
            if not self._check_port_forwarding():
                return False
            
            # Test 3: Drozer connectivity (if available)
            if not self._quick_drozer_check():
                return False
            
            # Update last seen timestamp
            self.primary_device.last_seen = time.time()
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Health check failed: {e}")
            return False

    def _check_port_forwarding(self) -> bool:
        """Check if port forwarding is active"""
        try:
            result = subprocess.run(
                ["adb", "-s", self.primary_device.device_id, "forward", "--list"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            return "31415" in result.stdout
            
        except Exception:
            return False

    def _quick_drozer_check(self) -> bool:
        """Quick drozer connectivity check"""
        try:
            # Simple drozer command with short timeout
            result = subprocess.run(
                ["drozer", "console", "connect", "--command", "list"],
                capture_output=True,
                timeout=45
            )
            
            return result.returncode == 0
            
        except Exception:
            return False

    def _attempt_recovery(self) -> bool:
        """Attempt to recover connection"""
        self.logger.info("🔄 Attempting connection recovery...")
        self.state = ConnectionState.RECOVERING
        self.performance_metrics["recovery_attempts"] += 1
        
        try:
            # Step 1: Re-scan devices
            self.scan_devices(force_rescan=True)
            
            # Step 2: Check if primary device is still available
            if self.primary_device and self.primary_device.device_id in self.devices:
                # Step 3: Re-establish connection
                if self._connect_with_retries(self.primary_device):
                    self.logger.info("✅ Connection recovery successful")
                    self.performance_metrics["successful_recoveries"] += 1
                    return True
            
            # Step 4: Try alternative device if primary failed
            alternative_device = self._select_target_device()
            if alternative_device and alternative_device != self.primary_device:
                self.logger.info(f"🔄 Switching to alternative device: {alternative_device.device_id}")
                if self._connect_with_retries(alternative_device):
                    self.primary_device = alternative_device
                    self.logger.info("✅ Recovery successful with alternative device")
                    self.performance_metrics["successful_recoveries"] += 1
                    return True
            
            self.logger.error("❌ Connection recovery failed")
            self.state = ConnectionState.FAILED
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Recovery attempt failed: {e}")
            self.state = ConnectionState.FAILED
            return False

    def get_connection_status(self) -> Dict:
        """Get comprehensive connection status"""
        return {
            "state": self.state.value,
            "connected": self.state in [ConnectionState.CONNECTED, ConnectionState.STABLE],
            "primary_device": {
                "device_id": self.primary_device.device_id,
                "device_type": self.primary_device.device_type.value,
                "status": self.primary_device.status,
                "api_level": self.primary_device.api_level,
                "stability_score": self.primary_device.stability_score,
                "connection_quality": self.primary_device.connection_quality,
                "last_seen": self.primary_device.last_seen
            } if self.primary_device else None,
            "available_devices": len(self.devices),
            "monitoring_active": self.monitoring_active,
            "performance_metrics": self.performance_metrics.copy()
        }

    def add_health_check_callback(self, callback: Callable) -> None:
        """Add a callback function for health check events"""
        self.health_check_callbacks.append(callback)

    def _devices_recently_scanned(self) -> bool:
        """Check if devices were scanned recently"""
        if not self.devices:
            return False
        
        # Consider devices recently scanned if any device was seen in the last 30 seconds
        return any(
            time.time() - device.last_seen < 30
            for device in self.devices.values()
        )

    def _update_average_connection_time(self, connection_time: float) -> None:
        """Update average connection time metric"""
        current_avg = self.performance_metrics["average_connection_time"]
        attempts = self.performance_metrics["successful_connections"]
        
        # Calculate new average
        new_avg = ((current_avg * (attempts - 1)) + connection_time) / attempts
        self.performance_metrics["average_connection_time"] = new_avg

    def stop_monitoring(self) -> None:
        """Stop connection monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        self.logger.info("🔌 Connection monitoring stopped")

    def disconnect(self) -> None:
        """Disconnect from device and cleanup"""
        self.logger.info("🔌 Disconnecting from device...")
        
        # Stop monitoring
        self.stop_monitoring()
        
        # Cleanup port forwarding
        if self.primary_device:
            try:
                subprocess.run(
                    ["adb", "-s", self.primary_device.device_id, "forward", "--remove", "tcp:31415"],
                    capture_output=True,
                    timeout=10
                )
            except Exception as e:
                self.logger.debug(f"Port forwarding cleanup failed: {e}")
        
        # Reset state
        self.state = ConnectionState.DISCONNECTED
        self.primary_device = None
        
        self.logger.info("✅ Disconnection complete")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()

# Factory function for easy integration
def create_robust_connection_manager(config: Optional[ConnectionConfig] = None) -> RobustConnectionManager:
    """Create a robust connection manager instance"""
    return RobustConnectionManager(config) 