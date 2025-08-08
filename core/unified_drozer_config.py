#!/usr/bin/env python3
"""
Enhanced Unified Drozer Configuration System

High-quality Drozer orchestration with advanced capabilities including:
- Dynamic configuration adaptation
- Multi-device management
- Security validation and sanitization
- Configuration template system
- Error recovery and fallback mechanisms
- Performance optimization
- Comprehensive monitoring and logging
"""

import logging
import os
import json
import time
import subprocess
import socket
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

# Enhanced Configuration Constants
DROZER_CONNECTION_TIMEOUT = 60  # seconds - increased for stability
DROZER_COMMAND_TIMEOUT = 90     # seconds - increased for complex analysis
ADB_TIMEOUT = 30                # seconds
PORT_FORWARD_TIMEOUT = 15       # seconds
DEVICE_DISCOVERY_TIMEOUT = 20   # seconds
NETWORK_VALIDATION_TIMEOUT = 10 # seconds

# Connection Configuration
DROZER_PORT = 31415
ADB_PORT = 5037
MAX_RECONNECTION_ATTEMPTS = 3
RECONNECTION_DELAY = 2.0
HEALTH_CHECK_INTERVAL = 30      # seconds
CONNECTION_POOL_SIZE = 5

# Security Configuration
ENABLE_COMMAND_VALIDATION = True
ENABLE_PATH_VALIDATION = True
ENABLE_NETWORK_VALIDATION = True
LOG_SECURITY_EVENTS = True
COMMAND_WHITELIST_ENABLED = True
SANDBOX_MODE = False

# Manager Hierarchy Configuration
PRIMARY_MANAGER = "EnhancedAntiSpamDrozerWrapper"
SECONDARY_MANAGER = "RobustConnectionFramework"
FALLBACK_MANAGER = "EnhancedDrozerManager"

class ConfigurationType(Enum):
    """Configuration deployment types."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"
    ENTERPRISE = "enterprise"
    HIGH_SECURITY = "high_security"

class DeviceStatus(Enum):
    """Device connection status."""
    UNKNOWN = "unknown"
    AVAILABLE = "available"
    CONNECTED = "connected"
    BUSY = "busy"
    OFFLINE = "offline"
    ERROR = "error"

class NetworkCondition(Enum):
    """Network condition types."""
    UNKNOWN = "unknown"
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    CRITICAL = "critical"

@dataclass
class DeviceInfo:
    """Information about a connected device."""
    device_id: str
    model: str = "Unknown"
    android_version: str = "Unknown"
    api_level: int = 0
    architecture: str = "Unknown"
    status: DeviceStatus = DeviceStatus.UNKNOWN
    last_seen: float = 0.0
    capabilities: List[str] = field(default_factory=list)
    performance_score: float = 0.0
    drozer_port: Optional[int] = None
    connection_count: int = 0

@dataclass
class NetworkMetrics:
    """Network performance metrics."""
    latency: float = 0.0
    bandwidth: float = 0.0
    packet_loss: float = 0.0
    condition: NetworkCondition = NetworkCondition.UNKNOWN
    last_measured: float = 0.0

@dataclass
class SecurityPolicy:
    """Security policy configuration."""
    command_validation: bool = True
    path_validation: bool = True
    network_validation: bool = True
    sandbox_mode: bool = False
    whitelist_enabled: bool = True
    allowed_commands: List[str] = field(default_factory=list)
    blocked_commands: List[str] = field(default_factory=list)
    max_command_length: int = 1000
    log_all_commands: bool = True

@dataclass
class PerformanceConfig:
    """Performance optimization configuration."""
    connection_pool_size: int = 5
    max_concurrent_operations: int = 3
    command_timeout: int = 90
    connection_timeout: int = 60
    health_check_interval: int = 30
    retry_attempts: int = 3
    retry_delay: float = 2.0
    enable_caching: bool = True
    cache_ttl: int = 300

@dataclass
class DrozerConfiguration:
    """Comprehensive Drozer configuration."""
    config_type: ConfigurationType
    device_info: Optional[DeviceInfo] = None
    network_metrics: Optional[NetworkMetrics] = None
    security_policy: SecurityPolicy = field(default_factory=SecurityPolicy)
    performance_config: PerformanceConfig = field(default_factory=PerformanceConfig)
    custom_settings: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)

class DeviceManager:
    """Manages Android device discovery and selection."""
    
    def __init__(self):
        self.devices: Dict[str, DeviceInfo] = {}
        self.last_discovery: float = 0.0
        self.discovery_lock = threading.Lock()
    
    def discover_devices(self, force_refresh: bool = False) -> List[DeviceInfo]:
        """Discover available Android devices."""
        current_time = time.time()
        
        # Use cached results if recent
        if not force_refresh and (current_time - self.last_discovery) < 30:
            return list(self.devices.values())
        
        with self.discovery_lock:
            try:
                # Run adb devices command
                result = subprocess.run(
                    ["adb", "devices", "-l"],
                    capture_output=True,
                    text=True,
                    timeout=DEVICE_DISCOVERY_TIMEOUT
                )
                
                if result.returncode != 0:
                    logging.error(f"Failed to discover devices: {result.stderr}")
                    return []
                
                self._parse_device_list(result.stdout)
                self.last_discovery = current_time
                
                # Update device information
                for device_id in list(self.devices.keys()):
                    self._update_device_info(device_id)
                
                return list(self.devices.values())
                
            except subprocess.TimeoutExpired:
                logging.error("Device discovery timed out")
                return []
            except Exception as e:
                logging.error(f"Device discovery failed: {e}")
                return []
    
    def _parse_device_list(self, output: str) -> None:
        """Parse adb devices output."""
        lines = output.strip().split('\n')[1:]  # Skip header
        current_devices = set()
        
        for line in lines:
            if not line.strip():
                continue
                
            parts = line.split()
            if len(parts) >= 2:
                device_id = parts[0]
                status = parts[1]
                
                current_devices.add(device_id)
                
                if device_id not in self.devices:
                    self.devices[device_id] = DeviceInfo(device_id=device_id)
                
                # Update status
                if status == "device":
                    self.devices[device_id].status = DeviceStatus.AVAILABLE
                elif status == "offline":
                    self.devices[device_id].status = DeviceStatus.OFFLINE
                else:
                    self.devices[device_id].status = DeviceStatus.UNKNOWN
                
                self.devices[device_id].last_seen = time.time()
        
        # Remove devices that are no longer connected
        for device_id in list(self.devices.keys()):
            if device_id not in current_devices:
                del self.devices[device_id]
    
    def _update_device_info(self, device_id: str) -> None:
        """Update detailed device information."""
        if device_id not in self.devices:
            return
        
        device = self.devices[device_id]
        
        try:
            # Get device properties
            props_cmd = ["adb", "-s", device_id, "shell", "getprop"]
            result = subprocess.run(props_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                props = self._parse_device_properties(result.stdout)
                device.model = props.get("ro.product.model", "Unknown")
                device.android_version = props.get("ro.build.version.release", "Unknown")
                device.api_level = int(props.get("ro.build.version.sdk", "0"))
                device.architecture = props.get("ro.product.cpu.abi", "Unknown")
        
        except Exception as e:
            logging.warning(f"Failed to update device info for {device_id}: {e}")
    
    def _parse_device_properties(self, output: str) -> Dict[str, str]:
        """Parse device properties output."""
        props = {}
        for line in output.split('\n'):
            if ': [' in line and line.endswith(']'):
                key, value = line.split(': [', 1)
                key = key.strip('[]')
                value = value.rstrip(']')
                props[key] = value
        return props
    
    def get_best_device(self, requirements: Optional[Dict[str, Any]] = None) -> Optional[DeviceInfo]:
        """Select the best available device based on requirements."""
        available_devices = [d for d in self.devices.values() 
                           if d.status == DeviceStatus.AVAILABLE]
        
        if not available_devices:
            return None
        
        if not requirements:
            # Return device with highest performance score
            return max(available_devices, key=lambda d: d.performance_score)
        
        # Filter by requirements
        filtered_devices = []
        for device in available_devices:
            if self._meets_requirements(device, requirements):
                filtered_devices.append(device)
        
        if not filtered_devices:
            return None
        
        return max(filtered_devices, key=lambda d: d.performance_score)
    
    def _meets_requirements(self, device: DeviceInfo, requirements: Dict[str, Any]) -> bool:
        """Check if device meets requirements."""
        if "min_api_level" in requirements:
            if device.api_level < requirements["min_api_level"]:
                return False
        
        if "architecture" in requirements:
            if device.architecture not in requirements["architecture"]:
                return False
        
        if "model" in requirements:
            if device.model not in requirements["model"]:
                return False
        
        return True

class NetworkAnalyzer:
    """Analyzes network conditions for optimization."""
    
    def __init__(self):
        self.metrics_cache: Dict[str, NetworkMetrics] = {}
        self.cache_ttl = 60  # seconds
    
    def analyze_network_conditions(self, target_host: str = "8.8.8.8") -> NetworkMetrics:
        """Analyze current network conditions."""
        cache_key = f"network_{target_host}"
        current_time = time.time()
        
        # Check cache
        if cache_key in self.metrics_cache:
            cached = self.metrics_cache[cache_key]
            if (current_time - cached.last_measured) < self.cache_ttl:
                return cached
        
        metrics = NetworkMetrics()
        
        try:
            # Measure latency
            metrics.latency = self._measure_latency(target_host)
            
            # Estimate bandwidth (simplified)
            metrics.bandwidth = self._estimate_bandwidth()
            
            # Calculate packet loss (simplified)
            metrics.packet_loss = self._measure_packet_loss(target_host)
            
            # Determine overall condition
            metrics.condition = self._determine_condition(metrics)
            metrics.last_measured = current_time
            
            # Cache results
            self.metrics_cache[cache_key] = metrics
            
        except Exception as e:
            logging.error(f"Network analysis failed: {e}")
            metrics.condition = NetworkCondition.CRITICAL
        
        return metrics
    
    def _measure_latency(self, host: str) -> float:
        """Measure network latency."""
        try:
            import time
            start_time = time.time()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(NETWORK_VALIDATION_TIMEOUT)
            
            result = sock.connect_ex((host, 53))  # DNS port
            sock.close()
            
            end_time = time.time()
            
            if result == 0:
                return (end_time - start_time) * 1000  # Convert to ms
            else:
                return 9999.0  # High latency for failed connections
                
        except Exception:
            return 9999.0
    
    def _estimate_bandwidth(self) -> float:
        """Estimate available bandwidth using multiple measurement techniques."""
        try:
            bandwidth_estimates = []
            
            # Method 1: Use speedtest-cli if available
            speedtest_result = self._measure_bandwidth_speedtest()
            if speedtest_result > 0:
                bandwidth_estimates.append(speedtest_result)
            
            # Method 2: Network interface statistics (Linux/Android)
            interface_bandwidth = self._estimate_bandwidth_from_interface()
            if interface_bandwidth > 0:
                bandwidth_estimates.append(interface_bandwidth)
            
            # Method 3: Simple download test
            download_bandwidth = self._measure_bandwidth_download_test()
            if download_bandwidth > 0:
                bandwidth_estimates.append(download_bandwidth)
            
            # Method 4: TCP throughput test
            tcp_bandwidth = self._measure_tcp_throughput()
            if tcp_bandwidth > 0:
                bandwidth_estimates.append(tcp_bandwidth)
            
            # Calculate conservative estimate
            if bandwidth_estimates:
                # Use median to avoid outliers
                bandwidth_estimates.sort()
                n = len(bandwidth_estimates)
                if n % 2 == 0:
                    estimated_bandwidth = (bandwidth_estimates[n//2-1] + bandwidth_estimates[n//2]) / 2
                else:
                    estimated_bandwidth = bandwidth_estimates[n//2]
                
                self.logger.info(f"Estimated bandwidth: {estimated_bandwidth:.1f} Mbps (from {n} measurements)")
                return max(1.0, min(estimated_bandwidth, 1000.0))  # Clamp between 1-1000 Mbps
            else:
                # Fallback: assume reasonable mobile connection
                self.logger.warning("Could not measure bandwidth, using fallback estimate")
                return 50.0  # Conservative mobile estimate
                
        except Exception as e:
            self.logger.error(f"Bandwidth estimation failed: {e}")
            return 25.0  # Conservative fallback
    
    def _measure_packet_loss(self, host: str = "8.8.8.8") -> float:
        """Measure packet loss percentage using ping tests."""
        try:
            # Method 1: Use ping command
            ping_loss = self._measure_packet_loss_ping(host)
            if ping_loss >= 0:
                return ping_loss
            
            # Method 2: TCP connection success rate
            tcp_loss = self._measure_packet_loss_tcp(host)
            if tcp_loss >= 0:
                return tcp_loss
            
            # Method 3: UDP echo test
            udp_loss = self._measure_packet_loss_udp(host)
            if udp_loss >= 0:
                return udp_loss
            
            # Fallback: assume no packet loss
            self.logger.warning("Could not measure packet loss, assuming 0%")
            return 0.0
            
        except Exception as e:
            self.logger.error(f"Packet loss measurement failed: {e}")
            return 1.0  # Conservative 1% loss assumption
    
    # Helper methods for bandwidth estimation
    def _measure_bandwidth_speedtest(self) -> float:
        """Measure bandwidth using speedtest-cli if available."""
        try:
            import subprocess
            result = subprocess.run(['speedtest-cli', '--simple'], 
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'Download:' in line:
                        # Parse "Download: XX.XX Mbit/s"
                        download_speed = float(line.split(':')[1].strip().split()[0])
                        self.logger.info(f"Speedtest download: {download_speed:.1f} Mbps")
                        return download_speed
            
            return 0.0
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            # speedtest-cli not available or failed
            return 0.0
        except Exception as e:
            self.logger.error(f"Speedtest measurement failed: {e}")
            return 0.0
    
    def _estimate_bandwidth_from_interface(self) -> float:
        """Estimate bandwidth from network interface statistics."""
        try:
            import subprocess
            import re
            
            # Try to get interface statistics on Linux/Android
            result = subprocess.run(['cat', '/proc/net/dev'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                max_bandwidth = 0.0
                
                for line in lines[2:]:  # Skip header lines
                    if ':' in line:
                        parts = line.split(':')
                        interface = parts[0].strip()
                        
                        # Skip loopback and other virtual interfaces
                        if interface in ['lo', 'sit0', 'tunl0']:
                            continue
                        
                        # Estimate based on interface type
                        if 'wlan' in interface or 'wifi' in interface:
                            max_bandwidth = max(max_bandwidth, 100.0)  # WiFi estimate
                        elif 'rmnet' in interface or 'ccmni' in interface:
                            max_bandwidth = max(max_bandwidth, 50.0)   # Mobile data estimate
                        elif 'eth' in interface:
                            max_bandwidth = max(max_bandwidth, 1000.0) # Ethernet estimate
                
                if max_bandwidth > 0:
                    self.logger.info(f"Interface-based bandwidth estimate: {max_bandwidth:.1f} Mbps")
                    return max_bandwidth
            
            return 0.0
            
        except Exception as e:
            self.logger.error(f"Interface bandwidth estimation failed: {e}")
            return 0.0
    
    def _measure_bandwidth_download_test(self) -> float:
        """Measure bandwidth with a simple download test."""
        try:
            import time
            import urllib.request
            import threading
            
            # Test with a small file download
            test_url = "http://httpbin.org/bytes/1048576"  # 1MB test file
            
            start_time = time.time()
            
            # Set a timeout for the download
            request = urllib.request.Request(test_url)
            request.add_header('User-Agent', 'AODS-NetworkTest/1.0')
            
            with urllib.request.urlopen(request, timeout=10) as response:
                data = response.read()
                download_size = len(data)
            
            end_time = time.time()
            duration = end_time - start_time
            
            if duration > 0 and download_size > 0:
                # Calculate bandwidth in Mbps
                bandwidth_mbps = (download_size * 8) / (duration * 1000000)
                self.logger.info(f"Download test bandwidth: {bandwidth_mbps:.1f} Mbps")
                return bandwidth_mbps
            
            return 0.0
            
        except Exception as e:
            self.logger.error(f"Download test failed: {e}")
            return 0.0
    
    def _measure_tcp_throughput(self) -> float:
        """Measure TCP throughput to estimate bandwidth."""
        try:
            import socket
            import time
            
            # Simple TCP throughput test
            test_data = b'A' * 65536  # 64KB test data
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            start_time = time.time()
            
            try:
                # Connect to a reliable host
                sock.connect(('httpbin.org', 80))
                
                # Send some data
                bytes_sent = sock.send(test_data)
                
                end_time = time.time()
                duration = end_time - start_time
                
                if duration > 0 and bytes_sent > 0:
                    # Calculate bandwidth in Mbps
                    bandwidth_mbps = (bytes_sent * 8) / (duration * 1000000)
                    self.logger.info(f"TCP throughput: {bandwidth_mbps:.1f} Mbps")
                    return min(bandwidth_mbps, 1000.0)  # Cap at 1Gbps
                
            finally:
                sock.close()
            
            return 0.0
            
        except Exception as e:
            self.logger.error(f"TCP throughput test failed: {e}")
            return 0.0
    
    # Helper methods for packet loss measurement
    def _measure_packet_loss_ping(self, host: str) -> float:
        """Measure packet loss using ping command."""
        try:
            import subprocess
            import re
            
            # Run ping test with 10 packets
            ping_cmd = ['ping', '-c', '10', '-W', '2', host]
            result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Look for packet loss statistics
                loss_pattern = r'(\d+)% packet loss'
                match = re.search(loss_pattern, output)
                
                if match:
                    packet_loss = float(match.group(1))
                    self.logger.info(f"Ping packet loss to {host}: {packet_loss}%")
                    return packet_loss
            
            return -1.0  # Indicate failure
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            return -1.0
        except Exception as e:
            self.logger.error(f"Ping packet loss measurement failed: {e}")
            return -1.0
    
    def _measure_packet_loss_tcp(self, host: str) -> float:
        """Measure packet loss by TCP connection success rate."""
        try:
            import socket
            import time
            
            total_attempts = 10
            successful_connections = 0
            
            for _ in range(total_attempts):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    
                    start_time = time.time()
                    result = sock.connect_ex((host, 80))
                    
                    if result == 0:
                        successful_connections += 1
                    
                    sock.close()
                    time.sleep(0.1)  # Small delay between attempts
                    
                except Exception:
                    pass
            
            if total_attempts > 0:
                success_rate = successful_connections / total_attempts
                packet_loss = (1 - success_rate) * 100
                self.logger.info(f"TCP connection success rate to {host}: {success_rate:.1%} (loss: {packet_loss:.1f}%)")
                return packet_loss
            
            return -1.0
            
        except Exception as e:
            self.logger.error(f"TCP packet loss measurement failed: {e}")
            return -1.0
    
    def _measure_packet_loss_udp(self, host: str) -> float:
        """Measure packet loss using UDP echo test."""
        try:
            import socket
            import time
            
            total_packets = 10
            received_packets = 0
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            
            for i in range(total_packets):
                try:
                    test_data = f"AODS-TEST-{i}".encode()
                    
                    # Send to DNS port (should get some response or ICMP)
                    sock.sendto(test_data, (host, 53))
                    
                    try:
                        # Try to receive response (or timeout)
                        data, addr = sock.recvfrom(1024)
                        received_packets += 1
                    except socket.timeout:
                        pass  # Expected for many UDP services
                    
                    time.sleep(0.1)
                    
                except Exception:
                    pass
            
            sock.close()
            
            if total_packets > 0:
                packet_loss = ((total_packets - received_packets) / total_packets) * 100
                self.logger.info(f"UDP packet loss to {host}: {packet_loss:.1f}%")
                return packet_loss
            
            return -1.0
            
        except Exception as e:
            self.logger.error(f"UDP packet loss measurement failed: {e}")
            return -1.0

class SecurityValidator:
    """Validates security aspects of Drozer configurations."""
    
    def __init__(self):
        self.default_whitelist = [
            "run", "list", "module", "info", "shell", "exit", "quit"
        ]
        self.dangerous_commands = [
            "rm", "del", "format", "dd", "fdisk", "mkfs", "chmod 777"
        ]
    
    def validate_configuration(self, config: DrozerConfiguration) -> Tuple[bool, List[str]]:
        """Validate security aspects of configuration."""
        issues = []
        
        # Check security policy
        if not config.security_policy.command_validation:
            issues.append("Command validation is disabled")
        
        if not config.security_policy.path_validation:
            issues.append("Path validation is disabled")
        
        if config.config_type == ConfigurationType.PRODUCTION:
            if not config.security_policy.whitelist_enabled:
                issues.append("Command whitelist should be enabled in production")
            
            if not config.security_policy.log_all_commands:
                issues.append("Command logging should be enabled in production")
        
        # Check for dangerous settings
        if config.security_policy.sandbox_mode and config.config_type == ConfigurationType.PRODUCTION:
            issues.append("Sandbox mode should not be used in production")
        
        # Validate command lists
        for cmd in config.security_policy.allowed_commands:
            if cmd in self.dangerous_commands:
                issues.append(f"Dangerous command '{cmd}' in whitelist")
        
        return len(issues) == 0, issues
    
    def sanitize_command(self, command: str, policy: SecurityPolicy) -> Tuple[str, bool]:
        """Sanitize and validate a command."""
        if not policy.command_validation:
            return command, True
        
        # Length check
        if len(command) > policy.max_command_length:
            return "", False
        
        # Whitelist check
        if policy.whitelist_enabled:
            cmd_parts = command.split()
            if cmd_parts and cmd_parts[0] not in policy.allowed_commands:
                return "", False
        
        # Dangerous command check
        for dangerous in self.dangerous_commands:
            if dangerous in command.lower():
                return "", False
        
        # Path validation
        if policy.path_validation:
            if "../" in command or "..\\" in command:
                return "", False
        
        return command, True

class ConfigurationTemplateManager:
    """Manages configuration templates for different scenarios."""
    
    def __init__(self):
        self.templates = self._initialize_templates()
    
    def _initialize_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize built-in configuration templates."""
        return {
            "development": {
                "security_policy": {
                    "command_validation": True,
                    "path_validation": True,
                    "network_validation": False,
                    "sandbox_mode": True,
                    "whitelist_enabled": False,
                    "log_all_commands": True
                },
                "performance_config": {
                    "connection_timeout": 30,
                    "command_timeout": 60,
                    "retry_attempts": 2,
                    "enable_caching": True
                }
            },
            "testing": {
                "security_policy": {
                    "command_validation": True,
                    "path_validation": True,
                    "network_validation": True,
                    "sandbox_mode": True,
                    "whitelist_enabled": True,
                    "log_all_commands": True
                },
                "performance_config": {
                    "connection_timeout": 45,
                    "command_timeout": 75,
                    "retry_attempts": 3,
                    "enable_caching": True
                }
            },
            "production": {
                "security_policy": {
                    "command_validation": True,
                    "path_validation": True,
                    "network_validation": True,
                    "sandbox_mode": False,
                    "whitelist_enabled": True,
                    "log_all_commands": True
                },
                "performance_config": {
                    "connection_timeout": 60,
                    "command_timeout": 90,
                    "retry_attempts": 3,
                    "enable_caching": True
                }
            },
            "enterprise": {
                "security_policy": {
                    "command_validation": True,
                    "path_validation": True,
                    "network_validation": True,
                    "sandbox_mode": False,
                    "whitelist_enabled": True,
                    "log_all_commands": True,
                    "max_command_length": 500
                },
                "performance_config": {
                    "connection_timeout": 90,
                    "command_timeout": 120,
                    "retry_attempts": 5,
                    "enable_caching": True,
                    "connection_pool_size": 10
                }
            }
        }
    
    def get_template(self, template_name: str) -> Optional[Dict[str, Any]]:
        """Get a configuration template."""
        return self.templates.get(template_name)
    
    def create_custom_template(self, name: str, template_data: Dict[str, Any]) -> None:
        """Create a custom configuration template."""
        self.templates[name] = template_data
    
    def apply_template(self, config: DrozerConfiguration, template_name: str) -> bool:
        """Apply a template to a configuration."""
        template = self.get_template(template_name)
        if not template:
            return False
        
        # Apply security policy
        if "security_policy" in template:
            for key, value in template["security_policy"].items():
                setattr(config.security_policy, key, value)
        
        # Apply performance config
        if "performance_config" in template:
            for key, value in template["performance_config"].items():
                setattr(config.performance_config, key, value)
        
        config.last_updated = time.time()
        return True

class EnhancedDrozerConfigManager:
    """Enhanced Drozer configuration management system."""
    
    def __init__(self):
        self.device_manager = DeviceManager()
        self.network_analyzer = NetworkAnalyzer()
        self.security_validator = SecurityValidator()
        self.template_manager = ConfigurationTemplateManager()
        self.configurations: Dict[str, DrozerConfiguration] = {}
        self.active_config: Optional[DrozerConfiguration] = None
        self.monitoring_enabled = True
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Setup enhanced logging."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def create_configuration(self, config_type: ConfigurationType, 
                           device_requirements: Optional[Dict[str, Any]] = None) -> DrozerConfiguration:
        """Create a new Drozer configuration."""
        # Discover devices
        devices = self.device_manager.discover_devices()
        selected_device = self.device_manager.get_best_device(device_requirements)
        
        # Analyze network
        network_metrics = self.network_analyzer.analyze_network_conditions()
        
        # Create configuration
        config = DrozerConfiguration(config_type=config_type)
        config.device_info = selected_device
        config.network_metrics = network_metrics
        
        # Apply template
        template_name = config_type.value
        self.template_manager.apply_template(config, template_name)
        
        # Adapt to conditions
        self._adapt_to_conditions(config)
        
        # Validate configuration
        is_valid, issues = self.security_validator.validate_configuration(config)
        if not is_valid:
            self.logger.warning(f"Configuration validation issues: {issues}")
        
        # Store configuration
        config_id = f"{config_type.value}_{int(time.time())}"
        self.configurations[config_id] = config
        
        self.logger.info(f"Created configuration: {config_id}")
        return config
    
    def _adapt_to_conditions(self, config: DrozerConfiguration) -> None:
        """Adapt configuration based on device and network conditions."""
        if not config.network_metrics:
            return
        
        # Adjust timeouts based on network conditions
        if config.network_metrics.condition in [NetworkCondition.POOR, NetworkCondition.CRITICAL]:
            config.performance_config.connection_timeout *= 2
            config.performance_config.command_timeout *= 2
            config.performance_config.retry_attempts += 2
        elif config.network_metrics.condition == NetworkCondition.EXCELLENT:
            config.performance_config.connection_timeout = int(config.performance_config.connection_timeout * 0.8)
            config.performance_config.command_timeout = int(config.performance_config.command_timeout * 0.8)
        
        # Adjust based on device performance
        if config.device_info and config.device_info.performance_score < 0.5:
            config.performance_config.max_concurrent_operations = 1
            config.performance_config.connection_pool_size = 2
    
    def get_optimized_configuration(self, requirements: Dict[str, Any]) -> Optional[DrozerConfiguration]:
        """Get an optimized configuration for specific requirements."""
        config_type = ConfigurationType(requirements.get("type", "development"))
        device_reqs = requirements.get("device_requirements")
        
        return self.create_configuration(config_type, device_reqs)
    
    def monitor_and_adapt(self) -> None:
        """Monitor conditions and adapt configurations."""
        if not self.monitoring_enabled:
            return
        
        # Update device information
        self.device_manager.discover_devices(force_refresh=True)
        
        # Update network metrics
        network_metrics = self.network_analyzer.analyze_network_conditions()
        
        # Adapt active configuration if needed
        if self.active_config:
            old_condition = self.active_config.network_metrics.condition if self.active_config.network_metrics else NetworkCondition.UNKNOWN
            self.active_config.network_metrics = network_metrics
            
            if old_condition != network_metrics.condition:
                self._adapt_to_conditions(self.active_config)
                self.logger.info(f"Adapted configuration to network condition: {network_metrics.condition.value}")

# Legacy compatibility functions
def get_default_drozer_config():
    """Get standardized drozer configuration (legacy compatibility)."""
    return {
        "connection_settings": {
            "drozer_port": DROZER_PORT,
            "adb_port": ADB_PORT,
            "connection_timeout": DROZER_CONNECTION_TIMEOUT,
            "command_timeout": DROZER_COMMAND_TIMEOUT
        },
        "reconnection_strategy": {
            "max_reconnection_attempts": MAX_RECONNECTION_ATTEMPTS,
            "reconnection_delay": RECONNECTION_DELAY,
            "persistent_mode": True,
            "force_reconnect_every_command": False
        },
        "security_settings": {
            "enable_command_validation": ENABLE_COMMAND_VALIDATION,
            "enable_path_validation": ENABLE_PATH_VALIDATION,
            "enable_network_validation": ENABLE_NETWORK_VALIDATION,
            "log_security_events": LOG_SECURITY_EVENTS
        }
    }

def get_production_drozer_config():
    """Get production-optimized drozer configuration (legacy compatibility)."""
    manager = EnhancedDrozerConfigManager()
    config = manager.create_configuration(ConfigurationType.PRODUCTION)
    
    # Convert to legacy format
    return {
        "connection_settings": {
            "drozer_port": DROZER_PORT,
            "adb_port": ADB_PORT,
            "connection_timeout": config.performance_config.connection_timeout,
            "command_timeout": config.performance_config.command_timeout
        },
        "reconnection_strategy": {
            "max_reconnection_attempts": config.performance_config.retry_attempts,
            "reconnection_delay": config.performance_config.retry_delay,
            "persistent_mode": True,
            "force_reconnect_every_command": False
        },
        "security_settings": {
            "enable_command_validation": config.security_policy.command_validation,
            "enable_path_validation": config.security_policy.path_validation,
            "enable_network_validation": config.security_policy.network_validation,
            "log_security_events": config.security_policy.log_all_commands
        }
    }

def get_enterprise_drozer_config():
    """Get enterprise-grade drozer configuration (legacy compatibility)."""
    manager = EnhancedDrozerConfigManager()
    config = manager.create_configuration(ConfigurationType.ENTERPRISE)
    
    # Convert to legacy format
    return {
        "connection_settings": {
            "drozer_port": DROZER_PORT,
            "adb_port": ADB_PORT,
            "connection_timeout": config.performance_config.connection_timeout,
            "command_timeout": config.performance_config.command_timeout
        },
        "reconnection_strategy": {
            "max_reconnection_attempts": config.performance_config.retry_attempts,
            "reconnection_delay": config.performance_config.retry_delay,
            "persistent_mode": True,
            "force_reconnect_every_command": False
        },
        "security_settings": {
            "enable_command_validation": config.security_policy.command_validation,
            "enable_path_validation": config.security_policy.path_validation,
            "enable_network_validation": config.security_policy.network_validation,
            "log_security_events": config.security_policy.log_all_commands
        }
    }

# Global configuration manager instance
_config_manager = None

def get_config_manager() -> EnhancedDrozerConfigManager:
    """Get the global configuration manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = EnhancedDrozerConfigManager()
    return _config_manager
