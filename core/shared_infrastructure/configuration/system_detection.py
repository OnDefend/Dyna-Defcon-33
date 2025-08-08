#!/usr/bin/env python3
"""
System Detection Framework for AODS Shared Infrastructure

Provides comprehensive hardware capability detection, operating system analysis,
and environment assessment for intelligent configuration optimization.

Features:
- Hardware capability detection (CPU, memory, storage)
- Operating system and distribution identification
- Container and virtualization detection
- Network and security environment analysis
- Performance baseline establishment
- Resource availability assessment
- Android development environment detection
- Security tool availability detection

This component enables AODS to automatically adapt its configuration
based on the runtime environment for optimal performance and capability.
"""

import os
import sys
import platform
import subprocess
import logging
import psutil
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import json
import re
import time

logger = logging.getLogger(__name__)

class OSType(Enum):
    """Supported operating system types."""
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    UNKNOWN = "unknown"

class VirtualizationType(Enum):
    """Virtualization environment types."""
    BARE_METAL = "bare_metal"
    DOCKER = "docker"
    LXC = "lxc"
    VM_VMWARE = "vmware"
    VM_VIRTUALBOX = "virtualbox"
    VM_KVM = "kvm"
    WSL = "wsl"
    UNKNOWN = "unknown"

class SecurityEnvironment(Enum):
    """Security analysis environment types."""
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    TESTING = "testing"
    SANDBOX = "sandbox"
    KALI_LINUX = "kali_linux"
    UNKNOWN = "unknown"

@dataclass
class HardwareCapabilities:
    """Hardware capability information."""
    cpu_count: int
    cpu_frequency: float  # GHz
    memory_total_gb: float
    memory_available_gb: float
    storage_available_gb: float
    storage_type: str  # SSD, HDD, or mixed
    is_64bit: bool
    has_hardware_virtualization: bool
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'cpu_count': self.cpu_count,
            'cpu_frequency': self.cpu_frequency,
            'memory_total_gb': self.memory_total_gb,
            'memory_available_gb': self.memory_available_gb,
            'storage_available_gb': self.storage_available_gb,
            'storage_type': self.storage_type,
            'is_64bit': self.is_64bit,
            'has_hardware_virtualization': self.has_hardware_virtualization
        }

@dataclass
class SystemEnvironment:
    """Complete system environment information."""
    os_type: OSType
    os_version: str
    distribution: str
    virtualization_type: VirtualizationType
    security_environment: SecurityEnvironment
    python_version: str
    working_directory: Path
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'os_type': self.os_type.value,
            'os_version': self.os_version,
            'distribution': self.distribution,
            'virtualization_type': self.virtualization_type.value,
            'security_environment': self.security_environment.value,
            'python_version': self.python_version,
            'working_directory': str(self.working_directory)
        }

@dataclass
class AndroidEnvironment:
    """Android development environment capabilities."""
    has_adb: bool
    adb_version: str
    has_aapt: bool
    aapt_version: str
    has_jadx: bool
    jadx_version: str
    has_frida: bool
    frida_version: str
    has_emulator: bool
    connected_devices: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'has_adb': self.has_adb,
            'adb_version': self.adb_version,
            'has_aapt': self.has_aapt,
            'aapt_version': self.aapt_version,
            'has_jadx': self.has_jadx,
            'jadx_version': self.jadx_version,
            'has_frida': self.has_frida,
            'frida_version': self.frida_version,
            'has_emulator': self.has_emulator,
            'connected_devices': self.connected_devices
        }

@dataclass
class PerformanceCharacteristics:
    """System performance characteristics."""
    disk_io_speed: float  # MB/s
    memory_bandwidth: float  # GB/s
    cpu_benchmark_score: float
    network_available: bool
    network_speed: Optional[float] = None  # Mbps
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'disk_io_speed': self.disk_io_speed,
            'memory_bandwidth': self.memory_bandwidth,
            'cpu_benchmark_score': self.cpu_benchmark_score,
            'network_available': self.network_available,
            'network_speed': self.network_speed
        }

class SystemDetector:
    """
    Comprehensive system detection and capability assessment.
    
    Provides detailed analysis of hardware, software, and environment
    characteristics for intelligent AODS configuration optimization.
    """
    
    def __init__(self):
        """Initialize system detector."""
        self.logger = logging.getLogger(__name__)
        self.cache_timeout = 300  # 5 minutes
        self._cache = {}
        self._cache_timestamps = {}
        
        self.logger.info("System detector initialized")
    
    def get_complete_system_profile(self) -> Dict[str, Any]:
        """
        Get complete system profile with all capabilities.
        
        Returns:
            Dictionary containing complete system analysis
        """
        if self._is_cached('complete_profile'):
            return self._get_cached('complete_profile')
        
        try:
            profile = {
                'hardware': self.detect_hardware_capabilities().to_dict(),
                'environment': self.detect_system_environment().to_dict(),
                'android': self.detect_android_environment().to_dict(),
                'performance': self.assess_performance_characteristics().to_dict(),
                'security_tools': self.detect_security_tools(),
                'recommendations': self.generate_configuration_recommendations()
            }
            
            self._cache_result('complete_profile', profile)
            return profile
            
        except Exception as e:
            self.logger.error(f"Failed to generate complete system profile: {e}")
            return self._get_fallback_profile()
    
    def detect_hardware_capabilities(self) -> HardwareCapabilities:
        """Detect hardware capabilities and specifications."""
        if self._is_cached('hardware'):
            return self._get_cached('hardware')
        
        try:
            # CPU information
            cpu_count = psutil.cpu_count(logical=True)
            cpu_freq = psutil.cpu_freq()
            cpu_frequency = cpu_freq.current / 1000.0 if cpu_freq else 2.0  # Default 2 GHz
            
            # Memory information
            memory = psutil.virtual_memory()
            memory_total_gb = memory.total / (1024**3)
            memory_available_gb = memory.available / (1024**3)
            
            # Storage information
            disk_usage = psutil.disk_usage('/')
            storage_available_gb = disk_usage.free / (1024**3)
            storage_type = self._detect_storage_type()
            
            # Architecture information
            is_64bit = platform.machine().endswith('64') or sys.maxsize > 2**32
            
            # Hardware virtualization
            has_hw_virt = self._detect_hardware_virtualization()
            
            capabilities = HardwareCapabilities(
                cpu_count=cpu_count,
                cpu_frequency=cpu_frequency,
                memory_total_gb=memory_total_gb,
                memory_available_gb=memory_available_gb,
                storage_available_gb=storage_available_gb,
                storage_type=storage_type,
                is_64bit=is_64bit,
                has_hardware_virtualization=has_hw_virt
            )
            
            self._cache_result('hardware', capabilities)
            return capabilities
            
        except Exception as e:
            self.logger.error(f"Hardware detection failed: {e}")
            return self._get_fallback_hardware()
    
    def detect_system_environment(self) -> SystemEnvironment:
        """Detect system environment and configuration."""
        if self._is_cached('environment'):
            return self._get_cached('environment')
        
        try:
            # Operating system detection
            os_type = self._detect_os_type()
            os_version = platform.version()
            distribution = self._detect_distribution()
            
            # Virtualization detection
            virtualization_type = self._detect_virtualization()
            
            # Security environment detection
            security_environment = self._detect_security_environment()
            
            # Python environment
            python_version = platform.python_version()
            
            # Working directory
            working_directory = Path.cwd()
            
            environment = SystemEnvironment(
                os_type=os_type,
                os_version=os_version,
                distribution=distribution,
                virtualization_type=virtualization_type,
                security_environment=security_environment,
                python_version=python_version,
                working_directory=working_directory
            )
            
            self._cache_result('environment', environment)
            return environment
            
        except Exception as e:
            self.logger.error(f"Environment detection failed: {e}")
            return self._get_fallback_environment()
    
    def detect_android_environment(self) -> AndroidEnvironment:
        """Detect Android development environment capabilities."""
        if self._is_cached('android'):
            return self._get_cached('android')
        
        try:
            # ADB detection
            has_adb, adb_version = self._check_tool_version('adb', ['version'])
            
            # AAPT detection
            has_aapt, aapt_version = self._check_tool_version('aapt', ['version'])
            
            # JADX detection
            has_jadx, jadx_version = self._check_tool_version('jadx', ['--version'])
            
            # Frida detection
            has_frida, frida_version = self._check_frida()
            
            # Android Emulator detection
            has_emulator = shutil.which('emulator') is not None
            
            # Connected devices
            connected_devices = self._get_connected_devices() if has_adb else []
            
            android_env = AndroidEnvironment(
                has_adb=has_adb,
                adb_version=adb_version,
                has_aapt=has_aapt,
                aapt_version=aapt_version,
                has_jadx=has_jadx,
                jadx_version=jadx_version,
                has_frida=has_frida,
                frida_version=frida_version,
                has_emulator=has_emulator,
                connected_devices=connected_devices
            )
            
            self._cache_result('android', android_env)
            return android_env
            
        except Exception as e:
            self.logger.error(f"Android environment detection failed: {e}")
            return self._get_fallback_android_environment()
    
    def assess_performance_characteristics(self) -> PerformanceCharacteristics:
        """Assess system performance characteristics."""
        if self._is_cached('performance'):
            return self._get_cached('performance')
        
        try:
            # Disk I/O speed assessment
            disk_io_speed = self._benchmark_disk_io()
            
            # Memory bandwidth estimation
            memory_bandwidth = self._estimate_memory_bandwidth()
            
            # CPU benchmark
            cpu_benchmark_score = self._benchmark_cpu()
            
            # Network availability
            network_available = self._check_network_connectivity()
            network_speed = self._estimate_network_speed() if network_available else None
            
            performance = PerformanceCharacteristics(
                disk_io_speed=disk_io_speed,
                memory_bandwidth=memory_bandwidth,
                cpu_benchmark_score=cpu_benchmark_score,
                network_available=network_available,
                network_speed=network_speed
            )
            
            self._cache_result('performance', performance)
            return performance
            
        except Exception as e:
            self.logger.error(f"Performance assessment failed: {e}")
            return self._get_fallback_performance()
    
    def detect_security_tools(self) -> Dict[str, Any]:
        """Detect available security analysis tools."""
        if self._is_cached('security_tools'):
            return self._get_cached('security_tools')
        
        try:
            tools = {}
            
            # Static analysis tools
            tools['static_analysis'] = {
                'jadx': shutil.which('jadx') is not None,
                'apktool': shutil.which('apktool') is not None,
                'dex2jar': shutil.which('dex2jar') is not None,
                'baksmali': shutil.which('baksmali') is not None
            }
            
            # Dynamic analysis tools
            tools['dynamic_analysis'] = {
                'frida': self._check_frida()[0],
                'gdb': shutil.which('gdb') is not None,
                'strace': shutil.which('strace') is not None,
                'ltrace': shutil.which('ltrace') is not None
            }
            
            # Network analysis tools
            tools['network_analysis'] = {
                'tcpdump': shutil.which('tcpdump') is not None,
                'wireshark': shutil.which('wireshark') is not None or shutil.which('tshark') is not None,
                'netstat': shutil.which('netstat') is not None,
                'ss': shutil.which('ss') is not None
            }
            
            # Android tools
            tools['android_tools'] = {
                'adb': shutil.which('adb') is not None,
                'aapt': shutil.which('aapt') is not None,
                'fastboot': shutil.which('fastboot') is not None
            }
            
            self._cache_result('security_tools', tools)
            return tools
            
        except Exception as e:
            self.logger.error(f"Security tools detection failed: {e}")
            return {}
    
    def generate_configuration_recommendations(self) -> Dict[str, Any]:
        """Generate configuration recommendations based on system analysis."""
        try:
            hardware = self.detect_hardware_capabilities()
            environment = self.detect_system_environment()
            android = self.detect_android_environment()
            performance = self.assess_performance_characteristics()
            
            recommendations = {
                'performance': self._recommend_performance_settings(hardware, performance),
                'analysis': self._recommend_analysis_settings(android, environment),
                'parallel_processing': self._recommend_parallel_settings(hardware),
                'memory_management': self._recommend_memory_settings(hardware),
                'timeout_settings': self._recommend_timeout_settings(performance)
            }
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Failed to generate recommendations: {e}")
            return {}
    
    def _detect_os_type(self) -> OSType:
        """Detect operating system type."""
        system = platform.system().lower()
        if system == 'linux':
            return OSType.LINUX
        elif system == 'windows':
            return OSType.WINDOWS
        elif system == 'darwin':
            return OSType.MACOS
        else:
            return OSType.UNKNOWN
    
    def _detect_distribution(self) -> str:
        """Detect Linux distribution or OS details."""
        try:
            if platform.system().lower() == 'linux':
                # Check for WSL
                if self._is_wsl():
                    return "WSL"
                
                # Check for Kali Linux
                if Path('/etc/kali-version').exists():
                    return "Kali Linux"
                
                # Try to read distribution info
                if Path('/etc/os-release').exists():
                    with open('/etc/os-release', 'r') as f:
                        content = f.read()
                        if 'NAME=' in content:
                            for line in content.split('\n'):
                                if line.startswith('NAME='):
                                    return line.split('=')[1].strip('"')
                
                # Fallback to platform detection
                return platform.platform()
            else:
                return platform.platform()
                
        except Exception:
            return platform.system()
    
    def _detect_virtualization(self) -> VirtualizationType:
        """Detect virtualization environment."""
        try:
            # Check for WSL
            if self._is_wsl():
                return VirtualizationType.WSL
            
            # Check for Docker
            if Path('/.dockerenv').exists():
                return VirtualizationType.DOCKER
            
            # Check for LXC
            if Path('/proc/1/cgroup').exists():
                with open('/proc/1/cgroup', 'r') as f:
                    if 'lxc' in f.read():
                        return VirtualizationType.LXC
            
            # Check DMI information for VM detection
            try:
                result = subprocess.run(['dmidecode', '-s', 'system-product-name'], 
                                     capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    product_name = result.stdout.strip().lower()
                    if 'vmware' in product_name:
                        return VirtualizationType.VM_VMWARE
                    elif 'virtualbox' in product_name:
                        return VirtualizationType.VM_VIRTUALBOX
                    elif 'kvm' in product_name:
                        return VirtualizationType.VM_KVM
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            return VirtualizationType.BARE_METAL
            
        except Exception:
            return VirtualizationType.UNKNOWN
    
    def _detect_security_environment(self) -> SecurityEnvironment:
        """Detect security analysis environment type."""
        try:
            # Check for Kali Linux
            if Path('/etc/kali-version').exists():
                return SecurityEnvironment.KALI_LINUX
            
            # Check environment variables
            env_type = os.environ.get('AODS_ENVIRONMENT', '').lower()
            if env_type == 'production':
                return SecurityEnvironment.PRODUCTION
            elif env_type == 'development':
                return SecurityEnvironment.DEVELOPMENT
            elif env_type == 'testing':
                return SecurityEnvironment.TESTING
            elif env_type == 'sandbox':
                return SecurityEnvironment.SANDBOX
            
            # Heuristic detection based on working directory
            cwd = Path.cwd()
            if any(keyword in str(cwd).lower() for keyword in ['test', 'sandbox', 'lab']):
                return SecurityEnvironment.TESTING
            elif any(keyword in str(cwd).lower() for keyword in ['dev', 'development']):
                return SecurityEnvironment.DEVELOPMENT
            
            return SecurityEnvironment.UNKNOWN
            
        except Exception:
            return SecurityEnvironment.UNKNOWN
    
    def _detect_storage_type(self) -> str:
        """Detect primary storage type."""
        try:
            # Linux-specific detection
            if platform.system().lower() == 'linux':
                try:
                    result = subprocess.run(['lsblk', '-o', 'NAME,ROTA'], 
                                         capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')[1:]  # Skip header
                        rota_values = [line.split()[-1] for line in lines if line.strip()]
                        
                        if '0' in rota_values and '1' in rota_values:
                            return 'mixed'
                        elif all(val == '0' for val in rota_values):
                            return 'SSD'
                        elif all(val == '1' for val in rota_values):
                            return 'HDD'
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass
            
            return 'unknown'
            
        except Exception:
            return 'unknown'
    
    def _detect_hardware_virtualization(self) -> bool:
        """Detect hardware virtualization support."""
        try:
            if platform.system().lower() == 'linux':
                # Check CPU flags
                with open('/proc/cpuinfo', 'r') as f:
                    content = f.read()
                    return 'vmx' in content or 'svm' in content
            return False
        except Exception:
            return False
    
    def _is_wsl(self) -> bool:
        """Check if running in Windows Subsystem for Linux."""
        try:
            with open('/proc/version', 'r') as f:
                return 'microsoft' in f.read().lower()
        except Exception:
            return False
    
    def _check_tool_version(self, tool: str, version_args: List[str]) -> Tuple[bool, str]:
        """Check if tool is available and get version."""
        try:
            if not shutil.which(tool):
                return False, ""
            
            result = subprocess.run([tool] + version_args, 
                                 capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                output = result.stdout + result.stderr
                # Extract version number
                version_match = re.search(r'\d+\.\d+(?:\.\d+)?', output)
                version = version_match.group(0) if version_match else "unknown"
                return True, version
            
            return True, "unknown"
            
        except Exception:
            return False, ""
    
    def _check_frida(self) -> Tuple[bool, str]:
        """Check Frida availability and version."""
        try:
            # Check frida-server
            has_server = shutil.which('frida-server') is not None
            
            # Check frida Python module
            try:
                import frida
                frida_version = frida.__version__
                return True, frida_version
            except ImportError:
                pass
            
            # Check frida command line tool
            if shutil.which('frida'):
                result = subprocess.run(['frida', '--version'], 
                                     capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return True, result.stdout.strip()
            
            return has_server, "unknown" if has_server else ""
            
        except Exception:
            return False, ""
    
    def _get_connected_devices(self) -> List[str]:
        """Get list of connected Android devices."""
        try:
            result = subprocess.run(['adb', 'devices'], 
                                 capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                devices = []
                for line in lines:
                    if line.strip() and '\tdevice' in line:
                        device_id = line.split('\t')[0]
                        devices.append(device_id)
                return devices
            
            return []
            
        except Exception:
            return []
    
    def _benchmark_disk_io(self) -> float:
        """Benchmark disk I/O speed (MB/s)."""
        try:
            # Simple write test
            test_file = Path('/tmp/aods_disk_test.tmp')
            test_data = b'0' * 1024 * 1024  # 1 MB
            
            start_time = time.time()
            with open(test_file, 'wb') as f:
                for _ in range(10):  # Write 10 MB
                    f.write(test_data)
                f.flush()
                os.fsync(f.fileno())
            end_time = time.time()
            
            # Clean up
            test_file.unlink(missing_ok=True)
            
            # Calculate speed
            elapsed = end_time - start_time
            if elapsed > 0:
                return 10.0 / elapsed  # MB/s
            
            return 100.0  # Default fallback
            
        except Exception:
            return 100.0  # Conservative estimate
    
    def _estimate_memory_bandwidth(self) -> float:
        """Estimate memory bandwidth (GB/s)."""
        try:
            # Simple memory copy test
            test_size = 1024 * 1024 * 10  # 10 MB
            test_data = bytearray(test_size)
            
            start_time = time.time()
            for _ in range(10):
                copy_data = test_data[:]
                del copy_data
            end_time = time.time()
            
            elapsed = end_time - start_time
            if elapsed > 0:
                # Calculate bandwidth (very rough estimate)
                bytes_copied = test_size * 10
                return (bytes_copied / elapsed) / (1024**3)  # GB/s
            
            return 5.0  # Default fallback
            
        except Exception:
            return 5.0  # Conservative estimate
    
    def _benchmark_cpu(self) -> float:
        """Simple CPU benchmark score."""
        try:
            # Simple calculation benchmark
            start_time = time.time()
            result = 0
            for i in range(100000):
                result += i * i
            end_time = time.time()
            
            elapsed = end_time - start_time
            if elapsed > 0:
                return 1.0 / elapsed  # Higher is better
            
            return 1000.0  # Default fallback
            
        except Exception:
            return 1000.0  # Conservative estimate
    
    def _check_network_connectivity(self) -> bool:
        """Check basic network connectivity."""
        try:
            import socket
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except Exception:
            return False
    
    def _estimate_network_speed(self) -> Optional[float]:
        """Estimate network speed (Mbps) - placeholder implementation."""
        # This would require actual speed testing, which is complex
        # For now, just indicate that network is available
        return None
    
    def _recommend_performance_settings(self, hardware: HardwareCapabilities, 
                                      performance: PerformanceCharacteristics) -> Dict[str, Any]:
        """Recommend performance settings based on hardware."""
        settings = {}
        
        # Cache size recommendations
        if hardware.memory_total_gb >= 16:
            settings['cache_size'] = 'large'
            settings['max_cache_entries'] = 10000
        elif hardware.memory_total_gb >= 8:
            settings['cache_size'] = 'medium'
            settings['max_cache_entries'] = 5000
        else:
            settings['cache_size'] = 'small'
            settings['max_cache_entries'] = 2000
        
        # I/O optimization
        if performance.disk_io_speed > 200:  # Fast SSD
            settings['io_optimization'] = 'aggressive'
            settings['batch_size'] = 'large'
        elif performance.disk_io_speed > 50:  # Regular SSD
            settings['io_optimization'] = 'moderate'
            settings['batch_size'] = 'medium'
        else:  # HDD
            settings['io_optimization'] = 'conservative'
            settings['batch_size'] = 'small'
        
        return settings
    
    def _recommend_analysis_settings(self, android: AndroidEnvironment, 
                                   environment: SystemEnvironment) -> Dict[str, Any]:
        """Recommend analysis settings based on environment."""
        settings = {}
        
        # Enable features based on tool availability
        settings['enable_static_analysis'] = android.has_jadx and android.has_aapt
        settings['enable_dynamic_analysis'] = android.has_frida and android.has_adb
        settings['enable_network_analysis'] = len(android.connected_devices) > 0
        
        # Environment-specific settings
        if environment.security_environment == SecurityEnvironment.KALI_LINUX:
            settings['security_mode'] = 'enhanced'
            settings['enable_advanced_features'] = True
        else:
            settings['security_mode'] = 'standard'
            settings['enable_advanced_features'] = False
        
        return settings
    
    def _recommend_parallel_settings(self, hardware: HardwareCapabilities) -> Dict[str, Any]:
        """Recommend parallel processing settings."""
        settings = {}
        
        # Worker thread recommendations
        if hardware.cpu_count >= 16:
            settings['max_workers'] = min(hardware.cpu_count - 2, 24)
            settings['parallel_strategy'] = 'aggressive'
        elif hardware.cpu_count >= 8:
            settings['max_workers'] = min(hardware.cpu_count - 1, 12)
            settings['parallel_strategy'] = 'moderate'
        elif hardware.cpu_count >= 4:
            settings['max_workers'] = min(hardware.cpu_count, 6)
            settings['parallel_strategy'] = 'conservative'
        else:
            settings['max_workers'] = 2
            settings['parallel_strategy'] = 'minimal'
        
        # Memory-based adjustments
        if hardware.memory_available_gb < 4:
            settings['max_workers'] = min(settings['max_workers'], 2)
            settings['parallel_strategy'] = 'minimal'
        
        return settings
    
    def _recommend_memory_settings(self, hardware: HardwareCapabilities) -> Dict[str, Any]:
        """Recommend memory management settings."""
        settings = {}
        
        # Memory allocation recommendations
        available_gb = hardware.memory_available_gb
        
        if available_gb >= 16:
            settings['max_memory_usage'] = '8GB'
            settings['memory_strategy'] = 'generous'
        elif available_gb >= 8:
            settings['max_memory_usage'] = '4GB'
            settings['memory_strategy'] = 'moderate'
        elif available_gb >= 4:
            settings['max_memory_usage'] = '2GB'
            settings['memory_strategy'] = 'conservative'
        else:
            settings['max_memory_usage'] = '1GB'
            settings['memory_strategy'] = 'minimal'
        
        # Garbage collection settings
        if available_gb >= 8:
            settings['gc_threshold'] = 'high'
        else:
            settings['gc_threshold'] = 'low'
        
        return settings
    
    def _recommend_timeout_settings(self, performance: PerformanceCharacteristics) -> Dict[str, Any]:
        """Recommend timeout settings based on performance."""
        settings = {}
        
        # Base timeouts on CPU performance
        base_factor = 1.0
        if performance.cpu_benchmark_score > 2000:
            base_factor = 0.7  # Faster system
        elif performance.cpu_benchmark_score < 500:
            base_factor = 1.5  # Slower system
        
        settings['analysis_timeout'] = int(300 * base_factor)  # seconds
        settings['command_timeout'] = int(60 * base_factor)
        settings['network_timeout'] = int(30 * base_factor)
        
        return settings
    
    def _get_fallback_hardware(self) -> HardwareCapabilities:
        """Get fallback hardware capabilities."""
        return HardwareCapabilities(
            cpu_count=4,
            cpu_frequency=2.0,
            memory_total_gb=8.0,
            memory_available_gb=4.0,
            storage_available_gb=100.0,
            storage_type='unknown',
            is_64bit=True,
            has_hardware_virtualization=False
        )
    
    def _get_fallback_environment(self) -> SystemEnvironment:
        """Get fallback system environment."""
        return SystemEnvironment(
            os_type=OSType.LINUX,
            os_version='unknown',
            distribution='unknown',
            virtualization_type=VirtualizationType.UNKNOWN,
            security_environment=SecurityEnvironment.UNKNOWN,
            python_version=platform.python_version(),
            working_directory=Path.cwd()
        )
    
    def _get_fallback_android_environment(self) -> AndroidEnvironment:
        """Get fallback Android environment."""
        return AndroidEnvironment(
            has_adb=False,
            adb_version="",
            has_aapt=False,
            aapt_version="",
            has_jadx=False,
            jadx_version="",
            has_frida=False,
            frida_version="",
            has_emulator=False,
            connected_devices=[]
        )
    
    def _get_fallback_performance(self) -> PerformanceCharacteristics:
        """Get fallback performance characteristics."""
        return PerformanceCharacteristics(
            disk_io_speed=100.0,
            memory_bandwidth=5.0,
            cpu_benchmark_score=1000.0,
            network_available=False
        )
    
    def _get_fallback_profile(self) -> Dict[str, Any]:
        """Get fallback system profile."""
        return {
            'hardware': self._get_fallback_hardware().to_dict(),
            'environment': self._get_fallback_environment().to_dict(),
            'android': self._get_fallback_android_environment().to_dict(),
            'performance': self._get_fallback_performance().to_dict(),
            'security_tools': {},
            'recommendations': {}
        }
    
    def _is_cached(self, key: str) -> bool:
        """Check if result is cached and not expired."""
        if key not in self._cache:
            return False
        
        timestamp = self._cache_timestamps.get(key, 0)
        return time.time() - timestamp < self.cache_timeout
    
    def _get_cached(self, key: str) -> Any:
        """Get cached result."""
        return self._cache.get(key)
    
    def _cache_result(self, key: str, result: Any) -> None:
        """Cache result with timestamp."""
        self._cache[key] = result
        self._cache_timestamps[key] = time.time()

# Global system detector instance
_system_detector = None

def get_system_detector() -> SystemDetector:
    """Get global system detector instance."""
    global _system_detector
    if _system_detector is None:
        _system_detector = SystemDetector()
    return _system_detector

def detect_system_profile() -> Dict[str, Any]:
    """Get complete system profile using global detector."""
    return get_system_detector().get_complete_system_profile()

def get_hardware_capabilities() -> HardwareCapabilities:
    """Get hardware capabilities using global detector."""
    return get_system_detector().detect_hardware_capabilities()

def get_android_environment() -> AndroidEnvironment:
    """Get Android environment using global detector."""
    return get_system_detector().detect_android_environment() 