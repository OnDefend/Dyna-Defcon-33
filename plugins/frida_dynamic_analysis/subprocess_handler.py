"""
Subprocess execution handler for Frida Dynamic Analysis Plugin.

This module provides robust subprocess execution with proper error handling,
caching, and timeout management for external tool interactions.
"""

import logging
import subprocess
import time
import threading
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

from .data_structures import SubprocessConfig, FridaTestResult, FridaTestCache

logger = logging.getLogger(__name__)

@dataclass
class SubprocessResult:
    """Result of subprocess execution with detailed information."""
    success: bool
    returncode: int
    stdout: str
    stderr: str
    execution_time: float
    command: List[str]
    error_message: Optional[str] = None
    timed_out: bool = False

class SubprocessHandler:
    """Handle subprocess execution with caching and error management."""
    
    def __init__(self, cache_ttl: int = 300):
        self.cache = FridaTestCache(ttl=cache_ttl)
        self._lock = threading.RLock()
    
    def execute_with_cache(self, config: SubprocessConfig, cache_key: Optional[str] = None) -> SubprocessResult:
        """Execute subprocess with caching support."""
        # Check cache if key provided
        if cache_key:
            cached_result = self.cache.get(cache_key)
            if cached_result and cached_result.subprocess_result:
                logger.debug(f"Using cached subprocess result for {cache_key}")
                return SubprocessResult(**cached_result.subprocess_result)
        
        # Execute subprocess
        result = self.execute(config)
        
        # Cache result if key provided and successful
        if cache_key and result.success:
            test_result = FridaTestResult(
                test_type=None,  # Not applicable for subprocess
                status=None,     # Not applicable for subprocess
                success=result.success,
                evidence={},
                subprocess_result=result.__dict__
            )
            self.cache.set(cache_key, test_result)
        
        return result
    
    def execute(self, config: SubprocessConfig) -> SubprocessResult:
        """Execute subprocess with robust error handling."""
        start_time = time.time()
        
        try:
            logger.debug(f"Executing command: {' '.join(config.command)}")
            
            # Execute subprocess with timeout
            process = subprocess.run(
                config.command,
                capture_output=config.capture_output,
                text=config.text,
                timeout=config.timeout,
                shell=config.shell,
                cwd=config.cwd,
                env=config.env
            )
            
            execution_time = time.time() - start_time
            
            return SubprocessResult(
                success=process.returncode == 0,
                returncode=process.returncode,
                stdout=process.stdout or "",
                stderr=process.stderr or "",
                execution_time=execution_time,
                command=config.command
            )
            
        except subprocess.TimeoutExpired as e:
            execution_time = time.time() - start_time
            logger.warning(f"Command timed out after {config.timeout}s: {' '.join(config.command)}")
            
            return SubprocessResult(
                success=False,
                returncode=-1,
                stdout=e.stdout or "",
                stderr=e.stderr or "",
                execution_time=execution_time,
                command=config.command,
                error_message=f"Command timed out after {config.timeout} seconds",
                timed_out=True
            )
            
        except FileNotFoundError as e:
            execution_time = time.time() - start_time
            logger.error(f"Command not found: {config.command[0]}")
            
            return SubprocessResult(
                success=False,
                returncode=-1,
                stdout="",
                stderr=str(e),
                execution_time=execution_time,
                command=config.command,
                error_message=f"Command not found: {config.command[0]}"
            )
            
        except PermissionError as e:
            execution_time = time.time() - start_time
            logger.error(f"Permission denied executing: {' '.join(config.command)}")
            
            return SubprocessResult(
                success=False,
                returncode=-1,
                stdout="",
                stderr=str(e),
                execution_time=execution_time,
                command=config.command,
                error_message=f"Permission denied: {str(e)}"
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Unexpected error executing command: {str(e)}")
            
            return SubprocessResult(
                success=False,
                returncode=-1,
                stdout="",
                stderr=str(e),
                execution_time=execution_time,
                command=config.command,
                error_message=f"Unexpected error: {str(e)}"
            )

class FridaEnvironmentValidator:
    """Validate Frida environment and dependencies."""
    
    def __init__(self, subprocess_handler: SubprocessHandler):
        self.subprocess_handler = subprocess_handler
        self._validation_cache: Dict[str, Any] = {}
        self._cache_ttl = 60  # 1 minute cache for environment checks
    
    def validate_frida_environment(self) -> Dict[str, Any]:
        """Validate complete Frida environment with caching."""
        cache_key = "frida_environment_validation"
        
        # Check cache
        if cache_key in self._validation_cache:
            cached_time, cached_result = self._validation_cache[cache_key]
            if time.time() - cached_time < self._cache_ttl:
                return cached_result
        
        # Perform validation
        validation_result = {
            "frida_available": False,
            "frida_version": None,
            "devices_available": False,
            "device_list": [],
            "adb_available": False,
            "frida_server_running": False,
            "errors": [],
            "is_ready": False
        }
        
        # Check Frida installation
        frida_check = self._check_frida_installation()
        validation_result.update(frida_check)
        
        # Check ADB availability
        adb_check = self._check_adb_availability()
        validation_result.update(adb_check)
        
        # Check connected devices (only if ADB is available)
        if validation_result["adb_available"]:
            device_check = self._check_connected_devices()
            validation_result.update(device_check)
        
        # Check Frida server (only if devices are available)
        if validation_result["devices_available"]:
            server_check = self._check_frida_server()
            validation_result.update(server_check)
        
        # Determine overall readiness
        validation_result["is_ready"] = (
            validation_result["frida_available"] and
            validation_result["adb_available"] and
            validation_result["devices_available"] and
            len(validation_result["errors"]) == 0
        )
        
        # Cache result
        self._validation_cache[cache_key] = (time.time(), validation_result)
        
        return validation_result
    
    def _check_frida_installation(self) -> Dict[str, Any]:
        """Check if Frida is properly installed."""
        config = SubprocessConfig(
            command=["frida", "--version"],
            timeout=10
        )
        
        result = self.subprocess_handler.execute_with_cache(config, "frida_version_check")
        
        if result.success:
            return {
                "frida_available": True,
                "frida_version": result.stdout.strip()
            }
        else:
            return {
                "frida_available": False,
                "frida_version": None,
                "errors": [result.error_message or "Frida not found or not working"]
            }
    
    def _check_adb_availability(self) -> Dict[str, Any]:
        """Check if ADB is available."""
        config = SubprocessConfig(
            command=["adb", "version"],
            timeout=10
        )
        
        result = self.subprocess_handler.execute_with_cache(config, "adb_version_check")
        
        if result.success:
            return {"adb_available": True}
        else:
            return {
                "adb_available": False,
                "errors": [result.error_message or "ADB not found or not working"]
            }
    
    def _check_connected_devices(self) -> Dict[str, Any]:
        """Check for connected Android devices."""
        config = SubprocessConfig(
            command=["frida-ls-devices"],
            timeout=15
        )
        
        result = self.subprocess_handler.execute(config)  # Don't cache device list
        
        if result.success:
            # Parse device list
            devices = []
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if line.strip() and not line.startswith('Id'):
                    devices.append(line.strip())
            
            # Check for USB devices
            usb_devices = [d for d in devices if 'usb' in d.lower()]
            
            return {
                "devices_available": len(usb_devices) > 0,
                "device_list": devices
            }
        else:
            return {
                "devices_available": False,
                "device_list": [],
                "errors": [result.error_message or "Failed to list devices"]
            }
    
    def _check_frida_server(self) -> Dict[str, Any]:
        """Check if Frida server is running on device."""
        config = SubprocessConfig(
            command=["frida-ps", "-U"],
            timeout=15
        )
        
        result = self.subprocess_handler.execute(config)  # Don't cache process list
        
        if result.success:
            return {"frida_server_running": True}
        else:
            return {
                "frida_server_running": False,
                "errors": [result.error_message or "Frida server not running or not accessible"]
            }
    
    def get_installation_guidance(self) -> Dict[str, List[str]]:
        """Get installation guidance for missing components."""
        return {
            "frida_installation": [
                "Install Frida tools: pip install frida-tools",
                "Download frida-server from: https://github.com/frida/frida/releases",
                "Push to device: adb push frida-server /data/local/tmp/",
                "Make executable: adb shell chmod 755 /data/local/tmp/frida-server",
                "Run as root: adb shell su -c '/data/local/tmp/frida-server &'"
            ],
            "adb_installation": [
                "Install Android SDK platform tools",
                "Add platform-tools to PATH",
                "Enable USB debugging on device",
                "Connect device via USB"
            ],
            "device_connection": [
                "Connect Android device via USB",
                "Enable USB debugging in Developer Options",
                "Accept USB debugging prompt on device",
                "Verify connection: adb devices"
            ],
            "frida_server": [
                "Ensure device is rooted",
                "Download correct frida-server architecture",
                "Start frida-server as root on device",
                "Verify connection: frida-ps -U"
            ]
        }

def create_subprocess_handler(cache_ttl: int = 300) -> SubprocessHandler:
    """Factory function to create subprocess handler."""
    return SubprocessHandler(cache_ttl=cache_ttl)

def create_environment_validator(subprocess_handler: SubprocessHandler) -> FridaEnvironmentValidator:
    """Factory function to create environment validator."""
    return FridaEnvironmentValidator(subprocess_handler) 