#!/usr/bin/env python3
"""
Drozer Connection Manager with error handling

This module provides drozer connection management with error logging and diagnostics.
"""

import asyncio
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from threading import Lock, Timer
from typing import Dict, List, Optional, Tuple, Union
import concurrent.futures
import signal

class ConnectionState(Enum):
    """Enhanced connection states for better lifecycle management"""
    UNKNOWN = "unknown"
    INITIALIZING = "initializing"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    AUTHENTICATED = "authenticated"
    RECONNECTING = "reconnecting"
    DISCONNECTED = "disconnected"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    ERROR = "error"

class ErrorType(Enum):
    """Classification of drozer error types for better handling"""
    CONNECTION_ERROR = "connection_error"
    TIMEOUT_ERROR = "timeout_error"
    ATTRIBUTE_ERROR = "attribute_error"
    COMMAND_ERROR = "command_error"
    PERMISSION_ERROR = "permission_error"
    DEVICE_ERROR = "device_error"
    DROZER_ERROR = "drozer_error"
    UNKNOWN_ERROR = "unknown_error"

@dataclass
class ConnectionConfig:
    """Configuration for drozer connection parameters"""
    max_retries: int = 3
    base_timeout: int = 60
    connection_timeout: int = 45
    command_timeout: int = 90
    keepalive_interval: int = 30
    max_concurrent_commands: int = 3
    enable_connection_pooling: bool = True
    enable_adaptive_timeout: bool = True
    fallback_to_static: bool = True

@dataclass
class ErrorInfo:
    """Detailed error information for diagnostics"""
    error_type: ErrorType
    message: str
    timestamp: float
    command: Optional[str] = None
    retry_count: int = 0
    diagnostic_info: Optional[Dict] = None

class EnhancedDrozerManager:
    """
    Enhanced drozer connection manager with robust error handling and intelligence.
    
    This manager provides comprehensive drozer connectivity with automatic error
    recovery, connection pooling, intelligent timeouts, and graceful degradation
    to ensure security analysis continues despite connectivity issues.
    """

    def __init__(self, package_name: str, config: Optional[ConnectionConfig] = None):
        """
        Initialize the enhanced drozer manager.
        
        Args:
            package_name: Android package name for analysis
            config: Connection configuration parameters
        """
        self.package_name = package_name
        self.config = config or ConnectionConfig()
        
        # Connection state management
        self.connection_state = ConnectionState.UNKNOWN
        self.last_successful_connection = None
        self.connection_lock = Lock()
        
        # Error handling and diagnostics
        self.error_history: List[ErrorInfo] = []
        self.last_error: Optional[ErrorInfo] = None
        self.retry_count = 0
        self.consecutive_failures = 0
        
        # Connection pool and command management
        self.active_connections: Dict[str, subprocess.Popen] = {}
        self.command_queue: List[Tuple] = []
        self.command_executor = None
        
        # Adaptive configuration
        self.adaptive_timeout = self._calculate_adaptive_timeout()
        self.device_capabilities: Dict = {}
        
        # Keepalive and monitoring
        self.keepalive_timer: Optional[Timer] = None
        self.connection_monitor_active = False
        
        # Initialize logging
        self.logger = logging.getLogger(f"drozer_manager_{package_name}")
        self._setup_logging()
        
        # Initialize connection manager
        self._initialize_manager()

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
        """Setup enhanced logging for drozer operations"""
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)

    def _initialize_manager(self) -> None:
        """Initialize the drozer manager and perform initial setup"""
        self.logger.info("🔧 Initializing Enhanced Drozer Manager...")
        self.connection_state = ConnectionState.INITIALIZING
        
        # Check drozer availability
        if not self._check_drozer_availability():
            self.connection_state = ConnectionState.UNAVAILABLE
            return
            
        # Initialize command executor if pooling is enabled
        if self.config.enable_connection_pooling:
            self.command_executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=self.config.max_concurrent_commands,
                thread_name_prefix="drozer_cmd"
            )
            
        # Detect device capabilities
        self._detect_device_capabilities()

    def _calculate_adaptive_timeout(self) -> int:
        """Calculate adaptive timeout based on package characteristics"""
        if not self.config.enable_adaptive_timeout:
            return self.config.command_timeout
            
        # Known large applications requiring extended timeouts
        large_apps_config = {
            "com.zhiliaoapp.musically": {"multiplier": 1.5, "base_add": 30},  # TikTok
            "com.facebook.katana": {"multiplier": 1.3, "base_add": 20},       # Facebook
            "com.instagram.android": {"multiplier": 1.3, "base_add": 20},     # Instagram
            "com.whatsapp": {"multiplier": 1.2, "base_add": 15},              # WhatsApp
            "com.snapchat.android": {"multiplier": 1.3, "base_add": 20},      # Snapchat
            "com.google.android.youtube": {"multiplier": 1.4, "base_add": 25}, # YouTube
            "com.amazon.mShop.android.shopping": {"multiplier": 1.2, "base_add": 15}, # Amazon
        }
        
        if self.package_name in large_apps_config:
            app_config = large_apps_config[self.package_name]
            adaptive_timeout = int(
                self.config.command_timeout * app_config["multiplier"] + app_config["base_add"]
            )
            self.logger.info(
                f"🕒 Adaptive timeout: {self.config.command_timeout}s → {adaptive_timeout}s for {self.package_name}"
            )
            return adaptive_timeout
        
        return self.config.command_timeout

    def _check_drozer_availability(self) -> bool:
        """Check if drozer is available and properly installed"""
        try:
            result = subprocess.run(
                ["drozer", "--help"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.logger.info("✅ Drozer framework detected and available")
                return True
            else:
                self._log_error(
                    ErrorType.DROZER_ERROR,
                    f"Drozer help command failed: {result.stderr}"
                )
                return False
                
        except FileNotFoundError:
            self._log_error(
                ErrorType.DROZER_ERROR,
                "Drozer executable not found - ensure Drozer is installed and in PATH"
            )
            return False
        except subprocess.TimeoutExpired:
            self._log_error(
                ErrorType.TIMEOUT_ERROR,
                "Drozer availability check timed out"
            )
            return False
        except Exception as e:
            self._log_error(
                ErrorType.UNKNOWN_ERROR,
                f"Unexpected error checking drozer availability: {str(e)}"
            )
            return False

    def _detect_device_capabilities(self) -> None:
        """Detect connected device capabilities and configurations"""
        try:
            # Check ADB connectivity
            adb_result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if adb_result.returncode == 0:
                devices = [line for line in adb_result.stdout.split('\n') 
                          if '\tdevice' in line]
                self.device_capabilities['adb_devices'] = len(devices)
                self.logger.info(f"📱 Detected {len(devices)} ADB device(s)")
            
            # Check device properties if device is connected
            if self.device_capabilities.get('adb_devices', 0) > 0:
                prop_result = subprocess.run(
                    ["adb", "shell", "getprop", "ro.build.version.sdk"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if prop_result.returncode == 0:
                    self.device_capabilities['android_sdk'] = prop_result.stdout.strip()
                    self.logger.info(
                        f"🤖 Device Android SDK: {self.device_capabilities['android_sdk']}"
                    )
                    
        except Exception as e:
            self.logger.warning(f"⚠️ Could not detect device capabilities: {e}")

    def start_connection(self) -> bool:
        """
        Start drozer connection with enhanced error handling and recovery.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        with self.connection_lock:
            if self.connection_state == ConnectionState.UNAVAILABLE:
                return False
                
            # Quick device availability check first
            if not self._check_device_availability():
                self.logger.info("📱 No Android devices detected - enabling static-only mode")
                self.connection_state = ConnectionState.UNAVAILABLE
                return False
                
            self.logger.info("🔧 Starting Enhanced Drozer Connection...")
            self.connection_state = ConnectionState.CONNECTING
            
            # Use exponential backoff for retries
            for attempt in range(self.config.max_retries):
                try:
                    # Step 1: Setup port forwarding
                    if not self._setup_port_forwarding():
                        self._wait_before_retry(attempt)
                        continue
                        
                    # Step 2: Verify drozer agent connectivity  
                    if not self._verify_drozer_agent():
                        self._wait_before_retry(attempt)
                        continue
                        
                    # Step 3: Establish authenticated connection
                    if not self._establish_connection():
                        self._wait_before_retry(attempt)
                        continue
                        
                    # Success!
                    if self.connection_state == ConnectionState.CONNECTED:
                        self._start_connection_monitoring()
                        self.logger.info(f"✅ Drozer connection established on attempt {attempt + 1}")
                        return True
                        
                except Exception as e:
                    self.logger.warning(f"🔄 Connection attempt {attempt + 1} failed: {e}")
                    self._wait_before_retry(attempt)
                    
            # All attempts failed
            self.connection_state = ConnectionState.FAILED
            self.logger.warning("❌ All Drozer connection attempts failed - continuing with static analysis")
            return False

    def _check_device_availability(self) -> bool:
        """Quick check if any Android devices/emulators are available"""
        try:
            result = subprocess.run(
                ["adb", "devices"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            if result.returncode != 0:
                return False
                
            # Parse adb devices output
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            available_devices = [line for line in lines if line.strip() and 'device' in line]
            
            if not available_devices:
                self.logger.info("📱 No Android devices/emulators found")
                return False
                
            self.logger.info(f"📱 Found {len(available_devices)} Android device(s)")
            return True
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.debug(f"Device availability check failed: {e}")
            return False

    def _wait_before_retry(self, attempt: int) -> None:
        """Wait before retry with exponential backoff"""
        if attempt < self.config.max_retries - 1:
            wait_time = min(2 ** attempt, 10)  # Cap at 10 seconds
            self.logger.info(f"⏳ Waiting {wait_time}s before retry...")
            time.sleep(wait_time)

    def _setup_port_forwarding(self) -> bool:
        """Setup ADB port forwarding with comprehensive error handling"""
        try:
            # Clean up existing port forwarding
            cleanup_cmd = ["adb", "forward", "--remove", "tcp:31415"]
            subprocess.run(cleanup_cmd, capture_output=True, timeout=10)
            
            # Setup new port forwarding
            forward_cmd = ["adb", "forward", "tcp:31415", "tcp:31415"]
            result = subprocess.run(
                forward_cmd,
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                self.logger.info("✅ ADB port forwarding established")
                return True
            else:
                self._log_error(
                    ErrorType.CONNECTION_ERROR,
                    f"Port forwarding failed: {result.stderr or result.stdout}",
                    command=" ".join(forward_cmd)
                )
                return False
                
        except subprocess.TimeoutExpired:
            self._log_error(
                ErrorType.TIMEOUT_ERROR,
                "Port forwarding setup timed out",
                command="adb forward"
            )
            return False
        except FileNotFoundError:
            self._log_error(
                ErrorType.DEVICE_ERROR,
                "ADB not found - ensure Android SDK is installed and in PATH"
            )
            self.connection_state = ConnectionState.UNAVAILABLE
            return False
        except Exception as e:
            self._log_error(
                ErrorType.UNKNOWN_ERROR,
                f"Unexpected error during port forwarding: {str(e)}"
            )
            return False

    def _verify_drozer_agent(self) -> bool:
        """Verify drozer agent is running on device"""
        try:
            # Test basic connectivity with minimal command
            test_cmd = "list"
            result = self._execute_drozer_command_direct(test_cmd, timeout=45)
            
            if result[0]:  # Success
                self.logger.info("✅ Drozer agent connectivity verified")
                return True
            else:
                self._log_error(
                    ErrorType.CONNECTION_ERROR,
                    f"Drozer agent verification failed: {result[1]}",
                    command=test_cmd
                )
                return False
                
        except Exception as e:
            self._log_error(
                ErrorType.CONNECTION_ERROR,
                f"Error verifying drozer agent: {str(e)}"
            )
            return False

    def _establish_connection(self) -> bool:
        """Establish authenticated drozer connection"""
        try:
            # Try to run a basic information command to verify full connectivity
            info_cmd = f"run information.packageinfo -a {self.package_name}"
            success, output = self._execute_drozer_command_direct(info_cmd, timeout=45)
            
            if success:
                self.connection_state = ConnectionState.CONNECTED
                self.last_successful_connection = time.time()
                self.consecutive_failures = 0
                self.logger.info("✅ Drozer connection established and authenticated")
                return True
            else:
                self._log_error(
                    ErrorType.CONNECTION_ERROR,
                    f"Connection authentication failed: {output}",
                    command=info_cmd
                )
                return False
                
        except Exception as e:
            self._log_error(
                ErrorType.CONNECTION_ERROR,
                f"Error establishing connection: {str(e)}"
            )
            return False

    def _execute_drozer_command_direct(self, command: str, timeout: Optional[int] = None) -> Tuple[bool, str]:
        """
        Execute drozer command directly with enhanced error handling.
        
        Args:
            command: Drozer command to execute
            timeout: Command timeout in seconds
            
        Returns:
            Tuple[bool, str]: (success, output_or_error)
        """
        cmd_timeout = timeout or self.adaptive_timeout
        full_command = f"drozer console connect --command '{command}'"
        
        try:
            self.logger.debug(f"🔨 Executing: {command} (timeout: {cmd_timeout}s)")
            
            process = subprocess.run(
                full_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=cmd_timeout
            )
            
            if process.returncode == 0:
                return True, process.stdout.strip()
            else:
                error_output = process.stderr.strip() or process.stdout.strip()
                return False, self._normalize_error_message(error_output)
                
        except subprocess.TimeoutExpired:
            error_msg = f"Command '{command}' timed out after {cmd_timeout}s"
            self._log_error(ErrorType.TIMEOUT_ERROR, error_msg, command)
            return False, error_msg
        except Exception as e:
            error_msg = f"Command execution failed: {self._normalize_error_message(str(e))}"
            self._log_error(ErrorType.COMMAND_ERROR, error_msg, command)
            return False, error_msg

    def _normalize_error_message(self, error_msg: str) -> str:
        """
        Normalize error messages to handle Python 3.x ConnectionError attribute issues.
        
        Args:
            error_msg: Raw error message
            
        Returns:
            str: Normalized error message
        """
        # Fix the infamous "'ConnectionError' object has no attribute 'message'" error
        if "'ConnectionError' object has no attribute 'message'" in error_msg:
            return "Connection error: Unable to connect to drozer server. Check if drozer agent is running on device."
        
        # Handle other common error patterns
        error_patterns = {
            "There was a problem connecting to the drozer Server": 
                "Connection failed: Drozer server not responding. Verify agent is running.",
            "No route to host": 
                "Network error: Cannot reach device. Check ADB connection.",
            "Connection refused": 
                "Connection refused: Drozer agent may not be running on port 31415.",
            "timeout": 
                "Operation timed out: Device or network may be slow.",
        }
        
        for pattern, replacement in error_patterns.items():
            if pattern in error_msg:
                return replacement
                
        return error_msg

    def execute_command(self, command: str, timeout_override: Optional[int] = None) -> Tuple[bool, str]:
        """
        Execute drozer command with enhanced stability checking and recovery.
        
        Args:
            command: Drozer command to execute
            timeout_override: Optional timeout override
            
        Returns:
            Tuple[bool, str]: (success, output_or_error)
        """
        if self.connection_state == ConnectionState.UNAVAILABLE:
            return False, "Drozer framework is not available"
        
        # Check and recover connection stability
        if not self._recover_connection_if_needed():
            return False, "Connection recovery failed"
        """
        Execute drozer command with full error handling and recovery.
        
        Args:
            command: Drozer command to execute
            timeout_override: Optional timeout override
            
        Returns:
            Tuple[bool, str]: (success, output_or_error)
        """
        if self.connection_state == ConnectionState.UNAVAILABLE:
            return False, "Drozer framework is not available"
            
        # Check connection state and attempt recovery if needed
        if self.connection_state != ConnectionState.CONNECTED:
            if not self._attempt_connection_recovery():
                return False, f"Connection recovery failed: {self.last_error.message if self.last_error else 'Unknown error'}"
        
        # Execute command with retry logic
        max_attempts = 2
        for attempt in range(max_attempts):
            try:
                success, output = self._execute_drozer_command_direct(command, timeout_override)
                
                if success:
                    return True, output
                else:
                    # On failure, check if it's a connection issue
                    if self._is_connection_error(output) and attempt < max_attempts - 1:
                        self.logger.info(f"🔄 Connection error detected, attempting recovery...")
                        if self._attempt_connection_recovery():
                            continue  # Retry command
                    
                    return False, output
                    
            except Exception as e:
                error_msg = f"Command execution error: {self._normalize_error_message(str(e))}"
                if attempt < max_attempts - 1:
                    self.logger.warning(f"⚠️ {error_msg}, retrying...")
                    time.sleep(2)
                else:
                    self._log_error(ErrorType.COMMAND_ERROR, error_msg, command)
                    return False, error_msg
        
        return False, "Command execution failed after retries"

    def execute_command_safe(self, command: str, fallback_message: Optional[str] = None) -> str:
        """
        Execute command with safe fallback for legacy compatibility.
        
        Args:
            command: Drozer command to execute
            fallback_message: Custom fallback message
            
        Returns:
            str: Command output or formatted error message
        """
        success, output = self.execute_command(command)
        
        if success:
            return output
        else:
            if fallback_message:
                return fallback_message
            else:
                return f"⚠️ Drozer command failed: {output}"

    def run_command(self, command: str, timeout_override: Optional[int] = None) -> Tuple[bool, str]:
        """Legacy compatibility method - returns tuple for proper compatibility"""
        try:
            return self.execute_command(command, timeout_override)
        except Exception as e:
            return False, f"Drozer command execution failed: {e}"

    def run_command_safe(self, command: str, fallback_message: Optional[str] = None) -> str:
        """
        Legacy compatibility method for run_command_safe.
        Delegates to execute_command_safe.
        
        Args:
            command: Drozer command to execute
            fallback_message: Custom fallback message
            
        Returns:
            str: Command output or formatted error message
        """
        return self.execute_command_safe(command, fallback_message)

    def _is_connection_error(self, error_msg: str) -> bool:
        """Check if error message indicates a connection issue"""
        connection_indicators = [
            "connection",
            "server",
            "timeout",
            "refused",
            "unreachable",
            "network",
            "device"
        ]
        return any(indicator in error_msg.lower() for indicator in connection_indicators)

    def _check_connection_stability(self) -> bool:
        """Check connection stability before executing commands"""
        try:
            # Quick ping test
            result = subprocess.run(
                ["adb", "shell", "echo", "stability_test"],
                capture_output=True,
                text=True,
                timeout=3
            )
            
            return result.returncode == 0 and "stability_test" in result.stdout
            
        except Exception:
            return False
    
    def _recover_connection_if_needed(self) -> bool:
        """Recover connection if stability check fails"""
        if not self._check_connection_stability():
            self.logger.warning("🔄 Connection instability detected, attempting recovery...")
            return self._attempt_connection_recovery()
        return True
    def _attempt_connection_recovery(self) -> bool:
        """Attempt to recover from connection issues"""
        self.logger.info("🔄 Attempting connection recovery...")
        
        # Reset connection state
        self.connection_state = ConnectionState.RECONNECTING
        
        # Wait a moment for any pending operations
        time.sleep(1)
        
        # Attempt to re-establish connection
        return self.start_connection()

    def _start_connection_monitoring(self) -> None:
        """Start background connection monitoring and keepalive"""
        if self.connection_monitor_active:
            return
            
        self.connection_monitor_active = True
        
        def keepalive_check():
            if self.connection_state == ConnectionState.CONNECTED:
                # Simple keepalive command
                success, _ = self._execute_drozer_command_direct("list", timeout=10)
                if not success:
                    self.logger.warning("⚠️ Keepalive failed, connection may be unstable")
                    self.connection_state = ConnectionState.DISCONNECTED
                
                # Schedule next keepalive
                if self.connection_monitor_active:
                    self.keepalive_timer = Timer(self.config.keepalive_interval, keepalive_check)
                    self.keepalive_timer.start()
        
        # Start initial keepalive timer
        self.keepalive_timer = Timer(self.config.keepalive_interval, keepalive_check)
        self.keepalive_timer.start()

    def _log_error(self, error_type: ErrorType, message: str, command: Optional[str] = None) -> None:
        """Log error with detailed information"""
        error_info = ErrorInfo(
            error_type=error_type,
            message=message,
            timestamp=time.time(),
            command=command,
            retry_count=self.retry_count,
            diagnostic_info=self._gather_diagnostic_info()
        )
        
        self.error_history.append(error_info)
        self.last_error = error_info
        
        # Keep error history manageable
        if len(self.error_history) > 50:
            self.error_history = self.error_history[-30:]
        
        self.logger.error(f"❌ {error_type.value}: {message}")

    def _gather_diagnostic_info(self) -> Dict:
        """Gather diagnostic information for troubleshooting"""
        return {
            "connection_state": self.connection_state.value,
            "package_name": self.package_name,
            "adaptive_timeout": self.adaptive_timeout,
            "device_capabilities": self.device_capabilities,
            "consecutive_failures": self.consecutive_failures,
            "last_successful_connection": self.last_successful_connection,
            "timestamp": time.time()
        }

    def get_connection_status(self) -> Dict:
        """Get comprehensive connection status information"""
        return {
            "state": self.connection_state.value,
            "connected": self.connection_state == ConnectionState.CONNECTED,
            "available": self.connection_state != ConnectionState.UNAVAILABLE,
            "last_error": self.last_error.message if self.last_error else None,
            "error_type": self.last_error.error_type.value if self.last_error else None,
            "retry_count": self.retry_count,
            "consecutive_failures": self.consecutive_failures,
            "adaptive_timeout": self.adaptive_timeout,
            "device_capabilities": self.device_capabilities,
            "error_history_count": len(self.error_history),
            "last_successful_connection": self.last_successful_connection,
            "connection_monitor_active": self.connection_monitor_active
        }

    def get_diagnostic_report(self) -> str:
        """Generate comprehensive diagnostic report for troubleshooting"""
        report = [
            "🔍 Enhanced Drozer Manager Diagnostic Report",
            "=" * 50,
            f"Package: {self.package_name}",
            f"Connection State: {self.connection_state.value}",
            f"Adaptive Timeout: {self.adaptive_timeout}s",
            f"Device Capabilities: {self.device_capabilities}",
            f"Consecutive Failures: {self.consecutive_failures}",
            "",
            "Recent Errors:",
        ]
        
        # Add recent errors
        recent_errors = self.error_history[-5:] if self.error_history else []
        for i, error in enumerate(recent_errors, 1):
            report.append(f"  {i}. {error.error_type.value}: {error.message}")
            if error.command:
                report.append(f"     Command: {error.command}")
        
        if not recent_errors:
            report.append("  No recent errors")
        
        return "\n".join(report)

    def cleanup(self) -> None:
        """Clean up resources and connections"""
        self.logger.info("🧹 Cleaning up Enhanced Drozer Manager...")
        
        # Stop connection monitoring
        self.connection_monitor_active = False
        if self.keepalive_timer:
            self.keepalive_timer.cancel()
        
        # Clean up command executor
        if self.command_executor:
            self.command_executor.shutdown(wait=True)
        
        # Clean up active connections
        for conn_id, process in self.active_connections.items():
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
        
        self.active_connections.clear()
        self.connection_state = ConnectionState.DISCONNECTED
        
        self.logger.info("✅ Enhanced Drozer Manager cleanup complete")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup"""
        self.cleanup()

    def stop_connection(self) -> bool:
        """
        Stop drozer connection and cleanup resources.
        
        Returns:
            bool: True if disconnection successful, False otherwise
        """
        with self.connection_lock:
            try:
                self.logger.info("🔌 Stopping Enhanced Drozer Connection...")
                
                # Stop connection monitoring
                if hasattr(self, '_monitoring_active'):
                    self._monitoring_active = False
                
                # Clean up port forwarding
                try:
                    cleanup_cmd = ["adb", "forward", "--remove", "tcp:31415"]
                    subprocess.run(cleanup_cmd, capture_output=True, timeout=10)
                    self.logger.info("✅ Port forwarding cleaned up")
                except Exception as e:
                    self.logger.warning(f"⚠️ Port forwarding cleanup warning: {e}")
                
                # Update connection state
                self.connection_state = ConnectionState.DISCONNECTED
                self.last_successful_connection = 0
                
                self.logger.info("✅ Drozer connection stopped successfully")
                return True
                
            except Exception as e:
                self._log_error(
                    ErrorType.CONNECTION_ERROR,
                    f"Error stopping connection: {str(e)}"
                )
                return False

# Factory function for easy integration
def create_drozer_manager(package_name: str, config: Optional[ConnectionConfig] = None) -> EnhancedDrozerManager:
    """
    Create and initialize an enhanced drozer manager.
    
    Args:
        package_name: Android package name for analysis
        config: Optional configuration parameters
        
    Returns:
        EnhancedDrozerManager: Configured and initialized manager
    """
    manager = EnhancedDrozerManager(package_name, config)
    return manager

# Backward compatibility wrapper
class DrozerHelper(EnhancedDrozerManager):
    """Backward compatibility wrapper for existing code"""
    
    def __init__(self, package_name: str, max_retries: int = 3, 
                 command_timeout: int = 90, connection_timeout: int = 45):
        config = ConnectionConfig(
            max_retries=max_retries,
            command_timeout=command_timeout,
            connection_timeout=connection_timeout
        )
        super().__init__(package_name, config)
    
    def start_drozer(self) -> bool:
        """Legacy compatibility method for starting drozer connection"""
        try:
            return self.start_connection()
        except Exception as e:
            self.logger.error(f"Legacy start_drozer failed: {e}")
            return False
    
    def check_connection(self) -> bool:
        """Legacy compatibility method for checking connection status"""
        try:
            return self.connection_state == ConnectionState.CONNECTED
        except Exception as e:
            self.logger.error(f"Legacy check_connection failed: {e}")
            return False
    
    def run_command(self, command: str, timeout_override: Optional[int] = None) -> Tuple[bool, str]:
        """Legacy compatibility method - returns tuple for proper compatibility"""
        try:
            return self.execute_command(command, timeout_override)
        except Exception as e:
            return False, f"Drozer command execution failed: {e}"
    
    def run_command_safe(self, command: str, fallback_message: Optional[str] = None) -> str:
        """Legacy compatibility method for safe command execution"""
        try:
            return self.execute_command_safe(command, fallback_message)
        except Exception as e:
            self.logger.error(f"Legacy run_command_safe failed: {e}")
            return fallback_message or f"Command failed: {e}"
    
    def get_connection_status(self) -> Dict:
        """Enhanced compatibility method"""
        try:
            status = super().get_connection_status()
            # Add legacy compatibility fields
            status["last_error"] = status.get("last_error", "No errors")
            return status
        except Exception as e:
            return {
                "last_error": f"Status check failed: {e}",
                "connected": False,
                "state": "error"
            } 