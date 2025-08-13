#!/usr/bin/env python3
"""
Robust Drozer Connection Manager
Provides intelligent device detection, stable connections, and graceful fallback
"""

import logging
import subprocess
import time
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Tuple

class DeviceState(Enum):
    """Device connection states"""
    UNKNOWN = "unknown"
    AVAILABLE = "available" 
    UNAVAILABLE = "unavailable"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"

@dataclass
class RobustConnectionConfig:
    """Configuration for robust connection management"""
    max_connection_attempts: int = 2  # Reduced from 3
    device_check_timeout: int = 5  # Quick device detection
    connection_timeout: int = 15  # Faster timeout
    enable_fallback: bool = True
    quiet_mode: bool = False  # Reduce log spam

class RobustDrozerManager:
    """
    Robust Drozer connection manager with intelligent device detection
    and graceful fallback to static analysis when devices unavailable.
    """
    
    def __init__(self, package_name: str, config: Optional[RobustConnectionConfig] = None):
        self.package_name = package_name
        self.config = config or RobustConnectionConfig()
        self.device_state = DeviceState.UNKNOWN
        self.connection_lock = threading.Lock()
        self.last_connection_attempt = 0
        self.consecutive_failures = 0
        
        # Setup logging
        self.logger = logging.getLogger(f"robust_drozer_{package_name}")
        
        # Quick initialization
        self._initialize()
    
    def _initialize(self) -> None:
        """Quick initialization with device detection"""
        self.device_state = self._detect_device_state()
        
        if self.device_state == DeviceState.UNAVAILABLE:
            if not self.config.quiet_mode:
                self.logger.info("📱 No devices detected - static analysis mode enabled")
    
    def _detect_device_state(self) -> DeviceState:
        """Fast device state detection"""
        try:
            # Quick adb devices check
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=self.config.device_check_timeout
            )
            
            if result.returncode != 0:
                return DeviceState.UNAVAILABLE
            
            # Parse output quickly
            lines = result.stdout.strip().split('\n')[1:]
            active_devices = [line for line in lines if 'device' in line and line.strip()]
            
            if active_devices:
                if not self.config.quiet_mode:
                    self.logger.info(f"📱 Detected {len(active_devices)} device(s)")
                return DeviceState.AVAILABLE
            else:
                return DeviceState.UNAVAILABLE
                
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return DeviceState.UNAVAILABLE
    
    def start_connection(self) -> bool:
        """Attempt Drozer connection with intelligent strategy"""
        with self.connection_lock:
            # Quick bailout if no devices
            if self.device_state == DeviceState.UNAVAILABLE:
                return False
            
            # Rate limiting - don't retry too frequently
            current_time = time.time()
            if current_time - self.last_connection_attempt < 10:  # 10 second cooldown
                return False
            
            self.last_connection_attempt = current_time
            return self._smart_connection_attempt()
    
    def _smart_connection_attempt(self) -> bool:
        """Smart connection with adaptive behavior"""
        try:
            if not self.config.quiet_mode:
                self.logger.info("🔧 Smart Drozer connection attempt...")
            
            # Try with moderate timeout
            success = self._attempt_drozer_connection(timeout=15)
            
            if success:
                self.device_state = DeviceState.CONNECTED
                self.consecutive_failures = 0
                if not self.config.quiet_mode:
                    self.logger.info("✅ Smart connection successful")
                return True
            else:
                self.consecutive_failures += 1
                if not self.config.quiet_mode:
                    self.logger.info("📱 Connection failed - enabling static-only mode")
                return False
                
        except Exception as e:
            if not self.config.quiet_mode:
                self.logger.debug(f"Smart connection error: {e}")
            return False
    
    def _attempt_drozer_connection(self, timeout: int = 15) -> bool:
        """Single connection attempt with specified timeout"""
        try:
            # 1. Setup port forwarding
            if not self._setup_port_forwarding(timeout):
                return False
            
            # 2. Test basic drozer connectivity
            if not self._test_drozer_agent(timeout):
                return False
            
            return True
            
        except Exception:
            return False
    
    def _setup_port_forwarding(self, timeout: int) -> bool:
        """Setup ADB port forwarding quickly"""
        try:
            # Clean existing forwards quietly
            subprocess.run(
                ["adb", "forward", "--remove", "tcp:31415"],
                capture_output=True,
                timeout=5
            )
            
            # Setup new forwarding
            result = subprocess.run(
                ["adb", "forward", "tcp:31415", "tcp:31415"],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    def _test_drozer_agent(self, timeout: int) -> bool:
        """Quick test of drozer agent availability"""
        try:
            # Simple connectivity test
            result = subprocess.run(
                ["drozer", "console", "connect", "--command", "list"],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    def execute_command(self, command: str, timeout: int = 30) -> Tuple[bool, str]:
        """Execute drozer command with error handling"""
        if self.device_state != DeviceState.CONNECTED:
            return False, "No active drozer connection"
        
        try:
            cmd = f"drozer console connect --command '{command}'"
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                return True, result.stdout.strip()
            else:
                # Connection might have failed
                self.device_state = DeviceState.DISCONNECTED
                return False, result.stderr.strip() or "Command failed"
                
        except subprocess.TimeoutExpired:
            return False, f"Command timed out after {timeout}s"
        except Exception as e:
            return False, f"Command execution error: {e}"
    
    def get_connection_status(self) -> Dict:
        """Get current connection status"""
        return {
            "connected": self.device_state == DeviceState.CONNECTED,
            "device_state": self.device_state.value,
            "consecutive_failures": self.consecutive_failures,
            "last_attempt": self.last_connection_attempt
        }
    
    def stop_connection(self) -> bool:
        """Clean up connection resources"""
        try:
            if self.device_state in [DeviceState.CONNECTED, DeviceState.CONNECTING]:
                # Clean up port forwarding
                subprocess.run(
                    ["adb", "forward", "--remove", "tcp:31415"],
                    capture_output=True,
                    timeout=5
                )
            
            self.device_state = DeviceState.DISCONNECTED
            return True
            
        except Exception:
            return False
    
    # Legacy compatibility methods
    def check_connection(self) -> bool:
        """Legacy compatibility method"""
        return self.device_state == DeviceState.CONNECTED
    
    def run_command(self, command: str, timeout: int = 30) -> Tuple[bool, str]:
        """Legacy compatibility method"""
        return self.execute_command(command, timeout)
    
    def run_command_safe(self, command: str, fallback: str = "Analysis unavailable") -> str:
        """Legacy compatibility method with safe fallback"""
        success, result = self.execute_command(command)
        return result if success else fallback 
 
 
 
 