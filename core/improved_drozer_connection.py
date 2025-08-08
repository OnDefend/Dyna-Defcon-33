#!/usr/bin/env python3
"""
Improved Drozer Connection Manager
Solves connection stability and reduces log spam when no devices available
"""

import subprocess
import time
import logging
from typing import Dict, Tuple, Optional, Union
from threading import Lock
from dataclasses import dataclass

@dataclass
class ConnectionState:
    """Track connection state and prevent repeated failures"""
    last_check_time: float = 0
    last_result: bool = False
    consecutive_failures: int = 0
    device_available: Optional[bool] = None
    cooldown_until: float = 0

class ImprovedDrozerManager:
    """
    Improved Drozer connection manager with:
    - Fast device detection
    - Intelligent retry prevention
    - Graceful fallback to static analysis
    - Reduced log spam
    """
    
    # Class-level connection state to share across instances
    _connection_state = ConnectionState()
    _state_lock = Lock()
    
    def __init__(self, package_name: str, quiet_mode: bool = False):
        self.package_name = package_name
        self.logger = logging.getLogger(f"drozer_{package_name}")
        self.quiet_mode = quiet_mode
        self.connected = False
        
        # Quick initialization check
        self._initialize_device_state()
    
    def _initialize_device_state(self) -> None:
        """Quick device state initialization"""
        with self._state_lock:
            current_time = time.time()
            
            # Use cached result if recent (within 30 seconds)
            if (current_time - self._connection_state.last_check_time) < 30:
                if self._connection_state.device_available is False:
                    if not self.quiet_mode:
                        self.logger.info("📱 No devices detected (cached) - static analysis mode")
                return
            
            # Quick device check
            self._connection_state.device_available = self._quick_device_check()
            self._connection_state.last_check_time = current_time
            
            if not self._connection_state.device_available:
                if not self.quiet_mode:
                    self.logger.info("📱 No Android devices detected - enabling static-only mode")
    
    def _quick_device_check(self) -> bool:
        """Ultra-fast device availability check (3 second timeout)"""
        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=3
            )
            
            if result.returncode != 0:
                return False
            
            # Quick parse for active devices
            lines = result.stdout.strip().split('\n')[1:]
            active_devices = [line for line in lines if line.strip() and 'device' in line and not 'offline' in line]
            
            return len(active_devices) > 0
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    def start_connection(self) -> bool:
        """
        Smart connection start with cooldown prevention
        
        Returns:
            bool: True if connected, False if should use static analysis
        """
        with self._state_lock:
            current_time = time.time()
            
            # Check cooldown period to prevent spam
            if current_time < self._connection_state.cooldown_until:
                return False
            
            # Quick bailout if no devices (and recently checked)
            if not self._connection_state.device_available:
                if (current_time - self._connection_state.last_check_time) < 60:  # 1 minute cache
                    return False
                # Re-check after cache expiry
                self._connection_state.device_available = self._quick_device_check()
                self._connection_state.last_check_time = current_time
                if not self._connection_state.device_available:
                    return False
            
            # Attempt connection with fast timeout
            success = self._attempt_quick_connection()
            
            if success:
                self._connection_state.consecutive_failures = 0
                self.connected = True
                if not self.quiet_mode:
                    self.logger.info("Drozer connection established")
                return True
            else:
                # Implement exponential backoff cooldown
                self._connection_state.consecutive_failures += 1
                cooldown_time = min(2 ** self._connection_state.consecutive_failures, 120)  # Max 2 minutes
                self._connection_state.cooldown_until = current_time + cooldown_time
                
                if not self.quiet_mode and self._connection_state.consecutive_failures <= 2:
                    self.logger.info(f"Drozer connection failed - cooling down for {cooldown_time}s")
                
                return False
    
    def _attempt_quick_connection(self) -> bool:
        """Single quick connection attempt with 10-second total timeout"""
        try:
            # 1. Quick port forwarding setup (3 seconds)
            if not self._setup_port_forwarding_quick():
                return False
            
            # 2. Test drozer connectivity (7 seconds)  
            if not self._test_drozer_quick():
                return False
            
            return True
            
        except Exception:
            return False
    
    def _setup_port_forwarding_quick(self) -> bool:
        """Quick port forwarding with minimal timeout"""
        try:
            # Clean existing (don't wait for result)
            subprocess.run(
                ["adb", "forward", "--remove", "tcp:31415"],
                capture_output=True,
                timeout=1
            )
            
            # Setup new forwarding
            result = subprocess.run(
                ["adb", "forward", "tcp:31415", "tcp:31415"],
                capture_output=True,
                timeout=3
            )
            
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    def _test_drozer_quick(self) -> bool:
        """Quick drozer connectivity test"""
        try:
            result = subprocess.run(
                ["drozer", "console", "connect", "--command", "list"],
                capture_output=True,
                timeout=7
            )
            
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    def check_connection(self) -> bool:
        """Check if connection is active"""
        return self.connected
    
    def run_command(self, command: str, timeout: int = 30) -> Tuple[bool, str]:
        """Execute drozer command with fallback handling"""
        if not self.connected:
            return False, "No drozer connection available - static analysis mode active"
        
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
                # Mark as disconnected on failure
                self.connected = False
                error_msg = result.stderr.strip() or "Command execution failed"
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            self.connected = False
            return False, f"Command timed out after {timeout}s"
        except Exception as e:
            self.connected = False
            return False, f"Command execution error: {str(e)}"
    
    def run_command_safe(self, command: str, fallback: str = "Analysis unavailable - no device connection") -> str:
        """Safe command execution with meaningful fallback"""
        success, result = self.run_command(command)
        return result if success else fallback
    
    def get_connection_status(self) -> Dict:
        """Get comprehensive connection status"""
        with self._state_lock:
            return {
                "connected": self.connected,
                "device_available": self._connection_state.device_available,
                "consecutive_failures": self._connection_state.consecutive_failures,
                "last_check": self._connection_state.last_check_time,
                "in_cooldown": time.time() < self._connection_state.cooldown_until,
                "cooldown_remaining": max(0, self._connection_state.cooldown_until - time.time())
            }
    
    def stop_connection(self) -> bool:
        """Clean up connection resources"""
        try:
            if self.connected:
                # Clean up port forwarding
                subprocess.run(
                    ["adb", "forward", "--remove", "tcp:31415"],
                    capture_output=True,
                    timeout=3
                )
            
            self.connected = False
            return True
            
        except Exception:
            return False
    
    # Additional legacy compatibility methods
    def start_drozer(self) -> bool:
        """Legacy compatibility"""
        return self.start_connection()

def create_improved_drozer_manager(package_name: str, quiet_mode: bool = False) -> ImprovedDrozerManager:
    """
    Factory function for creating improved drozer manager
    
    Args:
        package_name: Package name for the app
        quiet_mode: Reduce logging output
        
    Returns:
        ImprovedDrozerManager instance
    """
    return ImprovedDrozerManager(package_name, quiet_mode) 
 
 
 
 