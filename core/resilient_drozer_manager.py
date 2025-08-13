#!/usr/bin/env python3
"""
Resilient Drozer Connection Manager
Provides automatic connection recovery, health monitoring, and seamless scan continuation
"""

import time
import threading
import subprocess
import logging
from typing import Dict, Tuple, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import json

class ConnectionHealth(Enum):
    """Connection health states"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    RECOVERING = "recovering"
    UNKNOWN = "unknown"

@dataclass
class ConnectionMetrics:
    """Track connection performance metrics"""
    successful_commands: int = 0
    failed_commands: int = 0
    total_reconnections: int = 0
    last_successful_command: float = 0
    last_reconnection: float = 0
    average_response_time: float = 0
    recent_response_times: deque = field(default_factory=lambda: deque(maxlen=10))
    
    def update_success(self, response_time: float):
        """Update metrics after successful command"""
        self.successful_commands += 1
        self.last_successful_command = time.time()
        self.recent_response_times.append(response_time)
        if self.recent_response_times:
            self.average_response_time = sum(self.recent_response_times) / len(self.recent_response_times)
    
    def update_failure(self):
        """Update metrics after failed command"""
        self.failed_commands += 1
    
    def update_reconnection(self):
        """Update metrics after reconnection"""
        self.total_reconnections += 1
        self.last_reconnection = time.time()
    
    @property
    def success_rate(self) -> float:
        """Calculate command success rate"""
        total = self.successful_commands + self.failed_commands
        return (self.successful_commands / total) if total > 0 else 0.0
    
    @property
    def health_score(self) -> float:
        """Calculate overall connection health (0-1)"""
        success_weight = 0.6
        recency_weight = 0.3
        latency_weight = 0.1
        
        # Success rate component
        success_component = self.success_rate * success_weight
        
        # Recency component (commands within last 60 seconds)
        recency_component = 0
        if self.last_successful_command > 0:
            time_since_success = time.time() - self.last_successful_command
            recency_component = max(0, 1 - (time_since_success / 60)) * recency_weight
        
        # Latency component (lower is better)
        latency_component = 0
        if self.average_response_time > 0:
            # Normalize: 0-5s = good (1.0), >10s = poor (0.0)
            normalized_latency = max(0, 1 - (self.average_response_time - 5) / 5)
            latency_component = normalized_latency * latency_weight
        
        return success_component + recency_component + latency_component

class ResilientDrozerManager:
    """
    Resilient Drozer manager with automatic connection recovery and health monitoring.
    
    Features:
    - Automatic connection recovery
    - Health monitoring and metrics
    - Command retry with exponential backoff
    - Seamless scan continuation
    - Connection state persistence
    """
    
    def __init__(self, package_name: str, auto_recovery: bool = True):
        self.package_name = package_name
        self.auto_recovery = auto_recovery
        self.logger = logging.getLogger(f"resilient_drozer_{package_name}")
        
        # Connection state
        self.connected = False
        self.health = ConnectionHealth.UNKNOWN
        self.connection_lock = threading.Lock()
        self.metrics = ConnectionMetrics()
        
        # Recovery configuration
        self.max_recovery_attempts = 3
        self.recovery_delay_base = 2  # seconds
        self.health_check_interval = 30  # seconds
        self.command_timeout = 30
        
        # Health monitoring
        self.health_monitor_thread = None
        self.health_monitor_active = False
        
        # Device state cache
        self._last_device_check = 0
        self._device_available = None
        
        self.logger.info(f"🔧 Resilient Drozer Manager initialized for {package_name}")
    
    def start_connection(self) -> bool:
        """Start connection with automatic recovery setup"""
        with self.connection_lock:
            if self._establish_initial_connection():
                self.connected = True
                self.health = ConnectionHealth.HEALTHY
                
                if self.auto_recovery:
                    self._start_health_monitoring()
                
                self.logger.info("✅ Resilient connection established with auto-recovery enabled")
                return True
            else:
                self.logger.info("⚠️ Initial connection failed - static analysis mode")
                return False
    
    def _establish_initial_connection(self) -> bool:
        """Establish initial connection to Drozer agent"""
        try:
            # Quick device availability check
            if not self._check_device_availability():
                return False
            
            # Setup ADB port forwarding
            if not self._setup_port_forwarding():
                return False
            
            # Test Drozer connectivity
            if not self._test_drozer_connectivity():
                return False
            
            self.logger.info("🔗 Initial Drozer connection established")
            return True
            
        except Exception as e:
            self.logger.debug(f"Initial connection failed: {e}")
            return False
    
    def _check_device_availability(self) -> bool:
        """Check if Android devices are available"""
        current_time = time.time()
        
        # Use cached result if recent
        if current_time - self._last_device_check < 30:
            return self._device_available or False
        
        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                self._device_available = False
            else:
                lines = result.stdout.strip().split('\n')[1:]
                active_devices = [line for line in lines if 'device' in line and line.strip()]
                self._device_available = len(active_devices) > 0
            
            self._last_device_check = current_time
            return self._device_available
            
        except Exception:
            self._device_available = False
            self._last_device_check = current_time
            return False
    
    def _setup_port_forwarding(self) -> bool:
        """Setup ADB port forwarding with retry"""
        for attempt in range(2):
            try:
                # Clean existing forwards
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
                    timeout=10
                )
                
                if result.returncode == 0:
                    return True
                else:
                    self.logger.debug(f"Port forwarding attempt {attempt + 1} failed")
                    if attempt < 1:  # Retry once
                        time.sleep(2)
                        
            except Exception as e:
                self.logger.debug(f"Port forwarding error on attempt {attempt + 1}: {e}")
                if attempt < 1:
                    time.sleep(2)
        
        return False
    
    def _test_drozer_connectivity(self) -> bool:
        """Test basic Drozer connectivity"""
        try:
            result = subprocess.run(
                ["drozer", "console", "connect", "--command", "list"],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _start_health_monitoring(self):
        """Start background health monitoring"""
        if self.health_monitor_active:
            return
        
        self.health_monitor_active = True
        self.health_monitor_thread = threading.Thread(
            target=self._health_monitor_loop,
            daemon=True
        )
        self.health_monitor_thread.start()
        self.logger.debug("🩺 Health monitoring started")
    
    def _health_monitor_loop(self):
        """Background health monitoring loop"""
        while self.health_monitor_active:
            try:
                self._perform_health_check()
                time.sleep(self.health_check_interval)
            except Exception as e:
                self.logger.debug(f"Health monitor error: {e}")
                time.sleep(5)
    
    def _perform_health_check(self):
        """Perform connection health check"""
        if not self.connected:
            return
        
        try:
            # Quick health check command
            start_time = time.time()
            result = subprocess.run(
                ["drozer", "console", "connect", "--command", "list"],
                capture_output=True,
                timeout=10
            )
            response_time = time.time() - start_time
            
            if result.returncode == 0:
                self.metrics.update_success(response_time)
                self._update_health_status()
            else:
                self.metrics.update_failure()
                self._handle_connection_failure()
                
        except Exception:
            self.metrics.update_failure()
            self._handle_connection_failure()
    
    def _update_health_status(self):
        """Update connection health based on metrics"""
        health_score = self.metrics.health_score
        
        if health_score >= 0.8:
            self.health = ConnectionHealth.HEALTHY
        elif health_score >= 0.5:
            self.health = ConnectionHealth.DEGRADED
        else:
            self.health = ConnectionHealth.FAILED
    
    def _handle_connection_failure(self):
        """Handle connection failure with automatic recovery"""
        if not self.auto_recovery:
            self.connected = False
            self.health = ConnectionHealth.FAILED
            return
        
        self.logger.warning("🔄 Connection failure detected - attempting recovery...")
        self.health = ConnectionHealth.RECOVERING
        
        # Attempt recovery in background
        recovery_thread = threading.Thread(
            target=self._attempt_recovery,
            daemon=True
        )
        recovery_thread.start()
    
    def _attempt_recovery(self):
        """Attempt connection recovery with exponential backoff"""
        for attempt in range(self.max_recovery_attempts):
            try:
                delay = self.recovery_delay_base * (2 ** attempt)
                self.logger.info(f"🔄 Recovery attempt {attempt + 1}/{self.max_recovery_attempts} (delay: {delay}s)")
                
                time.sleep(delay)
                
                # Check device availability
                if not self._check_device_availability():
                    self.logger.warning("📱 No devices available for recovery")
                    break
                
                # Attempt full reconnection
                with self.connection_lock:
                    if self._establish_initial_connection():
                        self.connected = True
                        self.health = ConnectionHealth.HEALTHY
                        self.metrics.update_reconnection()
                        self.logger.info(f"✅ Connection recovered on attempt {attempt + 1}")
                        return
                
            except Exception as e:
                self.logger.debug(f"Recovery attempt {attempt + 1} failed: {e}")
        
        # All recovery attempts failed
        self.connected = False
        self.health = ConnectionHealth.FAILED
        self.logger.warning("❌ Connection recovery failed - falling back to static analysis")
    
    def execute_command_with_recovery(self, command: str, timeout: int = None) -> Tuple[bool, str]:
        """Execute Drozer command with automatic recovery on failure"""
        if not self.connected:
            return False, "No active connection - static analysis mode"
        
        timeout = timeout or self.command_timeout
        
        for attempt in range(2):  # Try twice
            try:
                start_time = time.time()
                cmd = f"drozer console connect --command '{command}'"
                
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                
                response_time = time.time() - start_time
                
                if result.returncode == 0:
                    self.metrics.update_success(response_time)
                    return True, result.stdout.strip()
                else:
                    self.metrics.update_failure()
                    
                    # If first attempt failed and auto-recovery enabled, try recovery
                    if attempt == 0 and self.auto_recovery:
                        self.logger.debug("🔄 Command failed - attempting inline recovery...")
                        if self._quick_recovery():
                            continue  # Retry the command
                    
                    # Mark as disconnected on final failure
                    if attempt == 1:
                        self.connected = False
                        self.health = ConnectionHealth.FAILED
                    
                    return False, result.stderr.strip() or "Command execution failed"
                    
            except subprocess.TimeoutExpired:
                self.metrics.update_failure()
                return False, f"Command timed out after {timeout}s"
            except Exception as e:
                self.metrics.update_failure()
                if attempt == 1:  # Last attempt
                    self.connected = False
                    self.health = ConnectionHealth.FAILED
                return False, f"Command execution error: {str(e)}"
        
        return False, "Command failed after recovery attempts"
    
    def _quick_recovery(self) -> bool:
        """Attempt quick recovery without delay"""
        try:
            with self.connection_lock:
                if self._check_device_availability() and self._establish_initial_connection():
                    self.connected = True
                    self.health = ConnectionHealth.HEALTHY
                    self.metrics.update_reconnection()
                    self.logger.debug("⚡ Quick recovery successful")
                    return True
        except Exception:
            pass
        
        return False
    
    def run_command(self, command: str, timeout: int = None) -> Tuple[bool, str]:
        """Legacy compatibility method"""
        return self.execute_command_with_recovery(command, timeout)
    
    def run_command_safe(self, command: str, fallback: str = "Analysis unavailable - connection issue") -> str:
        """Execute command with safe fallback"""
        success, result = self.execute_command_with_recovery(command)
        return result if success else fallback
    
    def check_connection(self) -> bool:
        """Check if connection is active"""
        return self.connected and self.health != ConnectionHealth.FAILED
    
    def get_connection_status(self) -> Dict:
        """Get comprehensive connection status"""
        return {
            "connected": self.connected,
            "health": self.health.value,
            "device_available": self._device_available,
            "auto_recovery": self.auto_recovery,
            "metrics": {
                "success_rate": self.metrics.success_rate,
                "health_score": self.metrics.health_score,
                "total_commands": self.metrics.successful_commands + self.metrics.failed_commands,
                "reconnections": self.metrics.total_reconnections,
                "avg_response_time": self.metrics.average_response_time
            }
        }
    
    def get_detailed_status(self) -> str:
        """Get detailed status report for diagnostics"""
        status = self.get_connection_status()
        
        report = f"""
🔗 Resilient Drozer Connection Status for {self.package_name}
============================================================
Connection: {'✅ Active' if status['connected'] else '❌ Inactive'}
Health: {status['health'].upper()}
Device Available: {'✅ Yes' if status['device_available'] else '❌ No'}
Auto Recovery: {'✅ Enabled' if status['auto_recovery'] else '❌ Disabled'}

📊 Performance Metrics:
  Success Rate: {status['metrics']['success_rate']:.1%}
  Health Score: {status['metrics']['health_score']:.2f}/1.0
  Total Commands: {status['metrics']['total_commands']}
  Reconnections: {status['metrics']['reconnections']}
  Avg Response Time: {status['metrics']['avg_response_time']:.2f}s

🔄 Recovery Status:
  Max Attempts: {self.max_recovery_attempts}
  Base Delay: {self.recovery_delay_base}s
  Health Check Interval: {self.health_check_interval}s
"""
        return report.strip()
    
    def stop_connection(self) -> bool:
        """Stop connection and cleanup resources"""
        self.health_monitor_active = False
        
        if self.health_monitor_thread and self.health_monitor_thread.is_alive():
            self.health_monitor_thread.join(timeout=2)
        
        try:
            # Clean up port forwarding
            subprocess.run(
                ["adb", "forward", "--remove", "tcp:31415"],
                capture_output=True,
                timeout=5
            )
        except Exception:
            pass
        
        self.connected = False
        self.health = ConnectionHealth.UNKNOWN
        self.logger.info("🔌 Resilient connection stopped")
        return True
    
    def __enter__(self):
        """Context manager entry"""
        self.start_connection()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop_connection()

def create_resilient_drozer_manager(package_name: str, auto_recovery: bool = True) -> ResilientDrozerManager:
    """
    Factory function for creating resilient drozer manager
    
    Args:
        package_name: Package name for the app
        auto_recovery: Enable automatic connection recovery
        
    Returns:
        ResilientDrozerManager instance
    """
    return ResilientDrozerManager(package_name, auto_recovery) 
 
 
 
 