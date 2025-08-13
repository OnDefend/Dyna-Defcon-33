#!/usr/bin/env python3
"""
Connection Stability Manager for AODS

This module provides comprehensive connection stability monitoring and recovery
to ensure AODS maintains stable connections throughout security scans.

Key Features:
- Real-time connection monitoring
- Automatic recovery mechanisms
- Network stability assessment
- Connection quality metrics
- Graceful degradation handling
"""

import asyncio
import logging
import threading
import time
import subprocess
from typing import Dict, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import queue

class StabilityLevel(Enum):
    """Connection stability levels"""
    EXCELLENT = "excellent"    # 95%+ success rate
    GOOD = "good"             # 85-high success rate
    FAIR = "fair"             # 70-high success rate
    POOR = "poor"             # 50-high success rate
    UNSTABLE = "unstable"     # <high success rate
    FAILED = "failed"         # No connectivity

@dataclass
class ConnectionMetrics:
    """Connection quality and performance metrics"""
    success_rate: float = 0.0
    average_latency: float = 0.0
    max_latency: float = 0.0
    min_latency: float = float('inf')
    total_checks: int = 0
    successful_checks: int = 0
    failed_checks: int = 0
    disconnection_events: int = 0
    recovery_attempts: int = 0
    successful_recoveries: int = 0
    last_check_time: float = field(default_factory=time.time)
    stability_level: StabilityLevel = StabilityLevel.EXCELLENT

@dataclass
class StabilityEvent:
    """Stability monitoring event"""
    timestamp: float
    event_type: str
    success: bool
    latency: Optional[float] = None
    error_message: Optional[str] = None
    device_id: Optional[str] = None

class ConnectionStabilityManager:
    """
    Manages connection stability monitoring and recovery for Android devices
    """

    def __init__(self, device_id: Optional[str] = None, check_interval: int = 15):
        """
        Initialize the connection stability manager
        
        Args:
            device_id: Target device ID (None for auto-detection)
            check_interval: Stability check interval in seconds
        """
        self.device_id = device_id
        self.check_interval = check_interval
        self.logger = logging.getLogger("connection_stability")
        
        # Monitoring state
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        
        # Metrics and history
        self.metrics = ConnectionMetrics()
        self.event_history: List[StabilityEvent] = []
        self.max_history_size = 1000
        
        # Recovery configuration
        self.auto_recovery_enabled = True
        self.max_recovery_attempts = 3
        self.recovery_delay_base = 2  # Base delay for exponential backoff
        
        # Callbacks
        self.stability_callbacks: List[Callable] = []
        self.recovery_callbacks: List[Callable] = []
        
        # Thread safety
        self._lock = threading.Lock()
        self._event_queue = queue.Queue()
        
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Setup logging for stability manager"""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def start_monitoring(self, device_id: Optional[str] = None) -> bool:
        """
        Start connection stability monitoring
        
        Args:
            device_id: Device to monitor (overrides constructor parameter)
            
        Returns:
            bool: True if monitoring started successfully
        """
        if self.monitoring_active:
            self.logger.warning("Monitoring already active")
            return True

        if device_id:
            self.device_id = device_id

        if not self.device_id:
            # Auto-detect device
            self.device_id = self._detect_primary_device()
            if not self.device_id:
                self.logger.error("No device available for monitoring")
                return False

        self.logger.info(f"🔍 Starting stability monitoring for device: {self.device_id}")
        
        # Reset metrics
        self.metrics = ConnectionMetrics()
        self.event_history.clear()
        
        # Start monitoring thread
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            name="stability_monitor",
            daemon=True
        )
        self.monitoring_thread.start()
        
        return True

    def stop_monitoring(self) -> None:
        """Stop connection stability monitoring"""
        if not self.monitoring_active:
            return

        self.logger.info("🔌 Stopping stability monitoring...")
        self.monitoring_active = False
        
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        
        self.logger.info("✅ Stability monitoring stopped")

    def _monitoring_loop(self) -> None:
        """Main monitoring loop"""
        consecutive_failures = 0
        
        while self.monitoring_active:
            try:
                # Perform stability check
                check_result = self._perform_stability_check()
                
                # Update metrics
                self._update_metrics(check_result)
                
                # Handle check result
                if check_result.success:
                    consecutive_failures = 0
                    
                    # Call success callbacks
                    self._notify_stability_callbacks(True, check_result)
                    
                else:
                    consecutive_failures += 1
                    self.logger.warning(
                        f"⚠️ Stability check failed ({consecutive_failures} consecutive failures)"
                    )
                    
                    # Call failure callbacks
                    self._notify_stability_callbacks(False, check_result)
                    
                    # Attempt recovery if threshold exceeded
                    if consecutive_failures >= 3 and self.auto_recovery_enabled:
                        recovery_success = self._attempt_recovery()
                        if recovery_success:
                            consecutive_failures = 0
                        else:
                            self.logger.error("❌ Recovery failed")

                # Sleep until next check
                time.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"❌ Monitoring loop error: {e}")
                time.sleep(self.check_interval)

    def _perform_stability_check(self) -> StabilityEvent:
        """Perform comprehensive stability check"""
        start_time = time.time()
        
        try:
            # Test 1: Basic ADB connectivity
            adb_latency = self._check_adb_connectivity()
            
            if adb_latency is None:
                return StabilityEvent(
                    timestamp=start_time,
                    event_type="adb_check",
                    success=False,
                    error_message="ADB connectivity failed",
                    device_id=self.device_id
                )

            # Test 2: Device responsiveness
            shell_latency = self._check_shell_responsiveness()
            
            if shell_latency is None:
                return StabilityEvent(
                    timestamp=start_time,
                    event_type="shell_check",
                    success=False,
                    error_message="Shell responsiveness failed",
                    device_id=self.device_id
                )

            # Test 3: Port forwarding status
            port_ok = self._check_port_forwarding()
            
            if not port_ok:
                return StabilityEvent(
                    timestamp=start_time,
                    event_type="port_check",
                    success=False,
                    error_message="Port forwarding failed",
                    device_id=self.device_id
                )

            # Calculate overall latency
            total_latency = adb_latency + shell_latency
            
            return StabilityEvent(
                timestamp=start_time,
                event_type="stability_check",
                success=True,
                latency=total_latency,
                device_id=self.device_id
            )

        except Exception as e:
            return StabilityEvent(
                timestamp=start_time,
                event_type="stability_check",
                success=False,
                error_message=str(e),
                device_id=self.device_id
            )

    def _check_adb_connectivity(self) -> Optional[float]:
        """Check basic ADB connectivity and return latency"""
        try:
            start_time = time.time()
            
            result = subprocess.run(
                ["adb", "-s", self.device_id, "get-state"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                return time.time() - start_time
            
        except Exception as e:
            self.logger.debug(f"ADB connectivity check failed: {e}")
        
        return None

    def _check_shell_responsiveness(self) -> Optional[float]:
        """Check shell responsiveness and return latency"""
        try:
            start_time = time.time()
            
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "echo", "stability_test"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and "stability_test" in result.stdout:
                return time.time() - start_time
            
        except Exception as e:
            self.logger.debug(f"Shell responsiveness check failed: {e}")
        
        return None

    def _check_port_forwarding(self) -> bool:
        """Check if port forwarding is active"""
        try:
            result = subprocess.run(
                ["adb", "-s", self.device_id, "forward", "--list"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Check if drozer port (31415) is forwarded
            return result.returncode == 0 and "31415" in result.stdout
            
        except Exception as e:
            self.logger.debug(f"Port forwarding check failed: {e}")
            return False

    def _update_metrics(self, event: StabilityEvent) -> None:
        """Update connection metrics with new event"""
        with self._lock:
            self.metrics.total_checks += 1
            
            if event.success:
                self.metrics.successful_checks += 1
                
                if event.latency is not None:
                    # Update latency metrics
                    total_latency = (self.metrics.average_latency * 
                                   (self.metrics.successful_checks - 1) + event.latency)
                    self.metrics.average_latency = total_latency / self.metrics.successful_checks
                    self.metrics.max_latency = max(self.metrics.max_latency, event.latency)
                    self.metrics.min_latency = min(self.metrics.min_latency, event.latency)
            else:
                self.metrics.failed_checks += 1
                
                if "connectivity" in event.error_message.lower():
                    self.metrics.disconnection_events += 1

            # Calculate success rate
            self.metrics.success_rate = (
                self.metrics.successful_checks / self.metrics.total_checks
            )
            
            # Determine stability level
            self.metrics.stability_level = self._calculate_stability_level(
                self.metrics.success_rate
            )
            
            # Update timestamp
            self.metrics.last_check_time = event.timestamp
            
            # Add to history
            self.event_history.append(event)
            
            # Trim history if needed
            if len(self.event_history) > self.max_history_size:
                self.event_history = self.event_history[-self.max_history_size//2:]

    def _calculate_stability_level(self, success_rate: float) -> StabilityLevel:
        """Calculate stability level from success rate"""
        if success_rate >= 0.95:
            return StabilityLevel.EXCELLENT
        elif success_rate >= 0.85:
            return StabilityLevel.GOOD
        elif success_rate >= 0.70:
            return StabilityLevel.FAIR
        elif success_rate >= 0.50:
            return StabilityLevel.POOR
        elif success_rate > 0:
            return StabilityLevel.UNSTABLE
        else:
            return StabilityLevel.FAILED

    def _attempt_recovery(self) -> bool:
        """Attempt to recover connection stability"""
        self.logger.info("🔄 Attempting connection recovery...")
        self.metrics.recovery_attempts += 1
        
        try:
            # Step 1: Reset ADB connection
            if self._reset_adb_connection():
                # Step 2: Re-establish port forwarding
                if self._reestablish_port_forwarding():
                    # Step 3: Verify connectivity
                    if self._verify_recovery():
                        self.metrics.successful_recoveries += 1
                        self.logger.info("✅ Connection recovery successful")
                        
                        # Notify recovery callbacks
                        self._notify_recovery_callbacks(True)
                        return True

            self.logger.warning("❌ Connection recovery failed")
            self._notify_recovery_callbacks(False)
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Recovery attempt failed: {e}")
            self._notify_recovery_callbacks(False)
            return False

    def _reset_adb_connection(self) -> bool:
        """Reset ADB connection to device"""
        try:
            # Disconnect and reconnect device
            subprocess.run(
                ["adb", "disconnect", self.device_id],
                capture_output=True,
                timeout=5
            )
            
            time.sleep(2)
            
            # For network devices, try to reconnect
            if ":" in self.device_id:
                result = subprocess.run(
                    ["adb", "connect", self.device_id],
                    capture_output=True,
                    timeout=10
                )
                return result.returncode == 0
            
            return True
            
        except Exception as e:
            self.logger.debug(f"ADB reset failed: {e}")
            return False

    def _reestablish_port_forwarding(self) -> bool:
        """Re-establish port forwarding for drozer"""
        try:
            # Remove existing forwarding
            subprocess.run(
                ["adb", "-s", self.device_id, "forward", "--remove", "tcp:31415"],
                capture_output=True,
                timeout=5
            )
            
            time.sleep(1)
            
            # Re-establish forwarding
            result = subprocess.run(
                ["adb", "-s", self.device_id, "forward", "tcp:31415", "tcp:31415"],
                capture_output=True,
                timeout=10
            )
            
            return result.returncode == 0
            
        except Exception as e:
            self.logger.debug(f"Port forwarding re-establishment failed: {e}")
            return False

    def _verify_recovery(self) -> bool:
        """Verify that recovery was successful"""
        try:
            # Perform a quick stability check
            result = self._perform_stability_check()
            return result.success
            
        except Exception:
            return False

    def _detect_primary_device(self) -> Optional[str]:
        """Auto-detect the primary device for monitoring"""
        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    if '\tdevice' in line or ' device' in line:
                        return line.split()[0]
            
        except Exception as e:
            self.logger.debug(f"Device detection failed: {e}")
        
        return None

    def _notify_stability_callbacks(self, success: bool, event: StabilityEvent) -> None:
        """Notify stability event callbacks"""
        for callback in self.stability_callbacks:
            try:
                callback(success, event, self.metrics)
            except Exception as e:
                self.logger.debug(f"Stability callback failed: {e}")

    def _notify_recovery_callbacks(self, success: bool) -> None:
        """Notify recovery event callbacks"""
        for callback in self.recovery_callbacks:
            try:
                callback(success, self.metrics)
            except Exception as e:
                self.logger.debug(f"Recovery callback failed: {e}")

    def add_stability_callback(self, callback: Callable) -> None:
        """Add callback for stability events"""
        self.stability_callbacks.append(callback)

    def add_recovery_callback(self, callback: Callable) -> None:
        """Add callback for recovery events"""
        self.recovery_callbacks.append(callback)

    def get_connection_status(self) -> Dict:
        """Get comprehensive connection status"""
        with self._lock:
            return {
                "device_id": self.device_id,
                "monitoring_active": self.monitoring_active,
                "stability_level": self.metrics.stability_level.value,
                "success_rate": self.metrics.success_rate,
                "average_latency": self.metrics.average_latency,
                "total_checks": self.metrics.total_checks,
                "successful_checks": self.metrics.successful_checks,
                "failed_checks": self.metrics.failed_checks,
                "disconnection_events": self.metrics.disconnection_events,
                "recovery_attempts": self.metrics.recovery_attempts,
                "successful_recoveries": self.metrics.successful_recoveries,
                "last_check_time": self.metrics.last_check_time
            }

    def get_stability_report(self) -> str:
        """Generate a detailed stability report"""
        status = self.get_connection_status()
        
        report = f"""
📊 Connection Stability Report
═══════════════════════════════
Device: {status['device_id']}
Stability Level: {status['stability_level'].upper()}
Success Rate: {status['success_rate']:.1%}

📈 Performance Metrics:
  • Total Checks: {status['total_checks']}
  • Successful: {status['successful_checks']}
  • Failed: {status['failed_checks']}
  • Average Latency: {status['average_latency']:.3f}s

🔄 Recovery Statistics:
  • Disconnection Events: {status['disconnection_events']}
  • Recovery Attempts: {status['recovery_attempts']}
  • Successful Recoveries: {status['successful_recoveries']}

🔍 Monitoring Status: {'Active' if status['monitoring_active'] else 'Inactive'}
"""
        return report

    def force_recovery(self) -> bool:
        """Force a connection recovery attempt"""
        self.logger.info("🔧 Forcing connection recovery...")
        return self._attempt_recovery()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop_monitoring()

# Factory function for easy integration
def create_stability_manager(device_id: Optional[str] = None, 
                           check_interval: int = 15) -> ConnectionStabilityManager:
    """Create a connection stability manager instance"""
    return ConnectionStabilityManager(device_id, check_interval) 