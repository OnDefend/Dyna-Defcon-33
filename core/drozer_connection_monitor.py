#!/usr/bin/env python3
"""
Drozer Connection Monitor
Monitors and maintains Drozer connections during dynamic scans
"""

import time
import threading
import subprocess
import logging
from typing import Dict, List, Callable, Optional
from dataclasses import dataclass
from enum import Enum

class MonitorEvent(Enum):
    """Connection monitor events"""
    CONNECTION_ESTABLISHED = "connection_established"
    CONNECTION_LOST = "connection_lost"
    CONNECTION_RECOVERED = "connection_recovered"
    DEVICE_DISCONNECTED = "device_disconnected"
    RECOVERY_FAILED = "recovery_failed"

@dataclass
class ConnectionEvent:
    """Connection event data"""
    event: MonitorEvent
    timestamp: float
    details: str
    attempt_count: int = 0

class DrozerConnectionMonitor:
    """
    Monitors Drozer connections and automatically handles recovery during scans.
    
    Features:
    - Real-time connection monitoring
    - Automatic ADB port forwarding recovery
    - Event-based notifications
    - Scan state preservation
    - Performance metrics
    """
    
    def __init__(self, package_name: str, check_interval: int = 15):
        self.package_name = package_name
        self.check_interval = check_interval
        self.logger = logging.getLogger(f"drozer_monitor_{package_name}")
        
        # Monitor state
        self.monitoring = False
        self.monitor_thread = None
        self.connection_active = False
        self.last_check_time = 0
        
        # Recovery settings
        self.max_recovery_attempts = 3
        self.recovery_delay = 5
        self.current_recovery_attempt = 0
        
        # Event handling
        self.event_handlers: Dict[MonitorEvent, List[Callable]] = {
            event: [] for event in MonitorEvent
        }
        self.recent_events: List[ConnectionEvent] = []
        
        # Performance tracking
        self.connection_uptime_start = 0
        self.total_downtime = 0
        self.recovery_count = 0
        
        self.logger.info(f"Connection Monitor initialized for {package_name}")
    
    def add_event_handler(self, event: MonitorEvent, handler: Callable[[ConnectionEvent], None]):
        """Add event handler for connection events"""
        self.event_handlers[event].append(handler)
        self.logger.debug(f"Added handler for {event.value}")
    
    def start_monitoring(self) -> bool:
        """Start connection monitoring"""
        if self.monitoring:
            return True
        
        # Initial connection check
        if self._check_initial_connection():
            self.monitoring = True
            self.monitor_thread = threading.Thread(
                target=self._monitor_loop,
                daemon=True
            )
            self.monitor_thread.start()
            self.logger.info("Connection monitoring started")
            return True
        else:
            self.logger.warning("Initial connection check failed - monitoring not started")
            return False
    
    def stop_monitoring(self):
        """Stop connection monitoring"""
        self.monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=3)
        self.logger.info("Connection monitoring stopped")
    
    def _check_initial_connection(self) -> bool:
        """Check initial connection status"""
        try:
            # Check device availability
            if not self._is_device_available():
                self._emit_event(MonitorEvent.DEVICE_DISCONNECTED, "No devices detected")
                return False
            
            # Check Drozer connectivity
            if self._test_drozer_connection():
                self.connection_active = True
                self.connection_uptime_start = time.time()
                self._emit_event(MonitorEvent.CONNECTION_ESTABLISHED, "Initial connection verified")
                return True
            else:
                self._emit_event(MonitorEvent.CONNECTION_LOST, "Initial Drozer test failed")
                return False
                
        except Exception as e:
            self._emit_event(MonitorEvent.CONNECTION_LOST, f"Initial check error: {e}")
            return False
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                self._perform_connection_check()
                time.sleep(self.check_interval)
            except Exception as e:
                self.logger.debug(f"Monitor loop error: {e}")
                time.sleep(5)
    
    def _perform_connection_check(self):
        """Perform periodic connection health check"""
        self.last_check_time = time.time()
        
        # Check device availability first
        if not self._is_device_available():
            if self.connection_active:
                self.connection_active = False
                self._track_downtime()
                self._emit_event(MonitorEvent.DEVICE_DISCONNECTED, "Device no longer available")
            return
        
        # Check Drozer connection
        if self._test_drozer_connection():
            if not self.connection_active:
                # Connection restored
                self.connection_active = True
                self.connection_uptime_start = time.time()
                self.current_recovery_attempt = 0
                self._emit_event(MonitorEvent.CONNECTION_RECOVERED, "Connection restored")
        else:
            if self.connection_active:
                # Connection lost
                self.connection_active = False
                self._track_downtime()
                self._emit_event(MonitorEvent.CONNECTION_LOST, "Drozer connection lost")
                
                # Attempt automatic recovery
                self._attempt_connection_recovery()
    
    def _is_device_available(self) -> bool:
        """Check if Android device is available"""
        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                return False
            
            lines = result.stdout.strip().split('\n')[1:]
            active_devices = [line for line in lines if 'device' in line and line.strip()]
            return len(active_devices) > 0
            
        except Exception:
            return False
    
    def _test_drozer_connection(self) -> bool:
        """Test Drozer connection with lightweight command"""
        try:
            result = subprocess.run(
                ["drozer", "console", "connect", "--command", "list"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _attempt_connection_recovery(self):
        """Attempt to recover Drozer connection"""
        if self.current_recovery_attempt >= self.max_recovery_attempts:
            self._emit_event(
                MonitorEvent.RECOVERY_FAILED, 
                f"Max recovery attempts ({self.max_recovery_attempts}) exceeded"
            )
            return
        
        self.current_recovery_attempt += 1
        
        self.logger.info(f"Attempting connection recovery {self.current_recovery_attempt}/{self.max_recovery_attempts}")
        
        # Run recovery in background thread
        recovery_thread = threading.Thread(
            target=self._perform_recovery,
            daemon=True
        )
        recovery_thread.start()
    
    def _perform_recovery(self):
        """Perform connection recovery steps"""
        try:
            # Wait before recovery attempt
            time.sleep(self.recovery_delay)
            
            # Step 1: Reset ADB port forwarding
            self.logger.debug("Resetting ADB port forwarding...")
            self._reset_port_forwarding()
            
            # Step 2: Wait for stabilization
            time.sleep(2)
            
            # Step 3: Test connection
            if self._test_drozer_connection():
                self.connection_active = True
                self.connection_uptime_start = time.time()
                self.current_recovery_attempt = 0
                self.recovery_count += 1
                
                self._emit_event(
                    MonitorEvent.CONNECTION_RECOVERED, 
                    f"Recovery successful on attempt {self.current_recovery_attempt}"
                )
                self.logger.info(f"Connection recovered successfully")
            else:
                self.logger.warning(f"Recovery attempt {self.current_recovery_attempt} failed")
                
                # Schedule next attempt if within limits
                if self.current_recovery_attempt < self.max_recovery_attempts:
                    time.sleep(self.recovery_delay * self.current_recovery_attempt)  # Exponential backoff
                    self._attempt_connection_recovery()
                else:
                    self._emit_event(MonitorEvent.RECOVERY_FAILED, "All recovery attempts exhausted")
        
        except Exception as e:
            self.logger.debug(f"Recovery error: {e}")
            self._emit_event(MonitorEvent.RECOVERY_FAILED, f"Recovery error: {e}")
    
    def _reset_port_forwarding(self):
        """Reset ADB port forwarding"""
        try:
            # Remove existing forwarding
            subprocess.run(
                ["adb", "forward", "--remove", "tcp:31415"],
                capture_output=True,
                timeout=5
            )
            
            # Re-establish forwarding
            result = subprocess.run(
                ["adb", "forward", "tcp:31415", "tcp:31415"],
                capture_output=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.logger.debug("Port forwarding reset successful")
            else:
                self.logger.debug("Port forwarding reset failed")
                
        except Exception as e:
            self.logger.debug(f"Port forwarding reset error: {e}")
    
    def _track_downtime(self):
        """Track connection downtime"""
        if self.connection_uptime_start > 0:
            uptime = time.time() - self.connection_uptime_start
            self.total_downtime += uptime
            self.connection_uptime_start = 0
    
    def _emit_event(self, event: MonitorEvent, details: str):
        """Emit connection event to handlers"""
        event_obj = ConnectionEvent(
            event=event,
            timestamp=time.time(),
            details=details,
            attempt_count=self.current_recovery_attempt
        )
        
        # Store recent event
        self.recent_events.append(event_obj)
        if len(self.recent_events) > 50:  # Keep last 50 events
            self.recent_events.pop(0)
        
        # Call event handlers
        for handler in self.event_handlers[event]:
            try:
                handler(event_obj)
            except Exception as e:
                self.logger.debug(f"Event handler error: {e}")
        
        # Log event
        self.logger.info(f"📡 {event.value}: {details}")
    
    def force_connection_check(self) -> bool:
        """Force immediate connection check"""
        self._perform_connection_check()
        return self.connection_active
    
    def get_connection_status(self) -> Dict:
        """Get current connection status"""
        current_time = time.time()
        
        # Calculate current uptime
        current_uptime = 0
        if self.connection_active and self.connection_uptime_start > 0:
            current_uptime = current_time - self.connection_uptime_start
        
        return {
            "connected": self.connection_active,
            "monitoring": self.monitoring,
            "last_check": self.last_check_time,
            "recovery_attempts": self.current_recovery_attempt,
            "max_recovery_attempts": self.max_recovery_attempts,
            "total_recoveries": self.recovery_count,
            "current_uptime": current_uptime,
            "total_downtime": self.total_downtime,
            "recent_events": len(self.recent_events)
        }
    
    def get_event_history(self, limit: int = 10) -> List[Dict]:
        """Get recent event history"""
        recent = self.recent_events[-limit:]
        return [
            {
                "event": event.event.value,
                "timestamp": event.timestamp,
                "details": event.details,
                "attempt_count": event.attempt_count
            }
            for event in recent
        ]
    
    def get_performance_report(self) -> str:
        """Generate performance report"""
        status = self.get_connection_status()
        
        # Calculate availability percentage
        total_time = status["current_uptime"] + status["total_downtime"]
        availability = 0
        if total_time > 0:
            availability = (status["current_uptime"] / total_time) * 100
        
        report = f"""
🔍 Drozer Connection Monitor Report - {self.package_name}
========================================================
Status: {'🟢 Connected' if status['connected'] else '🔴 Disconnected'}
Monitoring: {'🟢 Active' if status['monitoring'] else '🔴 Inactive'}

📊 Performance Metrics:
  Availability: {availability:.1f}%
  Current Uptime: {status['current_uptime']:.1f}s
  Total Downtime: {status['total_downtime']:.1f}s
  Successful Recoveries: {status['total_recoveries']}
  
🔄 Recovery Status:
  Current Attempts: {status['recovery_attempts']}/{status['max_recovery_attempts']}
  Last Check: {time.time() - status['last_check']:.1f}s ago
  
📡 Recent Events: {status['recent_events']} events recorded
"""
        
        return report.strip()

# Integration helper functions
def create_scan_integrated_monitor(package_name: str) -> DrozerConnectionMonitor:
    """Create a monitor optimized for scan integration"""
    monitor = DrozerConnectionMonitor(package_name, check_interval=20)
    
    # Add default event handlers for scan integration
    def handle_connection_lost(event: ConnectionEvent):
        logging.warning(f"Dynamic scan paused - connection lost: {event.details}")
    
    def handle_connection_recovered(event: ConnectionEvent):
        logging.info(f"Dynamic scan resumed - connection recovered: {event.details}")
    
    def handle_recovery_failed(event: ConnectionEvent):
        logging.error(f"Dynamic scan degraded - recovery failed: {event.details}")
    
    monitor.add_event_handler(MonitorEvent.CONNECTION_LOST, handle_connection_lost)
    monitor.add_event_handler(MonitorEvent.CONNECTION_RECOVERED, handle_connection_recovered)
    monitor.add_event_handler(MonitorEvent.RECOVERY_FAILED, handle_recovery_failed)
    
    return monitor 
 
 
 
 