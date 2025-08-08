#!/usr/bin/env python3
"""
Resource Monitor

Unified resource monitoring for all execution strategies.
"""

import logging
import psutil
import threading
import time
from dataclasses import dataclass
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

@dataclass
class ResourceSnapshot:
    """Snapshot of system resources at a point in time."""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    memory_used_gb: float
    memory_total_gb: float

class ResourceMonitor:
    """Unified resource monitoring for execution strategies."""
    
    def __init__(self, enable_monitoring: bool = True):
        """Initialize resource monitor."""
        self.enable_monitoring = enable_monitoring
        self.logger = logging.getLogger(__name__)
        
        self._snapshots = []
        self._monitoring_thread = None
        self._stop_monitoring = threading.Event()
        
        if self.enable_monitoring:
            self.logger.info("Resource monitor initialized")
    
    def start_monitoring(self, interval_seconds: float = 1.0):
        """Start continuous resource monitoring."""
        if not self.enable_monitoring:
            return
        
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            return
        
        self._stop_monitoring.clear()
        self._monitoring_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval_seconds,),
            daemon=True
        )
        self._monitoring_thread.start()
        
        self.logger.debug("Started resource monitoring")
    
    def stop_monitoring(self):
        """Stop resource monitoring."""
        if self._monitoring_thread:
            self._stop_monitoring.set()
            self._monitoring_thread.join(timeout=2.0)
        
        self.logger.debug("Stopped resource monitoring")
    
    def get_current_snapshot(self) -> ResourceSnapshot:
        """Get current resource snapshot."""
        try:
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent()
            
            return ResourceSnapshot(
                timestamp=time.time(),
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_used_gb=memory.used / (1024**3),
                memory_total_gb=memory.total / (1024**3)
            )
        except Exception as e:
            self.logger.warning(f"Failed to get resource snapshot: {e}")
            return ResourceSnapshot(
                timestamp=time.time(),
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_used_gb=0.0,
                memory_total_gb=0.0
            )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get resource monitoring statistics."""
        if not self._snapshots:
            return {}
        
        cpu_values = [s.cpu_percent for s in self._snapshots]
        memory_values = [s.memory_percent for s in self._snapshots]
        
        return {
            'samples': len(self._snapshots),
            'cpu': {
                'min': min(cpu_values),
                'max': max(cpu_values),
                'avg': sum(cpu_values) / len(cpu_values)
            },
            'memory': {
                'min': min(memory_values),
                'max': max(memory_values),
                'avg': sum(memory_values) / len(memory_values)
            }
        }
    
    def _monitor_loop(self, interval_seconds: float):
        """Main monitoring loop."""
        while not self._stop_monitoring.wait(interval_seconds):
            try:
                snapshot = self.get_current_snapshot()
                self._snapshots.append(snapshot)
                
                # Keep only recent snapshots (last 1000)
                if len(self._snapshots) > 1000:
                    self._snapshots = self._snapshots[-1000:]
                    
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")

def create_resource_monitor(enable_monitoring: bool = True) -> ResourceMonitor:
    """Factory function to create resource monitor."""
    return ResourceMonitor(enable_monitoring) 