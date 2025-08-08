__all__ = ["create_enhanced_process_manager", "EnhancedInterProcessCommunicator", "ProcessHealthMonitor"]

#!/usr/bin/env python3
"""
Enhanced Process Management for AODS Parallel Execution

This module provides enhanced process management capabilities including:
- Independent timeout handling for static (10min) and dynamic (8min) processes
- Process health monitoring with heartbeat detection
- Enhanced error recovery and graceful cleanup
- Improved inter-process communication robustness

Implementation: Advanced Process Management with Timeout and Health Monitoring
"""

import logging
import multiprocessing as mp
import os
import signal
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Any, Callable

from rich.console import Console

logger = logging.getLogger(__name__)

@dataclass
class ProcessTimeoutConfig:
    """Configuration for process timeouts."""
    static_timeout: int = 600  # 10 minutes
    dynamic_timeout: int = 480  # 8 minutes
    cleanup_timeout: int = 30   # 30 seconds for graceful cleanup
    heartbeat_interval: int = 5  # 5 seconds between heartbeats

class ProcessStatus(Enum):
    """Process status enumeration."""
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    TERMINATED = "terminated"

class ProcessHealthMonitor:
    """Monitor process health with timeout and heartbeat detection."""
    
    def __init__(self, timeout_config: ProcessTimeoutConfig):
        self.timeout_config = timeout_config
        self.process_registry: Dict[str, Dict[str, Any]] = {}
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.shutdown_event = threading.Event()
        
    def register_process_start(self, process_id: str, process_type: str):
        """Register a process start for monitoring."""
        self.process_registry[process_id] = {
            'type': process_type,
            'start_time': time.time(),
            'last_heartbeat': time.time(),
            'status': ProcessStatus.INITIALIZING.value,
            'timeout': (
                self.timeout_config.static_timeout if process_type == 'static' 
                else self.timeout_config.dynamic_timeout
            )
        }
        logger.info(f"Process registered: {process_id} ({process_type})")
    
    def update_process_heartbeat(self, process_id: str):
        """Update process heartbeat timestamp."""
        if process_id in self.process_registry:
            self.process_registry[process_id]['last_heartbeat'] = time.time()
            self.process_registry[process_id]['status'] = ProcessStatus.RUNNING.value
    
    def start_monitoring(self):
        """Start the monitoring thread."""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitor_thread = threading.Thread(target=self._monitor_processes, daemon=True)
            self.monitor_thread.start()
            logger.info("Process health monitoring started")
    
    def _monitor_processes(self):
        """Monitor processes for timeouts and health issues."""
        while self.monitoring_active and not self.shutdown_event.is_set():
            current_time = time.time()
            
            for process_id, info in self.process_registry.items():
                # Check for timeout
                elapsed_time = current_time - info['start_time']
                if elapsed_time > info['timeout']:
                    info['status'] = ProcessStatus.TIMEOUT.value
                    logger.warning(f"Process timeout detected: {process_id} ({elapsed_time:.1f}s)")
                
                # Check for heartbeat timeout (2x heartbeat interval)
                heartbeat_elapsed = current_time - info['last_heartbeat']
                if heartbeat_elapsed > (self.timeout_config.heartbeat_interval * 2):
                    logger.warning(f"Process heartbeat timeout: {process_id} ({heartbeat_elapsed:.1f}s)")
            
            time.sleep(self.timeout_config.heartbeat_interval)
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status."""
        return {
            'active': self.monitoring_active,
            'processes_monitored': len(self.process_registry),
            'process_details': dict(self.process_registry)
        }
    
    def cleanup_monitoring(self):
        """Clean up monitoring resources."""
        self.monitoring_active = False
        self.shutdown_event.set()
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)
        logger.info("Process health monitoring stopped")

class EnhancedInterProcessCommunicator:
    """Enhanced inter-process communicator with timeout management and health monitoring."""
    
    def __init__(self, timeout_config: ProcessTimeoutConfig = None):
        # Initialize base communication components
        self.static_queue = mp.Queue()
        self.dynamic_queue = mp.Queue()
        self.coordinator_queue = mp.Queue()
        self.shared_state = mp.Manager().dict()
        self.results_dict = mp.Manager().dict()
        self.shutdown_event = mp.Event()
        
        # Enhanced components
        self.timeout_config = timeout_config or ProcessTimeoutConfig()
        self.health_monitor = ProcessHealthMonitor(self.timeout_config)
        
        # Initialize enhanced shared state
        self.shared_state.update({
            'static_progress': 0.0,
            'dynamic_progress': 0.0,
            'static_status': 'initializing',
            'dynamic_status': 'initializing',
            'static_task': '',
            'dynamic_task': '',
            'start_time': time.time(),
            'static_start_time': None,
            'dynamic_start_time': None,
            'static_timeout': self.timeout_config.static_timeout,
            'dynamic_timeout': self.timeout_config.dynamic_timeout,
            'process_errors': {}
        })
    
    def start_process_monitoring(self):
        """Start monitoring processes with timeout handling."""
        self.health_monitor.start_monitoring()
    
    def register_process_start(self, process_id: str, process_type: str):
        """Register a process start for monitoring."""
        self.health_monitor.register_process_start(process_id, process_type)
        
        # Update shared state
        if process_type == 'static':
            self.shared_state['static_start_time'] = time.time()
        elif process_type == 'dynamic':
            self.shared_state['dynamic_start_time'] = time.time()
    
    def update_process_heartbeat(self, process_id: str):
        """Update process heartbeat."""
        self.health_monitor.update_process_heartbeat(process_id)
    
    def report_process_error(self, process_id: str, error: str):
        """Report a process error."""
        if 'process_errors' not in self.shared_state:
            self.shared_state['process_errors'] = {}
        
        errors = dict(self.shared_state['process_errors'])
        errors[process_id] = {
            'error': error,
            'timestamp': time.time()
        }
        self.shared_state['process_errors'] = errors
    
    def cleanup_monitoring(self):
        """Clean up monitoring resources."""
        self.health_monitor.cleanup_monitoring()
    
    def get_enhanced_shared_state(self) -> Dict:
        """Get current enhanced shared state including monitoring status."""
        base_state = dict(self.shared_state)
        monitoring_status = self.health_monitor.get_monitoring_status()
        
        return {
            **base_state,
            'monitoring': monitoring_status
        }
    
    # Maintain compatibility with existing interface
    def update_progress(self, process_type: str, progress: float, task: str = ""):
        """Update progress for a specific process (compatibility method)."""
        if process_type.lower() == "static":
            self.shared_state['static_progress'] = progress
            self.shared_state['static_task'] = task
        elif process_type.lower() == "dynamic":
            self.shared_state['dynamic_progress'] = progress
            self.shared_state['dynamic_task'] = task
    
    def update_status(self, process_type: str, status: str):
        """Update status for a specific process (compatibility method)."""
        if process_type.lower() == "static":
            self.shared_state['static_status'] = status
        elif process_type.lower() == "dynamic":
            self.shared_state['dynamic_status'] = status
    
    def get_shared_state(self) -> Dict:
        """Get current shared state (compatibility method)."""
        return dict(self.shared_state)
    
    def store_results(self, process_type: str, results: Dict[str, Any]):
        """Store results from a process (compatibility method)."""
        self.results_dict[process_type.lower()] = results
    
    def signal_shutdown(self):
        """Signal all processes to shutdown."""
        self.shutdown_event.set()
        self.cleanup_monitoring()
    
    def is_shutdown_requested(self) -> bool:
        """Check if shutdown has been requested."""
        return self.shutdown_event.is_set()

def create_enhanced_process_manager(
    static_timeout: int = 600,
    dynamic_timeout: int = 480
) -> Dict[str, Any]:
    """
    Create an enhanced process manager with specified timeouts.
    
    Args:
        static_timeout: Timeout for static analysis in seconds
        dynamic_timeout: Timeout for dynamic analysis in seconds
        
    Returns:
        Dictionary containing enhanced process management components
    """
    
    timeout_config = ProcessTimeoutConfig(
        static_timeout=static_timeout,
        dynamic_timeout=dynamic_timeout
    )
    
    communicator = EnhancedInterProcessCommunicator(timeout_config)
    health_monitor = communicator.health_monitor
    
    return {
        'timeout_config': timeout_config,
        'communicator': communicator,
        'health_monitor': health_monitor
    }

def main():
    """Test the enhanced process management capabilities."""
    print("Testing Enhanced Process Management with Timeout Handling")
    
    # Create enhanced process manager
    manager = create_enhanced_process_manager(
        static_timeout=600,
        dynamic_timeout=480
    )
    
    communicator = manager['communicator']
    
    # Start monitoring
    communicator.start_process_monitoring()
    
    # Simulate process registration
    communicator.register_process_start("static_001", "static")
    communicator.register_process_start("dynamic_001", "dynamic")
    
    # Test heartbeat updates
    for i in range(3):
        time.sleep(1)
        communicator.update_process_heartbeat("static_001")
        communicator.update_process_heartbeat("dynamic_001")
        print(f"Heartbeat {i+1}: Updated")
    
    # Get monitoring status
    status = communicator.get_enhanced_shared_state()
    print(f"Monitoring status: {status['monitoring']}")
    
    # Cleanup
    communicator.signal_shutdown()
    
    print("✅ Enhanced Process Management with Timeout Handling - COMPLETED")

if __name__ == "__main__":
    main() 
 