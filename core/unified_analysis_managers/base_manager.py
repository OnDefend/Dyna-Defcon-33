#!/usr/bin/env python3
"""
Base Analysis Manager Interface

Provides common interface and functionality for all analysis managers
in the unified analysis management framework.
"""

import abc
import logging
import threading
import time
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field
from enum import Enum

class ManagerStatus(Enum):
    """Status of an analysis manager."""
    INITIALIZING = "initializing"
    READY = "ready"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RUNNING = "running"
    FAILED = "failed"
    DISCONNECTED = "disconnected"
    CLEANUP = "cleanup"

@dataclass
class AnalysisManagerConfig:
    """Configuration for analysis managers."""
    package_name: str
    strategy: str = "auto"
    enable_monitoring: bool = True
    enable_fallback: bool = True
    timeout_seconds: int = 300
    max_retries: int = 3
    retry_delay: float = 2.0
    enable_logging: bool = True
    custom_params: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ManagerMetrics:
    """Performance metrics for analysis managers."""
    connections_attempted: int = 0
    connections_successful: int = 0
    connections_failed: int = 0
    commands_executed: int = 0
    commands_successful: int = 0
    commands_failed: int = 0
    total_execution_time: float = 0.0
    average_response_time: float = 0.0
    last_activity_time: float = 0.0
    error_count: int = 0

class BaseAnalysisManager(abc.ABC):
    """
    Base class for all analysis managers.
    
    Provides common functionality including:
    - Connection management
    - Error handling and retry logic
    - Performance monitoring
    - Standardized logging
    - Resource cleanup
    """
    
    def __init__(self, config: AnalysisManagerConfig):
        self.config = config
        self.logger = logging.getLogger(f"{self.__class__.__name__}_{config.package_name}")
        
        # Manager state
        self.status = ManagerStatus.INITIALIZING
        self.connected = False
        self.last_error: Optional[Exception] = None
        self.retry_count = 0
        
        # Threading support
        self._lock = threading.RLock()
        self._shutdown_event = threading.Event()
        
        # Performance monitoring
        self.metrics = ManagerMetrics()
        self.start_time = time.time()
        
        # Initialize manager
        self._initialize()
    
    def _initialize(self) -> None:
        """Initialize the manager implementation."""
        try:
            self.status = ManagerStatus.READY
            self.logger.info(f"Manager initialized for {self.config.package_name} (strategy: {self.config.strategy})")
        except Exception as e:
            self.status = ManagerStatus.FAILED
            self.last_error = e
            self.logger.error(f"Manager initialization failed: {e}")
            raise
    
    @abc.abstractmethod
    def start_connection(self) -> bool:
        """
        Start connection to analysis target.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        pass
    
    @abc.abstractmethod
    def check_connection(self) -> bool:
        """
        Check if connection is active.
        
        Returns:
            bool: True if connected, False otherwise
        """
        pass
    
    @abc.abstractmethod
    def execute_command(self, command: str, **kwargs) -> tuple[bool, Any]:
        """
        Execute a command through the manager.
        
        Args:
            command: Command to execute
            **kwargs: Additional parameters
            
        Returns:
            tuple: (success, result)
        """
        pass
    
    @abc.abstractmethod
    def stop_connection(self) -> bool:
        """
        Stop connection and cleanup resources.
        
        Returns:
            bool: True if cleanup successful, False otherwise
        """
        pass
    
    def start_connection_with_retry(self) -> bool:
        """Start connection with automatic retry logic."""
        with self._lock:
            self.retry_count = 0
            
            while self.retry_count < self.config.max_retries:
                try:
                    self.status = ManagerStatus.CONNECTING
                    self.metrics.connections_attempted += 1
                    
                    if self.start_connection():
                        self.connected = True
                        self.status = ManagerStatus.CONNECTED
                        self.metrics.connections_successful += 1
                        self.metrics.last_activity_time = time.time()
                        
                        self.logger.info(f"Connection established (attempt {self.retry_count + 1})")
                        return True
                    
                except Exception as e:
                    self.last_error = e
                    self.logger.warning(f"Connection attempt {self.retry_count + 1} failed: {e}")
                
                self.retry_count += 1
                self.metrics.connections_failed += 1
                
                if self.retry_count < self.config.max_retries:
                    self.logger.info(f"Retrying connection in {self.config.retry_delay}s...")
                    time.sleep(self.config.retry_delay)
            
            self.status = ManagerStatus.FAILED
            self.logger.error(f"Connection failed after {self.config.max_retries} attempts")
            return False
    
    def execute_command_with_monitoring(self, command: str, **kwargs) -> tuple[bool, Any]:
        """Execute command with performance monitoring."""
        start_time = time.time()
        
        try:
            self.metrics.commands_executed += 1
            success, result = self.execute_command(command, **kwargs)
            
            execution_time = time.time() - start_time
            self.metrics.total_execution_time += execution_time
            self.metrics.average_response_time = (
                self.metrics.total_execution_time / self.metrics.commands_executed
            )
            self.metrics.last_activity_time = time.time()
            
            if success:
                self.metrics.commands_successful += 1
                self.logger.debug(f"Command executed successfully: {command[:50]}...")
            else:
                self.metrics.commands_failed += 1
                self.logger.warning(f"Command execution failed: {command[:50]}...")
            
            return success, result
            
        except Exception as e:
            self.metrics.commands_failed += 1
            self.metrics.error_count += 1
            self.last_error = e
            self.logger.error(f"Command execution error: {e}")
            return False, str(e)
    
    def get_status(self) -> Dict[str, Any]:
        """Get current manager status and metrics."""
        return {
            "status": self.status.value,
            "connected": self.connected,
            "package_name": self.config.package_name,
            "strategy": self.config.strategy,
            "uptime": time.time() - self.start_time,
            "retry_count": self.retry_count,
            "last_error": str(self.last_error) if self.last_error else None,
            "metrics": {
                "connections_attempted": self.metrics.connections_attempted,
                "connections_successful": self.metrics.connections_successful,
                "connections_failed": self.metrics.connections_failed,
                "commands_executed": self.metrics.commands_executed,
                "commands_successful": self.metrics.commands_successful,
                "commands_failed": self.metrics.commands_failed,
                "total_execution_time": self.metrics.total_execution_time,
                "average_response_time": self.metrics.average_response_time,
                "error_count": self.metrics.error_count
            }
        }
    
    def get_success_rate(self) -> float:
        """Calculate connection success rate."""
        if self.metrics.connections_attempted == 0:
            return 0.0
        return self.metrics.connections_successful / self.metrics.connections_attempted
    
    def get_command_success_rate(self) -> float:
        """Calculate command execution success rate."""
        if self.metrics.commands_executed == 0:
            return 0.0
        return self.metrics.commands_successful / self.metrics.commands_executed
    
    def is_healthy(self) -> bool:
        """Check if manager is in a healthy state."""
        if not self.connected or self.status == ManagerStatus.FAILED:
            return False
        
        # Check if too many recent errors
        if self.metrics.error_count > 10:
            return False
        
        # Check if recent activity
        if self.metrics.last_activity_time > 0:
            time_since_activity = time.time() - self.metrics.last_activity_time
            if time_since_activity > self.config.timeout_seconds:
                return False
        
        return True
    
    def reset_metrics(self) -> None:
        """Reset performance metrics."""
        self.metrics = ManagerMetrics()
        self.logger.info("Manager metrics reset")
    
    def cleanup(self) -> None:
        """Clean up manager resources."""
        try:
            self.status = ManagerStatus.CLEANUP
            self._shutdown_event.set()
            
            if self.connected:
                self.stop_connection()
                self.connected = False
            
            self.logger.info("Manager cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Manager cleanup failed: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        if self.start_connection_with_retry():
            return self
        else:
            raise ConnectionError(f"Failed to establish connection for {self.config.package_name}")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup() 