#!/usr/bin/env python3
"""
Resource Monitor for AODS Monitoring Framework

Advanced resource usage tracking and optimization with intelligent thresholds,
predictive analytics, and automated resource management recommendations.

Features:
- Real-time resource usage monitoring (CPU, memory, disk, network)
- Intelligent threshold management with adaptive baselines
- Resource optimization recommendations
- Predictive resource demand analysis
- Automated resource scaling suggestions
- Integration with AODS performance optimization
- Resource leak detection and prevention

This component enables intelligent resource management for optimal
AODS analysis performance and system stability.
"""

import time
import threading
import logging
import psutil
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict
import statistics
import json
from pathlib import Path

from ..analysis_exceptions import MonitoringError, ContextualLogger

logger = logging.getLogger(__name__)

class ResourceType(Enum):
    """Types of system resources."""
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    FILE_HANDLES = "file_handles"
    PROCESSES = "processes"

class AlertLevel(Enum):
    """Resource alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

@dataclass
class ResourceThresholds:
    """Resource usage thresholds for alerting."""
    resource_type: ResourceType
    info_threshold: float = 60.0
    warning_threshold: float = 75.0
    critical_threshold: float = 90.0
    emergency_threshold: float = 98.0
    adaptive: bool = True
    baseline_multiplier: float = 1.5
    
    def get_alert_level(self, usage_percent: float, baseline: Optional[float] = None) -> Optional[AlertLevel]:
        """Get alert level for current usage."""
        if self.adaptive and baseline:
            # Use adaptive thresholds based on baseline
            emergency = min(self.emergency_threshold, baseline * self.baseline_multiplier * 1.5)
            critical = min(self.critical_threshold, baseline * self.baseline_multiplier * 1.2)
            warning = min(self.warning_threshold, baseline * self.baseline_multiplier)
            info = min(self.info_threshold, baseline * self.baseline_multiplier * 0.8)
        else:
            # Use static thresholds
            emergency = self.emergency_threshold
            critical = self.critical_threshold
            warning = self.warning_threshold
            info = self.info_threshold
        
        if usage_percent >= emergency:
            return AlertLevel.EMERGENCY
        elif usage_percent >= critical:
            return AlertLevel.CRITICAL
        elif usage_percent >= warning:
            return AlertLevel.WARNING
        elif usage_percent >= info:
            return AlertLevel.INFO
        
        return None

@dataclass
class ResourceUsage:
    """Current resource usage snapshot."""
    timestamp: datetime
    resource_type: ResourceType
    usage_percent: float
    usage_absolute: float
    total_available: float
    rate_of_change: float = 0.0
    processes_using: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'resource_type': self.resource_type.value,
            'usage_percent': self.usage_percent,
            'usage_absolute': self.usage_absolute,
            'total_available': self.total_available,
            'rate_of_change': self.rate_of_change,
            'processes_using': self.processes_using,
            'metadata': self.metadata
        }

@dataclass
class ResourceAlert:
    """Resource usage alert."""
    timestamp: datetime
    resource_type: ResourceType
    alert_level: AlertLevel
    current_usage: float
    threshold_exceeded: float
    message: str
    recommendations: List[str] = field(default_factory=list)
    auto_actions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'resource_type': self.resource_type.value,
            'alert_level': self.alert_level.value,
            'current_usage': self.current_usage,
            'threshold_exceeded': self.threshold_exceeded,
            'message': self.message,
            'recommendations': self.recommendations,
            'auto_actions': self.auto_actions
        }

class ResourceBaseline:
    """Dynamic baseline calculation for resources."""
    
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.samples: deque = deque(maxlen=window_size)
        self.baseline_value = 0.0
        self.baseline_established = False
        self.last_update = datetime.now()
        
    def add_sample(self, value: float) -> None:
        """Add a new sample to the baseline calculation."""
        self.samples.append(value)
        self.last_update = datetime.now()
        
        # Calculate baseline
        if len(self.samples) >= min(50, self.window_size // 10):
            # Use median for robustness against outliers
            self.baseline_value = statistics.median(self.samples)
            self.baseline_established = True
    
    def get_baseline(self) -> Optional[float]:
        """Get current baseline value."""
        return self.baseline_value if self.baseline_established else None
    
    def is_anomaly(self, value: float, threshold_multiplier: float = 2.0) -> bool:
        """Check if value is anomalous compared to baseline."""
        if not self.baseline_established or len(self.samples) < 20:
            return False
        
        # Calculate standard deviation
        try:
            std_dev = statistics.stdev(self.samples)
            return abs(value - self.baseline_value) > (std_dev * threshold_multiplier)
        except statistics.StatisticsError:
            return False

class ResourceOptimizer:
    """Resource optimization recommendations engine."""
    
    def __init__(self):
        self.optimization_history: List[Dict[str, Any]] = []
        self.logger = ContextualLogger("resource_optimizer")
    
    def analyze_resource_usage(self, current_usage: Dict[ResourceType, ResourceUsage],
                             baselines: Dict[ResourceType, ResourceBaseline]) -> List[str]:
        """Analyze current resource usage and provide optimization recommendations."""
        recommendations = []
        
        # CPU optimization
        cpu_usage = current_usage.get(ResourceType.CPU)
        if cpu_usage:
            cpu_recommendations = self._analyze_cpu_usage(cpu_usage, baselines.get(ResourceType.CPU))
            recommendations.extend(cpu_recommendations)
        
        # Memory optimization
        memory_usage = current_usage.get(ResourceType.MEMORY)
        if memory_usage:
            memory_recommendations = self._analyze_memory_usage(memory_usage, baselines.get(ResourceType.MEMORY))
            recommendations.extend(memory_recommendations)
        
        # Disk optimization
        disk_usage = current_usage.get(ResourceType.DISK)
        if disk_usage:
            disk_recommendations = self._analyze_disk_usage(disk_usage, baselines.get(ResourceType.DISK))
            recommendations.extend(disk_recommendations)
        
        return recommendations
    
    def _analyze_cpu_usage(self, usage: ResourceUsage, baseline: Optional[ResourceBaseline]) -> List[str]:
        """Analyze CPU usage and provide recommendations."""
        recommendations = []
        
        if usage.usage_percent > 90:
            recommendations.append("Reduce number of parallel analysis workers to decrease CPU load")
            recommendations.append("Consider enabling CPU throttling for non-critical analysis tasks")
        elif usage.usage_percent > 75:
            recommendations.append("Monitor CPU usage closely during analysis operations")
            recommendations.append("Consider scheduling intensive tasks during off-peak hours")
        elif usage.usage_percent < 25 and baseline and baseline.get_baseline():
            if usage.usage_percent < baseline.get_baseline() * 0.5:
                recommendations.append("CPU underutilized - consider increasing parallel workers for better performance")
        
        # Check for high rate of change
        if abs(usage.rate_of_change) > 20:
            recommendations.append("CPU usage fluctuating rapidly - check for process instability")
        
        return recommendations
    
    def _analyze_memory_usage(self, usage: ResourceUsage, baseline: Optional[ResourceBaseline]) -> List[str]:
        """Analyze memory usage and provide recommendations."""
        recommendations = []
        
        if usage.usage_percent > 95:
            recommendations.append("URGENT: Memory critically low - enable aggressive memory cleanup")
            recommendations.append("Reduce cache sizes and buffer allocations")
            recommendations.append("Consider restarting analysis processes to free memory")
        elif usage.usage_percent > 85:
            recommendations.append("High memory usage - enable memory optimization features")
            recommendations.append("Clear unnecessary caches and temporary data")
        elif usage.usage_percent > 75:
            recommendations.append("Monitor memory usage during large APK analysis")
            recommendations.append("Consider enabling incremental garbage collection")
        
        # Check for memory leaks
        if usage.rate_of_change > 2 and baseline:
            baseline_val = baseline.get_baseline()
            if baseline_val and usage.usage_percent > baseline_val * 1.5:
                recommendations.append("Potential memory leak detected - investigate growing processes")
        
        return recommendations
    
    def _analyze_disk_usage(self, usage: ResourceUsage, baseline: Optional[ResourceBaseline]) -> List[str]:
        """Analyze disk usage and provide recommendations."""
        recommendations = []
        
        if usage.usage_percent > 98:
            recommendations.append("URGENT: Disk space critically low - clean up immediately")
            recommendations.append("Remove old analysis results and temporary files")
        elif usage.usage_percent > 90:
            recommendations.append("Disk space low - schedule cleanup tasks")
            recommendations.append("Enable automatic cleanup of old analysis artifacts")
        elif usage.usage_percent > 80:
            recommendations.append("Monitor disk usage growth patterns")
            recommendations.append("Consider archiving old analysis results")
        
        return recommendations

class ResourceMonitor:
    """
    Advanced resource usage monitoring and optimization system.
    
    Provides comprehensive resource tracking, intelligent alerting,
    and optimization recommendations for AODS framework.
    """
    
    def __init__(self, collection_interval: float = 10.0,
                 enable_adaptive_thresholds: bool = True,
                 enable_optimization: bool = True):
        """
        Initialize resource monitor.
        
        Args:
            collection_interval: Seconds between resource collections
            enable_adaptive_thresholds: Whether to use adaptive thresholds
            enable_optimization: Whether to generate optimization recommendations
        """
        self.collection_interval = collection_interval
        self.enable_adaptive_thresholds = enable_adaptive_thresholds
        self.enable_optimization = enable_optimization
        
        self.logger = ContextualLogger("resource_monitor")
        
        # State management
        self.monitoring_active = False
        self.collector_thread: Optional[threading.Thread] = None
        self._shutdown_event = threading.Event()
        
        # Resource tracking
        self.current_usage: Dict[ResourceType, ResourceUsage] = {}
        self.usage_history: Dict[ResourceType, deque] = {
            resource_type: deque(maxlen=1000) for resource_type in ResourceType
        }
        self.baselines: Dict[ResourceType, ResourceBaseline] = {
            resource_type: ResourceBaseline() for resource_type in ResourceType
        }
        
        # Thresholds and alerting
        self.thresholds: Dict[ResourceType, ResourceThresholds] = {
            ResourceType.CPU: ResourceThresholds(ResourceType.CPU, 60, 75, 90, 98),
            ResourceType.MEMORY: ResourceThresholds(ResourceType.MEMORY, 70, 80, 90, 95),
            ResourceType.DISK: ResourceThresholds(ResourceType.DISK, 80, 85, 90, 95),
            ResourceType.NETWORK: ResourceThresholds(ResourceType.NETWORK, 70, 80, 90, 95),
        }
        
        # Callbacks
        self.usage_callbacks: List[Callable[[Dict[ResourceType, ResourceUsage]], None]] = []
        self.alert_callbacks: List[Callable[[ResourceAlert], None]] = []
        self.optimization_callbacks: List[Callable[[List[str]], None]] = []
        
        # Optimization engine
        self.optimizer = ResourceOptimizer() if enable_optimization else None
        
        # Alert tracking
        self.active_alerts: Dict[str, ResourceAlert] = {}
        self.alert_history: deque = deque(maxlen=1000)
        
    def start_monitoring(self) -> None:
        """Start resource monitoring."""
        if self.monitoring_active:
            self.logger.warning("Resource monitoring already active")
            return
        
        self.monitoring_active = True
        self._shutdown_event.clear()
        
        self.collector_thread = threading.Thread(
            target=self._collection_loop,
            name="ResourceMonitor",
            daemon=True
        )
        self.collector_thread.start()
        
        self.logger.info(f"Started resource monitoring (interval: {self.collection_interval}s)")
    
    def stop_monitoring(self) -> None:
        """Stop resource monitoring."""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        self._shutdown_event.set()
        
        if self.collector_thread and self.collector_thread.is_alive():
            self.collector_thread.join(timeout=10.0)
        
        self.logger.info("Stopped resource monitoring")
    
    def register_usage_callback(self, callback: Callable[[Dict[ResourceType, ResourceUsage]], None]) -> None:
        """Register callback for resource usage updates."""
        self.usage_callbacks.append(callback)
    
    def register_alert_callback(self, callback: Callable[[ResourceAlert], None]) -> None:
        """Register callback for resource alerts."""
        self.alert_callbacks.append(callback)
    
    def register_optimization_callback(self, callback: Callable[[List[str]], None]) -> None:
        """Register callback for optimization recommendations."""
        self.optimization_callbacks.append(callback)
    
    def get_current_usage(self) -> Dict[ResourceType, ResourceUsage]:
        """Get current resource usage."""
        return self.current_usage.copy()
    
    def get_usage_history(self, resource_type: ResourceType, 
                         duration_minutes: int = 60) -> List[ResourceUsage]:
        """Get resource usage history for specified duration."""
        cutoff_time = datetime.now() - timedelta(minutes=duration_minutes)
        history = self.usage_history.get(resource_type, deque())
        
        return [usage for usage in history if usage.timestamp >= cutoff_time]
    
    def get_active_alerts(self) -> List[ResourceAlert]:
        """Get currently active alerts."""
        return list(self.active_alerts.values())
    
    def get_resource_summary(self, duration_minutes: int = 60) -> Dict[str, Any]:
        """Get resource usage summary for specified duration."""
        summary = {}
        
        for resource_type in ResourceType:
            history = self.get_usage_history(resource_type, duration_minutes)
            if history:
                usage_values = [h.usage_percent for h in history]
                summary[resource_type.value] = {
                    "current_usage": self.current_usage.get(resource_type, {}).usage_percent if resource_type in self.current_usage else 0,
                    "average_usage": statistics.mean(usage_values),
                    "peak_usage": max(usage_values),
                    "minimum_usage": min(usage_values),
                    "baseline": self.baselines[resource_type].get_baseline(),
                    "sample_count": len(history),
                    "anomalies_detected": sum(1 for h in history if self.baselines[resource_type].is_anomaly(h.usage_percent))
                }
            else:
                summary[resource_type.value] = {
                    "current_usage": 0,
                    "average_usage": 0,
                    "peak_usage": 0,
                    "minimum_usage": 0,
                    "baseline": None,
                    "sample_count": 0,
                    "anomalies_detected": 0
                }
        
        return {
            "duration_minutes": duration_minutes,
            "resources": summary,
            "active_alerts": len(self.active_alerts),
            "total_alerts_generated": len(self.alert_history)
        }
    
    def _collection_loop(self) -> None:
        """Main resource collection loop."""
        while self.monitoring_active and not self._shutdown_event.is_set():
            try:
                start_time = time.time()
                
                # Collect resource usage
                usage_data = self._collect_resource_usage()
                
                # Update current usage and history
                self.current_usage = usage_data
                for resource_type, usage in usage_data.items():
                    self.usage_history[resource_type].append(usage)
                    self.baselines[resource_type].add_sample(usage.usage_percent)
                
                # Check for alerts
                alerts = self._check_resource_alerts(usage_data)
                
                # Process alerts
                for alert in alerts:
                    alert_key = f"{alert.resource_type.value}_{alert.alert_level.value}"
                    self.active_alerts[alert_key] = alert
                    self.alert_history.append(alert)
                    
                    # Notify alert callbacks
                    for callback in self.alert_callbacks:
                        try:
                            callback(alert)
                        except Exception as e:
                            self.logger.error(f"Alert callback error: {e}")
                
                # Generate optimization recommendations
                if self.optimizer:
                    try:
                        recommendations = self.optimizer.analyze_resource_usage(
                            usage_data, self.baselines
                        )
                        
                        if recommendations:
                            for callback in self.optimization_callbacks:
                                try:
                                    callback(recommendations)
                                except Exception as e:
                                    self.logger.error(f"Optimization callback error: {e}")
                    except Exception as e:
                        self.logger.error(f"Resource optimization error: {e}")
                
                # Notify usage callbacks
                for callback in self.usage_callbacks:
                    try:
                        callback(usage_data)
                    except Exception as e:
                        self.logger.error(f"Usage callback error: {e}")
                
                # Calculate sleep time
                collection_time = time.time() - start_time
                sleep_time = max(0, self.collection_interval - collection_time)
                
                if sleep_time > 0:
                    self._shutdown_event.wait(timeout=sleep_time)
                
            except Exception as e:
                self.logger.error(f"Resource collection error: {e}")
                self._shutdown_event.wait(timeout=5.0)
    
    def _collect_resource_usage(self) -> Dict[ResourceType, ResourceUsage]:
        """Collect current resource usage for all resource types."""
        timestamp = datetime.now()
        usage_data = {}
        
        # CPU usage
        try:
            cpu_percent = psutil.cpu_percent(interval=1.0)
            cpu_count = psutil.cpu_count()
            
            # Get top CPU processes
            top_processes = []
            try:
                for proc in psutil.process_iter(['name', 'cpu_percent']):
                    if proc.info['cpu_percent'] and proc.info['cpu_percent'] > 5:
                        top_processes.append(proc.info['name'])
                top_processes = top_processes[:5]  # Top 5 processes
            except:
                pass
            
            usage_data[ResourceType.CPU] = ResourceUsage(
                timestamp=timestamp,
                resource_type=ResourceType.CPU,
                usage_percent=cpu_percent,
                usage_absolute=cpu_percent,
                total_available=100.0,
                processes_using=top_processes,
                metadata={'cpu_count': cpu_count}
            )
        except Exception as e:
            self.logger.warning(f"CPU collection error: {e}")
        
        # Memory usage
        try:
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_used_gb = memory.used / (1024**3)
            memory_total_gb = memory.total / (1024**3)
            
            # Get top memory processes
            top_processes = []
            try:
                for proc in psutil.process_iter(['name', 'memory_percent']):
                    if proc.info['memory_percent'] and proc.info['memory_percent'] > 2:
                        top_processes.append(proc.info['name'])
                top_processes = top_processes[:5]
            except:
                pass
            
            usage_data[ResourceType.MEMORY] = ResourceUsage(
                timestamp=timestamp,
                resource_type=ResourceType.MEMORY,
                usage_percent=memory_percent,
                usage_absolute=memory_used_gb,
                total_available=memory_total_gb,
                processes_using=top_processes,
                metadata={
                    'used_gb': memory_used_gb,
                    'total_gb': memory_total_gb,
                    'available_gb': memory.available / (1024**3)
                }
            )
        except Exception as e:
            self.logger.warning(f"Memory collection error: {e}")
        
        # Disk usage
        try:
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            disk_used_gb = disk.used / (1024**3)
            disk_total_gb = disk.total / (1024**3)
            
            usage_data[ResourceType.DISK] = ResourceUsage(
                timestamp=timestamp,
                resource_type=ResourceType.DISK,
                usage_percent=disk_percent,
                usage_absolute=disk_used_gb,
                total_available=disk_total_gb,
                metadata={
                    'used_gb': disk_used_gb,
                    'total_gb': disk_total_gb,
                    'free_gb': disk.free / (1024**3)
                }
            )
        except Exception as e:
            self.logger.warning(f"Disk collection error: {e}")
        
        # Network usage (simplified)
        try:
            network = psutil.net_io_counters()
            # Network usage as a percentage is complex, using a simple approximation
            # This could be enhanced with bandwidth monitoring
            network_usage = min(100, (network.bytes_sent + network.bytes_recv) / (1024 * 1024 * 100))  # Rough estimate
            
            usage_data[ResourceType.NETWORK] = ResourceUsage(
                timestamp=timestamp,
                resource_type=ResourceType.NETWORK,
                usage_percent=network_usage,
                usage_absolute=network.bytes_sent + network.bytes_recv,
                total_available=1024**3,  # 1GB reference
                metadata={
                    'bytes_sent': network.bytes_sent,
                    'bytes_recv': network.bytes_recv,
                    'packets_sent': network.packets_sent,
                    'packets_recv': network.packets_recv
                }
            )
        except Exception as e:
            self.logger.warning(f"Network collection error: {e}")
        
        return usage_data
    
    def _check_resource_alerts(self, usage_data: Dict[ResourceType, ResourceUsage]) -> List[ResourceAlert]:
        """Check resource usage against thresholds and generate alerts."""
        alerts = []
        
        for resource_type, usage in usage_data.items():
            threshold = self.thresholds.get(resource_type)
            if not threshold:
                continue
            
            baseline = self.baselines[resource_type].get_baseline() if self.enable_adaptive_thresholds else None
            alert_level = threshold.get_alert_level(usage.usage_percent, baseline)
            
            if alert_level:
                # Get appropriate threshold value
                if alert_level == AlertLevel.EMERGENCY:
                    threshold_value = threshold.emergency_threshold
                elif alert_level == AlertLevel.CRITICAL:
                    threshold_value = threshold.critical_threshold
                elif alert_level == AlertLevel.WARNING:
                    threshold_value = threshold.warning_threshold
                else:
                    threshold_value = threshold.info_threshold
                
                # Generate alert message
                message = f"{alert_level.value.upper()}: {resource_type.value.title()} usage at {usage.usage_percent:.1f}%"
                
                # Generate recommendations
                recommendations = []
                if self.optimizer:
                    recommendations = self.optimizer.analyze_resource_usage({resource_type: usage}, {resource_type: self.baselines[resource_type]})
                
                alert = ResourceAlert(
                    timestamp=usage.timestamp,
                    resource_type=resource_type,
                    alert_level=alert_level,
                    current_usage=usage.usage_percent,
                    threshold_exceeded=threshold_value,
                    message=message,
                    recommendations=recommendations
                )
                
                alerts.append(alert)
        
        return alerts

# Global resource monitor instance
_resource_monitor: Optional[ResourceMonitor] = None

def get_resource_monitor() -> ResourceMonitor:
    """Get the global resource monitor instance."""
    global _resource_monitor
    if _resource_monitor is None:
        _resource_monitor = ResourceMonitor()
    return _resource_monitor 