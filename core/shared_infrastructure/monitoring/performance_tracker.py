#!/usr/bin/env python3
"""
Performance Tracker for AODS Monitoring Framework

Real-time system performance monitoring with comprehensive metrics collection,
threshold-based alerting, and performance analytics.

Features:
- Real-time CPU, memory, disk, and network monitoring
- Process-level performance tracking
- Historical performance analysis
- Automatic threshold detection and alerting
- Performance baseline establishment
- Resource utilization optimization recommendations
- Integration with AODS analysis components

This component provides the foundation for performance-aware AODS operations
and automatic performance optimization.
"""

import time
import threading
import logging
import psutil
import queue
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict
import statistics
import json
from pathlib import Path

from ..analysis_exceptions import MonitoringError, ContextualLogger

logger = logging.getLogger(__name__)

class PerformanceLevel(Enum):
    """Performance level classifications."""
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    CRITICAL = "critical"

@dataclass
class SystemMetrics:
    """System-level performance metrics."""
    timestamp: datetime
    cpu_percent: float
    cpu_count: int
    memory_percent: float
    memory_used_gb: float
    memory_total_gb: float
    disk_usage_percent: float
    disk_read_mb_per_sec: float
    disk_write_mb_per_sec: float
    network_sent_mb_per_sec: float
    network_recv_mb_per_sec: float
    load_average_1m: float
    load_average_5m: float
    load_average_15m: float
    temperature_celsius: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary format."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'cpu_percent': self.cpu_percent,
            'cpu_count': self.cpu_count,
            'memory_percent': self.memory_percent,
            'memory_used_gb': self.memory_used_gb,
            'memory_total_gb': self.memory_total_gb,
            'disk_usage_percent': self.disk_usage_percent,
            'disk_read_mb_per_sec': self.disk_read_mb_per_sec,
            'disk_write_mb_per_sec': self.disk_write_mb_per_sec,
            'network_sent_mb_per_sec': self.network_sent_mb_per_sec,
            'network_recv_mb_per_sec': self.network_recv_mb_per_sec,
            'load_average_1m': self.load_average_1m,
            'load_average_5m': self.load_average_5m,
            'load_average_15m': self.load_average_15m,
            'temperature_celsius': self.temperature_celsius
        }

@dataclass
class ProcessMetrics:
    """Process-level performance metrics."""
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    num_threads: int
    num_fds: int
    status: str
    create_time: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary format."""
        return {
            'pid': self.pid,
            'name': self.name,
            'cpu_percent': self.cpu_percent,
            'memory_percent': self.memory_percent,
            'memory_mb': self.memory_mb,
            'num_threads': self.num_threads,
            'num_fds': self.num_fds,
            'status': self.status,
            'create_time': self.create_time.isoformat()
        }

@dataclass
class PerformanceMetrics:
    """Comprehensive performance metrics container."""
    timestamp: datetime
    system: SystemMetrics
    processes: List[ProcessMetrics]
    aods_processes: List[ProcessMetrics]
    performance_level: PerformanceLevel
    recommendations: List[str] = field(default_factory=list)
    alerts: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary format."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'system': self.system.to_dict(),
            'processes': [p.to_dict() for p in self.processes],
            'aods_processes': [p.to_dict() for p in self.aods_processes],
            'performance_level': self.performance_level.value,
            'recommendations': self.recommendations,
            'alerts': self.alerts
        }

class PerformanceBaseline:
    """Performance baseline for comparison and alerting."""
    
    def __init__(self):
        self.cpu_baseline = 0.0
        self.memory_baseline = 0.0
        self.disk_baseline = 0.0
        self.network_baseline = 0.0
        self.established = False
        self.sample_count = 0
        self.baseline_window = 100
        
    def update_baseline(self, metrics: SystemMetrics):
        """Update baseline with new metrics."""
        if self.sample_count < self.baseline_window:
            # Build initial baseline
            alpha = 1.0 / (self.sample_count + 1)
            self.cpu_baseline = self.cpu_baseline * (1 - alpha) + metrics.cpu_percent * alpha
            self.memory_baseline = self.memory_baseline * (1 - alpha) + metrics.memory_percent * alpha
            self.disk_baseline = self.disk_baseline * (1 - alpha) + metrics.disk_usage_percent * alpha
            self.network_baseline = self.network_baseline * (1 - alpha) + (
                metrics.network_sent_mb_per_sec + metrics.network_recv_mb_per_sec
            ) * alpha
            
            self.sample_count += 1
            
            if self.sample_count >= self.baseline_window:
                self.established = True
                
        else:
            # Slowly adapt baseline for long-term trends
            alpha = 0.01
            self.cpu_baseline = self.cpu_baseline * (1 - alpha) + metrics.cpu_percent * alpha
            self.memory_baseline = self.memory_baseline * (1 - alpha) + metrics.memory_percent * alpha

class PerformanceTracker:
    """
    Real-time performance tracking system for AODS framework.
    
    Provides comprehensive system monitoring, performance analysis,
    and intelligent alerting capabilities.
    """
    
    def __init__(self, collection_interval: float = 5.0, 
                 history_size: int = 1000,
                 enable_process_tracking: bool = True):
        """
        Initialize performance tracker.
        
        Args:
            collection_interval: Seconds between metric collections
            history_size: Number of historical metrics to retain
            enable_process_tracking: Whether to track individual processes
        """
        self.collection_interval = collection_interval
        self.history_size = history_size
        self.enable_process_tracking = enable_process_tracking
        
        self.logger = ContextualLogger("performance_tracker")
        
        # State management
        self.monitoring_active = False
        self.collector_thread: Optional[threading.Thread] = None
        self._shutdown_event = threading.Event()
        
        # Metrics storage
        self.metrics_history: deque = deque(maxlen=history_size)
        self.system_history: deque = deque(maxlen=history_size)
        self.process_history: Dict[int, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Performance analysis
        self.baseline = PerformanceBaseline()
        self.performance_callbacks: List[Callable[[PerformanceMetrics], None]] = []
        self.alert_callbacks: List[Callable[[str, str], None]] = []
        
        # Thresholds
        self.cpu_warning_threshold = 80.0
        self.cpu_critical_threshold = 95.0
        self.memory_warning_threshold = 85.0
        self.memory_critical_threshold = 95.0
        self.disk_warning_threshold = 90.0
        self.disk_critical_threshold = 98.0
        
        # Previous metrics for rate calculations
        self._previous_disk_io = None
        self._previous_network_io = None
        self._previous_timestamp = None
        
    def start_monitoring(self) -> None:
        """Start performance monitoring."""
        if self.monitoring_active:
            self.logger.warning("Performance monitoring already active")
            return
        
        self.monitoring_active = True
        self._shutdown_event.clear()
        
        self.collector_thread = threading.Thread(
            target=self._collection_loop,
            name="PerformanceTracker",
            daemon=True
        )
        self.collector_thread.start()
        
        self.logger.info(f"Started performance monitoring (interval: {self.collection_interval}s)")
    
    def stop_monitoring(self) -> None:
        """Stop performance monitoring."""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        self._shutdown_event.set()
        
        if self.collector_thread and self.collector_thread.is_alive():
            self.collector_thread.join(timeout=10.0)
        
        self.logger.info("Stopped performance monitoring")
    
    def register_performance_callback(self, callback: Callable[[PerformanceMetrics], None]) -> None:
        """Register callback for performance updates."""
        self.performance_callbacks.append(callback)
    
    def register_alert_callback(self, callback: Callable[[str, str], None]) -> None:
        """Register callback for performance alerts."""
        self.alert_callbacks.append(callback)
    
    def get_current_metrics(self) -> Optional[PerformanceMetrics]:
        """Get the most recent performance metrics."""
        if self.metrics_history:
            return self.metrics_history[-1]
        return None
    
    def get_metrics_history(self, limit: Optional[int] = None) -> List[PerformanceMetrics]:
        """Get historical performance metrics."""
        if limit:
            return list(self.metrics_history)[-limit:]
        return list(self.metrics_history)
    
    def get_performance_summary(self, duration_minutes: int = 60) -> Dict[str, Any]:
        """Get performance summary for specified duration."""
        cutoff_time = datetime.now() - timedelta(minutes=duration_minutes)
        recent_metrics = [
            m for m in self.metrics_history 
            if m.timestamp >= cutoff_time
        ]
        
        if not recent_metrics:
            return {"error": "No metrics available for specified duration"}
        
        # Calculate statistics
        cpu_values = [m.system.cpu_percent for m in recent_metrics]
        memory_values = [m.system.memory_percent for m in recent_metrics]
        
        return {
            "duration_minutes": duration_minutes,
            "sample_count": len(recent_metrics),
            "cpu_statistics": {
                "average": statistics.mean(cpu_values),
                "minimum": min(cpu_values),
                "maximum": max(cpu_values),
                "median": statistics.median(cpu_values)
            },
            "memory_statistics": {
                "average": statistics.mean(memory_values),
                "minimum": min(memory_values),
                "maximum": max(memory_values),
                "median": statistics.median(memory_values)
            },
            "performance_level_distribution": self._calculate_performance_distribution(recent_metrics),
            "alerts_generated": sum(len(m.alerts) for m in recent_metrics),
            "recommendations_count": sum(len(m.recommendations) for m in recent_metrics)
        }
    
    def _collection_loop(self) -> None:
        """Main metrics collection loop."""
        while self.monitoring_active and not self._shutdown_event.is_set():
            try:
                start_time = time.time()
                
                # Collect metrics
                metrics = self._collect_metrics()
                
                # Store metrics
                self.metrics_history.append(metrics)
                self.system_history.append(metrics.system)
                
                # Update baseline
                self.baseline.update_baseline(metrics.system)
                
                # Notify callbacks
                for callback in self.performance_callbacks:
                    try:
                        callback(metrics)
                    except Exception as e:
                        self.logger.error(f"Performance callback error: {e}")
                
                # Send alerts
                for alert in metrics.alerts:
                    for callback in self.alert_callbacks:
                        try:
                            callback("performance", alert)
                        except Exception as e:
                            self.logger.error(f"Alert callback error: {e}")
                
                # Calculate sleep time
                collection_time = time.time() - start_time
                sleep_time = max(0, self.collection_interval - collection_time)
                
                if sleep_time > 0:
                    self._shutdown_event.wait(timeout=sleep_time)
                
            except Exception as e:
                self.logger.error(f"Metrics collection error: {e}")
                self._shutdown_event.wait(timeout=5.0)
    
    def _collect_metrics(self) -> PerformanceMetrics:
        """Collect current system and process metrics."""
        timestamp = datetime.now()
        
        # Collect system metrics
        system_metrics = self._collect_system_metrics(timestamp)
        
        # Collect process metrics
        processes = []
        aods_processes = []
        
        if self.enable_process_tracking:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 
                                               'memory_info', 'num_threads', 'num_fds', 'status', 'create_time']):
                    try:
                        pinfo = proc.info
                        process_metrics = ProcessMetrics(
                            pid=pinfo['pid'],
                            name=pinfo['name'] or 'unknown',
                            cpu_percent=pinfo['cpu_percent'] or 0.0,
                            memory_percent=pinfo['memory_percent'] or 0.0,
                            memory_mb=(pinfo['memory_info'].rss / 1024 / 1024) if pinfo['memory_info'] else 0.0,
                            num_threads=pinfo['num_threads'] or 0,
                            num_fds=pinfo['num_fds'] or 0,
                            status=pinfo['status'] or 'unknown',
                            create_time=datetime.fromtimestamp(pinfo['create_time']) if pinfo['create_time'] else timestamp
                        )
                        
                        processes.append(process_metrics)
                        
                        # Check if this is an AODS-related process
                        if any(keyword in process_metrics.name.lower() 
                               for keyword in ['aods', 'drozer', 'frida', 'jadx', 'python']):
                            if process_metrics.memory_mb > 10:  # Only significant processes
                                aods_processes.append(process_metrics)
                                
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
            except Exception as e:
                self.logger.warning(f"Process metrics collection failed: {e}")
        
        # Analyze performance level
        performance_level = self._analyze_performance_level(system_metrics)
        
        # Generate recommendations and alerts
        recommendations = self._generate_recommendations(system_metrics, aods_processes)
        alerts = self._check_performance_alerts(system_metrics)
        
        return PerformanceMetrics(
            timestamp=timestamp,
            system=system_metrics,
            processes=processes[:20],  # Limit to top 20 processes
            aods_processes=aods_processes,
            performance_level=performance_level,
            recommendations=recommendations,
            alerts=alerts
        )
    
    def _collect_system_metrics(self, timestamp: datetime) -> SystemMetrics:
        """Collect system-level metrics."""
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1.0)
        cpu_count = psutil.cpu_count()
        
        # Memory metrics
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used_gb = memory.used / (1024**3)
        memory_total_gb = memory.total / (1024**3)
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        disk_usage_percent = disk.percent
        
        # Disk I/O metrics
        disk_io = psutil.disk_io_counters()
        disk_read_mb_per_sec = 0.0
        disk_write_mb_per_sec = 0.0
        
        if self._previous_disk_io and self._previous_timestamp:
            time_delta = (timestamp - self._previous_timestamp).total_seconds()
            if time_delta > 0:
                disk_read_mb_per_sec = (
                    (disk_io.read_bytes - self._previous_disk_io.read_bytes) / 
                    (1024 * 1024) / time_delta
                )
                disk_write_mb_per_sec = (
                    (disk_io.write_bytes - self._previous_disk_io.write_bytes) / 
                    (1024 * 1024) / time_delta
                )
        
        self._previous_disk_io = disk_io
        
        # Network I/O metrics
        network_io = psutil.net_io_counters()
        network_sent_mb_per_sec = 0.0
        network_recv_mb_per_sec = 0.0
        
        if self._previous_network_io and self._previous_timestamp:
            time_delta = (timestamp - self._previous_timestamp).total_seconds()
            if time_delta > 0:
                network_sent_mb_per_sec = (
                    (network_io.bytes_sent - self._previous_network_io.bytes_sent) / 
                    (1024 * 1024) / time_delta
                )
                network_recv_mb_per_sec = (
                    (network_io.bytes_recv - self._previous_network_io.bytes_recv) / 
                    (1024 * 1024) / time_delta
                )
        
        self._previous_network_io = network_io
        self._previous_timestamp = timestamp
        
        # Load average (Unix systems)
        load_average_1m = load_average_5m = load_average_15m = 0.0
        try:
            load_avg = psutil.getloadavg()
            load_average_1m, load_average_5m, load_average_15m = load_avg
        except (AttributeError, OSError):
            pass
        
        # Temperature (if available)
        temperature_celsius = None
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                temp_values = []
                for name, entries in temps.items():
                    for entry in entries:
                        if entry.current:
                            temp_values.append(entry.current)
                if temp_values:
                    temperature_celsius = statistics.mean(temp_values)
        except (AttributeError, OSError):
            pass
        
        return SystemMetrics(
            timestamp=timestamp,
            cpu_percent=cpu_percent,
            cpu_count=cpu_count,
            memory_percent=memory_percent,
            memory_used_gb=memory_used_gb,
            memory_total_gb=memory_total_gb,
            disk_usage_percent=disk_usage_percent,
            disk_read_mb_per_sec=disk_read_mb_per_sec,
            disk_write_mb_per_sec=disk_write_mb_per_sec,
            network_sent_mb_per_sec=network_sent_mb_per_sec,
            network_recv_mb_per_sec=network_recv_mb_per_sec,
            load_average_1m=load_average_1m,
            load_average_5m=load_average_5m,
            load_average_15m=load_average_15m,
            temperature_celsius=temperature_celsius
        )
    
    def _analyze_performance_level(self, system: SystemMetrics) -> PerformanceLevel:
        """Analyze overall system performance level."""
        # Calculate performance score (0-100)
        cpu_score = max(0, 100 - system.cpu_percent)
        memory_score = max(0, 100 - system.memory_percent)
        disk_score = max(0, 100 - system.disk_usage_percent)
        
        # Weight the scores
        overall_score = (cpu_score * 0.4 + memory_score * 0.4 + disk_score * 0.2)
        
        # Classify performance level
        if overall_score >= 80:
            return PerformanceLevel.EXCELLENT
        elif overall_score >= 60:
            return PerformanceLevel.GOOD
        elif overall_score >= 40:
            return PerformanceLevel.FAIR
        elif overall_score >= 20:
            return PerformanceLevel.POOR
        else:
            return PerformanceLevel.CRITICAL
    
    def _generate_recommendations(self, system: SystemMetrics, 
                                aods_processes: List[ProcessMetrics]) -> List[str]:
        """Generate performance optimization recommendations."""
        recommendations = []
        
        # CPU recommendations
        if system.cpu_percent > 85:
            recommendations.append("High CPU usage detected. Consider reducing parallel analysis workers.")
        elif system.cpu_percent < 30 and len(aods_processes) > 0:
            recommendations.append("Low CPU usage. Consider increasing parallel analysis workers for better performance.")
        
        # Memory recommendations
        if system.memory_percent > 90:
            recommendations.append("High memory usage. Consider enabling memory optimization or reducing cache size.")
        
        # Disk recommendations
        if system.disk_usage_percent > 95:
            recommendations.append("Disk space critically low. Clean up temporary files and analysis outputs.")
        
        # Process-specific recommendations
        heavy_processes = [p for p in aods_processes if p.memory_mb > 1000]
        if heavy_processes:
            recommendations.append(f"Heavy memory usage by {len(heavy_processes)} AODS processes. Consider memory optimization.")
        
        return recommendations
    
    def _check_performance_alerts(self, system: SystemMetrics) -> List[str]:
        """Check for performance-related alerts."""
        alerts = []
        
        # CPU alerts
        if system.cpu_percent >= self.cpu_critical_threshold:
            alerts.append(f"CRITICAL: CPU usage at {system.cpu_percent:.1f}% (threshold: {self.cpu_critical_threshold}%)")
        elif system.cpu_percent >= self.cpu_warning_threshold:
            alerts.append(f"WARNING: CPU usage at {system.cpu_percent:.1f}% (threshold: {self.cpu_warning_threshold}%)")
        
        # Memory alerts
        if system.memory_percent >= self.memory_critical_threshold:
            alerts.append(f"CRITICAL: Memory usage at {system.memory_percent:.1f}% (threshold: {self.memory_critical_threshold}%)")
        elif system.memory_percent >= self.memory_warning_threshold:
            alerts.append(f"WARNING: Memory usage at {system.memory_percent:.1f}% (threshold: {self.memory_warning_threshold}%)")
        
        # Disk alerts
        if system.disk_usage_percent >= self.disk_critical_threshold:
            alerts.append(f"CRITICAL: Disk usage at {system.disk_usage_percent:.1f}% (threshold: {self.disk_critical_threshold}%)")
        elif system.disk_usage_percent >= self.disk_warning_threshold:
            alerts.append(f"WARNING: Disk usage at {system.disk_usage_percent:.1f}% (threshold: {self.disk_warning_threshold}%)")
        
        # Temperature alerts
        if system.temperature_celsius and system.temperature_celsius > 80:
            alerts.append(f"WARNING: High system temperature at {system.temperature_celsius:.1f}°C")
        
        return alerts
    
    def _calculate_performance_distribution(self, metrics: List[PerformanceMetrics]) -> Dict[str, int]:
        """Calculate distribution of performance levels."""
        distribution = defaultdict(int)
        for metric in metrics:
            distribution[metric.performance_level.value] += 1
        return dict(distribution)

# Global performance tracker instance
_performance_tracker: Optional[PerformanceTracker] = None

def get_performance_tracker() -> PerformanceTracker:
    """Get the global performance tracker instance."""
    global _performance_tracker
    if _performance_tracker is None:
        _performance_tracker = PerformanceTracker()
    return _performance_tracker 