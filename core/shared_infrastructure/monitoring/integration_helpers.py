#!/usr/bin/env python3
"""
Integration Helpers for AODS Monitoring Framework

Integration utilities for connecting monitoring framework with AODS components,
dashboard data generation, metric export capabilities, and monitoring hooks.

Features:
- AODS component monitoring integration
- Dashboard data generation and formatting
- Metric export to external systems
- Monitoring hook registration and management
- Performance tracking for AODS operations
- Health status aggregation
- Custom metric collection for AODS plugins

This module enables seamless integration between the monitoring framework
and the broader AODS security analysis platform.
"""

import time
import logging
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from collections import defaultdict, deque
from pathlib import Path

from ..analysis_exceptions import ContextualLogger
from .performance_tracker import get_performance_tracker, PerformanceMetrics
from .resource_monitor import get_resource_monitor, ResourceUsage
from .health_checker import get_health_checker, HealthStatus
from .alert_manager import get_alert_manager, AlertSeverity, AlertType
from .metrics_collector import get_metrics_collector, MetricDataPoint, MetricType

logger = logging.getLogger(__name__)

@dataclass
class AODSOperationMetrics:
    """Metrics for AODS operations."""
    operation_name: str
    component: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    success: bool = True
    error_message: Optional[str] = None
    files_processed: int = 0
    vulnerabilities_found: int = 0
    analysis_accuracy: Optional[float] = None
    memory_peak_mb: Optional[float] = None
    cpu_usage_avg: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'operation_name': self.operation_name,
            'component': self.component,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self.duration_seconds,
            'success': self.success,
            'error_message': self.error_message,
            'files_processed': self.files_processed,
            'vulnerabilities_found': self.vulnerabilities_found,
            'analysis_accuracy': self.analysis_accuracy,
            'memory_peak_mb': self.memory_peak_mb,
            'cpu_usage_avg': self.cpu_usage_avg
        }

class AODSMonitoringIntegration:
    """
    Main integration class for AODS monitoring.
    
    Provides seamless integration between monitoring framework
    and AODS security analysis components.
    """
    
    def __init__(self):
        self.logger = ContextualLogger("aods_monitoring_integration")
        
        # Component references
        self.performance_tracker = get_performance_tracker()
        self.resource_monitor = get_resource_monitor()
        self.health_checker = get_health_checker()
        self.alert_manager = get_alert_manager()
        self.metrics_collector = get_metrics_collector()
        
        # Integration state
        self.integration_active = False
        self.operation_history: deque = deque(maxlen=10000)
        self.registered_hooks: Dict[str, List[Callable]] = defaultdict(list)
        
        # AODS-specific metrics
        self.component_metrics: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self.plugin_performance: Dict[str, List[float]] = defaultdict(list)
        
        # Thread safety
        self._lock = threading.Lock()
        
    def initialize_integration(self) -> bool:
        """Initialize monitoring integration with AODS components."""
        try:
            self.logger.info("Initializing AODS monitoring integration...")
            
            # Start monitoring components
            self.performance_tracker.start_monitoring()
            self.resource_monitor.start_monitoring()
            self.health_checker.start_monitoring()
            self.alert_manager.start_processing()
            self.metrics_collector.start_collection()
            
            # Register AODS-specific health checks
            self._register_aods_health_checks()
            
            # Register AODS-specific metrics
            self._register_aods_metrics()
            
            # Set up monitoring hooks
            self._setup_monitoring_hooks()
            
            self.integration_active = True
            self.logger.info("AODS monitoring integration initialized successfully")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize AODS monitoring integration: {e}")
            return False
    
    def shutdown_integration(self) -> None:
        """Shutdown monitoring integration."""
        try:
            self.logger.info("Shutting down AODS monitoring integration...")
            
            # Stop monitoring components
            self.performance_tracker.stop_monitoring()
            self.resource_monitor.stop_monitoring()
            self.health_checker.stop_monitoring()
            self.alert_manager.stop_processing()
            self.metrics_collector.stop_collection()
            
            self.integration_active = False
            self.logger.info("AODS monitoring integration shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during monitoring integration shutdown: {e}")
    
    def track_aods_operation(self, operation_name: str, component: str,
                           files_processed: int = 0, vulnerabilities_found: int = 0,
                           analysis_accuracy: Optional[float] = None) -> str:
        """Track an AODS operation and return operation ID."""
        operation_id = f"aods_{int(time.time() * 1000)}_{hash(f'{component}_{operation_name}')}"
        
        # Create operation metrics
        operation_metrics = AODSOperationMetrics(
            operation_name=operation_name,
            component=component,
            start_time=datetime.now(),
            files_processed=files_processed,
            vulnerabilities_found=vulnerabilities_found,
            analysis_accuracy=analysis_accuracy
        )
        
        # Store operation
        with self._lock:
            self.operation_history.append(operation_metrics)
        
        # Record metrics
        self.metrics_collector.record_metric(
            f"aods.operations.started",
            1,
            labels={'component': component, 'operation': operation_name}
        )
        
        self.logger.debug(f"Started tracking AODS operation: {operation_id}")
        return operation_id
    
    def complete_aods_operation(self, operation_id: str, success: bool = True,
                              error_message: Optional[str] = None) -> None:
        """Mark an AODS operation as complete."""
        try:
            # Find the operation in history
            operation_metrics = None
            with self._lock:
                for op in reversed(self.operation_history):
                    if f"aods_{int(op.start_time.timestamp() * 1000)}" in operation_id:
                        operation_metrics = op
                        break
            
            if not operation_metrics:
                self.logger.warning(f"Operation not found for completion: {operation_id}")
                return
            
            # Update operation metrics
            operation_metrics.end_time = datetime.now()
            operation_metrics.duration_seconds = (
                operation_metrics.end_time - operation_metrics.start_time
            ).total_seconds()
            operation_metrics.success = success
            operation_metrics.error_message = error_message
            
            # Record completion metrics
            self.metrics_collector.record_metric(
                f"aods.operations.completed",
                1,
                labels={
                    'component': operation_metrics.component,
                    'operation': operation_metrics.operation_name,
                    'success': str(success)
                }
            )
            
            self.metrics_collector.record_metric(
                f"aods.operations.duration_seconds",
                operation_metrics.duration_seconds,
                labels={
                    'component': operation_metrics.component,
                    'operation': operation_metrics.operation_name
                }
            )
            
            # Track plugin performance
            with self._lock:
                self.plugin_performance[operation_metrics.component].append(
                    operation_metrics.duration_seconds
                )
                # Keep only recent performance data
                if len(self.plugin_performance[operation_metrics.component]) > 1000:
                    self.plugin_performance[operation_metrics.component] = \
                        self.plugin_performance[operation_metrics.component][-500:]
            
            # Generate alerts for failures or performance issues
            if not success:
                self.alert_manager.send_alert(
                    title=f"AODS Operation Failed: {operation_metrics.operation_name}",
                    message=f"Operation in {operation_metrics.component} failed: {error_message}",
                    severity=AlertSeverity.WARNING,
                    alert_type=AlertType.OPERATIONAL,
                    source=operation_metrics.component,
                    metadata={'operation_id': operation_id, 'duration': operation_metrics.duration_seconds}
                )
            elif operation_metrics.duration_seconds > 300:  # 5 minutes
                self.alert_manager.send_alert(
                    title=f"AODS Operation Slow: {operation_metrics.operation_name}",
                    message=f"Operation in {operation_metrics.component} took {operation_metrics.duration_seconds:.1f} seconds",
                    severity=AlertSeverity.INFO,
                    alert_type=AlertType.PERFORMANCE,
                    source=operation_metrics.component,
                    metadata={'operation_id': operation_id, 'duration': operation_metrics.duration_seconds}
                )
            
            self.logger.debug(f"Completed tracking AODS operation: {operation_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to complete operation tracking: {e}")
    
    def record_vulnerability_detection(self, component: str, vulnerability_type: str,
                                     severity: str, confidence: float) -> None:
        """Record vulnerability detection metrics."""
        try:
            self.metrics_collector.record_metric(
                "aods.vulnerabilities.detected",
                1,
                labels={
                    'component': component,
                    'vulnerability_type': vulnerability_type,
                    'severity': severity
                }
            )
            
            self.metrics_collector.record_metric(
                "aods.vulnerabilities.confidence",
                confidence,
                labels={
                    'component': component,
                    'vulnerability_type': vulnerability_type
                }
            )
            
        except Exception as e:
            self.logger.error(f"Failed to record vulnerability detection: {e}")
    
    def record_analysis_accuracy(self, component: str, accuracy: float,
                               total_findings: int, false_positives: int) -> None:
        """Record analysis accuracy metrics."""
        try:
            self.metrics_collector.record_metric(
                "aods.analysis.accuracy",
                accuracy,
                labels={'component': component}
            )
            
            self.metrics_collector.record_metric(
                "aods.analysis.total_findings",
                total_findings,
                labels={'component': component}
            )
            
            self.metrics_collector.record_metric(
                "aods.analysis.false_positives",
                false_positives,
                labels={'component': component}
            )
            
            false_positive_rate = false_positives / total_findings if total_findings > 0 else 0
            self.metrics_collector.record_metric(
                "aods.analysis.false_positive_rate",
                false_positive_rate,
                labels={'component': component}
            )
            
        except Exception as e:
            self.logger.error(f"Failed to record analysis accuracy: {e}")
    
    def get_component_status(self, component: str) -> Dict[str, Any]:
        """Get comprehensive status for an AODS component."""
        try:
            # Get component health
            health = self.health_checker.get_component_health(component)
            health_status = health.current_status.value if health else "unknown"
            
            # Get recent operations
            recent_operations = []
            cutoff_time = datetime.now() - timedelta(hours=1)
            
            with self._lock:
                for op in self.operation_history:
                    if (op.component == component and 
                        op.start_time >= cutoff_time):
                        recent_operations.append(op.to_dict())
            
            # Get performance metrics
            performance_data = []
            if component in self.plugin_performance:
                recent_performance = self.plugin_performance[component][-50:]  # Last 50 operations
                if recent_performance:
                    avg_duration = sum(recent_performance) / len(recent_performance)
                    max_duration = max(recent_performance)
                    min_duration = min(recent_performance)
                    
                    performance_data = {
                        'average_duration': avg_duration,
                        'max_duration': max_duration,
                        'min_duration': min_duration,
                        'recent_operations': len(recent_performance)
                    }
            
            return {
                'component': component,
                'health_status': health_status,
                'recent_operations': recent_operations,
                'performance_metrics': performance_data,
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get component status for {component}: {e}")
            return {'component': component, 'error': str(e)}
    
    def _register_aods_health_checks(self) -> None:
        """Register AODS-specific health checks."""
        from .health_checker import HealthCheckDefinition, ComponentType, HealthCheckResult
        
        # Core AODS components health check
        def check_aods_core():
            try:
                # Check if core directories exist
                core_paths = ['core', 'plugins', 'config']
                accessible_paths = []
                
                for path in core_paths:
                    if Path(path).exists():
                        accessible_paths.append(path)
                
                if len(accessible_paths) == len(core_paths):
                    status = HealthStatus.HEALTHY
                    message = "All AODS core paths accessible"
                else:
                    status = HealthStatus.WARNING
                    message = f"Some AODS paths missing: {set(core_paths) - set(accessible_paths)}"
                
                return HealthCheckResult(
                    component_name="aods_core",
                    component_type=ComponentType.CORE_SERVICE,
                    status=status,
                    timestamp=datetime.now(),
                    response_time_ms=10.0,
                    message=message,
                    details={'accessible_paths': accessible_paths}
                )
                
            except Exception as e:
                return HealthCheckResult(
                    component_name="aods_core",
                    component_type=ComponentType.CORE_SERVICE,
                    status=HealthStatus.CRITICAL,
                    timestamp=datetime.now(),
                    response_time_ms=0.0,
                    message=f"AODS core check failed: {e}"
                )
        
        # Plugin availability health check
        def check_aods_plugins():
            try:
                plugins_dir = Path('plugins')
                if not plugins_dir.exists():
                    status = HealthStatus.CRITICAL
                    message = "Plugins directory not found"
                    plugin_count = 0
                else:
                    plugin_count = len([p for p in plugins_dir.iterdir() if p.is_dir()])
                    if plugin_count > 10:
                        status = HealthStatus.HEALTHY
                        message = f"Found {plugin_count} plugin directories"
                    elif plugin_count > 5:
                        status = HealthStatus.WARNING
                        message = f"Found {plugin_count} plugin directories (expected more)"
                    else:
                        status = HealthStatus.CRITICAL
                        message = f"Only {plugin_count} plugin directories found"
                
                return HealthCheckResult(
                    component_name="aods_plugins",
                    component_type=ComponentType.CORE_SERVICE,
                    status=status,
                    timestamp=datetime.now(),
                    response_time_ms=5.0,
                    message=message,
                    details={'plugin_count': plugin_count}
                )
                
            except Exception as e:
                return HealthCheckResult(
                    component_name="aods_plugins",
                    component_type=ComponentType.CORE_SERVICE,
                    status=HealthStatus.CRITICAL,
                    timestamp=datetime.now(),
                    response_time_ms=0.0,
                    message=f"Plugin check failed: {e}"
                )
        
        # Register health checks
        self.health_checker.register_health_check(HealthCheckDefinition(
            name="aods_core",
            component_type=ComponentType.CORE_SERVICE,
            check_function=check_aods_core,
            interval_seconds=120.0
        ))
        
        self.health_checker.register_health_check(HealthCheckDefinition(
            name="aods_plugins",
            component_type=ComponentType.CORE_SERVICE,
            check_function=check_aods_plugins,
            interval_seconds=300.0
        ))
    
    def _register_aods_metrics(self) -> None:
        """Register AODS-specific metrics."""
        from .metrics_collector import MetricDefinition
        
        # AODS operation rate
        self.metrics_collector.register_metric(MetricDefinition(
            name="aods.operations.rate",
            metric_type=MetricType.RATE,
            description="Rate of AODS operations per second",
            collection_interval=60.0
        ))
        
        # AODS vulnerability detection rate
        self.metrics_collector.register_metric(MetricDefinition(
            name="aods.vulnerabilities.rate",
            metric_type=MetricType.RATE,
            description="Rate of vulnerability detections per hour",
            collection_interval=300.0
        ))
        
        # AODS analysis accuracy
        self.metrics_collector.register_metric(MetricDefinition(
            name="aods.analysis.overall_accuracy",
            metric_type=MetricType.GAUGE,
            description="Overall analysis accuracy percentage",
            collection_interval=600.0
        ))
    
    def _setup_monitoring_hooks(self) -> None:
        """Set up monitoring hooks for AODS operations."""
        # Performance monitoring hooks
        def performance_hook(metrics: PerformanceMetrics):
            # Track AODS process performance
            for process in metrics.aods_processes:
                self.metrics_collector.record_metric(
                    "aods.processes.memory_mb",
                    process.memory_mb,
                    labels={'process_name': process.name, 'pid': str(process.pid)}
                )
                
                self.metrics_collector.record_metric(
                    "aods.processes.cpu_percent",
                    process.cpu_percent,
                    labels={'process_name': process.name, 'pid': str(process.pid)}
                )
        
        self.performance_tracker.register_performance_callback(performance_hook)
        
        # Resource monitoring hooks
        def resource_hook(usage_data):
            # Send alerts for critical resource usage
            for resource_type, usage in usage_data.items():
                if usage.usage_percent > 95:
                    self.alert_manager.send_alert(
                        title=f"Critical {resource_type.value} Usage",
                        message=f"{resource_type.value} usage at {usage.usage_percent:.1f}%",
                        severity=AlertSeverity.CRITICAL,
                        alert_type=AlertType.RESOURCE,
                        source="resource_monitor"
                    )
        
        self.resource_monitor.register_usage_callback(resource_hook)

def register_monitoring_hooks(component: str, hooks: Dict[str, Callable]) -> None:
    """Register monitoring hooks for a component."""
    integration = get_aods_monitoring_integration()
    
    for hook_type, hook_function in hooks.items():
        integration.registered_hooks[f"{component}_{hook_type}"].append(hook_function)
    
    logger.info(f"Registered {len(hooks)} monitoring hooks for {component}")

def get_monitoring_dashboard_data() -> Dict[str, Any]:
    """Get comprehensive monitoring data for dashboard display."""
    try:
        integration = get_aods_monitoring_integration()
        
        # Get current system metrics
        performance_tracker = get_performance_tracker()
        resource_monitor = get_resource_monitor()
        health_checker = get_health_checker()
        alert_manager = get_alert_manager()
        
        current_performance = performance_tracker.get_current_metrics()
        current_resources = resource_monitor.get_current_usage()
        system_health = health_checker.get_system_health_summary()
        active_alerts = alert_manager.get_active_alerts()
        
        # Get AODS-specific data
        recent_operations = []
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        with integration._lock:
            for op in integration.operation_history:
                if op.start_time >= cutoff_time:
                    recent_operations.append(op.to_dict())
        
        # Component status summary
        components = ['static_analysis', 'dynamic_analysis', 'network_analysis', 'crypto_analysis']
        component_status = {}
        for component in components:
            component_status[component] = integration.get_component_status(component)
        
        dashboard_data = {
            'timestamp': datetime.now().isoformat(),
            'system_overview': {
                'performance': current_performance.to_dict() if current_performance else {},
                'resources': {k: v.to_dict() for k, v in current_resources.items()},
                'health': system_health,
                'active_alerts': len(active_alerts)
            },
            'aods_overview': {
                'recent_operations': len(recent_operations),
                'component_status': component_status,
                'integration_active': integration.integration_active
            },
            'recent_operations': recent_operations[-20:],  # Last 20 operations
            'active_alerts': [alert.to_dict() for alert in active_alerts],
            'performance_summary': performance_tracker.get_performance_summary(60) if current_performance else {},
            'resource_summary': resource_monitor.get_resource_summary(60)
        }
        
        return dashboard_data
        
    except Exception as e:
        logger.error(f"Failed to get monitoring dashboard data: {e}")
        return {'error': str(e), 'timestamp': datetime.now().isoformat()}

def export_monitoring_metrics(format_type: str = "json", 
                            duration_hours: int = 24) -> Union[str, Dict]:
    """Export monitoring metrics in specified format."""
    try:
        # Get metrics data
        metrics_collector = get_metrics_collector()
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=duration_hours)
        
        # Query all metrics
        all_metrics = metrics_collector.query_metrics(
            start_time=start_time,
            end_time=end_time,
            limit=10000
        )
        
        # Organize metrics by name
        metrics_by_name = defaultdict(list)
        for metric in all_metrics:
            metrics_by_name[metric.metric_name].append(metric.to_dict())
        
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'export_period': {
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_hours': duration_hours
            },
            'total_metrics': len(all_metrics),
            'unique_metric_names': len(metrics_by_name),
            'metrics': dict(metrics_by_name)
        }
        
        if format_type.lower() == "json":
            return json.dumps(export_data, indent=2, default=str)
        elif format_type.lower() == "dict":
            return export_data
        else:
            logger.error(f"Unsupported export format: {format_type}")
            return export_data
            
    except Exception as e:
        logger.error(f"Failed to export monitoring metrics: {e}")
        return {"error": str(e)}

# Global AODS monitoring integration instance
_aods_monitoring_integration: Optional[AODSMonitoringIntegration] = None

def get_aods_monitoring_integration() -> AODSMonitoringIntegration:
    """Get the global AODS monitoring integration instance."""
    global _aods_monitoring_integration
    if _aods_monitoring_integration is None:
        _aods_monitoring_integration = AODSMonitoringIntegration()
    return _aods_monitoring_integration 