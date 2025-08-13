#!/usr/bin/env python3
"""
AODS Unified Monitoring Framework

Comprehensive system monitoring framework providing:
- System performance tracking (CPU, memory, disk, network)
- Component health monitoring and alerting
- Resource usage analytics and optimization
- Real-time metrics collection and aggregation
- Alert management and notification system
- Historical trend analysis and reporting
- Integration with existing AODS infrastructure

Key Components:
- PerformanceTracker: Real-time system performance monitoring
- ResourceMonitor: Resource usage tracking and optimization
- HealthChecker: Component health assessment and validation
- AlertManager: Alert generation, routing, and notification
- MetricsCollector: Comprehensive metrics collection and storage
- TrendAnalyzer: Historical analysis and predictive insights

Usage:
    from core.shared_infrastructure.monitoring import (
        get_performance_tracker,
        get_resource_monitor,
        get_health_checker,
        get_alert_manager,
        get_metrics_collector
    )
    
    # Start comprehensive monitoring
    performance = get_performance_tracker()
    performance.start_monitoring()
    
    # Monitor specific component health
    health = get_health_checker()
    health_status = health.check_component_health('analysis_engine')
    
    # Collect and analyze metrics
    metrics = get_metrics_collector()
    current_metrics = metrics.collect_current_metrics()
"""

# Core monitoring components
from .performance_tracker import (
    PerformanceTracker,
    PerformanceMetrics,
    SystemMetrics,
    ProcessMetrics,
    get_performance_tracker
)

from .resource_monitor import (
    ResourceMonitor,
    ResourceUsage,
    ResourceThresholds,
    ResourceAlert,
    get_resource_monitor
)

from .health_checker import (
    HealthChecker,
    HealthStatus,
    ComponentHealth,
    HealthCheckResult,
    get_health_checker
)

from .alert_manager import (
    AlertManager,
    Alert,
    AlertSeverity,
    AlertType,
    NotificationChannel,
    get_alert_manager
)

from .metrics_collector import (
    MetricsCollector,
    MetricType,
    MetricDataPoint,
    MetricsSnapshot,
    get_metrics_collector
)

from .trend_analyzer import (
    TrendAnalyzer,
    TrendData,
    TrendPrediction,
    TrendInsight,
    get_trend_analyzer
)

# Monitoring utilities
from .monitoring_utils import (
    MonitoringConfiguration,
    MonitoringException,
    format_metric_value,
    calculate_metric_percentile,
    get_system_baseline
)

# Integration helpers
from .integration_helpers import (
    AODSMonitoringIntegration,
    register_monitoring_hooks,
    get_monitoring_dashboard_data,
    export_monitoring_metrics
)

__all__ = [
    # Core monitoring classes
    'PerformanceTracker',
    'PerformanceMetrics',
    'SystemMetrics',
    'ProcessMetrics',
    'ResourceMonitor',
    'ResourceUsage',
    'ResourceThresholds',
    'ResourceAlert',
    'HealthChecker',
    'HealthStatus',
    'ComponentHealth',
    'HealthCheckResult',
    'AlertManager',
    'Alert',
    'AlertSeverity',
    'AlertType',
    'NotificationChannel',
    'MetricsCollector',
    'MetricType',
    'MetricDataPoint',
    'MetricsSnapshot',
    'TrendAnalyzer',
    'TrendData',
    'TrendPrediction',
    'TrendInsight',
    
    # Utility classes
    'MonitoringConfiguration',
    'MonitoringException',
    'AODSMonitoringIntegration',
    
    # Singleton getter functions
    'get_performance_tracker',
    'get_resource_monitor',
    'get_health_checker',
    'get_alert_manager',
    'get_metrics_collector',
    'get_trend_analyzer',
    
    # Utility functions
    'format_metric_value',
    'calculate_metric_percentile',
    'get_system_baseline',
    'register_monitoring_hooks',
    'get_monitoring_dashboard_data',
    'export_monitoring_metrics'
]

# Package metadata
__version__ = "1.0.0"
__author__ = "AODS Development Team"
__description__ = "Unified monitoring framework for AODS security analysis platform" 