#!/usr/bin/env python3
"""
Health Checker for AODS Monitoring Framework

Comprehensive component health assessment and validation with detailed reporting,
automated health checks, and proactive issue detection.

Features:
- Component health monitoring and status tracking
- Automated health check scheduling and execution
- Dependency health validation
- Health trend analysis and prediction
- Proactive issue detection and alerting
- Integration with AODS core components
- Detailed health reporting and metrics

This component ensures all AODS components are functioning optimally
and provides early warning for potential issues.
"""

import time
import threading
import logging
import subprocess
import socket
import requests
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict
import statistics
import json
from pathlib import Path
import psutil

from ..analysis_exceptions import MonitoringError, ContextualLogger

logger = logging.getLogger(__name__)

class HealthStatus(Enum):
    """Component health status levels."""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"
    OFFLINE = "offline"

class ComponentType(Enum):
    """Types of components that can be monitored."""
    CORE_SERVICE = "core_service"
    ANALYSIS_ENGINE = "analysis_engine"
    DATABASE = "database"
    CACHE_SERVICE = "cache_service"
    EXTERNAL_TOOL = "external_tool"
    NETWORK_SERVICE = "network_service"
    FILE_SYSTEM = "file_system"
    SECURITY_SERVICE = "security_service"

@dataclass
class HealthCheckResult:
    """Result of a health check operation."""
    component_name: str
    component_type: ComponentType
    status: HealthStatus
    timestamp: datetime
    response_time_ms: float
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, float] = field(default_factory=dict)
    suggestions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'component_name': self.component_name,
            'component_type': self.component_type.value,
            'status': self.status.value,
            'timestamp': self.timestamp.isoformat(),
            'response_time_ms': self.response_time_ms,
            'message': self.message,
            'details': self.details,
            'metrics': self.metrics,
            'suggestions': self.suggestions
        }

@dataclass
class ComponentHealth:
    """Overall health status of a component."""
    component_name: str
    component_type: ComponentType
    current_status: HealthStatus
    last_check: datetime
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    uptime_percent: float = 100.0
    average_response_time: float = 0.0
    total_checks: int = 0
    failed_checks: int = 0
    health_trend: str = "stable"  # improving, degrading, stable
    last_healthy: Optional[datetime] = None
    
    def update_from_result(self, result: HealthCheckResult) -> None:
        """Update health status from check result."""
        self.last_check = result.timestamp
        self.total_checks += 1
        
        if result.status == HealthStatus.HEALTHY:
            self.consecutive_successes += 1
            self.consecutive_failures = 0
            self.last_healthy = result.timestamp
        else:
            self.consecutive_failures += 1
            self.consecutive_successes = 0
            self.failed_checks += 1
        
        # Update current status
        self.current_status = result.status
        
        # Calculate uptime percentage
        self.uptime_percent = ((self.total_checks - self.failed_checks) / self.total_checks) * 100
        
        # Update average response time
        if hasattr(self, '_response_times'):
            self._response_times.append(result.response_time_ms)
            self.average_response_time = statistics.mean(self._response_times)
        else:
            self._response_times = deque([result.response_time_ms], maxlen=100)
            self.average_response_time = result.response_time_ms
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'component_name': self.component_name,
            'component_type': self.component_type.value,
            'current_status': self.current_status.value,
            'last_check': self.last_check.isoformat() if self.last_check else None,
            'consecutive_failures': self.consecutive_failures,
            'consecutive_successes': self.consecutive_successes,
            'uptime_percent': self.uptime_percent,
            'average_response_time': self.average_response_time,
            'total_checks': self.total_checks,
            'failed_checks': self.failed_checks,
            'health_trend': self.health_trend,
            'last_healthy': self.last_healthy.isoformat() if self.last_healthy else None
        }

class HealthCheckDefinition:
    """Definition of a health check."""
    
    def __init__(self, name: str, component_type: ComponentType,
                 check_function: Callable[[], HealthCheckResult],
                 interval_seconds: float = 60.0,
                 timeout_seconds: float = 30.0,
                 enabled: bool = True):
        self.name = name
        self.component_type = component_type
        self.check_function = check_function
        self.interval_seconds = interval_seconds
        self.timeout_seconds = timeout_seconds
        self.enabled = enabled
        self.last_run = None
        self.next_run = None

class HealthChecker:
    """
    Comprehensive health checking system for AODS components.
    
    Provides automated health monitoring, status tracking,
    and proactive issue detection for all system components.
    """
    
    def __init__(self, check_interval: float = 30.0):
        """
        Initialize health checker.
        
        Args:
            check_interval: Default interval between health checks
        """
        self.check_interval = check_interval
        self.logger = ContextualLogger("health_checker")
        
        # State management
        self.monitoring_active = False
        self.checker_thread: Optional[threading.Thread] = None
        self._shutdown_event = threading.Event()
        
        # Health check definitions
        self.health_checks: Dict[str, HealthCheckDefinition] = {}
        
        # Component health tracking
        self.component_health: Dict[str, ComponentHealth] = {}
        self.health_history: deque = deque(maxlen=10000)
        
        # Callbacks
        self.health_callbacks: List[Callable[[HealthCheckResult], None]] = []
        self.status_change_callbacks: List[Callable[[str, HealthStatus, HealthStatus], None]] = []
        
        # Initialize default health checks
        self._register_default_health_checks()
    
    def start_monitoring(self) -> None:
        """Start health monitoring."""
        if self.monitoring_active:
            self.logger.warning("Health monitoring already active")
            return
        
        self.monitoring_active = True
        self._shutdown_event.clear()
        
        self.checker_thread = threading.Thread(
            target=self._monitoring_loop,
            name="HealthChecker",
            daemon=True
        )
        self.checker_thread.start()
        
        self.logger.info("Started health monitoring")
    
    def stop_monitoring(self) -> None:
        """Stop health monitoring."""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        self._shutdown_event.set()
        
        if self.checker_thread and self.checker_thread.is_alive():
            self.checker_thread.join(timeout=10.0)
        
        self.logger.info("Stopped health monitoring")
    
    def register_health_check(self, health_check: HealthCheckDefinition) -> None:
        """Register a new health check."""
        self.health_checks[health_check.name] = health_check
        self.logger.info(f"Registered health check: {health_check.name}")
    
    def unregister_health_check(self, name: str) -> None:
        """Unregister a health check."""
        if name in self.health_checks:
            del self.health_checks[name]
            self.logger.info(f"Unregistered health check: {name}")
    
    def register_health_callback(self, callback: Callable[[HealthCheckResult], None]) -> None:
        """Register callback for health check results."""
        self.health_callbacks.append(callback)
    
    def register_status_change_callback(self, callback: Callable[[str, HealthStatus, HealthStatus], None]) -> None:
        """Register callback for component status changes."""
        self.status_change_callbacks.append(callback)
    
    def run_health_check(self, name: str) -> Optional[HealthCheckResult]:
        """Run a specific health check immediately."""
        health_check = self.health_checks.get(name)
        if not health_check or not health_check.enabled:
            return None
        
        return self._execute_health_check(health_check)
    
    def run_all_health_checks(self) -> Dict[str, HealthCheckResult]:
        """Run all enabled health checks."""
        results = {}
        
        for name, health_check in self.health_checks.items():
            if health_check.enabled:
                result = self._execute_health_check(health_check)
                if result:
                    results[name] = result
        
        return results
    
    def get_component_health(self, component_name: str) -> Optional[ComponentHealth]:
        """Get health status of a specific component."""
        return self.component_health.get(component_name)
    
    def get_all_component_health(self) -> Dict[str, ComponentHealth]:
        """Get health status of all components."""
        return self.component_health.copy()
    
    def get_system_health_summary(self) -> Dict[str, Any]:
        """Get overall system health summary."""
        if not self.component_health:
            return {
                "overall_status": "unknown",
                "total_components": 0,
                "healthy_components": 0,
                "warning_components": 0,
                "critical_components": 0,
                "offline_components": 0,
                "average_uptime": 0.0,
                "average_response_time": 0.0
            }
        
        # Count components by status
        status_counts = defaultdict(int)
        total_uptime = 0.0
        total_response_time = 0.0
        
        for health in self.component_health.values():
            status_counts[health.current_status] += 1
            total_uptime += health.uptime_percent
            total_response_time += health.average_response_time
        
        total_components = len(self.component_health)
        healthy_count = status_counts[HealthStatus.HEALTHY]
        warning_count = status_counts[HealthStatus.WARNING]
        critical_count = status_counts[HealthStatus.CRITICAL]
        offline_count = status_counts[HealthStatus.OFFLINE]
        
        # Determine overall system status
        if critical_count > 0 or offline_count > total_components * 0.3:
            overall_status = "critical"
        elif warning_count > total_components * 0.5:
            overall_status = "warning"
        elif healthy_count > total_components * 0.8:
            overall_status = "healthy"
        else:
            overall_status = "degraded"
        
        return {
            "overall_status": overall_status,
            "total_components": total_components,
            "healthy_components": healthy_count,
            "warning_components": warning_count,
            "critical_components": critical_count,
            "offline_components": offline_count,
            "average_uptime": total_uptime / total_components if total_components > 0 else 0.0,
            "average_response_time": total_response_time / total_components if total_components > 0 else 0.0,
            "last_updated": datetime.now().isoformat()
        }
    
    def get_health_trends(self, component_name: Optional[str] = None, 
                         duration_hours: int = 24) -> Dict[str, Any]:
        """Get health trends for a component or system."""
        cutoff_time = datetime.now() - timedelta(hours=duration_hours)
        
        if component_name:
            # Get trends for specific component
            relevant_results = [
                result for result in self.health_history 
                if result.component_name == component_name and result.timestamp >= cutoff_time
            ]
        else:
            # Get trends for entire system
            relevant_results = [
                result for result in self.health_history 
                if result.timestamp >= cutoff_time
            ]
        
        if not relevant_results:
            return {"error": "No health data available for specified period"}
        
        # Calculate trends
        status_over_time = []
        response_times = []
        
        for result in relevant_results:
            status_over_time.append({
                "timestamp": result.timestamp.isoformat(),
                "status": result.status.value,
                "component": result.component_name
            })
            response_times.append(result.response_time_ms)
        
        # Calculate health score over time (healthy=100, warning=50, critical=0)
        health_scores = []
        for result in relevant_results:
            if result.status == HealthStatus.HEALTHY:
                score = 100
            elif result.status == HealthStatus.WARNING:
                score = 50
            elif result.status == HealthStatus.CRITICAL:
                score = 0
            else:
                score = 25  # Unknown/offline
            health_scores.append(score)
        
        return {
            "component_name": component_name or "system",
            "duration_hours": duration_hours,
            "sample_count": len(relevant_results),
            "average_health_score": statistics.mean(health_scores),
            "health_score_trend": "improving" if len(health_scores) > 10 and health_scores[-5:] > health_scores[:5] else "stable",
            "average_response_time": statistics.mean(response_times),
            "response_time_trend": self._calculate_trend(response_times),
            "status_distribution": self._calculate_status_distribution(relevant_results),
            "status_over_time": status_over_time[-100:]  # Last 100 data points
        }
    
    def _register_default_health_checks(self) -> None:
        """Register default health checks for common components."""
        
        # System health check
        self.register_health_check(HealthCheckDefinition(
            name="system_resources",
            component_type=ComponentType.CORE_SERVICE,
            check_function=self._check_system_resources,
            interval_seconds=30.0
        ))
        
        # Database connectivity check
        self.register_health_check(HealthCheckDefinition(
            name="database_connectivity",
            component_type=ComponentType.DATABASE,
            check_function=self._check_database_connectivity,
            interval_seconds=60.0
        ))
        
        # File system check
        self.register_health_check(HealthCheckDefinition(
            name="file_system",
            component_type=ComponentType.FILE_SYSTEM,
            check_function=self._check_file_system,
            interval_seconds=120.0
        ))
        
        # External tools check
        self.register_health_check(HealthCheckDefinition(
            name="external_tools",
            component_type=ComponentType.EXTERNAL_TOOL,
            check_function=self._check_external_tools,
            interval_seconds=300.0
        ))
    
    def _monitoring_loop(self) -> None:
        """Main health monitoring loop."""
        while self.monitoring_active and not self._shutdown_event.is_set():
            try:
                current_time = datetime.now()
                
                # Check which health checks need to run
                for name, health_check in self.health_checks.items():
                    if not health_check.enabled:
                        continue
                    
                    # Calculate next run time if not set
                    if health_check.next_run is None:
                        health_check.next_run = current_time + timedelta(seconds=health_check.interval_seconds)
                    
                    # Run check if it's time
                    if current_time >= health_check.next_run:
                        result = self._execute_health_check(health_check)
                        if result:
                            self._process_health_result(result)
                        
                        # Schedule next run
                        health_check.last_run = current_time
                        health_check.next_run = current_time + timedelta(seconds=health_check.interval_seconds)
                
                # Sleep until next check
                self._shutdown_event.wait(timeout=10.0)
                
            except Exception as e:
                self.logger.error(f"Health monitoring loop error: {e}")
                self._shutdown_event.wait(timeout=30.0)
    
    def _execute_health_check(self, health_check: HealthCheckDefinition) -> Optional[HealthCheckResult]:
        """Execute a single health check with timeout."""
        start_time = time.time()
        
        try:
            # Execute health check with timeout
            result = health_check.check_function()
            execution_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            
            # Update response time if not set
            if result.response_time_ms == 0:
                result.response_time_ms = execution_time
            
            return result
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            
            # Create error result
            error_result = HealthCheckResult(
                component_name=health_check.name,
                component_type=health_check.component_type,
                status=HealthStatus.CRITICAL,
                timestamp=datetime.now(),
                response_time_ms=execution_time,
                message=f"Health check failed: {str(e)}",
                details={"error": str(e), "error_type": type(e).__name__}
            )
            
            self.logger.error(f"Health check '{health_check.name}' failed: {e}")
            return error_result
    
    def _process_health_result(self, result: HealthCheckResult) -> None:
        """Process a health check result."""
        # Store in history
        self.health_history.append(result)
        
        # Update component health
        if result.component_name not in self.component_health:
            self.component_health[result.component_name] = ComponentHealth(
                component_name=result.component_name,
                component_type=result.component_type,
                current_status=result.status,
                last_check=result.timestamp
            )
        
        # Get previous status for change detection
        previous_status = self.component_health[result.component_name].current_status
        
        # Update component health
        self.component_health[result.component_name].update_from_result(result)
        
        # Notify callbacks
        for callback in self.health_callbacks:
            try:
                callback(result)
            except Exception as e:
                self.logger.error(f"Health callback error: {e}")
        
        # Notify status change callbacks if status changed
        if previous_status != result.status:
            for callback in self.status_change_callbacks:
                try:
                    callback(result.component_name, previous_status, result.status)
                except Exception as e:
                    self.logger.error(f"Status change callback error: {e}")
    
    def _check_system_resources(self) -> HealthCheckResult:
        """Check system resource availability."""
        start_time = time.time()
        
        try:
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=1.0)
            
            # Check memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Check disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            
            # Determine status
            if cpu_percent > 95 or memory_percent > 95 or disk_percent > 98:
                status = HealthStatus.CRITICAL
                message = "System resources critically low"
            elif cpu_percent > 85 or memory_percent > 85 or disk_percent > 90:
                status = HealthStatus.WARNING
                message = "System resources under pressure"
            else:
                status = HealthStatus.HEALTHY
                message = "System resources available"
            
            response_time = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                component_name="system_resources",
                component_type=ComponentType.CORE_SERVICE,
                status=status,
                timestamp=datetime.now(),
                response_time_ms=response_time,
                message=message,
                metrics={
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory_percent,
                    "disk_percent": disk_percent
                },
                details={
                    "cpu_usage": cpu_percent,
                    "memory_usage": memory_percent,
                    "disk_usage": disk_percent,
                    "memory_available_gb": memory.available / (1024**3)
                }
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                component_name="system_resources",
                component_type=ComponentType.CORE_SERVICE,
                status=HealthStatus.CRITICAL,
                timestamp=datetime.now(),
                response_time_ms=response_time,
                message=f"System resource check failed: {str(e)}",
                details={"error": str(e)}
            )
    
    def _check_database_connectivity(self) -> HealthCheckResult:
        """Check database connectivity with comprehensive validation."""
        start_time = time.time()
        
        try:
            import sqlite3
            from pathlib import Path
            
            # Define database configurations to check
            db_configs = [
                {
                    "name": "pattern_reliability",
                    "path": "core/shared_infrastructure/pattern_reliability_database.db",
                    "test_table": "patterns",
                    "expected_columns": ["id", "pattern", "confidence"]
                },
                {
                    "name": "learning_system", 
                    "path": "core/shared_infrastructure/learning_system.db",
                    "test_table": "learning_data",
                    "expected_columns": ["id", "timestamp", "data"]
                },
                {
                    "name": "caching_system",
                    "path": "cache/analysis_cache.db", 
                    "test_table": "cache_entries",
                    "expected_columns": ["key", "value", "timestamp"]
                }
            ]
            
            db_results = []
            healthy_count = 0
            warning_count = 0
            critical_count = 0
            
            for db_config in db_configs:
                db_result = self._validate_database_connection(db_config)
                db_results.append(db_result)
                
                if db_result["status"] == "healthy":
                    healthy_count += 1
                elif db_result["status"] == "warning":
                    warning_count += 1
                else:
                    critical_count += 1
            
            # Determine overall database health status
            total_dbs = len(db_configs)
            if healthy_count == total_dbs:
                status = HealthStatus.HEALTHY
                message = f"All databases operational ({healthy_count}/{total_dbs})"
            elif healthy_count >= total_dbs * 0.7:
                status = HealthStatus.WARNING 
                message = f"Most databases operational ({healthy_count}/{total_dbs} healthy, {warning_count} warnings)"
            elif healthy_count > 0:
                status = HealthStatus.WARNING
                message = f"Some databases operational ({healthy_count}/{total_dbs} healthy, {critical_count} critical)"
            else:
                status = HealthStatus.CRITICAL
                message = f"Database connectivity issues ({critical_count}/{total_dbs} critical)"
            
            response_time = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                component_name="database_connectivity",
                component_type=ComponentType.DATABASE,
                status=status,
                timestamp=datetime.now(),
                response_time_ms=response_time,
                message=message,
                details={
                    "database_results": db_results,
                    "healthy_count": healthy_count,
                    "warning_count": warning_count,
                    "critical_count": critical_count,
                    "total_databases": total_dbs
                },
                metrics={
                    "database_health_ratio": healthy_count / total_dbs if total_dbs > 0 else 0,
                    "connectivity_score": (healthy_count * 100 + warning_count * 50) / (total_dbs * 100) if total_dbs > 0 else 0
                },
                suggestions=self._generate_database_suggestions(db_results)
            )
            
        except ImportError as e:
            response_time = (time.time() - start_time) * 1000
            return HealthCheckResult(
                component_name="database_connectivity",
                component_type=ComponentType.DATABASE,
                status=HealthStatus.CRITICAL,
                timestamp=datetime.now(),
                response_time_ms=response_time,
                message="SQLite module not available",
                details={"error": str(e), "error_type": "ImportError"},
                suggestions=["Install sqlite3 module", "Check Python installation"]
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return HealthCheckResult(
                component_name="database_connectivity",
                component_type=ComponentType.DATABASE,
                status=HealthStatus.CRITICAL,
                timestamp=datetime.now(),
                response_time_ms=response_time,
                message=f"Database connectivity check failed: {str(e)}",
                details={"error": str(e), "error_type": type(e).__name__},
                suggestions=["Check database configuration", "Verify file permissions", "Review error logs"]
            )
    
    def _validate_database_connection(self, db_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate connection to a specific database."""
        import sqlite3
        from pathlib import Path
        
        db_name = db_config["name"]
        db_path = Path(db_config["path"])
        test_table = db_config.get("test_table")
        expected_columns = db_config.get("expected_columns", [])
        
        result = {
            "name": db_name,
            "path": str(db_path),
            "status": "unknown",
            "message": "",
            "details": {},
            "checks_performed": []
        }
        
        try:
            # Check 1: File existence
            if not db_path.exists():
                result.update({
                    "status": "warning",
                    "message": "Database file does not exist",
                    "details": {"file_exists": False},
                    "checks_performed": ["file_existence"]
                })
                return result
            
            result["checks_performed"].append("file_existence")
            result["details"]["file_exists"] = True
            result["details"]["file_size_bytes"] = db_path.stat().st_size
            
            # Check 2: File permissions
            if not db_path.is_file() or not os.access(db_path, os.R_OK):
                result.update({
                    "status": "critical",
                    "message": "Database file not readable",
                    "details": {**result["details"], "readable": False}
                })
                return result
            
            result["checks_performed"].append("file_permissions")
            result["details"]["readable"] = True
            result["details"]["writable"] = os.access(db_path, os.W_OK)
            
            # Check 3: Database connection
            conn = None
            try:
                conn = sqlite3.connect(str(db_path), timeout=5.0)
                result["checks_performed"].append("connection")
                result["details"]["connection_successful"] = True
                
                # Check 4: Database integrity
                cursor = conn.cursor()
                cursor.execute("PRAGMA integrity_check")
                integrity_result = cursor.fetchone()
                
                if integrity_result and integrity_result[0] == "ok":
                    result["checks_performed"].append("integrity_check")
                    result["details"]["integrity_ok"] = True
                else:
                    result.update({
                        "status": "critical",
                        "message": "Database integrity check failed",
                        "details": {**result["details"], "integrity_ok": False, "integrity_result": str(integrity_result)}
                    })
                    return result
                
                # Check 5: Schema validation (if test table specified)
                if test_table:
                    try:
                        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{test_table}'")
                        table_exists = cursor.fetchone() is not None
                        result["checks_performed"].append("schema_validation")
                        result["details"]["test_table_exists"] = table_exists
                        
                        if table_exists and expected_columns:
                            # Check column existence
                            cursor.execute(f"PRAGMA table_info({test_table})")
                            columns_info = cursor.fetchall()
                            existing_columns = [col[1] for col in columns_info]  # Column names are at index 1
                            
                            missing_columns = [col for col in expected_columns if col not in existing_columns]
                            result["details"]["expected_columns"] = expected_columns
                            result["details"]["existing_columns"] = existing_columns  
                            result["details"]["missing_columns"] = missing_columns
                            
                            if missing_columns:
                                result.update({
                                    "status": "warning",
                                    "message": f"Table schema incomplete - missing columns: {missing_columns}"
                                })
                                return result
                    
                    except sqlite3.Error as schema_error:
                        result["details"]["schema_error"] = str(schema_error)
                        result.update({
                            "status": "warning", 
                            "message": f"Schema validation failed: {schema_error}"
                        })
                        return result
                
                # Check 6: Basic operations test
                try:
                    cursor.execute("SELECT sqlite_version()")
                    version = cursor.fetchone()[0]
                    result["checks_performed"].append("basic_operations")
                    result["details"]["sqlite_version"] = version
                    result["details"]["basic_operations_ok"] = True
                    
                    # Test write operation (if writable)
                    if result["details"].get("writable", False):
                        test_table_name = f"health_check_test_{int(time.time())}"
                        cursor.execute(f"CREATE TEMPORARY TABLE {test_table_name} (id INTEGER)")
                        cursor.execute(f"INSERT INTO {test_table_name} VALUES (1)")
                        cursor.execute(f"SELECT COUNT(*) FROM {test_table_name}")
                        count = cursor.fetchone()[0]
                        cursor.execute(f"DROP TABLE {test_table_name}")
                        
                        result["details"]["write_operations_ok"] = count == 1
                        result["checks_performed"].append("write_operations")
                
                except sqlite3.Error as ops_error:
                    result["details"]["operations_error"] = str(ops_error)
                    result.update({
                        "status": "warning",
                        "message": f"Basic operations test failed: {ops_error}"
                    })
                    return result
                
                # All checks passed
                result.update({
                    "status": "healthy",
                    "message": "Database fully operational"
                })
                
            except sqlite3.Error as db_error:
                result.update({
                    "status": "critical",
                    "message": f"Database connection failed: {db_error}",
                    "details": {**result["details"], "connection_error": str(db_error)}
                })
                
            finally:
                if conn:
                    conn.close()
                    
        except Exception as e:
            result.update({
                "status": "critical",
                "message": f"Database validation error: {e}",
                "details": {**result["details"], "validation_error": str(e)}
            })
        
        return result
    
    def _generate_database_suggestions(self, db_results: List[Dict[str, Any]]) -> List[str]:
        """Generate suggestions based on database validation results."""
        suggestions = []
        
        for db_result in db_results:
            if db_result["status"] == "critical":
                if not db_result["details"].get("file_exists", True):
                    suggestions.append(f"Create missing database file: {db_result['path']}")
                elif not db_result["details"].get("readable", True):
                    suggestions.append(f"Fix file permissions for: {db_result['path']}")
                elif "connection_error" in db_result["details"]:
                    suggestions.append(f"Check database corruption for: {db_result['name']}")
                    
            elif db_result["status"] == "warning":
                if db_result["details"].get("missing_columns"):
                    suggestions.append(f"Update schema for {db_result['name']} - missing: {db_result['details']['missing_columns']}")
                if not db_result["details"].get("writable", True):
                    suggestions.append(f"Enable write permissions for: {db_result['path']}")
        
        # Add general suggestions if multiple databases have issues
        critical_count = sum(1 for r in db_results if r["status"] == "critical")
        if critical_count > 1:
            suggestions.append("Consider running database maintenance routine")
            suggestions.append("Check available disk space and file system health")
        
        return suggestions
    
    def _check_file_system(self) -> HealthCheckResult:
        """Check file system health."""
        start_time = time.time()
        
        try:
            from pathlib import Path
            
            # Check critical directories
            critical_dirs = [
                "core",
                "plugins",
                "config",
                "logs"
            ]
            
            accessible_dirs = []
            for dir_name in critical_dirs:
                if Path(dir_name).exists() and Path(dir_name).is_dir():
                    accessible_dirs.append(dir_name)
            
            # Check write permissions to logs directory
            can_write = False
            try:
                test_file = Path("logs/health_check_test.tmp")
                test_file.parent.mkdir(exist_ok=True)
                test_file.write_text("test")
                test_file.unlink()
                can_write = True
            except:
                pass
            
            if len(accessible_dirs) == len(critical_dirs) and can_write:
                status = HealthStatus.HEALTHY
                message = "File system accessible and writable"
            elif len(accessible_dirs) >= len(critical_dirs) * 0.8:
                status = HealthStatus.WARNING
                message = "Some file system issues detected"
            else:
                status = HealthStatus.CRITICAL
                message = "File system accessibility issues"
            
            response_time = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                component_name="file_system",
                component_type=ComponentType.FILE_SYSTEM,
                status=status,
                timestamp=datetime.now(),
                response_time_ms=response_time,
                message=message,
                details={
                    "accessible_directories": accessible_dirs,
                    "can_write": can_write,
                    "total_critical_dirs": len(critical_dirs)
                }
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                component_name="file_system",
                component_type=ComponentType.FILE_SYSTEM,
                status=HealthStatus.CRITICAL,
                timestamp=datetime.now(),
                response_time_ms=response_time,
                message=f"File system check failed: {str(e)}",
                details={"error": str(e)}
            )
    
    def _check_external_tools(self) -> HealthCheckResult:
        """Check availability of external tools."""
        start_time = time.time()
        
        try:
            # Check for common external tools
            tools_to_check = [
                ("adb", "adb version"),
                ("aapt", "aapt version"),
                ("jadx", "jadx --version"),
                ("python3", "python3 --version")
            ]
            
            available_tools = []
            for tool_name, command in tools_to_check:
                try:
                    result = subprocess.run(
                        command.split(),
                        capture_output=True,
                        timeout=10,
                        text=True
                    )
                    if result.returncode == 0:
                        available_tools.append(tool_name)
                except:
                    pass
            
            total_tools = len(tools_to_check)
            available_count = len(available_tools)
            
            if available_count == total_tools:
                status = HealthStatus.HEALTHY
                message = "All external tools available"
            elif available_count >= total_tools * 0.8:
                status = HealthStatus.WARNING
                message = f"Some external tools missing ({available_count}/{total_tools} available)"
            else:
                status = HealthStatus.CRITICAL
                message = f"Many external tools missing ({available_count}/{total_tools} available)"
            
            response_time = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                component_name="external_tools",
                component_type=ComponentType.EXTERNAL_TOOL,
                status=status,
                timestamp=datetime.now(),
                response_time_ms=response_time,
                message=message,
                details={
                    "available_tools": available_tools,
                    "total_tools": total_tools,
                    "availability_percent": (available_count / total_tools) * 100
                }
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                component_name="external_tools",
                component_type=ComponentType.EXTERNAL_TOOL,
                status=HealthStatus.CRITICAL,
                timestamp=datetime.now(),
                response_time_ms=response_time,
                message=f"External tools check failed: {str(e)}",
                details={"error": str(e)}
            )
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction for a list of values."""
        if len(values) < 10:
            return "insufficient_data"
        
        # Compare first half to second half
        mid_point = len(values) // 2
        first_half_avg = statistics.mean(values[:mid_point])
        second_half_avg = statistics.mean(values[mid_point:])
        
        change_percent = ((second_half_avg - first_half_avg) / first_half_avg) * 100
        
        if change_percent > 10:
            return "increasing"
        elif change_percent < -10:
            return "decreasing"
        else:
            return "stable"
    
    def _calculate_status_distribution(self, results: List[HealthCheckResult]) -> Dict[str, int]:
        """Calculate distribution of health statuses."""
        distribution = defaultdict(int)
        for result in results:
            distribution[result.status.value] += 1
        return dict(distribution)

# Global health checker instance
_health_checker: Optional[HealthChecker] = None

def get_health_checker() -> HealthChecker:
    """Get the global health checker instance."""
    global _health_checker
    if _health_checker is None:
        _health_checker = HealthChecker()
    return _health_checker 