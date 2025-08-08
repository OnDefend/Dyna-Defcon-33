#!/usr/bin/env python3
"""
Metrics Collector for AODS Monitoring Framework

Comprehensive metrics collection and storage system with time-series data
management, aggregation, and analytics capabilities.

Features:
- Multi-type metrics collection (counter, gauge, histogram, summary)
- Time-series data storage and management
- Metrics aggregation and rollup
- Historical data retention policies
- Query interface for metrics analysis
- Integration with monitoring components
- Performance-optimized storage

This component provides the foundation for metrics-driven monitoring
and performance analysis across the AODS platform.
"""

import time
import threading
import logging
import sqlite3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict
import statistics
from pathlib import Path
import concurrent.futures

from ..analysis_exceptions import MonitoringError, ContextualLogger

logger = logging.getLogger(__name__)

class MetricType(Enum):
    """Types of metrics that can be collected."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    RATE = "rate"

@dataclass
class MetricDataPoint:
    """Single metric data point."""
    metric_name: str
    metric_type: MetricType
    value: Union[float, int, Dict[str, Any]]
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'metric_name': self.metric_name,
            'metric_type': self.metric_type.value,
            'value': self.value,
            'timestamp': self.timestamp.isoformat(),
            'labels': self.labels,
            'metadata': self.metadata
        }

@dataclass
class MetricsSnapshot:
    """Snapshot of multiple metrics at a point in time."""
    timestamp: datetime
    metrics: Dict[str, MetricDataPoint]
    source: str
    snapshot_id: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'metrics': {name: metric.to_dict() for name, metric in self.metrics.items()},
            'source': self.source,
            'snapshot_id': self.snapshot_id
        }

class MetricDefinition:
    """Definition of a metric to be collected."""
    
    def __init__(self, name: str, metric_type: MetricType,
                 description: str = "", unit: str = "",
                 labels: Optional[Dict[str, str]] = None,
                 collection_function: Optional[Callable[[], Union[float, int, Dict]]] = None,
                 collection_interval: float = 60.0):
        self.name = name
        self.metric_type = metric_type
        self.description = description
        self.unit = unit
        self.labels = labels or {}
        self.collection_function = collection_function
        self.collection_interval = collection_interval
        self.last_collection = None
        self.next_collection = None
        self.enabled = True

class MetricsStorage:
    """Storage backend for metrics data."""
    
    def __init__(self, db_path: str = "metrics.db"):
        self.db_path = db_path
        self.logger = ContextualLogger("metrics_storage")
        self._lock = threading.Lock()
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize the metrics database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        metric_name TEXT NOT NULL,
                        metric_type TEXT NOT NULL,
                        value TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        labels TEXT,
                        metadata TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        INDEX(metric_name),
                        INDEX(timestamp),
                        INDEX(metric_type)
                    )
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS metric_snapshots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        snapshot_id TEXT UNIQUE NOT NULL,
                        timestamp TEXT NOT NULL,
                        source TEXT NOT NULL,
                        metrics_data TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        INDEX(snapshot_id),
                        INDEX(timestamp),
                        INDEX(source)
                    )
                """)
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to initialize metrics database: {e}")
            raise MonitoringError(f"Database initialization failed: {e}")
    
    def store_metric(self, metric: MetricDataPoint) -> None:
        """Store a single metric data point."""
        try:
            with self._lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT INTO metrics 
                        (metric_name, metric_type, value, timestamp, labels, metadata)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        metric.metric_name,
                        metric.metric_type.value,
                        json.dumps(metric.value),
                        metric.timestamp.isoformat(),
                        json.dumps(metric.labels),
                        json.dumps(metric.metadata)
                    ))
                    conn.commit()
                    
        except Exception as e:
            self.logger.error(f"Failed to store metric {metric.metric_name}: {e}")
    
    def store_snapshot(self, snapshot: MetricsSnapshot) -> None:
        """Store a metrics snapshot."""
        try:
            with self._lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT INTO metric_snapshots 
                        (snapshot_id, timestamp, source, metrics_data)
                        VALUES (?, ?, ?, ?)
                    """, (
                        snapshot.snapshot_id,
                        snapshot.timestamp.isoformat(),
                        snapshot.source,
                        json.dumps(snapshot.to_dict())
                    ))
                    conn.commit()
                    
        except Exception as e:
            self.logger.error(f"Failed to store snapshot {snapshot.snapshot_id}: {e}")
    
    def query_metrics(self, metric_name: Optional[str] = None,
                     start_time: Optional[datetime] = None,
                     end_time: Optional[datetime] = None,
                     labels: Optional[Dict[str, str]] = None,
                     limit: int = 1000) -> List[MetricDataPoint]:
        """Query metrics from storage."""
        try:
            query_parts = ["SELECT * FROM metrics WHERE 1=1"]
            params = []
            
            if metric_name:
                query_parts.append("AND metric_name = ?")
                params.append(metric_name)
            
            if start_time:
                query_parts.append("AND timestamp >= ?")
                params.append(start_time.isoformat())
            
            if end_time:
                query_parts.append("AND timestamp <= ?")
                params.append(end_time.isoformat())
            
            query_parts.append("ORDER BY timestamp DESC LIMIT ?")
            params.append(limit)
            
            query = " ".join(query_parts)
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()
            
            metrics = []
            for row in rows:
                try:
                    metric = MetricDataPoint(
                        metric_name=row['metric_name'],
                        metric_type=MetricType(row['metric_type']),
                        value=json.loads(row['value']),
                        timestamp=datetime.fromisoformat(row['timestamp']),
                        labels=json.loads(row['labels'] or '{}'),
                        metadata=json.loads(row['metadata'] or '{}')
                    )
                    
                    # Apply label filtering if specified
                    if labels:
                        if all(metric.labels.get(k) == v for k, v in labels.items()):
                            metrics.append(metric)
                    else:
                        metrics.append(metric)
                        
                except Exception as e:
                    self.logger.warning(f"Failed to parse metric row: {e}")
                    continue
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Failed to query metrics: {e}")
            return []
    
    def cleanup_old_metrics(self, retention_days: int = 30) -> int:
        """Clean up metrics older than retention period."""
        try:
            cutoff_time = datetime.now() - timedelta(days=retention_days)
            
            with self._lock:
                with sqlite3.connect(self.db_path) as conn:
                    # Clean up old metrics
                    cursor = conn.execute("""
                        DELETE FROM metrics WHERE timestamp < ?
                    """, (cutoff_time.isoformat(),))
                    metrics_deleted = cursor.rowcount
                    
                    # Clean up old snapshots
                    cursor = conn.execute("""
                        DELETE FROM metric_snapshots WHERE timestamp < ?
                    """, (cutoff_time.isoformat(),))
                    snapshots_deleted = cursor.rowcount
                    
                    conn.commit()
                    
                    total_deleted = metrics_deleted + snapshots_deleted
                    self.logger.info(f"Cleaned up {total_deleted} old records (metrics: {metrics_deleted}, snapshots: {snapshots_deleted})")
                    return total_deleted
                    
        except Exception as e:
            self.logger.error(f"Failed to cleanup old metrics: {e}")
            return 0

class MetricsAggregator:
    """Aggregates metrics over time periods."""
    
    def __init__(self, storage: MetricsStorage):
        self.storage = storage
        self.logger = ContextualLogger("metrics_aggregator")
    
    def aggregate_metrics(self, metric_name: str,
                         aggregation_period: timedelta = timedelta(hours=1),
                         aggregation_function: str = "average",
                         start_time: Optional[datetime] = None,
                         end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Aggregate metrics over specified time periods."""
        try:
            # Set default time range
            if not end_time:
                end_time = datetime.now()
            if not start_time:
                start_time = end_time - timedelta(days=1)
            
            # Query raw metrics
            raw_metrics = self.storage.query_metrics(
                metric_name=metric_name,
                start_time=start_time,
                end_time=end_time,
                limit=10000
            )
            
            if not raw_metrics:
                return []
            
            # Group metrics by time periods
            period_groups = defaultdict(list)
            
            for metric in raw_metrics:
                # Calculate period bucket
                period_start = self._get_period_start(metric.timestamp, aggregation_period)
                period_groups[period_start].append(metric)
            
            # Aggregate each period
            aggregated_results = []
            
            for period_start, period_metrics in period_groups.items():
                period_end = period_start + aggregation_period
                
                # Extract numeric values
                values = []
                for metric in period_metrics:
                    if isinstance(metric.value, (int, float)):
                        values.append(float(metric.value))
                    elif isinstance(metric.value, dict) and 'value' in metric.value:
                        values.append(float(metric.value['value']))
                
                if not values:
                    continue
                
                # Apply aggregation function
                if aggregation_function == "average":
                    aggregated_value = statistics.mean(values)
                elif aggregation_function == "sum":
                    aggregated_value = sum(values)
                elif aggregation_function == "min":
                    aggregated_value = min(values)
                elif aggregation_function == "max":
                    aggregated_value = max(values)
                elif aggregation_function == "median":
                    aggregated_value = statistics.median(values)
                elif aggregation_function == "count":
                    aggregated_value = len(values)
                else:
                    aggregated_value = statistics.mean(values)  # Default to average
                
                aggregated_results.append({
                    'period_start': period_start.isoformat(),
                    'period_end': period_end.isoformat(),
                    'metric_name': metric_name,
                    'aggregated_value': aggregated_value,
                    'sample_count': len(values),
                    'aggregation_function': aggregation_function
                })
            
            # Sort by period start
            aggregated_results.sort(key=lambda x: x['period_start'])
            
            return aggregated_results
            
        except Exception as e:
            self.logger.error(f"Failed to aggregate metrics: {e}")
            return []
    
    def _get_period_start(self, timestamp: datetime, period: timedelta) -> datetime:
        """Get the start of the period for a given timestamp."""
        # Align to period boundaries
        if period == timedelta(hours=1):
            return timestamp.replace(minute=0, second=0, microsecond=0)
        elif period == timedelta(minutes=5):
            minute = (timestamp.minute // 5) * 5
            return timestamp.replace(minute=minute, second=0, microsecond=0)
        elif period == timedelta(days=1):
            return timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            # For custom periods, use floor division
            epoch = datetime(1970, 1, 1)
            seconds_since_epoch = (timestamp - epoch).total_seconds()
            period_seconds = period.total_seconds()
            period_number = int(seconds_since_epoch // period_seconds)
            return epoch + timedelta(seconds=period_number * period_seconds)

class MetricsCollector:
    """
    Comprehensive metrics collection system for AODS monitoring.
    
    Provides automated metrics collection, storage, aggregation,
    and querying capabilities for monitoring and analytics.
    """
    
    def __init__(self, storage_path: str = "metrics.db",
                 collection_interval: float = 30.0,
                 retention_days: int = 30):
        """
        Initialize metrics collector.
        
        Args:
            storage_path: Path to metrics database
            collection_interval: Default collection interval in seconds
            retention_days: Number of days to retain metrics
        """
        self.collection_interval = collection_interval
        self.retention_days = retention_days
        self.logger = ContextualLogger("metrics_collector")
        
        # State management
        self.collecting_active = False
        self.collector_thread: Optional[threading.Thread] = None
        self._shutdown_event = threading.Event()
        
        # Storage and aggregation
        self.storage = MetricsStorage(storage_path)
        self.aggregator = MetricsAggregator(self.storage)
        
        # Metric definitions
        self.metric_definitions: Dict[str, MetricDefinition] = {}
        
        # In-memory metrics for fast access
        self.current_metrics: Dict[str, MetricDataPoint] = {}
        self.metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Callbacks
        self.collection_callbacks: List[Callable[[MetricDataPoint], None]] = []
        
        # Thread pool for parallel collection
        self.collection_executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
        
        # Metrics about metrics
        self.collector_metrics = {
            'metrics_collected': 0,
            'collection_errors': 0,
            'storage_errors': 0,
            'last_collection_time': None,
            'collection_duration_ms': 0
        }
        
        # Initialize default metrics
        self._register_default_metrics()
    
    def start_collection(self) -> None:
        """Start metrics collection."""
        if self.collecting_active:
            self.logger.warning("Metrics collection already active")
            return
        
        self.collecting_active = True
        self._shutdown_event.clear()
        
        self.collector_thread = threading.Thread(
            target=self._collection_loop,
            name="MetricsCollector",
            daemon=True
        )
        self.collector_thread.start()
        
        self.logger.info(f"Started metrics collection (interval: {self.collection_interval}s)")
    
    def stop_collection(self) -> None:
        """Stop metrics collection."""
        if not self.collecting_active:
            return
        
        self.collecting_active = False
        self._shutdown_event.set()
        
        if self.collector_thread and self.collector_thread.is_alive():
            self.collector_thread.join(timeout=10.0)
        
        self.collection_executor.shutdown(wait=True)
        
        self.logger.info("Stopped metrics collection")
    
    def register_metric(self, metric_def: MetricDefinition) -> None:
        """Register a new metric for collection."""
        self.metric_definitions[metric_def.name] = metric_def
        self.logger.info(f"Registered metric: {metric_def.name}")
    
    def unregister_metric(self, metric_name: str) -> None:
        """Unregister a metric."""
        if metric_name in self.metric_definitions:
            del self.metric_definitions[metric_name]
            self.logger.info(f"Unregistered metric: {metric_name}")
    
    def record_metric(self, metric_name: str, value: Union[float, int, Dict],
                     labels: Optional[Dict[str, str]] = None,
                     metadata: Optional[Dict[str, Any]] = None) -> None:
        """Record a metric value immediately."""
        try:
            # Get metric definition
            metric_def = self.metric_definitions.get(metric_name)
            if not metric_def:
                # Create a basic metric definition
                metric_def = MetricDefinition(
                    name=metric_name,
                    metric_type=MetricType.GAUGE
                )
            
            # Create metric data point
            metric = MetricDataPoint(
                metric_name=metric_name,
                metric_type=metric_def.metric_type,
                value=value,
                timestamp=datetime.now(),
                labels={**metric_def.labels, **(labels or {})},
                metadata=metadata or {}
            )
            
            # Store in memory
            self.current_metrics[metric_name] = metric
            self.metrics_history[metric_name].append(metric)
            
            # Store persistently
            self.storage.store_metric(metric)
            
            # Update collector metrics
            self.collector_metrics['metrics_collected'] += 1
            
            # Notify callbacks
            for callback in self.collection_callbacks:
                try:
                    callback(metric)
                except Exception as e:
                    self.logger.error(f"Collection callback error: {e}")
            
        except Exception as e:
            self.logger.error(f"Failed to record metric {metric_name}: {e}")
            self.collector_metrics['collection_errors'] += 1
    
    def collect_current_metrics(self) -> MetricsSnapshot:
        """Collect all current metrics into a snapshot."""
        timestamp = datetime.now()
        snapshot_id = f"snapshot_{int(timestamp.timestamp() * 1000)}"
        
        snapshot = MetricsSnapshot(
            timestamp=timestamp,
            metrics=self.current_metrics.copy(),
            source="metrics_collector",
            snapshot_id=snapshot_id
        )
        
        # Store snapshot
        self.storage.store_snapshot(snapshot)
        
        return snapshot
    
    def query_metrics(self, metric_name: Optional[str] = None,
                     start_time: Optional[datetime] = None,
                     end_time: Optional[datetime] = None,
                     labels: Optional[Dict[str, str]] = None,
                     limit: int = 1000) -> List[MetricDataPoint]:
        """Query metrics from storage."""
        return self.storage.query_metrics(metric_name, start_time, end_time, labels, limit)
    
    def get_metric_statistics(self, metric_name: str,
                            duration_hours: int = 24) -> Dict[str, Any]:
        """Get statistics for a specific metric."""
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=duration_hours)
        
        metrics = self.query_metrics(metric_name, start_time, end_time)
        
        if not metrics:
            return {"error": "No data available for specified metric and time range"}
        
        # Extract numeric values
        values = []
        for metric in metrics:
            if isinstance(metric.value, (int, float)):
                values.append(float(metric.value))
            elif isinstance(metric.value, dict) and 'value' in metric.value:
                values.append(float(metric.value['value']))
        
        if not values:
            return {"error": "No numeric values found for metric"}
        
        return {
            "metric_name": metric_name,
            "duration_hours": duration_hours,
            "sample_count": len(values),
            "average": statistics.mean(values),
            "minimum": min(values),
            "maximum": max(values),
            "median": statistics.median(values),
            "standard_deviation": statistics.stdev(values) if len(values) > 1 else 0,
            "latest_value": values[0] if metrics else None,
            "latest_timestamp": metrics[0].timestamp.isoformat() if metrics else None
        }
    
    def register_collection_callback(self, callback: Callable[[MetricDataPoint], None]) -> None:
        """Register callback for metric collection events."""
        self.collection_callbacks.append(callback)
    
    def get_collector_status(self) -> Dict[str, Any]:
        """Get collector status and metrics."""
        return {
            "collecting_active": self.collecting_active,
            "registered_metrics": len(self.metric_definitions),
            "current_metrics": len(self.current_metrics),
            "collection_interval": self.collection_interval,
            "retention_days": self.retention_days,
            "collector_metrics": self.collector_metrics
        }
    
    def _register_default_metrics(self) -> None:
        """Register default system metrics."""
        import psutil
        
        # CPU usage metric
        self.register_metric(MetricDefinition(
            name="system.cpu.usage_percent",
            metric_type=MetricType.GAUGE,
            description="System CPU usage percentage",
            unit="percent",
            collection_function=lambda: psutil.cpu_percent(interval=1.0),
            collection_interval=30.0
        ))
        
        # Memory usage metric
        self.register_metric(MetricDefinition(
            name="system.memory.usage_percent",
            metric_type=MetricType.GAUGE,
            description="System memory usage percentage",
            unit="percent",
            collection_function=lambda: psutil.virtual_memory().percent,
            collection_interval=30.0
        ))
        
        # Disk usage metric
        self.register_metric(MetricDefinition(
            name="system.disk.usage_percent",
            metric_type=MetricType.GAUGE,
            description="System disk usage percentage",
            unit="percent",
            collection_function=lambda: psutil.disk_usage('/').percent,
            collection_interval=60.0
        ))
        
        # Process count metric
        self.register_metric(MetricDefinition(
            name="system.processes.count",
            metric_type=MetricType.GAUGE,
            description="Number of running processes",
            unit="count",
            collection_function=lambda: len(psutil.pids()),
            collection_interval=60.0
        ))
    
    def _collection_loop(self) -> None:
        """Main metrics collection loop."""
        while self.collecting_active and not self._shutdown_event.is_set():
            try:
                collection_start = time.time()
                
                # Collect metrics with automatic functions
                futures = []
                for metric_def in self.metric_definitions.values():
                    if metric_def.enabled and metric_def.collection_function:
                        current_time = datetime.now()
                        
                        # Check if it's time to collect this metric
                        if metric_def.next_collection is None:
                            metric_def.next_collection = current_time + timedelta(seconds=metric_def.collection_interval)
                        
                        if current_time >= metric_def.next_collection:
                            # Submit collection task
                            future = self.collection_executor.submit(
                                self._collect_metric,
                                metric_def
                            )
                            futures.append(future)
                            
                            # Schedule next collection
                            metric_def.last_collection = current_time
                            metric_def.next_collection = current_time + timedelta(seconds=metric_def.collection_interval)
                
                # Wait for collection tasks to complete
                for future in concurrent.futures.as_completed(futures, timeout=self.collection_interval):
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.error(f"Metric collection task failed: {e}")
                
                # Periodic cleanup
                if int(time.time()) % 3600 == 0:  # Every hour
                    self.storage.cleanup_old_metrics(self.retention_days)
                
                # Update collection metrics
                collection_duration = (time.time() - collection_start) * 1000
                self.collector_metrics['collection_duration_ms'] = collection_duration
                self.collector_metrics['last_collection_time'] = datetime.now().isoformat()
                
                # Sleep until next collection
                self._shutdown_event.wait(timeout=max(1.0, self.collection_interval - (time.time() - collection_start)))
                
            except Exception as e:
                self.logger.error(f"Metrics collection loop error: {e}")
                self._shutdown_event.wait(timeout=30.0)
    
    def _collect_metric(self, metric_def: MetricDefinition) -> None:
        """Collect a single metric."""
        try:
            if metric_def.collection_function:
                value = metric_def.collection_function()
                self.record_metric(
                    metric_name=metric_def.name,
                    value=value,
                    labels=metric_def.labels.copy()
                )
        except Exception as e:
            self.logger.error(f"Failed to collect metric {metric_def.name}: {e}")
            self.collector_metrics['collection_errors'] += 1

# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None

def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector instance."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector 