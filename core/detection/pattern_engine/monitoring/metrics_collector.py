#!/usr/bin/env python3
"""
Metrics Collection and Monitoring

Comprehensive metrics collection system for pattern engine monitoring,
performance tracking, and operational health assessment.
"""

import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
import json
import logging

from ..models import VulnerabilityPattern, PatternMatch

@dataclass
class PatternEffectivenessMetrics:
    """Metrics for pattern effectiveness tracking."""
    
    pattern_id: str
    total_matches: int = 0
    true_positives: int = 0
    false_positives: int = 0
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    confidence_distribution: Dict[str, int] = field(default_factory=dict)
    performance_score: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)

@dataclass
class SourcePerformanceMetrics:
    """Metrics for pattern source performance."""
    
    source_id: str
    patterns_loaded: int = 0
    loading_time_seconds: float = 0.0
    error_count: int = 0
    success_rate: float = 0.0
    average_pattern_quality: float = 0.0
    memory_usage_mb: float = 0.0
    last_load_time: Optional[datetime] = None

@dataclass
class EngineOperationalMetrics:
    """Overall engine operational metrics."""
    
    uptime_seconds: float = 0.0
    total_patterns_processed: int = 0
    total_matches_found: int = 0
    average_processing_time_ms: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    error_rate: float = 0.0
    cache_hit_rate: float = 0.0

class MetricsCollector:
    """
    Comprehensive metrics collection system.
    
    Collects, aggregates, and provides access to various performance
    and effectiveness metrics for the pattern engine.
    """
    
    def __init__(self, retention_days: int = 7, collection_interval_seconds: int = 60):
        """
        Initialize metrics collector.
        
        Args:
            retention_days: How long to retain historical metrics
            collection_interval_seconds: How often to collect metrics
        """
        self.retention_days = retention_days
        self.collection_interval = collection_interval_seconds
        self.logger = logging.getLogger(__name__)
        
        # Metrics storage
        self._pattern_metrics: Dict[str, PatternEffectivenessMetrics] = {}
        self._source_metrics: Dict[str, SourcePerformanceMetrics] = {}
        self._engine_metrics: EngineOperationalMetrics = EngineOperationalMetrics()
        
        # Historical data (time-series)
        self._historical_metrics: deque = deque(maxlen=retention_days * 24 * 60)  # 1 minute resolution
        
        # Real-time tracking
        self._start_time = datetime.now()
        self._processing_times: deque = deque(maxlen=1000)  # Last 1000 operations
        self._error_counts: Dict[str, int] = defaultdict(int)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Background collection
        self._collection_thread: Optional[threading.Thread] = None
        self._stop_collection = threading.Event()
    
    def start_collection(self):
        """Start background metrics collection."""
        if self._collection_thread is None or not self._collection_thread.is_alive():
            self._stop_collection.clear()
            self._collection_thread = threading.Thread(target=self._collection_loop, daemon=True)
            self._collection_thread.start()
            self.logger.info("Started metrics collection")
    
    def stop_collection(self):
        """Stop background metrics collection."""
        if self._collection_thread and self._collection_thread.is_alive():
            self._stop_collection.set()
            self._collection_thread.join(timeout=5.0)
            self.logger.info("Stopped metrics collection")
    
    def _collection_loop(self):
        """Background metrics collection loop."""
        while not self._stop_collection.wait(self.collection_interval):
            try:
                self._collect_snapshot()
            except Exception as e:
                self.logger.error(f"Metrics collection error: {e}")
    
    def _collect_snapshot(self):
        """Collect a metrics snapshot."""
        with self._lock:
            snapshot = {
                "timestamp": datetime.now().isoformat(),
                "engine_metrics": self._engine_metrics.__dict__.copy(),
                "pattern_count": len(self._pattern_metrics),
                "source_count": len(self._source_metrics),
                "total_errors": sum(self._error_counts.values())
            }
            
            self._historical_metrics.append(snapshot)
            
            # Clean up old metrics
            self._cleanup_old_metrics()
    
    def _cleanup_old_metrics(self):
        """Clean up metrics older than retention period."""
        cutoff_time = datetime.now() - timedelta(days=self.retention_days)
        
        # Clean up pattern metrics
        old_patterns = [
            pattern_id for pattern_id, metrics in self._pattern_metrics.items()
            if metrics.last_updated < cutoff_time
        ]
        
        for pattern_id in old_patterns:
            del self._pattern_metrics[pattern_id]
    
    def record_pattern_match(self, pattern_id: str, match: PatternMatch, is_true_positive: bool):
        """
        Record a pattern match for effectiveness tracking.
        
        Args:
            pattern_id: ID of the pattern that matched
            match: Match details
            is_true_positive: Whether this is a true positive
        """
        with self._lock:
            if pattern_id not in self._pattern_metrics:
                self._pattern_metrics[pattern_id] = PatternEffectivenessMetrics(pattern_id=pattern_id)
            
            metrics = self._pattern_metrics[pattern_id]
            metrics.total_matches += 1
            
            if is_true_positive:
                metrics.true_positives += 1
            else:
                metrics.false_positives += 1
            
            # Update rates
            if metrics.total_matches > 0:
                metrics.detection_rate = metrics.true_positives / metrics.total_matches
                metrics.false_positive_rate = metrics.false_positives / metrics.total_matches
            
            # Update confidence distribution
            confidence_bucket = self._get_confidence_bucket(match.confidence_score)
            metrics.confidence_distribution[confidence_bucket] = metrics.confidence_distribution.get(confidence_bucket, 0) + 1
            
            # Calculate performance score
            metrics.performance_score = self._calculate_performance_score(metrics)
            metrics.last_updated = datetime.now()
    
    def _get_confidence_bucket(self, confidence: float) -> str:
        """Get confidence bucket for distribution tracking."""
        if confidence >= 0.9:
            return "very_high"
        elif confidence >= 0.7:
            return "high"
        elif confidence >= 0.5:
            return "medium"
        elif confidence >= 0.3:
            return "low"
        else:
            return "very_low"
    
    def _calculate_performance_score(self, metrics: PatternEffectivenessMetrics) -> float:
        """Calculate overall performance score for a pattern."""
        if metrics.total_matches == 0:
            return 0.0
        
        # Weighted score based on detection rate and false positive rate
        detection_weight = 0.7
        fp_weight = 0.3
        
        detection_score = metrics.detection_rate
        fp_penalty = metrics.false_positive_rate
        
        return max(0.0, (detection_score * detection_weight) - (fp_penalty * fp_weight))
    
    def record_source_performance(self, source_id: str, patterns_loaded: int, loading_time: float, 
                                 error_count: int = 0, memory_usage: float = 0.0):
        """
        Record pattern source performance metrics.
        
        Args:
            source_id: Source identifier
            patterns_loaded: Number of patterns loaded
            loading_time: Time taken to load patterns
            error_count: Number of errors encountered
            memory_usage: Memory usage in MB
        """
        with self._lock:
            if source_id not in self._source_metrics:
                self._source_metrics[source_id] = SourcePerformanceMetrics(source_id=source_id)
            
            metrics = self._source_metrics[source_id]
            metrics.patterns_loaded = patterns_loaded
            metrics.loading_time_seconds = loading_time
            metrics.error_count += error_count
            metrics.memory_usage_mb = memory_usage
            metrics.last_load_time = datetime.now()
            
            # Calculate success rate
            total_attempts = getattr(metrics, 'total_attempts', 0) + 1
            setattr(metrics, 'total_attempts', total_attempts)
            
            if total_attempts > 0:
                success_attempts = total_attempts - metrics.error_count
                metrics.success_rate = max(0.0, success_attempts / total_attempts)
    
    def record_processing_time(self, processing_time_ms: float):
        """Record processing time for performance tracking."""
        with self._lock:
            self._processing_times.append(processing_time_ms)
            
            # Update engine metrics
            if self._processing_times:
                self._engine_metrics.average_processing_time_ms = sum(self._processing_times) / len(self._processing_times)
    
    def record_error(self, error_type: str, error_details: str):
        """
        Record error for error rate tracking.
        
        Args:
            error_type: Type/category of error
            error_details: Error details for logging
        """
        with self._lock:
            self._error_counts[error_type] += 1
            
            # Update error rate
            total_operations = getattr(self._engine_metrics, 'total_operations', 0) + 1
            setattr(self._engine_metrics, 'total_operations', total_operations)
            
            total_errors = sum(self._error_counts.values())
            if total_operations > 0:
                self._engine_metrics.error_rate = total_errors / total_operations
            
            self.logger.warning(f"Error recorded - Type: {error_type}, Details: {error_details}")
    
    def update_engine_metrics(self, **kwargs):
        """Update engine operational metrics."""
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self._engine_metrics, key):
                    setattr(self._engine_metrics, key, value)
            
            # Update uptime
            self._engine_metrics.uptime_seconds = (datetime.now() - self._start_time).total_seconds()
    
    def get_pattern_effectiveness_report(self, top_n: int = 10) -> Dict[str, Any]:
        """
        Get pattern effectiveness report.
        
        Args:
            top_n: Number of top/bottom patterns to include
            
        Returns:
            Effectiveness report
        """
        with self._lock:
            if not self._pattern_metrics:
                return {"message": "No pattern metrics available"}
            
            # Sort patterns by performance score
            sorted_patterns = sorted(
                self._pattern_metrics.values(),
                key=lambda x: x.performance_score,
                reverse=True
            )
            
            return {
                "total_patterns_tracked": len(self._pattern_metrics),
                "top_performing_patterns": [
                    {
                        "pattern_id": p.pattern_id,
                        "performance_score": p.performance_score,
                        "detection_rate": p.detection_rate,
                        "false_positive_rate": p.false_positive_rate,
                        "total_matches": p.total_matches
                    }
                    for p in sorted_patterns[:top_n]
                ],
                "bottom_performing_patterns": [
                    {
                        "pattern_id": p.pattern_id,
                        "performance_score": p.performance_score,
                        "detection_rate": p.detection_rate,
                        "false_positive_rate": p.false_positive_rate,
                        "total_matches": p.total_matches
                    }
                    for p in sorted_patterns[-top_n:]
                ],
                "overall_statistics": {
                    "average_performance_score": sum(p.performance_score for p in sorted_patterns) / len(sorted_patterns),
                    "average_detection_rate": sum(p.detection_rate for p in sorted_patterns) / len(sorted_patterns),
                    "average_false_positive_rate": sum(p.false_positive_rate for p in sorted_patterns) / len(sorted_patterns),
                    "total_matches": sum(p.total_matches for p in sorted_patterns)
                }
            }
    
    def get_source_performance_report(self) -> Dict[str, Any]:
        """Get source performance report."""
        with self._lock:
            if not self._source_metrics:
                return {"message": "No source metrics available"}
            
            return {
                "sources": {
                    source_id: {
                        "patterns_loaded": metrics.patterns_loaded,
                        "loading_time_seconds": metrics.loading_time_seconds,
                        "success_rate": metrics.success_rate,
                        "error_count": metrics.error_count,
                        "memory_usage_mb": metrics.memory_usage_mb,
                        "patterns_per_second": metrics.patterns_loaded / metrics.loading_time_seconds if metrics.loading_time_seconds > 0 else 0,
                        "last_load_time": metrics.last_load_time.isoformat() if metrics.last_load_time else None
                    }
                    for source_id, metrics in self._source_metrics.items()
                },
                "summary": {
                    "total_sources": len(self._source_metrics),
                    "total_patterns_loaded": sum(m.patterns_loaded for m in self._source_metrics.values()),
                    "average_success_rate": sum(m.success_rate for m in self._source_metrics.values()) / len(self._source_metrics),
                    "total_memory_usage_mb": sum(m.memory_usage_mb for m in self._source_metrics.values())
                }
            }
    
    def get_engine_health_report(self) -> Dict[str, Any]:
        """Get comprehensive engine health report."""
        with self._lock:
            # Calculate health score
            health_score = self._calculate_health_score()
            
            return {
                "health_score": health_score,
                "health_status": self._get_health_status(health_score),
                "operational_metrics": {
                    "uptime_hours": self._engine_metrics.uptime_seconds / 3600,
                    "total_patterns_processed": self._engine_metrics.total_patterns_processed,
                    "total_matches_found": self._engine_metrics.total_matches_found,
                    "average_processing_time_ms": self._engine_metrics.average_processing_time_ms,
                    "error_rate": self._engine_metrics.error_rate,
                    "cache_hit_rate": self._engine_metrics.cache_hit_rate
                },
                "resource_usage": {
                    "memory_usage_mb": self._engine_metrics.memory_usage_mb,
                    "cpu_usage_percent": self._engine_metrics.cpu_usage_percent
                },
                "recent_errors": dict(self._error_counts),
                "recommendations": self._generate_health_recommendations(health_score)
            }
    
    def _calculate_health_score(self) -> float:
        """Calculate overall health score (0-100)."""
        scores = []
        
        # Error rate score (lower is better)
        error_score = max(0, 100 - (self._engine_metrics.error_rate * 100))
        scores.append(error_score)
        
        # Cache hit rate score
        cache_score = self._engine_metrics.cache_hit_rate * 100
        scores.append(cache_score)
        
        # Processing time score (faster is better)
        if self._engine_metrics.average_processing_time_ms > 0:
            # Assume 100ms is baseline, anything faster gets higher score
            time_score = max(0, 100 - (self._engine_metrics.average_processing_time_ms / 10))
            scores.append(min(100, time_score))
        
        # Source success rate score
        if self._source_metrics:
            avg_success_rate = sum(m.success_rate for m in self._source_metrics.values()) / len(self._source_metrics)
            scores.append(avg_success_rate * 100)
        
        return sum(scores) / len(scores) if scores else 0.0
    
    def _get_health_status(self, health_score: float) -> str:
        """Get health status string based on score."""
        if health_score >= 90:
            return "EXCELLENT"
        elif health_score >= 75:
            return "GOOD"
        elif health_score >= 60:
            return "FAIR"
        elif health_score >= 40:
            return "POOR"
        else:
            return "CRITICAL"
    
    def _generate_health_recommendations(self, health_score: float) -> List[str]:
        """Generate health improvement recommendations."""
        recommendations = []
        
        if self._engine_metrics.error_rate > 0.05:  # > 5% error rate
            recommendations.append("High error rate detected - investigate error sources")
        
        if self._engine_metrics.cache_hit_rate < 0.7:  # < 70% cache hit rate
            recommendations.append("Low cache hit rate - consider increasing cache size")
        
        if self._engine_metrics.average_processing_time_ms > 1000:  # > 1 second
            recommendations.append("High processing time - optimize pattern matching or consider performance tuning")
        
        if health_score < 70:
            recommendations.append("Overall health is below optimal - review system configuration")
        
        if not recommendations:
            recommendations.append("System health is optimal")
        
        return recommendations
    
    def export_metrics(self, format_type: str = "json") -> str:
        """
        Export metrics in specified format.
        
        Args:
            format_type: Export format ('json', 'csv')
            
        Returns:
            Formatted metrics data
        """
        with self._lock:
            data = {
                "export_timestamp": datetime.now().isoformat(),
                "pattern_metrics": {pid: m.__dict__ for pid, m in self._pattern_metrics.items()},
                "source_metrics": {sid: m.__dict__ for sid, m in self._source_metrics.items()},
                "engine_metrics": self._engine_metrics.__dict__,
                "historical_data": list(self._historical_metrics)
            }
            
            if format_type.lower() == "json":
                return json.dumps(data, indent=2, default=str)
            else:
                raise ValueError(f"Unsupported export format: {format_type}")

# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None

def get_metrics_collector() -> MetricsCollector:
    """Get or create global metrics collector."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
        _metrics_collector.start_collection()
    return _metrics_collector 