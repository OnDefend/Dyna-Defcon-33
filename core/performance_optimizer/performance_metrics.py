#!/usr/bin/env python3
"""
Performance Optimizer - Performance Metrics

performance monitoring and metrics collection with
intelligent analysis and optimization recommendations.
"""

import logging
import time
import psutil
import functools
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass

from .data_structures import PerformanceMetrics

class PerformanceTracker:
    """
    performance tracking system for enterprise vulnerability analysis
    
    Features:
    - Comprehensive performance metrics collection
    - Real-time performance monitoring
    - Intelligent performance analysis and recommendations
    - logging without decorative elements
    - Historical performance trending
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.metrics_history: List[PerformanceMetrics] = []
        self._operation_baselines: Dict[str, Dict[str, float]] = {}
        
        self.logger.info("Performance tracker initialized")
    
    def record_metrics(self, metrics: PerformanceMetrics):
        """Record performance metrics for analysis."""
        self.metrics_history.append(metrics)
        
        # Update operation baseline
        self._update_baseline(metrics)
        
        # Keep only recent history (last 1000 operations)
        if len(self.metrics_history) > 1000:
            self.metrics_history = self.metrics_history[-1000:]
        
        self.logger.debug(f"Recorded metrics for {metrics.operation_name}: {metrics.duration_ms:.1f}ms")
    
    def _update_baseline(self, metrics: PerformanceMetrics):
        """Update performance baseline for operation type."""
        operation_name = metrics.operation_name
        
        if operation_name not in self._operation_baselines:
            self._operation_baselines[operation_name] = {
                'avg_duration_ms': metrics.duration_ms,
                'avg_memory_mb': metrics.memory_usage_mb,
                'avg_cpu_percent': metrics.cpu_usage_percent,
                'operation_count': 1
            }
        else:
            baseline = self._operation_baselines[operation_name]
            count = baseline['operation_count']
            
            # Calculate running averages
            baseline['avg_duration_ms'] = (baseline['avg_duration_ms'] * count + metrics.duration_ms) / (count + 1)
            baseline['avg_memory_mb'] = (baseline['avg_memory_mb'] * count + metrics.memory_usage_mb) / (count + 1)
            baseline['avg_cpu_percent'] = (baseline['avg_cpu_percent'] * count + metrics.cpu_usage_percent) / (count + 1)
            baseline['operation_count'] = count + 1
    
    def get_performance_analysis(self, operation_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get comprehensive performance analysis.
        """
        if operation_name:
            relevant_metrics = [m for m in self.metrics_history if m.operation_name == operation_name]
        else:
            relevant_metrics = self.metrics_history
        
        if not relevant_metrics:
            return {'error': f'No metrics found for operation: {operation_name}'}
        
        # Calculate statistics
        durations = [m.duration_ms for m in relevant_metrics]
        memory_usage = [m.memory_usage_mb for m in relevant_metrics]
        cpu_usage = [m.cpu_usage_percent for m in relevant_metrics]
        cache_hit_rates = [m.cache_hit_rate for m in relevant_metrics]
        
        analysis = {
            'operation_name': operation_name or 'all_operations',
            'total_operations': len(relevant_metrics),
            'duration_stats': {
                'average_ms': sum(durations) / len(durations),
                'min_ms': min(durations),
                'max_ms': max(durations),
                'median_ms': sorted(durations)[len(durations) // 2]
            },
            'memory_stats': {
                'average_mb': sum(memory_usage) / len(memory_usage),
                'peak_mb': max(memory_usage),
                'min_mb': min(memory_usage)
            },
            'cpu_stats': {
                'average_percent': sum(cpu_usage) / len(cpu_usage),
                'peak_percent': max(cpu_usage),
                'min_percent': min(cpu_usage)
            },
            'cache_stats': {
                'average_hit_rate': sum(cache_hit_rates) / len(cache_hit_rates),
                'best_hit_rate': max(cache_hit_rates),
                'worst_hit_rate': min(cache_hit_rates)
            }
        }
        
        # Add performance trends
        if len(relevant_metrics) > 10:
            analysis['trends'] = self._calculate_trends(relevant_metrics)
        
        # Add optimization recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _calculate_trends(self, metrics: List[PerformanceMetrics]) -> Dict[str, str]:
        """Calculate performance trends."""
        if len(metrics) < 10:
            return {}
        
        # Split into first and second half for comparison
        mid_point = len(metrics) // 2
        first_half = metrics[:mid_point]
        second_half = metrics[mid_point:]
        
        # Calculate averages for each half
        first_avg_duration = sum(m.duration_ms for m in first_half) / len(first_half)
        second_avg_duration = sum(m.duration_ms for m in second_half) / len(second_half)
        
        first_avg_memory = sum(m.memory_usage_mb for m in first_half) / len(first_half)
        second_avg_memory = sum(m.memory_usage_mb for m in second_half) / len(second_half)
        
        # Determine trends
        duration_trend = 'improving' if second_avg_duration < first_avg_duration else 'degrading'
        memory_trend = 'improving' if second_avg_memory < first_avg_memory else 'degrading'
        
        return {
            'duration_trend': duration_trend,
            'memory_trend': memory_trend,
            'duration_change_percent': ((second_avg_duration - first_avg_duration) / first_avg_duration) * 100,
            'memory_change_percent': ((second_avg_memory - first_avg_memory) / first_avg_memory) * 100
        }
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate optimization recommendations based on analysis."""
        recommendations = []
        
        # Duration recommendations
        if analysis['duration_stats']['average_ms'] > 10000:  # 10 seconds
            recommendations.append("Consider enabling parallel processing to reduce operation duration")
        
        # Memory recommendations
        if analysis['memory_stats']['average_mb'] > 500:
            recommendations.append("High memory usage detected - consider enabling memory optimization")
        
        # Cache recommendations
        if analysis['cache_stats']['average_hit_rate'] < 50:
            recommendations.append("Low cache hit rate - consider increasing cache size or adjusting cache strategy")
        
        # CPU recommendations
        if analysis['cpu_stats']['average_percent'] > 80:
            recommendations.append("High CPU usage - consider reducing parallel workers or optimization level")
        
        # Trend-based recommendations
        trends = analysis.get('trends', {})
        if trends.get('duration_trend') == 'degrading':
            recommendations.append("Performance degradation detected - consider system cleanup or optimization")
        
        return recommendations

# Global performance tracker instance
_performance_tracker = PerformanceTracker()

def performance_monitor(func: Callable) -> Callable:
    """
    performance monitoring decorator without decorative elements.
    
    Monitors function execution time, memory usage, and system resources
    to provide comprehensive performance metrics.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Record start state
        start_time = time.time()
        process = psutil.Process()
        start_memory = process.memory_info().rss / (1024 * 1024)  # MB
        start_cpu = process.cpu_percent()
        
        try:
            # Execute function
            result = func(*args, **kwargs)
            
            # Record end state
            end_time = time.time()
            end_memory = process.memory_info().rss / (1024 * 1024)  # MB
            end_cpu = process.cpu_percent()
            
            # Calculate metrics
            duration_ms = (end_time - start_time) * 1000
            memory_usage_mb = max(start_memory, end_memory)
            cpu_usage_percent = max(start_cpu, end_cpu)
            
            # Create performance metrics
            metrics = PerformanceMetrics(
                operation_name=func.__name__,
                start_time=start_time,
                end_time=end_time,
                duration_ms=duration_ms,
                memory_usage_mb=memory_usage_mb,
                cpu_usage_percent=cpu_usage_percent,
                cache_hit_rate=0.0,  # Will be updated by cache system if applicable
                parallel_workers=1,   # Will be updated by parallel system if applicable
                optimization_applied=[]
            )
            
            # Record metrics
            _performance_tracker.record_metrics(metrics)
            
            # Add metrics to result if it's a dictionary
            if isinstance(result, dict):
                result['performance_metrics'] = metrics.__dict__
            
            return result
            
        except Exception as e:
            # Record failure metrics
            end_time = time.time()
            duration_ms = (end_time - start_time) * 1000
            
            metrics = PerformanceMetrics(
                operation_name=func.__name__,
                start_time=start_time,
                end_time=end_time,
                duration_ms=duration_ms,
                memory_usage_mb=start_memory,
                cpu_usage_percent=start_cpu,
                cache_hit_rate=0.0,
                parallel_workers=1,
                optimization_applied=['error_occurred']
            )
            
            _performance_tracker.record_metrics(metrics)
            raise
    
    return wrapper

def get_performance_tracker() -> PerformanceTracker:
    """Get the global performance tracker instance."""
    return _performance_tracker

def reset_performance_tracker():
    """Reset the global performance tracker."""
    global _performance_tracker
    _performance_tracker = PerformanceTracker() 