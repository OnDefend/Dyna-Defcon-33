#!/usr/bin/env python3
"""
Enterprise Performance Integration - Metrics Calculator

Performance measurement and tracking with evidence-based
calculation and comprehensive metric aggregation.
"""

import time
import logging
import psutil
from typing import Dict, List, Any, Optional

from .data_structures import IntegratedPerformanceMetrics, OptimizationStrategy


class MetricsCalculator:
    """
    Metrics calculator that provides evidence-based performance
    measurement and comprehensive tracking of optimization effectiveness.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._peak_memory_tracker = 0.0
    
    def calculate_integrated_metrics(self, analysis_start_time: float, analysis_end_time: float,
                                   initial_memory: float, final_memory: float,
                                   original_findings: int, optimization_result: Dict[str, Any],
                                   apk_size_mb: float, strategy: OptimizationStrategy) -> IntegratedPerformanceMetrics:
        """
        Calculate comprehensive integrated performance metrics with evidence-based scoring.
        """
        total_duration = analysis_end_time - analysis_start_time
        
        # Extract results from optimization
        final_findings = optimization_result.get('total_findings', original_findings)
        
        # Calculate reduction percentage
        reduction_percentage = self._calculate_reduction_percentage(original_findings, final_findings)
        
        # Calculate memory metrics
        peak_memory = max(self._peak_memory_tracker, initial_memory, final_memory)
        memory_efficiency = self._calculate_memory_efficiency(initial_memory, peak_memory, final_memory)
        
        # Extract cache metrics
        cache_metrics = optimization_result.get('cache_metrics', {})
        cache_hits = cache_metrics.get('hits', 0)
        cache_misses = cache_metrics.get('misses', 0)
        cache_hit_rate = self._calculate_cache_hit_rate(cache_hits, cache_misses)
        
        # Extract parallel processing metrics
        parallel_metrics = optimization_result.get('parallel_metrics', {})
        parallel_workers = parallel_metrics.get('workers_used', 1)
        parallel_efficiency = parallel_metrics.get('efficiency_percent', 100.0)
        sequential_estimate = parallel_metrics.get('sequential_time_estimate', total_duration)
        speedup_factor = self._calculate_speedup_factor(sequential_estimate, total_duration)
        
        # Calculate complexity score
        complexity_score = self._calculate_complexity_score(apk_size_mb, original_findings)
        
        return IntegratedPerformanceMetrics(
            analysis_start_time=analysis_start_time,
            analysis_end_time=analysis_end_time,
            total_duration_seconds=total_duration,
            
            initial_memory_mb=initial_memory,
            peak_memory_mb=peak_memory,
            final_memory_mb=final_memory,
            memory_efficiency_percent=memory_efficiency,
            
            findings_processed=original_findings,
            findings_filtered=final_findings,
            reduction_percentage=reduction_percentage,
            
            cache_hits=cache_hits,
            cache_misses=cache_misses,
            cache_hit_rate_percent=cache_hit_rate,
            
            parallel_workers_used=parallel_workers,
            parallel_efficiency_percent=parallel_efficiency,
            sequential_time_estimate=sequential_estimate,
            parallel_speedup_factor=speedup_factor,
            
            apk_size_mb=apk_size_mb,
            complexity_score=complexity_score,
            optimization_strategy=strategy.value,
            batch_processing_enabled=optimization_result.get('batch_processing', False)
        )
    
    def _calculate_reduction_percentage(self, original_count: int, final_count: int) -> float:
        """Calculate the percentage reduction in findings."""
        if original_count == 0:
            return 0.0
        
        reduction = max(0, original_count - final_count)
        return (reduction / original_count) * 100.0
    
    def _calculate_memory_efficiency(self, initial_mb: float, peak_mb: float, final_mb: float) -> float:
        """
        Calculate memory efficiency as a percentage.
        Higher efficiency means lower peak memory usage relative to processing requirements.
        """
        if peak_mb <= initial_mb:
            return 100.0  # Perfect efficiency - no additional memory used
        
        # Calculate efficiency based on memory usage patterns
        memory_growth = peak_mb - initial_mb
        memory_cleanup = max(0, peak_mb - final_mb)
        
        # Efficiency factors
        growth_efficiency = max(0, 100 - (memory_growth / initial_mb * 100)) if initial_mb > 0 else 0
        cleanup_efficiency = (memory_cleanup / memory_growth * 100) if memory_growth > 0 else 100
        
        # Combined efficiency score
        efficiency = (growth_efficiency * 0.6 + cleanup_efficiency * 0.4)
        return max(0, min(100, efficiency))
    
    def _calculate_cache_hit_rate(self, hits: int, misses: int) -> float:
        """Calculate cache hit rate as a percentage."""
        total_requests = hits + misses
        if total_requests == 0:
            return 0.0
        
        return (hits / total_requests) * 100.0
    
    def _calculate_speedup_factor(self, sequential_time: float, parallel_time: float) -> float:
        """Calculate the speedup factor from parallel processing."""
        if parallel_time <= 0:
            return 1.0
        
        return max(1.0, sequential_time / parallel_time)
    
    def _calculate_complexity_score(self, apk_size_mb: float, findings_count: int) -> int:
        """
        Calculate a complexity score for the analysis based on APK characteristics.
        Score ranges from 0-100, with higher scores indicating more complex analysis.
        """
        # Size-based complexity (0-50 points)
        size_score = min(apk_size_mb / 10, 50)  # Max 50 points for size
        
        # Findings-based complexity (0-50 points)
        findings_score = min(findings_count / 100, 50)  # Max 50 points for findings
        
        return int(size_score + findings_score)
    
    def update_peak_memory(self, current_memory_mb: float):
        """Update the peak memory tracker."""
        self._peak_memory_tracker = max(self._peak_memory_tracker, current_memory_mb)
    
    def get_current_memory_mb(self) -> float:
        """Get current memory usage in MB."""
        try:
            process = psutil.Process()
            memory_mb = process.memory_info().rss / (1024 * 1024)
            self.update_peak_memory(memory_mb)
            return memory_mb
        except Exception as e:
            self.logger.warning(f"Could not get current memory usage: {e}")
            return 0.0
    
    def calculate_performance_trends(self, metrics_history: List[IntegratedPerformanceMetrics]) -> Dict[str, Any]:
        """Calculate performance trends from historical metrics."""
        if not metrics_history:
            return {'error': 'No metrics history available'}
        
        if len(metrics_history) < 2:
            return {'error': 'Insufficient data for trend analysis'}
        
        # Calculate trends
        duration_trend = self._calculate_trend([m.total_duration_seconds for m in metrics_history])
        memory_trend = self._calculate_trend([m.memory_efficiency_percent for m in metrics_history])
        reduction_trend = self._calculate_trend([m.reduction_percentage for m in metrics_history])
        cache_trend = self._calculate_trend([m.cache_hit_rate_percent for m in metrics_history])
        speedup_trend = self._calculate_trend([m.parallel_speedup_factor for m in metrics_history])
        
        return {
            'total_analyses': len(metrics_history),
            'trends': {
                'duration_seconds': duration_trend,
                'memory_efficiency_percent': memory_trend,
                'reduction_percentage': reduction_trend,
                'cache_hit_rate_percent': cache_trend,
                'parallel_speedup_factor': speedup_trend
            },
            'averages': {
                'duration_seconds': sum(m.total_duration_seconds for m in metrics_history) / len(metrics_history),
                'memory_efficiency_percent': sum(m.memory_efficiency_percent for m in metrics_history) / len(metrics_history),
                'reduction_percentage': sum(m.reduction_percentage for m in metrics_history) / len(metrics_history),
                'cache_hit_rate_percent': sum(m.cache_hit_rate_percent for m in metrics_history) / len(metrics_history),
                'parallel_speedup_factor': sum(m.parallel_speedup_factor for m in metrics_history) / len(metrics_history)
            }
        }
    
    def _calculate_trend(self, values: List[float]) -> Dict[str, Any]:
        """Calculate trend direction and magnitude for a series of values."""
        if len(values) < 2:
            return {'direction': 'stable', 'magnitude': 0.0}
        
        # Simple linear trend calculation
        n = len(values)
        x_values = list(range(n))
        
        # Calculate slope using least squares
        sum_x = sum(x_values)
        sum_y = sum(values)
        sum_xy = sum(x * y for x, y in zip(x_values, values))
        sum_x2 = sum(x * x for x in x_values)
        
        slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x) if (n * sum_x2 - sum_x * sum_x) != 0 else 0
        
        # Determine trend direction and magnitude
        if abs(slope) < 0.01:  # Very small change
            direction = 'stable'
        elif slope > 0:
            direction = 'improving' if any(keyword in str(values) for keyword in ['efficiency', 'hit_rate', 'speedup']) else 'increasing'
        else:
            direction = 'declining' if any(keyword in str(values) for keyword in ['efficiency', 'hit_rate', 'speedup']) else 'decreasing'
        
        return {
            'direction': direction,
            'magnitude': abs(slope),
            'slope': slope,
            'recent_value': values[-1],
            'initial_value': values[0],
            'change_percent': ((values[-1] - values[0]) / values[0] * 100) if values[0] != 0 else 0
        }
    
    def generate_performance_summary(self, metrics: IntegratedPerformanceMetrics) -> Dict[str, Any]:
        """Generate a comprehensive performance summary."""
        return {
            'analysis_performance': {
                'duration_seconds': metrics.total_duration_seconds,
                'findings_reduction': f"{metrics.reduction_percentage:.1f}%",
                'memory_efficiency': f"{metrics.memory_efficiency_percent:.1f}%",
                'optimization_strategy': metrics.optimization_strategy
            },
            'resource_utilization': {
                'memory_usage': {
                    'initial_mb': metrics.initial_memory_mb,
                    'peak_mb': metrics.peak_memory_mb,
                    'final_mb': metrics.final_memory_mb,
                    'efficiency_percent': metrics.memory_efficiency_percent
                },
                'parallel_processing': {
                    'workers_used': metrics.parallel_workers_used,
                    'efficiency_percent': metrics.parallel_efficiency_percent,
                    'speedup_factor': metrics.parallel_speedup_factor
                },
                'caching': {
                    'hits': metrics.cache_hits,
                    'misses': metrics.cache_misses,
                    'hit_rate_percent': metrics.cache_hit_rate_percent
                }
            },
            'workload_characteristics': {
                'apk_size_mb': metrics.apk_size_mb,
                'findings_processed': metrics.findings_processed,
                'findings_filtered': metrics.findings_filtered,
                'complexity_score': metrics.complexity_score,
                'batch_processing': metrics.batch_processing_enabled
            }
        } 
 
 