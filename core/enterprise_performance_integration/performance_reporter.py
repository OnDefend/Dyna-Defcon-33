#!/usr/bin/env python3
"""
Enterprise Performance Integration - Performance Reporter

Comprehensive logging, status reporting, and performance visualization
for performance integration results.
"""

import logging
from typing import Dict, List, Any
from .data_structures import IntegratedPerformanceMetrics, FrameworkStatus


class PerformanceReporter:
    """
    Performance reporting with comprehensive logging,
    status tracking, and result visualization.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def log_integration_status(self, framework_status: Dict[str, FrameworkStatus]):
        """Log comprehensive integration status."""
        self.logger.info("Framework Integration Status:")
        
        for name, status in framework_status.items():
            availability_icon = "PASS" if status.initialization_success else "FAIL"
            capabilities_text = ", ".join(status.capabilities) if status.capabilities else "None"
            
            self.logger.info(f"   {availability_icon} {status.name}: {status.availability.value}")
            if status.capabilities:
                self.logger.info(f"      Capabilities: {capabilities_text}")
            if status.error_message:
                self.logger.info(f"      Error: {status.error_message}")
        
        # Calculate integration percentage
        total_frameworks = len(framework_status)
        successful_frameworks = sum(1 for status in framework_status.values() if status.initialization_success)
        integration_percentage = (successful_frameworks / total_frameworks) * 100 if total_frameworks > 0 else 0
        
        self.logger.info(f"Overall Integration: {integration_percentage:.1f}% ({successful_frameworks}/{total_frameworks})")
    
    def log_optimization_start(self, apk_path: str, findings_count: int, apk_size_mb: float, 
                             initial_memory_mb: float, strategy: str):
        """Log optimization start information."""
        self.logger.info("Starting optimized analysis")
        self.logger.info(f"   APK: {apk_path} ({apk_size_mb:.1f}MB)")
        self.logger.info(f"   Findings: {findings_count}")
        self.logger.info(f"   Initial Memory: {initial_memory_mb:.1f}MB")
        self.logger.info(f"   Strategy: {strategy}")
    
    def log_optimization_results(self, result: Dict[str, Any]):
        """Log comprehensive optimization results."""
        self.logger.info("Optimization completed successfully")
        self.logger.info("Analysis Results:")
        self.logger.info(f"   Findings: {result['original_findings']} → {result['final_findings']} ({result['reduction_percentage']:.1f}% reduction)")
        self.logger.info(f"   Time: {result['analysis_time_seconds']:.2f}s")
        self.logger.info(f"   Memory Efficiency: {result['memory_efficiency_percent']:.1f}%")
        self.logger.info(f"   Parallel Speedup: {result['parallel_speedup_factor']:.2f}x")
        self.logger.info(f"   Cache Hit Rate: {result['cache_hit_rate_percent']:.1f}%")
        self.logger.info(f"   Strategy: {result['optimization_strategy']}")
    
    def log_performance_summary(self, metrics_history: List[IntegratedPerformanceMetrics]):
        """Log performance summary from historical metrics."""
        if not metrics_history:
            self.logger.info("No performance history available")
            return
        
        total_analyses = len(metrics_history)
        avg_duration = sum(m.total_duration_seconds for m in metrics_history) / total_analyses
        avg_memory_efficiency = sum(m.memory_efficiency_percent for m in metrics_history) / total_analyses
        avg_reduction = sum(m.reduction_percentage for m in metrics_history) / total_analyses
        avg_speedup = sum(m.parallel_speedup_factor for m in metrics_history) / total_analyses
        avg_cache_hit = sum(m.cache_hit_rate_percent for m in metrics_history) / total_analyses
        
        self.logger.info("Performance Summary:")
        self.logger.info(f"   Total Analyses: {total_analyses}")
        self.logger.info(f"   Average Duration: {avg_duration:.2f}s")
        self.logger.info(f"   Average Memory Efficiency: {avg_memory_efficiency:.1f}%")
    
    def create_status_report(self, framework_status: Dict[str, FrameworkStatus], 
                           metrics_history: List[IntegratedPerformanceMetrics]) -> Dict[str, Any]:
        """Create comprehensive status report."""
        total_frameworks = len(framework_status)
        successful_frameworks = sum(1 for status in framework_status.values() if status.initialization_success)
        
        framework_details = {}
        for name, status in framework_status.items():
            framework_details[name] = {
                'available': status.initialization_success,
                'availability': status.availability.value,
                'capabilities': status.capabilities,
                'error': status.error_message
            }
        
        # Performance statistics
        performance_stats = {}
        if metrics_history:
            total_analyses = len(metrics_history)
            performance_stats = {
                'total_analyses': total_analyses,
                'average_duration_seconds': sum(m.total_duration_seconds for m in metrics_history) / total_analyses,
                'average_memory_efficiency_percent': sum(m.memory_efficiency_percent for m in metrics_history) / total_analyses,
                'average_reduction_percentage': sum(m.reduction_percentage for m in metrics_history) / total_analyses,
                'average_speedup_factor': sum(m.parallel_speedup_factor for m in metrics_history) / total_analyses,
                'average_cache_hit_rate_percent': sum(m.cache_hit_rate_percent for m in metrics_history) / total_analyses
            }
        
        return {
            'integration_status': {
                'total_frameworks': total_frameworks,
                'successful_frameworks': successful_frameworks,
                'success_percentage': (successful_frameworks / total_frameworks) * 100 if total_frameworks > 0 else 0,
                'framework_details': framework_details
            },
            'performance_statistics': performance_stats,
            'system_health': self._assess_system_health(framework_status, metrics_history)
        }
    
    def _assess_system_health(self, framework_status: Dict[str, FrameworkStatus], 
                            metrics_history: List[IntegratedPerformanceMetrics]) -> Dict[str, Any]:
        """Assess overall system health based on framework status and performance."""
        total_frameworks = len(framework_status)
        successful_frameworks = sum(1 for status in framework_status.values() if status.initialization_success)
        success_rate = (successful_frameworks / total_frameworks) if total_frameworks > 0 else 0
        
        # Determine health status
        if success_rate >= 0.9:
            health_status = 'excellent'
        elif success_rate >= 0.75:
            health_status = 'good'
        elif success_rate >= 0.5:
            health_status = 'fair'
        elif success_rate >= 0.25:
            health_status = 'poor'
        else:
            health_status = 'critical'
        
        # Performance health assessment
        performance_health = 'unknown'
        if metrics_history:
            recent_metrics = metrics_history[-5:]  # Last 5 analyses
            avg_efficiency = sum(m.memory_efficiency_percent for m in recent_metrics) / len(recent_metrics)
            avg_speedup = sum(m.parallel_speedup_factor for m in recent_metrics) / len(recent_metrics)
            
            if avg_efficiency >= 80 and avg_speedup >= 2.0:
                performance_health = 'excellent'
            elif avg_efficiency >= 60 and avg_speedup >= 1.5:
                performance_health = 'good'
            elif avg_efficiency >= 40 and avg_speedup >= 1.2:
                performance_health = 'fair'
            else:
                performance_health = 'needs_attention'
        
        return {
            'overall_status': health_status,
            'framework_success_rate': success_rate,
            'performance_health': performance_health,
            'recommendations': self._generate_health_recommendations(success_rate, performance_health)
        }
    
    def _generate_health_recommendations(self, success_rate: float, performance_health: str) -> List[str]:
        """Generate health improvement recommendations."""
        recommendations = []
        
        if success_rate < 0.75:
            recommendations.append("Check framework dependencies and installation")
            recommendations.append("Review system resource availability")
        
        if performance_health in ['fair', 'needs_attention']:
            recommendations.append("Consider increasing cache size for better performance")
            recommendations.append("Review parallel processing configuration")
            recommendations.append("Monitor memory usage patterns")
        
        if success_rate < 0.5:
            recommendations.append("Critical: Multiple frameworks failing - immediate attention required")
        
        if not recommendations:
            recommendations.append("System operating optimally")
        
        return recommendations 
 
 