#!/usr/bin/env python3
"""
Enterprise Performance Integration - Main Orchestrator

Main orchestration class that coordinates all modular components to provide
optimized performance for AODS analysis.
"""

import logging
import time
from typing import Dict, List, Any, Optional

from .data_structures import IntegratedPerformanceMetrics, OptimizationStrategy
from .configuration_manager import ConfigurationManager
from .framework_initializer import FrameworkInitializer
from .optimization_engine import OptimizationEngine
from .metrics_calculator import MetricsCalculator
from .fallback_handler import FallbackHandler
from .performance_reporter import PerformanceReporter


class EnterprisePerformanceIntegrator:
    """
    Main integration class that orchestrates all performance optimization frameworks
    to provide optimized performance for AODS analysis.
    
    Features:
    - Modular architecture with clean separation of concerns
    - System-aware configuration management
    - Performance metrics and reporting
    - Graceful degradation and fallback handling
    - Evidence-based optimization strategy selection
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the performance integrator."""
        self.logger = logging.getLogger(__name__)
        
        # Initialize modular components
        self.config_manager = ConfigurationManager()
        self.config = self.config_manager.validate_config(
            config or self.config_manager.get_default_config()
        )
        
        self.framework_initializer = FrameworkInitializer(self.config)
        self.metrics_calculator = MetricsCalculator()
        self.fallback_handler = FallbackHandler()
        self.performance_reporter = PerformanceReporter()
        
        # Initialize frameworks
        self.framework_initializer.initialize_all_frameworks()
        
        # Create optimization engine after frameworks are initialized
        self.optimization_engine = OptimizationEngine(
            self.config, 
            self.framework_initializer.frameworks
        )
        
        # Performance tracking
        self.metrics: Optional[IntegratedPerformanceMetrics] = None
        self.optimization_history: List[IntegratedPerformanceMetrics] = []
        
        # Log initialization
        self.logger.info("Performance Integrator initialized")
        self.performance_reporter.log_integration_status(
            self.framework_initializer.framework_status
        )
    
    def optimize_apk_analysis(self, apk_path: str, findings: List[Dict[str, Any]], 
                            app_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for optimized APK analysis.
        
        This method orchestrates all optimization frameworks to provide maximum performance.
        """
        analysis_start_time = time.time()
        initial_memory = self.metrics_calculator.get_current_memory_mb()
        apk_size_mb = self.optimization_engine._get_apk_size_mb(apk_path)
        
        try:
            # Determine optimization strategy
            strategy = self.optimization_engine.determine_optimization_strategy(
                apk_path, findings, app_context
            )
            
            # Log optimization start
            self.performance_reporter.log_optimization_start(
                apk_path, len(findings), apk_size_mb, initial_memory, strategy.value
            )
            
            # Execute optimization
            optimization_result = self.optimization_engine.optimize_apk_analysis(
                apk_path, findings, app_context, strategy
            )
            
            # Calculate comprehensive metrics
            analysis_end_time = time.time()
            final_memory = self.metrics_calculator.get_current_memory_mb()
            
            self.metrics = self.metrics_calculator.calculate_integrated_metrics(
                analysis_start_time, analysis_end_time, initial_memory, final_memory,
                len(findings), optimization_result, apk_size_mb, strategy
            )
            
            # Add metrics to history
            self.optimization_history.append(self.metrics)
            
            # Prepare comprehensive result
            result = {
                'status': 'success',
                'optimization_applied': True,
                'enterprise_mode': True,
                
                # Core results
                'original_findings': len(findings),
                'final_findings': optimization_result.get('total_findings', len(findings)),
                'reduction_percentage': self.metrics.reduction_percentage,
                
                # Performance metrics
                'analysis_time_seconds': self.metrics.total_duration_seconds,
                'memory_efficiency_percent': self.metrics.memory_efficiency_percent,
                'parallel_speedup_factor': self.metrics.parallel_speedup_factor,
                'cache_hit_rate_percent': self.metrics.cache_hit_rate_percent,
                
                # Features
                'optimization_strategy': strategy.value,
                'large_apk_mode': apk_size_mb >= self.config['large_apk_threshold_mb'],
                'batch_processing_ready': self.config['enable_batch_processing'],
                
                # Detailed results
                'detailed_results': optimization_result,
                'comprehensive_metrics': self.metrics.__dict__
            }
            
            # Log results
            self.performance_reporter.log_optimization_results(result)
            return result
            
        except Exception as e:
            self.logger.error(f"Optimization failed: {e}")
            return self.fallback_handler.create_fallback_result(
                apk_path, findings, app_context, str(e)
            )
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        if not self.optimization_history:
            return {
                "message": "No optimization history available",
                "integration_status": self.framework_initializer.get_integration_status()
            }
        
        # Calculate summary statistics
        total_analyses = len(self.optimization_history)
        avg_duration = sum(m.total_duration_seconds for m in self.optimization_history) / total_analyses
        avg_memory_efficiency = sum(m.memory_efficiency_percent for m in self.optimization_history) / total_analyses
        avg_reduction = sum(m.reduction_percentage for m in self.optimization_history) / total_analyses
        avg_speedup = sum(m.parallel_speedup_factor for m in self.optimization_history) / total_analyses
        avg_cache_hit = sum(m.cache_hit_rate_percent for m in self.optimization_history) / total_analyses
        
        return {
            "total_analyses": total_analyses,
            "average_duration_seconds": avg_duration,
            "average_memory_efficiency_percent": avg_memory_efficiency,
            "average_reduction_percentage": avg_reduction,
            "average_speedup_factor": avg_speedup,
            "average_cache_hit_rate_percent": avg_cache_hit,
            "integration_status": self.framework_initializer.get_integration_status(),
            "performance_trends": self.metrics_calculator.calculate_performance_trends(self.optimization_history)
        }
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status report."""
        return self.performance_reporter.create_status_report(
            self.framework_initializer.framework_status,
            self.optimization_history
        )
    
    def get_optimization_recommendations(self, apk_path: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get optimization strategy recommendations without executing them."""
        return self.optimization_engine.get_strategy_recommendations(apk_path, findings)


# Legacy compatibility functions
def create_enterprise_performance_integrator(config: Optional[Dict[str, Any]] = None) -> EnterprisePerformanceIntegrator:
    """Create performance integrator instance."""
    return EnterprisePerformanceIntegrator(config)


def integrate_enterprise_performance_with_aods(test_suite_instance, enable_enterprise: bool = True):
    """
    Integrate performance optimization with AODS test suite.
    
    This function provides backward compatibility with existing AODS integration.
    """
    if not enable_enterprise:
        logging.info("Performance integration disabled")
        return
    
    try:
        # Create integrator instance
        integrator = create_enterprise_performance_integrator()
        
        # Add optimization method to test suite
        if hasattr(test_suite_instance, 'enterprise_performance_integrator'):
            test_suite_instance.enterprise_performance_integrator = integrator
            logging.info("Performance integration added to AODS test suite")
        else:
            logging.warning("Test suite does not support performance integration")
            
    except Exception as e:
        logging.error(f"Failed to integrate performance optimization: {e}")


# For direct testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test performance integrator
    integrator = create_enterprise_performance_integrator()
    
    # Mock test data
    mock_findings = [{"type": "test", "severity": "medium"} for _ in range(50)]
    mock_context = {"app_name": "test_app", "analysis_type": "security"}
    
    # Test optimization
    result = integrator.optimize_apk_analysis("test.apk", mock_findings, mock_context)
    
    print(f"Optimization Applied: {result['optimization_applied']}")
    print(f"Enterprise Mode: {result['enterprise_mode']}")
    print(f"Findings: {result['original_findings']} → {result['final_findings']}")
    print(f"Strategy: {result['optimization_strategy']}")
    
    # Get performance summary
    summary = integrator.get_performance_summary()
    print("\nPerformance Summary:")
    print(f"Total Analyses: {summary['total_analyses']}")
    print(f"Average Duration: {summary['average_duration_seconds']:.2f}s")
    print(f"Average Reduction: {summary['average_reduction_percentage']:.1f}%")
    
    print("\nPerformance Integration test completed!") 