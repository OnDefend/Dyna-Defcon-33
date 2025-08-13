#!/usr/bin/env python3
"""
Performance Optimization Framework

Modular performance optimization framework with consolidated
strategies for different optimization scenarios.

Unified framework that combines multiple optimization approaches into
a single, intelligent system with automatic strategy selection based
on target characteristics and available resources.

Features:
- Multiple optimization strategies for different use cases
- Intelligent strategy selection based on target characteristics
- Resource management and monitoring
- Timeout handling and error recovery
- Performance metrics and analysis

Components:
- optimized_pipeline.py: Core optimization pipeline
- intelligent_cache.py: Caching with SQLite persistence
- memory_manager.py: Memory allocation and monitoring
- parallel_processor.py: Parallel processing framework
- resource_manager.py: Resource allocation management
- timeout_manager.py: Timeout and error handling
- performance_metrics.py: Performance tracking
- optimization_strategies.py: Strategy implementations
- unified_strategy_manager.py: Strategy coordination
"""

import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum

# Import modular components
from .performance_optimizer import (
    OptimizedPipeline,
    IntelligentCache,
    MemoryManager,
    ParallelProcessor,
    ResourceManager,
    TimeoutManager,
    PerformanceMetrics,
    OptimizationStrategies,
    UnifiedStrategyManager,
    PerformanceDataStructures
)

# Import unified strategy framework (new approach)
from .performance_optimizer.unified_strategy_manager import (
    UnifiedStrategyManager,
    get_unified_strategy_manager,
    optimize_performance,
    get_optimization_report,
    OptimizationResult
)

from .performance_optimizer.data_structures import OptimizationConfig, OptimizationLevel, ParallelMode
from .performance_optimizer.optimized_pipeline import OptimizedPerformancePipeline

import logging
from typing import Dict, Any, Optional, Union
from pathlib import Path

class PerformanceOptimizer:
    """
    Unified Performance Optimizer with intelligent strategy selection.
    
    Consolidates all performance optimization approaches into a single,
    professional interface with automatic strategy selection based on
    target characteristics and system resources.
    """
    
    def __init__(self, config: Optional[OptimizationConfig] = None):
        """Initialize unified performance optimizer."""
        self.logger = logging.getLogger(__name__)
        
        if config is None:
            config = OptimizationConfig(
                optimization_level=OptimizationLevel.BALANCED,
                parallel_mode=ParallelMode.AUTO,
                cache_enabled=True,
                memory_limit_mb=2048
            )
        
        self.config = config
        self.strategy_manager = get_unified_strategy_manager(config)
        self.legacy_pipeline = OptimizedPerformancePipeline(config)
        
        self.logger.info("Unified Performance Optimizer initialized")
    
    def optimize_analysis(self, apk_path: Union[str, Path], 
                         analysis_functions: Dict[str, Any],
                         **kwargs) -> Dict[str, Any]:
        """Optimize APK analysis using intelligent strategy selection."""
        context = {
            'analysis_functions': analysis_functions,
            'analysis_type': 'apk_analysis',
            'operation_id': f"apk_{Path(apk_path).name}",
            **kwargs
        }
        
        result = self.strategy_manager.execute_optimization(apk_path, context)
        
        if result.success:
            return {
                'analysis_results': result.analysis_results,
                'performance_metrics': result.metrics,
                'optimization_strategy': result.strategy_used,
                'recommendations': result.recommendations,
                'success': True
            }
        else:
            return {
                'analysis_results': {},
                'error': result.error_message,
                'success': False,
                'optimization_strategy': result.strategy_used,
                'recommendations': result.recommendations
            }
    
    def optimize_source_code(self, source_code: str, file_path: str = "") -> OptimizationResult:
        """Optimize source code using general optimization strategies."""
        context = {
            'analysis_type': 'source_code_optimization',
            'file_path': file_path
        }
        return self.strategy_manager.execute_optimization(source_code, context)
    
    def get_optimization_report(self) -> Dict[str, Any]:
        """Generate comprehensive optimization performance report."""
        return self.strategy_manager.get_strategy_performance_report()

# Legacy compatibility - maintain all original APIs
__all__ = [
    'PerformanceOptimizer',
    'PerformanceMetrics',
    'IntelligentCache', 
    'MemoryManager',
    'ParallelProcessor',
    'ResourceManager',
    'TimeoutManager',
    'OptimizedPipeline',
    'OptimizationStrategies',
    'UnifiedStrategyManager',
    'PerformanceDataStructures',
    'optimize_performance',
    'get_optimization_report',
    'OptimizationResult'
]

# Convenience functions for backward compatibility
def optimize_apk_analysis(apk_path: Union[str, Path], 
                         analysis_functions: Dict[str, Any],
                         **kwargs) -> Dict[str, Any]:
    """Backward compatibility function for APK analysis optimization."""
    optimizer = PerformanceOptimizer()
    return optimizer.optimize_analysis(apk_path, analysis_functions, **kwargs)

def optimize_code_performance(source_code: str, file_path: str = "") -> OptimizationResult:
    """Optimize source code performance using general optimization strategies."""
    optimizer = PerformanceOptimizer()
    return optimizer.optimize_source_code(source_code, file_path)

# Legacy function for backward compatibility
def performance_monitor(func):
    """Legacy decorator for performance monitoring - maintained for compatibility"""
    return func 