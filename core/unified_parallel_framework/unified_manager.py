#!/usr/bin/env python3
"""
Unified Parallel Framework - Unified Manager

Central coordinator for all parallel execution strategies, providing intelligent
strategy selection and unified execution interface.

Consolidates and coordinates:
- Plugin-level parallel execution (from parallel_analysis_engine.py)
- Process-level execution management (from parallel_execution_manager.py)
- Robust execution patterns (from enhanced_parallel_execution.py)
- Adaptive strategy selection based on task characteristics

Strategy Selection Logic:
- Automatic strategy selection based on task analysis
- Performance monitoring and strategy effectiveness tracking
- Resource-aware execution optimization
- integration with existing systems
"""

import logging
import threading
import time
from typing import Dict, List, Any, Optional, Union, Callable, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path

from .execution_engine import (
    ExecutionEngine, ExecutionTask, ExecutionContext, ExecutionMetrics,
    ExecutionMode, ExecutionLevel, ResourceLevel, create_execution_engine
)
from .execution_strategies import (
    ExecutionStrategy, ExecutionResult, StrategyConfig,
    PluginExecutionStrategy, ProcessSeparationStrategy, 
    RobustExecutionStrategy, AdaptiveExecutionStrategy
)

@dataclass
class UnifiedConfig:
    """Unified configuration for parallel execution framework."""
    max_workers: int = 4
    memory_limit_gb: float = 8.0
    timeout_seconds: int = 300
    enable_monitoring: bool = True
    enable_caching: bool = True
    retry_attempts: int = 3
    
    # Strategy preferences
    preferred_strategy: Optional[str] = None
    enable_adaptive_selection: bool = True
    enable_process_separation: bool = True
    enable_window_management: bool = False
    
    # Performance settings
    resource_threshold: float = 0.8
    optimization_level: str = "balanced"  # conservative, balanced, aggressive

@dataclass
class ExecutionSummary:
    """Summary of unified execution results."""
    total_tasks: int
    successful_tasks: int
    failed_tasks: int
    total_execution_time: float
    strategy_used: str
    parallel_efficiency: float
    resource_utilization: Dict[str, float]
    recommendations: List[str]
    
    @property
    def success_rate(self) -> float:
        if self.total_tasks == 0:
            return 0.0
        return self.successful_tasks / self.total_tasks

class UnifiedParallelManager:
    """
    Central manager for all parallel execution approaches.
    
    Provides intelligent strategy selection, performance monitoring,
    and unified execution interface for all parallel execution needs.
    """
    
    def __init__(self, config: UnifiedConfig = None):
        self.config = config or UnifiedConfig()
        self.logger = logging.getLogger(__name__)
        
        # Initialize strategies
        self.strategies = self._initialize_strategies()
        
        # Strategy performance tracking
        self.strategy_performance: Dict[str, List[float]] = defaultdict(list)
        self.execution_history: List[ExecutionResult] = []
        
        # Thread safety
        self._execution_lock = threading.RLock()
        
        # Resource monitoring
        self.resource_monitor = ResourceMonitor()
        
        self.logger.info("Unified Parallel Manager initialized with professional framework integration")
    
    def _initialize_strategies(self) -> Dict[str, ExecutionStrategy]:
        """Initialize all available execution strategies."""
        strategy_config = StrategyConfig(
            max_workers=self.config.max_workers,
            memory_limit_gb=self.config.memory_limit_gb,
            timeout_seconds=self.config.timeout_seconds,
            enable_monitoring=self.config.enable_monitoring,
            enable_caching=self.config.enable_caching,
            retry_attempts=self.config.retry_attempts,
            resource_threshold=self.config.resource_threshold,
            process_isolation=self.config.enable_process_separation,
            window_management=self.config.enable_window_management,
            real_time_monitoring=self.config.enable_monitoring
        )
        
        strategies = {}
        
        try:
            strategies['plugin_execution'] = PluginExecutionStrategy(strategy_config)
            strategies['process_separation'] = ProcessSeparationStrategy(strategy_config)
            strategies['robust_execution'] = RobustExecutionStrategy(strategy_config)
            
            if self.config.enable_adaptive_selection:
                strategies['adaptive_execution'] = AdaptiveExecutionStrategy(strategy_config)
            
            self.logger.info(f"Initialized {len(strategies)} execution strategies")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize strategies: {e}")
            # Fallback to basic strategy
            strategies['basic_execution'] = self._create_basic_strategy(strategy_config)
        
        return strategies
    
    def _create_basic_strategy(self, config: StrategyConfig) -> ExecutionStrategy:
        """Create a basic fallback strategy."""
        return RobustExecutionStrategy(config)
    
    def execute_parallel(self, tasks: List[ExecutionTask], 
                        execution_context: Optional[ExecutionContext] = None) -> ExecutionSummary:
        """
        Execute tasks using intelligent parallel strategy selection.
        
        Args:
            tasks: List of tasks to execute
            execution_context: Optional execution context
            
        Returns:
            Execution summary with comprehensive results
        """
        with self._execution_lock:
            start_time = time.time()
            
            # Create execution context if not provided
            if execution_context is None:
                execution_context = ExecutionContext(
                    execution_id=f"unified_execution_{int(time.time())}",
                    config=self.config.__dict__
                )
            
            try:
                self.logger.info(f"Starting unified parallel execution of {len(tasks)} tasks")
                
                # Select optimal strategy
                strategy = self._select_optimal_strategy(tasks, execution_context)
                
                # Execute with selected strategy
                result = strategy.execute(tasks, execution_context)
                
                # Update performance tracking
                self._update_performance_tracking(strategy.get_strategy_name(), result)
                
                # Generate execution summary
                summary = self._create_execution_summary(tasks, result, strategy, start_time)
                
                self.logger.info(f"Unified execution completed: {summary.success_rate*100:.1f}% success rate")
                
                return summary
                
            except Exception as e:
                self.logger.error(f"Unified parallel execution failed: {e}")
                
                # Return error summary
                execution_time = time.time() - start_time
                return ExecutionSummary(
                    total_tasks=len(tasks),
                    successful_tasks=0,
                    failed_tasks=len(tasks),
                    total_execution_time=execution_time,
                    strategy_used="error",
                    parallel_efficiency=0.0,
                    resource_utilization={},
                    recommendations=[f"Execution failed: {e}", "Review system resources and task configuration"]
                )
    
    def _select_optimal_strategy(self, tasks: List[ExecutionTask], 
                               context: ExecutionContext) -> ExecutionStrategy:
        """Select optimal execution strategy for given tasks."""
        # If user specified preferred strategy, use it
        if self.config.preferred_strategy and self.config.preferred_strategy in self.strategies:
            strategy = self.strategies[self.config.preferred_strategy]
            self.logger.info(f"Using preferred strategy: {strategy.get_strategy_name()}")
            return strategy
        
        # Use adaptive strategy if available and enabled
        if self.config.enable_adaptive_selection and 'adaptive_execution' in self.strategies:
            return self.strategies['adaptive_execution']
        
        # Calculate strategy scores
        strategy_scores = {}
        
        for name, strategy in self.strategies.items():
            if name == 'adaptive_execution':
                continue  # Skip adaptive for manual selection
            
            # Base suitability score
            suitability = strategy.is_suitable_for(tasks, context)
            
            # Historical performance score
            performance = self._get_strategy_performance_score(name)
            
            # Resource compatibility score
            resource_score = self._calculate_resource_compatibility(strategy, tasks)
            
            # Combined score
            total_score = (suitability * 0.5) + (performance * 0.3) + (resource_score * 0.2)
            strategy_scores[strategy] = total_score
        
        # Select strategy with highest score
        if strategy_scores:
            best_strategy = max(strategy_scores.items(), key=lambda x: x[1])[0]
            self.logger.info(f"Selected strategy: {best_strategy.get_strategy_name()} "
                           f"(score: {strategy_scores[best_strategy]:.2f})")
            return best_strategy
        else:
            # Fallback to first available strategy
            return list(self.strategies.values())[0]
    
    def _get_strategy_performance_score(self, strategy_name: str) -> float:
        """Get historical performance score for strategy."""
        if strategy_name not in self.strategy_performance:
            return 0.5  # Neutral score for new strategies
        
        recent_scores = self.strategy_performance[strategy_name][-10:]  # Last 10 executions
        if not recent_scores:
            return 0.5
        
        return sum(recent_scores) / len(recent_scores)
    
    def _calculate_resource_compatibility(self, strategy: ExecutionStrategy, 
                                        tasks: List[ExecutionTask]) -> float:
        """Calculate resource compatibility score for strategy."""
        try:
            import psutil
            
            # Current system state
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory_percent = psutil.virtual_memory().percent
            available_memory_gb = psutil.virtual_memory().available / (1024**3)
            
            # Task resource requirements
            total_memory_mb = sum(task.memory_requirement_mb for task in tasks)
            cpu_intensive_count = sum(1 for task in tasks if task.cpu_intensive)
            
            # Strategy-specific compatibility
            strategy_name = strategy.get_strategy_name()
            
            if strategy_name == "process_separation":
                # Process separation needs more resources
                if cpu_percent < 70 and memory_percent < 70 and available_memory_gb > 2:
                    return 0.9
                else:
                    return 0.3
            elif strategy_name == "plugin_execution":
                # Plugin execution is more memory efficient
                if memory_percent < 80:
                    return 0.8
                else:
                    return 0.5
            elif strategy_name == "robust_execution":
                # Robust execution is conservative
                return 0.7
            else:
                return 0.6
                
        except Exception as e:
            self.logger.warning(f"Failed to assess resource compatibility: {e}")
            return 0.5
    
    def _update_performance_tracking(self, strategy_name: str, result: ExecutionResult):
        """Update performance tracking for strategy."""
        # Calculate performance score
        performance_score = 0.0
        
        if result.success:
            # Success contributes 50%
            performance_score += 0.5
            
            # Execution time contributes 30% (faster is better)
            if result.execution_time > 0:
                time_score = min(1.0, 60.0 / result.execution_time)  # Target under 60 seconds
                performance_score += time_score * 0.3
            
            # Parallel efficiency contributes 20%
            if hasattr(result.metrics, 'parallel_efficiency'):
                performance_score += result.metrics.parallel_efficiency * 0.2
        
        # Store performance score
        self.strategy_performance[strategy_name].append(performance_score)
        
        # Keep only recent history
        if len(self.strategy_performance[strategy_name]) > 20:
            self.strategy_performance[strategy_name] = self.strategy_performance[strategy_name][-10:]
        
        # Store full result
        self.execution_history.append(result)
        if len(self.execution_history) > 50:
            self.execution_history = self.execution_history[-25:]
    
    def _create_execution_summary(self, tasks: List[ExecutionTask], result: ExecutionResult, 
                                strategy: ExecutionStrategy, start_time: float) -> ExecutionSummary:
        """Create comprehensive execution summary."""
        total_execution_time = time.time() - start_time
        
        # Count results
        successful_tasks = 0
        failed_tasks = 0
        
        for task_result in result.results.values():
            if isinstance(task_result, dict) and "error" in task_result:
                failed_tasks += 1
            else:
                successful_tasks += 1
        
        # Calculate parallel efficiency
        parallel_efficiency = 1.0
        if hasattr(result.metrics, 'parallel_efficiency'):
            parallel_efficiency = result.metrics.parallel_efficiency
        elif len(tasks) > 1 and total_execution_time > 0:
            # Estimate efficiency
            sequential_time = sum(task.estimated_time_seconds for task in tasks)
            parallel_efficiency = min(1.0, sequential_time / total_execution_time)
        
        # Get resource utilization
        resource_utilization = self._get_resource_utilization()
        
        # Enhanced recommendations
        recommendations = result.recommendations.copy() if result.recommendations else []
        recommendations.extend(self._generate_unified_recommendations(
            tasks, result, strategy, total_execution_time
        ))
        
        return ExecutionSummary(
            total_tasks=len(tasks),
            successful_tasks=successful_tasks,
            failed_tasks=failed_tasks,
            total_execution_time=total_execution_time,
            strategy_used=strategy.get_strategy_name(),
            parallel_efficiency=parallel_efficiency,
            resource_utilization=resource_utilization,
            recommendations=recommendations
        )
    
    def _get_resource_utilization(self) -> Dict[str, float]:
        """Get current resource utilization."""
        try:
            import psutil
            
            return {
                'cpu_percent': psutil.cpu_percent(interval=0.1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_io_percent': 0.0,  # Could be enhanced with disk monitoring
                'network_io_percent': 0.0  # Could be enhanced with network monitoring
            }
        except Exception:
            return {}
    
    def _generate_unified_recommendations(self, tasks: List[ExecutionTask], result: ExecutionResult,
                                        strategy: ExecutionStrategy, execution_time: float) -> List[str]:
        """Generate unified framework recommendations."""
        recommendations = []
        
        # Performance recommendations
        if execution_time < 30:
            recommendations.append("Excellent execution speed achieved")
        elif execution_time > 120:
            recommendations.append("Consider task optimization for better performance")
        
        # Strategy recommendations
        strategy_name = strategy.get_strategy_name()
        if strategy_name == "adaptive_execution":
            recommendations.append("Adaptive strategy selection optimized execution")
        else:
            recommendations.append(f"Used {strategy_name} strategy for optimal performance")
        
        # Resource recommendations
        resource_util = self._get_resource_utilization()
        if resource_util.get('memory_percent', 0) > 85:
            recommendations.append("High memory usage detected - consider memory optimization")
        
        if resource_util.get('cpu_percent', 0) > 90:
            recommendations.append("High CPU usage detected - consider load balancing")
        
        # Success rate recommendations
        success_rate = result.metrics.success_rate if hasattr(result.metrics, 'success_rate') else 1.0
        if success_rate < 0.8:
            recommendations.append("Low success rate - review task error handling")
        elif success_rate == 1.0:
            recommendations.append("Perfect execution - all tasks completed successfully")
        
        return recommendations
    
    def get_framework_report(self) -> Dict[str, Any]:
        """Generate comprehensive framework performance report."""
        report = {
            'framework_version': 'unified_parallel_framework_1.0',
            'total_executions': len(self.execution_history),
            'available_strategies': list(self.strategies.keys()),
            'strategy_performance': {},
            'overall_statistics': {},
            'recommendations': []
        }
        
        # Strategy performance breakdown
        for strategy_name, scores in self.strategy_performance.items():
            if scores:
                report['strategy_performance'][strategy_name] = {
                    'executions': len(scores),
                    'average_score': sum(scores) / len(scores),
                    'latest_score': scores[-1],
                    'trend': 'improving' if len(scores) > 5 and scores[-1] > scores[-6] else 'stable'
                }
        
        # Overall statistics
        if self.execution_history:
            successful_executions = sum(1 for result in self.execution_history if result.success)
            total_executions = len(self.execution_history)
            avg_execution_time = sum(result.execution_time for result in self.execution_history) / total_executions
            
            report['overall_statistics'] = {
                'success_rate': successful_executions / total_executions,
                'average_execution_time': avg_execution_time,
                'total_executions': total_executions,
                'framework_efficiency': 'high' if successful_executions / total_executions > 0.9 else 'moderate'
            }
        
        # Framework recommendations
        if report['overall_statistics'].get('success_rate', 0) > 0.95:
            report['recommendations'].append("Framework performing excellently")
        
        if len(report['available_strategies']) >= 4:
            report['recommendations'].append("Full strategy suite available for optimal execution")
        
        return report
    
    def configure_strategy_preference(self, strategy_name: str):
        """Configure preferred execution strategy."""
        if strategy_name in self.strategies:
            self.config.preferred_strategy = strategy_name
            self.logger.info(f"Strategy preference set to: {strategy_name}")
        else:
            available = list(self.strategies.keys())
            raise ValueError(f"Strategy '{strategy_name}' not available. Available: {available}")
    
    def enable_adaptive_selection(self, enable: bool = True):
        """Enable or disable adaptive strategy selection."""
        self.config.enable_adaptive_selection = enable
        self.logger.info(f"Adaptive strategy selection: {'enabled' if enable else 'disabled'}")
    
    def set_resource_limits(self, max_workers: int = None, memory_limit_gb: float = None):
        """Set resource limits for execution."""
        if max_workers is not None:
            self.config.max_workers = max_workers
            self.logger.info(f"Max workers set to: {max_workers}")
        
        if memory_limit_gb is not None:
            self.config.memory_limit_gb = memory_limit_gb
            self.logger.info(f"Memory limit set to: {memory_limit_gb}GB")
        
        # Update strategies with new limits
        if max_workers is not None or memory_limit_gb is not None:
            self.strategies = self._initialize_strategies()
    
    def cleanup(self):
        """Cleanup framework resources."""
        for strategy in self.strategies.values():
            try:
                if hasattr(strategy, 'cleanup'):
                    strategy.cleanup()
            except Exception as e:
                self.logger.warning(f"Error cleaning up strategy {strategy.get_strategy_name()}: {e}")
        
        self.resource_monitor.cleanup()
        self.logger.info("Unified Parallel Manager cleanup completed")

class ResourceMonitor:
    """System resource monitoring for the unified framework."""
    
    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.resource_history = []
    
    def start_monitoring(self):
        """Start resource monitoring."""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop resource monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)
    
    def cleanup(self):
        """Cleanup monitoring resources."""
        self.stop_monitoring()
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.monitoring:
            try:
                import psutil
                
                resource_snapshot = {
                    'timestamp': time.time(),
                    'cpu_percent': psutil.cpu_percent(interval=1),
                    'memory_percent': psutil.virtual_memory().percent,
                    'available_memory_gb': psutil.virtual_memory().available / (1024**3)
                }
                
                self.resource_history.append(resource_snapshot)
                
                # Keep only recent history
                if len(self.resource_history) > 100:
                    self.resource_history = self.resource_history[-50:]
                
                time.sleep(5)  # Monitor every 5 seconds
                
            except Exception as e:
                logging.getLogger(__name__).warning(f"Resource monitoring error: {e}")
                break

# Global unified manager instance
_unified_manager = None
_manager_lock = threading.Lock()

def get_unified_parallel_manager(config: UnifiedConfig = None) -> UnifiedParallelManager:
    """Get the global unified parallel manager instance."""
    global _unified_manager
    
    if _unified_manager is None:
        with _manager_lock:
            if _unified_manager is None:
                _unified_manager = UnifiedParallelManager(config)
    
    return _unified_manager

# Convenience functions for different execution patterns
def execute_plugin_tasks(plugin_functions: List[Callable], apk_context: Any, 
                        **kwargs) -> ExecutionSummary:
    """Execute plugin functions in parallel."""
    manager = get_unified_parallel_manager()
    
    # Create tasks for plugin functions
    tasks = []
    for i, plugin_func in enumerate(plugin_functions):
        task = ExecutionTask(
            task_id=f"plugin_{i}_{plugin_func.__name__}",
            task_type="plugin",
            priority=100,
            io_intensive=True,
            payload={
                'function': plugin_func,
                'args': (apk_context,),
                'kwargs': kwargs
            }
        )
        tasks.append(task)
    
    return manager.execute_parallel(tasks)

def execute_analysis_tasks(static_function: Callable = None, dynamic_function: Callable = None,
                          apk_context: Any = None, **kwargs) -> ExecutionSummary:
    """Execute static and dynamic analysis in parallel."""
    manager = get_unified_parallel_manager()
    
    tasks = []
    
    if static_function:
        task = ExecutionTask(
            task_id="static_analysis",
            task_type="analysis",
            priority=50,
            cpu_intensive=True,
            memory_requirement_mb=300,
            estimated_time_seconds=90,
            payload={
                'function': static_function,
                'args': (apk_context,) if apk_context else (),
                'kwargs': kwargs
            }
        )
        tasks.append(task)
    
    if dynamic_function:
        task = ExecutionTask(
            task_id="dynamic_analysis",
            task_type="analysis",
            priority=60,
            cpu_intensive=True,
            memory_requirement_mb=400,
            estimated_time_seconds=120,
            dependencies={'static_analysis'} if static_function else set(),
            payload={
                'function': dynamic_function,
                'args': (apk_context,) if apk_context else (),
                'kwargs': kwargs
            }
        )
        tasks.append(task)
    
    return manager.execute_parallel(tasks)

def execute_custom_parallel(task_functions: List[Tuple[str, Callable]], 
                           dependencies: Dict[str, List[str]] = None,
                           **kwargs) -> ExecutionSummary:
    """Execute custom parallel tasks with optional dependencies."""
    manager = get_unified_parallel_manager()
    dependencies = dependencies or {}
    
    tasks = []
    for task_name, task_func in task_functions:
        task_deps = set(dependencies.get(task_name, []))
        
        task = ExecutionTask(
            task_id=task_name,
            task_type="custom",
            priority=100,
            dependencies=task_deps,
            payload={
                'function': task_func,
                'args': (),
                'kwargs': kwargs
            }
        )
        tasks.append(task)
    
    return manager.execute_parallel(tasks) 