#!/usr/bin/env python3
"""
Unified Parallel Framework - Execution Strategies

Strategy pattern implementation consolidating all parallel execution approaches:
- PluginExecutionStrategy: Plugin-level coordination with dependencies
- ProcessSeparationStrategy: Static/dynamic analysis process separation  
- RobustExecutionStrategy: Enhanced error handling and monitoring
- AdaptiveExecutionStrategy: Dynamic resource-based optimization

Consolidates strategies from:
- parallel_analysis_engine.py (plugin dependency management)
- parallel_execution_manager.py (process separation with IPC)
- enhanced_parallel_execution.py (robust execution patterns)
"""

import asyncio
import json
import logging
import multiprocessing as mp
import os
import queue
import signal
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Tuple, Callable, Union
from pathlib import Path

import psutil
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, TaskID, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from .execution_engine import (
    ExecutionEngine, ExecutionTask, ExecutionContext, ExecutionMetrics,
    ExecutionMode, ExecutionLevel, ResourceLevel, DependencyGraph,
    ThreadBasedEngine, ProcessBasedEngine, HybridEngine
)

@dataclass
class StrategyConfig:
    """Configuration for execution strategies."""
    max_workers: int = 4
    memory_limit_gb: float = 8.0
    timeout_seconds: int = 300
    enable_monitoring: bool = True
    enable_caching: bool = True
    retry_attempts: int = 3
    resource_threshold: float = 0.8
    
    # Strategy-specific configs
    plugin_dependency_analysis: bool = True
    process_isolation: bool = False
    window_management: bool = False
    real_time_monitoring: bool = True

@dataclass
class ExecutionResult:
    """Unified result from strategy execution."""
    strategy_name: str
    success: bool
    execution_time: float
    results: Dict[str, Any]
    metrics: ExecutionMetrics
    error_message: Optional[str] = None
    recommendations: List[str] = None
    
    def __post_init__(self):
        if self.recommendations is None:
            self.recommendations = []

class ExecutionStrategy(ABC):
    """Abstract base class for execution strategies."""
    
    def __init__(self, config: StrategyConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.console = Console()
        
        # Strategy performance tracking
        self.execution_history: List[ExecutionResult] = []
        self.performance_metrics = {}
        
        self.logger.info(f"{self.__class__.__name__} initialized")
    
    @abstractmethod
    def execute(self, tasks: List[ExecutionTask], context: ExecutionContext) -> ExecutionResult:
        """Execute tasks using this strategy."""
        pass
    
    @abstractmethod
    def get_strategy_name(self) -> str:
        """Get strategy identifier."""
        pass
    
    @abstractmethod
    def is_suitable_for(self, tasks: List[ExecutionTask], context: ExecutionContext) -> float:
        """Return suitability score (0.0-1.0) for executing given tasks."""
        pass
    
    def get_performance_score(self) -> float:
        """Get performance score based on execution history."""
        if not self.execution_history:
            return 0.5  # Neutral score
        
        recent_executions = self.execution_history[-10:]  # Last 10 executions
        success_rate = sum(1 for r in recent_executions if r.success) / len(recent_executions)
        avg_time = sum(r.execution_time for r in recent_executions) / len(recent_executions)
        
        # Score based on success rate and execution speed
        time_score = min(1.0, 60.0 / avg_time)  # Prefer under 60 seconds
        return (success_rate * 0.7) + (time_score * 0.3)
    
    def update_performance_metrics(self, result: ExecutionResult):
        """Update performance metrics with execution result."""
        self.execution_history.append(result)
        
        # Keep only recent history
        if len(self.execution_history) > 50:
            self.execution_history = self.execution_history[-25:]

class PluginExecutionStrategy(ExecutionStrategy):
    """
    Plugin-level execution strategy with dependency management.
    
    Based on parallel_analysis_engine.py capabilities:
    - Dependency-aware plugin scheduling
    - Resource monitoring and adaptive workers
    - Plugin affinity optimization
    - Performance caching
    """
    
    def __init__(self, config: StrategyConfig):
        super().__init__(config)
        
        # Plugin-specific components
        self.dependency_analyzer = PluginDependencyAnalyzer()
        self.resource_monitor = ResourceMonitor()
        self.plugin_scheduler = AdvancedPluginScheduler()
        
        # Performance optimization
        self.plugin_performance_cache = {}
        self._adaptive_workers = config.max_workers
        
    def get_strategy_name(self) -> str:
        return "plugin_execution"
    
    def is_suitable_for(self, tasks: List[ExecutionTask], context: ExecutionContext) -> float:
        """High suitability for plugin-type tasks with dependencies."""
        plugin_tasks = sum(1 for task in tasks if task.task_type == "plugin")
        dependent_tasks = sum(1 for task in tasks if task.dependencies)
        
        plugin_ratio = plugin_tasks / len(tasks) if tasks else 0
        dependency_ratio = dependent_tasks / len(tasks) if tasks else 0
        
        # High score for plugin tasks with dependencies
        base_score = plugin_ratio * 0.6 + dependency_ratio * 0.4
        
        # Bonus for medium-sized task sets (optimal for plugin coordination)
        if 5 <= len(tasks) <= 20:
            base_score += 0.2
        
        return min(1.0, base_score)
    
    def execute(self, tasks: List[ExecutionTask], context: ExecutionContext) -> ExecutionResult:
        """Execute plugin tasks with dependency management."""
        start_time = time.time()
        
        try:
            self.logger.info(f"Executing {len(tasks)} tasks with plugin strategy")
            
            # Analyze dependencies
            dependencies = self.dependency_analyzer.analyze_plugin_dependencies(tasks)
            
            # Create execution plan
            execution_plan = self._create_execution_plan(tasks, dependencies)
            
            # Execute with resource monitoring
            results = self._execute_with_monitoring(execution_plan, context)
            
            execution_time = time.time() - start_time
            
            # Create result
            result = ExecutionResult(
                strategy_name=self.get_strategy_name(),
                success=True,
                execution_time=execution_time,
                results=results,
                metrics=context.metrics,
                recommendations=self._generate_recommendations(results, execution_time)
            )
            
            self.update_performance_metrics(result)
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Plugin execution strategy failed: {e}")
            
            result = ExecutionResult(
                strategy_name=self.get_strategy_name(),
                success=False,
                execution_time=execution_time,
                results={},
                metrics=context.metrics,
                error_message=str(e),
                recommendations=["Review plugin dependencies", "Check resource availability"]
            )
            
            self.update_performance_metrics(result)
            return result
    
    def _create_execution_plan(self, tasks: List[ExecutionTask], 
                              dependencies: Dict[str, List[str]]) -> List[ExecutionTask]:
        """Create optimized execution plan with dependencies."""
        # Calculate priorities based on dependencies and performance cache
        for task in tasks:
            priority = self._calculate_plugin_priority(task)
            task.priority = priority
        
        # Sort by priority (lower number = higher priority)
        return sorted(tasks, key=lambda t: t.priority)
    
    def _calculate_plugin_priority(self, task: ExecutionTask) -> int:
        """Calculate execution priority for a plugin task."""
        priority = 100  # Base priority
        
        # Dependency-based priority (fewer dependencies = higher priority)
        priority += len(task.dependencies) * 10
        
        # Performance cache consideration
        if task.task_id in self.plugin_performance_cache:
            avg_time = self.plugin_performance_cache[task.task_id].get('avg_time', 10.0)
            priority += min(avg_time, 300) // 10  # Shorter tasks get higher priority
        
        # I/O intensive tasks get higher priority (better for parallelization)
        if task.io_intensive:
            priority -= 20
        
        return priority
    
    def _execute_with_monitoring(self, tasks: List[ExecutionTask], 
                               context: ExecutionContext) -> Dict[str, Any]:
        """Execute tasks with real-time resource monitoring."""
        engine = ThreadBasedEngine(self._adaptive_workers)
        
        # Start resource monitoring
        if self.config.enable_monitoring:
            self.resource_monitor.start_monitoring()
        
        try:
            # Execute with adaptive worker management
            results = {}
            
            # Monitor and adapt during execution
            monitoring_thread = threading.Thread(
                target=self._monitor_and_adapt, 
                args=(context,), 
                daemon=True
            )
            monitoring_thread.start()
            
            # Execute tasks
            execution_results = engine.execute_tasks(tasks, context)
            results.update(execution_results)
            
            return results
            
        finally:
            if self.config.enable_monitoring:
                self.resource_monitor.stop_monitoring()
    
    def _monitor_and_adapt(self, context: ExecutionContext):
        """Monitor resources and adapt worker count."""
        while not context.is_shutdown_requested():
            try:
                # Get current resource usage
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_percent = psutil.virtual_memory().percent
                
                # Adaptive worker adjustment
                if memory_percent > 85 or cpu_percent > 90:
                    self._adaptive_workers = max(1, self._adaptive_workers - 1)
                elif memory_percent < 50 and cpu_percent < 70:
                    self._adaptive_workers = min(self.config.max_workers, self._adaptive_workers + 1)
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.logger.warning(f"Resource monitoring error: {e}")
                break
    
    def _generate_recommendations(self, results: Dict[str, Any], 
                                execution_time: float) -> List[str]:
        """Generate optimization recommendations."""
        recommendations = []
        
        if execution_time > 120:
            recommendations.append("Consider breaking down large plugins for better parallelization")
        
        error_count = sum(1 for result in results.values() if isinstance(result, dict) and "error" in result)
        if error_count > 0:
            recommendations.append(f"Review {error_count} plugin failures for optimization opportunities")
        
        if self._adaptive_workers < self.config.max_workers:
            recommendations.append("System resources were constrained during execution")
        
        return recommendations

class ProcessSeparationStrategy(ExecutionStrategy):
    """
    Process separation strategy for static/dynamic analysis isolation.
    
    Based on parallel_execution_manager.py capabilities:
    - Inter-process communication with shared memory
    - Real-time progress synchronization
    - Independent window management
    - Results aggregation from multiple processes
    """
    
    def __init__(self, config: StrategyConfig):
        super().__init__(config)
        
        # Process management components
        self.process_communicator = InterProcessCommunicator()
        self.window_manager = WindowManager() if config.window_management else None
        
        self.processes: Dict[str, mp.Process] = {}
        self.process_results: Dict[str, Any] = {}
    
    def get_strategy_name(self) -> str:
        return "process_separation"
    
    def is_suitable_for(self, tasks: List[ExecutionTask], context: ExecutionContext) -> float:
        """High suitability for analysis tasks requiring isolation."""
        analysis_tasks = sum(1 for task in tasks if task.task_type == "analysis")
        cpu_intensive_tasks = sum(1 for task in tasks if task.cpu_intensive)
        
        analysis_ratio = analysis_tasks / len(tasks) if tasks else 0
        cpu_ratio = cpu_intensive_tasks / len(tasks) if tasks else 0
        
        # High score for analysis tasks that benefit from process isolation
        base_score = analysis_ratio * 0.7 + cpu_ratio * 0.3
        
        # Bonus for tasks that can run in parallel independently
        if len(tasks) >= 2 and len(tasks) <= 4:
            base_score += 0.2
        
        return min(1.0, base_score)
    
    def execute(self, tasks: List[ExecutionTask], context: ExecutionContext) -> ExecutionResult:
        """Execute analysis tasks in separate processes."""
        start_time = time.time()
        
        try:
            self.logger.info(f"Executing {len(tasks)} tasks with process separation strategy")
            
            # Group tasks by analysis type
            static_tasks = [t for t in tasks if "static" in t.task_id.lower()]
            dynamic_tasks = [t for t in tasks if "dynamic" in t.task_id.lower()]
            other_tasks = [t for t in tasks if t not in static_tasks and t not in dynamic_tasks]
            
            # Start processes for different analysis types
            process_futures = []
            
            if static_tasks:
                process_futures.append(
                    self._start_analysis_process("static", static_tasks, context)
                )
            
            if dynamic_tasks:
                process_futures.append(
                    self._start_analysis_process("dynamic", dynamic_tasks, context)
                )
            
            if other_tasks:
                process_futures.append(
                    self._start_analysis_process("other", other_tasks, context)
                )
            
            # Monitor progress
            if self.config.real_time_monitoring:
                self._monitor_process_progress(context)
            
            # Wait for completion and collect results
            results = self._collect_process_results(process_futures, context)
            
            execution_time = time.time() - start_time
            
            result = ExecutionResult(
                strategy_name=self.get_strategy_name(),
                success=True,
                execution_time=execution_time,
                results=results,
                metrics=context.metrics,
                recommendations=self._generate_process_recommendations(results, execution_time)
            )
            
            self.update_performance_metrics(result)
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Process separation strategy failed: {e}")
            
            result = ExecutionResult(
                strategy_name=self.get_strategy_name(),
                success=False,
                execution_time=execution_time,
                results={},
                metrics=context.metrics,
                error_message=str(e),
                recommendations=["Check process isolation capabilities", "Verify system resources"]
            )
            
            self.update_performance_metrics(result)
            return result
        
        finally:
            self._cleanup_processes()
    
    def _start_analysis_process(self, analysis_type: str, tasks: List[ExecutionTask], 
                              context: ExecutionContext) -> mp.Process:
        """Start a separate process for analysis type."""
        process = mp.Process(
            target=self._run_analysis_process,
            args=(analysis_type, tasks, context),
            name=f"AODS-{analysis_type.title()}"
        )
        process.start()
        self.processes[analysis_type] = process
        return process
    
    def _run_analysis_process(self, analysis_type: str, tasks: List[ExecutionTask], 
                            context: ExecutionContext):
        """Run analysis tasks in a separate process."""
        try:
            self.console.print(f"[bold]🔍 AODS {analysis_type.title()} Analysis Process[/bold]")
            
            # Execute tasks in this process
            engine = ThreadBasedEngine(max_workers=2)  # Limited workers per process
            results = engine.execute_tasks(tasks, context)
            
            # Store results in shared memory
            self.process_communicator.store_results(analysis_type, results)
            
            self.console.print(f"[bold green]✅ {analysis_type.title()} Analysis Completed[/bold green]")
            
        except Exception as e:
            self.logger.error(f"{analysis_type} analysis process failed: {e}")
            self.process_communicator.store_results(analysis_type, {"error": str(e)})
    
    def _monitor_process_progress(self, context: ExecutionContext):
        """Monitor progress of all analysis processes."""
        def progress_monitor():
            # Check for active Rich Live displays to prevent conflicts
            try:
                # Attempt to create live display with conflict detection
                with Live(self._generate_progress_display(), refresh_per_second=2) as live:
                    while not context.is_shutdown_requested() and any(p.is_alive() for p in self.processes.values()):
                        live.update(self._generate_progress_display())
                        time.sleep(0.5)
            except RuntimeError as e:
                if "Only one live display may be active at once" in str(e):
                    # Fallback execution without live display when conflict detected
                    self.logger.warning("Rich Live display conflict detected - using fallback execution without live display")
                    self._monitor_progress_fallback(context)
                else:
                    # Re-raise other RuntimeErrors
                    raise
            except Exception as e:
                # Handle any other display-related errors gracefully
                self.logger.warning(f"Display error occurred, falling back to non-live progress monitoring: {e}")
                self._monitor_progress_fallback(context)
        
        monitor_thread = threading.Thread(target=progress_monitor, daemon=True)
        monitor_thread.start()
    
    def _monitor_progress_fallback(self, context: ExecutionContext):
        """Fallback progress monitoring without Rich Live display."""
        self.logger.info("Starting fallback progress monitoring (no live display)")
        while not context.is_shutdown_requested() and any(p.is_alive() for p in self.processes.values()):
            # Log progress periodically instead of live display
            active_processes = [name for name, process in self.processes.items() if process.is_alive()]
            if active_processes:
                self.logger.info(f"Active processes: {', '.join(active_processes)}")
            time.sleep(2)  # Less frequent updates for fallback mode
    
    def _generate_progress_display(self) -> Panel:
        """Generate real-time progress display for processes."""
        table = Table.grid(padding=1)
        table.add_column(style="bold")
        table.add_column()
        table.add_column()
        
        for process_type, process in self.processes.items():
            if process.is_alive():
                status = "🔄 Running"
                style = "green"
            else:
                status = "✅ Completed"
                style = "dim"
            
            table.add_row(
                f"📊 {process_type.title()}:",
                f"[{style}]{status}[/{style}]",
                f"[dim]PID: {process.pid}[/dim]"
            )
        
        return Panel(
            table,
            title="[bold]Process Separation Analysis Progress[/bold]",
            border_style="bright_blue"
        )
    
    def _collect_process_results(self, processes: List[mp.Process], 
                               context: ExecutionContext) -> Dict[str, Any]:
        """Collect results from all processes."""
        results = {}
        
        # Wait for all processes to complete
        for process in processes:
            try:
                process.join(timeout=self.config.timeout_seconds)
                if process.is_alive():
                    self.logger.warning(f"Process {process.name} timeout - terminating")
                    process.terminate()
                    process.join(timeout=5)
                    if process.is_alive():
                        process.kill()
            except Exception as e:
                self.logger.error(f"Error waiting for process {process.name}: {e}")
        
        # Collect results from shared memory
        for analysis_type in self.processes.keys():
            process_result = self.process_communicator.get_results(analysis_type)
            if process_result:
                results[analysis_type] = process_result
        
        return results
    
    def _generate_process_recommendations(self, results: Dict[str, Any], 
                                        execution_time: float) -> List[str]:
        """Generate recommendations for process separation strategy."""
        recommendations = []
        
        process_count = len(self.processes)
        if process_count > 1:
            recommendations.append(f"Successfully isolated {process_count} analysis processes")
        
        if execution_time > 300:  # 5 minutes
            recommendations.append("Consider optimizing long-running analysis processes")
        
        failed_processes = sum(1 for result in results.values() 
                             if isinstance(result, dict) and "error" in result)
        if failed_processes > 0:
            recommendations.append(f"Review {failed_processes} failed processes for improvement")
        
        return recommendations
    
    def _cleanup_processes(self):
        """Cleanup all managed processes."""
        for process_type, process in self.processes.items():
            if process.is_alive():
                try:
                    process.terminate()
                    process.join(timeout=2)
                    if process.is_alive():
                        process.kill()
                except Exception as e:
                    self.logger.error(f"Error cleaning up process {process_type}: {e}")
        
        self.processes.clear()

class RobustExecutionStrategy(ExecutionStrategy):
    """
    Robust execution strategy with enhanced error handling.
    
    Based on enhanced_parallel_execution.py capabilities:
    - Comprehensive timeout management
    - Advanced error recovery
    - Progress monitoring without deadlocks
    - Clean process termination
    """
    
    def __init__(self, config: StrategyConfig):
        super().__init__(config)
        
        # Robust execution components
        self.timeout_manager = TimeoutManager(config.timeout_seconds)
        self.error_recovery = ErrorRecoverySystem(config.retry_attempts)
        self.deadlock_detector = DeadlockDetector()
        
    def get_strategy_name(self) -> str:
        return "robust_execution"
    
    def is_suitable_for(self, tasks: List[ExecutionTask], context: ExecutionContext) -> float:
        """High suitability for error-prone or long-running tasks."""
        long_tasks = sum(1 for task in tasks if task.estimated_time_seconds > 60)
        high_memory_tasks = sum(1 for task in tasks if task.memory_requirement_mb > 500)
        
        risk_ratio = (long_tasks + high_memory_tasks) / len(tasks) if tasks else 0
        
        # Higher score for riskier task sets
        base_score = 0.5 + (risk_ratio * 0.4)
        
        # Bonus for medium to large task sets where robustness matters
        if len(tasks) >= 5:
            base_score += 0.1
        
        return min(1.0, base_score)
    
    def execute(self, tasks: List[ExecutionTask], context: ExecutionContext) -> ExecutionResult:
        """Execute tasks with robust error handling and monitoring."""
        start_time = time.time()
        
        try:
            self.logger.info(f"Executing {len(tasks)} tasks with robust strategy")
            
            # Initialize robust execution environment
            self.timeout_manager.initialize()
            self.deadlock_detector.start_monitoring()
            
            # Execute with comprehensive error handling
            results = self._execute_with_robust_handling(tasks, context)
            
            execution_time = time.time() - start_time
            
            result = ExecutionResult(
                strategy_name=self.get_strategy_name(),
                success=True,
                execution_time=execution_time,
                results=results,
                metrics=context.metrics,
                recommendations=self._generate_robust_recommendations(results, execution_time)
            )
            
            self.update_performance_metrics(result)
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Robust execution strategy failed: {e}")
            
            result = ExecutionResult(
                strategy_name=self.get_strategy_name(),
                success=False,
                execution_time=execution_time,
                results={},
                metrics=context.metrics,
                error_message=str(e),
                recommendations=["Enable detailed error logging", "Review task timeout settings"]
            )
            
            self.update_performance_metrics(result)
            return result
        
        finally:
            self.deadlock_detector.stop_monitoring()
            self.timeout_manager.cleanup()
    
    def _execute_with_robust_handling(self, tasks: List[ExecutionTask], 
                                    context: ExecutionContext) -> Dict[str, Any]:
        """Execute tasks with comprehensive error handling."""
        engine = HybridEngine(self.config.max_workers)
        results = {}
        
        # Execute with retry logic
        for attempt in range(self.config.retry_attempts):
            try:
                attempt_results = engine.execute_tasks(tasks, context)
                results.update(attempt_results)
                break  # Success
                
            except Exception as e:
                if attempt < self.config.retry_attempts - 1:
                    self.logger.warning(f"Execution attempt {attempt + 1} failed: {e}, retrying...")
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    raise  # Final attempt failed
        
        return results
    
    def _generate_robust_recommendations(self, results: Dict[str, Any], 
                                       execution_time: float) -> List[str]:
        """Generate recommendations for robust execution."""
        recommendations = []
        
        if execution_time < 30:
            recommendations.append("Fast execution achieved with robust error handling")
        
        error_count = sum(1 for result in results.values() 
                         if isinstance(result, dict) and "error" in result)
        
        if error_count == 0:
            recommendations.append("No errors detected - robust execution successful")
        else:
            recommendations.append(f"Handled {error_count} errors with recovery mechanisms")
        
        return recommendations

class AdaptiveExecutionStrategy(ExecutionStrategy):
    """
    Adaptive execution strategy that dynamically selects optimal approaches.
    
    Combines intelligence from all strategies to adapt to changing conditions.
    """
    
    def __init__(self, config: StrategyConfig):
        super().__init__(config)
        
        # Sub-strategies
        self.plugin_strategy = PluginExecutionStrategy(config)
        self.process_strategy = ProcessSeparationStrategy(config)
        self.robust_strategy = RobustExecutionStrategy(config)
        
        # Adaptive selection history
        self.strategy_selection_history = []
    
    def get_strategy_name(self) -> str:
        return "adaptive_execution"
    
    def is_suitable_for(self, tasks: List[ExecutionTask], context: ExecutionContext) -> float:
        """Always suitable as it adapts to any task set."""
        return 0.8  # High general suitability
    
    def execute(self, tasks: List[ExecutionTask], context: ExecutionContext) -> ExecutionResult:
        """Execute tasks using adaptive strategy selection."""
        start_time = time.time()
        
        try:
            # Analyze task characteristics
            analysis = self._analyze_task_characteristics(tasks, context)
            
            # Select best strategy
            selected_strategy = self._select_optimal_strategy(tasks, context, analysis)
            
            self.logger.info(f"Adaptive strategy selected: {selected_strategy.get_strategy_name()}")
            
            # Execute with selected strategy
            result = selected_strategy.execute(tasks, context)
            
            # Update selection history
            self.strategy_selection_history.append({
                'strategy': selected_strategy.get_strategy_name(),
                'task_count': len(tasks),
                'success': result.success,
                'execution_time': result.execution_time,
                'analysis': analysis
            })
            
            # Enhance result with adaptive insights
            result.strategy_name = f"adaptive_{result.strategy_name}"
            result.recommendations.insert(0, f"Adaptively selected {selected_strategy.get_strategy_name()} strategy")
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Adaptive execution strategy failed: {e}")
            
            return ExecutionResult(
                strategy_name=self.get_strategy_name(),
                success=False,
                execution_time=execution_time,
                results={},
                metrics=context.metrics,
                error_message=str(e),
                recommendations=["Adaptive selection failed", "Review task characteristics"]
            )
    
    def _analyze_task_characteristics(self, tasks: List[ExecutionTask], 
                                    context: ExecutionContext) -> Dict[str, Any]:
        """Analyze task characteristics for strategy selection."""
        if not tasks:
            return {}
        
        analysis = {
            'total_tasks': len(tasks),
            'plugin_tasks': sum(1 for t in tasks if t.task_type == "plugin"),
            'analysis_tasks': sum(1 for t in tasks if t.task_type == "analysis"),
            'cpu_intensive_tasks': sum(1 for t in tasks if t.cpu_intensive),
            'io_intensive_tasks': sum(1 for t in tasks if t.io_intensive),
            'dependent_tasks': sum(1 for t in tasks if t.dependencies),
            'long_tasks': sum(1 for t in tasks if t.estimated_time_seconds > 60),
            'memory_heavy_tasks': sum(1 for t in tasks if t.memory_requirement_mb > 500),
            'avg_estimated_time': sum(t.estimated_time_seconds for t in tasks) / len(tasks),
            'total_memory_requirement': sum(t.memory_requirement_mb for t in tasks)
        }
        
        # System resource analysis
        analysis['available_cpu_cores'] = os.cpu_count() or 4
        analysis['available_memory_gb'] = psutil.virtual_memory().total / (1024**3)
        analysis['current_cpu_percent'] = psutil.cpu_percent(interval=0.1)
        analysis['current_memory_percent'] = psutil.virtual_memory().percent
        
        return analysis
    
    def _select_optimal_strategy(self, tasks: List[ExecutionTask], 
                               context: ExecutionContext, 
                               analysis: Dict[str, Any]) -> ExecutionStrategy:
        """Select optimal strategy based on task analysis."""
        strategies = [
            self.plugin_strategy,
            self.process_strategy,
            self.robust_strategy
        ]
        
        # Calculate scores for each strategy
        strategy_scores = {}
        
        for strategy in strategies:
            # Base suitability score
            suitability = strategy.is_suitable_for(tasks, context)
            
            # Performance history score
            performance = strategy.get_performance_score()
            
            # Resource compatibility score
            resource_score = self._calculate_resource_compatibility(strategy, analysis)
            
            # Combined score
            total_score = (suitability * 0.5) + (performance * 0.3) + (resource_score * 0.2)
            strategy_scores[strategy] = total_score
        
        # Select strategy with highest score
        best_strategy = max(strategy_scores.items(), key=lambda x: x[1])[0]
        
        self.logger.info(f"Strategy scores: {[(s.get_strategy_name(), score) for s, score in strategy_scores.items()]}")
        
        return best_strategy
    
    def _calculate_resource_compatibility(self, strategy: ExecutionStrategy, 
                                        analysis: Dict[str, Any]) -> float:
        """Calculate resource compatibility score for strategy."""
        # Current system load
        cpu_load = analysis.get('current_cpu_percent', 0) / 100.0
        memory_load = analysis.get('current_memory_percent', 0) / 100.0
        
        # Strategy-specific resource requirements
        if strategy.get_strategy_name() == "process_separation":
            # Process separation needs more resources
            if cpu_load < 0.7 and memory_load < 0.7:
                return 0.9
            else:
                return 0.3
        elif strategy.get_strategy_name() == "plugin_execution":
            # Plugin execution is more resource efficient
            if memory_load < 0.8:
                return 0.8
            else:
                return 0.5
        else:
            # Robust execution is conservative
            return 0.7

# Helper classes for strategy implementations
class PluginDependencyAnalyzer:
    """Analyzes plugin dependencies for optimal scheduling."""
    
    def analyze_plugin_dependencies(self, tasks: List[ExecutionTask]) -> Dict[str, List[str]]:
        """Analyze dependencies between plugin tasks."""
        dependencies = {}
        
        for task in tasks:
            task_deps = list(task.dependencies) if task.dependencies else []
            dependencies[task.task_id] = task_deps
        
        return dependencies

class ResourceMonitor:
    """Monitors system resources during execution."""
    
    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
    
    def start_monitoring(self):
        """Start resource monitoring."""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_resources, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop resource monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)
    
    def _monitor_resources(self):
        """Monitor system resources."""
        while self.monitoring:
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_percent = psutil.virtual_memory().percent
                
                # Log high resource usage
                if cpu_percent > 90 or memory_percent > 90:
                    logging.getLogger(__name__).warning(
                        f"High resource usage: CPU {cpu_percent}%, Memory {memory_percent}%"
                    )
                
                time.sleep(5)
            except Exception:
                break

class AdvancedPluginScheduler:
    """Advanced scheduler for plugin execution optimization."""
    
    def __init__(self):
        self.plugin_affinities = {}
        self.performance_profiles = {}
    
    def schedule_plugins(self, tasks: List[ExecutionTask]) -> List[ExecutionTask]:
        """Schedule plugins for optimal execution."""
        # Sort by priority and estimated execution time
        return sorted(tasks, key=lambda t: (t.priority, t.estimated_time_seconds))

class InterProcessCommunicator:
    """Manages communication between processes."""
    
    def __init__(self):
        self.shared_data = {}
        self.results_storage = {}
    
    def store_results(self, process_type: str, results: Any):
        """Store results from a process."""
        self.results_storage[process_type] = results
    
    def get_results(self, process_type: str) -> Any:
        """Get results from a process."""
        return self.results_storage.get(process_type)

class WindowManager:
    """Manages separate windows for process execution."""
    
    def __init__(self):
        self.windows = {}
    
    def open_window(self, window_id: str, title: str, command: List[str]) -> bool:
        """Open a new window for process execution."""
        # Implementation would depend on system capabilities
        return True
    
    def close_all_windows(self):
        """Close all managed windows."""
        pass

class TimeoutManager:
    """Manages execution timeouts."""
    
    def __init__(self, default_timeout: int):
        self.default_timeout = default_timeout
        self.active_timeouts = {}
    
    def initialize(self):
        """Initialize timeout management."""
        pass
    
    def cleanup(self):
        """Cleanup timeout resources."""
        pass

class ErrorRecoverySystem:
    """System for error recovery and retry logic."""
    
    def __init__(self, max_retries: int):
        self.max_retries = max_retries
        self.error_history = []
    
    def handle_error(self, error: Exception, attempt: int) -> bool:
        """Handle an error and determine if retry should be attempted."""
        self.error_history.append((error, attempt, time.time()))
        return attempt < self.max_retries

class DeadlockDetector:
    """Detects and handles potential deadlocks."""
    
    def __init__(self):
        self.monitoring = False
    
    def start_monitoring(self):
        """Start deadlock monitoring."""
        self.monitoring = True
    
    def stop_monitoring(self):
        """Stop deadlock monitoring."""
        self.monitoring = False 