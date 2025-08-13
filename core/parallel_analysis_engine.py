#!/usr/bin/env python3
"""
Parallel Analysis Engine for AODS

Parallel plugin execution engine providing resource management,
load balancing, and performance optimization for Android security analysis.

Implements Parallel Plugin Execution Engine with Plugin Scheduler integration.
"""

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from queue import PriorityQueue, Queue
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.table import Table
from rich.text import Text

from core.advanced_plugin_scheduler import (AdvancedPluginScheduler,
                                            PluginAffinityType,
                                            PluginResourceProfile,
                                            create_advanced_scheduler)
from core.optimized_apk_processor import MemoryMetrics, MemoryMonitor
from core.output_manager import get_output_manager
from core.plugin_manager import (PluginCategory, PluginManager, PluginMetadata,
                                 PluginStatus)

logger = logging.getLogger(__name__)

class ExecutionMode(Enum):
    """Plugin execution mode for parallel processing."""

    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    ADAPTIVE = "adaptive"
    OPTIMIZED = "optimized"  # Optimization mode

class ResourceLevel(Enum):
    """System resource utilization levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ExecutionStats:
    """Statistics for parallel execution tracking."""

    total_plugins: int = 0
    completed_plugins: int = 0
    failed_plugins: int = 0
    parallel_efficiency: float = 0.0
    memory_peak_mb: float = 0.0
    total_execution_time: float = 0.0
    average_plugin_time: float = 0.0
    threads_used: int = 0

@dataclass
class PluginExecution:
    """Represents a plugin execution task."""

    plugin: PluginMetadata
    priority: int
    dependencies: Set[str] = field(default_factory=set)
    dependents: Set[str] = field(default_factory=set)
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    result: Optional[Tuple[str, Any]] = None
    error: Optional[str] = None

    def __lt__(self, other):
        return self.priority < other.priority

class DependencyGraph:
    """Manages plugin dependencies for parallel execution scheduling."""

    def __init__(self):
        self.graph: Dict[str, Set[str]] = {}  # plugin -> dependencies
        self.reverse_graph: Dict[str, Set[str]] = {}  # plugin -> dependents
        self.completed: Set[str] = set()
        self._lock = threading.Lock()

    def add_plugin(self, plugin_name: str, dependencies: Set[str] = None):
        """Add a plugin with its dependencies."""
        with self._lock:
            if dependencies is None:
                dependencies = set()

            self.graph[plugin_name] = dependencies.copy()

            # Update reverse graph
            if plugin_name not in self.reverse_graph:
                self.reverse_graph[plugin_name] = set()

            for dep in dependencies:
                if dep not in self.reverse_graph:
                    self.reverse_graph[dep] = set()
                self.reverse_graph[dep].add(plugin_name)

    def get_ready_plugins(self) -> List[str]:
        """Get plugins that are ready to execute (all dependencies satisfied)."""
        with self._lock:
            ready = []
            for plugin, dependencies in self.graph.items():
                if plugin not in self.completed:
                    if dependencies.issubset(self.completed):
                        ready.append(plugin)
            return ready

    def mark_completed(self, plugin_name: str):
        """Mark a plugin as completed."""
        with self._lock:
            self.completed.add(plugin_name)

    def get_dependents(self, plugin_name: str) -> Set[str]:
        """Get plugins that depend on the given plugin."""
        with self._lock:
            return self.reverse_graph.get(plugin_name, set()).copy()

class ParallelAnalysisEngine:
    """
    Parallel plugin execution engine.

    Provides dependency-aware parallel execution with memory management,
    resource optimization, and error handling.
    """

    def __init__(
        self,
        max_workers: int = 4,
        memory_limit_gb: float = 8.0,
        execution_mode: ExecutionMode = ExecutionMode.ADAPTIVE,
    ):
        """
        Initialize the parallel analysis engine.

        Args:
            max_workers: Maximum number of worker threads
            memory_limit_gb: Memory limit for parallel execution
            execution_mode: Execution mode (sequential, parallel, adaptive, optimized)
        """
        self.max_workers = max_workers
        self.memory_limit_gb = memory_limit_gb
        self.execution_mode = execution_mode

        # Auto-detect optimal worker count
        import os
        cpu_count = os.cpu_count() or 4
        if max_workers == 4:  # Default value
            # Use 75% of available CPU cores for optimal performance
            self.max_workers = max(2, int(cpu_count * 0.75))
            logger.info(f"Auto-optimized worker count: {self.max_workers} (based on {cpu_count} CPU cores)")

        # Core components
        self.console = Console()
        self.output_mgr = get_output_manager()
        self.memory_monitor = MemoryMonitor(
            warning_threshold_percent=70, critical_threshold_percent=85
        )

        # Execution management
        self.dependency_graph = DependencyGraph()
        self.execution_queue = PriorityQueue()
        self.results: Dict[str, Tuple[str, Any]] = {}
        self.execution_stats = ExecutionStats()

        # Thread safety
        self._results_lock = threading.Lock()
        self._stats_lock = threading.Lock()

        # Resource monitoring
        self.resource_level = ResourceLevel.LOW
        self._adaptive_workers = self.max_workers

        # Resource management
        self._cpu_utilization_history = []
        self._memory_utilization_history = []
        self._last_optimization_time = time.time()
        self._optimization_interval = 10.0  # seconds
        
        # Plugin execution cache
        self._plugin_performance_cache = {}
        self._plugin_memory_profiles = {}

        # Plugin Scheduler integration
        self.advanced_scheduler: Optional[AdvancedPluginScheduler] = None
        if execution_mode == ExecutionMode.OPTIMIZED:
            self.advanced_scheduler = create_advanced_scheduler(
                max_workers=self.max_workers, enable_profiling=True
            )
            logger.info(
                f"Plugin Scheduler enabled with {len(self.advanced_scheduler.worker_pools)} specialized pools"
            )

        logger.info(
            f"ParallelAnalysisEngine initialized: workers={self.max_workers}, "
            f"memory_limit={memory_limit_gb}GB, mode={execution_mode.value}"
        )

    def _analyze_plugin_dependencies(
        self, plugins: List[PluginMetadata]
    ) -> Dict[str, Set[str]]:
        """
        Analyze plugin dependencies based on categories and characteristics.

        Returns dependency mapping for intelligent scheduling.
        """
        dependencies = {}

        # Category-based dependency rules
        category_order = {
            PluginCategory.STATIC_ANALYSIS: 1,
            PluginCategory.PLATFORM_ANALYSIS: 2,
            PluginCategory.CRYPTO_ANALYSIS: 3,
            PluginCategory.NETWORK_ANALYSIS: 4,
            PluginCategory.DYNAMIC_ANALYSIS: 5,
            PluginCategory.VULNERABILITY_ANALYSIS: 6,
            PluginCategory.PRIVACY_ANALYSIS: 7,
            PluginCategory.RESILIENCE_ANALYSIS: 8,
        }

        for plugin in plugins:
            plugin_deps = set()

            # Static analysis should run first for most other plugins
            if plugin.category != PluginCategory.STATIC_ANALYSIS:
                static_plugins = [
                    p.module_name
                    for p in plugins
                    if p.category == PluginCategory.STATIC_ANALYSIS
                ]
                plugin_deps.update(static_plugins)

            # Dynamic analysis depends on platform analysis
            if plugin.category == PluginCategory.DYNAMIC_ANALYSIS:
                platform_plugins = [
                    p.module_name
                    for p in plugins
                    if p.category == PluginCategory.PLATFORM_ANALYSIS
                ]
                plugin_deps.update(platform_plugins)

            # Vulnerability analysis depends on most other categories
            if plugin.category == PluginCategory.VULNERABILITY_ANALYSIS:
                prerequisite_categories = [
                    PluginCategory.STATIC_ANALYSIS,
                    PluginCategory.PLATFORM_ANALYSIS,
                    PluginCategory.CRYPTO_ANALYSIS,
                    PluginCategory.NETWORK_ANALYSIS,
                ]
                for p in plugins:
                    if p.category in prerequisite_categories:
                        plugin_deps.add(p.module_name)

            # Invasive plugins should run after non-invasive ones
            if not plugin.invasive:
                invasive_plugins = [
                    p.module_name
                    for p in plugins
                    if p.invasive and p.module_name != plugin.module_name
                ]
                # Non-invasive plugins don't depend on invasive ones
            else:
                # Invasive plugins depend on non-invasive ones
                non_invasive_plugins = [
                    p.module_name for p in plugins if not p.invasive
                ]
                plugin_deps.update(non_invasive_plugins)

            dependencies[plugin.module_name] = plugin_deps

        return dependencies

    def _calculate_plugin_priority(self, plugin: PluginMetadata) -> int:
        """Calculate execution priority for a plugin."""
        priority = 100  # Base priority

        # Category-based priority
        category_priorities = {
            PluginCategory.STATIC_ANALYSIS: 10,
            PluginCategory.PLATFORM_ANALYSIS: 20,
            PluginCategory.CRYPTO_ANALYSIS: 30,
            PluginCategory.NETWORK_ANALYSIS: 40,
            PluginCategory.DYNAMIC_ANALYSIS: 50,
            PluginCategory.VULNERABILITY_ANALYSIS: 60,
            PluginCategory.PRIVACY_ANALYSIS: 70,
            PluginCategory.RESILIENCE_ANALYSIS: 80,
        }

        priority += category_priorities.get(plugin.category, 50)

        # Execution time consideration (shorter tasks first)
        priority += min(plugin.execution_time_estimate, 300) // 10

        # Invasive plugins get lower priority (higher number)
        if plugin.invasive:
            priority += 100

        # Required plugins get higher priority (lower number)
        if plugin.module_name in ["insecure_data_storage", "manifest_analysis"]:
            priority -= 50

        return priority

    def _update_resource_level(self, metrics: MemoryMetrics):
        """Update current resource utilization level."""
        if metrics.percentage >= 85:
            self.resource_level = ResourceLevel.CRITICAL
        elif metrics.percentage >= 70:
            self.resource_level = ResourceLevel.HIGH
        elif metrics.percentage >= 50:
            self.resource_level = ResourceLevel.MEDIUM
        else:
            self.resource_level = ResourceLevel.LOW

    def _adapt_worker_count(self):
        """Dynamically adjust worker count based on resource usage."""
        if self.execution_mode != ExecutionMode.ADAPTIVE:
            return

        # PERFORMANCE OPTIMIZATION: Enhanced adaptive worker management
        current_time = time.time()
        if current_time - self._last_optimization_time < self._optimization_interval:
            return
        
        self._last_optimization_time = current_time
        
        # Get current system metrics
        metrics = self.memory_monitor.get_current_metrics()
        
        # Store historical data for trend analysis
        self._memory_utilization_history.append(metrics.percentage)
        if len(self._memory_utilization_history) > 10:
            self._memory_utilization_history.pop(0)
        
        # Calculate memory trend
        memory_trend = 0
        if len(self._memory_utilization_history) >= 2:
            memory_trend = self._memory_utilization_history[-1] - self._memory_utilization_history[-2]
        
        # Adaptive worker count based on resource level and trend
        if self.resource_level == ResourceLevel.CRITICAL or metrics.percentage > 90:
            self._adaptive_workers = max(1, self.max_workers // 4)
            logger.warning(f"🔥 Critical resource usage: reduced workers to {self._adaptive_workers}")
        elif self.resource_level == ResourceLevel.HIGH or metrics.percentage > 75:
            self._adaptive_workers = max(2, self.max_workers // 2)
            logger.info(f"⚠️ High resource usage: reduced workers to {self._adaptive_workers}")
        elif self.resource_level == ResourceLevel.MEDIUM or metrics.percentage > 50:
            # Consider trend for medium usage
            if memory_trend > 5:  # Increasing memory usage
                self._adaptive_workers = max(2, int(self.max_workers * 0.6))
            else:
                self._adaptive_workers = max(2, int(self.max_workers * 0.75))
            logger.info(f"📊 Medium resource usage: adjusted workers to {self._adaptive_workers}")
        else:
            # Low resource usage - can increase workers if trend is stable
            if memory_trend < 2:  # Stable or decreasing
                self._adaptive_workers = min(self.max_workers, self._adaptive_workers + 1)
            else:
                self._adaptive_workers = self.max_workers
            logger.debug(f"✅ Low resource usage: workers set to {self._adaptive_workers}")

    def _optimize_plugin_execution_order(self, plugins: List[PluginMetadata]) -> List[PluginMetadata]:
        """PERFORMANCE OPTIMIZATION: Optimize plugin execution order based on historical performance."""
        if not self._plugin_performance_cache:
            return plugins  # No historical data available
        
        # Sort plugins by estimated execution time (fastest first for better parallelization)
        def get_estimated_time(plugin: PluginMetadata) -> float:
            if plugin.module_name in self._plugin_performance_cache:
                return self._plugin_performance_cache[plugin.module_name].get('avg_time', 10.0)
            return 10.0  # Default estimate for unknown plugins
        
        # Group plugins by estimated execution time
        fast_plugins = []  # < 5 seconds
        medium_plugins = []  # 5-30 seconds
        slow_plugins = []  # > 30 seconds
        
        for plugin in plugins:
            est_time = get_estimated_time(plugin)
            if est_time < 5:
                fast_plugins.append(plugin)
            elif est_time < 30:
                medium_plugins.append(plugin)
            else:
                slow_plugins.append(plugin)
        
        # Optimal execution order: fast plugins first (better parallelization), then medium, then slow
        optimized_order = fast_plugins + medium_plugins + slow_plugins
        
        if len(optimized_order) != len(plugins):
            logger.warning(f"⚠️ Plugin optimization changed count: {len(plugins)} -> {len(optimized_order)}")
            return plugins  # Fallback to original order
        
        logger.info(f"🚀 Optimized plugin execution order: {len(fast_plugins)} fast, {len(medium_plugins)} medium, {len(slow_plugins)} slow")
        return optimized_order

    def _update_plugin_performance_cache(self, plugin_name: str, execution_time: float, memory_used: float):
        """PERFORMANCE OPTIMIZATION: Update plugin performance cache for future optimizations."""
        if plugin_name not in self._plugin_performance_cache:
            self._plugin_performance_cache[plugin_name] = {
                'times': [],
                'memory_usage': [],
                'avg_time': 0.0,
                'avg_memory': 0.0
            }
        
        cache_entry = self._plugin_performance_cache[plugin_name]
        cache_entry['times'].append(execution_time)
        cache_entry['memory_usage'].append(memory_used)
        
        # Keep only last 10 executions for moving average
        if len(cache_entry['times']) > 10:
            cache_entry['times'].pop(0)
            cache_entry['memory_usage'].pop(0)
        
        # Update averages
        cache_entry['avg_time'] = sum(cache_entry['times']) / len(cache_entry['times'])
        cache_entry['avg_memory'] = sum(cache_entry['memory_usage']) / len(cache_entry['memory_usage'])
        
        logger.debug(f"📊 Updated performance cache for {plugin_name}: {cache_entry['avg_time']:.2f}s avg, {cache_entry['avg_memory']:.1f}MB avg")

    def _execute_plugin_safe(
        self, plugin_execution: PluginExecution, apk_ctx
    ) -> PluginExecution:
        """Execute a single plugin with error handling."""
        plugin_execution.start_time = time.time()
        
        # PERFORMANCE OPTIMIZATION: Track memory before execution
        initial_memory = self.memory_monitor.get_current_metrics().process_mb

        try:
            # Check memory before execution
            metrics = self.memory_monitor.get_current_metrics()
            if metrics.percentage > 90:
                plugin_execution.error = "Memory limit exceeded, execution skipped"
                plugin_execution.plugin.status = PluginStatus.SKIPPED
                return plugin_execution

            # Execute the plugin
            self.output_mgr.debug(
                f"Executing plugin in parallel: {plugin_execution.plugin.name}"
            )

            # Use the same execution logic as PluginManager
            plugin = plugin_execution.plugin

            # Determine function signature and call appropriately
            import inspect

            sig = inspect.signature(plugin.run_function)
            params = list(sig.parameters.keys())

            if len(params) >= 2 and "deep_mode" in params:
                result = plugin.run_function(apk_ctx, deep_mode=True)
            else:
                result = plugin.run_function(apk_ctx)

            # Validate result format
            if isinstance(result, tuple) and len(result) == 2:
                plugin_execution.result = result
            else:
                plugin_execution.result = (plugin.name, result)

            plugin_execution.plugin.status = PluginStatus.SUCCESS

        except Exception as e:
            error_msg = f"Plugin execution failed: {e}"
            plugin_execution.error = error_msg
            plugin_execution.plugin.status = PluginStatus.FAILED
            plugin_execution.result = (
                f"❌ {plugin_execution.plugin.name}",
                Text(f"Error: {error_msg}", style="red"),
            )

            logger.error(f"Plugin {plugin_execution.plugin.name} failed: {e}")

        finally:
            plugin_execution.end_time = time.time()
            
            # PERFORMANCE OPTIMIZATION: Track performance metrics
            execution_time = plugin_execution.end_time - plugin_execution.start_time
            final_memory = self.memory_monitor.get_current_metrics().process_mb
            memory_used = max(0, final_memory - initial_memory)
            
            # Update performance cache
            self._update_plugin_performance_cache(
                plugin_execution.plugin.module_name,
                execution_time,
                memory_used
            )

        return plugin_execution

    def _create_execution_plan(
        self, plugins: List[PluginMetadata]
    ) -> List[PluginExecution]:
        """Create optimized execution plan with dependencies."""
        # Analyze dependencies
        dependencies = self._analyze_plugin_dependencies(plugins)

        # Build dependency graph
        for plugin in plugins:
            plugin_deps = dependencies.get(plugin.module_name, set())
            self.dependency_graph.add_plugin(plugin.module_name, plugin_deps)

        # Create execution objects
        executions = []
        for plugin in plugins:
            priority = self._calculate_plugin_priority(plugin)
            execution = PluginExecution(
                plugin=plugin,
                priority=priority,
                dependencies=dependencies.get(plugin.module_name, set()),
            )
            executions.append(execution)

        return executions

    def execute_plugins_parallel(
        self, plugins: List[PluginMetadata], apk_ctx
    ) -> Dict[str, Tuple[str, Any]]:
        """
        Execute plugins in parallel with dependency management.

        Args:
            plugins: List of plugins to execute
            apk_ctx: APK context object

        Returns:
            Dictionary of plugin results
        """
        start_time = time.time()

        # Initialize stats
        with self._stats_lock:
            self.execution_stats.total_plugins = len(plugins)
            self.execution_stats.threads_used = min(self.max_workers, len(plugins))

        # Start memory monitoring
        self.memory_monitor.start_monitoring(interval=2)
        self.memory_monitor.add_callback(self._memory_callback)

        try:
            if self.execution_mode == ExecutionMode.SEQUENTIAL:
                return self._execute_sequential(plugins, apk_ctx)
            elif self.execution_mode == ExecutionMode.OPTIMIZED:
                return self._execute_optimized(plugins, apk_ctx)
            else:
                return self._execute_parallel(plugins, apk_ctx)

        finally:
            self.memory_monitor.stop_monitoring()

            # Finalize stats
            with self._stats_lock:
                self.execution_stats.total_execution_time = time.time() - start_time
                if self.execution_stats.completed_plugins > 0:
                    self.execution_stats.average_plugin_time = (
                        self.execution_stats.total_execution_time
                        / self.execution_stats.completed_plugins
                    )

    def _execute_sequential(
        self, plugins: List[PluginMetadata], apk_ctx
    ) -> Dict[str, Tuple[str, Any]]:
        """Execute plugins sequentially (fallback mode)."""
        self.output_mgr.info("Running plugins in sequential mode")
        results = {}

        for plugin in plugins:
            execution = PluginExecution(plugin=plugin, priority=0)
            execution = self._execute_plugin_safe(execution, apk_ctx)

            if execution.result:
                results[plugin.module_name] = execution.result

            with self._stats_lock:
                self.execution_stats.completed_plugins += 1
                if execution.error:
                    self.execution_stats.failed_plugins += 1

        return results

    def _execute_optimized(
        self, plugins: List[PluginMetadata], apk_ctx
    ) -> Dict[str, Tuple[str, Any]]:
        """Execute plugins using plugin scheduler with affinity-based optimization."""

        if not self.advanced_scheduler:
            # Fallback to parallel execution if scheduler not available
            self.output_mgr.warning(
                "Scheduler not available, falling back to parallel execution"
            )
            return self._execute_parallel(plugins, apk_ctx)

        self.output_mgr.info(
            f"Running plugins in optimized mode with {len(self.advanced_scheduler.worker_pools)} specialized pools"
        )

                    # Use scheduler for optimized execution
        def plugin_executor(plugin: PluginMetadata, apk_ctx) -> Tuple[str, Any]:
            """Execute individual plugin with proper error handling."""
            try:
                # Check memory before execution
                metrics = self.memory_monitor.get_current_metrics()
                if metrics.percentage > 90:
                    return (f"⚠️ {plugin.name}", "Execution skipped due to memory limit")

                # Execute the plugin using same logic as _execute_plugin_safe
                import inspect

                sig = inspect.signature(plugin.run_function)
                params = list(sig.parameters.keys())

                if len(params) >= 2 and "deep_mode" in params:
                    result = plugin.run_function(apk_ctx, deep_mode=True)
                else:
                    result = plugin.run_function(apk_ctx)

                # Validate result format
                if isinstance(result, tuple) and len(result) == 2:
                    return result
                else:
                    return (plugin.name, result)

            except Exception as e:
                logger.error(
                    f"Plugin {plugin.module_name} failed in optimized execution: {e}"
                )
                return (f"❌ {plugin.name}", f"Error: {e}")

                    # Execute with scheduler
        start_time = time.time()
        results = self.advanced_scheduler.schedule_plugins_optimized(
            plugins, apk_ctx, plugin_executor
        )
        execution_time = time.time() - start_time

        # Update execution statistics
        with self._stats_lock:
            self.execution_stats.completed_plugins = len(
                [r for r in results.values() if not r[0].startswith("❌")]
            )
            self.execution_stats.failed_plugins = len(
                [r for r in results.values() if r[0].startswith("❌")]
            )
            self.execution_stats.threads_used = sum(
                pool.max_workers
                for pool in self.advanced_scheduler.worker_pools.values()
            )

                    # Display scheduler optimization report
            optimization_report = self.advanced_scheduler.generate_optimization_report()
        self.output_mgr.console.print(optimization_report)

        # Display affinity grouping information
        self.output_mgr.info(
                            "Optimization complete with plugin affinity-based scheduling"
        )

        return results

    def _execute_parallel(
        self, plugins: List[PluginMetadata], apk_ctx
    ) -> Dict[str, Tuple[str, Any]]:
        """Execute plugins in parallel with dependency management."""
        
        # PERFORMANCE OPTIMIZATION: Optimize plugin execution order
        optimized_plugins = self._optimize_plugin_execution_order(plugins)
        
        self.output_mgr.info(
            f"Running plugins in parallel mode with {self._adaptive_workers} workers"
        )

        # Create execution plan
        executions = self._create_execution_plan(optimized_plugins)

        # Create a mapping for quick lookup
        execution_map = {ex.plugin.module_name: ex for ex in executions}

        # Track execution progress
        completed_plugins = set()
        results = {}

        # PERFORMANCE OPTIMIZATION: Dynamic thread pool management
        current_max_workers = self._adaptive_workers
        
        with ThreadPoolExecutor(max_workers=current_max_workers) as executor:
            # Submit initial ready plugins
            active_futures: Dict[Future, PluginExecution] = {}
            
            # PERFORMANCE OPTIMIZATION: Batch submission for better resource utilization
            batch_size = min(3, current_max_workers)  # Submit multiple plugins at once
            
            while len(completed_plugins) < len(plugins):
                # Adaptive worker adjustment
                if len(active_futures) < current_max_workers // 2:
                    self._adapt_worker_count()
                    # Note: We can't change ThreadPoolExecutor size dynamically,
                    # but we can limit submissions based on _adaptive_workers
                
                # Get plugins ready to execute
                ready_plugins = self.dependency_graph.get_ready_plugins()
                ready_plugins = [p for p in ready_plugins if p not in completed_plugins]

                # Submit ready plugins for execution (batch processing)
                submitted_count = 0
                for plugin_name in ready_plugins:
                    if plugin_name in execution_map and submitted_count < batch_size:
                        # Respect adaptive worker limit
                        if len(active_futures) >= self._adaptive_workers:
                            break
                            
                        execution = execution_map[plugin_name]
                        future = executor.submit(
                            self._execute_plugin_safe, execution, apk_ctx
                        )
                        active_futures[future] = execution
                        submitted_count += 1

                # Process completed futures
                if active_futures:
                    # Wait for at least one to complete (no timeout to avoid TimeoutError)
                    completed_futures = as_completed(active_futures)

                    for future in completed_futures:
                        try:
                            execution = future.result()
                            plugin_name = execution.plugin.module_name

                            # Store result
                            if execution.result:
                                with self._results_lock:
                                    results[plugin_name] = execution.result

                            # Mark as completed
                            completed_plugins.add(plugin_name)
                            self.dependency_graph.mark_completed(plugin_name)

                            # Update stats
                            with self._stats_lock:
                                self.execution_stats.completed_plugins += 1
                                if execution.error:
                                    self.execution_stats.failed_plugins += 1

                            # Remove from active futures
                            del active_futures[future]

                            # PERFORMANCE OPTIMIZATION: Log performance metrics
                            if execution.start_time and execution.end_time:
                                exec_time = execution.end_time - execution.start_time
                                self.output_mgr.debug(
                                    f"🚀 {plugin_name} completed in {exec_time:.2f}s "
                                    f"(workers: {len(active_futures)}/{self._adaptive_workers})"
                                )

                            break  # Process one completion at a time

                        except Exception as e:
                            logger.error(f"Future execution error: {e}")
                            # Remove failed future
                            if future in active_futures:
                                execution = active_futures[future]
                                plugin_name = execution.plugin.module_name

                                # Mark as completed even if failed
                                completed_plugins.add(plugin_name)
                                self.dependency_graph.mark_completed(plugin_name)

                                # Store error result
                                with self._results_lock:
                                    results[plugin_name] = (
                                        f"❌ {execution.plugin.name}",
                                        f"Error: {e}",
                                    )

                                # Update stats
                                with self._stats_lock:
                                    self.execution_stats.failed_plugins += 1

                                del active_futures[future]

                # Prevent busy waiting
                if not active_futures and not ready_plugins:
                    time.sleep(0.1)

        # PERFORMANCE OPTIMIZATION: Log final performance summary
        total_plugins = len(plugins)
        completed_count = self.execution_stats.completed_plugins
        failed_count = self.execution_stats.failed_plugins
        success_rate = (completed_count / total_plugins * 100) if total_plugins > 0 else 0
        
        self.output_mgr.info(
            f"🎯 Parallel execution completed: {completed_count}/{total_plugins} successful "
            f"({success_rate:.1f}% success rate, {failed_count} failed)"
        )

        return results

    def _memory_callback(self, level: str, metrics: MemoryMetrics):
        """Handle memory usage alerts during parallel execution."""
        self._update_resource_level(metrics)

        with self._stats_lock:
            self.execution_stats.memory_peak_mb = max(
                self.execution_stats.memory_peak_mb, metrics.process_mb
            )

        if level == "critical":
            logger.warning(
                f"Critical memory usage during parallel execution: {metrics.percentage:.1f}%"
            )
            # Force adaptive adjustment
            self._adapt_worker_count()

    def get_execution_statistics(self) -> ExecutionStats:
        """Get execution statistics."""
        with self._stats_lock:
            stats = ExecutionStats(
                total_plugins=self.execution_stats.total_plugins,
                completed_plugins=self.execution_stats.completed_plugins,
                failed_plugins=self.execution_stats.failed_plugins,
                memory_peak_mb=self.execution_stats.memory_peak_mb,
                total_execution_time=self.execution_stats.total_execution_time,
                average_plugin_time=self.execution_stats.average_plugin_time,
                threads_used=self.execution_stats.threads_used,
            )

            # Calculate parallel efficiency
            if (
                self.execution_stats.total_execution_time > 0
                and self.execution_stats.threads_used > 1
            ):
                theoretical_sequential_time = (
                    self.execution_stats.average_plugin_time
                    * self.execution_stats.completed_plugins
                )
                stats.parallel_efficiency = min(
                    1.0,
                    theoretical_sequential_time
                    / self.execution_stats.total_execution_time,
                )

            return stats

    def generate_performance_report(self) -> Table:
        """Generate performance report."""
        stats = self.get_execution_statistics()
        
        # Performance report
        table = Table(title="🚀 Parallel Execution Performance Report", show_header=True)
        table.add_column("Metric", style="bold cyan")
        table.add_column("Value", style="bold green")
        table.add_column("Optimization", style="bold yellow")
        
        # Basic statistics
        table.add_row("Total Plugins", str(stats.total_plugins), "✅ Optimized execution order")
        table.add_row("Completed", str(stats.completed_plugins), f"🎯 {(stats.completed_plugins/stats.total_plugins*100):.1f}% success rate")
        table.add_row("Failed", str(stats.failed_plugins), "Error handling")
        
        # Performance metrics
        table.add_row("Execution Time", f"{stats.total_execution_time:.2f}s", "⚡ Parallel processing")
        table.add_row("Average Plugin Time", f"{stats.average_plugin_time:.2f}s", "📊 Performance tracking")
        table.add_row("Peak Memory", f"{stats.memory_peak_mb:.1f}MB", "🧠 Memory optimization")
        
        # Parallel efficiency
        efficiency_str = f"{stats.parallel_efficiency:.1%}" if stats.parallel_efficiency > 0 else "N/A"
        table.add_row("Parallel Efficiency", efficiency_str, "🔄 Adaptive worker management")
        
        # Worker utilization
        table.add_row("Workers Used", f"{stats.threads_used}/{self.max_workers}", "⚙️ CPU core optimization")
        
        # Performance cache statistics
        cache_count = len(self._plugin_performance_cache)
        cache_status = "📈 Learning enabled" if cache_count > 0 else "🆕 Initial run"
        table.add_row("Performance Cache", f"{cache_count} plugins", cache_status)
        
        # Memory trend analysis
        if len(self._memory_utilization_history) > 1:
            memory_trend = self._memory_utilization_history[-1] - self._memory_utilization_history[0]
            trend_str = f"{memory_trend:+.1f}%" 
            trend_status = "📈 Increasing" if memory_trend > 0 else "📉 Stable/Decreasing"
            table.add_row("Memory Trend", trend_str, trend_status)
        
        # Execution mode
        mode_desc = {
            ExecutionMode.SEQUENTIAL: "🔄 Sequential execution",
            ExecutionMode.PARALLEL: "⚡ Parallel execution", 
            ExecutionMode.ADAPTIVE: "🧠 Adaptive optimization",
            ExecutionMode.OPTIMIZED: "🚀 Advanced optimization"
        }
        table.add_row("Execution Mode", self.execution_mode.value, mode_desc.get(self.execution_mode, "Unknown"))
        
        return table

# ==============================================================================
# UNIFIED EXECUTION FRAMEWORK INTEGRATION
# 
# The following code integrates the unified execution framework with the
# existing ParallelAnalysisEngine to eliminate duplication while maintaining
# full backward compatibility.
# ==============================================================================

def _migrate_to_unified_execution():
    """
    Check if unified execution framework is available and migrate if possible.
    
    Returns:
        tuple: (unified_available, unified_manager_or_none)
    """
    try:
        from core.execution import (
            UnifiedExecutionManager,
            ExecutionConfig,
            ExecutionMode as UnifiedMode,
            enhance_plugin_manager_with_unified_execution
        )
        
        # Create configuration that matches ParallelAnalysisEngine behavior
        config = ExecutionConfig(
            execution_mode=UnifiedMode.ADAPTIVE,
            enable_parallel_execution=True,
            enable_resource_monitoring=True,
            timeout_seconds=300
        )
        
        unified_manager = UnifiedExecutionManager(config)
        logger.info("✅ Unified execution framework available - using zero-duplication implementation")
        
        return True, unified_manager
        
    except ImportError:
        logger.info("ℹ️  Unified execution framework not available - using legacy ParallelAnalysisEngine")
        return False, None
    except Exception as e:
        logger.warning(f"⚠️  Failed to initialize unified execution: {e} - using legacy implementation")
        return False, None

# Check for unified execution on module load
_UNIFIED_AVAILABLE, _UNIFIED_MANAGER = _migrate_to_unified_execution()

def create_parallel_engine(
    max_workers: int = 4,
    memory_limit_gb: float = 8.0,
    execution_mode: ExecutionMode = ExecutionMode.ADAPTIVE
) -> Union[ParallelAnalysisEngine, 'UnifiedExecutionAdapter']:
    """
    Create parallel analysis engine with optional unified execution migration.
    
    This function now intelligently selects between:
    1. Unified execution framework (zero duplication, better performance)
    2. Legacy ParallelAnalysisEngine (fallback for compatibility)
    
    Args:
        max_workers: Maximum number of worker threads
        memory_limit_gb: Memory limit for parallel execution
        execution_mode: Execution mode
        
    Returns:
        ParallelAnalysisEngine or UnifiedExecutionAdapter
    """
    if _UNIFIED_AVAILABLE and _UNIFIED_MANAGER:
        # Return adapter that provides ParallelAnalysisEngine interface
        # using unified execution internally
        return UnifiedExecutionAdapter(_UNIFIED_MANAGER, max_workers, memory_limit_gb, execution_mode)
    else:
        # Fallback to legacy implementation
        return ParallelAnalysisEngine(max_workers, memory_limit_gb, execution_mode)

def enhance_plugin_manager_with_parallel_execution(
    plugin_manager: 'PluginManager', 
    parallel_engine: Optional[ParallelAnalysisEngine] = None
) -> 'PluginManager':
    """
    Enhanced version that uses unified execution when available.
    
    This function now:
    1. Tries to use unified execution framework for zero duplication
    2. Falls back to legacy parallel engine if unified not available
    3. Maintains full backward compatibility
    
    Args:
        plugin_manager: Existing PluginManager instance
        parallel_engine: Optional parallel engine
        
    Returns:
        Enhanced PluginManager
    """
    if _UNIFIED_AVAILABLE:
        try:
            # Use unified execution enhancement
            from core.execution import enhance_plugin_manager_with_unified_execution as unified_enhance
            return unified_enhance(plugin_manager)
        except ImportError:
            pass  # Fall through to legacy implementation
    
    # Legacy implementation for backward compatibility
    if parallel_engine is None:
        parallel_engine = create_parallel_engine()

    # Store original execute_all_plugins method
    original_execute = plugin_manager.execute_all_plugins

    def execute_all_plugins_parallel(apk_ctx):
        """Enhanced execute_all_plugins with parallel execution."""
        # Get executable plugins using original logic
        ordered_plugins = plugin_manager.plan_execution_order()

        if not ordered_plugins:
            plugin_manager.output_mgr.warning("No plugins available for execution")
            return {}

        # Use parallel engine for execution
        if parallel_engine.execution_mode == ExecutionMode.OPTIMIZED:
            plugin_manager.output_mgr.section_header(
                "Advanced Optimized Plugin Execution",
                f"Running {len(ordered_plugins)} plugins with {len(parallel_engine.advanced_scheduler.worker_pools)} specialized pools",
            )
        else:
            plugin_manager.output_mgr.section_header(
                "Parallel Plugin Execution",
                f"Running {len(ordered_plugins)} plugins with {parallel_engine._adaptive_workers} workers",
            )

        results = parallel_engine.execute_plugins_parallel(ordered_plugins, apk_ctx)

        # Update plugin statuses in the manager
        for plugin_name, _ in results.items():
            if plugin_name in plugin_manager.plugins:
                plugin_manager.plugins[plugin_name].status = PluginStatus.SUCCESS

        return results

    # Replace the method
    plugin_manager.execute_all_plugins = execute_all_plugins_parallel
    plugin_manager._parallel_engine = parallel_engine

    return plugin_manager

class UnifiedExecutionAdapter:
    """
    Adapter that provides ParallelAnalysisEngine interface using unified execution.
    
    This adapter eliminates code duplication by delegating to the unified execution
    framework while maintaining full API compatibility with existing code.
    """
    
    def __init__(self, unified_manager, max_workers: int, memory_limit_gb: float, execution_mode: ExecutionMode):
        """Initialize adapter with unified execution manager."""
        self.unified_manager = unified_manager
        self.max_workers = max_workers
        self.memory_limit_gb = memory_limit_gb
        self.execution_mode = execution_mode
        
        # Maintain compatibility attributes
        self.console = Console()
        self.output_mgr = get_output_manager()
        self.execution_stats = ExecutionStats()
        
        logger.info(f"🔄 Using unified execution adapter (eliminates duplication)")
    
    def execute_plugins_parallel(self, plugins: List[PluginMetadata], apk_ctx) -> Dict[str, Tuple[str, Any]]:
        """Execute plugins using unified execution framework."""
        try:
            # Convert execution mode
            mode_mapping = {
                ExecutionMode.SEQUENTIAL: "sequential", 
                ExecutionMode.PARALLEL: "parallel",
                ExecutionMode.ADAPTIVE: "adaptive",
                ExecutionMode.OPTIMIZED: "adaptive"
            }
            
            unified_mode = mode_mapping.get(self.execution_mode, "adaptive")
            
            # Execute using unified framework
            result = self.unified_manager.execute(plugins, apk_ctx, mode=unified_mode)
            
            # Update execution stats for compatibility
            self.execution_stats.total_plugins = result.total_plugins
            self.execution_stats.completed_plugins = result.successful_plugins
            self.execution_stats.failed_plugins = result.failed_plugins
            self.execution_stats.total_execution_time = result.execution_time
            
            # Return results in expected format
            return result.results
            
        except Exception as e:
            logger.error(f"Unified execution failed: {e}")
            # In case of failure, we can't fall back to legacy since we don't have it here
            # Return empty results with error indication
            return {
                "unified_execution_error": (
                    "❌ Unified Execution Error", 
                    f"Execution failed: {e}"
                )
            }
    
    def get_execution_statistics(self) -> Dict[str, Any]:
        """Get execution statistics."""
        return self.unified_manager.get_execution_statistics()
    
    # Compatibility methods
    def _assess_resource_level(self) -> ResourceLevel:
        """Assess current resource level for compatibility."""
        return ResourceLevel.MEDIUM  # Default safe value
    
    def _update_adaptive_workers(self):
        """Update adaptive workers for compatibility."""
        pass  # No-op since unified framework handles this internally

if __name__ == "__main__":
    # Example usage and testing
    engine = create_parallel_engine(
        max_workers=4, execution_mode=ExecutionMode.ADAPTIVE
    )
    print(f"Parallel Analysis Engine created with {engine.max_workers} workers")
    print(f"Memory limit: {engine.memory_limit_gb}GB")
    print(f"Execution mode: {engine.execution_mode.value}")
