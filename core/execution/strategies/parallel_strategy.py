#!/usr/bin/env python3
"""
Parallel Execution Strategy

Thread-based parallel plugin execution strategy consolidating logic from:
- ParallelAnalysisEngine
- Individual plugin ThreadPoolExecutor implementations
- Enhanced parallel execution systems
"""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Any, Dict, List, Optional, Tuple

from .base_strategy import ExecutionStrategy, StrategyResult
from ..shared.plugin_executor import PluginExecutor, PluginExecutionResult, PluginStatus
from ..shared.config_manager import ExecutionConfig

logger = logging.getLogger(__name__)

class ParallelExecutionStrategy(ExecutionStrategy):
    """
    Thread-based parallel execution strategy.
    
    Consolidates parallel execution logic from multiple systems while
    eliminating code duplication.
    """
    
    def __init__(self, config: ExecutionConfig, plugin_executor: PluginExecutor):
        """Initialize parallel execution strategy."""
        super().__init__(config, plugin_executor)
        self.strategy_name = "Parallel"
        
        # Parallel execution state
        self._active_futures: Dict[Future, Any] = {}
        self._execution_lock = threading.RLock()
        
        logger.info(f"Parallel execution strategy initialized with {self.config.max_workers} workers")
    
    def can_execute(self, plugins: List[Any], context: Dict[str, Any]) -> bool:
        """Check if parallel execution is suitable for the given plugins."""
        # Don't use parallel for very few plugins
        if len(plugins) < self.config.parallel_threshold_plugins:
            return False
        
        # Check system resources
        if not self.config.enable_parallel_execution:
            return False
        
        # Check for plugins that require sequential execution
        sequential_plugins = self._count_sequential_only_plugins(plugins)
        if sequential_plugins > len(plugins) * 0.7:  # More than 70% require sequential
            return False
        
        return True
    
    def execute(self, plugins: List[Any], apk_ctx: Any, 
               context: Optional[Dict[str, Any]] = None) -> StrategyResult:
        """
        Execute plugins in parallel using thread pool.
        
        Args:
            plugins: List of plugins to execute
            apk_ctx: APK context for analysis
            context: Additional execution context
            
        Returns:
            StrategyResult with execution details
        """
        start_time = time.time()
        context = context or {}
        
        self.logger.info(f"Starting parallel execution of {len(plugins)} plugins")
        
        # Create strategy result
        result = StrategyResult(
            strategy_name=self.strategy_name,
            total_plugins=len(plugins),
            start_time=start_time
        )
        
        try:
            # Filter plugins for parallel execution
            parallel_plugins, sequential_plugins = self._categorize_plugins(plugins)
            
            # Execute parallel plugins
            if parallel_plugins:
                parallel_results = self._execute_parallel_plugins(parallel_plugins, apk_ctx)
                result.plugin_results.update(parallel_results)
            
            # Execute sequential plugins (if any)
            if sequential_plugins:
                self.logger.info(f"Executing {len(sequential_plugins)} plugins sequentially")
                sequential_results = self._execute_sequential_plugins(sequential_plugins, apk_ctx)
                result.plugin_results.update(sequential_results)
            
            # Calculate final statistics
            result.execution_time = time.time() - start_time
            result.successful_plugins = sum(1 for r in result.plugin_results.values() if r.success)
            result.failed_plugins = sum(1 for r in result.plugin_results.values() if r.failed)
            result.success = result.failed_plugins == 0
            
            self.logger.info(f"Parallel execution completed in {result.execution_time:.2f}s "
                           f"({result.successful_plugins}/{result.total_plugins} successful)")
            
        except Exception as e:
            result.execution_time = time.time() - start_time
            result.error = str(e)
            result.success = False
            self.logger.error(f"Parallel execution failed: {e}")
        
        return result
    
    def _execute_parallel_plugins(self, plugins: List[Any], apk_ctx: Any) -> Dict[str, PluginExecutionResult]:
        """Execute plugins in parallel using thread pool."""
        results = {}
        
        # Determine optimal worker count
        max_workers = min(self.config.max_workers, len(plugins))
        
        with ThreadPoolExecutor(max_workers=max_workers, 
                               thread_name_prefix="AODS-Parallel") as executor:
            
            # Submit all plugins for execution
            future_to_plugin = {}
            for plugin in plugins:
                future = executor.submit(self._execute_single_plugin, plugin, apk_ctx)
                future_to_plugin[future] = plugin
            
            # Collect results as they complete
            with self._execution_lock:
                self._active_futures = future_to_plugin.copy()
            
            for future in as_completed(future_to_plugin):
                plugin = future_to_plugin[future]
                plugin_name = self.plugin_executor._get_plugin_name(plugin)
                
                try:
                    plugin_result = future.result()
                    results[plugin_name] = plugin_result
                    
                    self.logger.debug(f"Plugin '{plugin_name}' completed: {plugin_result.status.value}")
                    
                except Exception as e:
                    # Create error result for failed plugin
                    error_result = PluginExecutionResult(
                        plugin_name=plugin_name,
                        status=PluginStatus.FAILED,
                        error=str(e),
                        result=self.plugin_executor._create_error_result(plugin_name, str(e))
                    )
                    results[plugin_name] = error_result
                    self.logger.error(f"Plugin '{plugin_name}' failed in parallel execution: {e}")
                
                # Remove from active futures
                with self._execution_lock:
                    if future in self._active_futures:
                        del self._active_futures[future]
        
        return results
    
    def _execute_sequential_plugins(self, plugins: List[Any], apk_ctx: Any) -> Dict[str, PluginExecutionResult]:
        """Execute plugins sequentially (for those that can't run in parallel)."""
        results = {}
        
        for plugin in plugins:
            plugin_name = self.plugin_executor._get_plugin_name(plugin)
            try:
                plugin_result = self._execute_single_plugin(plugin, apk_ctx)
                results[plugin_name] = plugin_result
                
                self.logger.debug(f"Sequential plugin '{plugin_name}' completed: {plugin_result.status.value}")
                
            except Exception as e:
                error_result = PluginExecutionResult(
                    plugin_name=plugin_name,
                    status=PluginStatus.FAILED,
                    error=str(e),
                    result=self.plugin_executor._create_error_result(plugin_name, str(e))
                )
                results[plugin_name] = error_result
                self.logger.error(f"Sequential plugin '{plugin_name}' failed: {e}")
        
        return results
    
    def _execute_single_plugin(self, plugin: Any, apk_ctx: Any) -> PluginExecutionResult:
        """Execute a single plugin using the unified plugin executor."""
        return self.plugin_executor.execute_plugin(plugin, apk_ctx)
    
    def _categorize_plugins(self, plugins: List[Any]) -> Tuple[List[Any], List[Any]]:
        """
        Categorize plugins into parallel-safe and sequential-only.
        
        Returns:
            Tuple of (parallel_plugins, sequential_plugins)
        """
        parallel_plugins = []
        sequential_plugins = []
        
        for plugin in plugins:
            if self._is_plugin_parallel_safe(plugin):
                parallel_plugins.append(plugin)
            else:
                sequential_plugins.append(plugin)
        
        return parallel_plugins, sequential_plugins
    
    def _is_plugin_parallel_safe(self, plugin: Any) -> bool:
        """Check if plugin is safe for parallel execution."""
        plugin_name = self.plugin_executor._get_plugin_name(plugin).lower()
        
        # Plugins that should run sequentially
        sequential_patterns = [
            'anti_tampering',     # May interfere with other plugins
            'root_detection',     # Device state dependent
            'device_manager',     # Device access conflicts
        ]
        
        # Check if plugin explicitly supports parallel execution
        if hasattr(plugin, 'supports_parallel'):
            return getattr(plugin, 'supports_parallel', True)
        
        # Check for sequential-only patterns
        for pattern in sequential_patterns:
            if pattern in plugin_name:
                return False
        
        # Default to parallel-safe
        return True
    
    def _count_sequential_only_plugins(self, plugins: List[Any]) -> int:
        """Count plugins that require sequential execution."""
        count = 0
        for plugin in plugins:
            if not self._is_plugin_parallel_safe(plugin):
                count += 1
        return count
    
    def get_active_executions(self) -> Dict[str, Dict[str, Any]]:
        """Get information about currently active plugin executions."""
        with self._execution_lock:
            active_info = {}
            for future, plugin in self._active_futures.items():
                plugin_name = self.plugin_executor._get_plugin_name(plugin)
                active_info[plugin_name] = {
                    'running': future.running(),
                    'done': future.done(),
                    'cancelled': future.cancelled()
                }
            return active_info
    
    def cancel_execution(self) -> bool:
        """Cancel all active plugin executions."""
        cancelled_count = 0
        
        with self._execution_lock:
            for future in list(self._active_futures.keys()):
                if future.cancel():
                    cancelled_count += 1
        
        self.logger.info(f"Cancelled {cancelled_count} active plugin executions")
        return cancelled_count > 0 