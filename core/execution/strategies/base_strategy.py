#!/usr/bin/env python3
"""
Base Execution Strategy

Abstract base class defining the common interface for all execution strategies.
Provides shared functionality to eliminate duplication across strategies.
"""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..shared.config_manager import ExecutionConfig
from ..shared.plugin_executor import PluginExecutor, PluginExecutionResult

logger = logging.getLogger(__name__)

@dataclass
class StrategyResult:
    """
    Result from strategy execution.
    
    Standardized result format used by all execution strategies.
    """
    strategy_name: str
    success: bool = False
    execution_time: float = 0.0
    total_plugins: int = 0
    successful_plugins: int = 0
    failed_plugins: int = 0
    plugin_results: Dict[str, PluginExecutionResult] = field(default_factory=dict)
    error: Optional[str] = None
    statistics: Dict[str, Any] = field(default_factory=dict)
    start_time: Optional[float] = None

class ExecutionStrategy(ABC):
    """
    Abstract base class for all execution strategies.
    
    Defines the common interface and provides shared functionality
    to eliminate code duplication across different execution approaches.
    """
    
    def __init__(self, config: ExecutionConfig, plugin_executor: PluginExecutor):
        """
        Initialize execution strategy.
        
        Args:
            config: Unified execution configuration
            plugin_executor: Shared plugin executor (eliminates duplication)
        """
        self.config = config
        self.plugin_executor = plugin_executor
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Strategy identification
        self.strategy_name = self.__class__.__name__.replace('ExecutionStrategy', '')
        
        # Execution statistics
        self._total_executions = 0
        self._successful_executions = 0
        self._failed_executions = 0
        self._total_execution_time = 0.0
        
        self.logger.info(f"{self.strategy_name} execution strategy initialized")
    
    @abstractmethod
    def can_execute(self, plugins: List[Any], context: Dict[str, Any]) -> bool:
        """
        Check if this strategy can execute the given plugins.
        
        Args:
            plugins: List of plugins to execute
            context: Additional execution context
            
        Returns:
            True if strategy can handle the execution
        """
        pass
    
    @abstractmethod
    def execute(self, plugins: List[Any], apk_ctx: Any, 
               context: Optional[Dict[str, Any]] = None) -> StrategyResult:
        """
        Execute plugins using this strategy.
        
        Args:
            plugins: List of plugins to execute
            apk_ctx: APK context for analysis
            context: Additional execution context
            
        Returns:
            StrategyResult with execution details
        """
        pass
    
    def get_strategy_info(self) -> Dict[str, Any]:
        """Get information about this strategy."""
        return {
            'name': self.strategy_name,
            'total_executions': self._total_executions,
            'successful_executions': self._successful_executions,
            'failed_executions': self._failed_executions,
            'success_rate': self._get_success_rate(),
            'average_execution_time': self._get_average_execution_time()
        }
    
    def _record_execution(self, result: StrategyResult):
        """Record execution statistics."""
        self._total_executions += 1
        self._total_execution_time += result.execution_time
        
        if result.success:
            self._successful_executions += 1
        else:
            self._failed_executions += 1
    
    def _get_success_rate(self) -> float:
        """Calculate success rate for this strategy."""
        if self._total_executions == 0:
            return 0.0
        return self._successful_executions / self._total_executions
    
    def _get_average_execution_time(self) -> float:
        """Calculate average execution time for this strategy."""
        if self._successful_executions == 0:
            return 0.0
        return self._total_execution_time / self._successful_executions
    
    def _validate_plugins(self, plugins: List[Any]) -> List[Any]:
        """
        Validate and filter plugins for execution.
        
        Args:
            plugins: List of plugins to validate
            
        Returns:
            List of valid plugins
        """
        valid_plugins = []
        
        for plugin in plugins:
            if self._is_plugin_valid(plugin):
                valid_plugins.append(plugin)
            else:
                plugin_name = self.plugin_executor._get_plugin_name(plugin)
                self.logger.warning(f"Skipping invalid plugin: {plugin_name}")
        
        return valid_plugins
    
    def _is_plugin_valid(self, plugin: Any) -> bool:
        """
        Check if a plugin is valid for execution.
        
        Args:
            plugin: Plugin to validate
            
        Returns:
            True if plugin is valid
        """
        # Check if plugin has executable method
        if callable(plugin):
            return True
        
        # Check for common plugin execution methods
        execution_methods = ['run_function', 'run', 'run_plugin', 'execute']
        
        for method in execution_methods:
            if hasattr(plugin, method) and callable(getattr(plugin, method)):
                return True
        
        return False
    
    def _create_result_template(self, plugins: List[Any], start_time: float) -> StrategyResult:
        """
        Create a result template for tracking execution progress.
        
        Args:
            plugins: List of plugins being executed
            start_time: Execution start time
            
        Returns:
            StrategyResult template
        """
        return StrategyResult(
            strategy_name=self.strategy_name,
            total_plugins=len(plugins),
            start_time=start_time
        )
    
    def _finalize_result(self, result: StrategyResult) -> StrategyResult:
        """
        Finalize result with calculated statistics.
        
        Args:
            result: Result to finalize
            
        Returns:
            Finalized result
        """
        # Calculate final statistics
        if result.start_time:
            result.execution_time = time.time() - result.start_time
        
        result.successful_plugins = sum(1 for r in result.plugin_results.values() if r.success)
        result.failed_plugins = sum(1 for r in result.plugin_results.values() if r.failed)
        result.success = result.failed_plugins == 0 and result.successful_plugins > 0
        
        # Add detailed statistics
        result.statistics = {
            'strategy_name': self.strategy_name,
            'total_plugins': result.total_plugins,
            'successful_plugins': result.successful_plugins,
            'failed_plugins': result.failed_plugins,
            'success_rate': result.successful_plugins / result.total_plugins if result.total_plugins > 0 else 0.0,
            'execution_time': result.execution_time,
            'average_plugin_time': result.execution_time / result.successful_plugins if result.successful_plugins > 0 else 0.0
        }
        
        # Record for strategy statistics
        self._record_execution(result)
        
        return result 