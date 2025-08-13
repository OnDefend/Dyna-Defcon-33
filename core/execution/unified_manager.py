#!/usr/bin/env python3
"""
Unified Execution Manager

Main orchestrator for all execution strategies, providing a single entry point
that eliminates duplication while preserving all execution modes.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from .shared.config_manager import ConfigurationManager, ExecutionConfig, ExecutionMode
from .shared.plugin_executor import PluginExecutor, PluginExecutionResult
from .shared.timeout_manager import TimeoutManager
from .strategies.base_strategy import ExecutionStrategy, StrategyResult
from .strategies.parallel_strategy import ParallelExecutionStrategy
from .strategies.sequential_strategy import SequentialExecutionStrategy
from .strategies.process_strategy import ProcessSeparationStrategy
from .strategies.adaptive_strategy import AdaptiveExecutionStrategy

logger = logging.getLogger(__name__)

@dataclass
class ExecutionResult:
    """Result of unified execution."""
    strategy_used: str
    total_plugins: int
    successful_plugins: int
    failed_plugins: int
    execution_time: float
    results: Dict[str, Any]
    success: bool
    error: Optional[str] = None
    statistics: Dict[str, Any] = field(default_factory=dict)

@dataclass 
class ExecutionContext:
    """Context for plugin execution."""
    apk_ctx: Any
    mode: ExecutionMode
    additional_context: Dict[str, Any] = field(default_factory=dict)

class UnifiedExecutionManager:
    """
    Unified execution manager providing single entry point for all execution modes.
    
    This manager eliminates duplication by:
    - Using shared components (timeout, resource monitoring, etc.)
    - Providing strategy-based execution (parallel, process, sequential, adaptive)
    - Maintaining full backward compatibility with existing interfaces
    - Offering consistent configuration and error handling
    """
    
    def __init__(self, config: Optional[ExecutionConfig] = None):
        """Initialize unified execution manager."""
        self.config_manager = ConfigurationManager(config)
        self.config = self.config_manager.get_config()
        self.logger = logging.getLogger(__name__)
        
        # Initialize shared components (eliminates duplication)
        self.timeout_manager = TimeoutManager()
        self.plugin_executor = PluginExecutor(self.timeout_manager)
        
        # Initialize execution strategies
        self.strategies = self._initialize_strategies()
        
        # Execution state
        self.current_execution: Optional[StrategyResult] = None
        self._execution_history: List[ExecutionResult] = []
        
        self.logger.info(f"Unified execution manager initialized with {len(self.strategies)} strategies")
    
    def _initialize_strategies(self) -> Dict[str, ExecutionStrategy]:
        """Initialize all available execution strategies."""
        strategies = {}
        
        try:
            strategies[ExecutionMode.PARALLEL.value] = ParallelExecutionStrategy(
                self.config, self.plugin_executor
            )
            logger.debug("Parallel strategy initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize parallel strategy: {e}")
        
        try:
            strategies[ExecutionMode.SEQUENTIAL.value] = SequentialExecutionStrategy(
                self.config, self.plugin_executor  
            )
            logger.debug("Sequential strategy initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize sequential strategy: {e}")
        
        try:
            strategies[ExecutionMode.PROCESS_SEPARATED.value] = ProcessSeparationStrategy(
                self.config, self.plugin_executor
            )
            logger.debug("Process separation strategy initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize process separation strategy: {e}")
        
        try:
            strategies[ExecutionMode.ADAPTIVE.value] = AdaptiveExecutionStrategy(
                self.config, self.plugin_executor
            )
            logger.debug("Adaptive strategy initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize adaptive strategy: {e}")
        
        logger.info(f"Initialized {len(strategies)} execution strategies")
        return strategies
    
    def execute(self, plugins: List[Any], apk_ctx: Any, 
               mode: Optional[Union[str, ExecutionMode]] = None,
               **kwargs) -> ExecutionResult:
        """
        Execute plugins using the unified execution framework.
        
        Args:
            plugins: List of plugins to execute
            apk_ctx: APK context for analysis
            mode: Execution mode (parallel, process_separated, sequential, adaptive)
            **kwargs: Additional execution parameters
            
        Returns:
            ExecutionResult with comprehensive execution details
        """
        start_time = time.time()
        
        # Normalize execution mode
        if mode is None:
            execution_mode = self.config.execution_mode
        elif isinstance(mode, str):
            execution_mode = ExecutionMode(mode.lower())
        else:
            execution_mode = mode
        
        self.logger.info(f"Starting unified execution: {len(plugins)} plugins, mode={execution_mode.value}")
        
        # Create execution context
        context = ExecutionContext(
            apk_ctx=apk_ctx,
            mode=execution_mode,
            additional_context=kwargs
        )
        
        # Select execution strategy
        strategy = self._select_strategy(execution_mode, plugins, context)
        if not strategy:
            # Fallback to any available strategy
            if self.strategies:
                strategy_name = list(self.strategies.keys())[0]
                strategy = self.strategies[strategy_name]
                self.logger.warning(f"Requested mode {execution_mode.value} unavailable, using {strategy_name}")
            else:
                raise RuntimeError("No execution strategies available")
        
        # Execute using selected strategy
        try:
            strategy_result = strategy.execute(plugins, apk_ctx, context.additional_context)
            self.current_execution = strategy_result
            
            # Convert to unified result format
            result = ExecutionResult(
                strategy_used=strategy_result.strategy_name,
                total_plugins=strategy_result.total_plugins,
                successful_plugins=strategy_result.successful_plugins,
                failed_plugins=strategy_result.failed_plugins,
                execution_time=strategy_result.execution_time,
                results=self._convert_plugin_results(strategy_result.plugin_results),
                success=strategy_result.success,
                error=strategy_result.error,
                statistics=self._gather_execution_statistics(strategy_result)
            )
            
            # Record in history
            self._execution_history.append(result)
            
            self.logger.info(f"Execution completed: {result.strategy_used}, "
                           f"{result.successful_plugins}/{result.total_plugins} successful, "
                           f"{result.execution_time:.2f}s")
            
            return result
            
        except Exception as e:
            error_result = ExecutionResult(
                strategy_used=strategy.strategy_name if strategy else "unknown",
                total_plugins=len(plugins),
                successful_plugins=0,
                failed_plugins=len(plugins),
                execution_time=time.time() - start_time,
                results={},
                success=False,
                error=str(e)
            )
            
            self.logger.error(f"Execution failed: {e}")
            return error_result
    
    def _select_strategy(self, mode: ExecutionMode, plugins: List[Any], 
                        context: ExecutionContext) -> Optional[ExecutionStrategy]:
        """Select execution strategy based on mode and context."""
        
        # Direct mode selection
        if mode.value in self.strategies:
            strategy = self.strategies[mode.value]
            
            # Check if strategy can handle the plugins
            if strategy.can_execute(plugins, context.additional_context):
                return strategy
            else:
                self.logger.warning(f"Strategy {mode.value} cannot handle current plugins")
        
        # Fallback selection for adaptive mode or failed direct selection
        suitable_strategies = []
        for strategy_name, strategy in self.strategies.items():
            if strategy.can_execute(plugins, context.additional_context):
                suitable_strategies.append((strategy_name, strategy))
        
        if suitable_strategies:
            # Prefer adaptive if available and requested
            if mode == ExecutionMode.ADAPTIVE:
                for name, strategy in suitable_strategies:
                    if name == ExecutionMode.ADAPTIVE.value:
                        return strategy
            
            # Return first suitable strategy
            return suitable_strategies[0][1]
        
        return None
    
    def _convert_plugin_results(self, plugin_results: Dict[str, PluginExecutionResult]) -> Dict[str, Any]:
        """Convert plugin execution results to legacy format."""
        converted = {}
        for plugin_name, result in plugin_results.items():
            if hasattr(result, 'result') and result.result:
                converted[plugin_name] = result.result
            else:
                # Create tuple format for compatibility
                status = "✅" if result.success else "❌"
                converted[plugin_name] = (f"{status} {plugin_name}", result.error or "Unknown result")
        return converted
    
    def _gather_execution_statistics(self, strategy_result: StrategyResult) -> Dict[str, Any]:
        """Gather comprehensive execution statistics."""
        stats = {
            'strategy_name': strategy_result.strategy_name,
            'execution_time': strategy_result.execution_time,
            'success_rate': strategy_result.successful_plugins / strategy_result.total_plugins if strategy_result.total_plugins > 0 else 0,
            'plugin_breakdown': {
                'total': strategy_result.total_plugins,
                'successful': strategy_result.successful_plugins,
                'failed': strategy_result.failed_plugins
            }
        }
        
        # Add strategy-specific characteristics
        if hasattr(strategy_result, 'get_execution_characteristics'):
            stats['strategy_characteristics'] = strategy_result.get_execution_characteristics()
        
        return stats
    
    def get_execution_statistics(self) -> Dict[str, Any]:
        """Get comprehensive execution statistics."""
        if not self._execution_history:
            return {
                'total_executions': 0,
                'strategy_usage': {},
                'average_execution_time': 0.0,
                'overall_success_rate': 0.0
            }
        
        # Calculate strategy usage
        strategy_usage = {}
        total_time = 0.0
        total_success = 0
        total_plugins = 0
        
        for execution in self._execution_history:
            strategy = execution.strategy_used
            strategy_usage[strategy] = strategy_usage.get(strategy, 0) + 1
            total_time += execution.execution_time
            total_success += execution.successful_plugins
            total_plugins += execution.total_plugins
        
        return {
            'total_executions': len(self._execution_history),
            'strategy_usage': strategy_usage,
            'average_execution_time': total_time / len(self._execution_history),
            'overall_success_rate': total_success / total_plugins if total_plugins > 0 else 0.0,
            'available_strategies': list(self.strategies.keys())
        }
    
    def get_strategy_details(self, strategy_name: str) -> Dict[str, Any]:
        """Get detailed information about a specific strategy."""
        if strategy_name not in self.strategies:
            return {'error': f'Strategy {strategy_name} not available'}
        
        strategy = self.strategies[strategy_name]
        details = {
            'name': strategy_name,
            'class': strategy.__class__.__name__,
            'available': True
        }
        
        # Get strategy characteristics if available
        if hasattr(strategy, 'get_execution_characteristics'):
            details['characteristics'] = strategy.get_execution_characteristics()
        
        # Get strategy-specific statistics if available (for adaptive strategy)
        if hasattr(strategy, 'get_strategy_statistics'):
            details['statistics'] = strategy.get_strategy_statistics()
        
        return details
    
    def shutdown(self):
        """Cleanup and shutdown execution manager."""
        self.logger.info("Shutting down unified execution manager...")
        
        # Cleanup strategies
        for strategy in self.strategies.values():
            if hasattr(strategy, 'cleanup'):
                try:
                    strategy.cleanup()
                except Exception as e:
                    self.logger.warning(f"Error cleaning up strategy: {e}")
        
        # Clear state
        self.current_execution = None
        self._execution_history.clear()
        
        self.logger.info("Unified execution manager shutdown complete")
    
    # Backward compatibility methods
    def execute_plugins_parallel(self, plugins: List[Any], apk_ctx: Any) -> Dict[str, Any]:
        """Backward compatibility method for parallel execution."""
        result = self.execute(plugins, apk_ctx, mode=ExecutionMode.PARALLEL)
        return result.results
    
    def execute_plugins_sequential(self, plugins: List[Any], apk_ctx: Any) -> Dict[str, Any]:
        """Backward compatibility method for sequential execution.""" 
        result = self.execute(plugins, apk_ctx, mode=ExecutionMode.SEQUENTIAL)
        return result.results

def create_execution_manager(config: Optional[ExecutionConfig] = None) -> UnifiedExecutionManager:
    """Factory function to create unified execution manager."""
    return UnifiedExecutionManager(config) 