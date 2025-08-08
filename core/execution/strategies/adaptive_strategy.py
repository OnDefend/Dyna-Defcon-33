#!/usr/bin/env python3
"""
Adaptive Execution Strategy

Intelligent execution strategy that automatically selects the optimal
execution approach based on:
- System resources and capabilities
- Plugin characteristics and requirements
- Execution context and constraints
- Historical performance data
"""

import logging
import psutil
import time
from typing import Any, Dict, List, Optional, Type

from .base_strategy import ExecutionStrategy, StrategyResult
from .parallel_strategy import ParallelExecutionStrategy
from .sequential_strategy import SequentialExecutionStrategy
from .process_strategy import ProcessSeparationStrategy
from ..shared.plugin_executor import PluginExecutor
from ..shared.config_manager import ExecutionConfig

logger = logging.getLogger(__name__)

class AdaptiveExecutionStrategy(ExecutionStrategy):
    """
    Adaptive execution strategy that intelligently selects execution approach.
    
    This strategy analyzes the execution context and automatically chooses
    the most appropriate execution strategy from available options.
    """
    
    def __init__(self, config: ExecutionConfig, plugin_executor: PluginExecutor):
        """Initialize adaptive execution strategy."""
        super().__init__(config, plugin_executor)
        self.strategy_name = "Adaptive"
        
        # Initialize available strategies
        self.available_strategies = self._initialize_strategies()
        
        # Performance history for learning
        self.performance_history: List[Dict[str, Any]] = []
        
        # System capabilities
        self.system_info = self._analyze_system_capabilities()
        
        logger.info(f"Adaptive execution strategy initialized with {len(self.available_strategies)} strategies")
    
    def _initialize_strategies(self) -> Dict[str, ExecutionStrategy]:
        """Initialize all available execution strategies."""
        strategies = {}
        
        try:
            strategies['parallel'] = ParallelExecutionStrategy(self.config, self.plugin_executor)
            logger.debug("Parallel strategy available")
        except Exception as e:
            logger.warning(f"Parallel strategy unavailable: {e}")
        
        try:
            strategies['sequential'] = SequentialExecutionStrategy(self.config, self.plugin_executor)
            logger.debug("Sequential strategy available")
        except Exception as e:
            logger.warning(f"Sequential strategy unavailable: {e}")
        
        try:
            strategies['process_separation'] = ProcessSeparationStrategy(self.config, self.plugin_executor)
            logger.debug("Process separation strategy available")
        except Exception as e:
            logger.warning(f"Process separation strategy unavailable: {e}")
        
        return strategies
    
    def _analyze_system_capabilities(self) -> Dict[str, Any]:
        """Analyze system capabilities for decision making."""
        try:
            return {
                'cpu_count': psutil.cpu_count(),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_total': psutil.virtual_memory().total / (1024**3),  # GB
                'memory_available': psutil.virtual_memory().available / (1024**3),  # GB
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else (0, 0, 0)
            }
        except Exception as e:
            logger.warning(f"Could not analyze system capabilities: {e}")
            return {
                'cpu_count': 4,
                'memory_total': 8.0,
                'memory_available': 4.0,
                'memory_percent': 50.0
            }
    
    def can_execute(self, plugins: List[Any], context: Dict[str, Any]) -> bool:
        """Adaptive strategy can always execute if any child strategy can."""
        return len(self.available_strategies) > 0
    
    def execute(self, plugins: List[Any], apk_ctx: Any, 
               context: Optional[Dict[str, Any]] = None) -> StrategyResult:
        """
        Execute plugins using adaptively selected strategy.
        
        Args:
            plugins: List of plugins to execute
            apk_ctx: APK context for analysis
            context: Additional execution context
            
        Returns:
            StrategyResult with execution details
        """
        start_time = time.time()
        context = context or {}
        
        self.logger.info(f"Starting adaptive execution of {len(plugins)} plugins")
        
        # Analyze execution context
        execution_context = self._analyze_execution_context(plugins, context)
        
        # Select optimal strategy
        selected_strategy_name, selected_strategy = self._select_optimal_strategy(execution_context)
        
        self.logger.info(f"Selected strategy: {selected_strategy_name}")
        
        # Execute using selected strategy
        result = selected_strategy.execute(plugins, apk_ctx, context)
        
        # Update strategy name to reflect adaptive selection
        result.strategy_name = f"Adaptive({selected_strategy_name})"
        
        # Record performance for learning
        self._record_performance(execution_context, selected_strategy_name, result)
        
        self.logger.info(f"Adaptive execution completed using {selected_strategy_name} "
                        f"in {result.execution_time:.2f}s")
        
        return result
    
    def _analyze_execution_context(self, plugins: List[Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze execution context for strategy selection."""
        # Refresh system info
        current_system = self._analyze_system_capabilities()
        
        # Analyze plugin characteristics
        plugin_analysis = self._analyze_plugins(plugins)
        
        # Combine all context information
        execution_context = {
            'plugin_count': len(plugins),
            'system_info': current_system,
            'plugin_analysis': plugin_analysis,
            'user_context': context,
            'timestamp': time.time()
        }
        
        return execution_context
    
    def _analyze_plugins(self, plugins: List[Any]) -> Dict[str, Any]:
        """Analyze plugin characteristics for strategy selection."""
        analysis = {
            'total_plugins': len(plugins),
            'static_plugins': 0,
            'dynamic_plugins': 0,
            'heavy_plugins': 0,
            'sequential_only_plugins': 0,
            'estimated_complexity': 'medium'
        }
        
        # Analyze each plugin
        for plugin in plugins:
            plugin_name = self.plugin_executor._get_plugin_name(plugin).lower()
            
            # Categorize by analysis type
            if self._is_static_plugin(plugin_name):
                analysis['static_plugins'] += 1
            else:
                analysis['dynamic_plugins'] += 1
            
            # Check for heavy/complex plugins
            if self._is_heavy_plugin(plugin_name):
                analysis['heavy_plugins'] += 1
            
            # Check for sequential-only plugins
            if self._requires_sequential_execution(plugin_name):
                analysis['sequential_only_plugins'] += 1
        
        # Estimate overall complexity
        if analysis['heavy_plugins'] > len(plugins) * 0.3:
            analysis['estimated_complexity'] = 'high'
        elif analysis['heavy_plugins'] == 0 and len(plugins) < 5:
            analysis['estimated_complexity'] = 'low'
        
        return analysis
    
    def _select_optimal_strategy(self, context: Dict[str, Any]) -> tuple[str, ExecutionStrategy]:
        """Select the optimal execution strategy based on context."""
        plugin_analysis = context['plugin_analysis']
        system_info = context['system_info']
        
        # Decision criteria scores
        scores = {}
        
        # Score each available strategy
        for strategy_name, strategy in self.available_strategies.items():
            scores[strategy_name] = self._score_strategy(strategy_name, context)
        
        # Select strategy with highest score
        if not scores:
            # Fallback to first available strategy
            strategy_name = list(self.available_strategies.keys())[0]
            return strategy_name, self.available_strategies[strategy_name]
        
        best_strategy_name = max(scores, key=scores.get)
        best_score = scores[best_strategy_name]
        
        self.logger.debug(f"Strategy scores: {scores}")
        self.logger.info(f"Selected {best_strategy_name} with score {best_score:.2f}")
        
        return best_strategy_name, self.available_strategies[best_strategy_name]
    
    def _score_strategy(self, strategy_name: str, context: Dict[str, Any]) -> float:
        """Score a strategy based on execution context."""
        plugin_analysis = context['plugin_analysis']
        system_info = context['system_info']
        plugin_count = plugin_analysis['total_plugins']
        
        score = 0.0
        
        if strategy_name == 'sequential':
            # Sequential is good for:
            # - Low resource systems
            # - Few plugins
            # - High sequential-only plugin ratio
            # - Debugging scenarios
            
            if system_info['memory_percent'] > 80:
                score += 3.0  # High memory usage
            if system_info['cpu_percent'] > 90:
                score += 2.0  # High CPU usage
            if plugin_count <= 3:
                score += 2.0  # Few plugins
            if plugin_analysis['sequential_only_plugins'] > plugin_count * 0.5:
                score += 4.0  # Many sequential-only plugins
            if plugin_analysis['estimated_complexity'] == 'low':
                score += 1.0
            
        elif strategy_name == 'parallel':
            # Parallel is good for:
            # - Sufficient resources
            # - Many plugins
            # - Mixed or static-heavy workloads
            # - Normal system conditions
            
            if system_info['cpu_count'] >= 4:
                score += 2.0  # Multi-core system
            if system_info['memory_percent'] < 70:
                score += 2.0  # Sufficient memory
            if plugin_count >= 4:
                score += 3.0  # Many plugins benefit from parallelization
            if plugin_analysis['sequential_only_plugins'] < plugin_count * 0.3:
                score += 2.0  # Few sequential-only plugins
            if plugin_analysis['estimated_complexity'] == 'medium':
                score += 1.5
            
        elif strategy_name == 'process_separation':
            # Process separation is good for:
            # - Mixed static/dynamic workloads
            # - Fault isolation needs
            # - Large plugin sets
            # - Sufficient system resources
            
            static_ratio = plugin_analysis['static_plugins'] / plugin_count if plugin_count > 0 else 0
            dynamic_ratio = plugin_analysis['dynamic_plugins'] / plugin_count if plugin_count > 0 else 0
            
            if 0.2 <= static_ratio <= 0.8 and 0.2 <= dynamic_ratio <= 0.8:
                score += 4.0  # Good mix of static/dynamic
            if plugin_count >= 6:
                score += 2.0  # Large plugin set
            if system_info['memory_available'] >= 4.0:
                score += 2.0  # Sufficient memory for processes
            if plugin_analysis['heavy_plugins'] > 0:
                score += 1.5  # Heavy plugins benefit from isolation
            
        # Apply historical performance learning
        score += self._get_historical_performance_bonus(strategy_name, context)
        
        return score
    
    def _get_historical_performance_bonus(self, strategy_name: str, context: Dict[str, Any]) -> float:
        """Get performance bonus based on historical data."""
        if not self.performance_history:
            return 0.0
        
        # Find similar contexts in history
        similar_executions = []
        plugin_count = context['plugin_analysis']['total_plugins']
        
        for record in self.performance_history[-10:]:  # Last 10 executions
            if abs(record['context']['plugin_count'] - plugin_count) <= 2:
                similar_executions.append(record)
        
        if not similar_executions:
            return 0.0
        
        # Calculate average performance for this strategy
        strategy_performances = [
            record['performance']['execution_time'] 
            for record in similar_executions 
            if record['strategy'] == strategy_name
        ]
        
        if not strategy_performances:
            return 0.0
        
        # Bonus is inversely related to execution time
        avg_time = sum(strategy_performances) / len(strategy_performances)
        if avg_time < 10.0:  # Fast execution
            return 1.0
        elif avg_time < 30.0:  # Medium execution
            return 0.5
        else:  # Slow execution
            return -0.5
    
    def _record_performance(self, context: Dict[str, Any], strategy_name: str, result: StrategyResult):
        """Record performance data for learning."""
        performance_record = {
            'timestamp': time.time(),
            'context': {
                'plugin_count': context['plugin_count'],
                'system_memory_percent': context['system_info']['memory_percent'],
                'system_cpu_count': context['system_info']['cpu_count']
            },
            'strategy': strategy_name,
            'performance': {
                'execution_time': result.execution_time,
                'success_rate': result.successful_plugins / result.total_plugins if result.total_plugins > 0 else 0,
                'total_plugins': result.total_plugins
            }
        }
        
        self.performance_history.append(performance_record)
        
        # Keep only recent history (last 50 executions)
        if len(self.performance_history) > 50:
            self.performance_history = self.performance_history[-50:]
    
    def _is_static_plugin(self, plugin_name: str) -> bool:
        """Determine if plugin performs static analysis."""
        static_patterns = [
            'static', 'manifest', 'apk_structure', 'certificate', 
            'permission', 'decompiled', 'code_analysis', 'secret',
            'hardcoded', 'resource', 'asset'
        ]
        
        dynamic_patterns = [
            'dynamic', 'runtime', 'frida', 'network', 'traffic',
            'behavioral', 'monitoring', 'instrumentation'
        ]
        
        # Check for dynamic patterns first
        for pattern in dynamic_patterns:
            if pattern in plugin_name:
                return False
        
        # Check for static patterns
        for pattern in static_patterns:
            if pattern in plugin_name:
                return True
        
        return True  # Default to static
    
    def _is_heavy_plugin(self, plugin_name: str) -> bool:
        """Determine if plugin is resource-intensive."""
        heavy_patterns = [
            'decompiled', 'network_analysis', 'traffic_analysis',
            'comprehensive', 'deep_scan', 'ml_analysis', 'ai_analysis'
        ]
        
        return any(pattern in plugin_name for pattern in heavy_patterns)
    
    def _requires_sequential_execution(self, plugin_name: str) -> bool:
        """Determine if plugin requires sequential execution."""
        sequential_patterns = [
            'anti_tampering', 'root_detection', 'device_manager',
            'exclusive_access', 'singleton'
        ]
        
        return any(pattern in plugin_name for pattern in sequential_patterns)
    
    def get_execution_characteristics(self) -> Dict[str, Any]:
        """Get characteristics specific to adaptive execution."""
        return {
            'selection_algorithm': 'context_aware_scoring',
            'available_strategies': list(self.available_strategies.keys()),
            'learning_enabled': True,
            'system_awareness': True,
            'performance_history_size': len(self.performance_history),
            'suitable_for': [
                'mixed_workloads',
                'varying_system_conditions',
                'optimal_performance',
                'general_purpose_execution'
            ]
        }
    
    def get_strategy_statistics(self) -> Dict[str, Any]:
        """Get statistics about strategy selection and performance."""
        if not self.performance_history:
            return {'no_data': True}
        
        # Count strategy usage
        strategy_usage = {}
        total_executions = len(self.performance_history)
        
        for record in self.performance_history:
            strategy = record['strategy']
            strategy_usage[strategy] = strategy_usage.get(strategy, 0) + 1
        
        # Calculate average performance per strategy
        strategy_performance = {}
        for strategy in strategy_usage:
            performances = [
                record['performance']['execution_time']
                for record in self.performance_history
                if record['strategy'] == strategy
            ]
            strategy_performance[strategy] = {
                'avg_execution_time': sum(performances) / len(performances),
                'usage_count': strategy_usage[strategy],
                'usage_percentage': (strategy_usage[strategy] / total_executions) * 100
            }
        
        return {
            'total_executions': total_executions,
            'strategy_usage': strategy_usage,
            'strategy_performance': strategy_performance,
            'most_used_strategy': max(strategy_usage, key=strategy_usage.get) if strategy_usage else None
        } 