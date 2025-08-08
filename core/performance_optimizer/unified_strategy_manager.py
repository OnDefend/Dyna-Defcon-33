#!/usr/bin/env python3
"""
Performance Optimizer - Unified Strategy Manager

Central coordinator for all performance optimization strategies,
providing intelligent strategy selection and unified execution.

Strategy Selection Logic:
- Automatic strategy selection based on target characteristics
- Fallback strategies for edge cases
- Performance monitoring and strategy effectiveness tracking
- integration with modular framework components

Supported Strategies:
- GeneralOptimizationStrategy: O(1) conversions, algorithmic improvements
- LargeApkOptimizationStrategy: Memory mapping, intelligent caching
- MemoryConstrainedStrategy: Low-memory environment optimization
- HighSpeedStrategy: Maximum performance with available resources
- ComprehensiveStrategy: Balanced approach for general use
"""

import logging
import time
import threading
from typing import Dict, List, Any, Optional, Union, Type
from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict

from .data_structures import OptimizationConfig, OptimizationLevel, ParallelMode
from .resource_manager import OptimizedResourceManager
from .memory_manager import MemoryManager
from .intelligent_cache import IntelligentCache
from .parallel_processor import ParallelProcessor
from .optimization_strategies import (
    OptimizationStrategy,
    OptimizationResult,
    OptimizationMetrics,
    GeneralOptimizationStrategy,
    LargeApkOptimizationStrategy,
    MemoryConstrainedStrategy,
    HighSpeedStrategy,
    ComprehensiveStrategy
)

@dataclass
class StrategySelectionResult:
    """Result of strategy selection process."""
    selected_strategy: str
    confidence: float
    fallback_strategies: List[str]
    selection_reasoning: str
    estimated_performance: Dict[str, float]

@dataclass
class StrategyPerformanceStats:
    """Performance statistics for optimization strategies."""
    strategy_name: str
    total_executions: int = 0
    successful_executions: int = 0
    average_speedup: float = 1.0
    average_time_seconds: float = 0.0
    total_time_saved_seconds: float = 0.0
    memory_efficiency: float = 1.0
    applicability_score: float = 0.0
    
    @property
    def success_rate(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return self.successful_executions / self.total_executions
    
    @property
    def effectiveness_score(self) -> float:
        """Calculate overall effectiveness score."""
        return (self.success_rate * 0.4 + 
                min(self.average_speedup / 5.0, 1.0) * 0.3 +
                self.memory_efficiency * 0.2 +
                self.applicability_score * 0.1)

class UnifiedStrategyManager:
    """
    Central manager for all performance optimization strategies.
    
    Responsibilities:
    - Intelligent strategy selection based on target characteristics
    - Strategy performance monitoring and optimization
    - Unified execution interface for all optimization approaches
    - Integration with modular performance framework
    - error handling and recovery
    """
    
    def __init__(self, config: OptimizationConfig):
        self.logger = logging.getLogger(__name__)
        self.config = config
        
        # Initialize framework components
        self.framework_components = self._initialize_framework_components()
        
        # Initialize optimization strategies
        self.strategies = self._initialize_strategies()
        
        # Strategy performance tracking
        self.strategy_stats: Dict[str, StrategyPerformanceStats] = {}
        self._initialize_strategy_stats()
        
        # Strategy selection history
        self.selection_history: List[StrategySelectionResult] = []
        
        # Thread safety
        self._strategy_lock = threading.RLock()
        
        # Strategy selection rules
        self.selection_rules = self._initialize_selection_rules()
        
        self.logger.info("Unified Strategy Manager initialized with professional framework integration")
    
    def _initialize_framework_components(self) -> Dict[str, Any]:
        """Initialize modular performance framework components."""
        components = {}
        
        try:
            components['resource_manager'] = OptimizedResourceManager(self.config)
            components['memory_manager'] = MemoryManager(self.config)
            components['cache'] = IntelligentCache(self.config)
            components['parallel_processor'] = ParallelProcessor(self.config)
            
            self.logger.info("Framework components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize framework components: {e}")
            # Provide minimal fallback components
            components = {
                'resource_manager': None,
                'memory_manager': None,
                'cache': None,
                'parallel_processor': None
            }
        
        return components
    
    def _initialize_strategies(self) -> Dict[str, OptimizationStrategy]:
        """Initialize all optimization strategies."""
        strategies = {}
        
        strategy_classes = [
            GeneralOptimizationStrategy,
            LargeApkOptimizationStrategy,
            MemoryConstrainedStrategy,
            HighSpeedStrategy,
            ComprehensiveStrategy
        ]
        
        for strategy_class in strategy_classes:
            try:
                strategy = strategy_class(self.framework_components)
                strategies[strategy.get_strategy_name()] = strategy
                self.logger.info(f"Initialized strategy: {strategy.get_strategy_name()}")
            except Exception as e:
                self.logger.error(f"Failed to initialize strategy {strategy_class.__name__}: {e}")
        
        return strategies
    
    def _initialize_strategy_stats(self):
        """Initialize performance statistics for all strategies."""
        for strategy_name in self.strategies.keys():
            self.strategy_stats[strategy_name] = StrategyPerformanceStats(strategy_name=strategy_name)
    
    def _initialize_selection_rules(self) -> Dict[str, Dict[str, Any]]:
        """Initialize strategy selection rules."""
        return {
            'file_size_rules': {
                'large_apk_threshold_mb': 200,
                'memory_constrained_threshold_mb': 50,
                'high_speed_threshold_mb': 500
            },
            'system_resource_rules': {
                'memory_constrained_threshold_gb': 4,
                'high_speed_cpu_threshold': 8,
                'high_speed_memory_threshold_gb': 16
            },
            'file_type_rules': {
                'apk_extensions': ['.apk'],
                'python_extensions': ['.py'],
                'source_extensions': ['.py', '.java', '.kt', '.js', '.ts']
            },
            'performance_rules': {
                'max_analysis_time_seconds': 30,
                'target_speedup_factor': 2.0,
                'memory_efficiency_threshold': 0.8
            }
        }
    
    def select_optimal_strategy(self, target: Union[str, Path], 
                              context: Dict[str, Any]) -> StrategySelectionResult:
        """
        Select the optimal optimization strategy based on target characteristics.
        
        Args:
            target: Target file/path to optimize
            context: Additional context for strategy selection
            
        Returns:
            Strategy selection result with reasoning and alternatives
        """
        with self._strategy_lock:
            target_path = Path(target)
            
            # Analyze target characteristics
            target_analysis = self._analyze_target(target_path, context)
            
            # Calculate strategy applicability scores
            strategy_scores = self._calculate_strategy_scores(target_path, target_analysis, context)
            
            # Select best strategy
            best_strategy = max(strategy_scores.items(), key=lambda x: x[1]['total_score'])
            strategy_name, score_details = best_strategy
            
            # Determine fallback strategies
            fallback_strategies = [
                name for name, details in sorted(strategy_scores.items(), 
                                               key=lambda x: x[1]['total_score'], 
                                               reverse=True)[1:3]
            ]
            
            # Create selection result
            selection_result = StrategySelectionResult(
                selected_strategy=strategy_name,
                confidence=score_details['total_score'],
                fallback_strategies=fallback_strategies,
                selection_reasoning=score_details['reasoning'],
                estimated_performance=score_details['estimated_performance']
            )
            
            # Track selection history
            self.selection_history.append(selection_result)
            
            self.logger.info(f"Selected strategy: {strategy_name} (confidence: {selection_result.confidence:.2f})")
            self.logger.info(f"Reasoning: {selection_result.selection_reasoning}")
            
            return selection_result
    
    def _analyze_target(self, target_path: Path, context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze target characteristics for strategy selection."""
        analysis = {
            'file_exists': target_path.exists() if isinstance(target_path, Path) else False,
            'file_size_mb': 0.0,
            'file_extension': '',
            'is_apk': False,
            'is_source_code': False,
            'is_large_file': False,
            'analysis_type': context.get('analysis_type', 'unknown')
        }
        
        if analysis['file_exists']:
            try:
                file_stat = target_path.stat()
                analysis['file_size_mb'] = file_stat.st_size / (1024 * 1024)
                analysis['file_extension'] = target_path.suffix.lower()
                analysis['is_apk'] = analysis['file_extension'] == '.apk'
                analysis['is_source_code'] = analysis['file_extension'] in self.selection_rules['file_type_rules']['source_extensions']
                analysis['is_large_file'] = analysis['file_size_mb'] > self.selection_rules['file_size_rules']['large_apk_threshold_mb']
            except Exception as e:
                self.logger.warning(f"Failed to analyze target file: {e}")
        
        return analysis
    
    def _calculate_strategy_scores(self, target_path: Path, target_analysis: Dict[str, Any], 
                                 context: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Calculate applicability scores for each strategy."""
        strategy_scores = {}
        
        for strategy_name, strategy in self.strategies.items():
            try:
                # Base applicability check
                is_applicable = strategy.is_applicable(target_path, context)
                applicability_score = 1.0 if is_applicable else 0.1
                
                # Historical performance score
                historical_score = self._get_historical_performance_score(strategy_name)
                
                # Target-specific scoring
                target_score = self._calculate_target_specific_score(strategy_name, target_analysis)
                
                # System resource compatibility
                resource_score = self._calculate_resource_compatibility_score(strategy_name)
                
                # Calculate total score
                total_score = (
                    applicability_score * 0.4 +
                    historical_score * 0.3 +
                    target_score * 0.2 +
                    resource_score * 0.1
                )
                
                # Generate reasoning
                reasoning = self._generate_selection_reasoning(
                    strategy_name, applicability_score, historical_score, 
                    target_score, resource_score, target_analysis
                )
                
                # Estimate performance
                estimated_performance = self._estimate_strategy_performance(
                    strategy_name, target_analysis, context
                )
                
                strategy_scores[strategy_name] = {
                    'total_score': total_score,
                    'applicability_score': applicability_score,
                    'historical_score': historical_score,
                    'target_score': target_score,
                    'resource_score': resource_score,
                    'reasoning': reasoning,
                    'estimated_performance': estimated_performance
                }
                
            except Exception as e:
                self.logger.warning(f"Failed to calculate score for strategy {strategy_name}: {e}")
                strategy_scores[strategy_name] = {
                    'total_score': 0.0,
                    'reasoning': f"Strategy evaluation failed: {e}",
                    'estimated_performance': {}
                }
        
        return strategy_scores
    
    def _get_historical_performance_score(self, strategy_name: str) -> float:
        """Get historical performance score for strategy."""
        if strategy_name not in self.strategy_stats:
            return 0.5  # Neutral score for new strategies
        
        stats = self.strategy_stats[strategy_name]
        return stats.effectiveness_score
    
    def _calculate_target_specific_score(self, strategy_name: str, target_analysis: Dict[str, Any]) -> float:
        """Calculate target-specific scoring for strategy."""
        score = 0.5  # Base score
        
        if strategy_name == "large_apk_optimization":
            if target_analysis['is_apk'] and target_analysis['is_large_file']:
                score = 1.0
            elif target_analysis['is_apk']:
                score = 0.7
            else:
                score = 0.1
        
        elif strategy_name == "general_optimization":
            if target_analysis['is_source_code']:
                score = 0.9
            elif target_analysis['file_size_mb'] < 10:
                score = 0.8
            else:
                score = 0.6
        
        elif strategy_name == "memory_constrained":
            # Higher score for large files or when memory is limited
            if target_analysis['file_size_mb'] > 100:
                score = 0.8
            else:
                score = 0.3
        
        elif strategy_name == "high_speed":
            # Higher score for large files when resources are available
            if target_analysis['file_size_mb'] > 200:
                score = 0.9
            else:
                score = 0.5
        
        elif strategy_name == "comprehensive":
            # Always moderate score as fallback
            score = 0.6
        
        return score
    
    def _calculate_resource_compatibility_score(self, strategy_name: str) -> float:
        """Calculate system resource compatibility score."""
        try:
            import psutil
            
            cpu_count = psutil.cpu_count()
            memory_gb = psutil.virtual_memory().total / (1024**3)
            available_memory_gb = psutil.virtual_memory().available / (1024**3)
            
            if strategy_name == "high_speed":
                if cpu_count >= 8 and memory_gb >= 16:
                    return 1.0
                elif cpu_count >= 4 and memory_gb >= 8:
                    return 0.7
                else:
                    return 0.3
            
            elif strategy_name == "memory_constrained":
                if available_memory_gb < 4:
                    return 1.0
                elif available_memory_gb < 8:
                    return 0.6
                else:
                    return 0.3
            
            else:
                # General compatibility for other strategies
                return 0.8
                
        except Exception as e:
            self.logger.warning(f"Failed to assess resource compatibility: {e}")
            return 0.5
    
    def _generate_selection_reasoning(self, strategy_name: str, applicability: float, 
                                    historical: float, target: float, resource: float,
                                    target_analysis: Dict[str, Any]) -> str:
        """Generate human-readable reasoning for strategy selection."""
        reasons = []
        
        if applicability > 0.8:
            reasons.append("highly applicable to target")
        elif applicability > 0.5:
            reasons.append("moderately applicable")
        else:
            reasons.append("limited applicability")
        
        if historical > 0.7:
            reasons.append("excellent historical performance")
        elif historical > 0.5:
            reasons.append("good historical performance")
        
        if target > 0.8:
            reasons.append("well-suited for target characteristics")
        
        if resource > 0.7:
            reasons.append("compatible with system resources")
        
        # Add specific insights
        if target_analysis['is_apk'] and strategy_name == "large_apk_optimization":
            reasons.append(f"optimized for {target_analysis['file_size_mb']:.1f}MB APK")
        
        if target_analysis['is_source_code'] and strategy_name == "general_optimization":
            reasons.append("designed for source code optimization")
        
        return "; ".join(reasons)
    
    def _estimate_strategy_performance(self, strategy_name: str, target_analysis: Dict[str, Any], 
                                     context: Dict[str, Any]) -> Dict[str, float]:
        """Estimate performance metrics for strategy."""
        base_estimates = {
            'estimated_speedup': 1.0,
            'estimated_time_seconds': 10.0,
            'estimated_memory_mb': 100.0,
            'confidence_level': 0.5
        }
        
        # Get historical data if available
        if strategy_name in self.strategy_stats:
            stats = self.strategy_stats[strategy_name]
            if stats.total_executions > 0:
                base_estimates['estimated_speedup'] = stats.average_speedup
                base_estimates['estimated_time_seconds'] = stats.average_time_seconds
                base_estimates['confidence_level'] = stats.success_rate
        
        # Adjust based on target characteristics
        if target_analysis['file_size_mb'] > 100:
            base_estimates['estimated_time_seconds'] *= (target_analysis['file_size_mb'] / 100) ** 0.5
            base_estimates['estimated_memory_mb'] *= target_analysis['file_size_mb'] / 100
        
        return base_estimates
    
    def execute_optimization(self, target: Union[str, Path], context: Dict[str, Any] = None) -> OptimizationResult:
        """
        Execute optimization using the best available strategy.
        
        Args:
            target: Target to optimize
            context: Optional context for optimization
            
        Returns:
            Optimization result with performance metrics
        """
        if context is None:
            context = {}
        
        start_time = time.time()
        
        try:
            # Select optimal strategy
            selection_result = self.select_optimal_strategy(target, context)
            strategy_name = selection_result.selected_strategy
            
            # Get selected strategy
            strategy = self.strategies.get(strategy_name)
            if not strategy:
                raise ValueError(f"Strategy {strategy_name} not available")
            
            # Execute optimization
            self.logger.info(f"Executing optimization with {strategy_name} strategy")
            result = strategy.optimize(target, context)
            
            # Update performance statistics
            self._update_strategy_statistics(strategy_name, result, start_time)
            
            # Add selection info to result
            result.strategy_used = strategy_name
            
            return result
            
        except Exception as e:
            self.logger.error(f"Optimization execution failed: {e}")
            
            # Try fallback strategy
            fallback_result = self._execute_fallback_optimization(target, context, e)
            return fallback_result
    
    def _execute_fallback_optimization(self, target: Union[str, Path], 
                                     context: Dict[str, Any], original_error: Exception) -> OptimizationResult:
        """Execute fallback optimization when primary strategy fails."""
        try:
            # Use comprehensive strategy as fallback
            comprehensive_strategy = self.strategies.get("comprehensive")
            if comprehensive_strategy:
                self.logger.info("Executing fallback optimization with comprehensive strategy")
                result = comprehensive_strategy.optimize(target, context)
                result.recommendations.append(f"Fallback strategy used due to error: {original_error}")
                return result
        except Exception as fallback_error:
            self.logger.error(f"Fallback optimization also failed: {fallback_error}")
        
        # Return error result if all strategies fail
        return OptimizationResult(
            success=False,
            metrics=OptimizationMetrics(
                operation_name="failed_optimization",
                start_time=time.time(),
                end_time=time.time(),
                optimization_type="error"
            ),
            error_message=f"All optimization strategies failed. Original: {original_error}",
            strategy_used="none",
            recommendations=["Manual review required", "Check system resources", "Verify input format"]
        )
    
    def _update_strategy_statistics(self, strategy_name: str, result: OptimizationResult, start_time: float):
        """Update performance statistics for strategy."""
        if strategy_name not in self.strategy_stats:
            self.strategy_stats[strategy_name] = StrategyPerformanceStats(strategy_name=strategy_name)
        
        stats = self.strategy_stats[strategy_name]
        stats.total_executions += 1
        
        if result.success:
            stats.successful_executions += 1
            
            # Update performance metrics
            execution_time = time.time() - start_time
            stats.average_time_seconds = (
                (stats.average_time_seconds * (stats.successful_executions - 1) + execution_time) / 
                stats.successful_executions
            )
            
            if result.metrics.speedup_factor > 0:
                stats.average_speedup = (
                    (stats.average_speedup * (stats.successful_executions - 1) + result.metrics.speedup_factor) / 
                    stats.successful_executions
                )
            
            # Estimate time saved
            if result.metrics.speedup_factor > 1:
                time_saved = execution_time * (result.metrics.speedup_factor - 1)
                stats.total_time_saved_seconds += time_saved
    
    def get_strategy_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report for all strategies."""
        report = {
            'total_optimizations': sum(stats.total_executions for stats in self.strategy_stats.values()),
            'overall_success_rate': 0.0,
            'total_time_saved_seconds': sum(stats.total_time_saved_seconds for stats in self.strategy_stats.values()),
            'strategy_statistics': {},
            'recommendations': []
        }
        
        # Calculate overall success rate
        total_executions = report['total_optimizations']
        if total_executions > 0:
            total_successes = sum(stats.successful_executions for stats in self.strategy_stats.values())
            report['overall_success_rate'] = total_successes / total_executions
        
        # Add individual strategy statistics
        for strategy_name, stats in self.strategy_stats.items():
            report['strategy_statistics'][strategy_name] = {
                'executions': stats.total_executions,
                'success_rate': stats.success_rate,
                'average_speedup': stats.average_speedup,
                'average_time_seconds': stats.average_time_seconds,
                'effectiveness_score': stats.effectiveness_score,
                'time_saved_seconds': stats.total_time_saved_seconds
            }
        
        # Generate recommendations
        if report['overall_success_rate'] < 0.8:
            report['recommendations'].append("Consider reviewing strategy selection criteria")
        
        if report['total_time_saved_seconds'] > 3600:
            report['recommendations'].append(f"Optimization saved {report['total_time_saved_seconds']/3600:.1f} hours of processing time")
        
        # Find best performing strategy
        if self.strategy_stats:
            best_strategy = max(self.strategy_stats.values(), key=lambda s: s.effectiveness_score)
            report['recommendations'].append(f"Most effective strategy: {best_strategy.strategy_name}")
        
        return report
    
    def optimize_strategy_selection(self):
        """Optimize strategy selection based on historical performance."""
        with self._strategy_lock:
            # Analyze selection history and performance
            if len(self.selection_history) < 10:
                return  # Need more data
            
            # Update selection rules based on performance
            successful_selections = [
                selection for selection in self.selection_history[-50:]  # Last 50 selections
                if selection.selected_strategy in self.strategy_stats and 
                self.strategy_stats[selection.selected_strategy].success_rate > 0.8
            ]
            
            if successful_selections:
                # Update applicability scores based on successful patterns
                self._update_selection_rules_from_history(successful_selections)
                self.logger.info("Updated strategy selection rules based on performance history")
    
    def _update_selection_rules_from_history(self, successful_selections: List[StrategySelectionResult]):
        """Update selection rules based on successful optimization history."""
        # Analyze patterns in successful selections
        strategy_success_patterns = defaultdict(list)
        
        for selection in successful_selections:
            strategy_success_patterns[selection.selected_strategy].append(selection)
        
        # Update applicability scores
        for strategy_name, stats in self.strategy_stats.items():
            if strategy_name in strategy_success_patterns:
                successful_count = len(strategy_success_patterns[strategy_name])
                stats.applicability_score = min(1.0, successful_count / 20.0)  # Cap at 1.0
            else:
                stats.applicability_score *= 0.9  # Slight decrease for unused strategies
        
        self.logger.info("Strategy selection rules updated based on historical performance")

# Global unified strategy manager instance
_strategy_manager = None
_manager_lock = threading.Lock()

def get_unified_strategy_manager(config: OptimizationConfig = None) -> UnifiedStrategyManager:
    """Get the global unified strategy manager instance."""
    global _strategy_manager
    
    if _strategy_manager is None:
        with _manager_lock:
            if _strategy_manager is None:
                if config is None:
                    # Create default configuration
                    config = OptimizationConfig(
                        optimization_level=OptimizationLevel.BALANCED,
                        parallel_mode=ParallelMode.AUTO,
                        cache_enabled=True,
                        memory_limit_mb=2048
                    )
                _strategy_manager = UnifiedStrategyManager(config)
    
    return _strategy_manager

# Convenience functions for backward compatibility
def optimize_performance(target: Union[str, Path], context: Dict[str, Any] = None) -> OptimizationResult:
    """Convenience function for performance optimization."""
    manager = get_unified_strategy_manager()
    return manager.execute_optimization(target, context)

def get_optimization_report() -> Dict[str, Any]:
    """Convenience function to get optimization performance report."""
    manager = get_unified_strategy_manager()
    return manager.get_strategy_performance_report() 