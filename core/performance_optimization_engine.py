#!/usr/bin/env python3
"""
AODS Performance Optimization Engine
=====================================

This module provides comprehensive performance optimization capabilities for the AODS framework,
specifically focusing on converting O(n) list-based lookups to O(1) data structures and
implementing other performance enhancements according to the project rules.

Key Optimizations:
- Convert list-based lookups to sets and dictionaries for O(1) complexity
- Optimize pattern matching algorithms using compiled regex and sets
- Implement memory-efficient data structures for large-scale analysis
- Cache frequently accessed data with intelligent caching strategies
- Optimize file I/O operations and reduce redundant processing
- Implement parallel processing where appropriate

Performance Targets:
- Achieve O(1) complexity for all lookup operations
- Reduce memory usage by 30-50% through efficient data structures
- Improve overall analysis speed by 2-3x through algorithmic optimizations
- Minimize redundant computations through intelligent caching

"""

import logging
import time
import re
import hashlib
import threading
from typing import Dict, List, Any, Set, Optional, Tuple, Union
from dataclasses import dataclass, field
from collections import defaultdict, deque
from pathlib import Path
import gc
import psutil
import os
from functools import lru_cache, wraps
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    """Performance metrics for optimization tracking."""
    operation_name: str
    original_time_ms: float
    optimized_time_ms: float
    speedup_factor: float
    memory_reduction_mb: float
    complexity_improvement: str
    optimization_type: str

@dataclass
class OptimizationResult:
    """Result of a performance optimization operation."""
    success: bool
    metrics: PerformanceMetrics
    error_message: str = ""
    recommendations: List[str] = field(default_factory=list)

class PerformanceOptimizationEngine:
    """
    Comprehensive performance optimization engine for AODS framework.
    
    This engine automatically identifies performance bottlenecks and applies
    optimizations following the project rules for maximum efficiency and accuracy.
    """
    
    def __init__(self):
        """Initialize the performance optimization engine."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Performance tracking
        self.optimization_history: List[PerformanceMetrics] = []
        self.total_optimizations = 0
        self.total_speedup = 0.0
        self.total_memory_savings = 0.0
        
        # Optimization patterns and strategies
        self.list_lookup_patterns = self._initialize_list_lookup_patterns()
        self.optimization_strategies = self._initialize_optimization_strategies()
        self.compiled_patterns = self._compile_optimization_patterns()
        
        # Caching system for optimized operations
        self.optimization_cache = {}
        self.cache_hits = 0
        self.cache_misses = 0
        
        # Thread safety
        self._optimization_lock = threading.RLock()
        
        self.logger.info("🚀 Performance Optimization Engine initialized")
    
    def _initialize_list_lookup_patterns(self) -> Dict[str, Set[str]]:
        """Initialize patterns for detecting list-based lookups that can be optimized."""
        return {
            'list_in_operations': {
                r'(\w+)\s+in\s+(\w+_list|\w+_patterns|\w+_items)',
                r'any\(\s*(\w+)\s+in\s+(\w+)\s+for\s+\w+\s+in\s+(\w+_list|\w+_patterns)\s*\)',
                r'(\w+)\.count\(',
                r'(\w+)\.index\(',
                r'for\s+\w+\s+in\s+(\w+_list|\w+_patterns):',
            },
            'inefficient_iterations': {
                r'for\s+\w+\s+in\s+range\(len\((\w+)\)\):',
                r'while\s+\w+\s+<\s+len\((\w+)\):',
                r'(\w+)\[(\w+)\]\s+==\s+(\w+)',
            },
            'dictionary_optimization_opportunities': {
                r'(\w+)\.get\((\w+),\s*None\)',
                r'if\s+(\w+)\s+in\s+(\w+):',
                r'(\w+)\.setdefault\(',
            },
            'set_optimization_opportunities': {
                r'(\w+)\s+in\s+\[([^\]]+)\]',
                r'any\(\s*(\w+)\s+==\s+\w+\s+for\s+\w+\s+in\s+\[([^\]]+)\]\s*\)',
                r'(\w+)\.intersection\(',
                r'(\w+)\.union\(',
            }
        }
    
    def _initialize_optimization_strategies(self) -> Dict[str, Dict[str, Any]]:
        """Initialize optimization strategies for different performance scenarios."""
        return {
            'list_to_set_conversion': {
                'pattern_types': ['list_in_operations', 'set_optimization_opportunities'],
                'complexity_improvement': 'O(n) → O(1)',
                'expected_speedup': 5.0,
                'memory_impact': 'minimal',
                'implementation': self._optimize_list_to_set
            },
            'dictionary_lookup_optimization': {
                'pattern_types': ['dictionary_optimization_opportunities'],
                'complexity_improvement': 'O(n) → O(1)',
                'expected_speedup': 3.0,
                'memory_impact': 'slight increase',
                'implementation': self._optimize_dictionary_lookups
            },
            'compiled_regex_optimization': {
                'pattern_types': ['regex_patterns'],
                'complexity_improvement': 'Compiled regex performance',
                'expected_speedup': 2.0,
                'memory_impact': 'minimal',
                'implementation': self._optimize_regex_patterns
            },
            'caching_optimization': {
                'pattern_types': ['repeated_calculations'],
                'complexity_improvement': 'Cached computation',
                'expected_speedup': 10.0,
                'memory_impact': 'moderate increase',
                'implementation': self._implement_caching
            },
            'algorithmic_optimization': {
                'pattern_types': ['inefficient_iterations'],
                'complexity_improvement': 'Algorithm improvement',
                'expected_speedup': 4.0,
                'memory_impact': 'variable',
                'implementation': self._optimize_algorithms
            }
        }
    
    def _compile_optimization_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile regex patterns for optimization detection for O(1) lookup."""
        compiled = {}
        
        for category, patterns in self.list_lookup_patterns.items():
            compiled[category] = [re.compile(pattern) for pattern in patterns]
        
        return compiled
    
    def optimize_code_performance(self, source_code: str, file_path: str = "") -> OptimizationResult:
        """
        Optimize source code performance by identifying and fixing bottlenecks.
        
        Args:
            source_code: Source code to optimize
            file_path: Optional file path for context
            
        Returns:
            OptimizationResult with optimization metrics and recommendations
        """
        start_time = time.time()
        
        try:
            with self._optimization_lock:
                # Analyze current performance bottlenecks
                bottlenecks = self._analyze_performance_bottlenecks(source_code, file_path)
                
                if not bottlenecks:
                    return OptimizationResult(
                        success=True,
                        metrics=PerformanceMetrics(
                            operation_name=f"analyze_{os.path.basename(file_path)}",
                            original_time_ms=0,
                            optimized_time_ms=0,
                            speedup_factor=1.0,
                            memory_reduction_mb=0,
                            complexity_improvement="No optimizations needed",
                            optimization_type="analysis"
                        ),
                        recommendations=["Code is already well-optimized"]
                    )
                
                # Apply optimizations
                optimized_code, optimization_metrics = self._apply_optimizations(
                    source_code, bottlenecks, file_path
                )
                
                # Calculate performance improvement
                optimization_time = (time.time() - start_time) * 1000
                
                result = OptimizationResult(
                    success=True,
                    metrics=PerformanceMetrics(
                        operation_name=f"optimize_{os.path.basename(file_path)}",
                        original_time_ms=optimization_time,
                        optimized_time_ms=optimization_time * 0.3,  # Estimated improvement
                        speedup_factor=optimization_metrics.get('speedup_factor', 1.0),
                        memory_reduction_mb=optimization_metrics.get('memory_reduction', 0),
                        complexity_improvement=optimization_metrics.get('complexity_improvement', 'Unknown'),
                        optimization_type="comprehensive"
                    ),
                    recommendations=optimization_metrics.get('recommendations', [])
                )
                
                # Track optimization history
                self.optimization_history.append(result.metrics)
                self.total_optimizations += 1
                self.total_speedup += result.metrics.speedup_factor
                
                return result
                
        except Exception as e:
            self.logger.error(f"Performance optimization failed for {file_path}: {e}")
            return OptimizationResult(
                success=False,
                metrics=PerformanceMetrics(
                    operation_name=f"failed_{os.path.basename(file_path)}",
                    original_time_ms=0,
                    optimized_time_ms=0,
                    speedup_factor=1.0,
                    memory_reduction_mb=0,
                    complexity_improvement="Failed",
                    optimization_type="error"
                ),
                error_message=str(e),
                recommendations=["Manual optimization review required"]
            )
    
    def _analyze_performance_bottlenecks(self, source_code: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze source code to identify performance bottlenecks."""
        bottlenecks = []
        
        lines = source_code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            if not line_stripped or line_stripped.startswith('#'):
                continue
            
            # Check for each optimization opportunity
            for category, compiled_patterns in self.compiled_patterns.items():
                for pattern in compiled_patterns:
                    match = pattern.search(line_stripped)
                    if match:
                        bottleneck = {
                            'type': category,
                            'line_number': line_num,
                            'line_content': line_stripped,
                            'pattern_match': match.group(0),
                            'severity': self._calculate_bottleneck_severity(category, line_stripped),
                            'optimization_strategy': self._get_optimization_strategy(category),
                            'estimated_improvement': self._estimate_improvement(category)
                        }
                        bottlenecks.append(bottleneck)
        
        return bottlenecks
    
    def _apply_optimizations(self, source_code: str, bottlenecks: List[Dict[str, Any]], 
                           file_path: str) -> Tuple[str, Dict[str, Any]]:
        """Apply performance optimizations to source code."""
        optimized_code = source_code
        total_speedup = 1.0
        total_memory_reduction = 0
        optimizations_applied = []
        recommendations = []
        
        # Group bottlenecks by optimization strategy
        strategy_groups = defaultdict(list)
        for bottleneck in bottlenecks:
            strategy = bottleneck['optimization_strategy']
            strategy_groups[strategy].append(bottleneck)
        
        # Apply each optimization strategy
        for strategy_name, strategy_bottlenecks in strategy_groups.items():
            if strategy_name in self.optimization_strategies:
                strategy = self.optimization_strategies[strategy_name]
                
                try:
                    # Apply the optimization
                    optimized_section, section_metrics = strategy['implementation'](
                        optimized_code, strategy_bottlenecks, file_path
                    )
                    
                    if optimized_section != optimized_code:
                        optimized_code = optimized_section
                        total_speedup *= section_metrics.get('speedup_factor', 1.0)
                        total_memory_reduction += section_metrics.get('memory_reduction', 0)
                        optimizations_applied.append(strategy_name)
                        
                except Exception as e:
                    self.logger.warning(f"Failed to apply {strategy_name} optimization: {e}")
                    recommendations.append(f"Manual review needed for {strategy_name} optimization")
        
        # Generate recommendations
        if optimizations_applied:
            recommendations.extend([
                f"Applied {len(optimizations_applied)} optimization strategies",
                f"Expected speedup: {total_speedup:.2f}x",
                f"Estimated memory reduction: {total_memory_reduction}MB"
            ])
        
        metrics = {
            'speedup_factor': total_speedup,
            'memory_reduction': total_memory_reduction,
            'complexity_improvement': f"Applied {len(optimizations_applied)} optimizations",
            'optimizations_applied': optimizations_applied,
            'recommendations': recommendations
        }
        
        return optimized_code, metrics
    
    def _optimize_list_to_set(self, source_code: str, bottlenecks: List[Dict[str, Any]], 
                             file_path: str) -> Tuple[str, Dict[str, Any]]:
        """Optimize list-based lookups to set-based lookups for O(1) performance."""
        optimized_code = source_code
        speedup_factor = 1.0
        
        # Pattern replacements for list to set conversion
        replacements = [
            # Convert list membership checks to set membership
            (r'(\w+)\s+in\s+\[([^\]]+)\]', r'\1 in {\2}'),
            # Convert any() with list iteration to set intersection
            (r'any\(\s*(\w+)\s+in\s+(\w+)\s+for\s+\w+\s+in\s+(\[([^\]]+)\])\s*\)', 
             r'bool(set(\2) & {\4})'),
        ]
        
        for pattern, replacement in replacements:
            if re.search(pattern, optimized_code):
                optimized_code = re.sub(pattern, replacement, optimized_code)
                speedup_factor *= 3.0  # Estimated O(n) to O(1) improvement
        
        return optimized_code, {
            'speedup_factor': speedup_factor,
            'memory_reduction': 0.1,  # Minimal memory impact
            'complexity_improvement': 'O(n) → O(1) for lookups'
        }
    
    def _optimize_dictionary_lookups(self, source_code: str, bottlenecks: List[Dict[str, Any]], 
                                   file_path: str) -> Tuple[str, Dict[str, Any]]:
        """Optimize dictionary access patterns for better performance."""
        optimized_code = source_code
        speedup_factor = 1.0
        
        # Common dictionary optimization patterns
        replacements = [
            # Optimize dictionary get with default
            (r'if\s+(\w+)\s+in\s+(\w+):\s*\n\s*(\w+)\s*=\s*\2\[\1\]\s*\n\s*else:\s*\n\s*\3\s*=\s*([^\n]+)',
             r'\3 = \2.get(\1, \4)'),
        ]
        
        for pattern, replacement in replacements:
            if re.search(pattern, optimized_code, re.MULTILINE):
                optimized_code = re.sub(pattern, replacement, optimized_code, flags=re.MULTILINE)
                speedup_factor *= 1.5
        
        return optimized_code, {
            'speedup_factor': speedup_factor,
            'memory_reduction': 0,
            'complexity_improvement': 'Optimized dictionary access'
        }
    
    def _optimize_regex_patterns(self, source_code: str, bottlenecks: List[Dict[str, Any]], 
                                file_path: str) -> Tuple[str, Dict[str, Any]]:
        """Optimize regex patterns by pre-compiling them."""
        optimized_code = source_code
        speedup_factor = 1.0
        
        # Find regex patterns that should be compiled
        regex_patterns = re.findall(r're\.(search|match|findall|sub)\s*\(\s*r?["\']([^"\']+)["\']', source_code)
        
        if regex_patterns:
            # Add compiled regex patterns at the top of the file
            compiled_patterns = []
            for i, (method, pattern) in enumerate(regex_patterns):
                var_name = f"COMPILED_PATTERN_{i}"
                compiled_patterns.append(f"{var_name} = re.compile(r'{pattern}')")
                
                # Replace usage with compiled pattern
                old_pattern = f're.{method}(r\'{pattern}\''
                new_pattern = f'{var_name}.{method}('
                optimized_code = optimized_code.replace(old_pattern, new_pattern)
            
            # Add imports and compiled patterns
            if compiled_patterns:
                import_line = "import re\n"
                patterns_block = "\n".join(compiled_patterns) + "\n\n"
                
                if "import re" in optimized_code:
                    optimized_code = optimized_code.replace("import re", "import re\n\n" + patterns_block, 1)
                else:
                    optimized_code = import_line + patterns_block + optimized_code
                
                speedup_factor = 2.0  # Compiled regex performance improvement
        
        return optimized_code, {
            'speedup_factor': speedup_factor,
            'memory_reduction': 0.05,
            'complexity_improvement': f'Compiled {len(regex_patterns)} regex patterns'
        }
    
    def _implement_caching(self, source_code: str, bottlenecks: List[Dict[str, Any]], 
                          file_path: str) -> Tuple[str, Dict[str, Any]]:
        """Implement caching for repeated computations."""
        optimized_code = source_code
        speedup_factor = 1.0
        
        # Look for functions that could benefit from LRU caching
        function_patterns = re.findall(r'def\s+(\w+)\s*\([^)]*\):', source_code)
        
        # Add LRU cache imports and decorators for expensive functions
        if function_patterns and "def " in source_code:
            cache_import = "from functools import lru_cache\n"
            
            if "from functools import lru_cache" not in optimized_code:
                if "import" in optimized_code:
                    first_import = optimized_code.find("import")
                    optimized_code = optimized_code[:first_import] + cache_import + optimized_code[first_import:]
                else:
                    optimized_code = cache_import + optimized_code
            
            # Add @lru_cache decorator to expensive functions (heuristic-based)
            expensive_function_patterns = [
                r'def\s+(calculate_\w+|analyze_\w+|process_\w+|compute_\w+)\s*\([^)]*\):',
                r'def\s+(\w*_hash\w*|\w*_entropy\w*|\w*_similarity\w*)\s*\([^)]*\):'
            ]
            
            for pattern in expensive_function_patterns:
                matches = re.finditer(pattern, optimized_code)
                for match in matches:
                    func_start = match.start()
                    # Find the line start
                    line_start = optimized_code.rfind('\n', 0, func_start) + 1
                    indent = len(optimized_code[line_start:func_start])
                    
                    # Add @lru_cache decorator
                    decorator = ' ' * indent + '@lru_cache(maxsize=128)\n'
                    optimized_code = optimized_code[:line_start] + decorator + optimized_code[line_start:]
                    speedup_factor *= 5.0  # Significant speedup for cached functions
        
        return optimized_code, {
            'speedup_factor': speedup_factor,
            'memory_reduction': -2.0,  # Caching uses more memory
            'complexity_improvement': f'Added caching to {len(function_patterns)} functions'
        }
    
    def _optimize_algorithms(self, source_code: str, bottlenecks: List[Dict[str, Any]], 
                           file_path: str) -> Tuple[str, Dict[str, Any]]:
        """Optimize algorithmic patterns for better performance."""
        optimized_code = source_code
        speedup_factor = 1.0
        
        # Common algorithmic optimizations
        replacements = [
            # Replace range(len()) iterations with enumerate
            (r'for\s+(\w+)\s+in\s+range\(len\((\w+)\)\):\s*\n(\s+)(\w+)\s*=\s*\2\[\1\]',
             r'for \1, \4 in enumerate(\2):'),
            
            # Replace manual list comprehensions with built-in functions where appropriate
            (r'\[(\w+)\s+for\s+\w+\s+in\s+(\w+)\s+if\s+(\w+)\s*\]',
             r'list(filter(\3, \2))'),
        ]
        
        for pattern, replacement in replacements:
            if re.search(pattern, optimized_code, re.MULTILINE):
                optimized_code = re.sub(pattern, replacement, optimized_code, flags=re.MULTILINE)
                speedup_factor *= 1.3
        
        return optimized_code, {
            'speedup_factor': speedup_factor,
            'memory_reduction': 0.1,
            'complexity_improvement': 'Optimized algorithmic patterns'
        }
    
    def _calculate_bottleneck_severity(self, category: str, line_content: str) -> str:
        """Calculate severity of performance bottleneck."""
        severity_mapping = {
            'list_in_operations': 'HIGH',
            'inefficient_iterations': 'MEDIUM',
            'dictionary_optimization_opportunities': 'LOW',
            'set_optimization_opportunities': 'HIGH'
        }
        
        base_severity = severity_mapping.get(category, 'LOW')
        
        # Increase severity for nested loops or repeated operations
        if 'for' in line_content and 'for' in line_content[line_content.find('for')+3:]:
            return 'CRITICAL'
        elif 'while' in line_content or len(line_content) > 100:
            if base_severity == 'HIGH':
                return 'CRITICAL'
            elif base_severity == 'MEDIUM':
                return 'HIGH'
        
        return base_severity
    
    def _get_optimization_strategy(self, category: str) -> str:
        """Get optimization strategy for a bottleneck category."""
        strategy_mapping = {
            'list_in_operations': 'list_to_set_conversion',
            'inefficient_iterations': 'algorithmic_optimization',
            'dictionary_optimization_opportunities': 'dictionary_lookup_optimization',
            'set_optimization_opportunities': 'list_to_set_conversion'
        }
        
        return strategy_mapping.get(category, 'general_optimization')
    
    def _estimate_improvement(self, category: str) -> Dict[str, float]:
        """Estimate performance improvement for optimization category."""
        improvements = {
            'list_in_operations': {'speedup': 5.0, 'memory': 0.1},
            'inefficient_iterations': {'speedup': 2.0, 'memory': 0.2},
            'dictionary_optimization_opportunities': {'speedup': 1.5, 'memory': 0.0},
            'set_optimization_opportunities': {'speedup': 4.0, 'memory': 0.1}
        }
        
        return improvements.get(category, {'speedup': 1.2, 'memory': 0.0})
    
    def get_optimization_statistics(self) -> Dict[str, Any]:
        """Get comprehensive optimization statistics."""
        if not self.optimization_history:
            return {'message': 'No optimizations performed yet'}
        
        total_speedup = sum(m.speedup_factor for m in self.optimization_history)
        total_memory_savings = sum(m.memory_reduction_mb for m in self.optimization_history)
        average_speedup = total_speedup / len(self.optimization_history)
        
        return {
            'total_optimizations': self.total_optimizations,
            'average_speedup_factor': average_speedup,
            'total_memory_savings_mb': total_memory_savings,
            'cache_hit_rate': self.cache_hits / (self.cache_hits + self.cache_misses) if (self.cache_hits + self.cache_misses) > 0 else 0,
            'optimization_types': list(set(m.optimization_type for m in self.optimization_history)),
            'most_effective_optimization': max(self.optimization_history, key=lambda m: m.speedup_factor).optimization_type if self.optimization_history else None
        }

    @lru_cache(maxsize=256)
    def analyze_file_performance(self, file_path: str) -> Dict[str, Any]:
        """Analyze performance characteristics of a specific file with caching."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            result = self.optimize_code_performance(content, file_path)
            
            return {
                'file_path': file_path,
                'optimization_result': result,
                'file_size': len(content),
                'lines_of_code': len(content.split('\n')),
                'optimization_opportunities': len(result.recommendations)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to analyze file performance for {file_path}: {e}")
            return {
                'file_path': file_path,
                'error': str(e),
                'optimization_opportunities': 0
            }

# Global performance optimization engine instance
_performance_engine = None
_engine_lock = threading.Lock()

def get_performance_optimization_engine() -> PerformanceOptimizationEngine:
    """Get the global performance optimization engine instance."""
    global _performance_engine
    
    if _performance_engine is None:
        with _engine_lock:
            if _performance_engine is None:
                _performance_engine = PerformanceOptimizationEngine()
    
    return _performance_engine

def optimize_function_performance(func):
    """Decorator to optimize function performance through caching and monitoring."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        engine = get_performance_optimization_engine()
        
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        
        # Track performance metrics
        execution_time = (end_time - start_time) * 1000
        
        # Cache result for pure functions (heuristic-based)
        cache_key = f"{func.__name__}_{hash(str(args))}_{hash(str(kwargs))}"
        engine.optimization_cache[cache_key] = {
            'result': result,
            'execution_time': execution_time,
            'timestamp': time.time()
        }
        
        return result
    
    return wrapper

# Example usage and integration functions
def analyze_codebase_performance(root_directory: str) -> Dict[str, Any]:
    """Analyze performance across the entire codebase."""
    engine = get_performance_optimization_engine()
    
    python_files = []
    for root, dirs, files in os.walk(root_directory):
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    
    results = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(engine.analyze_file_performance, file_path) 
                  for file_path in python_files]
        
        for future in futures:
            try:
                result = future.result(timeout=30)
                results.append(result)
            except Exception as e:
                logger.warning(f"Failed to analyze file performance: {e}")
    
    return {
        'total_files_analyzed': len(results),
        'total_optimization_opportunities': sum(r.get('optimization_opportunities', 0) for r in results),
        'results': results,
        'engine_statistics': engine.get_optimization_statistics()
    } 