#!/usr/bin/env python3
"""
AODS Shared Infrastructure - Performance Benchmarks

Comprehensive performance benchmarking system for AODS framework validation,
providing standardized performance testing, analysis, and reporting capabilities.

Features:
- Plugin performance benchmarking
- Framework component performance testing
- Scalability testing with various APK sizes
- Memory usage analysis and optimization validation
- Parallel processing performance validation
- Historical performance tracking and comparison
- Performance regression detection
- Automated performance report generation

This component ensures AODS maintains optimal performance across all
components and identifies performance regressions early in development.
"""

import os
import json
import time
import logging
import statistics
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import hashlib
import gc

# Performance monitoring imports
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

try:
    import matplotlib.pyplot as plt
    import numpy as np
    PLOTTING_AVAILABLE = True
except ImportError:
    PLOTTING_AVAILABLE = False
    plt = None
    np = None

from .test_helpers import TestDataGenerator, PluginTestHelper
from ..analysis_exceptions import AnalysisError
from ..monitoring.performance_tracker import PerformanceTracker

logger = logging.getLogger(__name__)

@dataclass
class BenchmarkResult:
    """Individual benchmark test result."""
    test_name: str
    component_name: str
    execution_time: float
    memory_usage_mb: float
    cpu_usage_percent: float
    success: bool
    error_message: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    test_parameters: Dict[str, Any] = field(default_factory=dict)
    system_info: Dict[str, Any] = field(default_factory=dict)

@dataclass
class BenchmarkSuite:
    """Collection of benchmark results."""
    suite_name: str
    results: List[BenchmarkResult] = field(default_factory=list)
    total_execution_time: float = 0.0
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    system_info: Dict[str, Any] = field(default_factory=dict)
    
    def add_result(self, result: BenchmarkResult):
        """Add benchmark result to suite."""
        self.results.append(result)
        
    def finalize(self):
        """Finalize benchmark suite."""
        self.end_time = datetime.now()
        self.total_execution_time = (self.end_time - self.start_time).total_seconds()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistical summary of benchmark results."""
        if not self.results:
            return {}
            
        execution_times = [r.execution_time for r in self.results if r.success]
        memory_usage = [r.memory_usage_mb for r in self.results if r.success]
        cpu_usage = [r.cpu_usage_percent for r in self.results if r.success]
        
        success_rate = len([r for r in self.results if r.success]) / len(self.results)
        
        return {
            "total_tests": len(self.results),
            "successful_tests": len([r for r in self.results if r.success]),
            "failed_tests": len([r for r in self.results if not r.success]),
            "success_rate": success_rate,
            "avg_execution_time": statistics.mean(execution_times) if execution_times else 0,
            "median_execution_time": statistics.median(execution_times) if execution_times else 0,
            "min_execution_time": min(execution_times) if execution_times else 0,
            "max_execution_time": max(execution_times) if execution_times else 0,
            "std_execution_time": statistics.stdev(execution_times) if len(execution_times) > 1 else 0,
            "avg_memory_usage_mb": statistics.mean(memory_usage) if memory_usage else 0,
            "peak_memory_usage_mb": max(memory_usage) if memory_usage else 0,
            "avg_cpu_usage_percent": statistics.mean(cpu_usage) if cpu_usage else 0,
            "total_execution_time": self.total_execution_time
        }

class PerformanceBenchmark:
    """Comprehensive performance benchmarking system."""
    
    def __init__(self, results_dir: Path = None):
        """Initialize performance benchmark system."""
        self.results_dir = results_dir or Path("benchmark_results")
        self.results_dir.mkdir(exist_ok=True)
        
        self.test_data_generator = TestDataGenerator()
        self.performance_tracker = PerformanceTracker() if PSUTIL_AVAILABLE else None
        
        # Benchmark configuration
        self.benchmark_config = {
            "warmup_iterations": 2,
            "benchmark_iterations": 5,
            "timeout_seconds": 300,
            "memory_sampling_interval": 0.1,
            "enable_memory_profiling": True,
            "enable_cpu_profiling": True
        }
        
        logger.info(f"Performance benchmark system initialized - results: {self.results_dir}")
    
    def benchmark_plugin(self, plugin_class: type, 
                        test_scenarios: List[Dict[str, Any]] = None) -> BenchmarkSuite:
        """Benchmark plugin performance across multiple scenarios."""
        suite_name = f"{plugin_class.__name__}_benchmark"
        suite = BenchmarkSuite(suite_name=suite_name)
        
        if test_scenarios is None:
            test_scenarios = self._get_default_plugin_scenarios()
        
        logger.info(f"Starting plugin benchmark: {plugin_class.__name__}")
        
        try:
            # System information
            suite.system_info = self._get_system_info()
            
            for scenario in test_scenarios:
                scenario_name = scenario.get("name", "default_scenario")
                logger.info(f"Running scenario: {scenario_name}")
                
                # Run warmup iterations
                self._run_warmup(plugin_class, scenario)
                
                # Run benchmark iterations
                for iteration in range(self.benchmark_config["benchmark_iterations"]):
                    test_name = f"{scenario_name}_iteration_{iteration}"
                    
                    result = self._benchmark_single_plugin_run(
                        plugin_class, scenario, test_name
                    )
                    suite.add_result(result)
            
            suite.finalize()
            self._save_benchmark_results(suite)
            
            logger.info(f"Plugin benchmark completed: {suite.get_statistics()}")
            
        except Exception as e:
            logger.error(f"Plugin benchmark failed: {e}")
            suite.finalize()
        
        return suite
    
    def benchmark_framework_components(self, 
                                     components: List[Tuple[str, Callable]] = None) -> BenchmarkSuite:
        """Benchmark core framework components."""
        suite = BenchmarkSuite(suite_name="framework_components_benchmark")
        
        if components is None:
            components = self._get_default_framework_components()
        
        logger.info("Starting framework components benchmark")
        
        try:
            suite.system_info = self._get_system_info()
            
            for component_name, component_func in components:
                logger.info(f"Benchmarking component: {component_name}")
                
                # Run warmup
                self._run_component_warmup(component_func)
                
                # Run benchmark iterations
                for iteration in range(self.benchmark_config["benchmark_iterations"]):
                    test_name = f"{component_name}_iteration_{iteration}"
                    
                    result = self._benchmark_single_component_run(
                        component_name, component_func, test_name
                    )
                    suite.add_result(result)
            
            suite.finalize()
            self._save_benchmark_results(suite)
            
            logger.info(f"Framework benchmark completed: {suite.get_statistics()}")
            
        except Exception as e:
            logger.error(f"Framework benchmark failed: {e}")
            suite.finalize()
        
        return suite
    
    def scalability_test(self, plugin_class: type, 
                        apk_sizes: List[int] = None) -> BenchmarkSuite:
        """Test plugin scalability with different APK sizes."""
        suite = BenchmarkSuite(suite_name=f"{plugin_class.__name__}_scalability")
        
        if apk_sizes is None:
            apk_sizes = [1, 5, 10, 25, 50, 100]  # MB
        
        logger.info(f"Starting scalability test: {plugin_class.__name__}")
        
        try:
            suite.system_info = self._get_system_info()
            
            for size_mb in apk_sizes:
                logger.info(f"Testing with {size_mb}MB APK")
                
                # Generate test APK of specified size
                test_context = self._create_sized_test_context(size_mb)
                
                # Run multiple iterations for this size
                for iteration in range(self.benchmark_config["benchmark_iterations"]):
                    test_name = f"size_{size_mb}mb_iteration_{iteration}"
                    
                    result = self._benchmark_plugin_with_context(
                        plugin_class, test_context, test_name, 
                        {"apk_size_mb": size_mb}
                    )
                    suite.add_result(result)
            
            suite.finalize()
            self._save_benchmark_results(suite)
            
            logger.info(f"Scalability test completed: {suite.get_statistics()}")
            
        except Exception as e:
            logger.error(f"Scalability test failed: {e}")
            suite.finalize()
        
        return suite
    
    def parallel_processing_benchmark(self, plugin_class: type, 
                                    worker_counts: List[int] = None) -> BenchmarkSuite:
        """Benchmark parallel processing performance."""
        suite = BenchmarkSuite(suite_name=f"{plugin_class.__name__}_parallel_benchmark")
        
        if worker_counts is None:
            worker_counts = [1, 2, 4, 8, 16]
        
        logger.info(f"Starting parallel processing benchmark: {plugin_class.__name__}")
        
        try:
            suite.system_info = self._get_system_info()
            
            # Create multiple test contexts
            test_contexts = [
                self.test_data_generator.generate_apk_metadata(f"com.test.app{i}")
                for i in range(20)  # 20 test APKs
            ]
            
            for worker_count in worker_counts:
                logger.info(f"Testing with {worker_count} workers")
                
                for iteration in range(self.benchmark_config["benchmark_iterations"]):
                    test_name = f"workers_{worker_count}_iteration_{iteration}"
                    
                    result = self._benchmark_parallel_execution(
                        plugin_class, test_contexts, worker_count, test_name
                    )
                    suite.add_result(result)
            
            suite.finalize()
            self._save_benchmark_results(suite)
            
            logger.info(f"Parallel processing benchmark completed: {suite.get_statistics()}")
            
        except Exception as e:
            logger.error(f"Parallel processing benchmark failed: {e}")
            suite.finalize()
        
        return suite
    
    def memory_stress_test(self, plugin_class: type, 
                          memory_limits: List[int] = None) -> BenchmarkSuite:
        """Test plugin behavior under memory constraints."""
        suite = BenchmarkSuite(suite_name=f"{plugin_class.__name__}_memory_stress")
        
        if memory_limits is None:
            memory_limits = [100, 250, 500, 1000, 2000]  # MB
        
        logger.info(f"Starting memory stress test: {plugin_class.__name__}")
        
        try:
            suite.system_info = self._get_system_info()
            
            for memory_limit_mb in memory_limits:
                logger.info(f"Testing with {memory_limit_mb}MB memory limit")
                
                for iteration in range(self.benchmark_config["benchmark_iterations"]):
                    test_name = f"memory_{memory_limit_mb}mb_iteration_{iteration}"
                    
                    result = self._benchmark_with_memory_limit(
                        plugin_class, memory_limit_mb, test_name
                    )
                    suite.add_result(result)
            
            suite.finalize()
            self._save_benchmark_results(suite)
            
            logger.info(f"Memory stress test completed: {suite.get_statistics()}")
            
        except Exception as e:
            logger.error(f"Memory stress test failed: {e}")
            suite.finalize()
        
        return suite
    
    def _benchmark_single_plugin_run(self, plugin_class: type, 
                                   scenario: Dict[str, Any], 
                                   test_name: str) -> BenchmarkResult:
        """Benchmark single plugin execution."""
        gc.collect()  # Clean up before test
        
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil not available - limited performance monitoring")
        
        try:
            # Create test context
            test_context = PluginTestHelper.create_mock_apk_context(
                scenario.get("package_name", "com.test.app")
            )
            
            # Add scenario-specific context modifications
            if "context_modifications" in scenario:
                for key, value in scenario["context_modifications"].items():
                    setattr(test_context, key, value)
            
            # Initialize plugin
            plugin_instance = plugin_class()
            
            # Performance monitoring setup
            start_memory = 0
            start_cpu = 0
            if PSUTIL_AVAILABLE:
                process = psutil.Process()
                start_memory = process.memory_info().rss / (1024 * 1024)  # MB
                start_cpu = process.cpu_percent()
            
            # Execute plugin
            start_time = time.perf_counter()
            
            if hasattr(plugin_instance, 'run_plugin'):
                result = plugin_instance.run_plugin(test_context)
            else:
                result = plugin_instance(test_context)  # Fallback callable
            
            end_time = time.perf_counter()
            
            # Performance monitoring cleanup
            execution_time = end_time - start_time
            memory_usage = 0
            cpu_usage = 0
            
            if PSUTIL_AVAILABLE:
                end_memory = process.memory_info().rss / (1024 * 1024)  # MB
                memory_usage = end_memory - start_memory
                cpu_usage = process.cpu_percent()
            
            # Validate result
            success = self._validate_plugin_result(result)
            
            return BenchmarkResult(
                test_name=test_name,
                component_name=plugin_class.__name__,
                execution_time=execution_time,
                memory_usage_mb=memory_usage,
                cpu_usage_percent=cpu_usage,
                success=success,
                test_parameters=scenario,
                system_info=self._get_system_info()
            )
            
        except Exception as e:
            logger.error(f"Plugin benchmark failed: {e}")
            return BenchmarkResult(
                test_name=test_name,
                component_name=plugin_class.__name__,
                execution_time=0,
                memory_usage_mb=0,
                cpu_usage_percent=0,
                success=False,
                error_message=str(e),
                test_parameters=scenario,
                system_info=self._get_system_info()
            )
    
    def _benchmark_single_component_run(self, component_name: str, 
                                      component_func: Callable, 
                                      test_name: str) -> BenchmarkResult:
        """Benchmark single framework component execution."""
        gc.collect()
        
        try:
            # Performance monitoring setup
            start_memory = 0
            if PSUTIL_AVAILABLE:
                process = psutil.Process()
                start_memory = process.memory_info().rss / (1024 * 1024)
            
            # Execute component
            start_time = time.perf_counter()
            result = component_func()
            end_time = time.perf_counter()
            
            execution_time = end_time - start_time
            memory_usage = 0
            
            if PSUTIL_AVAILABLE:
                end_memory = process.memory_info().rss / (1024 * 1024)
                memory_usage = end_memory - start_memory
            
            return BenchmarkResult(
                test_name=test_name,
                component_name=component_name,
                execution_time=execution_time,
                memory_usage_mb=memory_usage,
                cpu_usage_percent=0,
                success=True,
                system_info=self._get_system_info()
            )
            
        except Exception as e:
            logger.error(f"Component benchmark failed: {e}")
            return BenchmarkResult(
                test_name=test_name,
                component_name=component_name,
                execution_time=0,
                memory_usage_mb=0,
                cpu_usage_percent=0,
                success=False,
                error_message=str(e),
                system_info=self._get_system_info()
            )
    
    def _benchmark_parallel_execution(self, plugin_class: type, 
                                    test_contexts: List[Any], 
                                    worker_count: int, 
                                    test_name: str) -> BenchmarkResult:
        """Benchmark parallel plugin execution."""
        gc.collect()
        
        try:
            start_memory = 0
            if PSUTIL_AVAILABLE:
                process = psutil.Process()
                start_memory = process.memory_info().rss / (1024 * 1024)
            
            start_time = time.perf_counter()
            
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = []
                
                for context in test_contexts:
                    plugin_instance = plugin_class()
                    future = executor.submit(plugin_instance.run_plugin, context)
                    futures.append(future)
                
                # Wait for all to complete
                results = []
                for future in as_completed(futures, timeout=self.benchmark_config["timeout_seconds"]):
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        logger.warning(f"Parallel execution failed: {e}")
            
            end_time = time.perf_counter()
            execution_time = end_time - start_time
            
            memory_usage = 0
            if PSUTIL_AVAILABLE:
                end_memory = process.memory_info().rss / (1024 * 1024)
                memory_usage = end_memory - start_memory
            
            success = len(results) == len(test_contexts)
            
            return BenchmarkResult(
                test_name=test_name,
                component_name=f"{plugin_class.__name__}_parallel",
                execution_time=execution_time,
                memory_usage_mb=memory_usage,
                cpu_usage_percent=0,
                success=success,
                test_parameters={"worker_count": worker_count, "context_count": len(test_contexts)},
                system_info=self._get_system_info()
            )
            
        except Exception as e:
            logger.error(f"Parallel benchmark failed: {e}")
            return BenchmarkResult(
                test_name=test_name,
                component_name=f"{plugin_class.__name__}_parallel",
                execution_time=0,
                memory_usage_mb=0,
                cpu_usage_percent=0,
                success=False,
                error_message=str(e),
                test_parameters={"worker_count": worker_count},
                system_info=self._get_system_info()
            )
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get current system information."""
        system_info = {
            "timestamp": datetime.now().isoformat(),
            "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}"
        }
        
        if PSUTIL_AVAILABLE:
            system_info.update({
                "cpu_count": psutil.cpu_count(),
                "cpu_count_logical": psutil.cpu_count(logical=True),
                "memory_total_gb": psutil.virtual_memory().total / (1024**3),
                "memory_available_gb": psutil.virtual_memory().available / (1024**3),
                "disk_free_gb": psutil.disk_usage('/').free / (1024**3)
            })
        
        return system_info
    
    def _get_default_plugin_scenarios(self) -> List[Dict[str, Any]]:
        """Get default plugin test scenarios."""
        return [
            {
                "name": "basic_scenario",
                "package_name": "com.test.basic",
                "context_modifications": {}
            },
            {
                "name": "large_app_scenario", 
                "package_name": "com.test.large",
                "context_modifications": {
                    "file_size": 50000000,  # 50MB
                    "version_code": 100
                }
            },
            {
                "name": "complex_permissions_scenario",
                "package_name": "com.test.permissions",
                "context_modifications": {
                    "get_permissions": lambda: [
                        "android.permission.INTERNET",
                        "android.permission.ACCESS_FINE_LOCATION",
                        "android.permission.CAMERA",
                        "android.permission.READ_CONTACTS",
                        "android.permission.WRITE_EXTERNAL_STORAGE"
                    ]
                }
            }
        ]
    
    def _get_default_framework_components(self) -> List[Tuple[str, Callable]]:
        """Get default framework components for testing."""
        return [
            ("test_data_generation", lambda: self.test_data_generator.generate_apk_metadata()),
            ("mock_context_creation", lambda: PluginTestHelper.create_mock_apk_context()),
            ("json_serialization", lambda: json.dumps({"test": "data", "nested": {"value": 123}})),
            ("file_hash_calculation", lambda: hashlib.sha256(b"test data for hashing").hexdigest())
        ]
    
    def _run_warmup(self, plugin_class: type, scenario: Dict[str, Any]):
        """Run warmup iterations for plugin."""
        for _ in range(self.benchmark_config["warmup_iterations"]):
            try:
                plugin_instance = plugin_class()
                test_context = PluginTestHelper.create_mock_apk_context(
                    scenario.get("package_name", "com.test.app")
                )
                
                if hasattr(plugin_instance, 'run_plugin'):
                    plugin_instance.run_plugin(test_context)
                else:
                    plugin_instance(test_context)
                    
            except Exception as e:
                logger.warning(f"Warmup iteration failed: {e}")
    
    def _run_component_warmup(self, component_func: Callable):
        """Run warmup iterations for component."""
        for _ in range(self.benchmark_config["warmup_iterations"]):
            try:
                component_func()
            except Exception as e:
                logger.warning(f"Component warmup failed: {e}")
    
    def _validate_plugin_result(self, result: Any) -> bool:
        """Validate plugin execution result."""
        if isinstance(result, dict):
            return result.get("success", False)
        elif hasattr(result, "success"):
            return result.success
        else:
            return result is not None
    
    def _save_benchmark_results(self, suite: BenchmarkSuite):
        """Save benchmark results to disk."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{suite.suite_name}_{timestamp}.json"
        filepath = self.results_dir / filename
        
        try:
            # Convert suite to serializable format
            suite_data = {
                "suite_name": suite.suite_name,
                "start_time": suite.start_time.isoformat(),
                "end_time": suite.end_time.isoformat() if suite.end_time else None,
                "total_execution_time": suite.total_execution_time,
                "system_info": suite.system_info,
                "statistics": suite.get_statistics(),
                "results": [asdict(result) for result in suite.results]
            }
            
            with open(filepath, 'w') as f:
                json.dump(suite_data, f, indent=2, default=str)
            
            logger.info(f"Benchmark results saved: {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to save benchmark results: {e}")
    
    def _create_sized_test_context(self, size_mb: int):
        """Create test context simulating specific APK size."""
        context = PluginTestHelper.create_mock_apk_context()
        context.file_size = size_mb * 1024 * 1024  # Convert to bytes
        return context
    
    def _benchmark_plugin_with_context(self, plugin_class: type, 
                                     test_context: Any, 
                                     test_name: str,
                                     test_parameters: Dict[str, Any]) -> BenchmarkResult:
        """Benchmark plugin with specific context."""
        gc.collect()
        
        try:
            start_memory = 0
            if PSUTIL_AVAILABLE:
                process = psutil.Process()
                start_memory = process.memory_info().rss / (1024 * 1024)
            
            plugin_instance = plugin_class()
            
            start_time = time.perf_counter()
            result = plugin_instance.run_plugin(test_context)
            end_time = time.perf_counter()
            
            execution_time = end_time - start_time
            memory_usage = 0
            
            if PSUTIL_AVAILABLE:
                end_memory = process.memory_info().rss / (1024 * 1024)
                memory_usage = end_memory - start_memory
            
            success = self._validate_plugin_result(result)
            
            return BenchmarkResult(
                test_name=test_name,
                component_name=plugin_class.__name__,
                execution_time=execution_time,
                memory_usage_mb=memory_usage,
                cpu_usage_percent=0,
                success=success,
                test_parameters=test_parameters,
                system_info=self._get_system_info()
            )
            
        except Exception as e:
            logger.error(f"Context benchmark failed: {e}")
            return BenchmarkResult(
                test_name=test_name,
                component_name=plugin_class.__name__,
                execution_time=0,
                memory_usage_mb=0,
                cpu_usage_percent=0,
                success=False,
                error_message=str(e),
                test_parameters=test_parameters,
                system_info=self._get_system_info()
            )
    
    def _benchmark_with_memory_limit(self, plugin_class: type, 
                                   memory_limit_mb: int, 
                                   test_name: str) -> BenchmarkResult:
        """Benchmark plugin with memory constraints."""
        # Note: Actual memory limiting would require OS-level controls
        # This is a simplified simulation
        
        test_context = PluginTestHelper.create_mock_apk_context()
        test_parameters = {"memory_limit_mb": memory_limit_mb}
        
        return self._benchmark_plugin_with_context(
            plugin_class, test_context, test_name, test_parameters
        )

# Convenience functions
def get_performance_benchmark(results_dir: Path = None) -> PerformanceBenchmark:
    """Get performance benchmark instance."""
    return PerformanceBenchmark(results_dir)

def quick_plugin_benchmark(plugin_class: type) -> Dict[str, Any]:
    """Run quick performance benchmark for plugin."""
    benchmark = PerformanceBenchmark()
    suite = benchmark.benchmark_plugin(plugin_class)
    return suite.get_statistics()

def benchmark_all_plugins(plugin_classes: List[type]) -> Dict[str, Dict[str, Any]]:
    """Benchmark multiple plugins and return comparative results."""
    benchmark = PerformanceBenchmark()
    results = {}
    
    for plugin_class in plugin_classes:
        logger.info(f"Benchmarking {plugin_class.__name__}")
        suite = benchmark.benchmark_plugin(plugin_class)
        results[plugin_class.__name__] = suite.get_statistics()
    
    return results

# Export all public components
__all__ = [
    "BenchmarkResult",
    "BenchmarkSuite", 
    "PerformanceBenchmark",
    "get_performance_benchmark",
    "quick_plugin_benchmark",
    "benchmark_all_plugins"
]

logger.info("AODS Performance Benchmarks initialized - comprehensive performance testing ready") 