#!/usr/bin/env python3
"""
AODS Shared Infrastructure - Testing Package

Comprehensive testing framework for AODS providing:
- Mock data generators for consistent test data
- Test helpers for plugin and framework testing
- Performance benchmarking and validation
- Common testing patterns and utilities
- APK test data generation
- Analysis result validation

This package ensures reliable, consistent testing across all AODS components
while reducing test code duplication and improving test maintainability.

Components:
- mock_generators: Mock data generation for testing
- test_helpers: Common test utilities and patterns  
- performance_benchmarks: Performance testing and validation

Usage:
    from core.shared_infrastructure.testing import (
        get_test_data_generator,
        create_test_apk_context,
        run_plugin_tests,
        benchmark_plugin,
        get_performance_benchmark
    )
    
    # Generate test data
    generator = get_test_data_generator()
    apk_metadata = generator.generate_apk_metadata()
    
    # Create test context
    context = create_test_apk_context("com.test.app")
    
    # Run plugin tests
    results = run_plugin_tests(MyPlugin, test_cases)
    
    # Benchmark plugin performance
    benchmark_results = benchmark_plugin(plugin_instance, context)
"""

# Mock data generators - import actual available classes
try:
    from .mock_generators import (
        MockConfiguration,
        MockAPKContext,
        MockAnalysisContext,
        MockVulnerabilityFinding,
        MockSecurityFinding,
        MockPluginManager,
        MockGenerator
    )
    MOCK_GENERATORS_AVAILABLE = True
except ImportError as e:
    MOCK_GENERATORS_AVAILABLE = False
    MockConfiguration = None
    MockAPKContext = None

# Test helpers and utilities
try:
    from .test_helpers import (
        TestAPKMetadata,
        TestAnalysisResult,
        TestDataGenerator,
        PluginTestHelper,
        FrameworkTestHelper,
        PerformanceTestHelper,
        get_test_data_generator,
        create_test_apk_context,
        run_plugin_tests,
        benchmark_plugin
    )
    TEST_HELPERS_AVAILABLE = True
except ImportError as e:
    TEST_HELPERS_AVAILABLE = False
    TestDataGenerator = None

# Performance benchmarking
try:
    from .performance_benchmarks import (
        BenchmarkResult,
        BenchmarkSuite,
        PerformanceBenchmark,
        get_performance_benchmark,
        quick_plugin_benchmark,
        benchmark_all_plugins
    )
    PERFORMANCE_BENCHMARKS_AVAILABLE = True
except ImportError as e:
    PERFORMANCE_BENCHMARKS_AVAILABLE = False
    PerformanceBenchmark = None

# Version and metadata
__version__ = "1.0.0"
__author__ = "AODS Development Team"
__description__ = "Comprehensive Testing Framework for AODS Shared Infrastructure"

# Build exports list based on available components
__all__ = []

if MOCK_GENERATORS_AVAILABLE:
    __all__.extend([
        "MockConfiguration",
        "MockAPKContext", 
        "MockAnalysisContext",
        "MockVulnerabilityFinding",
        "MockSecurityFinding",
        "MockPluginManager",
        "MockGenerator"
    ])

if TEST_HELPERS_AVAILABLE:
    __all__.extend([
        "TestAPKMetadata",
        "TestAnalysisResult",
        "TestDataGenerator",
        "PluginTestHelper",
        "FrameworkTestHelper", 
        "PerformanceTestHelper",
        "get_test_data_generator",
        "create_test_apk_context",
        "run_plugin_tests",
        "benchmark_plugin"
    ])

if PERFORMANCE_BENCHMARKS_AVAILABLE:
    __all__.extend([
        "BenchmarkResult",
        "BenchmarkSuite",
        "PerformanceBenchmark",
        "get_performance_benchmark",
        "quick_plugin_benchmark",
        "benchmark_all_plugins"
    ])

# Always include metadata
__all__.extend([
    "__version__",
    "__author__",
    "__description__"
])

# Convenience functions
def create_mock_apk_data(package_name: str = "com.test.app") -> MockAPKContext:
    """Create mock APK data for testing."""
    if not MOCK_GENERATORS_AVAILABLE:
        raise ImportError("Mock generators not available")
    return MockAPKContext(package_name=package_name)

def create_mock_analysis_result(plugin_name: str = "test_plugin", 
                               success: bool = True) -> Dict[str, Any]:
    """Create mock analysis result for testing."""
    return {
        "plugin_name": plugin_name,
        "success": success,
        "findings": [],
        "execution_time": 1.0,
        "timestamp": time.time()
    }

# Add convenience functions to exports if available
if MOCK_GENERATORS_AVAILABLE:
    __all__.extend(["create_mock_apk_data"])

__all__.append("create_mock_analysis_result")

import logging
import time
logger = logging.getLogger(__name__)
logger.info(f"AODS Testing Framework v{__version__} initialized")
logger.info(f"Available components: Mock Generators: {MOCK_GENERATORS_AVAILABLE}, "
           f"Test Helpers: {TEST_HELPERS_AVAILABLE}, "
           f"Performance Benchmarks: {PERFORMANCE_BENCHMARKS_AVAILABLE}") 