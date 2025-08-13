"""
AODS Shared Infrastructure Package

Provides enterprise-grade shared infrastructure components for AODS modular architecture:
- Dependency injection framework for clean component instantiation
- Structured error handling with hierarchical exceptions
- Parallel processing architecture for large-scale analysis
- Pattern reliability database for historical accuracy tracking
- Learning system for continuous confidence improvement
- Universal file handling utilities for consistent I/O operations
- Data transformation and parsing utilities
- Cross-plugin utilities for common operations
- Universal pattern matching system

This package enables clean separation of concerns, improved testability,
and maintainable architecture across all AODS plugins.
"""

# AODS Shared Infrastructure
# Core shared components for modular architecture

# Analysis exceptions - Generic naming for enterprise-grade API design
from .analysis_exceptions import (
    AnalysisError,  # Primary generic error class
    ErrorContext,
    ContextualLogger,
    ErrorRecoveryManager,
    get_recovery_manager,
    safe_execute,
    # Specific exception types
    ConfigurationError,
    PatternAnalysisError,
    ConfidenceCalculationError,
    CryptoAnalysisError,
    BinaryAnalysisError,
    NetworkAnalysisError,
    StorageAnalysisError,
    PlatformAnalysisError,
    DecompilationError,
    FileSystemError,
    DependencyInjectionError,
    ParallelProcessingError,
    ValidationError,
    # Backward compatibility
    AODSAnalysisError,  # Alias for AnalysisError - deprecated, use AnalysisError instead
)

# Dependency injection (only available functions)
from .dependency_injection import (
    AnalysisContext,
    create_analysis_context,
)

# File handling utilities
from .file_handlers import (
    FileTypeDetector,
    SafeFileReader,
    APKFileExtractor,
    DirectoryAnalyzer,
    StringExtractor,
    PathUtils
)

# Data transformation utilities
from .data_transformers import (
    CompiledPattern,
    PatternCompiler,
    ContentParser,
    DataValidator,
    EncodingUtils,
    ContentAnalyzer
)

# Cross-plugin utilities
from .cross_plugin_utilities import (
    PerformanceMetrics,
    PerformanceMonitor,
    TextFormatter,
    HashingUtils,
    ConfigurationHelper,
    ResultAggregator,
    ErrorHandler,
    performance_monitor
)

# Universal pattern matching
from .universal_pattern_matcher import (
    PatternMatch,
    PatternDefinition,
    PatternLibrary,
    UniversalPatternMatcher,
    global_pattern_matcher
)

# Monitoring framework
from .monitoring import (
    get_performance_tracker,
    get_resource_monitor,
    get_health_checker,
    get_alert_manager,
    get_metrics_collector,
    get_trend_analyzer,
    PerformanceTracker,
    ResourceMonitor,
    HealthChecker,
    AlertManager,
    MetricsCollector,
    TrendAnalyzer,
    AlertSeverity,
    AlertType,
    HealthStatus,
    MetricType
)

__all__ = [
    # Primary exports - Generic naming
    'AnalysisError',           # Primary generic error class
    'ErrorContext',
    'ContextualLogger',
    'ErrorRecoveryManager',
    'get_recovery_manager',
    'safe_execute',
    
    # Specific exception types  
    'ConfigurationError',
    'PatternAnalysisError',
    'ConfidenceCalculationError',
    'CryptoAnalysisError',
    'BinaryAnalysisError',
    'NetworkAnalysisError',
    'StorageAnalysisError',
    'PlatformAnalysisError',
    'DecompilationError',
    'FileSystemError',
    'DependencyInjectionError',
    'ParallelProcessingError',
    'ValidationError',
    
    # Dependency injection (actual available functions)
    'AnalysisContext',
    'create_analysis_context',
    
    # File handling utilities
    'FileTypeDetector',
    'SafeFileReader',
    'APKFileExtractor',
    'DirectoryAnalyzer',
    'StringExtractor',
    'PathUtils',
    
    # Data transformation utilities
    'CompiledPattern',
    'PatternCompiler',
    'ContentParser',
    'DataValidator',
    'EncodingUtils',
    'ContentAnalyzer',
    
    # Cross-plugin utilities
    'PerformanceMetrics',
    'PerformanceMonitor',
    'TextFormatter',
    'HashingUtils',
    'ConfigurationHelper',
    'ResultAggregator',
    'ErrorHandler',
    'performance_monitor',
    
    # Universal pattern matching
    'PatternMatch',
    'PatternDefinition',
    'PatternLibrary',
    'UniversalPatternMatcher',
    'global_pattern_matcher',
    
    # Monitoring framework - Core components
    'PerformanceTracker',
    'ResourceMonitor', 
    'HealthChecker',
    'AlertManager',
    'MetricsCollector',
    'TrendAnalyzer',
    
    # Monitoring framework - Enums and types
    'AlertSeverity',
    'AlertType',
    'HealthStatus',
    'MetricType',
    
    # Monitoring framework - Singleton getters
    'get_performance_tracker',
    'get_resource_monitor',
    'get_health_checker',
    'get_alert_manager',
    'get_metrics_collector',
    'get_trend_analyzer',
    
    # Monitoring framework - Integration helpers
    
    # JADX Unified Helper - Memory optimization for decompilation
    'JADXUnifiedHelper',
    'get_jadx_helper',
    'get_decompiled_sources_unified',
    'analyze_with_jadx_optimized',
]

# JADX Unified Helper - Memory optimization
from .jadx_unified_helper import (
    JADXUnifiedHelper,
    get_jadx_helper,
    get_decompiled_sources_unified,
    analyze_with_jadx_optimized,
)

__version__ = "2.0.0"
__author__ = "AODS Team"
__description__ = "Comprehensive shared infrastructure with consolidated utilities for AODS modular architecture" 