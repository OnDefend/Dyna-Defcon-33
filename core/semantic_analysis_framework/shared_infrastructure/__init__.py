"""
Shared Infrastructure for AODS Semantic Analysis Framework

This package provides shared infrastructure components that integrate with
existing AODS frameworks for optimal performance and compatibility.
"""

from .caching_manager import SemanticCacheManager

# Placeholder imports for components that will be created
try:
    from .performance_optimizer import SemanticPerformanceOptimizer
except ImportError:
    SemanticPerformanceOptimizer = None

try:
    from .error_handler import SemanticErrorHandler
except ImportError:
    SemanticErrorHandler = None

__all__ = [
    'SemanticCacheManager',
    'SemanticPerformanceOptimizer', 
    'SemanticErrorHandler'
] 