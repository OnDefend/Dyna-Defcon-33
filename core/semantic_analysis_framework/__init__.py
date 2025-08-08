"""
AODS Unified Semantic Analysis Framework

This module provides semantic code analysis capabilities for vulnerability detection,
following AODS established modular patterns with strategy-based architecture.

Key Features:
- Unified strategy pattern for multiple parsing approaches
- Intelligent parser selection and coordination
- Integration with existing AODS shared infrastructure
- Comprehensive error handling and fallback mechanisms
- Support for Java, Kotlin, JavaScript, and Smali languages

Architecture:
- UnifiedSemanticParserManager: Main orchestrator with strategy selection
- Multiple parsing strategies for different scenarios
- Language-specific handlers with interop support
- Shared infrastructure integration for caching and performance
"""

from typing import Dict, List, Optional, Union, Any
import logging

# Import strategy implementations
from .unified_parser_manager import UnifiedSemanticParserManager
from .parser_strategies import (
    ParsingStrategy,
    ComprehensiveParsingStrategy,
    PerformanceParsingStrategy,
    FallbackParsingStrategy,
    LargeFileParsingStrategy
)
from .ast_builder import SemanticASTBuilder
from .data_structures import (
    SemanticParsingResult,
    SemanticNode,
    VulnerabilityPattern,
    ParsingContext,
    LanguageInfo
)

# Language handlers
from .language_handlers.java_handler import JavaSemanticHandler
from .language_handlers.kotlin_handler import KotlinSemanticHandler
from .language_handlers.javascript_handler import JavaScriptSemanticHandler
from .language_handlers.smali_handler import SmaliSemanticHandler

# Shared infrastructure components
from .shared_infrastructure.caching_manager import SemanticCacheManager
from .shared_infrastructure.performance_optimizer import SemanticPerformanceOptimizer
from .shared_infrastructure.error_handler import SemanticErrorHandler

# Configure logging
logger = logging.getLogger(__name__)

# Framework version and metadata
__version__ = "1.0.0"
__author__ = "AODS Development Team"
__description__ = "Unified Semantic Analysis Framework for AODS"

# Supported languages
SUPPORTED_LANGUAGES = {
    'java': JavaSemanticHandler,
    'kotlin': KotlinSemanticHandler,
    'javascript': JavaScriptSemanticHandler,
    'smali': SmaliSemanticHandler
}

# Available parsing strategies
AVAILABLE_STRATEGIES = {
    'comprehensive': ComprehensiveParsingStrategy,
    'performance_optimized': PerformanceParsingStrategy,
    'fallback': FallbackParsingStrategy,
    'large_file': LargeFileParsingStrategy
}

def create_semantic_parser(strategy: str = 'auto', 
                          enable_caching: bool = True,
                          performance_optimization: bool = True) -> UnifiedSemanticParserManager:
    """
    Factory function to create a configured semantic parser manager.
    
    Args:
        strategy: Parsing strategy to use ('auto' for intelligent selection)
        enable_caching: Whether to enable intelligent caching
        performance_optimization: Whether to enable performance optimization
        
    Returns:
        Configured UnifiedSemanticParserManager instance
        
    Example:
        >>> parser = create_semantic_parser(strategy='comprehensive')
        >>> result = parser.parse_code(java_code, 'java')
        >>> print(f"Found {len(result.vulnerabilities)} potential issues")
    """
    try:
        return UnifiedSemanticParserManager(
            default_strategy=strategy,
            enable_caching=enable_caching,
            enable_optimization=performance_optimization
        )
    except Exception as e:
        logger.error(f"Failed to create semantic parser: {e}")
        # Return fallback parser with minimal configuration
        return UnifiedSemanticParserManager(
            default_strategy='fallback',
            enable_caching=False,
            enable_optimization=False
        )

def get_supported_languages() -> List[str]:
    """
    Get list of supported programming languages.
    
    Returns:
        List of supported language identifiers
    """
    return list(SUPPORTED_LANGUAGES.keys())

def get_available_strategies() -> List[str]:
    """
    Get list of available parsing strategies.
    
    Returns:
        List of available strategy identifiers
    """
    return list(AVAILABLE_STRATEGIES.keys())

def validate_language_support(language: str) -> bool:
    """
    Check if a programming language is supported.
    
    Args:
        language: Language identifier to check
        
    Returns:
        True if language is supported, False otherwise
    """
    return language.lower() in SUPPORTED_LANGUAGES

# Export main classes and functions
__all__ = [
    # Main framework classes
    'UnifiedSemanticParserManager',
    'SemanticASTBuilder',
    
    # Strategy classes
    'ParsingStrategy',
    'ComprehensiveParsingStrategy',
    'PerformanceParsingStrategy',  
    'FallbackParsingStrategy',
    'LargeFileParsingStrategy',
    
    # Data structures
    'SemanticParsingResult',
    'SemanticNode',
    'VulnerabilityPattern',
    'ParsingContext',
    'LanguageInfo',
    
    # Language handlers
    'JavaSemanticHandler',
    'KotlinSemanticHandler',
    'JavaScriptSemanticHandler',
    'SmaliSemanticHandler',
    
    # Infrastructure components
    'SemanticCacheManager',
    'SemanticPerformanceOptimizer',
    'SemanticErrorHandler',
    
    # Utility functions
    'create_semantic_parser',
    'get_supported_languages',
    'get_available_strategies',
    'validate_language_support',
    
    # Constants
    'SUPPORTED_LANGUAGES',
    'AVAILABLE_STRATEGIES',
    '__version__'
]

# Initialize framework
logger.info(f"AODS Semantic Analysis Framework v{__version__} initialized")
logger.info(f"Supported languages: {', '.join(get_supported_languages())}")
logger.info(f"Available strategies: {', '.join(get_available_strategies())}") 