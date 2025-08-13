#!/usr/bin/env python3
"""
Enhanced False Positive Reduction Framework
===========================================

This package provides comprehensive false positive reduction capabilities for
the AODS security analysis framework through a modular architecture.

The framework integrates multiple specialized libraries to achieve ultimate
accuracy in secret detection by eliminating false positives through:

1. High-quality secret detection with ML enhancement
2. Advanced entropy analysis with multiple algorithms  
3. Context-aware analysis with comprehensive API detection
4. Framework-specific pattern recognition and filtering
5. Performance-optimized analysis pipeline with caching
6. Explainable AI for classification reasoning and transparency

Architecture:
- data_structures: Core data models and result structures
- ml_classifier: Machine learning classifier targeting <2% false positive rate
- context_analyzer: Context-aware analysis with API detection capabilities
- secret_analyzer: Main analysis engine with comprehensive detection
- integration_helpers: Seamless integration with existing AODS components
- enhanced_false_positive_reducer: Backward-compatible main orchestrator

"""

# Version information
__version__ = "3.0.0"
__architecture__ = "modular"
__author__ = "AODS Development Team"
__description__ = "Enhanced False Positive Reduction Framework with ML and Context-Aware Analysis"

# Core data structures
from .data_structures import (
    ContextAnalysisResult,
    EntropyAnalysisResult,
    FrameworkAnalysisResult,
    MLModelPerformance,
    PatternMatchResult,
    SecretAnalysisResult
)

# Main components
from .context_analyzer import EnhancedContextAnalyzer
from .ml_classifier import MLEnhancedSecretClassifier
from .secret_analyzer import EnhancedSecretAnalyzer

# Main orchestrator (backward compatible)
from .enhanced_false_positive_reducer import (
    EnhancedFalsePositiveReducer,
    analyze_secret,
    create_enhanced_secret_analyzer,
    is_likely_secret_simple
)

# Integration helpers
from .integration_helpers import (
    integrate_enhanced_false_positive_reducer,
    integrate_with_apk2url_extraction,
    integrate_with_dynamic_analyzer,
    integrate_with_enhanced_static_analyzer,
    integrate_with_vulnerability_scanner
)

# Backward compatibility aliases
EnhancedSecretAnalyzer = EnhancedFalsePositiveReducer
integrate_with_enhanced_static_analyzer = integrate_with_enhanced_static_analyzer
integrate_with_apk2url_extraction = integrate_with_apk2url_extraction

# Public API exports
__all__ = [
    # Version and metadata
    "__version__",
    "__architecture__",
    "__author__",
    "__description__",
    
    # Data structures
    "SecretAnalysisResult",
    "ContextAnalysisResult", 
    "EntropyAnalysisResult",
    "FrameworkAnalysisResult",
    "PatternMatchResult",
    "MLModelPerformance",
    
    # Core components
    "EnhancedContextAnalyzer",
    "MLEnhancedSecretClassifier", 
    "EnhancedSecretAnalyzer",
    
    # Main orchestrator and convenience functions
    "EnhancedFalsePositiveReducer",
    "create_enhanced_secret_analyzer",
    "analyze_secret",
    "is_likely_secret_simple",
    
    # Integration functions
    "integrate_enhanced_false_positive_reducer",
    "integrate_with_enhanced_static_analyzer",
    "integrate_with_apk2url_extraction", 
    "integrate_with_dynamic_analyzer",
    "integrate_with_vulnerability_scanner",
]

# Framework capabilities
FRAMEWORK_CAPABILITIES = {
    "false_positive_reduction": {
        "target_rate": "< 2%",
        "ml_enhanced": True,
        "context_aware": True
    },
    "secret_detection": {
        "entropy_algorithms": ["shannon", "base64", "hex", "ascii", "compressed"],
        "pattern_matching": "comprehensive",
        "framework_awareness": ["android", "ios", "flutter", "react_native"]
    },
    "ml_capabilities": {
        "ensemble_learning": True,
        "explainable_ai": True,
        "continuous_learning": True,
        "performance_monitoring": True
    },
    "integration": {
        "static_analyzer": True,
        "dynamic_analyzer": True, 
        "url_extractor": True,
        "vulnerability_scanner": True,
        "backward_compatible": True
    },
    "performance": {
        "caching": "TTL-based",
        "batch_processing": True,
        "parallel_analysis": False,  # Can be added in future
        "memory_optimized": True
    }
}

# Configuration defaults
DEFAULT_CONFIG = {
    "entropy_thresholds": {
        "default": 4.5,
        "unicode_text": 3.0,
        "api_keys": 5.0,
        "base64_encoded": 4.8,
        "jwt_tokens": 5.2,
        "uuids": 4.6,
        "hex_encoded": 4.0,
        "random_strings": 4.7,
    },
    "context_analysis": {
        "enabled": True,
        "api_proximity_radius": 7,
        "confidence_boost_for_context": 0.2,
        "confidence_penalty_for_isolation": -0.3,
    },
    "ml_enhancement": {
        "enabled": True,
        "model_cache_dir": "models/ml_cache",
        "retrain_threshold": 100,  # Retrain after 100 new samples
        "target_false_positive_rate": 0.02  # 2%
    },
    "performance_limits": {
        "max_entropy_calculations_per_apk": 15000,
        "max_string_length_for_analysis": 10000,
        "max_context_analysis_time_seconds": 600,
        "memory_limit_mb": 1024,
        "cache_ttl_seconds": 3600
    },
    "rule_engine": {
        "enabled": True,
        "confidence_threshold": 0.7,
        "rule_weights": {
            "entropy_analysis": 0.25,
            "context_analysis": 0.35,
            "pattern_matching": 0.20,
            "framework_specific": 0.10,
            "file_path_analysis": 0.10
        }
    }
}

def get_framework_info() -> dict:
    """Get comprehensive framework information."""
    return {
        "version": __version__,
        "architecture": __architecture__,
        "author": __author__,
        "description": __description__,
        "capabilities": FRAMEWORK_CAPABILITIES,
        "default_config": DEFAULT_CONFIG,
        "components": {
            "data_structures": "Core data models and result structures",
            "ml_classifier": "ML classifier targeting <2% false positive rate",
            "context_analyzer": "Context-aware analysis with API detection",
            "secret_analyzer": "Main analysis engine with comprehensive detection",
            "integration_helpers": "Seamless AODS component integration",
            "enhanced_false_positive_reducer": "Backward-compatible orchestrator"
        },
        "modular_benefits": [
            "substantial code reduction through focused components",
            "100% backward compatibility maintained",
            "separation of concerns",
            "Enhanced maintainability and testability",
            "Improved performance through targeted optimization"
        ]
    }

def create_default_analyzer():
    """Create analyzer with default configuration."""
    return EnhancedFalsePositiveReducer()

def validate_framework_installation():
    """Validate that all framework components are properly installed."""
    try:
        # Test core components
        analyzer = EnhancedFalsePositiveReducer()
        
        # Test basic functionality
        test_result = analyzer.analyze_potential_secret("test_secret_123")
        
        if test_result and hasattr(test_result, 'is_likely_secret'):
            return {
                "status": "success",
                "message": "Enhanced False Positive Reduction Framework installed successfully",
                "version": __version__,
                "architecture": __architecture__,
                "components_tested": ["secret_analyzer", "ml_classifier", "context_analyzer"]
            }
        else:
            return {
                "status": "error", 
                "message": "Framework validation failed - invalid result structure"
            }
            
    except Exception as e:
        return {
            "status": "error",
            "message": f"Framework validation failed: {str(e)}"
        }

# Module-level convenience instance for simple usage
_default_analyzer = None

def get_default_analyzer():
    """Get or create default analyzer instance (singleton pattern)."""
    global _default_analyzer
    if _default_analyzer is None:
        _default_analyzer = EnhancedFalsePositiveReducer()
    return _default_analyzer

# Quick analysis functions using default analyzer
def quick_analyze(content: str, context: dict = None) -> bool:
    """Quick secret analysis using default analyzer."""
    return get_default_analyzer().is_likely_secret(content, context)

def quick_confidence(content: str, context: dict = None) -> float:
    """Quick confidence score using default analyzer."""
    return get_default_analyzer().get_confidence_score(content, context)

# Framework initialization
def _initialize_framework():
    """Initialize framework components and validate installation."""
    try:
        validation_result = validate_framework_installation()
        if validation_result["status"] == "success":
            print(f"✅ Enhanced False Positive Reduction Framework v{__version__} loaded successfully")
            return True
        else:
            print(f"❌ Framework initialization failed: {validation_result['message']}")
            return False
    except Exception as e:
        print(f"❌ Framework initialization error: {e}")
        return False

# Auto-initialize on import (optional - can be disabled)
import os
if os.getenv("AODS_AUTO_INIT_FP_REDUCER", "true").lower() == "true":
    _initialize_framework() 