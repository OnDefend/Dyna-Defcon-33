#!/usr/bin/env python3
"""
Enhanced False Positive Reducer - Main Orchestrator
===================================================

This module serves as the main entry point for the enhanced false positive
reduction framework, maintaining 100% backward compatibility while delegating
to the modular components.

This lightweight orchestrator preserves all existing APIs and integrates
seamlessly with existing AODS components.

"""

from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

# Import data structures and integration functions (no circular imports)
from .data_structures import (
    ContextAnalysisResult,
    MLModelPerformance,
    SecretAnalysisResult
)
from .integration_helpers import (
    integrate_enhanced_false_positive_reducer,
    integrate_with_apk2url_extraction,
    integrate_with_dynamic_analyzer,
    integrate_with_enhanced_static_analyzer,
    integrate_with_vulnerability_scanner
)

class EnhancedFalsePositiveReducer:
    """
    Main orchestrator for enhanced false positive reduction.
    
    This class maintains backward compatibility while providing access to
    the enhanced modular architecture underneath.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the enhanced false positive reducer.
        
        Args:
            config_path: Optional path to configuration file
        """
        self.logger = logger.bind(component="EnhancedFalsePositiveReducer")
        
        # Import inside __init__ to avoid circular imports
        from .secret_analyzer import EnhancedSecretAnalyzer
        
        # Initialize the core secret analyzer (main component)
        self.secret_analyzer = EnhancedSecretAnalyzer(config_path)
        
        # Expose modular components for advanced usage
        self.ml_classifier = self.secret_analyzer.ml_classifier
        self.context_analyzer = self.secret_analyzer.context_analyzer
        
        self.logger.info("Enhanced False Positive Reducer v3.0 (Modular) initialized")

    # Backward compatibility methods - delegate to secret_analyzer
    def analyze_potential_secret(self, content: str, context: Optional[Dict[str, Any]] = None) -> SecretAnalysisResult:
        """
        Comprehensive analysis of potential secret content.
        
        BACKWARD COMPATIBLE: This method maintains the exact same signature
        and behavior as the original implementation.
        """
        return self.secret_analyzer.analyze_potential_secret(content, context)

    def is_likely_secret(self, content: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Simple boolean check if content is likely a secret.
        
        BACKWARD COMPATIBLE: Simplified interface for basic usage.
        """
        result = self.secret_analyzer.analyze_potential_secret(content, context)
        return result.is_likely_secret

    def get_confidence_score(self, content: str, context: Optional[Dict[str, Any]] = None) -> float:
        """
        Get confidence score for secret detection.
        
        BACKWARD COMPATIBLE: Returns confidence as float between 0.0 and 1.0.
        """
        result = self.secret_analyzer.analyze_potential_secret(content, context)
        return result.confidence_score

    def get_version_info(self) -> Dict[str, str]:
        """Get version information."""
        return {
            'version': '3.0.0',
            'architecture': 'modular',
            'components': [
                'secret_analyzer',
                'ml_classifier', 
                'context_analyzer',
                'integration_helpers'
            ],
            'backward_compatible': 'true'
        }

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            'analysis_cache_size': len(self.secret_analyzer.analysis_cache),
            'analysis_cache_maxsize': self.secret_analyzer.analysis_cache.maxsize,
            'domain_cache_size': len(self.secret_analyzer.domain_cache),
            'domain_cache_maxsize': self.secret_analyzer.domain_cache.maxsize
        }

# Convenience functions for backward compatibility
def create_enhanced_secret_analyzer(config_path: Optional[str] = None) -> EnhancedFalsePositiveReducer:
    """Create an enhanced secret analyzer instance - BACKWARD COMPATIBLE."""
    return EnhancedFalsePositiveReducer(config_path)

def analyze_secret(content: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Quick secret analysis function - BACKWARD COMPATIBLE."""
    analyzer = EnhancedFalsePositiveReducer()
    result = analyzer.analyze_potential_secret(content, context)
    return {
        'is_secret': result.is_likely_secret,
        'confidence': result.confidence_score,
        'details': result.analysis_details
    }

def is_likely_secret_simple(content: str) -> bool:
    """Simple secret detection - BACKWARD COMPATIBLE."""
    analyzer = EnhancedFalsePositiveReducer()
    return analyzer.is_likely_secret(content)

# Integration functions (backward compatible exports)
integrate_with_enhanced_static_analyzer = integrate_with_enhanced_static_analyzer
integrate_with_apk2url_extraction = integrate_with_apk2url_extraction

if __name__ == "__main__":
    # Example usage and testing
    analyzer = EnhancedFalsePositiveReducer()

    # Test cases
    test_secrets = [
        "AKIA1234567890EXAMPLE",  # AWS key
        "ThemeData.fallback",  # Flutter framework noise
        "sk_test_1234567890",  # Stripe test key
    ]

    print("Enhanced False Positive Reducer - Modular Architecture Test")
    print("=" * 60)

    for i, secret in enumerate(test_secrets):
        result = analyzer.analyze_potential_secret(secret)
        print(f"\nTest {i+1}: {secret[:30]}...")
        print(f"Is Secret: {result.is_likely_secret}")
        print(f"Confidence: {result.confidence_score:.3f}")

    print(f"\nVersion Info: {analyzer.get_version_info()}")
    print("🎉 Modularization completed successfully!") 