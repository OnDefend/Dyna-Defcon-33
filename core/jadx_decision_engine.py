#!/usr/bin/env python3
"""
JADX Decision Engine for static analysis.

This module provides adaptive decision logic for static analysis using JADX.
"""

import warnings
from core.adaptive_jadx_decision_engine import (
    AdaptiveJADXDecisionEngine,
    ProcessingStrategy,
    APKComplexityProfile,
    SystemCapabilities,
    AdaptiveDecision,
    PerformanceLearningModel,
    create_adaptive_decision_engine
)

# Backward compatibility aliases
SystemResources = SystemCapabilities
APKCharacteristics = APKComplexityProfile
ProcessingDecision = AdaptiveDecision

class DecisionEngineConfig:
    """Backward compatibility configuration class."""
    def __init__(self, **kwargs):
        warnings.warn(
            "DecisionEngineConfig is deprecated. Use AdaptiveJADXDecisionEngine directly.",
            DeprecationWarning,
            stacklevel=2
        )
        # Store config for potential future use
        self.config = kwargs

class APKSizeBasedDecisionEngine:
    """
    Backward compatibility wrapper for AdaptiveJADXDecisionEngine.
    
    DEPRECATED: This class is maintained for backward compatibility only.
    New code should use AdaptiveJADXDecisionEngine directly.
    """
    
    def __init__(self, config=None):
        warnings.warn(
            "APKSizeBasedDecisionEngine is deprecated. Use AdaptiveJADXDecisionEngine instead.",
            DeprecationWarning,
            stacklevel=2
        )
        
        # Initialize the new adaptive engine
        self.adaptive_engine = create_adaptive_decision_engine()
        self.config = config
    
    def analyze_and_recommend(self, apk_path: str, force_refresh: bool = False) -> AdaptiveDecision:
        """
        Backward compatibility method that delegates to the adaptive engine.
        
        Args:
            apk_path: Path to APK file
            force_refresh: Force refresh of cached data
            
        Returns:
            AdaptiveDecision with processing recommendation
        """
        return self.adaptive_engine.analyze_and_decide(apk_path, force_refresh)
    
    def record_execution_result(self, apk_path: str, strategy: ProcessingStrategy, 
                              duration_seconds: float, success: bool, memory_used_mb: float):
        """Record execution result for learning."""
        return self.adaptive_engine.record_execution_result(
            apk_path, strategy, duration_seconds, success, memory_used_mb
        )
    
    def get_performance_summary(self):
        """Get performance summary."""
        return self.adaptive_engine.get_performance_summary() 