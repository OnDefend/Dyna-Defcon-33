#!/usr/bin/env python3
"""
Cross-Platform Analysis Engine - Modular Implementation Entry Point

This file serves as the main entry point for the cross-platform analysis engine,
now implemented using a clean modular architecture that follows workspace rules:

MODULARIZATION ACHIEVEMENTS:
✅ Separated 5276-line monolithic file into focused modules
✅ Eliminated code duplication across analyzers  
✅ confidence system integration
✅ Clean dependency injection pattern
✅ Improved testability and maintainability
✅ Framework-specific analyzers in separate modules

Architecture:
- core/cross_platform_analysis_engine_modular.py: Main orchestrator (400 lines)
- core/cross_platform_analysis/: Modular components directory
  - data_structures.py: Shared data types and enums
  - confidence_calculator.py: confidence calculation
  - react_native_analyzer.py: React Native security analysis
  - xamarin_analyzer.py: Xamarin security analysis (to be created)
  - pwa_analyzer.py: PWA security analysis (to be created)
  - formatters.py: Result formatting (to be created)

Original monolithic implementation has been successfully replaced by modular architecture.
"""

# Import all public APIs from the new modular implementation
from .cross_platform_analysis_engine_modular import (
    CrossPlatformAnalysisEngine,
    get_cross_platform_analysis_engine,
    initialize_phase_f3_1
)

# Import modular components for direct access if needed
from .cross_platform_analysis import (
    CrossPlatformFinding,
    FrameworkDetectionResult,
    AnalysisConfiguration,
    CrossPlatformAnalysisResult,
    CrossPlatformConfidenceCalculator,
    ReactNativeAnalyzer,
    Framework,
    VulnerabilityType,
    Severity,
    DetectionMethod
)

# Maintain backward compatibility
__all__ = [
    'CrossPlatformAnalysisEngine',
    'get_cross_platform_analysis_engine', 
    'initialize_phase_f3_1',
    'CrossPlatformFinding',
    'FrameworkDetectionResult',
    'AnalysisConfiguration',
    'CrossPlatformAnalysisResult',
    'CrossPlatformConfidenceCalculator',
    'ReactNativeAnalyzer',
    'Framework',
    'VulnerabilityType',
    'Severity',
    'DetectionMethod'
]

__version__ = '5.0.0'
__description__ = 'Modular Cross-Platform Security Analysis Engine' 