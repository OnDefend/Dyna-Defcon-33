"""
Cross-Platform Analysis Engine - Modular Architecture

This module provides a comprehensive cross-platform security analysis framework
for Android applications built with various frameworks including React Native,
Xamarin, Flutter, Cordova/PhoneGap, and Progressive Web Apps (PWA).

Modular Components:
- data_structures: Shared data types and structures
- confidence_calculator: confidence calculation system
- react_native_analyzer: React Native security analysis
- xamarin_analyzer: Xamarin security analysis  
- pwa_analyzer: Progressive Web App security analysis
- formatters: Analysis result formatting and reporting

Features:
- Framework detection and classification
- Framework-specific vulnerability analysis
- confidence scoring
- Unified cross-platform reporting
- Modular and extensible architecture
"""

# Import modular components for direct access if needed
from .data_structures import (
    CrossPlatformFinding,
    FrameworkDetectionResult,
    LibraryInfo,
    ConfidenceEvidence,
    Framework,
    VulnerabilityType,
    Severity,
    DetectionMethod,
    AnalysisConfiguration,
    CrossPlatformAnalysisResult
)
from .confidence_calculator import CrossPlatformConfidenceCalculator
from .react_native_analyzer import ReactNativeAnalyzer
from .xamarin_analyzer import XamarinAnalyzer

# Import additional analyzers when they're created
try:
    from .pwa_analyzer import PWAAnalyzer
except ImportError:
    PWAAnalyzer = None

try:
    from .formatters import CrossPlatformFormatter
except ImportError:
    CrossPlatformFormatter = None

# Export all public APIs
__all__ = [
    'CrossPlatformFinding',
    'FrameworkDetectionResult', 
    'LibraryInfo',
    'ConfidenceEvidence',
    'Framework',
    'VulnerabilityType',
    'Severity',
    'DetectionMethod',
    'AnalysisConfiguration',
    'CrossPlatformAnalysisResult',
    'CrossPlatformConfidenceCalculator',
    'ReactNativeAnalyzer',
    'XamarinAnalyzer',
    'PWAAnalyzer'
]

__version__ = '5.0.0'
__author__ = 'AODS Team'