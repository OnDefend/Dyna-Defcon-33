#!/usr/bin/env python3
"""
Enhanced Static Analysis Modular Framework

Modular static analysis framework for comprehensive Android security assessment.
Provides advanced static analysis capabilities with confidence scoring.

Components:
- EnhancedStaticAnalyzer: Main orchestrator for static analysis
- EntropyAnalyzer: Advanced entropy analysis for secret detection
- AndroidManifestParser: Binary XML manifest parsing
- CodePatternAnalyzer: Vulnerability pattern detection
- StaticAnalysisConfidenceCalculator: Confidence scoring
- SecurityFinding: Standardized finding structure
- SecretAnalysis: Secret analysis results
"""

from .data_structures import SecurityFinding, SecretAnalysis
from .entropy_analyzer import EntropyAnalyzer
from .manifest_parser import AndroidManifestParser
from .code_pattern_analyzer import CodePatternAnalyzer
from .confidence_calculator import StaticAnalysisConfidenceCalculator
from .enhanced_static_analyzer import EnhancedStaticAnalyzer, get_enhanced_static_analyzer

# Export all components
__all__ = [
    # Main analyzer
    'EnhancedStaticAnalyzer',
    'get_enhanced_static_analyzer',
    
    # Core analyzers
    'EntropyAnalyzer',
    'AndroidManifestParser',
    'CodePatternAnalyzer',
    'StaticAnalysisConfidenceCalculator',
    
    # Data structures
    'SecurityFinding',
    'SecretAnalysis',
]

 