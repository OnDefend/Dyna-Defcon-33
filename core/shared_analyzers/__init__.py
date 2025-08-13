#!/usr/bin/env python3
"""
Shared Analyzers Module for AODS Plugin Modularization

This module provides reusable analysis components that eliminate code duplication
across plugins and improve performance through optimized algorithms.

Components:
- UniversalPatternAnalyzer: Reusable pattern matching engine
- UniversalConfidenceCalculator: Standardized confidence calculation
- VulnerabilityReporter: Standardized vulnerability reporting
- PerformanceOptimizer: Shared performance optimization utilities
"""

from .universal_pattern_analyzer import UniversalPatternAnalyzer
from .universal_confidence_calculator import UniversalConfidenceCalculator
from .vulnerability_reporter import VulnerabilityReporter
from .performance_optimizer import PerformanceOptimizer

__version__ = "1.0.0"
__author__ = "AODS Development Team"

__all__ = [
    "UniversalPatternAnalyzer",
    "UniversalConfidenceCalculator", 
    "VulnerabilityReporter",
    "PerformanceOptimizer"
] 