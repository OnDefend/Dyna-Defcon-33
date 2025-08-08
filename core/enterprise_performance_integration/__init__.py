#!/usr/bin/env python3
"""
Performance Integration - Modular Architecture

This module provides a comprehensive integration of all performance optimization 
frameworks into the main AODS workflow using a clean modular architecture.

Features:
- Evidence-based optimization strategy selection
- Advanced memory management and caching systems
- Intelligent parallel processing optimization
- External configuration management
- performance metrics and reporting

Components:
- PerformanceIntegrator: Main orchestration class
- IntegratedPerformanceMetrics: Performance tracking data structures
- ConfigurationManager: System-aware configuration management
- OptimizationEngine: Core optimization algorithms
- MetricsCalculator: performance measurement
"""

from .data_structures import IntegratedPerformanceMetrics
from .configuration_manager import ConfigurationManager
from .framework_initializer import FrameworkInitializer
from .optimization_engine import OptimizationEngine
from .metrics_calculator import MetricsCalculator
from .fallback_handler import FallbackHandler
from .performance_reporter import PerformanceReporter
from .enterprise_performance_integrator import EnterprisePerformanceIntegrator

# Legacy compatibility imports
from .enterprise_performance_integrator import (
    create_enterprise_performance_integrator,
    integrate_enterprise_performance_with_aods
)

__all__ = [
    'EnterprisePerformanceIntegrator',
    'IntegratedPerformanceMetrics',
    'ConfigurationManager',
    'FrameworkInitializer',
    'OptimizationEngine',
    'MetricsCalculator',
    'FallbackHandler',
    'PerformanceReporter',
    'create_enterprise_performance_integrator',
    'integrate_enterprise_performance_with_aods'
] 