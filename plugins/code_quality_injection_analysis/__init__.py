"""
Code Quality & Injection Analysis Plugin Module

This module provides comprehensive code quality and injection vulnerability analysis
for Android applications, implementing MASTG testing guidelines.

Module Components:
- data_structures: Core data structures and enums
- pattern_libraries: Injection and vulnerability patterns
- injection_analyzer: Main analysis orchestrator
- sql_injection_analyzer: SQL injection specific analysis
- report_generator: Comprehensive reporting
"""

from .data_structures import (
    CodeVulnerability,
    AnalysisResult,
    AnalysisConfig,
    PatternMatch,
    VulnerabilityType,
    SeverityLevel
)

from .injection_analyzer import CodeQualityInjectionAnalyzer
from .sql_injection_analyzer import SQLInjectionAnalyzer
from .report_generator import CodeQualityInjectionReportGenerator
from .pattern_libraries import InjectionPatterns

# Import main plugin interface - need to import from parent to avoid circular import
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Import main plugin functions and metadata from the plugin file
try:
    # Import from the actual plugin file in the parent directory
    import importlib.util
    plugin_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'code_quality_injection_analysis.py')
    spec = importlib.util.spec_from_file_location("main_plugin", plugin_path)
    main_plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(main_plugin)
    
    # Export main plugin interface
    run = main_plugin.run
    run_plugin = main_plugin.run_plugin
    PLUGIN_INFO = main_plugin.PLUGIN_INFO
    PLUGIN_METADATA = main_plugin.PLUGIN_METADATA
    PLUGIN_CHARACTERISTICS = main_plugin.PLUGIN_CHARACTERISTICS
    
except Exception as e:
    # Fallback: create minimal interface
    def run(apk_ctx):
        from rich.text import Text
        return "Code Quality & Injection Analysis", Text("Modular plugin loaded but main interface unavailable", style="yellow")
    
    def run_plugin(apk_ctx):
        return run(apk_ctx)
    
    PLUGIN_INFO = {
        "name": "Code Quality & Injection Analysis",
        "description": "Modular injection analysis plugin",
        "version": "2.0",
        "architecture": "modular"
    }
    
    PLUGIN_CHARACTERISTICS = {
        "mode": "comprehensive",
        "category": "code_quality"
    }

__all__ = [
    'CodeVulnerability',
    'AnalysisResult', 
    'AnalysisConfig',
    'PatternMatch',
    'VulnerabilityType',
    'SeverityLevel',
    'CodeQualityInjectionAnalyzer',
    'SQLInjectionAnalyzer',
    'CodeQualityInjectionReportGenerator',
    'InjectionPatterns',
    'run',
    'run_plugin',
    'PLUGIN_INFO',
    'PLUGIN_METADATA',
    'PLUGIN_CHARACTERISTICS'
]

__version__ = "1.0.0"
__author__ = "AODS Security Framework" 