"""
Enhanced Frida Dynamic Analysis Plugin - Modular Architecture.

This package provides comprehensive Frida-based dynamic security analysis
with improved maintainability, performance, and error handling.
"""

from .main import run_plugin, run
from .enhanced_frida_analyzer import EnhancedFridaDynamicAnalyzer
from .icc_analyzer import ICCSecurityAnalyzer, ICCTestConfiguration
from .webview_exploitation_module import WebViewExploitationModule, WebViewExploitationConfig
from .dynamic_execution_module import DynamicExecutionModule, DynamicExecutionConfig
from .constants import PLUGIN_CHARACTERISTICS
from .data_structures import (
    FridaTestResult,
    FridaAnalysisConfig,
    FridaVulnerabilityPattern,
    FridaTestCache
)

# Create alias for backward compatibility
analyzer = EnhancedFridaDynamicAnalyzer

__all__ = [
    "run_plugin",
    "run", 
    "EnhancedFridaDynamicAnalyzer",
    "ICCSecurityAnalyzer",
    "ICCTestConfiguration",
    "WebViewExploitationModule",
    "WebViewExploitationConfig",
    "DynamicExecutionModule",
    "DynamicExecutionConfig",
    "analyzer",
    "PLUGIN_CHARACTERISTICS",
    "FridaTestResult",
    "FridaAnalysisConfig",
    "FridaVulnerabilityPattern",
    "FridaTestCache"
] 