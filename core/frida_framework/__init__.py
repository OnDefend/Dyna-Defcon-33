#!/usr/bin/env python3
"""
Frida Framework - Modular Dynamic Analysis Framework

modular Frida framework for comprehensive Android security testing.
Provides enterprise-grade dynamic analysis capabilities with clean architecture.

Components:
- FridaManager: Main orchestrator for dynamic analysis
- FridaConnection: Core connection and device management
- ScriptManager: Script loading and execution management
- FlutterAnalyzer: Flutter-specific analysis capabilities
- AnalysisOrchestrator: High-level analysis workflow coordination

Features:
- Modular architecture with clean separation of concerns
- SSL pinning bypass capabilities
- WebView security testing
- Anti-Frida detection bypass
- Flutter application support
- confidence scoring
- Comprehensive result aggregation
- 100% backward compatibility

"""

from .frida_connection import FridaConnection
from .script_manager import ScriptManager
from .flutter_analyzer import FlutterAnalyzer
from .analysis_orchestrator import AnalysisOrchestrator
from .frida_manager import FridaManager, get_frida_manager

# Export all components
__all__ = [
    # Main manager
    'FridaManager',
    'get_frida_manager',
    
    # Core components
    'FridaConnection',
    'ScriptManager',
    'FlutterAnalyzer',
    'AnalysisOrchestrator',
]

# Version information
__version__ = '2.0.0'
__author__ = 'AODS Development Team'
__description__ = 'Modular Frida Framework for Dynamic Android Security Testing'

# Framework capabilities
FRAMEWORK_CAPABILITIES = [
    'ssl_bypass',
    'webview_security',
    'anti_frida_detection',
    'flutter_analysis',
    'custom_scripts',
    'comprehensive_analysis',
    'targeted_analysis',
    'real_time_monitoring'
]

# Supported script types
SUPPORTED_SCRIPT_TYPES = [
    'ssl_bypass',
    'webview_security', 
    'anti_frida',
    'flutter_comprehensive',
    'flutter_architecture',
    'custom'
] 