"""
Advanced Dynamic Analysis Plugin Module

This module provides comprehensive dynamic security testing capabilities including
intent fuzzing, network traffic analysis, WebView security testing, and external
service interaction monitoring for complete runtime vulnerability assessment.

MASVS Controls Covered:
- MSTG-PLATFORM-01: App Permissions and Intent Handling
- MSTG-PLATFORM-02: WebView Security Configuration
- MASVS-PLATFORM-3: WebView JavaScript Bridge Security
- MSTG-NETWORK-01: Network Architecture Analysis
- MSTG-NETWORK-02: Network Request Authentication
- MSTG-CODE-02: Dynamic Code Loading Protection
- MSTG-RESILIENCE-10: Runtime Application Self Protection
"""

from .device_manager import DeviceManager
from .app_manager import AppManager
from .network_analyzer import NetworkAnalyzer
from .report_generator import ReportGenerator
from .data_structures import (
    AnalysisResult,
    AnalysisType,
    DeviceStatus,
    AppStatus,
    NetworkStatus,
    DynamicAnalysisConfig,
    NetworkConfig,
    Finding,
    RiskLevel
)

import logging

logger = logging.getLogger(__name__)

# Plugin metadata
PLUGIN_METADATA = {
    "name": "Advanced Dynamic Analysis",
    "description": "Comprehensive dynamic security testing with intent fuzzing, network analysis, and WebView security testing",
    "version": "2.0.0",
    "author": "AODS Development Team",
    "category": "DYNAMIC_ANALYSIS",
    "priority": "HIGH",
    "timeout": 300,
    "mode": "comprehensive",
    "requires_device": True,
    "requires_network": True,
    "invasive": True,
    "execution_time_estimate": 180,
    "dependencies": ["adb", "frida", "mitmproxy"],
    "modular_architecture": True,
    "components": [
        "device_manager",
        "app_manager",
        "network_analyzer",
        "report_generator"
    ],
    "security_controls": [
        "MSTG-PLATFORM-01",
        "MSTG-PLATFORM-02",
        "MASVS-PLATFORM-3",
        "MSTG-NETWORK-01",
        "MSTG-NETWORK-02",
        "MSTG-CODE-02",
        "MSTG-RESILIENCE-10"
    ],
    "owasp_categories": ["M1", "M2", "M3", "M4", "M6"]
}

# Module metadata
__version__ = "1.0.0"
__author__ = "AODS Team"
__description__ = "Advanced Dynamic Analysis Plugin Module"

# Plugin characteristics
PLUGIN_CHARACTERISTICS = {
    "mode": "deep",  # Advanced dynamic analysis requires deep mode
    "category": "dynamic_analysis",
    "masvs_control": "MASVS-PLATFORM-1,MASVS-PLATFORM-2,MASVS-PLATFORM-3,MASVS-NETWORK-1,MASVS-NETWORK-2",
}

# Plugin metadata for the framework
PLUGIN_INFO = {
    "name": "Advanced Dynamic Analysis",
    "description": "Comprehensive dynamic security testing including intent fuzzing, network analysis, and runtime monitoring",
    "masvs_control": "MASVS-PLATFORM-1,MASVS-PLATFORM-2,MASVS-PLATFORM-3,MASVS-NETWORK-1,MASVS-NETWORK-2",
    "risk_level": "HIGH",
    "mode": "deep",
    "category": "dynamic_analysis",
}

__all__ = [
    'DeviceManager',
    'AppManager',
    'NetworkAnalyzer',
    'ReportGenerator',
    'AnalysisResult',
    'DeviceStatus',
    'AppStatus',
    'NetworkStatus',
    'DynamicAnalysisConfig',
    'NetworkConfig',
    'Finding',
    'RiskLevel',
    'PLUGIN_CHARACTERISTICS',
    'PLUGIN_INFO'
]

# Plugin compatibility functions
def run(apk_ctx):
    try:
        from rich.text import Text
        # Import main analyzer
        from .network_analyzer import NetworkAnalysisOrchestrator

        orchestrator = NetworkAnalysisOrchestrator(apk_ctx)
        result = orchestrator.analyze()

        if hasattr(result, 'findings') and result.findings:
            findings_text = Text(f"Advanced Dynamic Analysis Modules - {len(result.findings)} findings\n", style="bold blue")
            for finding in result.findings[:10]:
                findings_text.append(f"• {finding.title}\n", style="yellow")
        else:
            findings_text = Text("Advanced Dynamic Analysis Modules completed - No issues found", style="green")

        return "Advanced Dynamic Analysis Modules", findings_text
    except Exception as e:
        error_text = Text(f"Advanced Dynamic Analysis Modules Error: {str(e)}", style="red")
        return "Advanced Dynamic Analysis Modules", error_text

def run_plugin(apk_ctx):
    return run(apk_ctx)

__all__.extend(['run', 'run_plugin']) 