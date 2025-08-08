#!/usr/bin/env python3
"""
Frida Manager - Modular Framework Orchestrator

Lightweight orchestrator for comprehensive Frida-based dynamic analysis.
Coordinates all modular components to provide enterprise-grade analysis capabilities.

Components:
- FridaManager: Main orchestrator using modular components
- analysis coordination
- Backward compatibility with existing interfaces
- Flutter support and advanced capabilities

"""

import json
import logging
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any

from rich.text import Text

from .frida_connection import FridaConnection
from .script_manager import ScriptManager
from .flutter_analyzer import FlutterAnalyzer
from .analysis_orchestrator import AnalysisOrchestrator

class FridaManager:
    """
    Advanced Frida Manager with enhanced Flutter SSL bypass capabilities.
    
    This manager provides comprehensive dynamic analysis capabilities including:
    - Traditional Android SSL pinning bypass
    - Architecture-aware Flutter SSL bypass
    - WebView security testing
    - Anti-Frida detection bypass
    - Advanced memory scanning and pattern matching
    - BoringSSL-specific hooks for Flutter applications
    """

    def __init__(self, package_name: str = None, device_id: str = None):
        """Initialize the enhanced Frida manager with professional modular architecture."""
        self.package_name = package_name
        self.device_id = device_id
        
        # Initialize modular components
        self.connection = FridaConnection(package_name, device_id)
        self.script_manager = ScriptManager()
        self.flutter_analyzer = FlutterAnalyzer()
        self.orchestrator = AnalysisOrchestrator(package_name)
        
        # Legacy compatibility properties
        self.device = self.connection.device
        self.session = self.connection.session
        self.scripts = self.script_manager.scripts
        self.analysis_results = self.script_manager.analysis_results
        self.is_available = self.connection.is_available
        self.connection_timeout = self.connection.connection_timeout
        self.analysis_duration = 60

        logging.info("Enhanced Frida Manager initialized with professional modular architecture")

    # Delegate methods to modular components for backward compatibility
    def _check_frida_availability(self) -> None:
        """Check Frida availability using modular connection."""
        self.connection._check_frida_availability()
        self.is_available = self.connection.is_available
        self.device = self.connection.device

    def check_frida_availability(self) -> Tuple[bool, str]:
        """Check if Frida is available and properly configured."""
        return self.connection.check_frida_availability()

    def start_frida_server(self) -> bool:
        """Start Frida server on the target device."""
        return self.connection.start_frida_server()

    def attach_to_app(self, package_name: str = None) -> bool:
        """Attach Frida to the target application."""
        target_package = package_name or self.package_name
        success = self.connection.attach_to_app(target_package)
        if success:
            self.session = self.connection.session
            self.script_manager.set_session(self.session)
        return success

    def load_ssl_pinning_bypass_script(self) -> bool:
        """Load SSL pinning bypass script."""
        if not self.session:
            self.script_manager.set_session(self.connection.session)
        return self.script_manager.load_ssl_pinning_bypass_script()

    def load_webview_security_script(self) -> bool:
        """Load WebView security testing script."""
        if not self.session:
            self.script_manager.set_session(self.connection.session)
        return self.script_manager.load_webview_security_script()

    def load_anti_frida_detection_script(self) -> bool:
        """Load anti-Frida detection and bypass script."""
        if not self.session:
            self.script_manager.set_session(self.connection.session)
        return self.script_manager.load_anti_frida_detection_script()

    def analyze_flutter_app(self, apk_path: str, package_name: str) -> Dict[str, Any]:
        """
        Comprehensive Flutter application analysis with architecture-aware SSL bypass.
        
        Args:
            apk_path: Path to the Flutter APK file
            package_name: Package name of the Flutter application
            
        Returns:
            Dictionary containing Flutter analysis results and SSL bypass capabilities
        """
        return self.flutter_analyzer.analyze_flutter_app(apk_path, package_name)

    def run_comprehensive_analysis(self, duration: int = 30) -> Dict[str, Any]:
        """
        Run comprehensive Frida-based analysis using modular orchestrator.

        Args:
            duration: Analysis duration in seconds

        Returns:
            Dict containing analysis results
        """
        # Update orchestrator package name if needed
        if self.package_name and not self.orchestrator.package_name:
            self.orchestrator.package_name = self.package_name
            self.orchestrator.connection.package_name = self.package_name

        return self.orchestrator.run_comprehensive_analysis(duration)

    def run_targeted_analysis(self, script_types: List[str], duration: int = 30) -> Dict[str, Any]:
        """
        Run targeted analysis with specific script types.
        
        Args:
            script_types: List of script types to run
            duration: Analysis duration in seconds
            
        Returns:
            Dict containing analysis results
        """
        return self.orchestrator.run_targeted_analysis(script_types, duration)

    def load_custom_script(self, script_name: str, script_content: str) -> bool:
        """Load a custom Frida script."""
        if not self.session:
            self.script_manager.set_session(self.connection.session)
        return self.script_manager.load_custom_script(script_name, script_content)

    def get_analysis_results(self) -> Dict[str, Any]:
        """Get collected analysis results from script manager."""
        return self.script_manager.get_analysis_results()

    def get_connection_status(self) -> Dict[str, Any]:
        """Get comprehensive connection status."""
        return self.orchestrator.get_connection_status()

    def cleanup(self) -> None:
        """Clean up Frida resources using modular components."""
        self.orchestrator.cleanup()
        
        # Update legacy properties
        self.device = None
        self.session = None
        self.is_available = False

    # Legacy message handlers for backward compatibility
    def _on_ssl_message(self, message, data):
        """Handle SSL bypass script messages (legacy compatibility)."""
        self.script_manager._on_ssl_message(message, data)

    def _on_webview_message(self, message, data):
        """Handle WebView security script messages (legacy compatibility)."""
        self.script_manager._on_webview_message(message, data)

    def _on_anti_frida_message(self, message, data):
        """Handle anti-Frida detection script messages (legacy compatibility)."""
        self.script_manager._on_anti_frida_message(message, data)

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations (legacy compatibility)."""
        findings = self.script_manager.get_analysis_results()
        return self.orchestrator._generate_recommendations(findings)

    # Enhanced capabilities using modular components
    def run_flutter_analysis_only(self, apk_path: str, duration: int = 30) -> Dict[str, Any]:
        """Run Flutter-specific analysis only."""
        results = self.analyze_flutter_app(apk_path, self.package_name or "flutter_app")
        
        if results.get("flutter_detected") and self.connection.is_available:
            # Execute dynamic analysis part
            try:
                if self.attach_to_app():
                    # Load Flutter scripts if available
                    flutter_scripts = self.flutter_analyzer.get_generated_scripts()
                    for script_name, script_content in flutter_scripts.items():
                        self.load_custom_script(script_name, script_content)
                    
                    # Run analysis
                    time.sleep(duration)
                    
                    # Collect results
                    dynamic_results = self.get_analysis_results()
                    results["dynamic_analysis_results"] = dynamic_results
                    
            except Exception as e:
                logging.error(f"Flutter dynamic analysis failed: {e}")
                results["dynamic_error"] = str(e)
        
        return results

    def get_script_status(self) -> Dict[str, bool]:
        """Get status of all loaded scripts."""
        return self.script_manager.get_script_status()

    def unload_script(self, script_name: str) -> bool:
        """Unload a specific script."""
        return self.script_manager.unload_script(script_name)

    def clear_analysis_results(self) -> None:
        """Clear all collected analysis results."""
        self.script_manager.clear_results()

    # Advanced analysis methods
    def run_ssl_analysis_only(self, duration: int = 30) -> Dict[str, Any]:
        """Run SSL bypass analysis only."""
        return self.run_targeted_analysis(["ssl_bypass"], duration)

    def run_webview_analysis_only(self, duration: int = 30) -> Dict[str, Any]:
        """Run WebView security analysis only."""
        return self.run_targeted_analysis(["webview_security"], duration)

    def run_anti_frida_analysis_only(self, duration: int = 30) -> Dict[str, Any]:
        """Run anti-Frida detection analysis only."""
        return self.run_targeted_analysis(["anti_frida"], duration)

    # Utility methods
    def is_connected(self) -> bool:
        """Check if Frida is connected and session is active."""
        return self.connection.is_connected()

    def get_frida_version(self) -> str:
        """Get Frida version information."""
        try:
            is_available, status_msg = self.check_frida_availability()
            if is_available and "Frida" in status_msg:
                return status_msg
            return "Unknown"
        except:
            return "Unknown"

    def export_analysis_results(self, output_path: str = None) -> str:
        """Export analysis results to JSON file."""
        results = self.get_analysis_results()
        
        if output_path is None:
            timestamp = int(time.time())
            output_path = f"frida_analysis_{self.package_name or 'unknown'}_{timestamp}.json"
        
        try:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            logging.info(f"Analysis results exported to: {output_path}")
            return output_path
            
        except Exception as e:
            logging.error(f"Failed to export results: {e}")
            return ""

# Global instance for backward compatibility
frida_manager = None

def get_frida_manager(package_name: str = None, device_id: str = None) -> FridaManager:
    """Get the global Frida manager instance."""
    global frida_manager
    if frida_manager is None or (package_name and frida_manager.package_name != package_name):
        frida_manager = FridaManager(package_name, device_id)
    return frida_manager

# Export the main components
__all__ = ['FridaManager', 'get_frida_manager'] 