#!/usr/bin/env python3
"""
Frida Analysis Orchestrator

Coordinates comprehensive Frida-based dynamic analysis workflows.
Provides high-level analysis coordination and result aggregation.

Components:
- AnalysisOrchestrator: Main analysis workflow coordination
- Comprehensive analysis execution
- Result collection and aggregation
- Security recommendation generation

"""

import logging
import time
from typing import Dict, List, Any, Optional

from .frida_connection import FridaConnection
from .script_manager import ScriptManager
from .flutter_analyzer import FlutterAnalyzer

class AnalysisOrchestrator:
    """Coordinates comprehensive Frida analysis workflows."""

    def __init__(self, package_name: str = None):
        """Initialize analysis orchestrator."""
        self.package_name = package_name
        self.connection = FridaConnection(package_name)
        self.script_manager = ScriptManager()
        self.flutter_analyzer = FlutterAnalyzer()
        
    def run_comprehensive_analysis(self, duration: int = 30, 
                                 enable_flutter: bool = True,
                                 custom_scripts: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Run comprehensive Frida-based analysis.

        Args:
            duration: Analysis duration in seconds
            enable_flutter: Whether to enable Flutter-specific analysis
            custom_scripts: Optional custom scripts to load {name: content}

        Returns:
            Dict containing analysis results
        """
        analysis_report = {
            "status": "success",
            "package_name": self.package_name,
            "analysis_duration": duration,
            "frida_version": "unknown",
            "scripts_loaded": [],
            "findings": {},
            "recommendations": [],
            "flutter_analysis": {},
        }

        try:
            # Check Frida availability
            is_available, status_msg = self.connection.check_frida_availability()
            if not is_available:
                analysis_report["status"] = "failed"
                analysis_report["error"] = status_msg
                return analysis_report

            # Start Frida server
            if not self.connection.start_frida_server():
                logging.warning("Frida server start failed, continuing with analysis")

            # Attach to application
            if not self.connection.attach_to_app():
                analysis_report["status"] = "failed"
                analysis_report["error"] = "Failed to attach to application"
                return analysis_report

            # Set session for script manager
            self.script_manager.set_session(self.connection.get_session())

            # Load analysis scripts
            scripts_status = {
                "ssl_bypass": self.script_manager.load_ssl_pinning_bypass_script(),
                "webview_security": self.script_manager.load_webview_security_script(),
                "anti_frida": self.script_manager.load_anti_frida_detection_script(),
            }

            # Load custom scripts if provided
            if custom_scripts:
                for script_name, script_content in custom_scripts.items():
                    scripts_status[script_name] = self.script_manager.load_custom_script(
                        script_name, script_content
                    )

            analysis_report["scripts_loaded"] = [
                name for name, loaded in scripts_status.items() if loaded
            ]

            # Run Flutter analysis if enabled
            if enable_flutter and self.flutter_analyzer.is_flutter_analyzer_available():
                logging.info("Running Flutter-specific analysis...")
                flutter_results = self._run_flutter_analysis()
                analysis_report["flutter_analysis"] = flutter_results

            # Run analysis for specified duration
            logging.info(f"Running Frida analysis for {duration} seconds...")
            time.sleep(duration)

            # Collect results
            analysis_report["findings"] = self.script_manager.get_analysis_results()

            # Generate recommendations
            analysis_report["recommendations"] = self._generate_recommendations(
                analysis_report["findings"], analysis_report["flutter_analysis"]
            )

        except Exception as e:
            logging.error(f"Frida analysis failed: {e}")
            analysis_report["status"] = "failed"
            analysis_report["error"] = str(e)

        finally:
            self.cleanup()

        return analysis_report

    def _run_flutter_analysis(self) -> Dict[str, Any]:
        """Run Flutter-specific analysis."""
        flutter_results = {
            "flutter_detected": False,
            "scripts_generated": [],
            "analysis_completed": False
        }

        try:
            # Note: In a real implementation, we would need APK path for Flutter analysis
            # For now, just check if Flutter capabilities are available
            if self.flutter_analyzer.is_flutter_analyzer_available():
                flutter_results["flutter_detected"] = True
                
                # Generate Flutter scripts (would need APK path in real implementation)
                scripts = self.flutter_analyzer.get_generated_scripts()
                flutter_results["scripts_generated"] = list(scripts.keys())
                
                # Load Flutter scripts into script manager
                for script_name, script_content in scripts.items():
                    success = self.script_manager.load_custom_script(script_name, script_content)
                    if success:
                        logging.info(f"Loaded Flutter script: {script_name}")
                
                flutter_results["analysis_completed"] = True
                
        except Exception as e:
            logging.error(f"Flutter analysis failed: {e}")
            flutter_results["error"] = str(e)

        return flutter_results

    def run_targeted_analysis(self, script_types: List[str], duration: int = 30) -> Dict[str, Any]:
        """
        Run targeted analysis with specific script types.
        
        Args:
            script_types: List of script types to run ['ssl_bypass', 'webview_security', 'anti_frida']
            duration: Analysis duration in seconds
            
        Returns:
            Dict containing analysis results
        """
        analysis_report = {
            "status": "success",
            "package_name": self.package_name,
            "analysis_duration": duration,
            "scripts_loaded": [],
            "findings": {},
        }

        try:
            # Check Frida availability and attach
            is_available, status_msg = self.connection.check_frida_availability()
            if not is_available:
                analysis_report["status"] = "failed"
                analysis_report["error"] = status_msg
                return analysis_report

            if not self.connection.start_frida_server():
                logging.warning("Frida server start failed, continuing with analysis")

            if not self.connection.attach_to_app():
                analysis_report["status"] = "failed"
                analysis_report["error"] = "Failed to attach to application"
                return analysis_report

            # Set session for script manager
            self.script_manager.set_session(self.connection.get_session())

            # Load only requested scripts
            scripts_status = {}
            for script_type in script_types:
                if script_type == "ssl_bypass":
                    scripts_status[script_type] = self.script_manager.load_ssl_pinning_bypass_script()
                elif script_type == "webview_security":
                    scripts_status[script_type] = self.script_manager.load_webview_security_script()
                elif script_type == "anti_frida":
                    scripts_status[script_type] = self.script_manager.load_anti_frida_detection_script()

            analysis_report["scripts_loaded"] = [
                name for name, loaded in scripts_status.items() if loaded
            ]

            # Run analysis
            logging.info(f"Running targeted analysis for {duration} seconds...")
            time.sleep(duration)

            # Collect results
            analysis_report["findings"] = self.script_manager.get_analysis_results()

        except Exception as e:
            logging.error(f"Targeted analysis failed: {e}")
            analysis_report["status"] = "failed"
            analysis_report["error"] = str(e)

        finally:
            self.cleanup()

        return analysis_report

    def _generate_recommendations(self, findings: Dict[str, Any], 
                                flutter_results: Dict[str, Any] = None) -> List[str]:
        """Generate security recommendations based on analysis results."""
        recommendations = []

        # SSL/TLS recommendations
        if "ssl_bypass" in findings and findings["ssl_bypass"]:
            recommendations.append("Implement certificate pinning with backup pins")
            recommendations.append("Use certificate transparency monitoring")
            recommendations.append("Implement anti-tampering checks for SSL configuration")

        # WebView recommendations
        if "webview_security" in findings:
            webview_findings = findings["webview_security"]
            for finding in webview_findings:
                if finding.get("type") == "webview_js_enabled" and finding.get("data"):
                    recommendations.append(
                        "Review JavaScript bridge security and input validation"
                    )
                if finding.get("type") == "webview_file_access" and finding.get("data"):
                    recommendations.append(
                        "Disable file access in WebView unless absolutely necessary"
                    )
                if finding.get("type") == "webview_universal_access" and finding.get("data"):
                    recommendations.append("Disable universal access from file URLs")

        # Anti-Frida recommendations
        if "anti_frida_detection" in findings and findings["anti_frida_detection"]:
            recommendations.append("Implement runtime application self-protection (RASP)")
            recommendations.append("Add integrity checks and anti-tampering mechanisms")
            recommendations.append("Use code obfuscation and anti-debugging techniques")

        # Flutter-specific recommendations
        if flutter_results and flutter_results.get("flutter_detected"):
            recommendations.append("Implement Flutter-specific SSL pinning mechanisms")
            recommendations.append("Use BoringSSL certificate validation for Flutter apps")
            recommendations.append("Implement native code obfuscation for libflutter.so")

        # Generic recommendations if no specific findings
        if not findings and not recommendations:
            recommendations.extend([
                "Implement comprehensive runtime protection mechanisms",
                "Add certificate pinning for all network communications",
                "Use secure WebView configurations",
                "Implement anti-tampering and integrity checks"
            ])

        return recommendations

    def get_connection_status(self) -> Dict[str, Any]:
        """Get current connection status information."""
        return {
            "frida_available": self.connection.is_available,
            "connected": self.connection.is_connected(),
            "device": str(self.connection.get_device()) if self.connection.get_device() else None,
            "session": str(self.connection.get_session()) if self.connection.get_session() else None,
            "scripts_loaded": self.script_manager.get_script_status()
        }

    def cleanup(self) -> None:
        """Clean up analysis resources."""
        try:
            # Unload all scripts
            self.script_manager.unload_all_scripts()
            
            # Disconnect Frida session
            self.connection.cleanup()
            
            logging.info("Analysis orchestrator cleanup completed")
            
        except Exception as e:
            logging.error(f"Cleanup failed: {e}")

# Export the orchestrator
__all__ = ['AnalysisOrchestrator'] 