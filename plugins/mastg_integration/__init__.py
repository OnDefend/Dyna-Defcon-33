#!/usr/bin/env python3
"""
MASTG Integration Plugin - Modular Architecture Entry Point

This module serves as the main orchestration point for the modularized MASTG Integration plugin,
providing dependency injection and clean component coordination.

Modular Components:
- test_case_manager.py: MASTG test case definitions and management
- robust_executor.py: Timeout-protected test execution logic
- compliance_reporter.py: MASTG compliance reporting and visualization
- plugin_integration.py: Dynamic plugin mapping and orchestration
- data_structures.py: Core data classes and enums
"""

import logging
from typing import Dict, List, Optional, Tuple, Union, Any
from pathlib import Path

from rich.text import Text

from .data_structures import MASTGTestCase, MASTGTestExecution, MASTGConfiguration
from .test_case_manager import MASTGTestCaseManager
from .robust_executor import RobustMASTGExecutor
from .compliance_reporter import MASTGComplianceReporter
from .plugin_integration import PluginIntegrationManager

class MASTGIntegrationPlugin:
    """
    Main MASTG Integration plugin with modular architecture.
    
    Orchestrates MASTG test execution, compliance validation, and reporting
    through specialized component modules with dependency injection.
    """
    
    def __init__(self, config: Optional[MASTGConfiguration] = None):
        """Initialize the MASTG Integration plugin with modular components."""
        self.logger = logging.getLogger(__name__)
        self.config = config or MASTGConfiguration()
        
        # Initialize modular components
        self._initialize_components()
        
        # Execution state
        self.test_executions: List[MASTGTestExecution] = []
        self.analysis_complete = False
    
    def _initialize_components(self):
        """Initialize all modular components with dependency injection."""
        try:
            # Initialize component managers
            self.test_case_manager = MASTGTestCaseManager(self.config)
            self.plugin_integration_manager = PluginIntegrationManager(self.config)
            self.executor = RobustMASTGExecutor(
                test_case_manager=self.test_case_manager,
                plugin_manager=self.plugin_integration_manager,
                config=self.config
            )
            self.compliance_reporter = MASTGComplianceReporter(self.config)
            
            self.logger.debug("MASTG modular components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize MASTG components: {e}", exc_info=True)
            raise
    
    def run_mastg_analysis(self, apk_ctx) -> Tuple[str, Union[str, Text]]:
        """
        Execute comprehensive MASTG compliance analysis.
        
        Args:
            apk_ctx: APK analysis context
            
        Returns:
            Tuple of (analysis_type, report)
        """
        try:
            self.logger.debug("Starting MASTG compliance analysis")
            
            # Get available test cases
            test_cases = self.test_case_manager.get_available_test_cases()
            self.logger.debug(f"Loaded {len(test_cases)} MASTG test cases")
            
            # Execute test cases with timeout protection
            self.test_executions = self.executor.execute_test_suite(apk_ctx, test_cases)
            
            # Generate compliance report
            compliance_report = self.compliance_reporter.generate_compliance_report(self.test_executions)
            
            # Export results if configured
            if self.config.export_results:
                self._export_results(apk_ctx)
            
            self.analysis_complete = True
            self.logger.debug(f"MASTG analysis completed: {len(self.test_executions)} tests executed")
            
            return "MASTG Compliance Analysis", compliance_report
            
        except Exception as e:
            self.logger.error(f"MASTG analysis failed: {e}", exc_info=True)
            error_report = self._generate_error_report(str(e))
            return "MASTG Compliance Analysis", error_report
    
    def _export_results(self, apk_ctx):
        """Export MASTG results to configured output format."""
        try:
            if self.config.output_path:
                output_path = Path(self.config.output_path)
                self.compliance_reporter.export_results(self.test_executions, output_path)
                self.logger.debug(f"MASTG results exported to {output_path}")
        except Exception as e:
            self.logger.error(f"Failed to export MASTG results: {e}")
    
    def _generate_error_report(self, error_message: str) -> Text:
        """Generate error report for failed MASTG analysis."""
        error_report = Text()
        error_report.append("MASTG Compliance Analysis - Error Report\n", style="bold red")
        error_report.append("=" * 50 + "\n\n", style="red")
        error_report.append(f"Analysis failed: {error_message}\n\n", style="red")
        error_report.append("Possible causes:\n", style="yellow")
        error_report.append("• Required plugins not available or misconfigured\n")
        error_report.append("• APK analysis context incomplete or invalid\n")
        error_report.append("• Timeout during test execution\n")
        error_report.append("• Permission issues accessing APK resources\n\n")
        error_report.append("Please check the logs for detailed error information.\n", style="white")
        return error_report
    
    def get_test_executions(self) -> List[MASTGTestExecution]:
        """Get list of executed MASTG tests for programmatic access."""
        return self.test_executions
    
    def get_compliance_summary(self) -> Dict[str, Any]:
        """Get compliance summary statistics."""
        if not self.test_executions:
            return {"status": "not_executed", "total_tests": 0}
        
        return self.compliance_reporter.get_compliance_summary(self.test_executions)
    
    def get_plugin_availability(self) -> Dict[str, bool]:
        """Get availability status of integrated plugins."""
        return self.plugin_integration_manager.get_plugin_availability()

# Main plugin interface functions for backward compatibility
def run(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Main plugin entry point with modular architecture.
    
    Maintains backward compatibility while providing enhanced functionality
    through the modular architecture.
    """
    try:
        plugin = MASTGIntegrationPlugin()
        return plugin.run_mastg_analysis(apk_ctx)
    except Exception as e:
        logging.error(f"MASTG plugin execution failed: {e}")
        error_text = Text()
        error_text.append(f"MASTG Compliance Analysis failed: {str(e)}", style="red")
        return "MASTG Compliance Analysis", error_text

def run_plugin(apk_ctx, config: Optional[Dict[str, Any]] = None) -> Tuple[str, Union[str, Text]]:
    """
    Enhanced plugin entry point with configuration support.
    
    Args:
        apk_ctx: APK analysis context
        config: Optional configuration dictionary
        
    Returns:
        Tuple of (analysis_type, report)
    """
    try:
        # Convert config dict to MASTGConfiguration if provided
        mastg_config = None
        if config:
            mastg_config = MASTGConfiguration(**config)
        
        plugin = MASTGIntegrationPlugin(mastg_config)
        return plugin.run_mastg_analysis(apk_ctx)
    except Exception as e:
        logging.error(f"Enhanced MASTG plugin execution failed: {e}")
        error_text = Text()
        error_text.append(f"MASTG Compliance Analysis failed: {str(e)}", style="red")
        return "MASTG Compliance Analysis", error_text

def run_mastg_compliance(apk_ctx) -> Tuple[str, Text]:
    """Legacy compatibility function for MASTG compliance analysis."""
    return run(apk_ctx)

def get_plugin_info() -> Dict[str, Any]:
    """Get plugin information and capabilities."""
    return {
        "name": "MASTG Integration Plugin",
        "version": "2.0.0",
        "description": "Modular OWASP MASTG compliance testing with enhanced capabilities",
        "author": "AODS Framework", 
        "modular_components": [
            "test_case_manager", "robust_executor", "compliance_reporter",
            "plugin_integration", "data_structures"
        ],
        "masvs_coverage": "ALL MASVS v1.5.0 controls",
        "analysis_capabilities": [
            "MASTG test case execution",
            "Plugin integration and orchestration",
            "Compliance validation and reporting",
            "Timeout-protected test execution",
            "Multi-format result export"
        ],
        "enterprise_features": [
            "Modular architecture",
            "Dependency injection",
            "Comprehensive error handling",
            "Performance optimization",
            "Rich text reporting"
        ]
    }

def validate_plugin() -> bool:
    """Validate plugin and modular components."""
    try:
        # Check if modular components are available
        from .test_case_manager import MASTGTestCaseManager
        from .robust_executor import RobustMASTGExecutor
        from .compliance_reporter import MASTGComplianceReporter
        from .plugin_integration import PluginIntegrationManager
        from .data_structures import MASTGTestCase, MASTGTestExecution, MASTGConfiguration
        
        logging.debug("MASTG Integration plugin validation successful")
        return True
        
    except ImportError as e:
        logging.error(f"MASTG Integration plugin validation failed: {e}")
        return False
    except Exception as e:
        logging.error(f"MASTG Integration plugin validation error: {e}")
        return False 