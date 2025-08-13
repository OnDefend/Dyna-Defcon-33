#!/usr/bin/env python3
"""
Dynamic Analysis Plugin for AODS Framework - Modular Architecture Redirect

This plugin provides dynamic analysis capabilities through modular components
to provide dynamic analysis capabilities.

The plugin uses a modular architecture with confidence calculation system
with dynamic scoring, external configuration with device management, 
testability and maintainability, clean dependency injection pattern, 
rich text formatting with runtime analysis, and error handling and logging.

Components:
- device_manager.py: Device management and orchestration
- network_analyzer.py: Network traffic analysis
- confidence_calculator.py: Dynamic confidence calculation
- Dynamic confidence calculation without hardcoded values
- Parallel processing support for large-scale dynamic analysis
- Structured error handling with logging
- Device detection and configuration management

Features:
- Multi-platform Dynamic Analysis: Intent fuzzing, network monitoring, WebView security testing
- Real Device Integration: Device management with real hardware support
- Performance optimization through parallel execution and caching
- Error handling with graceful degradation and device recovery
"""

import logging
import time
from typing import Tuple, Union, Dict, List, Any, Optional
from datetime import datetime

from rich.text import Text

# Import modular components
from plugins.advanced_dynamic_analysis_modules import (
    DeviceManager,
    AppManager,
    NetworkAnalyzer,
    ReportGenerator,
    AnalysisResult,
    AnalysisType,
    DynamicAnalysisConfig,
    NetworkConfig,
    Finding,
    RiskLevel,
    PLUGIN_CHARACTERISTICS,
    PLUGIN_INFO
)

# Configure logging
logger = logging.getLogger(__name__)

# Plugin metadata for AODS framework integration
PLUGIN_METADATA = {
    "name": "Advanced Dynamic Analysis",
    "description": "Comprehensive dynamic security testing with modular architecture",
    "version": "2.0.0",
    "author": "AODS Development Team",
    "category": "DYNAMIC_ANALYSIS",
    "priority": "HIGH",
    "timeout": 300,
    "mode": "comprehensive",
    "requires_device": True,
    "requires_network": True,
    "invasive": True,
    "execution_time_estimate": 240,
    "dependencies": ["adb", "frida"],
    "modular_architecture": True,
    "components": [
        "device_manager",
        "app_manager", 
        "network_analyzer",
        "report_generator",
        "data_structures"
    ],
    "masvs_controls": ["MSTG-PLATFORM-01", "MSTG-PLATFORM-02", "MASVS-PLATFORM-3", "MSTG-NETWORK-01", "MSTG-NETWORK-02", "MSTG-CODE-02", "MSTG-RESILIENCE-10"],
    "analysis_types": ["intent_fuzzing", "network_monitoring", "webview_security", "runtime_protection"]
}

# Legacy compatibility
PLUGIN_INFO = PLUGIN_METADATA
PLUGIN_CHARACTERISTICS = {
    "mode": "comprehensive",
    "category": "dynamic_analysis",
    "requires_device": True,
    "targets": ["runtime_vulnerabilities", "dynamic_behavior"],
    "modular": True
}

class AdvancedDynamicAnalysisOrchestrator:
    """
    Main orchestrator for advanced dynamic analysis using modular architecture.
    
    Coordinates device management, app lifecycle, network analysis, and reporting
    through specialized modular components with professional confidence calculation.
    """
    
    def __init__(self, config: Optional[DynamicAnalysisConfig] = None):
        """Initialize the orchestrator with modular components."""
        self.config = config or DynamicAnalysisConfig()
        self.logger = logging.getLogger(__name__)
        
        # Initialize modular components
        self._initialize_components()
        
        # Analysis state
        self.analysis_complete = False
        self.analysis_start_time = None
        
    def _initialize_components(self):
        """Initialize all modular components with dependency injection."""
        try:
            # Initialize enhanced Frida connection first
            self._initialize_enhanced_frida_connection()
            
            # Initialize core managers
            self.device_manager = DeviceManager(timeout=self.config.timeout)
            self.app_manager = AppManager(timeout=self.config.timeout)
            self.network_analyzer = NetworkAnalyzer(
                self.config.network_config, 
                self.config.timeout
            )
            self.report_generator = ReportGenerator()
            
            self.logger.info("Advanced dynamic analysis components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize dynamic analysis components: {e}", exc_info=True)
            raise
    
    def _initialize_enhanced_frida_connection(self):
        """Initialize enhanced Frida connection for all components to use."""
        try:
            from core.frida_framework.frida_connection import FridaConnection
            
            self.logger.info("🚀 Initializing enhanced Frida connection for dynamic analysis")
            
            # Create enhanced Frida connection (package name will be set during analysis)
            self.frida_connection = FridaConnection()
            
            # Validate Frida availability
            is_available, status_message = self.frida_connection.check_frida_availability()
            
            if is_available:
                self.logger.info(f"✅ Enhanced Frida connection initialized: {status_message}")
                self.frida_enabled = True
            else:
                self.logger.warning(f"⚠️ Frida not available, dynamic analysis will use fallback modes: {status_message}")
                self.frida_enabled = False
                
        except ImportError as e:
            self.logger.warning(f"⚠️ Enhanced FridaConnection not available, using legacy approach: {e}")
            self.frida_connection = None
            self.frida_enabled = False
        except Exception as e:
            self.logger.warning(f"⚠️ Failed to initialize enhanced Frida connection: {e}")
            self.frida_connection = None
            self.frida_enabled = False
    
    def _prepare_frida_server(self, package_name: str) -> bool:
        """Prepare Frida server using enhanced connection with auto-installation."""
        if not self.frida_enabled or not self.frida_connection:
            self.logger.debug("Frida not enabled or connection not available, skipping server preparation")
            return False
        
        try:
            self.logger.info(f"🚀 Preparing enhanced Frida server for {package_name}")
            
            # Update package name for the connection
            self.frida_connection.package_name = package_name
            
            # Start Frida server with auto-installation capabilities
            if self.frida_connection.start_frida_server():
                self.logger.info("✅ Enhanced Frida server ready for dynamic analysis")
                return True
            else:
                self.logger.warning("⚠️ Failed to start Frida server, dynamic analysis will continue with limited capabilities")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Error preparing Frida server: {e}")
            return False
    
    def analyze(self, apk_ctx) -> AnalysisResult:
        """
        Perform comprehensive dynamic analysis using modular components.
        
        Args:
            apk_ctx: APK context containing analysis targets
            
        Returns:
            AnalysisResult: Complete dynamic analysis results
        """
        self.analysis_start_time = time.time()
        
        try:
            # Initialize enhanced Frida server if available
            frida_server_ready = self._prepare_frida_server(apk_ctx.package_name)
            
            # Device setup and validation
            device_info = self.device_manager.check_device_connection()
            
            # Check if device is available - if not, use enhanced fallback analysis
            if (device_info.status.value in ['disconnected', 'unknown'] or 
                device_info.device_id in ['none', 'unknown'] or 
                not self.frida_enabled):
                
                self.logger.info("🔄 Device unavailable or Frida disabled - using enhanced dynamic fallback analysis")
                
                try:
                    from core.enhanced_dynamic_fallback_analyzer import EnhancedDynamicFallbackAnalyzer
                    
                    # Use enhanced dynamic fallback analyzer for meaningful results
                    fallback_analyzer = EnhancedDynamicFallbackAnalyzer(apk_ctx)
                    fallback_results = fallback_analyzer.analyze_dynamic_vulnerabilities()
                    
                    # Create enhanced analysis result with fallback findings
                    analysis_result = AnalysisResult(
                        analysis_id=f"enhanced_dynamic_fallback_{int(time.time())}",
                        package_name=apk_ctx.package_name,
                        analysis_type=AnalysisType.DYNAMIC,
                        start_time=datetime.fromtimestamp(self.analysis_start_time),
                        end_time=datetime.now(),
                        status="completed",
                        device_info={'status': 'unavailable', 'fallback_mode': 'enhanced_static_simulation'},
                        app_info={'status': 'simulated', 'note': 'Enhanced fallback analysis - no device required'},
                        network_analysis={'status': 'static_based', 'findings': []}
                    )
                    
                    # Add enhanced fallback results to metadata
                    analysis_result.metadata['enhanced_dynamic_vulnerabilities'] = fallback_results.get('vulnerabilities', [])
                    analysis_result.metadata['fallback_analysis_stats'] = fallback_results.get('summary', {})
                    analysis_result.metadata['files_analyzed'] = fallback_results.get('files_analyzed', 0)
                    analysis_result.metadata['analysis_duration'] = time.time() - self.analysis_start_time
                    analysis_result.metadata['analysis_method'] = 'enhanced_dynamic_fallback'
                    analysis_result.metadata['confidence_note'] = fallback_results.get('confidence_note', 'Enhanced static-based dynamic analysis')
                    
                    self.logger.info(f"✅ Enhanced dynamic fallback completed: {fallback_results.get('summary', {}).get('total_findings', 0)} findings")
                    
                    self.analysis_complete = True
                    return analysis_result
                    
                except Exception as e:
                    self.logger.error(f"❌ Enhanced fallback analysis failed: {e}")
                    # Continue with basic simulation below
            
            # Standard dynamic analysis when device is available
            # Application management
            app_info = self.app_manager.start_application(apk_ctx.device_id, apk_ctx.package_name)
            
            # Network analysis
            network_results = self.network_analyzer.analyze_network_behavior(apk_ctx, app_info)
            
            # Compile results
            # Fix: AnalysisResult doesn't accept analysis_duration parameter - use proper dataclass fields
            analysis_result = AnalysisResult(
                analysis_id=f"dynamic_analysis_{int(time.time())}",
                package_name=apk_ctx.package_name,
                analysis_type=AnalysisType.DYNAMIC,
                start_time=datetime.fromtimestamp(self.analysis_start_time),
                end_time=datetime.now(),
                status="completed",
                device_info=device_info,
                app_info=app_info,
                network_analysis=network_results
            )
            # Add duration to metadata
            analysis_result.metadata['analysis_duration'] = time.time() - self.analysis_start_time
            
            self.analysis_complete = True
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Dynamic analysis failed: {e}", exc_info=True)
            raise

def run(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Main plugin execution function using modular architecture.
    
    This function orchestrates comprehensive dynamic analysis through specialized
    modular components including device management, application lifecycle,
    network analysis, and professional reporting.
    
    Args:
        apk_ctx: APK context containing analysis targets and metadata
        
    Returns:
        Tuple[str, Union[str, Text]]: Analysis results with Rich text formatting
    """
    start_time = time.time()
    plugin_name = "Advanced Dynamic Analysis"
    
    try:
        logger.info("Starting modular advanced dynamic analysis")
        
        # Initialize configuration
        config = DynamicAnalysisConfig(
            timeout=300,
            enable_network_analysis=True,
            enable_intent_fuzzing=True,
            enable_webview_testing=True,
            network_config=NetworkConfig()
        )
        
        # Initialize modular orchestrator
        orchestrator = AdvancedDynamicAnalysisOrchestrator(config)
        
        # Perform comprehensive analysis
        analysis_result = orchestrator.analyze(apk_ctx)
        
        # Generate comprehensive report with configuration
        config = orchestrator.device_manager.config if hasattr(orchestrator.device_manager, 'config') else {}
        formatted_report = orchestrator.report_generator.generate_comprehensive_report(analysis_result, config)
        
        # Log completion statistics
        execution_time = time.time() - start_time
        findings_count = len(analysis_result.findings) if hasattr(analysis_result, 'findings') else 0
        
        logger.info(f"Dynamic analysis completed in {execution_time:.2f}s - Found {findings_count} findings")
        
        return plugin_name, formatted_report
        
    except Exception as e:
        logger.error(f"Advanced dynamic analysis failed: {e}", exc_info=True)
        error_report = Text()
        error_report.append(f"Advanced Dynamic Analysis - ERROR\n\n", style="bold red")
        error_report.append(f"Analysis failed with error: {str(e)}\n", style="red")
        error_report.append("Check logs for detailed error information.", style="dim")
        
        return plugin_name, error_report

def run_plugin(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Plugin interface function expected by the plugin manager.
    
    Args:
        apk_ctx: The APKContext instance containing APK path and metadata
        
    Returns:
        Tuple[str, Union[str, Text]]: Plugin execution result
    """
    return run(apk_ctx)

# Export for modular compatibility
__all__ = [
    'run',
    'run_plugin',
    'AdvancedDynamicAnalysisOrchestrator',
    'PLUGIN_INFO',
    'PLUGIN_CHARACTERISTICS',
    'PLUGIN_METADATA'
]
