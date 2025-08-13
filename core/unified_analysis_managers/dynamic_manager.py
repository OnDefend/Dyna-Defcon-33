#!/usr/bin/env python3
"""
Unified Dynamic Analysis Manager

Consolidates dynamic analysis coordination and management into a single,
intelligent manager that orchestrates Frida, drozer, and other dynamic tools.

KEY FEATURES:
- Intelligent coordination of dynamic analysis tools
- Device management and resource allocation
- orchestration of testing workflows
- Fallback strategies when tools unavailable
- Performance monitoring and optimization
- 100% backward compatibility with existing systems
"""

import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple, Union
from dataclasses import dataclass
from enum import Enum

from .base_manager import BaseAnalysisManager, AnalysisManagerConfig, ManagerStatus

class DynamicStrategy(Enum):
    """Dynamic analysis execution strategies."""
    AUTO = "auto"                        # Automatic strategy selection
    FULL_DYNAMIC = "full_dynamic"        # Full dynamic analysis (Frida + Drozer)
    FRIDA_ONLY = "frida_only"           # Frida-only dynamic analysis
    DROZER_ONLY = "drozer_only"         # Drozer-only dynamic analysis
    STATIC_SIMULATION = "static_simulation"  # Static simulation of dynamic analysis
    HYBRID = "hybrid"                   # Hybrid static-dynamic approach

@dataclass
class DynamicConfig:
    """Configuration for dynamic analysis strategies."""
    analysis_duration: int = 120
    enable_frida: bool = True
    enable_drozer: bool = True
    enable_ssl_bypass: bool = True
    enable_webview_testing: bool = True
    enable_runtime_manipulation: bool = True
    device_timeout: int = 30
    max_retries: int = 3
    enable_device_monitoring: bool = True
    enable_performance_monitoring: bool = True
    fallback_to_static: bool = True

class BaseDynamicStrategy(ABC):
    """Base class for dynamic analysis strategies."""
    
    def __init__(self, package_name: str, config: DynamicConfig):
        self.package_name = package_name
        self.config = config
        self.logger = logging.getLogger(f"{self.__class__.__name__}_{package_name}")
        self.analysis_results = {}
        self.analysis_complete = False
        self.tools_available = {}
    
    @abstractmethod
    def start_analysis(self) -> bool:
        """Start dynamic analysis."""
        pass
    
    @abstractmethod
    def check_analysis_status(self) -> bool:
        """Check if analysis is running."""
        pass
    
    @abstractmethod
    def stop_analysis(self) -> bool:
        """Stop dynamic analysis."""
        pass
    
    @abstractmethod
    def get_analysis_results(self) -> Dict[str, Any]:
        """Get analysis results."""
        pass
    
    def get_strategy_info(self) -> Dict[str, Any]:
        """Get strategy information."""
        return {
            "name": self.__class__.__name__,
            "package_name": self.package_name,
            "analysis_complete": self.analysis_complete,
            "tools_available": self.tools_available,
            "capabilities": self._get_capabilities()
        }
    
    @abstractmethod
    def _get_capabilities(self) -> List[str]:
        """Get strategy capabilities."""
        pass

class FullDynamicStrategy(BaseDynamicStrategy):
    """Full dynamic analysis strategy using all available tools."""
    
    def __init__(self, package_name: str, config: DynamicConfig):
        super().__init__(package_name, config)
        self.frida_manager = None
        self.drozer_manager = None
        self._initialize_tools()
    
    def _initialize_tools(self) -> None:
        """Initialize dynamic analysis tools."""
        try:
            # Initialize Frida manager
            if self.config.enable_frida:
                from .frida_manager import UnifiedFridaManager
                from .base_manager import AnalysisManagerConfig
                
                frida_config = AnalysisManagerConfig(
                    package_name=self.package_name,
                    strategy="auto"
                )
                self.frida_manager = UnifiedFridaManager(frida_config)
                self.tools_available["frida"] = True
                
            # Initialize Drozer manager
            if self.config.enable_drozer:
                from .drozer_manager import UnifiedDrozerManager
                from .base_manager import AnalysisManagerConfig
                
                drozer_config = AnalysisManagerConfig(
                    package_name=self.package_name,
                    strategy="auto"
                )
                self.drozer_manager = UnifiedDrozerManager(drozer_config)
                self.tools_available["drozer"] = True
                
        except Exception as e:
            self.logger.error(f"Tool initialization failed: {e}")
    
    def start_analysis(self) -> bool:
        """Start full dynamic analysis."""
        try:
            self.logger.info("Starting full dynamic analysis...")
            
            analysis_success = False
            
            # Start Frida analysis
            if self.frida_manager:
                if self.frida_manager.start_connection_with_retry():
                    self.logger.info("Frida analysis started successfully")
                    analysis_success = True
                    
                    # Load standard scripts
                    if self.config.enable_ssl_bypass:
                        self.frida_manager.load_ssl_bypass()
                    
                    if self.config.enable_webview_testing:
                        self.frida_manager.load_webview_security()
                else:
                    self.logger.warning("Frida analysis failed to start")
            
            # Start Drozer analysis
            if self.drozer_manager:
                if self.drozer_manager.start_connection_with_retry():
                    self.logger.info("Drozer analysis started successfully")
                    analysis_success = True
                else:
                    self.logger.warning("Drozer analysis failed to start")
            
            if analysis_success:
                # Run analysis for configured duration
                self._run_analysis_workflow()
                return True
            else:
                self.logger.error("No dynamic analysis tools could be started")
                return False
                
        except Exception as e:
            self.logger.error(f"Full dynamic analysis failed: {e}")
            return False
    
    def check_analysis_status(self) -> bool:
        """Check if any analysis is running."""
        frida_running = False
        drozer_running = False
        
        if self.frida_manager:
            frida_running = self.frida_manager.check_connection()
        
        if self.drozer_manager:
            drozer_running = self.drozer_manager.check_connection()
        
        return frida_running or drozer_running
    
    def stop_analysis(self) -> bool:
        """Stop all dynamic analysis."""
        try:
            success = True
            
            if self.frida_manager:
                if not self.frida_manager.stop_connection():
                    success = False
            
            if self.drozer_manager:
                if not self.drozer_manager.stop_connection():
                    success = False
            
            self.analysis_complete = True
            return success
            
        except Exception as e:
            self.logger.error(f"Error stopping analysis: {e}")
            return False
    
    def get_analysis_results(self) -> Dict[str, Any]:
        """Get comprehensive analysis results."""
        results = {
            "analysis_type": "full_dynamic",
            "package_name": self.package_name,
            "timestamp": time.time(),
            "tools_used": list(self.tools_available.keys()),
            "frida_results": {},
            "drozer_results": {},
            "combined_findings": []
        }
        
        # Get Frida results
        if self.frida_manager:
            results["frida_results"] = self.frida_manager.get_analysis_results()
        
        # Get Drozer results
        if self.drozer_manager:
            drozer_status = self.drozer_manager.get_status()
            results["drozer_results"] = {
                "status": drozer_status,
                "connection_available": drozer_status.get("connected", False)
            }
        
        # Combine and correlate findings
        results["combined_findings"] = self._correlate_findings(
            results["frida_results"], 
            results["drozer_results"]
        )
        
        self.analysis_results = results
        return results
    
    def _run_analysis_workflow(self) -> None:
        """Run the dynamic analysis workflow."""
        try:
            self.logger.info(f"Running dynamic analysis for {self.config.analysis_duration} seconds...")
            
            # Frida workflow
            if self.frida_manager and self.frida_manager.connected:
                # Attach to app
                if self.frida_manager.attach_to_app():
                    self.logger.info("Successfully attached to application")
                    
                    # Run standard analysis scripts
                    self._run_frida_analysis()
                else:
                    self.logger.warning("Failed to attach to application")
            
            # Drozer workflow
            if self.drozer_manager and self.drozer_manager.connected:
                self._run_drozer_analysis()
            
            # Wait for analysis completion
            time.sleep(self.config.analysis_duration)
            
            self.logger.info("Dynamic analysis workflow completed")
            
        except Exception as e:
            self.logger.error(f"Analysis workflow error: {e}")
    
    def _run_frida_analysis(self) -> None:
        """Run Frida-specific analysis."""
        try:
            # Runtime manipulation tests
            if self.config.enable_runtime_manipulation:
                runtime_script = """
                Java.perform(function() {
                    console.log("[+] Runtime manipulation test started");
                    
                    // Hook common Android APIs
                    try {
                        var Context = Java.use('android.content.Context');
                        Context.getPackageName.implementation = function() {
                            send({category: 'runtime_manipulation', message: 'getPackageName hooked'});
                            return this.getPackageName();
                        };
                    } catch (e) {
                        console.log('[-] Context hook failed: ' + e);
                    }
                });
                """
                
                self.frida_manager.execute_script(runtime_script, "runtime_manipulation")
            
        except Exception as e:
            self.logger.error(f"Frida analysis error: {e}")
    
    def _run_drozer_analysis(self) -> None:
        """Run Drozer-specific analysis."""
        try:
            # Basic drozer commands
            basic_commands = [
                "list",
                f"run app.package.info -a {self.package_name}",
                f"run app.activity.info -a {self.package_name}"
            ]
            
            for command in basic_commands:
                success, result = self.drozer_manager.execute_command_with_monitoring(command)
                if success:
                    self.logger.debug(f"Drozer command successful: {command}")
                else:
                    self.logger.warning(f"Drozer command failed: {command}")
            
        except Exception as e:
            self.logger.error(f"Drozer analysis error: {e}")
    
    def _correlate_findings(self, frida_results: Dict, drozer_results: Dict) -> List[Dict[str, Any]]:
        """Correlate findings from different tools."""
        combined_findings = []
        
        # Process Frida findings
        if frida_results:
            for category, findings in frida_results.items():
                if isinstance(findings, list):
                    for finding in findings:
                        combined_findings.append({
                            "source": "frida",
                            "category": category,
                            "finding": finding,
                            "confidence": 0.8  # High confidence for Frida
                        })
        
        # Process Drozer findings
        if drozer_results.get("status", {}).get("connected"):
            combined_findings.append({
                "source": "drozer",
                "category": "connectivity",
                "finding": "Drozer connection established",
                "confidence": 1.0
            })
        
        return combined_findings
    
    def _get_capabilities(self) -> List[str]:
        """Get full dynamic strategy capabilities."""
        return [
            "frida_integration",
            "drozer_integration",
            "ssl_bypass_testing",
            "webview_security_testing",
            "runtime_manipulation",
            "device_communication",
            "comprehensive_analysis",
            "finding_correlation"
        ]

class StaticSimulationStrategy(BaseDynamicStrategy):
    """Static simulation strategy when dynamic tools unavailable."""
    
    def start_analysis(self) -> bool:
        """Start static simulation of dynamic analysis."""
        try:
            self.logger.info("Starting static simulation of dynamic analysis...")
            
            # Simulate dynamic analysis behaviors
            self.analysis_results = {
                "analysis_type": "static_simulation",
                "package_name": self.package_name,
                "timestamp": time.time(),
                "simulated_findings": [
                    {
                        "category": "ssl_testing",
                        "finding": "SSL pinning bypass simulation",
                        "simulated": True,
                        "confidence": 0.3
                    },
                    {
                        "category": "webview_testing", 
                        "finding": "WebView security testing simulation",
                        "simulated": True,
                        "confidence": 0.3
                    }
                ],
                "limitations": [
                    "No actual device interaction",
                    "Simulated results only",
                    "Limited accuracy"
                ]
            }
            
            self.analysis_complete = True
            return True
            
        except Exception as e:
            self.logger.error(f"Static simulation failed: {e}")
            return False
    
    def check_analysis_status(self) -> bool:
        """Check simulation status (always complete quickly)."""
        return self.analysis_complete
    
    def stop_analysis(self) -> bool:
        """Stop simulation (always succeeds)."""
        self.analysis_complete = True
        return True
    
    def get_analysis_results(self) -> Dict[str, Any]:
        """Get simulation results."""
        return self.analysis_results
    
    def _get_capabilities(self) -> List[str]:
        """Get static simulation capabilities."""
        return [
            "static_simulation",
            "no_device_required",
            "compatibility_mode",
            "basic_analysis_flow"
        ]

class UnifiedDynamicManager(BaseAnalysisManager):
    """
    Unified dynamic analysis manager with intelligent strategy selection.
    
    Orchestrates dynamic analysis tools and provides a unified interface
    for all dynamic analysis capabilities.
    """
    
    def __init__(self, config: AnalysisManagerConfig = None):
        # Initialize with default config if none provided
        if config is None:
            config = AnalysisManagerConfig(
                package_name="default",
                strategy="auto"
            )
        
        super().__init__(config)
        
        # Initialize dynamic configuration
        self.dynamic_config = DynamicConfig()
        
        # Initialize strategy
        self.current_strategy: Optional[BaseDynamicStrategy] = None
        self._initialize_strategy()
    
    def _initialize_strategy(self) -> None:
        """Initialize dynamic strategy based on configuration."""
        try:
            strategy_name = self.config.strategy
            
            if strategy_name == "auto":
                strategy_name = self._select_optimal_strategy()
            
            self.current_strategy = self._create_strategy(strategy_name)
            self.logger.info(f"Initialized dynamic strategy: {strategy_name}")
            
        except Exception as e:
            self.logger.error(f"Strategy initialization failed: {e}")
            # Fallback to static simulation
            self.current_strategy = self._create_strategy("static_simulation")
    
    def _select_optimal_strategy(self) -> str:
        """Select optimal strategy based on system capabilities."""
        # Check device availability
        if not self._check_device_availability():
            return "static_simulation"
        
        # Check tool availability
        tools_available = self._assess_tool_availability()
        
        if tools_available["frida"] and tools_available["drozer"]:
            return "full_dynamic"
        elif tools_available["frida"]:
            return "frida_only"
        elif tools_available["drozer"]:
            return "drozer_only"
        else:
            return "static_simulation"
    
    def _check_device_availability(self) -> bool:
        """Check if Android device is available."""
        try:
            import subprocess
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return "device" in result.stdout or "emulator" in result.stdout
        except:
            return False
    
    def _assess_tool_availability(self) -> Dict[str, bool]:
        """Assess availability of dynamic analysis tools."""
        tools = {"frida": False, "drozer": False}
        
        # Check Frida
        try:
            import subprocess
            result = subprocess.run(
                ["frida", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            tools["frida"] = result.returncode == 0
        except:
            pass
        
        # Check Drozer
        try:
            import subprocess
            result = subprocess.run(
                ["drozer", "--help"],
                capture_output=True,
                text=True,
                timeout=5
            )
            tools["drozer"] = result.returncode == 0
        except:
            pass
        
        return tools
    
    def _create_strategy(self, strategy_name: str) -> BaseDynamicStrategy:
        """Create strategy instance based on name."""
        strategy_map = {
            "full_dynamic": FullDynamicStrategy,
            "static_simulation": StaticSimulationStrategy
        }
        
        strategy_class = strategy_map.get(strategy_name)
        if not strategy_class:
            self.logger.warning(f"Unknown strategy: {strategy_name}, using static simulation")
            strategy_class = StaticSimulationStrategy
        
        return strategy_class(self.config.package_name, self.dynamic_config)
    
    def start_connection(self) -> bool:
        """Start dynamic analysis using current strategy."""
        if not self.current_strategy:
            return False
        
        try:
            success = self.current_strategy.start_analysis()
            if success:
                self.connected = True
                self.status = ManagerStatus.RUNNING
            else:
                self.status = ManagerStatus.FAILED
            
            return success
            
        except Exception as e:
            self.last_error = e
            self.status = ManagerStatus.FAILED
            return False
    
    def check_connection(self) -> bool:
        """Check dynamic analysis status using current strategy."""
        if not self.current_strategy:
            return False
        
        try:
            running = self.current_strategy.check_analysis_status()
            
            if not running and self.status == ManagerStatus.RUNNING:
                self.status = ManagerStatus.CONNECTED  # Analysis completed
            
            return running
            
        except Exception as e:
            self.last_error = e
            return False
    
    def execute_command(self, command: str, **kwargs) -> tuple[bool, Any]:
        """Execute dynamic analysis command using current strategy."""
        if not self.current_strategy:
            return False, "No strategy available"
        
        try:
            if command == "start_analysis":
                return self.current_strategy.start_analysis(), "Analysis started"
            elif command == "stop_analysis":
                return self.current_strategy.stop_analysis(), "Analysis stopped"
            elif command == "get_results":
                results = self.current_strategy.get_analysis_results()
                return True, results
            else:
                return False, f"Unknown command: {command}"
            
        except Exception as e:
            self.last_error = e
            return False, f"Command execution failed: {e}"
    
    def stop_connection(self) -> bool:
        """Stop dynamic analysis using current strategy."""
        if not self.current_strategy:
            return True
        
        try:
            success = self.current_strategy.stop_analysis()
            if success:
                self.connected = False
                self.status = ManagerStatus.DISCONNECTED
            
            return success
            
        except Exception as e:
            self.last_error = e
            return False
    
    def start_analysis(self) -> bool:
        """Start dynamic analysis."""
        return self.start_connection()
    
    def get_analysis_results(self) -> Dict[str, Any]:
        """Get analysis results from current strategy."""
        if not self.current_strategy:
            return {}
        
        return self.current_strategy.get_analysis_results()
    
    def get_strategy_info(self) -> Dict[str, Any]:
        """Get information about current strategy."""
        if not self.current_strategy:
            return {"strategy": "none", "capabilities": []}
        
        return self.current_strategy.get_strategy_info()

# Export public interface
__all__ = [
    "UnifiedDynamicManager",
    "DynamicStrategy",
    "DynamicConfig"
] 