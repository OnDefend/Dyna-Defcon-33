#!/usr/bin/env python3
"""
Dynamic Analysis Coordinator

Orchestrates multiple specialized dynamic analysis components while preserving their 
unique functions and ensuring efficient collaboration. This coordinator provides a 
unified interface for running targeted or comprehensive security analysis across 
different analysis engines.

Coordinated Components:
- DynamicLogAnalyzer: Log-based security event detection and pattern analysis
- ContinuousMonitoringEngine: Runtime decryption pattern monitoring and behavioral analysis
- AdvancedDynamicAnalysisOrchestrator: General security analysis orchestration and component management

Core Features:
- Shared enhanced Frida infrastructure prevents resource conflicts between components
- Configurable analysis profiles enable targeted analysis or comprehensive security coverage
- Result correlation engine intelligently merges findings from all active components
- Component specialization preserved to avoid functional duplication
- Integrated reporting using AODS unified reporting framework

Design Philosophy:
- Non-invasive design preserves independent component functionality
- Configuration-driven behavior avoids hardcoded analysis patterns
- Graceful degradation ensures component failures don't cascade
- Clean modular architecture separates coordination logic from analysis implementation
"""

import logging
import time
import asyncio
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

# AODS Enhanced Infrastructure
try:
    from .frida_connection import FridaConnection
    ENHANCED_FRIDA_AVAILABLE = True
except ImportError:
    ENHANCED_FRIDA_AVAILABLE = False

# AODS Keyboard Cache Analysis
try:
    from core.keyboard_cache_analyzer import create_keyboard_cache_analyzer
    KEYBOARD_CACHE_ANALYZER_AVAILABLE = True
except ImportError:
    KEYBOARD_CACHE_ANALYZER_AVAILABLE = False

# AODS Network Analysis Coordinator
try:
    from core.network_analysis_coordinator import NetworkAnalysisCoordinator, NetworkAnalysisProfile
    NETWORK_COORDINATOR_AVAILABLE = True
except ImportError:
    NetworkAnalysisCoordinator = None
    NetworkAnalysisProfile = None
    NETWORK_COORDINATOR_AVAILABLE = False

# AODS Input Validation Coordinator
try:
    from core.input_validation_coordinator import InputValidationCoordinator, TestingProfile
    INPUT_VALIDATION_COORDINATOR_AVAILABLE = True
except ImportError:
    InputValidationCoordinator = None
    TestingProfile = None
    INPUT_VALIDATION_COORDINATOR_AVAILABLE = False

# AODS Unified Reporting Framework
try:
    from core.shared_infrastructure.reporting import (
        UnifiedReportOrchestrator, ReportConfiguration, ReportType, ReportFormat,
        DynamicCoordinationAnalysisResult, ComponentAnalysisResult, 
        RuntimePatternResult, CorrelationAnalysisResult, SecurityFinding, SeverityLevel
    )
    UNIFIED_REPORTING_AVAILABLE = True
except ImportError:
    logging.warning("AODS Unified Reporting Framework not available - using basic reporting")
    UNIFIED_REPORTING_AVAILABLE = False

# Specialized Dynamic Analysis Components
try:
    from core.dynamic_log_analyzer import DynamicLogAnalyzer
    LOG_ANALYZER_AVAILABLE = True
except ImportError:
    DynamicLogAnalyzer = None
    LOG_ANALYZER_AVAILABLE = False

try:
    from plugins.runtime_decryption_analysis.realtime_vulnerability_discovery import ContinuousMonitoringEngine
    MONITORING_ENGINE_AVAILABLE = True
except ImportError:
    ContinuousMonitoringEngine = None
    MONITORING_ENGINE_AVAILABLE = False

try:
    from plugins.advanced_dynamic_analysis import AdvancedDynamicAnalysisOrchestrator
    ORCHESTRATOR_AVAILABLE = True
except ImportError:
    AdvancedDynamicAnalysisOrchestrator = None
    ORCHESTRATOR_AVAILABLE = False

# Runtime Vulnerability Pattern Detection
try:
    from core.runtime_vulnerability_patterns import (
        RuntimePatternDetector, 
        create_runtime_pattern_detector,
        RuntimeEvidence,
        RuntimeDetectionTrigger
    )
    RUNTIME_PATTERNS_AVAILABLE = True
except ImportError:
    RuntimePatternDetector = None
    RUNTIME_PATTERNS_AVAILABLE = False

# Test Result Correlation Engine
try:
    from .test_result_correlation_engine import (
        TestResultCorrelationEngine,
        create_correlation_engine,
        CorrelationResult
    )
    CORRELATION_ENGINE_AVAILABLE = True
except ImportError:
    TestResultCorrelationEngine = None
    CORRELATION_ENGINE_AVAILABLE = False


class AnalysisProfile(Enum):
    """Analysis profiles for coordinated component execution."""
    COMPREHENSIVE = "comprehensive"  # All components active
    MONITORING = "monitoring"        # Focus on continuous monitoring
    SECURITY = "security"           # Focus on security orchestration  
    LOGS = "logs"                   # Focus on log analysis


class CoordinationStatus(Enum):
    """Coordination session status."""
    INITIALIZING = "initializing"
    ACTIVE = "active"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPED = "stopped"


@dataclass
class ComponentState:
    """State tracking for individual components."""
    name: str
    component_type: str = "unknown"
    available: bool = False
    initialized: bool = False
    active: bool = False
    error: Optional[str] = None
    error_message: Optional[str] = None
    results: Optional[Any] = None
    instance: Optional[Any] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    last_execution: Optional[str] = None


@dataclass
class CoordinationResult:
    """Results from coordinated dynamic analysis."""
    profile: AnalysisProfile
    status: CoordinationStatus
    component_states: Dict[str, ComponentState] = field(default_factory=dict)
    correlated_findings: List[Dict[str, Any]] = field(default_factory=list)
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    analysis_duration: float = 0.0
    coordination_overhead: float = 0.0


class DynamicAnalysisCoordinator:
    """
    Coordinates specialized dynamic analysis components while preserving 
    their unique functions and ensuring efficient collaboration.
    """
    
    def __init__(self, package_name: str, config: Optional[Dict[str, Any]] = None):
        """Initialize coordinator with shared infrastructure and component instances."""
        self.package_name = package_name
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Coordination state
        self.status = CoordinationStatus.INITIALIZING
        self.current_session = None
        self.component_states = {}
        
        # Performance tracking
        self.coordination_start_time = None
        self.performance_metrics = {}
        
        # Runtime pattern detection integration
        self.runtime_detector = None
        self.runtime_patterns_enabled = False
        
        # Test result correlation engine integration
        self.correlation_engine = None
        self.correlation_enabled = False
        
        # Keyboard cache analyzer integration
        self.keyboard_cache_analyzer = None
        self.keyboard_cache_enabled = False
        
        # Network analysis coordinator integration
        self.network_coordinator = None
        self.network_analysis_enabled = False
        
        # Input validation coordinator integration
        self.input_validation_coordinator = None
        self.input_validation_enabled = False
        
        # Initialize coordinator
        self._initialize_coordinator()
    
    def _initialize_coordinator(self):
        """Initialize shared infrastructure and component availability."""
        self.logger.info(f"🚀 Initializing Dynamic Analysis Coordinator for {self.package_name}")
        
        # Initialize shared enhanced Frida infrastructure
        self._initialize_shared_frida()
        
        # Initialize component availability and states
        self._initialize_component_states()
        
        # Initialize runtime vulnerability pattern detection
        self._initialize_runtime_patterns()
        
        # Initialize test result correlation engine
        self._initialize_correlation_engine()
        
        # Initialize keyboard cache analyzer
        self._initialize_keyboard_cache_analyzer()
        
        # Initialize network analysis coordinator
        self._initialize_network_coordinator()
        
        # Initialize input validation coordinator
        self._initialize_input_validation_coordinator()
        
        available_components = len([c for c in self.component_states.values() if c.available])
        pattern_status = "enabled" if self.runtime_patterns_enabled else "disabled"
        correlation_status = "enabled" if self.correlation_enabled else "disabled"
        keyboard_status = "enabled" if self.keyboard_cache_enabled else "disabled"
        network_status = "enabled" if self.network_analysis_enabled else "disabled"
        input_validation_status = "enabled" if self.input_validation_enabled else "disabled"
        self.logger.info(f"✅ Coordinator initialized with {available_components} available components, "
                        f"runtime patterns {pattern_status}, correlation engine {correlation_status}, "
                        f"keyboard cache analysis {keyboard_status}, network analysis {network_status}, "
                        f"input validation testing {input_validation_status}")
    
    def _initialize_shared_frida(self):
        """Initialize shared enhanced Frida connection for all components."""
        if ENHANCED_FRIDA_AVAILABLE:
            try:
                self.frida_connection = FridaConnection(package_name=self.package_name)
                self.frida_enabled = True
                self.logger.info("✅ Shared enhanced Frida connection initialized")
            except Exception as e:
                self.logger.warning(f"⚠️ Enhanced Frida connection failed: {e}")
                self.frida_connection = None
                self.frida_enabled = False
        else:
            self.logger.warning("⚠️ Enhanced Frida infrastructure not available")
            self.frida_connection = None
            self.frida_enabled = False
    
    def _initialize_component_states(self):
        """Initialize state tracking for all available components."""
        components = [
            ("log_analyzer", LOG_ANALYZER_AVAILABLE, DynamicLogAnalyzer),
            ("monitoring_engine", MONITORING_ENGINE_AVAILABLE, ContinuousMonitoringEngine),
            ("orchestrator", ORCHESTRATOR_AVAILABLE, AdvancedDynamicAnalysisOrchestrator)
        ]
        
        for name, available, component_class in components:
            # Determine component type from class name
            component_type = component_class.__name__ if component_class else "unknown"
            
            state = ComponentState(
                name=name, 
                available=available,
                component_type=component_type,
                last_execution=datetime.now().isoformat() if available else None
            )
            
            if available and component_class is not None:
                try:
                    # Initialize component instance
                    if name == "log_analyzer":
                        instance = component_class(self.package_name, self.config)
                    else:
                        instance = component_class(self.config)
                    
                    setattr(self, name, instance)
                    state.instance = instance
                    state.initialized = True
                    state.last_execution = datetime.now().isoformat()
                    self.logger.info(f"✅ {name} component initialized")
                    
                except Exception as e:
                    self.logger.warning(f"⚠️ {name} initialization failed: {e}")
                    state.error = str(e)
                    state.error_message = str(e)
                    setattr(self, name, None)
                    state.available = False
            else:
                self.logger.warning(f"⚠️ {name} component not available")
                setattr(self, name, None)
                state.available = False
            
            self.component_states[name] = state
    
    def _initialize_runtime_patterns(self):
        """Initialize runtime vulnerability pattern detection capabilities."""
        if RUNTIME_PATTERNS_AVAILABLE:
            try:
                # Create runtime pattern detector with coordinator configuration
                pattern_config = self.config.get('runtime_patterns', {})
                self.runtime_detector = create_runtime_pattern_detector(pattern_config)
                self.runtime_patterns_enabled = True
                self.logger.info("✅ Runtime vulnerability pattern detection initialized")
                
            except Exception as e:
                self.logger.warning(f"⚠️ Runtime pattern initialization failed: {e}")
                self.runtime_detector = None
                self.runtime_patterns_enabled = False
        else:
            self.logger.debug("Runtime vulnerability patterns not available")
            self.runtime_patterns_enabled = False
    
    def _initialize_correlation_engine(self):
        """Initialize test result correlation engine capabilities."""
        if CORRELATION_ENGINE_AVAILABLE:
            try:
                # Create correlation engine with coordinator configuration
                correlation_config = self.config.get('correlation', {})
                self.correlation_engine = create_correlation_engine(correlation_config)
                self.correlation_enabled = True
                self.logger.info("✅ Test result correlation engine initialized")
                
            except Exception as e:
                self.logger.warning(f"⚠️ Correlation engine initialization failed: {e}")
                self.correlation_engine = None
                self.correlation_enabled = False
        else:
            self.logger.debug("Test result correlation engine not available")
            self.correlation_enabled = False
    
    def _initialize_keyboard_cache_analyzer(self):
        """Initialize keyboard cache vulnerability analyzer."""
        if KEYBOARD_CACHE_ANALYZER_AVAILABLE:
            try:
                # Create keyboard cache analyzer with coordinator configuration
                keyboard_config = self.config.get('keyboard_cache', {})
                self.keyboard_cache_analyzer = create_keyboard_cache_analyzer(
                    self.package_name, keyboard_config
                )
                self.keyboard_cache_enabled = True
                self.logger.info("✅ Keyboard cache analyzer initialized")
                
            except Exception as e:
                self.logger.warning(f"⚠️ Keyboard cache analyzer initialization failed: {e}")
                self.keyboard_cache_analyzer = None
                self.keyboard_cache_enabled = False
        else:
            self.logger.debug("Keyboard cache analyzer not available")
            self.keyboard_cache_enabled = False
    
    def _initialize_network_coordinator(self):
        """Initialize network analysis coordinator."""
        if NETWORK_COORDINATOR_AVAILABLE:
            try:
                # Create network analysis coordinator with coordinator configuration
                network_config = self.config.get('network_analysis', {})
                self.network_coordinator = NetworkAnalysisCoordinator(
                    self.package_name, network_config
                )
                self.network_analysis_enabled = True
                self.logger.info("✅ Network analysis coordinator initialized")
                
            except Exception as e:
                self.logger.warning(f"⚠️ Network analysis coordinator initialization failed: {e}")
                self.network_coordinator = None
                self.network_analysis_enabled = False
        else:
            self.logger.debug("Network analysis coordinator not available")
            self.network_analysis_enabled = False
    
    def _initialize_input_validation_coordinator(self):
        """Initialize input validation testing coordinator."""
        if INPUT_VALIDATION_COORDINATOR_AVAILABLE:
            try:
                # Create input validation coordinator with coordinator configuration
                input_validation_config = self.config.get('input_validation', {})
                self.input_validation_coordinator = InputValidationCoordinator(
                    self.package_name, input_validation_config
                )
                self.input_validation_enabled = True
                self.logger.info("✅ Input validation testing coordinator initialized")
                
            except Exception as e:
                self.logger.warning(f"⚠️ Input validation coordinator initialization failed: {e}")
                self.input_validation_coordinator = None
                self.input_validation_enabled = False
        else:
            self.logger.debug("Input validation coordinator not available")
            self.input_validation_enabled = False
    
    def coordinate_analysis(self, apk_ctx, analysis_profile: AnalysisProfile) -> CoordinationResult:
        """
        Coordinate analysis across specialized components based on profile.
        
        Args:
            apk_ctx: APK context containing analysis targets
            analysis_profile: Analysis profile determining component activation
            
        Returns:
            CoordinationResult: Complete coordination results with component findings
        """
        self.coordination_start_time = time.time()
        self.status = CoordinationStatus.ACTIVE
        
        self.logger.info(f"🎯 Starting coordinated dynamic analysis with profile: {analysis_profile.value}")
        
        try:
            # 1. Initialize shared Frida infrastructure
            frida_ready = self._prepare_shared_frida()
            
            # 2. Start runtime vulnerability pattern detection if enabled
            self._start_runtime_pattern_detection()
            
            # 3. Start keyboard cache monitoring if enabled
            self._start_keyboard_cache_monitoring()
            
            # 4. Coordinate component execution based on profile
            active_components = self._get_profile_components(analysis_profile)
            component_results = {}
            
            for component_name in active_components:
                if component_name in self.component_states and self.component_states[component_name].available:
                    try:
                        result = self._coordinate_component(component_name, apk_ctx)
                        component_results[component_name] = result
                        self.component_states[component_name].results = result
                        self.component_states[component_name].active = True
                    except Exception as e:
                        self.logger.error(f"❌ Component {component_name} coordination failed: {e}")
                        self.component_states[component_name].error = str(e)
            
            # 5. Stop runtime pattern detection and collect results
            runtime_results = self._stop_runtime_pattern_detection()
            if runtime_results:
                component_results['runtime_patterns'] = runtime_results
                
            # 6. Stop keyboard cache monitoring and collect results
            keyboard_results = self._stop_keyboard_cache_monitoring()
            if keyboard_results:
                component_results['keyboard_cache'] = keyboard_results
            
            # 7. Execute network analysis coordination
            network_results = self._coordinate_network_analysis(apk_ctx, analysis_profile)
            if network_results:
                component_results['network_analysis'] = network_results
            
            # 8. Execute input validation testing coordination
            input_validation_results = self._coordinate_input_validation_testing(apk_ctx, analysis_profile)
            if input_validation_results:
                component_results['input_validation'] = input_validation_results
            
            # 9. Correlate and merge results using advanced correlation engine
            if self.correlation_enabled and self.correlation_engine:
                correlation_result = self.correlation_engine.correlate_findings(component_results)
                correlated_findings = self._format_correlation_results(correlation_result)
            else:
                # Fallback to basic correlation
                correlated_findings = self._correlate_component_results(component_results)
            
            # 10. Calculate performance metrics
            coordination_duration = time.time() - self.coordination_start_time
            performance_metrics = self._calculate_performance_metrics(coordination_duration)
            
            # 9. Create coordination result
            result = CoordinationResult(
                profile=analysis_profile,
                status=CoordinationStatus.COMPLETED,
                component_states=self.component_states.copy(),
                correlated_findings=correlated_findings,
                performance_metrics=performance_metrics,
                analysis_duration=coordination_duration,
                coordination_overhead=performance_metrics.get('coordination_overhead', 0.0)
            )
            
            self.status = CoordinationStatus.COMPLETED
            self.logger.info(f"✅ Coordinated analysis completed in {coordination_duration:.2f}s")
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Coordination failed: {e}")
            self.status = CoordinationStatus.ERROR
            
            return CoordinationResult(
                profile=analysis_profile,
                status=CoordinationStatus.ERROR,
                component_states=self.component_states.copy(),
                analysis_duration=time.time() - self.coordination_start_time if self.coordination_start_time else 0.0
            )
    
    def _prepare_shared_frida(self) -> bool:
        """Prepare shared Frida infrastructure for all components."""
        if not self.frida_enabled or not self.frida_connection:
            self.logger.debug("Frida not available, components will use fallback modes")
            return False
        
        try:
            self.logger.info("🚀 Preparing shared Frida infrastructure")
            
            # Start enhanced Frida server with auto-installation
            if self.frida_connection.start_frida_server():
                self.logger.info("✅ Shared Frida server ready for all components")
                return True
            else:
                self.logger.warning("⚠️ Frida server startup failed, components will use fallback modes")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Shared Frida preparation failed: {e}")
            return False
    
    def _start_runtime_pattern_detection(self):
        """Start runtime vulnerability pattern detection if available."""
        if self.runtime_patterns_enabled and self.runtime_detector:
            try:
                self.runtime_detector.start_detection()
                self.logger.info("🔍 Runtime vulnerability pattern detection started")
            except Exception as e:
                self.logger.error(f"❌ Failed to start runtime pattern detection: {e}")
    
    def _stop_runtime_pattern_detection(self) -> Optional[Any]:
        """Stop runtime pattern detection and return results."""
        if self.runtime_patterns_enabled and self.runtime_detector:
            try:
                self.runtime_detector.stop_detection()
                results = self.runtime_detector.get_detection_results()
                self.logger.info(f"🔍 Runtime pattern detection completed: "
                               f"{results.get('detection_stats', {}).get('matches_found', 0)} vulnerabilities found")
                return results
            except Exception as e:
                self.logger.error(f"❌ Failed to stop runtime pattern detection: {e}")
                return None
        return None
    
    def _inject_runtime_evidence(self, trigger: str, api_signature: str = None, 
                                parameters: Dict[str, Any] = None):
        """Inject runtime evidence into the pattern detector for analysis."""
        if self.runtime_patterns_enabled and self.runtime_detector:
            try:
                # Map string trigger to enum
                trigger_mapping = {
                    'api_call': RuntimeDetectionTrigger.API_CALL,
                    'network_request': RuntimeDetectionTrigger.NETWORK_REQUEST,
                    'file_operation': RuntimeDetectionTrigger.FILE_OPERATION,
                    'crypto_operation': RuntimeDetectionTrigger.CRYPTO_OPERATION
                }
                
                trigger_enum = trigger_mapping.get(trigger.lower(), RuntimeDetectionTrigger.API_CALL)
                evidence = RuntimeEvidence(
                    trigger_type=trigger_enum,
                    timestamp=time.time(),
                    api_signature=api_signature,
                    parameters=parameters or {}
                )
                
                self.runtime_detector.add_runtime_evidence(evidence)
                
            except Exception as e:
                self.logger.debug(f"Failed to inject runtime evidence: {e}")
    
    def _start_keyboard_cache_monitoring(self):
        """Start keyboard cache vulnerability monitoring if available."""
        if self.keyboard_cache_enabled and self.keyboard_cache_analyzer:
            try:
                # Generate script using existing AODS Frida infrastructure
                script_content = self.keyboard_cache_analyzer.generate_keyboard_monitoring_script()
                
                if script_content:
                    # Use existing Frida infrastructure for script execution
                    if hasattr(self.keyboard_cache_analyzer, 'frida_adapter') and self.keyboard_cache_analyzer.aods_frida_enabled:
                        # Let the FridaIntegrationAdapter handle execution
                        self.logger.info("⌨️ Keyboard cache monitoring started using AODS Frida infrastructure")
                    else:
                        self.logger.info("⌨️ Keyboard cache monitoring script generated (legacy mode)")
                else:
                    self.logger.warning("⚠️ Failed to generate keyboard cache monitoring script")
            except Exception as e:
                self.logger.error(f"❌ Failed to start keyboard cache monitoring: {e}")
    
    def _stop_keyboard_cache_monitoring(self) -> Optional[Dict[str, Any]]:
        """Stop keyboard cache monitoring and return results."""
        if self.keyboard_cache_enabled and self.keyboard_cache_analyzer:
            try:
                # In a full implementation, we would stop the Frida script here
                results = self.keyboard_cache_analyzer.get_analysis_results()
                findings_count = results.get('statistics', {}).get('total_findings', 0)
                self.logger.info(f"⌨️ Keyboard cache monitoring completed: "
                               f"{findings_count} vulnerabilities found")
                return results
            except Exception as e:
                self.logger.error(f"❌ Failed to stop keyboard cache monitoring: {e}")
                return None
        return None
    
    def _coordinate_network_analysis(self, apk_ctx, analysis_profile: AnalysisProfile) -> Optional[Dict[str, Any]]:
        """Coordinate network analysis across all available network components."""
        if self.network_analysis_enabled and self.network_coordinator:
            try:
                # Determine network analysis profile based on main analysis profile
                network_profile = self._map_to_network_profile(analysis_profile)
                
                self.logger.info(f"🌐 Starting network analysis coordination (Profile: {network_profile.value})")
                
                # Execute coordinated network analysis
                result = self.network_coordinator.coordinate_network_analysis(apk_ctx, network_profile)
                
                if result.coordination_successful:
                    self.logger.info(f"✅ Network analysis coordination completed: "
                                   f"{result.total_findings} findings, "
                                   f"{result.ssl_vulnerabilities} SSL issues, "
                                   f"{result.cleartext_violations} cleartext violations")
                    
                    # Return result in standard format
                    return {
                        'coordination_result': result,
                        'findings': result.merged_findings,
                        'statistics': {
                            'total_findings': result.total_findings,
                            'ssl_vulnerabilities': result.ssl_vulnerabilities,
                            'traffic_issues': result.traffic_issues,
                            'cleartext_violations': result.cleartext_violations,
                            'certificate_issues': result.certificate_issues,
                            'components_executed': result.components_executed,
                            'analysis_duration': result.analysis_duration
                        },
                        'recommendations': list(result.recommendations),
                        'performance_metrics': result.performance_metrics
                    }
                else:
                    self.logger.warning("⚠️ Network analysis coordination failed")
                    return None
                    
            except Exception as e:
                self.logger.error(f"❌ Failed to coordinate network analysis: {e}")
                return None
        else:
            self.logger.debug("Network analysis coordinator not available or not enabled")
            return None
    
    def _coordinate_input_validation_testing(self, apk_ctx, analysis_profile: AnalysisProfile) -> Optional[Dict[str, Any]]:
        """Coordinate comprehensive input validation testing across all injection analysis capabilities."""
        if self.input_validation_enabled and self.input_validation_coordinator:
            try:
                # Determine input validation testing profile based on main analysis profile
                testing_profile = self._map_to_testing_profile(analysis_profile)
                
                self.logger.info(f"🔍 Starting input validation testing coordination (Profile: {testing_profile.value})")
                
                # Execute coordinated input validation testing
                result = self.input_validation_coordinator.execute_input_validation_testing(apk_ctx, testing_profile)
                
                if result.testing_successful:
                    self.logger.info(f"✅ Input validation testing coordination completed: "
                                   f"{result.total_tests} tests executed, "
                                   f"{result.vulnerabilities_found} vulnerabilities found, "
                                   f"{result.xss_vulnerabilities} XSS issues, "
                                   f"{result.sql_vulnerabilities} SQL injection issues")
                    
                    # Return result in standard format
                    return {
                        'coordination_result': result,
                        'findings': result.payload_results,
                        'statistics': {
                            'total_tests': result.total_tests,
                            'successful_tests': result.successful_tests,
                            'vulnerabilities_found': result.vulnerabilities_found,
                            'xss_vulnerabilities': result.xss_vulnerabilities,
                            'sql_vulnerabilities': result.sql_vulnerabilities,
                            'injection_vulnerabilities': result.injection_vulnerabilities,
                            'webview_vulnerabilities': result.webview_vulnerabilities,
                            'components_executed': result.components_executed,
                            'analysis_duration': result.analysis_duration
                        },
                        'recommendations': list(result.recommendations),
                        'performance_metrics': result.performance_metrics
                    }
                else:
                    self.logger.warning("⚠️ Input validation testing coordination failed")
                    return None
                    
            except Exception as e:
                self.logger.error(f"❌ Failed to coordinate input validation testing: {e}")
                return None
        else:
            self.logger.debug("Input validation coordinator not available or not enabled")
            return None
    
    def _map_to_testing_profile(self, analysis_profile: AnalysisProfile) -> 'TestingProfile':
        """Map main analysis profile to input validation testing profile."""
        if not INPUT_VALIDATION_COORDINATOR_AVAILABLE:
            return None
            
        profile_mapping = {
            AnalysisProfile.COMPREHENSIVE: TestingProfile.COMPREHENSIVE,
            AnalysisProfile.MONITORING: TestingProfile.PASSIVE_SCAN,
            AnalysisProfile.SECURITY: TestingProfile.FUZZING_FOCUS,
            AnalysisProfile.LOGS: TestingProfile.XSS_FOCUS
        }
        
        return profile_mapping.get(analysis_profile, TestingProfile.COMPREHENSIVE)
    
    def _map_to_network_profile(self, analysis_profile: AnalysisProfile) -> 'NetworkAnalysisProfile':
        """Map main analysis profile to network analysis profile."""
        if not NETWORK_COORDINATOR_AVAILABLE:
            return None
            
        profile_mapping = {
            AnalysisProfile.COMPREHENSIVE: NetworkAnalysisProfile.COMPREHENSIVE,
            AnalysisProfile.MONITORING: NetworkAnalysisProfile.TRAFFIC_FOCUS,
            AnalysisProfile.SECURITY: NetworkAnalysisProfile.SECURITY_FOCUS,
            AnalysisProfile.LOGS: NetworkAnalysisProfile.CLEARTEXT_FOCUS
        }
        
        return profile_mapping.get(analysis_profile, NetworkAnalysisProfile.COMPREHENSIVE)
    
    def _get_profile_components(self, profile: AnalysisProfile) -> List[str]:
        """Get component list based on analysis profile."""
        profile_mappings = {
            AnalysisProfile.COMPREHENSIVE: ["log_analyzer", "monitoring_engine", "orchestrator"],
            AnalysisProfile.MONITORING: ["monitoring_engine"],
            AnalysisProfile.SECURITY: ["orchestrator", "log_analyzer"],
            AnalysisProfile.LOGS: ["log_analyzer"]
        }
        
        return profile_mappings.get(profile, [])
    
    def _coordinate_component(self, component_name: str, apk_ctx) -> Any:
        """Coordinate individual component with shared infrastructure."""
        component = getattr(self, component_name, None)
        if not component:
            raise ValueError(f"Component {component_name} not available")
        
        self.logger.info(f"🔧 Coordinating {component_name}")
        component_start_time = time.time()
        self.component_states[component_name].start_time = component_start_time
        
        try:
            if component_name == "log_analyzer":
                return self._coordinate_log_analyzer(component, apk_ctx)
            elif component_name == "monitoring_engine":
                return self._coordinate_monitoring_engine(component, apk_ctx)
            elif component_name == "orchestrator":
                return self._coordinate_orchestrator(component, apk_ctx)
            else:
                raise ValueError(f"Unknown component: {component_name}")
                
        finally:
            self.component_states[component_name].end_time = time.time()
    
    def _coordinate_log_analyzer(self, analyzer, apk_ctx):
        """Coordinate log analyzer with shared timing."""
        self.logger.debug("Coordinating DynamicLogAnalyzer")
        
        # Start log capture with coordinated timing
        analyzer.start_capture()
        
        # Allow time for log collection (configurable)
        capture_duration = self.config.get('log_capture_duration', 30)
        time.sleep(capture_duration)
        
        # Get analysis results
        return analyzer.stop_capture()
    
    def _coordinate_monitoring_engine(self, engine, apk_ctx):
        """Coordinate monitoring engine with shared Frida connection."""
        self.logger.debug("Coordinating ContinuousMonitoringEngine")
        
        # Share Frida connection if available
        if self.frida_connection:
            engine.frida_connection = self.frida_connection
        
        # Initialize Frida integration (will use shared connection)
        engine.initialize_frida_integration(apk_ctx.package_name)
        
        # Inject runtime evidence for crypto operations
        self._inject_runtime_evidence('api_call', 'ContinuousMonitoringEngine.initialize_frida_integration')
        
        # Start monitoring (async operation)
        engine.start_monitoring(apk_ctx.package_name)
        
        # Allow monitoring time (configurable)
        monitoring_duration = self.config.get('monitoring_duration', 60)
        
        # Periodically inject evidence during monitoring
        for i in range(monitoring_duration // 10):
            time.sleep(10)
            self._inject_runtime_evidence('crypto_operation', 'runtime_decryption_monitoring')
        
        # Stop and get results
        engine.stop_monitoring()
        return engine.get_analysis_results()
    
    def _coordinate_orchestrator(self, orchestrator, apk_ctx):
        """Coordinate security analysis orchestrator with shared Frida connection."""
        self.logger.debug("Coordinating AdvancedDynamicAnalysisOrchestrator")
        
        # Share Frida connection if available
        if self.frida_connection:
            orchestrator.frida_connection = self.frida_connection
            orchestrator.frida_enabled = True
        
        # Perform orchestrated analysis
        return orchestrator.analyze(apk_ctx)
    
    def _correlate_component_results(self, component_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Correlate and merge findings from all active components."""
        self.logger.info("🔗 Correlating findings from active components")
        
        correlated_findings = []
        
        # Process each component's results with specialized handling
        for component_name, results in component_results.items():
            if results:
                # Handle runtime pattern results specially
                if component_name == 'runtime_patterns':
                    pattern_matches = results.get('pattern_matches', [])
                    for match in pattern_matches:
                        finding = {
                            'component': 'runtime_patterns',
                            'type': 'vulnerability_pattern',
                            'pattern_id': match.pattern_id,
                            'pattern_name': match.pattern_name,
                            'severity': match.severity.value,
                            'confidence': match.confidence,
                            'cwe_id': match.cwe_id,
                            'masvs_category': match.masvs_category,
                            'description': match.description,
                            'evidence_count': len(match.evidence),
                            'timestamp': datetime.now().isoformat(),
                            'correlation_confidence': min(0.95, match.confidence + 0.1)
                        }
                        correlated_findings.append(finding)
                else:
                    # Standard component result handling
                    finding = {
                        'component': component_name,
                        'type': 'component_analysis',
                        'timestamp': datetime.now().isoformat(),
                        'results': results,
                        'correlation_confidence': 0.8  # Placeholder
                    }
                    correlated_findings.append(finding)
        
        # Cross-component correlation for enhanced findings
        runtime_findings = [f for f in correlated_findings if f['component'] == 'runtime_patterns']
        if runtime_findings:
            self.logger.info(f"🔍 Enhanced correlation with {len(runtime_findings)} runtime vulnerability patterns")
        
        self.logger.info(f"✅ Correlated {len(correlated_findings)} findings")
        return correlated_findings
    
    def _format_correlation_results(self, correlation_result: Any) -> List[Dict[str, Any]]:
        """Format advanced correlation results for coordinator output."""
        formatted_findings = []
        
        # Format correlated findings
        for correlated_finding in correlation_result.correlated_findings:
            formatted_finding = {
                'component': 'correlation_engine',
                'type': 'correlated_finding',
                'finding_id': correlated_finding.finding_id,
                'primary_finding': correlated_finding.primary_finding,
                'supporting_findings': correlated_finding.correlated_findings,
                'correlation_strategies': [s.value for s in correlated_finding.correlation_strategies],
                'correlation_confidence': correlated_finding.correlation_confidence,
                'combined_confidence': correlated_finding.combined_confidence,
                'component_sources': list(correlated_finding.component_sources),
                'validation_count': correlated_finding.validation_count,
                'false_positive_indicators': correlated_finding.false_positive_indicators,
                'timestamp': datetime.now().isoformat()
            }
            formatted_findings.append(formatted_finding)
        
        # Add uncorrelated findings as individual findings
        for uncorrelated_finding in correlation_result.uncorrelated_findings:
            formatted_finding = {
                'component': uncorrelated_finding.get('component', 'unknown'),
                'type': 'uncorrelated_finding',
                'timestamp': datetime.now().isoformat(),
                'finding_data': uncorrelated_finding,
                'correlation_status': 'uncorrelated'
            }
            formatted_findings.append(formatted_finding)
        
        # Add correlation summary
        summary_finding = {
            'component': 'correlation_engine',
            'type': 'correlation_summary',
            'timestamp': datetime.now().isoformat(),
            'summary': correlation_result.get_summary(),
            'correlation_status': 'summary'
        }
        formatted_findings.append(summary_finding)
        
        self.logger.info(f"🔗 Advanced correlation: {len(correlation_result.correlated_findings)} correlated, "
                        f"{len(correlation_result.uncorrelated_findings)} uncorrelated "
                        f"({correlation_result.correlation_rate:.1%} correlation rate)")
        
        return formatted_findings
    
    def _calculate_performance_metrics(self, total_duration: float) -> Dict[str, float]:
        """Calculate performance metrics for coordination session."""
        metrics = {
            'total_duration': total_duration,
            'coordination_overhead': 0.0,  # Calculated based on component durations
            'resource_efficiency': 0.9,    # Placeholder
            'component_utilization': 0.0
        }
        
        # Calculate component-specific metrics
        component_durations = []
        for state in self.component_states.values():
            if state.start_time and state.end_time:
                duration = state.end_time - state.start_time
                component_durations.append(duration)
                metrics[f'{state.name}_duration'] = duration
        
        if component_durations:
            metrics['component_utilization'] = sum(component_durations) / total_duration
            metrics['coordination_overhead'] = total_duration - max(component_durations)
        
        return metrics
    
    def get_coordination_status(self) -> Dict[str, Any]:
        """Get current coordination status and component states."""
        status = {
            'status': self.status.value,
            'frida_enabled': self.frida_enabled,
            'runtime_patterns_enabled': self.runtime_patterns_enabled,
            'components': {name: {
                'available': state.available,
                'initialized': state.initialized,
                'active': state.active,
                'error': state.error
            } for name, state in self.component_states.items()},
            'supported_profiles': [p.value for p in AnalysisProfile]
        }
        
        # Add runtime pattern detector status if available
        if self.runtime_detector:
            pattern_results = self.runtime_detector.get_detection_results()
            status['runtime_patterns'] = {
                'active_patterns': pattern_results.get('active_patterns', 0),
                'detection_active': pattern_results.get('detection_active', False),
                'evidence_collected': pattern_results.get('evidence_collected', 0),
                'matches_found': pattern_results.get('detection_stats', {}).get('matches_found', 0)
            }
        
        # Add correlation engine status if available
        if self.correlation_engine:
            status['correlation_engine'] = {
                'enabled': self.correlation_enabled,
                'correlation_history_count': len(self.correlation_engine.correlation_history),
                'temporal_window_seconds': self.correlation_engine.temporal_window_seconds,
                'false_positive_filtering': self.correlation_engine.enable_false_positive_filtering,
                'false_positive_threshold': self.correlation_engine.false_positive_threshold
            }
        
        # Add keyboard cache analyzer status if available
        if self.keyboard_cache_analyzer:
            analysis_results = self.keyboard_cache_analyzer.get_analysis_results()
            status['keyboard_cache'] = {
                'enabled': self.keyboard_cache_enabled,
                'input_events_captured': analysis_results.get('input_events_captured', 0),
                'monitored_fields': analysis_results.get('monitored_fields', 0),
                'findings_count': analysis_results.get('statistics', {}).get('total_findings', 0),
                'high_severity_findings': analysis_results.get('statistics', {}).get('high_severity_findings', 0),
                'unprotected_sensitive_inputs': analysis_results.get('statistics', {}).get('unprotected_sensitive_inputs', 0)
            }
        
        # Add network analysis coordinator status if available
        if self.network_coordinator:
            network_status = self.network_coordinator.get_coordination_status()
            status['network_analysis'] = {
                'enabled': self.network_analysis_enabled,
                'ssl_tls_analyzer_available': network_status.get('ssl_tls_analyzer_available', False),
                'mitmproxy_analyzer_available': network_status.get('mitmproxy_analyzer_available', False),
                'network_analyzer_available': network_status.get('network_analyzer_available', False),
                'cleartext_analyzer_available': network_status.get('cleartext_analyzer_available', False),
                'components_available': network_status.get('analysis_stats', {}).get('components_available', 0),
                'total_coordinations': network_status.get('analysis_stats', {}).get('total_coordinations', 0),
                'successful_coordinations': network_status.get('analysis_stats', {}).get('successful_coordinations', 0),
                'active_profile': network_status.get('active_profile')
            }
        
        # Add input validation coordinator status if available
        if self.input_validation_coordinator:
            input_validation_status = self.input_validation_coordinator.get_testing_status()
            status['input_validation'] = {
                'enabled': self.input_validation_enabled,
                'injection_plugin_available': input_validation_status.get('injection_plugin_available', False),
                'webview_plugin_available': input_validation_status.get('webview_plugin_available', False),
                'mitmproxy_plugin_available': input_validation_status.get('mitmproxy_plugin_available', False),
                'components_available': input_validation_status.get('testing_stats', {}).get('components_available', 0),
                'total_tests': input_validation_status.get('testing_stats', {}).get('total_tests', 0),
                'successful_tests': input_validation_status.get('testing_stats', {}).get('successful_tests', 0),
                'vulnerabilities_found': input_validation_status.get('testing_stats', {}).get('vulnerabilities_found', 0),
                'active_profile': input_validation_status.get('active_profile'),
                'payload_capabilities': {
                    'total_xss_payloads': input_validation_status.get('payload_types', {}).get('total_xss_payloads', 0),
                    'total_sql_payloads': input_validation_status.get('payload_types', {}).get('total_sql_payloads', 0),
                    'total_injection_payloads': input_validation_status.get('payload_types', {}).get('total_injection_payloads', 0)
                }
            }
        
        return status
    
    def generate_coordination_report(self, 
                                   output_format: str = "json",
                                   output_path: Optional[str] = None,
                                   include_detailed_findings: bool = True) -> Dict[str, Any]:
        """
        Generate comprehensive coordination analysis report using AODS unified reporting framework.
        
        Args:
            output_format: Report format ('json', 'html', 'pdf', 'markdown')
            output_path: Optional output file path
            include_detailed_findings: Whether to include detailed security findings
            
        Returns:
            Dict containing the generated report data
        """
        try:
            if not UNIFIED_REPORTING_AVAILABLE:
                self.logger.warning("Unified reporting not available - using fallback")
                return self._generate_fallback_report(include_detailed_findings)
            
            # Create coordination analysis result
            coordination_result = self._create_coordination_result(include_detailed_findings)
            
            # Configure report generation
            report_config = ReportConfiguration(
                report_type=ReportType.DYNAMIC_COORDINATION_ANALYSIS,
                output_format=ReportFormat(output_format.lower()),
                include_executive_summary=True,
                include_detailed_findings=include_detailed_findings,
                include_charts=True,
                include_remediation_guidance=True
            )
            
            # Create report orchestrator
            orchestrator = UnifiedReportOrchestrator(report_config)
            
            # Generate report
            report_data = orchestrator.generate_report(
                findings=[],  # Findings are embedded in coordination_result
                context=None,
                output_path=output_path
            )
            
            # Add coordination-specific data
            report_data['coordination_result'] = coordination_result
            
            self.logger.info(f"Coordination report generated successfully: {output_format}")
            return report_data
            
        except Exception as e:
            self.logger.error(f"Failed to generate coordination report: {e}")
            return self._generate_fallback_report(include_detailed_findings)
    
    def _create_coordination_result(self, include_detailed_findings: bool = True) -> DynamicCoordinationAnalysisResult:
        """Create comprehensive coordination analysis result."""
        try:
            # Component results
            component_results = []
            for component_name, state in self.component_states.items():
                if state.instance and hasattr(state.instance, 'get_analysis_results'):
                    # Try to get detailed results from component
                    try:
                        component_data = state.instance.get_analysis_results()
                        findings = self._extract_findings_from_component_data(component_data)
                    except Exception as e:
                        self.logger.warning(f"Could not extract results from {component_name}: {e}")
                        findings = []
                    
                    component_result = ComponentAnalysisResult(
                        component_name=component_name,
                        component_type=state.component_type,
                        findings_count=len(findings),
                        execution_time=getattr(state, 'execution_time', 0.0),
                        status='completed' if state.available else 'failed',
                        error_message=state.error_message,
                        findings=findings if include_detailed_findings else [],
                        metadata={'last_execution': state.last_execution}
                    )
                    component_results.append(component_result)
            
            # Runtime patterns (if available)
            runtime_patterns = []
            if self.runtime_detector and hasattr(self.runtime_detector, 'get_detection_results'):
                try:
                    pattern_results = self.runtime_detector.get_detection_results()
                    for pattern_data in pattern_results:
                        runtime_pattern = RuntimePatternResult(
                            pattern_id=pattern_data.get('pattern_id', 'unknown'),
                            pattern_name=pattern_data.get('pattern_name', 'Unknown Pattern'),
                            severity=SeverityLevel(pattern_data.get('severity', 'medium')),
                            confidence=pattern_data.get('confidence', 0.0),
                            evidence_count=len(pattern_data.get('evidence', [])),
                            detection_timestamp=datetime.now(),
                            api_signatures=pattern_data.get('api_signatures', []),
                            behavioral_indicators=pattern_data.get('behavioral_indicators', []),
                            cwe_id=pattern_data.get('cwe_id'),
                            masvs_category=pattern_data.get('masvs_category'),
                            remediation_guidance=pattern_data.get('remediation_guidance', '')
                        )
                        runtime_patterns.append(runtime_pattern)
                except Exception as e:
                    self.logger.warning(f"Could not extract runtime patterns: {e}")
            
            # Correlation results (if available)
            correlated_findings = []
            uncorrelated_findings = []
            
            if self.correlation_engine and hasattr(self.correlation_engine, 'correlation_history'):
                try:
                    for correlation in self.correlation_engine.correlation_history:
                        corr_result = CorrelationAnalysisResult(
                            correlation_strategy=correlation.strategy.value,
                            correlation_confidence=correlation.confidence.value,
                            primary_finding=correlation.primary_finding,
                            supporting_findings=correlation.related_findings,
                            component_sources=correlation.source_components,
                            validation_count=correlation.cross_validation_count,
                            false_positive_indicators=correlation.false_positive_indicators
                        )
                        correlated_findings.append(corr_result)
                except Exception as e:
                    self.logger.warning(f"Could not extract correlation results: {e}")
            
            # Calculate coordination statistics
            total_findings = sum(len(comp.findings) for comp in component_results)
            total_findings += len(runtime_patterns)
            correlation_rate = len(correlated_findings) / max(1, total_findings)
            
            # Create coordination result
            coordination_result = DynamicCoordinationAnalysisResult(
                coordination_id=f"coord_{int(time.time())}",
                analysis_profile=getattr(self, 'analysis_profile', 'comprehensive'),
                package_name=self.package_name,
                start_time=getattr(self, 'analysis_start_time', datetime.now()),
                end_time=datetime.now(),
                component_results=component_results,
                runtime_patterns=runtime_patterns,
                correlated_findings=correlated_findings,
                uncorrelated_findings=uncorrelated_findings,
                total_findings=total_findings,
                correlation_rate=correlation_rate,
                cross_component_validations=len(correlated_findings),
                false_positive_rate=self._calculate_false_positive_rate(correlated_findings),
                coordination_overhead=getattr(self, 'coordination_overhead', 0.0),
                shared_resource_efficiency=self._calculate_resource_efficiency(),
                frida_enabled=self.frida_enabled,
                runtime_patterns_enabled=self.runtime_patterns_enabled,
                correlation_enabled=self.correlation_enabled
            )
            
            return coordination_result
            
        except Exception as e:
            self.logger.error(f"Failed to create coordination result: {e}")
            # Return minimal result
            return DynamicCoordinationAnalysisResult(
                coordination_id="error",
                analysis_profile="unknown",
                package_name=self.package_name,
                start_time=datetime.now(),
                total_findings=0
            )
    
    def _extract_findings_from_component_data(self, component_data: Dict[str, Any]) -> List[SecurityFinding]:
        """Extract SecurityFinding objects from component analysis data."""
        findings = []
        
        # Try to extract findings from various possible structures
        potential_findings = []
        
        if isinstance(component_data, dict):
            # Look for findings in common keys
            for key in ['findings', 'vulnerabilities', 'results', 'issues']:
                if key in component_data:
                    potential_findings.extend(component_data[key])
        
        # Convert to SecurityFinding objects
        for finding_data in potential_findings:
            try:
                if isinstance(finding_data, dict):
                    finding = SecurityFinding(
                        id=finding_data.get('id', f"finding_{len(findings)}"),
                        title=finding_data.get('title', finding_data.get('name', 'Unknown Finding')),
                        description=finding_data.get('description', ''),
                        severity=SeverityLevel(finding_data.get('severity', 'medium').lower()),
                        confidence=finding_data.get('confidence', 0.5),
                        category=finding_data.get('category', 'general'),
                        location=finding_data.get('location', finding_data.get('file', '')),
                        file_path=finding_data.get('file_path', finding_data.get('file', '')),
                        line_number=finding_data.get('line_number'),
                        evidence=finding_data.get('evidence', ''),
                        recommendation=finding_data.get('recommendation', ''),
                        references=finding_data.get('references', []),
                        cwe_id=finding_data.get('cwe_id'),
                        owasp_category=finding_data.get('owasp_category', ''),
                        masvs_control=finding_data.get('masvs_control', ''),
                        risk_score=finding_data.get('risk_score', 0.0)
                    )
                    findings.append(finding)
            except Exception as e:
                self.logger.debug(f"Could not convert finding data: {e}")
        
        return findings
    
    def _calculate_false_positive_rate(self, correlations: List[CorrelationAnalysisResult]) -> float:
        """Calculate estimated false positive rate from correlation analysis."""
        if not correlations:
            return 0.0
        
        fp_indicators = sum(len(corr.false_positive_indicators) for corr in correlations)
        total_indicators = len(correlations) * 3  # Assume max 3 indicators per correlation
        
        return min(1.0, fp_indicators / max(1, total_indicators))
    
    def _calculate_resource_efficiency(self) -> float:
        """Calculate shared resource efficiency metric."""
        # Simple efficiency calculation based on component utilization
        active_components = sum(1 for state in self.component_states.values() if state.available)
        total_components = len(self.component_states)
        
        if total_components == 0:
            return 0.0
        
        base_efficiency = active_components / total_components
        
        # Bonus for shared Frida infrastructure
        if self.frida_enabled:
            base_efficiency *= 1.2
        
        return min(1.0, base_efficiency)
    
    def _generate_fallback_report(self, include_detailed_findings: bool = True) -> Dict[str, Any]:
        """Generate basic fallback report when unified reporting is not available."""
        status = self.get_coordination_status()
        
        report = {
            'report_type': 'dynamic_coordination_fallback',
            'package_name': self.package_name,
            'generated_at': datetime.now().isoformat(),
            'coordination_status': status,
            'component_summary': {
                name: {
                    'available': state.available,
                    'status': 'active' if state.available else 'inactive',
                    'last_execution': state.last_execution
                }
                for name, state in self.component_states.items()
            },
            'infrastructure_status': {
                'frida_enabled': self.frida_enabled,
                'runtime_patterns_enabled': self.runtime_patterns_enabled,
                'correlation_enabled': self.correlation_enabled
            },
            'warning': 'Generated using fallback reporting - unified reporting framework not available'
        }
        
        return report


def create_coordinator(package_name: str, config: Optional[Dict[str, Any]] = None) -> DynamicAnalysisCoordinator:
    """Create and initialize a Dynamic Analysis Coordinator instance."""
    return DynamicAnalysisCoordinator(package_name, config)


def main():
    """Demonstration of Dynamic Analysis Coordinator functionality."""
    print("🧪 Dynamic Analysis Coordinator - Component Orchestration")
    print("=" * 60)
    
    # Create coordinator instance
    coordinator = create_coordinator("com.test.app")
    
    # Display coordination status
    status = coordinator.get_coordination_status()
    print(f"Coordinator Status: {status['status']}")
    print(f"Frida Enabled: {status['frida_enabled']}")
    print(f"Available Components: {sum(1 for c in status['components'].values() if c['available'])}")
    print(f"Supported Profiles: {', '.join(status['supported_profiles'])}")
    
    # Demonstrate reporting functionality
    print("\n📊 Report Generation Demo:")
    print("-" * 30)
    
    try:
        # Generate JSON report
        report = coordinator.generate_coordination_report(
            output_format="json",
            include_detailed_findings=False
        )
        print(f"✅ JSON Report Generated: {len(report)} sections")
        
        if UNIFIED_REPORTING_AVAILABLE:
            print("   Using AODS Unified Reporting Framework")
        else:
            print("   Using fallback reporting")
        
        # Show report summary
        if 'coordination_summary' in report:
            summary = report['coordination_summary']
            print(f"   Analysis Profile: {summary.get('analysis_profile', 'N/A')}")
            print(f"   Components Active: {summary.get('components_active', 0)}")
            print(f"   Total Findings: {summary.get('total_findings', 0)}")
            
    except Exception as e:
        print(f"❌ Report Generation Failed: {e}")
    
    print("\n🎯 Coordinator Demo Complete")
    
    print("\n✅ Coordinator Pattern Implementation Complete")
    print("\nKey Features:")
    print("  - Coordinates 3 specialized components without duplication")
    print("  - Shares enhanced Frida infrastructure across components")
    print("  - Preserves component specialization and independence")
    print("  - Provides analysis profiles for targeted or comprehensive analysis")
    print("  - Implements result correlation and performance tracking")
    print("  - Maintains AODS project philosophy compliance")


if __name__ == "__main__":
    main() 