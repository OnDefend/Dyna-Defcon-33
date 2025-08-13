
#!/usr/bin/env python3
"""
Enhanced Frida Dynamic Analyzer - Main Orchestration Module

Central orchestration module that coordinates specialized security analyzers
for comprehensive dynamic analysis with improved modularity and maintainability.

This module serves as the main entry point for Frida-based dynamic analysis,
orchestrating SSL/TLS analysis, WebView security testing, and anti-tampering analysis
through dependency injection and professional confidence calculation.

Features:
- Modular orchestration of specialized analyzers
- Professional confidence calculation integration
- Parallel and sequential analysis execution
- Comprehensive error handling and logging
- Rich text reporting and vulnerability aggregation
- Performance optimization through caching
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeoutError
from typing import Dict, List, Tuple, Union, Optional, Any
from dataclasses import dataclass
from pathlib import Path

from rich.text import Text
from rich.console import Console

# Import APKContext for type annotations
try:
    from core.apk_ctx import APKContext
except ImportError:
    # Use Any as fallback for type annotation when APKContext is not available
    APKContext = Any

# Remove the problematic import and use UniversalConfidenceCalculator instead
# from core.shared_confidence.plugin_confidence_calculators import DynamicAnalysisConfidenceCalculator

# Initialize logger early to use in import error handling
logger = logging.getLogger(__name__)

try:
    from core.shared_analyzers.universal_confidence_calculator import (
        UniversalConfidenceCalculator, ConfidenceEvidence, PatternReliability,
        ConfidenceConfiguration, ConfidenceFactorType
    )
    CONFIDENCE_COMPONENTS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Confidence components not available: {e}")
    CONFIDENCE_COMPONENTS_AVAILABLE = False

# Import Universal Device Profile Library for enhanced anti-analysis capabilities
try:
    from core.security_testing.universal_device_profile_library import (
        universal_device_library, get_universal_device_profile, 
        get_universal_spoofing_script, UniversalDeviceProfile, DeviceCategory
    )
    UNIVERSAL_DEVICE_PROFILES_AVAILABLE = True
    logger.info("✅ Universal Device Profile Library integrated")
except ImportError as e:
    logger.warning(f"Universal Device Profile Library not available: {e}")
    UNIVERSAL_DEVICE_PROFILES_AVAILABLE = False
    
    # Create safe fallback classes that mimic the expected interface
    class FallbackPatternReliability:
        def __init__(self, pattern_id=None, pattern_name=None, **kwargs):
            self.pattern_id = pattern_id or "unknown"
            self.pattern_name = pattern_name or "Unknown Pattern"
            self.total_validations = kwargs.get('total_validations', 0)
            self.correct_predictions = kwargs.get('correct_predictions', 0)
            self.false_positive_rate = kwargs.get('false_positive_rate', 0.0)
            self.false_negative_rate = kwargs.get('false_negative_rate', 0.0)
            self.confidence_adjustment = kwargs.get('confidence_adjustment', 0.0)
            self.last_updated = kwargs.get('last_updated', '2024-01-01')
    
    class FallbackUniversalConfidenceCalculator:
        def __init__(self):
            pass
        
        def calculate_confidence(self, *args, **kwargs):
            return 0.5  # Default confidence
    
    # Use fallback implementations
    UniversalConfidenceCalculator = FallbackUniversalConfidenceCalculator
    ConfidenceEvidence = dict
    PatternReliability = FallbackPatternReliability
    ConfidenceConfiguration = dict
    ConfidenceFactorType = str

from .data_structures import (
    DetailedVulnerability, FridaAnalysisConfig, AnalysisMetadata,
    VulnerabilityLocation, VulnerabilityEvidence, RemediationGuidance,
    create_detailed_vulnerability
)
from .constants import MASVS_MAPPINGS, SECURITY_RECOMMENDATIONS
from .subprocess_handler import SubprocessHandler
from .ssl_analyzer import SSLSecurityAnalyzer, SSLTestConfiguration
from .webview_analyzer import WebViewSecurityAnalyzer, WebViewTestConfiguration
from .webview_exploitation_module import WebViewExploitationModule, WebViewExploitationConfig
from .dynamic_execution_module import DynamicExecutionModule, DynamicExecutionConfig
from .anti_tampering_analyzer import AntiTamperingAnalyzer, AntiTamperingTestConfiguration
from .icc_analyzer import ICCSecurityAnalyzer, ICCTestConfiguration

# Import the new Runtime Hook Engine for true dynamic analysis
try:
    from .runtime_hooks import RuntimeHookEngine, RuntimeHookResult, HookStatus
    RUNTIME_HOOKS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Runtime hooks not available: {e}")
    RUNTIME_HOOKS_AVAILABLE = False


class FridaDynamicConfidenceCalculator(UniversalConfidenceCalculator):
    """
    Professional confidence calculation system for Frida dynamic analysis.
    """
    
    def __init__(self):
        """Initialize confidence calculator with Frida-specific pattern reliabilities."""
        if CONFIDENCE_COMPONENTS_AVAILABLE:
            # Create a basic config for UniversalConfidenceCalculator with required parameters
            try:
                basic_config = ConfidenceConfiguration(
                    plugin_type="frida_dynamic",
                    evidence_weights={},
                    context_factors={},
                    reliability_database={}
                )
                super().__init__(basic_config)
            except Exception:
                # If ConfidenceConfiguration creation fails, just skip the super init
                pass
        
        # Define Frida-specific pattern reliabilities
        self.pattern_reliabilities = {
            'ssl_bypass_testing': PatternReliability(
                pattern_id='ssl_bypass_testing',
                pattern_name='SSL Bypass Testing',
                total_validations=100,
                correct_predictions=92,
                false_positive_rate=0.08,
                false_negative_rate=0.06,
                confidence_adjustment=0.0,
                last_updated='2024-01-01'
            ),
            'webview_security_testing': PatternReliability(
                pattern_id='webview_security_testing',
                pattern_name='WebView Security Testing',
                total_validations=100,
                correct_predictions=88,
                false_positive_rate=0.12,
                false_negative_rate=0.10,
                confidence_adjustment=0.0,
                last_updated='2024-01-01'
            ),
            'anti_tampering_testing': PatternReliability(
                pattern_id='anti_tampering_testing',
                pattern_name='Anti-Tampering Testing',
                total_validations=100,
                correct_predictions=85,
                false_positive_rate=0.15,
                false_negative_rate=0.12,
                confidence_adjustment=0.0,
                last_updated='2024-01-01'
            ),
            'runtime_manipulation': PatternReliability(
                pattern_id='runtime_manipulation',
                pattern_name='Runtime Manipulation',
                total_validations=100,
                correct_predictions=90,
                false_positive_rate=0.10,
                false_negative_rate=0.08,
                confidence_adjustment=0.0,
                last_updated='2024-01-01'
            ),
            'frida_instrumentation': PatternReliability(
                pattern_id='frida_instrumentation',
                pattern_name='Frida Instrumentation',
                total_validations=100,
                correct_predictions=87,
                false_positive_rate=0.13,
                false_negative_rate=0.11,
                confidence_adjustment=0.0,
                last_updated='2024-01-01'
            )
        }
    
    def calculate_confidence(self, *args, **kwargs):
        """Calculate confidence with fallback for missing components."""
        if CONFIDENCE_COMPONENTS_AVAILABLE:
            return super().calculate_confidence(*args, **kwargs)
        else:
            # Simple fallback calculation
            return 0.7  # Default confidence for Frida analysis
    
    def calculate_dynamic_confidence(self, analysis_type: str, evidence: Dict[str, Any],
                                   validation_methods: List[str] = None) -> float:
        """
        Calculate professional confidence for dynamic analysis findings.
        
        Args:
            analysis_type: Type of dynamic analysis performed
            evidence: Evidence supporting the finding
            validation_methods: List of validation methods used
            
        Returns:
            Dynamic confidence score (0.0-1.0)
        """
        try:
            # Get base evidence
            evidence_data = {
                'runtime_reliability': self._assess_runtime_reliability(analysis_type, evidence),
                'instrumentation_quality': self._assess_instrumentation_quality(evidence),
                'validation_coverage': self._assess_validation_coverage(validation_methods or []),
                'environment_context': self._assess_environment_context(evidence),
                'cross_validation': self._assess_cross_validation(evidence)
            }
            
            # Calculate weighted confidence
            confidence = self._calculate_weighted_confidence(evidence_data)
            
            # Apply dynamic analysis specific adjustments
            confidence = self._apply_dynamic_adjustments(confidence, analysis_type, evidence)
            
            # Ensure confidence is in valid range
            confidence = max(0.1, min(1.0, confidence))
            
            return confidence
            
        except Exception as e:
            logging.error(f"Error calculating dynamic analysis confidence: {e}")
            return 0.5  # Conservative fallback
    
    def _assess_runtime_reliability(self, analysis_type: str, evidence: Dict[str, Any]) -> float:
        """Assess the reliability of runtime analysis."""
        if analysis_type in self.pattern_reliabilities:
            return self.pattern_reliabilities[analysis_type].confidence_score
        return 0.8  # Default reliability for unknown analysis types
    
    def _assess_instrumentation_quality(self, evidence: Dict[str, Any]) -> float:
        """Assess the quality of Frida instrumentation."""
        instrumentation_success = evidence.get('instrumentation_success', True)
        hook_effectiveness = evidence.get('hook_effectiveness', 'medium')
        script_errors = evidence.get('script_errors', 0)
        
        # Base score from instrumentation success
        base_score = 1.0 if instrumentation_success else 0.3
        
        # Adjust based on hook effectiveness
        effectiveness_factors = {'high': 1.0, 'medium': 0.8, 'low': 0.6, 'failed': 0.2}
        effectiveness_factor = effectiveness_factors.get(hook_effectiveness, 0.8)
        
        # Penalty for script errors
        error_penalty = min(script_errors * 0.1, 0.4)  # Max 40% penalty
        
        quality_score = base_score * effectiveness_factor - error_penalty
        return max(0.2, min(1.0, quality_score))
    
    def _assess_validation_coverage(self, validation_methods: List[str]) -> float:
        """Assess validation coverage from multiple methods."""
        if not validation_methods:
            return 0.5
        
        # More validation methods increase confidence
        method_count = len(validation_methods)
        if method_count >= 3:
            return 1.0
        elif method_count == 2:
            return 0.8
        elif method_count == 1:
            return 0.6
        else:
            return 0.5
    
    def _assess_environment_context(self, evidence: Dict[str, Any]) -> float:
        """Assess runtime environment context."""
        environment_type = evidence.get('environment_type', 'runtime_analysis')
        return 0.8 # Default context factor
    
    def _assess_cross_validation(self, evidence: Dict[str, Any]) -> float:
        """Assess cross-validation evidence."""
        static_validation = evidence.get('static_validation', False)
        manual_validation = evidence.get('manual_validation', False)
        automated_validation = evidence.get('automated_validation', False)
        
        validation_count = sum([static_validation, manual_validation, automated_validation])
        
        if validation_count >= 2:
            return 1.0
        elif validation_count == 1:
            return 0.7
        else:
            return 0.5
    
    def _apply_dynamic_adjustments(self, confidence: float, analysis_type: str, evidence: Dict[str, Any]) -> float:
        """Apply dynamic analysis specific confidence adjustments."""
        # High-confidence analysis types
        if analysis_type in ['ssl_bypass_testing', 'runtime_manipulation']:
            confidence *= 1.05
        
        # Medium-confidence analysis types
        elif analysis_type in ['webview_security_testing', 'dynamic_validation']:
            confidence *= 1.0
        
        # Lower-confidence analysis types
        elif analysis_type in ['anti_tampering_testing', 'simulation_testing']:
            confidence *= 0.95
        
        # Runtime environment bonus
        if evidence.get('environment_type') == 'runtime_analysis':
            confidence *= 1.02
        
        return confidence


@dataclass
class EnhancedAnalysisConfiguration:
    """Configuration for enhanced Frida dynamic analysis."""
    
    # Analysis scope configuration
    enable_ssl_analysis: bool = True
    enable_webview_analysis: bool = True
    enable_anti_tampering_analysis: bool = True
    
    # Execution configuration
    enable_parallel_analysis: bool = True
    analysis_timeout: int = 300  # 5 minutes
    max_workers: int = 3
    
    # SSL analysis configuration
    ssl_config: Optional[SSLTestConfiguration] = None
    
    # WebView analysis configuration
    webview_config: Optional[WebViewTestConfiguration] = None
    webview_exploitation_config: Optional[WebViewExploitationConfig] = None
    
    # Dynamic execution analysis configuration
    dynamic_execution_config: Optional[DynamicExecutionConfig] = None
    
    # Anti-tampering analysis configuration
    anti_tampering_config: Optional[AntiTamperingTestConfiguration] = None
    
    # Reporting configuration
    enable_detailed_reporting: bool = True
    
    # Professional confidence threshold - now calculated dynamically
    def get_confidence_threshold(self, confidence_calculator: FridaDynamicConfidenceCalculator) -> float:
        """Get dynamic confidence threshold based on analysis context."""
        try:
            # Calculate dynamic threshold based on analysis configuration
            evidence = {
                'environment_type': 'runtime_analysis',
                'instrumentation_success': True,
                'validation_methods': ['frida_instrumentation', 'runtime_validation']
            }
            
            # Use 70% of calculated confidence as threshold
            base_confidence = confidence_calculator.calculate_dynamic_confidence(
                'dynamic_validation', evidence, ['frida_instrumentation']
            )
            return base_confidence * 0.7
            
        except Exception:
            return 0.3  # Conservative fallback
    
    def __post_init__(self):
        """Initialize default configurations if not provided."""
        if self.ssl_config is None:
            self.ssl_config = SSLTestConfiguration()
        if self.webview_config is None:
            self.webview_config = WebViewTestConfiguration()
        
        if self.webview_exploitation_config is None:
            self.webview_exploitation_config = WebViewExploitationConfig()
        
        if self.dynamic_execution_config is None:
            self.dynamic_execution_config = DynamicExecutionConfig()
        if self.anti_tampering_config is None:
            self.anti_tampering_config = AntiTamperingTestConfiguration()


class EnhancedFridaDynamicAnalyzer:
    """
    Enhanced Frida Dynamic Analyzer with modular architecture.
    
    Orchestrates specialized security analyzers for comprehensive dynamic analysis
    of Android applications using Frida instrumentation framework.
    """
    
    def __init__(self, package_name: str, config: Optional[EnhancedAnalysisConfiguration] = None):
        """Initialize the enhanced Frida dynamic analyzer."""
        self.package_name = package_name
        self.config = config or EnhancedAnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
        self.console = Console()
        
        # Initialize professional confidence calculator
        self.confidence_calculator = FridaDynamicConfidenceCalculator()
        
        # Initialize analysis metadata
        import uuid
        self.analysis_metadata = AnalysisMetadata(
            analysis_id=str(uuid.uuid4()),
            package_name=self.package_name,
            start_time=time.time()
        )
        self.detailed_vulnerabilities: List[DetailedVulnerability] = []
        
        # Initialize specialized analyzers
        self._initialize_analyzers()
        
        # Initialize subprocess handler
        self.subprocess_handler = SubprocessHandler()
        
        # Analysis state
        self.analysis_start_time = None
        self.analysis_complete = False
    
    def _initialize_analyzers(self):
        """Initialize specialized security analyzers with professional confidence integration."""
        try:
            # Initialize SSL analyzer with confidence calculator
            if self.config.enable_ssl_analysis:
                self.ssl_analyzer = SSLSecurityAnalyzer(
                    confidence_calculator=self.confidence_calculator,
                    config=self.config.ssl_config
                )
            else:
                self.ssl_analyzer = None
                
            # Initialize WebView analyzer with confidence calculator
            if self.config.enable_webview_analysis:
                self.webview_analyzer = WebViewSecurityAnalyzer(
                    confidence_calculator=self.confidence_calculator,
                    config=self.config.webview_config
                )
            else:
                self.webview_analyzer = None
                
            # Initialize anti-tampering analyzer with confidence calculator
            if self.config.enable_anti_tampering_analysis:
                self.anti_tampering_analyzer = AntiTamperingAnalyzer(
                    confidence_calculator=self.confidence_calculator,
                    config=self.config.anti_tampering_config
                )
            else:
                self.anti_tampering_analyzer = None
                
            # Initialize ICC analyzer with configuration
            if getattr(self.config, 'enable_icc_analysis', True):
                self.icc_analyzer = ICCSecurityAnalyzer(
                    config=getattr(self.config, 'icc_config', ICCTestConfiguration())
                )
            else:
                self.icc_analyzer = None
                
            # Initialize WebView exploitation module with configuration
            if getattr(self.config, 'enable_webview_exploitation', True):
                self.webview_exploitation_module = WebViewExploitationModule(
                    config=getattr(self.config, 'webview_exploitation_config', WebViewExploitationConfig())
                )
            else:
                self.webview_exploitation_module = None
                
            # Initialize Dynamic execution module with configuration
            if getattr(self.config, 'enable_dynamic_execution', True):
                self.dynamic_execution_module = DynamicExecutionModule(
                    config=getattr(self.config, 'dynamic_execution_config', DynamicExecutionConfig())
                )
            else:
                self.dynamic_execution_module = None
                
        except Exception as e:
            self.logger.error(f"Failed to initialize analyzers: {e}", exc_info=True)
            raise
    
    def analyze(self, apk_ctx=None) -> Dict[str, Any]:
        """
        Main analysis entry point with proper dynamic analysis integration.
        
        Args:
            apk_ctx: Optional APK context for enhanced analysis
        
        Returns:
            Dict containing analysis results
        """
        try:
            self.logger.info(f"Starting Frida analysis for {self.package_name}")
            
            # If APK context is provided, perform full dynamic analysis
            if apk_ctx is not None:
                try:
                    # Perform comprehensive dynamic security analysis
                    vulnerabilities = self.analyze_dynamic_security(apk_ctx)
                    
                    # Format results with full vulnerability details
                    return {
                        'vulnerabilities': [vuln.__dict__ for vuln in vulnerabilities],
                        'total_vulnerabilities': len(vulnerabilities),
                        'analysis_metadata': self.analysis_metadata.__dict__ if self.analysis_metadata else {},
                        'analysis_type': 'full_dynamic',
                        'package_name': self.package_name
                    }
                except Exception as e:
                    self.logger.warning(f"Full dynamic analysis failed, falling back to basic analysis: {e}")
                    # Fall through to basic analysis
            
            # Basic analysis without full APK context (fallback mode)
            self.logger.info("Performing basic Frida analysis without full APK context")
            
            # Perform basic environment checks and minimal analysis
            basic_vulnerabilities = []
            
            try:
                # At minimum, check if Frida can connect
                if self._validate_basic_frida_connection():
                    # Create a basic finding to show Frida is working
                    from .data_structures import DetailedVulnerability
                    basic_vuln = DetailedVulnerability(
                        title="Frida Connection Successful",
                        description="Frida successfully connected to target environment",
                        severity="INFO",
                        confidence=1.0,
                        file_path="runtime",
                        line_number=0,
                        vulnerable_code="",
                        remediation="No action required - informational finding",
                        cwe_id="CWE-200",
                        owasp_category="M10"
                    )
                    basic_vulnerabilities.append(basic_vuln)
                    
            except Exception as e:
                self.logger.error(f"Basic Frida connection failed: {e}")
            
            # Format basic results
            return {
                'vulnerabilities': [vuln.__dict__ for vuln in basic_vulnerabilities],
                'total_vulnerabilities': len(basic_vulnerabilities),
                'analysis_metadata': self.analysis_metadata.__dict__ if self.analysis_metadata else {},
                'analysis_type': 'basic_fallback',
                'package_name': self.package_name
            }
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return {
                'error': str(e),
                'vulnerabilities': [],
                'total_vulnerabilities': 0,
                'analysis_type': 'error',
                'package_name': self.package_name
            }
    
    def analyze_dynamic_security(self, apk_ctx) -> List[DetailedVulnerability]:
        """
        Perform comprehensive dynamic security analysis.
        
        Args:
            apk_ctx: APK analysis context
            
        Returns:
            List of detected vulnerabilities
        """
        try:
            self.analysis_start_time = time.time()
            self.logger.info(f"Starting enhanced Frida dynamic analysis for {self.package_name}")
            
            # Validate environment
            environment_ready = self._validate_environment()
            if not environment_ready:
                self.logger.warning("⚠️ Frida environment validation failed, switching to fallback analysis mode")
                return self._perform_fallback_analysis(apk_ctx)
            
            # Perform full security analysis with connected devices
            self.logger.info("✅ Environment ready - performing full dynamic security analysis")
            
            # Execute runtime hook analysis for true dynamic vulnerability detection
            self._execute_runtime_hook_analysis(apk_ctx)
            
            if self.config.enable_parallel_analysis and self._should_use_parallel_execution():
                self._perform_parallel_security_analysis(apk_ctx)
            else:
                self._perform_sequential_security_analysis(apk_ctx)
            
            # Post-process results
            self._post_process_analysis_results()
            
            # Finalize analysis metadata
            self._finalize_analysis_metadata()
            
            self.analysis_complete = True
            self.logger.info(f"Enhanced Frida analysis completed. Found {len(self.detailed_vulnerabilities)} vulnerabilities.")
            
            return self.detailed_vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Enhanced Frida analysis failed: {e}", exc_info=True)
            return self.detailed_vulnerabilities  # Return partial results
    
    def _validate_environment(self) -> bool:
        """
        Validate Frida environment and requirements with comprehensive device detection.
        
        Returns:
            bool: True if environment is ready for dynamic analysis, False otherwise
        """
        try:
            self.logger.info("🔍 Validating Frida dynamic analysis environment...")
            
            validation_results = {
                'frida_installed': False,
                'adb_available': False,
                'devices_connected': False,
                'frida_server_running': False,
                'apk_installed': False
            }
            
            # Check 1: Frida installation
            validation_results['frida_installed'] = self._check_frida_installation()
            if not validation_results['frida_installed']:
                self.logger.warning("❌ Frida is not installed or not accessible")
                self._provide_frida_installation_guidance()
                return False
            
            # Check 2: ADB availability
            validation_results['adb_available'] = self._check_adb_availability()
            if not validation_results['adb_available']:
                self.logger.warning("❌ ADB is not available or not in PATH")
                self._provide_adb_setup_guidance()
                return False
            
            # Check 3: Connected devices
            validation_results['devices_connected'] = self._check_device_connectivity()
            if not validation_results['devices_connected']:
                self.logger.warning("❌ No Android devices connected or authorized")
                self._provide_device_connection_guidance()
                return False
            
            # Check 4: Frida server on device (optional but recommended)
            validation_results['frida_server_running'] = self._check_frida_server_status()
            if not validation_results['frida_server_running']:
                self.logger.warning("⚠️ Frida server is not running on target device")
                self._provide_frida_server_guidance()
                # Continue without failing - some analysis may still be possible
            
            # Check 5: Target APK installation (optional check)
            validation_results['apk_installed'] = self._check_target_apk_installation()
            if not validation_results['apk_installed']:
                self.logger.info("ℹ️ Target APK may not be installed on device")
                self._provide_apk_installation_guidance()
                # Continue without failing - static analysis components can still run
            
            # Determine overall readiness
            essential_checks = ['frida_installed', 'adb_available', 'devices_connected']
            environment_ready = all(validation_results[check] for check in essential_checks)
            
            if environment_ready:
                self.logger.info("✅ Frida dynamic analysis environment is ready")
                if validation_results['frida_server_running']:
                    self.logger.info("✅ Frida server is running - full dynamic analysis available")
                else:
                    self.logger.info("⚠️ Frida server not detected - limited dynamic analysis available")
            else:
                self.logger.error("❌ Frida dynamic analysis environment validation failed")
                self._provide_environment_setup_summary()
            
            return environment_ready
            
        except Exception as e:
            self.logger.error(f"Environment validation failed: {e}", exc_info=True)
            return False

    def _check_frida_installation(self) -> bool:
        """Check if Frida is properly installed and accessible."""
        try:
            # Use Python import instead of subprocess for venv compatibility
            import frida
            version = frida.__version__
            self.logger.debug(f"✅ Frida version: {version}")
            
            # Additional verification: check if we can enumerate devices
            devices = frida.enumerate_devices()
            self.logger.debug(f"✅ Frida devices available: {len(devices)}")
            for device in devices:
                self.logger.debug(f"   📱 {device.id}: {device.name} ({device.type})")
            
            return True
        except ImportError as e:
            self.logger.debug(f"❌ Frida import failed: {e}")
        except Exception as e:
            self.logger.debug(f"❌ Frida installation check failed: {e}")
        return False
    
    def _check_adb_availability(self) -> bool:
        """Check if ADB is available and functional."""
        try:
            import subprocess
            result = subprocess.run(['adb', 'version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.debug(f"ADB availability check failed: {e}")
        return False
    
    def _check_device_connectivity(self) -> bool:
        """Check for connected and authorized Android devices."""
        try:
            import subprocess
            result = subprocess.run(['adb', 'devices'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                authorized_devices = [line for line in lines 
                                    if line.strip() and 'device' in line and 'unauthorized' not in line]
                self.logger.debug(f"Found {len(authorized_devices)} authorized devices")
                return len(authorized_devices) > 0
        except (subprocess.TimeoutExpired, Exception) as e:
            self.logger.debug(f"Device connectivity check failed: {e}")
        return False
    
    def _check_frida_server_status(self) -> bool:
        """Check if Frida server is running on any connected device."""
        try:
            import subprocess
            result = subprocess.run(['frida-ls-devices'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                usb_devices = [line for line in lines if 'usb' in line.lower()]
                self.logger.debug(f"Found {len(usb_devices)} USB devices with Frida")
                return len(usb_devices) > 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.debug(f"Frida server status check failed: {e}")
        return False
    
    def _check_target_apk_installation(self) -> bool:
        """Check if target APK is installed on device."""
        try:
            import subprocess
            # Check if the package is installed
            result = subprocess.run(['adb', 'shell', 'pm', 'list', 'packages', self.package_name], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0 and self.package_name in result.stdout
        except (subprocess.TimeoutExpired, Exception) as e:
            self.logger.debug(f"APK installation check failed: {e}")
        return False
    
    def _provide_frida_installation_guidance(self):
        """Provide guidance for installing Frida."""
        self.logger.info("📋 FRIDA INSTALLATION GUIDE:")
        self.logger.info("   1. Install Frida: pip install frida-tools")
        self.logger.info("   2. Verify installation: frida --version")
        self.logger.info("   3. Documentation: https://frida.re/docs/installation/")
    
    def _provide_adb_setup_guidance(self):
        """Provide guidance for setting up ADB."""
        self.logger.info("📋 ADB SETUP GUIDE:")
        self.logger.info("   1. Install Android SDK Platform Tools")
        self.logger.info("   2. Add ADB to your PATH environment variable")
        self.logger.info("   3. Verify with: adb version")
        self.logger.info("   4. Enable USB debugging on your Android device")
    
    def _provide_device_connection_guidance(self):
        """Provide guidance for connecting Android devices."""
        self.logger.info("📋 DEVICE CONNECTION GUIDE:")
        self.logger.info("   1. Enable USB debugging on your Android device")
        self.logger.info("   2. Connect device via USB cable")
        self.logger.info("   3. Authorize the computer when prompted on device")
        self.logger.info("   4. Verify with: adb devices")
        self.logger.info("   5. Device should show as 'device' (not 'unauthorized')")
    
    def _provide_frida_server_guidance(self):
        """Provide guidance for setting up Frida server on device."""
        self.logger.info("📋 FRIDA SERVER SETUP GUIDE:")
        self.logger.info("   1. Download frida-server for your device architecture")
        self.logger.info("   2. Push to device: adb push frida-server /data/local/tmp/")
        self.logger.info("   3. Make executable: adb shell chmod 755 /data/local/tmp/frida-server")
        self.logger.info("   4. Run as root: adb shell su -c '/data/local/tmp/frida-server &'")
        self.logger.info("   5. Verify with: frida-ls-devices")
    
    def _provide_apk_installation_guidance(self):
        """Provide guidance for installing target APK on device."""
        self.logger.info("📋 APK INSTALLATION GUIDE:")
        self.logger.info(f"   1. Install APK: adb install /path/to/your/apk")
        self.logger.info(f"   2. Verify installation: adb shell pm list packages | grep {self.package_name}")
        self.logger.info("   3. Launch app manually to ensure it runs correctly")
    
    def _provide_environment_setup_summary(self):
        """Provide a summary of required environment setup steps."""
        self.logger.info("📋 DYNAMIC ANALYSIS ENVIRONMENT SETUP SUMMARY:")
        self.logger.info("   Prerequisites for full dynamic analysis:")
        self.logger.info("   ✓ Frida installed (pip install frida-tools)")
        self.logger.info("   ✓ ADB available and in PATH")
        self.logger.info("   ✓ Android device connected with USB debugging enabled")
        self.logger.info("   ✓ Frida server running on target device")
        self.logger.info("   ✓ Target APK installed on device")
        self.logger.info("   📚 Documentation: https://frida.re/docs/")
    
    def _perform_fallback_analysis(self, apk_ctx) -> List:
        """
        Perform fallback analysis when device connectivity is not available.
        
        Provides static-based recommendations and prepares for future dynamic analysis.
        
        Args:
            apk_ctx: APK analysis context
            
        Returns:
            List of analysis recommendations and findings
        """
        try:
            self.logger.info("🔄 Performing fallback analysis in device-unavailable mode")
            
            fallback_findings = []
            
            # Generate environment setup recommendations
            setup_finding = self._generate_environment_setup_finding()
            if setup_finding:
                fallback_findings.append(setup_finding)
            
            # Generate dynamic analysis readiness report
            readiness_finding = self._generate_dynamic_readiness_finding()
            if readiness_finding:
                fallback_findings.append(readiness_finding)
            
            # Suggest static analysis alternatives
            static_alternatives_finding = self._generate_static_alternatives_finding(apk_ctx)
            if static_alternatives_finding:
                fallback_findings.append(static_alternatives_finding)
            
            # Update analysis metadata
            self.analysis_metadata.analysis_duration = time.time() - self.analysis_start_time
            self.analysis_metadata.execution_mode = "fallback"
            self.analysis_metadata.device_connectivity = False
            
            self.logger.info(f"✅ Fallback analysis completed with {len(fallback_findings)} recommendations")
            return fallback_findings
            
        except Exception as e:
            self.logger.error(f"Fallback analysis failed: {e}", exc_info=True)
            return []
    
    def _generate_environment_setup_finding(self):
        """Generate a finding with environment setup recommendations."""
        try:
            from .data_structures import DetailedVulnerability, VulnerabilityLocation, VulnerabilityEvidence, VulnerabilityRemediation
            
            return DetailedVulnerability(
                vulnerability_type="Dynamic Analysis Environment Setup Required",
                severity="INFO",
                cwe_id="CWE-1059",  # Incomplete Documentation
                masvs_control="V1.5",
                security_impact="Dynamic security testing capabilities are not available",
                location=VulnerabilityLocation(
                    file_path="system_environment",
                    component_type="development_environment"
                ),
                evidence=VulnerabilityEvidence(
                    matched_pattern="device_connectivity_check",
                    detection_method="environment_validation",
                    confidence_score=0.95
                ),
                remediation=VulnerabilityRemediation(
                    fix_description="Set up Frida dynamic analysis environment with connected Android device",
                    code_example="# Setup commands:\npip install frida-tools\nadb devices\nfrida-ls-devices",
                    references=["https://frida.re/docs/installation/"]
                )
            )
        except Exception as e:
            self.logger.error(f"Failed to generate environment setup finding: {e}")
            return None
    
    def _generate_dynamic_readiness_finding(self):
        """Generate a finding about dynamic analysis readiness."""
        try:
            from .data_structures import DetailedVulnerability, VulnerabilityLocation, VulnerabilityEvidence, VulnerabilityRemediation
            
            return DetailedVulnerability(
                vulnerability_type="Dynamic Analysis Prerequisites Missing",
                severity="MEDIUM", 
                cwe_id="CWE-1059",
                masvs_control="V1.5",
                security_impact="Runtime security vulnerabilities may remain undetected",
                location=VulnerabilityLocation(
                    file_path="dynamic_analysis_pipeline",
                    component_type="testing_infrastructure"
                ),
                evidence=VulnerabilityEvidence(
                    matched_pattern="runtime_analysis_unavailable",
                    detection_method="prerequisite_validation",
                    confidence_score=0.90
                ),
                remediation=VulnerabilityRemediation(
                    fix_description="Complete dynamic analysis environment setup to detect runtime vulnerabilities",
                    code_example="# Essential steps:\n1. Connect Android device\n2. Enable USB debugging\n3. Install frida-server on device\n4. Install target APK on device",
                    references=["https://frida.re/docs/", "https://developer.android.com/studio/debug/dev-options"]
                )
            )
        except Exception as e:
            self.logger.error(f"Failed to generate dynamic readiness finding: {e}")
            return None
    
    def _generate_static_alternatives_finding(self, apk_ctx):
        """Generate recommendations for static analysis alternatives."""
        try:
            from .data_structures import DetailedVulnerability, VulnerabilityLocation, VulnerabilityEvidence, VulnerabilityRemediation
            
            return DetailedVulnerability(
                vulnerability_type="Static Analysis Alternatives Available",
                severity="INFO",
                cwe_id="CWE-1059",
                masvs_control="V1.2",
                security_impact="Static analysis can provide partial security coverage while dynamic setup is completed",
                location=VulnerabilityLocation(
                    file_path="static_analysis_pipeline",
                    component_type="code_analysis"
                ),
                evidence=VulnerabilityEvidence(
                    matched_pattern="static_analysis_available",
                    detection_method="capability_assessment",
                    confidence_score=0.85
                ),
                remediation=VulnerabilityRemediation(
                    fix_description="Leverage comprehensive static analysis while preparing dynamic environment",
                    code_example="# Available static analysis:\n- Manifest security analysis\n- Code vulnerability scanning\n- Cryptographic implementation review\n- Network security configuration analysis",
                    references=["https://owasp.org/www-project-mobile-security-testing-guide/"]
                )
            )
        except Exception as e:
            self.logger.error(f"Failed to generate static alternatives finding: {e}")
            return None
    
    def _should_use_parallel_execution(self) -> bool:
        """Determine if parallel execution should be used."""
        # Use parallel execution if multiple analyzers are enabled
        enabled_analyzers = sum([
            self.config.enable_ssl_analysis,
            self.config.enable_webview_analysis,
            self.config.enable_anti_tampering_analysis
        ])
        return enabled_analyzers > 1
    
    def _perform_parallel_security_analysis(self, apk_ctx):
        """Perform security analysis using parallel execution."""
        try:
            self.logger.info("Performing parallel security analysis using unified performance optimization")
            
            # Use unified performance optimization framework
            from core.performance_optimizer import ParallelProcessor
            
            # Create parallel processor with unified framework
            parallel_processor = ParallelProcessor(max_workers=self.config.max_workers)
            
            # Prepare analysis tasks
            analysis_tasks = []
            task_names = []
            
            if self.ssl_analyzer:
                analysis_tasks.append(lambda: self._run_ssl_analysis(apk_ctx))
                task_names.append("SSL Analysis")
            
            if self.webview_analyzer:
                analysis_tasks.append(lambda: self._run_webview_analysis(apk_ctx))
                task_names.append("WebView Analysis")
            
            if self.anti_tampering_analyzer:
                analysis_tasks.append(lambda: self._run_anti_tampering_analysis(apk_ctx))
                task_names.append("Anti-Tampering Analysis")
            
            if self.icc_analyzer:
                analysis_tasks.append(lambda: self._run_icc_analysis(apk_ctx))
                task_names.append("ICC Analysis")
            
            if self.webview_exploitation_module:
                analysis_tasks.append(lambda: self._run_webview_exploitation(apk_ctx))
                task_names.append("WebView Exploitation")
            
            if self.dynamic_execution_module:
                analysis_tasks.append(lambda: self._run_dynamic_execution(apk_ctx))
                task_names.append("Dynamic Execution")
            
            # Process tasks using unified parallel framework
            if analysis_tasks:
                results = parallel_processor.process_parallel(
                    items=analysis_tasks,
                    processor_func=lambda task: task(),
                    timeout=self.config.analysis_timeout
                )
                
                # Process results
                for i, result in enumerate(results):
                    if result:
                        analyzer_name = task_names[i] if i < len(task_names) else f"Analysis {i}"
                        self.logger.info(f"Unified framework: {analyzer_name} completed successfully")
                        
                        # Store results (assuming results are findings)
                        if hasattr(result, '__iter__') and not isinstance(result, str):
                            self.detailed_vulnerabilities.extend(result)
                
                self.logger.info(f"Unified parallel analysis completed: {len(analysis_tasks)} tasks, "
                               f"{len(self.detailed_vulnerabilities)} vulnerabilities found")
            
        except Exception as e:
            self.logger.warning(f"Unified performance framework failed, using fallback: {e}")
            # Fallback to original ThreadPoolExecutor implementation
            self._perform_parallel_analysis_fallback(apk_ctx)

    def _perform_parallel_analysis_fallback(self, apk_ctx: APKContext):
        """Fallback parallel analysis method using ThreadPoolExecutor."""
        try:
            self.logger.info("Performing parallel security analysis (fallback)")
            
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                # Submit analysis tasks
                future_to_analyzer = {}
                
                if self.ssl_analyzer:
                    future = executor.submit(self._run_ssl_analysis, apk_ctx)
                    future_to_analyzer[future] = "SSL Analysis"
                
                if self.webview_analyzer:
                    future = executor.submit(self._run_webview_analysis, apk_ctx)
                    future_to_analyzer[future] = "WebView Analysis"
                
                if self.anti_tampering_analyzer:
                    future = executor.submit(self._run_anti_tampering_analysis, apk_ctx)
                    future_to_analyzer[future] = "Anti-Tampering Analysis"
                
                if self.icc_analyzer:
                    future = executor.submit(self._run_icc_analysis, apk_ctx)
                    future_to_analyzer[future] = "ICC Analysis"
                
                if self.webview_exploitation_module:
                    future = executor.submit(self._run_webview_exploitation, apk_ctx)
                    future_to_analyzer[future] = "WebView Exploitation"
                
                if self.dynamic_execution_module:
                    future = executor.submit(self._run_dynamic_execution, apk_ctx)
                    future_to_analyzer[future] = "Dynamic Execution"
                
                # Collect results with timeout
                for future in as_completed(future_to_analyzer, timeout=self.config.analysis_timeout):
                    analyzer_name = future_to_analyzer[future]
                    try:
                        result = future.result()
                        if result:
                            self.logger.info(f"{analyzer_name} completed successfully")
                            # Store results (assuming results are findings)
                            if hasattr(result, '__iter__') and not isinstance(result, str):
                                self.detailed_vulnerabilities.extend(result)
                    except FutureTimeoutError:
                        self.logger.warning(f"{analyzer_name} timed out")
                    except Exception as e:
                        self.logger.error(f"{analyzer_name} failed: {e}")
                        
        except Exception as e:
            self.logger.error(f"Fallback parallel analysis failed: {e}")
            # Sequential fallback
            if self.ssl_analyzer:
                try:
                    result = self._run_ssl_analysis(apk_ctx)
                    if result:
                        self.detailed_vulnerabilities.extend(result)
                except Exception as e:
                    self.logger.error(f"Sequential SSL analysis failed: {e}")
            
            if self.webview_analyzer:
                try:
                    result = self._run_webview_analysis(apk_ctx)
                    if result:
                        self.detailed_vulnerabilities.extend(result)
                except Exception as e:
                    self.logger.error(f"Sequential WebView analysis failed: {e}")
            
            if self.anti_tampering_analyzer:
                try:
                    result = self._run_anti_tampering_analysis(apk_ctx)
                    if result:
                        self.detailed_vulnerabilities.extend(result)
                except Exception as e:
                    self.logger.error(f"Sequential anti-tampering analysis failed: {e}")
            
            if self.icc_analyzer:
                try:
                    result = self._run_icc_analysis(apk_ctx)
                    if result:
                        self.detailed_vulnerabilities.extend(result)
                except Exception as e:
                    self.logger.error(f"Sequential ICC analysis failed: {e}")
            
            if self.webview_exploitation_module:
                try:
                    result = self._run_webview_exploitation(apk_ctx)
                    if result:
                        self.detailed_vulnerabilities.extend(result)
                except Exception as e:
                    self.logger.error(f"Sequential WebView exploitation failed: {e}")
            
            if self.dynamic_execution_module:
                try:
                    result = self._run_dynamic_execution(apk_ctx)
                    if result:
                        self.detailed_vulnerabilities.extend(result)
                except Exception as e:
                    self.logger.error(f"Sequential dynamic execution failed: {e}")
    
    def _run_ssl_analysis(self, apk_ctx) -> List[DetailedVulnerability]:
        """Run SSL/TLS security analysis."""
        try:
            self.logger.debug("Running SSL security analysis")
            return self.ssl_analyzer.perform_ssl_pinning_tests(apk_ctx)
        except Exception as e:
            self.logger.error(f"SSL analysis failed: {e}")
            return []
    
    def _run_webview_analysis(self, apk_ctx) -> List[DetailedVulnerability]:
        """Run WebView security analysis."""
        try:
            self.logger.debug("Running WebView security analysis")
            return self.webview_analyzer.perform_webview_security_tests(apk_ctx)
        except Exception as e:
            self.logger.error(f"WebView analysis failed: {e}")
            return []
    
    def _run_anti_tampering_analysis(self, apk_ctx) -> List[DetailedVulnerability]:
        """Run anti-tampering security analysis."""
        try:
            self.logger.debug("Running anti-tampering analysis")
            return self.anti_tampering_analyzer.perform_anti_tampering_tests(apk_ctx)
        except Exception as e:
            self.logger.error(f"Anti-tampering analysis failed: {e}")
            return []
    
    def _run_icc_analysis(self, apk_ctx) -> List[DetailedVulnerability]:
        """Run ICC (Inter-Component Communication) security analysis."""
        try:
            self.logger.debug("Running ICC security analysis")
            return self.icc_analyzer.perform_icc_security_tests(apk_ctx)
        except Exception as e:
            self.logger.error(f"ICC analysis failed: {e}")
            return []
    
    def _run_webview_exploitation(self, apk_ctx) -> List[DetailedVulnerability]:
        """Run advanced WebView exploitation testing."""
        try:
            self.logger.debug("Running advanced WebView exploitation")
            return self.webview_exploitation_module.perform_advanced_webview_exploitation(apk_ctx)
        except Exception as e:
            self.logger.error(f"WebView exploitation failed: {e}")
            return []
    
    def _run_dynamic_execution(self, apk_ctx) -> List[DetailedVulnerability]:
        """Run dynamic code execution and reflection testing."""
        try:
            self.logger.debug("Running dynamic code execution testing")
            return self.dynamic_execution_module.perform_dynamic_execution_testing(apk_ctx)
        except Exception as e:
            self.logger.error(f"Dynamic execution testing failed: {e}")
            return []
    
    def _post_process_analysis_results(self):
        """Post-process analysis results for optimization and deduplication."""
        try:
            # Remove duplicates
            self._deduplicate_vulnerabilities()
            
            # Filter by confidence threshold
            self._filter_by_confidence_threshold()
            
            # Sort by severity
            self._sort_vulnerabilities_by_severity()
            
        except Exception as e:
            self.logger.error(f"Post-processing failed: {e}")
    
    def _deduplicate_vulnerabilities(self):
        """Remove duplicate vulnerabilities using unified deduplication framework."""
        if not self.detailed_vulnerabilities:
            return
        
        try:
            # Import unified deduplication framework
            from core.unified_deduplication_framework import (
                deduplicate_findings,
                DeduplicationStrategy
            )
            
            # Convert vulnerabilities to dictionaries for unified deduplication
            dict_findings = []
            for vuln in self.detailed_vulnerabilities:
                dict_finding = {
                    'title': f"{vuln.vulnerability_type}: CWE-{vuln.cwe_id}",
                    'file_path': vuln.location.file_path if vuln.location else "unknown",
                    'severity': vuln.severity.value if hasattr(vuln, 'severity') else 'MEDIUM',
                    'category': 'dynamic_analysis',
                    'description': vuln.evidence.matched_pattern if vuln.evidence else "Unknown pattern",
                    'cwe_id': vuln.cwe_id,
                    'vulnerability_type': vuln.vulnerability_type,
                    'finding_id': id(vuln)
                }
                dict_findings.append(dict_finding)
            
            # Use unified deduplication framework with INTELLIGENT strategy for dynamic analysis
            result = deduplicate_findings(dict_findings, DeduplicationStrategy.INTELLIGENT)
            
            # Map deduplicated results back to original vulnerabilities
            unique_vuln_ids = {f['finding_id'] for f in result.unique_findings}
            unique_vulnerabilities = [v for v in self.detailed_vulnerabilities if id(v) in unique_vuln_ids]
            
            # Log deduplication results for transparency
            removed_count = len(self.detailed_vulnerabilities) - len(unique_vulnerabilities)
            if removed_count > 0:
                self.logger.info(f"Unified deduplication: {len(self.detailed_vulnerabilities)} -> {len(unique_vulnerabilities)} "
                                f"({removed_count} duplicates removed)")
            
            self.detailed_vulnerabilities = unique_vulnerabilities
            
        except Exception as e:
            # Fallback to original custom deduplication
            self.logger.warning(f"Unified deduplication failed, using fallback: {e}")
            self._deduplicate_vulnerabilities_fallback()
    
    def _deduplicate_vulnerabilities_fallback(self):
        """Fallback deduplication method (original logic)."""
        seen_vulnerabilities = set()
        unique_vulnerabilities = []
        
        for vuln in self.detailed_vulnerabilities:
            # Create a unique identifier for the vulnerability
            vuln_id = (
                vuln.vulnerability_type,
                vuln.cwe_id,
                vuln.location.file_path if vuln.location else "unknown",
                vuln.evidence.matched_pattern if vuln.evidence else "unknown"
            )
            
            if vuln_id not in seen_vulnerabilities:
                seen_vulnerabilities.add(vuln_id)
                unique_vulnerabilities.append(vuln)
        
        removed_count = len(self.detailed_vulnerabilities) - len(unique_vulnerabilities)
        if removed_count > 0:
            self.logger.info(f"Removed {removed_count} duplicate vulnerabilities")
            
        self.detailed_vulnerabilities = unique_vulnerabilities
    
    def _filter_by_confidence_threshold(self):
        """Filter vulnerabilities by confidence threshold."""
        original_count = len(self.detailed_vulnerabilities)
        
        self.detailed_vulnerabilities = [
            vuln for vuln in self.detailed_vulnerabilities
            if vuln.evidence and vuln.evidence.confidence_score >= self.config.confidence_threshold
        ]
        
        filtered_count = original_count - len(self.detailed_vulnerabilities)
        if filtered_count > 0:
            self.logger.info(f"Filtered out {filtered_count} low-confidence vulnerabilities")
    
    def _sort_vulnerabilities_by_severity(self):
        """Sort vulnerabilities by severity."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        
        self.detailed_vulnerabilities.sort(
            key=lambda vuln: severity_order.get(vuln.severity, 5)
        )
    
    def _finalize_analysis_metadata(self):
        """Finalize analysis metadata."""
        if self.analysis_start_time:
            self.analysis_metadata.analysis_duration = time.time() - self.analysis_start_time
        self.analysis_metadata.vulnerabilities_found = len(self.detailed_vulnerabilities)
        self.analysis_metadata.analysis_complete = True
    
    def _execute_runtime_hook_analysis(self, apk_ctx) -> List[DetailedVulnerability]:
        """
        Execute runtime hook analysis for true dynamic vulnerability detection.
        
        Args:
            apk_ctx: APK analysis context
            
        Returns:
            List of vulnerabilities detected through runtime hooks
        """
        runtime_vulnerabilities = []
        
        if not RUNTIME_HOOKS_AVAILABLE:
            self.logger.warning("⚠️ Runtime hooks not available - skipping runtime analysis")
            return runtime_vulnerabilities
        
        try:
            self.logger.info("🚀 Starting runtime hook analysis for true dynamic vulnerability detection")
            
            # Get Frida device
            device = self._get_frida_device()
            if not device:
                self.logger.warning("⚠️ No Frida device available - skipping runtime hook analysis")
                return runtime_vulnerabilities
            
            # Initialize runtime hook engine
            with RuntimeHookEngine(device, self.package_name, apk_ctx) as hook_engine:
                self.logger.info(f"🔗 Runtime hook engine initialized for {self.package_name}")
                
                # Initialize comprehensive coordination framework (Task 3.2)
                from .interaction import AppAutomationFramework
                from .scenarios import VulnerabilityScenarioEngine
                from .coordinator import (
                    RuntimeAnalysisCoordinator, RealTimeProcessingPipeline,
                    DataSynchronizationManager, AnalysisPhaseManager
                )
                
                # Initialize all analysis components
                app_automator = AppAutomationFramework(device, self.package_name, apk_ctx)
                scenario_engine = VulnerabilityScenarioEngine(self.package_name, apk_ctx)
                
                # Initialize Task 3.2 coordination components
                processing_pipeline = RealTimeProcessingPipeline(
                    detector=getattr(hook_engine, 'vulnerability_detector', None),
                    collector=getattr(hook_engine, 'evidence_collector', None)
                )
                
                data_sync_manager = DataSynchronizationManager()
                phase_manager = AnalysisPhaseManager()
                
                # Initialize runtime analysis coordinator (Task 3.2 core)
                coordinator = RuntimeAnalysisCoordinator(
                    hook_engine=hook_engine,
                    detector=getattr(hook_engine, 'vulnerability_detector', None),
                    automator=app_automator,
                    scenario_engine=scenario_engine,
                    collector=getattr(hook_engine, 'evidence_collector', None)
                )
                
                # Set processing components integration
                coordinator.set_processing_components(
                    pipeline=processing_pipeline,
                    sync_manager=data_sync_manager,
                    phase_manager=phase_manager
                )
                
                # Register components for synchronization
                data_sync_manager.register_component('hook_engine', hook_engine)
                data_sync_manager.register_component('automator', app_automator)
                data_sync_manager.register_component('scenario_engine', scenario_engine)
                if getattr(hook_engine, 'vulnerability_detector', None):
                    data_sync_manager.register_component('detector', hook_engine.vulnerability_detector)
                if getattr(hook_engine, 'evidence_collector', None):
                    data_sync_manager.register_component('collector', hook_engine.evidence_collector)
                
                # Register components for phase management
                phase_manager.register_component('hook_engine', hook_engine)
                phase_manager.register_component('automator', app_automator)
                phase_manager.register_component('scenario_engine', scenario_engine)
                if getattr(hook_engine, 'vulnerability_detector', None):
                    phase_manager.register_component('detector', hook_engine.vulnerability_detector)
                if getattr(hook_engine, 'evidence_collector', None):
                    phase_manager.register_component('collector', hook_engine.evidence_collector)
                
                # Start coordinated runtime analysis with automated phase management
                monitoring_duration = getattr(self.config, 'runtime_monitoring_duration', 300)  # 5 minutes for full coordination
                self.logger.info(f"🎯 Starting automated coordinated runtime analysis for {monitoring_duration}s")
                
                # Execute coordinated analysis using Task 3.2 framework
                coordination_success = self._execute_coordinated_runtime_analysis(
                    coordinator, processing_pipeline, data_sync_manager, phase_manager, monitoring_duration
                )
                
                if not coordination_success:
                    self.logger.warning("⚠️ Coordinated analysis failed, falling back to basic hook monitoring")
                    # Fallback to basic monitoring
                    hook_results = hook_engine.start_runtime_monitoring(duration=60)
                
                # Convert runtime hook results to DetailedVulnerability objects
                for hook_result in hook_results:
                    if hook_result.status == HookStatus.COMPLETED and hook_result.vulnerabilities_found:
                        for vuln_data in hook_result.vulnerabilities_found:
                            try:
                                # Create DetailedVulnerability from runtime hook data
                                runtime_vuln = DetailedVulnerability(
                                    vulnerability_type=vuln_data.get('vulnerability_type', 'RUNTIME_VULNERABILITY'),
                                    title=vuln_data.get('title', 'Runtime Vulnerability'),
                                    description=vuln_data.get('description', 'Vulnerability detected during runtime analysis'),
                                    severity=vuln_data.get('severity', 'MEDIUM'),
                                    cwe_id=vuln_data.get('cwe_id', 'CWE-200'),
                                    masvs_control=vuln_data.get('masvs_control', 'V1.1'),
                                    security_impact="Runtime vulnerability detected through dynamic instrumentation",
                                    location=VulnerabilityLocation(
                                        file_path="runtime_analysis",
                                        component_type="dynamic_instrumentation"
                                    ),
                                    evidence=VulnerabilityEvidence(
                                        matched_pattern=f"runtime_hook:{hook_result.hook_name}",
                                        detection_method="frida_javascript_injection",
                                        confidence_score=vuln_data.get('confidence', 0.8),
                                        context_data=vuln_data.get('evidence', {})
                                    ),
                                    remediation=RemediationGuidance(
                                        fix_description=f"Address the {vuln_data.get('vulnerability_type')} vulnerability detected during runtime",
                                        code_example="Review application runtime behavior and implement proper security controls"
                                    )
                                )
                                
                                runtime_vulnerabilities.append(runtime_vuln)
                                self.logger.info(f"✅ Runtime vulnerability detected: {runtime_vuln.title}")
                                
                            except Exception as e:
                                self.logger.error(f"❌ Failed to convert runtime vulnerability: {e}")
                
                # Add runtime vulnerabilities to the main list
                self.detailed_vulnerabilities.extend(runtime_vulnerabilities)
                
                # Get total runtime events for metadata
                total_events = len(hook_engine.get_runtime_events())
                total_vulnerabilities = len(hook_engine.get_detected_vulnerabilities())
                
                self.logger.info(f"🎯 Runtime hook analysis completed: {total_vulnerabilities} vulnerabilities detected from {total_events} runtime events")
                
                # Update analysis metadata
                if hasattr(self, 'analysis_metadata') and self.analysis_metadata:
                    self.analysis_metadata.runtime_events_captured = total_events
                    self.analysis_metadata.runtime_vulnerabilities_found = total_vulnerabilities
                
        except Exception as e:
            self.logger.error(f"❌ Runtime hook analysis failed: {e}", exc_info=True)
            
        return runtime_vulnerabilities
    
    def _get_frida_device(self):
        """Get Frida device for runtime analysis."""
        try:
            import frida
            device = frida.get_usb_device()
            self.logger.info(f"✅ Frida device connected: {device}")
            return device
        except Exception as e:
            self.logger.error(f"❌ Failed to get Frida device: {e}")
            return None
    
    def _execute_coordinated_runtime_analysis(self, coordinator, processing_pipeline, 
                                            data_sync_manager, phase_manager, duration: int) -> bool:
        """
        Execute coordinated runtime analysis using Task 3.2 framework.
        
        Args:
            coordinator: RuntimeAnalysisCoordinator instance
            processing_pipeline: RealTimeProcessingPipeline instance
            data_sync_manager: DataSynchronizationManager instance
            phase_manager: AnalysisPhaseManager instance
            duration: Total duration for coordinated analysis in seconds
            
        Returns:
            True if coordinated analysis executed successfully, False otherwise
        """
        try:
            self.logger.info(f"🚀 Starting coordinated runtime analysis using Task 3.2 framework ({duration}s)")
            
            # Start all coordination components
            coordination_session = coordinator.start_coordination_session(
                session_id=f"coord_session_{int(time.time())}", 
                timeout=duration
            )
            
            # Start real-time processing pipeline
            processing_pipeline.start_processing()
            self.logger.info("⚡ Real-time processing pipeline started")
            
            # Start data synchronization
            data_sync_manager.start_synchronization()
            self.logger.info("🔄 Data synchronization started")
            
            # Start automated phase management
            phase_manager.start_phase_management()
            self.logger.info("📋 Automated phase management started")
            
            # Execute coordinated analysis
            coordination_results = coordinator.coordinate_analysis()
            
            # Process results and update metadata
            if coordination_results and 'session_summary' in coordination_results:
                session_summary = coordination_results['session_summary']
                
                self.logger.info(f"✅ Coordinated analysis completed successfully:")
                self.logger.info(f"   ⏱️ Duration: {session_summary.get('duration', 0):.1f}s")
                self.logger.info(f"   ⚡ Events processed: {session_summary.get('events_processed', 0)}")
                self.logger.info(f"   🔍 Vulnerabilities detected: {session_summary.get('vulnerabilities_detected', 0)}")
                self.logger.info(f"   📊 Success rate: {session_summary.get('success_rate', 0):.2%}")
                self.logger.info(f"   📋 Phases completed: {session_summary.get('phases_completed', 0)}")
                
                # Get synchronized data from all components
                all_sync_data = data_sync_manager.get_all_synchronized_data()
                
                # Get processing pipeline metrics
                pipeline_metrics = processing_pipeline.get_pipeline_metrics()
                
                # Get phase execution summary
                phase_summary = phase_manager.get_phase_summary()
                
                self.logger.info(f"📊 Coordination Framework Metrics:")
                self.logger.info(f"   🔄 Pipeline events processed: {pipeline_metrics.get('events_processed', 0)}")
                self.logger.info(f"   📈 Pipeline throughput: {pipeline_metrics.get('throughput_rate', 0):.2f} events/s")
                self.logger.info(f"   🔗 Data sync components: {len(all_sync_data)}")
                self.logger.info(f"   📋 Phase execution success: {phase_summary.get('metrics', {}).get('success_rate', 0):.2%}")
                
                # Update analysis metadata with coordination results
                if hasattr(self, 'analysis_metadata'):
                    self.analysis_metadata.runtime_events.extend(
                        coordination_results.get('runtime_events', [])
                    )
                    
                    # Add coordination framework statistics
                    self.analysis_metadata.coordination_session_id = coordination_session.session_id
                    self.analysis_metadata.events_processed = session_summary.get('events_processed', 0)
                    self.analysis_metadata.vulnerabilities_detected = session_summary.get('vulnerabilities_detected', 0)
                    self.analysis_metadata.coordination_success_rate = session_summary.get('success_rate', 0)
                    self.analysis_metadata.phases_completed = session_summary.get('phases_completed', 0)
                    self.analysis_metadata.pipeline_throughput = pipeline_metrics.get('throughput_rate', 0)
                    self.analysis_metadata.coordination_effectiveness = session_summary.get('success_rate', 0)
            
            # Stop coordination components gracefully
            self._stop_coordination_components(coordinator, processing_pipeline, data_sync_manager, phase_manager)
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Coordinated runtime analysis failed: {e}")
            
            # Ensure components are stopped on error
            try:
                self._stop_coordination_components(coordinator, processing_pipeline, data_sync_manager, phase_manager)
            except Exception as cleanup_error:
                self.logger.error(f"❌ Cleanup error: {cleanup_error}")
            
            return False
    
    def _stop_coordination_components(self, coordinator, processing_pipeline, data_sync_manager, phase_manager):
        """Stop all coordination components gracefully."""
        try:
            # Stop phase manager
            if phase_manager:
                phase_manager.stop_phase_management()
                self.logger.debug("📋 Phase management stopped")
            
            # Stop data synchronization
            if data_sync_manager:
                data_sync_manager.stop_synchronization()
                self.logger.debug("🔄 Data synchronization stopped")
            
            # Stop processing pipeline
            if processing_pipeline:
                processing_pipeline.stop_processing()
                self.logger.debug("⚡ Processing pipeline stopped")
            
            # Stop coordinator
            if coordinator:
                coordinator.stop_coordination()
                self.logger.debug("🔗 Runtime coordination stopped")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping coordination components: {e}")

    def generate_enhanced_report(self) -> Text:
        """Generate enhanced vulnerability report."""
        try:
            report = Text()
            report.append("Enhanced Frida Dynamic Analysis Report\n", style="bold blue")
            report.append("=" * 50 + "\n\n", style="blue")
            
            # Analysis summary
            report.append(f"Package: {self.package_name}\n", style="bold")
            report.append(f"Analysis Duration: {self.analysis_metadata.analysis_duration:.2f}s\n")
            report.append(f"Vulnerabilities Found: {len(self.detailed_vulnerabilities)}\n\n")
            
            # Vulnerability breakdown by severity
            severity_counts = self._get_severity_breakdown()
            for severity, count in severity_counts.items():
                if count > 0:
                    color = self._get_severity_color(severity)
                    report.append(f"{severity}: {count}\n", style=color)
            
            report.append("\n")
            
            # Detailed vulnerabilities
            if self.detailed_vulnerabilities:
                report.append("Detailed Vulnerabilities:\n", style="bold yellow")
                report.append("-" * 30 + "\n\n")
                
                for i, vuln in enumerate(self.detailed_vulnerabilities, 1):
                    self._append_vulnerability_details(report, vuln, i)
            else:
                report.append("No vulnerabilities detected.\n", style="green")
            
            return report
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            error_report = Text()
            error_report.append("Enhanced Frida Dynamic Analysis Report\n", style="bold red")
            error_report.append(f"Report generation failed: {str(e)}\n", style="red")
            return error_report
    
    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Get breakdown of vulnerabilities by severity."""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for vuln in self.detailed_vulnerabilities:
            if vuln.severity in severity_counts:
                severity_counts[vuln.severity] += 1
        
        return severity_counts
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "white"
        }
        return colors.get(severity, "white")
    
    def _append_vulnerability_details(self, report: Text, vuln: DetailedVulnerability, index: int):
        """Append detailed vulnerability information to report."""
        try:
            # Vulnerability header
            severity_color = self._get_severity_color(vuln.severity)
            report.append(f"{index}. {vuln.vulnerability_type}\n", style="bold white")
            report.append(f"   Severity: {vuln.severity}\n", style=severity_color)
            report.append(f"   CWE: {vuln.cwe_id}\n")
            report.append(f"   MASVS: {vuln.masvs_control}\n")
            
            # Location information
            if vuln.location:
                report.append(f"   Location: {vuln.location.file_path}\n")
                if vuln.location.component_type:
                    report.append(f"   Component: {vuln.location.component_type}\n")
            
            # Security impact
            if vuln.security_impact:
                report.append(f"   Impact: {vuln.security_impact}\n")
            
            # Evidence
            if vuln.evidence:
                report.append(f"   Evidence: {vuln.evidence.matched_pattern}\n")
                report.append(f"   Detection: {vuln.evidence.detection_method}\n")
                report.append(f"   Confidence: {vuln.evidence.confidence_score:.2f}\n")
            
            # Remediation
            if vuln.remediation and vuln.remediation.fix_description:
                report.append(f"   Remediation: {vuln.remediation.fix_description}\n")
            
            report.append("\n")
            
        except Exception as e:
            self.logger.error(f"Failed to append vulnerability details: {e}")
            report.append(f"   Error displaying vulnerability details: {str(e)}\n\n", style="red")
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get comprehensive analysis statistics."""
        return {
            "package_name": self.package_name,
            "analysis_complete": self.analysis_complete,
            "analysis_duration": self.analysis_metadata.analysis_duration,
            "vulnerabilities_found": len(self.detailed_vulnerabilities),
            "severity_breakdown": self._get_severity_breakdown(),
            "analyzers_enabled": {
                "ssl_analysis": self.config.enable_ssl_analysis,
                "webview_analysis": self.config.enable_webview_analysis,
                "anti_tampering_analysis": self.config.enable_anti_tampering_analysis
            },
            "execution_mode": "parallel" if self.config.enable_parallel_analysis else "sequential"
        } 