#!/usr/bin/env python3
"""
AODS Frida Integration Adapter

Integrates the AI/ML-Enhanced Frida Script Generator with the existing AODS Frida framework,
providing seamless integration with ScriptManager, AnalysisOrchestrator, and UnifiedFridaManager.

Features:
- Integration with AODS Frida Framework (core.frida_framework)
- Custom script loading via ScriptManager
- Analysis orchestration support
- Message handling and result collection
- Professional error handling and fallback
- Support for both base and AI/ML enhanced scripts

Integration Points:
- core.frida_framework.ScriptManager: Custom script loading
- core.frida_framework.AnalysisOrchestrator: Analysis workflow integration
- core.unified_analysis_managers.frida_manager: Unified manager integration
- core.frida_manager: Legacy compatibility

Architecture:
- FridaIntegrationAdapter: Main integration interface
- AODSFridaScriptLoader: AODS-compatible script loader
- EnhancedScriptMessageHandler: Message handling for AI/ML scripts
- ResultCollectionManager: Result aggregation and formatting
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Any, Optional, Callable, Tuple, Union
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime

# Import our AI/ML enhanced components
try:
    from .ai_ml_enhanced_generator import (
        AIMLEnhancedFridaScriptGenerator,
        AIMLScriptGenerationContext,
        create_ai_ml_enhanced_generator
    )
    from .frida_script_generator import FridaScriptGenerator
    from .data_structures import RuntimeDecryptionFinding, RuntimeDecryptionConfig
    AI_ML_ENHANCEMENT_AVAILABLE = True
except ImportError as e:
    logging.getLogger(__name__).debug(f"AI/ML enhancement not available: {e}")
    AI_ML_ENHANCEMENT_AVAILABLE = False

# Import AODS Frida framework components
try:
    from core.frida_framework import ScriptManager, AnalysisOrchestrator, FridaManager
    from core.frida_framework.script_manager import ScriptManager as CoreScriptManager
    AODS_FRIDA_FRAMEWORK_AVAILABLE = True
except ImportError as e:
    logging.getLogger(__name__).debug(f"AODS Frida framework not available: {e}")
    AODS_FRIDA_FRAMEWORK_AVAILABLE = False

# Import unified managers
try:
    from core.unified_analysis_managers.frida_manager import UnifiedFridaManager
    UNIFIED_FRIDA_AVAILABLE = True
except ImportError as e:
    logging.getLogger(__name__).debug(f"Unified Frida manager not available: {e}")
    UNIFIED_FRIDA_AVAILABLE = False


@dataclass
class FridaScriptInfo:
    """Information about a loaded Frida script."""
    script_name: str
    script_type: str  # 'base', 'ai_ml_enhanced', 'custom'
    script_content: str
    generation_time: float
    hooks_count: int
    ml_recommendations: int = 0
    cve_correlations: int = 0
    confidence_score: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class FridaAnalysisResults:
    """Results from Frida script execution."""
    script_name: str
    execution_success: bool
    execution_time: float
    messages_received: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities_detected: List[Dict[str, Any]] = field(default_factory=list)
    ml_insights: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None


class EnhancedScriptMessageHandler:
    """Enhanced message handler for AI/ML generated Frida scripts."""
    
    def __init__(self, script_name: str, result_collector: 'ResultCollectionManager'):
        """Initialize enhanced message handler."""
        self.script_name = script_name
        self.result_collector = result_collector
        self.logger = logging.getLogger(f"{__name__}.{script_name}")
        self.messages_received = []
        self.vulnerabilities_found = []
        
    def handle_message(self, message: Dict[str, Any], data: Any = None) -> None:
        """Handle messages from AI/ML enhanced Frida scripts."""
        try:
            self.messages_received.append({
                'timestamp': datetime.now().isoformat(),
                'message': message,
                'data': data
            })
            
            # Parse message type
            if message.get('type') == 'send':
                self._handle_send_message(message.get('payload', {}))
            elif message.get('type') == 'error':
                self._handle_error_message(message.get('description', ''))
            else:
                self.logger.debug(f"Received message: {message}")
                
        except Exception as e:
            self.logger.error(f"Message handling error: {e}")
    
    def _handle_send_message(self, payload: Dict[str, Any]) -> None:
        """Handle send-type messages from scripts."""
        try:
            # AI/ML enhanced script messages
            if 'AODS-ML-PREDICTION' in str(payload):
                self._handle_ml_prediction(payload)
            elif 'AODS-CVE-' in str(payload):
                self._handle_cve_detection(payload)
            elif 'AODS-ADAPTIVE' in str(payload):
                self._handle_adaptive_learning(payload)
            elif 'AODS-THREAT-INTEL' in str(payload):
                self._handle_threat_intelligence(payload)
            else:
                # Standard vulnerability detection
                self._handle_standard_detection(payload)
                
        except Exception as e:
            self.logger.error(f"Send message handling error: {e}")
    
    def _handle_ml_prediction(self, payload: Dict[str, Any]) -> None:
        """Handle ML prediction messages."""
        vulnerability = {
            'type': 'ml_prediction',
            'confidence': payload.get('confidence', 0.0),
            'pattern': payload.get('pattern', ''),
            'evidence': payload.get('evidence', ''),
            'timestamp': datetime.now().isoformat(),
            'script_name': self.script_name
        }
        
        self.vulnerabilities_found.append(vulnerability)
        self.result_collector.add_vulnerability(vulnerability)
        
        self.logger.info(f"ML prediction detected: {vulnerability['pattern']} "
                        f"(confidence: {vulnerability['confidence']})")
    
    def _handle_cve_detection(self, payload: Dict[str, Any]) -> None:
        """Handle CVE-targeted detection messages."""
        vulnerability = {
            'type': 'cve_detection',
            'cve_id': payload.get('cve_id', ''),
            'pattern': payload.get('pattern', ''),
            'evidence': payload.get('evidence', ''),
            'severity': payload.get('severity', 'MEDIUM'),
            'timestamp': datetime.now().isoformat(),
            'script_name': self.script_name
        }
        
        self.vulnerabilities_found.append(vulnerability)
        self.result_collector.add_vulnerability(vulnerability)
        
        self.logger.warning(f"CVE pattern detected: {vulnerability['cve_id']} - {vulnerability['pattern']}")
    
    def _handle_adaptive_learning(self, payload: Dict[str, Any]) -> None:
        """Handle adaptive learning messages."""
        learning_data = {
            'type': 'adaptive_learning',
            'confidence': payload.get('confidence', 0.0),
            'method_signature': payload.get('method_signature', ''),
            'learning_iteration': payload.get('learning_iteration', 0),
            'timestamp': datetime.now().isoformat(),
            'script_name': self.script_name
        }
        
        self.result_collector.add_learning_data(learning_data)
        
        self.logger.debug(f"Adaptive learning update: {learning_data['method_signature']} "
                         f"(confidence: {learning_data['confidence']})")
    
    def _handle_threat_intelligence(self, payload: Dict[str, Any]) -> None:
        """Handle threat intelligence messages."""
        threat = {
            'type': 'threat_intelligence',
            'threat_id': payload.get('threat_id', ''),
            'severity': payload.get('severity', 'MEDIUM'),
            'cve_references': payload.get('cve_references', []),
            'evidence': payload.get('evidence', ''),
            'timestamp': datetime.now().isoformat(),
            'script_name': self.script_name
        }
        
        self.vulnerabilities_found.append(threat)
        self.result_collector.add_vulnerability(threat)
        
        self.logger.warning(f"Threat intelligence match: {threat['threat_id']}")
    
    def _handle_standard_detection(self, payload: Dict[str, Any]) -> None:
        """Handle standard vulnerability detection messages."""
        vulnerability = {
            'type': 'standard_detection',
            'description': str(payload),
            'timestamp': datetime.now().isoformat(),
            'script_name': self.script_name
        }
        
        self.vulnerabilities_found.append(vulnerability)
        self.result_collector.add_vulnerability(vulnerability)
    
    def _handle_error_message(self, description: str) -> None:
        """Handle error messages from scripts."""
        self.logger.error(f"Script error: {description}")
        
        error_info = {
            'type': 'script_error',
            'description': description,
            'timestamp': datetime.now().isoformat(),
            'script_name': self.script_name
        }
        
        self.result_collector.add_error(error_info)
    
    def get_results(self) -> FridaAnalysisResults:
        """Get analysis results from this message handler."""
        return FridaAnalysisResults(
            script_name=self.script_name,
            execution_success=len(self.vulnerabilities_found) > 0,
            execution_time=0.0,  # Will be set by caller
            messages_received=self.messages_received,
            vulnerabilities_detected=self.vulnerabilities_found
        )


class ResultCollectionManager:
    """Manages collection and aggregation of results from multiple Frida scripts."""
    
    def __init__(self):
        """Initialize result collection manager."""
        self.vulnerabilities = []
        self.learning_data = []
        self.errors = []
        self.script_results = {}
        self.logger = logging.getLogger(__name__)
    
    def add_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """Add a vulnerability finding."""
        self.vulnerabilities.append(vulnerability)
    
    def add_learning_data(self, learning_data: Dict[str, Any]) -> None:
        """Add adaptive learning data."""
        self.learning_data.append(learning_data)
    
    def add_error(self, error_info: Dict[str, Any]) -> None:
        """Add error information."""
        self.errors.append(error_info)
    
    def add_script_result(self, script_name: str, result: FridaAnalysisResults) -> None:
        """Add results from a specific script."""
        self.script_results[script_name] = result
    
    def get_aggregated_results(self) -> Dict[str, Any]:
        """Get aggregated results from all scripts."""
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities_by_type': self._group_vulnerabilities_by_type(),
            'ml_predictions': len([v for v in self.vulnerabilities if v.get('type') == 'ml_prediction']),
            'cve_detections': len([v for v in self.vulnerabilities if v.get('type') == 'cve_detection']),
            'threat_intelligence_matches': len([v for v in self.vulnerabilities if v.get('type') == 'threat_intelligence']),
            'adaptive_learning_updates': len(self.learning_data),
            'script_errors': len(self.errors),
            'scripts_executed': len(self.script_results),
            'vulnerabilities': self.vulnerabilities,
            'learning_data': self.learning_data,
            'errors': self.errors,
            'script_results': self.script_results
        }
    
    def _group_vulnerabilities_by_type(self) -> Dict[str, int]:
        """Group vulnerabilities by type."""
        type_counts = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        return type_counts


class AODSFridaScriptLoader:
    """AODS-compatible script loader for AI/ML enhanced Frida scripts."""
    
    def __init__(self, config: Optional[RuntimeDecryptionConfig] = None):
        """Initialize AODS script loader."""
        self.config = config or RuntimeDecryptionConfig()
        self.logger = logging.getLogger(__name__)
        self.result_collector = ResultCollectionManager()
        
        # Initialize generators
        self.base_generator = FridaScriptGenerator(self.config)
        self.ai_ml_generator = None
        
        if AI_ML_ENHANCEMENT_AVAILABLE and self.config.enable_ai_ml_enhancement:
            try:
                ai_ml_config = self._load_ai_ml_config()
                self.ai_ml_generator = create_ai_ml_enhanced_generator(ai_ml_config)
                self.logger.info("✅ AI/ML enhanced script loader initialized")
            except Exception as e:
                self.logger.warning(f"⚠️ AI/ML enhancement initialization failed: {e}")
    
    def _load_ai_ml_config(self) -> Dict[str, Any]:
        """Load AI/ML configuration."""
        try:
            import yaml
            config_path = Path(__file__).parent / "ai_ml_config.yaml"
            
            if config_path.exists():
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f)
            else:
                return {}
        except Exception as e:
            self.logger.warning(f"Failed to load AI/ML config: {e}")
            return {}
    
    async def generate_enhanced_script(self, 
                                     findings: List[RuntimeDecryptionFinding],
                                     script_name: str = "runtime_decryption_analysis") -> Tuple[str, FridaScriptInfo]:
        """Generate enhanced Frida script with AI/ML capabilities."""
        start_time = time.time()
        
        try:
            if self.ai_ml_generator:
                # Use AI/ML enhanced generation
                context = AIMLScriptGenerationContext(
                    findings=findings,
                    enable_ml_hook_selection=True,
                    enable_cve_correlation=True,
                    ml_confidence_threshold=0.7
                )
                
                result = await self.ai_ml_generator.generate_ai_ml_enhanced_script(findings, context)
                
                script_info = FridaScriptInfo(
                    script_name=script_name,
                    script_type="ai_ml_enhanced",
                    script_content=result.script_content,
                    generation_time=time.time() - start_time,
                    hooks_count=len(result.hooks_generated),
                    ml_recommendations=len(result.ml_hook_recommendations),
                    cve_correlations=len(result.cve_correlations),
                    confidence_score=result.intelligence_metadata.get('average_confidence', 0.0)
                )
                
                self.logger.info(f"🤖 AI/ML enhanced script generated: {script_name}")
                return result.script_content, script_info
                
            else:
                # Fallback to base generator
                result = self.base_generator.generate_script(findings)
                
                script_info = FridaScriptInfo(
                    script_name=script_name,
                    script_type="base",
                    script_content=result.script_content,
                    generation_time=time.time() - start_time,
                    hooks_count=len(result.hooks_generated)
                )
                
                self.logger.info(f"📝 Base script generated: {script_name}")
                return result.script_content, script_info
                
        except Exception as e:
            self.logger.error(f"❌ Script generation failed: {e}")
            
            # Generate minimal fallback script
            fallback_script = """
            Java.perform(function() {
                console.log("[+] AODS Runtime Decryption Analysis - Fallback Script");
                console.log("[!] AI/ML enhanced generation failed, using fallback");
            });
            """
            
            script_info = FridaScriptInfo(
                script_name=script_name,
                script_type="fallback",
                script_content=fallback_script,
                generation_time=time.time() - start_time,
                hooks_count=0
            )
            
            return fallback_script, script_info
    
    def create_message_handler(self, script_name: str) -> Callable:
        """Create message handler for a script."""
        handler = EnhancedScriptMessageHandler(script_name, self.result_collector)
        return lambda message, data=None: handler.handle_message(message, data)
    
    def get_script_results(self) -> Dict[str, Any]:
        """Get aggregated results from all loaded scripts."""
        return self.result_collector.get_aggregated_results()


class FridaIntegrationAdapter:
    """
    Main adapter for integrating AI/ML enhanced Frida scripts with AODS Frida framework.
    
    Provides seamless integration with existing AODS Frida infrastructure while
    adding AI/ML enhancement capabilities with graceful fallback support.
    """
    
    def __init__(self, package_name: str, config: Optional[RuntimeDecryptionConfig] = None):
        """Initialize Frida integration adapter."""
        self.package_name = package_name
        self.config = config or RuntimeDecryptionConfig()
        self.logger = logging.getLogger(__name__)
        
        # Initialize script loader
        self.script_loader = AODSFridaScriptLoader(self.config)
        
        # AODS Frida framework integration
        self.script_manager = None
        self.analysis_orchestrator = None
        self.unified_manager = None
        
        self._initialize_aods_integration()
        
        # Script tracking
        self.loaded_scripts = {}
        self.execution_results = {}
        
    def _initialize_aods_integration(self):
        """Initialize integration with AODS Frida framework."""
        try:
            if AODS_FRIDA_FRAMEWORK_AVAILABLE:
                self.script_manager = CoreScriptManager()
                self.analysis_orchestrator = AnalysisOrchestrator(self.package_name)
                self.logger.info("✅ AODS Frida framework integration initialized")
            
            if UNIFIED_FRIDA_AVAILABLE:
                self.unified_manager = UnifiedFridaManager(
                    package_name=self.package_name,
                    strategy="enhanced"
                )
                self.logger.info("✅ Unified Frida manager integration initialized")
                
        except Exception as e:
            self.logger.warning(f"⚠️ AODS Frida framework integration failed: {e}")
    
    async def load_enhanced_runtime_analysis_script(self, 
                                                  findings: List[RuntimeDecryptionFinding],
                                                  session: Any = None) -> bool:
        """
        Load AI/ML enhanced runtime analysis script into AODS Frida framework.
        
        Args:
            findings: Runtime decryption findings to generate script for
            session: Active Frida session (optional, will use script_manager session if available)
            
        Returns:
            bool: True if script loaded successfully
        """
        script_name = "aods_runtime_decryption_analysis"
        
        try:
            # Generate enhanced script
            script_content, script_info = await self.script_loader.generate_enhanced_script(
                findings, script_name
            )
            
            # Store script info
            self.loaded_scripts[script_name] = script_info
            
            # Load script using AODS framework
            success = False
            
            # Try ScriptManager integration
            if self.script_manager and hasattr(self.script_manager, 'load_custom_script'):
                try:
                    # Set session if provided
                    if session:
                        self.script_manager.set_session(session)
                    
                    # Create message handler
                    message_handler = self.script_loader.create_message_handler(script_name)
                    
                    # Load script via ScriptManager
                    success = self.script_manager.load_custom_script(
                        script_name, 
                        script_content, 
                        message_handler
                    )
                    
                    if success:
                        self.logger.info(f"✅ Script loaded via ScriptManager: {script_name}")
                        return True
                        
                except Exception as e:
                    self.logger.warning(f"ScriptManager loading failed: {e}")
            
            # Try UnifiedFridaManager integration
            if self.unified_manager and not success:
                try:
                    success, result = self.unified_manager.execute_script(script_content, script_name)
                    
                    if success:
                        self.logger.info(f"✅ Script executed via UnifiedFridaManager: {script_name}")
                        return True
                        
                except Exception as e:
                    self.logger.warning(f"UnifiedFridaManager execution failed: {e}")
            
            # Fallback: direct session usage
            if session and not success:
                try:
                    script = session.create_script(script_content)
                    message_handler = self.script_loader.create_message_handler(script_name)
                    script.on("message", message_handler)
                    script.load()
                    
                    self.logger.info(f"✅ Script loaded via direct session: {script_name}")
                    return True
                    
                except Exception as e:
                    self.logger.error(f"Direct session loading failed: {e}")
            
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Enhanced script loading failed: {e}")
            return False
    
    def integrate_with_analysis_orchestrator(self, 
                                           findings: List[RuntimeDecryptionFinding],
                                           duration: int = 30) -> Dict[str, Any]:
        """
        Integrate with AODS Analysis Orchestrator for comprehensive analysis.
        
        Args:
            findings: Runtime decryption findings
            duration: Analysis duration in seconds
            
        Returns:
            Dict containing analysis results
        """
        if not self.analysis_orchestrator:
            return {"error": "Analysis orchestrator not available"}
        
        try:
            # Prepare custom scripts for orchestrator
            async def prepare_custom_scripts():
                script_content, script_info = await self.script_loader.generate_enhanced_script(
                    findings, "runtime_decryption_enhanced"
                )
                return {"runtime_decryption_enhanced": script_content}
            
            # Run async script preparation
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                custom_scripts = loop.run_until_complete(prepare_custom_scripts())
            finally:
                loop.close()
            
            # Run comprehensive analysis with custom scripts
            results = self.analysis_orchestrator.run_comprehensive_analysis(
                duration=duration,
                enable_flutter=False,  # Focus on runtime decryption
                custom_scripts=custom_scripts
            )
            
            # Add our specific results
            results["runtime_decryption_analysis"] = self.script_loader.get_script_results()
            results["ai_ml_enhanced"] = self.script_loader.ai_ml_generator is not None
            
            self.logger.info("✅ Analysis orchestrator integration completed")
            return results
            
        except Exception as e:
            self.logger.error(f"❌ Analysis orchestrator integration failed: {e}")
            return {"error": str(e)}
    
    def get_integration_status(self) -> Dict[str, Any]:
        """Get status of AODS Frida framework integration."""
        return {
            "script_manager_available": self.script_manager is not None,
            "analysis_orchestrator_available": self.analysis_orchestrator is not None,
            "unified_manager_available": self.unified_manager is not None,
            "ai_ml_enhancement_available": AI_ML_ENHANCEMENT_AVAILABLE,
            "aods_frida_framework_available": AODS_FRIDA_FRAMEWORK_AVAILABLE,
            "loaded_scripts": list(self.loaded_scripts.keys()),
            "package_name": self.package_name
        }
    
    def get_analysis_results(self) -> Dict[str, Any]:
        """Get comprehensive analysis results."""
        base_results = self.script_loader.get_script_results()
        
        return {
            "integration_status": self.get_integration_status(),
            "script_analysis": base_results,
            "loaded_scripts": {name: {
                "script_type": info.script_type,
                "hooks_count": info.hooks_count,
                "ml_recommendations": info.ml_recommendations,
                "cve_correlations": info.cve_correlations,
                "confidence_score": info.confidence_score,
                "generation_time": info.generation_time
            } for name, info in self.loaded_scripts.items()},
            "summary": {
                "total_scripts_loaded": len(self.loaded_scripts),
                "ai_ml_scripts": len([s for s in self.loaded_scripts.values() if s.script_type == "ai_ml_enhanced"]),
                "total_vulnerabilities": base_results.get("total_vulnerabilities", 0),
                "ml_predictions": base_results.get("ml_predictions", 0),
                "cve_detections": base_results.get("cve_detections", 0)
            }
        }


# Factory functions for easy integration
def create_frida_integration_adapter(package_name: str, 
                                   config: Optional[RuntimeDecryptionConfig] = None) -> FridaIntegrationAdapter:
    """Factory function to create Frida integration adapter."""
    return FridaIntegrationAdapter(package_name, config)


async def load_enhanced_scripts_into_aods(package_name: str,
                                        findings: List[RuntimeDecryptionFinding],
                                        session: Any = None,
                                        config: Optional[RuntimeDecryptionConfig] = None) -> Dict[str, Any]:
    """
    Convenience function to load AI/ML enhanced scripts into AODS Frida framework.
    
    Args:
        package_name: Target package name
        findings: Runtime decryption findings
        session: Active Frida session (optional)
        config: Configuration (optional)
        
    Returns:
        Dict containing loading results and analysis information
    """
    adapter = create_frida_integration_adapter(package_name, config)
    
    # Load enhanced script
    success = await adapter.load_enhanced_runtime_analysis_script(findings, session)
    
    # Get results
    results = adapter.get_analysis_results()
    results["loading_success"] = success
    
    return results


if __name__ == "__main__":
    # Integration test
    print("🔗 AODS Frida Integration Adapter")
    print(f"AI/ML Enhancement Available: {AI_ML_ENHANCEMENT_AVAILABLE}")
    print(f"AODS Frida Framework Available: {AODS_FRIDA_FRAMEWORK_AVAILABLE}")
    print(f"Unified Frida Available: {UNIFIED_FRIDA_AVAILABLE}")
    
    # Test adapter creation
    try:
        adapter = create_frida_integration_adapter("com.example.test")
        status = adapter.get_integration_status()
        print(f"Integration Status: {status}")
        print("✅ Frida integration adapter created successfully")
    except Exception as e:
        print(f"❌ Integration adapter creation failed: {e}") 
"""
AODS Frida Integration Adapter

Integrates the AI/ML-Enhanced Frida Script Generator with the existing AODS Frida framework,
providing seamless integration with ScriptManager, AnalysisOrchestrator, and UnifiedFridaManager.

Features:
- Integration with AODS Frida Framework (core.frida_framework)
- Custom script loading via ScriptManager
- Analysis orchestration support
- Message handling and result collection
- Professional error handling and fallback
- Support for both base and AI/ML enhanced scripts

Integration Points:
- core.frida_framework.ScriptManager: Custom script loading
- core.frida_framework.AnalysisOrchestrator: Analysis workflow integration
- core.unified_analysis_managers.frida_manager: Unified manager integration
- core.frida_manager: Legacy compatibility

Architecture:
- FridaIntegrationAdapter: Main integration interface
- AODSFridaScriptLoader: AODS-compatible script loader
- EnhancedScriptMessageHandler: Message handling for AI/ML scripts
- ResultCollectionManager: Result aggregation and formatting
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Any, Optional, Callable, Tuple, Union
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime

# Import our AI/ML enhanced components
try:
    from .ai_ml_enhanced_generator import (
        AIMLEnhancedFridaScriptGenerator,
        AIMLScriptGenerationContext,
        create_ai_ml_enhanced_generator
    )
    from .frida_script_generator import FridaScriptGenerator
    from .data_structures import RuntimeDecryptionFinding, RuntimeDecryptionConfig
    AI_ML_ENHANCEMENT_AVAILABLE = True
except ImportError as e:
    logging.getLogger(__name__).debug(f"AI/ML enhancement not available: {e}")
    AI_ML_ENHANCEMENT_AVAILABLE = False

# Import AODS Frida framework components
try:
    from core.frida_framework import ScriptManager, AnalysisOrchestrator, FridaManager
    from core.frida_framework.script_manager import ScriptManager as CoreScriptManager
    AODS_FRIDA_FRAMEWORK_AVAILABLE = True
except ImportError as e:
    logging.getLogger(__name__).debug(f"AODS Frida framework not available: {e}")
    AODS_FRIDA_FRAMEWORK_AVAILABLE = False

# Import unified managers
try:
    from core.unified_analysis_managers.frida_manager import UnifiedFridaManager
    UNIFIED_FRIDA_AVAILABLE = True
except ImportError as e:
    logging.getLogger(__name__).debug(f"Unified Frida manager not available: {e}")
    UNIFIED_FRIDA_AVAILABLE = False


@dataclass
class FridaScriptInfo:
    """Information about a loaded Frida script."""
    script_name: str
    script_type: str  # 'base', 'ai_ml_enhanced', 'custom'
    script_content: str
    generation_time: float
    hooks_count: int
    ml_recommendations: int = 0
    cve_correlations: int = 0
    confidence_score: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class FridaAnalysisResults:
    """Results from Frida script execution."""
    script_name: str
    execution_success: bool
    execution_time: float
    messages_received: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities_detected: List[Dict[str, Any]] = field(default_factory=list)
    ml_insights: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None


class EnhancedScriptMessageHandler:
    """Enhanced message handler for AI/ML generated Frida scripts."""
    
    def __init__(self, script_name: str, result_collector: 'ResultCollectionManager'):
        """Initialize enhanced message handler."""
        self.script_name = script_name
        self.result_collector = result_collector
        self.logger = logging.getLogger(f"{__name__}.{script_name}")
        self.messages_received = []
        self.vulnerabilities_found = []
        
    def handle_message(self, message: Dict[str, Any], data: Any = None) -> None:
        """Handle messages from AI/ML enhanced Frida scripts."""
        try:
            self.messages_received.append({
                'timestamp': datetime.now().isoformat(),
                'message': message,
                'data': data
            })
            
            # Parse message type
            if message.get('type') == 'send':
                self._handle_send_message(message.get('payload', {}))
            elif message.get('type') == 'error':
                self._handle_error_message(message.get('description', ''))
            else:
                self.logger.debug(f"Received message: {message}")
                
        except Exception as e:
            self.logger.error(f"Message handling error: {e}")
    
    def _handle_send_message(self, payload: Dict[str, Any]) -> None:
        """Handle send-type messages from scripts."""
        try:
            # AI/ML enhanced script messages
            if 'AODS-ML-PREDICTION' in str(payload):
                self._handle_ml_prediction(payload)
            elif 'AODS-CVE-' in str(payload):
                self._handle_cve_detection(payload)
            elif 'AODS-ADAPTIVE' in str(payload):
                self._handle_adaptive_learning(payload)
            elif 'AODS-THREAT-INTEL' in str(payload):
                self._handle_threat_intelligence(payload)
            else:
                # Standard vulnerability detection
                self._handle_standard_detection(payload)
                
        except Exception as e:
            self.logger.error(f"Send message handling error: {e}")
    
    def _handle_ml_prediction(self, payload: Dict[str, Any]) -> None:
        """Handle ML prediction messages."""
        vulnerability = {
            'type': 'ml_prediction',
            'confidence': payload.get('confidence', 0.0),
            'pattern': payload.get('pattern', ''),
            'evidence': payload.get('evidence', ''),
            'timestamp': datetime.now().isoformat(),
            'script_name': self.script_name
        }
        
        self.vulnerabilities_found.append(vulnerability)
        self.result_collector.add_vulnerability(vulnerability)
        
        self.logger.info(f"ML prediction detected: {vulnerability['pattern']} "
                        f"(confidence: {vulnerability['confidence']})")
    
    def _handle_cve_detection(self, payload: Dict[str, Any]) -> None:
        """Handle CVE-targeted detection messages."""
        vulnerability = {
            'type': 'cve_detection',
            'cve_id': payload.get('cve_id', ''),
            'pattern': payload.get('pattern', ''),
            'evidence': payload.get('evidence', ''),
            'severity': payload.get('severity', 'MEDIUM'),
            'timestamp': datetime.now().isoformat(),
            'script_name': self.script_name
        }
        
        self.vulnerabilities_found.append(vulnerability)
        self.result_collector.add_vulnerability(vulnerability)
        
        self.logger.warning(f"CVE pattern detected: {vulnerability['cve_id']} - {vulnerability['pattern']}")
    
    def _handle_adaptive_learning(self, payload: Dict[str, Any]) -> None:
        """Handle adaptive learning messages."""
        learning_data = {
            'type': 'adaptive_learning',
            'confidence': payload.get('confidence', 0.0),
            'method_signature': payload.get('method_signature', ''),
            'learning_iteration': payload.get('learning_iteration', 0),
            'timestamp': datetime.now().isoformat(),
            'script_name': self.script_name
        }
        
        self.result_collector.add_learning_data(learning_data)
        
        self.logger.debug(f"Adaptive learning update: {learning_data['method_signature']} "
                         f"(confidence: {learning_data['confidence']})")
    
    def _handle_threat_intelligence(self, payload: Dict[str, Any]) -> None:
        """Handle threat intelligence messages."""
        threat = {
            'type': 'threat_intelligence',
            'threat_id': payload.get('threat_id', ''),
            'severity': payload.get('severity', 'MEDIUM'),
            'cve_references': payload.get('cve_references', []),
            'evidence': payload.get('evidence', ''),
            'timestamp': datetime.now().isoformat(),
            'script_name': self.script_name
        }
        
        self.vulnerabilities_found.append(threat)
        self.result_collector.add_vulnerability(threat)
        
        self.logger.warning(f"Threat intelligence match: {threat['threat_id']}")
    
    def _handle_standard_detection(self, payload: Dict[str, Any]) -> None:
        """Handle standard vulnerability detection messages."""
        vulnerability = {
            'type': 'standard_detection',
            'description': str(payload),
            'timestamp': datetime.now().isoformat(),
            'script_name': self.script_name
        }
        
        self.vulnerabilities_found.append(vulnerability)
        self.result_collector.add_vulnerability(vulnerability)
    
    def _handle_error_message(self, description: str) -> None:
        """Handle error messages from scripts."""
        self.logger.error(f"Script error: {description}")
        
        error_info = {
            'type': 'script_error',
            'description': description,
            'timestamp': datetime.now().isoformat(),
            'script_name': self.script_name
        }
        
        self.result_collector.add_error(error_info)
    
    def get_results(self) -> FridaAnalysisResults:
        """Get analysis results from this message handler."""
        return FridaAnalysisResults(
            script_name=self.script_name,
            execution_success=len(self.vulnerabilities_found) > 0,
            execution_time=0.0,  # Will be set by caller
            messages_received=self.messages_received,
            vulnerabilities_detected=self.vulnerabilities_found
        )


class ResultCollectionManager:
    """Manages collection and aggregation of results from multiple Frida scripts."""
    
    def __init__(self):
        """Initialize result collection manager."""
        self.vulnerabilities = []
        self.learning_data = []
        self.errors = []
        self.script_results = {}
        self.logger = logging.getLogger(__name__)
    
    def add_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """Add a vulnerability finding."""
        self.vulnerabilities.append(vulnerability)
    
    def add_learning_data(self, learning_data: Dict[str, Any]) -> None:
        """Add adaptive learning data."""
        self.learning_data.append(learning_data)
    
    def add_error(self, error_info: Dict[str, Any]) -> None:
        """Add error information."""
        self.errors.append(error_info)
    
    def add_script_result(self, script_name: str, result: FridaAnalysisResults) -> None:
        """Add results from a specific script."""
        self.script_results[script_name] = result
    
    def get_aggregated_results(self) -> Dict[str, Any]:
        """Get aggregated results from all scripts."""
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities_by_type': self._group_vulnerabilities_by_type(),
            'ml_predictions': len([v for v in self.vulnerabilities if v.get('type') == 'ml_prediction']),
            'cve_detections': len([v for v in self.vulnerabilities if v.get('type') == 'cve_detection']),
            'threat_intelligence_matches': len([v for v in self.vulnerabilities if v.get('type') == 'threat_intelligence']),
            'adaptive_learning_updates': len(self.learning_data),
            'script_errors': len(self.errors),
            'scripts_executed': len(self.script_results),
            'vulnerabilities': self.vulnerabilities,
            'learning_data': self.learning_data,
            'errors': self.errors,
            'script_results': self.script_results
        }
    
    def _group_vulnerabilities_by_type(self) -> Dict[str, int]:
        """Group vulnerabilities by type."""
        type_counts = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        return type_counts


class AODSFridaScriptLoader:
    """AODS-compatible script loader for AI/ML enhanced Frida scripts."""
    
    def __init__(self, config: Optional[RuntimeDecryptionConfig] = None):
        """Initialize AODS script loader."""
        self.config = config or RuntimeDecryptionConfig()
        self.logger = logging.getLogger(__name__)
        self.result_collector = ResultCollectionManager()
        
        # Initialize generators
        self.base_generator = FridaScriptGenerator(self.config)
        self.ai_ml_generator = None
        
        if AI_ML_ENHANCEMENT_AVAILABLE and self.config.enable_ai_ml_enhancement:
            try:
                ai_ml_config = self._load_ai_ml_config()
                self.ai_ml_generator = create_ai_ml_enhanced_generator(ai_ml_config)
                self.logger.info("✅ AI/ML enhanced script loader initialized")
            except Exception as e:
                self.logger.warning(f"⚠️ AI/ML enhancement initialization failed: {e}")
    
    def _load_ai_ml_config(self) -> Dict[str, Any]:
        """Load AI/ML configuration."""
        try:
            import yaml
            config_path = Path(__file__).parent / "ai_ml_config.yaml"
            
            if config_path.exists():
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f)
            else:
                return {}
        except Exception as e:
            self.logger.warning(f"Failed to load AI/ML config: {e}")
            return {}
    
    async def generate_enhanced_script(self, 
                                     findings: List[RuntimeDecryptionFinding],
                                     script_name: str = "runtime_decryption_analysis") -> Tuple[str, FridaScriptInfo]:
        """Generate enhanced Frida script with AI/ML capabilities."""
        start_time = time.time()
        
        try:
            if self.ai_ml_generator:
                # Use AI/ML enhanced generation
                context = AIMLScriptGenerationContext(
                    findings=findings,
                    enable_ml_hook_selection=True,
                    enable_cve_correlation=True,
                    ml_confidence_threshold=0.7
                )
                
                result = await self.ai_ml_generator.generate_ai_ml_enhanced_script(findings, context)
                
                script_info = FridaScriptInfo(
                    script_name=script_name,
                    script_type="ai_ml_enhanced",
                    script_content=result.script_content,
                    generation_time=time.time() - start_time,
                    hooks_count=len(result.hooks_generated),
                    ml_recommendations=len(result.ml_hook_recommendations),
                    cve_correlations=len(result.cve_correlations),
                    confidence_score=result.intelligence_metadata.get('average_confidence', 0.0)
                )
                
                self.logger.info(f"🤖 AI/ML enhanced script generated: {script_name}")
                return result.script_content, script_info
                
            else:
                # Fallback to base generator
                result = self.base_generator.generate_script(findings)
                
                script_info = FridaScriptInfo(
                    script_name=script_name,
                    script_type="base",
                    script_content=result.script_content,
                    generation_time=time.time() - start_time,
                    hooks_count=len(result.hooks_generated)
                )
                
                self.logger.info(f"📝 Base script generated: {script_name}")
                return result.script_content, script_info
                
        except Exception as e:
            self.logger.error(f"❌ Script generation failed: {e}")
            
            # Generate minimal fallback script
            fallback_script = """
            Java.perform(function() {
                console.log("[+] AODS Runtime Decryption Analysis - Fallback Script");
                console.log("[!] AI/ML enhanced generation failed, using fallback");
            });
            """
            
            script_info = FridaScriptInfo(
                script_name=script_name,
                script_type="fallback",
                script_content=fallback_script,
                generation_time=time.time() - start_time,
                hooks_count=0
            )
            
            return fallback_script, script_info
    
    def create_message_handler(self, script_name: str) -> Callable:
        """Create message handler for a script."""
        handler = EnhancedScriptMessageHandler(script_name, self.result_collector)
        return lambda message, data=None: handler.handle_message(message, data)
    
    def get_script_results(self) -> Dict[str, Any]:
        """Get aggregated results from all loaded scripts."""
        return self.result_collector.get_aggregated_results()


class FridaIntegrationAdapter:
    """
    Main adapter for integrating AI/ML enhanced Frida scripts with AODS Frida framework.
    
    Provides seamless integration with existing AODS Frida infrastructure while
    adding AI/ML enhancement capabilities with graceful fallback support.
    """
    
    def __init__(self, package_name: str, config: Optional[RuntimeDecryptionConfig] = None):
        """Initialize Frida integration adapter."""
        self.package_name = package_name
        self.config = config or RuntimeDecryptionConfig()
        self.logger = logging.getLogger(__name__)
        
        # Initialize script loader
        self.script_loader = AODSFridaScriptLoader(self.config)
        
        # AODS Frida framework integration
        self.script_manager = None
        self.analysis_orchestrator = None
        self.unified_manager = None
        
        self._initialize_aods_integration()
        
        # Script tracking
        self.loaded_scripts = {}
        self.execution_results = {}
        
    def _initialize_aods_integration(self):
        """Initialize integration with AODS Frida framework."""
        try:
            if AODS_FRIDA_FRAMEWORK_AVAILABLE:
                self.script_manager = CoreScriptManager()
                self.analysis_orchestrator = AnalysisOrchestrator(self.package_name)
                self.logger.info("✅ AODS Frida framework integration initialized")
            
            if UNIFIED_FRIDA_AVAILABLE:
                self.unified_manager = UnifiedFridaManager(
                    package_name=self.package_name,
                    strategy="enhanced"
                )
                self.logger.info("✅ Unified Frida manager integration initialized")
                
        except Exception as e:
            self.logger.warning(f"⚠️ AODS Frida framework integration failed: {e}")
    
    async def load_enhanced_runtime_analysis_script(self, 
                                                  findings: List[RuntimeDecryptionFinding],
                                                  session: Any = None) -> bool:
        """
        Load AI/ML enhanced runtime analysis script into AODS Frida framework.
        
        Args:
            findings: Runtime decryption findings to generate script for
            session: Active Frida session (optional, will use script_manager session if available)
            
        Returns:
            bool: True if script loaded successfully
        """
        script_name = "aods_runtime_decryption_analysis"
        
        try:
            # Generate enhanced script
            script_content, script_info = await self.script_loader.generate_enhanced_script(
                findings, script_name
            )
            
            # Store script info
            self.loaded_scripts[script_name] = script_info
            
            # Load script using AODS framework
            success = False
            
            # Try ScriptManager integration
            if self.script_manager and hasattr(self.script_manager, 'load_custom_script'):
                try:
                    # Set session if provided
                    if session:
                        self.script_manager.set_session(session)
                    
                    # Create message handler
                    message_handler = self.script_loader.create_message_handler(script_name)
                    
                    # Load script via ScriptManager
                    success = self.script_manager.load_custom_script(
                        script_name, 
                        script_content, 
                        message_handler
                    )
                    
                    if success:
                        self.logger.info(f"✅ Script loaded via ScriptManager: {script_name}")
                        return True
                        
                except Exception as e:
                    self.logger.warning(f"ScriptManager loading failed: {e}")
            
            # Try UnifiedFridaManager integration
            if self.unified_manager and not success:
                try:
                    success, result = self.unified_manager.execute_script(script_content, script_name)
                    
                    if success:
                        self.logger.info(f"✅ Script executed via UnifiedFridaManager: {script_name}")
                        return True
                        
                except Exception as e:
                    self.logger.warning(f"UnifiedFridaManager execution failed: {e}")
            
            # Fallback: direct session usage
            if session and not success:
                try:
                    script = session.create_script(script_content)
                    message_handler = self.script_loader.create_message_handler(script_name)
                    script.on("message", message_handler)
                    script.load()
                    
                    self.logger.info(f"✅ Script loaded via direct session: {script_name}")
                    return True
                    
                except Exception as e:
                    self.logger.error(f"Direct session loading failed: {e}")
            
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Enhanced script loading failed: {e}")
            return False
    
    def integrate_with_analysis_orchestrator(self, 
                                           findings: List[RuntimeDecryptionFinding],
                                           duration: int = 30) -> Dict[str, Any]:
        """
        Integrate with AODS Analysis Orchestrator for comprehensive analysis.
        
        Args:
            findings: Runtime decryption findings
            duration: Analysis duration in seconds
            
        Returns:
            Dict containing analysis results
        """
        if not self.analysis_orchestrator:
            return {"error": "Analysis orchestrator not available"}
        
        try:
            # Prepare custom scripts for orchestrator
            async def prepare_custom_scripts():
                script_content, script_info = await self.script_loader.generate_enhanced_script(
                    findings, "runtime_decryption_enhanced"
                )
                return {"runtime_decryption_enhanced": script_content}
            
            # Run async script preparation
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                custom_scripts = loop.run_until_complete(prepare_custom_scripts())
            finally:
                loop.close()
            
            # Run comprehensive analysis with custom scripts
            results = self.analysis_orchestrator.run_comprehensive_analysis(
                duration=duration,
                enable_flutter=False,  # Focus on runtime decryption
                custom_scripts=custom_scripts
            )
            
            # Add our specific results
            results["runtime_decryption_analysis"] = self.script_loader.get_script_results()
            results["ai_ml_enhanced"] = self.script_loader.ai_ml_generator is not None
            
            self.logger.info("✅ Analysis orchestrator integration completed")
            return results
            
        except Exception as e:
            self.logger.error(f"❌ Analysis orchestrator integration failed: {e}")
            return {"error": str(e)}
    
    def get_integration_status(self) -> Dict[str, Any]:
        """Get status of AODS Frida framework integration."""
        return {
            "script_manager_available": self.script_manager is not None,
            "analysis_orchestrator_available": self.analysis_orchestrator is not None,
            "unified_manager_available": self.unified_manager is not None,
            "ai_ml_enhancement_available": AI_ML_ENHANCEMENT_AVAILABLE,
            "aods_frida_framework_available": AODS_FRIDA_FRAMEWORK_AVAILABLE,
            "loaded_scripts": list(self.loaded_scripts.keys()),
            "package_name": self.package_name
        }
    
    def get_analysis_results(self) -> Dict[str, Any]:
        """Get comprehensive analysis results."""
        base_results = self.script_loader.get_script_results()
        
        return {
            "integration_status": self.get_integration_status(),
            "script_analysis": base_results,
            "loaded_scripts": {name: {
                "script_type": info.script_type,
                "hooks_count": info.hooks_count,
                "ml_recommendations": info.ml_recommendations,
                "cve_correlations": info.cve_correlations,
                "confidence_score": info.confidence_score,
                "generation_time": info.generation_time
            } for name, info in self.loaded_scripts.items()},
            "summary": {
                "total_scripts_loaded": len(self.loaded_scripts),
                "ai_ml_scripts": len([s for s in self.loaded_scripts.values() if s.script_type == "ai_ml_enhanced"]),
                "total_vulnerabilities": base_results.get("total_vulnerabilities", 0),
                "ml_predictions": base_results.get("ml_predictions", 0),
                "cve_detections": base_results.get("cve_detections", 0)
            }
        }


# Factory functions for easy integration
def create_frida_integration_adapter(package_name: str, 
                                   config: Optional[RuntimeDecryptionConfig] = None) -> FridaIntegrationAdapter:
    """Factory function to create Frida integration adapter."""
    return FridaIntegrationAdapter(package_name, config)


async def load_enhanced_scripts_into_aods(package_name: str,
                                        findings: List[RuntimeDecryptionFinding],
                                        session: Any = None,
                                        config: Optional[RuntimeDecryptionConfig] = None) -> Dict[str, Any]:
    """
    Convenience function to load AI/ML enhanced scripts into AODS Frida framework.
    
    Args:
        package_name: Target package name
        findings: Runtime decryption findings
        session: Active Frida session (optional)
        config: Configuration (optional)
        
    Returns:
        Dict containing loading results and analysis information
    """
    adapter = create_frida_integration_adapter(package_name, config)
    
    # Load enhanced script
    success = await adapter.load_enhanced_runtime_analysis_script(findings, session)
    
    # Get results
    results = adapter.get_analysis_results()
    results["loading_success"] = success
    
    return results


if __name__ == "__main__":
    # Integration test
    print("🔗 AODS Frida Integration Adapter")
    print(f"AI/ML Enhancement Available: {AI_ML_ENHANCEMENT_AVAILABLE}")
    print(f"AODS Frida Framework Available: {AODS_FRIDA_FRAMEWORK_AVAILABLE}")
    print(f"Unified Frida Available: {UNIFIED_FRIDA_AVAILABLE}")
    
    # Test adapter creation
    try:
        adapter = create_frida_integration_adapter("com.example.test")
        status = adapter.get_integration_status()
        print(f"Integration Status: {status}")
        print("✅ Frida integration adapter created successfully")
    except Exception as e:
        print(f"❌ Integration adapter creation failed: {e}") 