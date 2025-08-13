#!/usr/bin/env python3
"""
Unified Hybrid Analysis Manager

Combines static and dynamic analysis into intelligent hybrid workflows
that maximize analysis coverage and efficiency.

KEY FEATURES:
- Intelligent hybrid analysis workflows
- Static-dynamic analysis coordination
- Adaptive analysis based on findings
- orchestration and scheduling
- Result correlation and synthesis
- 100% backward compatibility with existing systems
"""

import logging
import time
import threading
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple, Union
from dataclasses import dataclass
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base_manager import BaseAnalysisManager, AnalysisManagerConfig, ManagerStatus

class HybridStrategy(Enum):
    """Hybrid analysis execution strategies."""
    AUTO = "auto"                       # Automatic strategy selection
    FULL_HYBRID = "full_hybrid"         # Full static + dynamic analysis
    STATIC_GUIDED = "static_guided"     # Static analysis guides dynamic
    DYNAMIC_GUIDED = "dynamic_guided"   # Dynamic analysis guides static
    PARALLEL_HYBRID = "parallel_hybrid" # Parallel static and dynamic
    SEQUENTIAL_HYBRID = "sequential_hybrid"  # Sequential static then dynamic
    ADAPTIVE_HYBRID = "adaptive_hybrid" # Adaptive based on findings
    STATIC_ONLY = "static_only"         # Static only fallback

@dataclass
class HybridConfig:
    """Configuration for hybrid analysis strategies."""
    enable_static_analysis: bool = True
    enable_dynamic_analysis: bool = True
    static_timeout: int = 300
    dynamic_timeout: int = 120
    enable_parallel_execution: bool = True
    enable_adaptive_analysis: bool = True
    correlation_threshold: float = 0.7
    max_analysis_rounds: int = 3
    enable_finding_correlation: bool = True
    enable_guided_analysis: bool = True
    static_priority: int = 50
    dynamic_priority: int = 50

class BaseHybridStrategy(ABC):
    """Base class for hybrid analysis strategies."""
    
    def __init__(self, package_name: str, config: HybridConfig):
        self.package_name = package_name
        self.config = config
        self.logger = logging.getLogger(f"{self.__class__.__name__}_{package_name}")
        self.analysis_results = {}
        self.analysis_complete = False
        self.static_manager = None
        self.dynamic_manager = None
        self.correlation_engine = HybridCorrelationEngine()
    
    @abstractmethod
    def start_hybrid_analysis(self, apk_path: str, extracted_path: str = None) -> bool:
        """Start hybrid analysis."""
        pass
    
    @abstractmethod
    def check_analysis_status(self) -> bool:
        """Check if analysis is running."""
        pass
    
    @abstractmethod
    def stop_analysis(self) -> bool:
        """Stop analysis."""
        pass
    
    @abstractmethod
    def get_hybrid_results(self) -> Dict[str, Any]:
        """Get hybrid analysis results."""
        pass
    
    def get_strategy_info(self) -> Dict[str, Any]:
        """Get strategy information."""
        return {
            "name": self.__class__.__name__,
            "package_name": self.package_name,
            "analysis_complete": self.analysis_complete,
            "managers_available": {
                "static": self.static_manager is not None,
                "dynamic": self.dynamic_manager is not None
            },
            "capabilities": self._get_capabilities()
        }
    
    @abstractmethod
    def _get_capabilities(self) -> List[str]:
        """Get strategy capabilities."""
        pass
    
    def _initialize_managers(self) -> None:
        """Initialize static and dynamic managers."""
        try:
            # Initialize static manager
            if self.config.enable_static_analysis:
                from .static_manager import UnifiedStaticManager
                from .base_manager import AnalysisManagerConfig
                
                static_config = AnalysisManagerConfig(
                    package_name=self.package_name,
                    strategy="auto",
                    timeout_seconds=self.config.static_timeout
                )
                self.static_manager = UnifiedStaticManager(static_config)
                
            # Initialize dynamic manager
            if self.config.enable_dynamic_analysis:
                from .dynamic_manager import UnifiedDynamicManager
                from .base_manager import AnalysisManagerConfig
                
                dynamic_config = AnalysisManagerConfig(
                    package_name=self.package_name,
                    strategy="auto",
                    timeout_seconds=self.config.dynamic_timeout
                )
                self.dynamic_manager = UnifiedDynamicManager(dynamic_config)
                
        except Exception as e:
            self.logger.error(f"Manager initialization failed: {e}")

class FullHybridStrategy(BaseHybridStrategy):
    """Full hybrid strategy combining comprehensive static and dynamic analysis."""
    
    def __init__(self, package_name: str, config: HybridConfig):
        super().__init__(package_name, config)
        self._initialize_managers()
    
    def start_hybrid_analysis(self, apk_path: str, extracted_path: str = None) -> bool:
        """Start full hybrid analysis."""
        try:
            self.logger.info("Starting full hybrid analysis...")
            
            if self.config.enable_parallel_execution:
                return self._run_parallel_analysis(apk_path, extracted_path)
            else:
                return self._run_sequential_analysis(apk_path, extracted_path)
                
        except Exception as e:
            self.logger.error(f"Full hybrid analysis failed: {e}")
            return False
    
    def _run_parallel_analysis(self, apk_path: str, extracted_path: str = None) -> bool:
        """Run static and dynamic analysis in parallel."""
        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = {}
                
                # Submit static analysis
                if self.static_manager:
                    static_future = executor.submit(
                        self._run_static_analysis, apk_path, extracted_path
                    )
                    futures["static"] = static_future
                
                # Submit dynamic analysis
                if self.dynamic_manager:
                    dynamic_future = executor.submit(
                        self._run_dynamic_analysis
                    )
                    futures["dynamic"] = dynamic_future
                
                # Collect results
                results = {}
                for analysis_type, future in futures.items():
                    try:
                        success, result = future.result(timeout=max(
                            self.config.static_timeout, 
                            self.config.dynamic_timeout
                        ))
                        results[analysis_type] = {"success": success, "data": result}
                    except Exception as e:
                        self.logger.error(f"{analysis_type} analysis failed: {e}")
                        results[analysis_type] = {"success": False, "error": str(e)}
                
                # Correlate results
                self.analysis_results = self._correlate_parallel_results(results)
                self.analysis_complete = True
                
                return any(r["success"] for r in results.values())
                
        except Exception as e:
            self.logger.error(f"Parallel analysis failed: {e}")
            return False
    
    def _run_sequential_analysis(self, apk_path: str, extracted_path: str = None) -> bool:
        """Run static analysis followed by dynamic analysis."""
        try:
            # Phase 1: Static Analysis
            static_success = False
            static_results = {}
            
            if self.static_manager:
                self.logger.info("Phase 1: Running static analysis...")
                static_success, static_results = self._run_static_analysis(apk_path, extracted_path)
            
            # Phase 2: Dynamic Analysis (guided by static findings)
            dynamic_success = False
            dynamic_results = {}
            
            if self.dynamic_manager:
                self.logger.info("Phase 2: Running dynamic analysis...")
                # Use static results to guide dynamic analysis
                dynamic_success, dynamic_results = self._run_guided_dynamic_analysis(static_results)
            
            # Phase 3: Correlation and Synthesis
            self.analysis_results = self._correlate_sequential_results(
                static_results, dynamic_results
            )
            self.analysis_complete = True
            
            return static_success or dynamic_success
            
        except Exception as e:
            self.logger.error(f"Sequential analysis failed: {e}")
            return False
    
    def _run_static_analysis(self, apk_path: str, extracted_path: str = None) -> Tuple[bool, Dict[str, Any]]:
        """Run static analysis component."""
        try:
            if not self.static_manager:
                return False, {"error": "Static manager not available"}
            
            # Start static analysis
            if not self.static_manager.start_connection():
                return False, {"error": "Failed to start static analysis"}
            
            # Perform APK analysis
            success, results = self.static_manager.analyze_apk(apk_path, extracted_path)
            
            self.logger.info(f"Static analysis completed: success={success}")
            return success, results
            
        except Exception as e:
            self.logger.error(f"Static analysis error: {e}")
            return False, {"error": str(e)}
    
    def _run_dynamic_analysis(self) -> Tuple[bool, Dict[str, Any]]:
        """Run dynamic analysis component."""
        try:
            if not self.dynamic_manager:
                return False, {"error": "Dynamic manager not available"}
            
            # Start dynamic analysis
            if not self.dynamic_manager.start_connection():
                return False, {"error": "Failed to start dynamic analysis"}
            
            # Run analysis
            success, _ = self.dynamic_manager.execute_command("start_analysis")
            
            if success:
                # Wait for analysis completion
                time.sleep(self.config.dynamic_timeout)
                
                # Get results
                _, results = self.dynamic_manager.execute_command("get_results")
                
                self.logger.info("Dynamic analysis completed successfully")
                return True, results
            else:
                return False, {"error": "Dynamic analysis failed to start"}
                
        except Exception as e:
            self.logger.error(f"Dynamic analysis error: {e}")
            return False, {"error": str(e)}
    
    def _run_guided_dynamic_analysis(self, static_results: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Run dynamic analysis guided by static findings."""
        try:
            # Extract guidance from static results
            guidance = self._extract_static_guidance(static_results)
            
            # Run standard dynamic analysis
            success, dynamic_results = self._run_dynamic_analysis()
            
            if success and guidance:
                # Enhance dynamic analysis with static guidance
                dynamic_results["guidance_applied"] = guidance
                dynamic_results["guided_analysis"] = True
            
            return success, dynamic_results
            
        except Exception as e:
            self.logger.error(f"Guided dynamic analysis error: {e}")
            return False, {"error": str(e)}
    
    def _extract_static_guidance(self, static_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract guidance for dynamic analysis from static results."""
        guidance = {
            "focus_areas": [],
            "suspicious_components": [],
            "security_concerns": []
        }
        
        try:
            # Analyze static findings for dynamic guidance
            findings = static_results.get("findings", {})
            
            # Look for exported components
            manifest_data = findings.get("manifest", {})
            if manifest_data.get("security_findings"):
                for finding in manifest_data["security_findings"]:
                    if finding.get("type") == "exported_activity":
                        guidance["focus_areas"].append("exported_components")
                        guidance["suspicious_components"].append(finding.get("component"))
            
            # Look for security vulnerabilities
            source_data = findings.get("source_code", {})
            if source_data.get("security_findings"):
                guidance["focus_areas"].append("runtime_security")
                guidance["security_concerns"].extend([
                    f.get("type") for f in source_data["security_findings"]
                ])
            
            # Look for secrets
            if source_data.get("secrets_detected"):
                guidance["focus_areas"].append("credential_testing")
            
        except Exception as e:
            self.logger.warning(f"Failed to extract guidance: {e}")
        
        return guidance
    
    def _correlate_parallel_results(self, results: Dict[str, Dict]) -> Dict[str, Any]:
        """Correlate results from parallel analysis."""
        correlated = {
            "analysis_type": "parallel_hybrid",
            "package_name": self.package_name,
            "timestamp": time.time(),
            "static_results": results.get("static", {}),
            "dynamic_results": results.get("dynamic", {}),
            "correlation": {},
            "combined_findings": [],
            "overall_risk": "UNKNOWN"
        }
        
        try:
            # Use correlation engine
            correlation = self.correlation_engine.correlate_findings(
                results.get("static", {}).get("data", {}),
                results.get("dynamic", {}).get("data", {})
            )
            
            correlated["correlation"] = correlation
            correlated["combined_findings"] = correlation.get("combined_findings", [])
            correlated["overall_risk"] = correlation.get("overall_risk", "UNKNOWN")
            
        except Exception as e:
            self.logger.error(f"Correlation failed: {e}")
        
        return correlated
    
    def _correlate_sequential_results(self, static_results: Dict, dynamic_results: Dict) -> Dict[str, Any]:
        """Correlate results from sequential analysis."""
        correlated = {
            "analysis_type": "sequential_hybrid",
            "package_name": self.package_name,
            "timestamp": time.time(),
            "static_results": static_results,
            "dynamic_results": dynamic_results,
            "correlation": {},
            "analysis_flow": "static_then_dynamic",
            "combined_findings": [],
            "overall_risk": "UNKNOWN"
        }
        
        try:
            # Enhanced correlation for sequential analysis
            correlation = self.correlation_engine.correlate_sequential_findings(
                static_results, dynamic_results
            )
            
            correlated["correlation"] = correlation
            correlated["combined_findings"] = correlation.get("combined_findings", [])
            correlated["overall_risk"] = correlation.get("overall_risk", "UNKNOWN")
            
        except Exception as e:
            self.logger.error(f"Sequential correlation failed: {e}")
        
        return correlated
    
    def check_analysis_status(self) -> bool:
        """Check if hybrid analysis is running."""
        static_running = False
        dynamic_running = False
        
        if self.static_manager:
            static_running = self.static_manager.is_healthy()
        
        if self.dynamic_manager:
            dynamic_running = self.dynamic_manager.check_connection()
        
        return static_running or dynamic_running
    
    def stop_analysis(self) -> bool:
        """Stop hybrid analysis."""
        try:
            success = True
            
            if self.static_manager:
                if not self.static_manager.stop_connection():
                    success = False
            
            if self.dynamic_manager:
                if not self.dynamic_manager.stop_connection():
                    success = False
            
            self.analysis_complete = True
            return success
            
        except Exception as e:
            self.logger.error(f"Error stopping hybrid analysis: {e}")
            return False
    
    def get_hybrid_results(self) -> Dict[str, Any]:
        """Get comprehensive hybrid analysis results."""
        return self.analysis_results
    
    def _get_capabilities(self) -> List[str]:
        """Get full hybrid strategy capabilities."""
        return [
            "static_analysis",
            "dynamic_analysis",
            "parallel_execution",
            "sequential_execution",
            "guided_analysis",
            "finding_correlation",
            "risk_assessment",
            "comprehensive_coverage"
        ]

class StaticOnlyStrategy(BaseHybridStrategy):
    """Static-only hybrid strategy for fallback scenarios."""
    
    def __init__(self, package_name: str, config: HybridConfig):
        super().__init__(package_name, config)
        self.config.enable_dynamic_analysis = False
        self._initialize_managers()
    
    def start_hybrid_analysis(self, apk_path: str, extracted_path: str = None) -> bool:
        """Start static-only analysis."""
        try:
            self.logger.info("Starting static-only hybrid analysis...")
            
            if not self.static_manager:
                return False
            
            # Run static analysis
            success, results = self._run_static_analysis(apk_path, extracted_path)
            
            # Format as hybrid results
            self.analysis_results = {
                "analysis_type": "static_only_hybrid",
                "package_name": self.package_name,
                "timestamp": time.time(),
                "static_results": results,
                "dynamic_results": {"status": "not_available"},
                "limitations": ["Dynamic analysis not available"],
                "overall_risk": results.get("risk_level", "UNKNOWN")
            }
            
            self.analysis_complete = True
            return success
            
        except Exception as e:
            self.logger.error(f"Static-only hybrid analysis failed: {e}")
            return False
    
    def _run_static_analysis(self, apk_path: str, extracted_path: str = None) -> Tuple[bool, Dict[str, Any]]:
        """Run static analysis."""
        try:
            if not self.static_manager.start_connection():
                return False, {"error": "Failed to start static analysis"}
            
            return self.static_manager.analyze_apk(apk_path, extracted_path)
            
        except Exception as e:
            return False, {"error": str(e)}
    
    def check_analysis_status(self) -> bool:
        """Check static analysis status."""
        return self.analysis_complete
    
    def stop_analysis(self) -> bool:
        """Stop static analysis."""
        if self.static_manager:
            return self.static_manager.stop_connection()
        return True
    
    def get_hybrid_results(self) -> Dict[str, Any]:
        """Get static-only results."""
        return self.analysis_results
    
    def _get_capabilities(self) -> List[str]:
        """Get static-only capabilities."""
        return [
            "static_analysis",
            "manifest_analysis",
            "source_code_analysis",
            "basic_risk_assessment",
            "fallback_mode"
        ]

class HybridCorrelationEngine:
    """Engine for correlating static and dynamic analysis findings."""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def correlate_findings(self, static_results: Dict, dynamic_results: Dict) -> Dict[str, Any]:
        """Correlate findings from static and dynamic analysis."""
        correlation = {
            "correlation_timestamp": time.time(),
            "static_findings_count": 0,
            "dynamic_findings_count": 0,
            "correlated_findings": [],
            "combined_findings": [],
            "overall_risk": "LOW",
            "confidence": 0.0
        }
        
        try:
            # Count findings
            static_findings = self._extract_static_findings(static_results)
            dynamic_findings = self._extract_dynamic_findings(dynamic_results)
            
            correlation["static_findings_count"] = len(static_findings)
            correlation["dynamic_findings_count"] = len(dynamic_findings)
            
            # Find correlations
            correlated = self._find_correlations(static_findings, dynamic_findings)
            correlation["correlated_findings"] = correlated
            
            # Combine all findings
            all_findings = static_findings + dynamic_findings
            correlation["combined_findings"] = self._deduplicate_findings(all_findings)
            
            # Calculate overall risk
            correlation["overall_risk"] = self._calculate_overall_risk(correlation["combined_findings"])
            
            # Calculate confidence
            correlation["confidence"] = self._calculate_correlation_confidence(correlation)
            
        except Exception as e:
            self.logger.error(f"Correlation failed: {e}")
        
        return correlation
    
    def correlate_sequential_findings(self, static_results: Dict, dynamic_results: Dict) -> Dict[str, Any]:
        """Enhanced correlation for sequential analysis."""
        correlation = self.correlate_findings(static_results, dynamic_results)
        
        # Add sequential-specific analysis
        correlation["analysis_flow"] = "sequential"
        correlation["static_guided_dynamic"] = dynamic_results.get("guided_analysis", False)
        
        if dynamic_results.get("guidance_applied"):
            correlation["guidance_effectiveness"] = self._assess_guidance_effectiveness(
                dynamic_results["guidance_applied"],
                self._extract_dynamic_findings(dynamic_results)
            )
        
        return correlation
    
    def _extract_static_findings(self, static_results: Dict) -> List[Dict[str, Any]]:
        """Extract findings from static analysis results."""
        findings = []
        
        try:
            if "findings" in static_results:
                # Extract manifest findings
                manifest_findings = static_results["findings"].get("manifest", {}).get("security_findings", [])
                for finding in manifest_findings:
                    findings.append({
                        "source": "static_manifest",
                        "type": finding.get("type"),
                        "severity": finding.get("severity", "MEDIUM"),
                        "component": finding.get("component"),
                        "confidence": 0.8
                    })
                
                # Extract source code findings
                source_findings = static_results["findings"].get("source_code", {}).get("security_findings", [])
                for finding in source_findings:
                    findings.append({
                        "source": "static_source",
                        "type": finding.get("type"),
                        "severity": finding.get("severity", "MEDIUM"),
                        "file": finding.get("file"),
                        "line": finding.get("line"),
                        "confidence": 0.7
                    })
                
                # Extract secrets
                secrets = static_results["findings"].get("source_code", {}).get("secrets_detected", [])
                for secret in secrets:
                    findings.append({
                        "source": "static_secrets",
                        "type": "hardcoded_secret",
                        "severity": "HIGH",
                        "file": secret.get("file"),
                        "confidence": secret.get("confidence", 0.6)
                    })
                    
        except Exception as e:
            self.logger.warning(f"Failed to extract static findings: {e}")
        
        return findings
    
    def _extract_dynamic_findings(self, dynamic_results: Dict) -> List[Dict[str, Any]]:
        """Extract findings from dynamic analysis results."""
        findings = []
        
        try:
            # Extract Frida findings
            if "frida_results" in dynamic_results:
                frida_results = dynamic_results["frida_results"]
                for category, results in frida_results.items():
                    if isinstance(results, list):
                        for result in results:
                            findings.append({
                                "source": "dynamic_frida",
                                "category": category,
                                "type": result.get("type", "runtime_finding"),
                                "severity": "MEDIUM",
                                "confidence": 0.8
                            })
            
            # Extract combined findings
            if "combined_findings" in dynamic_results:
                for finding in dynamic_results["combined_findings"]:
                    findings.append({
                        "source": f"dynamic_{finding.get('source')}",
                        "category": finding.get("category"),
                        "type": "dynamic_finding",
                        "severity": "MEDIUM",
                        "confidence": finding.get("confidence", 0.5)
                    })
                    
        except Exception as e:
            self.logger.warning(f"Failed to extract dynamic findings: {e}")
        
        return findings
    
    def _find_correlations(self, static_findings: List, dynamic_findings: List) -> List[Dict[str, Any]]:
        """Find correlations between static and dynamic findings."""
        correlations = []
        
        for static_finding in static_findings:
            for dynamic_finding in dynamic_findings:
                correlation_score = self._calculate_correlation_score(static_finding, dynamic_finding)
                
                if correlation_score > 0.5:  # Threshold for correlation
                    correlations.append({
                        "static_finding": static_finding,
                        "dynamic_finding": dynamic_finding,
                        "correlation_score": correlation_score,
                        "correlation_type": self._determine_correlation_type(static_finding, dynamic_finding)
                    })
        
        return correlations
    
    def _calculate_correlation_score(self, static_finding: Dict, dynamic_finding: Dict) -> float:
        """Calculate correlation score between two findings."""
        score = 0.0
        
        # Type correlation
        if static_finding.get("type") == dynamic_finding.get("type"):
            score += 0.4
        
        # Category correlation
        if static_finding.get("category") == dynamic_finding.get("category"):
            score += 0.3
        
        # Component correlation
        if static_finding.get("component") == dynamic_finding.get("component"):
            score += 0.3
        
        return min(1.0, score)
    
    def _determine_correlation_type(self, static_finding: Dict, dynamic_finding: Dict) -> str:
        """Determine the type of correlation between findings."""
        if static_finding.get("type") == dynamic_finding.get("type"):
            return "direct_match"
        elif static_finding.get("category") == dynamic_finding.get("category"):
            return "category_match"
        else:
            return "contextual_match"
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings."""
        unique_findings = []
        seen_findings = set()
        
        for finding in findings:
            # Create a simple hash for deduplication
            finding_key = f"{finding.get('type')}_{finding.get('source')}_{finding.get('component', '')}"
            
            if finding_key not in seen_findings:
                seen_findings.add(finding_key)
                unique_findings.append(finding)
        
        return unique_findings
    
    def _calculate_overall_risk(self, findings: List[Dict[str, Any]]) -> str:
        """Calculate overall risk based on all findings."""
        if not findings:
            return "LOW"
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for finding in findings:
            severity = finding.get("severity", "LOW")
            severity_counts[severity] += 1
        
        if severity_counts["CRITICAL"] > 0:
            return "CRITICAL"
        elif severity_counts["HIGH"] > 3:
            return "HIGH"
        elif severity_counts["HIGH"] > 0 or severity_counts["MEDIUM"] > 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _calculate_correlation_confidence(self, correlation: Dict) -> float:
        """Calculate confidence in the correlation."""
        static_count = correlation["static_findings_count"]
        dynamic_count = correlation["dynamic_findings_count"]
        correlated_count = len(correlation["correlated_findings"])
        
        if static_count == 0 and dynamic_count == 0:
            return 0.0
        
        total_findings = static_count + dynamic_count
        correlation_ratio = correlated_count / max(1, total_findings)
        
        # Base confidence on correlation ratio and finding diversity
        confidence = 0.5 + (correlation_ratio * 0.5)
        
        # Boost confidence if we have both static and dynamic findings
        if static_count > 0 and dynamic_count > 0:
            confidence += 0.2
        
        return min(1.0, confidence)
    
    def _assess_guidance_effectiveness(self, guidance: Dict, dynamic_findings: List) -> Dict[str, Any]:
        """Assess how effective static guidance was for dynamic analysis."""
        effectiveness = {
            "guidance_followed": False,
            "additional_findings": 0,
            "focus_areas_productive": []
        }
        
        try:
            focus_areas = guidance.get("focus_areas", [])
            
            # Check if dynamic findings align with guidance
            for finding in dynamic_findings:
                finding_category = finding.get("category", "")
                
                if any(area in finding_category for area in focus_areas):
                    effectiveness["guidance_followed"] = True
                    effectiveness["additional_findings"] += 1
            
            effectiveness["focus_areas_productive"] = focus_areas
            
        except Exception as e:
            self.logger.warning(f"Failed to assess guidance effectiveness: {e}")
        
        return effectiveness

class UnifiedHybridManager(BaseAnalysisManager):
    """
    Unified hybrid analysis manager with intelligent strategy selection.
    
    Orchestrates combined static and dynamic analysis workflows with
    comprehensive correlation and synthesis capabilities.
    """
    
    def __init__(self, config: AnalysisManagerConfig = None):
        # Initialize with default config if none provided
        if config is None:
            config = AnalysisManagerConfig(
                package_name="default",
                strategy="auto"
            )
        
        super().__init__(config)
        
        # Initialize hybrid configuration
        self.hybrid_config = HybridConfig()
        
        # Initialize strategy
        self.current_strategy: Optional[BaseHybridStrategy] = None
        self._initialize_strategy()
    
    def _initialize_strategy(self) -> None:
        """Initialize hybrid strategy based on configuration."""
        try:
            strategy_name = self.config.strategy
            
            if strategy_name == "auto":
                strategy_name = self._select_optimal_strategy()
            
            self.current_strategy = self._create_strategy(strategy_name)
            self.logger.info(f"Initialized hybrid strategy: {strategy_name}")
            
        except Exception as e:
            self.logger.error(f"Strategy initialization failed: {e}")
            # Fallback to static-only
            self.current_strategy = self._create_strategy("static_only")
    
    def _select_optimal_strategy(self) -> str:
        """Select optimal strategy based on system capabilities."""
        # Assess system capabilities
        capabilities = self._assess_system_capabilities()
        
        if capabilities["static"] and capabilities["dynamic"]:
            return "full_hybrid"
        elif capabilities["static"]:
            return "static_only"
        else:
            # Last resort fallback
            return "static_only"
    
    def _assess_system_capabilities(self) -> Dict[str, bool]:
        """Assess available system capabilities."""
        capabilities = {"static": True, "dynamic": False}  # Static always available
        
        try:
            # Check dynamic capabilities (device + tools)
            import subprocess
            
            # Check device
            device_result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=5
            )
            device_available = "device" in device_result.stdout
            
            # Check Frida
            frida_result = subprocess.run(
                ["frida", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            frida_available = frida_result.returncode == 0
            
            capabilities["dynamic"] = device_available and frida_available
            
        except Exception:
            pass
        
        return capabilities
    
    def _create_strategy(self, strategy_name: str) -> BaseHybridStrategy:
        """Create strategy instance based on name."""
        strategy_map = {
            "full_hybrid": FullHybridStrategy,
            "static_only": StaticOnlyStrategy
        }
        
        strategy_class = strategy_map.get(strategy_name)
        if not strategy_class:
            self.logger.warning(f"Unknown strategy: {strategy_name}, using static_only")
            strategy_class = StaticOnlyStrategy
        
        return strategy_class(self.config.package_name, self.hybrid_config)
    
    def start_connection(self) -> bool:
        """Start hybrid analysis using current strategy."""
        # This is a placeholder - actual analysis requires APK path
        self.connected = True
        self.status = ManagerStatus.READY
        return True
    
    def check_connection(self) -> bool:
        """Check hybrid analysis status using current strategy."""
        if not self.current_strategy:
            return False
        
        return self.current_strategy.check_analysis_status()
    
    def execute_command(self, command: str, **kwargs) -> tuple[bool, Any]:
        """Execute hybrid analysis command using current strategy."""
        if not self.current_strategy:
            return False, "No strategy available"
        
        try:
            if command == "start_hybrid_analysis":
                apk_path = kwargs.get('apk_path', '')
                extracted_path = kwargs.get('extracted_path')
                success = self.current_strategy.start_hybrid_analysis(apk_path, extracted_path)
                return success, "Hybrid analysis started" if success else "Failed to start"
            elif command == "stop_analysis":
                return self.current_strategy.stop_analysis(), "Analysis stopped"
            elif command == "get_results":
                results = self.current_strategy.get_hybrid_results()
                return True, results
            else:
                return False, f"Unknown command: {command}"
            
        except Exception as e:
            self.last_error = e
            return False, f"Command execution failed: {e}"
    
    def stop_connection(self) -> bool:
        """Stop hybrid analysis using current strategy."""
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
    
    def start_hybrid_analysis(self, apk_path: str, extracted_path: str = None) -> bool:
        """Start hybrid analysis workflow."""
        if not self.current_strategy:
            return False
        
        return self.current_strategy.start_hybrid_analysis(apk_path, extracted_path)
    
    def get_hybrid_results(self) -> Dict[str, Any]:
        """Get hybrid analysis results from current strategy."""
        if not self.current_strategy:
            return {}
        
        return self.current_strategy.get_hybrid_results()
    
    def get_strategy_info(self) -> Dict[str, Any]:
        """Get information about current strategy."""
        if not self.current_strategy:
            return {"strategy": "none", "capabilities": []}
        
        return self.current_strategy.get_strategy_info()

# Export public interface
__all__ = [
    "UnifiedHybridManager",
    "HybridStrategy",
    "HybridConfig",
    "HybridCorrelationEngine"
] 