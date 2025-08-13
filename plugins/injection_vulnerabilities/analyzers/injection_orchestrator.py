"""
Injection Vulnerability Analysis Orchestrator

This module coordinates the injection vulnerability analysis process using both
dynamic and static analysis techniques.
"""

import logging
from typing import Dict, Any, List, Optional
from enum import Enum

from core.apk_ctx import APKContext
from .dynamic_analyzer import DynamicInjectionAnalyzer
from .static_analyzer import StaticInjectionAnalyzer
from .drozer_analyzer import DrozerInjectionAnalyzer

# Import unified deduplication framework
from core.unified_deduplication_framework import (
    deduplicate_findings,
    DeduplicationStrategy,
    create_deduplication_engine
)

logger = logging.getLogger(__name__)

class AnalysisMode(Enum):
    """Analysis mode enumeration."""
    DYNAMIC_ONLY = "dynamic_only"
    STATIC_ONLY = "static_only"
    HYBRID = "hybrid"
    AUTO = "auto"

class InjectionVulnerabilityOrchestrator:
    """
    Main orchestrator for injection vulnerability analysis.
    
    Coordinates dynamic and static analysis to provide comprehensive injection
    vulnerability detection.
    """
    
    def __init__(self):
        """Initialize the orchestrator with all analysis engines."""
        self.dynamic_analyzer = DynamicInjectionAnalyzer()
        self.static_analyzer = StaticInjectionAnalyzer()
        self.drozer_analyzer = DrozerInjectionAnalyzer()
        
        # Analysis configuration
        self.analysis_mode = AnalysisMode.AUTO
        self.timeout_seconds = 30
        self.max_static_files = 1000
        
    def analyze_injection_vulnerabilities(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Perform comprehensive injection vulnerability analysis.
        
        Args:
            apk_ctx: The APKContext instance containing APK data
            
        Returns:
            Dict[str, Any]: Complete analysis results
        """
        logger.info("Starting injection vulnerability analysis orchestration")
        
        # Check for graceful shutdown support
        shutdown_available = self._check_shutdown_support()
        
        # Initialize results structure
        results = {
            "analysis_mode": self.analysis_mode.value,
            "dynamic_analysis": {},
            "static_analysis": {},
            "drozer_analysis": {},
            "vulnerabilities": [],
            "risk_assessment": {},
            "analysis_metadata": {
                "timestamp": self._get_timestamp(),
                "analyzer_version": "2.0.0",
                "analysis_type": "injection_vulnerability",
                "shutdown_available": shutdown_available
            }
        }
        
        try:
            # Check for shutdown before starting
            if shutdown_available and self._is_shutdown_requested():
                results["analysis_metadata"]["status"] = "cancelled"
                results["analysis_metadata"]["reason"] = "shutdown_requested"
                return results
            
            # Determine analysis strategy
            analysis_strategy = self._determine_analysis_strategy(apk_ctx)
            results["analysis_strategy"] = analysis_strategy
            
            # Perform dynamic analysis if available
            if analysis_strategy["use_dynamic"]:
                logger.info("Performing dynamic injection analysis")
                results["dynamic_analysis"] = self._perform_dynamic_analysis(apk_ctx)
                
                # Check for shutdown after dynamic analysis
                if shutdown_available and self._is_shutdown_requested():
                    results["analysis_metadata"]["status"] = "cancelled_after_dynamic"
                    return results
            
            # Perform static analysis if needed
            if analysis_strategy["use_static"]:
                logger.info("Performing static injection analysis")
                results["static_analysis"] = self._perform_static_analysis(apk_ctx)
                
                # Check for shutdown after static analysis
                if shutdown_available and self._is_shutdown_requested():
                    results["analysis_metadata"]["status"] = "cancelled_after_static"
                    return results
            
            # Consolidate vulnerabilities
            results["vulnerabilities"] = self._consolidate_vulnerabilities(results)
            
            # Perform risk assessment
            results["risk_assessment"] = self._perform_risk_assessment(results)
            
            # Set completion status
            results["analysis_metadata"]["status"] = "completed"
            
            logger.info("Injection vulnerability analysis orchestration completed successfully")
            return results
            
        except Exception as e:
            logger.error(f"Injection vulnerability analysis orchestration failed: {str(e)}")
            results["analysis_metadata"]["status"] = "failed"
            results["analysis_metadata"]["error"] = str(e)
            return results
    
    def _determine_analysis_strategy(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Determine the best analysis strategy based on available tools and context.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            Dict[str, Any]: Analysis strategy configuration
        """
        strategy = {
            "use_dynamic": False,
            "use_static": True,  # Always available
            "use_drozer": False,
            "primary_method": "static",
            "fallback_method": "static",
            "rationale": []
        }
        
        # Check if package name is available
        if not hasattr(apk_ctx, 'package_name') or not apk_ctx.package_name:
            strategy["rationale"].append("Package name not available - static analysis only")
            return strategy
        
        # Check Drozer availability
        if hasattr(apk_ctx, 'drozer') and apk_ctx.drozer:
            drozer_available = self.drozer_analyzer.check_drozer_availability(apk_ctx.drozer)
            if drozer_available:
                strategy["use_dynamic"] = True
                strategy["use_drozer"] = True
                strategy["primary_method"] = "dynamic"
                strategy["fallback_method"] = "static"
                strategy["rationale"].append("Drozer available - using dynamic analysis")
            else:
                strategy["rationale"].append("Drozer not available - using static analysis")
        else:
            strategy["rationale"].append("No Drozer instance - using static analysis")
        
        # Check static analysis prerequisites
        if hasattr(apk_ctx, 'jadx_output_dir') and apk_ctx.jadx_output_dir:
            strategy["rationale"].append("JADX output available for static analysis")
        else:
            strategy["rationale"].append("Limited static analysis - no JADX output")
        
        return strategy
    
    def _perform_dynamic_analysis(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Perform dynamic injection vulnerability analysis.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            Dict[str, Any]: Dynamic analysis results
        """
        results = {
            "enabled": True,
            "drozer_results": {},
            "vulnerabilities": [],
            "analysis_time": 0.0,
            "status": "pending"
        }
        
        try:
            import time
            start_time = time.time()
            
            # Perform Drozer analysis
            drozer_results = self.drozer_analyzer.analyze_injection_vulnerabilities(apk_ctx)
            results["drozer_results"] = drozer_results
            
            # Extract vulnerabilities from dynamic analysis
            if drozer_results.get("has_vulnerabilities", False):
                vulnerabilities = self.dynamic_analyzer.extract_vulnerabilities_from_drozer_results(drozer_results)
                results["vulnerabilities"] = vulnerabilities
            
            results["analysis_time"] = time.time() - start_time
            results["status"] = "completed"
            
        except Exception as e:
            results["status"] = "failed"
            results["error"] = str(e)
            logger.error(f"Dynamic analysis failed: {str(e)}")
        
        return results
    
    def _perform_static_analysis(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Perform static injection vulnerability analysis.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            Dict[str, Any]: Static analysis results
        """
        results = {
            "enabled": True,
            "manifest_analysis": {},
            "code_analysis": {},
            "vulnerabilities": [],
            "analysis_time": 0.0,
            "status": "pending"
        }
        
        try:
            import time
            start_time = time.time()
            
            # Perform static analysis
            static_results = self.static_analyzer.analyze_injection_vulnerabilities(apk_ctx)
            
            # Extract components
            results["manifest_analysis"] = static_results.get("manifest_analysis", {})
            results["code_analysis"] = static_results.get("code_analysis", {})
            results["vulnerabilities"] = static_results.get("vulnerabilities", [])
            
            results["analysis_time"] = time.time() - start_time
            results["status"] = "completed"
            
        except Exception as e:
            results["status"] = "failed"
            results["error"] = str(e)
            logger.error(f"Static analysis failed: {str(e)}")
        
        return results
    
    def _consolidate_vulnerabilities(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Consolidate vulnerabilities from all analysis methods.
        
        Args:
            results: Analysis results from all methods
            
        Returns:
            List[Dict[str, Any]]: Consolidated vulnerability list
        """
        consolidated = []
        
        # Add dynamic vulnerabilities
        dynamic_vulns = results.get("dynamic_analysis", {}).get("vulnerabilities", [])
        for vuln in dynamic_vulns:
            vuln["source"] = "dynamic"
            consolidated.append(vuln)
        
        # Add static vulnerabilities
        static_vulns = results.get("static_analysis", {}).get("vulnerabilities", [])
        for vuln in static_vulns:
            vuln["source"] = "static"
            consolidated.append(vuln)
        
        # Remove duplicates and sort by severity
        consolidated = self._deduplicate_vulnerabilities(consolidated)
        consolidated.sort(key=lambda x: self._get_severity_weight(x.get("severity", "LOW")), reverse=True)
        
        return consolidated
    
    def _perform_risk_assessment(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform risk assessment based on analysis results.
        
        Args:
            results: Complete analysis results
            
        Returns:
            Dict[str, Any]: Risk assessment
        """
        vulnerabilities = results.get("vulnerabilities", [])
        
        # Count vulnerabilities by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "LOW")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Calculate risk score
        risk_score = (
            severity_counts["CRITICAL"] * 0.4 +
            severity_counts["HIGH"] * 0.3 +
            severity_counts["MEDIUM"] * 0.2 +
            severity_counts["LOW"] * 0.1
        )
        
        # Normalize risk score
        risk_score = min(1.0, risk_score / 3.0)
        
        # Determine overall risk level
        if risk_score >= 0.8 or severity_counts["CRITICAL"] > 0:
            risk_level = "CRITICAL"
        elif risk_score >= 0.6 or severity_counts["HIGH"] > 0:
            risk_level = "HIGH"
        elif risk_score >= 0.4 or severity_counts["MEDIUM"] > 0:
            risk_level = "MEDIUM"
        elif severity_counts["LOW"] > 0:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "total_vulnerabilities": len(vulnerabilities),
            "severity_breakdown": severity_counts,
            "has_critical": severity_counts["CRITICAL"] > 0,
            "has_high": severity_counts["HIGH"] > 0,
            "analysis_confidence": self._calculate_analysis_confidence(results)
        }
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List) -> List:
        """Remove duplicate vulnerabilities using unified deduplication framework."""
        if not vulnerabilities:
            return vulnerabilities
        
        # Convert to dict format
        dict_findings = []
        for vuln in vulnerabilities:
            dict_finding = {
                'title': getattr(vuln, 'vulnerability_type', str(vuln)),
                'description': getattr(vuln, 'description', ''),
                'location': getattr(vuln, 'location', ''),
                'evidence': getattr(vuln, 'evidence', []),
                'original_object': vuln
            }
            dict_findings.append(dict_finding)
        
        try:
            result = deduplicate_findings(dict_findings, DeduplicationStrategy.INTELLIGENT)
            return [f['original_object'] for f in result.unique_findings if 'original_object' in f]
        except Exception:
            return self._deduplicate_vulnerabilities_fallback(vulnerabilities)

    def _deduplicate_vulnerabilities_fallback(self, vulnerabilities: List) -> List:
        """Fallback deduplication method (original logic)."""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            # Create signature for deduplication
            signature = (
                getattr(vuln, 'vulnerability_type', ''),
                getattr(vuln, 'location', ''),
                str(getattr(vuln, 'evidence', []))[:100]  # First 100 chars of evidence
            )
            
            if signature not in seen:
                seen.add(signature)
                unique_vulns.append(vuln)
        
        return unique_vulns

    def _calculate_analysis_confidence(self, results: Dict[str, Any]) -> float:
        """
        Calculate confidence in the analysis results.
        
        Args:
            results: Analysis results
            
        Returns:
            float: Confidence score (0.0 to 1.0)
        """
        confidence = 0.5  # Base confidence
        
        # Dynamic analysis increases confidence
        if results.get("dynamic_analysis", {}).get("status") == "completed":
            confidence += 0.3
        
        # Static analysis provides additional confidence
        if results.get("static_analysis", {}).get("status") == "completed":
            confidence += 0.2
        
        # Successful Drozer analysis increases confidence
        drozer_results = results.get("dynamic_analysis", {}).get("drozer_results", {})
        if drozer_results.get("status") == "completed":
            confidence += 0.2
        
        return min(1.0, confidence)
    
    def _get_severity_weight(self, severity: str) -> int:
        """Get numeric weight for severity sorting."""
        weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return weights.get(severity, 0)
    
    def _check_shutdown_support(self) -> bool:
        """Check if graceful shutdown support is available."""
        try:
            from core.graceful_shutdown_manager import is_shutdown_requested
            return True
        except ImportError:
            return False
    
    def _is_shutdown_requested(self) -> bool:
        """Check if shutdown has been requested."""
        try:
            from core.graceful_shutdown_manager import is_shutdown_requested
            return is_shutdown_requested()
        except ImportError:
            return False
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for analysis metadata."""
        import datetime
        return datetime.datetime.now().isoformat() 