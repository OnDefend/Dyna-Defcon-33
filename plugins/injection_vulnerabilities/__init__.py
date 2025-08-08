"""
Injection Vulnerabilities Plugin - Modular Architecture

This plugin provides comprehensive SQL injection vulnerability analysis with modular
architecture, dependency injection, and professional confidence calculation.

Features:
- Dynamic analysis using Drozer for SQL injection testing
- Static analysis of AndroidManifest.xml and code patterns
- Content provider security assessment
- confidence calculation
- Modular component architecture
- Graceful shutdown support
"""

import logging
from typing import Dict, List, Any, Optional, Tuple, Union
import time
import datetime

from rich.text import Text

from core.apk_ctx import APKContext
from plugins.injection_vulnerabilities.data_structures import (
    InjectionVulnerabilityResult, AnalysisContext, InjectionVulnerability,
    DynamicAnalysisResult, StaticAnalysisResult, RiskAssessment,
    InjectionAnalysisConfiguration, RiskLevel, SeverityLevel
)
from plugins.injection_vulnerabilities.dynamic_analyzer import DynamicInjectionAnalyzer
from plugins.injection_vulnerabilities.static_analyzer import StaticInjectionAnalyzer
from plugins.injection_vulnerabilities.risk_assessor import InjectionRiskAssessor
from plugins.injection_vulnerabilities.confidence_calculator import InjectionConfidenceCalculator

# Import directly from formatters.py to avoid circular import with formatters/
import importlib.util
import sys
from pathlib import Path

# Direct import to avoid circular import
formatters_path = Path(__file__).parent / "formatters.py"
spec = importlib.util.spec_from_file_location("formatters", formatters_path)
formatters_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(formatters_module)
InjectionVulnerabilityFormatter = formatters_module.InjectionVulnerabilityFormatter

# Import graceful shutdown support
try:
    from core.graceful_shutdown_manager import is_shutdown_requested
    GRACEFUL_SHUTDOWN_AVAILABLE = True
except ImportError:
    GRACEFUL_SHUTDOWN_AVAILABLE = False
    def is_shutdown_requested():
        return False

logger = logging.getLogger(__name__)

# Plugin metadata
PLUGIN_METADATA = {
    "name": "Injection Vulnerabilities",
    "description": "Comprehensive SQL injection vulnerability analysis with dynamic and static testing",
    "version": "2.0.0",
    "author": "AODS Development Team",
    "category": "INJECTION_VULNERABILITIES",
    "priority": "HIGH",
    "timeout": 180,
    "mode": "comprehensive",
    "requires_device": True,
    "requires_network": False,
    "invasive": True,
    "execution_time_estimate": 120,
    "dependencies": ["drozer", "adb"],
    "modular_architecture": True,
    "components": [
        "dynamic_analyzer",
        "static_analyzer",
        "risk_assessor",
        "confidence_calculator"
    ],
    "security_controls": ["MASVS-CODE-8"],
    "owasp_categories": ["M7"]
}

class InjectionVulnerabilityPlugin:
    """Main injection vulnerability analysis plugin with modular architecture."""
    
    def __init__(self, config: Optional[InjectionAnalysisConfiguration] = None):
        """Initialize the injection vulnerability plugin."""
        self.config = config or InjectionAnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
        
        # Initialize modular components
        self.dynamic_analyzer = DynamicInjectionAnalyzer(self.config)
        self.static_analyzer = StaticInjectionAnalyzer(self.config)
        self.risk_assessor = InjectionRiskAssessor(self.config)
        self.confidence_calculator = InjectionConfidenceCalculator()
        self.formatter = InjectionVulnerabilityFormatter()
        
        # Analysis state
        self.analysis_results = None
    
    def analyze_injection_vulnerabilities(self, apk_ctx: APKContext) -> InjectionVulnerabilityResult:
        """Perform comprehensive injection vulnerability analysis."""
        self.logger.debug("Starting injection vulnerability analysis...")
        
        # Check for shutdown at the beginning
        if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
            self.logger.debug("Analysis cancelled due to shutdown request")
            return self._create_cancelled_result(apk_ctx)
        
        # Create analysis context
        context = AnalysisContext(
            apk_path=apk_ctx.apk_path,
            package_name=apk_ctx.package_name or "unknown",
            drozer_available=self._is_drozer_available(apk_ctx),
            analysis_timestamp=datetime.datetime.now().isoformat()
        )
        
        # Initialize result
        result = InjectionVulnerabilityResult(context=context)
        
        try:
            # Perform dynamic analysis (priority if available)
            if self.config.enable_dynamic_analysis and context.drozer_available:
                self.logger.debug("Performing dynamic analysis with Drozer...")
                result.dynamic_analysis = self.dynamic_analyzer.analyze_injection_vulnerabilities(apk_ctx)
                
                # Check for shutdown after dynamic analysis
                if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
                    self.logger.debug("Analysis cancelled after dynamic analysis")
                    return self._finalize_partial_result(result)
            
            # Perform static analysis (fallback or complement)
            if self.config.enable_static_analysis:
                self.logger.debug("Performing static analysis...")
                result.static_analysis = self.static_analyzer.analyze_static_vulnerabilities(apk_ctx)
                
                # Check for shutdown after static analysis
                if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
                    self.logger.debug("Analysis cancelled after static analysis")
                    return self._finalize_partial_result(result)
            
            # Collect all vulnerabilities
            result.vulnerabilities = self._collect_vulnerabilities(result)
            
            # Perform risk assessment
            result.risk_assessment = self._assess_risk(result)
            
            # Generate analysis summary
            result.analysis_summary = self._generate_summary(result)
            
            # Cache results
            self.analysis_results = result
            self._cache_results(apk_ctx, result)
            
            self.logger.debug("Injection vulnerability analysis completed successfully")
            return result
            
        except Exception as e:
            self.logger.error(f"Injection vulnerability analysis failed: {e}")
            # Return partial results with error
            result.analysis_summary = {
                'error': str(e),
                'timestamp': datetime.datetime.now().isoformat()
            }
            return result
    
    def _is_drozer_available(self, apk_ctx: APKContext) -> bool:
        """Check if Drozer is available for analysis."""
        return (
            hasattr(apk_ctx, 'drozer') and 
            apk_ctx.drozer is not None and
            hasattr(apk_ctx, 'package_name') and
            apk_ctx.package_name is not None
        )
    
    def _collect_vulnerabilities(self, result: InjectionVulnerabilityResult) -> List[InjectionVulnerability]:
        """Collect vulnerabilities from all analysis components."""
        vulnerabilities = []
        
        # Get vulnerabilities from dynamic analysis
        if result.dynamic_analysis:
            vulnerabilities.extend(result.dynamic_analysis.vulnerabilities_found)
        
        # Get vulnerabilities from static analysis
        if result.static_analysis:
            static_vulnerabilities = self.static_analyzer.get_vulnerabilities_from_analysis(result.static_analysis)
            vulnerabilities.extend(static_vulnerabilities)
        
        # Enhance vulnerabilities with confidence calculation
        for vulnerability in vulnerabilities:
            enhanced_confidence = self.confidence_calculator.calculate_confidence(vulnerability)
            vulnerability.confidence = enhanced_confidence
        
        return vulnerabilities
    
    def _assess_risk(self, result: InjectionVulnerabilityResult) -> RiskAssessment:
        """Assess overall risk based on analysis results."""
        try:
            return self.risk_assessor.assess_risk(result)
        except Exception as e:
            self.logger.error(f"Risk assessment failed: {e}")
            return RiskAssessment(
                overall_risk=RiskLevel.UNKNOWN,
                risk_score=0.0,
                risk_factors=["Risk assessment failed"]
            )
    
    def _generate_summary(self, result: InjectionVulnerabilityResult) -> Dict[str, Any]:
        """Generate comprehensive analysis summary."""
        summary = {
            'timestamp': result.context.analysis_timestamp,
            'analysis_method': self._get_analysis_method(result),
            'total_vulnerabilities': len(result.vulnerabilities),
            'drozer_available': result.context.drozer_available
        }
        
        # Add severity breakdown
        severity_counts = {}
        for vulnerability in result.vulnerabilities:
            severity = vulnerability.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary['severity_breakdown'] = severity_counts
        
        # Add analysis-specific summaries
        if result.dynamic_analysis:
            summary['dynamic_analysis'] = self.dynamic_analyzer.get_analysis_summary(result.dynamic_analysis)
        
        if result.static_analysis:
            summary['static_analysis'] = self.static_analyzer.get_analysis_summary(result.static_analysis)
        
        # Add risk assessment summary
        if result.risk_assessment:
            summary['risk_assessment'] = {
                'overall_risk': result.risk_assessment.overall_risk.value,
                'risk_score': result.risk_assessment.risk_score,
                'total_vulnerabilities': result.risk_assessment.total_vulnerabilities
            }
        
        return summary
    
    def _get_analysis_method(self, result: InjectionVulnerabilityResult) -> str:
        """Determine the analysis method used."""
        if result.dynamic_analysis and result.static_analysis:
            return "hybrid"
        elif result.dynamic_analysis:
            return "dynamic"
        elif result.static_analysis:
            return "static"
        else:
            return "none"
    
    def _create_cancelled_result(self, apk_ctx: APKContext) -> InjectionVulnerabilityResult:
        """Create a result for cancelled analysis."""
        context = AnalysisContext(
            apk_path=apk_ctx.apk_path,
            package_name=apk_ctx.package_name or "unknown",
            drozer_available=False,
            analysis_timestamp=datetime.datetime.now().isoformat()
        )
        
        result = InjectionVulnerabilityResult(context=context)
        result.analysis_summary = {
            'status': 'cancelled',
            'reason': 'Analysis cancelled due to shutdown request',
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        return result
    
    def _finalize_partial_result(self, result: InjectionVulnerabilityResult) -> InjectionVulnerabilityResult:
        """Finalize partial results when analysis is cancelled."""
        # Collect any vulnerabilities found so far
        result.vulnerabilities = self._collect_vulnerabilities(result)
        
        # Perform risk assessment on partial results
        if result.vulnerabilities:
            result.risk_assessment = self._assess_risk(result)
        
        # Generate summary for partial results
        result.analysis_summary = self._generate_summary(result)
        result.analysis_summary['status'] = 'partial'
        result.analysis_summary['reason'] = 'Analysis cancelled during execution'
        
        return result
    
    def _cache_results(self, apk_ctx: APKContext, result: InjectionVulnerabilityResult) -> None:
        """Cache analysis results."""
        try:
            if hasattr(apk_ctx, 'set_cache'):
                apk_ctx.set_cache('injection_vulnerability_results', result.to_dict())
                apk_ctx.set_cache('injection_vulnerability_summary', result.analysis_summary)
        except Exception as e:
            self.logger.debug(f"Failed to cache results: {e}")
    
    def generate_report(self, apk_ctx: APKContext) -> Tuple[str, Text]:
        """Generate formatted report."""
        if not self.analysis_results:
            self.analyze_injection_vulnerabilities(apk_ctx)
        
        return self.formatter.format_report(self.analysis_results)

# Factory function for creating plugin instance
def create_injection_vulnerability_plugin(config: Optional[InjectionAnalysisConfiguration] = None) -> InjectionVulnerabilityPlugin:
    """Create an injection vulnerability plugin instance."""
    return InjectionVulnerabilityPlugin(config)

# Plugin interface functions for backward compatibility
def run(apk_ctx: APKContext) -> Tuple[str, Union[str, Text]]:
    """Run injection vulnerability analysis (backward compatibility)."""
    plugin = create_injection_vulnerability_plugin()
    return plugin.generate_report(apk_ctx)

def run_plugin(apk_ctx: APKContext) -> Tuple[str, Union[str, Text]]:
    """Plugin interface function for plugin manager."""
    return run(apk_ctx)

# Export main components
__all__ = [
    'InjectionVulnerabilityPlugin',
    'create_injection_vulnerability_plugin',
    'InjectionAnalysisConfiguration',
    'InjectionVulnerabilityFormatter',
    'PLUGIN_METADATA',
    'run',
    'run_plugin'
] 