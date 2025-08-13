#!/usr/bin/env python3
"""
Improper Platform Usage Analysis Plugin - Modular Architecture

This module provides the entry point for the modularized improper platform usage
analysis plugin, coordinating between specialized analysis modules for optimal
performance and maintainability.

Enhanced Features (Phase 2.5.1):
- Advanced root bypass validation with security control assessment
- Comprehensive anti-tampering protection strength assessment
- Runtime application self-protection (RASP) analysis
- Device attestation security analysis
- Transparent analysis failure notification system

Architecture Components:
- platform_analyzer.py: Core platform usage analysis logic
- security_control_analyzer.py: Enhanced security control assessment (NEW - Phase 2.5.1)
- confidence_calculator.py: evidence-based confidence calculation
- data_structures.py: Type-safe data structures and enums
- formatters.py: Professional Rich text output formatting
- platform_patterns_config.yaml: External security pattern configuration

External Configuration:
- 100+ platform security patterns in structured YAML format
- Evidence-based confidence calculation with pattern reliability database
- multi-factor analysis methodology

"""

import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
from datetime import datetime

from rich.text import Text

from .platform_analyzer import PlatformUsageAnalyzer
from .security_control_analyzer import SecurityControlAnalyzer  # NEW - Phase 2.5.1
from .confidence_calculator import PlatformUsageConfidenceCalculator
from .formatters import PlatformUsageFormatter
from .data_structures import (
    ManifestAnalysisResult, 
    PlatformUsageAnalysisResult,
    RootBypassValidationResult,
    SecurityControlAssessment,
    PlatformUsageVulnerability,
    ComponentAnalysisResult
)

# Also import VulnerabilitySeverity for severity determination
from core.shared_data_structures.base_vulnerability import VulnerabilitySeverity

logger = logging.getLogger(__name__)

# Plugin characteristics for AODS discovery
PLUGIN_CHARACTERISTICS = {
    "mode": "safe",
    "requires_static": True,
    "requires_dynamic": False,
    "masvs_categories": [
        "MSTG-PLATFORM-1", "MSTG-PLATFORM-2", "MSTG-PLATFORM-3",
        "MSTG-RESILIENCE-1", "MSTG-RESILIENCE-2", "MSTG-RESILIENCE-3"  # Enhanced for Phase 2.5.1
    ],
    "enterprise_ready": True,
    "description": "Comprehensive improper platform usage analysis with component-based architecture and enhanced security controls",
    "modular_architecture": True,
    "performance_optimized": True,
    "version": "2.1.0",
    "phase_2_5_1_enhanced": True  # NEW - Phase 2.5.1 marker
}

# Plugin metadata for integration
PLUGIN_METADATA = {
    "name": "improper_platform_usage",
    "version": "2.1.0",
    "author": "AODS Development Team",
    "description": "Detects improper platform usage patterns with evidence-based security control assessment",
    "categories": ["platform_security", "manifest_analysis", "component_security", "security_controls"],
    "masvs_mapping": [
        "MSTG-PLATFORM-1", "MSTG-PLATFORM-2", "MSTG-PLATFORM-3",
        "MSTG-RESILIENCE-1", "MSTG-RESILIENCE-2", "MSTG-RESILIENCE-3"
    ],
    "risk_level": "HIGH",
    "analysis_type": "static",
    "output_format": "rich_text",
    "phase_2_5_1_features": [
        "root_bypass_validation",
        "security_control_assessment", 
        "anti_tampering_analysis",
        "rasp_detection",
        "device_attestation_analysis"
    ]
}

class ImproperPlatformUsagePlugin:
    """
    Main plugin orchestrator with dependency injection and Phase 2.5.1 enhancements.
    
    Coordinates between specialized analysis modules while maintaining
    complete backward compatibility with the original plugin interface.
    
    Enhanced Features (Phase 2.5.1):
    - Comprehensive security control assessment
    - Root bypass validation with effectiveness scoring
    - Anti-tampering protection strength assessment
    - Device attestation and integrity verification analysis
    """
    
    def __init__(self, apk_ctx, config: Optional[Dict[str, Any]] = None):
        """Initialize the improper platform usage plugin with dependency injection."""
        self.apk_ctx = apk_ctx
        self.config = config or {}
        self.analysis_start_time = time.time()
        
        # Initialize modular components with dependency injection
        self.confidence_calculator = self._create_confidence_calculator()
        self.platform_analyzer = self._create_platform_analyzer()
        self.security_control_analyzer = self._create_security_control_analyzer()  # NEW - Phase 2.5.1
        self.formatter = self._create_formatter()
        
        # Phase 2.5.1 configuration
        self.enable_security_control_analysis = self.config.get('enable_security_control_analysis', True)
        self.enable_root_bypass_validation = self.config.get('enable_root_bypass_validation', True)
        self.enable_transparency_reporting = self.config.get('enable_transparency_reporting', True)
        
        logger.debug("Improper Platform Usage Plugin initialized with Phase 2.5.1 enhancements")
    
    def _create_confidence_calculator(self) -> PlatformUsageConfidenceCalculator:
        """Factory method for confidence calculator with dependency injection."""
        config_path = self.config.get('patterns_config_path')
        return PlatformUsageConfidenceCalculator(config_path=config_path)
    
    def _create_platform_analyzer(self) -> PlatformUsageAnalyzer:
        """Factory method for platform analyzer with dependency injection."""
        return PlatformUsageAnalyzer(
            apk_ctx=self.apk_ctx,
            confidence_calculator=self.confidence_calculator
        )
    
    def _create_security_control_analyzer(self) -> SecurityControlAnalyzer:
        """Factory method for security control analyzer with dependency injection (Phase 2.5.1)."""
        return SecurityControlAnalyzer(
            apk_ctx=self.apk_ctx,
            confidence_calculator=self.confidence_calculator
        )
    
    def _create_formatter(self) -> PlatformUsageFormatter:
        """Factory method for formatter with dependency injection."""
        return PlatformUsageFormatter()
    
    def analyze(self) -> Tuple[str, Union[str, Text]]:
        """
        Execute comprehensive platform usage analysis with Phase 2.5.1 enhancements.
        
        Returns:
            Tuple containing analysis title and formatted results
        """
        try:
            # Perform comprehensive analysis
            analysis_result = self._perform_enhanced_analysis()  # Enhanced for Phase 2.5.1
            
            # Format results with enhanced security control information
            formatted_output = self._format_enhanced_results(analysis_result)
            
            return ("Enhanced Improper Platform Usage Analysis", formatted_output)
            
        except Exception as e:
            logger.error(f"Enhanced platform usage analysis failed: {e}")
            error_output = self._create_error_output(f"Enhanced analysis failed: {str(e)}")
            return ("Enhanced Improper Platform Usage Analysis - Error", error_output)
    
    def _perform_enhanced_analysis(self) -> PlatformUsageAnalysisResult:
        """Perform the comprehensive platform usage analysis with Phase 2.5.1 enhancements."""
        
        # Perform standard manifest analysis
        manifest_result = self.platform_analyzer.analyze_platform_usage()
        
        # Create overall analysis result
        analysis_result = PlatformUsageAnalysisResult(
            target_name=getattr(self.apk_ctx, 'app_name', 'Unknown'),
            analysis_timestamp=datetime.now().isoformat(),
            analysis_duration=time.time() - self.analysis_start_time
        )
        
        # Set analysis components
        analysis_result.manifest_analysis = manifest_result
        
        # Aggregate vulnerabilities
        analysis_result.vulnerabilities = manifest_result.security_issues.copy()
        
        # NEW - Phase 2.5.1: Enhanced security control analysis
        if self.enable_security_control_analysis:
            try:
                # Get manifest and source content for analysis
                manifest_content = self._get_manifest_content()
                source_content = self._get_source_content()
                
                # Perform comprehensive security control analysis
                root_bypass_result = self.security_control_analyzer.analyze_security_controls(
                    manifest_content, source_content
                )
                
                # Integrate security control assessment
                analysis_result.root_bypass_validation = root_bypass_result
                
                # Add security control vulnerabilities to overall results
                security_control_vulnerabilities = self._convert_security_assessments_to_vulnerabilities(
                    root_bypass_result.security_control_assessments
                )
                analysis_result.vulnerabilities.extend(security_control_vulnerabilities)
                
                logger.debug(f"Security control analysis completed: {len(root_bypass_result.security_control_assessments)} controls analyzed")
                
            except Exception as e:
                logger.warning(f"Security control analysis failed: {e}")
                # Create fallback result with error information
                analysis_result.root_bypass_validation = RootBypassValidationResult(
                    overall_protection_score=0.0,
                    security_control_assessments=[],
                    bypass_techniques_detected=[],
                    recommendations=[f"Security control analysis failed: {str(e)}"]
                )
        
        # Calculate overall score
        analysis_result.calculate_overall_score()
        
        # Set compliance status
        analysis_result.platform_compliance_status = self._determine_enhanced_compliance_status(analysis_result)
        
        # Add enhanced metadata
        analysis_result.analysis_metadata = {
            "modular_architecture": True,
            "phase_2_5_1_enhanced": True,
            "analysis_modules": [
                "platform_analyzer", 
                "security_control_analyzer",  # NEW
                "confidence_calculator", 
                "formatter"
            ],
            "patterns_loaded": True,
            "professional_confidence": True,
            "security_control_analysis": self.enable_security_control_analysis,
            "root_bypass_validation": self.enable_root_bypass_validation
        }
        
        # Generate enhanced recommendations
        analysis_result.recommendations = self._generate_enhanced_recommendations(analysis_result)
        
        return analysis_result
    
    def _get_manifest_content(self) -> str:
        """Get AndroidManifest.xml content for analysis."""
        try:
            if hasattr(self.apk_ctx, 'manifest_path') and self.apk_ctx.manifest_path:
                with open(self.apk_ctx.manifest_path, 'r', encoding='utf-8') as f:
                    return f.read()
        except Exception as e:
            logger.warning(f"Could not read manifest content: {e}")
        return ""
    
    def _get_source_content(self) -> str:
        """Get application source content for analysis."""
        try:
            source_content = ""
            
            # Try to get jadx output directory
            if hasattr(self.apk_ctx, 'jadx_output_dir') and self.apk_ctx.jadx_output_dir:
                jadx_dir = Path(self.apk_ctx.jadx_output_dir)
                if jadx_dir.exists():
                    # Read Java source files
                    for java_file in jadx_dir.rglob("*.java"):
                        try:
                            with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                                source_content += f.read() + "\n"
                        except Exception:
                            continue
            
            return source_content
            
        except Exception as e:
            logger.warning(f"Could not read source content: {e}")
            return ""
    
    def _convert_security_assessments_to_vulnerabilities(self, 
                                                       assessments: List[SecurityControlAssessment]) -> List[PlatformUsageVulnerability]:
        """Convert security control assessments to platform usage vulnerabilities."""
        vulnerabilities = []
        
        for assessment in assessments:
            # Create vulnerability for weak or missing security controls
            if not assessment.is_effective:
                severity = self._determine_vulnerability_severity(assessment)
                
                vulnerability = PlatformUsageVulnerability(
                    id=f"SECURITY_CONTROL_{assessment.control_type.value.upper()}",
                    title=f"Weak {assessment.control_type.value.replace('_', ' ').title()} Implementation",
                    description=f"Security control assessment: {assessment.description}",
                    severity=severity,
                    category=PlatformUsageCategory.MANIFEST_CONFIGURATION,
                    cwe_id="CWE-693",  # Protection Mechanism Failure
                    masvs_refs=assessment.masvs_controls,
                    confidence=assessment.confidence,
                    evidence=assessment.evidence,
                    recommendations=[
                        f"Strengthen {assessment.control_type.value.replace('_', ' ')} implementation",
                        f"Improve bypass resistance (current: {assessment.bypass_resistance:.2f})",
                        f"Enhance effectiveness score (current: {assessment.effectiveness_score:.2f})"
                    ]
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _determine_vulnerability_severity(self, assessment: SecurityControlAssessment) -> VulnerabilitySeverity:
        """Determine vulnerability severity based on security control assessment."""
        effectiveness = assessment.effectiveness_score
        bypass_resistance = assessment.bypass_resistance
        
        # Calculate combined score
        combined_score = (effectiveness + bypass_resistance) / 2
        
        if combined_score < 0.3:
            return VulnerabilitySeverity.CRITICAL
        elif combined_score < 0.5:
            return VulnerabilitySeverity.HIGH
        elif combined_score < 0.7:
            return VulnerabilitySeverity.MEDIUM
        else:
            return VulnerabilitySeverity.LOW
    
    def _determine_compliance_status(self, result: PlatformUsageAnalysisResult) -> str:
        """Determine base MASVS compliance status based on platform usage analysis."""
        critical_count = result.critical_vulnerabilities
        high_count = result.high_vulnerabilities
        total_vulnerabilities = result.total_vulnerabilities
        security_score = result.overall_security_score
        
        # Critical vulnerabilities mean immediate non-compliance
        if critical_count > 0:
            return "NON_COMPLIANT"
        
        # High vulnerability count assessment
        if high_count == 0:
            # No high or critical vulnerabilities
            if total_vulnerabilities <= 2:
                return "COMPLIANT"
            elif total_vulnerabilities <= 5:
                return "PARTIALLY_COMPLIANT"
            else:
                return "NON_COMPLIANT"
        elif high_count <= 2:
            # Limited high vulnerabilities
            return "PARTIALLY_COMPLIANT"
        else:
            # Too many high vulnerabilities
            return "NON_COMPLIANT"
    
    def _determine_enhanced_compliance_status(self, result: PlatformUsageAnalysisResult) -> str:
        """Determine enhanced MASVS compliance status including security controls."""
        base_status = self._determine_compliance_status(result)
        
        # Factor in security control assessment
        if result.root_bypass_validation:
            protection_score = result.root_bypass_validation.overall_protection_score
            
            if protection_score < 0.3:
                return "NON_COMPLIANT"
            elif protection_score < 0.6 and base_status == "COMPLIANT":
                return "PARTIALLY_COMPLIANT"
        
        return base_status
    
    def _generate_comprehensive_recommendations(self, result: PlatformUsageAnalysisResult) -> List[str]:
        """
        Generate comprehensive security recommendations based on platform usage analysis.
        
        Args:
            result: Platform usage analysis result
            
        Returns:
            List of security recommendations
        """
        recommendations = []
        
        try:
            # Base recommendations for platform usage issues
            if hasattr(result, 'vulnerabilities') and result.vulnerabilities:
                recommendations.extend([
                    "🔒 Implement proper API usage following security best practices",
                    "📱 Review and validate all platform API interactions for security compliance",
                    "⚠️ Address identified platform usage vulnerabilities immediately"
                ])
                
                # Add specific recommendations based on vulnerability severity
                high_severity_count = sum(1 for vuln in result.vulnerabilities if hasattr(vuln, 'severity') and vuln.severity.value == 'HIGH')
                if high_severity_count > 0:
                    recommendations.append(f"🚨 {high_severity_count} high-severity platform usage issues require immediate attention")
            
            # Security control recommendations
            if hasattr(result, 'security_control_assessment') and result.security_control_assessment:
                recommendations.extend([
                    "🛡️ Strengthen security controls to prevent platform exploitation",
                    "🔍 Implement runtime monitoring for platform usage anomalies",
                    "📊 Regular security assessment of platform integration points"
                ])
            
            # Compliance-based recommendations
            if hasattr(result, 'masvs_compliance_status'):
                compliance_status = getattr(result, 'masvs_compliance_status', 'UNKNOWN')
                if 'NON_COMPLIANT' in str(compliance_status).upper():
                    recommendations.extend([
                        "📋 Address MASVS compliance gaps in platform usage",
                        "🔧 Implement MASVS-recommended security controls",
                        "✅ Validate compliance through security testing"
                    ])
            
            # General security hardening recommendations
            recommendations.extend([
                "🔐 Implement defense-in-depth strategy for platform interactions",
                "📝 Document and review all platform API usage patterns",
                "🎯 Establish secure coding practices for platform integration",
                "🔄 Regular security audits of platform usage implementations"
            ])
            
        except Exception as e:
            logger.warning(f"Error generating comprehensive recommendations: {e}")
            # Fallback recommendations
            recommendations = [
                "🔒 Review platform usage for security best practices",
                "⚠️ Implement security controls for platform interactions",
                "📊 Conduct security assessment of platform integration"
            ]
        
        return recommendations
    
    def _generate_enhanced_recommendations(self, result: PlatformUsageAnalysisResult) -> List[str]:
        """Generate enhanced security recommendations including security controls."""
        recommendations = self._generate_comprehensive_recommendations(result)
        
        # Add security control specific recommendations
        if result.root_bypass_validation:
            recommendations.extend(result.root_bypass_validation.recommendations)
            
            # Add bypass technique specific recommendations
            if result.root_bypass_validation.bypass_techniques_detected:
                recommendations.append(
                    "⚠️ Bypass techniques detected - implement countermeasures and monitoring"
                )
        
        # Add Phase 2.5.1 specific recommendations
        recommendations.extend([
            "🔒 Implement comprehensive security control monitoring and assessment",
            "🛡️ Deploy multi-layer security controls with bypass resistance",
            "📊 Regular security control effectiveness assessment and improvement"
        ])
        
        return recommendations
    
    def _format_enhanced_results(self, result: PlatformUsageAnalysisResult) -> Text:
        """Format results with enhanced security control information."""
        return self.formatter.format_analysis_results(
            result.manifest_analysis,
            bypass_result=result.root_bypass_validation  # Enhanced formatting
        )
    
    def _create_error_output(self, error_message: str) -> Text:
        """Create error output with enhanced formatting."""
        output = Text()
        output.append("Enhanced Improper Platform Usage Analysis\n", style="bold red")
        output.append("=" * 50 + "\n\n", style="red")
        output.append(f"Analysis Error: {error_message}\n", style="red")
        output.append("\nPlease check the application and try again.\n", style="yellow")
        return output
    
    def get_enhanced_analysis_summary(self) -> Dict[str, Any]:
        """Get enhanced analysis summary with security control statistics."""
        summary = {
            "plugin_info": {
                "name": "improper_platform_usage",
                "version": "2.1.0",
                "phase_2_5_1_enhanced": True,
                "modular_architecture": True
            },
            "analysis_duration": time.time() - self.analysis_start_time,
            "security_control_analysis_enabled": self.enable_security_control_analysis,
            "root_bypass_validation_enabled": self.enable_root_bypass_validation
        }
        
        # Add security control analyzer statistics
        if hasattr(self, 'security_control_analyzer'):
            summary.update(self.security_control_analyzer.get_analysis_statistics())
        
        return summary

# Legacy compatibility interface - maintains backward compatibility
class EnhancedImproperPlatformUsageAnalyzer:
    """Legacy compatibility wrapper for the modular plugin."""
    
    def __init__(self, apk_ctx):
        """Initialize with legacy interface."""
        self.plugin = ImproperPlatformUsagePlugin(apk_ctx)
    
    def analyze(self) -> Tuple[str, Union[str, Text]]:
        """Legacy analyze method."""
        return self.plugin.analyze()
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Legacy summary method."""
        return self.plugin.get_analysis_summary()

# Main plugin functions for AODS integration
def run(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Main plugin entry point for AODS framework.
    
    Args:
        apk_ctx: APK context object with analysis data
        
    Returns:
        Tuple of (status, formatted_result)
    """
    try:
        plugin = ImproperPlatformUsagePlugin(apk_ctx)
        return plugin.analyze()
    except Exception as e:
        logger.error(f"Plugin execution error: {e}")
        error_text = Text()
        error_text.append(f"Improper Platform Usage Analysis Error: {e}", style="red")
        return "ERROR", error_text

def run_plugin(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """Alternative entry point for plugin execution."""
    return run(apk_ctx)

# Module exports
__version__ = "2.1.0"
__author__ = "AODS Development Team"
__description__ = "Modularized Improper Platform Usage Analysis Plugin"

__all__ = [
    "ImproperPlatformUsagePlugin",
    "EnhancedImproperPlatformUsageAnalyzer",
    "PLUGIN_CHARACTERISTICS",
    "PLUGIN_METADATA",
    "run",
    "run_plugin"
]