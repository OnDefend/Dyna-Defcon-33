"""
Enhanced Manifest Analysis Plugin - Modular Architecture

This plugin provides comprehensive AndroidManifest.xml analysis with modular
architecture, dependency injection, and professional confidence calculation.

Features:
- Package information analysis with security assessment
- Security flags analysis (debuggable, allowBackup, cleartext traffic)
- Exported components analysis with risk assessment
- Permissions analysis with dangerous permission detection
- confidence calculation
- Modular component architecture
- Comprehensive risk assessment and reporting
"""

import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
import datetime

from rich.text import Text

from core.apk_ctx import APKContext
from .data_structures import (
    ManifestAnalysisResult, ManifestAnalysisContext, ManifestSecurityFinding,
    ManifestRiskAssessment, ManifestAnalysisConfiguration, SecurityStatus, RiskLevel
)
from .package_analyzer import PackageAnalyzer
from .security_flags_analyzer import SecurityFlagsAnalyzer
from .components_analyzer import ComponentsAnalyzer
from .permissions_analyzer import PermissionsAnalyzer
from .risk_assessor import ManifestRiskAssessor
from .confidence_calculator import ManifestConfidenceCalculator
from .formatters import ManifestAnalysisFormatter

logger = logging.getLogger(__name__)

# Plugin metadata
PLUGIN_METADATA = {
    "name": "Enhanced Manifest Analysis",
    "description": "Comprehensive AndroidManifest.xml security analysis with modular architecture",
    "version": "2.0.0", 
    "author": "AODS Development Team",
    "category": "MANIFEST_ANALYSIS",
    "priority": "HIGH",
    "timeout": 60,
    "mode": "comprehensive",
    "requires_device": False,
    "requires_network": False,
    "invasive": False,
    "execution_time_estimate": 30,
    "dependencies": [],
    "modular_architecture": True,
    "components": [
        "package_analyzer",
        "security_flags_analyzer", 
        "components_analyzer",
        "permissions_analyzer",
        "risk_assessor",
        "confidence_calculator"
    ],
    "security_controls": ["MASVS-PLATFORM-1", "MASVS-PLATFORM-2"],
    "owasp_categories": ["M2", "M6"]
}

class EnhancedManifestAnalysisPlugin:
    """Main enhanced manifest analysis plugin with modular architecture."""
    
    def __init__(self, config: Optional[ManifestAnalysisConfiguration] = None):
        """Initialize the enhanced manifest analysis plugin."""
        self.config = config or ManifestAnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
        
        # Initialize modular components
        self.package_analyzer = PackageAnalyzer(self.config)
        self.security_flags_analyzer = SecurityFlagsAnalyzer(self.config)
        self.components_analyzer = ComponentsAnalyzer(self.config)
        self.permissions_analyzer = PermissionsAnalyzer(self.config)
        self.risk_assessor = ManifestRiskAssessor(self.config)
        self.confidence_calculator = ManifestConfidenceCalculator()
        self.formatter = ManifestAnalysisFormatter()
        
        # Analysis state
        self.analysis_results = None
    
    def analyze_manifest(self, apk_ctx: APKContext) -> ManifestAnalysisResult:
        """Perform comprehensive manifest analysis."""
        self.logger.debug("Starting enhanced manifest analysis...")
        
        # Validate input
        if not self._validate_context(apk_ctx):
            return self._create_error_result(apk_ctx, "Invalid APK context")
        
        # Get manifest path
        manifest_path = self._get_manifest_path(apk_ctx)
        if not manifest_path:
            return self._create_error_result(apk_ctx, "AndroidManifest.xml not found")
        
        # Create analysis context
        context = ManifestAnalysisContext(
            apk_path=apk_ctx.apk_path,
            manifest_path=str(manifest_path),
            package_name=getattr(apk_ctx, 'package_name', None),
            analysis_timestamp=datetime.datetime.now().isoformat()
        )
        
        # Initialize result
        result = ManifestAnalysisResult(context=context)
        
        try:
            # Parse manifest XML
            manifest_root = self._parse_manifest(manifest_path)
            if manifest_root is None:
                return self._create_error_result(apk_ctx, "Failed to parse AndroidManifest.xml")
            
            # Perform package analysis
            if self.config.enable_package_analysis:
                self.logger.debug("Analyzing package information...")
                result.package_info = self.package_analyzer.analyze_package_info(manifest_root)
                
                # Update context with package name if extracted
                if result.package_info and result.package_info.package_name:
                    context.package_name = result.package_info.package_name
            
            # Perform security flags analysis
            if self.config.enable_security_flags_analysis:
                self.logger.debug("Analyzing security flags...")
                result.security_flags = self.security_flags_analyzer.analyze_security_flags(manifest_root)
            
            # Perform components analysis
            if self.config.enable_component_analysis:
                self.logger.debug("Analyzing components...")
                result.component_analysis = self.components_analyzer.analyze_components(manifest_root)
            
            # Perform permissions analysis
            if self.config.enable_permission_analysis:
                self.logger.debug("Analyzing permissions...")
                result.permission_analysis = self.permissions_analyzer.analyze_permissions(manifest_root)
            
            # Collect all security findings
            result.security_findings = self._collect_security_findings(result)
            
            # Enhance findings with confidence calculation
            self._enhance_findings_with_confidence(result.security_findings)
            
            # Perform risk assessment
            if self.config.enable_risk_assessment:
                result.risk_assessment = self.risk_assessor.assess_risk(result)
            
            # Generate analysis summary
            result.analysis_summary = self._generate_summary(result)
            
            # Cache results
            self.analysis_results = result
            self._cache_results(apk_ctx, result)
            
            self.logger.debug("Enhanced manifest analysis completed successfully")
            return result
            
        except Exception as e:
            self.logger.error(f"Enhanced manifest analysis failed: {e}")
            return self._create_error_result(apk_ctx, f"Analysis failed: {str(e)}")
    
    def _validate_context(self, apk_ctx: APKContext) -> bool:
        """Validate APK context."""
        return apk_ctx is not None and hasattr(apk_ctx, 'apk_path')
    
    def _get_manifest_path(self, apk_ctx: APKContext) -> Optional[Path]:
        """Get AndroidManifest.xml path from APK context."""
        # Try direct manifest path attribute
        if hasattr(apk_ctx, 'manifest_path') and apk_ctx.manifest_path:
            manifest_path = Path(apk_ctx.manifest_path)
            if manifest_path.exists():
                return manifest_path
        
        # Try APKTool output directory
        if hasattr(apk_ctx, 'apktool_output_dir') and apk_ctx.apktool_output_dir:
            manifest_path = Path(apk_ctx.apktool_output_dir) / "AndroidManifest.xml"
            if manifest_path.exists():
                return manifest_path
        
        # Try extraction path
        if hasattr(apk_ctx, 'extraction_path') and apk_ctx.extraction_path:
            manifest_path = Path(apk_ctx.extraction_path) / "AndroidManifest.xml"
            if manifest_path.exists():
                return manifest_path
        
        # Try to construct from APK path
        if apk_ctx.apk_path:
            apk_name = Path(apk_ctx.apk_path).stem
            base_dir = Path(apk_ctx.apk_path).parent
            
            # Try different directory patterns
            possible_paths = [
                base_dir / f"{apk_name}_extracted" / "AndroidManifest.xml",
                base_dir / f"{apk_name}_apktool" / "AndroidManifest.xml",
                base_dir / "AndroidManifest.xml"
            ]
            
            for path in possible_paths:
                if path.exists():
                    return path
        
        return None
    
    def _parse_manifest(self, manifest_path: Path) -> Optional[ET.Element]:
        """Parse AndroidManifest.xml file."""
        try:
            tree = ET.parse(manifest_path)
            return tree.getroot()
        except ET.ParseError as e:
            self.logger.error(f"Failed to parse manifest XML: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to read manifest file: {e}")
            return None
    
    def _collect_security_findings(self, result: ManifestAnalysisResult) -> List[ManifestSecurityFinding]:
        """Collect security findings from all analysis components."""
        findings = []
        
        # Package security findings
        if result.package_info:
            package_findings = self.package_analyzer.analyze_package_security(result.package_info)
            findings.extend(package_findings)
        
        # Security flags findings
        if result.security_flags:
            flags_findings = self.security_flags_analyzer.analyze_security_flags_findings(result.security_flags)
            findings.extend(flags_findings)
        
        # Components findings
        if result.component_analysis:
            components_findings = self.components_analyzer.get_component_findings(result.component_analysis)
            findings.extend(components_findings)
        
        # Permissions findings
        if result.permission_analysis:
            permissions_findings = self.permissions_analyzer.get_permission_findings(result.permission_analysis)
            findings.extend(permissions_findings)
        
        return findings
    
    def _enhance_findings_with_confidence(self, findings: List[ManifestSecurityFinding]) -> None:
        """Enhance security findings with professional confidence calculation."""
        for finding in findings:
            enhanced_confidence = self.confidence_calculator.calculate_confidence(finding)
            finding.confidence = enhanced_confidence
    
    def _generate_summary(self, result: ManifestAnalysisResult) -> Dict[str, Any]:
        """Generate comprehensive analysis summary."""
        summary = {
            'timestamp': result.context.analysis_timestamp,
            'package_name': result.context.package_name,
            'total_findings': len(result.security_findings),
            'analysis_components': []
        }
        
        # Add component summaries
        if result.package_info:
            summary['package_analysis'] = self.package_analyzer.get_package_security_summary(
                result.package_info, 
                [f for f in result.security_findings if f.location.startswith('AndroidManifest.xml - manifest')]
            )
            summary['analysis_components'].append('package_info')
        
        if result.security_flags:
            summary['security_flags_analysis'] = self.security_flags_analyzer.get_security_flags_summary(
                result.security_flags,
                [f for f in result.security_findings if f.location.startswith('AndroidManifest.xml - application')]
            )
            summary['analysis_components'].append('security_flags')
        
        if result.component_analysis:
            summary['component_analysis'] = self.components_analyzer.get_component_summary(result.component_analysis)
            summary['analysis_components'].append('components')
        
        if result.permission_analysis:
            summary['permission_analysis'] = self.permissions_analyzer.get_permission_summary(result.permission_analysis)
            summary['analysis_components'].append('permissions')
        
        # Add severity breakdown
        severity_counts = {}
        for finding in result.security_findings:
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary['severity_breakdown'] = severity_counts
        
        # Add risk assessment summary
        if result.risk_assessment:
            summary['risk_assessment'] = {
                'overall_risk': result.risk_assessment.overall_risk.value,
                'security_status': result.risk_assessment.security_status.value,
                'risk_score': result.risk_assessment.risk_score,
                'risk_factors_count': len(result.risk_assessment.risk_factors),
                'priority_actions_count': len(result.risk_assessment.priority_actions)
            }
        
        return summary
    
    def _create_error_result(self, apk_ctx: APKContext, error_message: str) -> ManifestAnalysisResult:
        """Create error result for failed analysis."""
        context = ManifestAnalysisContext(
            apk_path=apk_ctx.apk_path,
            manifest_path="unknown",
            package_name=getattr(apk_ctx, 'package_name', None),
            analysis_timestamp=datetime.datetime.now().isoformat()
        )
        
        result = ManifestAnalysisResult(context=context)
        result.analysis_summary = {
            'error': error_message,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        return result
    
    def _cache_results(self, apk_ctx: APKContext, result: ManifestAnalysisResult) -> None:
        """Cache analysis results."""
        try:
            if hasattr(apk_ctx, 'set_cache'):
                apk_ctx.set_cache('manifest_analysis_results', result.to_dict())
                apk_ctx.set_cache('manifest_analysis_summary', result.analysis_summary)
        except Exception as e:
            self.logger.debug(f"Failed to cache results: {e}")
    
    def generate_report(self, apk_ctx: APKContext) -> Tuple[str, Text]:
        """Generate formatted report."""
        if not self.analysis_results:
            self.analysis_results = self.analyze_manifest(apk_ctx)
        
        return self.formatter.format_report(self.analysis_results)

# Factory function for creating plugin instance
def create_enhanced_manifest_analysis_plugin(config: Optional[ManifestAnalysisConfiguration] = None) -> EnhancedManifestAnalysisPlugin:
    """Create an enhanced manifest analysis plugin instance."""
    return EnhancedManifestAnalysisPlugin(config)

# Plugin interface functions for backward compatibility
def run(apk_ctx: APKContext) -> Tuple[str, Union[str, Text]]:
    """Run enhanced manifest analysis (backward compatibility)."""
    plugin = create_enhanced_manifest_analysis_plugin()
    return plugin.generate_report(apk_ctx)

def run_plugin(apk_ctx: APKContext) -> Tuple[str, Union[str, Text]]:
    """Plugin interface function for plugin manager."""
    return run(apk_ctx)

def run_enhanced_manifest_analysis(apk_ctx: APKContext) -> Tuple[str, Text]:
    """Legacy compatibility wrapper for the enhanced manifest analysis."""
    title, result = run(apk_ctx)
    return title, result if isinstance(result, Text) else Text(str(result))

def get_analysis_result(apk_ctx: APKContext) -> ManifestAnalysisResult:
    """Get structured analysis result with security findings for AODS core processing."""
    plugin = create_enhanced_manifest_analysis_plugin()
    return plugin.analyze_manifest(apk_ctx)

def run_with_structured_data(apk_ctx: APKContext) -> Tuple[str, Tuple[str, ManifestAnalysisResult]]:
    """Run analysis and return both formatted output and structured data."""
    plugin = create_enhanced_manifest_analysis_plugin()
    analysis_result = plugin.analyze_manifest(apk_ctx)
    title, formatted_result = plugin.generate_report(apk_ctx)
    return title, (title, analysis_result)

# Export main components
__all__ = [
    'EnhancedManifestAnalysisPlugin',
    'create_enhanced_manifest_analysis_plugin',
    'run',
    'run_plugin',
    'run_enhanced_manifest_analysis',
    'get_analysis_result',
    'run_with_structured_data'
] 