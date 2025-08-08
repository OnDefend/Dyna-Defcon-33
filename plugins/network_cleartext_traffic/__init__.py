#!/usr/bin/env python3
"""
Network Cleartext Traffic Analyzer - Main Orchestration Module

This module provides the main orchestration for the modularized Network Cleartext Traffic
analyzer, integrating all components using dependency injection patterns.

Features:
- Dependency injection for all analyzer components
- Comprehensive analysis orchestration
- confidence calculation integration
- Structured error handling and logging
- Rich text output formatting
- Legacy compatibility maintenance

Classes:
    NetworkCleartextTrafficPlugin: Main plugin orchestration class
"""

import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime

from rich.text import Text

from core.apk_ctx import APKContext

# Import modular components
from .data_structures import (
    CleartextTrafficAnalysisResult, NetworkSecurityFinding, AnalysisStatus, RiskLevel
)
from .confidence_calculator import NetworkCleartextConfidenceCalculator
from .manifest_analyzer import ManifestAnalyzer
from .nsc_analyzer import NSCAnalyzer
from .resource_analyzer import ResourceAnalyzer
from .risk_assessor import RiskAssessor
from .formatter import NetworkCleartextFormatter

class NetworkCleartextTrafficPlugin:
    """
    Main Network Cleartext Traffic analyzer plugin using modular architecture.
    
    Orchestrates all analysis components using dependency injection to provide
    comprehensive network cleartext traffic security analysis.
    """
    
    def __init__(self, apk_ctx: APKContext):
        """
        Initialize the plugin with dependency injection.
        
        Args:
            apk_ctx: APK context containing manifest and analysis data
        """
        self.apk_ctx = apk_ctx
        self.logger = logging.getLogger(__name__)
        
        # Initialize components using dependency injection
        self.confidence_calculator = self._create_confidence_calculator()
        self.manifest_analyzer = self._create_manifest_analyzer()
        self.nsc_analyzer = self._create_nsc_analyzer()
        self.resource_analyzer = self._create_resource_analyzer()
        self.risk_assessor = self._create_risk_assessor()
        self.formatter = self._create_formatter()
        
        self.logger.debug("Network Cleartext Traffic plugin initialized with modular architecture")
    
    def analyze(self) -> CleartextTrafficAnalysisResult:
        """
        Perform comprehensive network cleartext traffic analysis.
        
        Returns:
            CleartextTrafficAnalysisResult with complete analysis data
        """
        start_time = time.time()
        
        # Initialize result
        result = CleartextTrafficAnalysisResult(
            overall_status=AnalysisStatus.PASS,
            risk_level=RiskLevel.LOW,
            analysis_timestamp=datetime.now()
        )
        
        try:
            self.logger.debug("Starting comprehensive network cleartext traffic analysis...")
            
            # Phase 1: AndroidManifest.xml Analysis
            self.logger.debug("Phase 1: Analyzing AndroidManifest.xml...")
            manifest_result = self._analyze_manifest()
            result.manifest_analysis = manifest_result
            
            # Generate manifest findings
            manifest_findings = self.manifest_analyzer.generate_security_findings(manifest_result)
            result.findings.extend(manifest_findings)
            
            # Phase 2: Network Security Configuration Analysis
            self.logger.debug("Phase 2: Analyzing Network Security Configuration...")
            nsc_result = self._analyze_network_security_config()
            result.nsc_analysis = nsc_result
            
            # Generate NSC findings
            nsc_findings = self.nsc_analyzer.generate_security_findings(nsc_result)
            result.findings.extend(nsc_findings)
            
            # Phase 3: Resource and Code Analysis
            self.logger.debug("Phase 3: Analyzing resources and code...")
            resource_result = self._analyze_resources_and_code()
            result.resource_analysis = resource_result
            
            # Generate resource findings
            resource_findings = self.resource_analyzer.generate_security_findings(resource_result)
            result.findings.extend(resource_findings)
            
            # Phase 4: Risk Assessment
            self.logger.debug("Phase 4: Performing risk assessment...")
            self.risk_assessor.assess_overall_risk(
                result, manifest_result, nsc_result, resource_result
            )
            
            # Phase 5: Generate Recommendations
            self.logger.debug("Phase 5: Generating security recommendations...")
            recommendations = self.risk_assessor.generate_recommendations(
                manifest_result, nsc_result, resource_result,
                result.analysis_metadata.get('overall_risk_score', 0.0)
            )
            result.recommendations = recommendations
            
            # Phase 6: Generate Verification Commands
            self.logger.debug("Phase 6: Generating verification commands...")
            verification_commands = self.risk_assessor.generate_verification_commands(
                manifest_result, nsc_result, resource_result
            )
            result.verification_commands = verification_commands
            
            # Calculate analysis duration
            result.analysis_duration = time.time() - start_time
            
            # Update metadata
            result.analysis_metadata.update({
                'plugin_version': '2.0.0',
                'analysis_phases': 6,
                'modular_architecture': True,
                'components_used': [
                    'manifest_analyzer',
                    'nsc_analyzer', 
                    'resource_analyzer',
                    'risk_assessor',
                    'confidence_calculator'
                ]
            })
            
            self.logger.debug(
                f"Network cleartext traffic analysis completed in {result.analysis_duration:.2f}s - "
                f"Status: {result.overall_status.value}, Risk: {result.risk_level.value}, "
                f"Findings: {len(result.findings)}"
            )
            
        except Exception as e:
            self.logger.error(f"Error during network cleartext traffic analysis: {e}")
            result.overall_status = AnalysisStatus.ERROR
            result.risk_level = RiskLevel.UNKNOWN
            result.analysis_duration = time.time() - start_time
            
            # Add error finding
            error_finding = NetworkSecurityFinding(
                finding_type=self._map_to_finding_type("ANALYSIS_ERROR"),
                severity=RiskLevel.MEDIUM,
                title="Analysis Error",
                description=f"Error during network cleartext traffic analysis: {str(e)}",
                location="analyzer",
                evidence=[f"Error: {str(e)}"],
                remediation=["Manual verification required", "Check application structure"],
                detection_method="error_handler",
                confidence=0.9
            )
            result.findings.append(error_finding)
        
        return result
    
    def _analyze_manifest(self):
        """Analyze AndroidManifest.xml using manifest analyzer"""
        try:
            manifest_path = self.apk_ctx.manifest_path
            return self.manifest_analyzer.analyze_manifest(manifest_path)
        except Exception as e:
            self.logger.error(f"Error in manifest analysis: {e}")
            # Return empty result on error
            from .data_structures import ManifestAnalysisResult
            result = ManifestAnalysisResult()
            result.findings.append({
                'type': 'MANIFEST_ANALYSIS_ERROR',
                'message': f'Manifest analysis failed: {e}',
                'severity': 'MEDIUM'
            })
            return result
    
    def _analyze_network_security_config(self):
        """Analyze Network Security Configuration using NSC analyzer"""
        try:
            # Get APK extraction directory
            apk_path = self.apk_ctx.apk_path.parent if self.apk_ctx.apk_path else Path('.')
            return self.nsc_analyzer.analyze_network_security_config(apk_path)
        except Exception as e:
            self.logger.error(f"Error in NSC analysis: {e}")
            # Return empty result on error
            from .data_structures import NSCAnalysisResult
            result = NSCAnalysisResult()
            result.validation_errors.append(f"NSC analysis failed: {e}")
            return result
    
    def _analyze_resources_and_code(self):
        """Analyze resources and code using resource analyzer"""
        try:
            # Get APK extraction directory
            apk_path = self.apk_ctx.apk_path.parent if self.apk_ctx.apk_path else Path('.')
            return self.resource_analyzer.analyze_resources_and_code(apk_path)
        except Exception as e:
            self.logger.error(f"Error in resource analysis: {e}")
            # Return empty result on error
            from .data_structures import ResourceAnalysisResult
            result = ResourceAnalysisResult()
            result.analysis_errors.append(f"Resource analysis failed: {e}")
            return result
    
    def generate_rich_output(self, result: CleartextTrafficAnalysisResult) -> Text:
        """
        Generate Rich text output for analysis results.
        
        Args:
            result: Complete cleartext traffic analysis result
            
        Returns:
            Rich Text object with formatted analysis report
        """
        try:
            return self.formatter.generate_rich_output(result)
        except Exception as e:
            self.logger.error(f"Error generating Rich output: {e}")
            # Fallback to simple text
            error_output = Text()
            error_output.append("Network Cleartext Traffic Analysis - Formatting Error\n", style="bold red")
            error_output.append(f"Analysis completed but formatting failed: {str(e)}\n", style="red")
            error_output.append(f"Status: {result.overall_status.value}, Risk: {result.risk_level.value}\n")
            error_output.append(f"Findings: {len(result.findings)}\n")
            return error_output
    
    def _create_confidence_calculator(self) -> NetworkCleartextConfidenceCalculator:
        """Create confidence calculator with dependency injection"""
        try:
            config_path = Path(__file__).parent / "cleartext_patterns_config.yaml"
            return NetworkCleartextConfidenceCalculator(config_path)
        except Exception as e:
            self.logger.warning(f"Error creating confidence calculator: {e}")
            # Fallback to default configuration
            return NetworkCleartextConfidenceCalculator()
    
    def _create_manifest_analyzer(self) -> ManifestAnalyzer:
        """Create manifest analyzer with dependency injection"""
        return ManifestAnalyzer(self.confidence_calculator)
    
    def _create_nsc_analyzer(self) -> NSCAnalyzer:
        """Create NSC analyzer with dependency injection"""
        return NSCAnalyzer(self.confidence_calculator)
    
    def _create_resource_analyzer(self) -> ResourceAnalyzer:
        """Create resource analyzer with dependency injection"""
        return ResourceAnalyzer(self.confidence_calculator)
    
    def _create_risk_assessor(self) -> RiskAssessor:
        """Create risk assessor with dependency injection"""
        return RiskAssessor()
    
    def _create_formatter(self) -> NetworkCleartextFormatter:
        """Create formatter with dependency injection"""
        return NetworkCleartextFormatter()
    
    def _map_to_finding_type(self, finding_type_str: str):
        """Map string finding type to enum (helper method)"""
        from .data_structures import FindingType
        
        mapping = {
            'ANALYSIS_ERROR': FindingType.ANALYSIS_ERROR,
            'CLEARTEXT_ENABLED': FindingType.CLEARTEXT_ENABLED,
            'HTTP_URL_FOUND': FindingType.HTTP_URL_FOUND
        }
        
        return mapping.get(finding_type_str, FindingType.ANALYSIS_ERROR)

# Legacy compatibility class for existing plugin manager integration
class NetworkCleartextTrafficAnalyzer(NetworkCleartextTrafficPlugin):
    """
    Legacy compatibility wrapper for the original analyzer class.
    
    Maintains backward compatibility while using the new modular architecture.
    """
    
    def __init__(self, apk_ctx: APKContext):
        """Initialize with legacy interface"""
        super().__init__(apk_ctx)
        self.logger.debug("Legacy NetworkCleartextTrafficAnalyzer wrapper initialized")

def run(apk_ctx: APKContext) -> Tuple[str, Text]:
    """
    Main plugin entry point for AODS framework.
    
    Performs comprehensive network cleartext traffic analysis using modular architecture
    and returns detailed results with recommendations and verification commands.
    
    Args:
        apk_ctx: APK context containing manifest and analysis data
        
    Returns:
        Tuple of (title, analysis_result) where analysis_result contains
        comprehensive network security analysis with Rich formatting
    """
    logger = logging.getLogger(__name__)
    logger.debug("Starting Network Cleartext Traffic Analysis with modular architecture...")
    
    try:
        # Initialize plugin with modular architecture
        plugin = NetworkCleartextTrafficPlugin(apk_ctx)
        
        # Perform comprehensive analysis
        analysis_result = plugin.analyze()
        
        # Generate rich text output
        output = plugin.generate_rich_output(analysis_result)
        
        # Create title with status and summary
        title = f"Network Cleartext Traffic Analysis ({analysis_result.overall_status.value})"
        
        # Add summary to title if significant findings
        if analysis_result.findings:
            critical_count = len(analysis_result.get_critical_findings())
            if critical_count > 0:
                title += f" - {critical_count} Critical Issues"
            elif len(analysis_result.findings) > 5:
                title += f" - {len(analysis_result.findings)} Issues Found"
        
        logger.debug(
            f"Network cleartext traffic analysis completed - "
            f"Status: {analysis_result.overall_status.value}, "
            f"Risk: {analysis_result.risk_level.value}, "
            f"Findings: {len(analysis_result.findings)}, "
            f"Duration: {analysis_result.analysis_duration:.2f}s"
        )
        
        return title, output
        
    except Exception as e:
        logger.error(f"Error in network cleartext traffic analysis: {e}")
        
        # Generate error output
        error_output = Text()
        error_output.append("Network Cleartext Traffic Analysis - ERROR\n", style="bold red")
        error_output.append(f"Analysis failed: {str(e)}\n", style="red")
        error_output.append("This may indicate:\n", style="yellow")
        error_output.append("• Corrupted or invalid APK structure\n", style="yellow")
        error_output.append("• Missing AndroidManifest.xml file\n", style="yellow")
        error_output.append("• Insufficient file system permissions\n", style="yellow")
        error_output.append("\nRecommendations:\n", style="bold")
        error_output.append("• Verify APK extraction completed successfully\n")
        error_output.append("• Check AndroidManifest.xml exists and is readable\n")
        error_output.append("• Review file permissions in extracted APK directory\n")
        error_output.append("• Consider manual verification of network security settings\n")
        
        return "Network Cleartext Traffic Analysis (ERROR)", error_output

def run_plugin(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Plugin interface function expected by the plugin manager.
    
    Args:
        apk_ctx: The APKContext instance containing APK path and metadata
        
    Returns:
        Tuple[str, Union[str, Text]]: Plugin execution result with Rich formatting
    """
    return run(apk_ctx)

# Plugin metadata for AODS framework integration
PLUGIN_METADATA = {
    "name": "Network Cleartext Traffic Analyzer",
    "description": "Comprehensive analysis of cleartext traffic vulnerabilities and network security configuration using modular architecture",
    "version": "2.0.0",
    "author": "AODS Security Framework",
    "category": "NETWORK_SECURITY",
    "masvs_controls": ["MASVS-NETWORK-1", "MASVS-NETWORK-2"],
    "mastg_references": ["MASTG-TEST-0024", "MASTG-TEST-0025"],
    "risk_level": "HIGH",
    "mode": "safe",
    "requires_device": False,
    "requires_network": False,
    "invasive": False,
    "execution_time_estimate": 45,
    "dependencies": [],
    "modular_architecture": True,
    "components": [
        "manifest_analyzer",
        "nsc_analyzer", 
        "resource_analyzer",
        "risk_assessor",
        "confidence_calculator",
        "formatter"
    ],
    "confidence_system": "professional_evidence_based"
}

# Legacy compatibility metadata
PLUGIN_CHARACTERISTICS = {
    "mode": "safe",
    "category": "NETWORK_SECURITY",
    "masvs_control": "MASVS-NETWORK-1",
    "targets": ["cleartext_traffic", "network_security", "http_urls"],
    "modular": True
}

if __name__ == "__main__":
    # Plugin testing and validation
    print("🔒 Network Cleartext Traffic Analyzer Plugin (Modular Architecture)")
    print(f"Version: {PLUGIN_METADATA['version']}")
    print(f"MASVS Controls: {', '.join(PLUGIN_METADATA['masvs_controls'])}")
    print(f"MASTG References: {', '.join(PLUGIN_METADATA['mastg_references'])}")
    print(f"Components: {', '.join(PLUGIN_METADATA['components'])}")
    print("Ready for comprehensive network security analysis with professional confidence calculation") 