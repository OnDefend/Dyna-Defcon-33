"""
Enhanced Encoding and Cloud Analysis Plugin

This module provides comprehensive analysis of encoding methods and cloud service
integrations in Android applications implementing MASVS data protection requirements.

Features:
- Cloud service URL detection and analysis
- Encoding method detection (Base64, custom schemes)
- File analysis for sensitive data patterns
- Configuration file assessment
- Risk evaluation
- Confidence calculation
- Rich text reporting

Modular Components:
- cloud_service_analyzer.py: Cloud service detection
- encoding_analyzer.py: Encoding method analysis
- file_analyzers.py: File pattern analysis
- confidence_calculator.py: Confidence calculation
- formatters.py: Rich text output formatting
- data_structures.py: Core data classes

MASVS Controls: MASVS-STORAGE, MASVS-CRYPTO
"""

import logging
import subprocess
import os
import re
import time
from typing import Dict, List, Any, Optional, Tuple, Union, Set
from pathlib import Path

from rich.text import Text
from rich.console import Console

from core.apk_ctx import APKContext
from .data_structures import (
    ComprehensiveAnalysisResult, EncodingContext, 
    EncodingFinding, AnalysisConfiguration,
    EncodingType, CloudServiceType, SeverityLevel, FileType, AnalysisPattern
)
from .cloud_service_analyzer import CloudServiceAnalyzer
from .encoding_analyzer import AdvancedEncodingAnalyzer
from .file_analyzers import FileAnalysisOrchestrator
from .confidence_calculator import EnhancedEncodingCloudConfidenceCalculator
from .formatters import EnhancedEncodingCloudFormatter

logger = logging.getLogger(__name__)

# Plugin metadata
PLUGIN_METADATA = {
    "name": "Enhanced Encoding Cloud Analysis",
    "description": "Comprehensive encoding methods and cloud service integration analysis",
    "version": "2.0.0",
    "author": "AODS Development Team", 
    "category": "DATA_PROTECTION",
    "priority": "MEDIUM",
    "timeout": 90,
    "mode": "comprehensive",
    "requires_device": False,
    "requires_network": False,
    "invasive": False,
    "execution_time_estimate": 60,
    "dependencies": [],
    "modular_architecture": True,
    "components": [
        "cloud_service_analyzer",
        "encoding_analyzer",
        "file_analyzers", 
        "confidence_calculator"
    ],
    "security_controls": ["MASVS-STORAGE-1", "MASVS-CRYPTO-1"],
    "owasp_categories": ["M2", "M9"]
}

class EnhancedEncodingCloudAnalysisPlugin:
    """
    Main plugin class that orchestrates enhanced encoding and cloud analysis.
    
    This class provides the primary interface for the modular enhanced encoding
    and cloud analysis system, coordinating all specialized components to deliver
    comprehensive security analysis.
    """
    
    def __init__(self, console: Optional[Console] = None):
        """
        Initialize the enhanced encoding and cloud analysis plugin.
        
        Args:
            console: Optional Rich console for output formatting
        """
        self.console = console or Console()
        
        # Initialize core analyzers
        self.encoding_analyzer = AdvancedEncodingAnalyzer()
        self.cloud_analyzer = CloudServiceAnalyzer()
        
        # Initialize file analysis orchestrator
        self.file_orchestrator = FileAnalysisOrchestrator(
            self.encoding_analyzer, 
            self.cloud_analyzer
        )
        
        # Initialize confidence calculator
        self.confidence_calculator = EnhancedEncodingCloudConfidenceCalculator()
        
        # Initialize formatter
        self.formatter = EnhancedEncodingCloudFormatter(self.console)
        
        # Default configuration
        self.default_config = AnalysisConfiguration(
            enable_deep_analysis=True,
            analyze_binary_files=True,
            extract_strings_from_binaries=True,
            max_file_size_mb=50,
            max_encoding_chain_depth=5,
            confidence_threshold=0.7,
            analyze_source_files=True,
            analyze_resource_files=True,
            analyze_config_files=True,
            analyze_native_files=True,
            target_patterns=[
                AnalysisPattern.ANDROID_SECURITY,
                AnalysisPattern.FIREBASE_INTEGRATION,
                AnalysisPattern.AWS_CREDENTIALS,
                AnalysisPattern.ENCODING_CHAINS,
                AnalysisPattern.CLOUD_ENDPOINTS
            ]
        )
        
        logger.debug("Enhanced Encoding & Cloud Analysis Plugin initialized")
    
    def analyze(self, apk_ctx, config: Optional[AnalysisConfiguration] = None) -> ComprehensiveAnalysisResult:
        """
        Perform comprehensive enhanced encoding and cloud analysis.
        
        Args:
            apk_ctx: APK analysis context containing paths and metadata
            config: Optional analysis configuration
            
        Returns:
            ComprehensiveAnalysisResult with all findings and analysis data
        """
        start_time = time.time()
        analysis_config = config or self.default_config
        
        try:
            # Initialize analysis result
            result = ComprehensiveAnalysisResult(
                package_name=getattr(apk_ctx, 'package_name', 'Unknown'),
                analysis_duration=0.0,
                files_analyzed=0
            )
            
            logger.debug(f"Starting enhanced encoding & cloud analysis for {result.package_name}")
            
            # Collect files for analysis
            file_paths = self._collect_analysis_files(apk_ctx, analysis_config)
            result.files_analyzed = len(file_paths)
            
            if not file_paths:
                logger.warning("No files found for analysis")
                result.analysis_duration = time.time() - start_time
                return result
            
            # Perform file analysis
            file_results = self.file_orchestrator.analyze_files(file_paths, analysis_config)
            result.file_results = file_results
            
            # Consolidate findings
            result.consolidate_findings()
            
            # Calculate professional confidence scores
            self._calculate_confidence_scores(result)
            
            # Detect and analyze encoding chains
            result.encoding_chains = self._detect_comprehensive_encoding_chains(result)
            
            # Identify security patterns
            result.security_patterns = self._identify_security_patterns(result)
            
            # Generate recommendations and compliance assessment
            self._generate_recommendations(result)
            self._assess_masvs_compliance(result)
            
            # Finalize analysis
            result.analysis_duration = time.time() - start_time
            
            logger.debug(
                f"Analysis completed: {result.total_findings} findings in "
                f"{result.analysis_duration:.2f}s"
            )
            
            return result
            
        except Exception as e:
            error_msg = f"Enhanced encoding & cloud analysis failed: {e}"
            logger.error(error_msg)
            raise EncodingCloudAnalysisError(error_msg, {
                'package_name': getattr(apk_ctx, 'package_name', 'Unknown'),
                'analysis_duration': time.time() - start_time
            }) from e
    
    def generate_report(self, result: ComprehensiveAnalysisResult, 
                       format_type: str = "rich") -> Union[Text, str]:
        """
        Generate formatted analysis report.
        
        Args:
            result: ComprehensiveAnalysisResult to format
            format_type: Output format ("rich", "json", "summary_json")
            
        Returns:
            Formatted report as Rich Text or JSON string
        """
        try:
            if format_type == "rich":
                return self.formatter.format_comprehensive_report(result)
            elif format_type == "json":
                return self.formatter.export_to_json(result, include_metadata=True)
            elif format_type == "summary_json":
                return self.formatter.export_summary_json(result)
            else:
                raise ValueError(f"Unsupported format type: {format_type}")
                
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            raise EncodingCloudAnalysisError(f"Report generation failed: {e}") from e
    
    def display_results(self, result: ComprehensiveAnalysisResult):
        """
        Display comprehensive analysis results to console.
        
        Args:
            result: ComprehensiveAnalysisResult to display
        """
        try:
            self.formatter.generate_console_output(result)
        except Exception as e:
            logger.error(f"Error displaying results: {e}")
            self.console.print(f"[red]Error displaying results: {e}[/red]")
    
    def analyze_with_report(self, apk_ctx, 
                           config: Optional[AnalysisConfiguration] = None,
                           display_output: bool = True) -> Tuple[ComprehensiveAnalysisResult, Text]:
        """
        Perform analysis and generate report in one operation.
        
        Args:
            apk_ctx: APK analysis context
            config: Optional analysis configuration
            display_output: Whether to display results to console
            
        Returns:
            Tuple of (analysis_result, formatted_report)
        """
        # Perform analysis
        result = self.analyze(apk_ctx, config)
        
        # Generate report
        report = self.generate_report(result, format_type="rich")
        
        # Display if requested
        if display_output:
            self.display_results(result)
        
        return result, report
    
    def get_plugin_info(self) -> Dict[str, Any]:
        """
        Get information about the plugin and its capabilities.
        
        Returns:
            Dictionary with plugin information
        """
        return {
            'name': 'Enhanced Encoding & Cloud Analysis',
            'version': '2.0.0',
            'description': 'Comprehensive analysis of encoding patterns and cloud service configurations',
            'capabilities': [
                'Advanced Base64 detection',
                'ROT47/ROT13 encoding analysis',
                'Multi-layer encoding chain detection',
                'Firebase security configuration analysis',
                'AWS credentials exposure detection',
                'Google Cloud service analysis',
                'Azure configuration security',
                'confidence scoring',
                'MASVS compliance mapping'
            ],
            'supported_file_types': [ft.value for ft in self.file_orchestrator.get_supported_file_types()],
            'analysis_patterns': [pattern.value for pattern in AnalysisPattern],
            'confidence_methodology': 'Evidence-based multi-factor scoring',
            'output_formats': ['rich_text', 'json', 'summary_json']
        }
    
    def validate_configuration(self, config: AnalysisConfiguration) -> List[str]:
        """
        Validate analysis configuration and return any issues.
        
        Args:
            config: AnalysisConfiguration to validate
            
        Returns:
            List of validation issues (empty if valid)
        """
        issues = []
        
        if config.max_file_size_mb <= 0:
            issues.append("max_file_size_mb must be positive")
        
        if config.max_encoding_chain_depth <= 0:
            issues.append("max_encoding_chain_depth must be positive")
        
        if not (0.0 <= config.confidence_threshold <= 1.0):
            issues.append("confidence_threshold must be between 0.0 and 1.0")
        
        if not any([config.analyze_source_files, config.analyze_resource_files,
                   config.analyze_config_files, config.analyze_native_files]):
            issues.append("At least one file type must be enabled for analysis")
        
        return issues
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """
        Get analysis statistics from all components.
        
        Returns:
            Dictionary with comprehensive analysis statistics
        """
        stats = {
            'encoding_analyzer': self.encoding_analyzer.get_analysis_statistics(),
            'cloud_analyzer': self.cloud_analyzer.get_analysis_statistics(),
            'file_orchestrator': self.file_orchestrator.get_analysis_statistics(),
            'supported_patterns': len(AnalysisPattern),
            'supported_file_types': len(self.file_orchestrator.get_supported_file_types())
        }
        
        return stats
    
    # Private helper methods
    
    def _collect_analysis_files(self, apk_ctx, config: AnalysisConfiguration) -> List[str]:
        """Collect files for analysis based on configuration and APK context."""
        file_paths = []
        
        try:
            # Collect from decompiled source (JADX output)
            if config.analyze_source_files and hasattr(apk_ctx, 'jadx_output_dir'):
                jadx_files = self._collect_files_from_directory(
                    apk_ctx.jadx_output_dir,
                    ['.java', '.kt', '.dart'],
                    config.max_file_size_mb
                )
                file_paths.extend(jadx_files)
            
            # Collect from resources (APKTool output)
            if config.analyze_resource_files and hasattr(apk_ctx, 'apktool_output_dir'):
                apktool_files = self._collect_files_from_directory(
                    apk_ctx.apktool_output_dir,
                    ['.xml', '.json', '.txt', '.properties'],
                    config.max_file_size_mb
                )
                file_paths.extend(apktool_files)
            
            # Collect configuration files
            if config.analyze_config_files:
                config_files = self._find_config_files(apk_ctx, config.max_file_size_mb)
                file_paths.extend(config_files)
            
            # Collect native files
            if config.analyze_native_files:
                native_files = self._find_native_files(apk_ctx, config.max_file_size_mb)
                file_paths.extend(native_files)
            
            # Remove duplicates and sort
            file_paths = sorted(list(set(file_paths)))
            
            logger.debug(f"Collected {len(file_paths)} files for analysis")
            
        except Exception as e:
            logger.error(f"Error collecting files for analysis: {e}")
        
        return file_paths
    
    def _collect_files_from_directory(self, directory: str, extensions: List[str], 
                                     max_size_mb: int) -> List[str]:
        """Collect files from directory with extension and size filtering."""
        files = []
        
        if not directory or not os.path.exists(directory):
            return files
        
        try:
            for root, dirs, filenames in os.walk(directory):
                for filename in filenames:
                    if any(filename.lower().endswith(ext) for ext in extensions):
                        file_path = os.path.join(root, filename)
                        
                        # Check file size
                        try:
                            file_size = os.path.getsize(file_path)
                            max_size_bytes = max_size_mb * 1024 * 1024
                            
                            if file_size <= max_size_bytes:
                                files.append(file_path)
                        except OSError:
                            continue
        
        except Exception as e:
            logger.debug(f"Error collecting files from {directory}: {e}")
        
        return files
    
    def _find_config_files(self, apk_ctx, max_size_mb: int) -> List[str]:
        """Find configuration files in APK context."""
        config_files = []
        
        # Look for configuration files in common locations
        config_extensions = ['.conf', '.config', '.ini', '.cfg', '.env', '.plist']
        
        # Check APKTool output
        if hasattr(apk_ctx, 'apktool_output_dir') and apk_ctx.apktool_output_dir:
            config_files.extend(
                self._collect_files_from_directory(
                    apk_ctx.apktool_output_dir, config_extensions, max_size_mb
                )
            )
        
        return config_files
    
    def _find_native_files(self, apk_ctx, max_size_mb: int) -> List[str]:
        """Find native binary files in APK context."""
        native_files = []
        
        # Look for native libraries
        native_extensions = ['.so', '.a', '.dylib']
        
        # Check for lib directory in APKTool output
        if hasattr(apk_ctx, 'apktool_output_dir') and apk_ctx.apktool_output_dir:
            lib_dir = os.path.join(apk_ctx.apktool_output_dir, 'lib')
            if os.path.exists(lib_dir):
                native_files.extend(
                    self._collect_files_from_directory(
                        lib_dir, native_extensions, max_size_mb
                    )
                )
        
        return native_files
    
    def _calculate_confidence_scores(self, result: ComprehensiveAnalysisResult):
        """Calculate professional confidence scores for all findings."""
        try:
            # Calculate confidence for encoding findings
            for finding in result.all_encoding_findings:
                if finding.confidence == 0.0:  # Only calculate if not already set
                    finding.confidence = self.confidence_calculator.calculate_encoding_confidence(finding)
            
            # Calculate confidence for cipher findings
            for finding in result.all_cipher_findings:
                if finding.confidence == 0.0:
                    finding.confidence = self.confidence_calculator.calculate_cipher_confidence(finding)
            
            # Calculate confidence for cloud service findings
            for finding in result.all_cloud_findings:
                if finding.confidence == 0.0:
                    finding.confidence = self.confidence_calculator.calculate_cloud_service_confidence(finding)
            
            logger.debug("confidence scores calculated for all findings")
            
        except Exception as e:
            logger.error(f"Error calculating confidence scores: {e}")
    
    def _detect_comprehensive_encoding_chains(self, result: ComprehensiveAnalysisResult) -> List:
        """Detect comprehensive encoding chains across all findings."""
        chains = []
        
        try:
            # Look for multi-layer encoding patterns in findings
            for finding in result.all_encoding_findings:
                if finding.encoding_chain and len(finding.encoding_chain) > 1:
                    # This is already a chain, add to comprehensive chains
                    chains.append({
                        'chain': finding.encoding_chain,
                        'confidence': finding.confidence,
                        'location': getattr(finding, 'location', 'Unknown'),
                        'type': 'detected_chain'
                    })
            
            # Additional chain detection logic would go here
            
        except Exception as e:
            logger.error(f"Error detecting encoding chains: {e}")
        
        return chains
    
    def _identify_security_patterns(self, result: ComprehensiveAnalysisResult) -> List:
        """Identify security patterns across all findings."""
        patterns = []
        
        try:
            # Analyze patterns across all findings
            # Implementation would identify cross-cutting security patterns
            
            # Group findings by encoding type to identify patterns
            encoding_groups = {}
            for finding in result.all_encoding_findings:
                encoding_type = getattr(finding, 'encoding_type', 'unknown')
                if encoding_type not in encoding_groups:
                    encoding_groups[encoding_type] = []
                encoding_groups[encoding_type].append(finding)
            
            # Identify patterns within each encoding type
            for encoding_type, findings in encoding_groups.items():
                if len(findings) > 2:  # Pattern needs at least 3 instances
                    patterns.append({
                        'type': 'repeated_encoding',
                        'encoding_type': encoding_type,
                        'count': len(findings),
                        'confidence': min(0.9, 0.5 + (len(findings) * 0.1)),
                        'description': f"Repeated use of {encoding_type} encoding ({len(findings)} instances)"
                    })
            
            # Look for suspicious encoding combinations
            if result.all_encoding_findings:
                base64_count = len([f for f in result.all_encoding_findings if 'base64' in getattr(f, 'encoding_type', '').lower()])
                hex_count = len([f for f in result.all_encoding_findings if 'hex' in getattr(f, 'encoding_type', '').lower()])
                url_count = len([f for f in result.all_encoding_findings if 'url' in getattr(f, 'encoding_type', '').lower()])
                
                if base64_count > 0 and hex_count > 0:
                    patterns.append({
                        'type': 'mixed_encoding',
                        'encodings': ['base64', 'hex'],
                        'confidence': 0.7,
                        'description': f"Mixed encoding usage: {base64_count} base64, {hex_count} hex encodings"
                    })
                
                if base64_count > 5:  # Many base64 encodings might indicate obfuscation
                    patterns.append({
                        'type': 'potential_obfuscation',
                        'encoding_type': 'base64',
                        'count': base64_count,
                        'confidence': min(0.9, 0.6 + (base64_count * 0.05)),
                        'description': f"High base64 usage ({base64_count} instances) may indicate data obfuscation"
                    })
                
                # Check for potential data exfiltration patterns
                if url_count > 0 and (base64_count > 0 or hex_count > 0):
                    patterns.append({
                        'type': 'potential_exfiltration',
                        'encodings': ['url_encoding', 'data_encoding'],
                        'confidence': 0.6,
                        'description': f"URL encoding combined with data encoding may indicate exfiltration attempts"
                    })
            
        except Exception as e:
            logger.error(f"Error identifying security patterns: {e}")
        
        return patterns
    
    def _generate_recommendations(self, result: ComprehensiveAnalysisResult):
        """Generate security recommendations based on findings."""
        recommendations = set()
        
        try:
            # Collect recommendations from all findings
            for finding in result.all_encoding_findings:
                recommendations.update(finding.recommendations)
            
            for finding in result.all_cipher_findings:
                recommendations.update(finding.recommendations)
            
            for finding in result.all_cloud_findings:
                recommendations.update(finding.recommendations)
            
            # Add general recommendations based on finding patterns
            if result.critical_issues > 0:
                recommendations.add("Immediately address critical security issues")
            
            if result.all_cloud_findings:
                recommendations.add("Review cloud service configurations for security best practices")
            
            if result.encoding_chains:
                recommendations.add("Investigate multi-layer encoding usage for potential obfuscation")
            
            result.recommendations = list(recommendations)
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
    
    def _assess_masvs_compliance(self, result: ComprehensiveAnalysisResult):
        """Assess MASVS compliance based on findings."""
        masvs_controls = set()
        
        try:
            # Collect MASVS controls from findings
            for finding in result.all_encoding_findings:
                if finding.masvs_control:
                    masvs_controls.add(finding.masvs_control)
            
            for finding in result.all_cipher_findings:
                if finding.masvs_control:
                    masvs_controls.add(finding.masvs_control)
            
            for finding in result.all_cloud_findings:
                if finding.masvs_control:
                    masvs_controls.add(finding.masvs_control)
            
            result.masvs_controls = list(masvs_controls)
            
        except Exception as e:
            logger.error(f"Error assessing MASVS compliance: {e}")

# Plugin interface functions for backward compatibility
def run_plugin(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Run the enhanced encoding and cloud analysis plugin.
    
    This function provides the main entry point for the plugin, maintaining
    backward compatibility with the existing plugin framework.
    
    Args:
        apk_ctx: APK analysis context containing paths and metadata
        
    Returns:
        Tuple of (title, content) for the security report
    """
    try:
        # Initialize plugin
        plugin = EnhancedEncodingCloudAnalysisPlugin()
        
        # Perform analysis
        result, report = plugin.analyze_with_report(apk_ctx, display_output=False)
        
        # Return title and formatted content
        title = "Enhanced Encoding & Cloud Analysis"
        
        return title, report
        
    except Exception as e:
        logger.error(f"Enhanced encoding & cloud analysis plugin failed: {e}")
        error_text = Text()
        error_text.append("Enhanced Encoding & Cloud Analysis Failed\n", style="bold red")
        error_text.append(f"Error: {str(e)}\n", style="red")
        error_text.append("\nThis may be due to:\n", style="yellow")
        error_text.append("• Missing decompiled files (JADX/APKTool output)\n")
        error_text.append("• Insufficient permissions to read files\n")
        error_text.append("• Corrupted APK structure\n")
        
        return "Enhanced Encoding & Cloud Analysis - Error", error_text

def run(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Alternative entry point for the enhanced encoding and cloud analysis plugin.
    
    Args:
        apk_ctx: APK analysis context
        
    Returns:
        Tuple of (title, content) for the security report
    """
    return run_plugin(apk_ctx) 