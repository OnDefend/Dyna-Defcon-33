"""
Traversal Vulnerabilities Analysis Plugin - Modular Implementation

This module provides the main orchestration for the traversal vulnerabilities analysis plugin.
It coordinates between all specialized modules to deliver comprehensive path traversal analysis.

Modular Architecture:
- data_structures.py: Core data classes and enums
- confidence_calculator.py: confidence calculation system
- analyzer.py: Core analysis engine for traversal vulnerabilities
- formatter.py: reporting and output formatting
- __init__.py: Main orchestration and coordination
"""

import logging
import time
from typing import Dict, List, Tuple, Union, Any, Optional
from pathlib import Path

from .data_structures import (
    TraversalVulnerability, ContentProviderAnalysis, IntentFilterAnalysis,
    FileOperationAnalysis, TraversalAnalysisConfig, TraversalAnalysisResult,
    TraversalType, SeverityLevel, RiskLevel, PayloadGenerationResult,
    SecurityControlAssessment, MAVSTraversalControls, CWETraversalCategories
)
from .confidence_calculator import TraversalConfidenceCalculator
from .analyzer import TraversalVulnerabilityAnalyzer
from .formatter import TraversalVulnerabilityFormatter

logger = logging.getLogger(__name__)

class EnhancedTraversalAnalyzer:
    """
    Enhanced Traversal Vulnerability Analyzer - Modular Implementation
    
    Provides comprehensive path traversal and directory traversal analysis
    through a modular architecture with proper separation of concerns.
    """
    
    def __init__(self, apk_ctx, config: Optional[TraversalAnalysisConfig] = None):
        """Initialize the enhanced traversal analyzer."""
        self.apk_ctx = apk_ctx
        self.config = config or TraversalAnalysisConfig()
        
        # Initialize modular components
        self.analyzer = TraversalVulnerabilityAnalyzer(self.config)
        self.confidence_calculator = TraversalConfidenceCalculator()
        self.formatter = TraversalVulnerabilityFormatter()
        
        # Analysis tracking
        self.analysis_start_time = None
        self.analysis_metadata = {
            'analyzed_files': 0,
            'skipped_files': 0,
            'failed_analyses': [],
            'vulnerability_counts': {},
            'analysis_duration': 0.0
        }
        
        # Results storage
        self.vulnerabilities = []
        self.content_providers = []
        self.intent_filters = []
        self.file_operations = []
        
        logger.debug("Enhanced Traversal Analyzer initialized (modular)")
    
    def analyze(self) -> Tuple[str, Union[str, Any]]:
        """
        Main analysis entry point that orchestrates the complete traversal analysis.
        
        Returns:
            Tuple[str, Union[str, Any]]: (analysis_type, formatted_report)
        """
        try:
            self.analysis_start_time = time.time()
            
            logger.debug("Starting enhanced traversal vulnerability analysis")
            
            # Analyze all available content
            self._analyze_all_content()
            
            # Analyze content providers
            if self.config.enable_content_provider_analysis:
                self._analyze_content_providers()
            
            # Analyze intent filters
            if self.config.enable_intent_filter_analysis:
                self._analyze_intent_filters()
            
            # Analyze file operations
            if self.config.enable_file_operation_analysis:
                self._analyze_file_operations()
            
            # Generate payloads if enabled
            if self.config.enable_payload_generation:
                self._generate_payloads()
            
            # Create comprehensive results
            results = self._create_analysis_results()
            
            # Format and return results
            formatted_report = self.formatter.format_analysis_results(results)
            
            # Log completion statistics
            self._log_analysis_statistics()
            
            logger.debug("Enhanced traversal vulnerability analysis completed successfully")
            return "enhanced_traversal_analysis", formatted_report
            
        except Exception as e:
            logger.error(f"Enhanced traversal vulnerability analysis failed: {e}")
            error_report = self.formatter.format_error_report(str(e))
            return "enhanced_traversal_analysis", error_report
    
    def _analyze_all_content(self) -> None:
        """Analyze all available content for traversal vulnerabilities."""
        try:
            # Analyze AndroidManifest.xml
            if hasattr(self.apk_ctx, 'manifest_content'):
                manifest_vulns = self.analyzer.analyze_content(
                    self.apk_ctx.manifest_content,
                    "AndroidManifest.xml"
                )
                self.vulnerabilities.extend(manifest_vulns)
                self.analysis_metadata['analyzed_files'] += 1
            
            # Analyze Java/Kotlin source files
            if hasattr(self.apk_ctx, 'java_files'):
                for java_file in self.apk_ctx.java_files:
                    try:
                        java_vulns = self.analyzer.analyze_content(
                            java_file.get('content', ''),
                            java_file.get('path', '')
                        )
                        self.vulnerabilities.extend(java_vulns)
                        self.analysis_metadata['analyzed_files'] += 1
                    except Exception as e:
                        logger.warning(f"Failed to analyze Java file: {e}")
                        self.analysis_metadata['skipped_files'] += 1
            
            # Analyze DEX files
            if hasattr(self.apk_ctx, 'dex_files'):
                for dex_file in self.apk_ctx.dex_files:
                    try:
                        # Convert DEX content to string for analysis
                        dex_content = str(dex_file.get('content', ''))
                        dex_vulns = self.analyzer.analyze_content(
                            dex_content,
                            dex_file.get('path', '')
                        )
                        self.vulnerabilities.extend(dex_vulns)
                        self.analysis_metadata['analyzed_files'] += 1
                    except Exception as e:
                        logger.warning(f"Failed to analyze DEX file: {e}")
                        self.analysis_metadata['skipped_files'] += 1
            
            # Analyze resources
            if hasattr(self.apk_ctx, 'resources'):
                for resource_path, resource_content in self.apk_ctx.resources.items():
                    try:
                        resource_vulns = self.analyzer.analyze_content(
                            resource_content,
                            resource_path
                        )
                        self.vulnerabilities.extend(resource_vulns)
                        self.analysis_metadata['analyzed_files'] += 1
                    except Exception as e:
                        logger.warning(f"Failed to analyze resource {resource_path}: {e}")
                        self.analysis_metadata['skipped_files'] += 1
            
            logger.debug(f"Analyzed {self.analysis_metadata['analyzed_files']} files, found {len(self.vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error during content analysis: {e}")
            self.analysis_metadata['failed_analyses'].append({
                'phase': 'content_analysis',
                'error': str(e)
            })
    
    def _analyze_content_providers(self) -> None:
        """Analyze content providers for traversal vulnerabilities."""
        try:
            if not hasattr(self.apk_ctx, 'manifest_content'):
                return
            
            # This would typically involve more detailed analysis
            # For now, we'll collect provider information from vulnerabilities
            provider_vulns = [v for v in self.vulnerabilities if v.traversal_type == TraversalType.CONTENT_PROVIDER.value]
            
            # Group vulnerabilities by provider
            provider_groups = {}
            for vuln in provider_vulns:
                provider_name = vuln.location
                if provider_name not in provider_groups:
                    provider_groups[provider_name] = []
                provider_groups[provider_name].append(vuln)
            
            # Create content provider analyses
            for provider_name, vulns in provider_groups.items():
                analysis = ContentProviderAnalysis(
                    provider_name=provider_name,
                    authority="unknown",
                    exported=True,  # Assuming exported if vulnerabilities found
                    permissions=[],
                    grant_uri_permissions=False,
                    path_permissions=[],
                    vulnerabilities=vulns,
                    risk_level=self._assess_provider_risk(vulns)
                )
                self.content_providers.append(analysis)
            
            logger.debug(f"Analyzed {len(self.content_providers)} content providers")
            
        except Exception as e:
            logger.error(f"Error during content provider analysis: {e}")
            self.analysis_metadata['failed_analyses'].append({
                'phase': 'content_provider_analysis',
                'error': str(e)
            })
    
    def _analyze_intent_filters(self) -> None:
        """Analyze intent filters for traversal vulnerabilities."""
        try:
            # Collect intent-based vulnerabilities
            intent_vulns = [v for v in self.vulnerabilities if v.traversal_type == TraversalType.INTENT_BASED.value]
            
            # Group vulnerabilities by component
            intent_groups = {}
            for vuln in intent_vulns:
                component_name = vuln.location
                if component_name not in intent_groups:
                    intent_groups[component_name] = []
                intent_groups[component_name].append(vuln)
            
            # Create intent filter analyses
            for component_name, vulns in intent_groups.items():
                analysis = IntentFilterAnalysis(
                    component_name=component_name,
                    action="unknown",
                    data_scheme="unknown",
                    data_host="unknown",
                    data_path="unknown",
                    data_path_pattern="unknown",
                    data_path_prefix="unknown",
                    exported=True,  # Assuming exported if vulnerabilities found
                    vulnerabilities=vulns,
                    risk_assessment=self._assess_intent_risk(vulns)
                )
                self.intent_filters.append(analysis)
            
            logger.debug(f"Analyzed {len(self.intent_filters)} intent filters")
            
        except Exception as e:
            logger.error(f"Error during intent filter analysis: {e}")
            self.analysis_metadata['failed_analyses'].append({
                'phase': 'intent_filter_analysis',
                'error': str(e)
            })
    
    def _analyze_file_operations(self) -> None:
        """Analyze file operations for traversal vulnerabilities."""
        try:
            # Collect file operation vulnerabilities
            file_vulns = [v for v in self.vulnerabilities 
                         if v.traversal_type in [TraversalType.PATH_TRAVERSAL.value, 
                                               TraversalType.DIRECTORY_TRAVERSAL.value,
                                               TraversalType.FILE_INCLUSION.value]]
            
            # Group vulnerabilities by operation type
            operation_groups = {}
            for vuln in file_vulns:
                operation_type = vuln.traversal_type
                if operation_type not in operation_groups:
                    operation_groups[operation_type] = []
                operation_groups[operation_type].append(vuln)
            
            # Create file operation analyses
            for operation_type, vulns in operation_groups.items():
                analysis = FileOperationAnalysis(
                    operation_type=operation_type,
                    file_path="multiple",
                    validation_present=False,  # Assuming no validation if vulnerabilities found
                    sanitization_present=False,
                    user_input_source="unknown",
                    vulnerabilities=vulns,
                    security_controls=[],
                    bypass_techniques=self._extract_bypass_techniques(vulns)
                )
                self.file_operations.append(analysis)
            
            logger.debug(f"Analyzed {len(self.file_operations)} file operations")
            
        except Exception as e:
            logger.error(f"Error during file operation analysis: {e}")
            self.analysis_metadata['failed_analyses'].append({
                'phase': 'file_operation_analysis',
                'error': str(e)
            })
    
    def _generate_payloads(self) -> None:
        """Generate test payloads for discovered vulnerabilities."""
        try:
            payload_count = 0
            
            for vuln in self.vulnerabilities:
                if payload_count >= self.config.max_payloads_per_vulnerability * len(self.vulnerabilities):
                    break
                
                payload_result = self.analyzer.generate_payloads(vuln)
                if payload_result.generated_payloads:
                    vuln.payload_examples = payload_result.generated_payloads
                    payload_count += len(payload_result.generated_payloads)
            
            logger.debug(f"Generated {payload_count} test payloads")
            
        except Exception as e:
            logger.error(f"Error during payload generation: {e}")
            self.analysis_metadata['failed_analyses'].append({
                'phase': 'payload_generation',
                'error': str(e)
            })
    
    def _create_analysis_results(self) -> TraversalAnalysisResult:
        """Create comprehensive analysis results."""
        # Calculate overall risk score
        overall_risk_score = self._calculate_overall_risk_score()
        
        # Assess security level
        security_assessment = self._assess_security_level(overall_risk_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations()
        
        # Assess MASVS compliance
        masvs_compliance = self._assess_masvs_compliance()
        
        # Generate CWE mappings
        cwe_mappings = self._generate_cwe_mappings()
        
        # Update analysis metadata
        self.analysis_metadata['vulnerability_counts'] = self._count_vulnerabilities_by_type()
        self.analysis_metadata['analysis_duration'] = time.time() - self.analysis_start_time if self.analysis_start_time else 0.0
        
        return TraversalAnalysisResult(
            vulnerabilities=self.vulnerabilities,
            content_provider_analyses=self.content_providers,
            intent_filter_analyses=self.intent_filters,
            file_operation_analyses=self.file_operations,
            overall_risk_score=overall_risk_score,
            security_assessment=security_assessment,
            recommendations=recommendations,
            masvs_compliance=masvs_compliance,
            cwe_mappings=cwe_mappings,
            analysis_metadata=self.analysis_metadata
        )
    
    def _calculate_overall_risk_score(self) -> float:
        """Calculate overall risk score based on vulnerabilities."""
        if not self.vulnerabilities:
            return 0.0
        
        severity_weights = {
            SeverityLevel.CRITICAL.value: 10.0,
            SeverityLevel.HIGH.value: 7.0,
            SeverityLevel.MEDIUM.value: 5.0,
            SeverityLevel.LOW.value: 3.0,
            SeverityLevel.INFO.value: 1.0
        }
        
        total_score = 0.0
        max_possible_score = 0.0
        
        for vuln in self.vulnerabilities:
            weight = severity_weights.get(vuln.severity, 5.0)
            total_score += weight * vuln.confidence
            max_possible_score += weight
        
        if max_possible_score == 0:
            return 0.0
        
        return (total_score / max_possible_score) * 10.0
    
    def _assess_security_level(self, risk_score: float) -> str:
        """Assess security level based on risk score."""
        if risk_score >= 8.0:
            return RiskLevel.CRITICAL.value
        elif risk_score >= 6.0:
            return RiskLevel.HIGH.value
        elif risk_score >= 4.0:
            return RiskLevel.MEDIUM.value
        elif risk_score >= 2.0:
            return RiskLevel.LOW.value
        else:
            return RiskLevel.MINIMAL.value
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        # Base recommendations
        if self.vulnerabilities:
            recommendations.append("Implement comprehensive input validation for all user inputs")
            recommendations.append("Use canonicalization to resolve path references")
            recommendations.append("Implement allowlist-based path validation")
            recommendations.append("Avoid direct file system access from user inputs")
        
        # Type-specific recommendations
        path_traversal_vulns = [v for v in self.vulnerabilities if v.traversal_type == TraversalType.PATH_TRAVERSAL.value]
        if path_traversal_vulns:
            recommendations.append("Implement proper path traversal protection mechanisms")
        
        content_provider_vulns = [v for v in self.vulnerabilities if v.traversal_type == TraversalType.CONTENT_PROVIDER.value]
        if content_provider_vulns:
            recommendations.append("Secure content provider configurations and permissions")
        
        webview_vulns = [v for v in self.vulnerabilities if v.traversal_type == TraversalType.WEBVIEW_BASED.value]
        if webview_vulns:
            recommendations.append("Implement secure WebView configuration and URL validation")
        
        return recommendations
    
    def _assess_masvs_compliance(self) -> List[str]:
        """Assess MASVS compliance based on findings."""
        compliance = set()
        
        for vuln in self.vulnerabilities:
            compliance.update(vuln.masvs_refs)
        
        # Add default MASVS controls for traversal vulnerabilities
        compliance.add(MAVSTraversalControls.PLATFORM_1)
        compliance.add(MAVSTraversalControls.CODE_8)
        
        return list(compliance)
    
    def _generate_cwe_mappings(self) -> List[str]:
        """Generate CWE mappings based on findings."""
        cwe_mappings = set()
        
        for vuln in self.vulnerabilities:
            if vuln.cwe_id:
                cwe_mappings.add(vuln.cwe_id)
        
        return list(cwe_mappings)
    
    def _count_vulnerabilities_by_type(self) -> Dict[str, int]:
        """Count vulnerabilities by type."""
        counts = {}
        
        for vuln in self.vulnerabilities:
            vuln_type = vuln.traversal_type
            counts[vuln_type] = counts.get(vuln_type, 0) + 1
        
        return counts
    
    def _assess_provider_risk(self, vulns: List[TraversalVulnerability]) -> str:
        """Assess risk level for content provider."""
        if not vulns:
            return RiskLevel.LOW.value
        
        max_severity = max(vuln.severity for vuln in vulns)
        
        if max_severity == SeverityLevel.CRITICAL.value:
            return RiskLevel.CRITICAL.value
        elif max_severity == SeverityLevel.HIGH.value:
            return RiskLevel.HIGH.value
        else:
            return RiskLevel.MEDIUM.value
    
    def _assess_intent_risk(self, vulns: List[TraversalVulnerability]) -> str:
        """Assess risk level for intent filter."""
        return self._assess_provider_risk(vulns)  # Same logic
    
    def _extract_bypass_techniques(self, vulns: List[TraversalVulnerability]) -> List[str]:
        """Extract bypass techniques from vulnerabilities."""
        techniques = set()
        
        for vuln in vulns:
            if hasattr(vuln, 'bypass_methods'):
                techniques.update(vuln.bypass_methods)
        
        return list(techniques)
    
    def _log_analysis_statistics(self) -> None:
        """Log analysis statistics."""
        duration = time.time() - self.analysis_start_time if self.analysis_start_time else 0.0
        
        logger.debug("=== TRAVERSAL VULNERABILITY ANALYSIS STATISTICS ===")
        logger.debug(f"Files analyzed: {self.analysis_metadata['analyzed_files']}")
        logger.debug(f"Files skipped: {self.analysis_metadata['skipped_files']}")
        logger.debug(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        logger.debug(f"Content providers analyzed: {len(self.content_providers)}")
        logger.debug(f"Intent filters analyzed: {len(self.intent_filters)}")
        logger.debug(f"File operations analyzed: {len(self.file_operations)}")
        logger.debug(f"Failed analyses: {len(self.analysis_metadata['failed_analyses'])}")
        logger.debug(f"Analysis duration: {duration:.2f}s")
        logger.debug("=== END STATISTICS ===")

# Export classes for backward compatibility
__all__ = [
    'EnhancedTraversalAnalyzer',
    'TraversalVulnerability',
    'TraversalAnalysisConfig',
    'TraversalAnalysisResult'
] 

# Plugin compatibility functions
def run(apk_ctx):
    """
    Main plugin entry point for compatibility with plugin manager.
    
    Args:
        apk_ctx: APK context object
        
    Returns:
        Tuple of (plugin_name, result)
    """
    try:
        from rich.text import Text
        
        # Create analyzer with APK context - Fixed: Use EnhancedTraversalAnalyzer instead
        analyzer = EnhancedTraversalAnalyzer(apk_ctx)
        
        # Perform analysis
        analysis_type, result = analyzer.analyze()
        
        # Format results
        if hasattr(result, 'vulnerabilities') and result.vulnerabilities:
            findings_text = Text()
            findings_text.append(f"Traversal Vulnerability Analysis - {len(result.vulnerabilities)} findings\n", style="bold blue")
            
            for finding in result.vulnerabilities[:10]:
                findings_text.append(f"• {finding.title}\n", style="yellow")
                findings_text.append(f"  {finding.description}\n", style="dim")
        else:
            findings_text = Text("Traversal Vulnerability Analysis completed - No vulnerabilities found", style="green")
            
        return "Traversal Vulnerability Analysis", findings_text
        
    except Exception as e:
        logger.error(f"Traversal vulnerability analysis failed: {e}")
        error_text = Text(f"Traversal Vulnerability Analysis Error: {str(e)}", style="red")
        return "Traversal Vulnerability Analysis", error_text

def run_plugin(apk_ctx):
    """
    Plugin interface function expected by the plugin manager.
    
    Args:
        apk_ctx: APK context object
        
    Returns:
        Tuple of (plugin_name, result)
    """
    return run(apk_ctx)

# Add run functions to exports
__all__.extend(['run', 'run_plugin']) 