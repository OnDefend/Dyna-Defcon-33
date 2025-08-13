"""
Enhanced Root Detection Bypass Analyzer Plugin - Modular Implementation

This module provides the main orchestration for the enhanced root detection bypass analyzer plugin.
It coordinates between all specialized modules to deliver comprehensive root detection analysis.

Modular Architecture:
- data_structures.py: Core data classes and enums
- confidence_calculator.py: confidence calculation system
- root_analyzer.py: Core analysis engine
- formatters.py: reporting and output formatting
- root_patterns_config.yaml: External pattern configuration
"""

import os
import time
import logging
from typing import Dict, List, Tuple, Union, Any, Optional
from pathlib import Path
import threading

# Import unified deduplication framework
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)

from .data_structures import (
    RootDetectionFinding, SecurityControlAssessment, BypassAnalysisResult,
    RootDetectionAnalysisConfig, RootDetectionAnalysisResult,
    RootDetectionType, BypassTechnique, SecurityControlType,
    DetectionMethodMetrics, ExecutionStatistics
)
from .confidence_calculator import EnhancedRootDetectionConfidenceCalculator
from .root_analyzer import RootDetectionAnalyzer
from .formatters import RootDetectionFormatter

logger = logging.getLogger(__name__)

class EnhancedRootDetectionBypassAnalyzer:
    """
    Enhanced Root Detection Bypass Analyzer - Modular Implementation
    
    Provides comprehensive root detection and bypass analysis capabilities
    through a modular architecture with proper separation of concerns.
    """
    
    def __init__(self, apk_ctx, config: Optional[RootDetectionAnalysisConfig] = None):
        """Initialize the enhanced root detection bypass analyzer."""
        self.apk_ctx = apk_ctx
        self.config = config or RootDetectionAnalysisConfig()
        
        # Initialize modular components
        self.analyzer = RootDetectionAnalyzer(self.config)
        self.confidence_calculator = EnhancedRootDetectionConfidenceCalculator()
        self.formatter = RootDetectionFormatter()
        
        # Analysis tracking
        self.analysis_start_time = None
        self.analysis_metadata = {
            'analyzed_files': 0,
            'skipped_files': 0,
            'failed_analyses': [],
            'execution_stats': {}
        }
        
        # Thread-safe tracking
        self._lock = threading.Lock()
        self._processed_recommendations = set()
        
        logger.debug("Enhanced Root Detection Bypass Analyzer initialized (modular)")
    
    def analyze_root_detection_and_bypass(self) -> Tuple[str, Union[str, Any]]:
        """
        Main analysis entry point that orchestrates the complete analysis.
        
        Returns:
            Tuple[str, Union[str, Any]]: (analysis_type, formatted_report)
        """
        try:
            self.analysis_start_time = time.time()
            
            logger.debug("Starting enhanced root detection and bypass analysis")
            
            # Analyze root detection patterns
            detection_findings = self._analyze_root_detection()
            
            # Analyze security controls
            security_assessments = self._analyze_security_controls()
            
            # Analyze bypass effectiveness
            bypass_analysis = self._analyze_bypass_effectiveness(detection_findings)
            
            # Integrate dynamic analysis if enabled
            dynamic_results = self._integrate_dynamic_analysis()
            
            # Generate comprehensive results
            results = RootDetectionAnalysisResult(
                detection_findings=detection_findings,
                security_assessments=security_assessments,
                bypass_analysis=bypass_analysis,
                dynamic_analysis_results=dynamic_results,
                overall_security_score=self._calculate_overall_score(detection_findings, security_assessments),
                risk_assessment=self._assess_overall_risk(detection_findings, security_assessments),
                recommendations=self._generate_recommendations(detection_findings, security_assessments),
                masvs_compliance=self._assess_masvs_compliance(detection_findings),
                analysis_metadata=self.analysis_metadata
            )
            
            # Format and return results
            formatted_report = self.formatter.format_analysis_results(results)
            
            # Log execution statistics
            self._log_execution_statistics()
            
            logger.debug("Enhanced root detection analysis completed successfully")
            return "enhanced_root_detection_analysis", formatted_report
            
        except Exception as e:
            logger.error(f"Enhanced root detection analysis failed: {e}")
            error_report = self.formatter.format_error_report(str(e))
            return "enhanced_root_detection_analysis", error_report
    
    def _analyze_root_detection(self) -> List[RootDetectionFinding]:
        """Analyze root detection patterns across all app files."""
        findings = []
        
        try:
            # Analyze AndroidManifest.xml
            if hasattr(self.apk_ctx, 'manifest_content'):
                manifest_findings = self.analyzer.analyze_root_detection(
                    self.apk_ctx.manifest_content,
                    "AndroidManifest.xml"
                )
                findings.extend(manifest_findings)
            
            # Analyze Java/Kotlin source files
            java_files = getattr(self.apk_ctx, 'get_java_files', lambda: [])()
            # Ensure java_files is a list/tuple, not a string or other type
            if java_files and isinstance(java_files, (list, tuple)) and not isinstance(java_files, str):
                for java_file_path in java_files:
                    try:
                        # Handle file paths (strings) by reading content
                        if isinstance(java_file_path, str):
                            try:
                                with open(java_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                java_findings = self.analyzer.analyze_root_detection(content, java_file_path)
                                findings.extend(java_findings)
                            except Exception as e:
                                logger.debug(f"Failed to read Java file {java_file_path}: {e}")
                        # Handle dictionary format (legacy compatibility)
                        elif isinstance(java_file_path, dict):
                            java_findings = self.analyzer.analyze_root_detection(
                                java_file_path.get('content', ''),
                                java_file_path.get('path', '')
                            )
                            findings.extend(java_findings)
                        else:
                            logger.debug(f"Skipping unsupported java_file type: {type(java_file_path)}")
                    except Exception as e:
                        logger.warning(f"Failed to analyze Java file: {e}")
            
            # Analyze native libraries
            if hasattr(self.apk_ctx, 'native_libraries') and isinstance(self.apk_ctx.native_libraries, dict) and not isinstance(self.apk_ctx.native_libraries, str):
                for lib_path, lib_content in self.apk_ctx.native_libraries.items():
                    try:
                        # Ensure lib_content is string before analyzing
                        if isinstance(lib_content, str):
                            native_findings = self.analyzer.analyze_root_detection(
                                lib_content,
                                lib_path
                            )
                            findings.extend(native_findings)
                    except Exception as e:
                        logger.warning(f"Failed to analyze native library {lib_path}: {e}")
            
            # Analyze resources
            if hasattr(self.apk_ctx, 'resources') and isinstance(self.apk_ctx.resources, dict) and not isinstance(self.apk_ctx.resources, str):
                for resource_path, resource_content in self.apk_ctx.resources.items():
                    try:
                        # Ensure resource_content is string before analyzing
                        if isinstance(resource_content, str):
                            resource_findings = self.analyzer.analyze_root_detection(
                                resource_content,
                                resource_path
                            )
                            findings.extend(resource_findings)
                    except Exception as e:
                        logger.warning(f"Failed to analyze resource {resource_path}: {e}")
            
            # Deduplicate findings
            findings = self._deduplicate_findings(findings)
            
            self.analysis_metadata['analyzed_files'] += len(findings)
            
            logger.debug(f"Root detection analysis found {len(findings)} findings")
            return findings
            
        except Exception as e:
            logger.error(f"Root detection analysis failed: {e}")
            self.analysis_metadata['failed_analyses'].append({
                'phase': 'root_detection_analysis',
                'error': str(e)
            })
            return []
    
    def _analyze_security_controls(self) -> List[SecurityControlAssessment]:
        """Analyze security control strength across all app files."""
        assessments = []
        
        try:
            # Analyze all available content
            content_sources = []
            
            if hasattr(self.apk_ctx, 'manifest_content'):
                content_sources.append(('AndroidManifest.xml', self.apk_ctx.manifest_content))
            
            if hasattr(self.apk_ctx, 'java_files') and isinstance(self.apk_ctx.java_files, (list, tuple)):
                for java_file in self.apk_ctx.java_files:
                    # Ensure java_file is a dictionary before accessing with .get()
                    if isinstance(java_file, dict):
                        content_sources.append((
                            java_file.get('path', ''),
                            java_file.get('content', '')
                        ))
            
            # Analyze each content source
            for file_path, content in content_sources:
                try:
                    file_assessments = self.analyzer.analyze_security_controls(content, file_path)
                    assessments.extend(file_assessments)
                except Exception as e:
                    logger.warning(f"Failed to analyze security controls in {file_path}: {e}")
            
            logger.debug(f"Security control analysis found {len(assessments)} assessments")
            return assessments
            
        except Exception as e:
            logger.error(f"Security control analysis failed: {e}")
            self.analysis_metadata['failed_analyses'].append({
                'phase': 'security_control_analysis',
                'error': str(e)
            })
            return []
    
    def _analyze_bypass_effectiveness(self, detection_findings: List[RootDetectionFinding]) -> Dict[str, Any]:
        """Analyze bypass effectiveness for detected root detection mechanisms."""
        bypass_analysis = {
            'bypass_methods': [],
            'effectiveness_scores': {},
            'countermeasures': [],
            'overall_bypass_resistance': 0.0
        }
        
        try:
            if not detection_findings:
                return bypass_analysis
            
            # Analyze bypass methods for each finding
            for finding in detection_findings:
                bypass_resistance = self._calculate_bypass_resistance(finding)
                bypass_analysis['effectiveness_scores'][finding.detection_id] = bypass_resistance
                
                # Add bypass methods
                if finding.bypass_methods:
                    bypass_analysis['bypass_methods'].extend(finding.bypass_methods)
            
            # Calculate overall bypass resistance
            if bypass_analysis['effectiveness_scores']:
                scores = list(bypass_analysis['effectiveness_scores'].values())
                bypass_analysis['overall_bypass_resistance'] = sum(scores) / len(scores)
            
            # Generate countermeasures
            bypass_analysis['countermeasures'] = self._generate_countermeasures(detection_findings)
            
            logger.debug(f"Bypass analysis completed for {len(detection_findings)} findings")
            return bypass_analysis
            
        except Exception as e:
            logger.error(f"Bypass effectiveness analysis failed: {e}")
            self.analysis_metadata['failed_analyses'].append({
                'phase': 'bypass_effectiveness_analysis',
                'error': str(e)
            })
            return bypass_analysis
    
    def _integrate_dynamic_analysis(self) -> Dict[str, Any]:
        """Integrate dynamic analysis results if available."""
        dynamic_results = {
            'enabled': self.config.enable_dynamic_analysis,
            'results': {},
            'frida_available': False,
            'analysis_performed': False
        }
        
        try:
            if not self.config.enable_dynamic_analysis:
                return dynamic_results
            
            # Check if Frida analysis components are available
            try:
                from frida_dynamic_analysis import FridaDynamicAnalyzer
                dynamic_results['frida_available'] = True
                
                # Perform dynamic analysis
                frida_analyzer = FridaDynamicAnalyzer(self.apk_ctx)
                frida_results = frida_analyzer.analyze_root_detection()
                
                dynamic_results['results'] = frida_results
                dynamic_results['analysis_performed'] = True
                
                logger.debug("Dynamic analysis integration completed")
                
            except ImportError:
                logger.warning("Frida dynamic analysis not available")
                dynamic_results['frida_available'] = False
            
            return dynamic_results
            
        except Exception as e:
            logger.error(f"Dynamic analysis integration failed: {e}")
            self.analysis_metadata['failed_analyses'].append({
                'phase': 'dynamic_analysis_integration',
                'error': str(e)
            })
            return dynamic_results
    
    def _calculate_overall_score(self, detection_findings: List[RootDetectionFinding],
                               security_assessments: List[SecurityControlAssessment]) -> float:
        """Calculate overall security score based on findings and assessments."""
        if not detection_findings and not security_assessments:
            return 0.0
        
        detection_score = 0.0
        if detection_findings:
            detection_score = sum(f.confidence for f in detection_findings) / len(detection_findings)
        
        control_score = 0.0
        if security_assessments:
            control_score = sum(a.effectiveness_score for a in security_assessments) / len(security_assessments)
        
        # Weighted average
        overall_score = (detection_score * 0.6) + (control_score * 0.4)
        return min(overall_score, 1.0)
    
    def _assess_overall_risk(self, detection_findings: List[RootDetectionFinding],
                           security_assessments: List[SecurityControlAssessment]) -> str:
        """Assess overall risk level based on findings and assessments."""
        overall_score = self._calculate_overall_score(detection_findings, security_assessments)
        
        if overall_score >= 0.8:
            return "HIGH"
        elif overall_score >= 0.6:
            return "MEDIUM"
        elif overall_score >= 0.4:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _generate_recommendations(self, detection_findings: List[RootDetectionFinding],
                                security_assessments: List[SecurityControlAssessment]) -> List[str]:
        """Generate security recommendations based on analysis results."""
        recommendations = []
        
        # Base recommendations
        if detection_findings:
            recommendations.append("Implement comprehensive root detection mechanisms")
            recommendations.append("Add bypass resistance through multiple detection layers")
        
        if security_assessments:
            for assessment in security_assessments:
                recommendations.extend(assessment.recommendations)
        
        # Remove duplicates while preserving order
        unique_recommendations = []
        seen = set()
        for rec in recommendations:
            if rec not in seen:
                unique_recommendations.append(rec)
                seen.add(rec)
        
        return unique_recommendations
    
    def _assess_masvs_compliance(self, detection_findings: List[RootDetectionFinding]) -> List[str]:
        """Assess MASVS compliance based on findings."""
        compliance = []
        
        if detection_findings:
            # Check for MASVS references in findings
            for finding in detection_findings:
                if finding.masvs_refs:
                    compliance.extend(finding.masvs_refs)
        
        # Default MASVS controls for root detection
        compliance.extend([
            "MSTG-RESILIENCE-1",  # Anti-tampering protection
            "MSTG-RESILIENCE-2",  # Runtime application self-protection
            "MSTG-RESILIENCE-3"   # Device binding and attestation
        ])
        
        return list(set(compliance))  # Remove duplicates
    
    def _deduplicate_findings(self, findings: List) -> List:
        """Deduplicate findings using unified deduplication framework."""
        if not findings:
            return findings
        
        # Convert to dict format
        dict_findings = []
        for finding in findings:
            dict_finding = {
                'title': getattr(finding, 'detection_method', str(finding)),
                'description': getattr(finding, 'description', ''),
                'location': getattr(finding, 'location', ''),
                'evidence': getattr(finding, 'evidence', []),
                'original_object': finding
            }
            dict_findings.append(dict_finding)
        
        try:
            result = deduplicate_findings(dict_findings, DeduplicationStrategy.INTELLIGENT)
            return [f['original_object'] for f in result.unique_findings if 'original_object' in f]
        except Exception:
            return self._deduplicate_findings_fallback(findings)
    def _calculate_bypass_resistance(self, finding: RootDetectionFinding) -> float:
        """Calculate bypass resistance score for a finding."""
        base_score = finding.confidence
        
        # Adjust based on detection type
        type_multipliers = {
            'native_binary': 1.2,
            'file_system': 1.0,
            'process_execution': 0.9,
            'system_property': 0.8,
            'package_manager': 0.7,
            'runtime_detection': 1.1
        }
        
        multiplier = type_multipliers.get(finding.detection_type, 1.0)
        resistance_score = base_score * multiplier
        
        return min(resistance_score, 1.0)
    
    def _generate_countermeasures(self, detection_findings: List[RootDetectionFinding]) -> List[str]:
        """Generate countermeasures for detected bypass methods."""
        countermeasures = []
        
        for finding in detection_findings:
            if finding.bypass_methods:
                for method in finding.bypass_methods:
                    if method == 'hooking':
                        countermeasures.append("Implement anti-hooking protection")
                    elif method == 'binary_patching':
                        countermeasures.append("Add binary integrity checks")
                    elif method == 'environment_manipulation':
                        countermeasures.append("Validate environment consistency")
        
        return list(set(countermeasures))  # Remove duplicates
    
    def _log_execution_statistics(self) -> None:
        """Log execution statistics for performance monitoring."""
        if self.analysis_start_time:
            total_time = time.time() - self.analysis_start_time
            self.analysis_metadata['execution_stats']['total_time'] = total_time
            
            logger.debug(f"Enhanced root detection analysis completed in {total_time:.2f}s")
            logger.debug(f"Files analyzed: {self.analysis_metadata['analyzed_files']}")
            logger.debug(f"Failed analyses: {len(self.analysis_metadata['failed_analyses'])}")


def run(apk_ctx):
    """
    Main entry point for AODS plugin execution.
    
    Args:
        apk_ctx: APK context containing analysis information
        
    Returns:
        Tuple[str, Union[str, Any]]: Plugin name and result
    """
    try:
        # Initialize analyzer with APK context
        analyzer = EnhancedRootDetectionBypassAnalyzer(apk_ctx)
        
        # Execute analysis
        return analyzer.analyze_root_detection_and_bypass()
        
    except Exception as e:
        logger.error(f"Enhanced root detection bypass analysis failed: {e}")
        return "Enhanced Root Detection Bypass Analysis", f"Analysis failed: {str(e)}"


def run_plugin(apk_ctx):
    """Alias for run function for backward compatibility."""
    return run(apk_ctx) 