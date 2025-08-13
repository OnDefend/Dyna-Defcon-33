#!/usr/bin/env python3
"""
Analysis Transparency Manager for Phase 2.5.1

This module provides comprehensive analysis transparency and user notification capabilities
for Phase 2.5.1 Critical Detection Gap Resolution. It ensures users are fully informed
about analysis limitations, failures, and coverage gaps with prominent notifications
and detailed technical explanations.

Phase 2.5.1 Implementation Features:
- File reading failure notification with technical details
- Analysis coverage reporting with quantitative metrics
- Plugin execution failure tracking and user guidance
- Security finding confidence explanation with evidence
- Analysis limitation documentation with impact assessment
- Prominent UI display of critical analysis issues

MASVS Controls: Supporting all controls through transparency
"""

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.markup import escape

class AnalysisEventType(Enum):
    """Types of analysis events for transparency tracking."""
    FILE_READ_FAILURE = "file_read_failure"
    PLUGIN_EXECUTION_FAILURE = "plugin_execution_failure"
    ANALYSIS_LIMITATION = "analysis_limitation"
    COVERAGE_GAP = "coverage_gap"
    CONFIDENCE_EXPLANATION = "confidence_explanation"
    SECURITY_CONTROL_BYPASS = "security_control_bypass"
    DYNAMIC_ANALYSIS_UNAVAILABLE = "dynamic_analysis_unavailable"
    PATTERN_DETECTION_FAILURE = "pattern_detection_failure"
    PERFORMANCE_IMPACT = "performance_impact"
    INTEGRATION_FAILURE = "integration_failure"

class AnalysisSeverity(Enum):
    """Severity levels for analysis transparency events."""
    CRITICAL = "critical"    # Major analysis capability lost
    HIGH = "high"           # Significant analysis limitation
    MEDIUM = "medium"       # Moderate impact on analysis
    LOW = "low"            # Minor limitation or informational
    INFO = "info"          # General transparency information

@dataclass
class TransparencyEvent:
    """Individual transparency event with comprehensive details."""
    event_id: str
    event_type: AnalysisEventType
    severity: AnalysisSeverity
    title: str
    description: str
    technical_details: Dict[str, Any] = field(default_factory=dict)
    impact_assessment: str = ""
    remediation_guidance: List[str] = field(default_factory=list)
    affected_components: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    plugin_name: Optional[str] = None
    file_path: Optional[str] = None
    error_message: Optional[str] = None
    confidence_factors: Dict[str, float] = field(default_factory=dict)
    coverage_metrics: Dict[str, float] = field(default_factory=dict)
    user_visible: bool = True

@dataclass
class AnalysisTransparencyReport:
    """Comprehensive analysis transparency report for Phase 2.5.1."""
    package_name: str
    analysis_start_time: float
    analysis_end_time: float = 0.0
    total_events: int = 0
    critical_events: int = 0
    high_severity_events: int = 0
    transparency_events: List[TransparencyEvent] = field(default_factory=list)
    overall_analysis_coverage: float = 0.0
    plugin_execution_success_rate: float = 0.0
    file_access_success_rate: float = 0.0
    confidence_explanation_coverage: float = 0.0
    analysis_limitations_summary: Dict[str, Any] = field(default_factory=dict)
    remediation_priorities: List[Dict[str, Any]] = field(default_factory=list)
    user_notification_summary: Dict[str, Any] = field(default_factory=dict)

class AnalysisTransparencyManager:
    """
    Comprehensive Analysis Transparency Manager for Phase 2.5.1.
    
    Provides transparent reporting of analysis failures, limitations, and coverage gaps
    with prominent user notifications and detailed technical explanations.
    """
    
    def __init__(self, package_name: str):
        """Initialize the analysis transparency manager."""
        self.package_name = package_name
        self.console = Console()
        self.logger = logging.getLogger(__name__)
        
        # Initialize transparency tracking
        self.transparency_events: List[TransparencyEvent] = []
        self.event_counter = 0
        self.analysis_start_time = time.time()
        
        # Analysis tracking metrics
        self.plugin_execution_attempts = 0
        self.plugin_execution_successes = 0
        self.file_access_attempts = 0
        self.file_access_successes = 0
        self.confidence_explanations_provided = 0
        self.security_findings_count = 0
        
        # User notification configuration
        self.enable_prominent_notifications = True
        self.enable_technical_details = True
        self.enable_remediation_guidance = True
        self.max_user_visible_events = 10
        
        logger.info(f"Analysis Transparency Manager initialized for {package_name}")
    
    def record_file_read_failure(self, file_path: str, error_message: str, 
                                plugin_name: str = None, impact_level: str = "high") -> str:
        """
        Record file reading failure with detailed transparency reporting.
        
        Args:
            file_path: Path to file that couldn't be read
            error_message: Detailed error message
            plugin_name: Plugin that attempted file access
            impact_level: Impact on analysis (critical, high, medium, low)
            
        Returns:
            Event ID for tracking
        """
        event_id = self._generate_event_id("FILE_READ_FAILURE")
        
        # Determine severity based on file importance and impact
        severity = self._assess_file_failure_severity(file_path, impact_level)
        
        # Create transparency event
        event = TransparencyEvent(
            event_id=event_id,
            event_type=AnalysisEventType.FILE_READ_FAILURE,
            severity=severity,
            title=f"File Access Failure: {Path(file_path).name}",
            description=f"Unable to read file required for security analysis: {file_path}",
            technical_details={
                'file_path': file_path,
                'error_type': type(error_message).__name__ if hasattr(error_message, '__class__') else 'Unknown',
                'error_details': str(error_message),
                'file_size_estimate': self._estimate_file_importance(file_path),
                'alternative_analysis_methods': self._suggest_alternative_analysis(file_path),
                'analysis_completeness_impact': self._assess_completeness_impact(file_path)
            },
            impact_assessment=self._generate_file_failure_impact_assessment(file_path, severity),
            remediation_guidance=self._generate_file_failure_remediation(file_path, error_message),
            affected_components=[plugin_name] if plugin_name else [],
            plugin_name=plugin_name,
            file_path=file_path,
            error_message=str(error_message),
            user_visible=severity in [AnalysisSeverity.CRITICAL, AnalysisSeverity.HIGH]
        )
        
        self._add_transparency_event(event)
        
        # Update tracking metrics
        self.file_access_attempts += 1
        
        # Display prominent notification if critical
        if severity == AnalysisSeverity.CRITICAL and self.enable_prominent_notifications:
            self._display_prominent_file_failure_notification(event)
        
        logger.warning(f"File read failure recorded: {file_path} - {error_message}")
        return event_id
    
    def record_plugin_execution_failure(self, plugin_name: str, error_message: str,
                                      execution_phase: str = "unknown", 
                                      recovery_attempted: bool = False) -> str:
        """
        Record plugin execution failure with comprehensive analysis impact assessment.
        
        Args:
            plugin_name: Name of plugin that failed
            error_message: Detailed error message
            execution_phase: Phase where failure occurred
            recovery_attempted: Whether recovery was attempted
            
        Returns:
            Event ID for tracking
        """
        event_id = self._generate_event_id("PLUGIN_EXECUTION_FAILURE")
        
        # Assess severity based on plugin criticality
        severity = self._assess_plugin_failure_severity(plugin_name)
        
        event = TransparencyEvent(
            event_id=event_id,
            event_type=AnalysisEventType.PLUGIN_EXECUTION_FAILURE,
            severity=severity,
            title=f"Plugin Execution Failure: {plugin_name}",
            description=f"Security analysis plugin failed during execution: {plugin_name}",
            technical_details={
                'plugin_name': plugin_name,
                'execution_phase': execution_phase,
                'error_type': type(error_message).__name__ if hasattr(error_message, '__class__') else 'Unknown',
                'error_details': str(error_message),
                'recovery_attempted': recovery_attempted,
                'plugin_criticality': self._assess_plugin_criticality(plugin_name),
                'alternative_plugins': self._identify_alternative_plugins(plugin_name),
                'security_coverage_impact': self._assess_security_coverage_impact(plugin_name)
            },
            impact_assessment=self._generate_plugin_failure_impact_assessment(plugin_name, severity),
            remediation_guidance=self._generate_plugin_failure_remediation(plugin_name, error_message, recovery_attempted),
            affected_components=[plugin_name],
            plugin_name=plugin_name,
            error_message=str(error_message),
            user_visible=severity in [AnalysisSeverity.CRITICAL, AnalysisSeverity.HIGH]
        )
        
        self._add_transparency_event(event)
        
        # Update tracking metrics
        self.plugin_execution_attempts += 1
        
        # Display prominent notification if critical
        if severity == AnalysisSeverity.CRITICAL and self.enable_prominent_notifications:
            self._display_prominent_plugin_failure_notification(event)
        
        logger.error(f"Plugin execution failure recorded: {plugin_name} - {error_message}")
        return event_id
    
    def record_analysis_limitation(self, limitation_type: str, description: str,
                                 affected_analysis: List[str], impact_level: str = "medium",
                                 workaround_available: bool = False) -> str:
        """
        Record analysis limitation with detailed impact and workaround information.
        
        Args:
            limitation_type: Type of limitation (e.g., 'dynamic_analysis_unavailable')
            description: Detailed description of limitation
            affected_analysis: List of affected analysis types
            impact_level: Impact on overall analysis
            workaround_available: Whether workaround exists
            
        Returns:
            Event ID for tracking
        """
        event_id = self._generate_event_id("ANALYSIS_LIMITATION")
        
        severity = AnalysisSeverity(impact_level) if impact_level in [s.value for s in AnalysisSeverity] else AnalysisSeverity.MEDIUM
        
        event = TransparencyEvent(
            event_id=event_id,
            event_type=AnalysisEventType.ANALYSIS_LIMITATION,
            severity=severity,
            title=f"Analysis Limitation: {limitation_type.replace('_', ' ').title()}",
            description=description,
            technical_details={
                'limitation_type': limitation_type,
                'affected_analysis_types': affected_analysis,
                'workaround_available': workaround_available,
                'impact_quantification': self._quantify_analysis_impact(affected_analysis),
                'alternative_approaches': self._suggest_alternative_approaches(limitation_type),
                'coverage_reduction_estimate': self._estimate_coverage_reduction(affected_analysis)
            },
            impact_assessment=self._generate_limitation_impact_assessment(limitation_type, affected_analysis),
            remediation_guidance=self._generate_limitation_remediation(limitation_type, workaround_available),
            affected_components=affected_analysis,
            user_visible=severity in [AnalysisSeverity.CRITICAL, AnalysisSeverity.HIGH] or not workaround_available
        )
        
        self._add_transparency_event(event)
        
        logger.info(f"Analysis limitation recorded: {limitation_type} affecting {len(affected_analysis)} analysis types")
        return event_id
    
    def record_coverage_gap(self, gap_type: str, missing_coverage: List[str],
                          estimated_impact: float = 0.0, detection_alternatives: List[str] = None) -> str:
        """
        Record analysis coverage gap with quantitative impact assessment.
        
        Args:
            gap_type: Type of coverage gap
            missing_coverage: List of missing coverage areas
            estimated_impact: Estimated impact on overall security assessment (0.0-1.0)
            detection_alternatives: Alternative detection methods
            
        Returns:
            Event ID for tracking
        """
        event_id = self._generate_event_id("COVERAGE_GAP")
        
        # Determine severity based on impact
        if estimated_impact >= 0.7:
            severity = AnalysisSeverity.CRITICAL
        elif estimated_impact >= 0.4:
            severity = AnalysisSeverity.HIGH
        elif estimated_impact >= 0.2:
            severity = AnalysisSeverity.MEDIUM
        else:
            severity = AnalysisSeverity.LOW
        
        event = TransparencyEvent(
            event_id=event_id,
            event_type=AnalysisEventType.COVERAGE_GAP,
            severity=severity,
            title=f"Analysis Coverage Gap: {gap_type.replace('_', ' ').title()}",
            description=f"Identified gap in security analysis coverage affecting {len(missing_coverage)} areas",
            technical_details={
                'gap_type': gap_type,
                'missing_coverage_areas': missing_coverage,
                'estimated_impact_percentage': estimated_impact * 100,
                'detection_alternatives': detection_alternatives or [],
                'coverage_metrics': self._calculate_coverage_metrics(missing_coverage),
                'remediation_priority': self._assess_remediation_priority(estimated_impact)
            },
            impact_assessment=self._generate_coverage_gap_impact_assessment(gap_type, estimated_impact),
            remediation_guidance=self._generate_coverage_gap_remediation(gap_type, missing_coverage, detection_alternatives),
            affected_components=missing_coverage,
            coverage_metrics={'estimated_impact': estimated_impact, 'missing_areas': len(missing_coverage)},
            user_visible=estimated_impact >= 0.3 or severity in [AnalysisSeverity.CRITICAL, AnalysisSeverity.HIGH]
        )
        
        self._add_transparency_event(event)
        
        logger.warning(f"Coverage gap recorded: {gap_type} with {estimated_impact:.1%} estimated impact")
        return event_id
    
    def record_confidence_explanation(self, finding_id: str, confidence_score: float,
                                    evidence_factors: Dict[str, float], calculation_method: str) -> str:
        """
        Record confidence explanation for transparent confidence calculation.
        
        Args:
            finding_id: Security finding identifier
            confidence_score: Calculated confidence score
            evidence_factors: Factors contributing to confidence
            calculation_method: Method used for calculation
            
        Returns:
            Event ID for tracking
        """
        event_id = self._generate_event_id("CONFIDENCE_EXPLANATION")
        
        event = TransparencyEvent(
            event_id=event_id,
            event_type=AnalysisEventType.CONFIDENCE_EXPLANATION,
            severity=AnalysisSeverity.INFO,
            title=f"Confidence Explanation: {finding_id}",
            description=f"confidence calculation explanation for security finding",
            technical_details={
                'finding_id': finding_id,
                'confidence_score': confidence_score,
                'calculation_method': calculation_method,
                'evidence_breakdown': evidence_factors,
                'factor_weights': self._get_factor_weights(calculation_method),
                'confidence_category': self._categorize_confidence(confidence_score),
                'reliability_assessment': self._assess_confidence_reliability(evidence_factors)
            },
            impact_assessment=self._generate_confidence_impact_assessment(confidence_score),
            remediation_guidance=self._generate_confidence_remediation(confidence_score, evidence_factors),
            confidence_factors=evidence_factors,
            user_visible=False  # Detailed explanations available on request
        )
        
        self._add_transparency_event(event)
        
        # Update tracking metrics
        self.confidence_explanations_provided += 1
        
        logger.debug(f"Confidence explanation recorded for {finding_id}: {confidence_score:.3f}")
        return event_id
    
    def generate_comprehensive_transparency_report(self) -> AnalysisTransparencyReport:
        """
        Generate comprehensive analysis transparency report for Phase 2.5.1.
        
        Returns:
            Complete transparency report with all analysis limitations and coverage
        """
        self.analysis_end_time = time.time()
        
        # Calculate metrics
        total_events = len(self.transparency_events)
        critical_events = len([e for e in self.transparency_events if e.severity == AnalysisSeverity.CRITICAL])
        high_events = len([e for e in self.transparency_events if e.severity == AnalysisSeverity.HIGH])
        
        # Calculate success rates
        plugin_success_rate = (self.plugin_execution_successes / max(self.plugin_execution_attempts, 1)) * 100
        file_success_rate = (self.file_access_successes / max(self.file_access_attempts, 1)) * 100
        confidence_coverage = (self.confidence_explanations_provided / max(self.security_findings_count, 1)) * 100
        
        # Calculate overall analysis coverage
        overall_coverage = self._calculate_overall_analysis_coverage()
        
        # Generate limitations summary
        limitations_summary = self._generate_limitations_summary()
        
        # Generate remediation priorities
        remediation_priorities = self._generate_remediation_priorities()
        
        # Generate user notification summary
        user_notification_summary = self._generate_user_notification_summary()
        
        report = AnalysisTransparencyReport(
            package_name=self.package_name,
            analysis_start_time=self.analysis_start_time,
            analysis_end_time=self.analysis_end_time,
            total_events=total_events,
            critical_events=critical_events,
            high_severity_events=high_events,
            transparency_events=self.transparency_events,
            overall_analysis_coverage=overall_coverage,
            plugin_execution_success_rate=plugin_success_rate,
            file_access_success_rate=file_success_rate,
            confidence_explanation_coverage=confidence_coverage,
            analysis_limitations_summary=limitations_summary,
            remediation_priorities=remediation_priorities,
            user_notification_summary=user_notification_summary
        )
        
        logger.info(f"Comprehensive transparency report generated: {total_events} events, "
                   f"{overall_coverage:.1f}% coverage, {critical_events} critical issues")
        
        return report
    
    def display_prominent_transparency_summary(self, report: AnalysisTransparencyReport):
        """Display prominent transparency summary for user awareness."""
        if not self.enable_prominent_notifications:
            return
        
        # Create summary panel
        summary_content = []
        
        # Analysis coverage status
        coverage_color = "green" if report.overall_analysis_coverage >= 85 else "yellow" if report.overall_analysis_coverage >= 60 else "red"
        summary_content.append(f"[{coverage_color}]Analysis Coverage: {report.overall_analysis_coverage:.1f}%[/{coverage_color}]")
        
        # Critical issues
        if report.critical_events > 0:
            summary_content.append(f"[red]Critical Issues: {report.critical_events}[/red]")
        
        # High severity issues
        if report.high_severity_events > 0:
            summary_content.append(f"[yellow]High Severity Issues: {report.high_severity_events}[/yellow]")
        
        # Plugin execution status
        plugin_color = "green" if report.plugin_execution_success_rate >= 90 else "yellow" if report.plugin_execution_success_rate >= 70 else "red"
        summary_content.append(f"[{plugin_color}]Plugin Success Rate: {report.plugin_execution_success_rate:.1f}%[/{plugin_color}]")
        
        # File access status
        file_color = "green" if report.file_access_success_rate >= 90 else "yellow" if report.file_access_success_rate >= 70 else "red"
        summary_content.append(f"[{file_color}]File Access Rate: {report.file_access_success_rate:.1f}%[/{file_color}]")
        
        # Create summary panel
        summary_panel = Panel(
            "\n".join(summary_content),
            title="[bold]Analysis Transparency Summary[/bold]",
            border_style="blue",
            padding=(1, 2)
        )
        
        self.console.print(summary_panel)
        
        # Display critical issues if any
        if report.critical_events > 0 or report.high_severity_events > 0:
            self._display_critical_issues_table(report)
        
        # Display remediation priorities
        if report.remediation_priorities:
            self._display_remediation_priorities(report.remediation_priorities[:3])  # Top 3
    
    def record_successful_plugin_execution(self, plugin_name: str):
        """Record successful plugin execution for metrics."""
        self.plugin_execution_attempts += 1
        self.plugin_execution_successes += 1
        logger.debug(f"Successful plugin execution recorded: {plugin_name}")
    
    def record_successful_file_access(self, file_path: str):
        """Record successful file access for metrics."""
        self.file_access_attempts += 1
        self.file_access_successes += 1
        logger.debug(f"Successful file access recorded: {file_path}")
    
    def record_security_finding(self, finding_id: str):
        """Record security finding for confidence coverage calculation."""
        self.security_findings_count += 1
        logger.debug(f"Security finding recorded: {finding_id}")
    
    # Private helper methods for internal processing
    
    def _generate_event_id(self, event_type: str) -> str:
        """Generate unique event ID."""
        self.event_counter += 1
        timestamp = int(time.time())
        return f"{event_type}_{timestamp}_{self.event_counter:04d}"
    
    def _add_transparency_event(self, event: TransparencyEvent):
        """Add transparency event to tracking."""
        self.transparency_events.append(event)
        
        # Log event based on severity
        if event.severity == AnalysisSeverity.CRITICAL:
            logger.critical(f"CRITICAL transparency event: {event.title}")
        elif event.severity == AnalysisSeverity.HIGH:
            logger.error(f"HIGH severity transparency event: {event.title}")
        elif event.severity == AnalysisSeverity.MEDIUM:
            logger.warning(f"MEDIUM severity transparency event: {event.title}")
        else:
            logger.info(f"Transparency event: {event.title}")
    
    def _assess_file_failure_severity(self, file_path: str, impact_level: str) -> AnalysisSeverity:
        """Assess severity of file reading failure."""
        # Critical files that severely impact analysis
        critical_files = ['AndroidManifest.xml', 'classes.dex', 'resources.arsc']
        
        if any(critical in file_path for critical in critical_files):
            return AnalysisSeverity.CRITICAL
        elif impact_level == "critical":
            return AnalysisSeverity.CRITICAL
        elif impact_level == "high":
            return AnalysisSeverity.HIGH
        elif impact_level == "medium":
            return AnalysisSeverity.MEDIUM
        else:
            return AnalysisSeverity.LOW
    
    def _assess_plugin_failure_severity(self, plugin_name: str) -> AnalysisSeverity:
        """Assess severity of plugin execution failure."""
        critical_plugins = ['cryptography_tests', 'improper_platform_usage', 'insecure_data_storage']
        high_priority_plugins = ['ssl_tls_analyzer', 'native_binary_analysis', 'attack_surface_analysis']
        
        if any(critical in plugin_name.lower() for critical in critical_plugins):
            return AnalysisSeverity.CRITICAL
        elif any(high in plugin_name.lower() for high in high_priority_plugins):
            return AnalysisSeverity.HIGH
        else:
            return AnalysisSeverity.MEDIUM
    
    def _estimate_file_importance(self, file_path: str) -> str:
        """Estimate file importance for analysis."""
        if 'AndroidManifest.xml' in file_path:
            return "Critical - Core app configuration"
        elif '.dex' in file_path:
            return "Critical - Application bytecode"
        elif 'resources.arsc' in file_path:
            return "High - Application resources"
        elif 'lib/' in file_path:
            return "Medium - Native libraries"
        else:
            return "Low - Supplementary files"
    
    def _suggest_alternative_analysis(self, file_path: str) -> List[str]:
        """Suggest alternative analysis methods for failed file access."""
        alternatives = []
        
        if 'AndroidManifest.xml' in file_path:
            alternatives.extend([
                "Extract manifest using aapt tool",
                "Use alternative APK parsing library",
                "Manual manifest extraction from APK"
            ])
        elif '.dex' in file_path:
            alternatives.extend([
                "Use jadx for direct decompilation",
                "Extract with alternative dex2jar",
                "Static analysis without full decompilation"
            ])
        else:
            alternatives.append("Continue analysis without this file")
        
        return alternatives
    
    def _assess_completeness_impact(self, file_path: str) -> float:
        """Assess impact on analysis completeness (0.0-1.0)."""
        if 'AndroidManifest.xml' in file_path:
            return 0.8  # High impact
        elif '.dex' in file_path:
            return 0.9  # Very high impact
        elif 'resources.arsc' in file_path:
            return 0.4  # Medium impact
        else:
            return 0.1  # Low impact
    
    def _generate_file_failure_impact_assessment(self, file_path: str, severity: AnalysisSeverity) -> str:
        """Generate impact assessment for file failure."""
        if severity == AnalysisSeverity.CRITICAL:
            return f"Critical analysis component unavailable due to file access failure. Analysis accuracy significantly reduced."
        elif severity == AnalysisSeverity.HIGH:
            return f"Important analysis capability lost. Some security vulnerabilities may not be detected."
        else:
            return f"Minor analysis limitation. Overall security assessment minimally affected."
    
    def _generate_file_failure_remediation(self, file_path: str, error_message: str) -> List[str]:
        """Generate remediation guidance for file failures."""
        remediation = [
            "Verify APK file integrity and accessibility",
            "Check file system permissions for analysis tools",
            "Try alternative APK extraction methods"
        ]
        
        if "permission" in error_message.lower():
            remediation.insert(0, "Run analysis with appropriate file system permissions")
        
        if "not found" in error_message.lower():
            remediation.insert(0, "Verify APK file structure and contents")
        
        return remediation
    
    def _assess_plugin_criticality(self, plugin_name: str) -> str:
        """Assess plugin criticality for security analysis."""
        critical_plugins = {
            'cryptography_tests': 'Critical - Core cryptographic security analysis',
            'improper_platform_usage': 'Critical - Platform security assessment',
            'insecure_data_storage': 'Critical - Data protection analysis'
        }
        
        high_plugins = {
            'ssl_tls_analyzer': 'High - Network security analysis',
            'native_binary_analysis': 'High - Binary security assessment',
            'attack_surface_analysis': 'High - Attack vector identification'
        }
        
        for critical, description in critical_plugins.items():
            if critical in plugin_name.lower():
                return description
        
        for high, description in high_plugins.items():
            if high in plugin_name.lower():
                return description
        
        return "Medium - Supplementary security analysis"
    
    def _identify_alternative_plugins(self, plugin_name: str) -> List[str]:
        """Identify alternative plugins for similar analysis."""
        alternatives = {
            'cryptography_tests': ['ssl_tls_analyzer', 'insecure_data_storage'],
            'ssl_tls_analyzer': ['enhanced_network_security_analysis', 'cryptography_tests'],
            'native_binary_analysis': ['attack_surface_analysis', 'anti_tampering_analysis'],
            'improper_platform_usage': ['attack_surface_analysis', 'traversal_vulnerabilities']
        }
        
        for plugin, alts in alternatives.items():
            if plugin in plugin_name.lower():
                return alts
        
        return []
    
    def _assess_security_coverage_impact(self, plugin_name: str) -> Dict[str, float]:
        """Assess impact on security coverage by analysis area."""
        impact_map = {
            'cryptography_tests': {'cryptography': 0.9, 'data_protection': 0.6, 'authentication': 0.7},
            'ssl_tls_analyzer': {'network_security': 0.8, 'communication': 0.9, 'certificates': 0.9},
            'native_binary_analysis': {'binary_security': 0.9, 'reverse_engineering': 0.8, 'exploitation': 0.7},
            'improper_platform_usage': {'platform_security': 0.8, 'permissions': 0.7, 'components': 0.9}
        }
        
        for plugin, impact in impact_map.items():
            if plugin in plugin_name.lower():
                return impact
        
        return {'general_security': 0.3}
    
    def _generate_plugin_failure_impact_assessment(self, plugin_name: str, severity: AnalysisSeverity) -> str:
        """Generate impact assessment for plugin failure."""
        coverage_impact = self._assess_security_coverage_impact(plugin_name)
        primary_area = max(coverage_impact.items(), key=lambda x: x[1])
        
        if severity == AnalysisSeverity.CRITICAL:
            return f"Critical security analysis capability lost. {primary_area[0].replace('_', ' ').title()} analysis severely compromised ({primary_area[1]:.0%} reduction)."
        elif severity == AnalysisSeverity.HIGH:
            return f"Significant analysis limitation. {primary_area[0].replace('_', ' ').title()} coverage reduced by approximately {primary_area[1]:.0%}."
        else:
            return f"Minor analysis impact. {primary_area[0].replace('_', ' ').title()} coverage slightly reduced."
    
    def _generate_plugin_failure_remediation(self, plugin_name: str, error_message: str, recovery_attempted: bool) -> List[str]:
        """Generate remediation guidance for plugin failures."""
        remediation = [
            f"Check {plugin_name} plugin dependencies and configuration",
            "Verify required tools and libraries are installed",
            "Review plugin logs for detailed error information"
        ]
        
        if not recovery_attempted:
            remediation.insert(0, "Attempt plugin recovery or alternative execution mode")
        
        if "import" in error_message.lower() or "module" in error_message.lower():
            remediation.insert(0, "Install missing Python dependencies")
        
        if "permission" in error_message.lower():
            remediation.insert(0, "Check file and execution permissions")
        
        # Add plugin-specific remediation
        alternatives = self._identify_alternative_plugins(plugin_name)
        if alternatives:
            remediation.append(f"Consider using alternative plugins: {', '.join(alternatives)}")
        
        return remediation
    
    def _quantify_analysis_impact(self, affected_analysis: List[str]) -> Dict[str, float]:
        """Quantify impact on different analysis areas."""
        impact_weights = {
            'static_analysis': 0.4,
            'dynamic_analysis': 0.3,
            'cryptographic_analysis': 0.8,
            'network_analysis': 0.6,
            'binary_analysis': 0.7,
            'platform_analysis': 0.6
        }
        
        total_impact = 0.0
        affected_count = 0
        
        for analysis in affected_analysis:
            for category, weight in impact_weights.items():
                if category in analysis.lower():
                    total_impact += weight
                    affected_count += 1
                    break
        
        return {
            'total_impact': total_impact,
            'average_impact': total_impact / max(affected_count, 1),
            'affected_areas': affected_count,
            'severity_assessment': 'high' if total_impact > 1.5 else 'medium' if total_impact > 0.8 else 'low'
        }
    
    def _suggest_alternative_approaches(self, limitation_type: str) -> List[str]:
        """Suggest alternative approaches for analysis limitations."""
        alternatives = {
            'dynamic_analysis_unavailable': [
                "Enhanced static analysis with behavioral pattern detection",
                "Manual testing with rooted device when available",
                "Code review for dynamic behavior patterns"
            ],
            'frida_unavailable': [
                "Alternative dynamic analysis tools (Xposed, DroidBox)",
                "Instrumentation-free dynamic analysis",
                "Static analysis with runtime pattern detection"
            ],
            'device_unavailable': [
                "Emulator-based analysis",
                "Enhanced static analysis",
                "Cloud-based mobile analysis platforms"
            ]
        }
        
        return alternatives.get(limitation_type, ["Enhanced static analysis as fallback"])
    
    def _estimate_coverage_reduction(self, affected_analysis: List[str]) -> float:
        """Estimate overall coverage reduction due to limitation."""
        impact_data = self._quantify_analysis_impact(affected_analysis)
        
        # Base coverage reduction on number of affected areas and their importance
        base_reduction = min(0.3 * len(affected_analysis), 0.8)  # Max 80% reduction
        
        # Adjust based on severity
        severity_multiplier = {
            'high': 1.0,
            'medium': 0.7,
            'low': 0.4
        }.get(impact_data['severity_assessment'], 0.5)
        
        return base_reduction * severity_multiplier
    
    def _generate_limitation_impact_assessment(self, limitation_type: str, affected_analysis: List[str]) -> str:
        """Generate impact assessment for analysis limitation."""
        impact_data = self._quantify_analysis_impact(affected_analysis)
        coverage_reduction = self._estimate_coverage_reduction(affected_analysis)
        
        return (f"Analysis limitation affects {len(affected_analysis)} security analysis areas "
                f"with estimated {coverage_reduction:.1%} reduction in overall coverage. "
                f"Impact severity: {impact_data['severity_assessment'].upper()}")
    
    def _generate_limitation_remediation(self, limitation_type: str, workaround_available: bool) -> List[str]:
        """Generate remediation guidance for analysis limitations."""
        remediation = []
        
        if workaround_available:
            remediation.append("Apply available workaround to minimize impact")
        
        alternatives = self._suggest_alternative_approaches(limitation_type)
        remediation.extend(alternatives)
        
        if limitation_type == 'dynamic_analysis_unavailable':
            remediation.extend([
                "Setup Android testing environment for future analysis",
                "Consider cloud-based mobile analysis services",
                "Implement CI/CD integration with mobile testing platforms"
            ])
        
        return remediation
    
    def _calculate_coverage_metrics(self, missing_coverage: List[str]) -> Dict[str, float]:
        """Calculate detailed coverage metrics."""
        total_security_areas = 10  # Estimated total security analysis areas
        missing_count = len(missing_coverage)
        
        return {
            'missing_areas_count': missing_count,
            'coverage_percentage': max(0, (total_security_areas - missing_count) / total_security_areas * 100),
            'gap_severity': min(missing_count / total_security_areas, 1.0),
            'estimated_false_negative_risk': min(missing_count * 0.15, 0.8)  # 15% risk per missing area, max 80%
        }
    
    def _assess_remediation_priority(self, estimated_impact: float) -> str:
        """Assess remediation priority based on impact."""
        if estimated_impact >= 0.7:
            return "URGENT - Immediate attention required"
        elif estimated_impact >= 0.4:
            return "HIGH - Address in next iteration"
        elif estimated_impact >= 0.2:
            return "MEDIUM - Include in improvement planning"
        else:
            return "LOW - Monitor for accumulation"
    
    def _generate_coverage_gap_impact_assessment(self, gap_type: str, estimated_impact: float) -> str:
        """Generate impact assessment for coverage gap."""
        impact_description = {
            0.8: "CRITICAL - Major security analysis capability missing",
            0.6: "HIGH - Significant vulnerability detection gap",
            0.4: "MEDIUM - Notable analysis limitation",
            0.2: "LOW - Minor coverage gap",
            0.0: "MINIMAL - Negligible impact on analysis"
        }
        
        # Find closest impact threshold
        for threshold, description in sorted(impact_description.items(), reverse=True):
            if estimated_impact >= threshold:
                return f"{description}. Estimated impact: {estimated_impact:.1%}"
        
        return f"Impact assessment: {estimated_impact:.1%} reduction in analysis effectiveness"
    
    def _generate_coverage_gap_remediation(self, gap_type: str, missing_coverage: List[str], 
                                         detection_alternatives: List[str] = None) -> List[str]:
        """Generate remediation guidance for coverage gaps."""
        remediation = [
            f"Implement missing {gap_type.replace('_', ' ')} analysis capabilities",
            "Evaluate and deploy additional security analysis plugins",
            "Consider third-party tools for gap areas"
        ]
        
        if detection_alternatives:
            remediation.append(f"Alternative detection methods: {', '.join(detection_alternatives)}")
        
        if len(missing_coverage) > 3:
            remediation.append("Prioritize most critical missing areas for implementation")
        
        return remediation
    
    def _get_factor_weights(self, calculation_method: str) -> Dict[str, float]:
        """Get factor weights for confidence calculation method."""
        # Return standard factor weights for different calculation methods
        weights = {
            'multi_factor_evidence': {
                'pattern_reliability': 0.3,
                'context_relevance': 0.25,
                'cross_validation': 0.2,
                'evidence_quality': 0.15,
                'implementation_context': 0.1
            },
            'pattern_based': {
                'pattern_reliability': 0.5,
                'pattern_specificity': 0.3,
                'validation_coverage': 0.2
            },
            'dynamic_analysis': {
                'runtime_validation': 0.4,
                'behavioral_evidence': 0.3,
                'cross_reference': 0.3
            }
        }
        
        return weights.get(calculation_method, {'unknown_method': 1.0})
    
    def _categorize_confidence(self, confidence_score: float) -> str:
        """Categorize confidence score."""
        if confidence_score >= 0.8:
            return "HIGH - Strong evidence and validation"
        elif confidence_score >= 0.6:
            return "MEDIUM - Moderate evidence with some validation"
        elif confidence_score >= 0.4:
            return "LOW - Limited evidence or validation"
        else:
            return "VERY LOW - Weak evidence, requires manual verification"
    
    def _assess_confidence_reliability(self, evidence_factors: Dict[str, float]) -> str:
        """Assess reliability of confidence calculation."""
        factor_count = len(evidence_factors)
        evidence_spread = max(evidence_factors.values()) - min(evidence_factors.values()) if evidence_factors else 0
        
        if factor_count >= 4 and evidence_spread < 0.3:
            return "RELIABLE - Multiple consistent evidence factors"
        elif factor_count >= 3:
            return "MODERATE - Adequate evidence factors"
        elif factor_count >= 2:
            return "LIMITED - Few evidence factors"
        else:
            return "UNRELIABLE - Insufficient evidence factors"
    
    def _generate_confidence_impact_assessment(self, confidence_score: float) -> str:
        """Generate impact assessment for confidence score."""
        if confidence_score >= 0.8:
            return "High confidence - Strong basis for security decision making"
        elif confidence_score >= 0.6:
            return "Medium confidence - Adequate for security assessment with additional validation"
        elif confidence_score >= 0.4:
            return "Low confidence - Requires additional validation before security decision"
        else:
            return "Very low confidence - Manual verification strongly recommended"
    
    def _generate_confidence_remediation(self, confidence_score: float, 
                                       evidence_factors: Dict[str, float]) -> List[str]:
        """Generate remediation guidance for confidence scores."""
        remediation = []
        
        if confidence_score < 0.6:
            remediation.extend([
                "Gather additional evidence through alternative analysis methods",
                "Perform manual verification of findings",
                "Cross-validate with multiple detection techniques"
            ])
        
        if len(evidence_factors) < 3:
            remediation.append("Expand evidence collection to include more validation factors")
        
        weak_factors = [factor for factor, score in evidence_factors.items() if score < 0.4]
        if weak_factors:
            remediation.append(f"Strengthen weak evidence factors: {', '.join(weak_factors)}")
        
        return remediation
    
    def _calculate_overall_analysis_coverage(self) -> float:
        """Calculate overall analysis coverage percentage."""
        # Base coverage calculation on successful operations vs total attempts
        plugin_coverage = (self.plugin_execution_successes / max(self.plugin_execution_attempts, 1)) * 0.6
        file_coverage = (self.file_access_successes / max(self.file_access_attempts, 1)) * 0.3
        
        # Penalty for critical events
        critical_penalty = len([e for e in self.transparency_events if e.severity == AnalysisSeverity.CRITICAL]) * 0.1
        high_penalty = len([e for e in self.transparency_events if e.severity == AnalysisSeverity.HIGH]) * 0.05
        
        # Base coverage + file coverage - penalties, clamped to 0-100%
        coverage = max(0, min(100, (plugin_coverage + file_coverage - critical_penalty - high_penalty) * 100))
        
        return coverage
    
    def _generate_limitations_summary(self) -> Dict[str, Any]:
        """Generate summary of analysis limitations."""
        limitations = {}
        
        # Group events by type
        for event in self.transparency_events:
            event_type = event.event_type.value
            if event_type not in limitations:
                limitations[event_type] = {
                    'count': 0,
                    'severity_breakdown': {s.value: 0 for s in AnalysisSeverity},
                    'affected_components': set(),
                    'sample_issues': []
                }
            
            limitations[event_type]['count'] += 1
            limitations[event_type]['severity_breakdown'][event.severity.value] += 1
            limitations[event_type]['affected_components'].update(event.affected_components)
            
            if len(limitations[event_type]['sample_issues']) < 3:
                limitations[event_type]['sample_issues'].append(event.title)
        
        # Convert sets to lists for JSON serialization
        for limitation_type in limitations:
            limitations[limitation_type]['affected_components'] = list(limitations[limitation_type]['affected_components'])
        
        return limitations
    
    def _generate_remediation_priorities(self) -> List[Dict[str, Any]]:
        """Generate prioritized remediation recommendations."""
        priorities = []
        
        # Sort events by severity and impact
        critical_events = [e for e in self.transparency_events if e.severity == AnalysisSeverity.CRITICAL]
        high_events = [e for e in self.transparency_events if e.severity == AnalysisSeverity.HIGH]
        
        # Add critical priorities
        for event in critical_events[:5]:  # Top 5 critical
            priorities.append({
                'priority': 'URGENT',
                'issue': event.title,
                'impact': event.impact_assessment,
                'remediation': event.remediation_guidance[:2],  # Top 2 recommendations
                'affected_components': event.affected_components,
                'estimated_effort': 'HIGH'
            })
        
        # Add high priority items
        for event in high_events[:3]:  # Top 3 high priority
            priorities.append({
                'priority': 'HIGH',
                'issue': event.title,
                'impact': event.impact_assessment,
                'remediation': event.remediation_guidance[:2],
                'affected_components': event.affected_components,
                'estimated_effort': 'MEDIUM'
            })
        
        return priorities
    
    def _generate_user_notification_summary(self) -> Dict[str, Any]:
        """Generate user notification summary."""
        user_visible_events = [e for e in self.transparency_events if e.user_visible]
        
        return {
            'total_user_notifications': len(user_visible_events),
            'critical_notifications': len([e for e in user_visible_events if e.severity == AnalysisSeverity.CRITICAL]),
            'high_priority_notifications': len([e for e in user_visible_events if e.severity == AnalysisSeverity.HIGH]),
            'notification_categories': {
                event_type.value: len([e for e in user_visible_events if e.event_type == event_type])
                for event_type in AnalysisEventType
            },
            'prominent_notifications_enabled': self.enable_prominent_notifications,
            'technical_details_enabled': self.enable_technical_details,
            'remediation_guidance_enabled': self.enable_remediation_guidance
        }
    
    def _display_prominent_file_failure_notification(self, event: TransparencyEvent):
        """Display prominent notification for critical file failures."""
        failure_panel = Panel(
            f"[red]CRITICAL FILE ACCESS FAILURE[/red]\n\n"
            f"[bold]File:[/bold] {event.file_path}\n"
            f"[bold]Impact:[/bold] {event.impact_assessment}\n\n"
            f"[bold]Recommended Actions:[/bold]\n" +
            "\n".join(f"• {action}" for action in event.remediation_guidance[:3]),
            title="[bold red]Analysis Limitation[/bold red]",
            border_style="red",
            padding=(1, 2)
        )
        
        self.console.print(failure_panel)
    
    def _display_prominent_plugin_failure_notification(self, event: TransparencyEvent):
        """Display prominent notification for critical plugin failures."""
        failure_panel = Panel(
            f"[red]CRITICAL PLUGIN FAILURE[/red]\n\n"
            f"[bold]Plugin:[/bold] {event.plugin_name}\n"
            f"[bold]Impact:[/bold] {event.impact_assessment}\n\n"
            f"[bold]Recommended Actions:[/bold]\n" +
            "\n".join(f"• {action}" for action in event.remediation_guidance[:3]),
            title="[bold red]Security Analysis Limitation[/bold red]",
            border_style="red",
            padding=(1, 2)
        )
        
        self.console.print(failure_panel)
    
    def _display_critical_issues_table(self, report: AnalysisTransparencyReport):
        """Display table of critical issues."""
        critical_events = [e for e in report.transparency_events 
                          if e.severity in [AnalysisSeverity.CRITICAL, AnalysisSeverity.HIGH]]
        
        if not critical_events:
            return
        
        table = Table(title="Critical Analysis Issues", show_header=True, header_style="bold red")
        table.add_column("Severity", style="red", width=10)
        table.add_column("Issue", style="white", width=40)
        table.add_column("Component", style="yellow", width=20)
        table.add_column("Impact", style="cyan", width=30)
        
        for event in critical_events[:10]:  # Show top 10
            severity_color = "red" if event.severity == AnalysisSeverity.CRITICAL else "yellow"
            component = event.plugin_name or ', '.join(event.affected_components[:2]) or "General"
            
            table.add_row(
                f"[{severity_color}]{event.severity.value.upper()}[/{severity_color}]",
                escape(event.title[:38] + "..." if len(event.title) > 38 else event.title),
                escape(component[:18] + "..." if len(component) > 18 else component),
                escape(event.impact_assessment[:28] + "..." if len(event.impact_assessment) > 28 else event.impact_assessment)
            )
        
        self.console.print(table)
    
    def _display_remediation_priorities(self, priorities: List[Dict[str, Any]]):
        """Display remediation priorities table."""
        if not priorities:
            return
        
        table = Table(title="Top Remediation Priorities", show_header=True, header_style="bold green")
        table.add_column("Priority", style="red", width=8)
        table.add_column("Issue", style="white", width=35)
        table.add_column("Primary Action", style="green", width=40)
        table.add_column("Effort", style="yellow", width=8)
        
        for priority in priorities:
            priority_color = "red" if priority['priority'] == 'URGENT' else "yellow"
            
            table.add_row(
                f"[{priority_color}]{priority['priority']}[/{priority_color}]",
                escape(priority['issue'][:33] + "..." if len(priority['issue']) > 33 else priority['issue']),
                escape(priority['remediation'][0][:38] + "..." if len(priority['remediation'][0]) > 38 else priority['remediation'][0]),
                priority['estimated_effort']
            )
        
        self.console.print(table) 