#!/usr/bin/env python3
"""
Anti-Tampering Analysis Output Formatters

Structured output formatting for anti-tampering analysis results.

Features:
- Structured output formatting for anti-tampering findings
- Multiple output format support (JSON, text, structured)
- Evidence-based report generation
- Integration with confidence calculation results
"""

import logging
from typing import Dict, List, Optional
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn

from core.shared_infrastructure.dependency_injection import AnalysisContext

from .data_structures import (
    AntiTamperingAnalysisResult,
    AntiTamperingVulnerability,
    TamperingVulnerabilitySeverity,
    DetectionStrength,
    BypassResistance
)

logger = logging.getLogger(__name__)

class AntiTamperingFormatter:
    """
    formatter for anti-tampering analysis results.
    
    Provides comprehensive formatting capabilities for analysis results
    including vulnerability reporting, security scoring, and recommendations.
    """
    
    def __init__(self, context: AnalysisContext):
        """
        Initialize formatter.
        
        Args:
            context: Analysis context with configuration
        """
        self.context = context
        self.console = Console()
        
        # Formatting configuration
        self.enable_rich_formatting = context.config.get('enable_rich_formatting', True)
        self.max_vulnerabilities_display = context.config.get('max_vulnerabilities_display', 20)
        
        # Color schemes
        self.severity_colors = {
            TamperingVulnerabilitySeverity.CRITICAL: "bright_red",
            TamperingVulnerabilitySeverity.HIGH: "red",
            TamperingVulnerabilitySeverity.MEDIUM: "yellow",
            TamperingVulnerabilitySeverity.LOW: "blue",
            TamperingVulnerabilitySeverity.INFO: "cyan"
        }
        
        self.strength_colors = {
            DetectionStrength.ADVANCED: "bright_green",
            DetectionStrength.HIGH: "green",
            DetectionStrength.MODERATE: "yellow",
            DetectionStrength.WEAK: "red",
            DetectionStrength.NONE: "bright_red"
        }
    
    def format_analysis_results(self, analysis: AntiTamperingAnalysisResult) -> Text:
        """
        Format comprehensive anti-tampering analysis results.
        
        Args:
            analysis: Analysis results to format
            
        Returns:
            Text: Formatted analysis results
        """
        result = Text()
        
        try:
            # Title and summary
            result.append("🛡️  Anti-Tampering & Resilience Analysis\n", style="bold blue")
            result.append("=" * 50 + "\n\n", style="dim")
            
            # Executive summary
            self._add_executive_summary(result, analysis)
            
            # Component analysis sections
            self._add_component_analysis(result, analysis)
            
            # Vulnerability summary
            self._add_vulnerability_summary(result, analysis)
            
            # MASVS compliance
            self._add_masvs_compliance(result, analysis)
            
            # Recommendations
            self._add_recommendations(result, analysis)
            
            # Analysis metadata
            self._add_analysis_metadata(result, analysis)
            
        except Exception as e:
            logger.error(f"Error formatting anti-tampering results: {e}")
            result.append(f"❌ Formatting error: {str(e)}\n", style="red")
        
        return result
    
    def _add_executive_summary(self, result: Text, analysis: AntiTamperingAnalysisResult):
        """Add executive summary section."""
        result.append("📊 Executive Summary\n", style="bold")
        result.append("-" * 20 + "\n")
        
        # Overall resilience score
        score_color = self._get_score_color(analysis.overall_resilience_score)
        result.append(f"Overall Resilience Score: ", style="bold")
        result.append(f"{analysis.overall_resilience_score:.1f}/100\n", style=score_color)
        
        # Resilience level
        level_color = self.strength_colors.get(analysis.resilience_level, "white")
        result.append(f"Resilience Level: ", style="bold")
        result.append(f"{analysis.resilience_level.value.title()}\n", style=level_color)
        
        # Vulnerability counts
        result.append(f"Total Vulnerabilities: {analysis.total_vulnerabilities}\n")
        if analysis.critical_vulnerabilities > 0:
            result.append(f"  Critical: {analysis.critical_vulnerabilities}\n", style="bright_red")
        if analysis.high_vulnerabilities > 0:
            result.append(f"  High: {analysis.high_vulnerabilities}\n", style="red")
        if analysis.medium_vulnerabilities > 0:
            result.append(f"  Medium: {analysis.medium_vulnerabilities}\n", style="yellow")
        
        # Protection coverage
        coverage_color = self._get_score_color(analysis.protection_coverage)
        result.append(f"Protection Coverage: ", style="bold")
        result.append(f"{analysis.protection_coverage:.1f}%\n", style=coverage_color)
        
        result.append("\n")
    
    def _add_component_analysis(self, result: Text, analysis: AntiTamperingAnalysisResult):
        """Add component analysis sections."""
        result.append("🔍 Component Analysis\n", style="bold")
        result.append("-" * 20 + "\n")
        
        # Root detection
        self._add_component_section(result, "Root Detection", analysis.root_detection)
        
        # Debugger detection
        self._add_component_section(result, "Debugger Detection", analysis.debugger_detection)
        
        # Code obfuscation
        self._add_component_section(result, "Code Obfuscation", analysis.code_obfuscation)
        
        # Anti-Frida
        self._add_component_section(result, "Anti-Frida Protection", analysis.anti_frida)
        
        # RASP
        self._add_component_section(result, "RASP Mechanisms", analysis.rasp_analysis)
        
        result.append("\n")
    
    def _add_component_section(self, result: Text, title: str, component):
        """Add individual component analysis section."""
        result.append(f"  {title}:\n", style="bold cyan")
        
        # Strength assessment
        if hasattr(component, 'strength_assessment'):
            strength_color = self.strength_colors.get(component.strength_assessment, "white")
            result.append(f"    Strength: {component.strength_assessment.value.title()}\n", style=strength_color)
        
        # Confidence score
        if hasattr(component, 'confidence_score'):
            confidence_color = self._get_score_color(component.confidence_score)
            result.append(f"    Confidence: {component.confidence_score:.1f}%\n", style=confidence_color)
        
        # Mechanism count
        if hasattr(component, 'mechanism_count'):
            result.append(f"    Mechanisms Found: {component.mechanism_count}\n")
        
        # Vulnerabilities
        if hasattr(component, 'vulnerabilities') and component.vulnerabilities:
            vuln_count = len(component.vulnerabilities)
            if vuln_count > 0:
                result.append(f"    Vulnerabilities: {vuln_count}\n", style="yellow")
        
        result.append("\n")
    
    def _add_vulnerability_summary(self, result: Text, analysis: AntiTamperingAnalysisResult):
        """Add vulnerability summary section."""
        if analysis.total_vulnerabilities == 0:
            result.append("✅ No anti-tampering vulnerabilities detected\n\n", style="green")
            return
        
        result.append("🚨 Vulnerability Summary\n", style="bold")
        result.append("-" * 22 + "\n")
        
        # Get high-risk vulnerabilities
        high_risk_vulns = analysis.get_high_risk_vulnerabilities()
        
        if high_risk_vulns:
            result.append(f"High-Risk Vulnerabilities ({len(high_risk_vulns)}):\n", style="bold red")
            
            for i, vuln in enumerate(high_risk_vulns[:self.max_vulnerabilities_display]):
                severity_color = self.severity_colors.get(vuln.severity, "white")
                result.append(f"  {i+1}. {vuln.title}\n", style="bold")
                result.append(f"     Severity: {vuln.severity.value}\n", style=severity_color)
                result.append(f"     Confidence: {vuln.confidence:.1%}\n")
                result.append(f"     Location: {vuln.location}\n", style="dim")
                result.append("\n")
        
        result.append("\n")
    
    def _add_masvs_compliance(self, result: Text, analysis: AntiTamperingAnalysisResult):
        """Add MASVS compliance section."""
        result.append("📋 MASVS Compliance\n", style="bold")
        result.append("-" * 17 + "\n")
        
        if analysis.masvs_compliance:
            for control, compliant in analysis.masvs_compliance.items():
                status_icon = "✅" if compliant else "❌"
                status_color = "green" if compliant else "red"
                result.append(f"  {status_icon} {control}\n", style=status_color)
        
        # Overall compliance score
        compliance_color = self._get_score_color(analysis.compliance_score)
        result.append(f"\nCompliance Score: ", style="bold")
        result.append(f"{analysis.compliance_score:.1f}%\n", style=compliance_color)
        
        result.append("\n")
    
    def _add_recommendations(self, result: Text, analysis: AntiTamperingAnalysisResult):
        """Add security recommendations section."""
        if not analysis.security_recommendations:
            return
        
        result.append("💡 Security Recommendations\n", style="bold")
        result.append("-" * 26 + "\n")
        
        for i, recommendation in enumerate(analysis.security_recommendations, 1):
            result.append(f"  {i}. {recommendation}\n")
        
        result.append("\n")
    
    def _add_analysis_metadata(self, result: Text, analysis: AntiTamperingAnalysisResult):
        """Add analysis metadata section."""
        result.append("ℹ️  Analysis Information\n", style="bold dim")
        result.append("-" * 22 + "\n", style="dim")
        
        result.append(f"Package: {analysis.package_name}\n", style="dim")
        result.append(f"Analysis Version: {analysis.analysis_version}\n", style="dim")
        result.append(f"Analysis Duration: {analysis.analysis_duration:.2f}s\n", style="dim")
        result.append(f"Files Analyzed: {analysis.files_analyzed}\n", style="dim")
        result.append(f"Analysis Date: {analysis.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n", style="dim")
        
        if analysis.limitations:
            result.append(f"\nLimitations:\n", style="dim")
            for limitation in analysis.limitations:
                result.append(f"  • {limitation}\n", style="dim")
    
    def _get_score_color(self, score: float) -> str:
        """Get color for score display."""
        if score >= 80:
            return "bright_green"
        elif score >= 60:
            return "green"
        elif score >= 40:
            return "yellow"
        elif score >= 20:
            return "red"
        else:
            return "bright_red"
    
    def format_vulnerability_details(self, vulnerability: AntiTamperingVulnerability) -> Text:
        """Format detailed vulnerability information."""
        result = Text()
        
        # Title
        severity_color = self.severity_colors.get(vulnerability.severity, "white")
        result.append(f"🚨 {vulnerability.title}\n", style="bold")
        result.append(f"Severity: {vulnerability.severity.value}\n", style=severity_color)
        result.append(f"Confidence: {vulnerability.confidence:.1%}\n")
        result.append("\n")
        
        # Description
        result.append("Description:\n", style="bold")
        result.append(f"{vulnerability.description}\n\n")
        
        # Evidence
        if vulnerability.evidence:
            result.append("Evidence:\n", style="bold")
            result.append(f"{vulnerability.evidence}\n\n")
        
        # Location
        result.append("Location:\n", style="bold")
        result.append(f"{vulnerability.location}\n\n")
        
        # Remediation
        if vulnerability.remediation:
            result.append("Remediation:\n", style="bold")
            result.append(f"{vulnerability.remediation}\n\n")
        
        # MASVS references
        if vulnerability.masvs_refs:
            result.append("MASVS Controls:\n", style="bold")
            for ref in vulnerability.masvs_refs:
                result.append(f"  • {ref}\n")
            result.append("\n")
        
        return result
    
    def create_summary_table(self, analysis: AntiTamperingAnalysisResult) -> Table:
        """Create summary table for analysis results."""
        table = Table(title="Anti-Tampering Analysis Summary")
        
        table.add_column("Component", style="cyan")
        table.add_column("Strength", style="bold")
        table.add_column("Confidence", style="bold")
        table.add_column("Vulnerabilities", style="red")
        
        # Add component rows
        components = [
            ("Root Detection", analysis.root_detection),
            ("Debugger Detection", analysis.debugger_detection),
            ("Code Obfuscation", analysis.code_obfuscation),
            ("Anti-Frida", analysis.anti_frida),
            ("RASP", analysis.rasp_analysis)
        ]
        
        for name, component in components:
            if hasattr(component, 'strength_assessment'):
                strength = component.strength_assessment.value.title()
                confidence = f"{component.confidence_score:.1f}%" if hasattr(component, 'confidence_score') else "N/A"
                vuln_count = len(component.vulnerabilities) if hasattr(component, 'vulnerabilities') else 0
                
                table.add_row(name, strength, confidence, str(vuln_count))
        
        return table

# Factory function for easy instantiation
def create_anti_tampering_formatter(context: AnalysisContext) -> AntiTamperingFormatter:
    """Create an anti-tampering formatter instance."""
    return AntiTamperingFormatter(context) 