"""
Binary Analysis Formatters Module

output formatting for binary analysis results.
Provides structured, readable output for all analysis components.

Features:
- Rich text formatting with color coding
- report generation
- Structured vulnerability reporting
- MASVS control mapping display
- Security scoring visualization
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
    NativeBinaryAnalysisResult,
    BinaryHardeningAnalysis,
    NativeBinaryVulnerability,
    VulnerabilitySeverity,
    BinaryProtectionLevel
)

class BinaryAnalysisFormatter:
    """
    formatter for binary analysis results.
    
    Provides structured, readable output formatting for all types of
    binary analysis results with rich text support.
    """
    
    def __init__(self, context: AnalysisContext, logger: logging.Logger):
        """
        Initialize formatter.
        
        Args:
            context: Analysis context
            logger: Logger instance
        """
        self.context = context
        self.logger = logger
        self.console = Console()
        
        # Color scheme for different severity levels
        self.severity_colors = {
            VulnerabilitySeverity.CRITICAL: "red",
            VulnerabilitySeverity.HIGH: "orange3",
            VulnerabilitySeverity.MEDIUM: "yellow",
            VulnerabilitySeverity.LOW: "blue",
            VulnerabilitySeverity.INFO: "green"
        }
        
        # Color scheme for protection levels
        self.protection_colors = {
            BinaryProtectionLevel.EXCELLENT: "green",
            BinaryProtectionLevel.GOOD: "blue",
            BinaryProtectionLevel.FAIR: "yellow",
            BinaryProtectionLevel.POOR: "orange3",
            BinaryProtectionLevel.CRITICAL: "red"
        }
    
    def format_analysis_results(self, analysis_result: NativeBinaryAnalysisResult) -> Text:
        """
        Format complete analysis results.
        
        Args:
            analysis_result: Complete analysis result
            
        Returns:
            Rich Text object with formatted results
        """
        output = Text()
        
        # Header
        output.append("Enhanced Native Binary Analysis Results\n", style="bold blue")
        output.append("=" * 60 + "\n\n", style="blue")
        
        # Summary
        output.append(self._format_summary(analysis_result))
        output.append("\n")
        
        # Security Score
        output.append(self._format_security_score(analysis_result))
        output.append("\n")
        
        # Vulnerability Summary
        output.append(self._format_vulnerability_summary(analysis_result))
        output.append("\n")
        
        # Hardening Analysis
        if analysis_result.hardening_analyses:
            output.append(self._format_hardening_analyses(analysis_result.hardening_analyses))
            output.append("\n")
        
        # Detailed Vulnerabilities
        all_vulnerabilities = self._collect_all_vulnerabilities(analysis_result)
        if all_vulnerabilities:
            output.append(self._format_detailed_vulnerabilities(all_vulnerabilities))
            output.append("\n")
        
        # Recommendations
        if analysis_result.recommendations:
            output.append(self._format_recommendations(analysis_result.recommendations))
            output.append("\n")
        
        return output
    
    def _format_summary(self, analysis_result: NativeBinaryAnalysisResult) -> Text:
        """Format analysis summary."""
        summary = Text()
        
        summary.append("Analysis Summary\n", style="bold")
        summary.append("-" * 20 + "\n")
        
        summary.append(f"Package: {analysis_result.package_name}\n")
        summary.append(f"Total Libraries: {analysis_result.total_libraries}\n")
        summary.append(f"Analyzed Libraries: {analysis_result.analyzed_libraries}\n")
        
        if analysis_result.analysis_time > 0:
            summary.append(f"Analysis Time: {analysis_result.analysis_time:.2f}s\n")
        
        return summary
    
    def _format_security_score(self, analysis_result: NativeBinaryAnalysisResult) -> Text:
        """Format security score with visualization."""
        score_text = Text()
        
        score_text.append("Security Score\n", style="bold")
        score_text.append("-" * 15 + "\n")
        
        score = analysis_result.overall_security_score
        
        # Color code based on score
        if score >= 80:
            score_color = "green"
        elif score >= 60:
            score_color = "yellow"
        elif score >= 40:
            score_color = "orange3"
        else:
            score_color = "red"
        
        score_text.append(f"Overall Score: ", style="bold")
        score_text.append(f"{score:.1f}/100.0", style=f"bold {score_color}")
        score_text.append("\n")
        
        # Score bar visualization
        bar_length = 30
        filled_length = int(bar_length * score / 100)
        bar = "█" * filled_length + "░" * (bar_length - filled_length)
        score_text.append(f"[{bar}] {score:.1f}%\n", style=score_color)
        
        return score_text
    
    def _format_vulnerability_summary(self, analysis_result: NativeBinaryAnalysisResult) -> Text:
        """Format vulnerability summary table."""
        summary = Text()
        
        summary.append("Vulnerability Summary\n", style="bold")
        summary.append("-" * 25 + "\n")
        
        # Create summary table
        table_data = [
            ("Critical", analysis_result.critical_vulnerabilities, "red"),
            ("High", analysis_result.high_vulnerabilities, "orange3"),
            ("Medium", analysis_result.medium_vulnerabilities, "yellow"),
            ("Low", analysis_result.low_vulnerabilities, "blue"),
            ("Total", analysis_result.total_vulnerabilities, "bold")
        ]
        
        for severity, count, color in table_data:
            summary.append(f"{severity:>8}: ", style="bold")
            summary.append(f"{count:>3}", style=color)
            summary.append(" vulnerabilities\n")
        
        return summary
    
    def _format_hardening_analyses(self, hardening_analyses: List[BinaryHardeningAnalysis]) -> Text:
        """Format hardening analysis results."""
        output = Text()
        
        output.append("Binary Hardening Analysis\n", style="bold")
        output.append("-" * 30 + "\n")
        
        for analysis in hardening_analyses:
            output.append(f"\nLibrary: {analysis.library_name}\n", style="bold")
            output.append(f"Architecture: {analysis.architecture.value}\n")
            
            # Protection mechanisms
            protections = [
                ("PIE", analysis.pie_enabled),
                ("NX", analysis.nx_enabled),
                ("RELRO", analysis.relro_enabled),
                ("Stack Canary", analysis.canary_enabled),
                ("Fortify", analysis.fortify_enabled),
                ("CFI", analysis.cfi_enabled)
            ]
            
            for name, enabled in protections:
                status = "✓" if enabled else "✗"
                color = "green" if enabled else "red"
                output.append(f"  {name:>12}: ", style="bold")
                output.append(f"{status} {'Enabled' if enabled else 'Disabled'}\n", style=color)
            
            # Protection level
            level_color = self.protection_colors.get(analysis.protection_level, "white")
            output.append(f"Protection Level: ", style="bold")
            output.append(f"{analysis.protection_level.value}\n", style=level_color)
            
            # Protection score
            output.append(f"Protection Score: {analysis.protection_score:.1f}/100.0\n")
        
        return output
    
    def _format_detailed_vulnerabilities(self, vulnerabilities: List[NativeBinaryVulnerability]) -> Text:
        """Format detailed vulnerability information."""
        output = Text()
        
        output.append("Detailed Vulnerabilities\n", style="bold")
        output.append("-" * 28 + "\n")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_color = self.severity_colors.get(vuln.severity, "white")
            
            output.append(f"\n{i}. {vuln.title}\n", style="bold")
            output.append(f"   ID: {vuln.id}\n")
            output.append(f"   Severity: ", style="bold")
            output.append(f"{vuln.severity.value}\n", style=severity_color)
            output.append(f"   MASVS Control: {vuln.masvs_control}\n")
            
            if vuln.cwe_id:
                output.append(f"   CWE ID: {vuln.cwe_id}\n")
            
            if vuln.confidence is not None:
                confidence_color = self._get_confidence_color(vuln.confidence)
                output.append(f"   Confidence: ", style="bold")
                output.append(f"{vuln.confidence:.2f}\n", style=confidence_color)
            
            output.append(f"   Description: {vuln.description}\n")
            
            if vuln.affected_files:
                output.append(f"   Affected Files: {', '.join(vuln.affected_files)}\n")
            
            if vuln.evidence:
                output.append(f"   Evidence:\n")
                for evidence in vuln.evidence:
                    output.append(f"     • {evidence}\n")
            
            if vuln.remediation:
                output.append(f"   Remediation: {vuln.remediation}\n")
        
        return output
    
    def _format_recommendations(self, recommendations: List[str]) -> Text:
        """Format security recommendations."""
        output = Text()
        
        output.append("Security Recommendations\n", style="bold green")
        output.append("-" * 30 + "\n")
        
        for i, recommendation in enumerate(recommendations, 1):
            output.append(f"{i}. {recommendation}\n")
        
        return output
    
    def _collect_all_vulnerabilities(self, analysis_result: NativeBinaryAnalysisResult) -> List[NativeBinaryVulnerability]:
        """Collect all vulnerabilities from different analysis types."""
        all_vulnerabilities = []
        
        # Hardening vulnerabilities
        for hardening in analysis_result.hardening_analyses:
            all_vulnerabilities.extend(hardening.vulnerabilities)
        
        # Symbol vulnerabilities
        for symbol in analysis_result.symbol_analyses:
            all_vulnerabilities.extend(symbol.vulnerabilities)
        
        # Malware vulnerabilities
        for malware in analysis_result.malware_analyses:
            all_vulnerabilities.extend(malware.vulnerabilities)
        
        # JNI vulnerabilities
        for jni in analysis_result.jni_analyses:
            all_vulnerabilities.extend(jni.vulnerabilities)
        
        # Memory vulnerabilities
        for memory in analysis_result.memory_analyses:
            all_vulnerabilities.extend(memory.vulnerabilities)
        
        # Crypto vulnerabilities
        for crypto in analysis_result.crypto_analyses:
            all_vulnerabilities.extend(crypto.vulnerabilities)
        
        # Sort by severity (critical first)
        severity_order = {
            VulnerabilitySeverity.CRITICAL: 0,
            VulnerabilitySeverity.HIGH: 1,
            VulnerabilitySeverity.MEDIUM: 2,
            VulnerabilitySeverity.LOW: 3,
            VulnerabilitySeverity.INFO: 4
        }
        
        all_vulnerabilities.sort(key=lambda v: severity_order.get(v.severity, 5))
        
        return all_vulnerabilities
    
    def _get_confidence_color(self, confidence: float) -> str:
        """Get color for confidence level."""
        if confidence >= 0.8:
            return "green"
        elif confidence >= 0.6:
            return "yellow"
        elif confidence >= 0.4:
            return "orange3"
        else:
            return "red"
    
    def format_quick_summary(self, analysis_result: NativeBinaryAnalysisResult) -> Text:
        """Format a quick summary for overview."""
        summary = Text()
        
        # One-line summary
        summary.append(f"Binary Analysis: {analysis_result.analyzed_libraries}/{analysis_result.total_libraries} libraries, ", style="bold")
        summary.append(f"Score: {analysis_result.overall_security_score:.1f}/100, ", style="bold")
        
        if analysis_result.total_vulnerabilities > 0:
            summary.append(f"{analysis_result.total_vulnerabilities} vulnerabilities ", style="red")
            summary.append(f"({analysis_result.critical_vulnerabilities} critical, {analysis_result.high_vulnerabilities} high)", style="red")
        else:
            summary.append("No vulnerabilities found", style="green")
        
        return summary 