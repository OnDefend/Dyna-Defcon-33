"""
Storage Analysis Formatters Module

output formatting for storage analysis results.
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
    InsecureDataStorageAnalysisResult,
    StorageVulnerability,
    StorageVulnerabilitySeverity,
    StorageSecurityLevel
)

class StorageAnalysisFormatter:
    """
    formatter for storage analysis results.
    
    Provides structured, readable output formatting for all types of
    storage analysis results with rich text support.
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
            StorageVulnerabilitySeverity.CRITICAL: "red",
            StorageVulnerabilitySeverity.HIGH: "orange3",
            StorageVulnerabilitySeverity.MEDIUM: "yellow",
            StorageVulnerabilitySeverity.LOW: "blue",
            StorageVulnerabilitySeverity.INFO: "green"
        }
        
        # Color scheme for security levels
        self.security_level_colors = {
            StorageSecurityLevel.EXCELLENT: "green",
            StorageSecurityLevel.GOOD: "blue",
            StorageSecurityLevel.FAIR: "yellow",
            StorageSecurityLevel.POOR: "orange3",
            StorageSecurityLevel.CRITICAL: "red"
        }
    
    def format_analysis_results(self, analysis_result: InsecureDataStorageAnalysisResult) -> Text:
        """
        Format complete analysis results.
        
        Args:
            analysis_result: Complete analysis result
            
        Returns:
            Rich Text object with formatted results
        """
        output = Text()
        
        # Header
        output.append("Enhanced Insecure Data Storage Analysis Results\n", style="bold blue")
        output.append("=" * 65 + "\n\n", style="blue")
        
        # Summary
        output.append(self._format_summary(analysis_result))
        output.append("\n")
        
        # Security Score
        output.append(self._format_security_score(analysis_result))
        output.append("\n")
        
        # Vulnerability Summary
        output.append(self._format_vulnerability_summary(analysis_result))
        output.append("\n")
        
        # Detailed Analysis Results
        if analysis_result.database_analyses:
            output.append(self._format_database_analyses(analysis_result.database_analyses))
            output.append("\n")
        
        if analysis_result.shared_preferences_analyses:
            output.append(self._format_shared_preferences_analyses(analysis_result.shared_preferences_analyses))
            output.append("\n")
        
        if analysis_result.secret_findings:
            output.append(self._format_secret_findings(analysis_result.secret_findings))
            output.append("\n")
        
        if analysis_result.root_detection_findings:
            output.append(self._format_root_detection_findings(analysis_result.root_detection_findings))
            output.append("\n")
        
        # Recommendations
        if analysis_result.recommendations:
            output.append(self._format_recommendations(analysis_result.recommendations))
            output.append("\n")
        
        return output
    
    def _format_summary(self, analysis_result: InsecureDataStorageAnalysisResult) -> Text:
        """Format analysis summary."""
        summary = Text()
        
        summary.append("Analysis Summary\n", style="bold")
        summary.append("-" * 20 + "\n")
        
        summary.append(f"Package: {analysis_result.package_name}\n")
        summary.append(f"Total Vulnerabilities: {analysis_result.total_vulnerabilities}\n")
        
        if analysis_result.scan_statistics:
            stats = analysis_result.scan_statistics
            summary.append(f"Files Analyzed: {stats.files_analyzed}\n")
            summary.append(f"Databases Checked: {stats.databases_checked}\n")
            summary.append(f"Preferences Checked: {stats.preferences_checked}\n")
            summary.append(f"Secrets Found: {stats.secrets_found}\n")
            summary.append(f"Root Patterns Detected: {stats.root_patterns_detected}\n")
            
            if stats.total_scan_time > 0:
                summary.append(f"Analysis Time: {stats.total_scan_time:.2f}s\n")
        
        return summary
    
    def _format_security_score(self, analysis_result: InsecureDataStorageAnalysisResult) -> Text:
        """Format security score with visualization."""
        score_text = Text()
        
        score_text.append("Security Score\n", style="bold")
        score_text.append("-" * 15 + "\n")
        
        score = analysis_result.overall_security_score
        level = analysis_result.storage_security_level
        
        # Color code based on score
        level_color = self.security_level_colors.get(level, "white")
        
        score_text.append(f"Overall Score: ", style="bold")
        score_text.append(f"{score:.1f}/100.0", style=f"bold {level_color}")
        score_text.append("\n")
        
        score_text.append(f"Security Level: ", style="bold")
        score_text.append(f"{level.value}", style=f"bold {level_color}")
        score_text.append("\n")
        
        # Score bar visualization
        bar_length = 30
        filled_length = int(bar_length * score / 100)
        bar = "█" * filled_length + "░" * (bar_length - filled_length)
        score_text.append(f"[{bar}] {score:.1f}%\n", style=level_color)
        
        return score_text
    
    def _format_vulnerability_summary(self, analysis_result: InsecureDataStorageAnalysisResult) -> Text:
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
    
    def _format_database_analyses(self, database_analyses) -> Text:
        """Format database analysis results."""
        output = Text()
        
        output.append("Database Security Analysis\n", style="bold")
        output.append("-" * 30 + "\n")
        
        for analysis in database_analyses:
            output.append(f"\nDatabase: {analysis.database_path}\n", style="bold")
            output.append(f"Type: {analysis.database_type}\n")
            output.append(f"Encryption: {analysis.encryption_status}\n")
            
            if analysis.encryption_algorithm:
                output.append(f"Algorithm: {analysis.encryption_algorithm}\n")
            
            output.append(f"Security Score: {analysis.security_score:.1f}/100.0\n")
        
        return output
    
    def _format_shared_preferences_analyses(self, shared_prefs_analyses) -> Text:
        """Format shared preferences analysis results."""
        output = Text()
        
        output.append("Shared Preferences Analysis\n", style="bold")
        output.append("-" * 32 + "\n")
        
        for analysis in shared_prefs_analyses:
            output.append(f"\nPreferences: {analysis.preferences_file}\n", style="bold")
            output.append(f"Encryption: {analysis.encryption_status}\n")
            output.append(f"Mode: {analysis.mode}\n")
            output.append(f"Security Score: {analysis.security_score:.1f}/100.0\n")
        
        return output
    
    def _format_secret_findings(self, secret_findings) -> Text:
        """Format secret detection findings."""
        output = Text()
        
        output.append("Secret Detection Results\n", style="bold")
        output.append("-" * 28 + "\n")
        
        for i, secret in enumerate(secret_findings, 1):
            severity_color = self.severity_colors.get(secret.severity, "white")
            
            output.append(f"\n{i}. Secret: {secret.secret_type.value}\n", style="bold")
            output.append(f"   Location: {secret.location}\n")
            output.append(f"   Severity: ", style="bold")
            output.append(f"{secret.severity.value}\n", style=severity_color)
            output.append(f"   Confidence: {secret.confidence:.2f}\n")
            
            if secret.entropy_score is not None:
                output.append(f"   Entropy: {secret.entropy_score:.2f}\n")
        
        return output
    
    def _format_root_detection_findings(self, root_findings) -> Text:
        """Format root detection findings."""
        output = Text()
        
        output.append("Root Detection Analysis\n", style="bold")
        output.append("-" * 27 + "\n")
        
        # Group by category
        by_category = {}
        for finding in root_findings:
            category = finding.category.value
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(finding)
        
        for category, findings in by_category.items():
            output.append(f"\n{category.replace('_', ' ').title()}:\n", style="bold")
            for finding in findings:
                output.append(f"  • Pattern: {finding.pattern}\n")
                output.append(f"    Confidence: {finding.confidence:.2f}\n")
        
        return output
    
    def _format_recommendations(self, recommendations: List[str]) -> Text:
        """Format security recommendations."""
        output = Text()
        
        output.append("Security Recommendations\n", style="bold green")
        output.append("-" * 30 + "\n")
        
        for i, recommendation in enumerate(recommendations, 1):
            output.append(f"{i}. {recommendation}\n")
        
        return output
    
    def format_quick_summary(self, analysis_result: InsecureDataStorageAnalysisResult) -> Text:
        """Format a quick summary for overview."""
        summary = Text()
        
        # One-line summary
        summary.append(f"Storage Analysis: {analysis_result.total_vulnerabilities} vulnerabilities, ", style="bold")
        summary.append(f"Score: {analysis_result.overall_security_score:.1f}/100, ", style="bold")
        summary.append(f"Level: {analysis_result.storage_security_level.value}", style="bold")
        
        if analysis_result.total_vulnerabilities > 0:
            summary.append(f" ({analysis_result.critical_vulnerabilities} critical, {analysis_result.high_vulnerabilities} high)", style="red")
        else:
            summary.append(" - No vulnerabilities found", style="green")
        
        return summary 