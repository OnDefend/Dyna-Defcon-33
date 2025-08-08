#!/usr/bin/env python3
"""
Cryptography Analysis Formatters

This module provides comprehensive output formatting for cryptography analysis results,
including Rich Text formatting, structured reporting, and comprehensive output generation.
"""

from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from enum import Enum
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.markdown import Markdown
from rich.progress import Progress
from rich.syntax import Syntax
from rich.tree import Tree
from rich.align import Align
from rich.columns import Columns
from rich.rule import Rule

from .data_structures import (
    CryptographicVulnerability, VulnerabilitySeverity
)
from .advanced_crypto_analyzer import AdvancedCryptoVulnerability, AdvancedCryptoAnalysisType

class ReportFormat(Enum):
    """Report output formats."""
    CONSOLE = "console"
    MARKDOWN = "markdown"
    JSON = "json"
    HTML = "html"
    XML = "xml"
    CSV = "csv"

class SeverityColor:
    """Color schemes for severity levels."""
    CRITICAL = "red"
    HIGH = "orange_red1"
    MEDIUM = "yellow"
    LOW = "green"
    INFO = "blue"
    UNKNOWN = "grey"

@dataclass
class FormattingConfig:
    """Configuration for report formatting."""
    show_technical_details: bool = True
    show_evidence: bool = True
    show_remediation: bool = True
    show_compliance: bool = True
    show_statistics: bool = True
    color_output: bool = True
    compact_mode: bool = False
    max_evidence_items: int = 5
    table_width: int = 120

class CryptoAnalysisFormatter:
    """
    Comprehensive formatter for cryptography analysis results.
    Provides rich text formatting and structured output generation.
    """
    
    def __init__(self, config: Optional[FormattingConfig] = None):
        """Initialize the formatter."""
        self.config = config or FormattingConfig()
        self.console = Console(width=self.config.table_width)
        self.logger = logging.getLogger(__name__)
    
    def format_analysis_results(
        self, 
        vulnerabilities: List[CryptographicVulnerability],
        advanced_vulnerabilities: List[AdvancedCryptoVulnerability],
        statistics: Dict[str, Any],
        format_type: ReportFormat = ReportFormat.CONSOLE
    ) -> str:
        """
        Format complete analysis results.
        
        Args:
            vulnerabilities: List of standard cryptographic vulnerabilities
            advanced_vulnerabilities: List of advanced cryptographic vulnerabilities
            statistics: Analysis statistics
            format_type: Output format type
            
        Returns:
            Formatted report string
        """
        try:
            if format_type == ReportFormat.CONSOLE:
                return self._format_console_report(vulnerabilities, advanced_vulnerabilities, statistics)
            elif format_type == ReportFormat.MARKDOWN:
                return self._format_markdown_report(vulnerabilities, advanced_vulnerabilities, statistics)
            elif format_type == ReportFormat.JSON:
                return self._format_json_report(vulnerabilities, advanced_vulnerabilities, statistics)
            else:
                return self._format_console_report(vulnerabilities, advanced_vulnerabilities, statistics)
                
        except Exception as e:
            self.logger.error(f"Report formatting failed: {str(e)}")
            return f"Error formatting report: {str(e)}"
    
    def _format_console_report(
        self,
        vulnerabilities: List[CryptographicVulnerability],
        advanced_vulnerabilities: List[AdvancedCryptoVulnerability],
        statistics: Dict[str, Any]
    ) -> str:
        """Format console report with Rich Text."""
        try:
            # Capture console output
            with self.console.capture() as capture:
                self._render_console_header()
                self._render_statistics_panel(statistics)
                self._render_vulnerability_summary(vulnerabilities, advanced_vulnerabilities)
                
                if vulnerabilities:
                    self._render_standard_vulnerabilities(vulnerabilities)
                
                if advanced_vulnerabilities:
                    self._render_advanced_vulnerabilities(advanced_vulnerabilities)
                
                self._render_recommendations()
                self._render_console_footer()
            
            return capture.get()
            
        except Exception as e:
            self.logger.error(f"Console report formatting failed: {str(e)}")
            return f"Error formatting console report: {str(e)}"
    
    def _render_console_header(self) -> None:
        """Render console report header."""
        title = Text("AODS Cryptography Analysis Report", style="bold blue")
        self.console.print(Panel(
            Align.center(title),
            style="blue",
            padding=(1, 2)
        ))
        self.console.print()
    
    def _render_statistics_panel(self, statistics: Dict[str, Any]) -> None:
        """Render statistics panel."""
        stats_table = Table(title="Analysis Statistics", show_header=True)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")
        
        for key, value in statistics.items():
            formatted_key = key.replace('_', ' ').title()
            stats_table.add_row(formatted_key, str(value))
        
        self.console.print(stats_table)
        self.console.print()
    
    def _render_vulnerability_summary(
        self,
        vulnerabilities: List[CryptographicVulnerability],
        advanced_vulnerabilities: List[AdvancedCryptoVulnerability]
    ) -> None:
        """Render vulnerability summary."""
        total_vulns = len(vulnerabilities) + len(advanced_vulnerabilities)
        
        if total_vulns == 0:
            self.console.print(Panel(
                "[green]No cryptographic vulnerabilities detected[/green]",
                style="green"
            ))
            return
        
        # Count by severity
        severity_counts = self._count_vulnerabilities_by_severity(vulnerabilities, advanced_vulnerabilities)
        
        summary_table = Table(title="Vulnerability Summary", show_header=True)
        summary_table.add_column("Severity", style="cyan")
        summary_table.add_column("Count", style="green")
        summary_table.add_column("Percentage", style="yellow")
        
        for severity, count in severity_counts.items():
            percentage = (count / total_vulns) * 100 if total_vulns > 0 else 0
            color = self._get_severity_color(severity)
            summary_table.add_row(
                f"[{color}]{severity}[/{color}]",
                str(count),
                f"{percentage:.1f}%"
            )
        
        self.console.print(summary_table)
        self.console.print()
    
    def _render_standard_vulnerabilities(self, vulnerabilities: List[CryptographicVulnerability]) -> None:
        """Render standard vulnerabilities section."""
        self.console.print(Rule("Standard Cryptographic Vulnerabilities", style="blue"))
        self.console.print()
        
        for i, vuln in enumerate(vulnerabilities, 1):
            self._render_standard_vulnerability(vuln, i)
    
    def _render_standard_vulnerability(self, vuln: CryptographicVulnerability, index: int) -> None:
        """Render individual standard vulnerability."""
        severity_color = self._get_severity_color(vuln.severity.value)
        
        # Main vulnerability panel
        title = f"[{severity_color}]{vuln.severity.value.upper()}[/{severity_color}] - {vuln.description}"
        
        content = []
        content.append(f"**Type:** {vuln.vulnerability_type.value}")
        content.append(f"**Algorithm:** {vuln.algorithm.value}")
        content.append(f"**Confidence:** {vuln.confidence:.2f}")
        
        if self.config.show_technical_details and vuln.technical_details:
            content.append(f"**Technical Details:** {vuln.technical_details}")
        
        if self.config.show_evidence and vuln.evidence:
            evidence_items = vuln.evidence[:self.config.max_evidence_items]
            content.append("**Evidence:**")
            for evidence in evidence_items:
                content.append(f"  • {evidence}")
        
        if self.config.show_remediation and vuln.remediation:
            content.append(f"**Remediation:** {vuln.remediation}")
        
        panel_content = "\n".join(content)
        
        self.console.print(Panel(
            panel_content,
            title=f"Vulnerability #{index}",
            border_style=severity_color
        ))
        self.console.print()
    
    def _render_advanced_vulnerabilities(self, vulnerabilities: List[AdvancedCryptoVulnerability]) -> None:
        """Render advanced vulnerabilities section."""
        self.console.print(Rule("Advanced Cryptographic Analysis", style="red"))
        self.console.print()
        
        for i, vuln in enumerate(vulnerabilities, 1):
            self._render_advanced_vulnerability(vuln, i)
    
    def _render_advanced_vulnerability(self, vuln: AdvancedCryptoVulnerability, index: int) -> None:
        """Render individual advanced vulnerability."""
        severity_color = self._get_severity_color(vuln.severity.value)
        
        # Advanced vulnerability panel
        title = f"[{severity_color}]{vuln.severity.value.upper()}[/{severity_color}] - {vuln.description}"
        
        content = []
        content.append(f"**Analysis Type:** {vuln.vulnerability_type.value}")
        content.append(f"**Confidence:** {vuln.confidence:.2f}")
        content.append(f"**Complexity Score:** {vuln.complexity_score:.2f}")
        content.append(f"**Exploitability Score:** {vuln.exploitability_score:.2f}")
        
        if self.config.show_technical_details:
            content.append(f"**Technical Details:** {vuln.technical_details}")
            content.append(f"**Attack Vector:** {vuln.attack_vector}")
        
        if vuln.quantum_threat_level != "unknown":
            content.append(f"**Quantum Threat Level:** {vuln.quantum_threat_level}")
        
        if vuln.performance_impact != "unknown":
            content.append(f"**Performance Impact:** {vuln.performance_impact}")
        
        if self.config.show_evidence and vuln.evidence:
            evidence_items = vuln.evidence[:self.config.max_evidence_items]
            content.append("**Evidence:**")
            for evidence in evidence_items:
                content.append(f"  • {evidence}")
        
        if self.config.show_remediation:
            content.append(f"**Mitigation:** {vuln.mitigation}")
        
        panel_content = "\n".join(content)
        
        self.console.print(Panel(
            panel_content,
            title=f"Advanced Analysis #{index}",
            border_style=severity_color
        ))
        self.console.print()
    
    def _render_recommendations(self) -> None:
        """Render security recommendations."""
        self.console.print(Rule("Security Recommendations", style="green"))
        self.console.print()
        
        recommendations = [
            "Use strong, modern cryptographic algorithms (AES-256, RSA-4096, ECC-P384)",
            "Implement proper key management and secure key storage",
            "Use authenticated encryption modes (GCM, CCM) for symmetric encryption",
            "Enable certificate pinning and proper hostname verification",
            "Implement secure random number generation with proper entropy",
            "Regular security audits and cryptographic code reviews",
            "Stay updated with latest cryptographic standards and best practices",
            "Consider post-quantum cryptography for future-proofing",
            "Implement proper error handling without information leakage",
            "Use secure coding practices to prevent side-channel attacks"
        ]
        
        for i, recommendation in enumerate(recommendations, 1):
            self.console.print(f"[green]{i}.[/green] {recommendation}")
        
        self.console.print()
    
    def _render_console_footer(self) -> None:
        """Render console report footer."""
        footer = Text(
            "Generated by AODS Cryptography Analysis Framework",
            style="dim blue"
        )
        self.console.print(Panel(
            Align.center(footer),
            style="dim blue"
        ))
    
    def _format_markdown_report(
        self,
        vulnerabilities: List[CryptographicVulnerability],
        advanced_vulnerabilities: List[AdvancedCryptoVulnerability],
        statistics: Dict[str, Any]
    ) -> str:
        """Format markdown report."""
        try:
            lines = []
            lines.append("# AODS Cryptography Analysis Report")
            lines.append("")
            
            # Statistics section
            lines.append("## Analysis Statistics")
            lines.append("")
            for key, value in statistics.items():
                formatted_key = key.replace('_', ' ').title()
                lines.append(f"- **{formatted_key}:** {value}")
            lines.append("")
            
            # Vulnerability summary
            total_vulns = len(vulnerabilities) + len(advanced_vulnerabilities)
            lines.append("## Vulnerability Summary")
            lines.append("")
            lines.append(f"Total vulnerabilities detected: **{total_vulns}**")
            lines.append("")
            
            if total_vulns > 0:
                severity_counts = self._count_vulnerabilities_by_severity(vulnerabilities, advanced_vulnerabilities)
                lines.append("### By Severity")
                lines.append("")
                for severity, count in severity_counts.items():
                    percentage = (count / total_vulns) * 100
                    lines.append(f"- **{severity}:** {count} ({percentage:.1f}%)")
                lines.append("")
            
            # Standard vulnerabilities
            if vulnerabilities:
                lines.append("## Standard Cryptographic Vulnerabilities")
                lines.append("")
                for i, vuln in enumerate(vulnerabilities, 1):
                    lines.extend(self._format_markdown_vulnerability(vuln, i))
            
            # Advanced vulnerabilities
            if advanced_vulnerabilities:
                lines.append("## Advanced Cryptographic Analysis")
                lines.append("")
                for i, vuln in enumerate(advanced_vulnerabilities, 1):
                    lines.extend(self._format_markdown_advanced_vulnerability(vuln, i))
            
            # Recommendations
            lines.append("## Security Recommendations")
            lines.append("")
            recommendations = [
                "Use strong, modern cryptographic algorithms",
                "Implement proper key management and secure storage",
                "Use authenticated encryption modes",
                "Enable certificate pinning and hostname verification",
                "Implement secure random number generation",
                "Regular security audits and code reviews",
                "Stay updated with cryptographic standards",
                "Consider post-quantum cryptography",
                "Implement proper error handling",
                "Use secure coding practices"
            ]
            
            for i, recommendation in enumerate(recommendations, 1):
                lines.append(f"{i}. {recommendation}")
            
            lines.append("")
            lines.append("---")
            lines.append("*Generated by AODS Cryptography Analysis Framework*")
            
            return "\n".join(lines)
            
        except Exception as e:
            self.logger.error(f"Markdown report formatting failed: {str(e)}")
            return f"Error formatting markdown report: {str(e)}"
    
    def _format_markdown_vulnerability(self, vuln: CryptographicVulnerability, index: int) -> List[str]:
        """Format individual vulnerability for markdown."""
        lines = []
        lines.append(f"### Vulnerability #{index}: {vuln.description}")
        lines.append("")
        lines.append(f"- **Severity:** {vuln.severity.value.upper()}")
        lines.append(f"- **Type:** {vuln.vulnerability_type.value}")
        lines.append(f"- **Algorithm:** {vuln.algorithm.value}")
        lines.append(f"- **Confidence:** {vuln.confidence:.2f}")
        
        if vuln.technical_details:
            lines.append(f"- **Technical Details:** {vuln.technical_details}")
        
        if vuln.evidence:
            lines.append("- **Evidence:**")
            for evidence in vuln.evidence[:self.config.max_evidence_items]:
                lines.append(f"  - {evidence}")
        
        if vuln.remediation:
            lines.append(f"- **Remediation:** {vuln.remediation}")
        
        lines.append("")
        return lines
    
    def _format_markdown_advanced_vulnerability(self, vuln: AdvancedCryptoVulnerability, index: int) -> List[str]:
        """Format individual advanced vulnerability for markdown."""
        lines = []
        lines.append(f"### Advanced Analysis #{index}: {vuln.description}")
        lines.append("")
        lines.append(f"- **Severity:** {vuln.severity.value.upper()}")
        lines.append(f"- **Analysis Type:** {vuln.vulnerability_type.value}")
        lines.append(f"- **Confidence:** {vuln.confidence:.2f}")
        lines.append(f"- **Complexity Score:** {vuln.complexity_score:.2f}")
        lines.append(f"- **Exploitability Score:** {vuln.exploitability_score:.2f}")
        
        if vuln.technical_details:
            lines.append(f"- **Technical Details:** {vuln.technical_details}")
        
        if vuln.attack_vector:
            lines.append(f"- **Attack Vector:** {vuln.attack_vector}")
        
        if vuln.quantum_threat_level != "unknown":
            lines.append(f"- **Quantum Threat Level:** {vuln.quantum_threat_level}")
        
        if vuln.evidence:
            lines.append("- **Evidence:**")
            for evidence in vuln.evidence[:self.config.max_evidence_items]:
                lines.append(f"  - {evidence}")
        
        if vuln.mitigation:
            lines.append(f"- **Mitigation:** {vuln.mitigation}")
        
        lines.append("")
        return lines
    
    def _format_json_report(
        self,
        vulnerabilities: List[CryptographicVulnerability],
        advanced_vulnerabilities: List[AdvancedCryptoVulnerability],
        statistics: Dict[str, Any]
    ) -> str:
        """Format JSON report."""
        import json
        
        try:
            report_data = {
                "metadata": {
                    "report_type": "cryptography_analysis",
                    "generator": "AODS Cryptography Analysis Framework",
                    "timestamp": str(statistics.get('timestamp', 'unknown'))
                },
                "statistics": statistics,
                "vulnerabilities": {
                    "standard": [self._vulnerability_to_dict(vuln) for vuln in vulnerabilities],
                    "advanced": [self._advanced_vulnerability_to_dict(vuln) for vuln in advanced_vulnerabilities]
                },
                "summary": {
                    "total_vulnerabilities": len(vulnerabilities) + len(advanced_vulnerabilities),
                    "severity_distribution": self._count_vulnerabilities_by_severity(vulnerabilities, advanced_vulnerabilities)
                }
            }
            
            return json.dumps(report_data, indent=2, default=str)
            
        except Exception as e:
            self.logger.error(f"JSON report formatting failed: {str(e)}")
            return f'{{"error": "JSON formatting failed: {str(e)}"}}'
    
    def _vulnerability_to_dict(self, vuln: CryptographicVulnerability) -> Dict[str, Any]:
        """Convert vulnerability to dictionary."""
        return {
            "description": vuln.description,
            "severity": vuln.severity.value,
            "vulnerability_type": vuln.vulnerability_type.value,
            "algorithm": vuln.algorithm.value,
            "confidence": vuln.confidence,
            "technical_details": vuln.technical_details,
            "evidence": vuln.evidence,
            "remediation": vuln.remediation,
            "masvs_category": vuln.masvs_category,
            "location": vuln.location,
            "affected_files": vuln.affected_files
        }
    
    def _advanced_vulnerability_to_dict(self, vuln: AdvancedCryptoVulnerability) -> Dict[str, Any]:
        """Convert advanced vulnerability to dictionary."""
        return {
            "description": vuln.description,
            "severity": vuln.severity.value,
            "vulnerability_type": vuln.vulnerability_type.value,
            "confidence": vuln.confidence,
            "complexity_score": vuln.complexity_score,
            "exploitability_score": vuln.exploitability_score,
            "quantum_threat_level": vuln.quantum_threat_level,
            "performance_impact": vuln.performance_impact,
            "technical_details": vuln.technical_details,
            "attack_vector": vuln.attack_vector,
            "mitigation": vuln.mitigation,
            "evidence": vuln.evidence,
            "affected_algorithms": [alg.value for alg in vuln.affected_algorithms]
        }
    
    def _count_vulnerabilities_by_severity(
        self,
        vulnerabilities: List[CryptographicVulnerability],
        advanced_vulnerabilities: List[AdvancedCryptoVulnerability]
    ) -> Dict[str, int]:
        """Count vulnerabilities by severity level."""
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.severity.value.upper()
            if severity in counts:
                counts[severity] += 1
        
        for vuln in advanced_vulnerabilities:
            severity = vuln.severity.value.upper()
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        color_map = {
            "critical": SeverityColor.CRITICAL,
            "high": SeverityColor.HIGH,
            "medium": SeverityColor.MEDIUM,
            "low": SeverityColor.LOW,
            "info": SeverityColor.INFO
        }
        return color_map.get(severity.lower(), SeverityColor.UNKNOWN)
    
    def generate_executive_summary(
        self,
        vulnerabilities: List[CryptographicVulnerability],
        advanced_vulnerabilities: List[AdvancedCryptoVulnerability],
        statistics: Dict[str, Any]
    ) -> str:
        """Generate executive summary for management reporting."""
        try:
            total_vulns = len(vulnerabilities) + len(advanced_vulnerabilities)
            severity_counts = self._count_vulnerabilities_by_severity(vulnerabilities, advanced_vulnerabilities)
            
            summary = []
            summary.append("# Executive Summary - Cryptographic Security Analysis")
            summary.append("")
            
            # Risk assessment
            critical_count = severity_counts.get("CRITICAL", 0)
            high_count = severity_counts.get("HIGH", 0)
            
            if critical_count > 0:
                risk_level = "CRITICAL"
                risk_color = "red"
            elif high_count > 0:
                risk_level = "HIGH"
                risk_color = "orange"
            elif total_vulns > 0:
                risk_level = "MEDIUM"
                risk_color = "yellow"
            else:
                risk_level = "LOW"
                risk_color = "green"
            
            summary.append(f"**Overall Risk Level:** {risk_level}")
            summary.append(f"**Total Security Issues:** {total_vulns}")
            summary.append("")
            
            # Key findings
            if critical_count > 0:
                summary.append(f"⚠️ **{critical_count} CRITICAL** cryptographic vulnerabilities require immediate attention")
            if high_count > 0:
                summary.append(f"🔴 **{high_count} HIGH** severity issues need prompt remediation")
            
            if total_vulns == 0:
                summary.append("✅ **No critical cryptographic vulnerabilities detected**")
            
            summary.append("")
            
            # Recommendations
            summary.append("## Immediate Actions Required")
            summary.append("")
            
            if critical_count > 0:
                summary.append("1. **URGENT:** Address all critical cryptographic vulnerabilities")
                summary.append("2. Review and update cryptographic implementations")
                summary.append("3. Implement proper key management practices")
            elif high_count > 0:
                summary.append("1. Address high-severity cryptographic issues")
                summary.append("2. Review encryption implementations")
                summary.append("3. Enhance security controls")
            else:
                summary.append("1. Maintain current security posture")
                summary.append("2. Continue regular security assessments")
                summary.append("3. Stay updated with cryptographic best practices")
            
            return "\n".join(summary)
            
        except Exception as e:
            self.logger.error(f"Executive summary generation failed: {str(e)}")
            return f"Error generating executive summary: {str(e)}"
    
    def export_findings_csv(
        self,
        vulnerabilities: List[CryptographicVulnerability],
        advanced_vulnerabilities: List[AdvancedCryptoVulnerability]
    ) -> str:
        """Export findings to CSV format."""
        try:
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # CSV header
            writer.writerow([
                "Type", "Severity", "Description", "Confidence", "Algorithm",
                "Technical Details", "Remediation", "Evidence Count"
            ])
            
            # Standard vulnerabilities
            for vuln in vulnerabilities:
                writer.writerow([
                    "Standard",
                    vuln.severity.value,
                    vuln.description,
                    f"{vuln.confidence:.2f}",
                    vuln.algorithm.value,
                    vuln.technical_details,
                    vuln.remediation,
                    len(vuln.evidence)
                ])
            
            # Advanced vulnerabilities
            for vuln in advanced_vulnerabilities:
                writer.writerow([
                    "Advanced",
                    vuln.severity.value,
                    vuln.description,
                    f"{vuln.confidence:.2f}",
                    vuln.vulnerability_type.value,
                    vuln.technical_details,
                    vuln.mitigation,
                    len(vuln.evidence)
                ])
            
            return output.getvalue()
            
        except Exception as e:
            self.logger.error(f"CSV export failed: {str(e)}")
            return f"Error exporting CSV: {str(e)}"