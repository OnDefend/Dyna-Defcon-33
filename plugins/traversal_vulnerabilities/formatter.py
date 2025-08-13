"""
Traversal Vulnerabilities Formatter

formatting module for traversal vulnerability analysis results.
Provides rich text output with detailed reporting and structured presentation.
"""

import json
import logging
from typing import Dict, List, Union, Any
from datetime import datetime

from rich.text import Text
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

from .data_structures import (
    TraversalVulnerability, ContentProviderAnalysis, IntentFilterAnalysis,
    FileOperationAnalysis, TraversalAnalysisResult, SeverityLevel,
    RiskLevel, PayloadGenerationResult, SecurityControlAssessment
)

logger = logging.getLogger(__name__)
console = Console()

class TraversalVulnerabilityFormatter:
    """
    formatter for traversal vulnerability analysis results.
    
    Provides multiple output formats including:
    - Rich text reports with detailed analysis
    - Structured JSON output for integration
    - Summary reports with key metrics
    - Vulnerability-specific detailed reports
    """
    
    def __init__(self):
        """Initialize the formatter."""
        self.console = Console()
        
        # Color scheme for different severity levels
        self.severity_colors = {
            SeverityLevel.CRITICAL.value: "red",
            SeverityLevel.HIGH.value: "bright_red",
            SeverityLevel.MEDIUM.value: "yellow",
            SeverityLevel.LOW.value: "green",
            SeverityLevel.INFO.value: "blue"
        }
        
        # Icons for different vulnerability types
        self.vulnerability_icons = {
            "path_traversal": "🗂️",
            "directory_traversal": "📁",
            "file_inclusion": "📄",
            "content_provider": "🔗",
            "intent_based": "📨",
            "uri_based": "🔗",
            "webview_based": "🌐"
        }
        
        logger.info("Traversal vulnerability formatter initialized")
    
    def format_analysis_results(self, results: TraversalAnalysisResult) -> Text:
        """
        Format complete analysis results into rich text report.
        
        Args:
            results: Complete analysis results
            
        Returns:
            Rich text formatted report
        """
        report = Text()
        
        # Header
        report.append("🔍 TRAVERSAL VULNERABILITY ANALYSIS REPORT\n", style="bold blue")
        report.append("=" * 60 + "\n\n", style="blue")
        
        # Executive Summary
        report.append(self._format_executive_summary(results))
        
        # Vulnerability Details
        if results.vulnerabilities:
            report.append(self._format_vulnerability_details(results.vulnerabilities))
        
        # Content Provider Analysis
        if results.content_provider_analyses:
            report.append(self._format_content_provider_analysis(results.content_provider_analyses))
        
        # Intent Filter Analysis
        if results.intent_filter_analyses:
            report.append(self._format_intent_filter_analysis(results.intent_filter_analyses))
        
        # File Operation Analysis
        if results.file_operation_analyses:
            report.append(self._format_file_operation_analysis(results.file_operation_analyses))
        
        # Recommendations
        if results.recommendations:
            report.append(self._format_recommendations(results.recommendations))
        
        # Compliance Assessment
        report.append(self._format_compliance_assessment(results))
        
        # Analysis Metadata
        report.append(self._format_analysis_metadata(results.analysis_metadata))
        
        return report
    
    def _format_executive_summary(self, results: TraversalAnalysisResult) -> Text:
        """Format executive summary section."""
        summary = Text()
        summary.append("📊 EXECUTIVE SUMMARY\n", style="bold cyan")
        summary.append("-" * 30 + "\n\n", style="cyan")
        
        # Overall statistics
        total_vulnerabilities = len(results.vulnerabilities)
        severity_counts = self._count_vulnerabilities_by_severity(results.vulnerabilities)
        
        summary.append(f"Total Vulnerabilities Found: {total_vulnerabilities}\n", style="bold")
        summary.append(f"Overall Risk Score: {results.overall_risk_score:.2f}/10\n", style="bold")
        summary.append(f"Security Assessment: {results.security_assessment}\n", style="bold")
        summary.append("\n")
        
        # Severity breakdown
        summary.append("Severity Breakdown:\n", style="bold")
        for severity, count in severity_counts.items():
            if count > 0:
                color = self.severity_colors.get(severity, "white")
                summary.append(f"  • {severity.upper()}: {count}\n", style=color)
        
        summary.append("\n")
        
        # Risk assessment
        risk_color = self._get_risk_color(results.security_assessment)
        summary.append(f"Risk Level: {results.security_assessment}\n", style=f"bold {risk_color}")
        summary.append("\n")
        
        return summary
    
    def _format_vulnerability_details(self, vulnerabilities: List[TraversalVulnerability]) -> Text:
        """Format detailed vulnerability information."""
        details = Text()
        details.append("🚨 VULNERABILITY DETAILS\n", style="bold red")
        details.append("-" * 30 + "\n\n", style="red")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            details.append(f"[{i}] {vuln.title}\n", style="bold")
            details.append(f"    ID: {vuln.vulnerability_id}\n", style="dim")
            
            # Severity and confidence
            severity_color = self.severity_colors.get(vuln.severity, "white")
            details.append(f"    Severity: {vuln.severity.upper()}\n", style=severity_color)
            details.append(f"    Confidence: {vuln.confidence:.2f}\n", style="bold")
            
            # Location and type
            details.append(f"    Location: {vuln.location}\n", style="blue")
            details.append(f"    Type: {vuln.traversal_type}\n", style="blue")
            
            # Description
            details.append(f"    Description: {vuln.description}\n", style="white")
            
            # Evidence (truncated)
            evidence = vuln.evidence[:200] + "..." if len(vuln.evidence) > 200 else vuln.evidence
            details.append(f"    Evidence: {evidence}\n", style="dim")
            
            # Attack vectors
            if vuln.attack_vectors:
                details.append(f"    Attack Vectors: {', '.join(vuln.attack_vectors[:3])}\n", style="yellow")
            
            # Remediation
            if vuln.remediation:
                details.append(f"    Remediation: {vuln.remediation}\n", style="green")
            
            # MASVS references
            if vuln.masvs_refs:
                details.append(f"    MASVS: {', '.join(vuln.masvs_refs)}\n", style="magenta")
            
            # CWE ID
            if vuln.cwe_id:
                details.append(f"    CWE: {vuln.cwe_id}\n", style="magenta")
            
            details.append("\n")
        
        return details
    
    def _format_content_provider_analysis(self, analyses: List[ContentProviderAnalysis]) -> Text:
        """Format content provider analysis results."""
        content = Text()
        content.append("🔗 CONTENT PROVIDER ANALYSIS\n", style="bold cyan")
        content.append("-" * 35 + "\n\n", style="cyan")
        
        for analysis in analyses:
            content.append(f"Provider: {analysis.provider_name}\n", style="bold")
            content.append(f"    Authority: {analysis.authority}\n", style="blue")
            content.append(f"    Exported: {analysis.exported}\n", style="yellow" if analysis.exported else "green")
            content.append(f"    Grant URI Permissions: {analysis.grant_uri_permissions}\n", 
                         style="yellow" if analysis.grant_uri_permissions else "green")
            content.append(f"    Risk Level: {analysis.risk_level}\n", 
                         style=self._get_risk_color(analysis.risk_level))
            content.append(f"    Security Score: {analysis.security_score:.2f}\n", style="bold")
            
            if analysis.permissions:
                content.append(f"    Permissions: {', '.join(analysis.permissions)}\n", style="blue")
            
            if analysis.vulnerabilities:
                content.append(f"    Vulnerabilities: {len(analysis.vulnerabilities)}\n", style="red")
            
            content.append("\n")
        
        return content
    
    def _format_intent_filter_analysis(self, analyses: List[IntentFilterAnalysis]) -> Text:
        """Format intent filter analysis results."""
        content = Text()
        content.append("📨 INTENT FILTER ANALYSIS\n", style="bold cyan")
        content.append("-" * 30 + "\n\n", style="cyan")
        
        for analysis in analyses:
            content.append(f"Component: {analysis.component_name}\n", style="bold")
            content.append(f"    Action: {analysis.action}\n", style="blue")
            content.append(f"    Data Scheme: {analysis.data_scheme}\n", style="blue")
            content.append(f"    Data Host: {analysis.data_host}\n", style="blue")
            content.append(f"    Exported: {analysis.exported}\n", style="yellow" if analysis.exported else "green")
            content.append(f"    Risk Assessment: {analysis.risk_assessment}\n", 
                         style=self._get_risk_color(analysis.risk_assessment))
            
            if analysis.vulnerabilities:
                content.append(f"    Vulnerabilities: {len(analysis.vulnerabilities)}\n", style="red")
            
            content.append("\n")
        
        return content
    
    def _format_file_operation_analysis(self, analyses: List[FileOperationAnalysis]) -> Text:
        """Format file operation analysis results."""
        content = Text()
        content.append("📁 FILE OPERATION ANALYSIS\n", style="bold cyan")
        content.append("-" * 30 + "\n\n", style="cyan")
        
        for analysis in analyses:
            content.append(f"Operation: {analysis.operation_type}\n", style="bold")
            content.append(f"    File Path: {analysis.file_path}\n", style="blue")
            content.append(f"    Validation Present: {analysis.validation_present}\n", 
                         style="green" if analysis.validation_present else "red")
            content.append(f"    Sanitization Present: {analysis.sanitization_present}\n", 
                         style="green" if analysis.sanitization_present else "red")
            content.append(f"    User Input Source: {analysis.user_input_source}\n", style="yellow")
            
            if analysis.security_controls:
                content.append(f"    Security Controls: {', '.join(analysis.security_controls)}\n", style="green")
            
            if analysis.bypass_techniques:
                content.append(f"    Bypass Techniques: {', '.join(analysis.bypass_techniques)}\n", style="red")
            
            if analysis.vulnerabilities:
                content.append(f"    Vulnerabilities: {len(analysis.vulnerabilities)}\n", style="red")
            
            content.append("\n")
        
        return content
    
    def _format_recommendations(self, recommendations: List[str]) -> Text:
        """Format security recommendations."""
        content = Text()
        content.append("💡 SECURITY RECOMMENDATIONS\n", style="bold green")
        content.append("-" * 35 + "\n\n", style="green")
        
        for i, recommendation in enumerate(recommendations, 1):
            content.append(f"{i}. {recommendation}\n", style="white")
        
        content.append("\n")
        return content
    
    def _format_compliance_assessment(self, results: TraversalAnalysisResult) -> Text:
        """Format compliance assessment section."""
        content = Text()
        content.append("📋 COMPLIANCE ASSESSMENT\n", style="bold magenta")
        content.append("-" * 30 + "\n\n", style="magenta")
        
        # MASVS compliance
        if results.masvs_compliance:
            content.append("MASVS Controls:\n", style="bold")
            for control in results.masvs_compliance:
                content.append(f"  • {control}\n", style="blue")
            content.append("\n")
        
        # CWE mappings
        if results.cwe_mappings:
            content.append("CWE Mappings:\n", style="bold")
            for cwe in results.cwe_mappings:
                content.append(f"  • {cwe}\n", style="blue")
            content.append("\n")
        
        return content
    
    def _format_analysis_metadata(self, metadata: Dict[str, Any]) -> Text:
        """Format analysis metadata section."""
        content = Text()
        content.append("📊 ANALYSIS METADATA\n", style="bold dim")
        content.append("-" * 25 + "\n\n", style="dim")
        
        # Analysis timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        content.append(f"Analysis Date: {timestamp}\n", style="dim")
        
        # Analysis statistics
        if metadata:
            for key, value in metadata.items():
                if isinstance(value, (int, float, str)):
                    content.append(f"{key.replace('_', ' ').title()}: {value}\n", style="dim")
        
        content.append("\n")
        return content
    
    def format_vulnerability_summary(self, vulnerabilities: List[TraversalVulnerability]) -> Text:
        """Format a concise vulnerability summary."""
        summary = Text()
        summary.append("🔍 VULNERABILITY SUMMARY\n", style="bold blue")
        summary.append("-" * 25 + "\n\n", style="blue")
        
        # Count by severity
        severity_counts = self._count_vulnerabilities_by_severity(vulnerabilities)
        total = len(vulnerabilities)
        
        summary.append(f"Total Vulnerabilities: {total}\n\n", style="bold")
        
        for severity, count in severity_counts.items():
            if count > 0:
                percentage = (count / total) * 100 if total > 0 else 0
                color = self.severity_colors.get(severity, "white")
                summary.append(f"{severity.upper()}: {count} ({percentage:.1f}%)\n", style=color)
        
        return summary
    
    def format_json_report(self, results: TraversalAnalysisResult) -> str:
        """Format results as JSON for integration purposes."""
        try:
            json_data = {
                "analysis_type": "traversal_vulnerabilities",
                "timestamp": datetime.now().isoformat(),
                "results": results.to_dict()
            }
            
            return json.dumps(json_data, indent=2, ensure_ascii=False)
            
        except Exception as e:
            logger.error(f"Error formatting JSON report: {e}")
            return "{\"error\": \"Failed to generate JSON report\"}"
    
    def format_csv_report(self, vulnerabilities: List[TraversalVulnerability]) -> str:
        """Format vulnerabilities as CSV for spreadsheet analysis."""
        try:
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # CSV header
            writer.writerow([
                'ID', 'Title', 'Severity', 'Confidence', 'Location', 'Type',
                'Description', 'CWE', 'MASVS', 'Attack Vectors', 'Remediation'
            ])
            
            # CSV data
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln.vulnerability_id,
                    vuln.title,
                    vuln.severity,
                    vuln.confidence,
                    vuln.location,
                    vuln.traversal_type,
                    vuln.description,
                    vuln.cwe_id,
                    '; '.join(vuln.masvs_refs),
                    '; '.join(vuln.attack_vectors),
                    vuln.remediation
                ])
            
            return output.getvalue()
            
        except Exception as e:
            logger.error(f"Error formatting CSV report: {e}")
            return "Error generating CSV report"
    
    def format_error_report(self, error_message: str) -> Text:
        """Format error report with troubleshooting guidance."""
        report = Text()
        report.append("❌ TRAVERSAL VULNERABILITY ANALYSIS ERROR\n", style="bold red")
        report.append("-" * 45 + "\n\n", style="red")
        
        report.append(f"Error: {error_message}\n\n", style="red")
        
        report.append("Troubleshooting:\n", style="bold yellow")
        report.append("1. Check APK file accessibility and format\n", style="yellow")
        report.append("2. Verify manifest file is properly formatted\n", style="yellow")
        report.append("3. Ensure sufficient permissions for file access\n", style="yellow")
        report.append("4. Check system resources and memory availability\n", style="yellow")
        report.append("5. Review log files for detailed error information\n", style="yellow")
        
        return report
    
    def _count_vulnerabilities_by_severity(self, vulnerabilities: List[TraversalVulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by severity level."""
        counts = {
            SeverityLevel.CRITICAL.value: 0,
            SeverityLevel.HIGH.value: 0,
            SeverityLevel.MEDIUM.value: 0,
            SeverityLevel.LOW.value: 0,
            SeverityLevel.INFO.value: 0
        }
        
        for vuln in vulnerabilities:
            if vuln.severity in counts:
                counts[vuln.severity] += 1
        
        return counts
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level display."""
        risk_colors = {
            RiskLevel.CRITICAL.value: "red",
            RiskLevel.HIGH.value: "bright_red",
            RiskLevel.MEDIUM.value: "yellow",
            RiskLevel.LOW.value: "green",
            RiskLevel.MINIMAL.value: "bright_green"
        }
        
        return risk_colors.get(risk_level.lower(), "white")
    
    def create_vulnerability_table(self, vulnerabilities: List[TraversalVulnerability]) -> Table:
        """Create a rich table for vulnerability display."""
        table = Table(title="Traversal Vulnerabilities", show_header=True, header_style="bold blue")
        
        table.add_column("ID", style="dim", width=8)
        table.add_column("Title", style="bold", width=30)
        table.add_column("Severity", justify="center", width=10)
        table.add_column("Confidence", justify="center", width=10)
        table.add_column("Location", style="blue", width=25)
        table.add_column("Type", style="green", width=15)
        
        for vuln in vulnerabilities:
            severity_color = self.severity_colors.get(vuln.severity, "white")
            confidence_str = f"{vuln.confidence:.2f}"
            
            table.add_row(
                vuln.vulnerability_id[:8],
                vuln.title,
                f"[{severity_color}]{vuln.severity.upper()}[/{severity_color}]",
                confidence_str,
                vuln.location,
                vuln.traversal_type
            )
        
        return table 