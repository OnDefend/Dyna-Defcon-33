"""
Formatters for Network PII Traffic Analysis.

This module provides comprehensive formatting and reporting capabilities for
PII analysis results including console output, JSON export, and detailed reports.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Union
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.layout import Layout
from rich.align import Align

from .data_structures import (
    ComprehensivePIIAnalysisResult, PIINetworkFinding, NetworkEndpoint,
    FileAnalysisResult, TransmissionRisk, PrivacyImpactAssessment,
    PIIType, SeverityLevel, TransmissionMethod, FileType,
    AnalysisCategory
)

logger = logging.getLogger(__name__)

class NetworkPIIFormatter:
    """Comprehensive formatter for PII analysis results."""
    
    def __init__(self, console: Optional[Console] = None):
        """Initialize the formatter."""
        self.console = console or Console()
        self.color_scheme = self._initialize_color_scheme()
        
        logger.info("PII analysis formatter initialized")
    
    def _initialize_color_scheme(self) -> Dict[str, str]:
        """Initialize color scheme for different severity levels and PII types."""
        return {
            # Severity colors
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "cyan",
            
            # PII type colors
            "device_identifier": "magenta",
            "location_data": "red",
            "personal_identifier": "orange3",
            "authentication_data": "bright_red",
            "biometric_data": "purple",
            "network_identifier": "blue",
            "system_identifier": "cyan",
            "behavioral_data": "yellow",
            "unknown": "white",
            
            # Status colors
            "success": "green",
            "warning": "yellow",
            "error": "red",
            "info": "blue",
            
            # Transmission method colors
            "http": "red",
            "https": "green",
            "websocket": "yellow",
            "ftp": "orange3",
            "sms": "red",
            "email": "blue",
            "unknown": "white"
        }
    
    def format_comprehensive_report(self, analysis_result: ComprehensivePIIAnalysisResult) -> str:
        """Generate comprehensive formatted report."""
        logger.info("Generating comprehensive PII analysis report")
        
        # Build report sections
        sections = []
        
        # Title and summary
        sections.append(self._format_report_header(analysis_result))
        sections.append(self._format_executive_summary(analysis_result))
        
        # Detailed findings
        if analysis_result.all_pii_findings:
            sections.append(self._format_findings_overview(analysis_result))
            sections.append(self._format_detailed_findings(analysis_result))
        
        # Network endpoints
        if analysis_result.network_endpoints:
            sections.append(self._format_network_endpoints(analysis_result))
        
        # Risk assessment
        if analysis_result.transmission_risks:
            sections.append(self._format_risk_assessment(analysis_result))
        
        # Privacy impact
        if analysis_result.privacy_impact:
            sections.append(self._format_privacy_impact(analysis_result))
        
        # Compliance analysis
        sections.append(self._format_compliance_analysis(analysis_result))
        
        # Recommendations
        sections.append(self._format_recommendations(analysis_result))
        
        return "\n\n".join(sections)
    
    def _format_report_header(self, analysis_result: ComprehensivePIIAnalysisResult) -> str:
        """Format report header with title and metadata."""
        title = Panel.fit(
            f"[bold blue]Network PII Traffic Analysis Report[/bold blue]\n"
            f"[cyan]Package: {analysis_result.package_name or 'Unknown'}[/cyan]\n"
            f"[white]Generated: {analysis_result.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S')}[/white]\n"
            f"[white]Analysis Duration: {analysis_result.analysis_duration:.2f}s[/white]",
            title="[bold white]AODS Security Analysis[/bold white]",
            border_style="blue"
        )
        
        with self.console.capture() as capture:
            self.console.print(title)
        
        return capture.get()
    
    def _format_executive_summary(self, analysis_result: ComprehensivePIIAnalysisResult) -> str:
        """Format executive summary with key metrics."""
        # Create summary table
        summary_table = Table(title="Executive Summary", border_style="cyan")
        summary_table.add_column("Metric", style="bold white")
        summary_table.add_column("Value", justify="right")
        summary_table.add_column("Status", justify="center")
        
        # Add key metrics
        risk_color = self._get_risk_color(analysis_result.overall_risk_level)
        summary_table.add_row(
            "Overall Risk Level",
            f"[{risk_color}]{analysis_result.overall_risk_level}[/{risk_color}]",
            self._get_status_icon(analysis_result.overall_risk_level)
        )
        
        summary_table.add_row(
            "Total PII Findings",
            str(analysis_result.total_findings),
            self._get_count_status(analysis_result.total_findings)
        )
        
        summary_table.add_row(
            "Critical Issues",
            str(analysis_result.critical_findings),
            self._get_count_status(analysis_result.critical_findings, is_critical=True)
        )
        
        summary_table.add_row(
            "High Risk Issues",
            str(analysis_result.high_findings),
            self._get_count_status(analysis_result.high_findings)
        )
        
        summary_table.add_row(
            "Files Analyzed",
            str(analysis_result.files_analyzed),
            "[green]PASS[/green]"
        )
        
        summary_table.add_row(
            "Network Endpoints",
            str(len(analysis_result.network_endpoints)),
            self._get_count_status(len(analysis_result.network_endpoints))
        )
        
        with self.console.capture() as capture:
            self.console.print(summary_table)
        
        return capture.get()
    
    def _format_findings_overview(self, analysis_result: ComprehensivePIIAnalysisResult) -> str:
        """Format findings overview with charts and breakdowns."""
        layout = Layout()
        
        # Severity breakdown
        severity_table = Table(title="Findings by Severity", border_style="yellow")
        severity_table.add_column("Severity", style="bold")
        severity_table.add_column("Count", justify="right")
        severity_table.add_column("Percentage", justify="right")
        
        total = analysis_result.total_findings
        if total > 0:
            severity_counts = [
                ("Critical", analysis_result.critical_findings, "critical"),
                ("High", analysis_result.high_findings, "high"),
                ("Medium", analysis_result.medium_findings, "medium"),
                ("Low", analysis_result.low_findings, "low")
            ]
            
            for severity, count, color in severity_counts:
                if count > 0:
                    percentage = (count / total) * 100
                    severity_table.add_row(
                        f"[{self.color_scheme[color]}]{severity}[/{self.color_scheme[color]}]",
                        str(count),
                        f"{percentage:.1f}%"
                    )
        
        # PII type breakdown
        pii_type_table = Table(title="Findings by PII Type", border_style="magenta")
        pii_type_table.add_column("PII Type", style="bold")
        pii_type_table.add_column("Count", justify="right")
        pii_type_table.add_column("Risk Level", justify="center")
        
        pii_type_counts = analysis_result.get_findings_by_pii_type()
        for pii_type, count in pii_type_counts.items():
            if count > 0:
                color = self.color_scheme.get(pii_type, "white")
                risk_level = self._get_pii_type_risk_level(pii_type)
                pii_type_table.add_row(
                    f"[{color}]{pii_type.replace('_', ' ').title()}[/{color}]",
                    str(count),
                    f"[{self._get_risk_color(risk_level)}]{risk_level}[/{self._get_risk_color(risk_level)}]"
                )
        
        with self.console.capture() as capture:
            self.console.print(severity_table)
            self.console.print()
            self.console.print(pii_type_table)
        
        return capture.get()
    
    def _format_detailed_findings(self, analysis_result: ComprehensivePIIAnalysisResult) -> str:
        """Format detailed findings with full information."""
        sections = []
        
        # Group findings by severity
        findings_by_severity = {}
        for finding in analysis_result.all_pii_findings:
            severity = finding.severity.value
            if severity not in findings_by_severity:
                findings_by_severity[severity] = []
            findings_by_severity[severity].append(finding)
        
        # Format each severity group
        severity_order = ["critical", "high", "medium", "low", "info"]
        for severity in severity_order:
            if severity in findings_by_severity:
                sections.append(self._format_severity_group(severity, findings_by_severity[severity]))
        
        return "\n\n".join(sections)
    
    def _format_severity_group(self, severity: str, findings: List[PIINetworkFinding]) -> str:
        """Format a group of findings by severity."""
        color = self.color_scheme[severity]
        
        # Create severity header
        header = Panel.fit(
            f"[{color}]{severity.upper()} SEVERITY FINDINGS ({len(findings)})[/{color}]",
            border_style=color
        )
        
        # Create findings table
        findings_table = Table(border_style=color, show_header=True, header_style=f"bold {color}")
        findings_table.add_column("PII Type", style="bold")
        findings_table.add_column("Location", max_width=30)
        findings_table.add_column("Evidence", max_width=40)
        findings_table.add_column("Transmission", justify="center")
        findings_table.add_column("Confidence", justify="right")
        
        for finding in findings[:10]:  # Limit to top 10 per severity
            pii_color = self.color_scheme.get(finding.pii_type.value, "white")
            trans_color = self.color_scheme.get(finding.transmission_method.value, "white")
            
            # Truncate evidence for display
            evidence = finding.evidence[:80] + "..." if len(finding.evidence) > 80 else finding.evidence
            
            findings_table.add_row(
                f"[{pii_color}]{finding.pii_type.value.replace('_', ' ').title()}[/{pii_color}]",
                finding.location,
                evidence,
                f"[{trans_color}]{finding.transmission_method.value.upper()}[/{trans_color}]",
                f"{finding.confidence:.3f}"
            )
        
        if len(findings) > 10:
            findings_table.add_row(
                f"[dim]... and {len(findings) - 10} more findings[/dim]",
                "", "", "", ""
            )
        
        with self.console.capture() as capture:
            self.console.print(header)
            self.console.print(findings_table)
        
        return capture.get()
    
    def _format_network_endpoints(self, analysis_result: ComprehensivePIIAnalysisResult) -> str:
        """Format network endpoints analysis."""
        endpoints_table = Table(title="Network Endpoints Analysis", border_style="blue")
        endpoints_table.add_column("URL", max_width=50)
        endpoints_table.add_column("Protocol", justify="center")
        endpoints_table.add_column("TLS", justify="center")
        endpoints_table.add_column("PII Parameters", justify="center")
        endpoints_table.add_column("Risk Level", justify="center")
        
        for endpoint in analysis_result.network_endpoints[:20]:  # Limit display
            protocol_color = self.color_scheme.get(endpoint.protocol.lower(), "white")
            tls_status = "[green]SECURE[/green]" if endpoint.uses_tls else "[red]INSECURE[/red]"
            pii_count = len(endpoint.pii_parameters)
            risk_color = self._get_risk_color(endpoint.risk_level)
            
            endpoints_table.add_row(
                endpoint.url[:47] + "..." if len(endpoint.url) > 50 else endpoint.url,
                f"[{protocol_color}]{endpoint.protocol}[/{protocol_color}]",
                tls_status,
                str(pii_count) if pii_count > 0 else "[dim]0[/dim]",
                f"[{risk_color}]{endpoint.risk_level}[/{risk_color}]"
            )
        
        if len(analysis_result.network_endpoints) > 20:
            endpoints_table.add_row(
                f"[dim]... and {len(analysis_result.network_endpoints) - 20} more endpoints[/dim]",
                "", "", "", ""
            )
        
        with self.console.capture() as capture:
            self.console.print(endpoints_table)
        
        return capture.get()
    
    def _format_risk_assessment(self, analysis_result: ComprehensivePIIAnalysisResult) -> str:
        """Format risk assessment section."""
        risk_table = Table(title="Risk Assessment", border_style="red")
        risk_table.add_column("PII Type", style="bold")
        risk_table.add_column("Transmission Method", justify="center")
        risk_table.add_column("Risk Level", justify="center")
        risk_table.add_column("Risk Score", justify="right")
        risk_table.add_column("Mitigation Priority", justify="center")
        
        for risk in analysis_result.transmission_risks:
            pii_color = self.color_scheme.get(risk.pii_type.value, "white")
            trans_color = self.color_scheme.get(risk.transmission_method.value, "white")
            risk_color = self._get_risk_color(risk.risk_level)
            
            priority = self._get_mitigation_priority(risk.overall_risk_score)
            priority_color = self._get_priority_color(priority)
            
            risk_table.add_row(
                f"[{pii_color}]{risk.pii_type.value.replace('_', ' ').title()}[/{pii_color}]",
                f"[{trans_color}]{risk.transmission_method.value.upper()}[/{trans_color}]",
                f"[{risk_color}]{risk.risk_level}[/{risk_color}]",
                f"{risk.overall_risk_score:.3f}",
                f"[{priority_color}]{priority}[/{priority_color}]"
            )
        
        with self.console.capture() as capture:
            self.console.print(risk_table)
        
        return capture.get()
    
    def _format_privacy_impact(self, analysis_result: ComprehensivePIIAnalysisResult) -> str:
        """Format privacy impact assessment."""
        if not analysis_result.privacy_impact:
            return ""
        
        privacy = analysis_result.privacy_impact
        
        privacy_table = Table(title="Privacy Impact Assessment", border_style="purple")
        privacy_table.add_column("Aspect", style="bold")
        privacy_table.add_column("Status", justify="center")
        privacy_table.add_column("Compliance", justify="center")
        
        privacy_table.add_row(
            "Affected Users",
            privacy.affected_users,
            self._get_compliance_status(privacy.affected_users)
        )
        
        privacy_table.add_row(
            "Data Collection Purpose",
            privacy.data_collection_purpose,
            self._get_compliance_status(privacy.data_collection_purpose)
        )
        
        privacy_table.add_row(
            "User Consent",
            privacy.user_consent,
            self._get_compliance_status(privacy.user_consent)
        )
        
        privacy_table.add_row(
            "GDPR Compliance",
            privacy.gdpr_compliance,
            self._get_compliance_status(privacy.gdpr_compliance)
        )
        
        privacy_table.add_row(
            "CCPA Compliance",
            privacy.ccpa_compliance,
            self._get_compliance_status(privacy.ccpa_compliance)
        )
        
        with self.console.capture() as capture:
            self.console.print(privacy_table)
        
        return capture.get()
    
    def _format_compliance_analysis(self, analysis_result: ComprehensivePIIAnalysisResult) -> str:
        """Format MASVS/OWASP compliance analysis."""
        compliance_table = Table(title="Security Standards Compliance", border_style="green")
        compliance_table.add_column("Standard", style="bold")
        compliance_table.add_column("Controls Affected", justify="center")
        compliance_table.add_column("Violations", justify="center")
        compliance_table.add_column("Compliance Status", justify="center")
        
        # MASVS analysis
        masvs_controls = set(analysis_result.masvs_controls)
        masvs_violations = len([v for v in analysis_result.compliance_violations if 'MASVS' in v])
        masvs_status = "PARTIAL" if masvs_violations > 0 else "COMPLIANT"
        masvs_color = "yellow" if masvs_status == "PARTIAL" else "green"
        
        compliance_table.add_row(
            "MASVS (Mobile)",
            str(len(masvs_controls)),
            str(masvs_violations),
            f"[{masvs_color}]{masvs_status}[/{masvs_color}]"
        )
        
        # OWASP analysis
        owasp_violations = len([v for v in analysis_result.compliance_violations if 'OWASP' in v])
        owasp_status = "PARTIAL" if owasp_violations > 0 else "COMPLIANT"
        owasp_color = "yellow" if owasp_status == "PARTIAL" else "green"
        
        compliance_table.add_row(
            "OWASP Top 10",
            "Multiple",
            str(owasp_violations),
            f"[{owasp_color}]{owasp_status}[/{owasp_color}]"
        )
        
        with self.console.capture() as capture:
            self.console.print(compliance_table)
        
        return capture.get()
    
    def _format_recommendations(self, analysis_result: ComprehensivePIIAnalysisResult) -> str:
        """Format security recommendations."""
        if not analysis_result.recommendations:
            return ""
        
        recommendations_panel = Panel(
            "\n".join([f"• {rec}" for rec in analysis_result.recommendations[:10]]),
            title="[bold green]Security Recommendations[/bold green]",
            border_style="green"
        )
        
        with self.console.capture() as capture:
            self.console.print(recommendations_panel)
        
        return capture.get()
    
    def export_json_report(self, analysis_result: ComprehensivePIIAnalysisResult, 
                           output_path: Optional[str] = None) -> str:
        """Export analysis results to JSON format."""
        logger.info("Exporting PII analysis results to JSON")
        
        # Create JSON-serializable data structure
        json_data = self._convert_to_json_serializable(analysis_result)
        
        # Generate JSON string
        json_output = json.dumps(json_data, indent=2, default=str)
        
        # Save to file if path provided
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(json_output)
            
            logger.info(f"JSON report saved to {output_path}")
        
        return json_output
    
    def _convert_to_json_serializable(self, analysis_result: ComprehensivePIIAnalysisResult) -> Dict[str, Any]:
        """Convert analysis result to JSON-serializable dictionary."""
        return {
            "analysis_metadata": {
                "package_name": analysis_result.package_name,
                "analysis_timestamp": analysis_result.analysis_timestamp.isoformat(),
                "analysis_duration": analysis_result.analysis_duration,
                "files_analyzed": analysis_result.files_analyzed,
                "total_findings": analysis_result.total_findings
            },
            "summary_statistics": {
                "critical_findings": analysis_result.critical_findings,
                "high_findings": analysis_result.high_findings,
                "medium_findings": analysis_result.medium_findings,
                "low_findings": analysis_result.low_findings,
                "overall_risk_level": analysis_result.overall_risk_level,
                "risk_score": analysis_result.risk_score,
                "privacy_risk_percentage": analysis_result.privacy_risk_percentage
            },
            "findings_by_type": analysis_result.get_findings_by_pii_type(),
            "findings_by_transmission": analysis_result.get_findings_by_transmission_method(),
            "detailed_findings": [
                self._convert_finding_to_dict(finding) 
                for finding in analysis_result.all_pii_findings
            ],
            "network_endpoints": [
                self._convert_endpoint_to_dict(endpoint)
                for endpoint in analysis_result.network_endpoints
            ],
            "transmission_risks": [
                self._convert_risk_to_dict(risk)
                for risk in analysis_result.transmission_risks
            ],
            "privacy_impact": self._convert_privacy_impact_to_dict(analysis_result.privacy_impact),
            "compliance": {
                "masvs_controls": analysis_result.masvs_controls,
                "compliance_violations": analysis_result.compliance_violations,
                "recommendations": analysis_result.recommendations
            },
            "file_results": [
                self._convert_file_result_to_dict(file_result)
                for file_result in analysis_result.file_results
            ]
        }
    
    def _convert_finding_to_dict(self, finding: PIINetworkFinding) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "finding_id": finding.finding_id,
            "pii_type": finding.pii_type.value,
            "transmission_method": finding.transmission_method.value,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "description": finding.description,
            "location": finding.location,
            "evidence": finding.evidence,
            "pattern_matched": finding.pattern_matched,
            "matched_value": finding.matched_value,
            "attack_vectors": finding.attack_vectors,
            "privacy_impact": finding.privacy_impact,
            "remediation": finding.remediation,
            "masvs_control": finding.masvs_control,
            "mstg_reference": finding.mstg_reference,
            "timestamp": finding.timestamp.isoformat(),
            "risk_score": finding.get_risk_score()
        }
    
    def _convert_endpoint_to_dict(self, endpoint: NetworkEndpoint) -> Dict[str, Any]:
        """Convert network endpoint to dictionary."""
        return {
            "url": endpoint.url,
            "method": endpoint.method,
            "protocol": endpoint.protocol,
            "uses_tls": endpoint.uses_tls,
            "certificate_pinning": endpoint.certificate_pinning,
            "data_encryption": endpoint.data_encryption,
            "parameters": endpoint.parameters,
            "headers": endpoint.headers,
            "pii_parameters": list(endpoint.pii_parameters),
            "risk_level": endpoint.risk_level
        }
    
    def _convert_risk_to_dict(self, risk: TransmissionRisk) -> Dict[str, Any]:
        """Convert transmission risk to dictionary."""
        return {
            "pii_type": risk.pii_type.value,
            "transmission_method": risk.transmission_method.value,
            "risk_level": risk.risk_level,
            "risk_factors": risk.risk_factors,
            "mitigation_strategies": risk.mitigation_strategies,
            "exposure_likelihood": risk.exposure_likelihood,
            "impact_severity": risk.impact_severity,
            "detection_difficulty": risk.detection_difficulty,
            "overall_risk_score": risk.overall_risk_score
        }
    
    def _convert_privacy_impact_to_dict(self, privacy_impact: Optional[PrivacyImpactAssessment]) -> Optional[Dict[str, Any]]:
        """Convert privacy impact assessment to dictionary."""
        if not privacy_impact:
            return None
        
        return {
            "affected_users": privacy_impact.affected_users,
            "data_collection_purpose": privacy_impact.data_collection_purpose,
            "data_retention_period": privacy_impact.data_retention_period,
            "data_sharing": privacy_impact.data_sharing,
            "user_consent": privacy_impact.user_consent,
            "gdpr_compliance": privacy_impact.gdpr_compliance,
            "ccpa_compliance": privacy_impact.ccpa_compliance,
            "coppa_compliance": privacy_impact.coppa_compliance,
            "privacy_risks": privacy_impact.privacy_risks,
            "recommended_actions": privacy_impact.recommended_actions
        }
    
    def _convert_file_result_to_dict(self, file_result: FileAnalysisResult) -> Dict[str, Any]:
        """Convert file analysis result to dictionary."""
        return {
            "file_path": file_result.file_path,
            "file_type": file_result.file_type.value,
            "analysis_successful": file_result.analysis_successful,
            "error_message": file_result.error_message,
            "analysis_duration": file_result.analysis_duration,
            "patterns_checked": file_result.patterns_checked,
            "content_size": file_result.content_size,
            "lines_analyzed": file_result.lines_analyzed,
            "findings_count": len(file_result.pii_findings),
            "endpoints_count": len(file_result.network_endpoints),
            "findings_by_severity": file_result.get_findings_by_severity(),
            "findings_by_pii_type": file_result.get_findings_by_pii_type()
        }
    
    def create_summary_table(self, analysis_result: ComprehensivePIIAnalysisResult) -> Table:
        """Create a summary table for quick display."""
        table = Table(title="PII Analysis Summary", border_style="blue")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")
        
        table.add_row("Package", analysis_result.package_name or "Unknown")
        table.add_row("Total Findings", str(analysis_result.total_findings))
        table.add_row("Critical", f"[red]{analysis_result.critical_findings}[/red]")
        table.add_row("High", f"[orange3]{analysis_result.high_findings}[/orange3]")
        table.add_row("Medium", f"[yellow]{analysis_result.medium_findings}[/yellow]")
        table.add_row("Low", f"[blue]{analysis_result.low_findings}[/blue]")
        table.add_row("Risk Level", f"[{self._get_risk_color(analysis_result.overall_risk_level)}]{analysis_result.overall_risk_level}[/{self._get_risk_color(analysis_result.overall_risk_level)}]")
        table.add_row("Risk Score", f"{analysis_result.risk_score:.3f}")
        
        return table
    
    def print_progress_update(self, message: str, status: str = "info") -> None:
        """Print a progress update message."""
        color = self.color_scheme.get(status, "white")
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"[dim]{timestamp}[/dim] [{color}]{message}[/{color}]")
    
    def print_finding_alert(self, finding: PIINetworkFinding) -> None:
        """Print an alert for a high-priority finding."""
        if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            color = self.color_scheme[finding.severity.value]
            self.console.print(
                f"[{color}]ALERT: "
                f"{finding.pii_type.value.replace('_', ' ').title()} detected "
                f"in {finding.location}[/{color}]"
            )
    
    # Helper methods for formatting
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level."""
        risk_colors = {
            "CRITICAL": "bright_red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "cyan"
        }
        return risk_colors.get(risk_level.upper(), "white")
    
    def _get_status_icon(self, risk_level: str) -> str:
        """Get status icon for risk level."""
        if risk_level.upper() in ["CRITICAL", "HIGH"]:
            return "[red]HIGH[/red]"
        elif risk_level.upper() == "MEDIUM":
            return "[yellow]MED[/yellow]"
        else:
            return "[green]OK[/green]"
    
    def _get_count_status(self, count: int, is_critical: bool = False) -> str:
        """Get status icon for count."""
        if is_critical:
            return "[red]ALERT[/red]" if count > 0 else "[green]PASS[/green]"
        else:
            return "[yellow]WARN[/yellow]" if count > 0 else "[green]PASS[/green]"
    
    def _get_pii_type_risk_level(self, pii_type: str) -> str:
        """Get risk level for PII type."""
        high_risk_types = ["authentication_data", "biometric_data", "personal_identifier"]
        medium_risk_types = ["device_identifier", "location_data", "behavioral_data"]
        
        if pii_type in high_risk_types:
            return "HIGH"
        elif pii_type in medium_risk_types:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_mitigation_priority(self, risk_score: float) -> str:
        """Get mitigation priority based on risk score."""
        if risk_score >= 0.8:
            return "URGENT"
        elif risk_score >= 0.6:
            return "HIGH"
        elif risk_score >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_priority_color(self, priority: str) -> str:
        """Get color for priority level."""
        priority_colors = {
            "URGENT": "bright_red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue"
        }
        return priority_colors.get(priority, "white")
    
    def _get_compliance_status(self, status: str) -> str:
        """Get compliance status with color."""
        if "COMPLIANT" in status.upper():
            return "[green]PASS[/green]"
        elif "NON_COMPLIANT" in status.upper():
            return "[red]FAIL[/red]"
        elif "UNKNOWN" in status.upper():
            return "[yellow]UNKNOWN[/yellow]"
        else:
            return "[dim]—[/dim]"

class PIIReportGenerator:
    """Generator for detailed PII analysis reports."""
    
    def __init__(self, formatter: Optional[NetworkPIIFormatter] = None):
        """Initialize the report generator."""
        self.formatter = formatter or NetworkPIIFormatter()
        
    def generate_executive_report(self, analysis_result: ComprehensivePIIAnalysisResult) -> str:
        """Generate executive summary report."""
        sections = [
            "# Executive Summary - PII Analysis Report",
            f"**Package:** {analysis_result.package_name or 'Unknown'}",
            f"**Analysis Date:** {analysis_result.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Overall Risk Level:** {analysis_result.overall_risk_level}",
            "",
            "## Key Findings",
            f"- **Total PII Issues:** {analysis_result.total_findings}",
            f"- **Critical Issues:** {analysis_result.critical_findings}",
            f"- **High Risk Issues:** {analysis_result.high_findings}",
            f"- **Network Endpoints:** {len(analysis_result.network_endpoints)}",
            "",
            "## Privacy Concerns",
        ]
        
        concerns = analysis_result.get_privacy_concerns()
        if concerns:
            sections.extend([f"- {concern}" for concern in concerns])
        else:
            sections.append("- No major privacy concerns identified")
        
        sections.extend([
            "",
            "## Immediate Actions Required",
        ])
        
        urgent_recommendations = analysis_result.recommendations[:5] if analysis_result.recommendations else []
        if urgent_recommendations:
            sections.extend([f"1. {rec}" for rec in urgent_recommendations])
        else:
            sections.append("1. Review findings and implement security measures")
        
        return "\n".join(sections)
    
    def generate_technical_report(self, analysis_result: ComprehensivePIIAnalysisResult) -> str:
        """Generate detailed technical report."""
        return self.formatter.format_comprehensive_report(analysis_result)
    
    def generate_compliance_report(self, analysis_result: ComprehensivePIIAnalysisResult) -> str:
        """Generate compliance-focused report."""
        sections = [
            "# Compliance Analysis Report",
            f"**Package:** {analysis_result.package_name or 'Unknown'}",
            f"**Analysis Date:** {analysis_result.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## MASVS Compliance",
            f"**Controls Covered:** {', '.join(analysis_result.masvs_controls) if analysis_result.masvs_controls else 'None'}",
            "",
            "## Privacy Regulations",
        ]
        
        if analysis_result.privacy_impact:
            privacy = analysis_result.privacy_impact
            sections.extend([
                f"- **GDPR Compliance:** {privacy.gdpr_compliance}",
                f"- **CCPA Compliance:** {privacy.ccpa_compliance}",
                f"- **COPPA Compliance:** {privacy.coppa_compliance}",
                "",
                "## Data Protection Measures",
                f"- **User Consent:** {privacy.user_consent}",
                f"- **Data Purpose:** {privacy.data_collection_purpose}",
                f"- **Data Retention:** {privacy.data_retention_period}",
            ])
        
        sections.extend([
            "",
            "## Violations",
        ])
        
        if analysis_result.compliance_violations:
            sections.extend([f"- {violation}" for violation in analysis_result.compliance_violations])
        else:
            sections.append("- No compliance violations identified")
        
        return "\n".join(sections)

# Utility functions
def format_pii_analysis_results(analysis_result: ComprehensivePIIAnalysisResult, 
                                output_format: str = "console") -> str:
    """Format PII analysis results in specified format."""
    formatter = NetworkPIIFormatter()
    
    if output_format.lower() == "json":
        return formatter.export_json_report(analysis_result)
    elif output_format.lower() == "console":
        return formatter.format_comprehensive_report(analysis_result)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")

def export_pii_analysis_json(analysis_result: ComprehensivePIIAnalysisResult, 
                             output_path: str) -> None:
    """Export PII analysis results to JSON file."""
    formatter = NetworkPIIFormatter()
    formatter.export_json_report(analysis_result, output_path)

def create_pii_summary_table(analysis_result: ComprehensivePIIAnalysisResult) -> Table:
    """Create summary table for PII analysis results."""
    formatter = NetworkPIIFormatter()
    return formatter.create_summary_table(analysis_result) 

# Backward compatibility alias
PIIAnalysisFormatter = NetworkPIIFormatter 