"""
External Service Analysis Formatters

Formatting utilities for external service analysis results and reports.
"""

from typing import Dict, List, Any
import json
from datetime import datetime
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.console import Console

from .data_structures import (
    ExternalServiceAnalysisResult, ServiceEndpoint, ExternalServiceVulnerability,
    CredentialExposure, NetworkSecurityIssue, ConfigurationIssue,
    ServiceType, SeverityLevel, RiskAssessment
)

class ExternalServiceFormatter:
    """Formats external service analysis results for output."""
    
    def __init__(self):
        """Initialize formatter."""
        self.timestamp = datetime.now().isoformat()
        self.console = Console()
    
    def format_analysis_results(self, result: ExternalServiceAnalysisResult) -> Text:
        """
        Format complete analysis results for Rich display.
        
        Args:
            result: External service analysis results
            
        Returns:
            Rich Text object with formatted results
        """
        output = Text()
        
        # Header
        output.append("🔍 External Service Analysis Report\n", style="bold blue")
        output.append(f"Package: {result.package_name}\n", style="cyan")
        output.append(f"Analysis Date: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n", style="dim")
        output.append(f"Duration: {result.analysis_duration:.2f}s\n", style="dim")
        output.append(f"Files Analyzed: {result.files_analyzed}\n\n", style="dim")
        
        # Executive Summary
        output.append("📊 Executive Summary\n", style="bold yellow")
        output.append(f"Overall Risk Level: ", style="white")
        risk_color = self._get_risk_color(result.risk_assessment.risk_level)
        output.append(f"{result.risk_assessment.risk_level}\n", style=f"bold {risk_color}")
        output.append(f"Total Findings: {result.total_findings}\n", style="white")
        output.append(f"Services Detected: {len(result.detected_services)}\n", style="white")
        output.append(f"Risk Score: {result.risk_assessment.risk_score}\n\n", style="white")
        
        # Severity Breakdown
        if result.total_findings > 0:
            output.append("🎯 Findings by Severity\n", style="bold yellow")
            severity_counts = result.get_total_issues_by_severity()
            
            if severity_counts["critical"] > 0:
                output.append(f"Critical: {severity_counts['critical']}\n", style="bold red")
            if severity_counts["high"] > 0:
                output.append(f"High: {severity_counts['high']}\n", style="red")
            if severity_counts["medium"] > 0:
                output.append(f"Medium: {severity_counts['medium']}\n", style="yellow")
            if severity_counts["low"] > 0:
                output.append(f"Low: {severity_counts['low']}\n", style="green")
            output.append("\n")
        
        # Detected Services
        if result.detected_services:
            output.append("🌐 Detected External Services\n", style="bold yellow")
            service_summary = result.get_service_summary()
            
            for service_type, count in service_summary["service_breakdown"].items():
                output.append(f"• {service_type.replace('_', ' ').title()}: {count}\n", style="cyan")
            output.append("\n")
        
        # Vulnerabilities
        if result.vulnerabilities:
            output.append("🚨 Security Vulnerabilities\n", style="bold red")
            for vuln in result.vulnerabilities[:10]:  # Show top 10
                severity_color = self._get_severity_color(vuln.severity)
                output.append(f"• [{vuln.severity.value.upper()}] ", style=f"bold {severity_color}")
                output.append(f"{vuln.title}\n", style="white")
                output.append(f"  Location: {vuln.location}\n", style="dim")
                output.append(f"  Confidence: {vuln.confidence:.2f}\n", style="dim")
            
            if len(result.vulnerabilities) > 10:
                output.append(f"... and {len(result.vulnerabilities) - 10} more vulnerabilities\n", style="dim")
            output.append("\n")
        
        # Credential Exposures
        if result.credential_exposures:
            output.append("🔑 Credential Exposures\n", style="bold red")
            for cred in result.credential_exposures[:5]:  # Show top 5
                output.append(f"• {cred.credential_type.value.replace('_', ' ').title()}\n", style="red")
                output.append(f"  Location: {cred.location}\n", style="dim")
                output.append(f"  Value: {cred.value}\n", style="dim")
                output.append(f"  Confidence: {cred.confidence:.2f}\n", style="dim")
            
            if len(result.credential_exposures) > 5:
                output.append(f"... and {len(result.credential_exposures) - 5} more exposures\n", style="dim")
            output.append("\n")
        
        # Network Security Issues
        if result.network_security_issues:
            output.append("🔒 Network Security Issues\n", style="bold orange3")
            for issue in result.network_security_issues[:5]:  # Show top 5
                severity_color = self._get_severity_color(issue.severity)
                output.append(f"• [{issue.severity.value.upper()}] ", style=f"bold {severity_color}")
                output.append(f"{issue.issue_type.replace('_', ' ').title()}\n", style="white")
                output.append(f"  Description: {issue.description}\n", style="dim")
                output.append(f"  Confidence: {issue.confidence:.2f}\n", style="dim")
            
            if len(result.network_security_issues) > 5:
                output.append(f"... and {len(result.network_security_issues) - 5} more issues\n", style="dim")
            output.append("\n")
        
        # MASVS Controls
        if result.masvs_controls:
            output.append("📋 MASVS Controls\n", style="bold blue")
            for control in result.masvs_controls:
                output.append(f"• {control}\n", style="cyan")
            output.append("\n")
        
        # Recommendations
        if result.risk_assessment.recommendations:
            output.append("💡 Security Recommendations\n", style="bold green")
            for i, rec in enumerate(result.risk_assessment.recommendations[:5], 1):
                output.append(f"{i}. {rec}\n", style="green")
            
            if len(result.risk_assessment.recommendations) > 5:
                output.append(f"... and {len(result.risk_assessment.recommendations) - 5} more recommendations\n", style="dim")
            output.append("\n")
        
        # Footer
        output.append("=" * 60 + "\n", style="dim")
        output.append("External Service Analysis Complete\n", style="bold green")
        
        return output
    
    def format_analysis_result_json(self, result: ExternalServiceAnalysisResult) -> Dict[str, Any]:
        """Format complete analysis result as JSON-serializable dictionary."""
        return {
            'timestamp': result.timestamp.isoformat(),
            'package_name': result.package_name,
            'analysis_duration': result.analysis_duration,
            'files_analyzed': result.files_analyzed,
            'total_findings': result.total_findings,
            'summary': self._format_summary(result),
            'detected_services': self._format_services(result.detected_services),
            'vulnerabilities': self._format_vulnerabilities(result.vulnerabilities),
            'credential_exposures': self._format_credential_exposures(result.credential_exposures),
            'network_security_issues': self._format_network_issues(result.network_security_issues),
            'configuration_issues': self._format_configuration_issues(result.configuration_issues),
            'service_permissions': self._format_service_permissions(result.service_permissions),
            'risk_assessment': self._format_risk_assessment(result.risk_assessment),
            'masvs_controls': result.masvs_controls
        }
    
    def _format_summary(self, result: ExternalServiceAnalysisResult) -> Dict[str, Any]:
        """Format analysis summary."""
        service_summary = result.get_service_summary()
        severity_counts = result.get_total_issues_by_severity()
        
        return {
            'total_findings': result.total_findings,
            'detected_services': {
                'total': service_summary["total_services"],
                'types': service_summary["service_types"],
                'breakdown': service_summary["service_breakdown"]
            },
            'severity_breakdown': severity_counts,
            'risk_level': result.risk_assessment.risk_level,
            'risk_score': result.risk_assessment.risk_score
        }
    
    def _format_services(self, services: List[ServiceEndpoint]) -> List[Dict[str, Any]]:
        """Format detected services."""
        return [
            {
                'url': service.url,
                'service_type': service.service_type.value,
                'method': service.method,
                'authentication': service.authentication,
                'encryption': service.encryption,
                'location': service.location,
                'confidence': service.confidence
            }
            for service in services
        ]
    
    def _format_vulnerabilities(self, vulnerabilities: List[ExternalServiceVulnerability]) -> List[Dict[str, Any]]:
        """Format vulnerabilities."""
        return [
            {
                'id': vuln.vulnerability_id,
                'title': vuln.title,
                'description': vuln.description,
                'severity': vuln.severity.value,
                'service_type': vuln.service_type.value,
                'location': vuln.location,
                'evidence': vuln.evidence,
                'recommendations': vuln.recommendations,
                'cwe': vuln.cwe,
                'masvs_control': vuln.masvs_control,
                'confidence': vuln.confidence,
                'timestamp': vuln.timestamp.isoformat()
            }
            for vuln in vulnerabilities
        ]
    
    def _format_credential_exposures(self, exposures: List[CredentialExposure]) -> List[Dict[str, Any]]:
        """Format credential exposures."""
        return [
            {
                'credential_type': cred.credential_type.value,
                'value': cred.value,  # Already obfuscated
                'location': cred.location,
                'file_path': cred.file_path,
                'line_number': cred.line_number,
                'context': cred.context[:200] if cred.context else "",  # Limit context
                'severity': cred.severity.value,
                'confidence': cred.confidence
            }
            for cred in exposures
        ]
    
    def _format_network_issues(self, issues: List[NetworkSecurityIssue]) -> List[Dict[str, Any]]:
        """Format network security issues."""
        return [
            {
                'issue_type': issue.issue_type,
                'description': issue.description,
                'endpoint': issue.endpoint,
                'severity': issue.severity.value,
                'recommendation': issue.recommendation,
                'cwe': issue.cwe,
                'masvs_control': issue.masvs_control,
                'confidence': issue.confidence
            }
            for issue in issues
        ]
    
    def _format_configuration_issues(self, issues: List[ConfigurationIssue]) -> List[Dict[str, Any]]:
        """Format configuration issues."""
        return [
            {
                'config_type': issue.config_type,
                'file_path': issue.file_path,
                'description': issue.issue_description,
                'severity': issue.severity.value,
                'recommendation': issue.recommendation,
                'line_number': issue.line_number,
                'context': issue.context,
                'confidence': issue.confidence
            }
            for issue in issues
        ]
    
    def _format_service_permissions(self, permissions) -> List[Dict[str, Any]]:
        """Format service permissions."""
        return [
            {
                'permission': perm.permission_name,
                'service_type': perm.service_type.value,
                'description': perm.description,
                'risk_level': perm.risk_level.value,
                'justification': perm.justification,
                'location': perm.manifest_location
            }
            for perm in permissions
        ]
    
    def _format_risk_assessment(self, assessment: RiskAssessment) -> Dict[str, Any]:
        """Format risk assessment."""
        return {
            'risk_score': assessment.risk_score,
            'risk_level': assessment.risk_level,
            'issue_counts': {
                'critical': assessment.critical_issues,
                'high': assessment.high_issues,
                'medium': assessment.medium_issues,
                'low': assessment.low_issues
            },
            'recommendations': assessment.recommendations,
            'masvs_controls': assessment.masvs_controls
        }
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level."""
        colors = {
            'CRITICAL': 'red',
            'HIGH': 'red',
            'MEDIUM': 'yellow',
            'LOW': 'green'
        }
        return colors.get(risk_level, 'white')
    
    def _get_severity_color(self, severity: SeverityLevel) -> str:
        """Get color for severity level."""
        colors = {
            SeverityLevel.CRITICAL: 'red',
            SeverityLevel.HIGH: 'red',
            SeverityLevel.MEDIUM: 'yellow',
            SeverityLevel.LOW: 'green',
            SeverityLevel.INFO: 'blue'
        }
        return colors.get(severity, 'white')
    
    def create_vulnerability_table(self, vulnerabilities: List[ExternalServiceVulnerability]) -> Table:
        """Create a Rich table for vulnerabilities."""
        table = Table(title="External Service Vulnerabilities")
        
        table.add_column("Severity", style="bold")
        table.add_column("Title", style="cyan")
        table.add_column("Service Type")
        table.add_column("Confidence", justify="right")
        
        for vuln in vulnerabilities[:20]:  # Limit to top 20
            severity_color = self._get_severity_color(vuln.severity)
            table.add_row(
                vuln.severity.value.upper(),
                vuln.title,
                vuln.service_type.value.replace('_', ' ').title(),
                f"{vuln.confidence:.2f}",
                style=severity_color
            )
        
        return table
    
    def create_services_table(self, services: List[ServiceEndpoint]) -> Table:
        """Create a Rich table for detected services."""
        table = Table(title="Detected External Services")
        
        table.add_column("Service Type", style="cyan")
        table.add_column("URL/Endpoint")
        table.add_column("Authentication")
        table.add_column("Encryption")
        table.add_column("Confidence", justify="right")
        
        for service in services[:15]:  # Limit to top 15
            table.add_row(
                service.service_type.value.replace('_', ' ').title(),
                service.url[:60] + "..." if len(service.url) > 60 else service.url,
                service.authentication or "Unknown",
                service.encryption or "Unknown",
                f"{service.confidence:.2f}"
            )
        
        return table

def format_endpoint_summary(endpoint: ServiceEndpoint) -> str:
    """Format endpoint summary for quick display."""
    return f"{endpoint.service_type.value}: {endpoint.url}"

def format_vulnerability_summary(vulnerability: ExternalServiceVulnerability) -> str:
    """Format vulnerability summary for quick display."""
    return f"[{vulnerability.severity.value.upper()}] {vulnerability.title}" 