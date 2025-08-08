"""
Professional Formatters for Enhanced Encoding and Cloud Analysis

This module provides comprehensive formatting capabilities for encoding and cloud
analysis results using Rich library for beautiful console output and JSON export
for integration with other tools.
"""

import json
import logging
from typing import List, Dict, Any, Optional, Union
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.progress import Progress
from rich import box

from .data_structures import (
    ComprehensiveAnalysisResult, EncodingFinding, CipherFinding, CloudServiceFinding,
    EncodingChain, SecurityPattern, FileAnalysisResult, EncodingType, CipherType,
    CloudServiceType, SeverityLevel, FileType, AnalysisPattern
)

logger = logging.getLogger(__name__)

class SeverityColorMapping:
    """Color mapping for different severity levels."""
    
    COLORS = {
        SeverityLevel.CRITICAL: "bright_red",
        SeverityLevel.HIGH: "red",
        SeverityLevel.MEDIUM: "yellow",
        SeverityLevel.LOW: "blue",
        SeverityLevel.INFO: "cyan"
    }
    
    @classmethod
    def get_color(cls, severity: SeverityLevel) -> str:
        """Get color for severity level."""
        return cls.COLORS.get(severity, "white")
    
    @classmethod
    def get_severity_badge(cls, severity: SeverityLevel) -> Text:
        """Get colored severity badge."""
        color = cls.get_color(severity)
        return Text(f"[{severity.value.upper()}]", style=f"bold {color}")

class EnhancedEncodingCloudFormatter:
    """formatter for enhanced encoding and cloud analysis results."""
    
    def __init__(self, console: Optional[Console] = None):
        """Initialize the formatter."""
        self.console = console or Console()
        self.severity_colors = SeverityColorMapping()
    
    def format_comprehensive_report(self, result: ComprehensiveAnalysisResult) -> Text:
        """
        Format comprehensive analysis result into a professional report.
        
        Args:
            result: ComprehensiveAnalysisResult to format
            
        Returns:
            Rich Text object with formatted report
        """
        report = Text()
        
        # Title and header
        self._add_report_header(report, result)
        
        # Executive summary
        self._add_executive_summary(report, result)
        
        # Detailed findings sections
        if result.all_encoding_findings:
            self._add_encoding_findings_section(report, result.all_encoding_findings)
        
        if result.all_cipher_findings:
            self._add_cipher_findings_section(report, result.all_cipher_findings)
        
        if result.all_cloud_findings:
            self._add_cloud_findings_section(report, result.all_cloud_findings)
        
        if result.encoding_chains:
            self._add_encoding_chains_section(report, result.encoding_chains)
        
        if result.security_patterns:
            self._add_security_patterns_section(report, result.security_patterns)
        
        # Analysis summary and recommendations
        self._add_analysis_summary(report, result)
        self._add_recommendations_section(report, result)
        
        return report
    
    def format_findings_table(self, findings: List[Union[EncodingFinding, CipherFinding, CloudServiceFinding]]) -> Table:
        """
        Format findings into a comprehensive table.
        
        Args:
            findings: List of findings to format
            
        Returns:
            Rich Table with findings
        """
        table = Table(
            title="Security Findings Summary",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan"
        )
        
        # Add columns
        table.add_column("ID", style="dim", width=12)
        table.add_column("Type", width=15)
        table.add_column("Severity", width=10)
        table.add_column("Location", width=20)
        table.add_column("Description", width=40)
        table.add_column("Confidence", width=10)
        
        # Add findings
        for finding in findings:
            finding_type = self._get_finding_type(finding)
            severity_badge = self.severity_colors.get_severity_badge(finding.severity)
            confidence_text = Text(f"{finding.confidence:.2f}", style="bold green" if finding.confidence > 0.8 else "yellow")
            
            table.add_row(
                finding.finding_id[:12],
                finding_type,
                severity_badge,
                finding.location[:20],
                finding.description[:40],
                confidence_text
            )
        
        return table
    
    def format_file_analysis_summary(self, file_results: List[FileAnalysisResult]) -> Table:
        """
        Format file analysis results into a summary table.
        
        Args:
            file_results: List of file analysis results
            
        Returns:
            Rich Table with file analysis summary
        """
        table = Table(
            title="File Analysis Summary",
            box=box.SIMPLE,
            show_header=True,
            header_style="bold blue"
        )
        
        # Add columns
        table.add_column("File", width=30)
        table.add_column("Type", width=15)
        table.add_column("Size", width=10)
        table.add_column("Findings", width=10)
        table.add_column("Status", width=15)
        
        # Add file results
        for file_result in file_results:
            file_name = file_result.file_path.split('/')[-1] if '/' in file_result.file_path else file_result.file_path
            total_findings = file_result.get_total_findings()
            
            status_style = "green" if file_result.analysis_successful else "red"
            status_text = Text("Success" if file_result.analysis_successful else "Failed", style=status_style)
            
            findings_text = Text(str(total_findings), style="bold yellow" if total_findings > 0 else "dim")
            
            table.add_row(
                file_name[:30],
                file_result.file_type.value,
                f"{file_result.content_size:,}",
                findings_text,
                status_text
            )
        
        return table
    
    def format_encoding_chains_table(self, chains: List[EncodingChain]) -> Table:
        """
        Format encoding chains into a detailed table.
        
        Args:
            chains: List of encoding chains
            
        Returns:
            Rich Table with encoding chains
        """
        table = Table(
            title="Multi-Layer Encoding Chains",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta"
        )
        
        # Add columns
        table.add_column("Chain ID", width=12)
        table.add_column("Layers", width=25)
        table.add_column("Complexity", width=12)
        table.add_column("Confidence", width=12)
        table.add_column("Final Content", width=30)
        
        # Add chains
        for chain in chains:
            layers_text = " → ".join(layer.value for layer in chain.encoding_layers)
            complexity_text = Text(f"{chain.complexity_score:.2f}", style="yellow")
            confidence_text = Text(f"{chain.detection_confidence:.2f}", style="green")
            final_content = chain.final_decoded_content[:30] + "..." if len(chain.final_decoded_content) > 30 else chain.final_decoded_content
            
            table.add_row(
                chain.chain_id,
                layers_text,
                complexity_text,
                confidence_text,
                final_content
            )
        
        return table
    
    def format_security_patterns_table(self, patterns: List[SecurityPattern]) -> Table:
        """
        Format security patterns into a table.
        
        Args:
            patterns: List of security patterns
            
        Returns:
            Rich Table with security patterns
        """
        table = Table(
            title="Security Patterns Detected",
            box=box.DOUBLE,
            show_header=True,
            header_style="bold red"
        )
        
        # Add columns
        table.add_column("Pattern", width=20)
        table.add_column("Type", width=15)
        table.add_column("Severity", width=10)
        table.add_column("Confidence", width=12)
        table.add_column("Impact", width=35)
        
        # Add patterns
        for pattern in patterns:
            severity_badge = self.severity_colors.get_severity_badge(pattern.severity)
            confidence_text = Text(f"{pattern.confidence:.2f}", style="bold green" if pattern.confidence > 0.8 else "yellow")
            
            table.add_row(
                pattern.pattern_name,
                pattern.pattern_type.value,
                severity_badge,
                confidence_text,
                pattern.impact_assessment[:35]
            )
        
        return table
    
    def generate_console_output(self, result: ComprehensiveAnalysisResult) -> None:
        """
        Generate complete console output for analysis results.
        
        Args:
            result: ComprehensiveAnalysisResult to display
        """
        # Main report panel
        report_text = self.format_comprehensive_report(result)
        main_panel = Panel(
            report_text,
            title="Enhanced Encoding & Cloud Analysis Report",
            border_style="blue",
            padding=(1, 2)
        )
        
        self.console.print(main_panel)
        self.console.print()
        
        # Summary tables
        if result.file_results:
            file_table = self.format_file_analysis_summary(result.file_results)
            self.console.print(file_table)
            self.console.print()
        
        # Findings table
        all_findings = result.all_encoding_findings + result.all_cipher_findings + result.all_cloud_findings
        if all_findings:
            findings_table = self.format_findings_table(all_findings)
            self.console.print(findings_table)
            self.console.print()
        
        # Encoding chains table
        if result.encoding_chains:
            chains_table = self.format_encoding_chains_table(result.encoding_chains)
            self.console.print(chains_table)
            self.console.print()
        
        # Security patterns table
        if result.security_patterns:
            patterns_table = self.format_security_patterns_table(result.security_patterns)
            self.console.print(patterns_table)
    
    def export_to_json(self, result: ComprehensiveAnalysisResult, 
                      include_metadata: bool = True) -> str:
        """
        Export analysis results to JSON format.
        
        Args:
            result: ComprehensiveAnalysisResult to export
            include_metadata: Whether to include metadata in export
            
        Returns:
            JSON string with analysis results
        """
        export_data = {}
        
        # Basic information
        export_data['analysis_info'] = {
            'package_name': result.package_name,
            'analysis_timestamp': result.analysis_timestamp.isoformat(),
            'analysis_duration': result.analysis_duration,
            'files_analyzed': result.files_analyzed,
            'total_findings': result.total_findings
        }
        
        # Risk assessment
        export_data['risk_assessment'] = {
            'risk_score': result.risk_score,
            'risk_level': result.risk_level,
            'critical_issues': result.critical_issues,
            'high_issues': result.high_issues,
            'medium_issues': result.medium_issues,
            'low_issues': result.low_issues
        }
        
        # Findings
        export_data['findings'] = {
            'encoding_findings': [self._serialize_encoding_finding(f) for f in result.all_encoding_findings],
            'cipher_findings': [self._serialize_cipher_finding(f) for f in result.all_cipher_findings],
            'cloud_findings': [self._serialize_cloud_finding(f) for f in result.all_cloud_findings]
        }
        
        # Advanced analysis
        export_data['advanced_analysis'] = {
            'encoding_chains': [self._serialize_encoding_chain(c) for c in result.encoding_chains],
            'security_patterns': [self._serialize_security_pattern(p) for p in result.security_patterns]
        }
        
        # Compliance and recommendations
        export_data['compliance'] = {
            'masvs_controls': result.masvs_controls,
            'recommendations': result.recommendations,
            'compliance_gaps': result.compliance_gaps
        }
        
        # File analysis results (if metadata included)
        if include_metadata and result.file_results:
            export_data['file_analysis'] = [
                self._serialize_file_result(fr) for fr in result.file_results
            ]
        
        return json.dumps(export_data, indent=2, default=str)
    
    def export_summary_json(self, result: ComprehensiveAnalysisResult) -> str:
        """
        Export a summary version of analysis results to JSON.
        
        Args:
            result: ComprehensiveAnalysisResult to export
            
        Returns:
            JSON string with summary data
        """
        summary_data = {
            'analysis_summary': {
                'package_name': result.package_name,
                'analysis_timestamp': result.analysis_timestamp.isoformat(),
                'total_findings': result.total_findings,
                'risk_level': result.risk_level,
                'risk_score': result.risk_score
            },
            'findings_by_type': result.get_findings_by_type(),
            'findings_by_severity': {
                'critical': result.critical_issues,
                'high': result.high_issues,
                'medium': result.medium_issues,
                'low': result.low_issues
            },
            'top_concerns': result.get_top_security_concerns(),
            'recommendations': result.recommendations[:5]  # Top 5 recommendations
        }
        
        return json.dumps(summary_data, indent=2, default=str)
    
    # Private helper methods
    
    def _add_report_header(self, report: Text, result: ComprehensiveAnalysisResult):
        """Add report header with basic information."""
        report.append("\n")
        report.append("🔍 Enhanced Encoding & Cloud Security Analysis Report\n", style="bold blue")
        report.append("=" * 60 + "\n", style="dim")
        
        # Basic info
        report.append(f"Package: {result.package_name}\n", style="bold")
        report.append(f"Analysis Date: {result.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.append(f"Duration: {result.analysis_duration:.2f} seconds\n")
        report.append(f"Files Analyzed: {result.files_analyzed}\n")
        report.append("\n")
    
    def _add_executive_summary(self, report: Text, result: ComprehensiveAnalysisResult):
        """Add executive summary section."""
        report.append("📊 Executive Summary\n", style="bold yellow")
        report.append("-" * 20 + "\n", style="dim")
        
        # Risk assessment
        risk_color = self._get_risk_color(result.risk_level)
        report.append(f"Overall Risk Level: ", style="bold")
        report.append(f"{result.risk_level}\n", style=f"bold {risk_color}")
        report.append(f"Risk Score: {result.risk_score}/100\n")
        report.append(f"Total Findings: {result.total_findings}\n")
        
        # Severity breakdown
        if result.critical_issues > 0:
            report.append(f"  🔥 Critical Issues: {result.critical_issues}\n", style="bold red")
        if result.high_issues > 0:
            report.append(f"  ⚠️  High Issues: {result.high_issues}\n", style="bold red")
        if result.medium_issues > 0:
            report.append(f"  📋 Medium Issues: {result.medium_issues}\n", style="bold yellow")
        if result.low_issues > 0:
            report.append(f"  ℹ️  Low Issues: {result.low_issues}\n", style="bold blue")
        
        # Top concerns
        top_concerns = result.get_top_security_concerns()
        if top_concerns:
            report.append("\nTop Security Concerns:\n", style="bold red")
            for i, concern in enumerate(top_concerns[:3], 1):
                report.append(f"  {i}. {concern}\n")
        
        report.append("\n")
    
    def _add_encoding_findings_section(self, report: Text, findings: List[EncodingFinding]):
        """Add encoding findings section."""
        report.append("🔤 Encoding Analysis Results\n", style="bold cyan")
        report.append("-" * 30 + "\n", style="dim")
        
        # Group by encoding type
        by_type = {}
        for finding in findings:
            encoding_type = finding.encoding_type.value
            if encoding_type not in by_type:
                by_type[encoding_type] = []
            by_type[encoding_type].append(finding)
        
        for encoding_type, type_findings in by_type.items():
            report.append(f"\n{encoding_type.upper()} Encoding ({len(type_findings)} findings):\n", style="bold")
            
            for finding in type_findings[:3]:  # Show top 3 per type
                severity_color = self.severity_colors.get_color(finding.severity)
                report.append(f"  • [{finding.severity.value.upper()}] ", style=f"bold {severity_color}")
                report.append(f"{finding.description}\n")
                report.append(f"    Location: {finding.location}\n", style="dim")
                report.append(f"    Confidence: {finding.confidence:.2f}\n", style="dim")
                
                if finding.decoded_content:
                    preview = finding.decoded_content[:50] + "..." if len(finding.decoded_content) > 50 else finding.decoded_content
                    report.append(f"    Decoded: {preview}\n", style="italic")
        
        report.append("\n")
    
    def _add_cipher_findings_section(self, report: Text, findings: List[CipherFinding]):
        """Add cipher findings section."""
        report.append("🔐 Cipher Analysis Results\n", style="bold magenta")
        report.append("-" * 28 + "\n", style="dim")
        
        for finding in findings:
            severity_color = self.severity_colors.get_color(finding.severity)
            report.append(f"• [{finding.severity.value.upper()}] ", style=f"bold {severity_color}")
            report.append(f"{finding.cipher_type.value.upper()} Cipher Implementation\n")
            report.append(f"  Location: {finding.location}\n", style="dim")
            report.append(f"  Confidence: {finding.confidence:.2f}\n", style="dim")
            
            if finding.vulnerabilities:
                report.append("  Vulnerabilities:\n", style="bold red")
                for vuln in finding.vulnerabilities[:2]:
                    report.append(f"    - {vuln}\n", style="red")
            
            if finding.recommendations:
                report.append("  Recommendations:\n", style="bold green")
                for rec in finding.recommendations[:2]:
                    report.append(f"    - {rec}\n", style="green")
        
        report.append("\n")
    
    def _add_cloud_findings_section(self, report: Text, findings: List[CloudServiceFinding]):
        """Add cloud service findings section."""
        report.append("☁️  Cloud Service Analysis Results\n", style="bold green")
        report.append("-" * 35 + "\n", style="dim")
        
        # Group by service type
        by_service = {}
        for finding in findings:
            service_type = finding.service_type.value
            if service_type not in by_service:
                by_service[service_type] = []
            by_service[service_type].append(finding)
        
        for service_type, type_findings in by_service.items():
            report.append(f"\n{service_type.upper()} ({len(type_findings)} findings):\n", style="bold")
            
            for finding in type_findings:
                severity_color = self.severity_colors.get_color(finding.severity)
                report.append(f"  • [{finding.severity.value.upper()}] ", style=f"bold {severity_color}")
                report.append(f"{finding.description}\n")
                report.append(f"    Location: {finding.location}\n", style="dim")
                report.append(f"    Confidence: {finding.confidence:.2f}\n", style="dim")
                
                if finding.credential_exposure:
                    report.append("    ⚠️ Credential Exposure Risk\n", style="bold red")
                
                if finding.public_access_risk:
                    report.append("    🌐 Public Access Risk\n", style="bold orange")
                
                if finding.configuration_issues:
                    report.append("    Configuration Issues:\n", style="bold yellow")
                    for issue in finding.configuration_issues[:2]:
                        report.append(f"      - {issue}\n", style="yellow")
        
        report.append("\n")
    
    def _add_encoding_chains_section(self, report: Text, chains: List[EncodingChain]):
        """Add encoding chains section."""
        report.append("🔗 Multi-Layer Encoding Chains\n", style="bold red")
        report.append("-" * 32 + "\n", style="dim")
        
        for chain in chains:
            report.append(f"Chain {chain.chain_id}:\n", style="bold")
            layers = " → ".join(layer.value for layer in chain.encoding_layers)
            report.append(f"  Layers: {layers}\n")
            report.append(f"  Complexity: {chain.complexity_score:.2f}\n", style="yellow")
            report.append(f"  Confidence: {chain.detection_confidence:.2f}\n", style="green")
            
            if chain.final_decoded_content:
                preview = chain.final_decoded_content[:60] + "..." if len(chain.final_decoded_content) > 60 else chain.final_decoded_content
                report.append(f"  Final Content: {preview}\n", style="italic")
            
            report.append("\n")
    
    def _add_security_patterns_section(self, report: Text, patterns: List[SecurityPattern]):
        """Add security patterns section."""
        report.append("🛡️  Security Patterns Detected\n", style="bold red")
        report.append("-" * 32 + "\n", style="dim")
        
        for pattern in patterns:
            severity_color = self.severity_colors.get_color(pattern.severity)
            report.append(f"• [{pattern.severity.value.upper()}] ", style=f"bold {severity_color}")
            report.append(f"{pattern.pattern_name}\n")
            report.append(f"  Type: {pattern.pattern_type.value}\n", style="dim")
            report.append(f"  Confidence: {pattern.confidence:.2f}\n", style="dim")
            
            if pattern.impact_assessment:
                report.append(f"  Impact: {pattern.impact_assessment}\n", style="italic")
        
        report.append("\n")
    
    def _add_analysis_summary(self, report: Text, result: ComprehensiveAnalysisResult):
        """Add analysis summary section."""
        report.append("📈 Analysis Summary\n", style="bold blue")
        report.append("-" * 18 + "\n", style="dim")
        
        findings_by_type = result.get_findings_by_type()
        for finding_type, count in findings_by_type.items():
            if count > 0:
                type_name = finding_type.replace('_', ' ').title()
                report.append(f"  {type_name}: {count}\n")
        
        report.append(f"\nMAVS Controls Referenced: {len(result.masvs_controls)}\n")
        report.append(f"Compliance Gaps Identified: {len(result.compliance_gaps)}\n")
        report.append("\n")
    
    def _add_recommendations_section(self, report: Text, result: ComprehensiveAnalysisResult):
        """Add recommendations section."""
        if not result.recommendations:
            return
        
        report.append("💡 Security Recommendations\n", style="bold green")
        report.append("-" * 27 + "\n", style="dim")
        
        for i, recommendation in enumerate(result.recommendations[:5], 1):
            report.append(f"{i}. {recommendation}\n")
        
        if len(result.recommendations) > 5:
            report.append(f"... and {len(result.recommendations) - 5} more recommendations\n", style="dim")
        
        report.append("\n")
    
    def _get_finding_type(self, finding: Union[EncodingFinding, CipherFinding, CloudServiceFinding]) -> str:
        """Get finding type string."""
        if isinstance(finding, EncodingFinding):
            return f"Encoding ({finding.encoding_type.value})"
        elif isinstance(finding, CipherFinding):
            return f"Cipher ({finding.cipher_type.value})"
        elif isinstance(finding, CloudServiceFinding):
            return f"Cloud ({finding.service_type.value})"
        else:
            return "Unknown"
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level."""
        risk_colors = {
            "CRITICAL": "bright_red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green"
        }
        return risk_colors.get(risk_level, "white")
    
    def _serialize_encoding_finding(self, finding: EncodingFinding) -> Dict[str, Any]:
        """Serialize encoding finding to dictionary."""
        return {
            'finding_id': finding.finding_id,
            'encoding_type': finding.encoding_type.value,
            'encoded_content': finding.encoded_content,
            'decoded_content': finding.decoded_content,
            'location': finding.location,
            'severity': finding.severity.value,
            'confidence': finding.confidence,
            'description': finding.description,
            'pattern_matched': finding.pattern_matched,
            'encoding_chain': [et.value for et in finding.encoding_chain],
            'analysis_patterns': [ap.value for ap in finding.analysis_patterns],
            'security_impact': finding.security_impact,
            'recommendations': finding.recommendations,
            'cwe': finding.cwe,
            'masvs_control': finding.masvs_control,
            'timestamp': finding.timestamp.isoformat()
        }
    
    def _serialize_cipher_finding(self, finding: CipherFinding) -> Dict[str, Any]:
        """Serialize cipher finding to dictionary."""
        return {
            'finding_id': finding.finding_id,
            'cipher_type': finding.cipher_type.value,
            'implementation_details': finding.implementation_details,
            'location': finding.location,
            'severity': finding.severity.value,
            'confidence': finding.confidence,
            'description': finding.description,
            'key_size': finding.key_size,
            'mode': finding.mode,
            'padding': finding.padding,
            'iv_usage': finding.iv_usage,
            'vulnerabilities': finding.vulnerabilities,
            'recommendations': finding.recommendations,
            'compliance_issues': finding.compliance_issues,
            'cwe': finding.cwe,
            'masvs_control': finding.masvs_control,
            'timestamp': finding.timestamp.isoformat()
        }
    
    def _serialize_cloud_finding(self, finding: CloudServiceFinding) -> Dict[str, Any]:
        """Serialize cloud service finding to dictionary."""
        endpoint_data = None
        if finding.service_endpoint:
            endpoint_data = {
                'service_type': finding.service_endpoint.service_type.value,
                'endpoint_url': finding.service_endpoint.endpoint_url,
                'service_config': finding.service_endpoint.service_config,
                'authentication_method': finding.service_endpoint.authentication_method,
                'encryption_status': finding.service_endpoint.encryption_status,
                'access_permissions': finding.service_endpoint.access_permissions
            }
        
        return {
            'finding_id': finding.finding_id,
            'service_type': finding.service_type.value,
            'service_endpoint': endpoint_data,
            'location': finding.location,
            'severity': finding.severity.value,
            'confidence': finding.confidence,
            'description': finding.description,
            'configuration_issues': finding.configuration_issues,
            'credential_exposure': finding.credential_exposure,
            'public_access_risk': finding.public_access_risk,
            'integration_vulnerabilities': finding.integration_vulnerabilities,
            'security_impact': finding.security_impact,
            'recommendations': finding.recommendations,
            'compliance_violations': finding.compliance_violations,
            'cwe': finding.cwe,
            'masvs_control': finding.masvs_control,
            'timestamp': finding.timestamp.isoformat()
        }
    
    def _serialize_encoding_chain(self, chain: EncodingChain) -> Dict[str, Any]:
        """Serialize encoding chain to dictionary."""
        return {
            'chain_id': chain.chain_id,
            'encoding_layers': [layer.value for layer in chain.encoding_layers],
            'original_content': chain.original_content,
            'intermediate_steps': chain.intermediate_steps,
            'final_decoded_content': chain.final_decoded_content,
            'complexity_score': chain.complexity_score,
            'detection_confidence': chain.detection_confidence,
            'security_implications': chain.security_implications,
            'locations': chain.locations
        }
    
    def _serialize_security_pattern(self, pattern: SecurityPattern) -> Dict[str, Any]:
        """Serialize security pattern to dictionary."""
        return {
            'pattern_type': pattern.pattern_type.value,
            'pattern_name': pattern.pattern_name,
            'description': pattern.description,
            'confidence': pattern.confidence,
            'indicators': pattern.indicators,
            'evidence': pattern.evidence,
            'locations': pattern.locations,
            'severity': pattern.severity.value,
            'attack_vectors': pattern.attack_vectors,
            'impact_assessment': pattern.impact_assessment,
            'mitigation_strategies': pattern.mitigation_strategies
        }
    
    def _serialize_file_result(self, file_result: FileAnalysisResult) -> Dict[str, Any]:
        """Serialize file analysis result to dictionary."""
        return {
            'file_path': file_result.file_path,
            'file_type': file_result.file_type.value,
            'analysis_successful': file_result.analysis_successful,
            'error_message': file_result.error_message,
            'content_size': file_result.content_size,
            'analysis_duration': file_result.analysis_duration,
            'patterns_checked': [pattern.value for pattern in file_result.patterns_checked],
            'total_findings': file_result.get_total_findings(),
            'findings_by_severity': file_result.get_findings_by_severity()
        } 