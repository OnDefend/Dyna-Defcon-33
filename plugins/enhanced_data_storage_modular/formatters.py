"""
Enhanced Data Storage Formatters

This module provides professional Rich text formatting for enhanced data storage
analysis results, including PII detection, file permission analysis, storage security
assessment, and path traversal detection.

Features:
- Rich text output formatting
- Color-coded severity levels
- table generation
- Summary statistics formatting
- JSON export capabilities
- Compliance reporting
"""

import logging
import json
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from rich.text import Text
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.columns import Columns
from rich.align import Align
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from rich.markdown import Markdown

from .data_structures import (
    PIIFinding, FilePermissionFinding, StorageSecurityFinding, PathTraversalFinding,
    EnhancedDataStorageAnalysisResult, AnalysisStatistics,
    PIIType, FilePermissionLevel, StorageSecurityLevel, PathTraversalRisk,
    VulnerabilitySeverity
)

logger = logging.getLogger(__name__)

class EnhancedDataStorageFormatter:
    """
    formatter for enhanced data storage analysis results.
    
    Provides comprehensive formatting capabilities for PII findings, file permission
    analysis, storage security assessment, and path traversal detection with
    Rich text output and professional styling.
    """
    
    def __init__(self):
        """Initialize the formatter."""
        self.console = Console()
        
        # Color schemes for different severity levels
        self.severity_colors = {
            VulnerabilitySeverity.CRITICAL: "red",
            VulnerabilitySeverity.HIGH: "orange_red1",
            VulnerabilitySeverity.MEDIUM: "yellow",
            VulnerabilitySeverity.LOW: "cyan",
            VulnerabilitySeverity.INFO: "green"
        }
        
        # Icons for different finding types
        self.finding_icons = {
            "pii_detection": "🔍",
            "file_permission": "📁",
            "storage_security": "🔒",
            "path_traversal": "🛣️"
        }
        
        # Formatting statistics
        self.format_stats = {
            "reports_generated": 0,
            "total_findings_formatted": 0,
            "json_exports": 0,
            "table_generations": 0
        }
    
    def format_analysis_result(self, result: EnhancedDataStorageAnalysisResult) -> Text:
        """
        Format complete analysis result with all findings.
        
        Args:
            result: Complete analysis result to format
            
        Returns:
            Rich Text object with formatted output
        """
        try:
            output = Text()
            
            # Header
            output.append(self._create_header(result))
            output.append("\n\n")
            
            # Executive summary
            output.append(self._create_executive_summary(result))
            output.append("\n\n")
            
            # Findings sections
            if result.pii_findings:
                output.append(self._format_pii_findings(result.pii_findings))
                output.append("\n\n")
            
            if result.file_permission_findings:
                output.append(self._format_file_permission_findings(result.file_permission_findings))
                output.append("\n\n")
            
            if result.storage_security_findings:
                output.append(self._format_storage_security_findings(result.storage_security_findings))
                output.append("\n\n")
            
            if result.path_traversal_findings:
                output.append(self._format_path_traversal_findings(result.path_traversal_findings))
                output.append("\n\n")
            
            # Statistics and recommendations
            output.append(self._format_statistics(result.statistics))
            output.append("\n\n")
            output.append(self._format_recommendations(result.recommendations))
            
            # Update formatting statistics
            self.format_stats["reports_generated"] += 1
            self.format_stats["total_findings_formatted"] += result.total_findings
            
            return output
            
        except Exception as e:
            logger.error(f"Error formatting analysis result: {str(e)}")
            return Text(f"Error formatting analysis result: {str(e)}", style="red")
    
    def _create_header(self, result: EnhancedDataStorageAnalysisResult) -> Text:
        """Create formatted header for the analysis report."""
        header = Text()
        header.append("Enhanced Data Storage Analysis Report", style="bold blue")
        header.append("\n")
        header.append("=" * 50, style="blue")
        header.append("\n")
        header.append(f"Package: {result.package_name}", style="bold")
        header.append("\n")
        header.append(f"Analysis ID: {result.analysis_id}")
        header.append("\n")
        header.append(f"Start Time: {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        header.append("\n")
        header.append(f"End Time: {result.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        header.append("\n")
        duration = (result.end_time - result.start_time).total_seconds()
        header.append(f"Duration: {duration:.2f} seconds")
        
        return header
    
    def _create_executive_summary(self, result: EnhancedDataStorageAnalysisResult) -> Text:
        """Create executive summary section."""
        summary = Text()
        summary.append("Executive Summary", style="bold green")
        summary.append("\n")
        summary.append("-" * 20, style="green")
        summary.append("\n")
        
        # Overall risk assessment
        risk_color = self._get_risk_color(result.risk_level)
        summary.append(f"Overall Risk Level: ", style="bold")
        summary.append(f"{result.risk_level}", style=f"bold {risk_color}")
        summary.append("\n")
        summary.append(f"Risk Score: {result.overall_risk_score:.1f}/100", style="bold")
        summary.append("\n")
        summary.append(f"Compliance Status: {result.compliance_status}", style="bold")
        summary.append("\n\n")
        
        # Findings breakdown
        summary.append("Findings Breakdown:", style="bold")
        summary.append("\n")
        summary.append(f"  • Total Findings: {result.total_findings}")
        summary.append("\n")
        summary.append(f"  • Critical: ", style="bold")
        summary.append(f"{result.critical_findings}", style="bold red")
        summary.append("\n")
        summary.append(f"  • High: ", style="bold")
        summary.append(f"{result.high_findings}", style="bold orange_red1")
        summary.append("\n")
        summary.append(f"  • Medium: ", style="bold")
        summary.append(f"{result.medium_findings}", style="bold yellow")
        summary.append("\n")
        summary.append(f"  • Low: ", style="bold")
        summary.append(f"{result.low_findings}", style="bold cyan")
        summary.append("\n\n")
        
        # Analysis types
        summary.append("Analysis Coverage:", style="bold")
        summary.append("\n")
        summary.append(f"  • PII Findings: {len(result.pii_findings)}")
        summary.append("\n")
        summary.append(f"  • File Permission Issues: {len(result.file_permission_findings)}")
        summary.append("\n")
        summary.append(f"  • Storage Security Issues: {len(result.storage_security_findings)}")
        summary.append("\n")
        summary.append(f"  • Path Traversal Vulnerabilities: {len(result.path_traversal_findings)}")
        
        return summary
    
    def _format_pii_findings(self, findings: List[PIIFinding]) -> Text:
        """Format PII detection findings."""
        output = Text()
        output.append(f"{self.finding_icons['pii_detection']} PII Detection Findings ({len(findings)})", style="bold magenta")
        output.append("\n")
        output.append("=" * 40, style="magenta")
        output.append("\n\n")
        
        for i, finding in enumerate(findings, 1):
            output.append(f"[{i}] PII Type: ", style="bold")
            output.append(f"{finding.pii_type.value.upper()}", style="bold cyan")
            output.append("\n")
            
            output.append(f"    Location: {finding.location}")
            output.append("\n")
            
            output.append(f"    File: {finding.file_path}")
            output.append("\n")
            
            output.append(f"    Value: {finding.value[:50]}{'...' if len(finding.value) > 50 else ''}")
            output.append("\n")
            
            # Severity and confidence
            severity_color = self.severity_colors.get(finding.severity, "white")
            output.append(f"    Severity: ", style="bold")
            output.append(f"{finding.severity.value}", style=f"bold {severity_color}")
            output.append(f" | Confidence: {finding.confidence:.2f}")
            output.append("\n")
            
            # Risk assessment
            output.append(f"    Exposure Risk: {finding.exposure_risk}")
            output.append("\n")
            output.append(f"    Data Sensitivity: {finding.data_sensitivity}")
            output.append("\n")
            
            # Compliance impact
            if finding.compliance_impact:
                output.append(f"    Compliance Impact: {', '.join(finding.compliance_impact)}")
                output.append("\n")
            
            # Context
            if finding.context:
                output.append(f"    Context: {finding.context[:100]}{'...' if len(finding.context) > 100 else ''}")
                output.append("\n")
            
            # Remediation
            if finding.remediation_advice:
                output.append(f"    Remediation: {finding.remediation_advice}")
                output.append("\n")
            
            output.append("\n")
        
        return output
    
    def _format_file_permission_findings(self, findings: List[FilePermissionFinding]) -> Text:
        """Format file permission findings."""
        output = Text()
        output.append(f"{self.finding_icons['file_permission']} File Permission Findings ({len(findings)})", style="bold blue")
        output.append("\n")
        output.append("=" * 40, style="blue")
        output.append("\n\n")
        
        for i, finding in enumerate(findings, 1):
            output.append(f"[{i}] File: ", style="bold")
            output.append(f"{finding.file_path}", style="bold cyan")
            output.append("\n")
            
            output.append(f"    Permission Mode: {finding.permission_mode}")
            output.append("\n")
            
            output.append(f"    Owner: {finding.owner} | Group: {finding.group}")
            output.append("\n")
            
            # Security assessment
            level_color = self._get_permission_level_color(finding.permission_level)
            output.append(f"    Security Level: ", style="bold")
            output.append(f"{finding.permission_level.value.upper()}", style=f"bold {level_color}")
            output.append("\n")
            
            # Severity and confidence
            severity_color = self.severity_colors.get(finding.severity, "white")
            output.append(f"    Severity: ", style="bold")
            output.append(f"{finding.severity.value}", style=f"bold {severity_color}")
            output.append(f" | Confidence: {finding.confidence:.2f}")
            output.append("\n")
            
            # Security issues
            if finding.security_issues:
                output.append(f"    Security Issues: {', '.join(finding.security_issues)}")
                output.append("\n")
            
            # Access risks
            if finding.access_risks:
                output.append(f"    Access Risks: {', '.join(finding.access_risks)}")
                output.append("\n")
            
            # Context flags
            context_flags = []
            if finding.is_system_file:
                context_flags.append("System File")
            if finding.is_app_data:
                context_flags.append("App Data")
            if finding.is_external_storage:
                context_flags.append("External Storage")
            
            if context_flags:
                output.append(f"    Context: {', '.join(context_flags)}")
                output.append("\n")
            
            # Remediation steps
            if finding.remediation_steps:
                output.append(f"    Remediation Steps:")
                output.append("\n")
                for step in finding.remediation_steps:
                    output.append(f"      • {step}")
                    output.append("\n")
            
            output.append("\n")
        
        return output
    
    def _format_storage_security_findings(self, findings: List[StorageSecurityFinding]) -> Text:
        """Format storage security findings."""
        output = Text()
        output.append(f"{self.finding_icons['storage_security']} Storage Security Findings ({len(findings)})", style="bold red")
        output.append("\n")
        output.append("=" * 40, style="red")
        output.append("\n\n")
        
        for i, finding in enumerate(findings, 1):
            output.append(f"[{i}] Storage Type: ", style="bold")
            output.append(f"{finding.storage_type}", style="bold cyan")
            output.append("\n")
            
            output.append(f"    Path: {finding.storage_path}")
            output.append("\n")
            
            output.append(f"    Encryption Status: {finding.encryption_status}")
            output.append("\n")
            
            output.append(f"    Access Control: {finding.access_control}")
            output.append("\n")
            
            # Security level
            level_color = self._get_security_level_color(finding.security_level)
            output.append(f"    Security Level: ", style="bold")
            output.append(f"{finding.security_level.value.upper()}", style=f"bold {level_color}")
            output.append("\n")
            
            # Encryption details
            if finding.encryption_algorithm:
                output.append(f"    Encryption Algorithm: {finding.encryption_algorithm}")
                output.append("\n")
            
            if finding.key_management:
                output.append(f"    Key Management: {finding.key_management}")
                output.append("\n")
            
            # Severity and confidence
            severity_color = self.severity_colors.get(finding.severity, "white")
            output.append(f"    Severity: ", style="bold")
            output.append(f"{finding.severity.value}", style=f"bold {severity_color}")
            output.append(f" | Confidence: {finding.confidence:.2f}")
            output.append("\n")
            
            # Security issues
            if finding.security_issues:
                output.append(f"    Security Issues: {', '.join(finding.security_issues)}")
                output.append("\n")
            
            # Data leakage risks
            if finding.data_leakage_risks:
                output.append(f"    Data Leakage Risks: {', '.join(finding.data_leakage_risks)}")
                output.append("\n")
            
            # Context flags
            context_flags = []
            if finding.contains_sensitive_data:
                context_flags.append("Sensitive Data")
            if finding.is_backup_location:
                context_flags.append("Backup Location")
            if finding.is_shared_storage:
                context_flags.append("Shared Storage")
            
            if context_flags:
                output.append(f"    Context: {', '.join(context_flags)}")
                output.append("\n")
            
            # Security recommendations
            if finding.security_recommendations:
                output.append(f"    Security Recommendations:")
                output.append("\n")
                for rec in finding.security_recommendations:
                    output.append(f"      • {rec}")
                    output.append("\n")
            
            output.append("\n")
        
        return output
    
    def _format_path_traversal_findings(self, findings: List[PathTraversalFinding]) -> Text:
        """Format path traversal findings."""
        output = Text()
        output.append(f"{self.finding_icons['path_traversal']} Path Traversal Findings ({len(findings)})", style="bold orange_red1")
        output.append("\n")
        output.append("=" * 40, style="orange_red1")
        output.append("\n\n")
        
        for i, finding in enumerate(findings, 1):
            output.append(f"[{i}] Vulnerable Method: ", style="bold")
            output.append(f"{finding.vulnerable_method}", style="bold cyan")
            output.append("\n")
            
            output.append(f"    File: {finding.file_path}")
            output.append("\n")
            
            if finding.line_number:
                output.append(f"    Line: {finding.line_number}")
                output.append("\n")
            
            # Risk assessment
            risk_color = self._get_traversal_risk_color(finding.traversal_risk)
            output.append(f"    Traversal Risk: ", style="bold")
            output.append(f"{finding.traversal_risk.value.upper()}", style=f"bold {risk_color}")
            output.append("\n")
            
            # Severity and confidence
            severity_color = self.severity_colors.get(finding.severity, "white")
            output.append(f"    Severity: ", style="bold")
            output.append(f"{finding.severity.value}", style=f"bold {severity_color}")
            output.append(f" | Confidence: {finding.confidence:.2f}")
            output.append("\n")
            
            # User input source
            if finding.user_input_source:
                output.append(f"    User Input Source: {finding.user_input_source}")
                output.append("\n")
            
            # Vulnerable parameter
            if finding.vulnerable_parameter:
                output.append(f"    Vulnerable Parameter: {finding.vulnerable_parameter}")
                output.append("\n")
            
            # Path validation
            output.append(f"    Path Validation: {finding.path_validation}")
            output.append("\n")
            
            output.append(f"    Sanitization Present: {'Yes' if finding.sanitization_present else 'No'}")
            output.append("\n")
            
            # Context flags
            context_flags = []
            if finding.is_file_operation:
                context_flags.append("File Operation")
            if finding.is_directory_operation:
                context_flags.append("Directory Operation")
            if finding.allows_external_input:
                context_flags.append("External Input")
            
            if context_flags:
                output.append(f"    Context: {', '.join(context_flags)}")
                output.append("\n")
            
            # Potential targets
            if finding.potential_targets:
                output.append(f"    Potential Targets: {', '.join(finding.potential_targets)}")
                output.append("\n")
            
            # Attack vectors
            if finding.attack_vectors:
                output.append(f"    Attack Vectors: {', '.join(finding.attack_vectors)}")
                output.append("\n")
            
            # Mitigation strategies
            if finding.mitigation_strategies:
                output.append(f"    Mitigation Strategies:")
                output.append("\n")
                for strategy in finding.mitigation_strategies:
                    output.append(f"      • {strategy}")
                    output.append("\n")
            
            output.append("\n")
        
        return output
    
    def _format_statistics(self, statistics: AnalysisStatistics) -> Text:
        """Format analysis statistics."""
        output = Text()
        output.append("📊 Analysis Statistics", style="bold green")
        output.append("\n")
        output.append("=" * 25, style="green")
        output.append("\n\n")
        
        output.append(f"Files Analyzed: {statistics.files_analyzed}")
        output.append("\n")
        output.append(f"Directories Scanned: {statistics.directories_scanned}")
        output.append("\n")
        output.append(f"Analysis Duration: {statistics.analysis_duration:.2f} seconds")
        output.append("\n")
        output.append(f"Analysis Coverage: {statistics.analysis_coverage:.1f}%")
        output.append("\n\n")
        
        # PII statistics
        output.append("PII Detection Statistics:", style="bold")
        output.append("\n")
        output.append(f"  • Total PII Findings: {statistics.pii_findings_count}")
        output.append("\n")
        output.append(f"  • High Risk PII: {statistics.high_risk_pii_count}")
        output.append("\n")
        output.append(f"  • PII Types Found: {len(statistics.pii_types_found)}")
        output.append("\n\n")
        
        # File permission statistics
        output.append("File Permission Statistics:", style="bold")
        output.append("\n")
        output.append(f"  • Files with Issues: {statistics.files_with_permission_issues}")
        output.append("\n")
        output.append(f"  • Critical Issues: {statistics.critical_permission_issues}")
        output.append("\n")
        output.append(f"  • World Readable: {statistics.world_readable_files}")
        output.append("\n")
        output.append(f"  • World Writable: {statistics.world_writable_files}")
        output.append("\n\n")
        
        # Storage security statistics
        output.append("Storage Security Statistics:", style="bold")
        output.append("\n")
        output.append(f"  • Encrypted Storage: {statistics.encrypted_storage_count}")
        output.append("\n")
        output.append(f"  • Unencrypted Storage: {statistics.unencrypted_storage_count}")
        output.append("\n")
        output.append(f"  • Storage Vulnerabilities: {statistics.storage_vulnerabilities}")
        output.append("\n\n")
        
        # Path traversal statistics
        output.append("Path Traversal Statistics:", style="bold")
        output.append("\n")
        output.append(f"  • Traversal Vulnerabilities: {statistics.path_traversal_vulnerabilities}")
        output.append("\n")
        output.append(f"  • High Risk Traversals: {statistics.high_risk_traversal_count}")
        output.append("\n")
        output.append(f"  • Validated Paths: {statistics.validated_paths_count}")
        output.append("\n")
        
        return output
    
    def _format_recommendations(self, recommendations: List[str]) -> Text:
        """Format recommendations section."""
        output = Text()
        output.append("💡 Recommendations", style="bold yellow")
        output.append("\n")
        output.append("=" * 20, style="yellow")
        output.append("\n\n")
        
        for i, recommendation in enumerate(recommendations, 1):
            output.append(f"{i}. {recommendation}")
            output.append("\n")
        
        return output
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level."""
        risk_colors = {
            "CRITICAL": "red",
            "HIGH": "orange_red1",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "MINIMAL": "green"
        }
        return risk_colors.get(risk_level, "white")
    
    def _get_permission_level_color(self, level: FilePermissionLevel) -> str:
        """Get color for permission level."""
        level_colors = {
            FilePermissionLevel.INSECURE: "red",
            FilePermissionLevel.MODERATE: "yellow",
            FilePermissionLevel.SECURE: "green"
        }
        return level_colors.get(level, "white")
    
    def _get_security_level_color(self, level: StorageSecurityLevel) -> str:
        """Get color for security level."""
        level_colors = {
            StorageSecurityLevel.EXPOSED: "red",
            StorageSecurityLevel.VULNERABLE: "orange_red1",
            StorageSecurityLevel.PROTECTED: "yellow",
            StorageSecurityLevel.ENCRYPTED: "green"
        }
        return level_colors.get(level, "white")
    
    def _get_traversal_risk_color(self, risk: PathTraversalRisk) -> str:
        """Get color for traversal risk."""
        risk_colors = {
            PathTraversalRisk.CRITICAL_RISK: "red",
            PathTraversalRisk.HIGH_RISK: "orange_red1",
            PathTraversalRisk.MEDIUM_RISK: "yellow",
            PathTraversalRisk.LOW_RISK: "cyan",
            PathTraversalRisk.NO_RISK: "green"
        }
        return risk_colors.get(risk, "white")
    
    def export_to_json(self, result: EnhancedDataStorageAnalysisResult) -> str:
        """Export analysis result to JSON format."""
        try:
            def serialize_finding(finding):
                """Serialize finding to JSON-compatible format."""
                if isinstance(finding, PIIFinding):
                    return {
                        "type": "pii_finding",
                        "pii_type": finding.pii_type.value,
                        "value": finding.value,
                        "location": finding.location,
                        "file_path": finding.file_path,
                        "line_number": finding.line_number,
                        "confidence": finding.confidence,
                        "severity": finding.severity.value,
                        "context": finding.context,
                        "exposure_risk": finding.exposure_risk,
                        "data_sensitivity": finding.data_sensitivity,
                        "compliance_impact": finding.compliance_impact,
                        "remediation_advice": finding.remediation_advice,
                        "discovered_at": finding.discovered_at.isoformat()
                    }
                elif isinstance(finding, FilePermissionFinding):
                    return {
                        "type": "file_permission_finding",
                        "file_path": finding.file_path,
                        "permission_mode": finding.permission_mode,
                        "owner": finding.owner,
                        "group": finding.group,
                        "permission_level": finding.permission_level.value,
                        "security_issues": finding.security_issues,
                        "access_risks": finding.access_risks,
                        "confidence": finding.confidence,
                        "severity": finding.severity.value,
                        "location": finding.location,
                        "is_system_file": finding.is_system_file,
                        "is_app_data": finding.is_app_data,
                        "is_external_storage": finding.is_external_storage,
                        "compliance_violations": finding.compliance_violations,
                        "remediation_steps": finding.remediation_steps
                    }
                elif isinstance(finding, StorageSecurityFinding):
                    return {
                        "type": "storage_security_finding",
                        "storage_type": finding.storage_type,
                        "storage_path": finding.storage_path,
                        "encryption_status": finding.encryption_status,
                        "access_control": finding.access_control,
                        "security_level": finding.security_level.value,
                        "encryption_algorithm": finding.encryption_algorithm,
                        "key_management": finding.key_management,
                        "security_issues": finding.security_issues,
                        "data_leakage_risks": finding.data_leakage_risks,
                        "confidence": finding.confidence,
                        "severity": finding.severity.value,
                        "location": finding.location,
                        "contains_sensitive_data": finding.contains_sensitive_data,
                        "is_backup_location": finding.is_backup_location,
                        "is_shared_storage": finding.is_shared_storage,
                        "security_recommendations": finding.security_recommendations,
                        "compliance_requirements": finding.compliance_requirements
                    }
                elif isinstance(finding, PathTraversalFinding):
                    return {
                        "type": "path_traversal_finding",
                        "vulnerable_method": finding.vulnerable_method,
                        "file_path": finding.file_path,
                        "line_number": finding.line_number,
                        "user_input_source": finding.user_input_source,
                        "traversal_risk": finding.traversal_risk.value,
                        "potential_targets": finding.potential_targets,
                        "attack_vectors": finding.attack_vectors,
                        "vulnerable_parameter": finding.vulnerable_parameter,
                        "path_validation": finding.path_validation,
                        "sanitization_present": finding.sanitization_present,
                        "confidence": finding.confidence,
                        "severity": finding.severity.value,
                        "location": finding.location,
                        "is_file_operation": finding.is_file_operation,
                        "is_directory_operation": finding.is_directory_operation,
                        "allows_external_input": finding.allows_external_input,
                        "mitigation_strategies": finding.mitigation_strategies,
                        "code_examples": finding.code_examples
                    }
                else:
                    return {"type": "unknown", "data": str(finding)}
            
            # Serialize all findings
            all_findings = []
            for finding in result.pii_findings:
                all_findings.append(serialize_finding(finding))
            for finding in result.file_permission_findings:
                all_findings.append(serialize_finding(finding))
            for finding in result.storage_security_findings:
                all_findings.append(serialize_finding(finding))
            for finding in result.path_traversal_findings:
                all_findings.append(serialize_finding(finding))
            
            # Create JSON structure
            json_result = {
                "analysis_metadata": {
                    "analysis_id": result.analysis_id,
                    "package_name": result.package_name,
                    "start_time": result.start_time.isoformat(),
                    "end_time": result.end_time.isoformat(),
                    "duration": (result.end_time - result.start_time).total_seconds()
                },
                "summary": {
                    "total_findings": result.total_findings,
                    "critical_findings": result.critical_findings,
                    "high_findings": result.high_findings,
                    "medium_findings": result.medium_findings,
                    "low_findings": result.low_findings,
                    "overall_risk_score": result.overall_risk_score,
                    "risk_level": result.risk_level,
                    "compliance_status": result.compliance_status
                },
                "findings": all_findings,
                "statistics": {
                    "files_analyzed": result.statistics.files_analyzed,
                    "directories_scanned": result.statistics.directories_scanned,
                    "analysis_duration": result.statistics.analysis_duration,
                    "pii_findings_count": result.statistics.pii_findings_count,
                    "high_risk_pii_count": result.statistics.high_risk_pii_count,
                    "files_with_permission_issues": result.statistics.files_with_permission_issues,
                    "critical_permission_issues": result.statistics.critical_permission_issues,
                    "world_readable_files": result.statistics.world_readable_files,
                    "world_writable_files": result.statistics.world_writable_files,
                    "encrypted_storage_count": result.statistics.encrypted_storage_count,
                    "unencrypted_storage_count": result.statistics.unencrypted_storage_count,
                    "storage_vulnerabilities": result.statistics.storage_vulnerabilities,
                    "path_traversal_vulnerabilities": result.statistics.path_traversal_vulnerabilities,
                    "high_risk_traversal_count": result.statistics.high_risk_traversal_count,
                    "validated_paths_count": result.statistics.validated_paths_count,
                    "analysis_coverage": result.statistics.analysis_coverage
                },
                "recommendations": result.recommendations,
                "priority_actions": result.priority_actions,
                "export_metadata": {
                    "export_time": datetime.now().isoformat(),
                    "format_version": "1.0"
                }
            }
            
            # Update export statistics
            self.format_stats["json_exports"] += 1
            
            return json.dumps(json_result, indent=2)
            
        except Exception as e:
            logger.error(f"Error exporting to JSON: {str(e)}")
            return f'{{"error": "Failed to export to JSON: {str(e)}"}}'
    
    def get_format_statistics(self) -> Dict[str, Any]:
        """Get formatting statistics."""
        return {
            "formatter_type": "enhanced_data_storage",
            "statistics": self.format_stats.copy(),
            "supported_formats": ["rich_text", "json"],
            "severity_colors": {
                severity.value: color for severity, color in self.severity_colors.items()
            },
            "finding_icons": self.finding_icons.copy()
        } 