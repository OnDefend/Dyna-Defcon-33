#!/usr/bin/env python3
"""
Professional Output Formatters for Improper Platform Usage Analysis

This module provides Rich text formatting capabilities for platform usage
analysis results, extracted from the monolithic plugin for improved
maintainability and consistent output styling.

Features:
- Professional Rich text formatting
- Component analysis tables
- Vulnerability summary reports  
- Security score visualization
- Comprehensive analysis reports
"""

import logging
from typing import Dict, List, Optional, Any, Union
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.console import Console

from .data_structures import (
    ManifestAnalysisResult, ComponentAnalysisResult, PlatformUsageVulnerability,
    RootBypassValidationResult, SecurityControlAssessment
)

logger = logging.getLogger(__name__)

class PlatformUsageFormatter:
    """formatter for platform usage analysis results."""
    
    def __init__(self):
        """Initialize the formatter."""
        self.console = Console()
    
    def format_analysis_results(self, 
                               manifest_result: ManifestAnalysisResult,
                               *,
                               bypass_result: Optional[RootBypassValidationResult] = None) -> Text:
        """Format complete analysis results into Rich text."""
        output = Text()
        
        # Header
        output.append("🔍 IMPROPER PLATFORM USAGE ANALYSIS REPORT\n", style="bold blue")
        output.append("=" * 60 + "\n\n", style="blue")
        
        # Executive Summary
        output.append(self._format_executive_summary(manifest_result))
        output.append("\n")
        
        # Component Analysis
        if manifest_result.component_results:
            output.append(self._format_component_analysis(manifest_result.component_results))
            output.append("\n")
        
        # Vulnerability Summary
        if manifest_result.security_issues:
            output.append(self._format_vulnerability_summary(manifest_result.security_issues))
            output.append("\n")
        
        # Root Bypass Validation (if available)
        if bypass_result:
            output.append(self._format_bypass_validation(bypass_result))
            output.append("\n")
        
        # Recommendations
        if manifest_result.recommendations:
            output.append(self._format_recommendations(manifest_result.recommendations))
            output.append("\n")
        
        # Detailed Component Analysis
        output.append(self._format_detailed_component_analysis(manifest_result.component_results))
        
        return output
    
    def _format_executive_summary(self, result: ManifestAnalysisResult) -> Text:
        """Format executive summary section."""
        summary = Text()
        summary.append("📊 EXECUTIVE SUMMARY\n", style="bold yellow")
        summary.append("-" * 30 + "\n", style="yellow")
        
        # Security grade with color coding
        grade = result.security_grade
        grade_color = self._get_grade_color(grade)
        summary.append(f"Security Grade: ", style="white")
        summary.append(f"{grade}\n", style=f"bold {grade_color}")
        
        # Overall score
        score_color = self._get_score_color(result.overall_security_score)
        summary.append(f"Overall Score: ", style="white")
        summary.append(f"{result.overall_security_score:.1%}\n", style=f"bold {score_color}")
        
        # Component statistics
        summary.append(f"Components Analyzed: {result.components_analyzed}\n", style="white")
        summary.append(f"Exported Components: {result.exported_components}\n", style="white")
        summary.append(f"Export Ratio: ", style="white")
        
        export_ratio_color = "red" if result.export_ratio > 0.5 else "yellow" if result.export_ratio > 0.3 else "green"
        summary.append(f"{result.export_ratio:.1%}\n", style=f"bold {export_ratio_color}")
        
        # Vulnerability counts
        total_vulns = result.total_vulnerabilities
        critical_vulns = len([v for v in result.security_issues if v.severity == "CRITICAL"])
        high_vulns = len([v for v in result.security_issues if v.severity == "HIGH"])
        
        summary.append(f"Total Vulnerabilities: {total_vulns}\n", style="white")
        if critical_vulns > 0:
            summary.append(f"Critical Issues: {critical_vulns}\n", style="bold red")
        if high_vulns > 0:
            summary.append(f"High Risk Issues: {high_vulns}\n", style="bold orange1")
        
        # Permission statistics
        summary.append(f"Dangerous Permissions: {len(result.dangerous_permissions)}\n", style="white")
        summary.append(f"Custom Permissions: {len(result.custom_permissions)}\n", style="white")
        
        return summary
    
    def _format_component_analysis(self, components: List[ComponentAnalysisResult]) -> Text:
        """Format component analysis overview."""
        output = Text()
        output.append("🏗️ COMPONENT ANALYSIS OVERVIEW\n", style="bold cyan")
        output.append("-" * 35 + "\n", style="cyan")
        
        # Create component summary table
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Component", style="white", width=30)
        table.add_column("Type", style="blue", width=15)
        table.add_column("Exported", justify="center", width=10)
        table.add_column("Protected", justify="center", width=10)
        table.add_column("Risk Level", justify="center", width=12)
        table.add_column("Security Score", justify="center", width=14)
        
        for comp in components[:10]:  # Limit to first 10 for readability
            # Truncate long component names
            name = comp.component_name.split('.')[-1] if '.' in comp.component_name else comp.component_name
            if len(name) > 25:
                name = name[:22] + "..."
            
            exported_style = "red" if comp.exported else "green"
            exported_text = "✓" if comp.exported else "✗"
            
            protected_style = "green" if comp.permissions else "red"
            protected_text = "✓" if comp.permissions else "✗"
            
            risk_color = self._get_risk_color(comp.risk_level)
            score_color = self._get_score_color(comp.security_score)
            
            table.add_row(
                name,
                comp.component_type,
                f"[{exported_style}]{exported_text}[/{exported_style}]",
                f"[{protected_style}]{protected_text}[/{protected_style}]",
                f"[{risk_color}]{comp.risk_level}[/{risk_color}]",
                f"[{score_color}]{comp.security_score:.1%}[/{score_color}]"
            )
        
        # Convert table to text
        with self.console.capture() as capture:
            self.console.print(table)
        output.append(capture.get())
        
        if len(components) > 10:
            output.append(f"\n... and {len(components) - 10} more components\n", style="dim white")
        
        return output
    
    def _format_vulnerability_summary(self, vulnerabilities: List[PlatformUsageVulnerability]) -> Text:
        """Format vulnerability summary section."""
        output = Text()
        output.append("🚨 VULNERABILITY SUMMARY\n", style="bold red")
        output.append("-" * 30 + "\n", style="red")
        
        # Group vulnerabilities by severity
        severity_groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for vuln in vulnerabilities:
            severity = vuln.severity.value
            if severity in severity_groups:
                severity_groups[severity].append(vuln)
        
        # Display summary by severity
        for severity, vulns in severity_groups.items():
            if vulns:
                count = len(vulns)
                color = self._get_severity_color(severity)
                output.append(f"{severity}: {count} issue{'s' if count != 1 else ''}\n", 
                             style=f"bold {color}")
        
        output.append("\n")
        
        # Top vulnerabilities table
        if vulnerabilities:
            output.append("Top Platform Usage Issues:\n", style="bold white")
            
            table = Table(show_header=True, header_style="bold white")
            table.add_column("Severity", width=10)
            table.add_column("Issue", width=40)
            table.add_column("Component", width=25)
            table.add_column("Confidence", justify="center", width=12)
            
            for vuln in vulnerabilities[:5]:  # Top 5 vulnerabilities
                severity_color = self._get_severity_color(vuln.severity)
                confidence_color = self._get_confidence_color(vuln.confidence)
                
                # Truncate long titles
                title = vuln.title
                if len(title) > 35:
                    title = title[:32] + "..."
                
                # Extract component name from context
                component = "Unknown"
                # Fix: PlatformUsageVulnerability doesn't have 'location' attribute - use context instead
                location_info = f"{vuln.context.class_name}:{vuln.context.method_name}" if vuln.context.class_name else vuln.context.file_path
                if ":" in location_info:
                    component = location_info.split(":")[-1].strip()
                elif location_info:
                    component = location_info.strip()
                if len(component) > 20:
                    component = component[:17] + "..."
                
                table.add_row(
                    f"[{severity_color}]{vuln.severity}[/{severity_color}]",
                    title,
                    component,
                    f"[{confidence_color}]{vuln.confidence:.1%}[/{confidence_color}]"
                )
            
            with self.console.capture() as capture:
                self.console.print(table)
            output.append(capture.get())
        
        return output
    
    def _format_bypass_validation(self, result: RootBypassValidationResult) -> Text:
        """Format root bypass validation results."""
        output = Text()
        output.append("🛡️ SECURITY CONTROL ASSESSMENT\n", style="bold magenta")
        output.append("-" * 40 + "\n", style="magenta")
        
        # Overall protection metrics
        protection_color = self._get_score_color(result.overall_protection_score)
        output.append(f"Overall Protection Score: ", style="white")
        output.append(f"{result.overall_protection_score:.1%}\n", style=f"bold {protection_color}")
        
        output.append(f"Bypass Detection: {result.bypass_detection_strength}\n", style="white")
        output.append(f"Anti-Tampering: ", style="white")
        tampering_color = self._get_score_color(result.anti_tampering_effectiveness)
        output.append(f"{result.anti_tampering_effectiveness:.1%}\n", style=f"bold {tampering_color}")
        
        output.append(f"RASP Implementation: {result.rasp_implementation_quality}\n", style="white")
        output.append(f"Integrity Verification: {result.integrity_verification_strength}\n", style="white")
        output.append(f"Device Attestation: {result.device_attestation_coverage}\n", style="white")
        
        # Security controls summary
        if result.security_control_assessments:
            output.append(f"\nEffective Controls: {result.effective_controls_count}/{result.total_controls_count}\n", 
                         style="white")
            coverage_color = self._get_score_color(result.protection_coverage)
            output.append(f"Protection Coverage: ", style="white")
            output.append(f"{result.protection_coverage:.1%}\n", style=f"bold {coverage_color}")
        
        return output
    
    def _format_recommendations(self, recommendations: List[str]) -> Text:
        """Format security recommendations."""
        output = Text()
        output.append("💡 SECURITY RECOMMENDATIONS\n", style="bold green")
        output.append("-" * 35 + "\n", style="green")
        
        for i, recommendation in enumerate(recommendations[:8], 1):  # Limit to 8 recommendations
            output.append(f"{i}. {recommendation}\n", style="white")
        
        if len(recommendations) > 8:
            output.append(f"... and {len(recommendations) - 8} more recommendations\n", 
                         style="dim white")
        
        return output
    
    def _format_detailed_component_analysis(self, components: List[ComponentAnalysisResult]) -> Text:
        """Format detailed component analysis."""
        output = Text()
        output.append("📋 DETAILED COMPONENT ANALYSIS\n", style="bold blue")
        output.append("-" * 40 + "\n", style="blue")
        
        high_risk_components = [comp for comp in components if comp.risk_level in ["CRITICAL", "HIGH"]]
        
        if high_risk_components:
            output.append("High Risk Components:\n\n", style="bold red")
            
            for comp in high_risk_components[:3]:  # Show top 3 high-risk components
                output.append(f"Component: {comp.component_name}\n", style="bold white")
                output.append(f"Type: {comp.component_type}\n", style="white")
                output.append(f"Risk Level: ", style="white")
                risk_color = self._get_risk_color(comp.risk_level)
                output.append(f"{comp.risk_level}\n", style=f"bold {risk_color}")
                
                if comp.exported:
                    output.append("Status: EXPORTED\n", style="bold red")
                
                if comp.permissions:
                    output.append(f"Permissions: {', '.join(comp.permissions[:3])}\n", style="white")
                    if len(comp.permissions) > 3:
                        output.append(f"... and {len(comp.permissions) - 3} more\n", style="dim white")
                else:
                    output.append("Permissions: NONE\n", style="bold red")
                
                if comp.vulnerabilities:
                    output.append(f"Vulnerabilities: {len(comp.vulnerabilities)}\n", style="red")
                
                output.append("\n")
        else:
            output.append("No high-risk components detected.\n", style="green")
        
        return output
    
    def _get_grade_color(self, grade: str) -> str:
        """Get color for security grade."""
        grade_colors = {"A": "green", "B": "yellow", "C": "orange1", "D": "red", "F": "red"}
        return grade_colors.get(grade, "white")
    
    def _get_score_color(self, score: float) -> str:
        """Get color for numeric score."""
        if score >= 0.8:
            return "green"
        elif score >= 0.6:
            return "yellow"
        elif score >= 0.4:
            return "orange1"
        else:
            return "red"
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level."""
        risk_colors = {
            "LOW": "green",
            "MEDIUM": "yellow", 
            "HIGH": "orange1",
            "CRITICAL": "red"
        }
        return risk_colors.get(risk_level.upper(), "white")
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for vulnerability severity."""
        severity_colors = {
            "LOW": "green",
            "MEDIUM": "yellow",
            "HIGH": "orange1", 
            "CRITICAL": "red"
        }
        return severity_colors.get(severity.value if hasattr(severity, 'value') else str(severity).upper(), "white")
    
    def _get_confidence_color(self, confidence: float) -> str:
        """Get color for confidence level."""
        if confidence >= 0.8:
            return "green"
        elif confidence >= 0.6:
            return "yellow"
        else:
            return "orange1"
    
    def format_simple_summary(self, result: ManifestAnalysisResult) -> str:
        """Format a simple text summary for compatibility."""
        summary_lines = [
            f"Improper Platform Usage Analysis Results",
            f"Security Grade: {result.security_grade}",
            f"Overall Score: {result.overall_security_score:.1%}",
            f"Components Analyzed: {result.components_analyzed}",
            f"Exported Components: {result.exported_components}",
            f"Total Vulnerabilities: {result.total_vulnerabilities}",
            f"Dangerous Permissions: {len(result.dangerous_permissions)}"
        ]
        
        if result.high_risk_components:
            summary_lines.append(f"High Risk Components: {len(result.high_risk_components)}")
        
        return "\n".join(summary_lines) 