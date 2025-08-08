"""
Report Generator for Advanced Dynamic Analysis Plugin

This module handles comprehensive report generation and formatting for dynamic analysis results.
Provides rich output formatting and summary generation capabilities.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from rich.progress import Progress

from .data_structures import (
    AnalysisResult,
    Finding,
    RiskLevel,
    DeviceInfo,
    AppInfo,
    NetworkConfig,
    RISK_COLORS,
    MASVS_CONTROLS
)

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generates comprehensive reports for dynamic analysis results"""
    
    def __init__(self):
        """Initialize report generator"""
        self.console = Console()
        self.logger = logging.getLogger(__name__)
        
    def generate_comprehensive_report(self, result: AnalysisResult, config: Dict[str, Any]) -> Text:
        """
        Generate comprehensive analysis report
        
        Args:
            result: Complete analysis result
            config: Analysis configuration
            
        Returns:
            Text: Rich formatted report
        """
        try:
            report = Text()
            
            # Header
            report.append(self._generate_header(result))
            report.append("\n\n")
            
            # Executive Summary
            report.append(self._generate_executive_summary(result))
            report.append("\n\n")
            
            # Device Information
            if result.device_info:
                report.append(self._generate_device_section(result.device_info))
                report.append("\n\n")
            
            # Application Information
            if result.app_info:
                report.append(self._generate_app_section(result.app_info))
                report.append("\n\n")
            
            # Network Configuration
            if result.network_config:
                report.append(self._generate_network_section(result.network_config))
                report.append("\n\n")
            
            # Findings Analysis
            if result.findings:
                report.append(self._generate_findings_section(result.findings))
                report.append("\n\n")
            
            # Risk Assessment
            report.append(self._generate_risk_assessment(result))
            report.append("\n\n")
            
            # MASVS Compliance
            report.append(self._generate_masvs_compliance(result.findings))
            report.append("\n\n")
            
            # Recommendations
            report.append(self._generate_recommendations(result.findings))
            report.append("\n\n")
            
            # Footer
            report.append(self._generate_footer(result))
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating comprehensive report: {e}")
            return Text(f"Error generating report: {str(e)}", style="red")
    
    def _generate_header(self, result: AnalysisResult) -> Text:
        """Generate report header"""
        header = Text()
        header.append("🔍 ADVANCED DYNAMIC ANALYSIS REPORT\n", style="bold blue")
        header.append("=" * 50 + "\n", style="blue")
        header.append(f"Analysis ID: {result.analysis_id}\n", style="cyan")
        header.append(f"Package: {result.package_name}\n", style="cyan")
        header.append(f"Analysis Type: {result.analysis_type.value}\n", style="cyan")
        header.append(f"Start Time: {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n", style="cyan")
        
        if result.end_time:
            duration = result.end_time - result.start_time
            header.append(f"Duration: {duration}\n", style="cyan")
        
        header.append(f"Status: {result.status}\n", style="green" if result.status == "completed" else "yellow")
        
        return header
    
    def _generate_executive_summary(self, result: AnalysisResult) -> Text:
        """Generate executive summary"""
        summary = Text()
        summary.append("📊 EXECUTIVE SUMMARY\n", style="bold yellow")
        summary.append("-" * 30 + "\n", style="yellow")
        
        # Risk summary
        risk_summary = result.get_risk_summary()
        total_findings = len(result.findings)
        
        summary.append(f"Total Findings: {total_findings}\n", style="white")
        
        if total_findings > 0:
            for risk_level, count in risk_summary.items():
                if count > 0:
                    color = RISK_COLORS.get(RiskLevel(risk_level), "white")
                    summary.append(f"  • {risk_level.upper()}: {count}\n", style=color)
        
        # Overall risk assessment
        overall_risk = self._calculate_overall_risk(result.findings)
        summary.append(f"\nOverall Risk Level: {overall_risk}\n", style=RISK_COLORS.get(RiskLevel(overall_risk), "white"))
        
        return summary
    
    def _generate_device_section(self, device_info: DeviceInfo) -> Text:
        """Generate device information section"""
        section = Text()
        section.append("📱 DEVICE INFORMATION\n", style="bold green")
        section.append("-" * 30 + "\n", style="green")
        
        device_id = device_info.device_id if hasattr(device_info, 'device_id') else device_info.get('device_id', 'N/A')
        section.append(f"Device ID: {device_id}\n", style="white")
        section.append(f"Status: {device_info.status.value}\n", style="white")
        
        if device_info.android_version:
            section.append(f"Android Version: {device_info.android_version}\n", style="white")
        
        if device_info.api_level:
            section.append(f"API Level: {device_info.api_level}\n", style="white")
        
        if device_info.manufacturer:
            section.append(f"Manufacturer: {device_info.manufacturer}\n", style="white")
        
        if device_info.model:
            section.append(f"Model: {device_info.model}\n", style="white")
        
        if device_info.architecture:
            section.append(f"Architecture: {device_info.architecture}\n", style="white")
        
        if device_info.root_status is not None:
            root_status = "Yes" if device_info.root_status else "No"
            root_color = "green" if device_info.root_status else "yellow"
            section.append(f"Root Status: {root_status}\n", style=root_color)
        
        if device_info.error_message:
            section.append(f"Error: {device_info.error_message}\n", style="red")
        
        return section
    
    def _generate_app_section(self, app_info: AppInfo) -> Text:
        """Generate application information section"""
        section = Text()
        section.append("📦 APPLICATION INFORMATION\n", style="bold cyan")
        section.append("-" * 30 + "\n", style="cyan")
        
        section.append(f"Package Name: {app_info.package_name}\n", style="white")
        section.append(f"Status: {app_info.status.value}\n", style="white")
        
        if app_info.version_name:
            section.append(f"Version: {app_info.version_name}\n", style="white")
        
        if app_info.version_code:
            section.append(f"Version Code: {app_info.version_code}\n", style="white")
        
        if app_info.install_location:
            section.append(f"Install Location: {app_info.install_location}\n", style="white")
        
        if app_info.permissions:
            section.append(f"Permissions: {len(app_info.permissions)}\n", style="white")
            for perm in app_info.permissions[:5]:  # Show first 5
                section.append(f"  • {perm}\n", style="dim white")
            if len(app_info.permissions) > 5:
                section.append(f"  ... and {len(app_info.permissions) - 5} more\n", style="dim white")
        
        if app_info.activities:
            section.append(f"Activities: {len(app_info.activities)}\n", style="white")
        
        if app_info.services:
            section.append(f"Services: {len(app_info.services)}\n", style="white")
        
        if app_info.receivers:
            section.append(f"Receivers: {len(app_info.receivers)}\n", style="white")
        
        if app_info.error_message:
            section.append(f"Error: {app_info.error_message}\n", style="red")
        
        return section
    
    def _generate_network_section(self, network_config: NetworkConfig) -> Text:
        """Generate network configuration section"""
        section = Text()
        section.append("🌐 NETWORK CONFIGURATION\n", style="bold magenta")
        section.append("-" * 30 + "\n", style="magenta")
        
        section.append(f"Proxy Host: {network_config.proxy_host}\n", style="white")
        section.append(f"Proxy Port: {network_config.proxy_port}\n", style="white")
        section.append(f"Proxy Type: {network_config.proxy_type}\n", style="white")
        
        mitm_status = "Available" if network_config.mitm_available else "Not Available"
        mitm_color = "green" if network_config.mitm_available else "red"
        section.append(f"MITM Available: {mitm_status}\n", style=mitm_color)
        
        if network_config.certificate_path:
            section.append(f"Certificate: {network_config.certificate_path}\n", style="white")
        
        section.append(f"Capture Duration: {network_config.capture_duration}s\n", style="white")
        section.append(f"Max Requests: {network_config.max_requests}\n", style="white")
        
        return section
    
    def _generate_findings_section(self, findings: List[Finding]) -> Text:
        """Generate findings section"""
        section = Text()
        section.append("🔍 SECURITY FINDINGS\n", style="bold red")
        section.append("-" * 30 + "\n", style="red")
        
        if not findings:
            section.append("No security findings detected.\n", style="green")
            return section
        
        # Group findings by risk level
        risk_groups = {}
        for finding in findings:
            risk_level = finding.risk_level
            if risk_level not in risk_groups:
                risk_groups[risk_level] = []
            risk_groups[risk_level].append(finding)
        
        # Display findings by risk level (highest first)
        risk_order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]
        
        for risk_level in risk_order:
            if risk_level in risk_groups:
                group_findings = risk_groups[risk_level]
                color = RISK_COLORS.get(risk_level, "white")
                
                section.append(f"\n{risk_level.value.upper()} RISK ({len(group_findings)} findings):\n", style=f"bold {color}")
                
                for i, finding in enumerate(group_findings, 1):
                    section.append(f"\n{i}. {finding.title}\n", style=f"bold {color}")
                    section.append(f"   Description: {finding.description}\n", style="white")
                    section.append(f"   Category: {finding.category}\n", style="dim white")
                    section.append(f"   MASVS Control: {finding.masvs_control}\n", style="dim white")
                    section.append(f"   Confidence: {finding.confidence:.1%}\n", style="dim white")
                    section.append(f"   Source: {finding.source_component}\n", style="dim white")
                    
                    if finding.evidence:
                        section.append("   Evidence:\n", style="dim white")
                        for key, value in finding.evidence.items():
                            section.append(f"     • {key}: {value}\n", style="dim white")
                    
                    section.append(f"   Remediation: {finding.remediation}\n", style="dim cyan")
        
        return section
    
    def _generate_risk_assessment(self, result: AnalysisResult) -> Text:
        """Generate risk assessment section"""
        section = Text()
        section.append("⚠️ RISK ASSESSMENT\n", style="bold yellow")
        section.append("-" * 30 + "\n", style="yellow")
        
        risk_summary = result.get_risk_summary()
        total_findings = len(result.findings)
        
        if total_findings == 0:
            section.append("No security risks identified.\n", style="green")
            return section
        
        # Calculate risk metrics
        risk_score = self._calculate_risk_score(result.findings)
        overall_risk = self._calculate_overall_risk(result.findings)
        
        section.append(f"Risk Score: {risk_score:.1f}/100\n", style="white")
        section.append(f"Overall Risk: {overall_risk}\n", style=RISK_COLORS.get(RiskLevel(overall_risk), "white"))
        
        # Risk distribution
        section.append("\nRisk Distribution:\n", style="white")
        for risk_level, count in risk_summary.items():
            if count > 0:
                percentage = (count / total_findings) * 100
                color = RISK_COLORS.get(RiskLevel(risk_level), "white")
                section.append(f"  {risk_level.upper()}: {count} ({percentage:.1f}%)\n", style=color)
        
        # Risk categories
        category_counts = {}
        for finding in result.findings:
            category = finding.category
            if category not in category_counts:
                category_counts[category] = 0
            category_counts[category] += 1
        
        section.append("\nRisk Categories:\n", style="white")
        for category, count in sorted(category_counts.items()):
            section.append(f"  • {category}: {count}\n", style="white")
        
        return section
    
    def _generate_masvs_compliance(self, findings: List[Finding]) -> Text:
        """Generate MASVS compliance section"""
        section = Text()
        section.append("📋 MASVS COMPLIANCE\n", style="bold blue")
        section.append("-" * 30 + "\n", style="blue")
        
        # Group findings by MASVS control
        masvs_findings = {}
        for finding in findings:
            control = finding.masvs_control
            if control not in masvs_findings:
                masvs_findings[control] = []
            masvs_findings[control].append(finding)
        
        # Display compliance status
        all_controls = set(MASVS_CONTROLS.keys())
        violated_controls = set(masvs_findings.keys())
        compliant_controls = all_controls - violated_controls
        
        section.append(f"Controls Evaluated: {len(all_controls)}\n", style="white")
        section.append(f"Violations Found: {len(violated_controls)}\n", style="red" if violated_controls else "green")
        section.append(f"Compliant Controls: {len(compliant_controls)}\n", style="green")
        
        if violated_controls:
            section.append("\nViolated Controls:\n", style="red")
            for control in sorted(violated_controls):
                count = len(masvs_findings[control])
                description = MASVS_CONTROLS.get(control, "Unknown")
                section.append(f"  • {control}: {description} ({count} findings)\n", style="white")
        
        if compliant_controls:
            section.append("\nCompliant Controls:\n", style="green")
            for control in sorted(compliant_controls):
                description = MASVS_CONTROLS.get(control, "Unknown")
                section.append(f"  • {control}: {description}\n", style="dim white")
        
        return section
    
    def _generate_recommendations(self, findings: List[Finding]) -> Text:
        """Generate recommendations section"""
        section = Text()
        section.append("💡 RECOMMENDATIONS\n", style="bold cyan")
        section.append("-" * 30 + "\n", style="cyan")
        
        if not findings:
            section.append("No specific recommendations. Good security practices detected.\n", style="green")
            return section
        
        # Collect unique recommendations
        recommendations = set()
        for finding in findings:
            if finding.remediation:
                recommendations.add(finding.remediation)
        
        # Priority recommendations (based on risk level)
        priority_recommendations = []
        for finding in findings:
            if finding.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                priority_recommendations.append(finding.remediation)
        
        if priority_recommendations:
            section.append("Priority Recommendations:\n", style="bold red")
            for i, rec in enumerate(set(priority_recommendations), 1):
                section.append(f"{i}. {rec}\n", style="white")
        
        section.append("\nAll Recommendations:\n", style="white")
        for i, rec in enumerate(sorted(recommendations), 1):
            section.append(f"{i}. {rec}\n", style="white")
        
        return section
    
    def _generate_footer(self, result: AnalysisResult) -> Text:
        """Generate report footer"""
        footer = Text()
        footer.append("\n" + "=" * 50 + "\n", style="blue")
        footer.append("Generated by AODS Advanced Dynamic Analysis\n", style="dim white")
        footer.append(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", style="dim white")
        footer.append("For more information, visit: https://github.com/aods-security\n", style="dim blue")
        
        return footer
    
    def _calculate_risk_score(self, findings: List[Finding]) -> float:
        """Calculate numerical risk score"""
        if not findings:
            return 0.0
        
        risk_weights = {
            RiskLevel.CRITICAL: 10.0,
            RiskLevel.HIGH: 7.0,
            RiskLevel.MEDIUM: 5.0,
            RiskLevel.LOW: 2.0,
            RiskLevel.INFO: 1.0
        }
        
        total_score = 0
        for finding in findings:
            weight = risk_weights.get(finding.risk_level, 1.0)
            confidence = finding.confidence
            total_score += weight * confidence
        
        # Normalize to 0-100 scale
        max_possible_score = len(findings) * 10.0
        return min(100.0, (total_score / max_possible_score) * 100)
    
    def _calculate_overall_risk(self, findings: List[Finding]) -> str:
        """Calculate overall risk level"""
        if not findings:
            return "low"
        
        risk_counts = {}
        for finding in findings:
            risk_level = finding.risk_level
            if risk_level not in risk_counts:
                risk_counts[risk_level] = 0
            risk_counts[risk_level] += 1
        
        # Determine overall risk based on highest severity findings
        if risk_counts.get(RiskLevel.CRITICAL, 0) > 0:
            return "critical"
        elif risk_counts.get(RiskLevel.HIGH, 0) > 2:
            return "high"
        elif risk_counts.get(RiskLevel.HIGH, 0) > 0 or risk_counts.get(RiskLevel.MEDIUM, 0) > 3:
            return "medium"
        else:
            return "low"
    
    def generate_analysis_summary(self, result: AnalysisResult) -> Dict[str, Any]:
        """Generate analysis summary for programmatic use"""
        summary = {
            "analysis_id": result.analysis_id,
            "package_name": result.package_name,
            "analysis_type": result.analysis_type.value,
            "status": result.status,
            "start_time": result.start_time.isoformat(),
            "end_time": result.end_time.isoformat() if result.end_time else None,
            "total_findings": len(result.findings),
            "risk_summary": result.get_risk_summary(),
            "overall_risk": self._calculate_overall_risk(result.findings),
            "risk_score": self._calculate_risk_score(result.findings),
            "categories": self._get_category_summary(result.findings),
            "masvs_compliance": self._get_masvs_summary(result.findings),
            "metadata": result.metadata
        }
        
        if result.error_message:
            summary["error_message"] = result.error_message
        
        return summary
    
    def _get_category_summary(self, findings: List[Finding]) -> Dict[str, int]:
        """Get summary of findings by category"""
        category_counts = {}
        for finding in findings:
            category = finding.category
            if category not in category_counts:
                category_counts[category] = 0
            category_counts[category] += 1
        return category_counts
    
    def _get_masvs_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Get MASVS compliance summary"""
        masvs_findings = {}
        for finding in findings:
            control = finding.masvs_control
            if control not in masvs_findings:
                masvs_findings[control] = 0
            masvs_findings[control] += 1
        
        total_controls = len(MASVS_CONTROLS)
        violated_controls = len(masvs_findings)
        compliant_controls = total_controls - violated_controls
        
        return {
            "total_controls": total_controls,
            "violated_controls": violated_controls,
            "compliant_controls": compliant_controls,
            "compliance_percentage": (compliant_controls / total_controls) * 100,
            "violations": masvs_findings
        } 