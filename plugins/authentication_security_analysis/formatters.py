"""
Formatters for Authentication Security Analysis
Handles report generation and visualization of authentication security findings.
"""

import json
from typing import Dict, List, Tuple, Union

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .data_structures import (
    AuthenticationVulnerability,
    AuthenticationAnalysisResult,
    MASTGTestType,
    AuthenticationSeverity
)

class AuthenticationAnalysisFormatter:
    """Formatter for authentication security analysis results."""
    
    def __init__(self):
        """Initialize the formatter."""
        self.severity_colors = {
            "CRITICAL": "red",
            "HIGH": "orange_red1",
            "MEDIUM": "yellow",
            "LOW": "blue"
        }
        self.severity_icons = {
            "CRITICAL": "🔴",
            "HIGH": "🟠", 
            "MEDIUM": "🟡",
            "LOW": "🔵"
        }
    
    def generate_comprehensive_report(self, vulnerabilities: List[AuthenticationVulnerability]) -> Text:
        """Generate comprehensive authentication security report."""
        report = Text()
        
        if not vulnerabilities:
            report.append("✅ AUTHENTICATION SECURITY ANALYSIS\n\n", style="bold green")
            report.append("No critical authentication security vulnerabilities detected.", style="green")
            return report
        
        # Summary
        critical_count = sum(1 for v in vulnerabilities if v.severity == "CRITICAL")
        high_count = sum(1 for v in vulnerabilities if v.severity == "HIGH")
        medium_count = sum(1 for v in vulnerabilities if v.severity == "MEDIUM")
        low_count = sum(1 for v in vulnerabilities if v.severity == "LOW")
        
        report.append("🔐 AUTHENTICATION SECURITY ANALYSIS RESULTS\n\n", style="bold red")
        report.append(f"Total Vulnerabilities: {len(vulnerabilities)}\n", style="bold")
        report.append(f"🔴 Critical: {critical_count} | 🟠 High: {high_count} | 🟡 Medium: {medium_count} | 🔵 Low: {low_count}\n\n", style="bold")
        
        # MASTG compliance status
        mastg_status = self._get_mastg_compliance_status(vulnerabilities)
        report.append("📋 MASTG COMPLIANCE STATUS\n", style="bold blue")
        for test_id, status in mastg_status.items():
            status_icon = "✅" if status else "❌"
            report.append(f"  {status_icon} {test_id}: {'PASS' if status else 'FAIL'}\n")
        report.append("\n")
        
        # Group vulnerabilities by type
        vuln_groups = self._group_vulnerabilities_by_type(vulnerabilities)
        
        # Detailed findings
        for vuln_type, vulns in vuln_groups.items():
            severity_icon = self.severity_icons.get(vulns[0].severity, "")
            report.append(f"\n{severity_icon} {vuln_type.upper().replace('_', ' ')}\n", style="bold yellow")
            report.append(f"📋 MASTG Test: {vulns[0].mastg_test_id}\n", style="blue")
            report.append(f"📊 Count: {len(vulns)} | Severity: {vulns[0].severity}\n\n", style="bold")
            
            for i, vuln in enumerate(vulns[:5], 1):  # Show first 5 instances
                report.append(f"  {i}. 📍 Location: {vuln.location}\n", style="cyan")
                report.append(f"     💻 Code: {vuln.value}\n", style="white")
                
                if vuln.secret_value:
                    report.append(f"     🔑 Secret Value: {vuln.secret_value}\n", style="red")
                
                if vuln.decoded_value:
                    report.append(f"     🔓 Decoded: {vuln.decoded_value}\n", style="green")
                
                report.append("\n")
            
            if len(vulns) > 5:
                report.append(f"     ... and {len(vulns) - 5} more instances\n\n", style="dim")
        
        # Recommendations
        report.append(self._generate_recommendations(vulnerabilities))
        
        return report
    
    def generate_summary_report(self, vulnerabilities: List[AuthenticationVulnerability]) -> Text:
        """Generate summary authentication security report."""
        report = Text()
        
        if not vulnerabilities:
            report.append("✅ Authentication security: PASS", style="green")
            return report
        
        critical_count = sum(1 for v in vulnerabilities if v.severity == "CRITICAL")
        high_count = sum(1 for v in vulnerabilities if v.severity == "HIGH")
        
        if critical_count > 0:
            report.append(f"❌ Authentication security: FAIL ({critical_count} critical, {high_count} high)", style="red")
        elif high_count > 0:
            report.append(f"⚠️ Authentication security: WARNING ({high_count} high findings)", style="yellow")
        else:
            report.append("✅ Authentication security: PASS (minor issues found)", style="green")
        
        return report
    
    def generate_json_report(self, vulnerabilities: List[AuthenticationVulnerability]) -> str:
        """Generate JSON report of authentication security findings."""
        analysis_result = AuthenticationAnalysisResult.create_from_vulnerabilities(vulnerabilities)
        
        report_data = {
            "authentication_security_analysis": {
                "summary": {
                    "total_findings": analysis_result.total_findings,
                    "critical_findings": analysis_result.critical_findings,
                    "high_findings": analysis_result.high_findings,
                    "medium_findings": analysis_result.medium_findings,
                    "low_findings": analysis_result.low_findings,
                    "mastg_compliance": analysis_result.mastg_compliance
                },
                "vulnerabilities": [
                    {
                        "type": vuln.vuln_type,
                        "severity": vuln.severity,
                        "location": vuln.location,
                        "line_number": vuln.line_number,
                        "code": vuln.value,
                        "secret_value": vuln.secret_value,
                        "decoded_value": vuln.decoded_value,
                        "mastg_test_id": vuln.mastg_test_id
                    }
                    for vuln in vulnerabilities
                ]
            }
        }
        
        return json.dumps(report_data, indent=2)
    
    def generate_statistics_table(self, vulnerabilities: List[AuthenticationVulnerability]) -> Table:
        """Generate statistics table for authentication findings."""
        table = Table(title="Authentication Security Statistics")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")
        table.add_column("Status", style="green")
        
        critical_count = sum(1 for v in vulnerabilities if v.severity == "CRITICAL")
        high_count = sum(1 for v in vulnerabilities if v.severity == "HIGH")
        medium_count = sum(1 for v in vulnerabilities if v.severity == "MEDIUM")
        low_count = sum(1 for v in vulnerabilities if v.severity == "LOW")
        
        table.add_row("Total Vulnerabilities", str(len(vulnerabilities)), "❌" if len(vulnerabilities) > 0 else "✅")
        table.add_row("Critical Issues", str(critical_count), "❌" if critical_count > 0 else "✅")
        table.add_row("High Issues", str(high_count), "⚠️" if high_count > 0 else "✅")
        table.add_row("Medium Issues", str(medium_count), "ℹ️" if medium_count > 0 else "✅")
        table.add_row("Low Issues", str(low_count), "ℹ️" if low_count > 0 else "✅")
        
        # MASTG compliance
        mastg_status = self._get_mastg_compliance_status(vulnerabilities)
        for test_id, status in mastg_status.items():
            table.add_row(f"MASTG {test_id}", "PASS" if status else "FAIL", "✅" if status else "❌")
        
        return table
    
    def generate_vulnerability_breakdown(self, vulnerabilities: List[AuthenticationVulnerability]) -> Table:
        """Generate vulnerability breakdown table."""
        table = Table(title="Vulnerability Breakdown")
        table.add_column("Vulnerability Type", style="cyan")
        table.add_column("Count", justify="right", style="magenta")
        table.add_column("Severity", style="yellow")
        table.add_column("MASTG Test", style="blue")
        
        vuln_groups = self._group_vulnerabilities_by_type(vulnerabilities)
        
        for vuln_type, vulns in sorted(vuln_groups.items()):
            severity_icon = self.severity_icons.get(vulns[0].severity, "")
            table.add_row(
                vuln_type.replace('_', ' ').title(),
                str(len(vulns)),
                f"{severity_icon} {vulns[0].severity}",
                vulns[0].mastg_test_id
            )
        
        return table
    
    def _group_vulnerabilities_by_type(self, vulnerabilities: List[AuthenticationVulnerability]) -> Dict[str, List[AuthenticationVulnerability]]:
        """Group vulnerabilities by type."""
        vuln_groups = {}
        for vuln in vulnerabilities:
            if vuln.vuln_type not in vuln_groups:
                vuln_groups[vuln.vuln_type] = []
            vuln_groups[vuln.vuln_type].append(vuln)
        return vuln_groups
    
    def _get_mastg_compliance_status(self, vulnerabilities: List[AuthenticationVulnerability]) -> Dict[str, bool]:
        """Get MASTG compliance status."""
        # Check compliance (fails if any findings exist for that test)
        mastg_status = {
            MASTGTestType.AUTH_CONFIRM_CREDENTIALS.value: True,
            MASTGTestType.AUTH_BIOMETRIC.value: True
        }
        
        for vuln in vulnerabilities:
            if vuln.mastg_test_id in mastg_status:
                mastg_status[vuln.mastg_test_id] = False
        
        return mastg_status
    
    def _generate_recommendations(self, vulnerabilities: List[AuthenticationVulnerability]) -> Text:
        """Generate security recommendations based on findings."""
        recommendations = Text()
        recommendations.append("\n🔧 SECURITY RECOMMENDATIONS\n\n", style="bold green")
        
        vuln_types = [v.vuln_type for v in vulnerabilities]
        
        if any("hardcoded" in vtype for vtype in vuln_types):
            recommendations.append("🔑 Remove all hardcoded secrets and use secure storage mechanisms\n")
        
        if any("biometric" in vtype for vtype in vuln_types):
            recommendations.append("🔐 Implement proper biometric authentication with fallback mechanisms\n")
        
        if any("session" in vtype for vtype in vuln_types):
            recommendations.append("⏱️ Implement secure session management with proper timeouts\n")
        
        if any("bypass" in vtype for vtype in vuln_types):
            recommendations.append("🚫 Remove authentication bypass logic and debug code\n")
        
        if any("keystore" in vtype for vtype in vuln_types):
            recommendations.append("🔒 Configure Android Keystore with proper authentication requirements\n")
        
        recommendations.append("\n📖 Refer to MASTG guidelines for detailed implementation guidance.\n")
        
        return recommendations
    
    def format_plugin_result(self, vulnerabilities: List[AuthenticationVulnerability]) -> Tuple[str, Union[str, Text]]:
        """Format result for plugin system."""
        if not vulnerabilities:
            return "✅ PASS", Text("No critical authentication security vulnerabilities detected.", style="green")
        
        # Generate detailed report
        report = self.generate_comprehensive_report(vulnerabilities)
        return "❌ FAIL", report 