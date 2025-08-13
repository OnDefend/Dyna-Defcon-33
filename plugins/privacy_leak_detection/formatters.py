"""
Formatters for Privacy Leak Detection
Handles report generation and visualization of privacy analysis findings.
"""

import json
from typing import Dict, List, Tuple, Union

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .data_structures import (
    PrivacyFinding,
    PrivacyAnalysisResult,
    PrivacyCategory,
    PrivacySeverity,
    MASTGPrivacyTest,
    ComplianceFramework
)

class PrivacyAnalysisFormatter:
    """Formatter for privacy analysis results."""
    
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
    
    def generate_comprehensive_report(self, findings: List[PrivacyFinding]) -> Text:
        """Generate comprehensive privacy analysis report."""
        report = Text()
        
        if not findings:
            report.append("✅ PRIVACY LEAK ANALYSIS\n\n", style="bold green")
            report.append("No privacy vulnerabilities detected.", style="green")
            return report
        
        # Summary
        result = PrivacyAnalysisResult.create_from_findings(findings)
        
        report.append("🔒 PRIVACY LEAK DETECTION RESULTS\n\n", style="bold red")
        report.append(f"Privacy Score: {result.privacy_score:.1f}/100\n", style="bold")
        report.append(f"Total Issues: {result.total_issues}\n", style="bold")
        report.append(f"🔴 Critical: {result.critical_issues} | 🟠 High: {result.high_issues} | 🟡 Medium: {result.medium_issues} | 🔵 Low: {result.low_issues}\n\n", style="bold")
        
        # MASTG compliance status
        report.append("📋 MASTG COMPLIANCE STATUS\n", style="bold blue")
        for test_id, status in result.masvs_compliance.items():
            status_icon = "✅" if status else "❌"
            report.append(f"  {status_icon} {test_id}: {'PASS' if status else 'FAIL'}\n")
        report.append("\n")
        
        # Compliance framework status
        report.append("🏛️ COMPLIANCE FRAMEWORK STATUS\n", style="bold blue")
        for framework, status in result.compliance_frameworks.items():
            status_color = "green" if status == "COMPLIANT" else "red" if status == "HIGH_RISK" else "yellow"
            report.append(f"  {framework.value}: {status}\n", style=status_color)
        report.append("\n")
        
        # Group findings by category
        findings_by_category = self._group_findings_by_category(findings)
        
        # Detailed findings
        for category, category_findings in findings_by_category.items():
            report.append(f"\n{category.value} ANALYSIS\n", style="bold cyan")
            report.append("─" * 40 + "\n", style="cyan")
            
            for finding in category_findings[:5]:  # Show first 5 per category
                severity_icon = self.severity_icons.get(finding.severity.value, "")
                report.append(f"{severity_icon} {finding.title}\n", style="bold")
                
                if finding.description:
                    report.append(f"   📄 {finding.description}\n", style="dim")
                
                if finding.evidence:
                    report.append(f"   🔍 Evidence: {finding.evidence[0]}\n", style="cyan")
                
                if finding.recommendations:
                    report.append(f"   💡 {finding.recommendations[0]}\n", style="yellow")
                
                report.append("\n")
            
            if len(category_findings) > 5:
                report.append(f"   ... and {len(category_findings) - 5} more {category.value.lower()} issues\n\n", style="dim")
        
        return report
    
    def generate_summary_report(self, findings: List[PrivacyFinding]) -> Text:
        """Generate summary privacy analysis report."""
        report = Text()
        
        if not findings:
            report.append("✅ Privacy analysis: PASS", style="green")
            return report
        
        result = PrivacyAnalysisResult.create_from_findings(findings)
        
        if result.critical_issues > 0:
            report.append(f"❌ Privacy analysis: FAIL ({result.critical_issues} critical, {result.high_issues} high)", style="red")
        elif result.high_issues > 0:
            report.append(f"⚠️ Privacy analysis: WARNING ({result.high_issues} high findings)", style="yellow")
        else:
            report.append(f"✅ Privacy analysis: PASS (Score: {result.privacy_score:.1f}/100)", style="green")
        
        return report
    
    def generate_json_report(self, findings: List[PrivacyFinding]) -> str:
        """Generate JSON report of privacy analysis findings."""
        result = PrivacyAnalysisResult.create_from_findings(findings)
        
        report_data = {
            "privacy_leak_analysis": {
                "summary": {
                    "privacy_score": result.privacy_score,
                    "total_findings": result.total_issues,
                    "critical_findings": result.critical_issues,
                    "high_findings": result.high_issues,
                    "medium_findings": result.medium_issues,
                    "low_findings": result.low_issues,
                    "mastg_compliance": result.masvs_compliance,
                    "compliance_frameworks": {
                        framework.value: status for framework, status in result.compliance_frameworks.items()
                    }
                },
                "findings": [
                    {
                        "id": finding.finding_id,
                        "category": finding.category.value,
                        "data_types": [dt.value for dt in finding.data_types],
                        "severity": finding.severity.value,
                        "title": finding.title,
                        "description": finding.description,
                        "evidence": finding.evidence,
                        "affected_components": finding.affected_components,
                        "mastg_test_id": finding.mastg_test_id.value,
                        "recommendations": finding.recommendations,
                        "confidence": finding.confidence,
                        "file_path": finding.file_path,
                        "line_number": finding.line_number,
                        "risk_score": finding.risk_factors.overall_risk_score,
                        "compliance_impacts": [
                            {
                                "framework": ci.framework.value,
                                "impact_level": ci.impact_level,
                                "description": ci.description,
                                "required_actions": ci.required_actions
                            }
                            for ci in finding.compliance_impacts
                        ]
                    }
                    for finding in findings
                ]
            }
        }
        
        return json.dumps(report_data, indent=2)
    
    def generate_statistics_table(self, findings: List[PrivacyFinding]) -> Table:
        """Generate statistics table for privacy findings."""
        table = Table(title="Privacy Analysis Statistics")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")
        table.add_column("Status", style="green")
        
        result = PrivacyAnalysisResult.create_from_findings(findings)
        
        table.add_row("Privacy Score", f"{result.privacy_score:.1f}/100", 
                     "✅" if result.privacy_score >= 80 else "⚠️" if result.privacy_score >= 60 else "❌")
        table.add_row("Total Issues", str(result.total_issues), "❌" if result.total_issues > 0 else "✅")
        table.add_row("Critical Issues", str(result.critical_issues), "❌" if result.critical_issues > 0 else "✅")
        table.add_row("High Issues", str(result.high_issues), "⚠️" if result.high_issues > 0 else "✅")
        table.add_row("Medium Issues", str(result.medium_issues), "ℹ️" if result.medium_issues > 0 else "✅")
        table.add_row("Low Issues", str(result.low_issues), "ℹ️" if result.low_issues > 0 else "✅")
        
        # MASTG compliance
        for test_id, status in result.masvs_compliance.items():
            table.add_row(f"MASTG {test_id}", "PASS" if status else "FAIL", "✅" if status else "❌")
        
        return table
    
    def generate_category_breakdown(self, findings: List[PrivacyFinding]) -> Table:
        """Generate category breakdown table."""
        table = Table(title="Privacy Category Breakdown")
        table.add_column("Category", style="cyan")
        table.add_column("Count", justify="right", style="magenta")
        table.add_column("Avg Severity", style="yellow")
        table.add_column("Risk Level", style="red")
        
        findings_by_category = self._group_findings_by_category(findings)
        
        for category, category_findings in sorted(findings_by_category.items()):
            count = len(category_findings)
            
            # Calculate average severity
            severity_scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            avg_severity_score = sum(severity_scores[f.severity.value] for f in category_findings) / count
            avg_severity = "CRITICAL" if avg_severity_score >= 3.5 else "HIGH" if avg_severity_score >= 2.5 else "MEDIUM" if avg_severity_score >= 1.5 else "LOW"
            
            # Calculate risk level
            avg_risk_score = sum(f.risk_factors.overall_risk_score for f in category_findings) / count
            risk_level = "HIGH" if avg_risk_score >= 0.7 else "MEDIUM" if avg_risk_score >= 0.4 else "LOW"
            
            severity_icon = self.severity_icons.get(avg_severity, "")
            
            table.add_row(
                category.value,
                str(count),
                f"{severity_icon} {avg_severity}",
                risk_level
            )
        
        return table
    
    def generate_compliance_summary(self, findings: List[PrivacyFinding]) -> Table:
        """Generate compliance summary table."""
        table = Table(title="Compliance Framework Summary")
        table.add_column("Framework", style="cyan")
        table.add_column("Status", style="magenta")
        table.add_column("Risk Level", style="yellow")
        table.add_column("Issues", justify="right", style="red")
        
        result = PrivacyAnalysisResult.create_from_findings(findings)
        
        for framework, status in result.compliance_frameworks.items():
            # Count issues for this framework
            framework_issues = sum(1 for f in findings 
                                 if any(ci.framework == framework for ci in f.compliance_impacts))
            
            status_color = "green" if status == "COMPLIANT" else "red" if status == "HIGH_RISK" else "yellow"
            
            table.add_row(
                framework.value,
                status,
                status,
                str(framework_issues)
            )
        
        return table
    
    def _group_findings_by_category(self, findings: List[PrivacyFinding]) -> Dict[PrivacyCategory, List[PrivacyFinding]]:
        """Group findings by category."""
        grouped = {}
        for finding in findings:
            if finding.category not in grouped:
                grouped[finding.category] = []
            grouped[finding.category].append(finding)
        return grouped
    
    def format_plugin_result(self, findings: List[PrivacyFinding]) -> Tuple[str, Union[str, Text]]:
        """Format result for plugin system."""
        if not findings:
            return "✅ PASS", Text("No privacy vulnerabilities detected.", style="green")
        
        # Generate comprehensive report
        report = self.generate_comprehensive_report(findings)
        
        # Determine overall status
        result = PrivacyAnalysisResult.create_from_findings(findings)
        if result.critical_issues > 0:
            status = "❌ FAIL"
        elif result.high_issues > 0:
            status = "⚠️ WARNING"
        else:
            status = "✅ PASS"
        
        return status, report 