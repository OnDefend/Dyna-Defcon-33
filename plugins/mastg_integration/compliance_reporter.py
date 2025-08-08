#!/usr/bin/env python3
"""
MASTG Compliance Reporter Module

Provides comprehensive compliance reporting and visualization for MASTG test results.
Generates detailed reports with MASVS mapping, risk assessment, and remediation guidance.

Features:
- Comprehensive MASTG compliance reporting
- MASVS control mapping and coverage analysis
- Rich text formatting and visualization
- Risk assessment and scoring
- Export capabilities (JSON, XML, CSV)
- Executive summary generation
- Detailed technical findings presentation
"""

import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import logging

from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.console import Console

from .data_structures import (
    MASTGTestExecution, MASTGConfiguration, MASTGComplianceSummary,
    MASTGTestStatus, MASTGRiskLevel, MASTGCategory, MASTGFinding
)

class MASTGComplianceReporter:
    """
    Comprehensive MASTG compliance reporter with advanced visualization.
    
    Generates detailed compliance reports with MASVS mapping, risk assessment,
    and remediation guidance using Rich text formatting and multiple export formats.
    """
    
    def __init__(self, config: MASTGConfiguration):
        """Initialize the compliance reporter with configuration."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.console = Console(record=True, width=100)
        
        # MASVS control definitions
        self._masvs_controls = self._initialize_masvs_controls()
        
        # Risk scoring weights
        self._risk_weights = {
            MASTGRiskLevel.CRITICAL: 10,
            MASTGRiskLevel.HIGH: 7,
            MASTGRiskLevel.MEDIUM: 4,
            MASTGRiskLevel.LOW: 2,
            MASTGRiskLevel.INFO: 1,
            MASTGRiskLevel.UNKNOWN: 0
        }
        
        self.logger.info("MASTG Compliance Reporter initialized")
    
    def _initialize_masvs_controls(self) -> Dict[str, Dict[str, str]]:
        """Initialize MASVS control definitions and descriptions."""
        return {
            # MSTG-STORAGE controls
            "MSTG-STORAGE-1": {
                "title": "Sensitive Data Storage",
                "description": "The app does not store sensitive data in publicly accessible locations."
            },
            "MSTG-STORAGE-2": {
                "title": "Encryption of Sensitive Data", 
                "description": "Sensitive data is encrypted when stored."
            },
            "MSTG-STORAGE-3": {
                "title": "Log File Security",
                "description": "Sensitive data is not written to application logs."
            },
            
            # MSTG-CRYPTO controls
            "MSTG-CRYPTO-1": {
                "title": "Cryptographic Standards",
                "description": "The app uses strong, standard cryptographic algorithms."
            },
            "MSTG-CRYPTO-2": {
                "title": "Key Management",
                "description": "Cryptographic keys are managed securely."
            },
            "MSTG-CRYPTO-5": {
                "title": "Key Derivation",
                "description": "Cryptographic keys are derived using appropriate key derivation functions."
            },
            "MSTG-CRYPTO-6": {
                "title": "Random Number Generation",
                "description": "Cryptographically secure random number generators are used."
            },
            
            # MSTG-AUTH controls
            "MSTG-AUTH-1": {
                "title": "Authentication Mechanisms",
                "description": "Authentication mechanisms are properly implemented."
            },
            "MSTG-AUTH-2": {
                "title": "Session Management",
                "description": "Sessions are managed securely."
            },
            "MSTG-AUTH-8": {
                "title": "Biometric Authentication",
                "description": "Biometric authentication is implemented securely."
            },
            "MSTG-AUTH-9": {
                "title": "Biometric Policy",
                "description": "Biometric authentication policies are properly configured."
            },
            
            # MSTG-NETWORK controls
            "MSTG-NETWORK-1": {
                "title": "Network Communication",
                "description": "Network communication uses secure protocols."
            },
            "MSTG-NETWORK-2": {
                "title": "Certificate Validation",
                "description": "TLS certificates are properly validated."
            },
            "MSTG-NETWORK-3": {
                "title": "Certificate Pinning",
                "description": "Certificate pinning is implemented where appropriate."
            },
            "MSTG-NETWORK-4": {
                "title": "Network Security Configuration",
                "description": "Network security configuration is properly implemented."
            },
            
            # MSTG-PLATFORM controls
            "MSTG-PLATFORM-1": {
                "title": "App Permissions",
                "description": "The app uses platform permissions appropriately."
            },
            "MSTG-PLATFORM-3": {
                "title": "Deep Links",
                "description": "Deep links and custom URL schemes are handled securely."
            },
            "MSTG-PLATFORM-11": {
                "title": "Platform Interaction",
                "description": "Platform interaction mechanisms are secure."
            },
            
            # MSTG-CODE controls
            "MSTG-CODE-2": {
                "title": "Code Quality",
                "description": "Code quality meets security standards."
            },
            "MSTG-CODE-4": {
                "title": "Build Configuration",
                "description": "Build configuration is secure for production."
            },
            "MSTG-CODE-8": {
                "title": "Memory Corruption",
                "description": "Memory corruption vulnerabilities are mitigated."
            },
            
            # MSTG-RESILIENCE controls
            "MSTG-RESILIENCE-1": {
                "title": "Root Detection",
                "description": "Root detection mechanisms are implemented appropriately."
            },
            "MSTG-RESILIENCE-2": {
                "title": "Anti-Debugging",
                "description": "Anti-debugging mechanisms are implemented appropriately."
            }
        }
    
    def generate_compliance_report(self, executions: List[MASTGTestExecution]) -> Text:
        """
        Generate comprehensive MASTG compliance report.
        
        Args:
            executions: List of test execution results
            
        Returns:
            Rich Text report with comprehensive analysis
        """
        self.logger.info(f"Generating compliance report for {len(executions)} test executions")
        
        # Create compliance summary
        summary = self._create_compliance_summary(executions)
        
        # Build comprehensive report
        report = Text()
        
        # Report header
        report.append("MASTG COMPLIANCE ANALYSIS REPORT\n", style="bold blue")
        report.append("=" * 80 + "\n", style="blue")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n", style="white")
        
        # Executive summary
        report.append(self._generate_executive_summary(summary))
        
        # Test execution overview
        report.append(self._generate_execution_overview(executions))
        
        # MASVS compliance analysis
        report.append(self._generate_masvs_compliance_analysis(executions, summary))
        
        # Risk assessment
        report.append(self._generate_risk_assessment(executions, summary))
        
        # Category analysis
        report.append(self._generate_category_analysis(executions))
        
        # Detailed findings
        if self.config.detailed_reporting:
            report.append(self._generate_detailed_findings(executions))
        
        # Recommendations
        report.append(self._generate_recommendations(executions, summary))
        
        # Technical appendix
        report.append(self._generate_technical_appendix(executions))
        
        self.logger.info("Compliance report generated successfully")
        return report
    
    def _create_compliance_summary(self, executions: List[MASTGTestExecution]) -> MASTGComplianceSummary:
        """Create comprehensive compliance summary from execution results."""
        # Calculate basic metrics
        total_tests = len(executions)
        executed_tests = len([e for e in executions if e.status != MASTGTestStatus.SKIPPED])
        passed_tests = len([e for e in executions if e.status == MASTGTestStatus.PASSED])
        failed_tests = len([e for e in executions if e.status == MASTGTestStatus.FAILED])
        error_tests = len([e for e in executions if e.status == MASTGTestStatus.ERROR])
        skipped_tests = len([e for e in executions if e.status == MASTGTestStatus.SKIPPED])
        
        # Calculate risk findings
        all_findings = [finding for execution in executions for finding in execution.findings]
        critical_findings = len([f for f in all_findings if f.risk_level == MASTGRiskLevel.CRITICAL])
        high_findings = len([f for f in all_findings if f.risk_level == MASTGRiskLevel.HIGH])
        medium_findings = len([f for f in all_findings if f.risk_level == MASTGRiskLevel.MEDIUM])
        low_findings = len([f for f in all_findings if f.risk_level == MASTGRiskLevel.LOW])
        info_findings = len([f for f in all_findings if f.risk_level == MASTGRiskLevel.INFO])
        
        # MASVS control analysis
        masvs_controls_tested = set()
        masvs_controls_passed = set()
        masvs_controls_failed = set()
        
        for execution in executions:
            for control in execution.test_case.masvs_controls:
                masvs_controls_tested.add(control)
                if execution.status == MASTGTestStatus.PASSED and not execution.findings:
                    masvs_controls_passed.add(control)
                elif execution.findings or execution.status == MASTGTestStatus.FAILED:
                    masvs_controls_failed.add(control)
        
        # Execution timing
        execution_times = [e.execution_duration for e in executions if e.execution_duration]
        total_execution_time = sum(execution_times) if execution_times else 0
        average_test_time = total_execution_time / len(execution_times) if execution_times else 0
        
        # Plugin availability
        plugin_availability = {}
        for execution in executions:
            if execution.plugin_used:
                plugin_availability[execution.plugin_used] = True
        
        # Overall compliance score
        total_risk_score = sum(self._risk_weights.get(f.risk_level, 0) for f in all_findings)
        max_possible_score = total_tests * self._risk_weights[MASTGRiskLevel.CRITICAL]
        compliance_score = max(0, 100 - (total_risk_score / max_possible_score * 100)) if max_possible_score > 0 else 100
        
        # Compliance level
        if compliance_score >= 90:
            compliance_level = "EXCELLENT"
        elif compliance_score >= 75:
            compliance_level = "GOOD"
        elif compliance_score >= 60:
            compliance_level = "FAIR"
        else:
            compliance_level = "POOR"
        
        # Category results
        category_results = self._analyze_by_category(executions)
        
        return MASTGComplianceSummary(
            total_tests=total_tests,
            executed_tests=executed_tests,
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            error_tests=error_tests,
            skipped_tests=skipped_tests,
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=low_findings,
            info_findings=info_findings,
            masvs_controls_tested=list(masvs_controls_tested),
            masvs_controls_passed=list(masvs_controls_passed),
            masvs_controls_failed=list(masvs_controls_failed),
            total_execution_time=total_execution_time,
            average_test_time=average_test_time,
            plugin_availability=plugin_availability,
            overall_compliance_score=compliance_score,
            compliance_level=compliance_level,
            recommendation_summary=[],
            category_results=category_results
        )
    
    def _generate_executive_summary(self, summary: MASTGComplianceSummary) -> Text:
        """Generate executive summary section."""
        section = Text()
        section.append("EXECUTIVE SUMMARY\n", style="bold yellow")
        section.append("-" * 40 + "\n\n", style="yellow")
        
        # Overall compliance status
        style = "green" if summary.compliance_level in ["EXCELLENT", "GOOD"] else \
                "yellow" if summary.compliance_level == "FAIR" else "red"
        
        section.append(f"Overall Compliance Level: ", style="white")
        section.append(f"{summary.compliance_level}", style=f"bold {style}")
        section.append(f" ({summary.overall_compliance_score:.1f}%)\n\n", style=style)
        
        # Key metrics
        section.append("Key Metrics:\n", style="bold white")
        section.append(f"• Total Tests Executed: {summary.executed_tests}/{summary.total_tests}\n")
        section.append(f"• Success Rate: {(summary.passed_tests/summary.executed_tests*100):.1f}%\n" if summary.executed_tests > 0 else "• Success Rate: N/A\n")
        section.append(f"• MASVS Controls Tested: {len(summary.masvs_controls_tested)}\n")
        section.append(f"• Total Security Findings: {summary.critical_findings + summary.high_findings + summary.medium_findings + summary.low_findings}\n")
        
        # Risk breakdown
        if summary.critical_findings > 0:
            section.append(f"• Critical Risk Findings: {summary.critical_findings}\n", style="red")
        if summary.high_findings > 0:
            section.append(f"• High Risk Findings: {summary.high_findings}\n", style="red")
        if summary.medium_findings > 0:
            section.append(f"• Medium Risk Findings: {summary.medium_findings}\n", style="yellow")
        if summary.low_findings > 0:
            section.append(f"• Low Risk Findings: {summary.low_findings}\n", style="green")
        
        section.append("\n")
        return section
    
    def _generate_execution_overview(self, executions: List[MASTGTestExecution]) -> Text:
        """Generate test execution overview section."""
        section = Text()
        section.append("TEST EXECUTION OVERVIEW\n", style="bold cyan")
        section.append("-" * 40 + "\n\n", style="cyan")
        
        # Create execution status table
        table = Table(title="Test Execution Summary")
        table.add_column("Test ID", style="cyan")
        table.add_column("Category", style="blue")
        table.add_column("Status", style="white")
        table.add_column("Duration", style="yellow")
        table.add_column("Findings", style="red")
        table.add_column("Plugin", style="green")
        
        for execution in executions:
            status_style = "green" if execution.status == MASTGTestStatus.PASSED else \
                          "red" if execution.status == MASTGTestStatus.FAILED else \
                          "yellow" if execution.status == MASTGTestStatus.ERROR else "white"
            
            duration = f"{execution.execution_duration:.1f}s" if execution.execution_duration else "N/A"
            findings_count = len(execution.findings)
            plugin_name = execution.plugin_used or "Custom"
            
            table.add_row(
                execution.test_case.test_id,
                execution.test_case.category.value,
                f"[{status_style}]{execution.status.value}[/{status_style}]",
                duration,
                str(findings_count) if findings_count > 0 else "-",
                plugin_name
            )
        
        # Convert table to text (simplified representation)
        section.append("Test Execution Results:\n", style="bold white")
        for execution in executions:
            status_symbol = "✓" if execution.status == MASTGTestStatus.PASSED else \
                           "✗" if execution.status == MASTGTestStatus.FAILED else \
                           "!" if execution.status == MASTGTestStatus.ERROR else "⚠"
            
            section.append(f"{status_symbol} {execution.test_case.test_id} - {execution.status.value}")
            if execution.findings:
                section.append(f" ({len(execution.findings)} findings)", style="red")
            section.append("\n")
        
        section.append("\n")
        return section
    
    def _generate_masvs_compliance_analysis(self, executions: List[MASTGTestExecution], 
                                          summary: MASTGComplianceSummary) -> Text:
        """Generate MASVS compliance analysis section."""
        section = Text()
        section.append("MASVS COMPLIANCE ANALYSIS\n", style="bold magenta")
        section.append("-" * 40 + "\n\n", style="magenta")
        
        # MASVS coverage overview
        total_masvs_controls = len(self._masvs_controls)
        tested_controls = len(summary.masvs_controls_tested)
        passed_controls = len(summary.masvs_controls_passed)
        
        section.append(f"MASVS Coverage: {tested_controls}/{total_masvs_controls} controls tested\n")
        section.append(f"Passed Controls: {passed_controls}/{tested_controls}\n")
        
        # Detailed control analysis
        section.append("\nDetailed Control Analysis:\n", style="bold white")
        
        for control in summary.masvs_controls_tested:
            control_info = self._masvs_controls.get(control, {"title": "Unknown", "description": "No description"})
            
            if control in summary.masvs_controls_passed:
                status = "✓ PASSED"
                style = "green"
            elif control in summary.masvs_controls_failed:
                status = "✗ FAILED"
                style = "red"
            else:
                status = "⚠ UNKNOWN"
                style = "yellow"
            
            section.append(f"• {control}: {control_info['title']} - ", style="white")
            section.append(f"{status}\n", style=style)
        
        # Failed controls with recommendations
        if summary.masvs_controls_failed:
            section.append("\nFailed Controls Requiring Attention:\n", style="bold red")
            for control in summary.masvs_controls_failed:
                control_info = self._masvs_controls.get(control, {"title": "Unknown", "description": "No description"})
                section.append(f"• {control}: {control_info['title']}\n", style="red")
                section.append(f"  Description: {control_info['description']}\n", style="white")
        
        section.append("\n")
        return section
    
    def _generate_risk_assessment(self, executions: List[MASTGTestExecution],
                                 summary: MASTGComplianceSummary) -> Text:
        """Generate risk assessment section."""
        section = Text()
        section.append("RISK ASSESSMENT\n", style="bold red")
        section.append("-" * 40 + "\n\n", style="red")
        
        # Risk distribution
        total_findings = summary.critical_findings + summary.high_findings + summary.medium_findings + summary.low_findings
        
        if total_findings > 0:
            section.append("Risk Distribution:\n", style="bold white")
            section.append(f"• Critical: {summary.critical_findings} ({summary.critical_findings/total_findings*100:.1f}%)\n", style="red")
            section.append(f"• High: {summary.high_findings} ({summary.high_findings/total_findings*100:.1f}%)\n", style="red")
            section.append(f"• Medium: {summary.medium_findings} ({summary.medium_findings/total_findings*100:.1f}%)\n", style="yellow")
            section.append(f"• Low: {summary.low_findings} ({summary.low_findings/total_findings*100:.1f}%)\n", style="green")
            
            # Risk score calculation
            total_risk_score = (
                summary.critical_findings * self._risk_weights[MASTGRiskLevel.CRITICAL] +
                summary.high_findings * self._risk_weights[MASTGRiskLevel.HIGH] +
                summary.medium_findings * self._risk_weights[MASTGRiskLevel.MEDIUM] +
                summary.low_findings * self._risk_weights[MASTGRiskLevel.LOW]
            )
            
            section.append(f"\nTotal Risk Score: {total_risk_score}\n", style="bold white")
            
            # Risk recommendations
            section.append("\nRisk Mitigation Priorities:\n", style="bold yellow")
            if summary.critical_findings > 0:
                section.append("1. Address CRITICAL findings immediately - these pose severe security risks\n", style="red")
            if summary.high_findings > 0:
                section.append("2. Resolve HIGH risk findings in next development cycle\n", style="red")
            if summary.medium_findings > 0:
                section.append("3. Plan remediation for MEDIUM risk findings\n", style="yellow")
            if summary.low_findings > 0:
                section.append("4. Consider addressing LOW risk findings for security hardening\n", style="green")
        else:
            section.append("No security findings identified.\n", style="green")
        
        section.append("\n")
        return section
    
    def _generate_category_analysis(self, executions: List[MASTGTestExecution]) -> Text:
        """Generate category-based analysis section."""
        section = Text()
        section.append("CATEGORY ANALYSIS\n", style="bold blue")
        section.append("-" * 40 + "\n\n", style="blue")
        
        category_results = self._analyze_by_category(executions)
        
        for category, results in category_results.items():
            section.append(f"{category} Security:\n", style="bold white")
            section.append(f"• Tests: {results['total_tests']}\n")
            section.append(f"• Passed: {results['passed']}\n", style="green")
            section.append(f"• Failed: {results['failed']}\n", style="red" if results['failed'] > 0 else "white")
            section.append(f"• Findings: {results['total_findings']}\n", style="red" if results['total_findings'] > 0 else "green")
            
            if results['recommendations']:
                section.append("  Recommendations:\n", style="yellow")
                for rec in results['recommendations']:
                    section.append(f"    - {rec}\n", style="white")
            
            section.append("\n")
        
        return section
    
    def _generate_detailed_findings(self, executions: List[MASTGTestExecution]) -> Text:
        """Generate detailed findings section."""
        section = Text()
        section.append("DETAILED FINDINGS\n", style="bold red")
        section.append("-" * 40 + "\n\n", style="red")
        
        all_findings = []
        for execution in executions:
            for finding in execution.findings:
                all_findings.append((execution.test_case.test_id, finding))
        
        # Sort findings by risk level
        risk_order = [MASTGRiskLevel.CRITICAL, MASTGRiskLevel.HIGH, MASTGRiskLevel.MEDIUM, MASTGRiskLevel.LOW, MASTGRiskLevel.INFO]
        all_findings.sort(key=lambda x: risk_order.index(x[1].risk_level) if x[1].risk_level in risk_order else 999)
        
        for test_id, finding in all_findings:
            risk_style = "red" if finding.risk_level in [MASTGRiskLevel.CRITICAL, MASTGRiskLevel.HIGH] else \
                        "yellow" if finding.risk_level == MASTGRiskLevel.MEDIUM else "green"
            
            section.append(f"Finding: {finding.title}\n", style="bold white")
            section.append(f"Test: {test_id}\n", style="cyan")
            section.append(f"Risk Level: {finding.risk_level.value}\n", style=risk_style)
            section.append(f"Confidence: {finding.confidence_score:.2f}\n", style="white")
            section.append(f"Description: {finding.description}\n", style="white")
            
            if finding.remediation_guidance:
                section.append(f"Remediation: {finding.remediation_guidance}\n", style="yellow")
            
            section.append("\n")
        
        return section
    
    def _generate_recommendations(self, executions: List[MASTGTestExecution],
                                summary: MASTGComplianceSummary) -> Text:
        """Generate recommendations section."""
        section = Text()
        section.append("RECOMMENDATIONS\n", style="bold green")
        section.append("-" * 40 + "\n\n", style="green")
        
        recommendations = []
        
        # Risk-based recommendations
        if summary.critical_findings > 0:
            recommendations.append("IMMEDIATE: Address all critical security findings before production deployment")
        
        if summary.high_findings > 0:
            recommendations.append("HIGH PRIORITY: Resolve high-risk vulnerabilities in next development cycle")
        
        # MASVS compliance recommendations
        if len(summary.masvs_controls_failed) > 0:
            recommendations.append(f"Improve MASVS compliance by addressing {len(summary.masvs_controls_failed)} failed controls")
        
        # Category-specific recommendations
        category_results = self._analyze_by_category(executions)
        for category, results in category_results.items():
            if results['failed'] > 0:
                recommendations.append(f"Enhance {category.lower()} security implementation")
        
        # General recommendations
        if summary.executed_tests < summary.total_tests:
            recommendations.append("Ensure all MASTG tests can be executed successfully")
        
        recommendations.append("Implement continuous security testing in CI/CD pipeline")
        recommendations.append("Regular security code reviews with MASTG compliance focus")
        
        for i, rec in enumerate(recommendations, 1):
            section.append(f"{i}. {rec}\n", style="white")
        
        section.append("\n")
        return section
    
    def _generate_technical_appendix(self, executions: List[MASTGTestExecution]) -> Text:
        """Generate technical appendix section."""
        section = Text()
        section.append("TECHNICAL APPENDIX\n", style="bold white")
        section.append("-" * 40 + "\n\n", style="white")
        
        # Plugin usage statistics
        plugin_usage = {}
        for execution in executions:
            if execution.plugin_used:
                plugin_usage[execution.plugin_used] = plugin_usage.get(execution.plugin_used, 0) + 1
        
        if plugin_usage:
            section.append("Plugin Usage Statistics:\n", style="bold white")
            for plugin, count in plugin_usage.items():
                section.append(f"• {plugin}: {count} tests\n")
            section.append("\n")
        
        # Execution timing analysis
        execution_times = [e.execution_duration for e in executions if e.execution_duration]
        if execution_times:
            avg_time = sum(execution_times) / len(execution_times)
            max_time = max(execution_times)
            min_time = min(execution_times)
            
            section.append("Execution Timing Analysis:\n", style="bold white")
            section.append(f"• Average execution time: {avg_time:.2f}s\n")
            section.append(f"• Maximum execution time: {max_time:.2f}s\n")
            section.append(f"• Minimum execution time: {min_time:.2f}s\n")
            section.append("\n")
        
        # Test coverage analysis
        section.append("Test Coverage Analysis:\n", style="bold white")
        category_coverage = {}
        for execution in executions:
            category = execution.test_case.category.value
            category_coverage[category] = category_coverage.get(category, 0) + 1
        
        for category, count in category_coverage.items():
            section.append(f"• {category}: {count} tests\n")
        
        section.append("\n")
        return section
    
    def _analyze_by_category(self, executions: List[MASTGTestExecution]) -> Dict[str, Dict[str, Any]]:
        """Analyze test results by category."""
        category_results = {}
        
        for execution in executions:
            category = execution.test_case.category.value
            
            if category not in category_results:
                category_results[category] = {
                    "total_tests": 0,
                    "passed": 0,
                    "failed": 0,
                    "total_findings": 0,
                    "critical_findings": 0,
                    "high_findings": 0,
                    "recommendations": []
                }
            
            results = category_results[category]
            results["total_tests"] += 1
            
            if execution.status == MASTGTestStatus.PASSED:
                results["passed"] += 1
            else:
                results["failed"] += 1
            
            results["total_findings"] += len(execution.findings)
            
            for finding in execution.findings:
                if finding.risk_level == MASTGRiskLevel.CRITICAL:
                    results["critical_findings"] += 1
                elif finding.risk_level == MASTGRiskLevel.HIGH:
                    results["high_findings"] += 1
        
        # Add category-specific recommendations
        for category, results in category_results.items():
            if results["critical_findings"] > 0:
                results["recommendations"].append(f"Critical {category.lower()} vulnerabilities require immediate attention")
            if results["failed"] > results["passed"]:
                results["recommendations"].append(f"Improve {category.lower()} security implementation")
        
        return category_results
    
    def export_results(self, executions: List[MASTGTestExecution], output_path: Path):
        """Export test results to specified format."""
        try:
            if self.config.export_format == "json":
                self._export_json(executions, output_path)
            elif self.config.export_format == "xml":
                self._export_xml(executions, output_path)
            elif self.config.export_format == "csv":
                self._export_csv(executions, output_path)
            else:
                self.logger.warning(f"Unsupported export format: {self.config.export_format}")
                
        except Exception as e:
            self.logger.error(f"Failed to export results: {e}")
    
    def _export_json(self, executions: List[MASTGTestExecution], output_path: Path):
        """Export results to JSON format."""
        data = {
            "mastg_compliance_report": {
                "generated_at": datetime.now().isoformat(),
                "summary": self._create_compliance_summary(executions).__dict__,
                "test_executions": [
                    {
                        "test_id": exec.test_case.test_id,
                        "test_title": exec.test_case.title,
                        "category": exec.test_case.category.value,
                        "status": exec.status.value,
                        "execution_time": exec.execution_duration,
                        "plugin_used": exec.plugin_used,
                        "findings": [
                            {
                                "finding_id": finding.finding_id,
                                "title": finding.title,
                                "description": finding.description,
                                "risk_level": finding.risk_level.value,
                                "confidence_score": finding.confidence_score
                            } for finding in exec.findings
                        ]
                    } for exec in executions
                ]
            }
        }
        
        with open(output_path.with_suffix('.json'), 'w') as f:
            json.dump(data, f, indent=2)
    
    def _export_xml(self, executions: List[MASTGTestExecution], output_path: Path):
        """Export results to XML format."""
        root = ET.Element("mastg_compliance_report")
        root.set("generated_at", datetime.now().isoformat())
        
        # Summary section
        summary = self._create_compliance_summary(executions)
        summary_elem = ET.SubElement(root, "summary")
        ET.SubElement(summary_elem, "total_tests").text = str(summary.total_tests)
        ET.SubElement(summary_elem, "passed_tests").text = str(summary.passed_tests)
        ET.SubElement(summary_elem, "failed_tests").text = str(summary.failed_tests)
        ET.SubElement(summary_elem, "compliance_score").text = str(summary.overall_compliance_score)
        
        # Test executions section
        executions_elem = ET.SubElement(root, "test_executions")
        for execution in executions:
            exec_elem = ET.SubElement(executions_elem, "test_execution")
            exec_elem.set("test_id", execution.test_case.test_id)
            exec_elem.set("status", execution.status.value)
            
            ET.SubElement(exec_elem, "title").text = execution.test_case.title
            ET.SubElement(exec_elem, "category").text = execution.test_case.category.value
            
            if execution.findings:
                findings_elem = ET.SubElement(exec_elem, "findings")
                for finding in execution.findings:
                    finding_elem = ET.SubElement(findings_elem, "finding")
                    finding_elem.set("risk_level", finding.risk_level.value)
                    ET.SubElement(finding_elem, "title").text = finding.title
                    ET.SubElement(finding_elem, "description").text = finding.description
        
        # Write XML file
        tree = ET.ElementTree(root)
        tree.write(output_path.with_suffix('.xml'), encoding='utf-8', xml_declaration=True)
    
    def _export_csv(self, executions: List[MASTGTestExecution], output_path: Path):
        """Export results to CSV format."""
        with open(output_path.with_suffix('.csv'), 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Header
            writer.writerow([
                'Test ID', 'Title', 'Category', 'Status', 'Execution Time',
                'Plugin Used', 'Findings Count', 'Highest Risk Level'
            ])
            
            # Data rows
            for execution in executions:
                highest_risk = execution.get_highest_risk_level().value if execution.findings else 'NONE'
                
                writer.writerow([
                    execution.test_case.test_id,
                    execution.test_case.title,
                    execution.test_case.category.value,
                    execution.status.value,
                    execution.execution_duration or 0,
                    execution.plugin_used or '',
                    len(execution.findings),
                    highest_risk
                ])
    
    def get_compliance_summary(self, executions: List[MASTGTestExecution]) -> Dict[str, Any]:
        """Get compliance summary for programmatic access."""
        summary = self._create_compliance_summary(executions)
        return summary.__dict__ 