#!/usr/bin/env python3
"""
Advanced Reporting Dashboard for AODS
Executive-level threat intelligence reporting with interactive visualizations
"""

import json
import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import logging

class ReportType(Enum):
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAIL = "technical_detail"
    COMPLIANCE_REPORT = "compliance_report"
    THREAT_INTELLIGENCE = "threat_intelligence"
    ZERO_DAY_ANALYSIS = "zero_day_analysis"
    TREND_ANALYSIS = "trend_analysis"

class SeverityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class SecurityMetric:
    name: str
    value: float
    trend: str  # "up", "down", "stable"
    change_percentage: float
    description: str
    timestamp: datetime

@dataclass
class ThreatIntelligenceInsight:
    threat_type: str
    severity: SeverityLevel
    confidence: float
    indicators: List[str]
    mitigation_priority: int
    cve_references: List[str]
    attack_vectors: List[str]
    affected_components: List[str]

@dataclass
class ComplianceMapping:
    framework: str  # OWASP, NIST, PCI-DSS, etc.
    control_id: str
    status: str  # "compliant", "partial", "non-compliant"
    findings_count: int
    recommendations: List[str]

@dataclass
class AdvancedReport:
    report_id: str
    report_type: ReportType
    title: str
    generated_at: datetime
    executive_summary: str
    security_metrics: List[SecurityMetric]
    threat_intelligence: List[ThreatIntelligenceInsight]
    compliance_status: List[ComplianceMapping]
    zero_day_findings: List[Dict[str, Any]]
    recommendations: List[str]
    risk_score: float
    trend_analysis: Dict[str, Any]
    raw_data: Dict[str, Any]

class AdvancedReportingDashboard:
    """Advanced reporting dashboard with executive-level insights."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.reports_dir = Path("reports/advanced")
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.templates_dir = Path("templates/reports")
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize security metrics tracking
        self.metrics_history: List[SecurityMetric] = []
        self.baseline_metrics = self._load_baseline_metrics()
        
    def generate_executive_dashboard(self, scan_results: Dict[str, Any], 
                                   zero_day_findings: List[Dict[str, Any]] = None) -> AdvancedReport:
        """Generate comprehensive executive dashboard report."""
        
        self.logger.info("Generating executive dashboard report")
        
        report_id = f"exec_dashboard_{int(time.time())}"
        generated_at = datetime.now()
        
        # Extract and analyze security metrics
        security_metrics = self._calculate_security_metrics(scan_results)
        
        # Generate threat intelligence insights
        threat_intelligence = self._analyze_threat_intelligence(scan_results, zero_day_findings)
        
        # Map compliance frameworks
        compliance_status = self._map_compliance_frameworks(scan_results)
        
        # Create executive summary
        executive_summary = self._generate_executive_summary(
            security_metrics, threat_intelligence, compliance_status, zero_day_findings
        )
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(security_metrics, threat_intelligence)
        
        # Generate trend analysis
        trend_analysis = self._generate_trend_analysis(security_metrics)
        
        # Compile strategic recommendations
        recommendations = self._generate_strategic_recommendations(
            threat_intelligence, compliance_status, risk_score
        )
        
        report = AdvancedReport(
            report_id=report_id,
            report_type=ReportType.EXECUTIVE_SUMMARY,
            title=f"Executive Security Dashboard - {generated_at.strftime('%Y-%m-%d %H:%M')}",
            generated_at=generated_at,
            executive_summary=executive_summary,
            security_metrics=security_metrics,
            threat_intelligence=threat_intelligence,
            compliance_status=compliance_status,
            zero_day_findings=zero_day_findings or [],
            recommendations=recommendations,
            risk_score=risk_score,
            trend_analysis=trend_analysis,
            raw_data=scan_results
        )
        
        # Save report
        self._save_report(report)
        
        # Generate interactive HTML dashboard
        self._generate_html_dashboard(report)
        
        return report
    
    def _calculate_security_metrics(self, scan_results: Dict[str, Any]) -> List[SecurityMetric]:
        """Calculate key security metrics from scan results."""
        
        metrics = []
        current_time = datetime.now()
        
        # Total vulnerabilities found
        total_vulns = len(scan_results.get('vulnerabilities', []))
        vulns_metric = SecurityMetric(
            name="Total Vulnerabilities",
            value=total_vulns,
            trend=self._calculate_trend("total_vulnerabilities", total_vulns),
            change_percentage=self._calculate_change_percentage("total_vulnerabilities", total_vulns),
            description="Total number of security vulnerabilities detected",
            timestamp=current_time
        )
        metrics.append(vulns_metric)
        
        # Critical vulnerabilities
        critical_vulns = len([v for v in scan_results.get('vulnerabilities', []) 
                            if v.get('severity', '').lower() == 'critical'])
        critical_metric = SecurityMetric(
            name="Critical Vulnerabilities",
            value=critical_vulns,
            trend=self._calculate_trend("critical_vulnerabilities", critical_vulns),
            change_percentage=self._calculate_change_percentage("critical_vulnerabilities", critical_vulns),
            description="High-priority vulnerabilities requiring immediate attention",
            timestamp=current_time
        )
        metrics.append(critical_metric)
        
        # Security score (0-100, higher is better)
        security_score = max(0, 100 - (critical_vulns * 10 + total_vulns * 2))
        score_metric = SecurityMetric(
            name="Security Score",
            value=security_score,
            trend=self._calculate_trend("security_score", security_score),
            change_percentage=self._calculate_change_percentage("security_score", security_score),
            description="Overall security posture score (0-100, higher is better)",
            timestamp=current_time
        )
        metrics.append(score_metric)
        
        # Compliance coverage
        compliance_coverage = self._calculate_compliance_coverage(scan_results)
        compliance_metric = SecurityMetric(
            name="Compliance Coverage",
            value=compliance_coverage,
            trend=self._calculate_trend("compliance_coverage", compliance_coverage),
            change_percentage=self._calculate_change_percentage("compliance_coverage", compliance_coverage),
            description="Percentage of compliance frameworks adequately covered",
            timestamp=current_time
        )
        metrics.append(compliance_metric)
        
        # Update metrics history
        self.metrics_history.extend(metrics)
        
        return metrics
    
    def _analyze_threat_intelligence(self, scan_results: Dict[str, Any], 
                                   zero_day_findings: List[Dict[str, Any]] = None) -> List[ThreatIntelligenceInsight]:
        """Analyze threat intelligence from scan results."""
        
        insights = []
        
        # Analyze zero-day threats
        if zero_day_findings:
            for finding in zero_day_findings:
                insight = ThreatIntelligenceInsight(
                    threat_type=finding.get('category', 'unknown'),
                    severity=SeverityLevel(finding.get('threat_level', 'medium')),
                    confidence=finding.get('confidence_score', 0.5),
                    indicators=[finding.get('attack_vector', 'unknown')],
                    mitigation_priority=self._calculate_mitigation_priority(finding),
                    cve_references=finding.get('cve_references', []),
                    attack_vectors=[finding.get('attack_vector', 'unknown')],
                    affected_components=[finding.get('file_path', 'unknown')]
                )
                insights.append(insight)
        
        # Analyze vulnerability patterns for emerging threats
        vulnerabilities = scan_results.get('vulnerabilities', [])
        threat_patterns = self._identify_threat_patterns(vulnerabilities)
        
        for pattern in threat_patterns:
            insight = ThreatIntelligenceInsight(
                threat_type=pattern['type'],
                severity=SeverityLevel(pattern['severity']),
                confidence=pattern['confidence'],
                indicators=pattern['indicators'],
                mitigation_priority=pattern['priority'],
                cve_references=pattern.get('cves', []),
                attack_vectors=pattern.get('vectors', []),
                affected_components=pattern.get('components', [])
            )
            insights.append(insight)
        
        return insights
    
    def _map_compliance_frameworks(self, scan_results: Dict[str, Any]) -> List[ComplianceMapping]:
        """Map findings to compliance frameworks."""
        
        compliance_mappings = []
        
        # OWASP Mobile Top 10 mapping
        owasp_mapping = self._map_owasp_mobile_top10(scan_results)
        compliance_mappings.extend(owasp_mapping)
        
        # NIST Cybersecurity Framework mapping
        nist_mapping = self._map_nist_framework(scan_results)
        compliance_mappings.extend(nist_mapping)
        
        # PCI-DSS mapping (if applicable)
        pci_mapping = self._map_pci_dss(scan_results)
        compliance_mappings.extend(pci_mapping)
        
        return compliance_mappings
    
    def _generate_executive_summary(self, security_metrics: List[SecurityMetric],
                                  threat_intelligence: List[ThreatIntelligenceInsight],
                                  compliance_status: List[ComplianceMapping],
                                  zero_day_findings: List[Dict[str, Any]]) -> str:
        """Generate executive summary text."""
        
        total_vulns = next((m.value for m in security_metrics if m.name == "Total Vulnerabilities"), 0)
        critical_vulns = next((m.value for m in security_metrics if m.name == "Critical Vulnerabilities"), 0)
        security_score = next((m.value for m in security_metrics if m.name == "Security Score"), 0)
        
        # Determine risk level
        if critical_vulns > 5 or security_score < 50:
            risk_level = "HIGH"
            risk_color = "🔴"
        elif critical_vulns > 2 or security_score < 70:
            risk_level = "MEDIUM"
            risk_color = "🟡"
        else:
            risk_level = "LOW"
            risk_color = "🟢"
        
        # Count zero-day threats
        zero_day_count = len(zero_day_findings) if zero_day_findings else 0
        critical_zero_days = len([f for f in (zero_day_findings or []) 
                                if f.get('threat_level') == 'critical'])
        
        summary = f"""
{risk_color} **SECURITY RISK LEVEL: {risk_level}**

**KEY FINDINGS:**
• Total Vulnerabilities: {int(total_vulns)}
• Critical Issues: {int(critical_vulns)}
• Security Score: {security_score:.1f}/100
• Zero-Day Threats: {zero_day_count} (Critical: {critical_zero_days})

**THREAT LANDSCAPE:**
• {len(threat_intelligence)} active threat patterns identified
• {len([t for t in threat_intelligence if t.severity == SeverityLevel.CRITICAL])} critical threat vectors detected
• Emerging threat indicators require immediate attention

**COMPLIANCE STATUS:**
• {len([c for c in compliance_status if c.status == 'compliant'])} frameworks fully compliant
• {len([c for c in compliance_status if c.status == 'partial'])} frameworks partially compliant
• {len([c for c in compliance_status if c.status == 'non-compliant'])} frameworks non-compliant

**IMMEDIATE ACTIONS REQUIRED:**
{f'• Address {critical_vulns} critical vulnerabilities immediately' if critical_vulns > 0 else '• Maintain current security posture'}
{f'• Investigate {critical_zero_days} critical zero-day threats' if critical_zero_days > 0 else ''}
• Implement recommended security controls
• Schedule follow-up assessment in 30 days
        """.strip()
        
        return summary
    
    def _calculate_risk_score(self, security_metrics: List[SecurityMetric],
                            threat_intelligence: List[ThreatIntelligenceInsight]) -> float:
        """Calculate overall risk score (0-100, lower is better)."""
        
        # Base risk from vulnerabilities
        total_vulns = next((m.value for m in security_metrics if m.name == "Total Vulnerabilities"), 0)
        critical_vulns = next((m.value for m in security_metrics if m.name == "Critical Vulnerabilities"), 0)
        
        vuln_risk = min(50, critical_vulns * 10 + total_vulns * 2)
        
        # Additional risk from threat intelligence
        threat_risk = min(30, len([t for t in threat_intelligence if t.severity == SeverityLevel.CRITICAL]) * 10)
        
        # Compliance risk
        compliance_coverage = next((m.value for m in security_metrics if m.name == "Compliance Coverage"), 100)
        compliance_risk = max(0, (100 - compliance_coverage) * 0.2)
        
        total_risk = vuln_risk + threat_risk + compliance_risk
        return min(100, total_risk)
    
    def _generate_trend_analysis(self, security_metrics: List[SecurityMetric]) -> Dict[str, Any]:
        """Generate trend analysis from historical metrics."""
        
        trends = {
            'improving_metrics': [],
            'degrading_metrics': [],
            'stable_metrics': [],
            'predictions': {}
        }
        
        for metric in security_metrics:
            if metric.trend == "up" and metric.name in ["Security Score", "Compliance Coverage"]:
                trends['improving_metrics'].append(metric.name)
            elif metric.trend == "down" and metric.name in ["Security Score", "Compliance Coverage"]:
                trends['degrading_metrics'].append(metric.name)
            elif metric.trend == "up" and metric.name in ["Total Vulnerabilities", "Critical Vulnerabilities"]:
                trends['degrading_metrics'].append(metric.name)
            elif metric.trend == "down" and metric.name in ["Total Vulnerabilities", "Critical Vulnerabilities"]:
                trends['improving_metrics'].append(metric.name)
            else:
                trends['stable_metrics'].append(metric.name)
        
        return trends
    
    def _generate_strategic_recommendations(self, threat_intelligence: List[ThreatIntelligenceInsight],
                                          compliance_status: List[ComplianceMapping],
                                          risk_score: float) -> List[str]:
        """Generate strategic recommendations for executives."""
        
        recommendations = []
        
        # Risk-based recommendations
        if risk_score > 70:
            recommendations.append("🚨 URGENT: Implement emergency security measures and allocate additional resources")
            recommendations.append("📋 Schedule immediate security review with senior leadership")
        elif risk_score > 40:
            recommendations.append("⚠️ Accelerate security improvement initiatives")
            recommendations.append("🔍 Conduct quarterly security assessments")
        else:
            recommendations.append("✅ Maintain current security investments")
            recommendations.append("📈 Focus on proactive threat hunting")
        
        # Threat intelligence recommendations
        critical_threats = [t for t in threat_intelligence if t.severity == SeverityLevel.CRITICAL]
        if critical_threats:
            recommendations.append(f"🛡️ Address {len(critical_threats)} critical threat vectors immediately")
            recommendations.append("🔄 Implement automated threat detection and response")
        
        # Compliance recommendations
        non_compliant = [c for c in compliance_status if c.status == 'non-compliant']
        if non_compliant:
            frameworks = [c.framework for c in non_compliant]
            recommendations.append(f"📊 Achieve compliance with {', '.join(frameworks)} frameworks")
        
        # General strategic recommendations
        recommendations.extend([
            "🎯 Invest in security awareness training for development teams",
            "🔒 Implement secure coding practices in CI/CD pipeline",
            "📱 Establish mobile security testing standards",
            "🌐 Consider cyber insurance coverage review"
        ])
        
        return recommendations[:8]  # Limit to top 8 recommendations
    
    def _generate_html_dashboard(self, report: AdvancedReport) -> str:
        """Generate interactive HTML dashboard."""
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AODS Executive Security Dashboard</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .dashboard {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1e3c72, #2a5298); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }}
        .metric-card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .metric-value {{ font-size: 2.5em; font-weight: bold; margin: 10px 0; }}
        .trend-up {{ color: #28a745; }}
        .trend-down {{ color: #dc3545; }}
        .trend-stable {{ color: #6c757d; }}
        .section {{ background: white; padding: 30px; margin-bottom: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .risk-high {{ border-left: 5px solid #dc3545; }}
        .risk-medium {{ border-left: 5px solid #ffc107; }}
        .risk-low {{ border-left: 5px solid #28a745; }}
        .recommendations li {{ margin: 10px 0; }}
        .threat-item {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 3px solid #007bff; }}
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>🛡️ AODS Executive Security Dashboard</h1>
            <p>Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Risk Score: {report.risk_score:.1f}/100 | Report ID: {report.report_id}</p>
        </div>
        
        <div class="metrics-grid">
            {self._generate_metric_cards_html(report.security_metrics)}
        </div>
        
        <div class="section {'risk-high' if report.risk_score > 70 else 'risk-medium' if report.risk_score > 40 else 'risk-low'}">
            <h2>📋 Executive Summary</h2>
            <div style="white-space: pre-line; line-height: 1.6;">{report.executive_summary}</div>
        </div>
        
        <div class="section">
            <h2>🚨 Threat Intelligence</h2>
            {self._generate_threat_intelligence_html(report.threat_intelligence)}
        </div>
        
        <div class="section">
            <h2>✅ Strategic Recommendations</h2>
            <ul class="recommendations">
                {chr(10).join(f'<li>{rec}</li>' for rec in report.recommendations)}
            </ul>
        </div>
        
        <div class="section">
            <h2>📊 Compliance Status</h2>
            {self._generate_compliance_html(report.compliance_status)}
        </div>
    </div>
</body>
</html>
        """
        
        # Save HTML report
        html_file = self.reports_dir / f"{report.report_id}_dashboard.html"
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"Interactive dashboard saved: {html_file}")
        return str(html_file)
    
    def _generate_metric_cards_html(self, metrics: List[SecurityMetric]) -> str:
        """Generate HTML for metric cards."""
        
        cards = []
        for metric in metrics:
            trend_class = f"trend-{metric.trend}" if metric.trend in ["up", "down"] else "trend-stable"
            trend_icon = "📈" if metric.trend == "up" else "📉" if metric.trend == "down" else "➡️"
            
            card_html = f"""
            <div class="metric-card">
                <h3>{metric.name}</h3>
                <div class="metric-value {trend_class}">{metric.value:.1f}</div>
                <p>{trend_icon} {metric.change_percentage:+.1f}% change</p>
                <small>{metric.description}</small>
            </div>
            """
            cards.append(card_html)
        
        return "\n".join(cards)
    
    def _generate_threat_intelligence_html(self, threats: List[ThreatIntelligenceInsight]) -> str:
        """Generate HTML for threat intelligence section."""
        
        if not threats:
            return "<p>No specific threats identified.</p>"
        
        threat_html = []
        for threat in threats[:5]:  # Show top 5 threats
            threat_item = f"""
            <div class="threat-item">
                <h4>🚨 {threat.threat_type.replace('_', ' ').title()}</h4>
                <p><strong>Severity:</strong> {threat.severity.value.upper()} | <strong>Confidence:</strong> {threat.confidence:.1f}</p>
                <p><strong>Attack Vectors:</strong> {', '.join(threat.attack_vectors)}</p>
                <p><strong>Affected Components:</strong> {', '.join(threat.affected_components[:3])}{'...' if len(threat.affected_components) > 3 else ''}</p>
            </div>
            """
            threat_html.append(threat_item)
        
        return "\n".join(threat_html)
    
    def _generate_compliance_html(self, compliance: List[ComplianceMapping]) -> str:
        """Generate HTML for compliance section."""
        
        if not compliance:
            return "<p>No compliance mappings available.</p>"
        
        compliance_html = []
        for comp in compliance:
            status_color = "#28a745" if comp.status == "compliant" else "#ffc107" if comp.status == "partial" else "#dc3545"
            status_icon = "✅" if comp.status == "compliant" else "⚠️" if comp.status == "partial" else "❌"
            
            comp_item = f"""
            <div style="background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 3px solid {status_color};">
                <h4>{status_icon} {comp.framework} - {comp.control_id}</h4>
                <p><strong>Status:</strong> {comp.status.replace('_', ' ').title()} | <strong>Findings:</strong> {comp.findings_count}</p>
            </div>
            """
            compliance_html.append(comp_item)
        
        return "\n".join(compliance_html)
    
    # Helper methods for calculations and data processing
    def _load_baseline_metrics(self) -> Dict[str, float]:
        """Load baseline metrics for trend analysis."""
        return {
            "total_vulnerabilities": 10,
            "critical_vulnerabilities": 2,
            "security_score": 75,
            "compliance_coverage": 85
        }
    
    def _calculate_trend(self, metric_name: str, current_value: float) -> str:
        """Calculate trend direction for a metric."""
        baseline = self.baseline_metrics.get(metric_name, current_value)
        
        if metric_name in ["Security Score", "Compliance Coverage"]:
            # Higher is better
            if current_value > baseline * 1.05:
                return "up"
            elif current_value < baseline * 0.95:
                return "down"
        else:
            # Lower is better (vulnerabilities)
            if current_value > baseline * 1.05:
                return "up"  # More vulnerabilities = bad trend
            elif current_value < baseline * 0.95:
                return "down"  # Fewer vulnerabilities = good trend
        
        return "stable"
    
    def _calculate_change_percentage(self, metric_name: str, current_value: float) -> float:
        """Calculate percentage change from baseline."""
        baseline = self.baseline_metrics.get(metric_name, current_value)
        if baseline == 0:
            return 0.0
        return ((current_value - baseline) / baseline) * 100
    
    def _calculate_compliance_coverage(self, scan_results: Dict[str, Any]) -> float:
        """Calculate compliance framework coverage percentage."""
        # Simplified calculation - in practice, this would be more sophisticated
        total_frameworks = 3  # OWASP, NIST, PCI-DSS
        covered_frameworks = 2  # Assume 2 are adequately covered
        return (covered_frameworks / total_frameworks) * 100
    
    def _calculate_mitigation_priority(self, finding: Dict[str, Any]) -> int:
        """Calculate mitigation priority (1-10, higher is more urgent)."""
        severity = finding.get('threat_level', 'medium').lower()
        confidence = finding.get('confidence_score', 0.5)
        
        base_priority = {
            'critical': 9,
            'high': 7,
            'medium': 5,
            'low': 3
        }.get(severity, 5)
        
        # Adjust based on confidence
        priority = base_priority * confidence
        return min(10, max(1, int(priority)))
    
    def _identify_threat_patterns(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify threat patterns from vulnerabilities."""
        # Simplified pattern identification
        patterns = []
        
        # Group by type and identify patterns
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        # Create patterns for frequent vulnerability types
        for vuln_type, vulns in vuln_types.items():
            if len(vulns) >= 3:  # Pattern threshold
                patterns.append({
                    'type': f"Recurring {vuln_type}",
                    'severity': 'high',
                    'confidence': min(0.9, len(vulns) * 0.2),
                    'indicators': [f"Multiple {vuln_type} vulnerabilities"],
                    'priority': 8,
                    'vectors': ['Application Layer'],
                    'components': [v.get('file', 'unknown') for v in vulns[:3]]
                })
        
        return patterns
    
    def _map_owasp_mobile_top10(self, scan_results: Dict[str, Any]) -> List[ComplianceMapping]:
        """Map findings to OWASP Mobile Top 10."""
        mappings = []
        
        # Example mappings - in practice, these would be more detailed
        owasp_controls = [
            ("M1", "Improper Platform Usage"),
            ("M2", "Insecure Data Storage"),
            ("M3", "Insecure Communication"),
            ("M4", "Insecure Authentication"),
            ("M5", "Insufficient Cryptography")
        ]
        
        for control_id, control_name in owasp_controls:
            # Simplified compliance check
            findings_count = len([v for v in scan_results.get('vulnerabilities', []) 
                                if control_name.lower() in v.get('type', '').lower()])
            
            status = "compliant" if findings_count == 0 else "partial" if findings_count < 3 else "non-compliant"
            
            mapping = ComplianceMapping(
                framework="OWASP Mobile Top 10",
                control_id=control_id,
                status=status,
                findings_count=findings_count,
                recommendations=[f"Address {control_name} vulnerabilities"]
            )
            mappings.append(mapping)
        
        return mappings
    
    def _map_nist_framework(self, scan_results: Dict[str, Any]) -> List[ComplianceMapping]:
        """Map findings to NIST Cybersecurity Framework."""
        # Simplified NIST mapping
        return [
            ComplianceMapping(
                framework="NIST CSF",
                control_id="PR.DS-1",
                status="partial",
                findings_count=2,
                recommendations=["Implement data protection controls"]
            )
        ]
    
    def _map_pci_dss(self, scan_results: Dict[str, Any]) -> List[ComplianceMapping]:
        """Map findings to PCI-DSS requirements."""
        # Simplified PCI-DSS mapping
        return [
            ComplianceMapping(
                framework="PCI-DSS",
                control_id="6.5.1",
                status="compliant",
                findings_count=0,
                recommendations=["Maintain secure coding practices"]
            )
        ]
    
    def _save_report(self, report: AdvancedReport) -> str:
        """Save report to JSON file."""
        
        report_file = self.reports_dir / f"{report.report_id}.json"
        
        # Convert report to JSON-serializable format
        report_dict = asdict(report)
        report_dict['generated_at'] = report.generated_at.isoformat()
        
        # Convert enum types to strings
        report_dict['report_type'] = report.report_type.value
        
        # Convert SecurityMetric timestamps
        for metric in report_dict['security_metrics']:
            if 'timestamp' in metric:
                metric['timestamp'] = metric['timestamp'].isoformat() if hasattr(metric['timestamp'], 'isoformat') else str(metric['timestamp'])
        
        # Convert ThreatIntelligenceInsight enum types
        for threat in report_dict['threat_intelligence']:
            if 'severity' in threat:
                threat['severity'] = threat['severity'].value if hasattr(threat['severity'], 'value') else str(threat['severity'])
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Report saved: {report_file}")
        return str(report_file)

# Convenience functions for integration
def generate_executive_dashboard(scan_results: Dict[str, Any], 
                               zero_day_findings: List[Dict[str, Any]] = None) -> AdvancedReport:
    """Generate executive dashboard report."""
    dashboard = AdvancedReportingDashboard()
    return dashboard.generate_executive_dashboard(scan_results, zero_day_findings)

def create_threat_intelligence_report(threat_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Create focused threat intelligence report."""
    dashboard = AdvancedReportingDashboard()
    
    # Process threat data into insights
    insights = []
    for threat in threat_data:
        insight = ThreatIntelligenceInsight(
            threat_type=threat.get('type', 'unknown'),
            severity=SeverityLevel(threat.get('severity', 'medium')),
            confidence=threat.get('confidence', 0.5),
            indicators=threat.get('indicators', []),
            mitigation_priority=threat.get('priority', 5),
            cve_references=threat.get('cves', []),
            attack_vectors=threat.get('vectors', []),
            affected_components=threat.get('components', [])
        )
        insights.append(insight)
    
    return {
        'insights': insights,
        'summary': f"Analyzed {len(insights)} threat intelligence indicators",
        'critical_count': len([i for i in insights if i.severity == SeverityLevel.CRITICAL]),
        'recommendations': ["Implement threat hunting procedures", "Update detection rules"]
    }

if __name__ == "__main__":
    # Demo usage
    print("🚀 Advanced Reporting Dashboard - Demo Mode")
    
    # Sample scan results
    sample_results = {
        'vulnerabilities': [
            {'type': 'Insecure Data Storage', 'severity': 'critical', 'file': 'MainActivity.java'},
            {'type': 'Insecure Communication', 'severity': 'high', 'file': 'NetworkManager.java'},
            {'type': 'Weak Cryptography', 'severity': 'medium', 'file': 'CryptoHelper.java'}
        ]
    }
    
    # Sample zero-day findings
    sample_zero_days = [
        {
            'category': 'privilege_escalation',
            'threat_level': 'critical',
            'confidence_score': 0.9,
            'attack_vector': 'Root privilege escalation',
            'file_path': 'SuspiciousActivity.java'
        }
    ]
    
    dashboard = AdvancedReportingDashboard()
    report = dashboard.generate_executive_dashboard(sample_results, sample_zero_days)
    
    print(f"✅ Executive dashboard generated: {report.report_id}")
    print(f"📊 Risk Score: {report.risk_score:.1f}/100")
    print(f"🎯 Recommendations: {len(report.recommendations)}")
    print(f"📋 Threat Intelligence: {len(report.threat_intelligence)} insights")
    print(f"✅ Report saved and HTML dashboard created") 