"""
Privacy Formatter

Comprehensive privacy reporting with Rich text formatting and multi-format export.
Generates professional privacy analysis reports with GDPR and MASTG compliance summaries.
"""

import json
from typing import Dict, List, Optional, Union
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from rich.markup import escape

from .data_structures import PrivacyVulnerability, PrivacyAnalysisResult, ThirdPartySDK

class PrivacyFormatter:
    """
    Formats privacy analysis results for professional reporting.
    Supports Rich text, JSON, and structured reporting formats.
    """
    
    def __init__(self):
        self.console = Console()
        
    def generate_privacy_report(self, result: PrivacyAnalysisResult, 
                               detected_sdks: Optional[Dict[str, ThirdPartySDK]] = None) -> Text:
        """
        Generate comprehensive privacy analysis report
        
        Args:
            result: Privacy analysis result with vulnerabilities and metrics
            detected_sdks: Optional detected third-party SDKs
            
        Returns:
            Rich Text object with formatted report
        """
        
        report = Text()
        
        # Header
        report.append("PRIVACY CONTROLS ANALYSIS REPORT\n", style="bold red")
        report.append("=" * 50 + "\n\n", style="blue")
        
        # Executive Summary
        report.append(self._generate_executive_summary(result))
        
        # GDPR Compliance Summary
        report.append(self._generate_gdpr_summary(result))
        
        # MASTG Compliance Summary  
        report.append(self._generate_mastg_summary(result))
        
        # Third-Party SDKs Summary
        if detected_sdks:
            report.append(self._generate_sdk_summary(detected_sdks))
        
        # Detailed Vulnerabilities
        if result.vulnerabilities:
            report.append(self._generate_vulnerability_details(result.vulnerabilities))
        
        # Recommendations
        report.append(self._generate_recommendations(result))
        
        return report
    
    def _generate_executive_summary(self, result: PrivacyAnalysisResult) -> Text:
        """Generate executive summary section"""
        
        summary = Text()
        summary.append("EXECUTIVE SUMMARY\n", style="bold cyan")
        summary.append("-" * 20 + "\n\n", style="cyan")
        
        # Overall status
        if result.total_issues == 0:
            summary.append("✅ No significant privacy issues detected\n", style="green")
        elif result.critical_issues > 0:
            summary.append("🚨 CRITICAL privacy issues require immediate attention\n", style="bold red")
        elif result.high_issues > 0:
            summary.append("⚠️  HIGH priority privacy issues detected\n", style="bold yellow")
        else:
            summary.append("ℹ️  MEDIUM/LOW priority privacy issues detected\n", style="yellow")
        
        # Issue breakdown
        summary.append(f"\nIssue Breakdown:\n", style="bold")
        summary.append(f"  • Critical Issues: {result.critical_issues}\n", 
                      style="red" if result.critical_issues > 0 else "green")
        summary.append(f"  • High Issues: {result.high_issues}\n",
                      style="red" if result.high_issues > 0 else "green")
        summary.append(f"  • Medium Issues: {result.medium_issues}\n",
                      style="yellow" if result.medium_issues > 0 else "green")
        summary.append(f"  • Low Issues: {result.low_issues}\n",
                      style="yellow" if result.low_issues > 0 else "green")
        summary.append(f"  • Total Issues: {result.total_issues}\n\n", style="bold")
        
        # Compliance scores
        summary.append(f"Compliance Scores:\n", style="bold")
        summary.append(f"  • GDPR Compliance: {result.gdpr_compliance_score:.1f}%\n",
                      style=self._get_score_color(result.gdpr_compliance_score))
        summary.append(f"  • MASTG Compliance: {result.mastg_compliance_score:.1f}%\n",
                      style=self._get_score_color(result.mastg_compliance_score))
        
        # Key findings
        summary.append(f"\nKey Findings:\n", style="bold")
        summary.append(f"  • Privacy Controls Present: {'Yes' if result.privacy_controls_present else 'No'}\n",
                      style="green" if result.privacy_controls_present else "red")
        summary.append(f"  • Consent Mechanisms Found: {'Yes' if result.consent_mechanisms_found else 'No'}\n",
                      style="green" if result.consent_mechanisms_found else "red")
        summary.append(f"  • Third-Party SDKs: {len(result.third_party_sdks_detected)}\n",
                      style="yellow" if len(result.third_party_sdks_detected) > 3 else "green")
        
        summary.append("\n")
        return summary
    
    def _generate_gdpr_summary(self, result: PrivacyAnalysisResult) -> Text:
        """Generate GDPR compliance summary"""
        
        gdpr = Text()
        gdpr.append("GDPR COMPLIANCE ANALYSIS\n", style="bold magenta")
        gdpr.append("-" * 30 + "\n\n", style="magenta")
        
        # Overall GDPR score
        score_color = self._get_score_color(result.gdpr_compliance_score)
        gdpr.append(f"Overall GDPR Compliance Score: {result.gdpr_compliance_score:.1f}%\n\n", 
                   style=f"bold {score_color}")
        
        # Article-specific compliance (simplified)
        gdpr_articles = {
            "Article 5 (Data Processing Principles)": self._assess_article5_compliance(result),
            "Article 6 (Lawfulness of Processing)": self._assess_article6_compliance(result),
            "Article 7 (Consent)": self._assess_article7_compliance(result),
            "Article 12 (Transparent Information)": self._assess_article12_compliance(result),
            "Article 28 (Processor Requirements)": self._assess_article28_compliance(result),
            "Article 32 (Security of Processing)": self._assess_article32_compliance(result)
        }
        
        gdpr.append("Article-Specific Compliance:\n", style="bold")
        for article, score in gdpr_articles.items():
            color = self._get_score_color(score)
            gdpr.append(f"  • {article}: {score:.1f}%\n", style=color)
        
        gdpr.append("\n")
        return gdpr
    
    def _generate_mastg_summary(self, result: PrivacyAnalysisResult) -> Text:
        """Generate MASTG compliance summary"""
        
        mastg = Text()
        mastg.append("MASTG COMPLIANCE ANALYSIS\n", style="bold green")
        mastg.append("-" * 30 + "\n\n", style="green")
        
        # Overall MASTG score
        score_color = self._get_score_color(result.mastg_compliance_score)
        mastg.append(f"Overall MASTG Compliance Score: {result.mastg_compliance_score:.1f}%\n\n",
                    style=f"bold {score_color}")
        
        # Test-specific compliance
        mastg_tests = {
            "MASTG-TEST-0025 (User Privacy Controls)": self._assess_mastg_test_0025(result),
            "MASTG-TEST-0026 (Data Collection Consent)": self._assess_mastg_test_0026(result),
            "MASTG-TEST-0027 (Personal Data Processing)": self._assess_mastg_test_0027(result),
            "MASTG-TEST-0028 (Third-Party Data Sharing)": self._assess_mastg_test_0028(result),
            "MASTG-TEST-0029 (Data Retention Policies)": self._assess_mastg_test_0029(result),
            "MASTG-TEST-0030 (User Data Rights)": self._assess_mastg_test_0030(result)
        }
        
        mastg.append("Test-Specific Compliance:\n", style="bold")
        for test, score in mastg_tests.items():
            color = self._get_score_color(score)
            mastg.append(f"  • {test}: {score:.1f}%\n", style=color)
        
        mastg.append("\n")
        return mastg
    
    def _generate_sdk_summary(self, detected_sdks: Dict[str, ThirdPartySDK]) -> Text:
        """Generate third-party SDK summary"""
        
        sdk_summary = Text()
        sdk_summary.append("THIRD-PARTY SDKs DETECTED\n", style="bold yellow")
        sdk_summary.append("-" * 30 + "\n\n", style="yellow")
        
        if not detected_sdks:
            sdk_summary.append("No third-party SDKs detected.\n\n", style="green")
            return sdk_summary
        
        sdk_summary.append(f"Total SDKs Detected: {len(detected_sdks)}\n\n", style="bold")
        
        for sdk_key, sdk_info in detected_sdks.items():
            # SDK name and risk level
            risk_color = "red" if sdk_info.tracking_enabled and len(sdk_info.data_collected) > 2 else "yellow"
            sdk_summary.append(f"• {sdk_info.name}\n", style=f"bold {risk_color}")
            
            # Data collected
            data_types = [dt.value for dt in sdk_info.data_collected]
            sdk_summary.append(f"  Data Collected: {', '.join(data_types)}\n", style="white")
            
            # Privacy characteristics
            sdk_summary.append(f"  Consent Required: {'Yes' if sdk_info.consent_required else 'No'}\n",
                              style="red" if sdk_info.consent_required else "green")
            sdk_summary.append(f"  Data Sharing: {'Yes' if sdk_info.data_sharing else 'No'}\n",
                              style="red" if sdk_info.data_sharing else "green")
            sdk_summary.append(f"  Tracking Enabled: {'Yes' if sdk_info.tracking_enabled else 'No'}\n",
                              style="red" if sdk_info.tracking_enabled else "green")
            
            # Privacy policy
            if sdk_info.privacy_policy_url:
                sdk_summary.append(f"  Privacy Policy: {sdk_info.privacy_policy_url}\n", style="blue")
            
            sdk_summary.append("\n")
        
        return sdk_summary
    
    def _generate_vulnerability_details(self, vulnerabilities: List[PrivacyVulnerability]) -> Text:
        """Generate detailed vulnerability information"""
        
        details = Text()
        details.append("DETAILED VULNERABILITY ANALYSIS\n", style="bold red")
        details.append("-" * 40 + "\n\n", style="red")
        
        # Group vulnerabilities by type
        vuln_groups = {}
        for vuln in vulnerabilities:
            if vuln.vuln_type not in vuln_groups:
                vuln_groups[vuln.vuln_type] = []
            vuln_groups[vuln.vuln_type].append(vuln)
        
        for vuln_type, vulns in vuln_groups.items():
            details.append(f"{vuln_type.upper().replace('_', ' ')}\n", style="bold cyan")
            details.append("-" * len(vuln_type) + "\n", style="cyan")
            
            for i, vuln in enumerate(vulns, 1):
                severity_color = self._get_severity_color(vuln.severity)
                
                details.append(f"{i}. ", style="bold")
                details.append(f"[{vuln.severity}] ", style=f"bold {severity_color}")
                details.append(f"{escape(str(vuln.value))}\n", style="white")
                
                details.append(f"   Location: {escape(vuln.location)}\n", style="dim")
                
                if vuln.line_number:
                    details.append(f"   Line: {vuln.line_number}\n", style="dim")
                
                if vuln.privacy_data:
                    details.append(f"   Data Type: {vuln.privacy_data}\n", style="dim")
                
                if vuln.third_party:
                    details.append(f"   Third Party: {vuln.third_party}\n", style="dim")
                
                if vuln.processing_purpose:
                    details.append(f"   Purpose: {vuln.processing_purpose}\n", style="dim")
                
                details.append(f"   MASTG Test: {vuln._get_mastg_test_id()}\n", style="blue")
                details.append(f"   GDPR Article: {vuln._get_gdpr_article()}\n", style="blue")
                
                details.append("\n")
            
            details.append("\n")
        
        return details
    
    def _generate_recommendations(self, result: PrivacyAnalysisResult) -> Text:
        """Generate privacy recommendations"""
        
        recs = Text()
        recs.append("PRIVACY RECOMMENDATIONS\n", style="bold green")
        recs.append("-" * 30 + "\n\n", style="green")
        
        recommendations = []
        
        # General recommendations based on findings
        if result.critical_issues > 0:
            recommendations.append("🚨 Address all CRITICAL privacy issues immediately before production deployment")
        
        if not result.consent_mechanisms_found:
            recommendations.append("✅ Implement explicit consent mechanisms for all personal data collection")
        
        if not result.privacy_controls_present:
            recommendations.append("⚙️  Add user privacy controls and settings for data management")
        
        if len(result.third_party_sdks_detected) > 3:
            recommendations.append("🔍 Review and minimize third-party SDK usage to reduce privacy risks")
        
        # GDPR-specific recommendations
        if result.gdpr_compliance_score < 80:
            recommendations.extend([
                "📋 Document lawful basis for all personal data processing activities",
                "🔒 Implement data protection by design and by default",
                "👤 Provide clear privacy notice and data subject rights information"
            ])
        
        # MASTG-specific recommendations
        if result.mastg_compliance_score < 80:
            recommendations.extend([
                "🛡️  Follow MASTG privacy testing guidelines for mobile applications",
                "🔐 Implement proper encryption for personal data storage and transmission",
                "⏰ Define and implement appropriate data retention policies"
            ])
        
        # Default recommendations if no specific issues
        if not recommendations:
            recommendations.extend([
                "✅ Continue following privacy best practices",
                "🔄 Regular privacy impact assessments",
                "📚 Keep privacy policies and documentation up to date"
            ])
        
        for i, rec in enumerate(recommendations, 1):
            recs.append(f"{i}. {rec}\n", style="white")
        
        recs.append("\n")
        recs.append("For detailed privacy compliance guidance, refer to:\n", style="italic")
        recs.append("• GDPR Official Text: https://gdpr-info.eu/\n", style="dim blue")
        recs.append("• MASTG Privacy Tests: https://mas.owasp.org/MASTG/\n", style="dim blue")
        recs.append("• OWASP Mobile Top 10: https://owasp.org/www-project-mobile-top-10/\n", style="dim blue")
        
        return recs
    
    def export_json_report(self, result: PrivacyAnalysisResult, 
                          detected_sdks: Optional[Dict[str, ThirdPartySDK]] = None) -> str:
        """Export privacy analysis as JSON"""
        
        # Convert to serializable format
        export_data = {
            "summary": {
                "total_issues": result.total_issues,
                "critical_issues": result.critical_issues,
                "high_issues": result.high_issues,
                "medium_issues": result.medium_issues,
                "low_issues": result.low_issues,
                "gdpr_compliance_score": result.gdpr_compliance_score,
                "mastg_compliance_score": result.mastg_compliance_score,
                "privacy_controls_present": result.privacy_controls_present,
                "consent_mechanisms_found": result.consent_mechanisms_found
            },
            "vulnerabilities": [
                {
                    "type": vuln.vuln_type,
                    "location": vuln.location,
                    "value": vuln.value,
                    "severity": vuln.severity,
                    "line_number": vuln.line_number,
                    "privacy_data": vuln.privacy_data,
                    "third_party": vuln.third_party,
                    "processing_purpose": vuln.processing_purpose,
                    "mastg_test": vuln._get_mastg_test_id(),
                    "gdpr_article": vuln._get_gdpr_article()
                }
                for vuln in result.vulnerabilities
            ],
            "third_party_sdks": {
                sdk_key: {
                    "name": sdk.name,
                    "data_collected": [dt.value for dt in sdk.data_collected],
                    "consent_required": sdk.consent_required,
                    "data_sharing": sdk.data_sharing,
                    "tracking_enabled": sdk.tracking_enabled,
                    "privacy_policy_url": sdk.privacy_policy_url
                }
                for sdk_key, sdk in (detected_sdks or {}).items()
            }
        }
        
        return json.dumps(export_data, indent=2)
    
    def _get_score_color(self, score: float) -> str:
        """Get color based on compliance score"""
        if score >= 90:
            return "green"
        elif score >= 70:
            return "yellow"
        else:
            return "red"
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color based on vulnerability severity"""
        severity_colors = {
            "CRITICAL": "red",
            "HIGH": "red", 
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "green"
        }
        return severity_colors.get(severity, "white")
    
    # Simplified compliance assessment methods
    def _assess_article5_compliance(self, result: PrivacyAnalysisResult) -> float:
        """Assess GDPR Article 5 compliance (Data Processing Principles)"""
        excessive_issues = sum(1 for v in result.vulnerabilities if "excessive" in v.vuln_type)
        return max(0, 100 - (excessive_issues * 20))
    
    def _assess_article6_compliance(self, result: PrivacyAnalysisResult) -> float:
        """Assess GDPR Article 6 compliance (Lawfulness)"""
        return max(0, 100 - (result.total_issues * 10))
    
    def _assess_article7_compliance(self, result: PrivacyAnalysisResult) -> float:
        """Assess GDPR Article 7 compliance (Consent)"""
        consent_issues = sum(1 for v in result.vulnerabilities if "consent" in v.vuln_type)
        return max(0, 100 - (consent_issues * 25))
    
    def _assess_article12_compliance(self, result: PrivacyAnalysisResult) -> float:
        """Assess GDPR Article 12 compliance (Transparency)"""
        return 90.0 if result.privacy_controls_present else 60.0
    
    def _assess_article28_compliance(self, result: PrivacyAnalysisResult) -> float:
        """Assess GDPR Article 28 compliance (Processors)"""
        third_party_issues = sum(1 for v in result.vulnerabilities if "third_party" in v.vuln_type)
        return max(0, 100 - (third_party_issues * 15))
    
    def _assess_article32_compliance(self, result: PrivacyAnalysisResult) -> float:
        """Assess GDPR Article 32 compliance (Security)"""
        encryption_issues = sum(1 for v in result.vulnerabilities if "unencrypted" in v.vuln_type)
        return max(0, 100 - (encryption_issues * 20))
    
    # Simplified MASTG test assessments
    def _assess_mastg_test_0025(self, result: PrivacyAnalysisResult) -> float:
        """Assess MASTG-TEST-0025 compliance"""
        return 90.0 if result.privacy_controls_present else 50.0
    
    def _assess_mastg_test_0026(self, result: PrivacyAnalysisResult) -> float:
        """Assess MASTG-TEST-0026 compliance"""
        return 90.0 if result.consent_mechanisms_found else 40.0
    
    def _assess_mastg_test_0027(self, result: PrivacyAnalysisResult) -> float:
        """Assess MASTG-TEST-0027 compliance"""
        processing_issues = sum(1 for v in result.vulnerabilities if "personal_data" in v.vuln_type)
        return max(0, 100 - (processing_issues * 20))
    
    def _assess_mastg_test_0028(self, result: PrivacyAnalysisResult) -> float:
        """Assess MASTG-TEST-0028 compliance"""
        sharing_issues = sum(1 for v in result.vulnerabilities if "third_party" in v.vuln_type)
        return max(0, 100 - (sharing_issues * 25))
    
    def _assess_mastg_test_0029(self, result: PrivacyAnalysisResult) -> float:
        """Assess MASTG-TEST-0029 compliance"""
        retention_issues = sum(1 for v in result.vulnerabilities if "retention" in v.vuln_type)
        return max(0, 100 - (retention_issues * 30))
    
    def _assess_mastg_test_0030(self, result: PrivacyAnalysisResult) -> float:
        """Assess MASTG-TEST-0030 compliance"""
        rights_issues = sum(1 for v in result.vulnerabilities if "rights" in v.vuln_type)
        return max(0, 100 - (rights_issues * 25)) 