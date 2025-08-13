"""
APK Signing Certificate Analysis Formatter

Module for formatting and presenting APK signing certificate analysis results
in professional, human-readable format.
"""

import logging
from typing import Dict, List, Any, Union
from datetime import datetime

from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.console import Console

from .data_structures import (
    APKSigningAnalysisResult, APKSignature, SigningCertificate, SecurityAssessment,
    ComplianceAssessment, CertificateSecurityLevel, SignatureScheme
)

logger = logging.getLogger(__name__)

class CertificateAnalysisFormatter:
    """
    formatter for APK signing certificate analysis results.
    
    Provides multiple output formats:
    - Rich text for console display
    - Structured dictionary for JSON export
    - Summary tables for quick overview
    - Detailed technical reports
    """
    
    def __init__(self):
        """Initialize the formatter."""
        self.console = Console()
        
        # Color scheme for different security levels
        self.security_colors = {
            CertificateSecurityLevel.CRITICAL: "red",
            CertificateSecurityLevel.HIGH: "orange3",
            CertificateSecurityLevel.MEDIUM: "yellow",
            CertificateSecurityLevel.LOW: "blue",
            CertificateSecurityLevel.INFO: "green"
        }
        
        logger.debug("Certificate analysis formatter initialized")
    
    def format_analysis_result(self, result: APKSigningAnalysisResult) -> Text:
        """
        Format complete analysis result for display.
        
        Args:
            result: Complete analysis result
            
        Returns:
            Rich Text object with formatted output
        """
        try:
            output = Text()
            
            # Header
            output.append(self._create_header(result))
            output.append("\n\n")
            
            # Executive Summary
            output.append(self._create_executive_summary(result))
            output.append("\n")
            
            # Signature Analysis
            if result.signatures:
                output.append(self._create_signature_analysis(result.signatures))
                output.append("\n")
            
            # Certificate Details
            output.append(self._create_certificate_details(result))
            output.append("\n")
            
            # Security Assessment
            if result.security_assessment:
                output.append(self._create_security_assessment(result.security_assessment))
                output.append("\n")
            
            # Compliance Assessment
            if result.compliance_assessments:
                output.append(self._create_compliance_assessment(result.compliance_assessments))
                output.append("\n")
            
            # Recommendations
            output.append(self._create_recommendations(result))
            
            logger.debug("Analysis result formatted successfully")
            return output
            
        except Exception as e:
            logger.error(f"Failed to format analysis result: {e}")
            error_text = Text()
            error_text.append(f"Error formatting analysis result: {e}", style="red")
            return error_text
    
    def format_signature_summary(self, signatures: List[APKSignature]) -> Text:
        """Format a summary of signatures."""
        output = Text()
        
        if not signatures:
            output.append("No signatures found", style="red")
            return output
        
        # Create summary table
        table = Table(title="Signature Summary")
        table.add_column("Scheme", style="cyan")
        table.add_column("Algorithm", style="blue")
        table.add_column("Status", style="green")
        table.add_column("Certificates", justify="right")
        
        for signature in signatures:
            status = "✓ Valid" if signature.is_valid else "✗ Invalid"
            status_style = "green" if signature.is_valid else "red"
            
            table.add_row(
                signature.scheme.value,
                signature.algorithm,
                Text(status, style=status_style),
                str(len(signature.certificates))
            )
        
        # Convert table to text (simplified)
        output.append("Signature Summary:\n", style="bold")
        for i, signature in enumerate(signatures):
            status = "Valid" if signature.is_valid else "Invalid"
            output.append(f"  {i+1}. {signature.scheme.value}: {signature.algorithm} - {status}\n")
        
        return output
    
    def format_certificate_summary(self, certificates: List[SigningCertificate]) -> Text:
        """Format a summary of certificates."""
        output = Text()
        
        if not certificates:
            output.append("No certificates found", style="red")
            return output
        
        output.append("Certificate Summary:\n", style="bold")
        
        for i, cert in enumerate(certificates):
            # Certificate subject
            output.append(f"  {i+1}. Subject: {cert.subject}\n")
            
            # Validity
            if cert.is_expired():
                output.append(f"     Status: EXPIRED ({cert.valid_to})\n", style="red")
            else:
                days_left = cert.days_until_expiry()
                if days_left < 30:
                    output.append(f"     Status: Expires in {days_left} days\n", style="orange3")
                else:
                    output.append(f"     Status: Valid until {cert.valid_to}\n", style="green")
            
            # Key info
            output.append(f"     Key: {cert.key_algorithm}-{cert.key_size}\n")
            
            # Security level
            level_color = self.security_colors.get(cert.security_level, "white")
            output.append(f"     Security: {cert.security_level.name}\n", style=level_color)
            
            if i < len(certificates) - 1:
                output.append("\n")
        
        return output
    
    def _create_header(self, result: APKSigningAnalysisResult) -> Text:
        """Create formatted header."""
        header = Text()
        header.append("APK SIGNING CERTIFICATE ANALYSIS REPORT\n", style="bold blue")
        header.append("=" * 50 + "\n", style="blue")
        header.append(f"APK: {result.apk_path}\n")
        header.append(f"Package: {result.package_name}\n")
        header.append(f"Analysis Date: {result.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        return header
    
    def _create_executive_summary(self, result: APKSigningAnalysisResult) -> Text:
        """Create executive summary."""
        summary = Text()
        summary.append("EXECUTIVE SUMMARY\n", style="bold")
        summary.append("-" * 20 + "\n")
        
        # Overall status
        if result.digital_signature_valid and result.certificate_chain_valid:
            summary.append("✓ APK signature validation: PASSED\n", style="green")
        else:
            summary.append("✗ APK signature validation: FAILED\n", style="red")
        
        # Signature schemes found
        schemes = [scheme.value for scheme in result.signature_schemes_found]
        summary.append(f"Signature schemes: {', '.join(schemes) if schemes else 'None'}\n")
        
        # Total certificates
        summary.append(f"Total certificates: {result.total_certificates}\n")
        
        # Security score
        if result.security_assessment:
            score = result.security_assessment.overall_score
            level = result.security_assessment.security_level.name
            color = self.security_colors.get(result.security_assessment.security_level, "white")
            summary.append(f"Security score: {score:.1%} ({level})\n", style=color)
        
        # Critical issues
        if result.has_critical_issues:
            summary.append("⚠️  CRITICAL SECURITY ISSUES DETECTED\n", style="red bold")
        
        return summary
    
    def _create_signature_analysis(self, signatures: List[APKSignature]) -> Text:
        """Create signature analysis section."""
        analysis = Text()
        analysis.append("SIGNATURE ANALYSIS\n", style="bold")
        analysis.append("-" * 20 + "\n")
        
        for i, signature in enumerate(signatures):
            analysis.append(f"\nSignature {i+1}: {signature.scheme.value}\n", style="bold cyan")
            
            # Basic info
            analysis.append(f"  Algorithm: {signature.algorithm}\n")
            analysis.append(f"  Digest: {signature.digest_algorithm}\n")
            
            # Verification status
            if signature.verification:
                if signature.verification.is_valid:
                    analysis.append("  Status: ✓ Valid\n", style="green")
                else:
                    analysis.append(f"  Status: ✗ Invalid - {signature.verification.error_message}\n", style="red")
                
                # Trust chain
                if signature.verification.trust_chain_valid:
                    analysis.append("  Trust Chain: ✓ Valid\n", style="green")
                else:
                    analysis.append("  Trust Chain: ✗ Invalid\n", style="red")
            
            # Security issues
            if signature.security_issues:
                analysis.append("  Security Issues:\n", style="orange3")
                for issue in signature.security_issues:
                    analysis.append(f"    • {issue}\n", style="orange3")
            
            # Timestamp
            if signature.timestamp:
                analysis.append(f"  Timestamp: {signature.timestamp}\n")
        
        return analysis
    
    def _create_certificate_details(self, result: APKSigningAnalysisResult) -> Text:
        """Create certificate details section."""
        details = Text()
        details.append("CERTIFICATE DETAILS\n", style="bold")
        details.append("-" * 20 + "\n")
        
        cert_count = 0
        for signature in result.signatures:
            for cert in signature.certificates:
                cert_count += 1
                details.append(f"\nCertificate {cert_count}:\n", style="bold cyan")
                
                # Basic info
                details.append(f"  Subject: {cert.subject}\n")
                details.append(f"  Issuer: {cert.issuer}\n")
                details.append(f"  Serial: {cert.serial_number}\n")
                
                # Validity
                if cert.is_expired():
                    details.append(f"  Validity: EXPIRED on {cert.valid_to}\n", style="red")
                else:
                    days_left = cert.days_until_expiry()
                    details.append(f"  Validity: {cert.valid_from} to {cert.valid_to} ({days_left} days left)\n")
                
                # Key info
                details.append(f"  Public Key: {cert.key_algorithm}-{cert.key_size}\n")
                details.append(f"  Signature Algorithm: {cert.signature_algorithm}\n")
                
                # Fingerprints
                details.append(f"  SHA-256: {cert.fingerprint_sha256}\n")
                details.append(f"  SHA-1: {cert.fingerprint_sha1}\n")
                
                # Self-signed
                if cert.is_self_signed:
                    details.append("  Self-signed: Yes\n", style="yellow")
                
                # Security level
                level_color = self.security_colors.get(cert.security_level, "white")
                details.append(f"  Security Level: {cert.security_level.name}\n", style=level_color)
                
                # Security issues
                if cert.security_issues:
                    details.append("  Security Issues:\n", style="orange3")
                    for issue in cert.security_issues:
                        details.append(f"    • {issue}\n", style="orange3")
                
                # Extensions
                if cert.extensions:
                    details.append(f"  Extensions: {len(cert.extensions)} found\n")
                
                # Key usage
                if cert.key_usage:
                    details.append(f"  Key Usage: {', '.join(cert.key_usage)}\n")
        
        return details
    
    def _create_security_assessment(self, assessment: SecurityAssessment) -> Text:
        """Create security assessment section."""
        sec_assessment = Text()
        sec_assessment.append("SECURITY ASSESSMENT\n", style="bold")
        sec_assessment.append("-" * 20 + "\n")
        
        # Overall score
        score_color = self.security_colors.get(assessment.security_level, "white")
        sec_assessment.append(f"Overall Score: {assessment.overall_score:.1%}\n", style=score_color)
        sec_assessment.append(f"Security Level: {assessment.security_level.name}\n", style=score_color)
        
        # Issues by severity
        if assessment.critical_issues:
            sec_assessment.append(f"\nCRITICAL ISSUES ({len(assessment.critical_issues)}):\n", style="red bold")
            for issue in assessment.critical_issues:
                sec_assessment.append(f"  • {issue}\n", style="red")
        
        if assessment.high_issues:
            sec_assessment.append(f"\nHIGH PRIORITY ISSUES ({len(assessment.high_issues)}):\n", style="orange3 bold")
            for issue in assessment.high_issues:
                sec_assessment.append(f"  • {issue}\n", style="orange3")
        
        if assessment.medium_issues:
            sec_assessment.append(f"\nMEDIUM PRIORITY ISSUES ({len(assessment.medium_issues)}):\n", style="yellow bold")
            for issue in assessment.medium_issues:
                sec_assessment.append(f"  • {issue}\n", style="yellow")
        
        if assessment.low_issues:
            sec_assessment.append(f"\nLOW PRIORITY ISSUES ({len(assessment.low_issues)}):\n", style="blue bold")
            for issue in assessment.low_issues:
                sec_assessment.append(f"  • {issue}\n", style="blue")
        
        # Risk factors
        if assessment.risk_factors:
            sec_assessment.append(f"\nIDENTIFIED RISK FACTORS:\n", style="bold")
            for risk in assessment.risk_factors:
                sec_assessment.append(f"  • {risk}\n")
        
        return sec_assessment
    
    def _create_compliance_assessment(self, assessments: List[ComplianceAssessment]) -> Text:
        """Create compliance assessment section."""
        compliance = Text()
        compliance.append("COMPLIANCE ASSESSMENT\n", style="bold")
        compliance.append("-" * 20 + "\n")
        
        for assessment in assessments:
            # Standard name
            compliance.append(f"\n{assessment.standard.value}:\n", style="bold cyan")
            
            # Compliance status
            if assessment.compliant:
                compliance.append("  Status: ✓ COMPLIANT\n", style="green")
            else:
                compliance.append("  Status: ✗ NON-COMPLIANT\n", style="red")
            
            # Score
            compliance.append(f"  Score: {assessment.score:.1%}\n")
            
            # Issues
            if assessment.issues:
                compliance.append("  Issues:\n", style="orange3")
                for issue in assessment.issues:
                    compliance.append(f"    • {issue}\n", style="orange3")
            
            # Recommendations
            if assessment.recommendations:
                compliance.append("  Recommendations:\n", style="blue")
                for rec in assessment.recommendations:
                    compliance.append(f"    • {rec}\n", style="blue")
        
        return compliance
    
    def _create_recommendations(self, result: APKSigningAnalysisResult) -> Text:
        """Create recommendations section."""
        recommendations = Text()
        recommendations.append("RECOMMENDATIONS\n", style="bold")
        recommendations.append("-" * 20 + "\n")
        
        all_recommendations = set()
        
        # Security recommendations
        if result.security_assessment and result.security_assessment.recommendations:
            all_recommendations.update(result.security_assessment.recommendations)
        
        # Compliance recommendations
        for compliance in result.compliance_assessments:
            all_recommendations.update(compliance.recommendations)
        
        # General recommendations based on findings
        if result.has_critical_issues:
            all_recommendations.add("URGENT: Address critical security issues before deploying to production")
        
        if not result.digital_signature_valid:
            all_recommendations.add("Re-sign the APK with valid certificates and stronger cryptographic methods")
        
        if not result.certificate_chain_valid:
            all_recommendations.add("Establish proper certificate trust chain with recognized Certificate Authorities")
        
        # Format recommendations
        if all_recommendations:
            for i, rec in enumerate(sorted(all_recommendations), 1):
                recommendations.append(f"{i}. {rec}\n")
        else:
            recommendations.append("No specific recommendations at this time.\n", style="green")
        
        return recommendations
    
    def to_dict(self, result: APKSigningAnalysisResult) -> Dict[str, Any]:
        """Convert analysis result to dictionary format."""
        try:
            return result.to_dict()
        except Exception as e:
            logger.error(f"Failed to convert result to dictionary: {e}")
            return {
                'error': f"Failed to serialize result: {e}",
                'apk_path': result.apk_path,
                'analysis_timestamp': result.analysis_timestamp.isoformat()
            }
    
    def create_summary_table(self, results: List[APKSigningAnalysisResult]) -> Text:
        """Create a summary table for multiple APK analysis results."""
        summary = Text()
        summary.append("APK SIGNING ANALYSIS SUMMARY\n", style="bold blue")
        summary.append("=" * 40 + "\n", style="blue")
        
        if not results:
            summary.append("No analysis results to display\n", style="red")
            return summary
        
        for i, result in enumerate(results, 1):
            summary.append(f"\n{i}. {result.package_name}\n", style="bold")
            summary.append(f"   APK: {result.apk_path}\n")
            
            # Status
            if result.digital_signature_valid:
                summary.append("   Status: ✓ Valid\n", style="green")
            else:
                summary.append("   Status: ✗ Invalid\n", style="red")
            
            # Security score
            if result.security_assessment:
                score = result.security_assessment.overall_score
                level = result.security_assessment.security_level.name
                color = self.security_colors.get(result.security_assessment.security_level, "white")
                summary.append(f"   Security: {score:.1%} ({level})\n", style=color)
            
            # Signature schemes
            schemes = [scheme.value for scheme in result.signature_schemes_found]
            summary.append(f"   Schemes: {', '.join(schemes) if schemes else 'None'}\n")
            
            # Critical issues
            if result.has_critical_issues:
                summary.append("   ⚠️  Critical issues detected\n", style="red")
        
        return summary 