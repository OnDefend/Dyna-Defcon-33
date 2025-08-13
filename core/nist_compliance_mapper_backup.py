#!/usr/bin/env python3
"""
NIST Cybersecurity Framework Compliance Mapper for AODS

This module provides comprehensive mapping between AODS vulnerability findings
and the NIST Cybersecurity Framework (CSF) v1.1, enabling enterprise-grade
compliance reporting and risk assessment.

"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, Any

from rich.text import Text

# Import configuration loader
try:
    from .nist_config_loader import get_nist_config, NISTConfigLoader
except ImportError:
    from nist_config_loader import get_nist_config, NISTConfigLoader

class NISTFunction(Enum):
    """NIST Cybersecurity Framework Core Functions"""
    IDENTIFY = "ID"
    PROTECT = "PR" 
    DETECT = "DE"
    RESPOND = "RS"
    RECOVER = "RC"

class NISTCategory(Enum):
    """NIST Cybersecurity Framework Categories"""
    # IDENTIFY (ID)
    ID_AM = "ID.AM"  # Asset Management
    ID_BE = "ID.BE"  # Business Environment
    ID_GV = "ID.GV"  # Governance
    ID_RA = "ID.RA"  # Risk Assessment
    ID_RM = "ID.RM"  # Risk Management Strategy
    ID_SC = "ID.SC"  # Supply Chain Risk Management
    
    # PROTECT (PR)
    PR_AC = "PR.AC"  # Identity Management and Access Control
    PR_AT = "PR.AT"  # Awareness and Training
    PR_DS = "PR.DS"  # Data Security
    PR_IP = "PR.IP"  # Information Protection Processes and Procedures
    PR_MA = "PR.MA"  # Maintenance
    PR_PT = "PR.PT"  # Protective Technology
    
    # DETECT (DE)
    DE_AE = "DE.AE"  # Anomalies and Events
    DE_CM = "DE.CM"  # Security Continuous Monitoring
    DE_DP = "DE.DP"  # Detection Processes
    
    # RESPOND (RS)
    RS_RP = "RS.RP"  # Response Planning
    RS_CO = "RS.CO"  # Communications
    RS_AN = "RS.AN"  # Analysis
    RS_MI = "RS.MI"  # Mitigation
    RS_IM = "RS.IM"  # Improvements
    
    # RECOVER (RC)
    RC_RP = "RC.RP"  # Recovery Planning
    RC_IM = "RC.IM"  # Improvements
    RC_CO = "RC.CO"  # Communications

class NISTImplementationTier(Enum):
    """NIST Framework Implementation Tiers"""
    PARTIAL = 1      # Partial
    RISK_INFORMED = 2  # Risk Informed
    REPEATABLE = 3   # Repeatable
    ADAPTIVE = 4     # Adaptive

@dataclass
class NISTSubcategory:
    """NIST Framework Subcategory definition"""
    id: str
    category: NISTCategory
    title: str
    description: str
    informative_references: List[str] = field(default_factory=list)

@dataclass
class NISTMapping:
    """Mapping between AODS finding and NIST subcategory"""
    subcategory_id: str
    subcategory: NISTSubcategory
    vulnerability_type: str
    severity: str
    confidence: float
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

@dataclass
class NISTComplianceAssessment:
    """NIST Compliance Assessment Result"""
    subcategory_id: str
    current_tier: NISTImplementationTier
    target_tier: NISTImplementationTier
    compliance_score: float  # 0-100
    gaps_identified: List[str] = field(default_factory=list)
    improvement_recommendations: List[str] = field(default_factory=list)
    supporting_evidence: List[str] = field(default_factory=list)

@dataclass
class NISTFrameworkReport:
    """Comprehensive NIST Framework compliance report"""
    assessment_date: datetime
    organization_profile: Dict[str, Any]
    current_state_assessment: Dict[str, NISTComplianceAssessment]
    target_state_definition: Dict[str, NISTImplementationTier]
    gap_analysis: Dict[str, List[str]]
    priority_recommendations: List[str]
    implementation_roadmap: List[Dict[str, Any]]
    overall_maturity_score: float
    executive_summary: str

class NISTCybersecurityFrameworkMapper:
    """
    Comprehensive NIST Cybersecurity Framework compliance mapper for AODS.
    
    This class provides enterprise-grade mapping between mobile application
    security findings and NIST CSF requirements, enabling comprehensive
    compliance reporting and risk assessment.
    """
    
    def __init__(self, organization_name: str = "AODS Security Assessment"):
        """
        Initialize NIST Framework mapper.
        
        Args:
            organization_name: Name of organization for reporting
        """
        self.organization_name = organization_name
        self.logger = logging.getLogger(f"{__name__}.NISTMapper")
        
        # Load configuration
        self.config = get_nist_config()
        self.logger.info("🔧 NIST configuration loaded successfully")
        
        # Initialize NIST Framework structure
        self._initialize_nist_subcategories()
        self._initialize_vulnerability_mappings()
        
        # Assessment state
        self.current_findings: List[Dict[str, Any]] = []
        self.nist_mappings: List[NISTMapping] = []
        self.compliance_assessments: Dict[str, NISTComplianceAssessment] = {}
        
        self.logger.info("🏛️ NIST Cybersecurity Framework Mapper initialized")
    
    def _initialize_nist_subcategories(self) -> None:
        """Initialize comprehensive NIST Framework subcategories relevant to mobile security"""
        self.nist_subcategories = {
            # IDENTIFY - Asset Management
            "ID.AM-1": NISTSubcategory(
                "ID.AM-1", NISTCategory.ID_AM,
                "Physical devices and systems within the organization are inventoried",
                "Mobile devices, applications, and associated infrastructure are catalogued",
                ["ISO 27001", "NIST SP 800-53"]
            ),
            "ID.AM-2": NISTSubcategory(
                "ID.AM-2", NISTCategory.ID_AM,
                "Software platforms and applications within the organization are inventoried",
                "Mobile applications and their components are documented and tracked",
                ["OWASP MASVS", "NIST SP 800-53"]
            ),
            
            # IDENTIFY - Risk Assessment
            "ID.RA-1": NISTSubcategory(
                "ID.RA-1", NISTCategory.ID_RA,
                "Asset vulnerabilities are identified and documented",
                "Mobile application vulnerabilities are systematically identified",
                ["OWASP MASTG", "NIST SP 800-30"]
            ),
            "ID.RA-2": NISTSubcategory(
                "ID.RA-2", NISTCategory.ID_RA,
                "Cyber threat intelligence is received from information sharing forums",
                "Mobile security threat intelligence is incorporated into risk assessment",
                ["NIST SP 800-150", "MITRE ATT&CK"]
            ),
            
            # PROTECT - Access Control
            "PR.AC-1": NISTSubcategory(
                "PR.AC-1", NISTCategory.PR_AC,
                "Identities and credentials are issued, managed, verified, revoked, and audited",
                "Mobile application authentication mechanisms are properly implemented",
                ["OWASP MASVS-AUTH", "NIST SP 800-63"]
            ),
            "PR.AC-3": NISTSubcategory(
                "PR.AC-3", NISTCategory.PR_AC,
                "Remote access is managed",
                "Mobile application network communications are secured",
                ["OWASP MASVS-NETWORK", "NIST SP 800-114"]
            ),
            "PR.AC-4": NISTSubcategory(
                "PR.AC-4", NISTCategory.PR_AC,
                "Access permissions and authorizations are managed",
                "Mobile application permissions and access controls are properly configured",
                ["OWASP MASVS-PLATFORM", "Android Security"]
            ),
            
            # PROTECT - Data Security
            "PR.DS-1": NISTSubcategory(
                "PR.DS-1", NISTCategory.PR_DS,
                "Data-at-rest is protected",
                "Mobile application data storage is secured with encryption",
                ["OWASP MASVS-STORAGE", "NIST SP 800-111"]
            ),
            "PR.DS-2": NISTSubcategory(
                "PR.DS-2", NISTCategory.PR_DS,
                "Data-in-transit is protected",
                "Mobile application network communications use secure protocols",
                ["OWASP MASVS-NETWORK", "NIST SP 800-52"]
            ),
            "PR.DS-3": NISTSubcategory(
                "PR.DS-3", NISTCategory.PR_DS,
                "Assets are formally managed throughout removal, transfers, and disposition",
                "Mobile application data lifecycle is properly managed",
                ["OWASP MASVS-STORAGE", "NIST SP 800-88"]
            ),
            
            # PROTECT - Information Protection Processes
            "PR.IP-1": NISTSubcategory(
                "PR.IP-1", NISTCategory.PR_IP,
                "A baseline configuration of information technology/industrial control systems is created",
                "Mobile applications follow secure development and configuration baselines",
                ["OWASP MASVS", "NIST SP 800-70"]
            ),
            
            # PROTECT - Protective Technology
            "PR.PT-1": NISTSubcategory(
                "PR.PT-1", NISTCategory.PR_PT,
                "Audit/log records are determined, documented, implemented, and reviewed",
                "Mobile applications implement proper logging and monitoring",
                ["OWASP MASVS-PLATFORM", "NIST SP 800-92"]
            ),
            "PR.PT-3": NISTSubcategory(
                "PR.PT-3", NISTCategory.PR_PT,
                "The principle of least functionality is incorporated",
                "Mobile applications minimize attack surface and unnecessary functionality",
                ["OWASP MASVS-PLATFORM", "NIST SP 800-53"]
            ),
            
            # DETECT - Anomalies and Events
            "DE.AE-2": NISTSubcategory(
                "DE.AE-2", NISTCategory.DE_AE,
                "Detected events are analyzed to understand attack targets and methods",
                "Mobile application security events are analyzed for threat intelligence",
                ["NIST SP 800-61", "MITRE ATT&CK Mobile"]
            ),
            
            # DETECT - Security Continuous Monitoring
            "DE.CM-1": NISTSubcategory(
                "DE.CM-1", NISTCategory.DE_CM,
                "The network is monitored to detect potential cybersecurity events",
                "Mobile application network traffic is monitored for security events",
                ["NIST SP 800-94", "OWASP MASVS-NETWORK"]
            ),
            "DE.CM-4": NISTSubcategory(
                "DE.CM-4", NISTCategory.DE_CM,
                "Malicious code is detected",
                "Mobile applications are analyzed for malicious code and vulnerabilities",
                ["OWASP MASTG", "NIST SP 800-83"]
            ),
            
            # RESPOND - Analysis
            "RS.AN-1": NISTSubcategory(
                "RS.AN-1", NISTCategory.RS_AN,
                "Notifications from detection systems are investigated",
                "Mobile security findings are investigated and analyzed",
                ["NIST SP 800-61", "OWASP MASTG"]
            ),
            "RS.AN-2": NISTSubcategory(
                "RS.AN-2", NISTCategory.RS_AN,
                "The impact of the incident is understood",
                "Mobile application vulnerabilities are assessed for business impact",
                ["NIST SP 800-30", "OWASP Risk Rating"]
            ),
        }
        
        self.logger.info(f"📋 Initialized {len(self.nist_subcategories)} NIST Framework subcategories")
    
    def _initialize_vulnerability_mappings(self) -> None:
        """Initialize mappings between AODS vulnerability types and NIST subcategories"""
        self.vulnerability_mappings = {
            # Authentication and Access Control
            "hardcoded_credentials": ["PR.AC-1", "ID.RA-1"],
            "weak_authentication": ["PR.AC-1", "ID.RA-1"],
            "biometric_bypass": ["PR.AC-1", "PR.AC-4"],
            "session_management": ["PR.AC-1", "PR.DS-2"],
            
            # Data Protection
            "insecure_data_storage": ["PR.DS-1", "ID.RA-1"],
            "data_leakage": ["PR.DS-1", "PR.DS-3"],
            "external_storage": ["PR.DS-1", "PR.DS-3"],
            "database_encryption": ["PR.DS-1", "PR.PT-1"],
            
            # Network Security
            "insecure_communication": ["PR.DS-2", "DE.CM-1"],
            "certificate_pinning": ["PR.DS-2", "PR.AC-3"],
            "network_protocols": ["PR.DS-2", "DE.CM-1"],
            "man_in_the_middle": ["PR.DS-2", "DE.AE-2"],
            
            # Platform Security
            "excessive_permissions": ["PR.AC-4", "PR.PT-3"],
            "exported_components": ["PR.AC-4", "ID.AM-2"],
            "intent_vulnerabilities": ["PR.AC-4", "DE.CM-4"],
            "webview_security": ["PR.PT-3", "DE.CM-4"],
            
            # Code Quality
            "code_injection": ["DE.CM-4", "RS.AN-1"],
            "sql_injection": ["DE.CM-4", "RS.AN-1"],
            "xss_vulnerabilities": ["DE.CM-4", "RS.AN-1"],
            "path_traversal": ["DE.CM-4", "RS.AN-1"],
            
            # Cryptography
            "weak_cryptography": ["PR.DS-1", "PR.DS-2"],
            "crypto_implementation": ["PR.DS-1", "ID.RA-1"],
            "key_management": ["PR.DS-1", "PR.AC-1"],
            
            # Privacy
            "privacy_violations": ["PR.DS-3", "PR.IP-1"],
            "data_collection": ["PR.DS-3", "ID.RA-2"],
            "third_party_sharing": ["PR.DS-3", "ID.AM-2"],
            
            # Runtime Protection
            "anti_tampering": ["PR.PT-1", "DE.AE-2"],
            "runtime_protection": ["PR.PT-1", "DE.CM-4"],
            "debugging_enabled": ["PR.PT-3", "ID.RA-1"],
        }
        
        self.logger.info(f"🔗 Initialized {len(self.vulnerability_mappings)} vulnerability-to-NIST mappings")
    
    def map_aods_findings_to_nist(self, findings: List[Dict[str, Any]]) -> List[NISTMapping]:
        """
        Map AODS vulnerability findings to NIST Framework subcategories.
        
        Args:
            findings: List of AODS vulnerability findings
            
        Returns:
            List of NIST mappings with recommendations
        """
        self.current_findings = findings
        self.nist_mappings = []
        
        self.logger.info(f"🔍 Mapping {len(findings)} AODS findings to NIST Framework...")
        
        for finding in findings:
            # Extract vulnerability information
            vuln_type = self._extract_vulnerability_type(finding)
            severity = finding.get("severity", "MEDIUM")
            confidence = finding.get("confidence", 0.8)
            
            # Map to NIST subcategories
            mapped_subcategories = self.vulnerability_mappings.get(vuln_type, [])
            
            for subcategory_id in mapped_subcategories:
                if subcategory_id in self.nist_subcategories:
                    subcategory = self.nist_subcategories[subcategory_id]
                    
                    # Generate evidence and recommendations
                    evidence = self._generate_evidence(finding, subcategory)
                    recommendations = self._generate_nist_recommendations(finding, subcategory)
                    
                    mapping = NISTMapping(
                        subcategory_id=subcategory_id,
                        subcategory=subcategory,
                        vulnerability_type=vuln_type,
                        severity=severity,
                        confidence=confidence,
                        evidence=evidence,
                        recommendations=recommendations
                    )
                    
                    self.nist_mappings.append(mapping)
        
        self.logger.info(f"✅ Generated {len(self.nist_mappings)} NIST Framework mappings")
        return self.nist_mappings
    
    def assess_nist_compliance(self, target_tier: NISTImplementationTier = NISTImplementationTier.RISK_INFORMED) -> Dict[str, NISTComplianceAssessment]:
        """
        Assess current NIST Framework compliance based on findings.
        
        Args:
            target_tier: Target implementation tier for assessment
            
        Returns:
            Dictionary of compliance assessments by subcategory
        """
        self.compliance_assessments = {}
        
        self.logger.info(f"📊 Assessing NIST compliance against {target_tier.name} tier...")
        
        # Group mappings by subcategory
        subcategory_findings = {}
        for mapping in self.nist_mappings:
            subcategory_id = mapping.subcategory_id
            if subcategory_id not in subcategory_findings:
                subcategory_findings[subcategory_id] = []
            subcategory_findings[subcategory_id].append(mapping)
        
        # Assess each relevant subcategory
        for subcategory_id, subcategory in self.nist_subcategories.items():
            findings = subcategory_findings.get(subcategory_id, [])
            
            # Calculate current tier based on findings
            current_tier = self._calculate_current_tier(findings)
            
            # Calculate compliance score
            compliance_score = self._calculate_compliance_score(current_tier, target_tier, findings)
            
            # Identify gaps
            gaps = self._identify_compliance_gaps(findings, target_tier)
            
            # Generate improvement recommendations
            improvements = self._generate_improvement_recommendations(subcategory, findings, target_tier)
            
            # Collect supporting evidence
            evidence = [f.evidence for f in findings]
            flattened_evidence = [item for sublist in evidence for item in sublist]
            
            assessment = NISTComplianceAssessment(
                subcategory_id=subcategory_id,
                current_tier=current_tier,
                target_tier=target_tier,
                compliance_score=compliance_score,
                gaps_identified=gaps,
                improvement_recommendations=improvements,
                supporting_evidence=flattened_evidence
            )
            
            self.compliance_assessments[subcategory_id] = assessment
        
        self.logger.info(f"📈 Completed compliance assessment for {len(self.compliance_assessments)} subcategories")
        return self.compliance_assessments
    
    def generate_nist_framework_report(self, target_tier: NISTImplementationTier = NISTImplementationTier.RISK_INFORMED) -> NISTFrameworkReport:
        """
        Generate comprehensive NIST Framework compliance report.
        
        Args:
            target_tier: Target implementation tier
            
        Returns:
            Comprehensive NIST Framework report
        """
        self.logger.info("📋 Generating comprehensive NIST Framework report...")
        
        # Calculate overall maturity score
        overall_score = self._calculate_overall_maturity_score()
        
        # Generate gap analysis
        gap_analysis = self._generate_gap_analysis()
        
        # Generate priority recommendations
        priority_recommendations = self._generate_priority_recommendations()
        
        # Generate implementation roadmap
        implementation_roadmap = self._generate_implementation_roadmap()
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(overall_score)
        
        # Define organization profile
        organization_profile = {
            "organization_name": self.organization_name,
            "assessment_scope": "Mobile Application Security",
            "framework_version": "NIST CSF v1.1",
            "assessment_methodology": "AODS Automated Security Analysis",
            "target_implementation_tier": target_tier.name,
            "total_applications_assessed": 1,
            "total_vulnerabilities_analyzed": len(self.current_findings)
        }
        
        # Define target state
        target_state = {
            subcategory_id: target_tier 
            for subcategory_id in self.nist_subcategories.keys()
        }
        
        report = NISTFrameworkReport(
            assessment_date=datetime.now(),
            organization_profile=organization_profile,
            current_state_assessment=self.compliance_assessments,
            target_state_definition=target_state,
            gap_analysis=gap_analysis,
            priority_recommendations=priority_recommendations,
            implementation_roadmap=implementation_roadmap,
            overall_maturity_score=overall_score,
            executive_summary=executive_summary
        )
        
        self.logger.info("✅ NIST Framework report generation completed")
        return report
    
    def export_nist_compliance_report(self, report: NISTFrameworkReport, output_path: Path) -> Path:
        """
        Export NIST compliance report to JSON format.
        
        Args:
            report: NIST Framework report
            output_path: Output file path
            
        Returns:
            Path to exported report
        """
        self.logger.info(f"💾 Exporting NIST compliance report to {output_path}")
        
        # Convert report to serializable format
        report_data = {
            "nist_framework_compliance_report": {
                "metadata": {
                    "assessment_date": report.assessment_date.isoformat(),
                    "report_version": "1.0.0",
                    "framework_version": "NIST CSF v1.1",
                    "generated_by": "AODS NIST Compliance Mapper"
                },
                "organization_profile": report.organization_profile,
                "executive_summary": report.executive_summary,
                "overall_maturity_score": report.overall_maturity_score,
                "current_state_assessment": {
                    subcategory_id: {
                        "current_tier": assessment.current_tier.name,
                        "target_tier": assessment.target_tier.name,
                        "compliance_score": assessment.compliance_score,
                        "gaps_identified": assessment.gaps_identified,
                        "improvement_recommendations": assessment.improvement_recommendations,
                        "supporting_evidence_count": len(assessment.supporting_evidence)
                    }
                    for subcategory_id, assessment in report.current_state_assessment.items()
                },
                "gap_analysis": report.gap_analysis,
                "priority_recommendations": report.priority_recommendations,
                "implementation_roadmap": report.implementation_roadmap
            }
        }
        
        # Export to JSON
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"✅ NIST compliance report exported successfully")
        return output_path
    
    def generate_nist_compliance_text_report(self, report: NISTFrameworkReport) -> Text:
        """
        Generate formatted text report for console display.
        
        Args:
            report: NIST Framework report
            
        Returns:
            Rich Text object for display
        """
        text_report = Text()
        
        # Header
        text_report.append("🏛️ NIST Cybersecurity Framework Compliance Report\n", style="bold blue")
        text_report.append("=" * 80 + "\n\n", style="blue")
        
        # Executive Summary
        text_report.append("📊 Executive Summary\n", style="bold green")
        text_report.append(f"Organization: {report.organization_profile['organization_name']}\n")
        text_report.append(f"Assessment Date: {report.assessment_date.strftime('%Y-%m-%d %H:%M:%S')}\n")
        text_report.append(f"Framework Version: {report.organization_profile['framework_version']}\n")
        text_report.append(f"Target Tier: {list(report.target_state_definition.values())[0].name}\n")
        
        # Overall Maturity Score
        score_color = "green" if report.overall_maturity_score >= 80 else "yellow" if report.overall_maturity_score >= 60 else "red"
        text_report.append(f"Overall Maturity Score: {report.overall_maturity_score:.1f}%\n\n", style=f"bold {score_color}")
        
        # Function-level compliance
        text_report.append("🔍 NIST Function Compliance\n", style="bold cyan")
        function_scores = self._calculate_function_scores(report.current_state_assessment)
        
        for function, score in function_scores.items():
            score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
            text_report.append(f"  {function.value} ({function.name}): {score:.1f}%\n", style=score_color)
        
        text_report.append("\n")
        
        # Priority Recommendations
        text_report.append("💡 Priority Recommendations\n", style="bold yellow")
        for i, recommendation in enumerate(report.priority_recommendations[:10], 1):
            text_report.append(f"  {i}. {recommendation}\n", style="yellow")
        
        text_report.append("\n")
        
        # Implementation Roadmap
        text_report.append("🗺️ Implementation Roadmap\n", style="bold magenta")
        for phase in report.implementation_roadmap[:5]:
            text_report.append(f"  Phase {phase['phase']}: {phase['title']}\n", style="magenta")
            text_report.append(f"    Duration: {phase['duration']}\n", style="dim")
            text_report.append(f"    Priority: {phase['priority']}\n", style="dim")
        
        return text_report
    
    def _extract_vulnerability_type(self, finding: Dict[str, Any]) -> str:
        """Extract standardized vulnerability type from finding"""
        # Try different possible fields for vulnerability type
        vuln_type = finding.get("vulnerability_type", "")
        if not vuln_type:
            vuln_type = finding.get("type", "")
        if not vuln_type:
            vuln_type = finding.get("category", "")
        
        # Normalize vulnerability type
        vuln_type_lower = vuln_type.lower()
        
        # Map to standardized types
        if "credential" in vuln_type_lower or "password" in vuln_type_lower:
            return "hardcoded_credentials"
        elif "authentication" in vuln_type_lower or "auth" in vuln_type_lower:
            return "weak_authentication"
        elif "storage" in vuln_type_lower or "data" in vuln_type_lower:
            return "insecure_data_storage"
        elif "network" in vuln_type_lower or "communication" in vuln_type_lower:
            return "insecure_communication"
        elif "permission" in vuln_type_lower:
            return "excessive_permissions"
        elif "injection" in vuln_type_lower:
            return "code_injection"
        elif "crypto" in vuln_type_lower or "encryption" in vuln_type_lower:
            return "weak_cryptography"
        elif "privacy" in vuln_type_lower:
            return "privacy_violations"
        else:
            return "general_security"
    
    def _generate_evidence(self, finding: Dict[str, Any], subcategory: NISTSubcategory) -> List[str]:
        """Generate evidence for NIST mapping"""
        evidence = []
        
        # Add finding details as evidence
        if finding.get("file_path"):
            evidence.append(f"Vulnerability found in: {finding['file_path']}")
        
        if finding.get("line_number"):
            evidence.append(f"Location: Line {finding['line_number']}")
        
        if finding.get("description"):
            evidence.append(f"Description: {finding['description']}")
        
        if finding.get("cwe_id"):
            evidence.append(f"CWE Classification: {finding['cwe_id']}")
        
        # Add subcategory context
        evidence.append(f"NIST Subcategory: {subcategory.id} - {subcategory.title}")
        
        return evidence
    
    def _generate_nist_recommendations(self, finding: Dict[str, Any], subcategory: NISTSubcategory) -> List[str]:
        """Generate NIST-aligned recommendations"""
        recommendations = []
        
        # Base recommendations from finding
        if finding.get("recommendations"):
            recommendations.extend(finding["recommendations"])
        
        # Add NIST-specific recommendations based on subcategory
        if subcategory.category == NISTCategory.PR_AC:
            recommendations.append("Implement strong identity and access management controls")
            recommendations.append("Review and minimize application permissions")
        elif subcategory.category == NISTCategory.PR_DS:
            recommendations.append("Implement encryption for data at rest and in transit")
            recommendations.append("Establish data classification and handling procedures")
        elif subcategory.category == NISTCategory.DE_CM:
            recommendations.append("Implement continuous security monitoring")
            recommendations.append("Establish security event detection and analysis capabilities")
        
        return recommendations
    
    def _calculate_current_tier(self, findings: List[NISTMapping]) -> NISTImplementationTier:
        """Calculate current implementation tier based on findings"""
        if not findings:
            return NISTImplementationTier.PARTIAL
        
        # Calculate severity-weighted score
        severity_weights = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        total_weight = 0
        severity_score = 0
        
        for finding in findings:
            weight = severity_weights.get(finding.severity, 2)
            total_weight += weight
            # Higher severity = lower tier
            severity_score += weight * (5 - weight)
        
        if total_weight == 0:
            return NISTImplementationTier.PARTIAL
        
        normalized_score = severity_score / (total_weight * 4)  # Normalize to 0-1
        
        # Map to tiers
        if normalized_score >= 0.8:
            return NISTImplementationTier.ADAPTIVE
        elif normalized_score >= 0.6:
            return NISTImplementationTier.REPEATABLE
        elif normalized_score >= 0.4:
            return NISTImplementationTier.RISK_INFORMED
        else:
            return NISTImplementationTier.PARTIAL
    
    def _calculate_compliance_score(self, current_tier: NISTImplementationTier, target_tier: NISTImplementationTier, findings: List[NISTMapping]) -> float:
        """Calculate compliance score (0-100)"""
        tier_scores = {
            NISTImplementationTier.PARTIAL: 25,
            NISTImplementationTier.RISK_INFORMED: 50,
            NISTImplementationTier.REPEATABLE: 75,
            NISTImplementationTier.ADAPTIVE: 100
        }
        
        current_score = tier_scores[current_tier]
        target_score = tier_scores[target_tier]
        
        # Adjust based on findings severity
        if findings:
            critical_findings = len([f for f in findings if f.severity == "CRITICAL"])
            high_findings = len([f for f in findings if f.severity == "HIGH"])
            
            # Penalty for critical/high findings
            penalty = (critical_findings * 20) + (high_findings * 10)
            current_score = max(0, current_score - penalty)
        
        # Calculate compliance as percentage of target
        compliance_score = (current_score / target_score) * 100 if target_score > 0 else 0
        return min(100, compliance_score)
    
    def _identify_compliance_gaps(self, findings: List[NISTMapping], target_tier: NISTImplementationTier) -> List[str]:
        """Identify compliance gaps"""
        gaps = []
        
        if findings:
            critical_findings = [f for f in findings if f.severity == "CRITICAL"]
            high_findings = [f for f in findings if f.severity == "HIGH"]
            
            if critical_findings:
                gaps.append(f"{len(critical_findings)} critical security vulnerabilities identified")
            
            if high_findings:
                gaps.append(f"{len(high_findings)} high-severity security issues found")
            
            # Add specific gaps based on vulnerability types
            vuln_types = set(f.vulnerability_type for f in findings)
            for vuln_type in vuln_types:
                if vuln_type == "hardcoded_credentials":
                    gaps.append("Hardcoded credentials compromise identity management")
                elif vuln_type == "insecure_data_storage":
                    gaps.append("Insecure data storage violates data protection requirements")
                elif vuln_type == "insecure_communication":
                    gaps.append("Insecure network communications expose data in transit")
        
        return gaps
    
    def _generate_improvement_recommendations(self, subcategory: NISTSubcategory, findings: List[NISTMapping], target_tier: NISTImplementationTier) -> List[str]:
        """Generate improvement recommendations"""
        recommendations = []
        
        # Add tier-specific recommendations
        if target_tier == NISTImplementationTier.ADAPTIVE:
            recommendations.append("Implement adaptive risk management processes")
            recommendations.append("Establish continuous improvement mechanisms")
        elif target_tier == NISTImplementationTier.REPEATABLE:
            recommendations.append("Standardize security processes and procedures")
            recommendations.append("Implement regular security assessments")
        
        # Add category-specific recommendations
        if subcategory.category == NISTCategory.PR_AC:
            recommendations.append("Implement multi-factor authentication")
            recommendations.append("Regular access rights reviews and updates")
        elif subcategory.category == NISTCategory.PR_DS:
            recommendations.append("Implement comprehensive data encryption strategy")
            recommendations.append("Establish data loss prevention controls")
        
        return recommendations
    
    def _calculate_overall_maturity_score(self) -> float:
        """Calculate overall organizational maturity score"""
        if not self.compliance_assessments:
            return 0.0
        
        total_score = sum(assessment.compliance_score for assessment in self.compliance_assessments.values())
        return total_score / len(self.compliance_assessments)
    
    def _generate_gap_analysis(self) -> Dict[str, List[str]]:
        """Generate comprehensive gap analysis"""
        gap_analysis = {}
        
        for function in NISTFunction:
            function_gaps = []
            
            for subcategory_id, assessment in self.compliance_assessments.items():
                subcategory = self.nist_subcategories[subcategory_id]
                if subcategory.category.value.startswith(function.value):
                    function_gaps.extend(assessment.gaps_identified)
            
            if function_gaps:
                gap_analysis[function.name] = function_gaps
        
        return gap_analysis
    
    def _generate_priority_recommendations(self) -> List[str]:
        """Generate priority recommendations"""
        all_recommendations = []
        
        for assessment in self.compliance_assessments.values():
            all_recommendations.extend(assessment.improvement_recommendations)
        
        # Deduplicate and prioritize
        unique_recommendations = list(set(all_recommendations))
        
        # Sort by priority (critical security issues first)
        priority_keywords = ["critical", "encryption", "authentication", "access control"]
        
        def recommendation_priority(rec):
            rec_lower = rec.lower()
            for i, keyword in enumerate(priority_keywords):
                if keyword in rec_lower:
                    return i
            return len(priority_keywords)
        
        unique_recommendations.sort(key=recommendation_priority)
        return unique_recommendations[:15]  # Top 15 recommendations
    
    def _generate_implementation_roadmap(self) -> List[Dict[str, Any]]:
        """Generate implementation roadmap"""
        roadmap = [
            {
                "phase": 1,
                "title": "Critical Security Vulnerabilities Remediation",
                "duration": "1-2 months",
                "priority": "CRITICAL",
                "focus_areas": ["Authentication", "Data Protection", "Access Control"],
                "expected_outcomes": ["Eliminate critical vulnerabilities", "Improve security posture"]
            },
            {
                "phase": 2,
                "title": "Security Process Standardization",
                "duration": "2-3 months", 
                "priority": "HIGH",
                "focus_areas": ["Security Policies", "Procedures", "Training"],
                "expected_outcomes": ["Standardized security processes", "Improved compliance"]
            },
            {
                "phase": 3,
                "title": "Continuous Monitoring Implementation",
                "duration": "3-4 months",
                "priority": "MEDIUM",
                "focus_areas": ["Security Monitoring", "Incident Response", "Analytics"],
                "expected_outcomes": ["Real-time threat detection", "Faster response times"]
            },
            {
                "phase": 4,
                "title": "Advanced Security Capabilities",
                "duration": "4-6 months",
                "priority": "LOW",
                "focus_areas": ["Threat Intelligence", "Advanced Analytics", "Automation"],
                "expected_outcomes": ["Predictive security", "Automated response"]
            }
        ]
        
        return roadmap
    
    def _generate_executive_summary(self, overall_score: float) -> str:
        """Generate executive summary"""
        risk_level = "LOW" if overall_score >= 80 else "MEDIUM" if overall_score >= 60 else "HIGH"
        
        summary = f"""
        EXECUTIVE SUMMARY
        
        The NIST Cybersecurity Framework assessment of the mobile application reveals an overall 
        maturity score of {overall_score:.1f}%, indicating a {risk_level} risk posture.
        
        KEY FINDINGS:
        • {len(self.current_findings)} security vulnerabilities identified across NIST framework categories
        • {len(self.compliance_assessments)} NIST subcategories assessed for compliance
        • Priority focus areas: Identity Management, Data Protection, and Security Monitoring
        
        RECOMMENDATIONS:
        • Immediate remediation of critical and high-severity vulnerabilities
        • Implementation of comprehensive security controls aligned with NIST framework
        • Establishment of continuous monitoring and improvement processes
        
        This assessment provides a roadmap for achieving target NIST implementation tier and 
        improving overall cybersecurity posture.
        """
        
        return summary.strip()
    
    def _calculate_function_scores(self, assessments: Dict[str, NISTComplianceAssessment]) -> Dict[NISTFunction, float]:
        """Calculate compliance scores by NIST function"""
        function_scores = {}
        
        for function in NISTFunction:
            function_assessments = []
            
            for subcategory_id, assessment in assessments.items():
                subcategory = self.nist_subcategories[subcategory_id]
                if subcategory.category.value.startswith(function.value):
                    function_assessments.append(assessment)
            
            if function_assessments:
                avg_score = sum(a.compliance_score for a in function_assessments) / len(function_assessments)
                function_scores[function] = avg_score
            else:
                function_scores[function] = 0.0
        
        return function_scores

# Plugin Integration Function
def create_nist_compliance_mapper(organization_name: str = "AODS Security Assessment") -> NISTCybersecurityFrameworkMapper:
    """
    Create and initialize NIST Cybersecurity Framework mapper.
    
    Args:
        organization_name: Organization name for reporting
        
    Returns:
        Initialized NIST compliance mapper
    """
    return NISTCybersecurityFrameworkMapper(organization_name)

def run_nist_compliance_analysis(apk_ctx, findings: List[Dict[str, Any]]) -> Tuple[str, Union[str, Text]]:
    """
    Run comprehensive NIST Cybersecurity Framework compliance analysis.
    
    Args:
        apk_ctx: APK context object
        findings: List of AODS vulnerability findings
        
    Returns:
        Tuple of (title, analysis_result)
    """
    try:
        # Initialize NIST mapper
        nist_mapper = create_nist_compliance_mapper(
            organization_name=f"AODS Assessment - {apk_ctx.package_name}"
        )
        
        # Map findings to NIST framework
        nist_mappings = nist_mapper.map_aods_findings_to_nist(findings)
        
        # Assess compliance
        compliance_assessments = nist_mapper.assess_nist_compliance(
            target_tier=NISTImplementationTier.RISK_INFORMED
        )
        
        # Generate comprehensive report
        nist_report = nist_mapper.generate_nist_framework_report()
        
        # Export detailed report
        export_path = apk_ctx.workspace_dir / f"nist_compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        nist_mapper.export_nist_compliance_report(nist_report, export_path)
        
        # Generate text report for display
        text_report = nist_mapper.generate_nist_compliance_text_report(nist_report)
        
        # Add export information
        text_report.append(f"\n📄 Detailed NIST compliance report exported to: {export_path}\n", style="dim")
        
        # Cache results for integration
        apk_ctx.set_cache("nist_compliance_results", {
            "mappings": len(nist_mappings),
            "assessments": len(compliance_assessments),
            "overall_score": nist_report.overall_maturity_score,
            "export_path": str(export_path)
        })
        
        return "🏛️ NIST Cybersecurity Framework Compliance", text_report
        
    except Exception as e:
        error_msg = f"NIST compliance analysis failed: {str(e)}"
        logging.error(error_msg)
        return "❌ NIST Compliance Analysis", Text(error_msg, style="red")

if __name__ == "__main__":
    # Example usage
    mapper = create_nist_compliance_mapper("Example Organization")
    
    # Example findings
    example_findings = [
        {
            "vulnerability_type": "hardcoded_credentials",
            "severity": "HIGH",
            "file_path": "app/src/main/java/com/example/LoginActivity.java",
            "line_number": 42,
            "description": "Hardcoded API key found in source code",
            "cwe_id": "CWE-798"
        }
    ]
    
    # Run analysis
    mappings = mapper.map_aods_findings_to_nist(example_findings)
    assessments = mapper.assess_nist_compliance()
    report = mapper.generate_nist_framework_report()
    
    print(f"Generated {len(mappings)} NIST mappings")
    print(f"Overall maturity score: {report.overall_maturity_score:.1f}%") 