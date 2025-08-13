#!/usr/bin/env python3
"""
Data Structures for AODS Unified Reporting Framework

Standardized data structures for consistent report generation across all formats
and report types. Provides type safety and structured data organization.

Features:
- Standardized report metadata and context
- Security finding representations
- Report configuration and templates
- Rich data structures for complex reports
- Validation and serialization support
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union, Set
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

class ReportFormat(Enum):
    """Supported report output formats."""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    XML = "xml"
    MARKDOWN = "markdown"
    CSV = "csv"
    EXCEL = "excel"

class ReportType(Enum):
    """Types of reports that can be generated."""
    SECURITY_ANALYSIS = "security_analysis"
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAILS = "technical_details"
    COMPLIANCE_ASSESSMENT = "compliance_assessment"
    VULNERABILITY_REPORT = "vulnerability_report"
    DYNAMIC_COORDINATION_ANALYSIS = "dynamic_coordination_analysis"
    CUSTOM = "custom"

class SeverityLevel(Enum):
    """Security finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    MASVS = "MASVS"
    NIST = "NIST"
    OWASP_TOP_10 = "OWASP_TOP_10"
    CWE = "CWE"
    SANS_TOP_25 = "SANS_TOP_25"
    ISO_27001 = "ISO_27001"
    CUSTOM = "custom"

@dataclass
class ReportMetadata:
    """Comprehensive report metadata."""
    title: str
    report_type: ReportType
    format: ReportFormat
    generated_at: datetime = field(default_factory=datetime.now)
    generated_by: str = "AODS Framework"
    version: str = "2.0.0"
    target_application: str = ""
    analysis_duration: float = 0.0
    total_findings: int = 0
    unique_vulnerabilities: int = 0
    risk_score: float = 0.0
    compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)
    custom_metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SecurityFinding:
    """Standardized security finding representation."""
    id: str
    title: str
    description: str
    severity: SeverityLevel
    confidence: float
    category: str
    location: str
    file_path: str = ""
    line_number: Optional[int] = None
    evidence: str = ""
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    owasp_category: str = ""
    masvs_control: str = ""
    nist_control: str = ""
    risk_score: float = 0.0
    exploitability: str = "unknown"
    impact: str = "unknown"
    remediation_effort: str = "unknown"
    false_positive_probability: float = 0.0
    context: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.now)
    plugin_source: str = ""
    technical_details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ReportSection:
    """Individual report section structure."""
    id: str
    title: str
    content: str
    subsections: List['ReportSection'] = field(default_factory=list)
    findings: List[SecurityFinding] = field(default_factory=list)
    charts: List[Dict[str, Any]] = field(default_factory=list)
    tables: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    order: int = 0
    
    def add_subsection(self, subsection: 'ReportSection') -> None:
        """Add a subsection to this section."""
        self.subsections.append(subsection)
    
    def add_finding(self, finding: SecurityFinding) -> None:
        """Add a security finding to this section."""
        self.findings.append(finding)
    
    def get_total_findings(self) -> int:
        """Get total number of findings in this section and all subsections."""
        total = len(self.findings)
        for subsection in self.subsections:
            total += subsection.get_total_findings()
        return total

@dataclass
class ChartConfiguration:
    """Chart configuration for report visualizations."""
    chart_type: str  # bar, pie, line, scatter, heatmap
    title: str
    data: Dict[str, Any]
    width: int = 800
    height: int = 600
    color_scheme: str = "default"
    show_legend: bool = True
    interactive: bool = True
    export_format: str = "png"

@dataclass
class TableConfiguration:
    """Table configuration for report data presentation."""
    title: str
    headers: List[str]
    rows: List[List[str]]
    sortable: bool = True
    filterable: bool = True
    paginated: bool = False
    page_size: int = 50
    styling: Dict[str, str] = field(default_factory=dict)

@dataclass
class ReportTemplate:
    """Report template configuration."""
    name: str
    template_path: str
    supported_formats: List[ReportFormat]
    required_sections: List[str]
    optional_sections: List[str] = field(default_factory=list)
    styling: Dict[str, Any] = field(default_factory=dict)
    custom_fields: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ReportConfiguration:
    """Comprehensive report generation configuration."""
    output_format: ReportFormat
    report_type: ReportType
    template: Optional[ReportTemplate] = None
    output_path: str = ""
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_remediation_guidance: bool = True
    include_compliance_mapping: bool = True
    include_charts: bool = True
    include_appendices: bool = True
    filter_by_severity: List[SeverityLevel] = field(default_factory=list)
    filter_by_category: List[str] = field(default_factory=list)
    sort_findings_by: str = "severity"
    group_findings_by: str = "category"
    max_findings_per_section: int = 0  # 0 = no limit
    include_false_positives: bool = False
    confidence_threshold: float = 0.0
    custom_branding: Dict[str, str] = field(default_factory=dict)
    language: str = "en"
    timezone: str = "UTC"

@dataclass
class ReportContext:
    """Runtime context for report generation."""
    analysis_start_time: datetime
    analysis_end_time: datetime
    target_apk_path: str
    target_apk_hash: str = ""
    target_apk_size: int = 0
    environment_info: Dict[str, str] = field(default_factory=dict)
    plugin_versions: Dict[str, str] = field(default_factory=dict)
    configuration_used: Dict[str, Any] = field(default_factory=dict)
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    errors_encountered: List[str] = field(default_factory=list)
    warnings_issued: List[str] = field(default_factory=list)

@dataclass
class ComplianceAssessment:
    """Compliance framework assessment results."""
    framework: ComplianceFramework
    total_controls: int
    tested_controls: int
    passed_controls: int
    failed_controls: int
    not_applicable_controls: int
    compliance_percentage: float
    risk_score: float
    findings_by_control: Dict[str, List[SecurityFinding]] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    def calculate_compliance_percentage(self) -> float:
        """Calculate compliance percentage."""
        if self.tested_controls == 0:
            return 0.0
        return (self.passed_controls / self.tested_controls) * 100.0

@dataclass
class ExecutiveSummary:
    """Executive summary data structure."""
    overall_risk_score: float
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    info_vulnerabilities: int
    top_vulnerability_categories: List[Dict[str, Any]]
    compliance_assessments: List[ComplianceAssessment]
    key_recommendations: List[str]
    risk_trends: Dict[str, Any] = field(default_factory=dict)
    security_posture: str = ""
    executive_recommendations: List[str] = field(default_factory=list)

@dataclass
class TechnicalReport:
    """Technical report detailed structure."""
    methodology: str
    tools_used: List[str]
    analysis_scope: Dict[str, Any]
    detailed_findings: List[SecurityFinding]
    technical_recommendations: List[str]
    false_positive_analysis: Dict[str, Any]
    performance_analysis: Dict[str, Any]
    appendices: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ReportValidationResult:
    """Report validation results."""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    validation_score: float = 0.0

# Utility functions for data structure operations
def create_default_metadata(report_type: ReportType, format: ReportFormat) -> ReportMetadata:
    """Create default report metadata."""
    return ReportMetadata(
        title=f"AODS {report_type.value.replace('_', ' ').title()} Report",
        report_type=report_type,
        format=format
    )

def create_security_finding(
    title: str,
    description: str,
    severity: SeverityLevel,
    confidence: float,
    category: str,
    location: str,
    **kwargs
) -> SecurityFinding:
    """Create a standardized security finding."""
    return SecurityFinding(
        id=f"finding_{hash(title + location)}",
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        category=category,
        location=location,
        **kwargs
    )

def calculate_risk_score(findings: List[SecurityFinding]) -> float:
    """Calculate overall risk score from findings."""
    if not findings:
        return 0.0
    
    severity_weights = {
        SeverityLevel.CRITICAL: 10.0,
        SeverityLevel.HIGH: 7.5,
        SeverityLevel.MEDIUM: 5.0,
        SeverityLevel.LOW: 2.5,
        SeverityLevel.INFO: 0.0
    }
    
    total_score = 0.0
    total_weight = 0.0
    
    for finding in findings:
        weight = severity_weights.get(finding.severity, 0.0)
        confidence_factor = finding.confidence / 100.0 if finding.confidence > 1.0 else finding.confidence
        
        score = weight * confidence_factor
        total_score += score
        total_weight += weight
    
    if total_weight == 0:
        return 0.0
    
    # Normalize to 0-100 scale
    return min(100.0, (total_score / len(findings)) * 10.0)

def group_findings_by_severity(findings: List[SecurityFinding]) -> Dict[SeverityLevel, List[SecurityFinding]]:
    """Group findings by severity level."""
    grouped = {}
    for severity in SeverityLevel:
        grouped[severity] = [f for f in findings if f.severity == severity]
    return grouped

def group_findings_by_category(findings: List[SecurityFinding]) -> Dict[str, List[SecurityFinding]]:
    """Group findings by category."""
    grouped = {}
    for finding in findings:
        if finding.category not in grouped:
            grouped[finding.category] = []
        grouped[finding.category].append(finding)
    return grouped


# Dynamic Coordination Analysis Data Structures

@dataclass
class ComponentAnalysisResult:
    """Results from individual dynamic analysis components."""
    component_name: str
    component_type: str
    findings_count: int
    execution_time: float
    status: str
    error_message: Optional[str] = None
    findings: List[SecurityFinding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class RuntimePatternResult:
    """Results from runtime vulnerability pattern detection."""
    pattern_id: str
    pattern_name: str
    severity: SeverityLevel
    confidence: float
    evidence_count: int
    detection_timestamp: datetime
    api_signatures: List[str] = field(default_factory=list)
    behavioral_indicators: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    masvs_category: Optional[str] = None
    remediation_guidance: str = ""

@dataclass
class CorrelationAnalysisResult:
    """Results from test result correlation analysis."""
    correlation_strategy: str
    correlation_confidence: float
    primary_finding: SecurityFinding
    supporting_findings: List[SecurityFinding] = field(default_factory=list)
    component_sources: List[str] = field(default_factory=list)
    validation_count: int = 0
    false_positive_indicators: List[str] = field(default_factory=list)

@dataclass
class DynamicCoordinationAnalysisResult:
    """Complete results from coordinated dynamic analysis."""
    coordination_id: str
    analysis_profile: str
    package_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    
    # Component results
    component_results: List[ComponentAnalysisResult] = field(default_factory=list)
    
    # Runtime pattern detection
    runtime_patterns: List[RuntimePatternResult] = field(default_factory=list)
    
    # Correlation analysis
    correlated_findings: List[CorrelationAnalysisResult] = field(default_factory=list)
    uncorrelated_findings: List[SecurityFinding] = field(default_factory=list)
    
    # Coordination statistics
    total_findings: int = 0
    correlation_rate: float = 0.0
    cross_component_validations: int = 0
    false_positive_rate: float = 0.0
    
    # Performance metrics
    coordination_overhead: float = 0.0
    shared_resource_efficiency: float = 0.0
    
    # Infrastructure status
    frida_enabled: bool = False
    runtime_patterns_enabled: bool = False
    correlation_enabled: bool = False
    
    def get_analysis_duration(self) -> Optional[timedelta]:
        """Get analysis duration if end time is available."""
        if self.end_time:
            return self.end_time - self.start_time
        return None
    
    def get_component_summary(self) -> Dict[str, int]:
        """Get summary of component findings."""
        summary = {}
        for component in self.component_results:
            summary[component.component_name] = component.findings_count
        return summary
    
    def get_severity_distribution(self) -> Dict[str, int]:
        """Get distribution of findings by severity."""
        distribution = {severity.value: 0 for severity in SeverityLevel}
        
        # Count from runtime patterns
        for pattern in self.runtime_patterns:
            distribution[pattern.severity.value] += 1
        
        # Count from correlated findings
        for corr_finding in self.correlated_findings:
            distribution[corr_finding.primary_finding.severity.value] += 1
        
        # Count from uncorrelated findings
        for finding in self.uncorrelated_findings:
            distribution[finding.severity.value] += 1
            
        return distribution 