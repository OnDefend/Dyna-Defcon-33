#!/usr/bin/env python3
"""
NIST Compliance Reporting Data Structures

This module defines the core data structures, enums, and NIST Cybersecurity Framework
definitions used throughout the NIST compliance reporting plugin components.

Classes:
- NISTComplianceReport: Complete compliance assessment result
- NISTFinding: NIST-mapped vulnerability finding
- NISTSubcategoryAssessment: Individual subcategory compliance assessment
- NISTConfig: Configuration settings for compliance analysis
- ComplianceGapAnalysis: Gap analysis results
- ImplementationRoadmap: Remediation and implementation plan

Enums:
- NISTImplementationTier: NIST CSF implementation tiers
- ComplianceLevel: Overall compliance assessment levels
- NISTFunction: NIST CSF core functions
- RiskLevel: Risk assessment levels
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from datetime import datetime

class NISTImplementationTier(Enum):
    """NIST Cybersecurity Framework implementation tiers."""
    PARTIAL = "partial"
    RISK_INFORMED = "risk_informed"
    REPEATABLE = "repeatable"
    ADAPTIVE = "adaptive"

class ComplianceLevel(Enum):
    """Overall compliance assessment levels."""
    EXCELLENT = "excellent"
    GOOD = "good"
    ACCEPTABLE = "acceptable"
    NEEDS_IMPROVEMENT = "needs_improvement"
    CRITICAL = "critical"
    INSUFFICIENT_DATA = "insufficient_data"

class NISTFunction(Enum):
    """NIST CSF core functions."""
    IDENTIFY = "identify"
    PROTECT = "protect"
    DETECT = "detect"
    RESPOND = "respond"
    RECOVER = "recover"

class RiskLevel(Enum):
    """Risk assessment levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class MaturityLevel(Enum):
    """Organizational maturity levels for NIST subcategories."""
    NONE = 0
    BASIC = 1
    DEVELOPING = 2
    DEFINED = 3
    MANAGED = 4
    OPTIMIZING = 5

@dataclass
class NISTSubcategoryDefinition:
    """Definition of a NIST CSF subcategory."""
    subcategory_id: str
    function: NISTFunction
    category: str
    subcategory_name: str
    description: str
    informative_references: List[str] = field(default_factory=list)
    weight: float = 1.0

@dataclass
class NISTFinding:
    """NIST-mapped vulnerability finding."""
    # Original AODS finding information
    original_finding_id: str
    finding_type: str
    severity: str
    description: str
    file_path: str
    line_number: int
    
    # NIST CSF mapping
    nist_subcategory: str
    nist_function: NISTFunction
    nist_category: str
    
    # Confidence and validation
    confidence: float = 0.0
    mapping_rationale: str = ""
    automated_mapping: bool = True
    
    # Risk assessment
    risk_level: RiskLevel = RiskLevel.MEDIUM
    impact_description: str = ""
    
    # Evidence and context
    evidence: List[str] = field(default_factory=list)
    remediation_recommendations: List[str] = field(default_factory=list)
    
    # Compliance impact
    compliance_impact: str = ""
    regulatory_requirements: List[str] = field(default_factory=list)
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Post-initialization processing."""
        if isinstance(self.nist_function, str):
            self.nist_function = NISTFunction(self.nist_function)
        if isinstance(self.risk_level, str):
            self.risk_level = RiskLevel(self.risk_level)

@dataclass
class NISTSubcategoryAssessment:
    """Individual NIST subcategory compliance assessment."""
    subcategory_id: str
    subcategory_definition: NISTSubcategoryDefinition
    
    # Assessment results
    maturity_score: float = 0.0
    maturity_level: MaturityLevel = MaturityLevel.NONE
    compliance_status: str = "NOT_ASSESSED"
    
    # Supporting evidence
    mapped_findings: List[NISTFinding] = field(default_factory=list)
    evidence_count: int = 0
    confidence: float = 0.0
    
    # Gap analysis
    current_implementation: str = ""
    target_implementation: str = ""
    gap_description: str = ""
    priority_level: str = "MEDIUM"
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    implementation_guidance: str = ""
    estimated_effort: str = ""
    
    # Risk assessment
    risk_if_not_implemented: RiskLevel = RiskLevel.MEDIUM
    business_impact: str = ""
    
    # Metadata
    assessment_timestamp: datetime = field(default_factory=datetime.now)
    
    def calculate_maturity_score(self) -> float:
        """Calculate maturity score based on findings and evidence."""
        if not self.mapped_findings:
            return 0.0
        
        # Base score from findings quality
        finding_scores = [finding.confidence for finding in self.mapped_findings]
        base_score = sum(finding_scores) / len(finding_scores) if finding_scores else 0.0
        
        # Adjust based on evidence count
        evidence_multiplier = min(1.0, self.evidence_count / 3.0)  # Full score at 3+ evidence
        
        # Adjust based on implementation completeness
        implementation_multiplier = 0.5 if self.current_implementation else 0.2
        
        final_score = base_score * evidence_multiplier * implementation_multiplier
        return min(final_score, 1.0)
    
    def determine_maturity_level(self) -> MaturityLevel:
        """Determine maturity level based on score."""
        score = self.maturity_score
        if score >= 0.9:
            return MaturityLevel.OPTIMIZING
        elif score >= 0.7:
            return MaturityLevel.MANAGED
        elif score >= 0.5:
            return MaturityLevel.DEFINED
        elif score >= 0.3:
            return MaturityLevel.DEVELOPING
        elif score > 0.0:
            return MaturityLevel.BASIC
        else:
            return MaturityLevel.NONE

@dataclass
class ComplianceGap:
    """Individual compliance gap identification."""
    subcategory_id: str
    gap_type: str
    gap_description: str
    current_state: str
    desired_state: str
    
    # Priority and impact
    priority_level: str = "MEDIUM"
    business_impact: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    
    # Implementation details
    estimated_effort: str = ""
    required_resources: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    timeline: str = ""
    
    # Recommendations
    remediation_steps: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Post-initialization processing."""
        if isinstance(self.risk_level, str):
            self.risk_level = RiskLevel(self.risk_level)

@dataclass
class ComplianceGapAnalysis:
    """Complete compliance gap analysis results."""
    total_gaps_identified: int
    critical_gaps: List[ComplianceGap] = field(default_factory=list)
    high_priority_gaps: List[ComplianceGap] = field(default_factory=list)
    medium_priority_gaps: List[ComplianceGap] = field(default_factory=list)
    low_priority_gaps: List[ComplianceGap] = field(default_factory=list)
    
    # Summary statistics
    gap_distribution: Dict[str, int] = field(default_factory=dict)
    function_gaps: Dict[NISTFunction, int] = field(default_factory=dict)
    
    # Analysis metadata
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    target_tier: NISTImplementationTier = NISTImplementationTier.RISK_INFORMED
    
    def get_all_gaps(self) -> List[ComplianceGap]:
        """Get all gaps sorted by priority."""
        return (self.critical_gaps + self.high_priority_gaps + 
                self.medium_priority_gaps + self.low_priority_gaps)
    
    def get_gaps_by_function(self, function: NISTFunction) -> List[ComplianceGap]:
        """Get gaps filtered by NIST function."""
        # Would need subcategory mapping to implement properly
        return []

@dataclass
class ImplementationPhase:
    """Individual phase in implementation roadmap."""
    phase_number: int
    phase_name: str
    description: str
    duration_estimate: str
    
    # Deliverables
    deliverables: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    
    # Gaps addressed
    gaps_addressed: List[ComplianceGap] = field(default_factory=list)
    subcategories_improved: List[str] = field(default_factory=list)
    
    # Resources and dependencies
    required_resources: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    estimated_cost: str = ""
    
    # Risk and impact
    business_value: str = ""
    risk_reduction: str = ""

@dataclass
class ImplementationRoadmap:
    """Complete implementation roadmap for compliance improvement."""
    roadmap_name: str
    total_duration: str
    phases: List[ImplementationPhase] = field(default_factory=list)
    
    # Summary information
    total_gaps_addressed: int = 0
    expected_compliance_improvement: float = 0.0
    target_compliance_level: ComplianceLevel = ComplianceLevel.GOOD
    
    # Resource planning
    total_estimated_cost: str = ""
    resource_requirements: List[str] = field(default_factory=list)
    
    # Risk assessment
    implementation_risks: List[str] = field(default_factory=list)
    success_factors: List[str] = field(default_factory=list)
    
    # Metadata
    creation_timestamp: datetime = field(default_factory=datetime.now)
    target_completion: Optional[datetime] = None
    
    def get_phase_by_number(self, phase_number: int) -> Optional[ImplementationPhase]:
        """Get specific phase by number."""
        for phase in self.phases:
            if phase.phase_number == phase_number:
                return phase
        return None

@dataclass
class NISTComplianceReport:
    """Complete NIST Cybersecurity Framework compliance report."""
    # Overall assessment
    overall_maturity_score: float
    compliance_level: ComplianceLevel
    target_implementation_tier: NISTImplementationTier
    
    # Detailed assessments
    subcategory_assessments: List[NISTSubcategoryAssessment] = field(default_factory=list)
    
    # Analysis results
    gap_analysis: Optional[ComplianceGapAnalysis] = None
    implementation_roadmap: Optional[ImplementationRoadmap] = None
    
    # Supporting data
    findings_analyzed: int = 0
    nist_mappings: List[NISTFinding] = field(default_factory=list)
    
    # Function-level summaries
    function_scores: Dict[NISTFunction, float] = field(default_factory=dict)
    function_assessments: Dict[NISTFunction, str] = field(default_factory=dict)
    
    # Recommendations
    priority_recommendations: List[str] = field(default_factory=list)
    quick_wins: List[str] = field(default_factory=list)
    long_term_initiatives: List[str] = field(default_factory=list)
    
    # Executive summary
    executive_summary: str = ""
    key_strengths: List[str] = field(default_factory=list)
    key_weaknesses: List[str] = field(default_factory=list)
    
    # Metadata
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    analysis_duration: float = 0.0
    def __post_init__(self):
        """Post-initialization processing."""
        if isinstance(self.compliance_level, str):
            self.compliance_level = ComplianceLevel(self.compliance_level)
        if isinstance(self.target_implementation_tier, str):
            self.target_implementation_tier = NISTImplementationTier(self.target_implementation_tier)
        
        # Calculate function scores if not provided
        if not self.function_scores:
            self.function_scores = self._calculate_function_scores()
    
    def _calculate_function_scores(self) -> Dict[NISTFunction, float]:
        """Calculate scores for each NIST function."""
        function_scores = {}
        function_assessments = {}
        
        for function in NISTFunction:
            # Find assessments for this function
            function_assessments_list = [
                assessment for assessment in self.subcategory_assessments
                if assessment.subcategory_definition.function == function
            ]
            
            if function_assessments_list:
                scores = [assessment.maturity_score for assessment in function_assessments_list]
                function_scores[function] = sum(scores) / len(scores)
                
                # Determine assessment level
                avg_score = function_scores[function]
                if avg_score >= 0.8:
                    function_assessments[function] = "EXCELLENT"
                elif avg_score >= 0.6:
                    function_assessments[function] = "GOOD"
                elif avg_score >= 0.4:
                    function_assessments[function] = "ACCEPTABLE"
                else:
                    function_assessments[function] = "NEEDS_IMPROVEMENT"
            else:
                function_scores[function] = 0.0
                function_assessments[function] = "NOT_ASSESSED"
        
        self.function_assessments = function_assessments
        return function_scores
    
    def get_assessment_by_subcategory(self, subcategory_id: str) -> Optional[NISTSubcategoryAssessment]:
        """Get assessment for specific subcategory."""
        for assessment in self.subcategory_assessments:
            if assessment.subcategory_id == subcategory_id:
                return assessment
        return None
    
    def get_critical_gaps(self) -> List[ComplianceGap]:
        """Get critical compliance gaps."""
        if self.gap_analysis:
            return self.gap_analysis.critical_gaps
        return []
    
    def get_top_recommendations(self, count: int = 5) -> List[str]:
        """Get top priority recommendations."""
        return self.priority_recommendations[:count]

@dataclass
class NISTConfig:
    """Configuration settings for NIST compliance analysis."""
    # Analysis settings
    target_implementation_tier: NISTImplementationTier = NISTImplementationTier.RISK_INFORMED
    enable_detailed_mapping: bool = True
    enable_executive_reporting: bool = True
    enable_implementation_roadmap: bool = True
    
    # Compliance thresholds
    compliance_thresholds: Dict[str, float] = field(default_factory=lambda: {
        "excellent": 90.0,
        "good": 75.0,
        "acceptable": 60.0,
        "needs_improvement": 40.0
    })
    
    # Confidence calculation settings
    min_confidence_threshold: float = 0.3
    enable_automated_mapping: bool = True
    require_manual_validation: bool = False
    
    # Reporting settings
    max_recommendations: int = 20
    include_implementation_guidance: bool = True
    include_regulatory_mapping: bool = True
    
    # Performance settings
    timeout_seconds: int = 180
    enable_caching: bool = True
    parallel_processing: bool = True
    
    # Output settings
    export_format: str = "json"
    include_executive_summary: bool = True
    detailed_evidence: bool = True 
"""
NIST Compliance Reporting Data Structures

This module defines the core data structures, enums, and NIST Cybersecurity Framework
definitions used throughout the NIST compliance reporting plugin components.

Classes:
- NISTComplianceReport: Complete compliance assessment result
- NISTFinding: NIST-mapped vulnerability finding
- NISTSubcategoryAssessment: Individual subcategory compliance assessment
- NISTConfig: Configuration settings for compliance analysis
- ComplianceGapAnalysis: Gap analysis results
- ImplementationRoadmap: Remediation and implementation plan

Enums:
- NISTImplementationTier: NIST CSF implementation tiers
- ComplianceLevel: Overall compliance assessment levels
- NISTFunction: NIST CSF core functions
- RiskLevel: Risk assessment levels
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from datetime import datetime

class NISTImplementationTier(Enum):
    """NIST Cybersecurity Framework implementation tiers."""
    PARTIAL = "partial"
    RISK_INFORMED = "risk_informed"
    REPEATABLE = "repeatable"
    ADAPTIVE = "adaptive"

class ComplianceLevel(Enum):
    """Overall compliance assessment levels."""
    EXCELLENT = "excellent"
    GOOD = "good"
    ACCEPTABLE = "acceptable"
    NEEDS_IMPROVEMENT = "needs_improvement"
    CRITICAL = "critical"
    INSUFFICIENT_DATA = "insufficient_data"

class NISTFunction(Enum):
    """NIST CSF core functions."""
    IDENTIFY = "identify"
    PROTECT = "protect"
    DETECT = "detect"
    RESPOND = "respond"
    RECOVER = "recover"

class RiskLevel(Enum):
    """Risk assessment levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class MaturityLevel(Enum):
    """Organizational maturity levels for NIST subcategories."""
    NONE = 0
    BASIC = 1
    DEVELOPING = 2
    DEFINED = 3
    MANAGED = 4
    OPTIMIZING = 5

@dataclass
class NISTSubcategoryDefinition:
    """Definition of a NIST CSF subcategory."""
    subcategory_id: str
    function: NISTFunction
    category: str
    subcategory_name: str
    description: str
    informative_references: List[str] = field(default_factory=list)
    weight: float = 1.0

@dataclass
class NISTFinding:
    """NIST-mapped vulnerability finding."""
    # Original AODS finding information
    original_finding_id: str
    finding_type: str
    severity: str
    description: str
    file_path: str
    line_number: int
    
    # NIST CSF mapping
    nist_subcategory: str
    nist_function: NISTFunction
    nist_category: str
    
    # Confidence and validation
    confidence: float = 0.0
    mapping_rationale: str = ""
    automated_mapping: bool = True
    
    # Risk assessment
    risk_level: RiskLevel = RiskLevel.MEDIUM
    impact_description: str = ""
    
    # Evidence and context
    evidence: List[str] = field(default_factory=list)
    remediation_recommendations: List[str] = field(default_factory=list)
    
    # Compliance impact
    compliance_impact: str = ""
    regulatory_requirements: List[str] = field(default_factory=list)
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Post-initialization processing."""
        if isinstance(self.nist_function, str):
            self.nist_function = NISTFunction(self.nist_function)
        if isinstance(self.risk_level, str):
            self.risk_level = RiskLevel(self.risk_level)

@dataclass
class NISTSubcategoryAssessment:
    """Individual NIST subcategory compliance assessment."""
    subcategory_id: str
    subcategory_definition: NISTSubcategoryDefinition
    
    # Assessment results
    maturity_score: float = 0.0
    maturity_level: MaturityLevel = MaturityLevel.NONE
    compliance_status: str = "NOT_ASSESSED"
    
    # Supporting evidence
    mapped_findings: List[NISTFinding] = field(default_factory=list)
    evidence_count: int = 0
    confidence: float = 0.0
    
    # Gap analysis
    current_implementation: str = ""
    target_implementation: str = ""
    gap_description: str = ""
    priority_level: str = "MEDIUM"
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    implementation_guidance: str = ""
    estimated_effort: str = ""
    
    # Risk assessment
    risk_if_not_implemented: RiskLevel = RiskLevel.MEDIUM
    business_impact: str = ""
    
    # Metadata
    assessment_timestamp: datetime = field(default_factory=datetime.now)
    
    def calculate_maturity_score(self) -> float:
        """Calculate maturity score based on findings and evidence."""
        if not self.mapped_findings:
            return 0.0
        
        # Base score from findings quality
        finding_scores = [finding.confidence for finding in self.mapped_findings]
        base_score = sum(finding_scores) / len(finding_scores) if finding_scores else 0.0
        
        # Adjust based on evidence count
        evidence_multiplier = min(1.0, self.evidence_count / 3.0)  # Full score at 3+ evidence
        
        # Adjust based on implementation completeness
        implementation_multiplier = 0.5 if self.current_implementation else 0.2
        
        final_score = base_score * evidence_multiplier * implementation_multiplier
        return min(final_score, 1.0)
    
    def determine_maturity_level(self) -> MaturityLevel:
        """Determine maturity level based on score."""
        score = self.maturity_score
        if score >= 0.9:
            return MaturityLevel.OPTIMIZING
        elif score >= 0.7:
            return MaturityLevel.MANAGED
        elif score >= 0.5:
            return MaturityLevel.DEFINED
        elif score >= 0.3:
            return MaturityLevel.DEVELOPING
        elif score > 0.0:
            return MaturityLevel.BASIC
        else:
            return MaturityLevel.NONE

@dataclass
class ComplianceGap:
    """Individual compliance gap identification."""
    subcategory_id: str
    gap_type: str
    gap_description: str
    current_state: str
    desired_state: str
    
    # Priority and impact
    priority_level: str = "MEDIUM"
    business_impact: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    
    # Implementation details
    estimated_effort: str = ""
    required_resources: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    timeline: str = ""
    
    # Recommendations
    remediation_steps: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Post-initialization processing."""
        if isinstance(self.risk_level, str):
            self.risk_level = RiskLevel(self.risk_level)

@dataclass
class ComplianceGapAnalysis:
    """Complete compliance gap analysis results."""
    total_gaps_identified: int
    critical_gaps: List[ComplianceGap] = field(default_factory=list)
    high_priority_gaps: List[ComplianceGap] = field(default_factory=list)
    medium_priority_gaps: List[ComplianceGap] = field(default_factory=list)
    low_priority_gaps: List[ComplianceGap] = field(default_factory=list)
    
    # Summary statistics
    gap_distribution: Dict[str, int] = field(default_factory=dict)
    function_gaps: Dict[NISTFunction, int] = field(default_factory=dict)
    
    # Analysis metadata
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    target_tier: NISTImplementationTier = NISTImplementationTier.RISK_INFORMED
    
    def get_all_gaps(self) -> List[ComplianceGap]:
        """Get all gaps sorted by priority."""
        return (self.critical_gaps + self.high_priority_gaps + 
                self.medium_priority_gaps + self.low_priority_gaps)
    
    def get_gaps_by_function(self, function: NISTFunction) -> List[ComplianceGap]:
        """Get gaps filtered by NIST function."""
        # Would need subcategory mapping to implement properly
        return []

@dataclass
class ImplementationPhase:
    """Individual phase in implementation roadmap."""
    phase_number: int
    phase_name: str
    description: str
    duration_estimate: str
    
    # Deliverables
    deliverables: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    
    # Gaps addressed
    gaps_addressed: List[ComplianceGap] = field(default_factory=list)
    subcategories_improved: List[str] = field(default_factory=list)
    
    # Resources and dependencies
    required_resources: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    estimated_cost: str = ""
    
    # Risk and impact
    business_value: str = ""
    risk_reduction: str = ""

@dataclass
class ImplementationRoadmap:
    """Complete implementation roadmap for compliance improvement."""
    roadmap_name: str
    total_duration: str
    phases: List[ImplementationPhase] = field(default_factory=list)
    
    # Summary information
    total_gaps_addressed: int = 0
    expected_compliance_improvement: float = 0.0
    target_compliance_level: ComplianceLevel = ComplianceLevel.GOOD
    
    # Resource planning
    total_estimated_cost: str = ""
    resource_requirements: List[str] = field(default_factory=list)
    
    # Risk assessment
    implementation_risks: List[str] = field(default_factory=list)
    success_factors: List[str] = field(default_factory=list)
    
    # Metadata
    creation_timestamp: datetime = field(default_factory=datetime.now)
    target_completion: Optional[datetime] = None
    
    def get_phase_by_number(self, phase_number: int) -> Optional[ImplementationPhase]:
        """Get specific phase by number."""
        for phase in self.phases:
            if phase.phase_number == phase_number:
                return phase
        return None

@dataclass
class NISTComplianceReport:
    """Complete NIST Cybersecurity Framework compliance report."""
    # Overall assessment
    overall_maturity_score: float
    compliance_level: ComplianceLevel
    target_implementation_tier: NISTImplementationTier
    
    # Detailed assessments
    subcategory_assessments: List[NISTSubcategoryAssessment] = field(default_factory=list)
    
    # Analysis results
    gap_analysis: Optional[ComplianceGapAnalysis] = None
    implementation_roadmap: Optional[ImplementationRoadmap] = None
    
    # Supporting data
    findings_analyzed: int = 0
    nist_mappings: List[NISTFinding] = field(default_factory=list)
    
    # Function-level summaries
    function_scores: Dict[NISTFunction, float] = field(default_factory=dict)
    function_assessments: Dict[NISTFunction, str] = field(default_factory=dict)
    
    # Recommendations
    priority_recommendations: List[str] = field(default_factory=list)
    quick_wins: List[str] = field(default_factory=list)
    long_term_initiatives: List[str] = field(default_factory=list)
    
    # Executive summary
    executive_summary: str = ""
    key_strengths: List[str] = field(default_factory=list)
    key_weaknesses: List[str] = field(default_factory=list)
    
    # Metadata
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    analysis_duration: float = 0.0
    def __post_init__(self):
        """Post-initialization processing."""
        if isinstance(self.compliance_level, str):
            self.compliance_level = ComplianceLevel(self.compliance_level)
        if isinstance(self.target_implementation_tier, str):
            self.target_implementation_tier = NISTImplementationTier(self.target_implementation_tier)
        
        # Calculate function scores if not provided
        if not self.function_scores:
            self.function_scores = self._calculate_function_scores()
    
    def _calculate_function_scores(self) -> Dict[NISTFunction, float]:
        """Calculate scores for each NIST function."""
        function_scores = {}
        function_assessments = {}
        
        for function in NISTFunction:
            # Find assessments for this function
            function_assessments_list = [
                assessment for assessment in self.subcategory_assessments
                if assessment.subcategory_definition.function == function
            ]
            
            if function_assessments_list:
                scores = [assessment.maturity_score for assessment in function_assessments_list]
                function_scores[function] = sum(scores) / len(scores)
                
                # Determine assessment level
                avg_score = function_scores[function]
                if avg_score >= 0.8:
                    function_assessments[function] = "EXCELLENT"
                elif avg_score >= 0.6:
                    function_assessments[function] = "GOOD"
                elif avg_score >= 0.4:
                    function_assessments[function] = "ACCEPTABLE"
                else:
                    function_assessments[function] = "NEEDS_IMPROVEMENT"
            else:
                function_scores[function] = 0.0
                function_assessments[function] = "NOT_ASSESSED"
        
        self.function_assessments = function_assessments
        return function_scores
    
    def get_assessment_by_subcategory(self, subcategory_id: str) -> Optional[NISTSubcategoryAssessment]:
        """Get assessment for specific subcategory."""
        for assessment in self.subcategory_assessments:
            if assessment.subcategory_id == subcategory_id:
                return assessment
        return None
    
    def get_critical_gaps(self) -> List[ComplianceGap]:
        """Get critical compliance gaps."""
        if self.gap_analysis:
            return self.gap_analysis.critical_gaps
        return []
    
    def get_top_recommendations(self, count: int = 5) -> List[str]:
        """Get top priority recommendations."""
        return self.priority_recommendations[:count]

@dataclass
class NISTConfig:
    """Configuration settings for NIST compliance analysis."""
    # Analysis settings
    target_implementation_tier: NISTImplementationTier = NISTImplementationTier.RISK_INFORMED
    enable_detailed_mapping: bool = True
    enable_executive_reporting: bool = True
    enable_implementation_roadmap: bool = True
    
    # Compliance thresholds
    compliance_thresholds: Dict[str, float] = field(default_factory=lambda: {
        "excellent": 90.0,
        "good": 75.0,
        "acceptable": 60.0,
        "needs_improvement": 40.0
    })
    
    # Confidence calculation settings
    min_confidence_threshold: float = 0.3
    enable_automated_mapping: bool = True
    require_manual_validation: bool = False
    
    # Reporting settings
    max_recommendations: int = 20
    include_implementation_guidance: bool = True
    include_regulatory_mapping: bool = True
    
    # Performance settings
    timeout_seconds: int = 180
    enable_caching: bool = True
    parallel_processing: bool = True
    
    # Output settings
    export_format: str = "json"
    include_executive_summary: bool = True
    detailed_evidence: bool = True 