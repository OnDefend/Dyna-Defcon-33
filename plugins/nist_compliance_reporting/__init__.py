#!/usr/bin/env python3
"""
NIST Cybersecurity Framework Compliance Reporting Plugin - Modular Architecture

This module provides comprehensive NIST Cybersecurity Framework compliance reporting
through modular components with professional evidence-based confidence calculation.

Features:
- AODS findings extraction and normalization
- NIST CSF subcategory mapping with intelligent matching
- Compliance assessment with maturity scoring
- Gap analysis and implementation roadmaps
- Executive reporting with actionable insights
- confidence calculation
- Rich text formatting with detailed visualizations

Architecture Components:
- findings_extractor.py: AODS vulnerability findings extraction and normalization
- nist_mapper.py: NIST CSF subcategory mapping and classification
- compliance_assessor.py: Compliance level assessment and maturity scoring
- gap_analyzer.py: Compliance gap identification and priority analysis
- roadmap_generator.py: Implementation roadmap and remediation planning
- report_generator.py: Comprehensive report generation and formatting
- confidence_calculator.py: evidence-based confidence scoring
- data_structures.py: Core data classes and NIST framework definitions
- nist_patterns_config.yaml: External NIST CSF configuration

NIST CSF Integration:
- Full framework coverage across all 23 subcategories
- Implementation tier assessment (Partial, Risk-Informed, Repeatable, Adaptive)
- Industry-specific compliance guidance
- Regulatory requirement mapping
- Executive dashboard generation

"""

import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union

from rich.text import Text

# Import modular components
from .data_structures import (
    NISTComplianceReport, NISTFinding, NISTSubcategoryAssessment,
    NISTImplementationTier, ComplianceLevel, NISTConfig
)
from .findings_extractor import AODSFindingsExtractor
from .nist_mapper import NISTFrameworkMapper
from .compliance_assessor import ComplianceAssessor
from .gap_analyzer import ComplianceGapAnalyzer
from .roadmap_generator import ImplementationRoadmapGenerator
from .report_generator import NISTReportGenerator
from .confidence_calculator import NISTConfidenceCalculator

logger = logging.getLogger(__name__)

# Plugin metadata for AODS framework integration
PLUGIN_METADATA = {
    "name": "NIST Cybersecurity Framework Compliance Reporting",
    "description": "Comprehensive NIST CSF compliance assessment with modular architecture",
    "version": "2.0.0",
    "author": "AODS Security Intelligence Team",
    "category": "COMPLIANCE_REPORTING",
    "priority": "MEDIUM",
    "timeout": 180,
    "mode": "comprehensive",
    "requires_device": False,
    "requires_network": False,
    "invasive": False,
    "execution_time_estimate": 120,
    "dependencies": [],
    "modular_architecture": True,
    "components": [
        "findings_extractor",
        "nist_mapper",
        "compliance_assessor",
        "gap_analyzer",
        "roadmap_generator",
        "report_generator",
        "confidence_calculator"
    ],
    "confidence_system": "professional_evidence_based",
    "nist_csf_version": "1.1",
    "subcategories_covered": 23,
    "implementation_tiers": 4
}

# Legacy compatibility metadata
PLUGIN_CHARACTERISTICS = {
    "mode": "comprehensive",
    "category": "compliance_reporting",
    "priority": "medium",
    "targets": ["nist_compliance", "framework_assessment", "gap_analysis"],
    "modular": True
}

class NISTComplianceReportingPlugin:
    """
    Main NIST Cybersecurity Framework compliance reporting plugin with modular architecture.
    
    Orchestrates comprehensive NIST CSF compliance assessment through specialized
    component modules with dependency injection and professional confidence calculation.
    """
    
    def __init__(self, config: Optional[NISTConfig] = None):
        """Initialize the NIST compliance reporting plugin."""
        self.logger = logging.getLogger(__name__)
        self.config = config or NISTConfig()
        
        # Initialize modular components
        self._initialize_components()
        
        # Analysis state
        self.analysis_complete = False
        self.analysis_start_time = None
        self.processed_findings_count = 0
        
    def _initialize_components(self):
        """Initialize all modular components with dependency injection."""
        try:
            # Initialize core components
            self.findings_extractor = AODSFindingsExtractor(self.config)
            self.nist_mapper = NISTFrameworkMapper(self.config)
            self.compliance_assessor = ComplianceAssessor(self.config)
            self.gap_analyzer = ComplianceGapAnalyzer(self.config)
            self.roadmap_generator = ImplementationRoadmapGenerator(self.config)
            self.report_generator = NISTReportGenerator(self.config)
            self.confidence_calculator = NISTConfidenceCalculator()
            
            self.logger.debug("NIST compliance reporting components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize NIST compliance components: {e}", exc_info=True)
            raise
    
    def analyze_compliance(self, apk_ctx) -> NISTComplianceReport:
        """
        Perform comprehensive NIST CSF compliance analysis.
        
        Args:
            apk_ctx: APK context containing AODS analysis results
            
        Returns:
            NISTComplianceReport: Complete compliance assessment
        """
        self.analysis_start_time = time.time()
        self.logger.debug("Starting NIST Cybersecurity Framework compliance analysis...")
        
        try:
            # Phase 1: Extract and normalize AODS findings
            self.logger.debug("Phase 1: Extracting AODS vulnerability findings...")
            aods_findings = self.findings_extractor.extract_findings(apk_ctx)
            self.processed_findings_count = len(aods_findings)
            
            if not aods_findings:
                self.logger.warning("No AODS findings available for NIST compliance mapping")
                return self._create_empty_report()
            
            self.logger.debug(f"Extracted {len(aods_findings)} findings for NIST mapping")
            
            # Phase 2: Map findings to NIST CSF subcategories
            self.logger.debug("Phase 2: Mapping findings to NIST CSF subcategories...")
            nist_mappings = self.nist_mapper.map_findings_to_nist(aods_findings)
            
            # Phase 3: Assess compliance levels
            self.logger.debug("Phase 3: Assessing NIST compliance levels...")
            subcategory_assessments = self.compliance_assessor.assess_compliance(
                nist_mappings, aods_findings
            )
            
            # Phase 4: Calculate professional confidence scores
            self.logger.debug("Phase 4: Calculating professional confidence scores...")
            for assessment in subcategory_assessments:
                confidence = self.confidence_calculator.calculate_confidence(
                    assessment=assessment,
                    findings_count=len(aods_findings),
                    mapping_quality=self._assess_mapping_quality(nist_mappings)
                )
                assessment.confidence = confidence
            
            # Phase 5: Perform gap analysis
            self.logger.debug("Phase 5: Performing compliance gap analysis...")
            gap_analysis = self.gap_analyzer.analyze_gaps(
                subcategory_assessments, self.config.target_implementation_tier
            )
            
            # Phase 6: Generate implementation roadmap
            self.logger.debug("Phase 6: Generating implementation roadmap...")
            implementation_roadmap = self.roadmap_generator.generate_roadmap(
                gap_analysis, subcategory_assessments
            )
            
            # Phase 7: Calculate overall maturity score
            overall_score = self._calculate_overall_maturity_score(subcategory_assessments)
            compliance_level = self._determine_compliance_level(overall_score)
            
            # Create comprehensive report
            analysis_duration = time.time() - self.analysis_start_time
            
            compliance_report = NISTComplianceReport(
                overall_maturity_score=overall_score,
                compliance_level=compliance_level,
                subcategory_assessments=subcategory_assessments,
                gap_analysis=gap_analysis,
                implementation_roadmap=implementation_roadmap,
                findings_analyzed=len(aods_findings),
                nist_mappings=nist_mappings,
                target_implementation_tier=self.config.target_implementation_tier,
                analysis_duration=analysis_duration,
                analysis_timestamp=datetime.now()
            )
            
            self.analysis_complete = True
            self.logger.debug(
                f"NIST compliance analysis completed: {overall_score:.1f}% maturity score, "
                f"{compliance_level.value} level in {analysis_duration:.2f}s"
            )
            
            return compliance_report
            
        except Exception as e:
            self.logger.error(f"NIST compliance analysis failed: {e}", exc_info=True)
            raise
    
    def _create_empty_report(self) -> NISTComplianceReport:
        """Create an empty report when no findings are available."""
        return NISTComplianceReport(
            overall_maturity_score=0.0,
            compliance_level=ComplianceLevel.INSUFFICIENT_DATA,
            subcategory_assessments=[],
            gap_analysis=None,
            implementation_roadmap=None,
            findings_analyzed=0,
            nist_mappings=[],
            target_implementation_tier=self.config.target_implementation_tier,
            analysis_duration=0.0,
            analysis_timestamp=datetime.now()
        )
    
    def _assess_mapping_quality(self, nist_mappings: List[NISTFinding]) -> float:
        """Assess the quality of NIST CSF mappings."""
        if not nist_mappings:
            return 0.0
            
        # Calculate mapping quality based on confidence scores and coverage
        total_confidence = sum(mapping.confidence for mapping in nist_mappings)
        average_confidence = total_confidence / len(nist_mappings)
        
        # Assess subcategory coverage
        covered_subcategories = set(mapping.nist_subcategory for mapping in nist_mappings)
        coverage_ratio = len(covered_subcategories) / 23  # Total NIST subcategories
        
        # Combined quality score
        quality_score = (average_confidence * 0.7) + (coverage_ratio * 0.3)
        
        return min(quality_score, 1.0)
    
    def _calculate_overall_maturity_score(
        self, 
        assessments: List[NISTSubcategoryAssessment]
    ) -> float:
        """Calculate overall organizational maturity score."""
        if not assessments:
            return 0.0
        
        # Weight subcategories by importance
        weights = self._get_subcategory_weights()
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for assessment in assessments:
            weight = weights.get(assessment.subcategory_id, 1.0)
            total_weighted_score += assessment.maturity_score * weight
            total_weight += weight
        
        if total_weight == 0:
            return 0.0
            
        return total_weighted_score / total_weight
    
    def _get_subcategory_weights(self) -> Dict[str, float]:
        """Get importance weights for NIST subcategories."""
        # Higher weights for critical security functions
        return {
            # Identify function
            "ID.AM": 1.2,  # Asset Management
            "ID.RA": 1.3,  # Risk Assessment
            "ID.RM": 1.1,  # Risk Management Strategy
            
            # Protect function
            "PR.AC": 1.4,  # Identity Management and Access Control
            "PR.AT": 1.0,  # Awareness and Training
            "PR.DS": 1.3,  # Data Security
            "PR.IP": 1.2,  # Information Protection Processes
            "PR.MA": 1.1,  # Maintenance
            "PR.PT": 1.2,  # Protective Technology
            
            # Detect function
            "DE.AE": 1.3,  # Anomalies and Events
            "DE.CM": 1.2,  # Security Continuous Monitoring
            "DE.DP": 1.1,  # Detection Processes
            
            # Respond function
            "RS.RP": 1.2,  # Response Planning
            "RS.CO": 1.1,  # Communications
            "RS.AN": 1.2,  # Analysis
            "RS.MI": 1.3,  # Mitigation
            "RS.IM": 1.1,  # Improvements
            
            # Recover function
            "RC.RP": 1.1,  # Recovery Planning
            "RC.IM": 1.0,  # Improvements
            "RC.CO": 1.0,  # Communications
        }
    
    def _determine_compliance_level(self, maturity_score: float) -> ComplianceLevel:
        """Determine compliance level based on maturity score."""
        if maturity_score >= self.config.compliance_thresholds["excellent"]:
            return ComplianceLevel.EXCELLENT
        elif maturity_score >= self.config.compliance_thresholds["good"]:
            return ComplianceLevel.GOOD
        elif maturity_score >= self.config.compliance_thresholds["acceptable"]:
            return ComplianceLevel.ACCEPTABLE
        elif maturity_score >= self.config.compliance_thresholds["needs_improvement"]:
            return ComplianceLevel.NEEDS_IMPROVEMENT
        else:
            return ComplianceLevel.CRITICAL

def run_plugin(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Plugin interface function for AODS framework integration.
    
    Args:
        apk_ctx: APK context containing AODS analysis results
        
    Returns:
        Tuple[str, Union[str, Text]]: Plugin execution result
    """
    try:
        plugin = NISTComplianceReportingPlugin()
        compliance_report = plugin.analyze_compliance(apk_ctx)
        
        # Generate formatted report
        formatted_report = plugin.report_generator.generate_comprehensive_report(compliance_report)
        
        # Cache results for integration with other plugins
        apk_ctx.set_cache("nist_compliance_results", {
            "plugin_name": PLUGIN_METADATA["name"],
            "plugin_version": PLUGIN_METADATA["version"],
            "analysis_timestamp": compliance_report.analysis_timestamp.isoformat(),
            "findings_analyzed": compliance_report.findings_analyzed,
            "overall_maturity_score": compliance_report.overall_maturity_score,
            "compliance_level": compliance_report.compliance_level.value,
            "target_implementation_tier": compliance_report.target_implementation_tier.value,
            "subcategories_assessed": len(compliance_report.subcategory_assessments),
            "analysis_duration": compliance_report.analysis_duration
        })
        
        return (PLUGIN_METADATA["name"], formatted_report)
        
    except Exception as e:
        logger.error(f"NIST compliance reporting plugin failed: {e}", exc_info=True)
        error_text = Text.from_markup(f"[red]NIST compliance analysis failed: {str(e)}[/red]")
        return (PLUGIN_METADATA["name"], error_text)

# Legacy compatibility function
def run(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """Legacy compatibility function."""
    return run_plugin(apk_ctx)

if __name__ == "__main__":
    # Plugin testing and validation
    print("🏛️ NIST Cybersecurity Framework Compliance Reporting Plugin (Modular Architecture)")
    print(f"Version: {PLUGIN_METADATA['version']}")
    print(f"NIST CSF Version: {PLUGIN_METADATA['nist_csf_version']}")
    print(f"Subcategories Covered: {PLUGIN_METADATA['subcategories_covered']}")
    print(f"Implementation Tiers: {PLUGIN_METADATA['implementation_tiers']}")
    print(f"Components: {', '.join(PLUGIN_METADATA['components'])}")
    print("Ready for comprehensive NIST CSF compliance assessment with professional confidence calculation") 