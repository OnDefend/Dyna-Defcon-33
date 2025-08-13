#!/usr/bin/env python3
"""
Comprehensive Quality Assurance Framework

Advanced QA system that validates report integrity, ensures data consistency,
prevents identified issues, and maintains production-ready quality standards.
"""

import logging
import json
import re
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from collections import Counter
from datetime import datetime
import re # Added missing import for regex

# Import our specialized components
from .vulnerability_data_validator import VulnerabilityDataValidator, ValidationResult
from .advanced_deduplication_engine import AdvancedDeduplicationEngine
from .smart_code_location_mapper import SmartCodeLocationMapper
from .unified_risk_scoring_engine import UnifiedRiskScoringEngine
from .enhanced_masvs_accuracy_engine import EnhancedMASVSAccuracyEngine

# Import Android security coordination
try:
    from plugins.enhanced_android_security_plugin import AndroidSecurityCoordinationPlugin
    from plugins.enhanced_android_security_plugin.data_structures import AndroidSecurityConfig
    ANDROID_COORDINATION_AVAILABLE = True
except ImportError:
    ANDROID_COORDINATION_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class QualityMetrics:
    """Comprehensive quality metrics for vulnerability reports."""
    data_consistency_score: float      # 0-100
    deduplication_effectiveness: float # 0-100
    code_mapping_accuracy: float       # 0-100
    risk_scoring_consistency: float    # 0-100
    masvs_mapping_quality: float       # 0-100
    android_detection_coverage: float  # 0-100 (NEW)
    overall_quality_score: float       # 0-100
    report_completeness: float         # 0-100
    production_readiness: bool

@dataclass
class QualityReport:
    """Comprehensive quality report with all analysis results."""
    metrics: QualityMetrics
    validation_results: Dict[str, Any]
    issues_found: List[str]
    improvements_made: List[str]
    critical_issues: List[str]
    warnings: List[str]
    recommendations: List[str]
    android_coordination_results: Optional[Dict[str, Any]] = None  # NEW
    processing_statistics: Dict[str, Any] = None
    quality_grade: str = "Unknown"
    certification_status: str = "Unknown"

class ComprehensiveQualityAssuranceFramework:
    """
    Comprehensive QA framework that orchestrates all quality components
    to ensure production-ready vulnerability reports.
    """
    
    def __init__(self):
        """Initialize the comprehensive QA framework."""
        
        # Initialize all quality components
        self.data_validator = VulnerabilityDataValidator()
        self.deduplication_engine = AdvancedDeduplicationEngine()
        self.code_mapper = SmartCodeLocationMapper()
        self.risk_scorer = UnifiedRiskScoringEngine()
        self.masvs_enhancer = EnhancedMASVSAccuracyEngine()
        
        # Quality thresholds
        self.quality_thresholds = {
            'data_consistency': 90.0,      # Minimum data consistency score
            'deduplication': 85.0,         # Minimum deduplication effectiveness
            'code_accuracy': 75.0,         # Minimum code mapping accuracy
            'risk_consistency': 95.0,      # Minimum risk scoring consistency
            'masvs_quality': 80.0,         # Minimum MASVS mapping quality
            'overall_quality': 85.0,       # Minimum overall quality for production
            'completeness': 90.0           # Minimum report completeness
        }
        
        # Critical issues that block production deployment
        self.critical_issue_patterns = [
            'summary.*mismatch',
            'duplicate.*vulnerabilities',
            'nonsensical.*entries',
            'metadata.*instead.*code',
            'invalid.*masvs.*controls',
            'severity.*inconsistency'
        ]
        
        self.processing_statistics = {
            'start_time': None,
            'end_time': None,
            'processing_duration': 0.0,
            'original_vulnerability_count': 0,
            'final_vulnerability_count': 0,
            'issues_detected': 0,
            'issues_resolved': 0,
            'quality_improvements': 0
        }
    
    def process_vulnerability_dataset(self, vulnerabilities: List[Dict[str, Any]], 
                                    summary_stats: Dict[str, Any] = None,
                                    context: Dict[str, Any] = None,
                                    source_roots: List[str] = None) -> Tuple[List[Dict[str, Any]], QualityReport]:
        """
        Process vulnerability dataset through comprehensive QA pipeline.
        
        Args:
            vulnerabilities: Raw vulnerability findings
            summary_stats: Optional summary statistics to validate against
            context: Optional context information for enhanced processing
            source_roots: Optional source code root directories
            
        Returns:
            Tuple of (processed_vulnerabilities, quality_report)
        """
        logger.info(f"🏭 Starting comprehensive QA processing of {len(vulnerabilities)} vulnerabilities...")
        
        self.processing_statistics['start_time'] = datetime.now()
        self.processing_statistics['original_vulnerability_count'] = len(vulnerabilities)
        
        issues_found = []
        improvements_made = []
        warnings = []  # Initialize warnings list
        recommendations = []  # Initialize recommendations list  
        validation_results = {}
        
        try:
            # Stage 1: Data Validation and Consistency Checks
            logger.info("📊 Stage 1: Data validation and consistency checks...")
            validation_result = self.data_validator.validate_vulnerability_dataset(
                vulnerabilities, summary_stats
            )
            validation_results['data_validation'] = validation_result
            
            if not validation_result.is_valid:
                issues_found.extend([f"Data validation: {error}" for error in validation_result.errors])
                logger.warning(f"Found {len(validation_result.errors)} data validation errors")
            
            if validation_result.warnings:
                issues_found.extend([f"Data warning: {warning}" for warning in validation_result.warnings])
            
            # Use cleaned data from validation
            processed_vulnerabilities = validation_result.cleaned_data or vulnerabilities
            improvements_made.append(f"Data validation: Fixed {validation_result.statistics.get('data_errors_fixed', 0)} errors")
            
            # Stage 2: Advanced Deduplication
            logger.info("🔄 Stage 2: Advanced deduplication...")
            deduplicated_vulnerabilities = self.deduplication_engine.deduplicate_vulnerabilities(
                processed_vulnerabilities
            )
            
            dedup_stats = self.deduplication_engine.get_deduplication_statistics()
            validation_results['deduplication'] = dedup_stats
            
            duplicates_removed = len(processed_vulnerabilities) - len(deduplicated_vulnerabilities)
            if duplicates_removed > 0:
                improvements_made.append(f"Deduplication: Removed {duplicates_removed} duplicate vulnerabilities")
            
            processed_vulnerabilities = deduplicated_vulnerabilities
            
            # Stage 3: Smart Code Location Mapping
            logger.info("🎯 Stage 3: Smart code location mapping...")
            code_enhanced_vulnerabilities = self.code_mapper.map_vulnerability_locations(
                processed_vulnerabilities, source_roots
            )
            
            code_stats = self.code_mapper.statistics
            validation_results['code_mapping'] = code_stats
            
            if code_stats['successful_mappings'] > 0:
                improvements_made.append(f"Code mapping: Enhanced {code_stats['successful_mappings']} vulnerabilities with accurate code locations")
            
            if code_stats['metadata_filtered'] > 0:
                improvements_made.append(f"Code mapping: Filtered {code_stats['metadata_filtered']} metadata artifacts")
            
            processed_vulnerabilities = code_enhanced_vulnerabilities
            
            # Stage 4: Unified Risk Scoring
            logger.info("🎯 Stage 4: Unified risk scoring...")
            risk_scored_vulnerabilities = self.risk_scorer.score_vulnerabilities(
                processed_vulnerabilities, context
            )
            
            # Generate risk summary separately
            risk_summary = self.risk_scorer.generate_scoring_summary(risk_scored_vulnerabilities)
            
            validation_results['risk_scoring'] = {
                'summary': risk_summary,
                'statistics': self.risk_scorer.statistics
            }
            
            if self.risk_scorer.statistics['score_adjustments'] > 0:
                improvements_made.append(f"Risk scoring: Applied {self.risk_scorer.statistics['score_adjustments']} score adjustments")
            
            if self.risk_scorer.statistics['severity_changes'] > 0:
                improvements_made.append(f"Risk scoring: Made {self.risk_scorer.statistics['severity_changes']} severity corrections")
            
            processed_vulnerabilities = risk_scored_vulnerabilities
            
            # Stage 5: Enhanced MASVS Accuracy
            logger.info("🏷️ Stage 5: Enhanced MASVS accuracy...")
            masvs_enhanced_vulnerabilities = self.masvs_enhancer.enhance_masvs_mappings(
                processed_vulnerabilities
            )
            
            # Generate MASVS report separately  
            masvs_report = self.masvs_enhancer.generate_masvs_accuracy_report(masvs_enhanced_vulnerabilities)
            
            validation_results['masvs_enhancement'] = masvs_report
            
            if masvs_report.get('total_controls_enhanced', 0) > 0:
                improvements_made.append(f"MASVS enhancement: Enhanced {masvs_report['total_controls_enhanced']} control mappings")
            
            if masvs_report.get('over_tagged_prevented', 0) > 0:
                improvements_made.append(f"MASVS enhancement: Prevented {masvs_report['over_tagged_prevented']} over-tagging instances")
            
            processed_vulnerabilities = masvs_enhanced_vulnerabilities
            
            # Stage 6: Android Security Coordination
            logger.info("👥 Stage 6: Android Security Coordination...")
            if ANDROID_COORDINATION_AVAILABLE:
                try:
                    android_coordination_plugin = AndroidSecurityCoordinationPlugin()
                    
                    # Create default Android config if not provided
                    if hasattr(context, 'android_config') and context.android_config:
                        android_config = context.android_config
                    else:
                        # Import here to avoid circular imports
                        from plugins.enhanced_android_security_plugin.data_structures import AndroidSecurityConfig
                        android_config = AndroidSecurityConfig()
                    
                    android_results = android_coordination_plugin.coordinate_android_security(
                        processed_vulnerabilities, android_config
                    )
                    validation_results['android_coordination'] = android_results
                    
                    if android_results.get('critical_issues'):
                        issues_found.extend([f"Android Security: {issue}" for issue in android_results['critical_issues']])
                        
                    if android_results.get('additional_findings', 0) > 0:
                        improvements_made.append(f"Android Security: Identified {android_results['additional_findings']} additional security findings")
                        
                    if android_results.get('warnings'):
                        warnings.extend([f"Android Security: {warning}" for warning in android_results['warnings']])
                        
                    if android_results.get('recommendations'):
                        recommendations.extend([f"Android Security: {rec}" for rec in android_results['recommendations']])
                        
                except Exception as e:
                    logger.warning(f"Android Security Coordination failed: {e}")
                    android_results = {
                        'coverage_score': 0.0,
                        'coordination_status': 'FAILED',
                        'critical_issues': [f"Coordination failed: {str(e)}"],
                        'warnings': [],
                        'recommendations': ["Fix Android security coordination errors"]
                    }
                    validation_results['android_coordination'] = android_results
                    issues_found.append(f"Android Security coordination failed: {e}")
            else:
                logger.warning("Android Security Coordination plugin not available. Skipping stage.")
                validation_results['android_coordination'] = {
                    'coverage_score': 0.0,
                    'coordination_status': 'UNAVAILABLE',
                    'critical_issues': [],
                    'warnings': ['Android coordination plugin not available'],
                    'recommendations': ['Install Android security coordination plugin']
                }
                android_results = validation_results['android_coordination']
            
            # Stage 7: Final Quality Validation
            logger.info("✅ Stage 7: Final quality validation...")
            final_validation = self._perform_final_quality_validation(
                processed_vulnerabilities, risk_summary, masvs_report, android_results
            )
            validation_results['final_validation'] = final_validation
            
            if final_validation['critical_issues']:
                issues_found.extend([f"Critical: {issue}" for issue in final_validation['critical_issues']])
            
            # Calculate comprehensive quality metrics
            quality_metrics = self._calculate_quality_metrics(validation_results)
            
            # Generate recommendations
            recommendations = self._generate_quality_recommendations(quality_metrics, validation_results)
            
            # Update final statistics
            self.processing_statistics['end_time'] = datetime.now()
            self.processing_statistics['processing_duration'] = (
                self.processing_statistics['end_time'] - self.processing_statistics['start_time']
            ).total_seconds()
            self.processing_statistics['final_vulnerability_count'] = len(processed_vulnerabilities)
            self.processing_statistics['issues_detected'] = len(issues_found)
            self.processing_statistics['quality_improvements'] = len(improvements_made)
            
            # Create comprehensive quality report
            quality_report = QualityReport(
                metrics=quality_metrics,
                validation_results=validation_results,
                issues_found=issues_found,
                improvements_made=improvements_made,
                critical_issues=final_validation.get('critical_issues', []),
                warnings=final_validation.get('warnings', []),
                recommendations=recommendations,
                android_coordination_results=android_results,
                processing_statistics=self.processing_statistics.copy(),
                quality_grade=self._determine_quality_grade(quality_metrics),
                certification_status=self._determine_certification_status(quality_metrics)
            )
            
            logger.info(f"✅ QA processing complete:")
            logger.info(f"   Original vulnerabilities: {self.processing_statistics['original_vulnerability_count']}")
            logger.info(f"   Final vulnerabilities: {self.processing_statistics['final_vulnerability_count']}")
            logger.info(f"   Issues found: {len(issues_found)}")
            logger.info(f"   Improvements made: {len(improvements_made)}")
            logger.info(f"   Overall quality score: {quality_metrics.overall_quality_score:.1f}%")
            logger.info(f"   Production ready: {'✅' if quality_metrics.production_readiness else '❌'}")
            
            return processed_vulnerabilities, quality_report
            
        except Exception as e:
            logger.error(f"Critical error in QA processing: {e}")
            
            # Create error quality report
            error_metrics = QualityMetrics(
                data_consistency_score=0.0,
                deduplication_effectiveness=0.0,
                code_mapping_accuracy=0.0,
                risk_scoring_consistency=0.0,
                masvs_mapping_quality=0.0,
                android_detection_coverage=0.0, # NEW
                overall_quality_score=0.0,
                report_completeness=0.0,
                production_readiness=False
            )
            
            error_report = QualityReport(
                metrics=error_metrics,
                validation_results=validation_results,
                issues_found=[f"Critical processing error: {e}"],
                improvements_made=improvements_made,
                critical_issues=[f"Critical processing error: {e}"], # NEW
                warnings=[], # NEW
                recommendations=["Investigate and fix critical processing error"],
                android_coordination_results={}, # NEW
                processing_statistics=self.processing_statistics.copy(),
                quality_grade="Failed", # NEW
                certification_status="Failed" # NEW
            )
            
            return vulnerabilities, error_report
    
    def _perform_final_quality_validation(self, vulnerabilities: List[Dict[str, Any]], 
                                        risk_summary: Dict[str, Any],
                                        masvs_report: Dict[str, Any],
                                        android_results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform final comprehensive quality validation."""
        
        critical_issues = []
        warnings = []
        quality_scores = {}
        
        # Validate summary consistency
        actual_counts = Counter(vuln.get('severity', 'UNKNOWN') for vuln in vulnerabilities)
        summary_counts = risk_summary.get('severity_breakdown', {})
        
        for severity, actual_count in actual_counts.items():
            summary_count = summary_counts.get(severity, 0)
            if actual_count != summary_count:
                critical_issues.append(f"Summary mismatch: {severity} actual={actual_count}, summary={summary_count}")
        
        # Check for nonsensical entries
        nonsensical_count = 0
        for vuln in vulnerabilities:
            title = vuln.get('title', '').strip().lower()
            if any(pattern in title for pattern in ['pass', 'success', 'fail', 'error']):
                nonsensical_count += 1
        
        if nonsensical_count > 0:
            critical_issues.append(f"Found {nonsensical_count} nonsensical vulnerability entries")
        
        # Check for metadata in code locations
        metadata_count = 0
        for vuln in vulnerabilities:
            code = vuln.get('matching_code', '')
            if code and '@Metadata(' in code:
                metadata_count += 1
        
        if metadata_count > 0:
            critical_issues.append(f"Found {metadata_count} vulnerabilities with metadata instead of actual code")
        
        # Validate MASVS control consistency
        invalid_masvs_count = 0
        for vuln in vulnerabilities:
            controls = vuln.get('masvs_controls', [])
            if isinstance(controls, list):
                for control in controls:
                    if not re.match(r'^MASVS-[A-Z]+-\d+$', str(control)):
                        invalid_masvs_count += 1
                        break
        
        if invalid_masvs_count > 0:
            warnings.append(f"Found {invalid_masvs_count} vulnerabilities with invalid MASVS control format")
        
        # Android Security Coordination Validation
        android_critical_issues = android_results.get('critical_issues', [])
        if android_critical_issues:
            critical_issues.extend([f"Android Security: {issue}" for issue in android_critical_issues])
        
        # Calculate quality scores
        quality_scores['summary_consistency'] = 100.0 if len(critical_issues) == 0 else 0.0
        quality_scores['data_integrity'] = max(0.0, 100.0 - (nonsensical_count * 10))
        quality_scores['code_accuracy'] = max(0.0, 100.0 - (metadata_count * 20))
        quality_scores['masvs_validity'] = max(0.0, 100.0 - (invalid_masvs_count * 5))
        quality_scores['android_coverage'] = android_results.get('coverage_score', 0.0) # NEW
        
        return {
            'critical_issues': critical_issues,
            'warnings': warnings,
            'quality_scores': quality_scores,
            'overall_validation_score': sum(quality_scores.values()) / len(quality_scores) if quality_scores else 0.0
        }
    
    def _calculate_quality_metrics(self, validation_results: Dict[str, Any]) -> QualityMetrics:
        """Calculate comprehensive quality metrics."""
        
        # Data consistency score
        data_validation = validation_results.get('data_validation', {})
        if hasattr(data_validation, 'statistics'):
            data_score = data_validation.statistics.get('data_quality_score', 0.0)
        else:
            data_score = 70.0  # Default if not available
        
        # Deduplication effectiveness
        dedup_stats = validation_results.get('deduplication', {}).get('statistics', {})
        original_count = dedup_stats.get('total_processed', 1)
        preserved_count = dedup_stats.get('preserved_vulnerabilities', original_count)
        duplicates_found = dedup_stats.get('duplicates_found', 0)
        
        if duplicates_found > 0:
            dedup_effectiveness = min(100.0, (duplicates_found / original_count) * 100 + 85.0)
        else:
            dedup_effectiveness = 100.0
        
        # Code mapping accuracy
        code_stats = validation_results.get('code_mapping', {})
        total_processed = code_stats.get('total_processed', 1)
        successful_mappings = code_stats.get('successful_mappings', 0)
        metadata_filtered = code_stats.get('metadata_filtered', 0)
        
        code_accuracy = (successful_mappings / total_processed) * 100 if total_processed > 0 else 0.0
        if metadata_filtered > 0:
            code_accuracy += min(20.0, (metadata_filtered / total_processed) * 50)  # Bonus for filtering metadata
        
        # Risk scoring consistency
        risk_stats = validation_results.get('risk_scoring', {}).get('statistics', {})
        consistency_fixes = risk_stats.get('consistency_fixes', 0)
        score_adjustments = risk_stats.get('score_adjustments', 1)
        
        risk_consistency = max(80.0, 100.0 - (consistency_fixes / score_adjustments) * 30) if score_adjustments > 0 else 100.0
        
        # MASVS mapping quality
        masvs_report = validation_results.get('masvs_enhancement', {})
        masvs_quality = masvs_report.get('quality_score', 0.0)
        
        # Android Security Coordination Coverage
        android_results = validation_results.get('android_coordination', {})
        android_coverage = android_results.get('coverage_score', 0.0)
        
        # Overall quality score (weighted average)
        weights = {
            'data_consistency': 0.25,
            'deduplication': 0.15,
            'code_accuracy': 0.20,
            'risk_consistency': 0.25,
            'masvs_quality': 0.15,
            'android_coverage': 0.05 # NEW
        }
        
        overall_score = (
            data_score * weights['data_consistency'] +
            dedup_effectiveness * weights['deduplication'] +
            code_accuracy * weights['code_accuracy'] +
            risk_consistency * weights['risk_consistency'] +
            masvs_quality * weights['masvs_quality'] +
            android_coverage * weights['android_coverage'] # NEW
        )
        
        # Report completeness
        final_validation = validation_results.get('final_validation', {})
        completeness = final_validation.get('overall_validation_score', 0.0)
        
        # Production readiness
        production_ready = (
            overall_score >= self.quality_thresholds['overall_quality'] and
            data_score >= self.quality_thresholds['data_consistency'] and
            risk_consistency >= self.quality_thresholds['risk_consistency'] and
            len(final_validation.get('critical_issues', [])) == 0
        )
        
        return QualityMetrics(
            data_consistency_score=round(data_score, 1),
            deduplication_effectiveness=round(dedup_effectiveness, 1),
            code_mapping_accuracy=round(code_accuracy, 1),
            risk_scoring_consistency=round(risk_consistency, 1),
            masvs_mapping_quality=round(masvs_quality, 1),
            android_detection_coverage=round(android_coverage, 1), # NEW
            overall_quality_score=round(overall_score, 1),
            report_completeness=round(completeness, 1),
            production_readiness=production_ready
        )
    
    def _generate_quality_recommendations(self, metrics: QualityMetrics, 
                                        validation_results: Dict[str, Any]) -> List[str]:
        """Generate actionable quality improvement recommendations."""
        
        recommendations = []
        
        # Data consistency recommendations
        if metrics.data_consistency_score < self.quality_thresholds['data_consistency']:
            recommendations.append(
                f"Improve data consistency (current: {metrics.data_consistency_score}%, target: {self.quality_thresholds['data_consistency']}%). "
                "Review data validation rules and input sanitization."
            )
        
        # Deduplication recommendations
        if metrics.deduplication_effectiveness < self.quality_thresholds['deduplication']:
            recommendations.append(
                f"Enhance deduplication effectiveness (current: {metrics.deduplication_effectiveness}%, target: {self.quality_thresholds['deduplication']}%). "
                "Review fingerprinting algorithms and similarity thresholds."
            )
        
        # Code mapping recommendations
        if metrics.code_mapping_accuracy < self.quality_thresholds['code_accuracy']:
            recommendations.append(
                f"Improve code mapping accuracy (current: {metrics.code_mapping_accuracy}%, target: {self.quality_thresholds['code_accuracy']}%). "
                "Ensure source code paths are correctly configured and metadata filtering is working."
            )
        
        # Risk scoring recommendations
        if metrics.risk_scoring_consistency < self.quality_thresholds['risk_consistency']:
            recommendations.append(
                f"Enhance risk scoring consistency (current: {metrics.risk_scoring_consistency}%, target: {self.quality_thresholds['risk_consistency']}%). "
                "Review severity classification rules and confidence scoring algorithms."
            )
        
        # MASVS recommendations
        if metrics.masvs_mapping_quality < self.quality_thresholds['masvs_quality']:
            recommendations.append(
                f"Improve MASVS mapping quality (current: {metrics.masvs_mapping_quality}%, target: {self.quality_thresholds['masvs_quality']}%). "
                "Review control mapping rules and prevent over-tagging."
            )
        
        # Android Security Coordination Recommendations
        if metrics.android_detection_coverage < self.quality_thresholds['overall_quality']: # NEW
            recommendations.append(
                f"Enhance Android security detection coverage (current: {metrics.android_detection_coverage}%, target: {self.quality_thresholds['overall_quality']}%). "
                "Review Android security plugin configuration and ensure all relevant code paths are covered."
            )
        
        # Production readiness recommendations
        if not metrics.production_readiness:
            critical_issues = validation_results.get('final_validation', {}).get('critical_issues', [])
            if critical_issues:
                recommendations.append(
                    f"Resolve {len(critical_issues)} critical issues before production deployment: " +
                    "; ".join(critical_issues[:3]) + ("..." if len(critical_issues) > 3 else "")
                )
            else:
                recommendations.append(
                    f"Overall quality score ({metrics.overall_quality_score}%) below production threshold "
                    f"({self.quality_thresholds['overall_quality']}%). Address quality issues above."
                )
        
        # General improvement recommendations
        if metrics.overall_quality_score < 95.0:
            recommendations.append(
                "Consider implementing additional quality checks and validation rules for continuous improvement."
            )
        
        return recommendations

    def _determine_quality_grade(self, metrics: QualityMetrics) -> str:
        """Determine the overall quality grade based on metrics."""
        overall_score = metrics.overall_quality_score
        if overall_score >= 95.0:
            return "Excellent"
        elif overall_score >= 85.0:
            return "Good"
        elif overall_score >= 75.0:
            return "Fair"
        else:
            return "Poor"

    def _determine_certification_status(self, metrics: QualityMetrics) -> str:
        """Determine the certification status based on metrics."""
        overall_score = metrics.overall_quality_score
        if overall_score >= 95.0:
            return "Fully Certified"
        elif overall_score >= 85.0:
            return "Certified"
        elif overall_score >= 75.0:
            return "Approval Pending"
        else:
            return "Not Certified"

def process_vulnerabilities_with_comprehensive_qa(vulnerabilities: List[Dict[str, Any]], 
                                                 summary_stats: Dict[str, Any] = None,
                                                 context: Dict[str, Any] = None,
                                                 source_roots: List[str] = None) -> Tuple[List[Dict[str, Any]], QualityReport]:
    """Convenience function for comprehensive QA processing."""
    qa_framework = ComprehensiveQualityAssuranceFramework()
    return qa_framework.process_vulnerability_dataset(vulnerabilities, summary_stats, context, source_roots) 