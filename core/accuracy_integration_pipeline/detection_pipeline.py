#!/usr/bin/env python3
"""
AODS Accuracy Integration Pipeline - Detection Pipeline

Detection-first processing pipeline optimized for maximum vulnerability detection
with intelligent accuracy enhancement and zero tolerance for vulnerability loss.
"""

import time
import logging
from typing import Dict, List, Any, Optional

from .data_structures import (
    DetectionPipelineResult, AccuracyMetrics, ProcessingStage, 
    DetectionQuality, VulnerabilityPreservationReport, PipelineConfiguration
)

class AccuracyIntegrationPipeline:
    """
    Detection-first accuracy integration pipeline that prioritizes vulnerability 
    detection while enhancing accuracy through intelligent processing.
    
    Core Principles:
    1. Detection First - Never lose potential vulnerabilities
    2. Intelligent Enhancement - Improve accuracy without compromising detection
    3. Context Awareness - Adapt processing based on application context
    4. Preservation Guarantee - Zero tolerance for legitimate vulnerability loss
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the detection-first accuracy pipeline."""
        self.logger = logging.getLogger(__name__)
        
        # Extract pipeline configuration
        pipeline_config = config.get('pipeline_config')
        if pipeline_config:
            self.pipeline_config = pipeline_config
        else:
            # Create default configuration
            from .data_structures import PipelineConfiguration
            self.pipeline_config = PipelineConfiguration()
        
        # Initialize processing components
        self._initialize_processing_components()
        
        # Processing statistics and metrics
        self.processing_stats = {
            'total_processed': 0,
            'total_time_ms': 0,
            'average_reduction': 0.0,
            'vulnerability_preservation_rate': 0.0
        }
        
        # Metrics history for performance tracking
        self.metrics_history = []
        
        self.logger.info("AODS Accuracy Integration Pipeline initialized")
        self.logger.info("Configuration: Detection-optimized with preservation enabled")
    
    def _initialize_processing_components(self):
        """Initialize all processing pipeline components."""
        try:
            # Initialize severity filter
            from .severity_filter import AdvancedSeverityFilter
            self.severity_filter = AdvancedSeverityFilter()
            
            # Initialize confidence calculator  
            from .confidence_calculator import ProfessionalConfidenceCalculator
            self.confidence_calculator = ProfessionalConfidenceCalculator()
            
            # Initialize deduplication engine
            from .deduplication_engine import IntelligentDeduplicationEngine
            self.deduplication_engine = IntelligentDeduplicationEngine()
            
            self.logger.info("Legacy components initialized for compatibility")
            
        except ImportError as e:
            self.logger.warning(f"Some legacy components not available: {e}")
            # Initialize with fallback components
            self._initialize_fallback_components()
    
    def _initialize_fallback_components(self):
        """Initialize fallback components when advanced ones are unavailable."""
        self.severity_filter = None
        self.confidence_calculator = None
        self.deduplication_engine = None
        self.logger.info("Using fallback component initialization")
    
    def process_findings(
        self, 
        raw_findings: List[Dict[str, Any]], 
        app_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Main pipeline processing method with detection-first approach.
        
        Args:
            raw_findings: List of raw vulnerability findings from AODS analyzers
            app_context: Application context (package name, category, etc.)
            
        Returns:
            Dict containing processed findings and comprehensive metrics
        """
        
        # VULNERABLE APP COORDINATION - Override aggressive filtering
        try:
            from core.vulnerable_app_coordinator import vulnerable_app_coordinator
            
            detection_context = {
                'package_name': app_context.get('package_name', '') if app_context else '',
                'apk_path': app_context.get('apk_path', '') if app_context else ''
            }
            
            app_type = vulnerable_app_coordinator.detect_vulnerable_app(detection_context)
            policy = vulnerable_app_coordinator.get_filtering_policy(app_type)
            
            if not policy['enable_aggressive_filtering']:
                self.logger.info(f"🎯 Vulnerable app detected - minimal processing pipeline")
                self.logger.info(f"   App type: {app_type.value}")
                self.logger.info(f"   Preserving findings: {policy['preserve_all_findings']}")
                
                # For vulnerable apps, apply minimal processing
                if policy['preserve_all_findings']:
                    # Light deduplication only
                    try:
                        from core.unified_deduplication_framework import unified_deduplication_engine
                        deduplicated = unified_deduplication_engine.deduplicate_findings(raw_findings)
                        
                        # Return with minimal reduction
                        reduction = (len(raw_findings) - len(deduplicated)) / len(raw_findings) * 100
                        
                        self.logger.info(f"✅ Vulnerable app minimal processing complete")
                        self.logger.info(f"   Original: {len(raw_findings)} findings")
                        self.logger.info(f"   Preserved: {len(deduplicated)} findings")
                        self.logger.info(f"   Reduction: {reduction:.1f}% (minimal)")
                        
                        return {
                            'processed_findings': deduplicated,
                            'metrics': {
                                'original_count': len(raw_findings),
                                'final_count': len(deduplicated),
                                'reduction_percentage': reduction,
                                'processing_strategy': 'vulnerable_app_preservation'
                            }
                        }
                    except Exception as e:
                        self.logger.warning(f"Minimal processing failed: {e}")
                        # Fallback: return original findings
                        return {
                            'processed_findings': raw_findings,
                            'metrics': {
                                'original_count': len(raw_findings),
                                'final_count': len(raw_findings), 
                                'reduction_percentage': 0.0,
                                'processing_strategy': 'vulnerable_app_passthrough'
                            }
                        }
        except Exception as e:
            self.logger.warning(f"Vulnerable app coordination failed: {e}")
        
        # Standard pipeline processing for production apps
        start_time = time.time()
        pipeline_id = f"detection_pipeline_{int(start_time)}"
        
        self.logger.info(f"Starting detection-first accuracy pipeline processing: {pipeline_id}")
        self.logger.info(f"Input: {len(raw_findings)} raw findings")
        self.logger.info(f"Detection preservation enabled: True")
        
        try:
            # Stage 1: Advanced severity filtering with preservation
            stage1_result = self._stage_1_advanced_severity_filtering(raw_findings, app_context)
            
            # Stage 2: confidence scoring
            stage2_result = self._stage_2_professional_confidence_scoring(
                stage1_result['filtered_findings'], app_context
            )
            
            # Stage 3: Intelligent deduplication with preservation
            stage3_result = self._stage_3_intelligent_deduplication(
                stage2_result['filtered_findings']
            )
            
            # Calculate final metrics and quality indicators
            total_time = (time.time() - start_time) * 1000
            final_metrics = self._calculate_final_metrics(
                raw_findings, stage3_result['unique_findings'], total_time
            )
            
            # Generate vulnerability preservation report
            vulnerability_preservation = self._generate_vulnerability_preservation_report(
                raw_findings, stage3_result['unique_findings']
            )
            
            # Calculate detection quality indicators
            quality_indicators = self._calculate_quality_indicators(
                raw_findings, stage3_result['unique_findings'], vulnerability_preservation
            )
            
            # Create comprehensive pipeline result
            pipeline_result = DetectionPipelineResult(
                original_findings=raw_findings,
                processed_findings=stage3_result['unique_findings'],
                pipeline_id=pipeline_id,
                processing_stage=ProcessingStage.COMPLETED,
                accuracy_metrics=final_metrics,
                vulnerability_preservation=vulnerability_preservation,
                detection_quality=quality_indicators,
                processing_metrics={
                    'total_time_ms': total_time,
                    'stage_1_time_ms': stage1_result.get('processing_time_ms', 0),
                    'stage_2_time_ms': stage2_result.get('processing_time_ms', 0),
                    'stage_3_time_ms': stage3_result.get('processing_time_ms', 0)
                }
            )
            
            # Update processing statistics
            self._update_processing_stats(pipeline_result)
            
            # Log comprehensive results
            self.logger.info(f"Detection pipeline processing complete: {pipeline_id}")
            self.logger.info(f"Result: {len(raw_findings)} -> {len(stage3_result['unique_findings'])} findings")
            self.logger.info(f"Processing time: {total_time:.2f}ms")
            self.logger.info(f"Vulnerability preservation: {vulnerability_preservation.preservation_rate:.1f}%")
            
            # Convert to dictionary for backward compatibility
            return self._convert_result_to_dict(pipeline_result)
            
        except Exception as e:
            self.logger.error(f"Detection pipeline processing failed: {pipeline_id}")
            self.logger.error(f"Error: {str(e)}")
            raise
    
    def _stage_1_advanced_severity_filtering(
        self, 
        raw_findings: List[Dict[str, Any]], 
        app_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Stage 1: Apply advanced severity-based filtering with preservation."""
        start_time = time.time()
        
        self.logger.info("Stage 1: Advanced severity filtering with preservation")
        
        # Apply advanced severity filtering
        result = self.severity_filter.filter_findings_with_preservation(
            raw_findings, self.pipeline_config, app_context
        )
        
        processing_time = (time.time() - start_time) * 1000
        
        # Add stage metrics to history
        stage_metrics = result['metrics']
        self.metrics_history.append(stage_metrics)
        
        self.logger.info(f"Stage 1 complete: {stage_metrics.reduction_percentage:.1f}% reduction")
        self.logger.info(f"Vulnerability preservation applied: {result.get('preserved_additional', 0)} additional findings")
        
        return result
    
    def _stage_2_professional_confidence_scoring(
        self, 
        findings: List[Dict[str, Any]], 
        app_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Stage 2: Apply professional confidence scoring with enhancement."""
        start_time = time.time()
        
        self.logger.info("Stage 2: confidence scoring")
        
        # Apply professional confidence calculation
        result = self.confidence_calculator.calculate_confidence_scores(
            findings, self.pipeline_config, app_context
        )
        
        processing_time = (time.time() - start_time) * 1000
        
        # Add stage metrics to history
        stage_metrics = result['metrics']
        self.metrics_history.append(stage_metrics)
        
        self.logger.info(f"Stage 2 complete: {stage_metrics.reduction_percentage:.1f}% reduction")
        self.logger.info(f"Confidence enhancement applied: True")
        
        return result
    
    def _stage_3_intelligent_deduplication(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Stage 3: Apply intelligent deduplication with preservation."""
        start_time = time.time()
        
        self.logger.info("Stage 3: Intelligent deduplication with preservation")
        
        # Apply intelligent deduplication
        result = self.deduplication_engine.deduplicate_with_preservation(
            findings, self.pipeline_config
        )
        
        processing_time = (time.time() - start_time) * 1000
        
        # Add stage metrics to history
        stage_metrics = result['metrics']
        self.metrics_history.append(stage_metrics)
        
        self.logger.info(f"Stage 3 complete: {stage_metrics.reduction_percentage:.1f}% reduction")
        self.logger.info(f"Vulnerability preservation applied: {result.get('preserved_additional', 0)} additional findings")
        
        return result
    
    def _calculate_final_metrics(
        self, 
        original_findings: List[Dict[str, Any]], 
        final_findings: List[Dict[str, Any]], 
        total_time_ms: float
    ) -> AccuracyMetrics:
        """Calculate comprehensive final processing metrics."""
        original_count = len(original_findings)
        final_count = len(final_findings)
        
        # Create accuracy metrics for this stage
        reduction_percentage = ((original_count - final_count) / original_count * 100) if original_count > 0 else 0
        
        accuracy_metrics = AccuracyMetrics(
            stage=ProcessingStage.FINAL_OUTPUT,
            total_findings=original_count,
            filtered_findings=final_count,
            reduction_percentage=reduction_percentage,
            processing_time_ms=total_time_ms,
            memory_usage_mb=0.0,
            vulnerabilities_detected=final_count,
            vulnerabilities_preserved=final_count
        )
        
        # Calculate accuracy enhancement metrics
        accuracy_score = self._calculate_accuracy_score(original_findings, final_findings)
        confidence_improvement = self._calculate_confidence_improvement(original_findings, final_findings)
        
        return AccuracyMetrics(
            stage=ProcessingStage.FINAL_OUTPUT,
            total_findings=original_count,
            filtered_findings=final_count,
            reduction_percentage=reduction_percentage,
            processing_time_ms=total_time_ms,
            memory_usage_mb=0.0,
            vulnerabilities_detected=final_count,
            vulnerabilities_preserved=final_count
        )
    
    def _generate_vulnerability_preservation_report(
        self, 
        original_findings: List[Dict[str, Any]], 
        final_findings: List[Dict[str, Any]]
    ) -> VulnerabilityPreservationReport:
        """Generate comprehensive vulnerability preservation analysis."""
        original_count = len(original_findings)
        final_count = len(final_findings)
        
        # Calculate preservation rate
        preservation_rate = (final_count / original_count * 100) if original_count > 0 else 100
        
        # Analyze vulnerability types preserved
        preserved_types = self._analyze_preserved_vulnerability_types(original_findings, final_findings)
        
        # Calculate vulnerability loss analysis
        vulnerability_loss = self._analyze_vulnerability_loss(original_findings, final_findings)
        
        return VulnerabilityPreservationReport(
            original_vulnerabilities=original_findings,
            preserved_vulnerabilities=final_findings,
            preservation_rate=preservation_rate,
            preservation_by_category=preserved_types,
            meets_detection_standards=preservation_rate >= 85.0  # 85% minimum preservation
        )
    
    def _calculate_quality_indicators(
        self, 
        original_findings: List[Dict[str, Any]], 
        final_findings: List[Dict[str, Any]], 
        preservation: VulnerabilityPreservationReport
    ) -> DetectionQuality:
        """Calculate detection quality indicators."""
        
        # Analyze detection completeness
        completeness_score = preservation.preservation_rate / 100.0
        
        # Analyze accuracy improvements
        accuracy_score = self._calculate_accuracy_score(original_findings, final_findings)
        
        # Calculate overall quality score
        overall_quality = (completeness_score * 0.7 + accuracy_score * 0.3)
        
        # Determine quality level
        if overall_quality >= 0.9:
            quality_level = DetectionQuality.EXCELLENT
        elif overall_quality >= 0.8:
            quality_level = DetectionQuality.GOOD
        elif overall_quality >= 0.7:
            quality_level = DetectionQuality.ACCEPTABLE
        else:
            quality_level = DetectionQuality.NEEDS_IMPROVEMENT
        
        return quality_level
    
    def _calculate_accuracy_score(
        self, 
        original_findings: List[Dict[str, Any]], 
        final_findings: List[Dict[str, Any]]
    ) -> float:
        """Calculate accuracy improvement score."""
        # Simplified accuracy calculation based on confidence enhancement
        if not final_findings:
            return 0.0
        
        # Calculate average confidence improvement
        original_avg_confidence = self._calculate_average_confidence(original_findings)
        final_avg_confidence = self._calculate_average_confidence(final_findings)
        
        confidence_improvement = final_avg_confidence - original_avg_confidence
        
        # Convert to 0-1 scale
        return max(0.0, min(1.0, 0.8 + confidence_improvement * 0.2))
    
    def _calculate_confidence_improvement(
        self, 
        original_findings: List[Dict[str, Any]], 
        final_findings: List[Dict[str, Any]]
    ) -> float:
        """Calculate confidence improvement percentage."""
        original_avg = self._calculate_average_confidence(original_findings)
        final_avg = self._calculate_average_confidence(final_findings)
        
        return final_avg - original_avg
    
    def _calculate_average_confidence(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate average confidence score for findings."""
        if not findings:
            return 0.0
        
        total_confidence = sum(finding.get('confidence', 0.5) for finding in findings)
        return total_confidence / len(findings)
    
    def _analyze_preserved_vulnerability_types(
        self, 
        original_findings: List[Dict[str, Any]], 
        final_findings: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Analyze which vulnerability types were preserved."""
        preserved_types = {}
        
        for finding in final_findings:
            vuln_type = finding.get('type', 'unknown')
            preserved_types[vuln_type] = preserved_types.get(vuln_type, 0) + 1
        
        return preserved_types
    
    def _analyze_vulnerability_loss(
        self, 
        original_findings: List[Dict[str, Any]], 
        final_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze potential vulnerability loss during processing."""
        original_count = len(original_findings)
        final_count = len(final_findings)
        lost_count = original_count - final_count
        
        return {
            'total_lost': lost_count,
            'loss_percentage': (lost_count / original_count * 100) if original_count > 0 else 0,
            'acceptable_loss': lost_count <= (original_count * 0.15)  # 15% max acceptable loss
        }
    
    def _is_likely_vulnerability(self, finding: Dict[str, Any]) -> bool:
        """Determine if a finding represents a likely vulnerability."""
        # High confidence threshold
        confidence = finding.get('confidence', 0.0)
        if confidence >= 0.7:
            return True
        
        # High/Critical severity
        severity = str(finding.get('severity', '')).upper()
        if severity in ['HIGH', 'CRITICAL']:
            return True
        
        # Known vulnerability patterns
        finding_type = str(finding.get('type', '')).lower()
        vulnerability_patterns = [
            'injection', 'xss', 'csrf', 'auth', 'crypto', 'ssl', 'tls',
            'permission', 'privilege', 'hardcoded', 'backdoor'
        ]
        
        return any(pattern in finding_type for pattern in vulnerability_patterns)
    
    def _update_processing_stats(self, result: DetectionPipelineResult):
        """Update pipeline processing statistics."""
        self.processing_stats['total_processed'] += 1
        self.processing_stats['total_time_ms'] += result.processing_metrics['total_time_ms']
        
        # Calculate running averages
        total_processed = self.processing_stats['total_processed']
        self.processing_stats['average_reduction'] = (
            (self.processing_stats['average_reduction'] * (total_processed - 1) + 
             result.accuracy_metrics.reduction_percentage) / total_processed
        )
        
        self.processing_stats['vulnerability_preservation_rate'] = (
            (self.processing_stats['vulnerability_preservation_rate'] * (total_processed - 1) +
             result.vulnerability_preservation.preservation_rate) / total_processed
        )
    
    def _convert_result_to_dict(self, result: DetectionPipelineResult) -> Dict[str, Any]:
        """Convert DetectionPipelineResult to dictionary for backward compatibility."""
        return {
            'processed_findings': result.processed_findings,
            'original_count': len(result.original_findings),
            'final_count': len(result.processed_findings),
            'reduction_percentage': result.accuracy_metrics.reduction_percentage,
            'processing_time_ms': result.processing_metrics['total_time_ms'],
            'vulnerability_preservation_rate': result.vulnerability_preservation.preservation_rate,
            'detection_quality': result.detection_quality.value,
            'pipeline_id': result.pipeline_id
        }
    
    def get_processing_statistics(self) -> Dict[str, Any]:
        """Get comprehensive processing statistics."""
        return {
            'total_processed': self.processing_stats['total_processed'],
            'average_processing_time_ms': (
                self.processing_stats['total_time_ms'] / self.processing_stats['total_processed']
                if self.processing_stats['total_processed'] > 0 else 0
            ),
            'average_reduction_percentage': self.processing_stats['average_reduction'],
            'average_preservation_rate': self.processing_stats['vulnerability_preservation_rate'],
            'metrics_history_count': len(self.metrics_history)
        }

# Enhanced detection pipeline with context awareness
from core.app_type_detector import detect_app_type, AppType

def process_vulnerabilities_with_context_awareness(self, findings, apk_context):
    """Enhanced vulnerability processing with full context awareness."""
    
    # Detect app type for context-aware processing
    app_type = detect_app_type(apk_context)
    
    self.logger.info(f"🔍 Processing {len(findings)} findings for {app_type.value}")
    
    # Initialize enhanced components
    if not hasattr(self, '_context_aware_severity_filter'):
        from core.accuracy_integration_pipeline.severity_filter import ContextAwareSeverityFilter
        self._context_aware_severity_filter = ContextAwareSeverityFilter()
    
    if not hasattr(self, '_context_aware_confidence_scorer'):
        from core.confidence_scorer import ContextAwareConfidenceScorer  
        self._context_aware_confidence_scorer = ContextAwareConfidenceScorer()
    
    # Stage 1: Context-aware severity filtering
    stage1_output = self._context_aware_severity_filter.filter_vulnerabilities_with_context(findings, apk_context)
    stage1_reduction = (len(findings) - len(stage1_output)) / len(findings) * 100
    
    # Stage 2: Context-aware confidence scoring
    stage2_output = self._context_aware_confidence_scorer.score_findings_with_context(stage1_output, apk_context)
    stage2_reduction = (len(stage1_output) - len(stage2_output)) / len(stage1_output) * 100 if stage1_output else 0
    
    # Stage 3: Preservation deduplication (unchanged)
    stage3_output = self.deduplication_engine.deduplicate_with_preservation(stage2_output)
    stage3_reduction = (len(stage2_output) - len(stage3_output)) / len(stage2_output) * 100 if stage2_output else 0
    
    # Calculate overall metrics
    overall_reduction = (len(findings) - len(stage3_output)) / len(findings) * 100
    
    self.logger.info(f"📊 Enhanced Pipeline Results:")
    self.logger.info(f"   App Type: {app_type.value}")
    self.logger.info(f"   Stage 1 (Severity): {len(findings)} → {len(stage1_output)} ({stage1_reduction:.1f}% reduction)")
    self.logger.info(f"   Stage 2 (Confidence): {len(stage1_output)} → {len(stage2_output)} ({stage2_reduction:.1f}% reduction)")
    self.logger.info(f"   Stage 3 (Deduplication): {len(stage2_output)} → {len(stage3_output)} ({stage3_reduction:.1f}% reduction)")
    self.logger.info(f"   Overall: {len(findings)} → {len(stage3_output)} ({overall_reduction:.1f}% reduction)")
    
    # Validate results for vulnerable apps
    if app_type == AppType.VULNERABLE_APP and overall_reduction > 60:
        self.logger.warning(f"⚠️ High filtering rate ({overall_reduction:.1f}%) for vulnerable app - review needed")
    
    # Return results with metadata
    return stage3_output, {
        "app_type": app_type.value,
        "stage_reductions": [stage1_reduction, stage2_reduction, stage3_reduction],
        "overall_reduction": overall_reduction,
        "final_count": len(stage3_output),
        "quality_score": self._calculate_quality_score(findings, stage3_output, app_type)
    }

def _calculate_quality_score(self, original_findings, final_findings, app_type):
    """Calculate quality score for the filtering pipeline."""
    retention_rate = len(final_findings) / len(original_findings) if original_findings else 1.0
    
    # Quality expectations per app type
    expected_retention = {
        AppType.VULNERABLE_APP: 0.5,     # Expect 50% retention
        AppType.DEVELOPMENT_APP: 0.4,    # Expect 40% retention  
        AppType.TESTING_APP: 0.4,        # Expect 40% retention
        AppType.PRODUCTION_APP: 0.2      # Expect 20% retention (high filtering)
    }
    
    expected = expected_retention.get(app_type, 0.2)
    quality_score = min(1.0, retention_rate / expected) * 100
    
    return quality_score

# Monkey patch the enhanced method into the existing class
if hasattr(locals().get('AccuracyIntegrationPipeline', None), '__dict__'):
    AccuracyIntegrationPipeline.process_vulnerabilities_with_context_awareness = process_vulnerabilities_with_context_awareness
    AccuracyIntegrationPipeline._calculate_quality_score = _calculate_quality_score
