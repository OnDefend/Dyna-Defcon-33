#!/usr/bin/env python3
"""
AI/ML Integration Manager

Comprehensive integration manager that combines all AI/ML components with the
unified execution framework to provide intelligent, adaptive, and highly
accurate vulnerability detection.
"""

import logging
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import Counter

# Import AI/ML components
try:
    from .intelligent_vulnerability_detector import IntelligentVulnerabilityDetector, DetectionResult
    from .ml_false_positive_reducer import MLFalsePositiveReducer, FPReductionResult
    from .adaptive_scanning_intelligence import AdaptiveScanningIntelligence, AdaptiveRecommendation
    AI_ML_COMPONENTS_AVAILABLE = True
except ImportError:
    AI_ML_COMPONENTS_AVAILABLE = False

# Import unified execution framework
try:
    from core.execution import UnifiedExecutionManager, ExecutionConfig, ExecutionMode
    UNIFIED_EXECUTION_AVAILABLE = True
except ImportError:
    UNIFIED_EXECUTION_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class AIMLEnhancedResult:
    """Enhanced analysis result with AI/ML insights."""
    original_result: Any
    ai_vulnerability_analysis: Optional[DetectionResult]
    false_positive_analysis: Optional[FPReductionResult]
    confidence_score: float
    recommendations: List[str]
    ai_insights: Dict[str, Any]
    processing_time: float

@dataclass
class AdaptiveExecutionPlan:
    """Execution plan enhanced with AI/ML recommendations."""
    execution_strategy: str
    plugin_selection: List[str]
    timeout_settings: Dict[str, int]
    resource_allocation: Dict[str, Any]
    optimization_notes: List[str]
    expected_performance: Dict[str, float]

class AIMLIntegrationManager:
    """
    AI/ML Integration Manager.
    
    Provides comprehensive AI/ML enhancement to the AODS vulnerability detection
    system by integrating:
    - Intelligent vulnerability detection
    - ML-based false positive reduction  
    - Adaptive scanning strategies
    - Unified execution optimization
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the AI/ML integration manager."""
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        
        # Initialize AI/ML components
        self.ai_components_available = AI_ML_COMPONENTS_AVAILABLE
        self.unified_execution_available = UNIFIED_EXECUTION_AVAILABLE
        
        if self.ai_components_available:
            self._initialize_ai_components()
        else:
            self.logger.warning("AI/ML components not available - using standard detection")
        
        if self.unified_execution_available:
            self._initialize_unified_execution()
        else:
            self.logger.warning("Unified execution framework not available")
        
        # Performance tracking
        self.stats = {
            "analyses_processed": 0,
            "ai_enhancements_applied": 0,
            "false_positives_reduced": 0,
            "adaptive_optimizations": 0,
            "total_processing_time": 0.0
        }
        
        self.logger.info("AI/ML Integration Manager initialized")
    
    def _initialize_ai_components(self):
        """Initialize AI/ML components."""
        try:
            # Initialize vulnerability detector
            self.vulnerability_detector = IntelligentVulnerabilityDetector(
                model_cache_dir=self.config.get("vulnerability_models_dir", "models/vulnerability_detection")
            )
            
            # Initialize false positive reducer
            self.fp_reducer = MLFalsePositiveReducer(
                model_cache_dir=self.config.get("fp_models_dir", "models/false_positive_reduction")
            )
            
            # Initialize adaptive scanning intelligence
            self.adaptive_scanner = AdaptiveScanningIntelligence(
                model_cache_dir=self.config.get("adaptive_models_dir", "models/adaptive_scanning")
            )
            
            self.logger.info("AI/ML components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize AI/ML components: {e}")
            self.ai_components_available = False
    
    def _initialize_unified_execution(self):
        """Initialize unified execution framework integration."""
        try:
            # Create AI/ML optimized execution configuration
            self.execution_config = ExecutionConfig(
                execution_mode=ExecutionMode.ADAPTIVE,
                enable_performance_learning=True,
                enable_context_awareness=True,
                enable_intelligent_fallback=True
            )
            
            # Initialize unified execution manager
            self.unified_manager = UnifiedExecutionManager(self.execution_config)
            
            self.logger.info("Unified execution framework integration initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize unified execution: {e}")
            self.unified_execution_available = False
    
    def create_adaptive_execution_plan(self, apk_path: str, 
                                     context: Dict[str, Any] = None) -> AdaptiveExecutionPlan:
        """
        Create an adaptive execution plan based on APK analysis.
        
        Args:
            apk_path: Path to APK file
            context: Additional context information
            
        Returns:
            AdaptiveExecutionPlan with AI/ML optimized settings
        """
        context = context or {}
        
        if not self.ai_components_available:
            return self._create_default_execution_plan()
        
        try:
            # Get adaptive scanning recommendation
            recommendation = self.adaptive_scanner.analyze_and_recommend(apk_path, context)
            
            # Convert to execution plan
            plan = AdaptiveExecutionPlan(
                execution_strategy=recommendation.recommended_strategy.execution_mode,
                plugin_selection=recommendation.recommended_strategy.plugin_selection,
                timeout_settings={
                    "plugin_timeout": int(recommendation.recommended_strategy.estimated_duration / len(recommendation.recommended_strategy.plugin_selection)) if recommendation.recommended_strategy.plugin_selection else 300,
                    "total_timeout": int(recommendation.recommended_strategy.estimated_duration),
                    "timeout_multiplier": recommendation.recommended_strategy.timeout_multiplier
                },
                resource_allocation=recommendation.recommended_strategy.resource_allocation,
                optimization_notes=recommendation.optimization_tips,
                expected_performance={
                    "estimated_duration": recommendation.recommended_strategy.estimated_duration,
                    "expected_findings": recommendation.expected_findings,
                    "confidence": recommendation.confidence
                }
            )
            
            self.stats["adaptive_optimizations"] += 1
            return plan
            
        except Exception as e:
            self.logger.error(f"Failed to create adaptive execution plan: {e}")
            return self._create_default_execution_plan()
    
    def enhance_vulnerability_detection(self, finding: Dict[str, Any], 
                                      context: Dict[str, Any] = None) -> AIMLEnhancedResult:
        """
        Enhance vulnerability detection with AI/ML analysis.
        
        Args:
            finding: Original finding from plugin
            context: Additional context information
            
        Returns:
            AIMLEnhancedResult with AI/ML enhancements
        """
        start_time = time.time()
        context = context or {}
        
        # Extract content for analysis
        content = self._extract_finding_content(finding)
        title = finding.get("title", "")
        
        ai_vulnerability_analysis = None
        false_positive_analysis = None
        
        if self.ai_components_available:
            try:
                # AI-powered vulnerability detection
                ai_vulnerability_analysis = self.vulnerability_detector.detect_vulnerabilities(
                    content=content,
                    title=title,
                    file_path=finding.get("file_path", ""),
                    context=context
                )
                
                # ML-based false positive reduction
                false_positive_analysis = self.fp_reducer.analyze_for_false_positive(
                    content=content,
                    title=title,
                    vulnerability_info=finding,
                    context=context
                )
                
            except Exception as e:
                self.logger.error(f"AI/ML analysis failed: {e}")
        
        # Calculate enhanced confidence score
        confidence_score = self._calculate_enhanced_confidence(
            finding, ai_vulnerability_analysis, false_positive_analysis
        )
        
        # Generate recommendations
        recommendations = self._generate_enhanced_recommendations(
            finding, ai_vulnerability_analysis, false_positive_analysis
        )
        
        # Collect AI insights
        ai_insights = self._collect_ai_insights(
            ai_vulnerability_analysis, false_positive_analysis
        )
        
        processing_time = time.time() - start_time
        self.stats["analyses_processed"] += 1
        self.stats["total_processing_time"] += processing_time
        
        if ai_vulnerability_analysis or false_positive_analysis:
            self.stats["ai_enhancements_applied"] += 1
        
        if false_positive_analysis and false_positive_analysis.is_false_positive:
            self.stats["false_positives_reduced"] += 1
        
        return AIMLEnhancedResult(
            original_result=finding,
            ai_vulnerability_analysis=ai_vulnerability_analysis,
            false_positive_analysis=false_positive_analysis,
            confidence_score=confidence_score,
            recommendations=recommendations,
            ai_insights=ai_insights,
            processing_time=processing_time
        )
    
    def execute_with_ai_optimization(self, plugins: List[Any], apk_ctx: Any, 
                                   execution_plan: Optional[AdaptiveExecutionPlan] = None) -> Dict[str, Any]:
        """
        Execute plugin analysis with AI/ML optimization.
        
        Args:
            plugins: List of plugins to execute
            apk_ctx: APK context
            execution_plan: Optional adaptive execution plan
            
        Returns:
            Enhanced execution results with AI/ML insights
        """
        if not self.unified_execution_available:
            self.logger.warning("Unified execution not available - using fallback")
            return self._execute_fallback(plugins, apk_ctx)
        
        try:
            # Apply execution plan if provided
            if execution_plan:
                self._apply_execution_plan(execution_plan)
            
            # Execute with unified framework
            start_time = time.time()
            execution_result = self.unified_manager.execute(
                plugins, 
                apk_ctx, 
                mode=ExecutionMode.ADAPTIVE
            )
            execution_time = time.time() - start_time
            
            # Enhance results with AI/ML analysis
            enhanced_results = []
            for plugin_name, result in execution_result.results.items():
                if result and len(result) >= 2:
                    # Extract finding information
                    finding = {
                        "plugin_name": plugin_name,
                        "status": result[0],
                        "content": result[1] if len(result) > 1 else "",
                        "title": f"Result from {plugin_name}",
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    # Apply AI/ML enhancement
                    enhanced_result = self.enhance_vulnerability_detection(
                        finding, 
                        context={"plugin_name": plugin_name, "execution_time": execution_time}
                    )
                    enhanced_results.append(enhanced_result)
            
            # Compile comprehensive results
            comprehensive_results = {
                "execution_results": execution_result,
                "ai_enhanced_findings": enhanced_results,
                "performance_metrics": {
                    "execution_time": execution_time,
                    "strategy_used": execution_result.strategy_used,
                    "successful_plugins": execution_result.successful_plugins,
                    "total_plugins": execution_result.total_plugins,
                    "ai_processing_time": sum(r.processing_time for r in enhanced_results)
                },
                "ai_insights": {
                    "total_enhancements": len([r for r in enhanced_results if r.ai_vulnerability_analysis]),
                    "false_positives_detected": len([r for r in enhanced_results if r.false_positive_analysis and r.false_positive_analysis.is_false_positive]),
                    "average_confidence": sum(r.confidence_score for r in enhanced_results) / len(enhanced_results) if enhanced_results else 0.0,
                    "high_confidence_findings": len([r for r in enhanced_results if r.confidence_score > 0.8])
                }
            }
            
            return comprehensive_results
            
        except Exception as e:
            self.logger.error(f"AI-optimized execution failed: {e}")
            return self._execute_fallback(plugins, apk_ctx)
    
    def provide_post_scan_analysis(self, scan_results: Dict[str, Any], 
                                 execution_plan: Optional[AdaptiveExecutionPlan] = None) -> Dict[str, Any]:
        """
        Provide comprehensive post-scan analysis with AI/ML insights.
        
        Args:
            scan_results: Results from scan execution
            execution_plan: Execution plan used (if any)
            
        Returns:
            Comprehensive analysis with recommendations
        """
        analysis = {
            "summary": self._generate_scan_summary(scan_results),
            "quality_assessment": self._assess_result_quality(scan_results),
            "recommendations": self._generate_post_scan_recommendations(scan_results, execution_plan),
            "performance_analysis": self._analyze_performance(scan_results, execution_plan),
            "ai_insights": self._generate_ai_insights(scan_results)
        }
        
        return analysis
    
    def train_from_feedback(self, feedback_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train AI/ML models from user feedback.
        
        Args:
            feedback_data: List of feedback records
            
        Returns:
            Training results and performance metrics
        """
        if not self.ai_components_available:
            return {"error": "AI/ML components not available"}
        
        training_results = {}
        
        try:
            # Process feedback for each component
            vulnerability_feedback = []
            fp_feedback = []
            
            for feedback in feedback_data:
                feedback_type = feedback.get("type", "")
                
                if feedback_type == "vulnerability_accuracy":
                    vulnerability_feedback.append(feedback)
                elif feedback_type == "false_positive":
                    fp_feedback.append(feedback)
            
            # Train vulnerability detector
            if vulnerability_feedback:
                for feedback in vulnerability_feedback:
                    self.vulnerability_detector.add_feedback(
                        text=feedback.get("content", ""),
                        actual_result=feedback.get("is_vulnerability", False),
                        user_feedback=feedback.get("notes", "")
                    )
                vuln_results = self.vulnerability_detector.retrain_models()
                training_results["vulnerability_detector"] = vuln_results
            
            # Train false positive reducer
            if fp_feedback:
                for feedback in fp_feedback:
                    self.fp_reducer.add_feedback(
                        text=feedback.get("content", ""),
                        is_actual_fp=feedback.get("is_false_positive", False),
                        user_notes=feedback.get("notes", "")
                    )
                fp_results = self.fp_reducer.retrain_models()
                training_results["false_positive_reducer"] = fp_results
            
            # Update adaptive scanner with scan results
            scan_feedback = [f for f in feedback_data if f.get("type") == "scan_performance"]
            if scan_feedback:
                for feedback in scan_feedback:
                    self.adaptive_scanner.record_scan_results(
                        apk_path=feedback.get("apk_path", ""),
                        strategy_used=feedback.get("strategy_used", ""),
                        actual_duration=feedback.get("duration", 0),
                        findings_count=feedback.get("findings_count", 0),
                        success=feedback.get("success", True),
                        performance_metrics=feedback.get("performance_metrics", {})
                    )
                adaptive_results = self.adaptive_scanner.retrain_models()
                training_results["adaptive_scanner"] = adaptive_results
            
            self.logger.info(f"Processed {len(feedback_data)} feedback records for training")
            
        except Exception as e:
            self.logger.error(f"Training from feedback failed: {e}")
            training_results["error"] = str(e)
        
        return training_results
    
    def get_ai_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive AI/ML performance metrics."""
        metrics = {
            "integration_manager": self.stats.copy()
        }
        
        if self.ai_components_available:
            try:
                metrics["vulnerability_detector"] = self.vulnerability_detector.get_performance_metrics()
                metrics["false_positive_reducer"] = self.fp_reducer.get_performance_metrics()
                metrics["adaptive_scanner"] = self.adaptive_scanner.get_performance_insights()
            except Exception as e:
                metrics["component_metrics_error"] = str(e)
        
        # Calculate derived metrics
        if self.stats["analyses_processed"] > 0:
            metrics["integration_manager"]["ai_enhancement_rate"] = self.stats["ai_enhancements_applied"] / self.stats["analyses_processed"]
            metrics["integration_manager"]["false_positive_reduction_rate"] = self.stats["false_positives_reduced"] / self.stats["analyses_processed"]
            metrics["integration_manager"]["average_processing_time"] = self.stats["total_processing_time"] / self.stats["analyses_processed"]
        
        return metrics
    
    # Helper methods
    def _create_default_execution_plan(self) -> AdaptiveExecutionPlan:
        """Create default execution plan when AI/ML is not available."""
        return AdaptiveExecutionPlan(
            execution_strategy="parallel",
            plugin_selection=["all"],
            timeout_settings={"plugin_timeout": 300, "total_timeout": 1800, "timeout_multiplier": 1.0},
            resource_allocation={"workers": 4, "memory_gb": 4},
            optimization_notes=["Using default configuration - AI/ML optimization not available"],
            expected_performance={"estimated_duration": 600, "expected_findings": 10, "confidence": 0.7}
        )
    
    def _extract_finding_content(self, finding: Dict[str, Any]) -> str:
        """Extract text content from finding for analysis."""
        content_parts = []
        
        # Add various content fields
        for field in ["description", "content", "details", "message", "output"]:
            if field in finding and finding[field]:
                content_parts.append(str(finding[field]))
        
        return " ".join(content_parts)
    
    def _calculate_enhanced_confidence(self, finding: Dict[str, Any],
                                     ai_analysis: Optional[DetectionResult],
                                     fp_analysis: Optional[FPReductionResult]) -> float:
        """Calculate enhanced confidence score using AI/ML insights."""
        base_confidence = finding.get("confidence", 0.5)
        
        # AI vulnerability analysis contribution
        ai_confidence = 0.5
        if ai_analysis:
            ai_confidence = ai_analysis.confidence
        
        # False positive analysis contribution
        fp_confidence = 0.5
        if fp_analysis:
            fp_confidence = 1.0 - fp_analysis.confidence if fp_analysis.is_false_positive else fp_analysis.confidence
        
        # Weighted combination
        enhanced_confidence = (
            base_confidence * 0.4 +
            ai_confidence * 0.4 +
            fp_confidence * 0.2
        )
        
        return min(max(enhanced_confidence, 0.0), 1.0)
    
    def _generate_enhanced_recommendations(self, finding: Dict[str, Any],
                                         ai_analysis: Optional[DetectionResult],
                                         fp_analysis: Optional[FPReductionResult]) -> List[str]:
        """Generate enhanced recommendations based on AI/ML analysis."""
        recommendations = []
        
        # AI vulnerability analysis recommendations
        if ai_analysis:
            recommendations.append(ai_analysis.recommendation)
            if ai_analysis.confidence > 0.8:
                recommendations.append("High confidence AI detection - prioritize for review")
            elif ai_analysis.confidence < 0.4:
                recommendations.append("Low confidence AI detection - manual verification recommended")
        
        # False positive analysis recommendations
        if fp_analysis:
            recommendations.append(fp_analysis.recommendation)
            if fp_analysis.is_false_positive and fp_analysis.confidence > 0.7:
                recommendations.append("Likely false positive - consider filtering from results")
        
        # General recommendations based on finding characteristics
        if finding.get("severity", "").lower() in ["high", "critical"]:
            recommendations.append("High severity finding - immediate attention required")
        
        return recommendations
    
    def _collect_ai_insights(self, ai_analysis: Optional[DetectionResult],
                           fp_analysis: Optional[FPReductionResult]) -> Dict[str, Any]:
        """Collect AI insights from analyses."""
        insights = {}
        
        if ai_analysis:
            insights["vulnerability_detection"] = {
                "ml_confidence": ai_analysis.ml_confidence,
                "vulnerability_type": ai_analysis.vulnerability_type,
                "pattern_matches": ai_analysis.pattern_matches,
                "contextual_evidence": ai_analysis.contextual_evidence,
                "explanation": ai_analysis.explanation
            }
        
        if fp_analysis:
            insights["false_positive_analysis"] = {
                "is_false_positive": fp_analysis.is_false_positive,
                "ml_score": fp_analysis.ml_score,
                "pattern_matches": fp_analysis.pattern_matches,
                "evidence": fp_analysis.evidence,
                "reason": fp_analysis.reason
            }
        
        return insights
    
    def _apply_execution_plan(self, plan: AdaptiveExecutionPlan):
        """Apply execution plan to unified execution manager."""
        if self.unified_execution_available:
            # Update execution configuration based on plan
            self.execution_config.max_workers = plan.resource_allocation.get("workers", 4)
            self.execution_config.timeout_seconds = plan.timeout_settings.get("total_timeout", 1800)
            
            # Update execution mode
            mode_mapping = {
                "parallel": ExecutionMode.PARALLEL,
                "sequential": ExecutionMode.SEQUENTIAL,
                "adaptive": ExecutionMode.ADAPTIVE,
                "process_separated": ExecutionMode.PROCESS_SEPARATED
            }
            if plan.execution_strategy in mode_mapping:
                self.execution_config.execution_mode = mode_mapping[plan.execution_strategy]
    
    def _execute_fallback(self, plugins: List[Any], apk_ctx: Any) -> Dict[str, Any]:
        """Fallback execution when unified framework is not available."""
        # Simplified fallback execution
        results = {}
        start_time = time.time()
        
        for plugin in plugins[:5]:  # Limit to first 5 plugins for fallback
            try:
                plugin_name = getattr(plugin, 'name', str(plugin))
                # Simplified plugin execution simulation
                results[plugin_name] = ("✅ Executed", f"Fallback execution for {plugin_name}")
            except Exception as e:
                results[plugin_name] = ("❌ Error", str(e))
        
        execution_time = time.time() - start_time
        
        return {
            "execution_results": {
                "results": results,
                "strategy_used": "fallback",
                "execution_time": execution_time,
                "successful_plugins": len([r for r in results.values() if r[0] == "✅ Executed"]),
                "total_plugins": len(results)
            },
            "ai_enhanced_findings": [],
            "performance_metrics": {
                "execution_time": execution_time,
                "strategy_used": "fallback"
            },
            "ai_insights": {
                "message": "Fallback execution - AI/ML enhancement not available"
            }
        }
    
    def _generate_scan_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate scan summary with AI insights."""
        enhanced_findings = scan_results.get("ai_enhanced_findings", [])
        
        summary = {
            "total_findings": len(enhanced_findings),
            "high_confidence_findings": len([f for f in enhanced_findings if f.confidence_score > 0.8]),
            "potential_false_positives": len([f for f in enhanced_findings if f.false_positive_analysis and f.false_positive_analysis.is_false_positive]),
            "ai_enhanced_findings": len([f for f in enhanced_findings if f.ai_vulnerability_analysis]),
            "execution_strategy": scan_results.get("performance_metrics", {}).get("strategy_used", "unknown")
        }
        
        return summary
    
    def _assess_result_quality(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess quality of scan results."""
        enhanced_findings = scan_results.get("ai_enhanced_findings", [])
        
        if not enhanced_findings:
            return {"quality_score": 0.5, "assessment": "Limited data for quality assessment"}
        
        # Calculate quality metrics
        avg_confidence = sum(f.confidence_score for f in enhanced_findings) / len(enhanced_findings)
        ai_coverage = len([f for f in enhanced_findings if f.ai_vulnerability_analysis]) / len(enhanced_findings)
        fp_detection_rate = len([f for f in enhanced_findings if f.false_positive_analysis]) / len(enhanced_findings)
        
        quality_score = (avg_confidence * 0.5 + ai_coverage * 0.3 + fp_detection_rate * 0.2)
        
        assessment = "High quality" if quality_score > 0.8 else "Medium quality" if quality_score > 0.6 else "Needs improvement"
        
        return {
            "quality_score": quality_score,
            "assessment": assessment,
            "average_confidence": avg_confidence,
            "ai_coverage": ai_coverage,
            "fp_detection_rate": fp_detection_rate
        }
    
    def _generate_post_scan_recommendations(self, scan_results: Dict[str, Any], 
                                          execution_plan: Optional[AdaptiveExecutionPlan]) -> List[str]:
        """Generate post-scan recommendations."""
        recommendations = []
        
        enhanced_findings = scan_results.get("ai_enhanced_findings", [])
        performance_metrics = scan_results.get("performance_metrics", {})
        
        # Performance recommendations
        execution_time = performance_metrics.get("execution_time", 0)
        if execution_plan and execution_time > execution_plan.expected_performance.get("estimated_duration", 600) * 1.5:
            recommendations.append("Scan took longer than expected - consider optimizing strategy or increasing resources")
        
        # Finding quality recommendations
        high_conf_findings = len([f for f in enhanced_findings if f.confidence_score > 0.8])
        if high_conf_findings == 0:
            recommendations.append("No high-confidence findings detected - consider running comprehensive scan")
        
        # False positive recommendations
        fp_count = len([f for f in enhanced_findings if f.false_positive_analysis and f.false_positive_analysis.is_false_positive])
        if fp_count > len(enhanced_findings) * 0.3:
            recommendations.append("High false positive rate detected - review detection patterns")
        
        return recommendations
    
    def _analyze_performance(self, scan_results: Dict[str, Any], 
                           execution_plan: Optional[AdaptiveExecutionPlan]) -> Dict[str, Any]:
        """Analyze scan performance."""
        performance_metrics = scan_results.get("performance_metrics", {})
        
        analysis = {
            "execution_time": performance_metrics.get("execution_time", 0),
            "strategy_effectiveness": "unknown",
            "resource_utilization": "unknown",
            "optimization_opportunities": []
        }
        
        if execution_plan:
            expected_duration = execution_plan.expected_performance.get("estimated_duration", 600)
            actual_duration = performance_metrics.get("execution_time", 0)
            
            if actual_duration <= expected_duration * 1.1:
                analysis["strategy_effectiveness"] = "excellent"
            elif actual_duration <= expected_duration * 1.3:
                analysis["strategy_effectiveness"] = "good"
            else:
                analysis["strategy_effectiveness"] = "needs_improvement"
                analysis["optimization_opportunities"].append("Consider different execution strategy")
        
        return analysis
    
    def _generate_ai_insights(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI-specific insights from scan results."""
        enhanced_findings = scan_results.get("ai_enhanced_findings", [])
        ai_insights = scan_results.get("ai_insights", {})
        
        insights = {
            "ai_enhancement_summary": ai_insights,
            "pattern_analysis": self._analyze_detection_patterns(enhanced_findings),
            "confidence_distribution": self._analyze_confidence_distribution(enhanced_findings),
            "recommendation_summary": self._summarize_recommendations(enhanced_findings)
        }
        
        return insights
    
    def _analyze_detection_patterns(self, enhanced_findings: List[AIMLEnhancedResult]) -> Dict[str, Any]:
        """Analyze patterns in AI detections."""
        if not enhanced_findings:
            return {"message": "No findings to analyze"}
        
        # Analyze vulnerability types detected
        vuln_types = []
        for finding in enhanced_findings:
            if finding.ai_vulnerability_analysis:
                vuln_types.append(finding.ai_vulnerability_analysis.vulnerability_type)
        
        pattern_analysis = {
            "most_common_vulnerability_types": Counter(vuln_types).most_common(5),
            "ai_detection_rate": len([f for f in enhanced_findings if f.ai_vulnerability_analysis]) / len(enhanced_findings)
        }
        
        return pattern_analysis
    
    def _analyze_confidence_distribution(self, enhanced_findings: List[AIMLEnhancedResult]) -> Dict[str, Any]:
        """Analyze confidence score distribution."""
        if not enhanced_findings:
            return {"message": "No findings to analyze"}
        
        confidence_scores = [f.confidence_score for f in enhanced_findings]
        
        distribution = {
            "average_confidence": sum(confidence_scores) / len(confidence_scores),
            "high_confidence_count": len([s for s in confidence_scores if s > 0.8]),
            "medium_confidence_count": len([s for s in confidence_scores if 0.5 <= s <= 0.8]),
            "low_confidence_count": len([s for s in confidence_scores if s < 0.5])
        }
        
        return distribution
    
    def _summarize_recommendations(self, enhanced_findings: List[AIMLEnhancedResult]) -> Dict[str, Any]:
        """Summarize recommendations from AI analysis."""
        all_recommendations = []
        for finding in enhanced_findings:
            all_recommendations.extend(finding.recommendations)
        
        # Count recommendation types
        recommendation_counts = Counter(all_recommendations)
        
        summary = {
            "total_recommendations": len(all_recommendations),
            "unique_recommendations": len(recommendation_counts),
            "most_common_recommendations": recommendation_counts.most_common(5)
        }
        
        return summary 