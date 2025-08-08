#!/usr/bin/env python3
"""
Learning Analytics Dashboard for AODS Learning Framework

Provides comprehensive analytics and reporting for the learning system including
confidence accuracy metrics, pattern performance tracking, expert validation
analytics, and continuous improvement insights.

Key Features:
- Real-time confidence accuracy monitoring
- Pattern performance analytics and trends
- Expert validation metrics and insights
- Learning system health monitoring
- Automated reporting and alerting
- Interactive analytics dashboard
- Historical trend analysis
- Performance benchmarking

"""

import logging
import json
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from pathlib import Path
import statistics
from collections import defaultdict, deque
from enum import Enum
import concurrent.futures

# Optional visualization dependencies
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    import pandas as pd
    import numpy as np
    from matplotlib.dates import DateFormatter
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    VISUALIZATION_AVAILABLE = True
except ImportError:
    VISUALIZATION_AVAILABLE = False

from .analysis_exceptions import AnalyticsError, ErrorContext, ContextualLogger
from .pattern_reliability_database import PatternReliabilityDatabase, ValidationRecord
from .learning_system import ConfidenceLearningSystem, LearningMetrics
from .real_world_validation_system import RealWorldConfidenceValidator, CalibrationMetrics
from .user_feedback_integration import UserFeedbackIntegration, FeedbackSummary

class AnalyticsTimeframe(Enum):
    """Time frames for analytics reporting."""
    LAST_DAY = "last_day"
    LAST_WEEK = "last_week"
    LAST_MONTH = "last_month"
    LAST_QUARTER = "last_quarter"
    LAST_YEAR = "last_year"
    ALL_TIME = "all_time"

class MetricType(Enum):
    """Types of metrics to track."""
    CONFIDENCE_ACCURACY = "confidence_accuracy"
    PATTERN_PERFORMANCE = "pattern_performance"
    EXPERT_VALIDATION = "expert_validation"
    LEARNING_PROGRESS = "learning_progress"
    SYSTEM_HEALTH = "system_health"

@dataclass
class AnalyticsMetric:
    """Individual analytics metric."""
    metric_id: str
    metric_type: MetricType
    name: str
    value: float
    unit: str
    timestamp: datetime = field(default_factory=datetime.now)
    context: Dict[str, Any] = field(default_factory=dict)
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None
    
    @property
    def status(self) -> str:
        """Get metric status based on thresholds."""
        if self.threshold_critical is not None and self.value <= self.threshold_critical:
            return "CRITICAL"
        elif self.threshold_warning is not None and self.value <= self.threshold_warning:
            return "WARNING"
        else:
            return "OK"

@dataclass
class AnalyticsReport:
    """Comprehensive analytics report."""
    report_id: str
    report_title: str
    generated_at: datetime = field(default_factory=datetime.now)
    timeframe: AnalyticsTimeframe = AnalyticsTimeframe.LAST_WEEK
    
    # Core metrics
    confidence_accuracy_metrics: Dict[str, Any] = field(default_factory=dict)
    pattern_performance_metrics: Dict[str, Any] = field(default_factory=dict)
    expert_validation_metrics: Dict[str, Any] = field(default_factory=dict)
    learning_progress_metrics: Dict[str, Any] = field(default_factory=dict)
    system_health_metrics: Dict[str, Any] = field(default_factory=dict)
    
    # Insights and recommendations
    key_insights: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    alerts: List[str] = field(default_factory=list)
    
    # Visualizations
    charts: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        result = {}
        for key, value in self.__dict__.items():
            if isinstance(value, datetime):
                result[key] = value.isoformat()
            elif isinstance(value, Enum):
                result[key] = value.value
            else:
                result[key] = value
        return result

class ConfidenceAccuracyAnalyzer:
    """
    Analyzes confidence accuracy metrics and trends.
    """
    
    def __init__(self, 
                 reliability_db: PatternReliabilityDatabase,
                 validator: Optional[RealWorldConfidenceValidator] = None):
        """
        Initialize confidence accuracy analyzer.
        
        Args:
            reliability_db: Pattern reliability database
            validator: Real-world confidence validator
        """
        self.reliability_db = reliability_db
        self.validator = validator
        self.logger = ContextualLogger("confidence_accuracy_analyzer")
    
    def analyze_confidence_accuracy(self, timeframe: AnalyticsTimeframe) -> Dict[str, Any]:
        """Analyze confidence accuracy metrics."""
        end_date = datetime.now()
        start_date = self._get_start_date(end_date, timeframe)
        
        # Get validation records in timeframe
        validation_records = self._get_validation_records(start_date, end_date)
        
        if not validation_records:
            return {
                'overall_accuracy': 0.0,
                'total_predictions': 0,
                'confidence_distribution': {},
                'calibration_metrics': {},
                'trend_analysis': {},
                'status': 'NO_DATA'
            }
        
        # Calculate overall accuracy
        correct_predictions = sum(1 for r in validation_records if r.is_correct)
        overall_accuracy = correct_predictions / len(validation_records)
        
        # Analyze confidence distribution
        confidence_distribution = self._analyze_confidence_distribution(validation_records)
        
        # Get calibration metrics
        calibration_metrics = {}
        if self.validator:
            latest_calibration = self.validator.validate_confidence_accuracy()
            calibration_metrics = latest_calibration.to_dict()
        
        # Analyze trends
        trend_analysis = self._analyze_accuracy_trends(validation_records)
        
        return {
            'overall_accuracy': overall_accuracy,
            'total_predictions': len(validation_records),
            'correct_predictions': correct_predictions,
            'confidence_distribution': confidence_distribution,
            'calibration_metrics': calibration_metrics,
            'trend_analysis': trend_analysis,
            'status': 'OK' if overall_accuracy > 0.8 else 'WARNING'
        }
    
    def _get_validation_records(self, start_date: datetime, end_date: datetime) -> List[ValidationRecord]:
        """Get validation records within timeframe."""
        # This would query the database for validation records
        # For now, return a simplified implementation
        return []
    
    def _analyze_confidence_distribution(self, records: List[ValidationRecord]) -> Dict[str, Any]:
        """Analyze confidence score distribution."""
        if not records:
            return {}
        
        confidence_scores = [r.confidence_score for r in records]
        
        return {
            'mean': statistics.mean(confidence_scores),
            'median': statistics.median(confidence_scores),
            'std_dev': statistics.stdev(confidence_scores) if len(confidence_scores) > 1 else 0.0,
            'min': min(confidence_scores),
            'max': max(confidence_scores),
            'quartiles': {
                'q1': sorted(confidence_scores)[len(confidence_scores)//4],
                'q3': sorted(confidence_scores)[3*len(confidence_scores)//4]
            }
        }
    
    def _analyze_accuracy_trends(self, records: List[ValidationRecord]) -> Dict[str, Any]:
        """Analyze accuracy trends over time."""
        if len(records) < 2:
            return {'trend': 'INSUFFICIENT_DATA'}
        
        # Sort by timestamp
        sorted_records = sorted(records, key=lambda r: r.validation_timestamp)
        
        # Calculate rolling accuracy
        window_size = min(10, len(sorted_records) // 2)
        rolling_accuracy = []
        
        for i in range(window_size, len(sorted_records)):
            window_records = sorted_records[i-window_size:i]
            window_accuracy = sum(1 for r in window_records if r.is_correct) / len(window_records)
            rolling_accuracy.append(window_accuracy)
        
        if len(rolling_accuracy) < 2:
            return {'trend': 'INSUFFICIENT_DATA'}
        
        # Calculate trend
        trend_slope = (rolling_accuracy[-1] - rolling_accuracy[0]) / len(rolling_accuracy)
        
        return {
            'trend': 'IMPROVING' if trend_slope > 0.01 else 'DECLINING' if trend_slope < -0.01 else 'STABLE',
            'trend_slope': trend_slope,
            'rolling_accuracy': rolling_accuracy[-5:],  # Last 5 points
            'recent_accuracy': rolling_accuracy[-1] if rolling_accuracy else 0.0
        }
    
    def _get_start_date(self, end_date: datetime, timeframe: AnalyticsTimeframe) -> datetime:
        """Get start date for timeframe."""
        if timeframe == AnalyticsTimeframe.LAST_DAY:
            return end_date - timedelta(days=1)
        elif timeframe == AnalyticsTimeframe.LAST_WEEK:
            return end_date - timedelta(weeks=1)
        elif timeframe == AnalyticsTimeframe.LAST_MONTH:
            return end_date - timedelta(days=30)
        elif timeframe == AnalyticsTimeframe.LAST_QUARTER:
            return end_date - timedelta(days=90)
        elif timeframe == AnalyticsTimeframe.LAST_YEAR:
            return end_date - timedelta(days=365)
        else:  # ALL_TIME
            return datetime.min

class PatternPerformanceAnalyzer:
    """
    Analyzes pattern performance metrics and identifies top/bottom performers.
    """
    
    def __init__(self, reliability_db: PatternReliabilityDatabase):
        """
        Initialize pattern performance analyzer.
        
        Args:
            reliability_db: Pattern reliability database
        """
        self.reliability_db = reliability_db
        self.logger = ContextualLogger("pattern_performance_analyzer")
    
    def analyze_pattern_performance(self, timeframe: AnalyticsTimeframe) -> Dict[str, Any]:
        """Analyze pattern performance metrics."""
        # Get all patterns with their performance metrics
        patterns = self._get_all_patterns()
        
        if not patterns:
            return {
                'total_patterns': 0,
                'top_performers': [],
                'bottom_performers': [],
                'performance_distribution': {},
                'status': 'NO_DATA'
            }
        
        # Calculate performance metrics for each pattern
        pattern_metrics = []
        for pattern in patterns:
            metrics = self._calculate_pattern_metrics(pattern)
            pattern_metrics.append(metrics)
        
        # Sort by performance
        sorted_patterns = sorted(pattern_metrics, key=lambda x: x['performance_score'], reverse=True)
        
        # Identify top and bottom performers
        top_performers = sorted_patterns[:5]
        bottom_performers = sorted_patterns[-5:]
        
        # Calculate performance distribution
        performance_scores = [p['performance_score'] for p in pattern_metrics]
        performance_distribution = self._calculate_performance_distribution(performance_scores)
        
        return {
            'total_patterns': len(patterns),
            'top_performers': top_performers,
            'bottom_performers': bottom_performers,
            'performance_distribution': performance_distribution,
            'average_performance': statistics.mean(performance_scores),
            'median_performance': statistics.median(performance_scores),
            'status': 'OK' if statistics.mean(performance_scores) > 0.7 else 'WARNING'
        }
    
    def _get_all_patterns(self) -> List[Any]:
        """Get all patterns from database."""
        # This would query all patterns from the database
        # For now, return a simplified implementation
        return []
    
    def _calculate_pattern_metrics(self, pattern: Any) -> Dict[str, Any]:
        """Calculate performance metrics for a pattern."""
        # This would calculate comprehensive metrics for a pattern
        # For now, return a simplified structure
        return {
            'pattern_id': getattr(pattern, 'pattern_id', 'unknown'),
            'pattern_name': getattr(pattern, 'pattern_name', 'unknown'),
            'performance_score': getattr(pattern, 'reliability_score', 0.0),
            'accuracy_rate': getattr(pattern, 'accuracy_rate', 0.0),
            'usage_frequency': getattr(pattern, 'total_matches', 0),
            'false_positive_rate': getattr(pattern, 'false_positive_rate', 0.0)
        }
    
    def _calculate_performance_distribution(self, scores: List[float]) -> Dict[str, Any]:
        """Calculate performance distribution statistics."""
        if not scores:
            return {}
        
        return {
            'excellent': sum(1 for s in scores if s >= 0.9) / len(scores),
            'good': sum(1 for s in scores if 0.7 <= s < 0.9) / len(scores),
            'fair': sum(1 for s in scores if 0.5 <= s < 0.7) / len(scores),
            'poor': sum(1 for s in scores if s < 0.5) / len(scores)
        }

class ExpertValidationAnalyzer:
    """
    Analyzes expert validation metrics and feedback patterns.
    """
    
    def __init__(self, feedback_integration: Optional[UserFeedbackIntegration] = None):
        """
        Initialize expert validation analyzer.
        
        Args:
            feedback_integration: User feedback integration system
        """
        self.feedback_integration = feedback_integration
        self.logger = ContextualLogger("expert_validation_analyzer")
    
    def analyze_expert_validation(self, timeframe: AnalyticsTimeframe) -> Dict[str, Any]:
        """Analyze expert validation metrics."""
        if not self.feedback_integration:
            return {
                'total_experts': 0,
                'total_validations': 0,
                'validation_rate': 0.0,
                'expert_agreement': 0.0,
                'status': 'NO_DATA'
            }
        
        # Get feedback statistics
        feedback_stats = self.feedback_integration.feedback_db.get_statistics()
        
        # Calculate expert metrics
        expert_metrics = self._calculate_expert_metrics()
        
        # Calculate validation trends
        validation_trends = self._calculate_validation_trends(timeframe)
        
        return {
            'total_experts': feedback_stats.get('unique_experts', 0),
            'total_validations': feedback_stats.get('total_feedback', 0),
            'processed_validations': feedback_stats.get('processed_feedback', 0),
            'validation_rate': feedback_stats.get('processing_rate', 0.0),
            'positive_feedback_rate': feedback_stats.get('positive_feedback', 0) / max(feedback_stats.get('total_feedback', 1), 1),
            'expert_metrics': expert_metrics,
            'validation_trends': validation_trends,
            'status': 'OK' if feedback_stats.get('processing_rate', 0.0) > 0.8 else 'WARNING'
        }
    
    def _calculate_expert_metrics(self) -> Dict[str, Any]:
        """Calculate expert performance metrics."""
        # This would calculate expert-specific metrics
        # For now, return a basic structure
        return {
            'top_contributors': [],
            'expert_accuracy': {},
            'expertise_distribution': {}
        }
    
    def _calculate_validation_trends(self, timeframe: AnalyticsTimeframe) -> Dict[str, Any]:
        """Calculate validation trends over time."""
        return {
            'trend': 'STABLE',
            'validation_velocity': 0.0,
            'recent_activity': 0.0
        }

class LearningSystemHealthMonitor:
    """
    Monitors overall learning system health and performance.
    """
    
    def __init__(self, 
                 learning_system: Optional[ConfidenceLearningSystem] = None,
                 reliability_db: Optional[PatternReliabilityDatabase] = None):
        """
        Initialize learning system health monitor.
        
        Args:
            learning_system: Learning system instance
            reliability_db: Pattern reliability database
        """
        self.learning_system = learning_system
        self.reliability_db = reliability_db
        self.logger = ContextualLogger("learning_system_health")
    
    def monitor_system_health(self) -> Dict[str, Any]:
        """Monitor overall system health."""
        health_metrics = {
            'overall_status': 'OK',
            'component_status': {},
            'performance_metrics': {},
            'alerts': [],
            'recommendations': []
        }
        
        # Check learning system health
        if self.learning_system:
            learning_health = self._check_learning_system_health()
            health_metrics['component_status']['learning_system'] = learning_health
        
        # Check database health
        if self.reliability_db:
            db_health = self._check_database_health()
            health_metrics['component_status']['reliability_db'] = db_health
        
        # Calculate overall status
        component_statuses = list(health_metrics['component_status'].values())
        if any(status == 'CRITICAL' for status in component_statuses):
            health_metrics['overall_status'] = 'CRITICAL'
        elif any(status == 'WARNING' for status in component_statuses):
            health_metrics['overall_status'] = 'WARNING'
        
        return health_metrics
    
    def _check_learning_system_health(self) -> str:
        """Check learning system component health."""
        try:
            # Get learning metrics
            if hasattr(self.learning_system, 'get_learning_metrics'):
                metrics = self.learning_system.get_learning_metrics()
                
                # Check critical metrics
                if metrics.overall_accuracy < 0.6:
                    return 'CRITICAL'
                elif metrics.overall_accuracy < 0.8:
                    return 'WARNING'
                else:
                    return 'OK'
            
            return 'OK'
        except Exception as e:
            self.logger.error(f"Learning system health check failed: {e}")
            return 'CRITICAL'
    
    def _check_database_health(self) -> str:
        """Check database health."""
        try:
            # Get database statistics
            stats = self.reliability_db.get_statistics()
            
            # Check for basic functionality
            if stats.get('total_patterns', 0) == 0:
                return 'WARNING'
            
            return 'OK'
        except Exception as e:
            self.logger.error(f"Database health check failed: {e}")
            return 'CRITICAL'

class VisualizationGenerator:
    """
    Generates visualizations for analytics reports.
    """
    
    def __init__(self):
        """Initialize visualization generator."""
        self.logger = ContextualLogger("visualization_generator")
        self.available = VISUALIZATION_AVAILABLE
    
    def generate_confidence_accuracy_chart(self, accuracy_data: Dict[str, Any]) -> Optional[str]:
        """Generate confidence accuracy chart."""
        if not self.available:
            return None
        
        try:
            # Create accuracy trend chart
            fig = go.Figure()
            
            if 'trend_analysis' in accuracy_data and 'rolling_accuracy' in accuracy_data['trend_analysis']:
                rolling_accuracy = accuracy_data['trend_analysis']['rolling_accuracy']
                fig.add_trace(go.Scatter(
                    x=list(range(len(rolling_accuracy))),
                    y=rolling_accuracy,
                    mode='lines+markers',
                    name='Rolling Accuracy',
                    line=dict(color='blue', width=2)
                ))
            
            fig.update_layout(
                title='Confidence Accuracy Trend',
                xaxis_title='Time Period',
                yaxis_title='Accuracy',
                yaxis=dict(range=[0, 1])
            )
            
            # Save chart
            chart_path = "data/charts/confidence_accuracy.html"
            Path(chart_path).parent.mkdir(parents=True, exist_ok=True)
            fig.write_html(chart_path)
            
            return chart_path
            
        except Exception as e:
            self.logger.error(f"Failed to generate confidence accuracy chart: {e}")
            return None
    
    def generate_pattern_performance_chart(self, performance_data: Dict[str, Any]) -> Optional[str]:
        """Generate pattern performance chart."""
        if not self.available:
            return None
        
        try:
            # Create performance distribution chart
            fig = go.Figure()
            
            if 'performance_distribution' in performance_data:
                dist = performance_data['performance_distribution']
                categories = list(dist.keys())
                values = list(dist.values())
                
                fig.add_trace(go.Bar(
                    x=categories,
                    y=values,
                    name='Performance Distribution',
                    marker_color='green'
                ))
            
            fig.update_layout(
                title='Pattern Performance Distribution',
                xaxis_title='Performance Category',
                yaxis_title='Proportion'
            )
            
            # Save chart
            chart_path = "data/charts/pattern_performance.html"
            Path(chart_path).parent.mkdir(parents=True, exist_ok=True)
            fig.write_html(chart_path)
            
            return chart_path
            
        except Exception as e:
            self.logger.error(f"Failed to generate pattern performance chart: {e}")
            return None

class LearningAnalyticsDashboard:
    """
    Main learning analytics dashboard providing comprehensive reporting.
    """
    
    def __init__(self, 
                 reliability_db: PatternReliabilityDatabase,
                 learning_system: Optional[ConfidenceLearningSystem] = None,
                 validator: Optional[RealWorldConfidenceValidator] = None,
                 feedback_integration: Optional[UserFeedbackIntegration] = None):
        """
        Initialize learning analytics dashboard.
        
        Args:
            reliability_db: Pattern reliability database
            learning_system: Learning system instance
            validator: Real-world confidence validator
            feedback_integration: User feedback integration system
        """
        self.reliability_db = reliability_db
        self.learning_system = learning_system
        self.validator = validator
        self.feedback_integration = feedback_integration
        
        self.logger = ContextualLogger("learning_analytics_dashboard")
        
        # Initialize analyzers
        self.confidence_analyzer = ConfidenceAccuracyAnalyzer(reliability_db, validator)
        self.pattern_analyzer = PatternPerformanceAnalyzer(reliability_db)
        self.expert_analyzer = ExpertValidationAnalyzer(feedback_integration)
        self.health_monitor = LearningSystemHealthMonitor(learning_system, reliability_db)
        
        # Initialize visualization generator
        self.visualization_generator = VisualizationGenerator()
        
        # Report cache
        self.report_cache = deque(maxlen=100)
        self._cache_lock = threading.Lock()
    
    def generate_comprehensive_report(self, timeframe: AnalyticsTimeframe = AnalyticsTimeframe.LAST_WEEK) -> AnalyticsReport:
        """Generate comprehensive analytics report."""
        report_id = f"learning_analytics_{int(time.time())}"
        
        self.logger.info(f"Generating comprehensive analytics report: {report_id}")
        
        # Create report
        report = AnalyticsReport(
            report_id=report_id,
            report_title=f"Learning System Analytics - {timeframe.value.replace('_', ' ').title()}",
            timeframe=timeframe
        )
        
        # Analyze confidence accuracy
        try:
            report.confidence_accuracy_metrics = self.confidence_analyzer.analyze_confidence_accuracy(timeframe)
        except Exception as e:
            self.logger.error(f"Confidence accuracy analysis failed: {e}")
            report.confidence_accuracy_metrics = {'error': str(e)}
        
        # Analyze pattern performance
        try:
            report.pattern_performance_metrics = self.pattern_analyzer.analyze_pattern_performance(timeframe)
        except Exception as e:
            self.logger.error(f"Pattern performance analysis failed: {e}")
            report.pattern_performance_metrics = {'error': str(e)}
        
        # Analyze expert validation
        try:
            report.expert_validation_metrics = self.expert_analyzer.analyze_expert_validation(timeframe)
        except Exception as e:
            self.logger.error(f"Expert validation analysis failed: {e}")
            report.expert_validation_metrics = {'error': str(e)}
        
        # Monitor system health
        try:
            report.system_health_metrics = self.health_monitor.monitor_system_health()
        except Exception as e:
            self.logger.error(f"System health monitoring failed: {e}")
            report.system_health_metrics = {'error': str(e)}
        
        # Generate insights and recommendations
        report.key_insights = self._generate_key_insights(report)
        report.recommendations = self._generate_recommendations(report)
        report.alerts = self._generate_alerts(report)
        
        # Generate visualizations
        try:
            report.charts = self._generate_visualizations(report)
        except Exception as e:
            self.logger.error(f"Visualization generation failed: {e}")
            report.charts = {'error': str(e)}
        
        # Cache report
        with self._cache_lock:
            self.report_cache.append(report)
        
        self.logger.info(f"Completed analytics report generation: {report_id}")
        
        return report
    
    def _generate_key_insights(self, report: AnalyticsReport) -> List[str]:
        """Generate key insights from analytics data."""
        insights = []
        
        # Confidence accuracy insights
        if 'overall_accuracy' in report.confidence_accuracy_metrics:
            accuracy = report.confidence_accuracy_metrics['overall_accuracy']
            if accuracy > 0.9:
                insights.append(f"Excellent confidence accuracy: {accuracy:.1%}")
            elif accuracy > 0.8:
                insights.append(f"Good confidence accuracy: {accuracy:.1%}")
            else:
                insights.append(f"Confidence accuracy needs improvement: {accuracy:.1%}")
        
        # Pattern performance insights
        if 'average_performance' in report.pattern_performance_metrics:
            avg_performance = report.pattern_performance_metrics['average_performance']
            if avg_performance > 0.8:
                insights.append(f"Strong pattern performance: {avg_performance:.1%} average")
            else:
                insights.append(f"Pattern performance below target: {avg_performance:.1%} average")
        
        # Expert validation insights
        if 'total_experts' in report.expert_validation_metrics:
            expert_count = report.expert_validation_metrics['total_experts']
            if expert_count > 10:
                insights.append(f"Good expert engagement: {expert_count} active experts")
            elif expert_count > 5:
                insights.append(f"Moderate expert engagement: {expert_count} active experts")
            else:
                insights.append(f"Low expert engagement: {expert_count} active experts")
        
        # System health insights
        if 'overall_status' in report.system_health_metrics:
            status = report.system_health_metrics['overall_status']
            if status == 'OK':
                insights.append("Learning system is healthy and operating normally")
            else:
                insights.append(f"Learning system requires attention: {status}")
        
        return insights
    
    def _generate_recommendations(self, report: AnalyticsReport) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        # Confidence accuracy recommendations
        if 'overall_accuracy' in report.confidence_accuracy_metrics:
            accuracy = report.confidence_accuracy_metrics['overall_accuracy']
            if accuracy < 0.8:
                recommendations.append("Review confidence calculation methods and pattern reliability")
        
        # Pattern performance recommendations
        if 'bottom_performers' in report.pattern_performance_metrics:
            bottom_performers = report.pattern_performance_metrics['bottom_performers']
            if bottom_performers:
                recommendations.append(f"Review and improve {len(bottom_performers)} underperforming patterns")
        
        # Expert validation recommendations
        if 'total_experts' in report.expert_validation_metrics:
            expert_count = report.expert_validation_metrics['total_experts']
            if expert_count < 5:
                recommendations.append("Expand expert validation network to improve feedback quality")
        
        # System health recommendations
        if 'component_status' in report.system_health_metrics:
            for component, status in report.system_health_metrics['component_status'].items():
                if status in ['WARNING', 'CRITICAL']:
                    recommendations.append(f"Address {component} issues ({status})")
        
        return recommendations
    
    def _generate_alerts(self, report: AnalyticsReport) -> List[str]:
        """Generate alerts for critical issues."""
        alerts = []
        
        # Critical accuracy issues
        if 'overall_accuracy' in report.confidence_accuracy_metrics:
            accuracy = report.confidence_accuracy_metrics['overall_accuracy']
            if accuracy < 0.6:
                alerts.append(f"CRITICAL: Confidence accuracy below 60%: {accuracy:.1%}")
        
        # System health alerts
        if 'overall_status' in report.system_health_metrics:
            status = report.system_health_metrics['overall_status']
            if status == 'CRITICAL':
                alerts.append("CRITICAL: Learning system health issues detected")
        
        return alerts
    
    def _generate_visualizations(self, report: AnalyticsReport) -> Dict[str, Any]:
        """Generate visualizations for the report."""
        charts = {}
        
        # Confidence accuracy chart
        if report.confidence_accuracy_metrics:
            chart_path = self.visualization_generator.generate_confidence_accuracy_chart(
                report.confidence_accuracy_metrics
            )
            if chart_path:
                charts['confidence_accuracy'] = chart_path
        
        # Pattern performance chart
        if report.pattern_performance_metrics:
            chart_path = self.visualization_generator.generate_pattern_performance_chart(
                report.pattern_performance_metrics
            )
            if chart_path:
                charts['pattern_performance'] = chart_path
        
        return charts
    
    def get_real_time_metrics(self) -> Dict[str, Any]:
        """Get real-time learning system metrics."""
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'system_status': 'OK',
            'quick_stats': {}
        }
        
        try:
            # Get quick statistics
            if self.learning_system:
                learning_metrics = self.learning_system.get_learning_metrics()
                metrics['quick_stats']['overall_accuracy'] = learning_metrics.overall_accuracy
                metrics['quick_stats']['total_validations'] = learning_metrics.total_validations
                metrics['quick_stats']['model_accuracy'] = learning_metrics.model_accuracy
            
            # Get database statistics
            if self.reliability_db:
                db_stats = self.reliability_db.get_statistics()
                metrics['quick_stats']['total_patterns'] = db_stats.get('total_patterns', 0)
                metrics['quick_stats']['active_patterns'] = db_stats.get('active_patterns', 0)
            
            # Get feedback statistics
            if self.feedback_integration:
                feedback_stats = self.feedback_integration.feedback_db.get_statistics()
                metrics['quick_stats']['total_feedback'] = feedback_stats.get('total_feedback', 0)
                metrics['quick_stats']['unique_experts'] = feedback_stats.get('unique_experts', 0)
            
        except Exception as e:
            metrics['system_status'] = 'ERROR'
            metrics['error'] = str(e)
        
        return metrics
    
    def get_cached_reports(self, limit: int = 10) -> List[AnalyticsReport]:
        """Get cached reports."""
        with self._cache_lock:
            return list(self.report_cache)[-limit:]
    
    def export_report(self, report: AnalyticsReport, format: str = 'json') -> str:
        """Export report to specified format."""
        if format == 'json':
            export_path = f"data/reports/{report.report_id}.json"
            Path(export_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(export_path, 'w') as f:
                json.dump(report.to_dict(), f, indent=2)
            
            return export_path
        
        else:
            raise ValueError(f"Unsupported export format: {format}")

# Factory functions for integration
def create_learning_analytics_dashboard(
    reliability_db: PatternReliabilityDatabase,
    learning_system: Optional[ConfidenceLearningSystem] = None,
    validator: Optional[RealWorldConfidenceValidator] = None,
    feedback_integration: Optional[UserFeedbackIntegration] = None
) -> LearningAnalyticsDashboard:
    """Create learning analytics dashboard."""
    return LearningAnalyticsDashboard(
        reliability_db=reliability_db,
        learning_system=learning_system,
        validator=validator,
        feedback_integration=feedback_integration
    )

def initialize_analytics_system(
    reliability_db: PatternReliabilityDatabase,
    learning_system: Optional[ConfidenceLearningSystem] = None,
    validator: Optional[RealWorldConfidenceValidator] = None,
    feedback_integration: Optional[UserFeedbackIntegration] = None
) -> Dict[str, Any]:
    """Initialize complete analytics system."""
    dashboard = create_learning_analytics_dashboard(
        reliability_db, learning_system, validator, feedback_integration
    )
    
    # Generate initial report
    initial_report = dashboard.generate_comprehensive_report()
    
    # Get real-time metrics
    real_time_metrics = dashboard.get_real_time_metrics()
    
    return {
        'dashboard': dashboard,
        'initial_report': initial_report,
        'real_time_metrics': real_time_metrics,
        'status': 'initialized'
    } 