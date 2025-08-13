#!/usr/bin/env python3
"""
Trend Analyzer for AODS Monitoring Framework

Advanced trend analysis and predictive insights for monitoring data with
machine learning capabilities, anomaly detection, and forecasting.

Features:
- Time-series trend analysis and pattern recognition
- Anomaly detection using statistical and ML methods
- Predictive forecasting for resource planning
- Seasonal pattern analysis
- Change point detection
- Correlation analysis between metrics
- Performance degradation prediction

This component enables proactive monitoring and capacity planning
through intelligent analysis of historical monitoring data.
"""

import time
import logging
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict
import json
import math

# Optional ML dependencies
try:
    import numpy as np
    from scipy import stats
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.linear_model import LinearRegression
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    np = None

from ..analysis_exceptions import MonitoringError, ContextualLogger
from .metrics_collector import MetricsCollector, MetricDataPoint

logger = logging.getLogger(__name__)

class TrendDirection(Enum):
    """Trend direction classifications."""
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    VOLATILE = "volatile"
    UNKNOWN = "unknown"

class AnomalyType(Enum):
    """Types of anomalies that can be detected."""
    SPIKE = "spike"
    DIP = "dip"
    DRIFT = "drift"
    OUTLIER = "outlier"
    PATTERN_BREAK = "pattern_break"

@dataclass
class TrendData:
    """Trend analysis results for a metric."""
    metric_name: str
    analysis_period: timedelta
    direction: TrendDirection
    slope: float
    confidence: float
    correlation_coefficient: Optional[float] = None
    seasonal_pattern: bool = False
    change_points: List[datetime] = field(default_factory=list)
    anomalies_detected: int = 0
    volatility_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'metric_name': self.metric_name,
            'analysis_period_hours': self.analysis_period.total_seconds() / 3600,
            'direction': self.direction.value,
            'slope': self.slope,
            'confidence': self.confidence,
            'correlation_coefficient': self.correlation_coefficient,
            'seasonal_pattern': self.seasonal_pattern,
            'change_points': [cp.isoformat() for cp in self.change_points],
            'anomalies_detected': self.anomalies_detected,
            'volatility_score': self.volatility_score
        }

@dataclass
class TrendPrediction:
    """Prediction results from trend analysis."""
    metric_name: str
    prediction_horizon: timedelta
    predicted_values: List[Tuple[datetime, float]]
    confidence_intervals: List[Tuple[float, float]]
    prediction_accuracy: float
    model_type: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'metric_name': self.metric_name,
            'prediction_horizon_hours': self.prediction_horizon.total_seconds() / 3600,
            'predicted_values': [(dt.isoformat(), val) for dt, val in self.predicted_values],
            'confidence_intervals': self.confidence_intervals,
            'prediction_accuracy': self.prediction_accuracy,
            'model_type': self.model_type
        }

@dataclass
class TrendInsight:
    """High-level insight derived from trend analysis."""
    insight_type: str
    severity: str  # low, medium, high, critical
    title: str
    description: str
    recommendations: List[str]
    affected_metrics: List[str]
    confidence: float
    timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'insight_type': self.insight_type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'recommendations': self.recommendations,
            'affected_metrics': self.affected_metrics,
            'confidence': self.confidence,
            'timestamp': self.timestamp.isoformat()
        }

class AnomalyDetector:
    """Statistical and ML-based anomaly detection."""
    
    def __init__(self):
        self.logger = ContextualLogger("anomaly_detector")
        self.isolation_forest = None
        self.scaler = None
        if ML_AVAILABLE:
            self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
            self.scaler = StandardScaler()
    
    def detect_statistical_anomalies(self, values: List[float], 
                                   z_threshold: float = 3.0) -> List[int]:
        """Detect anomalies using z-score method."""
        if len(values) < 3:
            return []
        
        try:
            mean_val = statistics.mean(values)
            std_val = statistics.stdev(values)
            
            if std_val == 0:
                return []
            
            anomalies = []
            for i, value in enumerate(values):
                z_score = abs((value - mean_val) / std_val)
                if z_score > z_threshold:
                    anomalies.append(i)
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Statistical anomaly detection failed: {e}")
            return []
    
    def detect_iqr_anomalies(self, values: List[float]) -> List[int]:
        """Detect anomalies using Interquartile Range method."""
        if len(values) < 4:
            return []
        
        try:
            sorted_values = sorted(values)
            n = len(sorted_values)
            
            q1_idx = n // 4
            q3_idx = 3 * n // 4
            
            q1 = sorted_values[q1_idx]
            q3 = sorted_values[q3_idx]
            iqr = q3 - q1
            
            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr
            
            anomalies = []
            for i, value in enumerate(values):
                if value < lower_bound or value > upper_bound:
                    anomalies.append(i)
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"IQR anomaly detection failed: {e}")
            return []
    
    def detect_ml_anomalies(self, values: List[float]) -> List[int]:
        """Detect anomalies using machine learning (Isolation Forest)."""
        if not ML_AVAILABLE or len(values) < 10:
            return []
        
        try:
            # Prepare data
            X = np.array(values).reshape(-1, 1)
            X_scaled = self.scaler.fit_transform(X)
            
            # Detect anomalies
            anomaly_labels = self.isolation_forest.fit_predict(X_scaled)
            
            # Return indices of anomalies (labeled as -1)
            anomalies = [i for i, label in enumerate(anomaly_labels) if label == -1]
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"ML anomaly detection failed: {e}")
            return []

class TrendCalculator:
    """Calculates various trend metrics and patterns."""
    
    def __init__(self):
        self.logger = ContextualLogger("trend_calculator")
    
    def calculate_linear_trend(self, timestamps: List[datetime], 
                             values: List[float]) -> Tuple[float, float, float]:
        """Calculate linear trend slope, intercept, and correlation coefficient."""
        if len(timestamps) != len(values) or len(values) < 2:
            return 0.0, 0.0, 0.0
        
        try:
            # Convert timestamps to numeric values (seconds since first timestamp)
            base_time = timestamps[0]
            x_values = [(ts - base_time).total_seconds() for ts in timestamps]
            
            # Calculate linear regression
            if ML_AVAILABLE:
                X = np.array(x_values).reshape(-1, 1)
                y = np.array(values)
                
                model = LinearRegression()
                model.fit(X, y)
                
                slope = model.coef_[0]
                intercept = model.intercept_
                
                # Calculate correlation coefficient
                correlation = np.corrcoef(x_values, values)[0, 1]
                
            else:
                # Manual calculation
                n = len(values)
                sum_x = sum(x_values)
                sum_y = sum(values)
                sum_xy = sum(x * y for x, y in zip(x_values, values))
                sum_x2 = sum(x * x for x in x_values)
                sum_y2 = sum(y * y for y in values)
                
                # Slope and intercept
                denominator = n * sum_x2 - sum_x * sum_x
                if denominator == 0:
                    return 0.0, 0.0, 0.0
                
                slope = (n * sum_xy - sum_x * sum_y) / denominator
                intercept = (sum_y - slope * sum_x) / n
                
                # Correlation coefficient
                numerator = n * sum_xy - sum_x * sum_y
                denom_corr = math.sqrt((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y))
                correlation = numerator / denom_corr if denom_corr != 0 else 0.0
            
            return slope, intercept, correlation
            
        except Exception as e:
            self.logger.error(f"Linear trend calculation failed: {e}")
            return 0.0, 0.0, 0.0
    
    def calculate_volatility(self, values: List[float]) -> float:
        """Calculate volatility score for the values."""
        if len(values) < 2:
            return 0.0
        
        try:
            # Calculate standard deviation normalized by mean
            mean_val = statistics.mean(values)
            if mean_val == 0:
                return 0.0
            
            std_val = statistics.stdev(values)
            volatility = std_val / abs(mean_val)
            
            return min(volatility, 10.0)  # Cap at 10.0 for extreme cases
            
        except Exception as e:
            self.logger.error(f"Volatility calculation failed: {e}")
            return 0.0
    
    def detect_change_points(self, values: List[float], 
                           timestamps: List[datetime],
                           threshold: float = 2.0) -> List[datetime]:
        """Detect significant change points in the time series."""
        if len(values) < 10:
            return []
        
        try:
            change_points = []
            window_size = max(5, len(values) // 20)  # Adaptive window size
            
            for i in range(window_size, len(values) - window_size):
                # Calculate means before and after potential change point
                before_mean = statistics.mean(values[i-window_size:i])
                after_mean = statistics.mean(values[i:i+window_size])
                
                # Calculate standard deviation of the entire series
                overall_std = statistics.stdev(values)
                
                # Check if change is significant
                if overall_std > 0:
                    change_magnitude = abs(after_mean - before_mean) / overall_std
                    if change_magnitude > threshold:
                        change_points.append(timestamps[i])
            
            return change_points
            
        except Exception as e:
            self.logger.error(f"Change point detection failed: {e}")
            return []
    
    def detect_seasonal_pattern(self, values: List[float], 
                              timestamps: List[datetime]) -> bool:
        """Detect if there's a seasonal pattern in the data."""
        if len(values) < 24:  # Need at least 24 data points
            return False
        
        try:
            # Extract hour of day for each timestamp
            hours = [ts.hour for ts in timestamps]
            
            # Group values by hour
            hourly_groups = defaultdict(list)
            for hour, value in zip(hours, values):
                hourly_groups[hour].append(value)
            
            # Calculate average for each hour
            hourly_averages = {}
            for hour in range(24):
                if hour in hourly_groups and len(hourly_groups[hour]) > 0:
                    hourly_averages[hour] = statistics.mean(hourly_groups[hour])
            
            if len(hourly_averages) < 12:  # Need data for at least half the day
                return False
            
            # Check if there's significant variation across hours
            avg_values = list(hourly_averages.values())
            if len(avg_values) < 2:
                return False
            
            overall_mean = statistics.mean(avg_values)
            max_deviation = max(abs(v - overall_mean) for v in avg_values)
            
            if overall_mean == 0:
                return False
            
            # Consider seasonal if max deviation is > 20% of mean
            return (max_deviation / abs(overall_mean)) > 0.2
            
        except Exception as e:
            self.logger.error(f"Seasonal pattern detection failed: {e}")
            return False

class TrendAnalyzer:
    """
    Advanced trend analysis system for monitoring data.
    
    Provides comprehensive trend analysis, anomaly detection,
    predictive forecasting, and intelligent insights.
    """
    
    def __init__(self, metrics_collector: Optional[MetricsCollector] = None):
        """
        Initialize trend analyzer.
        
        Args:
            metrics_collector: Optional metrics collector for data access
        """
        self.metrics_collector = metrics_collector
        self.logger = ContextualLogger("trend_analyzer")
        
        # Analysis components
        self.anomaly_detector = AnomalyDetector()
        self.trend_calculator = TrendCalculator()
        
        # Analysis cache
        self.trend_cache: Dict[str, TrendData] = {}
        self.prediction_cache: Dict[str, TrendPrediction] = {}
        self.insights_cache: deque = deque(maxlen=1000)
        
        # Analysis parameters
        self.default_analysis_period = timedelta(hours=24)
        self.prediction_horizon = timedelta(hours=6)
        self.cache_duration = timedelta(minutes=15)
        
    def analyze_metric_trend(self, metric_name: str,
                           analysis_period: Optional[timedelta] = None) -> Optional[TrendData]:
        """Analyze trend for a specific metric."""
        if not self.metrics_collector:
            self.logger.error("No metrics collector available for trend analysis")
            return None
        
        analysis_period = analysis_period or self.default_analysis_period
        
        try:
            # Check cache first
            cache_key = f"{metric_name}_{analysis_period.total_seconds()}"
            if cache_key in self.trend_cache:
                cached_trend = self.trend_cache[cache_key]
                # Check if cache is still valid
                if (datetime.now() - cached_trend.change_points[-1] if cached_trend.change_points 
                    else datetime.now()) < self.cache_duration:
                    return cached_trend
            
            # Query metrics data
            end_time = datetime.now()
            start_time = end_time - analysis_period
            
            metrics = self.metrics_collector.query_metrics(
                metric_name=metric_name,
                start_time=start_time,
                end_time=end_time,
                limit=10000
            )
            
            if len(metrics) < 5:
                self.logger.warning(f"Insufficient data for trend analysis: {metric_name}")
                return None
            
            # Sort by timestamp
            metrics.sort(key=lambda m: m.timestamp)
            
            # Extract values and timestamps
            timestamps = [m.timestamp for m in metrics]
            values = []
            
            for metric in metrics:
                if isinstance(metric.value, (int, float)):
                    values.append(float(metric.value))
                elif isinstance(metric.value, dict) and 'value' in metric.value:
                    values.append(float(metric.value['value']))
                else:
                    continue
            
            if len(values) < 5:
                self.logger.warning(f"Insufficient numeric values for trend analysis: {metric_name}")
                return None
            
            # Calculate trend metrics
            slope, intercept, correlation = self.trend_calculator.calculate_linear_trend(timestamps, values)
            volatility = self.trend_calculator.calculate_volatility(values)
            change_points = self.trend_calculator.detect_change_points(values, timestamps)
            seasonal_pattern = self.trend_calculator.detect_seasonal_pattern(values, timestamps)
            
            # Detect anomalies
            statistical_anomalies = self.anomaly_detector.detect_statistical_anomalies(values)
            iqr_anomalies = self.anomaly_detector.detect_iqr_anomalies(values)
            ml_anomalies = self.anomaly_detector.detect_ml_anomalies(values) if ML_AVAILABLE else []
            
            # Combine anomaly results
            all_anomalies = set(statistical_anomalies + iqr_anomalies + ml_anomalies)
            
            # Determine trend direction
            direction = self._classify_trend_direction(slope, correlation, volatility)
            
            # Calculate confidence
            confidence = self._calculate_trend_confidence(correlation, len(values), volatility)
            
            # Create trend data
            trend_data = TrendData(
                metric_name=metric_name,
                analysis_period=analysis_period,
                direction=direction,
                slope=slope,
                confidence=confidence,
                correlation_coefficient=correlation,
                seasonal_pattern=seasonal_pattern,
                change_points=change_points,
                anomalies_detected=len(all_anomalies),
                volatility_score=volatility
            )
            
            # Cache result
            self.trend_cache[cache_key] = trend_data
            
            return trend_data
            
        except Exception as e:
            self.logger.error(f"Trend analysis failed for {metric_name}: {e}")
            return None
    
    def predict_metric_values(self, metric_name: str,
                            prediction_horizon: Optional[timedelta] = None) -> Optional[TrendPrediction]:
        """Predict future values for a metric."""
        if not self.metrics_collector:
            return None
        
        prediction_horizon = prediction_horizon or self.prediction_horizon
        
        try:
            # Get recent trend data
            trend_data = self.analyze_metric_trend(metric_name)
            if not trend_data:
                return None
            
            # Query recent metrics for prediction
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=48)  # Use more data for prediction
            
            metrics = self.metrics_collector.query_metrics(
                metric_name=metric_name,
                start_time=start_time,
                end_time=end_time,
                limit=1000
            )
            
            if len(metrics) < 10:
                return None
            
            # Sort and extract values
            metrics.sort(key=lambda m: m.timestamp)
            timestamps = [m.timestamp for m in metrics]
            values = []
            
            for metric in metrics:
                if isinstance(metric.value, (int, float)):
                    values.append(float(metric.value))
                elif isinstance(metric.value, dict) and 'value' in metric.value:
                    values.append(float(metric.value['value']))
            
            if len(values) < 10:
                return None
            
            # Generate predictions using linear extrapolation
            predicted_values = []
            confidence_intervals = []
            
            # Calculate prediction parameters
            slope = trend_data.slope
            last_timestamp = timestamps[-1]
            last_value = values[-1]
            
            # Calculate prediction error estimate
            recent_values = values[-20:]  # Use last 20 values
            prediction_error = statistics.stdev(recent_values) if len(recent_values) > 1 else 0.1
            
            # Generate predictions
            prediction_steps = 10
            step_size = prediction_horizon / prediction_steps
            
            for i in range(1, prediction_steps + 1):
                future_time = last_timestamp + (step_size * i)
                time_delta_seconds = (future_time - last_timestamp).total_seconds()
                
                # Linear prediction
                predicted_value = last_value + (slope * time_delta_seconds)
                
                # Add some uncertainty over time
                uncertainty = prediction_error * math.sqrt(i)
                confidence_interval = (
                    predicted_value - uncertainty,
                    predicted_value + uncertainty
                )
                
                predicted_values.append((future_time, predicted_value))
                confidence_intervals.append(confidence_interval)
            
            # Calculate prediction accuracy based on recent trend stability
            accuracy = max(0.1, trend_data.confidence * (1 - trend_data.volatility_score / 10))
            
            prediction = TrendPrediction(
                metric_name=metric_name,
                prediction_horizon=prediction_horizon,
                predicted_values=predicted_values,
                confidence_intervals=confidence_intervals,
                prediction_accuracy=accuracy,
                model_type="linear_extrapolation"
            )
            
            return prediction
            
        except Exception as e:
            self.logger.error(f"Prediction failed for {metric_name}: {e}")
            return None
    
    def generate_insights(self, metric_names: Optional[List[str]] = None) -> List[TrendInsight]:
        """Generate high-level insights from trend analysis."""
        insights = []
        timestamp = datetime.now()
        
        try:
            # If no specific metrics provided, analyze common system metrics
            if not metric_names:
                metric_names = [
                    "system.cpu.usage_percent",
                    "system.memory.usage_percent",
                    "system.disk.usage_percent"
                ]
            
            for metric_name in metric_names:
                trend_data = self.analyze_metric_trend(metric_name)
                if not trend_data:
                    continue
                
                # Generate insights based on trend analysis
                metric_insights = self._generate_metric_insights(trend_data, timestamp)
                insights.extend(metric_insights)
            
            # Generate cross-metric insights
            if len(metric_names) > 1:
                cross_insights = self._generate_cross_metric_insights(metric_names, timestamp)
                insights.extend(cross_insights)
            
            # Cache insights
            for insight in insights:
                self.insights_cache.append(insight)
            
            return insights
            
        except Exception as e:
            self.logger.error(f"Insight generation failed: {e}")
            return []
    
    def get_trend_summary(self, duration_hours: int = 24) -> Dict[str, Any]:
        """Get a summary of all trend analysis results."""
        cutoff_time = datetime.now() - timedelta(hours=duration_hours)
        
        recent_insights = [
            insight for insight in self.insights_cache
            if insight.timestamp >= cutoff_time
        ]
        
        # Analyze insights by severity
        severity_counts = defaultdict(int)
        insight_types = defaultdict(int)
        
        for insight in recent_insights:
            severity_counts[insight.severity] += 1
            insight_types[insight.insight_type] += 1
        
        return {
            "analysis_period_hours": duration_hours,
            "total_insights": len(recent_insights),
            "severity_distribution": dict(severity_counts),
            "insight_types": dict(insight_types),
            "cached_trends": len(self.trend_cache),
            "cached_predictions": len(self.prediction_cache),
            "recent_insights": [insight.to_dict() for insight in recent_insights[-10:]]
        }
    
    def _classify_trend_direction(self, slope: float, correlation: float, 
                                volatility: float) -> TrendDirection:
        """Classify trend direction based on slope, correlation, and volatility."""
        # High volatility indicates volatile trend
        if volatility > 1.0:
            return TrendDirection.VOLATILE
        
        # Low correlation indicates unstable trend
        if abs(correlation) < 0.3:
            return TrendDirection.UNKNOWN
        
        # Classify based on slope and correlation
        if abs(slope) < 1e-6:  # Very small slope
            return TrendDirection.STABLE
        elif slope > 0 and correlation > 0.5:
            return TrendDirection.INCREASING
        elif slope < 0 and correlation < -0.5:
            return TrendDirection.DECREASING
        else:
            return TrendDirection.STABLE
    
    def _calculate_trend_confidence(self, correlation: float, 
                                  sample_count: int, volatility: float) -> float:
        """Calculate confidence in trend analysis."""
        # Base confidence on correlation strength
        correlation_confidence = abs(correlation)
        
        # Adjust for sample size
        sample_confidence = min(1.0, sample_count / 100)
        
        # Penalize for high volatility
        volatility_penalty = max(0.1, 1 - volatility / 5)
        
        # Combined confidence
        confidence = correlation_confidence * sample_confidence * volatility_penalty
        
        return max(0.1, min(1.0, confidence))
    
    def _generate_metric_insights(self, trend_data: TrendData, 
                                timestamp: datetime) -> List[TrendInsight]:
        """Generate insights for a single metric."""
        insights = []
        
        # High volatility insight
        if trend_data.volatility_score > 2.0:
            insights.append(TrendInsight(
                insight_type="volatility",
                severity="medium" if trend_data.volatility_score < 5.0 else "high",
                title=f"High volatility detected in {trend_data.metric_name}",
                description=f"Metric showing high volatility (score: {trend_data.volatility_score:.2f}). This may indicate system instability or irregular load patterns.",
                recommendations=[
                    "Investigate potential causes of volatility",
                    "Consider implementing smoothing or averaging",
                    "Monitor for correlated metrics showing similar patterns"
                ],
                affected_metrics=[trend_data.metric_name],
                confidence=trend_data.confidence,
                timestamp=timestamp
            ))
        
        # Trending insights
        if trend_data.direction in [TrendDirection.INCREASING, TrendDirection.DECREASING]:
            severity = "low"
            if abs(trend_data.slope) > 1.0:
                severity = "medium"
            if abs(trend_data.slope) > 5.0:
                severity = "high"
            
            direction_word = "increasing" if trend_data.direction == TrendDirection.INCREASING else "decreasing"
            
            insights.append(TrendInsight(
                insight_type="trend",
                severity=severity,
                title=f"{trend_data.metric_name} is {direction_word}",
                description=f"Metric shows {direction_word} trend with slope {trend_data.slope:.4f} and confidence {trend_data.confidence:.2f}",
                recommendations=[
                    f"Monitor {direction_word} trend for potential threshold breaches",
                    "Consider capacity planning if trend continues",
                    "Investigate root causes of trend change"
                ],
                affected_metrics=[trend_data.metric_name],
                confidence=trend_data.confidence,
                timestamp=timestamp
            ))
        
        # Change point insights
        if trend_data.change_points:
            recent_changes = [cp for cp in trend_data.change_points 
                            if (timestamp - cp).total_seconds() < 3600]  # Last hour
            
            if recent_changes:
                insights.append(TrendInsight(
                    insight_type="change_point",
                    severity="medium",
                    title=f"Recent behavior change in {trend_data.metric_name}",
                    description=f"Detected {len(recent_changes)} significant change points in the last hour. This may indicate system state changes.",
                    recommendations=[
                        "Investigate events that occurred around change point times",
                        "Check for system configuration changes",
                        "Monitor for continued behavioral changes"
                    ],
                    affected_metrics=[trend_data.metric_name],
                    confidence=trend_data.confidence,
                    timestamp=timestamp
                ))
        
        # Anomaly insights
        if trend_data.anomalies_detected > 0:
            anomaly_rate = trend_data.anomalies_detected / 100  # Assuming ~100 data points
            severity = "low"
            if anomaly_rate > 0.1:
                severity = "medium"
            if anomaly_rate > 0.2:
                severity = "high"
            
            insights.append(TrendInsight(
                insight_type="anomaly",
                severity=severity,
                title=f"Anomalies detected in {trend_data.metric_name}",
                description=f"Detected {trend_data.anomalies_detected} anomalous values. Anomaly rate: {anomaly_rate:.1%}",
                recommendations=[
                    "Investigate anomalous time periods for root causes",
                    "Check for data quality issues",
                    "Consider adjusting monitoring thresholds"
                ],
                affected_metrics=[trend_data.metric_name],
                confidence=trend_data.confidence,
                timestamp=timestamp
            ))
        
        return insights
    
    def _generate_cross_metric_insights(self, metric_names: List[str], 
                                      timestamp: datetime) -> List[TrendInsight]:
        """Generate insights by analyzing multiple metrics together."""
        insights = []
        
        try:
            # Analyze correlations between metrics
            trends = {}
            for metric_name in metric_names:
                trend_data = self.analyze_metric_trend(metric_name)
                if trend_data:
                    trends[metric_name] = trend_data
            
            if len(trends) < 2:
                return insights
            
            # Check for correlated trends
            increasing_metrics = [name for name, trend in trends.items() 
                                if trend.direction == TrendDirection.INCREASING]
            decreasing_metrics = [name for name, trend in trends.items() 
                                if trend.direction == TrendDirection.DECREASING]
            
            # System-wide trend insight
            if len(increasing_metrics) >= 2:
                insights.append(TrendInsight(
                    insight_type="system_trend",
                    severity="medium",
                    title="Multiple metrics showing increasing trends",
                    description=f"Multiple system metrics are trending upward: {', '.join(increasing_metrics)}",
                    recommendations=[
                        "Investigate system-wide load increases",
                        "Consider capacity planning and scaling",
                        "Monitor for resource constraints"
                    ],
                    affected_metrics=increasing_metrics,
                    confidence=statistics.mean([trends[m].confidence for m in increasing_metrics]),
                    timestamp=timestamp
                ))
            
            if len(decreasing_metrics) >= 2:
                insights.append(TrendInsight(
                    insight_type="system_trend",
                    severity="low",
                    title="Multiple metrics showing decreasing trends",
                    description=f"Multiple system metrics are trending downward: {', '.join(decreasing_metrics)}",
                    recommendations=[
                        "Verify if decreased usage is expected",
                        "Check for potential system issues causing reduced activity",
                        "Monitor for service availability"
                    ],
                    affected_metrics=decreasing_metrics,
                    confidence=statistics.mean([trends[m].confidence for m in decreasing_metrics]),
                    timestamp=timestamp
                ))
            
        except Exception as e:
            self.logger.error(f"Cross-metric insight generation failed: {e}")
        
        return insights

# Global trend analyzer instance
_trend_analyzer: Optional[TrendAnalyzer] = None

def get_trend_analyzer() -> TrendAnalyzer:
    """Get the global trend analyzer instance."""
    global _trend_analyzer
    if _trend_analyzer is None:
        from .metrics_collector import get_metrics_collector
        _trend_analyzer = TrendAnalyzer(get_metrics_collector())
    return _trend_analyzer 