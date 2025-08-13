"""
Confidence Scoring and Model Validation System for AODS AI/ML
Advanced confidence assessment and model performance validation
"""

import json
import numpy as np
import pandas as pd
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum
import sqlite3
from collections import defaultdict, deque
import statistics

# ML imports with fallback
try:
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, classification_report, roc_auc_score,
        precision_recall_curve, roc_curve
    )
    from sklearn.model_selection import cross_val_score, StratifiedKFold
    from sklearn.calibration import calibration_curve
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

logger = logging.getLogger(__name__)

class ValidationMetric(Enum):
    """Model validation metrics."""
    ACCURACY = "accuracy"
    PRECISION = "precision"
    RECALL = "recall"
    F1_SCORE = "f1_score"
    ROC_AUC = "roc_auc"
    CALIBRATION = "calibration"
    STABILITY = "stability"

class ConfidenceLevel(Enum):
    """Confidence assessment levels."""
    VERY_HIGH = "very_high"  # 90%+
    HIGH = "high"           # 80-90%
    MEDIUM = "medium"       # 60-80%
    LOW = "low"            # 40-60%
    VERY_LOW = "very_low"  # <40%

@dataclass
class ConfidenceScore:
    """Comprehensive confidence score."""
    overall_confidence: float
    confidence_level: str
    component_scores: Dict[str, float]
    reliability_factors: Dict[str, Any]
    timestamp: str
    metadata: Dict[str, Any]

@dataclass
class ModelValidationResult:
    """Model validation result."""
    model_name: str
    validation_type: str
    metrics: Dict[str, float]
    performance_grade: str
    reliability_score: float
    recommendations: List[str]
    validation_date: str
    test_samples: int

@dataclass
class PredictionQuality:
    """Quality assessment of individual prediction."""
    prediction_id: str
    apk_name: str
    confidence_score: float
    quality_indicators: Dict[str, float]
    uncertainty_factors: List[str]
    reliability_assessment: str
    assessed_at: str

class ConfidenceCalculator:
    """Calculate confidence scores for threat predictions."""
    
    def __init__(self):
        self.weight_config = {
            'model_confidence': 0.35,      # ML model prediction confidence
            'feature_quality': 0.25,       # Quality of input features
            'model_reliability': 0.20,     # Historical model performance
            'prediction_consistency': 0.15, # Consistency across models
            'evidence_strength': 0.05      # Supporting evidence quality
        }
        
        self.feature_quality_factors = {
            'completeness': 0.3,    # Percentage of features available
            'data_quality': 0.25,   # Quality of feature values
            'feature_relevance': 0.25, # Relevance of available features
            'noise_level': 0.2      # Amount of noise in features
        }
    
    def calculate_confidence(self, prediction_data: Dict[str, Any]) -> ConfidenceScore:
        """Calculate comprehensive confidence score for prediction."""
        try:
            # Extract components
            model_confidence = self._calculate_model_confidence(prediction_data)
            feature_quality = self._calculate_feature_quality(prediction_data)
            model_reliability = self._calculate_model_reliability(prediction_data)
            prediction_consistency = self._calculate_prediction_consistency(prediction_data)
            evidence_strength = self._calculate_evidence_strength(prediction_data)
            
            # Component scores
            component_scores = {
                'model_confidence': model_confidence,
                'feature_quality': feature_quality,
                'model_reliability': model_reliability,
                'prediction_consistency': prediction_consistency,
                'evidence_strength': evidence_strength
            }
            
            # Weighted overall confidence
            overall_confidence = sum(
                score * self.weight_config[component]
                for component, score in component_scores.items()
            )
            
            # Determine confidence level
            confidence_level = self._determine_confidence_level(overall_confidence)
            
            # Calculate reliability factors
            reliability_factors = self._calculate_reliability_factors(
                prediction_data, component_scores
            )
            
            return ConfidenceScore(
                overall_confidence=round(overall_confidence, 3),
                confidence_level=confidence_level.value,
                component_scores=component_scores,
                reliability_factors=reliability_factors,
                timestamp=datetime.now().isoformat(),
                metadata={
                    'weight_config': self.weight_config,
                    'calculation_version': '1.0'
                }
            )
            
        except Exception as e:
            logger.error(f"Confidence calculation failed: {e}")
            return self._fallback_confidence_score(prediction_data)
    
    def _calculate_model_confidence(self, prediction_data: Dict[str, Any]) -> float:
        """Calculate model-based confidence."""
        # Get model prediction probability
        prediction_details = prediction_data.get('prediction_details', {})
        class_probabilities = prediction_details.get('class_probabilities', {})
        
        if class_probabilities:
            # Use maximum probability as base confidence
            max_probability = max(class_probabilities.values())
            
            # Adjust for probability distribution
            entropy = self._calculate_entropy(list(class_probabilities.values()))
            entropy_penalty = entropy / np.log(len(class_probabilities)) if len(class_probabilities) > 1 else 0
            
            # Confidence is high probability with low entropy
            confidence = max_probability * (1 - entropy_penalty * 0.3)
        else:
            # Fallback to provided confidence score
            confidence = prediction_data.get('confidence_score', 0.5)
        
        return min(max(confidence, 0), 1)
    
    def _calculate_feature_quality(self, prediction_data: Dict[str, Any]) -> float:
        """Calculate feature quality score."""
        feature_data = prediction_data.get('feature_vector', {})
        features = feature_data.get('features', {})
        
        if not features:
            return 0.1  # Very low confidence without features
        
        # Feature completeness
        expected_features = 50  # Expected number of features
        actual_features = len(features)
        completeness = min(actual_features / expected_features, 1.0)
        
        # Data quality (non-zero, non-null values)
        valid_features = sum(1 for v in features.values() 
                           if v is not None and v != 0)
        data_quality = valid_features / len(features) if features else 0
        
        # Feature relevance (based on important features)
        important_features = [
            'permission_count', 'exported_services', 'api_call_count',
            'suspicious_keywords', 'cert_is_debug', 'network_connections'
        ]
        relevant_features = sum(1 for f in important_features if f in features)
        feature_relevance = relevant_features / len(important_features)
        
        # Noise level (percentage of extreme values)
        extreme_values = sum(1 for v in features.values() 
                           if isinstance(v, (int, float)) and abs(v) > 100)
        noise_level = 1 - (extreme_values / len(features)) if features else 1
        
        # Weighted quality score
        quality_components = {
            'completeness': completeness,
            'data_quality': data_quality,
            'feature_relevance': feature_relevance,
            'noise_level': noise_level
        }
        
        quality_score = sum(
            score * self.feature_quality_factors[component]
            for component, score in quality_components.items()
        )
        
        return min(max(quality_score, 0), 1)
    
    def _calculate_model_reliability(self, prediction_data: Dict[str, Any]) -> float:
        """Calculate model reliability based on historical performance."""
        model_version = prediction_data.get('model_version', 'unknown')
        
        # Default reliability scores for different model types
        reliability_scores = {
            'ensemble': 0.85,
            'random_forest': 0.8,
            'gradient_boosting': 0.75,
            'neural_network': 0.7,
            'svm': 0.65,
            'rule_based': 0.5
        }
        
        # Extract model type from version
        model_type = 'rule_based'
        for model_name in reliability_scores.keys():
            if model_name in model_version.lower():
                model_type = model_name
                break
        
        base_reliability = reliability_scores.get(model_type, 0.5)
        
        # Adjust for model age (newer models might be less reliable)
        predicted_at = prediction_data.get('predicted_at', datetime.now().isoformat())
        try:
            prediction_time = datetime.fromisoformat(predicted_at)
            age_days = (datetime.now() - prediction_time).days
            
            # Slight penalty for very new models
            if age_days < 7:
                age_factor = 0.95
            else:
                age_factor = 1.0
        except:
            age_factor = 1.0
        
        return base_reliability * age_factor
    
    def _calculate_prediction_consistency(self, prediction_data: Dict[str, Any]) -> float:
        """Calculate prediction consistency across models."""
        prediction_details = prediction_data.get('prediction_details', {})
        
        # If ensemble model was used, check consistency
        if 'ensemble' in prediction_data.get('model_version', '').lower():
            # High consistency for ensemble models
            return 0.85
        
        # For single models, use confidence as proxy for consistency
        confidence_score = prediction_data.get('confidence_score', 0.5)
        
        # Convert confidence to consistency score
        if confidence_score > 0.8:
            consistency = 0.9
        elif confidence_score > 0.6:
            consistency = 0.7
        elif confidence_score > 0.4:
            consistency = 0.5
        else:
            consistency = 0.3
        
        return consistency
    
    def _calculate_evidence_strength(self, prediction_data: Dict[str, Any]) -> float:
        """Calculate strength of supporting evidence."""
        evidence = prediction_data.get('evidence', [])
        
        if not evidence:
            return 0.2  # Low evidence strength
        
        # Evaluate evidence quality
        strong_evidence = 0
        total_evidence = len(evidence)
        
        for item in evidence:
            importance = item.get('importance', 0)
            value = item.get('value', 0)
            
            # Strong evidence has high importance and significant values
            if importance > 0.1 and value > 0:
                strong_evidence += 1
        
        evidence_ratio = strong_evidence / total_evidence if total_evidence > 0 else 0
        
        # Bonus for having multiple pieces of evidence
        evidence_count_bonus = min(total_evidence / 10, 0.2)
        
        evidence_strength = evidence_ratio + evidence_count_bonus
        
        return min(evidence_strength, 1.0)
    
    def _calculate_entropy(self, probabilities: List[float]) -> float:
        """Calculate entropy of probability distribution."""
        if not probabilities:
            return 0
        
        # Normalize probabilities
        total = sum(probabilities)
        if total == 0:
            return 0
        
        normalized = [p / total for p in probabilities]
        
        # Calculate entropy
        entropy = -sum(p * np.log(p) for p in normalized if p > 0)
        
        return entropy
    
    def _determine_confidence_level(self, confidence: float) -> ConfidenceLevel:
        """Determine confidence level from score."""
        if confidence >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif confidence >= 0.8:
            return ConfidenceLevel.HIGH
        elif confidence >= 0.6:
            return ConfidenceLevel.MEDIUM
        elif confidence >= 0.4:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW
    
    def _calculate_reliability_factors(self, prediction_data: Dict[str, Any], 
                                     component_scores: Dict[str, float]) -> Dict[str, Any]:
        """Calculate factors affecting reliability."""
        factors = {}
        
        # Model type factor
        model_version = prediction_data.get('model_version', 'unknown')
        factors['model_type'] = 'ensemble' if 'ensemble' in model_version.lower() else 'single'
        
        # Feature availability
        feature_count = prediction_data.get('feature_vector', {}).get('feature_count', 0)
        factors['feature_availability'] = 'high' if feature_count > 30 else 'medium' if feature_count > 15 else 'low'
        
        # Prediction age
        predicted_at = prediction_data.get('predicted_at', datetime.now().isoformat())
        try:
            prediction_time = datetime.fromisoformat(predicted_at)
            age_hours = (datetime.now() - prediction_time).total_seconds() / 3600
            factors['prediction_age_hours'] = round(age_hours, 2)
        except:
            factors['prediction_age_hours'] = 0
        
        # Component score analysis
        weak_components = [comp for comp, score in component_scores.items() if score < 0.5]
        factors['weak_components'] = weak_components
        
        # Overall reliability category
        overall_confidence = sum(component_scores.values()) / len(component_scores)
        if overall_confidence >= 0.8:
            factors['reliability_category'] = 'high'
        elif overall_confidence >= 0.6:
            factors['reliability_category'] = 'medium'
        else:
            factors['reliability_category'] = 'low'
        
        return factors
    
    def _fallback_confidence_score(self, prediction_data: Dict[str, Any]) -> ConfidenceScore:
        """Fallback confidence score when calculation fails."""
        base_confidence = prediction_data.get('confidence_score', 0.5)
        
        return ConfidenceScore(
            overall_confidence=base_confidence,
            confidence_level=self._determine_confidence_level(base_confidence).value,
            component_scores={
                'model_confidence': base_confidence,
                'feature_quality': 0.5,
                'model_reliability': 0.5,
                'prediction_consistency': 0.5,
                'evidence_strength': 0.3
            },
            reliability_factors={'error': 'calculation_failed'},
            timestamp=datetime.now().isoformat(),
            metadata={'fallback': True}
        )

class ModelValidator:
    """Validate ML model performance and reliability."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.validation_history = deque(maxlen=100)  # Keep last 100 validations
        
        # Performance thresholds
        self.performance_thresholds = {
            'accuracy': {'excellent': 0.9, 'good': 0.8, 'acceptable': 0.7},
            'precision': {'excellent': 0.9, 'good': 0.8, 'acceptable': 0.7},
            'recall': {'excellent': 0.85, 'good': 0.75, 'acceptable': 0.65},
            'f1_score': {'excellent': 0.9, 'good': 0.8, 'acceptable': 0.7}
        }
    
    def validate_model_performance(self, model, X_test, y_test, 
                                 model_name: str) -> ModelValidationResult:
        """Validate model performance with test data."""
        if not ML_AVAILABLE:
            return self._create_basic_validation_result(model_name)
        
        try:
            # Make predictions
            y_pred = model.predict(X_test)
            y_pred_proba = None
            
            if hasattr(model, 'predict_proba'):
                y_pred_proba = model.predict_proba(X_test)
            
            # Calculate metrics
            metrics = {}
            metrics['accuracy'] = accuracy_score(y_test, y_pred)
            metrics['precision'] = precision_score(y_test, y_pred, average='weighted', zero_division=0)
            metrics['recall'] = recall_score(y_test, y_pred, average='weighted', zero_division=0)
            metrics['f1_score'] = f1_score(y_test, y_pred, average='weighted', zero_division=0)
            
            # ROC AUC for binary/multiclass
            if y_pred_proba is not None:
                try:
                    if len(np.unique(y_test)) == 2:
                        metrics['roc_auc'] = roc_auc_score(y_test, y_pred_proba[:, 1])
                    else:
                        metrics['roc_auc'] = roc_auc_score(y_test, y_pred_proba, multi_class='ovr')
                except:
                    metrics['roc_auc'] = 0.5
            
            # Cross-validation stability
            if len(X_test) > 10:  # Only if enough samples
                try:
                    cv_scores = cross_val_score(model, X_test, y_test, cv=min(5, len(X_test)//2))
                    metrics['cv_mean'] = np.mean(cv_scores)
                    metrics['cv_std'] = np.std(cv_scores)
                    metrics['stability'] = 1 - metrics['cv_std']  # Lower std = higher stability
                except:
                    metrics['stability'] = 0.5
            
            # Calibration assessment
            if y_pred_proba is not None and len(np.unique(y_test)) == 2:
                try:
                    fraction_of_positives, mean_predicted_value = calibration_curve(
                        y_test, y_pred_proba[:, 1], n_bins=min(10, len(y_test)//5)
                    )
                    calibration_error = np.mean(np.abs(fraction_of_positives - mean_predicted_value))
                    metrics['calibration'] = 1 - calibration_error
                except:
                    metrics['calibration'] = 0.5
            
            # Determine performance grade
            performance_grade = self._calculate_performance_grade(metrics)
            
            # Calculate reliability score
            reliability_score = self._calculate_reliability_score(metrics)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(metrics, model_name)
            
            result = ModelValidationResult(
                model_name=model_name,
                validation_type='comprehensive',
                metrics=metrics,
                performance_grade=performance_grade,
                reliability_score=reliability_score,
                recommendations=recommendations,
                validation_date=datetime.now().isoformat(),
                test_samples=len(X_test)
            )
            
            # Store validation result
            self.validation_history.append(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Model validation failed for {model_name}: {e}")
            return self._create_error_validation_result(model_name, str(e))
    
    def validate_prediction_quality(self, predictions: List[Dict[str, Any]], 
                                  ground_truth: List[str] = None) -> Dict[str, Any]:
        """Validate quality of recent predictions."""
        try:
            quality_metrics = {
                'total_predictions': len(predictions),
                'confidence_distribution': self._analyze_confidence_distribution(predictions),
                'prediction_distribution': self._analyze_prediction_distribution(predictions),
                'temporal_analysis': self._analyze_temporal_patterns(predictions)
            }
            
            # If ground truth is available, calculate accuracy
            if ground_truth and len(ground_truth) == len(predictions):
                predicted_labels = [p.get('threat_category', 'unknown') for p in predictions]
                quality_metrics['accuracy'] = accuracy_score(ground_truth, predicted_labels)
                quality_metrics['ground_truth_available'] = True
            else:
                quality_metrics['ground_truth_available'] = False
            
            # Analyze consistency
            quality_metrics['consistency_analysis'] = self._analyze_prediction_consistency(predictions)
            
            # Quality assessment
            quality_metrics['overall_quality'] = self._assess_overall_quality(quality_metrics)
            
            return quality_metrics
            
        except Exception as e:
            logger.error(f"Prediction quality validation failed: {e}")
            return {'error': str(e)}
    
    def monitor_model_drift(self, recent_predictions: List[Dict[str, Any]], 
                          baseline_period_days: int = 30) -> Dict[str, Any]:
        """Monitor for model performance drift."""
        try:
            # Analyze recent prediction patterns
            recent_patterns = self._extract_prediction_patterns(recent_predictions)
            
            # Get baseline patterns (would typically come from database)
            baseline_patterns = self._get_baseline_patterns(baseline_period_days)
            
            # Calculate drift metrics
            drift_metrics = {}
            
            # Confidence drift
            recent_confidence = [p.get('confidence_score', 0) for p in recent_predictions]
            baseline_confidence = baseline_patterns.get('confidence_scores', [0.5])
            
            if recent_confidence and baseline_confidence:
                drift_metrics['confidence_drift'] = abs(
                    np.mean(recent_confidence) - np.mean(baseline_confidence)
                )
            
            # Prediction distribution drift
            recent_categories = [p.get('threat_category', 'unknown') for p in recent_predictions]
            baseline_categories = baseline_patterns.get('threat_categories', ['unknown'])
            
            drift_metrics['distribution_drift'] = self._calculate_distribution_drift(
                recent_categories, baseline_categories
            )
            
            # Performance stability
            drift_metrics['stability_score'] = self._calculate_stability_score(recent_predictions)
            
            # Drift assessment
            drift_level = self._assess_drift_level(drift_metrics)
            
            return {
                'drift_metrics': drift_metrics,
                'drift_level': drift_level,
                'monitoring_period': f"last_{len(recent_predictions)}_predictions",
                'baseline_period_days': baseline_period_days,
                'recommendations': self._generate_drift_recommendations(drift_metrics),
                'monitored_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Model drift monitoring failed: {e}")
            return {'error': str(e)}
    
    def _calculate_performance_grade(self, metrics: Dict[str, float]) -> str:
        """Calculate overall performance grade."""
        grades = []
        
        for metric_name, value in metrics.items():
            if metric_name in self.performance_thresholds:
                thresholds = self.performance_thresholds[metric_name]
                if value >= thresholds['excellent']:
                    grades.append('A')
                elif value >= thresholds['good']:
                    grades.append('B')
                elif value >= thresholds['acceptable']:
                    grades.append('C')
                else:
                    grades.append('D')
        
        if not grades:
            return 'C'
        
        # Calculate average grade
        grade_values = {'A': 4, 'B': 3, 'C': 2, 'D': 1}
        avg_grade = sum(grade_values[g] for g in grades) / len(grades)
        
        if avg_grade >= 3.5:
            return 'A'
        elif avg_grade >= 2.5:
            return 'B'
        elif avg_grade >= 1.5:
            return 'C'
        else:
            return 'D'
    
    def _calculate_reliability_score(self, metrics: Dict[str, float]) -> float:
        """Calculate overall reliability score."""
        # Weight different metrics for reliability
        weights = {
            'accuracy': 0.25,
            'precision': 0.25,
            'recall': 0.20,
            'f1_score': 0.15,
            'stability': 0.10,
            'calibration': 0.05
        }
        
        reliability = 0
        total_weight = 0
        
        for metric, weight in weights.items():
            if metric in metrics:
                reliability += metrics[metric] * weight
                total_weight += weight
        
        if total_weight > 0:
            reliability /= total_weight
        
        return min(max(reliability, 0), 1)
    
    def _generate_recommendations(self, metrics: Dict[str, float], 
                                model_name: str) -> List[str]:
        """Generate recommendations based on metrics."""
        recommendations = []
        
        # Accuracy recommendations
        if metrics.get('accuracy', 0) < 0.8:
            recommendations.append("Consider retraining with more diverse data")
            recommendations.append("Review feature engineering and selection")
        
        # Precision recommendations
        if metrics.get('precision', 0) < 0.8:
            recommendations.append("Reduce false positives by adjusting decision threshold")
            recommendations.append("Add more discriminative features")
        
        # Recall recommendations
        if metrics.get('recall', 0) < 0.75:
            recommendations.append("Improve detection of positive cases")
            recommendations.append("Consider ensemble methods or boosting")
        
        # Stability recommendations
        if metrics.get('stability', 1) < 0.8:
            recommendations.append("Model performance is unstable - consider regularization")
            recommendations.append("Increase training data size for better generalization")
        
        # Calibration recommendations
        if metrics.get('calibration', 1) < 0.7:
            recommendations.append("Model confidence scores are poorly calibrated")
            recommendations.append("Apply probability calibration techniques")
        
        # Model-specific recommendations
        if 'neural_network' in model_name.lower():
            recommendations.append("Consider adjusting learning rate and network architecture")
        elif 'random_forest' in model_name.lower():
            recommendations.append("Tune number of trees and max depth parameters")
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    def _analyze_confidence_distribution(self, predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze distribution of confidence scores."""
        confidence_scores = [p.get('confidence_score', 0) for p in predictions]
        
        if not confidence_scores:
            return {'error': 'no_confidence_scores'}
        
        return {
            'mean': np.mean(confidence_scores),
            'median': np.median(confidence_scores),
            'std': np.std(confidence_scores),
            'min': np.min(confidence_scores),
            'max': np.max(confidence_scores),
            'high_confidence_ratio': sum(1 for c in confidence_scores if c >= 0.8) / len(confidence_scores),
            'low_confidence_ratio': sum(1 for c in confidence_scores if c < 0.6) / len(confidence_scores)
        }
    
    def _analyze_prediction_distribution(self, predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze distribution of predicted categories."""
        categories = [p.get('threat_category', 'unknown') for p in predictions]
        category_counts = defaultdict(int)
        
        for category in categories:
            category_counts[category] += 1
        
        total = len(categories)
        distribution = {cat: count/total for cat, count in category_counts.items()}
        
        return {
            'category_counts': dict(category_counts),
            'category_distribution': distribution,
            'most_common': max(category_counts.items(), key=lambda x: x[1])[0] if category_counts else 'none',
            'diversity_score': len(category_counts) / max(total, 1)
        }
    
    def _analyze_temporal_patterns(self, predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze temporal patterns in predictions."""
        timestamps = []
        
        for p in predictions:
            predicted_at = p.get('predicted_at', '')
            try:
                timestamps.append(datetime.fromisoformat(predicted_at))
            except:
                continue
        
        if not timestamps:
            return {'error': 'no_valid_timestamps'}
        
        # Sort timestamps
        timestamps.sort()
        
        # Calculate time intervals
        if len(timestamps) > 1:
            intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                        for i in range(len(timestamps)-1)]
            avg_interval = np.mean(intervals)
            interval_std = np.std(intervals)
        else:
            avg_interval = 0
            interval_std = 0
        
        # Time span
        time_span = (timestamps[-1] - timestamps[0]).total_seconds() if len(timestamps) > 1 else 0
        
        return {
            'prediction_count': len(timestamps),
            'time_span_hours': time_span / 3600,
            'avg_interval_minutes': avg_interval / 60,
            'interval_std_minutes': interval_std / 60,
            'prediction_rate_per_hour': len(timestamps) / max(time_span / 3600, 1)
        }
    
    def _analyze_prediction_consistency(self, predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze consistency of predictions."""
        # Group by similar APKs (simplified - in practice would use similarity measures)
        model_versions = [p.get('model_version', 'unknown') for p in predictions]
        confidence_levels = [p.get('confidence_level', 'unknown') for p in predictions]
        
        # Model version consistency
        version_counts = defaultdict(int)
        for version in model_versions:
            version_counts[version] += 1
        
        # Confidence level consistency
        confidence_counts = defaultdict(int)
        for level in confidence_levels:
            confidence_counts[level] += 1
        
        return {
            'model_version_diversity': len(version_counts),
            'most_used_model': max(version_counts.items(), key=lambda x: x[1])[0] if version_counts else 'none',
            'confidence_level_distribution': dict(confidence_counts),
            'consistency_score': max(confidence_counts.values()) / len(predictions) if predictions else 0
        }
    
    def _assess_overall_quality(self, quality_metrics: Dict[str, Any]) -> str:
        """Assess overall quality of predictions."""
        score = 0
        max_score = 0
        
        # Confidence quality
        conf_dist = quality_metrics.get('confidence_distribution', {})
        if 'high_confidence_ratio' in conf_dist:
            score += conf_dist['high_confidence_ratio'] * 30
            max_score += 30
        
        # Prediction diversity
        pred_dist = quality_metrics.get('prediction_distribution', {})
        if 'diversity_score' in pred_dist:
            score += pred_dist['diversity_score'] * 20
            max_score += 20
        
        # Consistency
        consistency = quality_metrics.get('consistency_analysis', {})
        if 'consistency_score' in consistency:
            score += consistency['consistency_score'] * 25
            max_score += 25
        
        # Accuracy (if available)
        if quality_metrics.get('ground_truth_available', False):
            accuracy = quality_metrics.get('accuracy', 0)
            score += accuracy * 25
            max_score += 25
        
        # Calculate final quality
        if max_score > 0:
            quality_score = score / max_score
        else:
            quality_score = 0.5
        
        if quality_score >= 0.8:
            return 'excellent'
        elif quality_score >= 0.6:
            return 'good'
        elif quality_score >= 0.4:
            return 'fair'
        else:
            return 'poor'
    
    def _extract_prediction_patterns(self, predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract patterns from predictions."""
        return {
            'confidence_scores': [p.get('confidence_score', 0) for p in predictions],
            'threat_categories': [p.get('threat_category', 'unknown') for p in predictions],
            'model_versions': [p.get('model_version', 'unknown') for p in predictions],
            'prediction_count': len(predictions)
        }
    
    def _get_baseline_patterns(self, days: int) -> Dict[str, Any]:
        """Get baseline patterns for drift comparison."""
        # In a real implementation, this would query the database
        # For now, return simulated baseline
        return {
            'confidence_scores': [0.7, 0.8, 0.6, 0.9, 0.5],
            'threat_categories': ['malware', 'benign', 'suspicious', 'malware', 'benign'],
            'prediction_count': 100
        }
    
    def _calculate_distribution_drift(self, recent: List[str], baseline: List[str]) -> float:
        """Calculate drift in category distributions."""
        # Calculate distributions
        recent_dist = defaultdict(int)
        baseline_dist = defaultdict(int)
        
        for cat in recent:
            recent_dist[cat] += 1
        for cat in baseline:
            baseline_dist[cat] += 1
        
        # Normalize
        recent_total = len(recent)
        baseline_total = len(baseline)
        
        if recent_total == 0 or baseline_total == 0:
            return 0
        
        # Calculate Kullback-Leibler divergence (simplified)
        all_categories = set(recent_dist.keys()) | set(baseline_dist.keys())
        
        drift = 0
        for cat in all_categories:
            p_recent = recent_dist[cat] / recent_total
            p_baseline = baseline_dist[cat] / baseline_total
            
            if p_recent > 0 and p_baseline > 0:
                drift += p_recent * np.log(p_recent / p_baseline)
        
        return min(drift, 1.0)  # Cap at 1.0
    
    def _calculate_stability_score(self, predictions: List[Dict[str, Any]]) -> float:
        """Calculate prediction stability score."""
        confidence_scores = [p.get('confidence_score', 0) for p in predictions]
        
        if len(confidence_scores) < 2:
            return 1.0
        
        # Stability is inverse of coefficient of variation
        mean_conf = np.mean(confidence_scores)
        std_conf = np.std(confidence_scores)
        
        if mean_conf == 0:
            return 0.5
        
        cv = std_conf / mean_conf
        stability = 1 / (1 + cv)  # Higher CV = lower stability
        
        return stability
    
    def _assess_drift_level(self, drift_metrics: Dict[str, float]) -> str:
        """Assess overall drift level."""
        confidence_drift = drift_metrics.get('confidence_drift', 0)
        distribution_drift = drift_metrics.get('distribution_drift', 0)
        stability_score = drift_metrics.get('stability_score', 1)
        
        # Combine drift indicators
        overall_drift = (confidence_drift + distribution_drift + (1 - stability_score)) / 3
        
        if overall_drift > 0.3:
            return 'high'
        elif overall_drift > 0.15:
            return 'medium'
        elif overall_drift > 0.05:
            return 'low'
        else:
            return 'minimal'
    
    def _generate_drift_recommendations(self, drift_metrics: Dict[str, float]) -> List[str]:
        """Generate recommendations based on drift analysis."""
        recommendations = []
        
        confidence_drift = drift_metrics.get('confidence_drift', 0)
        distribution_drift = drift_metrics.get('distribution_drift', 0)
        stability_score = drift_metrics.get('stability_score', 1)
        
        if confidence_drift > 0.2:
            recommendations.append("Significant confidence drift detected - consider model recalibration")
        
        if distribution_drift > 0.3:
            recommendations.append("Category distribution has shifted - retrain with recent data")
        
        if stability_score < 0.7:
            recommendations.append("Prediction stability is low - review model parameters")
        
        if not recommendations:
            recommendations.append("Model performance appears stable")
        
        return recommendations
    
    def _create_basic_validation_result(self, model_name: str) -> ModelValidationResult:
        """Create basic validation result when ML is not available."""
        return ModelValidationResult(
            model_name=model_name,
            validation_type='basic',
            metrics={'accuracy': 0.7, 'precision': 0.7, 'recall': 0.7, 'f1_score': 0.7},
            performance_grade='C',
            reliability_score=0.7,
            recommendations=['ML libraries not available for detailed validation'],
            validation_date=datetime.now().isoformat(),
            test_samples=0
        )
    
    def _create_error_validation_result(self, model_name: str, error: str) -> ModelValidationResult:
        """Create error validation result."""
        return ModelValidationResult(
            model_name=model_name,
            validation_type='error',
            metrics={},
            performance_grade='F',
            reliability_score=0.0,
            recommendations=[f'Validation failed: {error}'],
            validation_date=datetime.now().isoformat(),
            test_samples=0
        )

class PredictionQualityAssessor:
    """Assess quality of individual predictions."""
    
    def __init__(self):
        self.confidence_calculator = ConfidenceCalculator()
        self.quality_history = deque(maxlen=1000)
    
    def assess_prediction_quality(self, prediction_data: Dict[str, Any]) -> PredictionQuality:
        """Assess quality of individual prediction."""
        try:
            apk_name = prediction_data.get('apk_name', 'unknown')
            prediction_id = f"{apk_name}_{int(datetime.now().timestamp())}"
            
            # Calculate confidence score
            confidence_score_data = self.confidence_calculator.calculate_confidence(prediction_data)
            
            # Calculate quality indicators
            quality_indicators = self._calculate_quality_indicators(
                prediction_data, confidence_score_data
            )
            
            # Identify uncertainty factors
            uncertainty_factors = self._identify_uncertainty_factors(
                prediction_data, confidence_score_data
            )
            
            # Overall reliability assessment
            reliability_assessment = self._assess_reliability(
                confidence_score_data.overall_confidence, quality_indicators
            )
            
            quality = PredictionQuality(
                prediction_id=prediction_id,
                apk_name=apk_name,
                confidence_score=confidence_score_data.overall_confidence,
                quality_indicators=quality_indicators,
                uncertainty_factors=uncertainty_factors,
                reliability_assessment=reliability_assessment,
                assessed_at=datetime.now().isoformat()
            )
            
            # Store in history
            self.quality_history.append(quality)
            
            return quality
            
        except Exception as e:
            logger.error(f"Prediction quality assessment failed: {e}")
            return self._create_fallback_quality(prediction_data, str(e))
    
    def _calculate_quality_indicators(self, prediction_data: Dict[str, Any], 
                                    confidence_data: ConfidenceScore) -> Dict[str, float]:
        """Calculate various quality indicators."""
        indicators = {}
        
        # Feature completeness
        feature_vector = prediction_data.get('feature_vector', {})
        feature_count = feature_vector.get('feature_count', 0)
        indicators['feature_completeness'] = min(feature_count / 50, 1.0)  # Assume 50 optimal features
        
        # Model reliability
        model_version = prediction_data.get('model_version', '')
        if 'ensemble' in model_version.lower():
            indicators['model_reliability'] = 0.9
        elif any(model in model_version.lower() for model in ['random_forest', 'gradient_boosting']):
            indicators['model_reliability'] = 0.8
        else:
            indicators['model_reliability'] = 0.6
        
        # Evidence strength
        evidence = prediction_data.get('evidence', [])
        strong_evidence_count = sum(1 for e in evidence if e.get('importance', 0) > 0.1)
        indicators['evidence_strength'] = min(strong_evidence_count / 5, 1.0)  # Assume 5 pieces of strong evidence is optimal
        
        # Prediction consistency (based on confidence level)
        confidence_level = prediction_data.get('confidence_level', 'low')
        consistency_scores = {'very_high': 0.95, 'high': 0.85, 'medium': 0.65, 'low': 0.45, 'very_low': 0.25}
        indicators['prediction_consistency'] = consistency_scores.get(confidence_level, 0.5)
        
        # Temporal relevance (how recent is the prediction)
        predicted_at = prediction_data.get('predicted_at', datetime.now().isoformat())
        try:
            prediction_time = datetime.fromisoformat(predicted_at)
            age_hours = (datetime.now() - prediction_time).total_seconds() / 3600
            indicators['temporal_relevance'] = max(0, 1 - age_hours / 24)  # Decays over 24 hours
        except:
            indicators['temporal_relevance'] = 1.0
        
        return indicators
    
    def _identify_uncertainty_factors(self, prediction_data: Dict[str, Any], 
                                    confidence_data: ConfidenceScore) -> List[str]:
        """Identify factors that contribute to uncertainty."""
        factors = []
        
        # Low component scores
        for component, score in confidence_data.component_scores.items():
            if score < 0.5:
                factors.append(f"Low {component.replace('_', ' ')}: {score:.2f}")
        
        # Missing features
        feature_count = prediction_data.get('feature_vector', {}).get('feature_count', 0)
        if feature_count < 20:
            factors.append(f"Limited features available: {feature_count}")
        
        # Low evidence
        evidence_count = len(prediction_data.get('evidence', []))
        if evidence_count < 3:
            factors.append(f"Insufficient evidence: {evidence_count} pieces")
        
        # Model limitations
        model_version = prediction_data.get('model_version', 'unknown')
        if 'rule_based' in model_version.lower():
            factors.append("Using rule-based fallback model")
        
        # Prediction age
        predicted_at = prediction_data.get('predicted_at', datetime.now().isoformat())
        try:
            prediction_time = datetime.fromisoformat(predicted_at)
            age_hours = (datetime.now() - prediction_time).total_seconds() / 3600
            if age_hours > 12:
                factors.append(f"Prediction is {age_hours:.1f} hours old")
        except:
            pass
        
        return factors
    
    def _assess_reliability(self, overall_confidence: float, 
                          quality_indicators: Dict[str, float]) -> str:
        """Assess overall reliability of prediction."""
        # Calculate weighted reliability score
        weights = {
            'feature_completeness': 0.25,
            'model_reliability': 0.25,
            'evidence_strength': 0.20,
            'prediction_consistency': 0.20,
            'temporal_relevance': 0.10
        }
        
        reliability_score = sum(
            quality_indicators.get(indicator, 0.5) * weight
            for indicator, weight in weights.items()
        )
        
        # Combine with overall confidence
        final_score = (reliability_score * 0.6 + overall_confidence * 0.4)
        
        if final_score >= 0.85:
            return "highly_reliable"
        elif final_score >= 0.70:
            return "reliable"
        elif final_score >= 0.55:
            return "moderately_reliable"
        elif final_score >= 0.40:
            return "questionable"
        else:
            return "unreliable"
    
    def _create_fallback_quality(self, prediction_data: Dict[str, Any], 
                               error: str) -> PredictionQuality:
        """Create fallback quality assessment."""
        return PredictionQuality(
            prediction_id=f"error_{int(datetime.now().timestamp())}",
            apk_name=prediction_data.get('apk_name', 'unknown'),
            confidence_score=0.3,
            quality_indicators={'error': 0.0},
            uncertainty_factors=[f"Assessment failed: {error}"],
            reliability_assessment="unreliable",
            assessed_at=datetime.now().isoformat()
        )
    
    def get_quality_trends(self, days: int = 7) -> Dict[str, Any]:
        """Get quality trends over time."""
        cutoff_time = datetime.now() - timedelta(days=days)
        
        recent_assessments = [
            q for q in self.quality_history
            if datetime.fromisoformat(q.assessed_at) >= cutoff_time
        ]
        
        if not recent_assessments:
            return {'error': 'no_recent_assessments'}
        
        # Calculate trends
        confidence_scores = [q.confidence_score for q in recent_assessments]
        reliability_assessments = [q.reliability_assessment for q in recent_assessments]
        
        # Reliability distribution
        reliability_counts = defaultdict(int)
        for assessment in reliability_assessments:
            reliability_counts[assessment] += 1
        
        return {
            'period_days': days,
            'total_assessments': len(recent_assessments),
            'confidence_trends': {
                'mean': np.mean(confidence_scores),
                'median': np.median(confidence_scores),
                'std': np.std(confidence_scores),
                'trend': self._calculate_trend(confidence_scores)
            },
            'reliability_distribution': dict(reliability_counts),
            'quality_improvement_suggestions': self._generate_quality_suggestions(recent_assessments)
        }
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction."""
        if len(values) < 3:
            return "insufficient_data"
        
        # Simple linear trend
        x = np.arange(len(values))
        slope = np.polyfit(x, values, 1)[0]
        
        if slope > 0.01:
            return "improving"
        elif slope < -0.01:
            return "declining"
        else:
            return "stable"
    
    def _generate_quality_suggestions(self, assessments: List[PredictionQuality]) -> List[str]:
        """Generate suggestions for improving quality."""
        suggestions = []
        
        # Analyze common uncertainty factors
        all_factors = []
        for assessment in assessments:
            all_factors.extend(assessment.uncertainty_factors)
        
        factor_counts = defaultdict(int)
        for factor in all_factors:
            factor_counts[factor] += 1
        
        # Top issues
        for factor, count in sorted(factor_counts.items(), key=lambda x: x[1], reverse=True)[:3]:
            if 'feature' in factor.lower():
                suggestions.append("Improve feature extraction and completeness")
            elif 'evidence' in factor.lower():
                suggestions.append("Enhance evidence collection mechanisms")
            elif 'model' in factor.lower():
                suggestions.append("Consider upgrading to more advanced models")
        
        # Average confidence analysis
        avg_confidence = np.mean([q.confidence_score for q in assessments])
        if avg_confidence < 0.6:
            suggestions.append("Overall confidence is low - consider model retraining")
        
        return suggestions[:5]  # Limit to top 5

# Global instances
confidence_calculator = None
model_validator = None
quality_assessor = None

def initialize_confidence_system(db_path: Path) -> Tuple[ConfidenceCalculator, ModelValidator, PredictionQualityAssessor]:
    """Initialize global confidence scoring system."""
    global confidence_calculator, model_validator, quality_assessor
    
    confidence_calculator = ConfidenceCalculator()
    model_validator = ModelValidator(db_path)
    quality_assessor = PredictionQualityAssessor()
    
    return confidence_calculator, model_validator, quality_assessor

def get_confidence_system() -> Tuple[Optional[ConfidenceCalculator], Optional[ModelValidator], Optional[PredictionQualityAssessor]]:
    """Get global confidence scoring system instances."""
    return confidence_calculator, model_validator, quality_assessor 