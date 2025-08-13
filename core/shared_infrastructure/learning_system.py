"""
AODS Learning System for Continuous Confidence Improvement

Provides enterprise-grade learning system that continuously improves confidence
calculation accuracy through historical data analysis, machine learning integration,
and real-world validation feedback.

Features:
- Historical data collection and analysis for pattern reliability refinement
- Machine learning-enhanced confidence prediction with feature engineering
- Real-world validation system for confidence calibration
- Continuous monitoring and accuracy improvement tracking
- Pattern performance analytics and recommendation engine
- Integration with pattern reliability database for data persistence
"""

import asyncio
import logging
import json
import pickle
import threading
import time
import numpy as np
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union, Callable
from dataclasses import dataclass, field
from pathlib import Path
import sqlite3
from collections import defaultdict, deque
import statistics
from concurrent.futures import ThreadPoolExecutor, Future

# Optional ML dependencies
try:
    from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import mean_squared_error, r2_score, mean_absolute_error
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.isotonic import IsotonicRegression
    from sklearn.calibration import CalibratedClassifierCV
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from .analysis_exceptions import ParallelProcessingError, ErrorContext, ContextualLogger
from .pattern_reliability_database import (
    PatternReliability,
    ValidationRecord,
    PatternReliabilityDatabase,
    get_reliability_database
)
from .dependency_injection import AnalysisContext

logger = logging.getLogger(__name__)

@dataclass
class LearningMetrics:
    """Metrics for tracking learning system performance."""
    
    # Accuracy metrics
    overall_accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    
    # Confidence calibration metrics
    calibration_accuracy: float = 0.0
    brier_score: float = 0.0
    reliability_score: float = 0.0
    sharpness_score: float = 0.0
    
    # Learning progress metrics
    improvement_rate: float = 0.0
    data_quality_score: float = 0.0
    pattern_coverage: float = 0.0
    validation_coverage: float = 0.0
    
    # Performance metrics
    prediction_latency: float = 0.0
    model_accuracy: float = 0.0
    feature_importance: Dict[str, float] = field(default_factory=dict)
    
    # Temporal metrics
    last_updated: datetime = field(default_factory=datetime.now)
    total_predictions: int = 0
    total_validations: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for serialization."""
        result = {}
        for key, value in self.__dict__.items():
            if isinstance(value, datetime):
                result[key] = value.isoformat()
            else:
                result[key] = value
        return result

@dataclass
class ConfidencePredictionFeatures:
    """Features for confidence prediction machine learning model."""
    
    # Pattern characteristics
    pattern_reliability: float = 0.0
    pattern_age: float = 0.0  # Days since pattern creation
    pattern_usage_frequency: float = 0.0
    pattern_category_score: float = 0.0
    
    # Context characteristics
    file_type_score: float = 0.0
    location_risk_score: float = 0.0
    app_context_score: float = 0.0
    analysis_depth_score: float = 0.0
    
    # Validation characteristics
    validation_source_count: int = 0
    cross_validation_consistency: float = 0.0
    historical_accuracy: float = 0.0
    peer_pattern_agreement: float = 0.0
    
    # Temporal characteristics
    analysis_recency: float = 0.0  # Hours since analysis
    pattern_stability: float = 0.0
    trend_direction: float = 0.0  # Improving/declining trend
    
    # Evidence characteristics
    evidence_strength: float = 0.0
    evidence_diversity: float = 0.0
    evidence_consistency: float = 0.0
    anomaly_score: float = 0.0
    
    def to_array(self) -> np.ndarray:
        """Convert features to numpy array for ML model."""
        return np.array([
            self.pattern_reliability,
            self.pattern_age,
            self.pattern_usage_frequency,
            self.pattern_category_score,
            self.file_type_score,
            self.location_risk_score,
            self.app_context_score,
            self.analysis_depth_score,
            self.validation_source_count,
            self.cross_validation_consistency,
            self.historical_accuracy,
            self.peer_pattern_agreement,
            self.analysis_recency,
            self.pattern_stability,
            self.trend_direction,
            self.evidence_strength,
            self.evidence_diversity,
            self.evidence_consistency,
            self.anomaly_score
        ])
    
    @classmethod
    def get_feature_names(cls) -> List[str]:
        """Get list of feature names for model interpretation."""
        return [
            'pattern_reliability', 'pattern_age', 'pattern_usage_frequency',
            'pattern_category_score', 'file_type_score', 'location_risk_score',
            'app_context_score', 'analysis_depth_score', 'validation_source_count',
            'cross_validation_consistency', 'historical_accuracy', 'peer_pattern_agreement',
            'analysis_recency', 'pattern_stability', 'trend_direction',
            'evidence_strength', 'evidence_diversity', 'evidence_consistency',
            'anomaly_score'
        ]

class FeatureExtractor:
    """
    Extracts features from analysis context and patterns for ML model.
    """
    
    def __init__(self, reliability_db: PatternReliabilityDatabase):
        self.reliability_db = reliability_db
        self.logger = ContextualLogger("feature_extractor")
        
        # Category scoring weights
        self.category_weights = {
            'crypto': 1.0,
            'network': 0.9,
            'storage': 0.8,
            'platform': 0.7,
            'binary': 0.8,
            'general': 0.5
        }
        
        # File type risk scores
        self.file_type_scores = {
            'java': 0.8,
            'smali': 0.9,
            'xml': 0.6,
            'native': 1.0,
            'resource': 0.4,
            'manifest': 0.7
        }
        
        # Location risk scores
        self.location_risk_scores = {
            'external': 1.0,
            'cache': 0.9,
            'temp': 0.9,
            'internal': 0.6,
            'system': 0.8,
            'unknown': 0.7
        }
    
    def extract_features(self, 
                        pattern_id: str,
                        evidence: Dict[str, Any],
                        context: Dict[str, Any]) -> ConfidencePredictionFeatures:
        """
        Extract features for confidence prediction.
        
        Args:
            pattern_id: ID of the pattern
            evidence: Evidence dictionary
            context: Analysis context
            
        Returns:
            ConfidencePredictionFeatures object
        """
        features = ConfidencePredictionFeatures()
        
        # Extract pattern characteristics
        pattern = self.reliability_db.get_pattern_reliability(pattern_id)
        if pattern:
            features.pattern_reliability = pattern.reliability_score
            features.pattern_age = (datetime.now() - pattern.last_updated).days
            features.pattern_usage_frequency = pattern.total_matches / max(features.pattern_age, 1)
            features.pattern_category_score = self.category_weights.get(
                pattern.pattern_category.lower(), 0.5
            )
            features.historical_accuracy = pattern.accuracy_rate
            features.pattern_stability = self._calculate_pattern_stability(pattern)
            features.trend_direction = self._calculate_trend_direction(pattern)
        
        # Extract context characteristics
        features.file_type_score = self._extract_file_type_score(context)
        features.location_risk_score = self._extract_location_risk_score(context)
        features.app_context_score = self._extract_app_context_score(context)
        features.analysis_depth_score = self._extract_analysis_depth_score(context)
        
        # Extract validation characteristics
        features.validation_source_count = len(evidence.get('validation_sources', []))
        features.cross_validation_consistency = evidence.get('cross_validation_consistency', 0.5)
        features.peer_pattern_agreement = self._calculate_peer_agreement(pattern_id, evidence)
        
        # Extract temporal characteristics
        features.analysis_recency = context.get('analysis_time_hours', 0)
        
        # Extract evidence characteristics
        features.evidence_strength = self._calculate_evidence_strength(evidence)
        features.evidence_diversity = self._calculate_evidence_diversity(evidence)
        features.evidence_consistency = evidence.get('consistency_score', 0.5)
        features.anomaly_score = self._calculate_anomaly_score(evidence, context)
        
        return features
    
    def _calculate_pattern_stability(self, pattern: PatternReliability) -> float:
        """Calculate pattern stability from accuracy trend."""
        if not pattern.accuracy_trend or len(pattern.accuracy_trend) < 3:
            return 0.5  # Neutral for insufficient data
        
        # Calculate variance in recent accuracy
        recent_accuracy = pattern.accuracy_trend[-10:]  # Last 10 data points
        variance = statistics.variance(recent_accuracy) if len(recent_accuracy) > 1 else 0
        
        # Lower variance = higher stability
        stability = max(0.0, 1.0 - variance * 2)  # Scale variance to 0-1
        return min(1.0, stability)
    
    def _calculate_trend_direction(self, pattern: PatternReliability) -> float:
        """Calculate trend direction (-1 declining, 0 stable, +1 improving)."""
        if not pattern.accuracy_trend or len(pattern.accuracy_trend) < 5:
            return 0.0  # Neutral for insufficient data
        
        recent_trend = pattern.accuracy_trend[-5:]
        if len(recent_trend) < 2:
            return 0.0
        
        # Calculate slope of recent trend
        x = np.arange(len(recent_trend))
        y = np.array(recent_trend)
        slope = np.polyfit(x, y, 1)[0]
        
        # Normalize slope to -1 to +1 range
        return max(-1.0, min(1.0, slope * 10))
    
    def _extract_file_type_score(self, context: Dict[str, Any]) -> float:
        """Extract file type risk score."""
        file_type = context.get('file_type', 'unknown').lower()
        return self.file_type_scores.get(file_type, 0.5)
    
    def _extract_location_risk_score(self, context: Dict[str, Any]) -> float:
        """Extract location risk score."""
        location = context.get('storage_location', 'unknown').lower()
        return self.location_risk_scores.get(location, 0.5)
    
    def _extract_app_context_score(self, context: Dict[str, Any]) -> float:
        """Extract application context score."""
        app_context = context.get('app_context', 'unknown').lower()
        context_scores = {
            'production': 1.0,
            'release': 0.9,
            'debug': 0.6,
            'test': 0.4,
            'unknown': 0.5
        }
        return context_scores.get(app_context, 0.5)
    
    def _extract_analysis_depth_score(self, context: Dict[str, Any]) -> float:
        """Extract analysis depth score."""
        depth = context.get('analysis_depth', 'balanced').lower()
        depth_scores = {
            'comprehensive': 1.0,
            'thorough': 0.8,
            'balanced': 0.6,
            'fast': 0.4,
            'minimal': 0.2
        }
        return depth_scores.get(depth, 0.6)
    
    def _calculate_peer_agreement(self, pattern_id: str, evidence: Dict[str, Any]) -> float:
        """Calculate agreement with peer patterns."""
        # Get patterns in same category
        pattern = self.reliability_db.get_pattern_reliability(pattern_id)
        if not pattern:
            return 0.5
        
        peer_patterns = self.reliability_db.get_patterns_by_category(pattern.pattern_category)
        if len(peer_patterns) <= 1:
            return 0.5
        
        # Calculate average reliability of peer patterns
        peer_reliabilities = [p.reliability_score for p in peer_patterns if p.pattern_id != pattern_id]
        if not peer_reliabilities:
            return 0.5
        
        avg_peer_reliability = statistics.mean(peer_reliabilities)
        
        # Agreement is how close this pattern is to peer average
        agreement = 1.0 - abs(pattern.reliability_score - avg_peer_reliability)
        return max(0.0, min(1.0, agreement))
    
    def _calculate_evidence_strength(self, evidence: Dict[str, Any]) -> float:
        """Calculate overall evidence strength."""
        strength_factors = []
        
        # Pattern match quality
        if 'pattern_matches' in evidence:
            matches = evidence['pattern_matches']
            if matches:
                avg_confidence = statistics.mean([m.get('confidence', 0.5) for m in matches])
                strength_factors.append(avg_confidence)
        
        # Validation sources
        validation_count = len(evidence.get('validation_sources', []))
        validation_strength = min(1.0, validation_count / 3.0)  # Plateau at 3 sources
        strength_factors.append(validation_strength)
        
        # Context relevance
        context_relevance = evidence.get('context_relevance', 0.5)
        strength_factors.append(context_relevance)
        
        if not strength_factors:
            return 0.5
        
        return statistics.mean(strength_factors)
    
    def _calculate_evidence_diversity(self, evidence: Dict[str, Any]) -> float:
        """Calculate evidence diversity score."""
        diversity_factors = []
        
        # Source diversity
        sources = evidence.get('validation_sources', [])
        unique_sources = len(set(sources))
        source_diversity = min(1.0, unique_sources / 4.0)  # Plateau at 4 unique sources
        diversity_factors.append(source_diversity)
        
        # Pattern type diversity
        patterns = evidence.get('pattern_matches', [])
        if patterns:
            pattern_types = set(p.get('type', 'unknown') for p in patterns)
            type_diversity = min(1.0, len(pattern_types) / 3.0)  # Plateau at 3 types
            diversity_factors.append(type_diversity)
        
        # Analysis method diversity
        methods = evidence.get('analysis_methods', [])
        method_diversity = min(1.0, len(set(methods)) / 3.0)  # Plateau at 3 methods
        diversity_factors.append(method_diversity)
        
        if not diversity_factors:
            return 0.5
        
        return statistics.mean(diversity_factors)
    
    def _calculate_anomaly_score(self, evidence: Dict[str, Any], context: Dict[str, Any]) -> float:
        """Calculate anomaly score (higher = more anomalous)."""
        anomaly_factors = []
        
        # Unusual confidence for pattern type
        confidence = evidence.get('raw_confidence', 0.5)
        expected_confidence = context.get('expected_confidence', 0.5)
        confidence_anomaly = abs(confidence - expected_confidence)
        anomaly_factors.append(confidence_anomaly)
        
        # Unusual pattern combination
        patterns = evidence.get('pattern_matches', [])
        if len(patterns) > 1:
            # Check if pattern combination is unusual
            pattern_types = [p.get('type', 'unknown') for p in patterns]
            unusual_combination = self._is_unusual_combination(pattern_types)
            anomaly_factors.append(1.0 if unusual_combination else 0.0)
        
        # Context mismatch
        context_mismatch = evidence.get('context_mismatch_score', 0.0)
        anomaly_factors.append(context_mismatch)
        
        if not anomaly_factors:
            return 0.0
        
        return statistics.mean(anomaly_factors)
    
    def _is_unusual_combination(self, pattern_types: List[str]) -> bool:
        """Check if pattern type combination is unusual."""
        # Simple heuristic - this could be enhanced with actual data
        incompatible_combinations = [
            ('crypto_strong', 'crypto_weak'),
            ('secure_storage', 'insecure_storage'),
            ('encrypted', 'plaintext')
        ]
        
        pattern_set = set(pattern_types)
        for combo in incompatible_combinations:
            if all(pattern in pattern_set for pattern in combo):
                return True
        
        return False

class ConfidenceCalibrator:
    """
    Calibrates confidence scores to improve probability accuracy using
    real-world validation data.
    """
    
    def __init__(self, reliability_db: PatternReliabilityDatabase):
        self.reliability_db = reliability_db
        self.logger = ContextualLogger("confidence_calibrator")
        
        # Calibration models
        self.isotonic_calibrator = None
        self.platt_calibrator = None
        self.temperature_calibrator = None
        
        # Calibration data
        self.calibration_data = deque(maxlen=10000)  # Last 10k data points
        self.last_calibration_update = datetime.now()
        self.calibration_interval = timedelta(hours=24)  # Recalibrate daily
        
        self._lock = threading.Lock()
    
    def record_prediction(self, predicted_confidence: float, actual_outcome: bool, context: Dict[str, Any] = None):
        """
        Record a prediction for calibration learning.
        
        Args:
            predicted_confidence: Original predicted confidence (0-1)
            actual_outcome: Whether vulnerability actually existed
            context: Additional context for the prediction
        """
        with self._lock:
            record = {
                'predicted_confidence': predicted_confidence,
                'actual_outcome': 1.0 if actual_outcome else 0.0,
                'timestamp': datetime.now(),
                'context': context or {}
            }
            
            self.calibration_data.append(record)
            
            # Check if we need to update calibration
            if (datetime.now() - self.last_calibration_update) > self.calibration_interval:
                self._update_calibration()
    
    def calibrate_confidence(self, raw_confidence: float, method: str = 'ensemble') -> float:
        """
        Calibrate confidence score to improve probability accuracy.
        
        Args:
            raw_confidence: Raw confidence score (0-1)
            method: Calibration method ('isotonic', 'platt', 'temperature', 'ensemble')
            
        Returns:
            Calibrated confidence score (0-1)
        """
        if not self.calibration_data or len(self.calibration_data) < 50:
            return raw_confidence  # Insufficient data for calibration
        
        try:
            if method == 'isotonic' and self.isotonic_calibrator:
                return self.isotonic_calibrator.predict([raw_confidence])[0]
            elif method == 'platt' and self.platt_calibrator:
                return self._apply_platt_calibration(raw_confidence)
            elif method == 'temperature' and self.temperature_calibrator:
                return self._apply_temperature_calibration(raw_confidence)
            elif method == 'ensemble':
                return self._apply_ensemble_calibration(raw_confidence)
            else:
                return raw_confidence
                
        except Exception as e:
            self.logger.warning(f"Calibration failed: {e}")
            return raw_confidence
    
    def _update_calibration(self):
        """Update calibration models with recent data."""
        if len(self.calibration_data) < 50:
            return  # Need at least 50 data points
        
        try:
            # Prepare data
            predictions = []
            outcomes = []
            
            for record in self.calibration_data:
                predictions.append(record['predicted_confidence'])
                outcomes.append(record['actual_outcome'])
            
            predictions = np.array(predictions).reshape(-1, 1)
            outcomes = np.array(outcomes)
            
            # Update isotonic calibrator
            if ML_AVAILABLE:
                self.isotonic_calibrator = IsotonicRegression(out_of_bounds='clip')
                self.isotonic_calibrator.fit(predictions.flatten(), outcomes)
            
            # Update Platt calibrator (sigmoid)
            self._update_platt_calibrator(predictions.flatten(), outcomes)
            
            # Update temperature calibrator
            self._update_temperature_calibrator(predictions.flatten(), outcomes)
            
            self.last_calibration_update = datetime.now()
            self.logger.info(f"Updated calibration models with {len(predictions)} data points")
            
        except Exception as e:
            self.logger.error(f"Failed to update calibration: {e}")
    
    def _update_platt_calibrator(self, predictions: np.ndarray, outcomes: np.ndarray):
        """Update Platt (sigmoid) calibrator."""
        from scipy.optimize import minimize_scalar
        
        def sigmoid(x, a, b):
            return 1 / (1 + np.exp(-(a * x + b)))
        
        def log_loss(params):
            a, b = params
            epsilon = 1e-15
            p = sigmoid(predictions, a, b)
            p = np.clip(p, epsilon, 1 - epsilon)
            return -np.mean(outcomes * np.log(p) + (1 - outcomes) * np.log(1 - p))
        
        try:
            from scipy.optimize import minimize
            result = minimize(log_loss, [1.0, 0.0], method='BFGS')
            if result.success:
                self.platt_calibrator = {'a': result.x[0], 'b': result.x[1]}
        except ImportError:
            # Fallback simple calibrator
            mean_pred = np.mean(predictions)
            mean_outcome = np.mean(outcomes)
            self.platt_calibrator = {'a': 1.0, 'b': mean_outcome - mean_pred}
    
    def _update_temperature_calibrator(self, predictions: np.ndarray, outcomes: np.ndarray):
        """Update temperature scaling calibrator."""
        def temperature_scale(logits, temperature):
            return 1 / (1 + np.exp(-logits / temperature))
        
        def calibration_loss(temperature):
            # Convert probabilities to logits
            epsilon = 1e-15
            logits = np.log(np.clip(predictions, epsilon, 1 - epsilon) / 
                          np.clip(1 - predictions, epsilon, 1 - epsilon))
            
            calibrated_probs = temperature_scale(logits, temperature)
            calibrated_probs = np.clip(calibrated_probs, epsilon, 1 - epsilon)
            
            return -np.mean(outcomes * np.log(calibrated_probs) + 
                          (1 - outcomes) * np.log(1 - calibrated_probs))
        
        try:
            from scipy.optimize import minimize_scalar
            result = minimize_scalar(calibration_loss, bounds=(0.1, 10.0), method='bounded')
            if result.success:
                self.temperature_calibrator = result.x
        except ImportError:
            self.temperature_calibrator = 1.0  # No scaling
    
    def _apply_platt_calibration(self, confidence: float) -> float:
        """Apply Platt (sigmoid) calibration."""
        if not self.platt_calibrator:
            return confidence
        
        a = self.platt_calibrator['a']
        b = self.platt_calibrator['b']
        
        calibrated = 1 / (1 + np.exp(-(a * confidence + b)))
        return float(np.clip(calibrated, 0.0, 1.0))
    
    def _apply_temperature_calibration(self, confidence: float) -> float:
        """Apply temperature scaling calibration."""
        if not self.temperature_calibrator:
            return confidence
        
        # Convert probability to logits
        epsilon = 1e-15
        confidence = np.clip(confidence, epsilon, 1 - epsilon)
        logits = np.log(confidence / (1 - confidence))
        
        # Apply temperature scaling
        calibrated_logits = logits / self.temperature_calibrator
        calibrated = 1 / (1 + np.exp(-calibrated_logits))
        
        return float(np.clip(calibrated, 0.0, 1.0))
    
    def _apply_ensemble_calibration(self, confidence: float) -> float:
        """Apply ensemble of calibration methods."""
        calibrated_scores = []
        
        if self.isotonic_calibrator:
            try:
                iso_score = self.isotonic_calibrator.predict([confidence])[0]
                calibrated_scores.append(iso_score)
            except:
                pass
        
        if self.platt_calibrator:
            try:
                platt_score = self._apply_platt_calibration(confidence)
                calibrated_scores.append(platt_score)
            except:
                pass
        
        if self.temperature_calibrator:
            try:
                temp_score = self._apply_temperature_calibration(confidence)
                calibrated_scores.append(temp_score)
            except:
                pass
        
        if not calibrated_scores:
            return confidence
        
        # Weighted ensemble (isotonic gets highest weight)
        weights = [0.5, 0.3, 0.2][:len(calibrated_scores)]
        ensemble_score = sum(w * s for w, s in zip(weights, calibrated_scores)) / sum(weights)
        
        return float(np.clip(ensemble_score, 0.0, 1.0))
    
    def get_calibration_metrics(self) -> Dict[str, float]:
        """Get calibration quality metrics."""
        if len(self.calibration_data) < 10:
            return {}
        
        predictions = [r['predicted_confidence'] for r in self.calibration_data]
        outcomes = [r['actual_outcome'] for r in self.calibration_data]
        
        # Calculate calibration metrics
        metrics = {}
        
        # Brier Score (lower is better)
        brier_score = np.mean([(p - o) ** 2 for p, o in zip(predictions, outcomes)])
        metrics['brier_score'] = brier_score
        
        # Reliability (calibration accuracy)
        n_bins = 10
        bin_boundaries = np.linspace(0, 1, n_bins + 1)
        bin_lowers = bin_boundaries[:-1]
        bin_uppers = bin_boundaries[1:]
        
        reliabilities = []
        for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
            in_bin = [(p >= bin_lower) and (p < bin_upper) for p in predictions]
            if any(in_bin):
                bin_predictions = [p for p, in_b in zip(predictions, in_bin) if in_b]
                bin_outcomes = [o for o, in_b in zip(outcomes, in_bin) if in_b]
                
                avg_confidence = np.mean(bin_predictions)
                avg_accuracy = np.mean(bin_outcomes)
                reliability = abs(avg_confidence - avg_accuracy)
                reliabilities.append(reliability)
        
        if reliabilities:
            metrics['reliability'] = np.mean(reliabilities)
            metrics['max_reliability_error'] = max(reliabilities)
        
        # Overall accuracy
        binary_predictions = [1 if p > 0.5 else 0 for p in predictions]
        accuracy = np.mean([bp == o for bp, o in zip(binary_predictions, outcomes)])
        metrics['overall_accuracy'] = accuracy
        
        return metrics

class ConfidenceLearningSystem:
    """
    Main learning system that coordinates all learning components for
    continuous confidence improvement.
    """
    
    def __init__(self, context: AnalysisContext):
        """
        Initialize learning system.
        
        Args:
            context: Analysis context with dependencies
        """
        self.context = context
        self.reliability_db = get_reliability_database()
        self.logger = ContextualLogger("confidence_learning")
        
        # Learning components
        self.feature_extractor = FeatureExtractor(self.reliability_db)
        self.calibrator = ConfidenceCalibrator(self.reliability_db)
        
        # ML model (if available)
        self.ml_model = None
        self.feature_scaler = None
        self.model_trained = False
        self.min_training_samples = 100
        
        # Learning metrics
        self.metrics = LearningMetrics()
        self.metrics_history = deque(maxlen=1000)
        
        # Learning parameters
        self.learning_rate = 0.01
        self.model_update_interval = timedelta(hours=12)
        self.last_model_update = datetime.now()
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Initialize ML model if available
        if ML_AVAILABLE:
            self._initialize_ml_model()
    
    def _initialize_ml_model(self):
        """Initialize machine learning model for confidence prediction."""
        try:
            # Use ensemble of models for better performance
            self.ml_model = {
                'random_forest': RandomForestRegressor(
                    n_estimators=100,
                    max_depth=10,
                    random_state=42,
                    n_jobs=-1
                ),
                'gradient_boosting': GradientBoostingRegressor(
                    n_estimators=100,
                    max_depth=6,
                    learning_rate=0.1,
                    random_state=42
                )
            }
            
            self.feature_scaler = StandardScaler()
            self.logger.info("Initialized ML models for confidence prediction")
            
        except Exception as e:
            self.logger.warning(f"Failed to initialize ML models: {e}")
            self.ml_model = None
    
    def predict_confidence(self, 
                          pattern_id: str,
                          evidence: Dict[str, Any],
                          context: Dict[str, Any]) -> float:
        """
        Predict confidence score using learning system.
        
        Args:
            pattern_id: Pattern identifier
            evidence: Evidence dictionary
            context: Analysis context
            
        Returns:
            Predicted confidence score (0-1)
        """
        try:
            # Extract features
            features = self.feature_extractor.extract_features(pattern_id, evidence, context)
            
            # Get base confidence from pattern reliability
            base_confidence = features.pattern_reliability
            
            # Apply ML enhancement if available
            if self.ml_model and self.model_trained:
                ml_confidence = self._predict_with_ml(features)
                # Ensemble: 60% ML, 40% base
                enhanced_confidence = 0.6 * ml_confidence + 0.4 * base_confidence
            else:
                enhanced_confidence = base_confidence
            
            # Apply calibration
            calibrated_confidence = self.calibrator.calibrate_confidence(enhanced_confidence)
            
            # Apply learning rate adaptation
            final_confidence = self._apply_learning_adaptation(
                calibrated_confidence, pattern_id, context
            )
            
            return max(0.0, min(1.0, final_confidence))
            
        except Exception as e:
            self.logger.error(f"Confidence prediction failed: {e}")
            return 0.5  # Conservative fallback
    
    def _predict_with_ml(self, features: ConfidencePredictionFeatures) -> float:
        """Predict confidence using ML model."""
        if not self.ml_model or not self.feature_scaler:
            return features.pattern_reliability
        
        try:
            # Prepare features
            feature_array = features.to_array().reshape(1, -1)
            scaled_features = self.feature_scaler.transform(feature_array)
            
            # Ensemble prediction
            predictions = []
            for model_name, model in self.ml_model.items():
                try:
                    pred = model.predict(scaled_features)[0]
                    predictions.append(max(0.0, min(1.0, pred)))
                except Exception as e:
                    self.logger.warning(f"Model {model_name} prediction failed: {e}")
            
            if predictions:
                return statistics.mean(predictions)
            else:
                return features.pattern_reliability
                
        except Exception as e:
            self.logger.error(f"ML prediction failed: {e}")
            return features.pattern_reliability
    
    def _apply_learning_adaptation(self, 
                                 confidence: float,
                                 pattern_id: str,
                                 context: Dict[str, Any]) -> float:
        """Apply learning-based adaptation to confidence."""
        # Get pattern learning history
        pattern = self.reliability_db.get_pattern_reliability(pattern_id)
        if not pattern:
            return confidence
        
        # Apply trend-based adjustment
        if pattern.accuracy_trend and len(pattern.accuracy_trend) >= 3:
            recent_trend = pattern.accuracy_trend[-3:]
            if len(recent_trend) >= 2:
                # Calculate trend slope
                slope = (recent_trend[-1] - recent_trend[0]) / len(recent_trend)
                
                # Adjust confidence based on trend
                trend_adjustment = slope * self.learning_rate
                confidence += trend_adjustment
        
        # Apply context-specific learning
        context_key = f"{context.get('file_type', 'unknown')}_{context.get('location', 'unknown')}"
        if context_key in pattern.confidence_adjustments:
            context_adjustment = pattern.confidence_adjustments[context_key]
            confidence = (confidence + context_adjustment) / 2
        
        return max(0.0, min(1.0, confidence))
    
    def record_validation_result(self,
                               pattern_id: str,
                               finding_id: str,
                               predicted_confidence: float,
                               actual_vulnerability: bool,
                               context: Dict[str, Any] = None,
                               validator_id: str = "system"):
        """
        Record validation result for learning.
        
        Args:
            pattern_id: Pattern that generated the finding
            finding_id: Finding identifier
            predicted_confidence: Original confidence prediction
            actual_vulnerability: Whether vulnerability actually existed
            context: Additional context
            validator_id: Who validated this result
        """
        try:
            # Create validation record
            from .pattern_reliability_database import create_validation_record
            
            record = create_validation_record(
                pattern_id=pattern_id,
                finding_id=finding_id,
                predicted_vulnerability=predicted_confidence > 0.5,
                actual_vulnerability=actual_vulnerability,
                confidence_score=predicted_confidence,
                context=context or {},
                validator_id=validator_id,
                validation_method="learning_system"
            )
            
            # Record in database
            self.reliability_db.record_validation(record)
            
            # Record for calibration
            self.calibrator.record_prediction(
                predicted_confidence, actual_vulnerability, context
            )
            
            # Update learning metrics
            self._update_learning_metrics(record)
            
            # Schedule model update if needed
            if self._should_update_model():
                self._schedule_model_update()
            
            self.logger.debug(f"Recorded validation result: {record.record_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to record validation result: {e}")
    
    def _update_learning_metrics(self, record: ValidationRecord):
        """Update learning metrics with new validation result."""
        with self._lock:
            self.metrics.total_validations += 1
            
            if record.is_correct:
                self.metrics.total_predictions += 1
            
            # Calculate running accuracy
            if self.metrics.total_validations > 0:
                correct_count = sum(1 for r in self.reliability_db.validation_records 
                                  if r.is_correct)
                self.metrics.overall_accuracy = correct_count / self.metrics.total_validations
            
            # Update timestamp
            self.metrics.last_updated = datetime.now()
            
            # Store metrics history
            self.metrics_history.append(self.metrics.to_dict())
    
    def _should_update_model(self) -> bool:
        """Check if model should be updated."""
        if not ML_AVAILABLE or not self.ml_model:
            return False
        
        # Check time interval
        if datetime.now() - self.last_model_update < self.model_update_interval:
            return False
        
        # Check if we have enough new data
        recent_validations = len([
            r for r in self.reliability_db.validation_records
            if r.validation_timestamp > self.last_model_update
        ])
        
        return recent_validations >= 50  # Require at least 50 new validations
    
    def _schedule_model_update(self):
        """Schedule model update in background."""
        def update_model():
            try:
                self._update_ml_model()
            except Exception as e:
                self.logger.error(f"Model update failed: {e}")
        
        # Run in background thread
        threading.Thread(target=update_model, daemon=True).start()
    
    def _update_ml_model(self):
        """Update ML model with recent validation data."""
        if not ML_AVAILABLE or not self.ml_model:
            return
        
        try:
            # Collect training data
            training_data = self._collect_training_data()
            if len(training_data) < self.min_training_samples:
                self.logger.info(f"Insufficient training data: {len(training_data)} < {self.min_training_samples}")
                return
            
            # Prepare features and targets
            X, y = self._prepare_training_data(training_data)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Scale features
            self.feature_scaler.fit(X_train)
            X_train_scaled = self.feature_scaler.transform(X_train)
            X_test_scaled = self.feature_scaler.transform(X_test)
            
            # Train models
            model_scores = {}
            for model_name, model in self.ml_model.items():
                model.fit(X_train_scaled, y_train)
                score = model.score(X_test_scaled, y_test)
                model_scores[model_name] = score
                
                self.logger.info(f"Model {model_name} R² score: {score:.3f}")
            
            # Update model metrics
            self.metrics.model_accuracy = max(model_scores.values())
            self.metrics.total_predictions = len(training_data)
            
            # Calculate feature importance
            if 'random_forest' in self.ml_model:
                feature_names = ConfidencePredictionFeatures.get_feature_names()
                importances = self.ml_model['random_forest'].feature_importances_
                self.metrics.feature_importance = dict(zip(feature_names, importances))
            
            self.model_trained = True
            self.last_model_update = datetime.now()
            
            self.logger.info(f"Updated ML model with {len(training_data)} training samples")
            
        except Exception as e:
            self.logger.error(f"ML model update failed: {e}")
    
    def _collect_training_data(self) -> List[Dict[str, Any]]:
        """Collect training data from validation records."""
        training_data = []
        
        # Get recent validation records
        cutoff_date = datetime.now() - timedelta(days=90)  # Last 90 days
        
        with sqlite3.connect(self.reliability_db.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM validation_records 
                WHERE validation_timestamp > ?
                ORDER BY validation_timestamp DESC
            """, (cutoff_date.isoformat(),))
            
            for row in cursor.fetchall():
                try:
                    record = {
                        'pattern_id': row[1],
                        'confidence_score': row[5],
                        'actual_outcome': row[4],
                        'context': json.loads(row[6]) if row[6] else {}
                    }
                    training_data.append(record)
                except Exception as e:
                    self.logger.warning(f"Failed to parse training record: {e}")
        
        return training_data
    
    def _prepare_training_data(self, training_data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for ML model."""
        features_list = []
        targets = []
        
        for record in training_data:
            try:
                # Extract features
                features = self.feature_extractor.extract_features(
                    record['pattern_id'],
                    {'confidence_score': record['confidence_score']},
                    record['context']
                )
                
                features_list.append(features.to_array())
                targets.append(1.0 if record['actual_outcome'] else 0.0)
                
            except Exception as e:
                self.logger.warning(f"Failed to extract features for training: {e}")
        
        if not features_list:
            raise ValueError("No valid training features extracted")
        
        X = np.array(features_list)
        y = np.array(targets)
        
        return X, y
    
    def get_learning_metrics(self) -> LearningMetrics:
        """Get current learning system metrics."""
        # Update calibration metrics
        calibration_metrics = self.calibrator.get_calibration_metrics()
        
        if calibration_metrics:
            self.metrics.calibration_accuracy = calibration_metrics.get('overall_accuracy', 0.0)
            self.metrics.brier_score = calibration_metrics.get('brier_score', 0.0)
            self.metrics.reliability_score = 1.0 - calibration_metrics.get('reliability', 1.0)
        
        # Update database statistics
        db_stats = self.reliability_db.get_statistics()
        self.metrics.pattern_coverage = db_stats.get('active_patterns', 0) / max(db_stats.get('total_patterns', 1), 1)
        self.metrics.validation_coverage = db_stats.get('recent_validation_records', 0) / max(db_stats.get('total_validations', 1), 1)
        
        return self.metrics
    
    def export_learning_data(self, output_path: Path):
        """Export learning data for analysis or backup."""
        try:
            learning_data = {
                'metrics': self.metrics.to_dict(),
                'metrics_history': list(self.metrics_history),
                'calibration_metrics': self.calibrator.get_calibration_metrics(),
                'database_stats': self.reliability_db.get_statistics(),
                'model_info': {
                    'ml_available': ML_AVAILABLE,
                    'model_trained': self.model_trained,
                    'last_model_update': self.last_model_update.isoformat(),
                    'feature_importance': self.metrics.feature_importance
                }
            }
            
            with open(output_path, 'w') as f:
                json.dump(learning_data, f, indent=2, default=str)
            
            self.logger.info(f"Exported learning data to {output_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to export learning data: {e}")

# Global learning system instance
_learning_system: Optional[ConfidenceLearningSystem] = None

def get_learning_system(context: AnalysisContext) -> ConfidenceLearningSystem:
    """Get or create global learning system."""
    global _learning_system
    
    if _learning_system is None:
        _learning_system = ConfidenceLearningSystem(context)
    
    return _learning_system

def initialize_learning_system(context: AnalysisContext) -> ConfidenceLearningSystem:
    """Initialize learning system with analysis context."""
    return ConfidenceLearningSystem(context) 