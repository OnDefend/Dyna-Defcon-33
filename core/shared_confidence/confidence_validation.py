"""
Confidence Validation Framework

Provides comprehensive confidence accuracy measurement and calibration capabilities:
- Confidence accuracy validation against ground truth
- Calibration metrics and analysis
- Real-time confidence monitoring
- Accuracy improvement recommendations
- Statistical validation of confidence scores

This framework ensures confidence scores reflect actual vulnerability probability.
"""

import logging
import statistics
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import math

# Optional ML/statistics dependencies
try:
    import numpy as np
    from sklearn.metrics import brier_score_loss, roc_auc_score, log_loss
    from sklearn.calibration import calibration_curve
    from sklearn.isotonic import IsotonicRegression
    from scipy import stats
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from ..shared_infrastructure.pattern_reliability_database import (
    PatternReliabilityDatabase,
    ValidationRecord,
    get_reliability_database
)

logger = logging.getLogger(__name__)

@dataclass
class AccuracyMetrics:
    """Comprehensive accuracy metrics for confidence validation."""
    overall_accuracy: float
    precision: float
    recall: float
    f1_score: float
    brier_score: float
    auc_score: float
    calibration_error: float
    reliability_score: float
    sharpness_score: float
    resolution_score: float
    total_predictions: int
    correct_predictions: int
    false_positives: int
    false_negatives: int
    confidence_distribution: Dict[str, int] = field(default_factory=dict)
    calibration_data: List[Tuple[float, float]] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            'overall_accuracy': self.overall_accuracy,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'brier_score': self.brier_score,
            'auc_score': self.auc_score,
            'calibration_error': self.calibration_error,
            'reliability_score': self.reliability_score,
            'sharpness_score': self.sharpness_score,
            'resolution_score': self.resolution_score,
            'total_predictions': self.total_predictions,
            'correct_predictions': self.correct_predictions,
            'false_positives': self.false_positives,
            'false_negatives': self.false_negatives,
            'confidence_distribution': self.confidence_distribution,
            'timestamp': self.timestamp.isoformat()
        }

@dataclass
class ValidationResult:
    """Result of confidence validation analysis."""
    accuracy_metrics: AccuracyMetrics
    calibration_analysis: Dict[str, Any]
    improvement_recommendations: List[str]
    confidence_bins: List[Dict[str, Any]]
    statistical_significance: Dict[str, Any]
    validation_summary: Dict[str, Any]

class ConfidenceValidationLevel(Enum):
    """Confidence validation levels."""
    EXCELLENT = "excellent"    # 95%+ accuracy
    GOOD = "good"             # 85-95% accuracy
    ACCEPTABLE = "acceptable"  # 75-85% accuracy
    POOR = "poor"             # 60-75% accuracy
    UNACCEPTABLE = "unacceptable"  # <60% accuracy

class ConfidenceValidator:
    """
    Validates confidence accuracy and provides calibration analysis.
    """
    
    def __init__(self, reliability_db: Optional[PatternReliabilityDatabase] = None):
        """Initialize confidence validator."""
        self.reliability_db = reliability_db or get_reliability_database()
        self.logger = logging.getLogger(__name__)
        
        # Validation thresholds
        self.accuracy_thresholds = {
            ConfidenceValidationLevel.EXCELLENT: 0.95,
            ConfidenceValidationLevel.GOOD: 0.85,
            ConfidenceValidationLevel.ACCEPTABLE: 0.75,
            ConfidenceValidationLevel.POOR: 0.60,
            ConfidenceValidationLevel.UNACCEPTABLE: 0.0
        }
        
        # Calibration bins for analysis
        self.calibration_bins = [
            (0.0, 0.1), (0.1, 0.2), (0.2, 0.3), (0.3, 0.4), (0.4, 0.5),
            (0.5, 0.6), (0.6, 0.7), (0.7, 0.8), (0.8, 0.9), (0.9, 1.0)
        ]
    
    def validate_confidence_accuracy(self, 
                                   validation_records: List[ValidationRecord],
                                   time_window: Optional[timedelta] = None) -> ValidationResult:
        """
        Validate confidence accuracy against ground truth data.
        
        Args:
            validation_records: List of validation records
            time_window: Optional time window for analysis
            
        Returns:
            ValidationResult with comprehensive analysis
        """
        # Filter records by time window if specified
        if time_window:
            cutoff_time = datetime.now() - time_window
            validation_records = [
                r for r in validation_records 
                if r.validation_timestamp >= cutoff_time
            ]
        
        if not validation_records:
            return self._create_empty_validation_result()
        
        # Calculate accuracy metrics
        accuracy_metrics = self._calculate_accuracy_metrics(validation_records)
        
        # Perform calibration analysis
        calibration_analysis = self._perform_calibration_analysis(validation_records)
        
        # Generate improvement recommendations
        improvement_recommendations = self._generate_improvement_recommendations(
            accuracy_metrics, calibration_analysis
        )
        
        # Analyze confidence bins
        confidence_bins = self._analyze_confidence_bins(validation_records)
        
        # Calculate statistical significance
        statistical_significance = self._calculate_statistical_significance(validation_records)
        
        # Create validation summary
        validation_summary = self._create_validation_summary(
            accuracy_metrics, calibration_analysis, len(validation_records)
        )
        
        return ValidationResult(
            accuracy_metrics=accuracy_metrics,
            calibration_analysis=calibration_analysis,
            improvement_recommendations=improvement_recommendations,
            confidence_bins=confidence_bins,
            statistical_significance=statistical_significance,
            validation_summary=validation_summary
        )
    
    def _calculate_accuracy_metrics(self, validation_records: List[ValidationRecord]) -> AccuracyMetrics:
        """Calculate comprehensive accuracy metrics."""
        total_predictions = len(validation_records)
        correct_predictions = sum(1 for r in validation_records if r.is_correct)
        false_positives = sum(1 for r in validation_records if r.is_false_positive)
        false_negatives = sum(1 for r in validation_records if r.is_false_negative)
        true_positives = sum(1 for r in validation_records if r.is_true_positive)
        
        # Calculate basic metrics
        overall_accuracy = correct_predictions / total_predictions if total_predictions > 0 else 0.0
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        # Calculate advanced metrics if ML libraries available
        if ML_AVAILABLE:
            predicted_probs = [r.confidence_score for r in validation_records]
            actual_outcomes = [1.0 if r.actual_vulnerability else 0.0 for r in validation_records]
            
            brier_score = brier_score_loss(actual_outcomes, predicted_probs)
            auc_score = roc_auc_score(actual_outcomes, predicted_probs) if len(set(actual_outcomes)) > 1 else 0.5
            
            # Calculate calibration error
            calibration_error = self._calculate_calibration_error(predicted_probs, actual_outcomes)
            
            # Calculate reliability and resolution
            reliability_score = self._calculate_reliability_score(predicted_probs, actual_outcomes)
            sharpness_score = self._calculate_sharpness_score(predicted_probs)
            resolution_score = self._calculate_resolution_score(predicted_probs, actual_outcomes)
            
        else:
            brier_score = 0.0
            auc_score = 0.5
            calibration_error = 0.0
            reliability_score = overall_accuracy
            sharpness_score = 0.0
            resolution_score = 0.0
        
        # Calculate confidence distribution
        confidence_distribution = self._calculate_confidence_distribution(validation_records)
        
        # Calculate calibration data
        calibration_data = self._calculate_calibration_data(validation_records)
        
        return AccuracyMetrics(
            overall_accuracy=overall_accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            brier_score=brier_score,
            auc_score=auc_score,
            calibration_error=calibration_error,
            reliability_score=reliability_score,
            sharpness_score=sharpness_score,
            resolution_score=resolution_score,
            total_predictions=total_predictions,
            correct_predictions=correct_predictions,
            false_positives=false_positives,
            false_negatives=false_negatives,
            confidence_distribution=confidence_distribution,
            calibration_data=calibration_data
        )
    
    def _perform_calibration_analysis(self, validation_records: List[ValidationRecord]) -> Dict[str, Any]:
        """Perform calibration analysis."""
        calibration_analysis = {
            'is_well_calibrated': False,
            'calibration_slope': 0.0,
            'calibration_intercept': 0.0,
            'hosmer_lemeshow_p_value': 0.0,
            'calibration_bins': [],
            'calibration_recommendations': []
        }
        
        if not ML_AVAILABLE or len(validation_records) < 10:
            return calibration_analysis
        
        predicted_probs = [r.confidence_score for r in validation_records]
        actual_outcomes = [1.0 if r.actual_vulnerability else 0.0 for r in validation_records]
        
        # Calibration curve analysis
        try:
            fraction_of_positives, mean_predicted_value = calibration_curve(
                actual_outcomes, predicted_probs, n_bins=10
            )
            
            # Calculate calibration slope and intercept
            if len(mean_predicted_value) > 1:
                slope, intercept, r_value, p_value, std_err = stats.linregress(
                    mean_predicted_value, fraction_of_positives
                )
                calibration_analysis['calibration_slope'] = slope
                calibration_analysis['calibration_intercept'] = intercept
                calibration_analysis['is_well_calibrated'] = abs(slope - 1.0) < 0.1 and abs(intercept) < 0.1
            
            # Create calibration bins
            calibration_bins = []
            for i, (pred_val, actual_frac) in enumerate(zip(mean_predicted_value, fraction_of_positives)):
                calibration_bins.append({
                    'bin_index': i,
                    'predicted_probability': pred_val,
                    'actual_fraction': actual_frac,
                    'calibration_error': abs(pred_val - actual_frac),
                    'sample_count': len(predicted_probs) // 10  # Approximate
                })
            
            calibration_analysis['calibration_bins'] = calibration_bins
            
        except Exception as e:
            self.logger.warning(f"Calibration analysis failed: {e}")
        
        return calibration_analysis
    
    def _generate_improvement_recommendations(self, 
                                           accuracy_metrics: AccuracyMetrics,
                                           calibration_analysis: Dict[str, Any]) -> List[str]:
        """Generate improvement recommendations based on analysis."""
        recommendations = []
        
        # Accuracy-based recommendations
        if accuracy_metrics.overall_accuracy < 0.75:
            recommendations.append("Overall accuracy is below acceptable threshold. Review pattern reliability and evidence quality.")
        
        if accuracy_metrics.precision < 0.8:
            recommendations.append("High false positive rate detected. Consider strengthening evidence requirements.")
        
        if accuracy_metrics.recall < 0.8:
            recommendations.append("High false negative rate detected. Review pattern coverage and sensitivity.")
        
        if accuracy_metrics.f1_score < 0.8:
            recommendations.append("Imbalanced precision and recall. Consider adjusting confidence thresholds.")
        
        # Calibration-based recommendations
        if not calibration_analysis.get('is_well_calibrated', False):
            recommendations.append("Confidence scores are not well calibrated. Consider confidence score adjustment.")
        
        if calibration_analysis.get('calibration_slope', 0.0) > 1.2:
            recommendations.append("Overconfident predictions detected. Consider reducing confidence scores.")
        
        if calibration_analysis.get('calibration_slope', 0.0) < 0.8:
            recommendations.append("Underconfident predictions detected. Consider increasing confidence scores.")
        
        # Brier score recommendations
        if accuracy_metrics.brier_score > 0.25:
            recommendations.append("High Brier score indicates poor probability estimates. Review confidence calculation.")
        
        # AUC recommendations
        if accuracy_metrics.auc_score < 0.7:
            recommendations.append("Low AUC score indicates poor discrimination. Review pattern selection and evidence quality.")
        
        return recommendations
    
    def _analyze_confidence_bins(self, validation_records: List[ValidationRecord]) -> List[Dict[str, Any]]:
        """Analyze confidence distribution across bins."""
        confidence_bins = []
        
        for min_conf, max_conf in self.calibration_bins:
            bin_records = [
                r for r in validation_records 
                if min_conf <= r.confidence_score < max_conf
            ]
            
            if bin_records:
                correct_predictions = sum(1 for r in bin_records if r.is_correct)
                actual_vulnerabilities = sum(1 for r in bin_records if r.actual_vulnerability)
                
                bin_analysis = {
                    'confidence_range': (min_conf, max_conf),
                    'sample_count': len(bin_records),
                    'mean_confidence': statistics.mean([r.confidence_score for r in bin_records]),
                    'accuracy': correct_predictions / len(bin_records),
                    'actual_vulnerability_rate': actual_vulnerabilities / len(bin_records),
                    'calibration_error': abs(statistics.mean([r.confidence_score for r in bin_records]) - 
                                           (actual_vulnerabilities / len(bin_records)))
                }
                
                confidence_bins.append(bin_analysis)
        
        return confidence_bins
    
    def _calculate_statistical_significance(self, validation_records: List[ValidationRecord]) -> Dict[str, Any]:
        """Calculate statistical significance of results."""
        significance_analysis = {
            'sample_size': len(validation_records),
            'is_statistically_significant': False,
            'confidence_interval': (0.0, 0.0),
            'p_value': 1.0,
            'effect_size': 0.0
        }
        
        if len(validation_records) < 30:
            significance_analysis['is_statistically_significant'] = False
            return significance_analysis
        
        # Calculate confidence interval for accuracy
        correct_predictions = sum(1 for r in validation_records if r.is_correct)
        accuracy = correct_predictions / len(validation_records)
        
        # Binomial confidence interval
        z_score = 1.96  # 95% confidence
        margin_of_error = z_score * math.sqrt(accuracy * (1 - accuracy) / len(validation_records))
        
        significance_analysis['confidence_interval'] = (
            max(0.0, accuracy - margin_of_error),
            min(1.0, accuracy + margin_of_error)
        )
        
        # Statistical significance test (comparing to random chance)
        if ML_AVAILABLE:
            try:
                # Binomial test against random chance (0.5)
                from scipy.stats import binom_test
                p_value = binom_test(correct_predictions, len(validation_records), 0.5)
                significance_analysis['p_value'] = p_value
                significance_analysis['is_statistically_significant'] = p_value < 0.05
                
                # Effect size (Cohen's d)
                effect_size = (accuracy - 0.5) / math.sqrt(0.5 * (1 - 0.5))
                significance_analysis['effect_size'] = effect_size
                
            except Exception as e:
                self.logger.warning(f"Statistical significance calculation failed: {e}")
        
        return significance_analysis
    
    def _create_validation_summary(self, 
                                 accuracy_metrics: AccuracyMetrics,
                                 calibration_analysis: Dict[str, Any],
                                 sample_size: int) -> Dict[str, Any]:
        """Create validation summary."""
        # Determine validation level
        validation_level = ConfidenceValidationLevel.UNACCEPTABLE
        for level, threshold in self.accuracy_thresholds.items():
            if accuracy_metrics.overall_accuracy >= threshold:
                validation_level = level
                break
        
        return {
            'validation_level': validation_level.value,
            'sample_size': sample_size,
            'overall_accuracy': accuracy_metrics.overall_accuracy,
            'is_well_calibrated': calibration_analysis.get('is_well_calibrated', False),
            'key_metrics': {
                'precision': accuracy_metrics.precision,
                'recall': accuracy_metrics.recall,
                'f1_score': accuracy_metrics.f1_score,
                'brier_score': accuracy_metrics.brier_score,
                'auc_score': accuracy_metrics.auc_score
            },
            'validation_timestamp': datetime.now().isoformat(),
            'requires_improvement': validation_level in [
                ConfidenceValidationLevel.POOR,
                ConfidenceValidationLevel.UNACCEPTABLE
            ]
        }
    
    def _calculate_calibration_error(self, predicted_probs: List[float], actual_outcomes: List[float]) -> float:
        """Calculate Expected Calibration Error (ECE)."""
        if not ML_AVAILABLE:
            return 0.0
        
        try:
            # Calculate ECE using calibration curve
            fraction_of_positives, mean_predicted_value = calibration_curve(
                actual_outcomes, predicted_probs, n_bins=10
            )
            
            # Calculate bin weights
            bin_boundaries = np.linspace(0, 1, 11)
            bin_weights = []
            
            for i in range(len(bin_boundaries) - 1):
                in_bin = [(bin_boundaries[i] <= p < bin_boundaries[i+1]) for p in predicted_probs]
                bin_weights.append(sum(in_bin) / len(predicted_probs))
            
            # Calculate ECE
            ece = sum(w * abs(acc - conf) for w, acc, conf in 
                     zip(bin_weights, fraction_of_positives, mean_predicted_value))
            
            return ece
            
        except Exception as e:
            self.logger.warning(f"Calibration error calculation failed: {e}")
            return 0.0
    
    def _calculate_reliability_score(self, predicted_probs: List[float], actual_outcomes: List[float]) -> float:
        """Calculate reliability score (1 - calibration error)."""
        calibration_error = self._calculate_calibration_error(predicted_probs, actual_outcomes)
        return max(0.0, 1.0 - calibration_error)
    
    def _calculate_sharpness_score(self, predicted_probs: List[float]) -> float:
        """Calculate sharpness score (variance of predictions)."""
        if not predicted_probs:
            return 0.0
        
        mean_prob = statistics.mean(predicted_probs)
        variance = statistics.variance(predicted_probs) if len(predicted_probs) > 1 else 0.0
        
        # Normalize to 0-1 scale
        max_variance = 0.25  # Maximum variance for uniform distribution
        return min(1.0, variance / max_variance)
    
    def _calculate_resolution_score(self, predicted_probs: List[float], actual_outcomes: List[float]) -> float:
        """Calculate resolution score (ability to discriminate)."""
        if not ML_AVAILABLE or len(set(actual_outcomes)) < 2:
            return 0.0
        
        try:
            # Use AUC as resolution measure
            auc = roc_auc_score(actual_outcomes, predicted_probs)
            # Convert to resolution score (distance from random)
            return 2 * abs(auc - 0.5)
        except Exception as e:
            self.logger.warning(f"Resolution score calculation failed: {e}")
            return 0.0
    
    def _calculate_confidence_distribution(self, validation_records: List[ValidationRecord]) -> Dict[str, int]:
        """Calculate confidence score distribution."""
        distribution = {
            '0.0-0.1': 0, '0.1-0.2': 0, '0.2-0.3': 0, '0.3-0.4': 0, '0.4-0.5': 0,
            '0.5-0.6': 0, '0.6-0.7': 0, '0.7-0.8': 0, '0.8-0.9': 0, '0.9-1.0': 0
        }
        
        for record in validation_records:
            conf = record.confidence_score
            
            if conf < 0.1:
                distribution['0.0-0.1'] += 1
            elif conf < 0.2:
                distribution['0.1-0.2'] += 1
            elif conf < 0.3:
                distribution['0.2-0.3'] += 1
            elif conf < 0.4:
                distribution['0.3-0.4'] += 1
            elif conf < 0.5:
                distribution['0.4-0.5'] += 1
            elif conf < 0.6:
                distribution['0.5-0.6'] += 1
            elif conf < 0.7:
                distribution['0.6-0.7'] += 1
            elif conf < 0.8:
                distribution['0.7-0.8'] += 1
            elif conf < 0.9:
                distribution['0.8-0.9'] += 1
            else:
                distribution['0.9-1.0'] += 1
        
        return distribution
    
    def _calculate_calibration_data(self, validation_records: List[ValidationRecord]) -> List[Tuple[float, float]]:
        """Calculate calibration data for plotting."""
        calibration_data = []
        
        for min_conf, max_conf in self.calibration_bins:
            bin_records = [
                r for r in validation_records 
                if min_conf <= r.confidence_score < max_conf
            ]
            
            if bin_records:
                mean_confidence = statistics.mean([r.confidence_score for r in bin_records])
                actual_rate = sum(1 for r in bin_records if r.actual_vulnerability) / len(bin_records)
                calibration_data.append((mean_confidence, actual_rate))
        
        return calibration_data
    
    def _create_empty_validation_result(self) -> ValidationResult:
        """Create empty validation result for no data."""
        empty_metrics = AccuracyMetrics(
            overall_accuracy=0.0, precision=0.0, recall=0.0, f1_score=0.0,
            brier_score=0.0, auc_score=0.5, calibration_error=0.0,
            reliability_score=0.0, sharpness_score=0.0, resolution_score=0.0,
            total_predictions=0, correct_predictions=0, false_positives=0, false_negatives=0
        )
        
        return ValidationResult(
            accuracy_metrics=empty_metrics,
            calibration_analysis={},
            improvement_recommendations=["No validation data available"],
            confidence_bins=[],
            statistical_significance={'sample_size': 0, 'is_statistically_significant': False},
            validation_summary={'validation_level': 'unacceptable', 'sample_size': 0}
        )

class CalibrationAnalyzer:
    """
    Advanced calibration analysis for confidence scores.
    """
    
    def __init__(self):
        """Initialize calibration analyzer."""
        self.logger = logging.getLogger(__name__)
    
    def analyze_calibration(self, validation_records: List[ValidationRecord]) -> Dict[str, Any]:
        """
        Perform comprehensive calibration analysis.
        
        Args:
            validation_records: List of validation records
            
        Returns:
            Comprehensive calibration analysis
        """
        if not validation_records:
            return {'status': 'no_data'}
        
        analysis = {
            'basic_calibration': self._basic_calibration_analysis(validation_records),
            'hosmer_lemeshow_test': self._hosmer_lemeshow_test(validation_records),
            'calibration_belt': self._calibration_belt_analysis(validation_records),
            'reliability_diagram': self._reliability_diagram_data(validation_records),
            'calibration_recommendations': self._calibration_recommendations(validation_records)
        }
        
        return analysis
    
    def _basic_calibration_analysis(self, validation_records: List[ValidationRecord]) -> Dict[str, Any]:
        """Basic calibration analysis."""
        if not ML_AVAILABLE:
            return {'status': 'ml_unavailable'}
        
        predicted_probs = [r.confidence_score for r in validation_records]
        actual_outcomes = [1.0 if r.actual_vulnerability else 0.0 for r in validation_records]
        
        try:
            fraction_of_positives, mean_predicted_value = calibration_curve(
                actual_outcomes, predicted_probs, n_bins=10
            )
            
            # Calculate calibration statistics
            calibration_errors = [abs(pred - actual) for pred, actual in 
                                zip(mean_predicted_value, fraction_of_positives)]
            
            return {
                'mean_calibration_error': statistics.mean(calibration_errors),
                'max_calibration_error': max(calibration_errors),
                'calibration_bins': len(mean_predicted_value),
                'fraction_of_positives': fraction_of_positives.tolist(),
                'mean_predicted_value': mean_predicted_value.tolist()
            }
            
        except Exception as e:
            self.logger.warning(f"Basic calibration analysis failed: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def _hosmer_lemeshow_test(self, validation_records: List[ValidationRecord]) -> Dict[str, Any]:
        """Hosmer-Lemeshow goodness-of-fit test."""
        if not ML_AVAILABLE or len(validation_records) < 50:
            return {'status': 'insufficient_data'}
        
        try:
            # Implementation of Hosmer-Lemeshow test
            # This is a simplified version - full implementation would be more complex
            
            predicted_probs = [r.confidence_score for r in validation_records]
            actual_outcomes = [1.0 if r.actual_vulnerability else 0.0 for r in validation_records]
            
            # Sort by predicted probability
            sorted_data = sorted(zip(predicted_probs, actual_outcomes), key=lambda x: x[0])
            
            # Create 10 groups
            n_groups = 10
            group_size = len(sorted_data) // n_groups
            
            chi_square = 0.0
            degrees_of_freedom = n_groups - 2
            
            for i in range(n_groups):
                start_idx = i * group_size
                end_idx = start_idx + group_size if i < n_groups - 1 else len(sorted_data)
                
                group_data = sorted_data[start_idx:end_idx]
                observed_positive = sum(outcome for _, outcome in group_data)
                expected_positive = sum(prob for prob, _ in group_data)
                
                group_size_actual = len(group_data)
                observed_negative = group_size_actual - observed_positive
                expected_negative = group_size_actual - expected_positive
                
                if expected_positive > 0 and expected_negative > 0:
                    chi_square += ((observed_positive - expected_positive) ** 2 / expected_positive +
                                 (observed_negative - expected_negative) ** 2 / expected_negative)
            
            # Calculate p-value (simplified)
            p_value = 1.0 - stats.chi2.cdf(chi_square, degrees_of_freedom)
            
            return {
                'chi_square_statistic': chi_square,
                'degrees_of_freedom': degrees_of_freedom,
                'p_value': p_value,
                'is_well_calibrated': p_value > 0.05
            }
            
        except Exception as e:
            self.logger.warning(f"Hosmer-Lemeshow test failed: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def _calibration_belt_analysis(self, validation_records: List[ValidationRecord]) -> Dict[str, Any]:
        """Calibration belt analysis for confidence intervals."""
        # Simplified calibration belt analysis
        # Full implementation would include confidence bands
        
        return {
            'status': 'not_implemented',
            'note': 'Calibration belt analysis requires advanced statistical methods'
        }
    
    def _reliability_diagram_data(self, validation_records: List[ValidationRecord]) -> Dict[str, Any]:
        """Generate data for reliability diagram."""
        if not ML_AVAILABLE:
            return {'status': 'ml_unavailable'}
        
        predicted_probs = [r.confidence_score for r in validation_records]
        actual_outcomes = [1.0 if r.actual_vulnerability else 0.0 for r in validation_records]
        
        try:
            fraction_of_positives, mean_predicted_value = calibration_curve(
                actual_outcomes, predicted_probs, n_bins=10
            )
            
            return {
                'predicted_probabilities': mean_predicted_value.tolist(),
                'actual_frequencies': fraction_of_positives.tolist(),
                'perfect_calibration_line': mean_predicted_value.tolist(),  # y=x line
                'sample_sizes': [len(predicted_probs) // 10] * len(mean_predicted_value)
            }
            
        except Exception as e:
            self.logger.warning(f"Reliability diagram data generation failed: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def _calibration_recommendations(self, validation_records: List[ValidationRecord]) -> List[str]:
        """Generate calibration improvement recommendations."""
        recommendations = []
        
        if len(validation_records) < 100:
            recommendations.append("Increase sample size for more reliable calibration analysis")
        
        # Analyze confidence distribution
        confidence_scores = [r.confidence_score for r in validation_records]
        
        if statistics.mean(confidence_scores) < 0.3:
            recommendations.append("Confidence scores appear too low - consider confidence boosting")
        elif statistics.mean(confidence_scores) > 0.8:
            recommendations.append("Confidence scores appear too high - consider confidence reduction")
        
        # Check for extreme confidence scores
        extreme_high = sum(1 for c in confidence_scores if c > 0.95)
        extreme_low = sum(1 for c in confidence_scores if c < 0.05)
        
        if extreme_high > len(confidence_scores) * 0.1:
            recommendations.append("Too many extremely high confidence scores - review confidence calculation")
        
        if extreme_low > len(confidence_scores) * 0.1:
            recommendations.append("Too many extremely low confidence scores - review confidence calculation")
        
        return recommendations

def validate_confidence_accuracy(validation_records: List[ValidationRecord],
                               time_window: Optional[timedelta] = None) -> ValidationResult:
    """
    Convenient function to validate confidence accuracy.
    
    Args:
        validation_records: List of validation records
        time_window: Optional time window for analysis
        
    Returns:
        ValidationResult with comprehensive analysis
    """
    validator = ConfidenceValidator()
    return validator.validate_confidence_accuracy(validation_records, time_window) 