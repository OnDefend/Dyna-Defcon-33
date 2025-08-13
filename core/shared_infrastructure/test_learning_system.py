"""
Test Suite for AODS Learning System

Comprehensive tests for the learning system components including:
- Feature extraction and ML model integration
- Confidence calibration and validation tracking
- Pattern reliability learning and improvement
- Integration with existing confidence calculators
"""

import unittest
import tempfile
import shutil
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from .learning_system import (
    ConfidenceLearningSystem,
    FeatureExtractor,
    ConfidenceCalibrator,
    ConfidencePredictionFeatures,
    LearningMetrics
)
from .pattern_reliability_database import (
    PatternReliability,
    ValidationRecord,
    PatternReliabilityDatabase,
    create_validation_record
)
from .dependency_injection import AnalysisContext

class TestLearningSystem(unittest.TestCase):
    """Test suite for learning system functionality."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directory for test database
        self.test_dir = Path(tempfile.mkdtemp())
        self.db_path = self.test_dir / "test_reliability.db"
        
        # Create test analysis context
        self.context = AnalysisContext(
            apk_path=Path("test.apk"),
            config={
                'confidence': {
                    'enable_learning': True,
                    'enable_calibration': True,
                    'min_confidence': 0.1
                }
            }
        )
        
        # Initialize components
        self.reliability_db = PatternReliabilityDatabase(self.db_path)
        self.learning_system = ConfidenceLearningSystem(self.context)
        
        # Create test patterns
        self._create_test_patterns()
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def _create_test_patterns(self):
        """Create test patterns for testing."""
        patterns = [
            PatternReliability(
                pattern_id="crypto_weak_md5",
                pattern_name="Weak MD5 Usage",
                pattern_category="crypto",
                total_matches=100,
                true_positives=85,
                false_positives=15,
                true_negatives=80,
                false_negatives=5,
                accuracy_trend=[0.85, 0.87, 0.85, 0.88, 0.86]
            ),
            PatternReliability(
                pattern_id="storage_external",
                pattern_name="External Storage Usage",
                pattern_category="storage",
                total_matches=50,
                true_positives=40,
                false_positives=10,
                true_negatives=45,
                false_negatives=5,
                accuracy_trend=[0.80, 0.82, 0.85, 0.83, 0.84]
            ),
            PatternReliability(
                pattern_id="network_http",
                pattern_name="HTTP Usage",
                pattern_category="network",
                total_matches=75,
                true_positives=60,
                false_positives=15,
                true_negatives=70,
                false_negatives=10,
                accuracy_trend=[0.75, 0.78, 0.80, 0.82, 0.81]
            )
        ]
        
        for pattern in patterns:
            self.reliability_db.save_pattern_reliability(pattern)
    
    def test_feature_extraction(self):
        """Test feature extraction functionality."""
        feature_extractor = FeatureExtractor(self.reliability_db)
        
        # Test feature extraction with known pattern
        evidence = {
            'pattern_matches': [
                {'type': 'crypto', 'confidence': 0.8},
                {'type': 'crypto', 'confidence': 0.9}
            ],
            'validation_sources': ['static', 'dynamic'],
            'cross_validation_consistency': 0.85,
            'consistency_score': 0.8
        }
        
        context = {
            'file_type': 'java',
            'storage_location': 'internal',
            'app_context': 'production',
            'analysis_depth': 'thorough',
            'analysis_time_hours': 2
        }
        
        features = feature_extractor.extract_features("crypto_weak_md5", evidence, context)
        
        # Verify feature extraction
        self.assertIsInstance(features, ConfidencePredictionFeatures)
        self.assertGreater(features.pattern_reliability, 0.0)
        self.assertLessEqual(features.pattern_reliability, 1.0)
        self.assertEqual(features.validation_source_count, 2)
        self.assertEqual(features.cross_validation_consistency, 0.85)
        self.assertGreater(features.file_type_score, 0.0)
        
        # Test feature array conversion
        feature_array = features.to_array()
        self.assertEqual(len(feature_array), 19)  # All features
        self.assertTrue(all(isinstance(x, (int, float)) for x in feature_array))
    
    def test_confidence_calibration(self):
        """Test confidence calibration functionality."""
        calibrator = ConfidenceCalibrator(self.reliability_db)
        
        # Add calibration data
        test_data = [
            (0.9, True), (0.8, True), (0.7, False), (0.6, True),
            (0.5, False), (0.4, False), (0.3, False), (0.2, False),
            (0.95, True), (0.85, True), (0.75, True), (0.65, False)
        ]
        
        for confidence, outcome in test_data:
            calibrator.record_prediction(confidence, outcome)
        
        # Test calibration with insufficient data
        uncalibrated_confidence = 0.8
        calibrated = calibrator.calibrate_confidence(uncalibrated_confidence)
        self.assertEqual(calibrated, uncalibrated_confidence)  # Should return unchanged
        
        # Add more data to trigger calibration
        for i in range(50):
            calibrator.record_prediction(0.8, True if i % 2 == 0 else False)
        
        # Test calibration with sufficient data
        calibrated = calibrator.calibrate_confidence(0.8)
        self.assertIsInstance(calibrated, float)
        self.assertGreaterEqual(calibrated, 0.0)
        self.assertLessEqual(calibrated, 1.0)
        
        # Test calibration metrics
        metrics = calibrator.get_calibration_metrics()
        self.assertIn('brier_score', metrics)
        self.assertIn('overall_accuracy', metrics)
    
    def test_learning_system_integration(self):
        """Test full learning system integration."""
        # Test confidence prediction
        evidence = {
            'pattern_matches': [{'type': 'crypto', 'confidence': 0.8}],
            'validation_sources': ['static'],
            'cross_validation_consistency': 0.7
        }
        
        context = {
            'file_type': 'java',
            'storage_location': 'internal',
            'app_context': 'production'
        }
        
        confidence = self.learning_system.predict_confidence(
            "crypto_weak_md5", evidence, context
        )
        
        self.assertIsInstance(confidence, float)
        self.assertGreaterEqual(confidence, 0.0)
        self.assertLessEqual(confidence, 1.0)
        
        # Test validation recording
        self.learning_system.record_validation_result(
            pattern_id="crypto_weak_md5",
            finding_id="test_finding_1",
            predicted_confidence=confidence,
            actual_vulnerability=True,
            context=context
        )
        
        # Verify validation was recorded
        metrics = self.learning_system.get_learning_metrics()
        self.assertGreater(metrics.total_validations, 0)
    
    def test_ml_model_training(self):
        """Test ML model training functionality."""
        # Skip if ML dependencies not available
        try:
            from sklearn.ensemble import RandomForestRegressor
        except ImportError:
            self.skipTest("ML dependencies not available")
        
        # Create training data
        training_records = []
        for i in range(150):  # Enough for training
            record = create_validation_record(
                pattern_id="crypto_weak_md5",
                finding_id=f"test_finding_{i}",
                predicted_vulnerability=True,
                actual_vulnerability=i % 3 != 0,  # 2/3 true positive rate
                confidence_score=0.8 + (i % 10) * 0.02,
                context={'file_type': 'java', 'iteration': i}
            )
            self.reliability_db.record_validation(record)
        
        # Test model training
        self.learning_system._update_ml_model()
        
        # Verify model was trained
        if self.learning_system.ml_model:
            self.assertTrue(self.learning_system.model_trained)
            self.assertIsNotNone(self.learning_system.feature_scaler)
    
    def test_pattern_reliability_learning(self):
        """Test pattern reliability learning."""
        pattern_id = "crypto_weak_md5"
        original_pattern = self.reliability_db.get_pattern_reliability(pattern_id)
        original_reliability = original_pattern.reliability_score
        
        # Record several validation results
        validation_results = [
            (True, True),   # Correct positive
            (True, False),  # False positive
            (True, True),   # Correct positive
            (False, False), # Correct negative
            (True, True),   # Correct positive
        ]
        
        for i, (predicted, actual) in enumerate(validation_results):
            self.learning_system.record_validation_result(
                pattern_id=pattern_id,
                finding_id=f"learning_test_{i}",
                predicted_confidence=0.8 if predicted else 0.3,
                actual_vulnerability=actual,
                context={'test_iteration': i}
            )
        
        # Check that pattern reliability was updated
        updated_pattern = self.reliability_db.get_pattern_reliability(pattern_id)
        self.assertNotEqual(original_reliability, updated_pattern.reliability_score)
        self.assertGreater(updated_pattern.total_matches, original_pattern.total_matches)
    
    def test_learning_metrics(self):
        """Test learning metrics calculation."""
        # Record some validation results
        for i in range(10):
            self.learning_system.record_validation_result(
                pattern_id="crypto_weak_md5",
                finding_id=f"metrics_test_{i}",
                predicted_confidence=0.8,
                actual_vulnerability=i % 2 == 0,
                context={'test_case': i}
            )
        
        # Get metrics
        metrics = self.learning_system.get_learning_metrics()
        
        # Verify metrics structure
        self.assertIsInstance(metrics, LearningMetrics)
        self.assertGreaterEqual(metrics.overall_accuracy, 0.0)
        self.assertLessEqual(metrics.overall_accuracy, 1.0)
        self.assertGreater(metrics.total_validations, 0)
        self.assertIsInstance(metrics.last_updated, datetime)
        
        # Test metrics export
        metrics_dict = metrics.to_dict()
        self.assertIn('overall_accuracy', metrics_dict)
        self.assertIn('total_validations', metrics_dict)
    
    def test_confidence_prediction_features(self):
        """Test confidence prediction features."""
        features = ConfidencePredictionFeatures(
            pattern_reliability=0.85,
            pattern_age=30.0,
            validation_source_count=3,
            file_type_score=0.8
        )
        
        # Test feature array conversion
        feature_array = features.to_array()
        self.assertEqual(len(feature_array), 19)
        self.assertEqual(feature_array[0], 0.85)  # pattern_reliability
        self.assertEqual(feature_array[1], 30.0)  # pattern_age
        
        # Test feature names
        feature_names = ConfidencePredictionFeatures.get_feature_names()
        self.assertEqual(len(feature_names), 19)
        self.assertIn('pattern_reliability', feature_names)
        self.assertIn('validation_source_count', feature_names)
    
    def test_learning_system_export(self):
        """Test learning system data export."""
        # Record some data
        self.learning_system.record_validation_result(
            pattern_id="crypto_weak_md5",
            finding_id="export_test",
            predicted_confidence=0.8,
            actual_vulnerability=True
        )
        
        # Test export
        export_path = self.test_dir / "learning_export.json"
        self.learning_system.export_learning_data(export_path)
        
        # Verify export file
        self.assertTrue(export_path.exists())
        
        with open(export_path) as f:
            export_data = json.load(f)
        
        self.assertIn('metrics', export_data)
        self.assertIn('database_stats', export_data)
        self.assertIn('model_info', export_data)
    
    def test_edge_cases(self):
        """Test edge cases and error handling."""
        # Test with non-existent pattern
        confidence = self.learning_system.predict_confidence(
            "non_existent_pattern",
            {'validation_sources': []},
            {'file_type': 'unknown'}
        )
        self.assertIsInstance(confidence, float)
        self.assertGreaterEqual(confidence, 0.0)
        self.assertLessEqual(confidence, 1.0)
        
        # Test with empty evidence
        confidence = self.learning_system.predict_confidence(
            "crypto_weak_md5",
            {},
            {}
        )
        self.assertIsInstance(confidence, float)
        
        # Test with invalid data
        try:
            self.learning_system.record_validation_result(
                pattern_id="",  # Invalid pattern ID
                finding_id="test",
                predicted_confidence=1.5,  # Invalid confidence
                actual_vulnerability=True
            )
        except Exception:
            pass  # Expected to handle gracefully
    
    def test_performance(self):
        """Test learning system performance."""
        start_time = time.time()
        
        # Perform multiple predictions
        for i in range(100):
            confidence = self.learning_system.predict_confidence(
                "crypto_weak_md5",
                {'validation_sources': ['static']},
                {'file_type': 'java'}
            )
        
        end_time = time.time()
        avg_prediction_time = (end_time - start_time) / 100
        
        # Should be fast (< 10ms per prediction)
        self.assertLess(avg_prediction_time, 0.01)

class TestIntegrationWithExistingSystem(unittest.TestCase):
    """Test integration with existing confidence calculation system."""
    
    def setUp(self):
        """Set up integration test environment."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.context = AnalysisContext(
            apk_path=Path("test.apk"),
            config={'confidence': {'enable_learning': True}}
        )
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_integration_with_modular_plugins(self):
        """Test integration with modular plugin confidence systems."""
        # Mock a confidence calculator from our modular plugins
        from core.shared_infrastructure.learning_system import get_learning_system
        
        learning_system = get_learning_system(self.context)
        
        # Test that we can enhance existing confidence scores
        base_confidence = 0.7
        evidence = {
            'pattern_matches': [{'type': 'storage', 'confidence': 0.8}],
            'validation_sources': ['static', 'manifest']
        }
        context = {'file_type': 'xml', 'app_context': 'production'}
        
        enhanced_confidence = learning_system.predict_confidence(
            "storage_external", evidence, context
        )
        
        self.assertIsInstance(enhanced_confidence, float)
        self.assertGreaterEqual(enhanced_confidence, 0.0)
        self.assertLessEqual(enhanced_confidence, 1.0)

if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestLearningSystem))
    test_suite.addTest(unittest.makeSuite(TestIntegrationWithExistingSystem))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    if result.wasSuccessful():
        print("\n✅ All learning system tests passed!")
    else:
        print(f"\n❌ {len(result.failures)} test(s) failed, {len(result.errors)} error(s)")
        for test, error in result.failures + result.errors:
            print(f"  - {test}: {error}") 