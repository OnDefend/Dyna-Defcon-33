#!/usr/bin/env python3
"""
Enhanced False Positive Reduction - ML Classifier
=================================================

This module contains the machine learning classifier for enhanced false positive
reduction, targeting <2% false positive rate through ensemble learning and
explainable AI.

Features:
- Ensemble classifier with multiple algorithms
- Advanced feature extraction for secrets
- Model training and performance evaluation
- Explainable AI capabilities
- Model persistence and retraining

"""

import pickle
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from loguru import logger
from sklearn.ensemble import (
    GradientBoostingClassifier,
    RandomForestClassifier,
    VotingClassifier,
    AdaBoostClassifier
)
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score
)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from .data_structures import MLModelPerformance

class MLEnhancedSecretClassifier:
    """
    Advanced ML classifier for enhanced false positive reduction.
    Targets <2% false positive rate through ensemble learning and explainable AI.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ml_config = config.get("ml_enhancement", {})
        self.model_cache_dir = Path(self.ml_config.get("model_cache_dir", "models/ml_cache"))
        self.model_cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize ML components
        self.ensemble_classifier = None
        self.feature_vectorizer = None
        self.feature_scaler = None
        self.explainer = None
        self.performance_metrics = None
        
        # Initialize training data
        self.training_features = []
        self.training_labels = []
        self.feature_names = []
        
        self._initialize_ml_pipeline()
        
    def _initialize_ml_pipeline(self):
        """Initialize the ML pipeline with ensemble learning."""
        logger.info("Initializing ML-enhanced secret classification pipeline")
        
        # Create ensemble classifier targeting <2% false positive rate
        base_classifiers = [
            ('rf', RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                class_weight='balanced',
                random_state=42
            )),
            ('gb', GradientBoostingClassifier(
                n_estimators=50,
                learning_rate=0.1,
                max_depth=6,
                random_state=42
            )),
            ('lr', LogisticRegression(
                class_weight='balanced',
                random_state=42,
                max_iter=1000
            )),
            ('mlp', MLPClassifier(
                hidden_layer_sizes=(100, 50),
                alpha=0.01,
                random_state=42,
                max_iter=500
            ))
        ]
        
        # Create voting classifier with optimized weights for false positive reduction
        classifier_weights = [0.3, 0.3, 0.2, 0.2]  # Favor robust classifiers
        
        self.ensemble_classifier = VotingClassifier(
            estimators=base_classifiers,
            voting='soft',
            weights=classifier_weights
        )
        
        # Initialize feature extraction
        self.feature_vectorizer = TfidfVectorizer(
            max_features=2000,
            ngram_range=(1, 3),
            analyzer='char_wb',
            lowercase=True,
            min_df=2,
            max_df=0.95
        )
        
        self.feature_scaler = StandardScaler()
        
        # Try to load existing model
        self._load_existing_model()
        
        # If no model exists, train with default data
        if self.ensemble_classifier is None:
            logger.info("Training new ML model with default training data")
            self._train_with_default_data()

    def _load_existing_model(self):
        """Load existing trained model from disk."""
        model_path = self.model_cache_dir / "enhanced_secret_classifier.pkl"
        
        if not model_path.exists():
            logger.info("No existing ML model found")
            return False
        
        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.ensemble_classifier = model_data.get('classifier')
            self.feature_vectorizer = model_data.get('vectorizer')
            self.feature_scaler = model_data.get('scaler')
            self.performance_metrics = model_data.get('performance_metrics')
            
            logger.info(f"ML model loaded from {model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            return False

    def _train_with_default_data(self):
        """Train the model with default training data."""
        training_data = self._generate_training_data()
        self._train_model_with_data(training_data)

    def _generate_training_data(self) -> List[Dict[str, Any]]:
        """Generate comprehensive training data for the ML model."""
        training_data = []
        
        # True secrets (positive examples)
        true_secrets = [
            {'content': 'AKIAEXAMPLE1234567890', 'is_secret': True, 'context': 'aws configuration'},
            {'content': 'fake_test_1234567890abcdef', 'is_secret': True, 'context': 'stripe api key'},
            {'content': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'is_secret': True, 'context': 'jwt token'},
            {'content': 'github_1234567890abcdefghijklmnopqrstuvwx', 'is_secret': True, 'context': 'github token'},
            {'content': 'slack_1234567890_1234567890_abcdefghijklmnop', 'is_secret': True, 'context': 'slack bot token'},
            {'content': 'AIzaSyABC123DEF456GHI789JKL012MNO345PQR', 'is_secret': True, 'context': 'google api key'},
            {'content': 'fake_live_1234567890abcdefghijklmnopqrstuv', 'is_secret': True, 'context': 'live stripe key'},
        ]
        
        # False positives (negative examples)
        false_positives = [
            {'content': 'ThemeData.fallback', 'is_secret': False, 'context': 'flutter code'},
            {'content': 'http://schemas.android.com/apk/res/android', 'is_secret': False, 'context': 'android schema'},
            {'content': 'androidx.lifecycle.ViewModelProvider', 'is_secret': False, 'context': 'java import'},
            {'content': 'com.example.myapp.MainActivity', 'is_secret': False, 'context': 'package name'},
            {'content': '2.1.0-alpha01', 'is_secret': False, 'context': 'version number'},
            {'content': 'INTERNET', 'is_secret': False, 'context': 'permission'},
            {'content': 'YOUR_API_KEY_HERE', 'is_secret': False, 'context': 'placeholder'},
            {'content': 'example@example.com', 'is_secret': False, 'context': 'example email'},
            {'content': '127.0.0.1', 'is_secret': False, 'context': 'localhost ip'},
            {'content': 'password123', 'is_secret': False, 'context': 'test password'},
        ]
        
        training_data.extend(true_secrets)
        training_data.extend(false_positives)
        
        return training_data

    def _extract_ml_features(self, content: str, context: Optional[Dict[str, Any]] = None) -> np.ndarray:
        """Extract comprehensive features for ML classification."""
        features = []
        
        # Basic content features
        features.extend([
            len(content),                                    # Length
            len(set(content)),                              # Unique characters
            content.count('_'),                             # Underscores
            content.count('-'),                             # Hyphens
            content.count('.'),                             # Dots
            content.count('/'),                             # Slashes
            content.count('='),                             # Equals (base64)
            sum(c.isupper() for c in content),             # Uppercase
            sum(c.islower() for c in content),             # Lowercase
            sum(c.isdigit() for c in content),             # Digits
        ])
        
        # Entropy features
        features.extend([
            self._calculate_shannon_entropy(content),
            self._calculate_base64_entropy(content),
            self._calculate_hex_entropy(content),
        ])
        
        # Pattern matching features
        features.extend([
            1 if any(pattern in content.lower() for pattern in ['api', 'key', 'token', 'secret']) else 0,
            1 if any(pattern in content for pattern in ['AKIA', 'fake_', 'github_', 'slack_']) else 0,
            1 if content.startswith('ey') and len(content) > 20 else 0,  # JWT pattern
        ])
        
        # Context features
        if context:
            context_str = str(context).lower()
            features.extend([
                1 if 'test' in context_str else 0,
                1 if 'config' in context_str else 0,
                1 if any(word in context_str for word in ['example', 'placeholder']) else 0,
            ])
        else:
            features.extend([0, 0, 0])
        
        return np.array(features)

    def _calculate_shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of the content."""
        if not data:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        length = len(data)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy

    def _calculate_base64_entropy(self, data: str) -> float:
        """Calculate entropy assuming base64 encoding."""
        try:
            import base64
            if set(data) <= set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='):
                decoded = base64.b64decode(data + '==', validate=True)
                return self._calculate_shannon_entropy(decoded.decode('utf-8', errors='ignore'))
        except:
            pass
        return 0.0

    def _calculate_hex_entropy(self, data: str) -> float:
        """Calculate entropy assuming hex encoding."""
        if all(c in '0123456789abcdefABCDEF' for c in data):
            try:
                decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
                return self._calculate_shannon_entropy(decoded)
            except:
                pass
        return 0.0

    def predict_secret(self, content: str, context: Optional[Dict[str, Any]] = None) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Predict if content is a secret with confidence and explanation.
        
        Returns:
            Tuple of (is_secret, confidence, explanation_details)
        """
        if not self.ensemble_classifier:
            logger.warning("ML model not available, using rule-based fallback")
            return self._rule_based_prediction(content, context)
        
        try:
            # Extract features
            features = self._extract_ml_features(content, context)
            
            # Make prediction
            prediction = self.ensemble_classifier.predict([features])[0]
            prediction_proba = self.ensemble_classifier.predict_proba([features])[0]
            
            confidence = max(prediction_proba)
            is_secret = bool(prediction)
            
            # Generate explanation
            explanation = {
                'feature_importance': self._explain_prediction(features),
                'usage_pattern': self._determine_usage_pattern(content, context),
                'recommendation': self._generate_recommendation(prediction, confidence, 
                                                               self._determine_usage_pattern(content, context))
            }
            
            return is_secret, confidence, explanation
            
        except Exception as e:
            logger.error(f"ML prediction failed: {e}")
            return self._rule_based_prediction(content, context)

    def _rule_based_prediction(self, content: str, context: Optional[Dict[str, Any]] = None) -> Tuple[bool, float, Dict[str, Any]]:
        """Fallback rule-based prediction when ML is unavailable."""
        # Simple heuristics
        entropy = self._calculate_shannon_entropy(content)
        has_secret_patterns = any(pattern in content for pattern in ['AKIA', 'fake_', 'github_', 'slack_'])
        
        if has_secret_patterns and entropy > 4.0:
            return True, 0.8, {'method': 'rule_based', 'reason': 'high_entropy_with_patterns'}
        elif entropy > 5.0:
            return True, 0.6, {'method': 'rule_based', 'reason': 'high_entropy'}
        else:
            return False, 0.7, {'method': 'rule_based', 'reason': 'low_entropy_no_patterns'}

    def _explain_prediction(self, features: np.ndarray) -> Dict[str, float]:
        """Generate explanation for the prediction."""
        feature_names = [
            'length', 'unique_chars', 'underscores', 'hyphens', 'dots', 'slashes',
            'equals', 'uppercase', 'lowercase', 'digits', 'shannon_entropy',
            'base64_entropy', 'hex_entropy', 'has_secret_words', 'has_secret_patterns',
            'is_jwt_like', 'is_test_context', 'is_config_context', 'is_example_context'
        ]
        
        # Simple feature importance based on values
        importance = {}
        for i, name in enumerate(feature_names[:len(features)]):
            importance[name] = float(features[i])
        
        return importance

    def _determine_usage_pattern(self, content: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Determine the usage pattern of the potential secret."""
        if not context:
            return "unknown"
        
        context_str = str(context).lower()
        
        if any(word in context_str for word in ['test', 'mock', 'fake']):
            return "test_data"
        elif any(word in context_str for word in ['example', 'placeholder', 'your_', 'replace']):
            return "documentation"
        elif any(word in context_str for word in ['config', 'settings', 'properties']):
            return "configuration"
        elif any(word in context_str for word in ['api', 'key', 'token']):
            return "api_credential"
        else:
            return "production_secret"

    def _generate_recommendation(self, prediction: int, confidence: float, usage_pattern: str) -> str:
        """Generate actionable recommendation based on classification."""
        if not prediction:  # Not a secret
            if confidence > 0.9:
                return "Safe to ignore - high confidence non-secret"
            else:
                return "Likely safe but consider manual review if in sensitive context"
        else:  # Is a secret
            if usage_pattern == "test_data":
                return "Test data detected - verify it's not a real credential"
            elif usage_pattern == "documentation":
                return "Documentation example - ensure it's not a real secret"
            elif confidence > 0.9:
                return "HIGH RISK - Real secret detected with high confidence"
            else:
                return "Potential secret - manual review recommended"

    def _train_model_with_data(self, training_data: List[Dict[str, Any]]):
        """Train model with provided data."""
        features = []
        labels = []
        
        for sample in training_data:
            feature_vector = self._extract_ml_features(sample['content'], sample.get('context'))
            features.append(feature_vector)
            labels.append(1 if sample['is_secret'] else 0)
        
        X = np.array(features)
        y = np.array(labels)
        
        # Train the model
        self.ensemble_classifier.fit(X, y)
        
        # Update performance metrics
        self._evaluate_model_performance(X, y)
        
        # Save updated model
        self._save_model()

    def _evaluate_model_performance(self, X: np.ndarray, y: np.ndarray):
        """Evaluate model performance and update metrics."""
        # Use cross-validation for more robust evaluation
        cv_scores = cross_val_score(self.ensemble_classifier, X, y, cv=5, scoring='precision')
        
        # Get predictions for confusion matrix
        y_pred = self.ensemble_classifier.predict(X)
        
        # Calculate metrics
        tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
        
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        self.performance_metrics = MLModelPerformance(
            false_positive_rate=false_positive_rate,
            false_negative_rate=false_negative_rate,
            precision=precision_score(y, y_pred),
            recall=recall_score(y, y_pred),
            f1_score=f1_score(y, y_pred),
            accuracy=accuracy_score(y, y_pred),
            model_version="3.0.0",
            last_updated=time.strftime("%Y-%m-%d %H:%M:%S"),
            training_samples=len(X)
        )

    def _save_model(self):
        """Save the trained model to disk."""
        model_path = self.model_cache_dir / "enhanced_secret_classifier.pkl"
        
        model_data = {
            'classifier': self.ensemble_classifier,
            'vectorizer': self.feature_vectorizer,
            'scaler': self.feature_scaler,
            'performance_metrics': self.performance_metrics,
            'version': '3.0.0',
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        try:
            with open(model_path, 'wb') as f:
                pickle.dump(model_data, f)
            logger.info(f"ML model saved to {model_path}")
        except Exception as e:
            logger.error(f"Failed to save ML model: {e}")

    def get_performance_metrics(self) -> Optional[MLModelPerformance]:
        """Get current model performance metrics."""
        return self.performance_metrics

    def retrain_model(self, new_training_data: List[Dict[str, Any]]):
        """Retrain the model with new training data."""
        logger.info(f"Retraining ML model with {len(new_training_data)} new samples")
        
        # Add new data to existing training data
        existing_data = self._generate_training_data()
        combined_data = existing_data + new_training_data
        
        # Retrain with combined data
        self._train_model_with_data(combined_data) 