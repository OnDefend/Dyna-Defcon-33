#!/usr/bin/env python3
"""
Enhanced False Positive Reducer for AODS
========================================

This module integrates multiple specialized libraries to achieve ultimate accuracy
in secret detection by eliminating false positives through advanced analysis:

1. High-quality secret detection (detect-secrets)
2. Advanced entropy analysis with multiple algorithms
3. Context-aware analysis with comprehensive API detection
4. Framework-specific pattern recognition
5. Rule-based filtering with machine learning
6. Performance-optimized analysis pipeline
7. ML-Enhanced false positive reduction (<2% target)
8. Context-aware secret analysis with usage pattern detection
9. Explainable AI for classification reasoning

"""

import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import time
# ADDED: Suppress publicsuffix2 deprecation warning (functionality still works correctly)
import warnings
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import chardet
import filetype
# Binary and file analysis
import magic
# Machine learning and data analysis
import numpy as np
import pandas as pd
# Text analysis and similarity
import regex

# Optional jellyfish import with fallback
try:
    import jellyfish
    JELLYFISH_AVAILABLE = True
except ImportError:
    JELLYFISH_AVAILABLE = False
    # Create fallback jellyfish functions
    class FallbackJellyfish:
        @staticmethod
        def jaro_winkler(s1, s2):
            """Fallback jaro_winkler using simple similarity."""
            # Simple character-based similarity fallback
            if not s1 or not s2:
                return 0.0
            s1_lower = s1.lower()
            s2_lower = s2.lower()
            if s1_lower == s2_lower:
                return 1.0
            # Simple character overlap similarity
            common_chars = set(s1_lower) & set(s2_lower)
            return len(common_chars) / max(len(set(s1_lower)), len(set(s2_lower)))
    
    jellyfish = FallbackJellyfish()
import textdistance
import tldextract
# URL/Domain validation
import validators
import yaml
# Performance optimization
from cachetools import TTLCache, cached
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    # Graceful fallback when pycryptodome is not available
    AES = None
    get_random_bytes = None
    CRYPTO_AVAILABLE = False
from cryptography.hazmat.backends import default_backend
# Cryptographic analysis
from cryptography.hazmat.primitives import hashes
# Enhanced secret detection and analysis
# Note: Using AODS local secret detection instead of external detect-secrets
# from detect_secrets import SecretsCollection
# from detect_secrets.core import baseline  
# from detect_secrets.settings import default_settings, transient_settings
from Levenshtein import distance as levenshtein_distance
from loguru import logger

warnings.filterwarnings(
    "ignore", message="This function returns the private suffix", category=UserWarning
)

from publicsuffix2 import get_public_suffix
# Configuration and logging
from pydantic import BaseModel, Field, validator
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.preprocessing import StandardScaler
# Data structures
from sortedcontainers import SortedDict, SortedSet

# NEW: Advanced ML imports for enhanced false positive reduction capabilities
from sklearn.ensemble import GradientBoostingClassifier, AdaBoostClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_curve
from sklearn.model_selection import cross_val_score, GridSearchCV
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
import joblib
import pickle

@dataclass
class SecretAnalysisResult:
    """Comprehensive analysis result for a potential secret."""

    content: str
    is_likely_secret: bool
    confidence_score: float
    analysis_details: Dict[str, Any] = field(default_factory=dict)
    false_positive_indicators: List[str] = field(default_factory=list)
    true_positive_indicators: List[str] = field(default_factory=list)
    file_context: Optional[str] = None
    line_number: Optional[int] = None
    context_analysis: Optional[Dict[str, Any]] = field(default_factory=dict)
    framework_classification: Optional[str] = None
    # NEW: Enhanced ML fields for technical reporting
    ml_confidence: Optional[float] = None
    explainable_features: Optional[Dict[str, float]] = field(default_factory=dict)
    usage_pattern: Optional[str] = None
    risk_assessment: Optional[Dict[str, Any]] = field(default_factory=dict)
    recommendation: Optional[str] = None

@dataclass
class ContextAnalysisResult:
    """Result of context analysis around a potential secret."""

    apis_found: List[str] = field(default_factory=list)
    context_score: float = 0.0
    context_type: Optional[str] = None
    confidence_adjustment: float = 0.0
    analysis_radius: int = 0
    method_context: Optional[str] = None
    # NEW: Enhanced context fields
    usage_patterns: List[str] = field(default_factory=list)
    security_context: Optional[str] = None
    framework_context: Optional[str] = None

@dataclass
class MLModelPerformance:
    """ML model performance metrics for monitoring."""
    false_positive_rate: float
    false_negative_rate: float
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    model_version: str
    last_updated: str
    training_samples: int

class MLEnhancedSecretClassifier:
    """
    NEW CLASS: Advanced ML classifier for enhanced false positive reduction.
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
        
        # Use voting classifier with soft voting for probability estimates
        self.ensemble_classifier = VotingClassifier(
            estimators=base_classifiers,
            voting='soft'
        )
        
        # Initialize feature extraction pipeline
        self.feature_vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            analyzer='char_wb'
        )
        
        self.feature_scaler = StandardScaler()
        
        # Load existing model if available
        self._load_existing_model()
        
    def _load_existing_model(self):
        """Load existing trained model if available."""
        model_path = self.model_cache_dir / "enhanced_secret_classifier.pkl"
        
        if model_path.exists():
            try:
                with open(model_path, 'rb') as f:
                    model_data = pickle.load(f)
                    
                self.ensemble_classifier = model_data['classifier']
                self.feature_vectorizer = model_data['vectorizer']
                self.feature_scaler = model_data['scaler']
                self.performance_metrics = model_data.get('performance_metrics')
                
                logger.info(f"Loaded existing ML model with {self.performance_metrics.false_positive_rate:.1%} FP rate")
                
            except Exception as e:
                logger.warning(f"Failed to load existing model: {e}")
                self._train_initial_model()
        else:
            self._train_initial_model()
    
    def _train_initial_model(self):
        """Train initial model with synthetic and real data."""
        logger.info("Training initial ML model for enhanced secret detection")
        
        # Generate synthetic training data
        training_data = self._generate_training_data()
        
        if len(training_data) < 100:
            logger.warning("Insufficient training data, using rule-based fallback")
            return
        
        # Extract features and labels
        features = []
        labels = []
        
        for sample in training_data:
            feature_vector = self._extract_ml_features(sample['content'], sample.get('context'))
            features.append(feature_vector)
            labels.append(1 if sample['is_secret'] else 0)
        
        # Convert to numpy arrays
        X = np.array(features)
        y = np.array(labels)
        
        # Split training and validation data
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train the ensemble classifier
        self.ensemble_classifier.fit(X_train, y_train)
        
        # Evaluate performance
        y_pred = self.ensemble_classifier.predict(X_val)
        y_pred_proba = self.ensemble_classifier.predict_proba(X_val)[:, 1]
        
        # Calculate performance metrics
        from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
        
        # Calculate false positive rate (critical metric)
        tn = np.sum((y_val == 0) & (y_pred == 0))
        fp = np.sum((y_val == 0) & (y_pred == 1))
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        # Calculate false negative rate
        fn = np.sum((y_val == 1) & (y_pred == 0))
        tp = np.sum((y_val == 1) & (y_pred == 1))
        false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        self.performance_metrics = MLModelPerformance(
            false_positive_rate=false_positive_rate,
            false_negative_rate=false_negative_rate,
            precision=precision_score(y_val, y_pred),
            recall=recall_score(y_val, y_pred),
            f1_score=f1_score(y_val, y_pred),
            accuracy=accuracy_score(y_val, y_pred),
            model_version="3.0.0",
            last_updated=time.strftime("%Y-%m-%d %H:%M:%S"),
            training_samples=len(training_data)
        )
        
        logger.info(f"Model trained - FP Rate: {false_positive_rate:.1%}, Precision: {self.performance_metrics.precision:.1%}")
        
        # Save the trained model
        self._save_model()
        
    def _generate_training_data(self) -> List[Dict[str, Any]]:
        """Generate comprehensive synthetic training data for model training."""
        training_data = []
        
        # True secrets (positive examples) - Expanded to 60+ samples
        true_secrets = [
            # API Keys (20 samples)
            {"content": "fake_live_abcdefghijklmnopqrstuvwxyz123456", "is_secret": True, "type": "stripe_api_key"},
            {"content": "fake_test_1234567890abcdefghijklmnopqr", "is_secret": True, "type": "stripe_api_key"},
            {"content": "AKIA1234567890ABCDEF", "is_secret": True, "type": "aws_access_key"},
            {"content": "AKIAI44QH8DHBEXAMPLE", "is_secret": True, "type": "aws_access_key"},
            {"content": "github_1234567890abcdefghijklmnopqrstuvwxyz", "is_secret": True, "type": "github_token"},
            {"content": "gho_16C7e42F292c6912E7710c838347Ae178B4a", "is_secret": True, "type": "github_token"},
            {"content": "AIzaSyDaGmWKa4JsXZ-HjGw7ISLan_PiVMarGJY", "is_secret": True, "type": "google_api_key"},
            {"content": "ya29.Gl0pB9FKpk_YEHtJJmtQpQqVZTf1X2Wy", "is_secret": True, "type": "google_oauth"},
            {"content": "pk_live_abcdefghijklmnopqrstuvwxyz123456", "is_secret": True, "type": "stripe_publishable"},
            {"content": "rk_live_1234567890abcdefghijklmnopqr", "is_secret": True, "type": "stripe_restricted"},
            {"content": "slack_1234567890_1234567890_abcdefghijklmnopqrstuvwx", "is_secret": True, "type": "slack_bot_token"},
            {"content": "slack_user_1234567890_1234567890_1234567890_abcdef", "is_secret": True, "type": "slack_user_token"},
            {"content": "1234567890:AAEhBP0ev3rQhokMtC2ZaF8l0AAAAAAAAA", "is_secret": True, "type": "telegram_bot_token"},
            {"content": "fb_app_1234567890|abcdefghijklmnopqrstuvwxyz", "is_secret": True, "type": "facebook_app_token"},
            {"content": "EAACEdEose0cBA1234567890abcdefghijklmnopqr", "is_secret": True, "type": "facebook_access_token"},
            {"content": "ya29.Gl0oBsf2qEHOz_GzujqB3_k9Fv3mJ2YYs", "is_secret": True, "type": "google_oauth2"},
            {"content": "fake_test_4eC39HqLyjWDarjtT1zdp7dc", "is_secret": True, "type": "stripe_key"},
            {"content": "AKIA3SGQVQG7REXAMPLE", "is_secret": True, "type": "aws_access_key"},
            {"content": "1234567890abcdefghijklmnopqrstuvwxyz123456", "is_secret": True, "type": "generic_api_key"},
            {"content": "Bearer abcdefghijklmnopqrstuvwxyz1234567890", "is_secret": True, "type": "bearer_token"},
            
            # Database connections (15 samples)
            {"content": "mongodb://user:pass123@cluster.mongodb.net/db", "is_secret": True, "type": "db_connection"},
            {"content": "postgres://admin:secret123@db.example.com:5432/prod", "is_secret": True, "type": "db_connection"},
            {"content": "mysql://root:password@localhost:3306/database", "is_secret": True, "type": "db_connection"},
            {"content": "redis://user:password@redis.example.com:6379", "is_secret": True, "type": "db_connection"},
            {"content": "Server=tcp:server.database.windows.net;Database=db;User=admin;Password=secret123;", "is_secret": True, "type": "db_connection"},
            {"content": "Driver={SQL Server};Server=server;Database=db;Uid=user;Pwd=pass123;", "is_secret": True, "type": "db_connection"},
            {"content": "jdbc:postgresql://localhost:5432/db?user=admin&password=secret", "is_secret": True, "type": "db_connection"},
            {"content": "mongodb+srv://user:password@cluster.mongodb.net/database", "is_secret": True, "type": "db_connection"},
            {"content": "cassandra://user:pass@cassandra.example.com:9042/keyspace", "is_secret": True, "type": "db_connection"},
            {"content": "neo4j://user:password@neo4j.example.com:7687", "is_secret": True, "type": "db_connection"},
            {"content": "elasticsearch://elastic:changeme@localhost:9200", "is_secret": True, "type": "db_connection"},
            {"content": "influxdb://user:password@influx.example.com:8086/database", "is_secret": True, "type": "db_connection"},
            {"content": "couchbase://user:password@couchbase.example.com/bucket", "is_secret": True, "type": "db_connection"},
            {"content": "sqlite:///path/to/database.db?key=encryption_key", "is_secret": True, "type": "db_connection"},
            {"content": "oracle://user:password@oracle.example.com:1521/service", "is_secret": True, "type": "db_connection"},
            
            # JWT tokens (10 samples)
            {"content": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "is_secret": True, "type": "jwt_token"},
            {"content": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJleGFtcGxlLmNvbSIsImF1ZCI6ImV4YW1wbGUuY29tIiwic3ViIjoidXNlciIsImV4cCI6MTYxNjE2MTYxNn0", "is_secret": True, "type": "jwt_token"},
            {"content": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXVkIjoiYXBpLmV4YW1wbGUuY29tIn0", "is_secret": True, "type": "jwt_token"},
            {"content": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9", "is_secret": True, "type": "jwt_token"},
            {"content": "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9", "is_secret": True, "type": "jwt_token"},
            {"content": "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9", "is_secret": True, "type": "jwt_token"},
            {"content": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9", "is_secret": True, "type": "jwt_token"},
            {"content": "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9", "is_secret": True, "type": "jwt_token"},
            {"content": "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9", "is_secret": True, "type": "jwt_token"},
            {"content": "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9", "is_secret": True, "type": "jwt_token"},
            
            # Private keys (10 samples)
            {"content": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC", "is_secret": True, "type": "private_key"},
            {"content": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAuGbXWiK3dQTyCbX5xdE4yCuYp0ggugno", "is_secret": True, "type": "rsa_private_key"},
            {"content": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIIrYSSNdIIhp7ISzOi4+7w8cLqggJcKCONmnzEPq", "is_secret": True, "type": "ec_private_key"},
            {"content": "-----BEGIN DSA PRIVATE KEY-----\nMIIBugIBAAKBgQC3VwqCGkpUO2KeFlCvpFEHHnACm6M4j6+V", "is_secret": True, "type": "dsa_private_key"},
            {"content": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAA", "is_secret": True, "type": "openssh_private_key"},
            {"content": "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v1\n\nlQOYBFXuw3gBCAC8Q4gp", "is_secret": True, "type": "pgp_private_key"},
            {"content": "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEB", "is_secret": True, "type": "certificate"},
            {"content": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI", "is_secret": True, "type": "encrypted_private_key"},
            {"content": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDw+HdN", "is_secret": True, "type": "ssh_public_key"},
            {"content": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4rT3vTt99Ox5H5N", "is_secret": True, "type": "ssh_ed25519_key"},
            
            # Passwords and secrets (10 samples)
            {"content": "password123!", "is_secret": True, "type": "password"},
            {"content": "MySecretPassword2023", "is_secret": True, "type": "password"},
            {"content": "admin123", "is_secret": True, "type": "password"},
            {"content": "P@ssw0rd!", "is_secret": True, "type": "password"},
            {"content": "secretkey123", "is_secret": True, "type": "secret_key"},
            {"content": "encryption_key_12345", "is_secret": True, "type": "encryption_key"},
            {"content": "signing_secret_abcd1234", "is_secret": True, "type": "signing_secret"},
            {"content": "webhook_secret_xyz789", "is_secret": True, "type": "webhook_secret"},
            {"content": "session_secret_qwerty123", "is_secret": True, "type": "session_secret"},
            {"content": "csrf_token_abcdef123456", "is_secret": True, "type": "csrf_token"},
        ]
        
        # False positives (negative examples) - Expanded to 60+ samples
        false_positives = [
            # Documentation examples (15 samples)
            {"content": "your_api_key_here", "is_secret": False, "type": "placeholder"},
            {"content": "fake_test_example_key_123", "is_secret": False, "type": "example"},
            {"content": "AKIA_EXAMPLE_KEY_123", "is_secret": False, "type": "example"},
            {"content": "replace_with_your_key", "is_secret": False, "type": "placeholder"},
            {"content": "insert_api_key_here", "is_secret": False, "type": "placeholder"},
            {"content": "your_secret_key", "is_secret": False, "type": "placeholder"},
            {"content": "example_token_123", "is_secret": False, "type": "example"},
            {"content": "dummy_password", "is_secret": False, "type": "example"},
            {"content": "test_key_placeholder", "is_secret": False, "type": "placeholder"},
            {"content": "sample_api_key", "is_secret": False, "type": "example"},
            {"content": "YOUR_API_KEY", "is_secret": False, "type": "placeholder"},
            {"content": "API_KEY_HERE", "is_secret": False, "type": "placeholder"},
            {"content": "SECRET_TOKEN", "is_secret": False, "type": "placeholder"},
            {"content": "REPLACE_ME", "is_secret": False, "type": "placeholder"},
            {"content": "CHANGE_THIS", "is_secret": False, "type": "placeholder"},
            
            # Configuration templates (15 samples)
            {"content": "database_url=your_database_url_here", "is_secret": False, "type": "template"},
            {"content": "api_secret=<your-secret-here>", "is_secret": False, "type": "template"},
            {"content": "password=${PASSWORD}", "is_secret": False, "type": "template"},
            {"content": "token={{API_TOKEN}}", "is_secret": False, "type": "template"},
            {"content": "key=%API_KEY%", "is_secret": False, "type": "template"},
            {"content": "secret=$SECRET_KEY", "is_secret": False, "type": "template"},
            {"content": "url=http://example.com", "is_secret": False, "type": "template"},
            {"content": "host=localhost", "is_secret": False, "type": "template"},
            {"content": "port=8080", "is_secret": False, "type": "template"},
            {"content": "debug=true", "is_secret": False, "type": "template"},
            {"content": "enabled=false", "is_secret": False, "type": "template"},
            {"content": "timeout=30", "is_secret": False, "type": "template"},
            {"content": "max_connections=100", "is_secret": False, "type": "template"},
            {"content": "log_level=info", "is_secret": False, "type": "template"},
            {"content": "environment=development", "is_secret": False, "type": "template"},
            
            # Test data (15 samples)
            {"content": "test_key_12345", "is_secret": False, "type": "test_data"},
            {"content": "mock_secret_value", "is_secret": False, "type": "test_data"},
            {"content": "dummy_token", "is_secret": False, "type": "test_data"},
            {"content": "fake_api_key", "is_secret": False, "type": "test_data"},
            {"content": "test_password", "is_secret": False, "type": "test_data"},
            {"content": "mock_jwt_token", "is_secret": False, "type": "test_data"},
            {"content": "sample_hash", "is_secret": False, "type": "test_data"},
            {"content": "test_string_123", "is_secret": False, "type": "test_data"},
            {"content": "example_data", "is_secret": False, "type": "test_data"},
            {"content": "unit_test_key", "is_secret": False, "type": "test_data"},
            {"content": "integration_test_token", "is_secret": False, "type": "test_data"},
            {"content": "mock_response", "is_secret": False, "type": "test_data"},
            {"content": "test_payload", "is_secret": False, "type": "test_data"},
            {"content": "sample_request", "is_secret": False, "type": "test_data"},
            {"content": "dummy_response", "is_secret": False, "type": "test_data"},
            
            # Android/Framework specific (15 samples)
            {"content": "android.permission.INTERNET", "is_secret": False, "type": "android_permission"},
            {"content": "com.google.android.gms", "is_secret": False, "type": "android_package"},
            {"content": "BuildConfig.DEBUG", "is_secret": False, "type": "android_build"},
            {"content": "R.string.app_name", "is_secret": False, "type": "android_resource"},
            {"content": "androidx.appcompat.app.AppCompatActivity", "is_secret": False, "type": "android_class"},
            {"content": "Log.d(TAG, message)", "is_secret": False, "type": "android_logging"},
            {"content": "System.out.println(debug)", "is_secret": False, "type": "debug_output"},
            {"content": "Toast.makeText(context, text)", "is_secret": False, "type": "android_ui"},
            {"content": "getSystemService(Context.LOCATION_SERVICE)", "is_secret": False, "type": "android_service"},
            {"content": "okhttp3.OkHttpClient", "is_secret": False, "type": "library_class"},
            {"content": "retrofit2.Retrofit", "is_secret": False, "type": "library_class"},
            {"content": "com.google.firebase.FirebaseApp", "is_secret": False, "type": "firebase_class"},
            {"content": "gson.toJson(object)", "is_secret": False, "type": "library_method"},
            {"content": "volley.RequestQueue", "is_secret": False, "type": "library_class"},
            {"content": "glide.with(context).load(url)", "is_secret": False, "type": "library_method"},
            
            # Random/innocent strings (10 samples)
            {"content": "abcdefghijklmnopqrstuvwxyz123456", "is_secret": False, "type": "random"},
            {"content": "1234567890abcdefghijklmnopqrstuvwxyz", "is_secret": False, "type": "random"},
            {"content": "hello_world_application", "is_secret": False, "type": "identifier"},
            {"content": "my_awesome_feature", "is_secret": False, "type": "identifier"},
            {"content": "user_profile_manager", "is_secret": False, "type": "identifier"},
            {"content": "data_processing_service", "is_secret": False, "type": "identifier"},
            {"content": "authentication_handler", "is_secret": False, "type": "identifier"},
            {"content": "network_request_builder", "is_secret": False, "type": "identifier"},
            {"content": "image_loading_utility", "is_secret": False, "type": "identifier"},
            {"content": "background_task_executor", "is_secret": False, "type": "identifier"},
        ]
        
        training_data.extend(true_secrets)
        training_data.extend(false_positives)
        
        # Add context information
        for sample in training_data:
            sample['context'] = {
                'file_type': 'java',
                'framework': 'android',
                'line_context': f"String secret = \"{sample['content']}\";"
            }
        
        return training_data
    
    def _extract_ml_features(self, content: str, context: Optional[Dict[str, Any]] = None) -> np.ndarray:
        """Extract ML features from content and context."""
        features = []
        
        # Basic content features
        features.extend([
            len(content),                              # Length
            len(set(content)),                         # Unique characters
            content.count('_'),                        # Underscores
            content.count('-'),                        # Hyphens
            sum(c.isupper() for c in content),        # Uppercase count
            sum(c.islower() for c in content),        # Lowercase count
            sum(c.isdigit() for c in content),        # Digit count
            sum(c.isalnum() for c in content),        # Alphanumeric count
        ])
        
        # Entropy features
        features.append(self._calculate_shannon_entropy(content))
        
        # Pattern features
        features.extend([
            1 if re.search(r'^fake_', content) else 0,           # Stripe pattern
            1 if re.search(r'^AKIA', content) else 0,             # AWS pattern
            1 if re.search(r'^github_', content) else 0,         # GitHub pattern
            1 if re.search(r'BEGIN.*KEY', content) else 0,        # Private key pattern
            1 if content.count('.') == 2 else 0,                  # JWT pattern
        ])
        
        # Context features
        if context:
            features.extend([
                1 if 'test' in str(context).lower() else 0,
                1 if 'example' in str(context).lower() else 0,
                1 if 'placeholder' in str(context).lower() else 0,
                1 if 'mock' in str(context).lower() else 0,
            ])
        else:
            features.extend([0, 0, 0, 0])
        
        return np.array(features, dtype=float)
    
    def _calculate_shannon_entropy(self, content: str) -> float:
        """Calculate Shannon entropy of content."""
        if not content:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in content:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        content_length = len(content)
        
        for count in char_counts.values():
            probability = count / content_length
            entropy -= probability * np.log2(probability)
        
        return entropy
    
    def classify_with_ml(self, content: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Classify content using ML with explainable features."""
        if not self.ensemble_classifier:
            # Fallback to rule-based classification
            return self._rule_based_classification(content, context)
        
        # Extract features
        features = self._extract_ml_features(content, context).reshape(1, -1)
        
        # Get prediction and probability
        prediction = self.ensemble_classifier.predict(features)[0]
        probabilities = self.ensemble_classifier.predict_proba(features)[0]
        
        # Calculate confidence (probability of predicted class)
        confidence = probabilities[prediction]
        
        # Generate explainable features
        explainable_features = self._generate_feature_explanations(features[0], content)
        
        # Determine usage pattern
        usage_pattern = self._determine_usage_pattern(content, context)
        
        # Generate recommendation
        recommendation = self._generate_recommendation(prediction, confidence, usage_pattern)
        
        return {
            'is_secret': bool(prediction),
            'ml_confidence': float(confidence),
            'probabilities': {
                'not_secret': float(probabilities[0]),
                'is_secret': float(probabilities[1])
            },
            'explainable_features': explainable_features,
            'usage_pattern': usage_pattern,
            'recommendation': recommendation,
            'model_version': self.performance_metrics.model_version if self.performance_metrics else "fallback"
        }
    
    def _rule_based_classification(self, content: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Fallback rule-based classification when ML model is not available."""
        # Simple rule-based logic
        is_secret = (
            len(content) > 10 and
            self._calculate_shannon_entropy(content) > 3.5 and
            not any(word in content.lower() for word in ['test', 'example', 'placeholder', 'mock'])
        )
        
        confidence = 0.7 if is_secret else 0.8
        
        return {
            'is_secret': is_secret,
            'ml_confidence': confidence,
            'probabilities': {'not_secret': 1-confidence if is_secret else confidence, 'is_secret': confidence if is_secret else 1-confidence},
            'explainable_features': {'rule_based': 1.0},
            'usage_pattern': 'unknown',
            'recommendation': 'Manual review recommended (rule-based fallback)',
            'model_version': 'rule_based_fallback'
        }
    
    def _generate_feature_explanations(self, features: np.ndarray, content: str) -> Dict[str, float]:
        """Generate explanations for ML features."""
        feature_names = [
            'content_length', 'unique_chars', 'underscores', 'hyphens',
            'uppercase_count', 'lowercase_count', 'digit_count', 'alphanumeric_count',
            'shannon_entropy', 'stripe_pattern', 'aws_pattern', 'github_pattern',
            'private_key_pattern', 'jwt_pattern', 'test_context', 'example_context',
            'placeholder_context', 'mock_context'
        ]
        
        explanations = {}
        for i, (name, value) in enumerate(zip(feature_names, features)):
            if i < len(feature_names):
                explanations[name] = float(value)
        
        return explanations
    
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
        from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, confusion_matrix
        
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

class EnhancedContextAnalyzer:
    """Advanced context analyzer for comprehensive API detection."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize context analyzer with configuration."""
        self.config = config
        self.context_config = config.get("context_analysis", {})
        self.api_patterns = self._compile_api_patterns()
        self.analysis_cache = TTLCache(maxsize=5000, ttl=1800)  # 30 min cache
        
        # NEW: Initialize ML classifier for context analysis
        self.ml_classifier = MLEnhancedSecretClassifier(config)

    def _compile_api_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile API patterns for efficient matching."""
        patterns = {}
        required_apis = self.context_config.get("required_context_apis", {})

        for category, apis in required_apis.items():
            patterns[category] = [
                re.compile(rf"\b{re.escape(api)}\b", re.IGNORECASE) for api in apis
            ]

        return patterns

    @cached(cache=TTLCache(maxsize=5000, ttl=1800))
    def analyze_context(
        self,
        content: str,
        file_content: Optional[str] = None,
        line_number: Optional[int] = None,
    ) -> ContextAnalysisResult:
        """Analyze context around a potential secret with ML enhancement."""

        if not file_content:
            return ContextAnalysisResult()

        radius = self.context_config.get("api_proximity_radius", 7)

        # Extract context window around the finding
        context_window = self._extract_context_window(
            file_content, content, line_number, radius
        )

        # Analyze APIs in context
        apis_found = self._find_apis_in_context(context_window)

        # Calculate context score
        context_score = self._calculate_context_score(apis_found)

        # Determine context type
        context_type = self._determine_context_type(apis_found)

        # Calculate confidence adjustment
        confidence_adjustment = self._calculate_confidence_adjustment(
            context_score, apis_found
        )
        
        # NEW: Enhanced context analysis with usage patterns
        usage_patterns = self._analyze_usage_patterns(context_window, content)
        security_context = self._determine_security_context(context_window)
        framework_context = self._determine_framework_context(file_content)

        return ContextAnalysisResult(
            apis_found=apis_found,
            context_score=context_score,
            context_type=context_type,
            confidence_adjustment=confidence_adjustment,
            analysis_radius=radius,
            method_context=context_type,
            usage_patterns=usage_patterns,
            security_context=security_context,
            framework_context=framework_context
        )
    
    def _analyze_usage_patterns(self, context_window: str, content: str) -> List[str]:
        """NEW METHOD: Analyze usage patterns in the context."""
        patterns = []
        
        context_lower = context_window.lower()
        
        # Check for test patterns
        if any(word in context_lower for word in ['test', 'mock', 'fake', 'dummy']):
            patterns.append("test_usage")
        
        # Check for configuration patterns
        if any(word in context_lower for word in ['config', 'settings', 'properties']):
            patterns.append("configuration")
        
        # Check for API usage patterns
        if any(word in context_lower for word in ['api', 'request', 'http', 'curl']):
            patterns.append("api_usage")
        
        # Check for database patterns
        if any(word in context_lower for word in ['database', 'db', 'connection', 'jdbc']):
            patterns.append("database_usage")
        
        # Check for documentation patterns
        if any(word in context_lower for word in ['example', 'placeholder', 'your_', 'replace']):
            patterns.append("documentation")
        
        return patterns
    
    def _determine_security_context(self, context_window: str) -> Optional[str]:
        """NEW METHOD: Determine security context of the finding."""
        context_lower = context_window.lower()
        
        if any(word in context_lower for word in ['encrypt', 'decrypt', 'cipher', 'crypto']):
            return "cryptographic"
        elif any(word in context_lower for word in ['auth', 'login', 'password', 'credential']):
            return "authentication"
        elif any(word in context_lower for word in ['token', 'jwt', 'bearer', 'oauth']):
            return "authorization"
        elif any(word in context_lower for word in ['key', 'secret', 'private', 'public']):
            return "key_management"
        else:
            return "general"
    
    def _determine_framework_context(self, file_content: Optional[str]) -> Optional[str]:
        """NEW METHOD: Determine framework context from file content."""
        if not file_content:
            return None
        
        content_lower = file_content.lower()
        
        # Android framework detection
        if any(word in content_lower for word in ['android', 'activity', 'intent', 'bundle']):
            return "android"
        
        # Spring framework detection
        if any(word in content_lower for word in ['@controller', '@service', '@component', 'springframework']):
            return "spring"
        
        # React/JavaScript detection
        if any(word in content_lower for word in ['react', 'usestate', 'useeffect', 'component']):
            return "react"
        
        # Node.js detection
        if any(word in content_lower for word in ['require(', 'module.exports', 'process.env']):
            return "nodejs"
        
        return "unknown"

    def _extract_context_window(
        self, file_content: str, secret: str, line_number: Optional[int], radius: int
    ) -> str:
        """Extract context window around the secret."""

        if line_number:
            lines = file_content.split("\n")
            start_line = max(0, line_number - radius)
            end_line = min(len(lines), line_number + radius)
            return "\n".join(lines[start_line:end_line])
        else:
            # Find secret in content and extract surrounding context
            secret_pos = file_content.find(secret)
            if secret_pos == -1:
                return file_content[:2000]  # First 2KB as fallback

            start_pos = max(0, secret_pos - 1000)
            end_pos = min(len(file_content), secret_pos + 1000)
            return file_content[start_pos:end_pos]

    def _find_apis_in_context(self, context: str) -> List[str]:
        """Find APIs in the context window."""
        apis_found = []

        for category, patterns in self.api_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(context)
                for match in matches:
                    if match not in apis_found:
                        apis_found.append(match)

        return apis_found

    def _calculate_context_score(self, apis_found: List[str]) -> float:
        """Calculate context score based on APIs found."""
        if not apis_found:
            return 0.0

        # Weight different API categories
        category_weights = {
            "cryptographic_operations": 1.0,
            "authentication_authorization": 0.9,
            "network_communication": 0.8,
            "secure_storage": 0.7,
            "network_security": 0.8,
            "webview_javascript": 0.6,
            "logging_debugging": -0.3,  # Negative weight for debug context
            "broadcast_receivers": 0.5,
            "content_providers": 0.5,
            "location_services": 0.6,
        }

        total_score = 0.0
        for api in apis_found:
            for category, patterns in self.api_patterns.items():
                for pattern in patterns:
                    if pattern.search(api):
                        weight = category_weights.get(category, 0.5)
                        total_score += weight
                        break

        # Normalize score
        return min(1.0, total_score / max(1, len(apis_found)))

    def _determine_context_type(self, apis_found: List[str]) -> Optional[str]:
        """Determine the primary context type."""
        if not apis_found:
            return None

        category_counts = {}
        for api in apis_found:
            for category, patterns in self.api_patterns.items():
                for pattern in patterns:
                    if pattern.search(api):
                        category_counts[category] = category_counts.get(category, 0) + 1
                        break

        if category_counts:
            return max(category_counts, key=category_counts.get)
        return None

    def _calculate_confidence_adjustment(
        self, context_score: float, apis_found: List[str]
    ) -> float:
        """Calculate confidence adjustment based on context."""
        if not apis_found:
            return self.context_config.get("confidence_penalty_for_isolation", -0.3)

        if context_score > 0.7:
            return self.context_config.get("confidence_boost_for_context", 0.2)
        elif context_score > 0.3:
            return 0.1
        else:
            return -0.1

class EnhancedSecretAnalyzer:
    """
    Advanced secret analyzer using multiple specialized libraries for
    maximum accuracy and false positive reduction.
    """

    def __init__(self, config_path: Optional[str] = None):
        """Initialize the enhanced secret analyzer."""
        self.logger = logger.bind(component="EnhancedSecretAnalyzer")

        # Initialize caches for performance
        self.analysis_cache = TTLCache(maxsize=10000, ttl=3600)  # 1 hour TTL
        self.domain_cache = TTLCache(maxsize=5000, ttl=7200)  # 2 hour TTL

        # Load configuration first
        self.config = self._load_config(config_path)

        # Initialize analyzers
        self._init_entropy_analyzers()
        self._init_ml_classifiers()
        self._init_pattern_matchers()
        self._init_domain_validators()
        self._init_file_analyzers()
        self._init_context_analyzer()
        self._init_framework_detector()
        self._init_rule_engine()

        # Initialize detect-secrets integration
        self._init_detect_secrets()

        self.logger.info("Enhanced Secret Analyzer v2.0 initialized successfully")

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(__file__),
                "..",
                "config",
                "enhanced_detection_config.yaml",
            )

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
            self.logger.info(f"Configuration loaded from {config_path}")
            return config
        except Exception as e:
            self.logger.warning(f"Failed to load config from {config_path}: {e}")
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "entropy_thresholds": {
                "default": 4.5,
                "unicode_text": 3.0,
                "api_keys": 5.0,
                "base64_encoded": 4.8,
                "jwt_tokens": 5.2,
                "uuids": 4.6,
                "hex_encoded": 4.0,
                "random_strings": 4.7,
            },
            "context_analysis": {
                "enabled": True,
                "api_proximity_radius": 7,
                "confidence_boost_for_context": 0.2,
                "confidence_penalty_for_isolation": -0.3,
            },
            "performance_limits": {
                "max_entropy_calculations_per_apk": 15000,
                "max_string_length_for_analysis": 10000,
                "max_context_analysis_time_seconds": 600,
                "memory_limit_mb": 1024,
            },
        }

    def _init_context_analyzer(self):
        """Initialize context analyzer."""
        self.context_analyzer = EnhancedContextAnalyzer(self.config)

    def _init_framework_detector(self):
        """Initialize framework-specific detection."""
        self.framework_config = self.config.get("framework_specific", {})

        # Compile framework patterns
        self.framework_patterns = {}
        for framework, config in self.framework_config.items():
            patterns = config.get("whitelist_patterns", [])
            self.framework_patterns[framework] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]

    def _init_rule_engine(self):
        """Initialize advanced rule engine."""
        rule_config = self.config.get("rule_engine", {})
        self.rule_engine_enabled = rule_config.get("enabled", True)
        self.confidence_threshold = rule_config.get("confidence_threshold", 0.7)
        self.rule_weights = rule_config.get(
            "rule_weights",
            {
                "entropy_analysis": 0.25,
                "context_analysis": 0.35,
                "pattern_matching": 0.20,
                "framework_specific": 0.10,
                "file_path_analysis": 0.10,
            },
        )

    def _init_entropy_analyzers(self):
        """Initialize advanced entropy calculation methods."""
        self.entropy_methods = {
            "shannon": self._calculate_shannon_entropy,
            "base64": self._calculate_base64_entropy,
            "hex": self._calculate_hex_entropy,
            "ascii": self._calculate_ascii_entropy,
            "compressed": self._calculate_compressed_entropy,
        }

        # Load thresholds from config
        entropy_config = self.config.get("entropy_thresholds", {})
        self.entropy_thresholds = {
            "shannon_min": entropy_config.get("default", 4.5),
            "shannon_max": 6.0,
            "base64_min": entropy_config.get("base64_encoded", 4.8),
            "hex_min": entropy_config.get("hex_encoded", 4.0),
            "ascii_min": 4.2,
            "compressed_ratio": 0.85,
            "unicode_text": entropy_config.get("unicode_text", 3.0),
            "api_keys": entropy_config.get("api_keys", 5.0),
            "jwt_tokens": entropy_config.get("jwt_tokens", 5.2),
        }

    def _init_ml_classifiers(self):
        """Initialize machine learning classifiers for secret detection."""
        # Ensemble classifier combining multiple algorithms
        self.text_vectorizer = TfidfVectorizer(
            max_features=5000, ngram_range=(1, 3), analyzer="char_wb", lowercase=True
        )

        # Pre-trained classifiers (would be trained on labeled data)
        self.secret_classifier = VotingClassifier(
            [
                ("rf", RandomForestClassifier(n_estimators=100, random_state=42)),
                ("lr", LogisticRegression(random_state=42, max_iter=1000)),
                ("nb", MultinomialNB()),
            ],
            voting="soft",
        )

        self.feature_scaler = StandardScaler()
        self._train_initial_model()

    def _init_pattern_matchers(self):
        """Initialize advanced pattern matching with regex and YARA rules."""

        # Load false positive patterns from config
        fp_config = self.config.get("false_positive_patterns", {})

        # Framework noise patterns (enhanced from research)
        self.framework_patterns_base = {
            "flutter": [
                r"ThemeData\.fallback",
                r"PointerSignalKind\.\w+",
                r"ImageRepeat\.\w+",
                r"FloatingCursorDragState\.\w+",
                r"MaterialIcons\.\w+",
                r"flutter[_/]assets[_/]",
                r"packages[_/]flutter[_/]",
            ],
            "react_native": [
                r"React\.Component",
                r"StyleSheet\.create",
                r"Platform\.OS",
                r"Dimensions\.get",
                r"node_modules[_/]react[_-]native[_/]",
            ],
            "android": [
                r"http://schemas\.android\.com/",
                r"xmlns:android",
                r"@android:",
                r"R\.[a-z]+\.[a-z_]+",
                r"Ljava/[a-z/]+",
                r"Landroid/[a-z/]+",
            ],
            "xml_schemas": [
                r"http://schemas\.[a-z]+\.com/",
                r'xmlns:[\w_]+="[^"]*"',
                r"objectAnimator.*set.*",
                r"<[\w_]+:[^>]*>",
                r"xsi:schemaLocation",
            ],
            "build_systems": [
                r"gradle\.properties",
                r"build\.gradle",
                r"cmake\..*",
                r"Makefile\.",
                r"package\.json",
                r"yarn\.lock",
                r"package-lock\.json",
            ],
        }

        # Compile false positive patterns from config
        self.false_positive_patterns = {}
        for category, patterns in fp_config.items():
            self.false_positive_patterns[category] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]

        # Binary and encoded content patterns
        self.binary_patterns = [
            r"^[A-Za-z0-9+/]{20,}={0,2}$",  # Base64
            r"^[0-9a-fA-F]{32,}$",  # Hex
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",  # UUID
            r"^\d{13,19}$",  # Timestamps
            r"^[A-Za-z0-9]{40}$",  # Git commit hash
            r"^\$2[aby]\$[0-9]{2}\$",  # Bcrypt hash
        ]

        # File signature patterns (magic numbers)
        self.file_signatures = {
            "pdf": b"%PDF",
            "png": b"\x89PNG",
            "jpg": b"\xFF\xD8\xFF",
            "zip": b"PK\x03\x04",
            "exe": b"MZ",
            "elf": b"\x7fELF",
        }

    def _init_domain_validators(self):
        """Initialize domain and URL validation systems."""
        self.tld_extractor = tldextract.TLDExtract()

        # Common false positive domains
        self.false_positive_domains = {
            "example.com",
            "test.com",
            "localhost",
            "dummy.com",
            "fake.com",
            "sample.com",
            "placeholder.com",
            "temp.com",
            "dev.local",
            "staging.local",
            "test.local",
        }

        # Valid TLD patterns
        self.valid_tld_pattern = regex.compile(r"^[a-z]{2,}$", regex.IGNORECASE)

    def _init_file_analyzers(self):
        """Initialize file type and binary content analyzers."""
        # File type detection using python-magic
        try:
            self.magic_detector = magic.Magic(mime=True)
        except Exception:
            self.magic_detector = None
            self.logger.warning(
                "python-magic not available, file type detection limited"
            )

        # Binary content thresholds
        self.binary_thresholds = {
            "min_printable_ratio": 0.7,
            "max_null_bytes": 5,
            "max_control_chars": 10,
        }

    def _init_detect_secrets(self):
        """Initialize detect-secrets integration with proper error handling."""
        try:
            # Try to import detect-secrets components
            from detect_secrets import SecretsCollection
            from detect_secrets.settings import default_settings
            
            # Initialize with proper settings handling
            if callable(default_settings):
                # Handle function-type settings
                try:
                    settings = default_settings()
                except TypeError:
                    # If function call fails, use empty dict
                    settings = {}
            elif isinstance(default_settings, dict):
                # Handle dict-type settings
                settings = default_settings
            else:
                # Fallback to empty settings
                settings = {}
            
            # Initialize collection with proper settings
            self.secrets_collection = SecretsCollection()
            self.logger.info("detect-secrets integration initialized successfully")

        except ImportError:
            self.logger.warning("detect-secrets not available - secret analysis will use built-in patterns")
            self.secrets_collection = None
        except TypeError as e:
            self.logger.warning(f"detect-secrets settings configuration issue: {e} - using fallback")
            self.secrets_collection = None
        except Exception as e:
            self.logger.warning(f"Failed to initialize detect-secrets: {e} - using fallback")
            self.secrets_collection = None

    def analyze_potential_secret(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> SecretAnalysisResult:
        """
        Comprehensive analysis of potential secret with enhanced context awareness.

        Args:
            content: The potential secret content to analyze
            context: Optional context including file_content, line_number, file_path

        Returns:
            SecretAnalysisResult with comprehensive analysis
        """

        # Internal caching to avoid unhashable dict issues
        cache_key = f"{content}:{str(sorted(context.items()) if context else 'no_context')}"
        if hasattr(self, '_analysis_cache') and cache_key in self._analysis_cache:
            return self._analysis_cache[cache_key]
        
        if not hasattr(self, '_analysis_cache'):
            self._analysis_cache = {}

        start_time = time.time()

        # Initialize result
        result = SecretAnalysisResult(
            content=content,
            is_likely_secret=False,
            confidence_score=0.0,
            context_analysis={},
        )

        # Quick validation
        if not self._is_valid_secret_candidate(content):
            result.false_positive_indicators.append("invalid_candidate")
            return result
        # Store in cache
        self._analysis_cache[cache_key] = result
        # Limit cache size
        if len(self._analysis_cache) > 1000:
            # Remove oldest entries
            keys_to_remove = list(self._analysis_cache.keys())[:100]
            for key in keys_to_remove:
                del self._analysis_cache[key]

        return result
        # Performance limits check
        perf_limits = self.config.get("performance_limits", {})
        max_length = perf_limits.get("max_string_length_for_analysis", 10000)
        if len(content) > max_length:
            result.false_positive_indicators.append("content_too_long")
            return result
        # Store in cache
        self._analysis_cache[cache_key] = result
        # Limit cache size
        if len(self._analysis_cache) > 1000:
            # Remove oldest entries
            keys_to_remove = list(self._analysis_cache.keys())[:100]
            for key in keys_to_remove:
                del self._analysis_cache[key]

        return result
        # Framework classification
        framework = self._classify_framework(content, context)
        result.framework_classification = framework

        # Enhanced analysis pipeline
        analysis_scores = {}

        # 1. Entropy Analysis (25% weight)
        entropy_score, entropy_details = self._analyze_entropy_enhanced(
            content, framework
        )
        analysis_scores["entropy"] = entropy_score
        result.analysis_details["entropy"] = entropy_details

        # 2. Context Analysis (35% weight) - NEW ENHANCED FEATURE
        context_score, context_details = self._analyze_context_enhanced(
            content, context
        )
        analysis_scores["context"] = context_score
        result.analysis_details["context"] = context_details
        result.context_analysis = context_details

        # 3. Pattern Matching (20% weight)
        pattern_score, pattern_details = self._analyze_patterns_enhanced(
            content, context, framework
        )
        analysis_scores["pattern"] = pattern_score
        result.analysis_details["pattern"] = pattern_details

        # 4. Framework-Specific Analysis (10% weight)
        framework_score, framework_details = self._analyze_framework_specific(
            content, framework
        )
        analysis_scores["framework"] = framework_score
        result.analysis_details["framework"] = framework_details

        # 5. File Path Analysis (10% weight)
        filepath_score, filepath_details = self._analyze_file_path(content, context)
        analysis_scores["filepath"] = filepath_score
        result.analysis_details["filepath"] = filepath_details

        # Calculate weighted final score
        final_score = self._calculate_weighted_score(analysis_scores)

        # Apply context-based confidence adjustments
        if context_details.get("confidence_adjustment"):
            final_score += context_details["confidence_adjustment"]

        # Apply framework-specific adjustments
        if framework and framework in self.framework_config:
            multiplier = self.framework_config[framework].get(
                "confidence_multiplier", 1.0
            )
            final_score *= multiplier

        # Normalize score
        final_score = max(0.0, min(1.0, final_score))
        result.confidence_score = final_score

        # Collect indicators
        self._collect_indicators_enhanced(
            result.analysis_details,
            result.false_positive_indicators,
            result.true_positive_indicators,
            framework,
        )

        # Make final decision
        result.is_likely_secret = self._make_final_decision_enhanced(
            final_score,
            result.false_positive_indicators,
            result.true_positive_indicators,
            framework,
        )

        # Log performance
        analysis_time = time.time() - start_time
        if analysis_time > 0.1:  # Log slow analyses
            self.logger.debug(
                f"Slow analysis: {analysis_time:.3f}s for content length {len(content)}"
            )

        return result
        # Store in cache
        self._analysis_cache[cache_key] = result
        # Limit cache size
        if len(self._analysis_cache) > 1000:
            # Remove oldest entries
            keys_to_remove = list(self._analysis_cache.keys())[:100]
            for key in keys_to_remove:
                del self._analysis_cache[key]

        return result
    def _classify_framework(
        self, content: str, context: Optional[Dict[str, Any]]
    ) -> Optional[str]:
        """Classify the framework type based on content and context."""

        if not context:
            return None

        file_path = context.get("file_path", "")
        file_content = context.get("file_content", "")

        # Check framework patterns
        for framework, patterns in self.framework_patterns.items():
            for pattern in patterns:
                if (
                    pattern.search(content)
                    or pattern.search(file_path)
                    or pattern.search(file_content[:1000])
                ):
                    return framework

        return None

    def _analyze_entropy_enhanced(
        self, content: str, framework: Optional[str]
    ) -> Tuple[float, Dict[str, Any]]:
        """Enhanced entropy analysis with framework-specific adjustments."""

        # Calculate multiple entropy types
        shannon_entropy = self._calculate_shannon_entropy(content)
        base64_entropy = self._calculate_base64_entropy(content)
        hex_entropy = self._calculate_hex_entropy(content)

        # Framework-specific threshold adjustments
        threshold_adjustment = 0.0
        if framework and framework in self.framework_config:
            threshold_adjustment = self.framework_config[framework].get(
                "entropy_adjustment", 0.0
            )

        adjusted_threshold = (
            self.entropy_thresholds["shannon_min"] + threshold_adjustment
        )

        # Calculate entropy score
        if shannon_entropy > self.entropy_thresholds["api_keys"]:
            entropy_score = 0.9  # Very high entropy
        elif shannon_entropy > adjusted_threshold:
            entropy_score = 0.7  # High entropy
        elif shannon_entropy > self.entropy_thresholds["unicode_text"]:
            entropy_score = 0.4  # Medium entropy
        else:
            entropy_score = 0.1  # Low entropy

        details = {
            "shannon_entropy": shannon_entropy,
            "base64_entropy": base64_entropy,
            "hex_entropy": hex_entropy,
            "threshold_used": adjusted_threshold,
            "framework_adjustment": threshold_adjustment,
            "entropy_score": entropy_score,
        }

        return entropy_score, details

    def _analyze_context_enhanced(
        self, content: str, context: Optional[Dict[str, Any]]
    ) -> Tuple[float, Dict[str, Any]]:
        """Enhanced context analysis using comprehensive API detection."""

        if not context or not self.context_analyzer:
            return 0.0, {"enabled": False}

        file_content = context.get("file_content")
        line_number = context.get("line_number")

        if not file_content:
            return 0.0, {"no_file_content": True}

        # Perform context analysis
        context_result = self.context_analyzer.analyze_context(
            content, file_content, line_number
        )

        # Convert to score (0.0 - 1.0)
        context_score = context_result.context_score

        details = {
            "apis_found": context_result.apis_found,
            "context_score": context_score,
            "context_type": context_result.context_type,
            "confidence_adjustment": context_result.confidence_adjustment,
            "analysis_radius": context_result.analysis_radius,
            "method_context": context_result.method_context,
        }

        return context_score, details

    def _analyze_patterns_enhanced(
        self, content: str, context: Optional[Dict[str, Any]], framework: Optional[str]
    ) -> Tuple[float, Dict[str, Any]]:
        """Enhanced pattern analysis with framework awareness."""

        pattern_score = 0.5  # Default neutral score
        details = {"patterns_matched": [], "false_positive_patterns": []}

        # Check false positive patterns
        for category, patterns in self.false_positive_patterns.items():
            for pattern in patterns:
                if pattern.search(content):
                    details["false_positive_patterns"].append(
                        f"{category}:{pattern.pattern}"
                    )
                    pattern_score -= 0.2

        # Check for legitimate secret patterns
        if self._looks_like_api_key(content):
            details["patterns_matched"].append("api_key_pattern")
            pattern_score += 0.3

        if self._looks_like_jwt(content):
            details["patterns_matched"].append("jwt_pattern")
            pattern_score += 0.4

        if self._looks_like_private_key(content):
            details["patterns_matched"].append("private_key_pattern")
            pattern_score += 0.5

        # Framework-specific pattern adjustments
        if framework and framework in self.framework_patterns_base:
            for pattern in self.framework_patterns_base[framework]:
                if re.search(pattern, content, re.IGNORECASE):
                    details["false_positive_patterns"].append(f"framework:{pattern}")
                    pattern_score -= 0.3

        pattern_score = max(0.0, min(1.0, pattern_score))
        details["pattern_score"] = pattern_score

        return pattern_score, details

    def _analyze_framework_specific(
        self, content: str, framework: Optional[str]
    ) -> Tuple[float, Dict[str, Any]]:
        """Framework-specific analysis."""

        if not framework:
            return 0.5, {"framework": None}

        framework_config = self.framework_config.get(framework, {})
        whitelist_patterns = framework_config.get("whitelist_patterns", [])

        # Check if content matches framework whitelist (false positive indicators)
        matches = []
        for pattern in whitelist_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                matches.append(pattern)

        if matches:
            framework_score = 0.2  # Low score for framework noise
        else:
            framework_score = 0.7  # Higher score for non-framework content

        details = {
            "framework": framework,
            "whitelist_matches": matches,
            "framework_score": framework_score,
        }

        return framework_score, details

    def _analyze_file_path(
        self, content: str, context: Optional[Dict[str, Any]]
    ) -> Tuple[float, Dict[str, Any]]:
        """Analyze file path context for additional insights."""

        if not context:
            return 0.5, {"file_path": None}

        file_path = context.get("file_path", "")

        # File path scoring
        filepath_score = 0.5
        details = {"file_path": file_path, "path_indicators": []}

        # Configuration files are more likely to contain secrets
        if any(
            config_ext in file_path.lower()
            for config_ext in [".properties", ".config", ".env", ".json", ".xml"]
        ):
            filepath_score += 0.2
            details["path_indicators"].append("configuration_file")

        # Resource files are less likely to contain real secrets
        if any(
            res_path in file_path.lower()
            for res_path in ["/res/", "/assets/", "/resources/"]
        ):
            filepath_score -= 0.2
            details["path_indicators"].append("resource_file")

        # Test files are less likely to contain real secrets
        if any(
            test_path in file_path.lower()
            for test_path in ["/test/", "/tests/", "test_", "_test"]
        ):
            filepath_score -= 0.3
            details["path_indicators"].append("test_file")

        filepath_score = max(0.0, min(1.0, filepath_score))
        details["filepath_score"] = filepath_score

        return filepath_score, details

    def _calculate_weighted_score(self, analysis_scores: Dict[str, float]) -> float:
        """Calculate weighted final score from all analysis components."""

        total_score = 0.0
        for component, score in analysis_scores.items():
            weight = self.rule_weights.get(f"{component}_analysis", 0.2)
            total_score += score * weight

        return total_score

    def _collect_indicators_enhanced(
        self,
        analysis_details: Dict[str, Any],
        false_positive_indicators: List[str],
        true_positive_indicators: List[str],
        framework: Optional[str],
    ):
        """Enhanced indicator collection with framework awareness."""

        # Entropy indicators
        entropy_details = analysis_details.get("entropy", {})
        if entropy_details.get("shannon_entropy", 0) > 5.0:
            true_positive_indicators.append("high_entropy")
        elif entropy_details.get("shannon_entropy", 0) < 3.0:
            false_positive_indicators.append("low_entropy")

        # Context indicators
        context_details = analysis_details.get("context", {})
        if context_details.get("apis_found"):
            true_positive_indicators.append("context_apis_found")
        else:
            false_positive_indicators.append("no_context_apis")

        # Pattern indicators
        pattern_details = analysis_details.get("pattern", {})
        if pattern_details.get("false_positive_patterns"):
            false_positive_indicators.extend(pattern_details["false_positive_patterns"])
        if pattern_details.get("patterns_matched"):
            true_positive_indicators.extend(pattern_details["patterns_matched"])

        # Framework indicators
        framework_details = analysis_details.get("framework", {})
        if framework_details.get("whitelist_matches"):
            false_positive_indicators.append(f"framework_noise_{framework}")

        # File path indicators
        filepath_details = analysis_details.get("filepath", {})
        if filepath_details.get("path_indicators"):
            for indicator in filepath_details["path_indicators"]:
                if indicator in ["test_file", "resource_file"]:
                    false_positive_indicators.append(indicator)
                else:
                    true_positive_indicators.append(indicator)

    def _make_final_decision_enhanced(
        self,
        score: float,
        false_positive_indicators: List[str],
        true_positive_indicators: List[str],
        framework: Optional[str],
    ) -> bool:
        """Enhanced final decision making with framework awareness."""

        # Use configured threshold
        threshold = self.confidence_threshold

        # Framework-specific threshold adjustments
        if framework and framework in self.framework_config:
            multiplier = self.framework_config[framework].get(
                "confidence_multiplier", 1.0
            )
            threshold *= multiplier

        # Strong false positive indicators override score
        strong_fp_indicators = [
            "framework_noise",
            "test_file",
            "low_entropy",
            "common_placeholders",
        ]

        for indicator in false_positive_indicators:
            if any(strong_fp in indicator for strong_fp in strong_fp_indicators):
                return False

        # Strong true positive indicators lower threshold
        strong_tp_indicators = [
            "high_entropy",
            "context_apis_found",
            "api_key_pattern",
            "jwt_pattern",
        ]

        strong_tp_count = sum(
            1
            for indicator in true_positive_indicators
            if any(strong_tp in indicator for strong_tp in strong_tp_indicators)
        )

        if strong_tp_count >= 2:
            threshold *= 0.8  # Lower threshold for strong indicators

        return score >= threshold

    def _is_valid_secret_candidate(self, content: str) -> bool:
        """Quick validation of secret candidate."""
        if not content or not isinstance(content, str):
            return False

        content_len = len(content.strip())
        perf_limits = self.config.get("performance_limits", {})
        min_length = 8  # Minimum reasonable secret length
        max_length = perf_limits.get("max_string_length_for_analysis", 10000)

        if content_len < min_length or content_len > max_length:
            return False

        # Skip obvious non-secrets
        if content.strip().lower() in {
            "test",
            "example",
            "dummy",
            "fake",
            "placeholder",
            "todo",
            "fixme",
            "your_api_key_here",
            "replace_with_your_key",
            "insert_api_key",
        }:
            return False

        return True

    def _calculate_shannon_entropy(self, content: str) -> float:
        """Calculate Shannon entropy of the content."""
        if not content:
            return 0.0

        # Count character frequencies
        char_counts = {}
        for char in content:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate entropy
        content_len = len(content)
        entropy = 0.0

        for count in char_counts.values():
            probability = count / content_len
            if probability > 0:
                entropy -= probability * np.log2(probability)

        return entropy

    def _calculate_base64_entropy(self, content: str) -> float:
        """Calculate entropy specific to base64 character set."""
        base64_chars = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        )
        base64_content = "".join(c for c in content if c in base64_chars)

        if len(base64_content) < len(content) * 0.8:  # Less than 80% base64 chars
            return 0.0

        return self._calculate_shannon_entropy(base64_content)

    def _calculate_hex_entropy(self, content: str) -> float:
        """Calculate entropy specific to hexadecimal character set."""
        hex_chars = set("0123456789abcdefABCDEF")
        hex_content = "".join(c for c in content if c in hex_chars)

        if len(hex_content) < len(content) * 0.9:  # Less than 90% hex chars
            return 0.0

        return self._calculate_shannon_entropy(hex_content)

    def _calculate_ascii_entropy(self, content: str) -> float:
        """Calculate entropy for ASCII printable characters."""
        ascii_content = "".join(c for c in content if 32 <= ord(c) <= 126)
        return self._calculate_shannon_entropy(ascii_content)

    def _calculate_compressed_entropy(self, content: str) -> float:
        """Calculate entropy based on compression ratio."""
        import gzip

        try:
            original_size = len(content.encode("utf-8"))
            compressed_size = len(gzip.compress(content.encode("utf-8")))
            compression_ratio = (
                compressed_size / original_size if original_size > 0 else 1.0
            )

            # Higher compression ratio indicates lower entropy (more patterns)
            return 1.0 - compression_ratio
        except Exception:
            return 0.0

    def _train_initial_model(self):
        """Train initial ML model with synthetic data (placeholder)."""
        # This would train on real labeled data in production
        pass

    def _looks_like_api_key(self, content: str) -> bool:
        """Check if content looks like an API key."""
        # Common API key patterns
        api_key_patterns = [
            r"^AKIA[0-9A-Z]{16}$",  # AWS Access Key
            r"^fake_(live|test)_[0-9a-zA-Z]{24}$",  # Stripe Key
            r"^slack_[0-9]+_[0-9a-zA-Z]+$",  # Slack Bot Token
            r"^github_[0-9a-zA-Z]{36}$",  # GitHub Personal Access Token
            r"^AIza[0-9A-Za-z_-]{35}$",  # Google API Key
        ]

        for pattern in api_key_patterns:
            if re.match(pattern, content):
                return True

        # Generic high-entropy alphanumeric string
        if (
            len(content) >= 20
            and re.match(r"^[A-Za-z0-9_-]+$", content)
            and self._calculate_shannon_entropy(content) > 4.5
        ):
            return True

        return False

    def _looks_like_jwt(self, content: str) -> bool:
        """Check if content looks like a JWT token."""
        # JWT pattern: header.payload.signature
        jwt_pattern = r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"

        if re.match(jwt_pattern, content):
            parts = content.split(".")
            if len(parts) == 3:
                # Check if parts look like base64
                for part in parts:
                    if len(part) < 4:  # Too short for base64
                        return False
                return True

        return False

    def _looks_like_private_key(self, content: str) -> bool:
        """Check if content looks like a private key."""
        private_key_patterns = [
            r"-----BEGIN.*PRIVATE KEY-----",
            r"-----BEGIN RSA PRIVATE KEY-----",
            r"-----BEGIN EC PRIVATE KEY-----",
            r"-----BEGIN OPENSSH PRIVATE KEY-----",
        ]

        for pattern in private_key_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True

        return False

# Utility functions for integration with existing AODS components

def integrate_with_enhanced_static_analyzer(analyzer_instance):
    """Integration helper for enhanced static analyzer."""
    enhanced_analyzer = EnhancedSecretAnalyzer()

    def enhanced_is_likely_secret_content(self, content, context=None):
        """Enhanced secret detection method for static analyzer."""
        result = enhanced_analyzer.analyze_potential_secret(content, context)
        return result.is_likely_secret, result.confidence_score, result.analysis_details

    # Replace the existing method
    analyzer_instance.is_likely_secret_content = (
        enhanced_is_likely_secret_content.__get__(
            analyzer_instance, analyzer_instance.__class__
        )
    )

    return analyzer_instance

def integrate_with_apk2url_extraction(extractor_instance):
    """Integration helper for APK2URL extraction."""
    enhanced_analyzer = EnhancedSecretAnalyzer()

    def enhanced_is_framework_noise(self, url, context=None):
        """Enhanced framework noise detection for URL extractor."""
        result = enhanced_analyzer.analyze_potential_secret(url, context)
        # Invert logic: if it's likely a secret, it's NOT framework noise
        return not result.is_likely_secret, result.analysis_details

    # Replace the existing method
    extractor_instance.is_framework_noise = enhanced_is_framework_noise.__get__(
        extractor_instance, extractor_instance.__class__
    )

    return extractor_instance

if __name__ == "__main__":
    # Example usage and testing
    analyzer = EnhancedSecretAnalyzer()

    # Test cases
    test_secrets = [
        "AKIA1234567890EXAMPLE",  # AWS key
        "ThemeData.fallback",  # Flutter framework noise
        "fake_test_1234567890",  # Stripe test key
        "http://schemas.android.com/apk/res/android",  # Android schema
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",  # JWT token
        "::8",  # Invalid IPv6
    ]

    for i, secret in enumerate(test_secrets):
        result = analyzer.analyze_potential_secret(secret)
        print(f"\nTest {i+1}: {secret[:30]}...")
        print(f"Is Secret: {result.is_likely_secret}")
        print(f"Confidence: {result.confidence_score:.3f}")
        print(f"False Positive Indicators: {result.false_positive_indicators}")
        print(f"True Positive Indicators: {result.true_positive_indicators}")
