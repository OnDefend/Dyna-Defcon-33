"""
Advanced AI/ML Threat Detection System for AODS
Enhanced vulnerability detection using machine learning algorithms and behavioral analysis
"""

import os
import json
import pickle
import numpy as np
import pandas as pd
import logging
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum
import sqlite3
import hashlib
import re
from collections import defaultdict, Counter
import joblib

# Machine Learning imports
try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.svm import SVC
    from sklearn.naive_bayes import GaussianNB
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.decomposition import PCA
    from sklearn.cluster import DBSCAN, KMeans
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

logger = logging.getLogger(__name__)

class ThreatCategory(Enum):
    """Threat categories for classification."""
    MALWARE = "malware"
    SPYWARE = "spyware"
    ADWARE = "adware"
    TROJAN = "trojan"
    RANSOMWARE = "ransomware"
    BANKING_TROJAN = "banking_trojan"
    SMS_FRAUD = "sms_fraud"
    PHISHING = "phishing"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"

class AnalysisMode(Enum):
    """Analysis modes for threat detection."""
    STATIC_ANALYSIS = "static"
    DYNAMIC_ANALYSIS = "dynamic"
    BEHAVIORAL_ANALYSIS = "behavioral"
    HYBRID_ANALYSIS = "hybrid"

class ConfidenceLevel(Enum):
    """Confidence levels for predictions."""
    VERY_HIGH = "very_high"  # 90%+
    HIGH = "high"           # 80-90%
    MEDIUM = "medium"       # 60-80%
    LOW = "low"            # 40-60%
    VERY_LOW = "very_low"  # <40%

@dataclass
class FeatureVector:
    """Feature vector for ML analysis."""
    apk_name: str
    feature_type: str
    features: Dict[str, Any]
    extracted_at: str
    metadata: Dict[str, Any]

@dataclass
class ThreatPrediction:
    """Threat prediction result."""
    apk_name: str
    threat_category: str
    confidence_score: float
    confidence_level: str
    prediction_details: Dict[str, Any]
    model_version: str
    predicted_at: str
    evidence: List[Dict[str, Any]]

@dataclass
class BehavioralSignature:
    """Behavioral signature for analysis."""
    signature_id: str
    name: str
    description: str
    patterns: List[Dict[str, Any]]
    severity: str
    confidence_threshold: float
    created_at: str

@dataclass
class ModelMetrics:
    """Model performance metrics."""
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    training_samples: int
    last_trained: str
    feature_count: int

class FeatureExtractor:
    """Extract features from APK analysis for ML models."""
    
    def __init__(self):
        self.static_features = StaticFeatureExtractor()
        self.dynamic_features = DynamicFeatureExtractor()
        self.behavioral_features = BehavioralFeatureExtractor()
    
    def extract_features(self, apk_data: Dict[str, Any], 
                        analysis_mode: AnalysisMode = AnalysisMode.HYBRID_ANALYSIS) -> FeatureVector:
        """Extract comprehensive features from APK data."""
        features = {}
        
        try:
            # Extract static features
            if analysis_mode in [AnalysisMode.STATIC_ANALYSIS, AnalysisMode.HYBRID_ANALYSIS]:
                static_features = self.static_features.extract(apk_data)
                features.update(static_features)
            
            # Extract dynamic features
            if analysis_mode in [AnalysisMode.DYNAMIC_ANALYSIS, AnalysisMode.HYBRID_ANALYSIS]:
                dynamic_features = self.dynamic_features.extract(apk_data)
                features.update(dynamic_features)
            
            # Extract behavioral features
            if analysis_mode in [AnalysisMode.BEHAVIORAL_ANALYSIS, AnalysisMode.HYBRID_ANALYSIS]:
                behavioral_features = self.behavioral_features.extract(apk_data)
                features.update(behavioral_features)
            
            return FeatureVector(
                apk_name=apk_data.get('apk_name', 'unknown'),
                feature_type=analysis_mode.value,
                features=features,
                extracted_at=datetime.now().isoformat(),
                metadata={
                    'feature_count': len(features),
                    'analysis_mode': analysis_mode.value,
                    'apk_size': apk_data.get('size', 0)
                }
            )
            
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return FeatureVector(
                apk_name=apk_data.get('apk_name', 'unknown'),
                feature_type="error",
                features={},
                extracted_at=datetime.now().isoformat(),
                metadata={'error': str(e)}
            )

class StaticFeatureExtractor:
    """Extract static analysis features."""
    
    def extract(self, apk_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract static features from APK data."""
        features = {}
        
        # Manifest features
        manifest = apk_data.get('manifest', {})
        features.update(self._extract_manifest_features(manifest))
        
        # Permission features
        permissions = apk_data.get('permissions', [])
        features.update(self._extract_permission_features(permissions))
        
        # Code features
        code_analysis = apk_data.get('code_analysis', {})
        features.update(self._extract_code_features(code_analysis))
        
        # Certificate features
        certificate = apk_data.get('certificate', {})
        features.update(self._extract_certificate_features(certificate))
        
        # Resource features
        resources = apk_data.get('resources', {})
        features.update(self._extract_resource_features(resources))
        
        return features
    
    def _extract_manifest_features(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from Android manifest."""
        features = {}
        
        # Application features
        application = manifest.get('application', {})
        features['app_debuggable'] = application.get('debuggable', False)
        features['app_allow_backup'] = application.get('allowBackup', True)
        features['app_exported'] = application.get('exported', False)
        
        # Activity features
        activities = manifest.get('activities', [])
        features['activity_count'] = len(activities)
        features['exported_activities'] = sum(1 for a in activities if a.get('exported', False))
        
        # Service features
        services = manifest.get('services', [])
        features['service_count'] = len(services)
        features['exported_services'] = sum(1 for s in services if s.get('exported', False))
        
        # Receiver features
        receivers = manifest.get('receivers', [])
        features['receiver_count'] = len(receivers)
        features['exported_receivers'] = sum(1 for r in receivers if r.get('exported', False))
        
        # Intent filter features
        intent_filters = []
        for component_list in [activities, services, receivers]:
            for component in component_list:
                intent_filters.extend(component.get('intent_filters', []))
        
        features['intent_filter_count'] = len(intent_filters)
        features['has_main_action'] = any('android.intent.action.MAIN' in str(f) for f in intent_filters)
        features['has_boot_receiver'] = any('android.intent.action.BOOT_COMPLETED' in str(f) for f in intent_filters)
        
        return features
    
    def _extract_permission_features(self, permissions: List[str]) -> Dict[str, Any]:
        """Extract features from permissions."""
        features = {}
        
        # Permission counts
        features['permission_count'] = len(permissions)
        
        # Dangerous permission categories
        dangerous_permissions = {
            'sms': ['android.permission.SEND_SMS', 'android.permission.READ_SMS', 'android.permission.RECEIVE_SMS'],
            'contacts': ['android.permission.READ_CONTACTS', 'android.permission.WRITE_CONTACTS'],
            'location': ['android.permission.ACCESS_FINE_LOCATION', 'android.permission.ACCESS_COARSE_LOCATION'],
            'camera': ['android.permission.CAMERA'],
            'microphone': ['android.permission.RECORD_AUDIO'],
            'storage': ['android.permission.READ_EXTERNAL_STORAGE', 'android.permission.WRITE_EXTERNAL_STORAGE'],
            'phone': ['android.permission.READ_PHONE_STATE', 'android.permission.CALL_PHONE'],
            'admin': ['android.permission.DEVICE_ADMIN'],
            'internet': ['android.permission.INTERNET'],
            'network': ['android.permission.ACCESS_NETWORK_STATE', 'android.permission.ACCESS_WIFI_STATE']
        }
        
        for category, perms in dangerous_permissions.items():
            count = sum(1 for p in permissions if any(dp in p for dp in perms))
            features[f'{category}_permissions'] = count
            features[f'has_{category}_permission'] = count > 0
        
        # High-risk permission combinations
        features['sms_and_contacts'] = features.get('has_sms_permission', False) and features.get('has_contacts_permission', False)
        features['location_and_network'] = features.get('has_location_permission', False) and features.get('has_network_permission', False)
        features['admin_and_sms'] = features.get('has_admin_permission', False) and features.get('has_sms_permission', False)
        
        return features
    
    def _extract_code_features(self, code_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from code analysis."""
        features = {}
        
        # Code metrics
        features['method_count'] = code_analysis.get('method_count', 0)
        features['class_count'] = code_analysis.get('class_count', 0)
        features['string_count'] = code_analysis.get('string_count', 0)
        
        # Suspicious API calls
        api_calls = code_analysis.get('api_calls', [])
        features['api_call_count'] = len(api_calls)
        
        suspicious_apis = {
            'reflection': ['java.lang.reflect', 'getDeclaredMethod', 'getMethod'],
            'runtime': ['Runtime.getRuntime', 'ProcessBuilder', 'exec'],
            'crypto': ['Cipher', 'MessageDigest', 'KeyGenerator'],
            'network': ['HttpURLConnection', 'Socket', 'ServerSocket'],
            'file_ops': ['FileOutputStream', 'FileInputStream', 'File.delete']
        }
        
        for category, apis in suspicious_apis.items():
            count = sum(1 for call in api_calls if any(api in call for api in apis))
            features[f'{category}_api_calls'] = count
            features[f'uses_{category}_apis'] = count > 0
        
        # String analysis
        strings = code_analysis.get('strings', [])
        features.update(self._analyze_strings(strings))
        
        return features
    
    def _extract_certificate_features(self, certificate: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from certificate information."""
        features = {}
        
        if certificate:
            features['is_signed'] = True
            features['cert_valid_days'] = certificate.get('valid_days', 0)
            features['cert_is_debug'] = 'debug' in certificate.get('subject', '').lower()
            features['cert_is_self_signed'] = certificate.get('issuer') == certificate.get('subject')
            
            # Certificate algorithm
            algorithm = certificate.get('signature_algorithm', '').lower()
            features['cert_uses_sha1'] = 'sha1' in algorithm
            features['cert_uses_md5'] = 'md5' in algorithm
        else:
            features['is_signed'] = False
            features['cert_valid_days'] = 0
            features['cert_is_debug'] = False
            features['cert_is_self_signed'] = False
            features['cert_uses_sha1'] = False
            features['cert_uses_md5'] = False
        
        return features
    
    def _extract_resource_features(self, resources: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from resources."""
        features = {}
        
        # Resource counts
        features['layout_count'] = len(resources.get('layouts', []))
        features['drawable_count'] = len(resources.get('drawables', []))
        features['string_resource_count'] = len(resources.get('strings', {}))
        
        # Assets
        assets = resources.get('assets', [])
        features['asset_count'] = len(assets)
        
        # Look for suspicious files
        suspicious_extensions = ['.dex', '.so', '.jar', '.zip', '.apk']
        features['suspicious_assets'] = sum(1 for asset in assets 
                                          if any(asset.endswith(ext) for ext in suspicious_extensions))
        
        return features
    
    def _analyze_strings(self, strings: List[str]) -> Dict[str, Any]:
        """Analyze strings for suspicious content."""
        features = {}
        
        # String patterns
        patterns = {
            'url_count': r'https?://[^\s]+',
            'ip_count': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'phone_count': r'\b\d{3}-?\d{3}-?\d{4}\b',
            'email_count': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'base64_count': r'[A-Za-z0-9+/]{20,}={0,2}',
            'hex_count': r'[0-9a-fA-F]{16,}'
        }
        
        for feature_name, pattern in patterns.items():
            count = sum(1 for s in strings if re.search(pattern, s))
            features[feature_name] = count
        
        # Suspicious keywords
        suspicious_keywords = [
            'password', 'secret', 'key', 'token', 'admin', 'root',
            'hack', 'crack', 'bypass', 'exploit', 'payload',
            'shell', 'command', 'execute', 'runtime', 'system'
        ]
        
        features['suspicious_keywords'] = sum(1 for s in strings 
                                            for keyword in suspicious_keywords 
                                            if keyword.lower() in s.lower())
        
        return features

class DynamicFeatureExtractor:
    """Extract dynamic analysis features."""
    
    def extract(self, apk_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract dynamic features from APK runtime data."""
        features = {}
        
        # Runtime behavior
        runtime_data = apk_data.get('runtime_analysis', {})
        features.update(self._extract_runtime_features(runtime_data))
        
        # Network activity
        network_data = apk_data.get('network_analysis', {})
        features.update(self._extract_network_features(network_data))
        
        # File system activity
        file_data = apk_data.get('file_analysis', {})
        features.update(self._extract_file_features(file_data))
        
        return features
    
    def _extract_runtime_features(self, runtime_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract runtime behavior features."""
        features = {}
        
        # Process and thread activity
        features['process_count'] = len(runtime_data.get('processes', []))
        features['thread_count'] = len(runtime_data.get('threads', []))
        
        # System calls
        syscalls = runtime_data.get('system_calls', [])
        features['syscall_count'] = len(syscalls)
        
        # Memory usage
        memory_stats = runtime_data.get('memory_stats', {})
        features['max_memory_mb'] = memory_stats.get('max_memory', 0) / (1024 * 1024)
        features['memory_leaks'] = memory_stats.get('leak_count', 0)
        
        return features
    
    def _extract_network_features(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network activity features."""
        features = {}
        
        # Connection counts
        connections = network_data.get('connections', [])
        features['connection_count'] = len(connections)
        
        # Protocol analysis
        protocols = [conn.get('protocol', '').lower() for conn in connections]
        features['http_connections'] = protocols.count('http')
        features['https_connections'] = protocols.count('https')
        features['tcp_connections'] = protocols.count('tcp')
        features['udp_connections'] = protocols.count('udp')
        
        # Data transfer
        features['bytes_sent'] = sum(conn.get('bytes_sent', 0) for conn in connections)
        features['bytes_received'] = sum(conn.get('bytes_received', 0) for conn in connections)
        
        # Suspicious destinations
        destinations = [conn.get('destination', '') for conn in connections]
        features['unique_destinations'] = len(set(destinations))
        features['suspicious_domains'] = sum(1 for dest in destinations 
                                           if self._is_suspicious_domain(dest))
        
        return features
    
    def _extract_file_features(self, file_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract file system activity features."""
        features = {}
        
        # File operations
        file_ops = file_data.get('file_operations', [])
        features['file_op_count'] = len(file_ops)
        
        # Operation types
        op_types = [op.get('type', '') for op in file_ops]
        features['file_reads'] = op_types.count('read')
        features['file_writes'] = op_types.count('write')
        features['file_deletes'] = op_types.count('delete')
        features['file_creates'] = op_types.count('create')
        
        # Sensitive file access
        sensitive_paths = ['/system/', '/data/data/', '/sdcard/', '/storage/']
        features['sensitive_file_access'] = sum(1 for op in file_ops 
                                              if any(path in op.get('path', '') 
                                                   for path in sensitive_paths))
        
        return features
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is suspicious."""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        suspicious_keywords = ['temp', 'fake', 'phish', 'malware', 'trojan']
        
        return (any(domain.endswith(tld) for tld in suspicious_tlds) or
                any(keyword in domain.lower() for keyword in suspicious_keywords))

class BehavioralFeatureExtractor:
    """Extract behavioral analysis features."""
    
    def extract(self, apk_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract behavioral features from APK analysis."""
        features = {}
        
        # Behavioral patterns
        behavior_data = apk_data.get('behavioral_analysis', {})
        features.update(self._extract_behavioral_patterns(behavior_data))
        
        # User interaction patterns
        ui_data = apk_data.get('ui_analysis', {})
        features.update(self._extract_ui_patterns(ui_data))
        
        return features
    
    def _extract_behavioral_patterns(self, behavior_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract behavioral patterns."""
        features = {}
        
        # Activity patterns
        activities = behavior_data.get('activities', [])
        features['activity_switches'] = len(activities)
        
        # Background behavior
        background_events = behavior_data.get('background_events', [])
        features['background_activity'] = len(background_events)
        
        # Permission usage patterns
        permission_usage = behavior_data.get('permission_usage', {})
        features['permissions_used'] = len(permission_usage)
        features['immediate_permission_use'] = sum(1 for usage in permission_usage.values() 
                                                 if usage.get('first_use_seconds', 0) < 5)
        
        return features
    
    def _extract_ui_patterns(self, ui_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract UI interaction patterns."""
        features = {}
        
        # User interactions
        interactions = ui_data.get('interactions', [])
        features['user_interactions'] = len(interactions)
        
        # Screen analysis
        screens = ui_data.get('screens', [])
        features['unique_screens'] = len(screens)
        
        # Suspicious UI elements
        features['password_fields'] = sum(1 for screen in screens 
                                        if 'password' in str(screen).lower())
        features['hidden_elements'] = sum(1 for screen in screens 
                                        if screen.get('has_hidden_elements', False))
        
        return features

class ThreatClassifier:
    """Machine learning threat classifier."""
    
    def __init__(self, model_dir: Path):
        self.model_dir = model_dir
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize models
        self.models = {}
        self.scalers = {}
        self.label_encoders = {}
        self.vectorizers = {}
        
        # Model configurations
        self.model_configs = {
            'random_forest': {
                'model': RandomForestClassifier(n_estimators=100, random_state=42),
                'name': 'Random Forest'
            },
            'gradient_boosting': {
                'model': GradientBoostingClassifier(n_estimators=100, random_state=42),
                'name': 'Gradient Boosting'
            },
            'svm': {
                'model': SVC(probability=True, random_state=42),
                'name': 'Support Vector Machine'
            },
            'neural_network': {
                'model': MLPClassifier(hidden_layer_sizes=(100, 50), random_state=42),
                'name': 'Neural Network'
            },
            'ensemble': None  # Will be created after individual models
        }
        
        self.feature_importance = {}
        self.model_metrics = {}
        
        if ML_AVAILABLE:
            self._load_models()
    
    def train_models(self, training_data: List[Dict[str, Any]], 
                    labels: List[str]) -> Dict[str, ModelMetrics]:
        """Train all classification models."""
        if not ML_AVAILABLE:
            logger.error("Scikit-learn not available for ML training")
            return {}
        
        try:
            # Prepare training data
            X, y = self._prepare_training_data(training_data, labels)
            
            if len(X) == 0:
                logger.warning("No training data available")
                return {}
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Train individual models
            trained_models = {}
            for model_name, config in self.model_configs.items():
                if model_name == 'ensemble':
                    continue
                
                logger.info(f"Training {config['name']} model...")
                
                model = config['model']
                model.fit(X_train, y_train)
                
                # Evaluate model
                y_pred = model.predict(X_test)
                metrics = self._calculate_metrics(y_test, y_pred, model_name)
                
                # Save model
                self._save_model(model, model_name)
                
                trained_models[model_name] = model
                self.model_metrics[model_name] = metrics
                
                logger.info(f"{config['name']} - Accuracy: {metrics.accuracy:.3f}, F1: {metrics.f1_score:.3f}")
            
            # Create ensemble model
            if len(trained_models) >= 2:
                ensemble_estimators = [(name, model) for name, model in trained_models.items()]
                ensemble_model = VotingClassifier(estimators=ensemble_estimators, voting='soft')
                ensemble_model.fit(X_train, y_train)
                
                # Evaluate ensemble
                y_pred_ensemble = ensemble_model.predict(X_test)
                ensemble_metrics = self._calculate_metrics(y_test, y_pred_ensemble, 'ensemble')
                
                self._save_model(ensemble_model, 'ensemble')
                self.model_metrics['ensemble'] = ensemble_metrics
                
                logger.info(f"Ensemble Model - Accuracy: {ensemble_metrics.accuracy:.3f}, F1: {ensemble_metrics.f1_score:.3f}")
            
            # Calculate feature importance
            self._calculate_feature_importance(trained_models, X.columns if hasattr(X, 'columns') else None)
            
            return self.model_metrics
            
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            return {}
    
    def predict_threat(self, feature_vector: FeatureVector, 
                      model_name: str = 'ensemble') -> ThreatPrediction:
        """Predict threat category for feature vector."""
        if not ML_AVAILABLE or model_name not in self.models:
            # Fallback to rule-based prediction
            return self._rule_based_prediction(feature_vector)
        
        try:
            # Prepare features
            X = self._prepare_prediction_data([feature_vector.features])
            
            if len(X) == 0:
                return self._rule_based_prediction(feature_vector)
            
            # Make prediction
            model = self.models[model_name]
            prediction = model.predict(X)[0]
            probabilities = model.predict_proba(X)[0]
            
            # Get confidence
            max_prob = max(probabilities)
            confidence_level = self._determine_confidence_level(max_prob)
            
            # Get prediction details
            if hasattr(model, 'classes_'):
                class_probabilities = {
                    class_name: float(prob) 
                    for class_name, prob in zip(model.classes_, probabilities)
                }
            else:
                class_probabilities = {}
            
            return ThreatPrediction(
                apk_name=feature_vector.apk_name,
                threat_category=prediction,
                confidence_score=float(max_prob),
                confidence_level=confidence_level.value,
                prediction_details={
                    'model_used': model_name,
                    'class_probabilities': class_probabilities,
                    'feature_count': len(feature_vector.features)
                },
                model_version=f"{model_name}_v1.0",
                predicted_at=datetime.now().isoformat(),
                evidence=self._generate_evidence(feature_vector, prediction, max_prob)
            )
            
        except Exception as e:
            logger.error(f"ML prediction failed: {e}")
            return self._rule_based_prediction(feature_vector)
    
    def _prepare_training_data(self, training_data: List[Dict[str, Any]], 
                             labels: List[str]) -> Tuple[pd.DataFrame, pd.Series]:
        """Prepare training data for ML models."""
        if not training_data or not labels:
            return pd.DataFrame(), pd.Series()
        
        # Convert to DataFrame
        df = pd.DataFrame(training_data)
        
        # Handle missing values
        df = df.fillna(0)
        
        # Convert boolean columns
        bool_columns = df.select_dtypes(include=['bool']).columns
        df[bool_columns] = df[bool_columns].astype(int)
        
        # Encode categorical variables
        categorical_columns = df.select_dtypes(include=['object']).columns
        for col in categorical_columns:
            if col not in self.label_encoders:
                self.label_encoders[col] = LabelEncoder()
                df[col] = self.label_encoders[col].fit_transform(df[col].astype(str))
            else:
                df[col] = self.label_encoders[col].transform(df[col].astype(str))
        
        # Scale features
        if 'main_scaler' not in self.scalers:
            self.scalers['main_scaler'] = StandardScaler()
            X = self.scalers['main_scaler'].fit_transform(df)
        else:
            X = self.scalers['main_scaler'].transform(df)
        
        # Convert back to DataFrame for feature names
        X = pd.DataFrame(X, columns=df.columns)
        
        # Prepare labels
        if 'label_encoder' not in self.label_encoders:
            self.label_encoders['label_encoder'] = LabelEncoder()
            y = self.label_encoders['label_encoder'].fit_transform(labels)
        else:
            y = self.label_encoders['label_encoder'].transform(labels)
        
        y = pd.Series(y)
        
        return X, y
    
    def _prepare_prediction_data(self, feature_data: List[Dict[str, Any]]) -> pd.DataFrame:
        """Prepare feature data for prediction."""
        if not feature_data:
            return pd.DataFrame()
        
        # Convert to DataFrame
        df = pd.DataFrame(feature_data)
        
        # Handle missing values
        df = df.fillna(0)
        
        # Convert boolean columns
        bool_columns = df.select_dtypes(include=['bool']).columns
        df[bool_columns] = df[bool_columns].astype(int)
        
        # Encode categorical variables
        categorical_columns = df.select_dtypes(include=['object']).columns
        for col in categorical_columns:
            if col in self.label_encoders:
                # Handle unseen categories
                df[col] = df[col].astype(str)
                known_classes = set(self.label_encoders[col].classes_)
                df[col] = df[col].apply(lambda x: x if x in known_classes else 'unknown')
                df[col] = self.label_encoders[col].transform(df[col])
            else:
                # Drop unknown categorical columns
                df = df.drop(columns=[col])
        
        # Scale features
        if 'main_scaler' in self.scalers and len(df) > 0:
            X = self.scalers['main_scaler'].transform(df)
            X = pd.DataFrame(X, columns=df.columns)
        else:
            X = df
        
        return X
    
    def _calculate_metrics(self, y_true, y_pred, model_name: str) -> ModelMetrics:
        """Calculate model performance metrics."""
        return ModelMetrics(
            model_name=model_name,
            accuracy=float(accuracy_score(y_true, y_pred)),
            precision=float(precision_score(y_true, y_pred, average='weighted', zero_division=0)),
            recall=float(recall_score(y_true, y_pred, average='weighted', zero_division=0)),
            f1_score=float(f1_score(y_true, y_pred, average='weighted', zero_division=0)),
            training_samples=len(y_true),
            last_trained=datetime.now().isoformat(),
            feature_count=0  # Will be updated
        )
    
    def _calculate_feature_importance(self, models: Dict[str, Any], feature_names: Optional[List[str]]):
        """Calculate feature importance from models."""
        if not feature_names:
            return
        
        importance_scores = defaultdict(list)
        
        for model_name, model in models.items():
            if hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
                for feature, importance in zip(feature_names, importances):
                    importance_scores[feature].append(importance)
        
        # Average importance across models
        self.feature_importance = {
            feature: np.mean(scores) 
            for feature, scores in importance_scores.items()
        }
    
    def _determine_confidence_level(self, probability: float) -> ConfidenceLevel:
        """Determine confidence level from probability."""
        if probability >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif probability >= 0.8:
            return ConfidenceLevel.HIGH
        elif probability >= 0.6:
            return ConfidenceLevel.MEDIUM
        elif probability >= 0.4:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW
    
    def _generate_evidence(self, feature_vector: FeatureVector, 
                         prediction: str, confidence: float) -> List[Dict[str, Any]]:
        """Generate evidence for prediction."""
        evidence = []
        
        # Use feature importance to identify key evidence
        features = feature_vector.features
        
        for feature_name, value in features.items():
            if feature_name in self.feature_importance:
                importance = self.feature_importance[feature_name]
                if importance > 0.05 and value > 0:  # Significant feature with positive value
                    evidence.append({
                        'feature': feature_name,
                        'value': value,
                        'importance': float(importance),
                        'contribution': 'positive' if value > 0 else 'negative'
                    })
        
        # Sort by importance
        evidence.sort(key=lambda x: x['importance'], reverse=True)
        
        return evidence[:10]  # Top 10 pieces of evidence
    
    def _rule_based_prediction(self, feature_vector: FeatureVector) -> ThreatPrediction:
        """Fallback rule-based prediction when ML is not available."""
        features = feature_vector.features
        
        # Simple rule-based scoring
        threat_score = 0
        evidence = []
        
        # Check for high-risk features
        high_risk_features = {
            'admin_permissions': 3,
            'sms_permissions': 2,
            'suspicious_assets': 2,
            'cert_is_debug': 2,
            'exported_services': 1,
            'reflection_api_calls': 2,
            'runtime_api_calls': 3,
            'suspicious_keywords': 1
        }
        
        for feature, weight in high_risk_features.items():
            value = features.get(feature, 0)
            if value > 0:
                threat_score += weight * (1 if isinstance(value, bool) else min(value, 5))
                evidence.append({
                    'feature': feature,
                    'value': value,
                    'weight': weight,
                    'contribution': 'increases_risk'
                })
        
        # Determine threat category and confidence
        if threat_score >= 10:
            threat_category = ThreatCategory.MALWARE.value
            confidence = 0.8
        elif threat_score >= 6:
            threat_category = ThreatCategory.SUSPICIOUS.value
            confidence = 0.6
        else:
            threat_category = ThreatCategory.BENIGN.value
            confidence = 0.4
        
        confidence_level = self._determine_confidence_level(confidence)
        
        return ThreatPrediction(
            apk_name=feature_vector.apk_name,
            threat_category=threat_category,
            confidence_score=confidence,
            confidence_level=confidence_level.value,
            prediction_details={
                'model_used': 'rule_based',
                'threat_score': threat_score,
                'feature_count': len(features)
            },
            model_version="rule_based_v1.0",
            predicted_at=datetime.now().isoformat(),
            evidence=evidence
        )
    
    def _save_model(self, model, model_name: str):
        """Save trained model to disk."""
        try:
            model_path = self.model_dir / f"{model_name}_model.pkl"
            joblib.dump(model, model_path)
            self.models[model_name] = model
            logger.info(f"Model saved: {model_path}")
        except Exception as e:
            logger.error(f"Failed to save model {model_name}: {e}")
    
    def _load_models(self):
        """Load trained models from disk."""
        for model_name in self.model_configs.keys():
            model_path = self.model_dir / f"{model_name}_model.pkl"
            if model_path.exists():
                try:
                    self.models[model_name] = joblib.load(model_path)
                    logger.info(f"Model loaded: {model_name}")
                except Exception as e:
                    logger.error(f"Failed to load model {model_name}: {e}")

class BehavioralAnalysisEngine:
    """Behavioral analysis engine for runtime threat detection."""
    
    def __init__(self, signatures_path: Path):
        self.signatures_path = signatures_path
        self.signatures_path.mkdir(parents=True, exist_ok=True)
        
        self.behavioral_signatures = {}
        self.load_signatures()
    
    def load_signatures(self):
        """Load behavioral signatures from files."""
        try:
            signatures_file = self.signatures_path / "behavioral_signatures.json"
            if signatures_file.exists():
                with open(signatures_file, 'r') as f:
                    signatures_data = json.load(f)
                
                for sig_data in signatures_data:
                    signature = BehavioralSignature(**sig_data)
                    self.behavioral_signatures[signature.signature_id] = signature
                
                logger.info(f"Loaded {len(self.behavioral_signatures)} behavioral signatures")
            else:
                # Create default signatures
                self._create_default_signatures()
                
        except Exception as e:
            logger.error(f"Failed to load behavioral signatures: {e}")
            self._create_default_signatures()
    
    def _create_default_signatures(self):
        """Create default behavioral signatures."""
        default_signatures = [
            {
                "signature_id": "suspicious_sms_activity",
                "name": "Suspicious SMS Activity",
                "description": "App sends SMS messages without user interaction",
                "patterns": [
                    {"type": "sms_sent", "threshold": 3, "time_window": 300},
                    {"type": "user_interaction", "threshold": 0, "time_window": 300}
                ],
                "severity": "high",
                "confidence_threshold": 0.8,
                "created_at": datetime.now().isoformat()
            },
            {
                "signature_id": "data_exfiltration",
                "name": "Data Exfiltration Pattern",
                "description": "App uploads large amounts of data to external servers",
                "patterns": [
                    {"type": "network_upload", "threshold": 1048576, "time_window": 600},  # 1MB
                    {"type": "file_access", "path_pattern": "/data/data/", "threshold": 10}
                ],
                "severity": "critical",
                "confidence_threshold": 0.9,
                "created_at": datetime.now().isoformat()
            },
            {
                "signature_id": "privilege_escalation",
                "name": "Privilege Escalation Attempt",
                "description": "App attempts to gain elevated privileges",
                "patterns": [
                    {"type": "api_call", "pattern": "su", "threshold": 1},
                    {"type": "api_call", "pattern": "root", "threshold": 1},
                    {"type": "file_access", "path_pattern": "/system/", "threshold": 5}
                ],
                "severity": "critical",
                "confidence_threshold": 0.85,
                "created_at": datetime.now().isoformat()
            }
        ]
        
        for sig_data in default_signatures:
            signature = BehavioralSignature(**sig_data)
            self.behavioral_signatures[signature.signature_id] = signature
        
        # Save default signatures
        self.save_signatures()
    
    def analyze_behavior(self, runtime_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze runtime behavior against signatures."""
        matches = []
        
        for signature_id, signature in self.behavioral_signatures.items():
            match_result = self._match_signature(signature, runtime_data)
            if match_result['matched']:
                matches.append({
                    'signature_id': signature_id,
                    'signature_name': signature.name,
                    'severity': signature.severity,
                    'confidence': match_result['confidence'],
                    'description': signature.description,
                    'evidence': match_result['evidence'],
                    'detected_at': datetime.now().isoformat()
                })
        
        return matches
    
    def _match_signature(self, signature: BehavioralSignature, 
                        runtime_data: Dict[str, Any]) -> Dict[str, Any]:
        """Match runtime data against behavioral signature."""
        pattern_matches = []
        total_confidence = 0
        
        for pattern in signature.patterns:
            match_result = self._match_pattern(pattern, runtime_data)
            pattern_matches.append(match_result)
            if match_result['matched']:
                total_confidence += match_result.get('confidence', 0.5)
        
        # Calculate overall confidence
        matched_patterns = sum(1 for match in pattern_matches if match['matched'])
        if matched_patterns > 0:
            confidence = min(total_confidence / len(signature.patterns), 1.0)
        else:
            confidence = 0
        
        # Determine if signature matches
        matched = (confidence >= signature.confidence_threshold and 
                  matched_patterns >= len(signature.patterns) * 0.6)  # At least 60% of patterns
        
        return {
            'matched': matched,
            'confidence': confidence,
            'evidence': [match for match in pattern_matches if match['matched']]
        }
    
    def _match_pattern(self, pattern: Dict[str, Any], 
                      runtime_data: Dict[str, Any]) -> Dict[str, Any]:
        """Match individual pattern against runtime data."""
        pattern_type = pattern.get('type')
        threshold = pattern.get('threshold', 1)
        
        if pattern_type == 'sms_sent':
            sms_events = runtime_data.get('sms_events', [])
            count = len([event for event in sms_events if event.get('type') == 'sent'])
            return {
                'matched': count >= threshold,
                'confidence': min(count / threshold, 1.0) if threshold > 0 else 0,
                'details': f"SMS messages sent: {count}"
            }
        
        elif pattern_type == 'network_upload':
            network_events = runtime_data.get('network_events', [])
            total_upload = sum(event.get('bytes_sent', 0) for event in network_events)
            return {
                'matched': total_upload >= threshold,
                'confidence': min(total_upload / threshold, 1.0) if threshold > 0 else 0,
                'details': f"Data uploaded: {total_upload} bytes"
            }
        
        elif pattern_type == 'file_access':
            file_events = runtime_data.get('file_events', [])
            path_pattern = pattern.get('path_pattern', '')
            count = len([event for event in file_events 
                        if path_pattern in event.get('path', '')])
            return {
                'matched': count >= threshold,
                'confidence': min(count / threshold, 1.0) if threshold > 0 else 0,
                'details': f"File access count: {count}"
            }
        
        elif pattern_type == 'api_call':
            api_events = runtime_data.get('api_calls', [])
            api_pattern = pattern.get('pattern', '')
            count = len([event for event in api_events 
                        if api_pattern in event.get('call', '')])
            return {
                'matched': count >= threshold,
                'confidence': min(count / threshold, 1.0) if threshold > 0 else 0,
                'details': f"API call count: {count}"
            }
        
        elif pattern_type == 'user_interaction':
            ui_events = runtime_data.get('ui_events', [])
            count = len(ui_events)
            # For this pattern, we want low interaction count
            return {
                'matched': count <= threshold,
                'confidence': 1.0 - min(count / (threshold + 1), 1.0),
                'details': f"User interactions: {count}"
            }
        
        return {'matched': False, 'confidence': 0, 'details': 'Unknown pattern type'}
    
    def save_signatures(self):
        """Save behavioral signatures to file."""
        try:
            signatures_data = [
                asdict(signature) for signature in self.behavioral_signatures.values()
            ]
            
            signatures_file = self.signatures_path / "behavioral_signatures.json"
            with open(signatures_file, 'w') as f:
                json.dump(signatures_data, f, indent=2)
            
            logger.info(f"Saved {len(signatures_data)} behavioral signatures")
            
        except Exception as e:
            logger.error(f"Failed to save behavioral signatures: {e}")

class AdvancedThreatDetectionEngine:
    """Main advanced threat detection engine."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.base_dir = Path(config.get('base_dir', '.'))
        self.ml_dir = self.base_dir / "ml"
        self.ml_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.feature_extractor = FeatureExtractor()
        self.threat_classifier = ThreatClassifier(self.ml_dir / "models")
        self.behavioral_engine = BehavioralAnalysisEngine(self.ml_dir / "signatures")
        
        # Database for storing ML data
        self.db_path = self.ml_dir / "threat_detection.db"
        self._init_database()
        
        logger.info("Advanced Threat Detection Engine initialized")
    
    def _init_database(self):
        """Initialize threat detection database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Feature vectors table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feature_vectors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                apk_name TEXT NOT NULL,
                feature_type TEXT NOT NULL,
                features TEXT NOT NULL,
                extracted_at TEXT NOT NULL,
                metadata TEXT
            )
        ''')
        
        # Threat predictions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                apk_name TEXT NOT NULL,
                threat_category TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                confidence_level TEXT NOT NULL,
                model_version TEXT NOT NULL,
                predicted_at TEXT NOT NULL,
                prediction_details TEXT,
                evidence TEXT
            )
        ''')
        
        # Behavioral detections table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS behavioral_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                apk_name TEXT NOT NULL,
                signature_id TEXT NOT NULL,
                signature_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                detected_at TEXT NOT NULL,
                evidence TEXT
            )
        ''')
        
        # Model performance table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS model_performance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT NOT NULL,
                accuracy REAL NOT NULL,
                precision_score REAL NOT NULL,
                recall REAL NOT NULL,
                f1_score REAL NOT NULL,
                training_samples INTEGER NOT NULL,
                feature_count INTEGER NOT NULL,
                last_trained TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
        
        logger.info(f"Threat detection database initialized: {self.db_path}")
    
    def analyze_apk(self, apk_data: Dict[str, Any], 
                   analysis_mode: AnalysisMode = AnalysisMode.HYBRID_ANALYSIS) -> Dict[str, Any]:
        """Perform comprehensive threat analysis on APK."""
        try:
            apk_name = apk_data.get('apk_name', 'unknown')
            
            # Extract features
            feature_vector = self.feature_extractor.extract_features(apk_data, analysis_mode)
            self._store_feature_vector(feature_vector)
            
            # ML-based threat classification
            threat_prediction = self.threat_classifier.predict_threat(feature_vector)
            self._store_threat_prediction(threat_prediction)
            
            # Behavioral analysis (if runtime data available)
            behavioral_detections = []
            if 'runtime_analysis' in apk_data:
                behavioral_detections = self.behavioral_engine.analyze_behavior(apk_data)
                for detection in behavioral_detections:
                    self._store_behavioral_detection(apk_name, detection)
            
            # Combine results
            analysis_result = {
                'apk_name': apk_name,
                'analysis_mode': analysis_mode.value,
                'threat_prediction': asdict(threat_prediction),
                'behavioral_detections': behavioral_detections,
                'feature_vector': {
                    'feature_count': len(feature_vector.features),
                    'feature_type': feature_vector.feature_type,
                    'extracted_at': feature_vector.extracted_at
                },
                'analysis_summary': self._generate_analysis_summary(
                    threat_prediction, behavioral_detections
                ),
                'analyzed_at': datetime.now().isoformat()
            }
            
            logger.info(f"Threat analysis completed for {apk_name}: {threat_prediction.threat_category}")
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Threat analysis failed for {apk_data.get('apk_name', 'unknown')}: {e}")
            return {
                'apk_name': apk_data.get('apk_name', 'unknown'),
                'error': str(e),
                'analyzed_at': datetime.now().isoformat()
            }
    
    def train_models_with_data(self, training_data_path: Path) -> Dict[str, ModelMetrics]:
        """Train ML models with labeled training data."""
        try:
            if not training_data_path.exists():
                logger.error(f"Training data not found: {training_data_path}")
                return {}
            
            # Load training data
            with open(training_data_path, 'r') as f:
                training_data = json.load(f)
            
            features = []
            labels = []
            
            for sample in training_data:
                if 'features' in sample and 'label' in sample:
                    features.append(sample['features'])
                    labels.append(sample['label'])
            
            if not features:
                logger.error("No valid training samples found")
                return {}
            
            # Train models
            logger.info(f"Training models with {len(features)} samples...")
            model_metrics = self.threat_classifier.train_models(features, labels)
            
            # Store model performance
            for model_name, metrics in model_metrics.items():
                self._store_model_performance(metrics)
            
            return model_metrics
            
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            return {}
    
    def get_threat_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Get threat detection statistics."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            # Threat category distribution
            cursor.execute('''
                SELECT threat_category, COUNT(*) 
                FROM threat_predictions 
                WHERE predicted_at >= ?
                GROUP BY threat_category
            ''', (cutoff_date,))
            
            threat_distribution = dict(cursor.fetchall())
            
            # Confidence level distribution
            cursor.execute('''
                SELECT confidence_level, COUNT(*) 
                FROM threat_predictions 
                WHERE predicted_at >= ?
                GROUP BY confidence_level
            ''', (cutoff_date,))
            
            confidence_distribution = dict(cursor.fetchall())
            
            # Behavioral detection statistics
            cursor.execute('''
                SELECT signature_name, COUNT(*) 
                FROM behavioral_detections 
                WHERE detected_at >= ?
                GROUP BY signature_name
            ''', (cutoff_date,))
            
            behavioral_stats = dict(cursor.fetchall())
            
            # Model performance
            cursor.execute('''
                SELECT model_name, accuracy, f1_score 
                FROM model_performance 
                ORDER BY last_trained DESC
            ''')
            
            model_performance = [
                {'model': row[0], 'accuracy': row[1], 'f1_score': row[2]}
                for row in cursor.fetchall()
            ]
            
            conn.close()
            
            return {
                'period_days': days,
                'threat_distribution': threat_distribution,
                'confidence_distribution': confidence_distribution,
                'behavioral_detections': behavioral_stats,
                'model_performance': model_performance,
                'total_predictions': sum(threat_distribution.values()),
                'generated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get threat statistics: {e}")
            return {}
    
    def _generate_analysis_summary(self, threat_prediction: ThreatPrediction, 
                                 behavioral_detections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate analysis summary."""
        # Calculate overall risk score
        ml_risk = threat_prediction.confidence_score * 100
        
        # Behavioral risk
        behavioral_risk = 0
        if behavioral_detections:
            high_severity = sum(1 for d in behavioral_detections if d['severity'] == 'critical')
            medium_severity = sum(1 for d in behavioral_detections if d['severity'] == 'high')
            behavioral_risk = min((high_severity * 30 + medium_severity * 20), 100)
        
        # Combined risk score
        overall_risk = min((ml_risk * 0.7 + behavioral_risk * 0.3), 100)
        
        # Risk level
        if overall_risk >= 80:
            risk_level = "CRITICAL"
        elif overall_risk >= 60:
            risk_level = "HIGH"
        elif overall_risk >= 40:
            risk_level = "MEDIUM"
        elif overall_risk >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        return {
            'overall_risk_score': round(overall_risk, 1),
            'risk_level': risk_level,
            'ml_risk_score': round(ml_risk, 1),
            'behavioral_risk_score': round(behavioral_risk, 1),
            'threat_category': threat_prediction.threat_category,
            'confidence_level': threat_prediction.confidence_level,
            'behavioral_detections_count': len(behavioral_detections),
            'high_confidence_ml': threat_prediction.confidence_score >= 0.8,
            'critical_behavioral_detections': sum(1 for d in behavioral_detections 
                                                if d['severity'] == 'critical')
        }
    
    def _store_feature_vector(self, feature_vector: FeatureVector):
        """Store feature vector in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO feature_vectors 
                (apk_name, feature_type, features, extracted_at, metadata)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                feature_vector.apk_name,
                feature_vector.feature_type,
                json.dumps(feature_vector.features),
                feature_vector.extracted_at,
                json.dumps(feature_vector.metadata)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store feature vector: {e}")
    
    def _store_threat_prediction(self, prediction: ThreatPrediction):
        """Store threat prediction in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO threat_predictions 
                (apk_name, threat_category, confidence_score, confidence_level,
                 model_version, predicted_at, prediction_details, evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                prediction.apk_name,
                prediction.threat_category,
                prediction.confidence_score,
                prediction.confidence_level,
                prediction.model_version,
                prediction.predicted_at,
                json.dumps(prediction.prediction_details),
                json.dumps(prediction.evidence)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store threat prediction: {e}")
    
    def _store_behavioral_detection(self, apk_name: str, detection: Dict[str, Any]):
        """Store behavioral detection in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO behavioral_detections 
                (apk_name, signature_id, signature_name, severity, confidence,
                 detected_at, evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                apk_name,
                detection['signature_id'],
                detection['signature_name'],
                detection['severity'],
                detection['confidence'],
                detection['detected_at'],
                json.dumps(detection['evidence'])
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store behavioral detection: {e}")
    
    def _store_model_performance(self, metrics: ModelMetrics):
        """Store model performance metrics in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO model_performance 
                (model_name, accuracy, precision_score, recall, f1_score,
                 training_samples, feature_count, last_trained)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                metrics.model_name,
                metrics.accuracy,
                metrics.precision,
                metrics.recall,
                metrics.f1_score,
                metrics.training_samples,
                metrics.feature_count,
                metrics.last_trained
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store model performance: {e}")

# Global threat detection engine instance
threat_detection_engine = None

def initialize_threat_detection_engine(config: Dict[str, Any]) -> AdvancedThreatDetectionEngine:
    """Initialize global threat detection engine."""
    global threat_detection_engine
    threat_detection_engine = AdvancedThreatDetectionEngine(config)
    return threat_detection_engine

def get_threat_detection_engine() -> Optional[AdvancedThreatDetectionEngine]:
    """Get global threat detection engine instance."""
    return threat_detection_engine 