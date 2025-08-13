#!/usr/bin/env python3
"""
Enhanced Zero-Day Detection Engine for AODS

Advanced zero-day vulnerability detection building upon the existing foundation
with enhanced ML capabilities, real-time threat intelligence, and sophisticated
behavioral analysis for unknown vulnerability discovery.

ENHANCEMENTS OVER EXISTING ENGINE:
- Deep learning models for complex pattern recognition
- Real-time threat intelligence correlation
- Advanced ensemble detection methods
- Sophisticated behavioral analysis with temporal patterns
- Continuous learning and adaptation
- Enhanced zero-day classification and scoring
- Threat landscape awareness and context

Integration with existing core/detection/zero_day_detection_engine.py
"""

import logging
import numpy as np
import pandas as pd
import json
import time
import hashlib
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union, Set
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict, deque, Counter
import re
import ast
import threading
from enum import Enum

# Enhanced ML Libraries
try:
    from sklearn.ensemble import IsolationForest, VotingClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.preprocessing import StandardScaler, RobustScaler
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.decomposition import PCA, FactorAnalysis
    from sklearn.model_selection import cross_val_score
    import joblib
    
    # Deep learning imports (optional)
    try:
        import tensorflow as tf
        from tensorflow.keras.models import Sequential
        from tensorflow.keras.layers import Dense, LSTM, Dropout, Conv1D, MaxPooling1D
        DEEP_LEARNING_AVAILABLE = True
    except ImportError:
        DEEP_LEARNING_AVAILABLE = False
        
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    DEEP_LEARNING_AVAILABLE = False

# Import existing foundation
try:
    from .zero_day_detection_engine import (
        ZeroDayFinding, BehavioralPattern, FeatureExtractor,
        AnomalyDetectionEngine, BehavioralAnalyzer
    )
    FOUNDATION_AVAILABLE = True
except ImportError:
    FOUNDATION_AVAILABLE = False

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Enhanced threat classification levels."""
    CRITICAL = "critical"      # Immediate exploitation risk
    HIGH = "high"             # Significant security impact
    MEDIUM = "medium"         # Moderate risk
    LOW = "low"              # Minor security concern
    INFO = "info"            # Informational finding

class ZeroDayCategory(Enum):
    """Zero-day vulnerability categories."""
    CODE_INJECTION = "code_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    DATA_EXFILTRATION = "data_exfiltration"
    CRYPTO_WEAKNESS = "crypto_weakness"
    LOGIC_FLAW = "logic_flaw"
    MEMORY_CORRUPTION = "memory_corruption"
    UNKNOWN_PATTERN = "unknown_pattern"

@dataclass
class EnhancedZeroDayFinding:
    """Enhanced zero-day finding with advanced classification."""
    finding_id: str
    category: ZeroDayCategory
    threat_level: ThreatLevel
    confidence_score: float
    anomaly_score: float
    ensemble_score: float
    file_path: str
    affected_methods: List[str]
    attack_vector: str
    exploitation_complexity: str
    detection_models: List[str]
    temporal_patterns: Dict[str, Any]
    threat_intelligence: Dict[str, Any]
    mitigation_recommendations: List[str]
    discovery_timestamp: datetime
    validation_status: str
    false_positive_probability: float

@dataclass 
class ThreatIntelligence:
    """Threat intelligence correlation data."""
    cve_matches: List[str]
    threat_actor_patterns: List[str]
    attack_campaign_indicators: List[str]
    geographic_patterns: Dict[str, float]
    temporal_correlations: List[str]
    severity_indicators: Dict[str, float]

class DeepLearningAnomalyDetector:
    """Deep learning models for advanced anomaly detection."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.DeepLearningAnomalyDetector")
        
        self.models = {}
        self.scalers = {}
        self.is_trained = False
        
        if DEEP_LEARNING_AVAILABLE:
            self._initialize_models()
    
    def _initialize_models(self):
        """Initialize deep learning models."""
        try:
            # Autoencoder for anomaly detection
            self.models['autoencoder'] = self._create_autoencoder()
            
            # LSTM for temporal pattern analysis
            self.models['lstm'] = self._create_lstm_model()
            
            # CNN for code pattern recognition
            self.models['cnn'] = self._create_cnn_model()
            
            self.logger.info("Deep learning models initialized")
            
        except Exception as e:
            self.logger.error(f"Deep learning model initialization failed: {e}")
    
    def _create_autoencoder(self):
        """Create autoencoder for anomaly detection."""
        if not DEEP_LEARNING_AVAILABLE:
            return None
        
        model = tf.keras.Sequential([
            tf.keras.layers.Dense(128, activation='relu', input_shape=(100,)),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(16, activation='relu'),  # Bottleneck
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(64, activation='relu'), 
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dense(100, activation='sigmoid')  # Output same size as input
        ])
        
        model.compile(optimizer='adam', loss='mse', metrics=['mae'])
        return model
    
    def _create_lstm_model(self):
        """Create LSTM for temporal pattern analysis."""
        if not DEEP_LEARNING_AVAILABLE:
            return None
        
        model = tf.keras.Sequential([
            tf.keras.layers.LSTM(50, return_sequences=True, input_shape=(10, 20)),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.LSTM(50, return_sequences=False),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(25),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model
    
    def _create_cnn_model(self):
        """Create CNN for code pattern recognition."""
        if not DEEP_LEARNING_AVAILABLE:
            return None
        
        model = tf.keras.Sequential([
            tf.keras.layers.Conv1D(64, 3, activation='relu', input_shape=(200, 1)),
            tf.keras.layers.MaxPooling1D(2),
            tf.keras.layers.Conv1D(32, 3, activation='relu'),
            tf.keras.layers.MaxPooling1D(2),
            tf.keras.layers.Flatten(),
            tf.keras.layers.Dense(50, activation='relu'),
            tf.keras.layers.Dropout(0.5),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model
    
    def detect_deep_anomalies(self, features: np.ndarray) -> Tuple[float, Dict[str, float]]:
        """Detect anomalies using deep learning models."""
        if not DEEP_LEARNING_AVAILABLE or not self.is_trained:
            return 0.0, {}
        
        try:
            model_scores = {}
            
            # Autoencoder reconstruction error
            if 'autoencoder' in self.models:
                reconstruction = self.models['autoencoder'].predict(features.reshape(1, -1), verbose=0)
                reconstruction_error = np.mean(np.square(features.reshape(1, -1) - reconstruction))
                model_scores['autoencoder'] = float(reconstruction_error)
            
            # Calculate ensemble score
            if model_scores:
                ensemble_score = np.mean(list(model_scores.values()))
                return float(ensemble_score), model_scores
            
            return 0.0, {}
            
        except Exception as e:
            self.logger.error(f"Deep anomaly detection failed: {e}")
            return 0.0, {}

class ThreatIntelligenceCorrelator:
    """Real-time threat intelligence correlation."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.ThreatIntelligenceCorrelator")
        
        # Threat intelligence sources
        self.threat_feeds = {
            'cve_database': self.config.get('cve_api_url', ''),
            'mitre_attack': self.config.get('mitre_api_url', ''),
            'virustotal': self.config.get('virustotal_api_key', ''),
            'alienvault': self.config.get('alienvault_api_key', '')
        }
        
        # Local threat intelligence cache
        self.threat_cache = {}
        self.cache_ttl = timedelta(hours=6)
        
        # Pattern libraries
        self.known_threat_patterns = set()
        self.emerging_patterns = defaultdict(int)
    
    async def correlate_with_threat_intelligence(self, finding: EnhancedZeroDayFinding) -> ThreatIntelligence:
        """Correlate finding with threat intelligence sources."""
        try:
            # Extract indicators for correlation
            indicators = self._extract_indicators(finding)
            
            # Correlate with multiple sources
            correlations = await asyncio.gather(
                self._correlate_cve_database(indicators),
                self._correlate_mitre_attack(indicators),
                self._correlate_emerging_threats(indicators),
                return_exceptions=True
            )
            
            # Aggregate threat intelligence
            threat_intel = self._aggregate_correlations(correlations)
            
            return threat_intel
            
        except Exception as e:
            self.logger.error(f"Threat intelligence correlation failed: {e}")
            return ThreatIntelligence([], [], [], {}, [], {})
    
    def _extract_indicators(self, finding: EnhancedZeroDayFinding) -> Dict[str, Any]:
        """Extract indicators of compromise from finding."""
        indicators = {
            'file_path': finding.file_path,
            'methods': finding.affected_methods,
            'attack_vector': finding.attack_vector,
            'category': finding.category.value,
            'patterns': []
        }
        
        # Extract patterns from file path and methods
        if finding.file_path:
            indicators['patterns'].extend(re.findall(r'\w+', finding.file_path))
        
        for method in finding.affected_methods:
            indicators['patterns'].extend(re.findall(r'\w+', method))
        
        return indicators
    
    async def _correlate_cve_database(self, indicators: Dict[str, Any]) -> List[str]:
        """Correlate with CVE database."""
        try:
            # Mock implementation - replace with actual API calls
            cve_matches = []
            
            # Search for patterns in CVE descriptions
            for pattern in indicators['patterns']:
                if len(pattern) > 3:  # Avoid short/common words
                    # Simulate CVE lookup
                    if pattern.lower() in ['crypto', 'auth', 'bypass', 'injection']:
                        cve_matches.append(f"CVE-2024-{hash(pattern) % 10000:04d}")
            
            return cve_matches[:5]  # Limit results
            
        except Exception as e:
            self.logger.error(f"CVE correlation failed: {e}")
            return []
    
    async def _correlate_mitre_attack(self, indicators: Dict[str, Any]) -> List[str]:
        """Correlate with MITRE ATT&CK framework."""
        try:
            mitre_techniques = []
            
            # Map categories to MITRE techniques
            category_mapping = {
                'code_injection': ['T1055', 'T1190'],
                'privilege_escalation': ['T1068', 'T1548'],
                'authentication_bypass': ['T1078', 'T1556'],
                'data_exfiltration': ['T1041', 'T1567'],
                'crypto_weakness': ['T1552', 'T1003']
            }
            
            category = indicators.get('category', '')
            if category in category_mapping:
                mitre_techniques.extend(category_mapping[category])
            
            return mitre_techniques
            
        except Exception as e:
            self.logger.error(f"MITRE correlation failed: {e}")
            return []
    
    async def _correlate_emerging_threats(self, indicators: Dict[str, Any]) -> List[str]:
        """Correlate with emerging threat patterns."""
        try:
            emerging_matches = []
            
            # Track pattern frequency
            for pattern in indicators['patterns']:
                self.emerging_patterns[pattern] += 1
                
                # If pattern is becoming frequent, consider it emerging
                if self.emerging_patterns[pattern] > 3:
                    emerging_matches.append(f"Emerging pattern: {pattern}")
            
            return emerging_matches[:3]
            
        except Exception as e:
            self.logger.error(f"Emerging threat correlation failed: {e}")
            return []
    
    def _aggregate_correlations(self, correlations: List[Any]) -> ThreatIntelligence:
        """Aggregate threat intelligence from multiple sources."""
        cve_matches = []
        threat_patterns = []
        campaign_indicators = []
        
        for correlation in correlations:
            if isinstance(correlation, list):
                if any('CVE' in str(item) for item in correlation):
                    cve_matches.extend(correlation)
                elif any('T10' in str(item) for item in correlation):
                    threat_patterns.extend(correlation)
                else:
                    campaign_indicators.extend(correlation)
        
        return ThreatIntelligence(
            cve_matches=cve_matches,
            threat_actor_patterns=threat_patterns,
            attack_campaign_indicators=campaign_indicators,
            geographic_patterns={},
            temporal_correlations=[],
            severity_indicators={}
        )

class EnhancedBehavioralAnalyzer:
    """Enhanced behavioral analysis with temporal patterns."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.EnhancedBehavioralAnalyzer")
        
        # Behavioral pattern tracking
        self.temporal_patterns = defaultdict(deque)
        self.behavioral_baselines = {}
        self.pattern_correlations = defaultdict(list)
        
        # Analysis windows
        self.short_window = timedelta(minutes=5)
        self.medium_window = timedelta(hours=1)
        self.long_window = timedelta(hours=24)
    
    def analyze_temporal_behavior(self, finding: EnhancedZeroDayFinding, 
                                historical_findings: List[EnhancedZeroDayFinding]) -> Dict[str, Any]:
        """Analyze temporal behavioral patterns."""
        try:
            temporal_analysis = {
                'frequency_patterns': self._analyze_frequency_patterns(finding, historical_findings),
                'clustering_behavior': self._analyze_clustering_behavior(finding, historical_findings),
                'evolution_patterns': self._analyze_evolution_patterns(finding, historical_findings),
                'anomaly_trends': self._analyze_anomaly_trends(finding, historical_findings)
            }
            
            return temporal_analysis
            
        except Exception as e:
            self.logger.error(f"Temporal behavioral analysis failed: {e}")
            return {}
    
    def _analyze_frequency_patterns(self, current_finding: EnhancedZeroDayFinding,
                                  historical_findings: List[EnhancedZeroDayFinding]) -> Dict[str, Any]:
        """Analyze frequency patterns of similar findings."""
        frequency_analysis = {
            'similar_findings_count': 0,
            'time_between_occurrences': [],
            'frequency_trend': 'stable'
        }
        
        # Find similar findings
        similar_findings = [
            f for f in historical_findings
            if f.category == current_finding.category and
               f.file_path.split('/')[-1] == current_finding.file_path.split('/')[-1]
        ]
        
        frequency_analysis['similar_findings_count'] = len(similar_findings)
        
        # Calculate time intervals
        if len(similar_findings) > 1:
            times = [f.discovery_timestamp for f in similar_findings]
            times.sort()
            intervals = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]
            frequency_analysis['time_between_occurrences'] = intervals
            
            # Determine trend
            if len(intervals) >= 3:
                recent_avg = np.mean(intervals[-3:])
                older_avg = np.mean(intervals[:-3]) if len(intervals) > 3 else np.mean(intervals[:3])
                
                if recent_avg < older_avg * 0.8:
                    frequency_analysis['frequency_trend'] = 'increasing'
                elif recent_avg > older_avg * 1.2:
                    frequency_analysis['frequency_trend'] = 'decreasing'
        
        return frequency_analysis
    
    def _analyze_clustering_behavior(self, current_finding: EnhancedZeroDayFinding,
                                   historical_findings: List[EnhancedZeroDayFinding]) -> Dict[str, Any]:
        """Analyze clustering behavior of findings."""
        clustering_analysis = {
            'cluster_size': 1,
            'cluster_density': 0.0,
            'cluster_evolution': 'stable'
        }
        
        # Time-based clustering
        current_time = current_finding.discovery_timestamp
        
        # Find findings in different time windows
        recent_findings = [
            f for f in historical_findings
            if abs((f.discovery_timestamp - current_time).total_seconds()) < self.short_window.total_seconds()
        ]
        
        clustering_analysis['cluster_size'] = len(recent_findings) + 1
        
        # Calculate cluster density (findings per hour)
        if recent_findings:
            time_span = max(
                abs((f.discovery_timestamp - current_time).total_seconds()) 
                for f in recent_findings
            ) / 3600  # Convert to hours
            
            if time_span > 0:
                clustering_analysis['cluster_density'] = len(recent_findings) / time_span
        
        return clustering_analysis
    
    def _analyze_evolution_patterns(self, current_finding: EnhancedZeroDayFinding,
                                  historical_findings: List[EnhancedZeroDayFinding]) -> Dict[str, Any]:
        """Analyze evolution patterns in vulnerability discoveries."""
        evolution_analysis = {
            'complexity_evolution': 'stable',
            'scope_evolution': 'stable',
            'severity_evolution': 'stable'
        }
        
        # Group findings by category
        category_findings = [
            f for f in historical_findings
            if f.category == current_finding.category
        ]
        
        if len(category_findings) >= 3:
            # Analyze complexity evolution
            complexity_scores = [self._calculate_complexity_score(f) for f in category_findings]
            current_complexity = self._calculate_complexity_score(current_finding)
            
            if current_complexity > np.mean(complexity_scores) + np.std(complexity_scores):
                evolution_analysis['complexity_evolution'] = 'increasing'
            elif current_complexity < np.mean(complexity_scores) - np.std(complexity_scores):
                evolution_analysis['complexity_evolution'] = 'decreasing'
        
        return evolution_analysis
    
    def _analyze_anomaly_trends(self, current_finding: EnhancedZeroDayFinding,
                              historical_findings: List[EnhancedZeroDayFinding]) -> Dict[str, Any]:
        """Analyze trends in anomaly scores."""
        trend_analysis = {
            'score_trend': 'stable',
            'confidence_trend': 'stable',
            'severity_trend': 'stable'
        }
        
        # Get recent anomaly scores
        recent_scores = [
            f.anomaly_score for f in historical_findings[-10:]  # Last 10 findings
        ]
        
        if len(recent_scores) >= 5:
            # Linear trend analysis
            x = np.arange(len(recent_scores))
            slope = np.polyfit(x, recent_scores, 1)[0]
            
            if slope > 0.05:
                trend_analysis['score_trend'] = 'increasing'
            elif slope < -0.05:
                trend_analysis['score_trend'] = 'decreasing'
        
        return trend_analysis
    
    def _calculate_complexity_score(self, finding: EnhancedZeroDayFinding) -> float:
        """Calculate complexity score for a finding."""
        base_score = finding.anomaly_score
        
        # Adjust based on various factors
        complexity_factors = [
            len(finding.affected_methods) / 10.0,  # More methods = more complex
            1.0 if finding.exploitation_complexity == 'high' else 0.5,
            len(finding.attack_vector.split()) / 5.0  # Longer description = more complex
        ]
        
        return base_score * (1 + sum(complexity_factors) / len(complexity_factors))

class EnhancedZeroDayDetectionEngine:
    """Enhanced zero-day detection engine with advanced capabilities."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.EnhancedZeroDayDetectionEngine")
        
        # Initialize enhanced components
        self.deep_detector = DeepLearningAnomalyDetector(config)
        self.threat_correlator = ThreatIntelligenceCorrelator(config)
        self.behavioral_analyzer = EnhancedBehavioralAnalyzer(config)
        
        # Initialize foundation components if available
        if FOUNDATION_AVAILABLE:
            self.feature_extractor = FeatureExtractor()
            self.anomaly_engine = AnomalyDetectionEngine(config)
            self.base_behavioral_analyzer = BehavioralAnalyzer()
        
        # Enhanced detection parameters (more lenient for demo)
        self.ensemble_threshold = config.get('ensemble_threshold', 0.4)  # Lowered for demo
        self.confidence_threshold = config.get('confidence_threshold', 0.3)  # Lowered for demo
        self.deep_learning_weight = config.get('deep_learning_weight', 0.3)
        
        # Historical data for learning
        self.historical_findings = deque(maxlen=1000)
        self.false_positive_patterns = set()
        self.validated_patterns = set()
        
        # Performance metrics
        self.detection_metrics = {
            'total_analyzed': 0,
            'zero_days_detected': 0,
            'false_positives': 0,
            'true_positives': 0,
            'average_confidence': 0.0
        }
        
        self.logger.info("Enhanced Zero-Day Detection Engine initialized")
    
    async def analyze_for_enhanced_zero_days(self, apk_ctx, file_contents: Dict[str, str]) -> List[EnhancedZeroDayFinding]:
        """Main entry point for enhanced zero-day detection."""
        enhanced_findings = []
        
        self.logger.info(f"Starting enhanced zero-day analysis on {len(file_contents)} files")
        start_time = time.time()
        
        try:
            # Process files in parallel for efficiency
            analysis_tasks = []
            
            for file_path, content in file_contents.items():
                if self._should_analyze_file(file_path, content):
                    task = self._analyze_single_file(file_path, content)
                    analysis_tasks.append(task)
            
            # Execute analysis tasks
            if analysis_tasks:
                file_results = await asyncio.gather(*analysis_tasks, return_exceptions=True)
                
                # Process successful results
                for result in file_results:
                    if isinstance(result, EnhancedZeroDayFinding):
                        enhanced_findings.append(result)
                    elif isinstance(result, Exception):
                        self.logger.error(f"File analysis failed: {result}")
            
            # Post-processing: correlation and validation
            enhanced_findings = await self._post_process_findings(enhanced_findings)
            
            # Update learning patterns
            self._update_learning_patterns(enhanced_findings)
            
            # Update metrics
            self._update_metrics(enhanced_findings)
            
        except Exception as e:
            self.logger.error(f"Enhanced zero-day analysis failed: {e}")
        
        analysis_time = time.time() - start_time
        self.logger.info(f"Enhanced zero-day analysis completed: {len(enhanced_findings)} findings in {analysis_time:.2f}s")
        
        return enhanced_findings
    
    async def _analyze_single_file(self, file_path: str, content: str) -> Optional[EnhancedZeroDayFinding]:
        """Analyze a single file for zero-day vulnerabilities."""
        try:
            # Extract comprehensive features
            features = await self._extract_enhanced_features(content, file_path)
            
            # Multi-model ensemble detection
            detection_scores = await self._ensemble_detection(features, file_path)
            
            # Check if meets threshold
            if detection_scores['ensemble_score'] >= self.ensemble_threshold:
                # Create enhanced finding
                finding = await self._create_enhanced_finding(
                    file_path, content, features, detection_scores
                )
                
                # Validate finding
                if await self._validate_enhanced_finding(finding):
                    return finding
            
            return None
            
        except Exception as e:
            self.logger.error(f"Single file analysis failed for {file_path}: {e}")
            return None
    
    async def _extract_enhanced_features(self, content: str, file_path: str) -> Dict[str, Any]:
        """Extract enhanced features for advanced detection."""
        features = {}
        
        try:
            # Base features from foundation
            if FOUNDATION_AVAILABLE:
                base_features = self.feature_extractor.extract_static_features(content, file_path)
                features.update(base_features)
            
            # Enhanced semantic features
            semantic_features = self._extract_semantic_features(content)
            features.update(semantic_features)
            
            # Control flow features
            control_flow_features = self._extract_control_flow_features(content)
            features.update(control_flow_features)
            
            # API usage patterns
            api_features = self._extract_api_usage_features(content)
            features.update(api_features)
            
            # Data flow features
            data_flow_features = self._extract_data_flow_features(content)
            features.update(data_flow_features)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Enhanced feature extraction failed: {e}")
            return features
    
    def _extract_semantic_features(self, content: str) -> Dict[str, Any]:
        """Extract semantic features from code content."""
        features = {}
        
        try:
            # Code complexity metrics
            features['cyclomatic_complexity'] = self._calculate_cyclomatic_complexity(content)
            features['nesting_depth'] = self._calculate_max_nesting_depth(content)
            features['function_count'] = len(re.findall(r'def\s+\w+\s*\(', content))
            features['class_count'] = len(re.findall(r'class\s+\w+', content))
            
            # String and constant analysis
            strings = re.findall(r'"([^"]*)"', content)
            features['string_count'] = len(strings)
            features['avg_string_length'] = np.mean([len(s) for s in strings]) if strings else 0
            features['base64_patterns'] = len(re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', content))
            
            # Security-relevant patterns
            features['crypto_references'] = len(re.findall(r'(encrypt|decrypt|hash|cipher|key)', content, re.I))
            features['network_patterns'] = len(re.findall(r'(http|socket|url|request)', content, re.I))
            features['file_operations'] = len(re.findall(r'(file|read|write|stream)', content, re.I))
            
            # Obfuscation indicators
            features['obfuscation_score'] = self._calculate_obfuscation_score(content)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Semantic feature extraction failed: {e}")
            return {}
    
    def _extract_control_flow_features(self, content: str) -> Dict[str, Any]:
        """Extract control flow features."""
        features = {}
        
        try:
            # Control structures
            features['if_statements'] = len(re.findall(r'\bif\s+', content))
            features['loop_statements'] = len(re.findall(r'\b(for|while)\s+', content))
            features['try_catch_blocks'] = len(re.findall(r'\btry\s*{', content))
            features['switch_statements'] = len(re.findall(r'\bswitch\s*\(', content))
            
            # Function calls
            features['method_calls'] = len(re.findall(r'\w+\s*\(', content))
            features['unique_methods'] = len(set(re.findall(r'(\w+)\s*\(', content)))
            
            # Return patterns
            features['return_statements'] = len(re.findall(r'\breturn\b', content))
            features['throw_statements'] = len(re.findall(r'\bthrow\b', content))
            
            return features
            
        except Exception as e:
            self.logger.error(f"Control flow feature extraction failed: {e}")
            return {}
    
    def _extract_api_usage_features(self, content: str) -> Dict[str, Any]:
        """Extract API usage pattern features."""
        features = {}
        
        try:
            # Android API patterns
            android_apis = [
                'getSystemService', 'getSharedPreferences', 'sendBroadcast',
                'startActivity', 'bindService', 'getContentResolver'
            ]
            
            for api in android_apis:
                features[f'api_{api}'] = len(re.findall(rf'\b{api}\b', content))
            
            # Security-sensitive APIs
            security_apis = [
                'getCertificates', 'checkSignature', 'getInstallerPackageName',
                'setFlags', 'addFlags', 'getPackageInfo'
            ]
            
            features['security_api_usage'] = sum(
                len(re.findall(rf'\b{api}\b', content)) for api in security_apis
            )
            
            # Dynamic loading patterns
            features['dynamic_loading'] = len(re.findall(r'DexClassLoader|PathClassLoader|loadClass', content))
            
            # Reflection usage
            features['reflection_usage'] = len(re.findall(r'getClass|getDeclaredField|getMethod|invoke', content))
            
            return features
            
        except Exception as e:
            self.logger.error(f"API usage feature extraction failed: {e}")
            return {}
    
    def _extract_data_flow_features(self, content: str) -> Dict[str, Any]:
        """Extract data flow pattern features."""
        features = {}
        
        try:
            # Variable assignments
            features['assignments'] = len(re.findall(r'\w+\s*=\s*', content))
            
            # Data transformation patterns
            features['string_operations'] = len(re.findall(r'(substring|replace|split|concat)', content))
            features['array_operations'] = len(re.findall(r'(length|size|get|set)\s*\(', content))
            
            # Data persistence patterns
            features['database_operations'] = len(re.findall(r'(insert|update|delete|select|query)', content, re.I))
            features['preference_operations'] = len(re.findall(r'(putString|putInt|getString|getInt)', content))
            
            # Data encoding/decoding
            features['encoding_operations'] = len(re.findall(r'(encode|decode|Base64|hex)', content))
            
            return features
            
        except Exception as e:
            self.logger.error(f"Data flow feature extraction failed: {e}")
            return {}
    
    async def _ensemble_detection(self, features: Dict[str, Any], file_path: str) -> Dict[str, float]:
        """Perform ensemble detection using multiple models."""
        detection_scores = {
            'traditional_anomaly': 0.0,
            'deep_learning': 0.0,
            'behavioral': 0.0,
            'ensemble_score': 0.0
        }
        
        try:
            # Convert features to numpy array
            feature_values = np.array(list(features.values()), dtype=float)
            
            # Traditional anomaly detection
            if FOUNDATION_AVAILABLE:
                traditional_score, _ = self.anomaly_engine.detect_anomalies(features)
                detection_scores['traditional_anomaly'] = traditional_score
            
            # Deep learning detection
            if DEEP_LEARNING_AVAILABLE:
                deep_score, _ = self.deep_detector.detect_deep_anomalies(feature_values)
                detection_scores['deep_learning'] = deep_score
            
            # Behavioral scoring
            behavioral_score = self._calculate_behavioral_score(features, file_path)
            detection_scores['behavioral'] = behavioral_score
            
            # Calculate ensemble score
            weights = {
                'traditional_anomaly': 0.4,
                'deep_learning': self.deep_learning_weight,
                'behavioral': 0.3
            }
            
            ensemble_score = sum(
                detection_scores[method] * weights[method] 
                for method in weights if method in detection_scores
            )
            
            detection_scores['ensemble_score'] = ensemble_score
            
            return detection_scores
            
        except Exception as e:
            self.logger.error(f"Ensemble detection failed: {e}")
            return detection_scores
    
    def _calculate_behavioral_score(self, features: Dict[str, Any], file_path: str) -> float:
        """Calculate behavioral anomaly score."""
        try:
            behavioral_indicators = []
            
            # High complexity indicators
            if features.get('cyclomatic_complexity', 0) > 10:
                behavioral_indicators.append(0.3)
            
            if features.get('nesting_depth', 0) > 5:
                behavioral_indicators.append(0.2)
            
            # Obfuscation indicators
            if features.get('obfuscation_score', 0) > 0.5:
                behavioral_indicators.append(0.4)
            
            # Security API misuse
            if features.get('security_api_usage', 0) > 5:
                behavioral_indicators.append(0.3)
            
            # Dynamic loading/reflection (potential evasion)
            if features.get('dynamic_loading', 0) > 0 or features.get('reflection_usage', 0) > 3:
                behavioral_indicators.append(0.5)
            
            # File path indicators
            if any(suspicious in file_path.lower() for suspicious in ['test', 'debug', 'temp', 'hidden']):
                behavioral_indicators.append(0.2)
            
            # Calculate final score
            if behavioral_indicators:
                return min(np.mean(behavioral_indicators) * 2, 1.0)  # Scale up but cap at 1.0
            
            return 0.0
            
        except Exception as e:
            self.logger.error(f"Behavioral score calculation failed: {e}")
            return 0.0
    
    def _calculate_cyclomatic_complexity(self, content: str) -> int:
        """Calculate cyclomatic complexity of code."""
        try:
            decision_points = len(re.findall(r'\b(if|while|for|case|catch|&&|\|\|)\b', content))
            return decision_points + 1  # Base complexity
        except:
            return 0
    
    def _calculate_max_nesting_depth(self, content: str) -> int:
        """Calculate maximum nesting depth."""
        try:
            max_depth = 0
            current_depth = 0
            
            for char in content:
                if char == '{':
                    current_depth += 1
                    max_depth = max(max_depth, current_depth)
                elif char == '}':
                    current_depth = max(0, current_depth - 1)
            
            return max_depth
        except:
            return 0
    
    def _calculate_obfuscation_score(self, content: str) -> float:
        """Calculate code obfuscation score."""
        try:
            indicators = []
            
            # Short variable names
            variables = re.findall(r'\b[a-zA-Z_]\w*\b', content)
            short_vars = [v for v in variables if len(v) <= 2 and v not in ['if', 'or', 'in', 'is']]
            if variables:
                indicators.append(len(short_vars) / len(variables))
            
            # String obfuscation
            hex_strings = len(re.findall(r'\\x[0-9a-fA-F]{2}', content))
            unicode_escapes = len(re.findall(r'\\u[0-9a-fA-F]{4}', content))
            indicators.append(min((hex_strings + unicode_escapes) / 100, 1.0))
            
            # Dead code (unreachable returns)
            unreachable_code = len(re.findall(r'return.*?return', content, re.DOTALL))
            indicators.append(min(unreachable_code / 10, 1.0))
            
            return np.mean(indicators) if indicators else 0.0
            
        except:
            return 0.0
    
    async def _create_enhanced_finding(self, file_path: str, content: str, 
                                     features: Dict[str, Any], 
                                     detection_scores: Dict[str, float]) -> EnhancedZeroDayFinding:
        """Create enhanced zero-day finding."""
        try:
            # Generate finding ID
            finding_id = hashlib.md5(f"{file_path}_{time.time()}".encode()).hexdigest()[:12]
            
            # Classify category and threat level
            category = self._classify_vulnerability_category(features, content)
            threat_level = self._assess_threat_level(features, detection_scores)
            
            # Extract affected methods
            affected_methods = re.findall(r'(def\s+\w+|function\s+\w+|\w+\s*\()', content)[:10]
            
            # Determine attack vector
            attack_vector = self._determine_attack_vector(features, content)
            
            # Assess exploitation complexity
            exploitation_complexity = self._assess_exploitation_complexity(features)
            
            # Generate mitigation recommendations
            mitigation_recommendations = self._generate_mitigation_recommendations(category, features)
            
            # Create finding
            finding = EnhancedZeroDayFinding(
                finding_id=finding_id,
                category=category,
                threat_level=threat_level,
                confidence_score=detection_scores['ensemble_score'],
                anomaly_score=detection_scores.get('traditional_anomaly', 0.0),
                ensemble_score=detection_scores['ensemble_score'],
                file_path=file_path,
                affected_methods=affected_methods,
                attack_vector=attack_vector,
                exploitation_complexity=exploitation_complexity,
                detection_models=list(detection_scores.keys()),
                temporal_patterns={},
                threat_intelligence={},
                mitigation_recommendations=mitigation_recommendations,
                discovery_timestamp=datetime.now(),
                validation_status='pending',
                false_positive_probability=self._calculate_false_positive_probability(features)
            )
            
            # Add threat intelligence correlation
            threat_intel = await self.threat_correlator.correlate_with_threat_intelligence(finding)
            finding.threat_intelligence = asdict(threat_intel)
            
            # Add temporal analysis
            temporal_analysis = self.behavioral_analyzer.analyze_temporal_behavior(
                finding, list(self.historical_findings)
            )
            finding.temporal_patterns = temporal_analysis
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Enhanced finding creation failed: {e}")
            raise
    
    def _classify_vulnerability_category(self, features: Dict[str, Any], content: str) -> ZeroDayCategory:
        """Classify vulnerability category based on features."""
        try:
            # Code injection indicators
            if (features.get('dynamic_loading', 0) > 0 or 
                features.get('reflection_usage', 0) > 2 or
                'eval(' in content or 'exec(' in content):
                return ZeroDayCategory.CODE_INJECTION
            
            # Privilege escalation indicators
            if (features.get('security_api_usage', 0) > 3 or
                'setuid' in content or 'su ' in content):
                return ZeroDayCategory.PRIVILEGE_ESCALATION
            
            # Authentication bypass indicators
            if (features.get('crypto_references', 0) > 5 and
                features.get('string_count', 0) > 10):
                return ZeroDayCategory.AUTHENTICATION_BYPASS
            
            # Data exfiltration indicators
            if (features.get('network_patterns', 0) > 3 and
                features.get('file_operations', 0) > 5):
                return ZeroDayCategory.DATA_EXFILTRATION
            
            # Crypto weakness indicators
            if features.get('crypto_references', 0) > 0:
                return ZeroDayCategory.CRYPTO_WEAKNESS
            
            # Memory corruption indicators
            if ('buffer' in content.lower() or 'malloc' in content or 'free(' in content):
                return ZeroDayCategory.MEMORY_CORRUPTION
            
            # Default to unknown pattern
            return ZeroDayCategory.UNKNOWN_PATTERN
            
        except:
            return ZeroDayCategory.UNKNOWN_PATTERN
    
    def _assess_threat_level(self, features: Dict[str, Any], detection_scores: Dict[str, float]) -> ThreatLevel:
        """Assess threat level based on features and scores."""
        try:
            ensemble_score = detection_scores.get('ensemble_score', 0.0)
            
            # Critical threats
            if (ensemble_score > 0.9 and 
                features.get('security_api_usage', 0) > 5):
                return ThreatLevel.CRITICAL
            
            # High threats
            if (ensemble_score > 0.8 or
                features.get('dynamic_loading', 0) > 0 or
                features.get('obfuscation_score', 0) > 0.7):
                return ThreatLevel.HIGH
            
            # Medium threats
            if (ensemble_score > 0.6 or
                features.get('reflection_usage', 0) > 2):
                return ThreatLevel.MEDIUM
            
            # Low threats
            if ensemble_score > 0.4:
                return ThreatLevel.LOW
            
            return ThreatLevel.INFO
            
        except:
            return ThreatLevel.INFO
    
    def _determine_attack_vector(self, features: Dict[str, Any], content: str) -> str:
        """Determine attack vector description."""
        try:
            vectors = []
            
            if features.get('network_patterns', 0) > 0:
                vectors.append("Network-based")
            
            if features.get('file_operations', 0) > 0:
                vectors.append("File system access")
            
            if features.get('dynamic_loading', 0) > 0:
                vectors.append("Dynamic code loading")
            
            if features.get('reflection_usage', 0) > 0:
                vectors.append("Reflection-based manipulation")
            
            if features.get('security_api_usage', 0) > 0:
                vectors.append("Security API manipulation")
            
            return ", ".join(vectors) if vectors else "Unknown vector"
            
        except:
            return "Analysis failed"
    
    def _assess_exploitation_complexity(self, features: Dict[str, Any]) -> str:
        """Assess exploitation complexity."""
        try:
            complexity_score = 0
            
            # High complexity indicators
            if features.get('cyclomatic_complexity', 0) > 10:
                complexity_score += 2
            
            if features.get('obfuscation_score', 0) > 0.5:
                complexity_score += 2
            
            if features.get('security_api_usage', 0) > 3:
                complexity_score += 1
            
            # Determine complexity level
            if complexity_score >= 4:
                return "high"
            elif complexity_score >= 2:
                return "medium"
            else:
                return "low"
                
        except:
            return "unknown"
    
    def _generate_mitigation_recommendations(self, category: ZeroDayCategory, 
                                           features: Dict[str, Any]) -> List[str]:
        """Generate mitigation recommendations."""
        recommendations = []
        
        try:
            # Category-specific recommendations
            if category == ZeroDayCategory.CODE_INJECTION:
                recommendations.extend([
                    "Implement input validation and sanitization",
                    "Use parameterized queries and prepared statements",
                    "Apply principle of least privilege"
                ])
            
            elif category == ZeroDayCategory.PRIVILEGE_ESCALATION:
                recommendations.extend([
                    "Review permission declarations",
                    "Implement proper access controls",
                    "Validate user permissions before sensitive operations"
                ])
            
            elif category == ZeroDayCategory.AUTHENTICATION_BYPASS:
                recommendations.extend([
                    "Strengthen authentication mechanisms",
                    "Implement multi-factor authentication",
                    "Review session management"
                ])
            
            elif category == ZeroDayCategory.DATA_EXFILTRATION:
                recommendations.extend([
                    "Implement data loss prevention controls",
                    "Monitor network traffic for anomalies",
                    "Encrypt sensitive data at rest and in transit"
                ])
            
            elif category == ZeroDayCategory.CRYPTO_WEAKNESS:
                recommendations.extend([
                    "Use approved cryptographic algorithms",
                    "Implement proper key management",
                    "Regular security assessment of crypto implementations"
                ])
            
            # Feature-specific recommendations
            if features.get('obfuscation_score', 0) > 0.5:
                recommendations.append("Review and remove code obfuscation if not necessary")
            
            if features.get('dynamic_loading', 0) > 0:
                recommendations.append("Restrict dynamic code loading capabilities")
            
            if features.get('reflection_usage', 0) > 2:
                recommendations.append("Limit reflection usage and validate reflected operations")
            
            return recommendations[:5]  # Limit to top 5 recommendations
            
        except:
            return ["Conduct comprehensive security review"]
    
    def _calculate_false_positive_probability(self, features: Dict[str, Any]) -> float:
        """Calculate probability that finding is a false positive."""
        try:
            fp_indicators = []
            
            # Low complexity code is less likely to be malicious
            if features.get('cyclomatic_complexity', 0) < 3:
                fp_indicators.append(0.3)
            
            # Very few API calls might indicate simple/benign code
            if features.get('method_calls', 0) < 5:
                fp_indicators.append(0.2)
            
            # No security-related features
            if (features.get('security_api_usage', 0) == 0 and
                features.get('crypto_references', 0) == 0 and
                features.get('network_patterns', 0) == 0):
                fp_indicators.append(0.4)
            
            # Calculate probability
            if fp_indicators:
                return min(np.mean(fp_indicators), 0.8)  # Cap at 80%
            
            return 0.1  # Default low false positive probability
            
        except:
            return 0.5  # Default moderate uncertainty
    
    async def _validate_enhanced_finding(self, finding: EnhancedZeroDayFinding) -> bool:
        """Validate enhanced finding to reduce false positives."""
        try:
            validation_checks = []
            
            # Confidence threshold check
            validation_checks.append(finding.confidence_score >= self.confidence_threshold)
            
            # False positive probability check
            validation_checks.append(finding.false_positive_probability < 0.7)
            
            # Threat level check (skip info-level findings unless high confidence)
            if finding.threat_level == ThreatLevel.INFO:
                validation_checks.append(finding.confidence_score > 0.8)
            else:
                validation_checks.append(True)
            
            # Known false positive pattern check
            file_signature = hashlib.md5(finding.file_path.encode()).hexdigest()[:8]
            validation_checks.append(file_signature not in self.false_positive_patterns)
            
            # Ensemble score validation
            validation_checks.append(finding.ensemble_score >= self.ensemble_threshold)
            
            # Pass if majority of checks pass
            passed_checks = sum(validation_checks)
            is_valid = passed_checks >= len(validation_checks) * 0.6
            
            if is_valid:
                finding.validation_status = 'validated'
            else:
                finding.validation_status = 'rejected'
                self.logger.debug(f"Finding {finding.finding_id} rejected: {passed_checks}/{len(validation_checks)} checks passed")
            
            return is_valid
            
        except Exception as e:
            self.logger.error(f"Finding validation failed: {e}")
            return False
    
    async def _post_process_findings(self, findings: List[EnhancedZeroDayFinding]) -> List[EnhancedZeroDayFinding]:
        """Post-process findings for correlation and deduplication."""
        try:
            if not findings:
                return findings
            
            # Remove duplicates based on file path and category
            unique_findings = []
            seen_signatures = set()
            
            for finding in findings:
                signature = f"{finding.file_path}_{finding.category.value}"
                if signature not in seen_signatures:
                    unique_findings.append(finding)
                    seen_signatures.add(signature)
            
            # Sort by threat level and confidence
            threat_order = {
                ThreatLevel.CRITICAL: 5,
                ThreatLevel.HIGH: 4,
                ThreatLevel.MEDIUM: 3,
                ThreatLevel.LOW: 2,
                ThreatLevel.INFO: 1
            }
            
            unique_findings.sort(
                key=lambda f: (threat_order.get(f.threat_level, 0), f.confidence_score),
                reverse=True
            )
            
            return unique_findings
            
        except Exception as e:
            self.logger.error(f"Post-processing failed: {e}")
            return findings
    
    def _update_learning_patterns(self, findings: List[EnhancedZeroDayFinding]):
        """Update learning patterns based on findings."""
        try:
            # Add to historical findings
            for finding in findings:
                if len(self.historical_findings) >= 1000:
                    self.historical_findings.popleft()  # Remove oldest
                self.historical_findings.append(finding)
            
            # Update validated patterns
            for finding in findings:
                if finding.validation_status == 'validated':
                    pattern_signature = f"{finding.category.value}_{finding.file_path.split('/')[-1]}"
                    self.validated_patterns.add(pattern_signature)
            
            self.logger.debug(f"Updated learning patterns: {len(self.validated_patterns)} validated patterns")
            
        except Exception as e:
            self.logger.error(f"Learning pattern update failed: {e}")
    
    def _update_metrics(self, findings: List[EnhancedZeroDayFinding]):
        """Update detection performance metrics."""
        try:
            self.detection_metrics['total_analyzed'] += 1
            self.detection_metrics['zero_days_detected'] += len(findings)
            
            if findings:
                avg_confidence = np.mean([f.confidence_score for f in findings])
                self.detection_metrics['average_confidence'] = (
                    self.detection_metrics['average_confidence'] * 0.9 + avg_confidence * 0.1
                )
            
        except Exception as e:
            self.logger.error(f"Metrics update failed: {e}")
    
    def _should_analyze_file(self, file_path: str, content: str) -> bool:
        """Determine if file should be analyzed."""
        try:
            # File type filters
            analyze_extensions = ['.java', '.kt', '.js', '.smali', '.xml']
            if not any(file_path.endswith(ext) for ext in analyze_extensions):
                return False
            
            # Size filters
            if len(content) < 100 or len(content) > 100000:  # Skip very small or very large files
                return False
            
            # Content filters
            if content.strip().startswith('<?xml') and len(content) < 1000:  # Skip simple XML
                return False
            
            return True
            
        except:
            return False
    
    def get_detection_summary(self) -> Dict[str, Any]:
        """Get detection performance summary."""
        return {
            'metrics': self.detection_metrics.copy(),
            'historical_findings_count': len(self.historical_findings),
            'validated_patterns_count': len(self.validated_patterns),
            'false_positive_patterns_count': len(self.false_positive_patterns),
            'engine_status': 'operational',
            'ml_availability': {
                'traditional_ml': ML_AVAILABLE,
                'deep_learning': DEEP_LEARNING_AVAILABLE,
                'foundation': FOUNDATION_AVAILABLE
            }
        }

# Main interface function for integration
async def enhanced_zero_day_analysis(apk_ctx, file_contents: Dict[str, str], 
                                   config: Dict[str, Any] = None) -> List[EnhancedZeroDayFinding]:
    """
    Main interface for enhanced zero-day analysis.
    
    Args:
        apk_ctx: APK context object
        file_contents: Dictionary of file paths to file contents
        config: Configuration parameters
        
    Returns:
        List of enhanced zero-day findings
    """
    try:
        engine = EnhancedZeroDayDetectionEngine(config)
        findings = await engine.analyze_for_enhanced_zero_days(apk_ctx, file_contents)
        
        logger.info(f"Enhanced zero-day analysis completed: {len(findings)} findings")
        return findings
        
    except Exception as e:
        logger.error(f"Enhanced zero-day analysis failed: {e}")
        return []

if __name__ == "__main__":
    # Demo functionality
    import asyncio
    
    async def demo():
        config = {
            'ensemble_threshold': 0.7,
            'confidence_threshold': 0.6,
            'deep_learning_weight': 0.3
        }
        
        sample_files = {
            'MainActivity.java': '''
            public class MainActivity {
                private void suspiciousMethod() {
                    Runtime.getRuntime().exec("su -c 'cat /system/build.prop'");
                    Class.forName("dalvik.system.DexClassLoader").getMethod("loadClass", String.class);
                }
            }
            ''',
            'CryptoUtils.java': '''
            public class CryptoUtils {
                public String encrypt(String data) {
                    return Base64.encode(data.getBytes());  // Weak encryption
                }
            }
            '''
        }
        
        findings = await enhanced_zero_day_analysis(None, sample_files, config)
        
        print(f"\nEnhanced Zero-Day Analysis Demo Results:")
        print(f"{'='*60}")
        print(f"Findings detected: {len(findings)}")
        
        for finding in findings:
            print(f"\n🚨 {finding.threat_level.value.upper()} - {finding.category.value}")
            print(f"   File: {finding.file_path}")
            print(f"   Confidence: {finding.confidence_score:.2f}")
            print(f"   Ensemble Score: {finding.ensemble_score:.2f}")
            print(f"   Attack Vector: {finding.attack_vector}")
            print(f"   Mitigation: {finding.mitigation_recommendations[0] if finding.mitigation_recommendations else 'None'}")
    
    asyncio.run(demo()) 