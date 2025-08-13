"""
Context-Aware Secret Intelligence System for AODS

This module provides intelligent secret detection and analysis capabilities
using advanced machine learning and context-aware analysis techniques.

Timeline: Part of Secret Intelligence & ML Enhancement capabilities
"""

import logging
import re
import json
import time
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import hashlib

# Import existing AODS infrastructure
try:
    from core.secret_extractor import EnhancedSecretExtractor, Secret
    from core.encoding_analyzer import AdvancedEncodingAnalyzer
    from core.enhanced_static_analyzer import EnhancedStaticAnalyzer
    from core.contextual_location_enhancer import ContextualLocationEnhancer
except ImportError as e:
    logging.warning(f"Failed to import AODS infrastructure: {e}")

@dataclass
class UsagePattern:
    """Usage pattern analysis for secrets"""
    pattern_type: str
    confidence: float
    context_indicators: List[str]
    risk_level: str
    description: str

@dataclass
class NetworkCorrelation:
    """Network endpoint correlation for API secrets"""
    endpoints: List[str]
    protocols: List[str]
    authentication_methods: List[str]
    risk_assessment: str
    correlation_confidence: float

@dataclass
class AuthenticationContext:
    """Authentication context identification"""
    auth_type: str
    auth_flow: List[str]
    security_level: str
    context_confidence: float
    vulnerabilities: List[str]

@dataclass
class ContextualRiskAssessment:
    """Risk assessment based on usage patterns"""
    overall_risk: str
    risk_factors: List[str]
    mitigation_suggestions: List[str]
    business_impact: str
    risk_score: float

@dataclass
class ContextAwareSecretAnalysis:
    """Complete context-aware secret analysis result"""
    secret: Secret
    usage_pattern: UsagePattern
    network_correlation: Optional[NetworkCorrelation]
    auth_context: Optional[AuthenticationContext]
    risk_assessment: ContextualRiskAssessment
    code_flow_analysis: Dict[str, Any]
    confidence_boost: float
    analysis_timestamp: str
    context_metadata: Dict[str, Any]

class SecretContextAnalyzer:
    """
    Advanced Secret Context Analysis Engine
    
    Provides rich contextual understanding of secret usage patterns,
    network correlations, authentication contexts, and risk assessments.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Context analysis patterns
        self.usage_patterns = self._initialize_usage_patterns()
        self.network_patterns = self._initialize_network_patterns()
        self.auth_patterns = self._initialize_auth_patterns()
        self.code_flow_patterns = self._initialize_code_flow_patterns()
        
        # Risk assessment framework
        self.risk_factors = self._initialize_risk_factors()
        
        # Performance tracking
        self.analysis_stats = defaultdict(int)
        
        self.logger.debug("Secret Context Analyzer initialized")
    
    def _initialize_usage_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize usage pattern detection rules"""
        return {
            "cryptographic_operations": {
                "indicators": [
                    "KeyGenParameterSpec", "Cipher", "KeyStore", "SecretKey",
                    "encrypt", "decrypt", "CryptoManager", "AES", "RSA",
                    "MessageDigest", "Mac", "KeyGenerator", "SecretKeySpec"
                ],
                "proximity_radius": 10,
                "confidence_boost": 0.4,
                "risk_level": "HIGH",
                "description": "Secret used in cryptographic operations"
            },
            "api_authentication": {
                "indicators": [
                    "Authorization", "Bearer", "API-Key", "X-API-Key",
                    "authenticate", "oauth", "token", "credential",
                    "HttpClient", "RestTemplate", "OkHttp", "Retrofit"
                ],
                "proximity_radius": 8,
                "confidence_boost": 0.35,
                "risk_level": "HIGH",
                "description": "Secret used for API authentication"
            },
            "database_connection": {
                "indicators": [
                    "Connection", "DriverManager", "DataSource", "JDBC",
                    "SQLiteDatabase", "Room", "Realm", "mongodb",
                    "password", "username", "connection_string"
                ],
                "proximity_radius": 7,
                "confidence_boost": 0.3,
                "risk_level": "HIGH",
                "description": "Secret used for database connections"
            },
            "network_communication": {
                "indicators": [
                    "HttpURLConnection", "URL", "URI", "Socket",
                    "SSLContext", "TrustManager", "HostnameVerifier",
                    "WebView", "loadUrl", "WebSocket"
                ],
                "proximity_radius": 6,
                "confidence_boost": 0.25,
                "risk_level": "MEDIUM",
                "description": "Secret used in network communications"
            },
            "file_operations": {
                "indicators": [
                    "File", "FileInputStream", "FileOutputStream",
                    "SharedPreferences", "PreferenceManager",
                    "openFileOutput", "getFilesDir", "getExternalFilesDir"
                ],
                "proximity_radius": 5,
                "confidence_boost": 0.2,
                "risk_level": "MEDIUM",
                "description": "Secret used in file operations"
            },
            "test_context": {
                "indicators": [
                    "Test", "Mock", "Stub", "Fake", "junit",
                    "@Test", "TestCase", "Espresso", "Robolectric"
                ],
                "proximity_radius": 3,
                "confidence_boost": -0.3,  # Negative boost for test contexts
                "risk_level": "LOW",
                "description": "Secret found in test context"
            }
        }
    
    def _initialize_network_patterns(self) -> Dict[str, List[str]]:
        """Initialize network endpoint correlation patterns"""
        return {
            "api_endpoints": [
                r'https?://[^/]+/api/',
                r'https?://api\.[^/]+',
                r'https?://[^/]+/v\d+/',
                r'https?://[^/]+/rest/',
                r'https?://[^/]+/graphql'
            ],
            "authentication_endpoints": [
                r'https?://[^/]+/auth/',
                r'https?://[^/]+/login',
                r'https?://[^/]+/oauth/',
                r'https?://[^/]+/token',
                r'https?://[^/]+/sso/'
            ],
            "cloud_services": [
                r'https?://[^/]*amazonaws\.com',
                r'https?://[^/]*azure\.com',
                r'https?://[^/]*googleapis\.com',
                r'https?://[^/]*firebaseio\.com',
                r'https?://[^/]*herokuapp\.com'
            ],
            "payment_services": [
                r'https?://[^/]*stripe\.com',
                r'https?://[^/]*paypal\.com',
                r'https?://[^/]*square\.com',
                r'https?://[^/]*braintree\.com'
            ]
        }
    
    def _initialize_auth_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize authentication context patterns"""
        return {
            "oauth2": {
                "patterns": ["oauth", "OAuth2", "bearer", "access_token", "refresh_token"],
                "security_level": "HIGH",
                "flow_indicators": ["authorize", "token", "refresh", "revoke"]
            },
            "api_key": {
                "patterns": ["api_key", "apikey", "x-api-key", "api-key"],
                "security_level": "MEDIUM",
                "flow_indicators": ["header", "query", "parameter"]
            },
            "basic_auth": {
                "patterns": ["basic", "username", "password", "credentials"],
                "security_level": "LOW",
                "flow_indicators": ["encode", "base64", "authorization"]
            },
            "jwt": {
                "patterns": ["jwt", "jsonwebtoken", "token", "payload"],
                "security_level": "HIGH",
                "flow_indicators": ["sign", "verify", "decode", "header"]
            },
            "custom_auth": {
                "patterns": ["signature", "hmac", "hash", "digest"],
                "security_level": "MEDIUM",
                "flow_indicators": ["calculate", "verify", "generate"]
            }
        }
    
    def _initialize_code_flow_patterns(self) -> Dict[str, List[str]]:
        """Initialize code flow analysis patterns"""
        return {
            "data_flow": [
                r'(\w+)\s*=\s*["\']([^"\']+)["\']',  # Variable assignment
                r'\.put\(["\']([^"\']+)["\'],\s*([^)]+)\)',  # Map/Bundle put
                r'\.set\w*\(["\']([^"\']+)["\'],\s*([^)]+)\)',  # Setter methods
                r'\.add\w*\(["\']([^"\']+)["\'],\s*([^)]+)\)'  # Add methods
            ],
            "method_calls": [
                r'(\w+)\s*\.\s*(\w+)\s*\([^)]*["\']([^"\']+)["\'][^)]*\)',
                r'(\w+)\s*\(\s*[^)]*["\']([^"\']+)["\'][^)]*\)',
                r'new\s+(\w+)\s*\([^)]*["\']([^"\']+)["\'][^)]*\)'
            ],
            "control_flow": [
                r'if\s*\([^)]*["\']([^"\']+)["\'][^)]*\)',
                r'switch\s*\([^)]*["\']([^"\']+)["\'][^)]*\)',
                r'case\s+["\']([^"\']+)["\']:'
            ]
        }
    
    def _initialize_risk_factors(self) -> Dict[str, Dict[str, Any]]:
        """Initialize risk assessment factors"""
        return {
            "hardcoded_production_secret": {
                "weight": 0.9,
                "description": "Production secret hardcoded in application",
                "mitigation": "Use secure configuration management"
            },
            "weak_encryption_key": {
                "weight": 0.8,
                "description": "Weak or predictable encryption key",
                "mitigation": "Generate strong, random encryption keys"
            },
            "exposed_api_credentials": {
                "weight": 0.85,
                "description": "API credentials exposed in client code",
                "mitigation": "Move API calls to backend services"
            },
            "database_credentials": {
                "weight": 0.75,
                "description": "Database credentials in application code",
                "mitigation": "Use connection pooling and secure storage"
            },
            "third_party_service_keys": {
                "weight": 0.7,
                "description": "Third-party service keys in code",
                "mitigation": "Use secure key management services"
            },
            "test_secrets_in_production": {
                "weight": 0.6,
                "description": "Test secrets found in production code",
                "mitigation": "Separate test and production configurations"
            }
        }
    
    def analyze_secret_context(self, secret: Secret, code_context: str, 
                             file_path: str = "") -> ContextAwareSecretAnalysis:
        """
        Perform comprehensive context-aware analysis of a secret
        
        Epic 2.2 Story 2.2.1: Context-Aware Secret Analysis
        """
        start_time = time.time()
        
        try:
            # AC-2.2.1-01: Code flow analysis for 90% of detected secrets
            code_flow_analysis = self._analyze_code_flow(secret, code_context)
            
            # AC-2.2.1-01: Usage pattern analysis
            usage_pattern = self._analyze_usage_pattern(secret, code_context)
            
            # AC-2.2.1-02: Network endpoint correlation for API-related secrets
            network_correlation = self._find_network_correlation(secret, code_context)
            
            # AC-2.2.1-03: Authentication context identification
            auth_context = self._analyze_auth_context(secret, code_context)
            
            # AC-2.2.1-04: Risk scoring based on actual usage patterns
            risk_assessment = self._assess_contextual_risk(secret, usage_pattern, 
                                                         network_correlation, auth_context)
            
            # Calculate confidence boost from context
            confidence_boost = self._calculate_confidence_boost(usage_pattern, 
                                                              network_correlation, auth_context)
            
            # Gather context metadata
            context_metadata = self._gather_context_metadata(secret, code_context, file_path)
            
            analysis = ContextAwareSecretAnalysis(
                secret=secret,
                usage_pattern=usage_pattern,
                network_correlation=network_correlation,
                auth_context=auth_context,
                risk_assessment=risk_assessment,
                code_flow_analysis=code_flow_analysis,
                confidence_boost=confidence_boost,
                analysis_timestamp=datetime.now().isoformat(),
                context_metadata=context_metadata
            )
            
            # Update statistics
            self.analysis_stats["secrets_analyzed"] += 1
            self.analysis_stats["analysis_time"] += time.time() - start_time
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Context analysis failed for secret {secret.value[:20]}...: {e}")
            return self._create_fallback_analysis(secret, str(e))
    
    def _analyze_code_flow(self, secret: Secret, code_context: str) -> Dict[str, Any]:
        """Analyze code flow patterns around the secret"""
        flow_analysis = {
            "data_assignments": [],
            "method_calls": [],
            "control_structures": [],
            "variable_usage": [],
            "flow_confidence": 0.0
        }
        
        try:
            # Analyze data flow patterns
            for pattern in self.code_flow_patterns["data_flow"]:
                matches = re.finditer(pattern, code_context, re.IGNORECASE)
                for match in matches:
                    if secret.value in match.group(0):
                        flow_analysis["data_assignments"].append({
                            "pattern": match.group(0),
                            "variable": match.group(1) if len(match.groups()) >= 1 else None,
                            "value": match.group(2) if len(match.groups()) >= 2 else None
                        })
            
            # Analyze method calls
            for pattern in self.code_flow_patterns["method_calls"]:
                matches = re.finditer(pattern, code_context, re.IGNORECASE)
                for match in matches:
                    if secret.value in match.group(0):
                        flow_analysis["method_calls"].append({
                            "method": match.group(1) if len(match.groups()) >= 1 else None,
                            "context": match.group(0)
                        })
            
            # Analyze control flow
            for pattern in self.code_flow_patterns["control_flow"]:
                matches = re.finditer(pattern, code_context, re.IGNORECASE)
                for match in matches:
                    if secret.value in match.group(0):
                        flow_analysis["control_structures"].append({
                            "type": "conditional",
                            "context": match.group(0)
                        })
            
            # Calculate flow confidence
            total_patterns = (len(flow_analysis["data_assignments"]) + 
                            len(flow_analysis["method_calls"]) + 
                            len(flow_analysis["control_structures"]))
            
            flow_analysis["flow_confidence"] = min(1.0, total_patterns * 0.2)
            
        except Exception as e:
            self.logger.warning(f"Code flow analysis failed: {e}")
        
        return flow_analysis
    
    def _analyze_usage_pattern(self, secret: Secret, code_context: str) -> UsagePattern:
        """Analyze usage patterns for the secret"""
        best_pattern = None
        highest_confidence = 0.0
        
        for pattern_name, pattern_config in self.usage_patterns.items():
            confidence = 0.0
            found_indicators = []
            
            # Check for pattern indicators in context
            for indicator in pattern_config["indicators"]:
                if indicator.lower() in code_context.lower():
                    confidence += 0.1
                    found_indicators.append(indicator)
            
            # Boost confidence based on proximity and number of indicators
            if found_indicators:
                proximity_boost = min(0.3, len(found_indicators) * 0.1)
                confidence += proximity_boost
                
                if confidence > highest_confidence:
                    highest_confidence = confidence
                    best_pattern = UsagePattern(
                        pattern_type=pattern_name,
                        confidence=min(1.0, confidence),
                        context_indicators=found_indicators,
                        risk_level=pattern_config["risk_level"],
                        description=pattern_config["description"]
                    )
        
        # Default pattern if none found
        if not best_pattern:
            best_pattern = UsagePattern(
                pattern_type="unknown_usage",
                confidence=0.3,
                context_indicators=[],
                risk_level="MEDIUM",
                description="Unknown usage pattern"
            )
        
        return best_pattern
    
    def _find_network_correlation(self, secret: Secret, code_context: str) -> Optional[NetworkCorrelation]:
        """Find network endpoint correlations for API-related secrets"""
        endpoints = []
        protocols = []
        auth_methods = []
        
        # Search for network endpoints in context
        for category, patterns in self.network_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, code_context, re.IGNORECASE)
                for match in matches:
                    endpoint = match.group(0)
                    if endpoint not in endpoints:
                        endpoints.append(endpoint)
                        
                        # Determine protocol
                        if endpoint.startswith('https://'):
                            protocols.append('HTTPS')
                        elif endpoint.startswith('http://'):
                            protocols.append('HTTP')
        
        # Detect authentication methods
        auth_indicators = ['bearer', 'api-key', 'authorization', 'oauth', 'token']
        for indicator in auth_indicators:
            if indicator.lower() in code_context.lower():
                auth_methods.append(indicator.upper())
        
        if endpoints:
            # Assess risk based on protocol and endpoints
            risk_assessment = "HIGH" if any('http://' in ep for ep in endpoints) else "MEDIUM"
            if any('localhost' in ep or '127.0.0.1' in ep for ep in endpoints):
                risk_assessment = "LOW"
            
            correlation_confidence = min(1.0, len(endpoints) * 0.3 + len(auth_methods) * 0.2)
            
            return NetworkCorrelation(
                endpoints=endpoints,
                protocols=list(set(protocols)),
                authentication_methods=list(set(auth_methods)),
                risk_assessment=risk_assessment,
                correlation_confidence=correlation_confidence
            )
        
        return None
    
    def _analyze_auth_context(self, secret: Secret, code_context: str) -> Optional[AuthenticationContext]:
        """Analyze authentication context for the secret"""
        best_auth_context = None
        highest_confidence = 0.0
        
        for auth_type, auth_config in self.auth_patterns.items():
            confidence = 0.0
            flow_indicators = []
            vulnerabilities = []
            
            # Check for authentication patterns
            for pattern in auth_config["patterns"]:
                if pattern.lower() in code_context.lower():
                    confidence += 0.2
            
            # Check for flow indicators
            for flow_indicator in auth_config["flow_indicators"]:
                if flow_indicator.lower() in code_context.lower():
                    confidence += 0.15
                    flow_indicators.append(flow_indicator)
            
            # Identify potential vulnerabilities
            if auth_type == "basic_auth" and "http://" in code_context.lower():
                vulnerabilities.append("Basic auth over HTTP")
            elif auth_type == "api_key" and "url" in code_context.lower():
                vulnerabilities.append("API key in URL parameters")
            
            if confidence > highest_confidence:
                highest_confidence = confidence
                best_auth_context = AuthenticationContext(
                    auth_type=auth_type,
                    auth_flow=flow_indicators,
                    security_level=auth_config["security_level"],
                    context_confidence=min(1.0, confidence),
                    vulnerabilities=vulnerabilities
                )
        
        return best_auth_context
    
    def _assess_contextual_risk(self, secret: Secret, usage_pattern: UsagePattern,
                              network_correlation: Optional[NetworkCorrelation],
                              auth_context: Optional[AuthenticationContext]) -> ContextualRiskAssessment:
        """Assess risk based on contextual analysis"""
        risk_factors = []
        risk_score = 0.0
        mitigation_suggestions = []
        
        # Assess usage pattern risk
        if usage_pattern.risk_level == "HIGH":
            risk_score += 0.4
            risk_factors.append(f"High-risk usage pattern: {usage_pattern.pattern_type}")
        elif usage_pattern.risk_level == "MEDIUM":
            risk_score += 0.2
            risk_factors.append(f"Medium-risk usage pattern: {usage_pattern.pattern_type}")
        
        # Assess network correlation risk
        if network_correlation:
            if network_correlation.risk_assessment == "HIGH":
                risk_score += 0.3
                risk_factors.append("High-risk network endpoints detected")
                mitigation_suggestions.append("Use HTTPS for all network communications")
            
            if 'HTTP' in network_correlation.protocols:
                risk_score += 0.2
                risk_factors.append("Insecure HTTP protocol detected")
        
        # Assess authentication context risk
        if auth_context:
            if auth_context.vulnerabilities:
                risk_score += 0.25
                risk_factors.extend(auth_context.vulnerabilities)
                mitigation_suggestions.append("Implement secure authentication practices")
            
            if auth_context.security_level == "LOW":
                risk_score += 0.15
                risk_factors.append("Low-security authentication method")
        
        # Assess secret characteristics
        if len(secret.value) < 16:
            risk_score += 0.1
            risk_factors.append("Short secret length")
            mitigation_suggestions.append("Use longer, more complex secrets")
        
        if secret.entropy < 3.0:
            risk_score += 0.15
            risk_factors.append("Low entropy secret")
            mitigation_suggestions.append("Generate high-entropy secrets")
        
        # Determine overall risk level
        if risk_score >= 0.7:
            overall_risk = "CRITICAL"
        elif risk_score >= 0.5:
            overall_risk = "HIGH"
        elif risk_score >= 0.3:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"
        
        # Business impact assessment
        business_impact = self._assess_business_impact(overall_risk, usage_pattern, network_correlation)
        
        # Add general mitigation suggestions
        if not mitigation_suggestions:
            mitigation_suggestions = [
                "Store secrets in secure configuration management",
                "Use environment variables for sensitive data",
                "Implement proper secret rotation policies"
            ]
        
        return ContextualRiskAssessment(
            overall_risk=overall_risk,
            risk_factors=risk_factors,
            mitigation_suggestions=mitigation_suggestions,
            business_impact=business_impact,
            risk_score=min(1.0, risk_score)
        )
    
    def _assess_business_impact(self, risk_level: str, usage_pattern: UsagePattern,
                              network_correlation: Optional[NetworkCorrelation]) -> str:
        """Assess business impact of the secret exposure"""
        if risk_level == "CRITICAL":
            return "Severe: Potential for complete system compromise"
        elif risk_level == "HIGH":
            if usage_pattern.pattern_type == "api_authentication":
                return "High: Unauthorized API access and data breach"
            elif usage_pattern.pattern_type == "database_connection":
                return "High: Database compromise and data theft"
            else:
                return "High: Significant security breach potential"
        elif risk_level == "MEDIUM":
            return "Moderate: Limited security impact with containment possible"
        else:
            return "Low: Minimal business impact expected"
    
    def _calculate_confidence_boost(self, usage_pattern: UsagePattern,
                                  network_correlation: Optional[NetworkCorrelation],
                                  auth_context: Optional[AuthenticationContext]) -> float:
        """Calculate confidence boost from contextual analysis"""
        boost = 0.0
        
        # Usage pattern boost
        if usage_pattern.confidence > 0.7:
            boost += 0.2
        elif usage_pattern.confidence > 0.5:
            boost += 0.1
        
        # Network correlation boost
        if network_correlation and network_correlation.correlation_confidence > 0.6:
            boost += 0.15
        
        # Authentication context boost
        if auth_context and auth_context.context_confidence > 0.6:
            boost += 0.1
        
        return min(0.5, boost)  # Cap boost at 0.5
    
    def _gather_context_metadata(self, secret: Secret, code_context: str, file_path: str) -> Dict[str, Any]:
        """Gather additional context metadata"""
        return {
            "file_path": file_path,
            "context_length": len(code_context),
            "secret_position": code_context.find(secret.value) if secret.value in code_context else -1,
            "context_hash": hashlib.md5(code_context.encode()).hexdigest()[:8],
            "analysis_version": "2.2.1",
            "file_type": Path(file_path).suffix if file_path else "unknown"
        }
    
    def _create_fallback_analysis(self, secret: Secret, error_msg: str) -> ContextAwareSecretAnalysis:
        """Create fallback analysis when full analysis fails"""
        return ContextAwareSecretAnalysis(
            secret=secret,
            usage_pattern=UsagePattern(
                pattern_type="analysis_failed",
                confidence=0.1,
                context_indicators=[],
                risk_level="UNKNOWN",
                description=f"Analysis failed: {error_msg}"
            ),
            network_correlation=None,
            auth_context=None,
            risk_assessment=ContextualRiskAssessment(
                overall_risk="UNKNOWN",
                risk_factors=[f"Analysis failed: {error_msg}"],
                mitigation_suggestions=["Manual review required"],
                business_impact="Unknown due to analysis failure",
                risk_score=0.5
            ),
            code_flow_analysis={"error": error_msg},
            confidence_boost=0.0,
            analysis_timestamp=datetime.now().isoformat(),
            context_metadata={"error": error_msg}
        )

class ContextAwareSecretAnalyzer:
    """
    Context-Aware Secret Analysis System
    
    Enhances existing EnhancedSecretExtractor and AdvancedEncodingAnalyzer
    with rich contextual understanding of secret usage patterns.
    
    Builds upon AODS infrastructure to provide:
    - Code flow analysis for detected secrets
    - Network endpoint correlation for API secrets
    - Authentication context identification
    - Risk scoring based on actual usage patterns
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Initialize existing AODS components
        try:
            self.secret_extractor = EnhancedSecretExtractor()
            self.encoding_analyzer = AdvancedEncodingAnalyzer()
            self.static_analyzer = EnhancedStaticAnalyzer()
            self.location_enhancer = ContextualLocationEnhancer()
        except Exception as e:
            self.logger.warning(f"Failed to initialize AODS components: {e}")
            self.secret_extractor = None
            self.encoding_analyzer = None
            self.static_analyzer = None
            self.location_enhancer = None
        
        # Initialize context analyzer
        self.context_analyzer = SecretContextAnalyzer()
        
        # Performance tracking
        self.performance_stats = {
            "secrets_analyzed": 0,
            "context_analysis_time": 0.0,
            "successful_analyses": 0,
            "failed_analyses": 0
        }
        
        self.logger.debug("Context-Aware Secret Analyzer initialized")
    
    def analyze_secret_in_context(self, secret: Union[Secret, str], code_context: str,
                                file_path: str = "") -> ContextAwareSecretAnalysis:
        """
        Enhanced analysis with code flow understanding
        
        Epic 2.2 Story 2.2.1: Context-Aware Secret Analysis
        This is the main entry point for contextual secret analysis.
        """
        start_time = time.time()
        
        try:
            # Convert string to Secret object if needed
            if isinstance(secret, str):
                secret = Secret(
                    secret_type="unknown",
                    value=secret,
                    location="context_analysis",
                    confidence=0.5,
                    severity="MEDIUM",
                    entropy=self._calculate_entropy(secret),
                    validation_status="unverified",
                    extraction_method="context_aware_analysis"
                )
            
            # Perform context-aware analysis
            analysis = self.context_analyzer.analyze_secret_context(secret, code_context, file_path)
            
            # Update performance statistics
            self.performance_stats["secrets_analyzed"] += 1
            self.performance_stats["context_analysis_time"] += time.time() - start_time
            self.performance_stats["successful_analyses"] += 1
            
            self.logger.debug(f"Context analysis completed for secret: {secret.value[:20]}...")
            
            return analysis
            
        except Exception as e:
            self.performance_stats["failed_analyses"] += 1
            self.logger.error(f"Context-aware analysis failed: {e}")
            return self.context_analyzer._create_fallback_analysis(secret, str(e))
    
    def analyze_multiple_secrets(self, secrets: List[Union[Secret, str]], 
                               code_context: str, file_path: str = "") -> List[ContextAwareSecretAnalysis]:
        """Analyze multiple secrets in the same context"""
        analyses = []
        
        for secret in secrets:
            analysis = self.analyze_secret_in_context(secret, code_context, file_path)
            analyses.append(analysis)
        
        return analyses
    
    def extract_and_analyze_secrets(self, content: str, file_path: str = "") -> List[ContextAwareSecretAnalysis]:
        """
        Extract secrets using existing AODS infrastructure and perform context analysis
        
        Combines:
        - EnhancedSecretExtractor for secret detection
        - AdvancedEncodingAnalyzer for encoding analysis  
        - Context-aware analysis for rich understanding
        """
        analyses = []
        
        try:
            # Use existing secret extractor if available
            if self.secret_extractor:
                # Extract secrets using enhanced extractor
                extraction_result = self.secret_extractor.extract_secrets_from_content(content, file_path)
                
                # Perform context analysis on each secret
                for secret in extraction_result.secrets:
                    analysis = self.analyze_secret_in_context(secret, content, file_path)
                    analyses.append(analysis)
            
            # Use encoding analyzer for additional analysis
            if self.encoding_analyzer:
                encoding_findings = self.encoding_analyzer.analyze_content(content, file_path)
                
                # Convert encoding findings to context-aware analyses
                for finding in encoding_findings:
                    if hasattr(finding, 'decoded_content') and finding.decoded_content:
                        secret = Secret(
                            secret_type="encoded_secret",
                            value=finding.decoded_content,
                            location=f"encoded_in_{file_path}",
                            confidence=finding.confidence if hasattr(finding, 'confidence') else 0.7,
                            severity="MEDIUM",
                            entropy=self._calculate_entropy(finding.decoded_content),
                            validation_status="unverified",
                            extraction_method="encoding_analysis"
                        )
                        
                        analysis = self.analyze_secret_in_context(secret, content, file_path)
                        analyses.append(analysis)
            
        except Exception as e:
            self.logger.error(f"Secret extraction and analysis failed: {e}")
        
        return analyses
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0
        
        from collections import Counter
        import math
        
        counts = Counter(data)
        length = len(data)
        
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def generate_context_report(self, analyses: List[ContextAwareSecretAnalysis]) -> Dict[str, Any]:
        """Generate comprehensive context analysis report"""
        if not analyses:
            return {"error": "No analyses provided"}
        
        report = {
            "summary": {
                "total_secrets": len(analyses),
                "high_risk_secrets": len([a for a in analyses if a.risk_assessment.overall_risk in ["HIGH", "CRITICAL"]]),
                "context_analysis_coverage": len([a for a in analyses if a.code_flow_analysis.get("flow_confidence", 0) > 0.5]),
                "network_correlations": len([a for a in analyses if a.network_correlation]),
                "auth_contexts": len([a for a in analyses if a.auth_context])
            },
            "risk_distribution": {},
            "usage_patterns": {},
            "recommendations": [],
            "performance_stats": self.performance_stats
        }
        
        # Calculate risk distribution
        risk_levels = [a.risk_assessment.overall_risk for a in analyses]
        for risk in set(risk_levels):
            report["risk_distribution"][risk] = risk_levels.count(risk)
        
        # Calculate usage pattern distribution
        usage_patterns = [a.usage_pattern.pattern_type for a in analyses]
        for pattern in set(usage_patterns):
            report["usage_patterns"][pattern] = usage_patterns.count(pattern)
        
        # Generate recommendations
        if report["summary"]["high_risk_secrets"] > 0:
            report["recommendations"].append("Immediate review of high-risk secrets required")
        
        if any(a.network_correlation and 'HTTP' in a.network_correlation.protocols for a in analyses):
            report["recommendations"].append("Upgrade insecure HTTP connections to HTTPS")
        
        if any(a.auth_context and a.auth_context.vulnerabilities for a in analyses):
            report["recommendations"].append("Address authentication vulnerabilities")
        
        return report
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for secret analysis implementation"""
        total_analyses = self.performance_stats["successful_analyses"] + self.performance_stats["failed_analyses"]
        
        return {
            "epic_version": "2.2.1",
            "total_secrets_analyzed": self.performance_stats["secrets_analyzed"],
            "successful_analyses": self.performance_stats["successful_analyses"],
            "failed_analyses": self.performance_stats["failed_analyses"],
            "success_rate": (self.performance_stats["successful_analyses"] / total_analyses * 100) if total_analyses > 0 else 0,
            "average_analysis_time": (self.performance_stats["context_analysis_time"] / total_analyses) if total_analyses > 0 else 0,
            "context_analyzer_stats": self.context_analyzer.analysis_stats
        } 