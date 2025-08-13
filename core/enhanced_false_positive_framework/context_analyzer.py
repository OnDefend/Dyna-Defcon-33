#!/usr/bin/env python3
"""
Enhanced False Positive Reduction - Context Analyzer
====================================================

This module provides context-aware analysis capabilities for enhanced false
positive reduction, including API detection, proximity analysis, and
framework-specific context understanding.

Features:
- Context-aware secret analysis with API detection
- Method and variable context analysis
- Framework-specific context understanding
- Proximity-based relevance scoring
- Security context classification

"""

import re
from typing import Any, Dict, List, Optional, Set

from loguru import logger

from .data_structures import ContextAnalysisResult

class EnhancedContextAnalyzer:
    """
    Advanced context analyzer for enhanced secret detection with comprehensive
    API detection and framework-specific understanding.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize the enhanced context analyzer."""
        self.config = config
        self.context_config = config.get("context_analysis", {})
        self.api_proximity_radius = self.context_config.get("api_proximity_radius", 7)
        
        # Initialize API patterns
        self._init_api_patterns()
        self._init_security_patterns()
        self._init_framework_patterns()

    def _init_api_patterns(self):
        """Initialize comprehensive API detection patterns."""
        # Cryptographic and security APIs
        self.crypto_apis = {
            'cipher', 'encrypt', 'decrypt', 'hash', 'hmac', 'sign', 'verify',
            'keystore', 'keychain', 'ssl', 'tls', 'certificate', 'keypair',
            'aes', 'rsa', 'ecdsa', 'sha256', 'md5', 'pbkdf2', 'scrypt'
        }
        
        # Authentication APIs
        self.auth_apis = {
            'authenticate', 'login', 'signin', 'oauth', 'jwt', 'token',
            'session', 'cookie', 'credential', 'password', 'passcode',
            'biometric', 'fingerprint', 'faceauth', 'pin'
        }
        
        # Network and communication APIs
        self.network_apis = {
            'httpurl', 'request', 'response', 'client', 'server', 'api',
            'rest', 'graphql', 'websocket', 'retrofit', 'okhttp', 'volley',
            'networking', 'urlsession', 'alamofire'
        }
        
        # Storage and database APIs
        self.storage_apis = {
            'database', 'sqlite', 'realm', 'coredata', 'preferences',
            'sharedpreferences', 'userdefaults', 'keyvalue', 'cache',
            'persist', 'save', 'store', 'retrieve'
        }
        
        # Third-party service APIs
        self.service_apis = {
            'firebase', 'aws', 'azure', 'gcp', 'stripe', 'paypal',
            'twilio', 'sendgrid', 'mailgun', 'github', 'gitlab',
            'slack', 'discord', 'twitter', 'facebook', 'google'
        }
        
        # Combine all API patterns
        self.all_apis = (
            self.crypto_apis | self.auth_apis | self.network_apis |
            self.storage_apis | self.service_apis
        )

    def _init_security_patterns(self):
        """Initialize security-related patterns."""
        self.security_keywords = {
            'secret', 'key', 'token', 'password', 'credential', 'auth',
            'access', 'bearer', 'authorization', 'certificate', 'private',
            'public', 'signature', 'hash', 'salt', 'nonce', 'iv'
        }
        
        self.sensitive_contexts = {
            'config', 'configuration', 'settings', 'properties', 'env',
            'environment', 'secrets', 'credentials', 'keys', 'tokens'
        }

    def _init_framework_patterns(self):
        """Initialize framework-specific patterns."""
        # Android framework patterns
        self.android_framework = {
            'android', 'androidx', 'google', 'material', 'support',
            'lifecycle', 'navigation', 'room', 'workmanager', 'databinding'
        }
        
        # iOS framework patterns
        self.ios_framework = {
            'foundation', 'uikit', 'swiftui', 'core', 'avfoundation',
            'security', 'keychain', 'usernotifications', 'storekit'
        }
        
        # Flutter framework patterns
        self.flutter_framework = {
            'flutter', 'dart', 'material', 'cupertino', 'widgets',
            'theme', 'scaffold', 'appbar', 'navigator', 'provider'
        }
        
        # React Native framework patterns
        self.react_native_framework = {
            'react', 'native', 'navigation', 'gesture', 'reanimated',
            'screens', 'safe', 'async', 'storage', 'vector'
        }

    def analyze_context(self, content: str, surrounding_lines: List[str],
                       file_context: Optional[str] = None) -> ContextAnalysisResult:
        """
        Perform comprehensive context analysis around a potential secret.
        
        Args:
            content: The potential secret content
            surrounding_lines: Lines of code around the potential secret
            file_context: Optional file path/name context
            
        Returns:
            ContextAnalysisResult with comprehensive analysis
        """
        result = ContextAnalysisResult()
        
        # Combine all context for analysis
        context_text = ' '.join(surrounding_lines).lower()
        if file_context:
            context_text += f" {file_context.lower()}"
        
        # Analyze APIs in context
        result.apis_found = self._find_apis_in_context(context_text)
        
        # Determine context type
        result.context_type = self._determine_context_type(context_text, file_context)
        
        # Analyze method context
        result.method_context = self._analyze_method_context(surrounding_lines)
        
        # Enhanced context analysis
        result.usage_patterns = self._analyze_usage_patterns(context_text, content)
        result.security_context = self._analyze_security_context(context_text)
        result.framework_context = self._analyze_framework_context(context_text)
        
        # Calculate context score
        result.context_score = self._calculate_context_score(result, content)
        
        # Determine confidence adjustment
        result.confidence_adjustment = self._calculate_confidence_adjustment(result)
        
        # Set analysis radius
        result.analysis_radius = len(surrounding_lines)
        
        return result

    def _find_apis_in_context(self, context_text: str) -> List[str]:
        """Find API references in the context."""
        found_apis = []
        
        # Check for API patterns
        for api in self.all_apis:
            if api in context_text:
                found_apis.append(api)
        
        # Check for common API method patterns
        api_patterns = [
            r'\.get\w*\(',
            r'\.post\w*\(',
            r'\.put\w*\(',
            r'\.delete\w*\(',
            r'\.create\w*\(',
            r'\.update\w*\(',
            r'\.authenticate\w*\(',
            r'\.login\w*\(',
            r'\.connect\w*\(',
            r'\.execute\w*\(',
        ]
        
        for pattern in api_patterns:
            if re.search(pattern, context_text, re.IGNORECASE):
                found_apis.append(f"method_pattern:{pattern}")
        
        return found_apis

    def _determine_context_type(self, context_text: str, file_context: Optional[str]) -> str:
        """Determine the type of context."""
        # File-based context
        if file_context:
            file_lower = file_context.lower()
            if any(pattern in file_lower for pattern in ['config', 'setting', 'env']):
                return "configuration"
            elif any(pattern in file_lower for pattern in ['test', 'spec', 'mock']):
                return "test"
            elif any(pattern in file_lower for pattern in ['example', 'demo', 'sample']):
                return "documentation"
        
        # Content-based context
        if any(word in context_text for word in ['class', 'function', 'method']):
            return "code"
        elif any(word in context_text for word in ['config', 'setting', 'property']):
            return "configuration"
        elif any(word in context_text for word in ['test', 'mock', 'fake']):
            return "test"
        elif any(word in context_text for word in ['comment', 'note', 'todo']):
            return "documentation"
        else:
            return "unknown"

    def _analyze_method_context(self, surrounding_lines: List[str]) -> Optional[str]:
        """Analyze method context around the potential secret."""
        method_patterns = [
            r'def\s+(\w+)',          # Python
            r'function\s+(\w+)',     # JavaScript
            r'public\s+\w+\s+(\w+)', # Java/C#
            r'private\s+\w+\s+(\w+)', # Java/C#
            r'func\s+(\w+)',         # Swift/Go
        ]
        
        for line in surrounding_lines:
            for pattern in method_patterns:
                match = re.search(pattern, line)
                if match:
                    return match.group(1)
        
        return None

    def _analyze_usage_patterns(self, context_text: str, content: str) -> List[str]:
        """Analyze usage patterns in the context."""
        patterns = []
        
        # Variable assignment patterns
        if any(op in context_text for op in ['=', ':=', '<-']):
            patterns.append("variable_assignment")
        
        # Function parameter patterns
        if any(char in context_text for char in ['(', ')']):
            patterns.append("function_parameter")
        
        # Configuration patterns
        if any(word in context_text for word in ['config', 'setting', 'property']):
            patterns.append("configuration_value")
        
        # API call patterns
        if any(api in context_text for api in self.all_apis):
            patterns.append("api_usage")
        
        # Authentication patterns
        if any(word in context_text for word in self.auth_apis):
            patterns.append("authentication")
        
        # Encryption patterns
        if any(word in context_text for word in self.crypto_apis):
            patterns.append("cryptographic")
        
        return patterns

    def _analyze_security_context(self, context_text: str) -> Optional[str]:
        """Analyze security-related context."""
        if any(word in context_text for word in self.crypto_apis):
            return "cryptographic"
        elif any(word in context_text for word in self.auth_apis):
            return "authentication"
        elif any(word in context_text for word in self.security_keywords):
            return "security_related"
        elif any(word in context_text for word in self.sensitive_contexts):
            return "sensitive_configuration"
        else:
            return None

    def _analyze_framework_context(self, context_text: str) -> Optional[str]:
        """Analyze framework-specific context."""
        framework_scores = {
            'android': sum(1 for word in self.android_framework if word in context_text),
            'ios': sum(1 for word in self.ios_framework if word in context_text),
            'flutter': sum(1 for word in self.flutter_framework if word in context_text),
            'react_native': sum(1 for word in self.react_native_framework if word in context_text),
        }
        
        # Return framework with highest score
        if max(framework_scores.values()) > 0:
            return max(framework_scores, key=framework_scores.get)
        else:
            return None

    def _calculate_context_score(self, result: ContextAnalysisResult, content: str) -> float:
        """Calculate overall context score."""
        score = 0.0
        
        # APIs found boost score
        api_boost = min(len(result.apis_found) * 0.1, 0.5)
        score += api_boost
        
        # Security context boost
        if result.security_context in ['cryptographic', 'authentication']:
            score += 0.3
        elif result.security_context == 'security_related':
            score += 0.2
        
        # Usage patterns boost
        important_patterns = ['api_usage', 'authentication', 'cryptographic']
        pattern_boost = sum(0.1 for pattern in result.usage_patterns if pattern in important_patterns)
        score += pattern_boost
        
        # Context type adjustment
        if result.context_type == 'configuration':
            score += 0.2
        elif result.context_type == 'test':
            score -= 0.3  # Test context reduces likelihood of real secret
        elif result.context_type == 'documentation':
            score -= 0.4  # Documentation reduces likelihood
        
        # Framework context adjustment
        if result.framework_context:
            score -= 0.1  # Framework context slightly reduces likelihood
        
        return max(0.0, min(1.0, score))

    def _calculate_confidence_adjustment(self, result: ContextAnalysisResult) -> float:
        """Calculate confidence adjustment based on context analysis."""
        adjustment = 0.0
        
        # High context score boosts confidence
        if result.context_score > 0.7:
            adjustment += 0.2
        elif result.context_score > 0.4:
            adjustment += 0.1
        elif result.context_score < 0.2:
            adjustment -= 0.2
        
        # Security context boosts confidence
        if result.security_context in ['cryptographic', 'authentication']:
            adjustment += 0.15
        
        # Test/documentation context reduces confidence
        if result.context_type in ['test', 'documentation']:
            adjustment -= 0.25
        
        # Framework context slightly reduces confidence
        if result.framework_context:
            adjustment -= 0.05
        
        return adjustment

    def is_framework_noise(self, content: str, context_text: str) -> bool:
        """Determine if content is likely framework noise."""
        context_lower = context_text.lower()
        content_lower = content.lower()
        
        # Check for framework patterns in content
        framework_indicators = (
            self.android_framework | self.ios_framework |
            self.flutter_framework | self.react_native_framework
        )
        
        # Content contains framework keywords
        if any(keyword in content_lower for keyword in framework_indicators):
            return True
        
        # Context is heavily framework-oriented
        framework_count = sum(1 for keyword in framework_indicators if keyword in context_lower)
        if framework_count >= 3:
            return True
        
        # Common framework noise patterns
        noise_patterns = [
            r'\.fallback$',
            r'\.default$',
            r'schemas\.',
            r'xmlns:',
            r'@\w+/',
            r'com\.\w+\.\w+',
            r'org\.\w+\.\w+',
        ]
        
        for pattern in noise_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False

    def enhance_confidence_with_context(self, base_confidence: float, 
                                      context_result: ContextAnalysisResult) -> float:
        """Enhance confidence score using context analysis."""
        enhanced_confidence = base_confidence + context_result.confidence_adjustment
        
        # Apply bounds
        return max(0.0, min(1.0, enhanced_confidence)) 