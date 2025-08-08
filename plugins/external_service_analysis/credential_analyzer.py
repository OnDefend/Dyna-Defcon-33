"""
Credential Analysis Module for External Service Analysis

This module handles the detection and analysis of exposed credentials
including API keys, tokens, passwords, private keys, and connection strings.
"""

import re
import base64
import logging
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
import yaml

from .data_structures import (
    CredentialType, CredentialExposure, SeverityLevel,
    ExternalServiceVulnerability, AnalysisContext
)

logger = logging.getLogger(__name__)

class CredentialPatternLoader:
    """Loads and manages credential detection patterns."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize credential pattern loader."""
        if config_path is None:
            config_path = Path(__file__).parent / "service_patterns_config.yaml"
        
        self.config_path = Path(config_path)
        self.patterns: Dict[CredentialType, Dict] = {}
        self.compiled_patterns: Dict[CredentialType, List[re.Pattern]] = {}
        self._load_patterns()
    
    def _load_patterns(self):
        """Load credential patterns from configuration file."""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            credential_config = config.get('credential_patterns', {})
            
            # Map config credential names to CredentialType enum
            credential_mapping = {
                'api_key': CredentialType.API_KEY,
                'access_token': CredentialType.ACCESS_TOKEN,
                'secret_key': CredentialType.SECRET_KEY,
                'password': CredentialType.PASSWORD,
                'private_key': CredentialType.PRIVATE_KEY,
                'connection_string': CredentialType.CONNECTION_STRING
            }
            
            for cred_name, cred_type in credential_mapping.items():
                if cred_name in credential_config:
                    cred_config = credential_config[cred_name]
                    self.patterns[cred_type] = cred_config
                    
                    # Compile regex patterns
                    compiled = []
                    for pattern in cred_config.get('patterns', []):
                        try:
                            compiled.append(re.compile(pattern, re.IGNORECASE | re.MULTILINE))
                        except re.error as e:
                            logger.warning(f"Invalid credential regex pattern '{pattern}': {e}")
                    
                    self.compiled_patterns[cred_type] = compiled
            
            logger.info(f"Loaded {len(self.patterns)} credential pattern types")
            
        except Exception as e:
            logger.error(f"Failed to load credential patterns: {e}")
            self._initialize_default_patterns()
    
    def _initialize_default_patterns(self):
        """Initialize default credential patterns if loading fails."""
        default_patterns = {
            CredentialType.API_KEY: {
                'patterns': [
                    r'api[_-]?key["\s]*[=:]["\s]*[a-zA-Z0-9]{20,}',
                    r'apikey["\s]*[=:]["\s]*[a-zA-Z0-9]{20,}',
                    r'key["\s]*[=:]["\s]*[a-zA-Z0-9]{32,}'
                ],
                'severity': 'high',
                'confidence_base': 0.85
            },
            CredentialType.SECRET_KEY: {
                'patterns': [
                    r'secret[_-]?key["\s]*[=:]["\s]*[a-zA-Z0-9]{20,}',
                    r'client[_-]?secret["\s]*[=:]["\s]*[a-zA-Z0-9]{20,}'
                ],
                'severity': 'critical',
                'confidence_base': 0.90
            },
            CredentialType.PASSWORD: {
                'patterns': [
                    r'password["\s]*[=:]["\s]*[a-zA-Z0-9!@#$%^&*]{8,}',
                    r'passwd["\s]*[=:]["\s]*[a-zA-Z0-9!@#$%^&*]{8,}'
                ],
                'severity': 'critical',
                'confidence_base': 0.80
            }
        }
        
        for cred_type, config in default_patterns.items():
            self.patterns[cred_type] = config
            compiled = []
            for pattern in config['patterns']:
                try:
                    compiled.append(re.compile(pattern, re.IGNORECASE | re.MULTILINE))
                except re.error:
                    pass
            self.compiled_patterns[cred_type] = compiled

class CredentialAnalyzer:
    """Analyzes Android applications for exposed credentials."""
    
    def __init__(self, pattern_loader: Optional[CredentialPatternLoader] = None):
        """Initialize credential analyzer."""
        self.pattern_loader = pattern_loader or CredentialPatternLoader()
        self.patterns = self.pattern_loader.patterns
        self.compiled_patterns = self.pattern_loader.compiled_patterns
        
        # Cache for detected credentials to avoid duplicates
        self._detected_cache: Set[Tuple[str, str, str]] = set()
        
        # Additional patterns for specific credential types
        self._init_additional_patterns()
    
    def _init_additional_patterns(self):
        """Initialize additional credential detection patterns."""
        # JWT token patterns
        self.jwt_pattern = re.compile(
            r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            re.IGNORECASE
        )
        
        # Base64 encoded patterns (potential credentials)
        self.base64_pattern = re.compile(
            r'[a-zA-Z0-9+/]{40,}={0,2}',
            re.IGNORECASE
        )
        
        # Private key patterns
        self.private_key_patterns = [
            re.compile(r'-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----', re.DOTALL),
            re.compile(r'-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----', re.DOTALL),
            re.compile(r'-----BEGIN EC PRIVATE KEY-----.*?-----END EC PRIVATE KEY-----', re.DOTALL),
        ]
        
        # Connection string patterns
        self.connection_patterns = [
            re.compile(r'mongodb://[^"\s\']+:[^"\s\']+@[^"\s\']+', re.IGNORECASE),
            re.compile(r'mysql://[^"\s\']+:[^"\s\']+@[^"\s\']+', re.IGNORECASE),
            re.compile(r'postgres://[^"\s\']+:[^"\s\']+@[^"\s\']+', re.IGNORECASE),
            re.compile(r'redis://[^"\s\']+:[^"\s\']+@[^"\s\']+', re.IGNORECASE),
        ]
        
        # OAuth token patterns
        self.oauth_patterns = [
            re.compile(r'oauth[_-]?token["\s]*[=:]["\s]*[a-zA-Z0-9]{20,}', re.IGNORECASE),
            re.compile(r'bearer["\s]*[=:]["\s]*[a-zA-Z0-9]{20,}', re.IGNORECASE),
        ]
    
    def analyze_credentials_in_content(self, content: str, file_path: str,
                                     context: Optional[AnalysisContext] = None) -> List[CredentialExposure]:
        """
        Analyze content for exposed credentials.
        
        Args:
            content: File content to analyze
            file_path: Path to the file being analyzed
            context: Analysis context for confidence calculation
            
        Returns:
            List of detected credential exposures
        """
        exposures = []
        
        if not content or not content.strip():
            return exposures
        
        # Analyze using configured patterns
        for cred_type, compiled_patterns in self.compiled_patterns.items():
            for pattern in compiled_patterns:
                exposures.extend(self._find_credential_matches(
                    pattern, cred_type, content, file_path, context
                ))
        
        # Analyze using additional patterns
        exposures.extend(self._analyze_jwt_tokens(content, file_path, context))
        exposures.extend(self._analyze_private_keys(content, file_path, context))
        exposures.extend(self._analyze_connection_strings(content, file_path, context))
        exposures.extend(self._analyze_oauth_tokens(content, file_path, context))
        exposures.extend(self._analyze_base64_credentials(content, file_path, context))
        
        return exposures
    
    def _find_credential_matches(self, pattern: re.Pattern, cred_type: CredentialType,
                               content: str, file_path: str,
                               context: Optional[AnalysisContext] = None) -> List[CredentialExposure]:
        """Find credential matches using a specific pattern."""
        exposures = []
        
        for match in pattern.finditer(content):
            matched_text = match.group(0)
            
            # Extract the actual credential value (after = or :)
            credential_value = self._extract_credential_value(matched_text)
            
            # Create cache key to avoid duplicates
            cache_key = (cred_type.value, credential_value, file_path)
            if cache_key in self._detected_cache:
                continue
            
            self._detected_cache.add(cache_key)
            
            # Calculate line number
            line_number = content[:match.start()].count('\n') + 1
            
            # Extract context around the match
            context_start = max(0, match.start() - 100)
            context_end = min(len(content), match.end() + 100)
            match_context = content[context_start:context_end]
            
            # Calculate confidence
            confidence = self._calculate_credential_confidence(
                cred_type, matched_text, match_context, context
            )
            
            # Get severity from pattern config
            pattern_config = self.patterns.get(cred_type, {})
            severity = self._parse_severity(pattern_config.get('severity', 'high'))
            
            exposure = CredentialExposure(
                credential_type=cred_type,
                value=self._obfuscate_credential(credential_value),
                location=f"{file_path}:{line_number}",
                file_path=file_path,
                line_number=line_number,
                context=match_context,
                severity=severity,
                confidence=confidence
            )
            
            exposures.append(exposure)
        
        return exposures
    
    def _analyze_jwt_tokens(self, content: str, file_path: str,
                          context: Optional[AnalysisContext] = None) -> List[CredentialExposure]:
        """Analyze content for JWT tokens."""
        exposures = []
        
        for match in self.jwt_pattern.finditer(content):
            jwt_token = match.group(0)
            
            # Validate JWT structure
            if not self._is_valid_jwt(jwt_token):
                continue
            
            cache_key = (CredentialType.JWT_TOKEN.value, jwt_token, file_path)
            if cache_key in self._detected_cache:
                continue
            
            self._detected_cache.add(cache_key)
            
            line_number = content[:match.start()].count('\n') + 1
            
            exposure = CredentialExposure(
                credential_type=CredentialType.JWT_TOKEN,
                value=self._obfuscate_credential(jwt_token),
                location=f"{file_path}:{line_number}",
                file_path=file_path,
                line_number=line_number,
                context=content[max(0, match.start()-50):match.end()+50],
                severity=SeverityLevel.HIGH,
                confidence=0.90
            )
            
            exposures.append(exposure)
        
        return exposures
    
    def _analyze_private_keys(self, content: str, file_path: str,
                            context: Optional[AnalysisContext] = None) -> List[CredentialExposure]:
        """Analyze content for private keys."""
        exposures = []
        
        for pattern in self.private_key_patterns:
            for match in pattern.finditer(content):
                private_key = match.group(0)
                
                cache_key = (CredentialType.PRIVATE_KEY.value, private_key[:50], file_path)
                if cache_key in self._detected_cache:
                    continue
                
                self._detected_cache.add(cache_key)
                
                line_number = content[:match.start()].count('\n') + 1
                
                exposure = CredentialExposure(
                    credential_type=CredentialType.PRIVATE_KEY,
                    value="[PRIVATE KEY DETECTED]",
                    location=f"{file_path}:{line_number}",
                    file_path=file_path,
                    line_number=line_number,
                    context="Private key found in code",
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.95
                )
                
                exposures.append(exposure)
        
        return exposures
    
    def _analyze_connection_strings(self, content: str, file_path: str,
                                  context: Optional[AnalysisContext] = None) -> List[CredentialExposure]:
        """Analyze content for database connection strings."""
        exposures = []
        
        for pattern in self.connection_patterns:
            for match in pattern.finditer(content):
                conn_string = match.group(0)
                
                cache_key = (CredentialType.CONNECTION_STRING.value, conn_string, file_path)
                if cache_key in self._detected_cache:
                    continue
                
                self._detected_cache.add(cache_key)
                
                line_number = content[:match.start()].count('\n') + 1
                
                # Obfuscate credentials in connection string
                obfuscated = self._obfuscate_connection_string(conn_string)
                
                exposure = CredentialExposure(
                    credential_type=CredentialType.CONNECTION_STRING,
                    value=obfuscated,
                    location=f"{file_path}:{line_number}",
                    file_path=file_path,
                    line_number=line_number,
                    context=content[max(0, match.start()-50):match.end()+50],
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.90
                )
                
                exposures.append(exposure)
        
        return exposures
    
    def _analyze_oauth_tokens(self, content: str, file_path: str,
                            context: Optional[AnalysisContext] = None) -> List[CredentialExposure]:
        """Analyze content for OAuth tokens."""
        exposures = []
        
        for pattern in self.oauth_patterns:
            for match in pattern.finditer(content):
                token = match.group(0)
                
                # Extract token value
                token_value = self._extract_credential_value(token)
                
                cache_key = (CredentialType.OAUTH_TOKEN.value, token_value, file_path)
                if cache_key in self._detected_cache:
                    continue
                
                self._detected_cache.add(cache_key)
                
                line_number = content[:match.start()].count('\n') + 1
                
                exposure = CredentialExposure(
                    credential_type=CredentialType.OAUTH_TOKEN,
                    value=self._obfuscate_credential(token_value),
                    location=f"{file_path}:{line_number}",
                    file_path=file_path,
                    line_number=line_number,
                    context=content[max(0, match.start()-50):match.end()+50],
                    severity=SeverityLevel.HIGH,
                    confidence=0.85
                )
                
                exposures.append(exposure)
        
        return exposures
    
    def _analyze_base64_credentials(self, content: str, file_path: str,
                                  context: Optional[AnalysisContext] = None) -> List[CredentialExposure]:
        """Analyze content for potential Base64 encoded credentials."""
        exposures = []
        
        # Only check for base64 in certain contexts
        suspicious_keywords = ['key', 'token', 'secret', 'password', 'auth', 'credential']
        
        for match in self.base64_pattern.finditer(content):
            base64_text = match.group(0)
            
            # Check if the base64 string appears in a suspicious context
            context_start = max(0, match.start() - 50)
            context_end = min(len(content), match.end() + 50)
            surrounding_context = content[context_start:context_end].lower()
            
            if not any(keyword in surrounding_context for keyword in suspicious_keywords):
                continue
            
            # Try to decode to see if it's valid base64
            try:
                decoded = base64.b64decode(base64_text).decode('utf-8', errors='ignore')
                if not decoded or len(decoded) < 10:
                    continue
            except Exception:
                continue
            
            cache_key = (CredentialType.API_KEY.value, base64_text, file_path)
            if cache_key in self._detected_cache:
                continue
            
            self._detected_cache.add(cache_key)
            
            line_number = content[:match.start()].count('\n') + 1
            
            exposure = CredentialExposure(
                credential_type=CredentialType.API_KEY,  # Assume API key for base64
                value=self._obfuscate_credential(base64_text),
                location=f"{file_path}:{line_number}",
                file_path=file_path,
                line_number=line_number,
                context=surrounding_context,
                severity=SeverityLevel.MEDIUM,
                confidence=0.60  # Lower confidence for base64 detection
            )
            
            exposures.append(exposure)
        
        return exposures
    
    def _extract_credential_value(self, matched_text: str) -> str:
        """Extract the actual credential value from matched text."""
        # Look for patterns like key="value" or key: value
        value_patterns = [
            r'[=:]\s*["\']([^"\']+)["\']',
            r'[=:]\s*([^\s,;]+)'
        ]
        
        for pattern in value_patterns:
            match = re.search(pattern, matched_text)
            if match:
                return match.group(1)
        
        return matched_text
    
    def _obfuscate_credential(self, credential: str) -> str:
        """Obfuscate credential value for safe display."""
        if len(credential) <= 8:
            return "*" * len(credential)
        
        return credential[:4] + "*" * (len(credential) - 8) + credential[-4:]
    
    def _obfuscate_connection_string(self, conn_string: str) -> str:
        """Obfuscate connection string credentials."""
        # Replace password in connection string
        patterns = [
            (r'://([^:]+):([^@]+)@', r'://\1:****@'),
            (r'password=([^;]+)', r'password=****'),
            (r'pwd=([^;]+)', r'pwd=****')
        ]
        
        result = conn_string
        for pattern, replacement in patterns:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        
        return result
    
    def _is_valid_jwt(self, token: str) -> bool:
        """Validate if a string is a properly formatted JWT token."""
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        # Each part should be valid base64
        for part in parts:
            try:
                # Add padding if needed
                padded = part + '=' * (4 - len(part) % 4)
                base64.b64decode(padded)
            except Exception:
                return False
        
        return True
    
    def _calculate_credential_confidence(self, cred_type: CredentialType,
                                       matched_text: str, context: str,
                                       analysis_context: Optional[AnalysisContext] = None) -> float:
        """Calculate confidence score for a credential match."""
        pattern_config = self.patterns.get(cred_type, {})
        base_confidence = pattern_config.get('confidence_base', 0.75)
        
        adjustments = 0.0
        
        # Length-based adjustments
        credential_value = self._extract_credential_value(matched_text)
        if len(credential_value) > 32:
            adjustments += 0.1
        elif len(credential_value) < 16:
            adjustments -= 0.1
        
        # Context-based adjustments
        context_lower = context.lower()
        
        # Positive indicators
        if any(word in context_lower for word in ['production', 'live', 'prod']):
            adjustments += 0.1
        
        if any(word in context_lower for word in ['secret', 'private', 'confidential']):
            adjustments += 0.05
        
        # Negative indicators (likely test/fake credentials)
        if any(word in context_lower for word in ['test', 'demo', 'example', 'sample']):
            adjustments -= 0.2
        
        if any(word in context_lower for word in ['fake', 'dummy', 'placeholder']):
            adjustments -= 0.3
        
        # File type adjustments
        if analysis_context and analysis_context.file_type:
            if analysis_context.file_type in ['properties', 'config', 'xml']:
                adjustments += 0.1
            elif analysis_context.file_type in ['test', 'spec']:
                adjustments -= 0.2
        
        return max(0.1, min(1.0, base_confidence + adjustments))
    
    def _parse_severity(self, severity_str: str) -> SeverityLevel:
        """Parse severity string to SeverityLevel enum."""
        severity_map = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'info': SeverityLevel.INFO
        }
        return severity_map.get(severity_str.lower(), SeverityLevel.HIGH)
    
    def create_vulnerabilities_from_exposures(self, exposures: List[CredentialExposure]) -> List[ExternalServiceVulnerability]:
        """Create vulnerability objects from credential exposures."""
        vulnerabilities = []
        
        for exposure in exposures:
            vulnerability = ExternalServiceVulnerability(
                vulnerability_id=f"CRED_EXPOSURE_{exposure.credential_type.value.upper()}_{hash(exposure.value) % 10000:04d}",
                title=f"Exposed {exposure.credential_type.value.replace('_', ' ').title()}",
                description=f"Detected exposed {exposure.credential_type.value.replace('_', ' ')} in application code",
                severity=exposure.severity,
                service_type=self._get_service_type_for_credential(exposure.credential_type),
                location=exposure.location,
                evidence={
                    'credential_type': exposure.credential_type.value,
                    'obfuscated_value': exposure.value,
                    'context': exposure.context[:200] if exposure.context else "",
                    'file_path': exposure.file_path,
                    'line_number': exposure.line_number
                },
                recommendations=self._get_credential_recommendations(exposure.credential_type),
                cwe="CWE-798",  # Use of Hard-coded Credentials
                masvs_control="MSTG-CRYPTO-01",
                confidence=exposure.confidence
            )
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _get_service_type_for_credential(self, cred_type: CredentialType):
        """Get appropriate service type for credential type."""
        from .data_structures import ServiceType
        
        mapping = {
            CredentialType.API_KEY: ServiceType.REST_API,
            CredentialType.ACCESS_TOKEN: ServiceType.REST_API,
            CredentialType.SECRET_KEY: ServiceType.REST_API,
            CredentialType.OAUTH_TOKEN: ServiceType.REST_API,
            CredentialType.JWT_TOKEN: ServiceType.REST_API,
            CredentialType.CONNECTION_STRING: ServiceType.UNKNOWN,
            CredentialType.PRIVATE_KEY: ServiceType.UNKNOWN,
            CredentialType.PASSWORD: ServiceType.UNKNOWN
        }
        
        return mapping.get(cred_type, ServiceType.UNKNOWN)
    
    def _get_credential_recommendations(self, cred_type: CredentialType) -> List[str]:
        """Get security recommendations for credential exposure."""
        general_recommendations = [
            "Remove hardcoded credentials from source code",
            "Use secure credential storage mechanisms",
            "Implement proper secret management practices"
        ]
        
        specific_recommendations = {
            CredentialType.API_KEY: [
                "Store API keys in secure configuration or environment variables",
                "Use API key rotation mechanisms",
                "Implement proper API key scoping and permissions"
            ],
            CredentialType.PRIVATE_KEY: [
                "Store private keys in secure keystores",
                "Use hardware security modules when possible",
                "Implement proper key lifecycle management"
            ],
            CredentialType.CONNECTION_STRING: [
                "Use connection pooling with secure credential storage",
                "Implement database authentication tokens",
                "Use encrypted configuration files"
            ]
        }
        
        recommendations = general_recommendations.copy()
        recommendations.extend(specific_recommendations.get(cred_type, []))
        
        return recommendations
    
    def get_credential_statistics(self) -> Dict[str, int]:
        """Get statistics about credential detection."""
        credential_counts = {}
        
        for cache_entry in self._detected_cache:
            credential_type = cache_entry[0]
            credential_counts[credential_type] = credential_counts.get(credential_type, 0) + 1
        
        return {
            'total_exposures': len(self._detected_cache),
            'credential_breakdown': credential_counts,
            'unique_types': len(credential_counts)
        } 