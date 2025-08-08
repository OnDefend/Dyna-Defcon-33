"""
External Service Endpoint Analyzer

Core analysis engine for external service endpoint security assessment.
Analyzes API endpoints, authentication mechanisms, and security vulnerabilities.
"""

import re
import logging
import yaml
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
import os

from .data_structures import (
    ServiceEndpoint, ServiceAuthentication, APISecurityIssue,
    ServiceType, SecurityLevel, AuthenticationType, VulnerabilityType
)
from .confidence_calculator import ExternalServiceConfidenceCalculator

logger = logging.getLogger(__name__)

class EndpointAnalyzer:
    """Analyzes external service endpoints for security issues."""
    
    def __init__(self, patterns_config_path: str = None):
        """Initialize endpoint analyzer with pattern configuration."""
        self.confidence_calculator = ExternalServiceConfidenceCalculator()
        
        # Load patterns configuration
        if patterns_config_path is None:
            patterns_config_path = os.path.join(
                os.path.dirname(__file__), 'service_patterns_config.yaml'
            )
        
        self.patterns = self._load_patterns(patterns_config_path)
        
        # Compiled regex patterns for performance
        self._compile_patterns()
        
        logger.info("EndpointAnalyzer initialized with pattern configuration")
    
    def _load_patterns(self, config_path: str) -> Dict[str, Any]:
        """Load service patterns from YAML configuration."""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                patterns = yaml.safe_load(f)
            logger.info(f"Loaded {len(patterns)} pattern categories from {config_path}")
            return patterns
        except Exception as e:
            logger.error(f"Failed to load patterns from {config_path}: {e}")
            return self._get_default_patterns()
    
    def _get_default_patterns(self) -> Dict[str, Any]:
        """Get default patterns if configuration loading fails."""
        return {
            'rest_api_patterns': [
                {'pattern': r'https?://[^/]+/api/', 'description': 'REST API endpoint',
                 'severity': 'medium', 'confidence_base': 0.85, 'cwe': 'CWE-200'}
            ],
            'authentication_patterns': [
                {'pattern': r'Authorization:\s*Bearer', 'description': 'Bearer token',
                 'severity': 'high', 'confidence_base': 0.92, 'cwe': 'CWE-287'}
            ]
        }
    
    def _compile_patterns(self):
        """Compile regex patterns for performance optimization."""
        self.compiled_patterns = {}
        
        for category, patterns in self.patterns.items():
            if isinstance(patterns, list):
                self.compiled_patterns[category] = []
                for pattern_info in patterns:
                    try:
                        compiled = re.compile(pattern_info['pattern'], re.IGNORECASE)
                        self.compiled_patterns[category].append({
                            'regex': compiled,
                            'info': pattern_info
                        })
                    except re.error as e:
                        logger.warning(f"Invalid regex pattern in {category}: {e}")
        
        logger.debug(f"Compiled {len(self.compiled_patterns)} pattern categories")
    
    def analyze_endpoints(self, file_content: str, file_path: str = "") -> List[ServiceEndpoint]:
        """
        Analyze file content for external service endpoints.
        
        Args:
            file_content: File content to analyze
            file_path: Path of the file being analyzed
            
        Returns:
            List of discovered service endpoints
        """
        endpoints = []
        
        try:
            # Extract URLs from content
            urls = self._extract_urls(file_content)
            
            for url in urls:
                endpoint = self._analyze_single_endpoint(url, file_content, file_path)
                if endpoint:
                    endpoints.append(endpoint)
            
            # Additional pattern-based endpoint discovery
            pattern_endpoints = self._discover_pattern_endpoints(file_content, file_path)
            endpoints.extend(pattern_endpoints)
            
            logger.info(f"Discovered {len(endpoints)} endpoints in {file_path}")
            
        except Exception as e:
            logger.error(f"Error analyzing endpoints in {file_path}: {e}")
        
        return endpoints
    
    def _extract_urls(self, content: str) -> List[str]:
        """Extract URLs from file content using regex patterns."""
        url_patterns = [
            r'https?://[^\s\'"<>]+',
            r'"(https?://[^"]+)"',
            r"'(https?://[^']+)'",
            r'url\s*=\s*["\']([^"\']+)["\']',
            r'endpoint\s*=\s*["\']([^"\']+)["\']',
            r'baseURL\s*=\s*["\']([^"\']+)["\']'
        ]
        
        urls = set()
        for pattern in url_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                url = match if isinstance(match, str) else match[0] if match else ""
                if url and self._is_valid_url(url):
                    urls.add(url)
        
        return list(urls)
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate if string is a valid URL."""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False
    
    def _analyze_single_endpoint(self, url: str, content: str, file_path: str) -> Optional[ServiceEndpoint]:
        """Analyze a single endpoint for security characteristics."""
        try:
            parsed_url = urlparse(url)
            
            # Extract endpoint information
            endpoint_id = f"{parsed_url.netloc}_{parsed_url.path}"
            service_type = self._detect_service_type(url, content)
            
            # Create endpoint object
            endpoint = ServiceEndpoint(
                id=endpoint_id,
                url=url,
                method=self._detect_http_method(url, content),
                service_type=service_type,
                host=parsed_url.netloc,
                port=parsed_url.port or (443 if parsed_url.scheme == 'https' else 80),
                path=parsed_url.path,
                parameters=self._extract_parameters(parsed_url.query),
                headers=self._extract_headers(url, content),
                authentication_type=self._detect_authentication(url, content),
                security_level=self._assess_security_level(url, content),
                vulnerabilities=self._detect_vulnerabilities(url, content)
            )
            
            # Calculate confidence
            patterns = self._get_matched_patterns(url, content)
            endpoint.confidence = self.confidence_calculator.calculate_service_confidence(
                endpoint.to_dict(), patterns
            )
            
            return endpoint
            
        except Exception as e:
            logger.error(f"Error analyzing endpoint {url}: {e}")
            return None
    
    def _detect_service_type(self, url: str, content: str) -> str:
        """Detect the type of external service."""
        url_lower = url.lower()
        content_lower = content.lower()
        
        # Check for specific service types
        if '/api/' in url_lower or 'api.' in url_lower:
            if '/graphql' in url_lower or 'graphql' in content_lower:
                return ServiceType.GRAPHQL_API.value
            elif '.asmx' in url_lower or 'soap' in content_lower:
                return ServiceType.SOAP_API.value
            else:
                return ServiceType.REST_API.value
        
        if url_lower.startswith('ws://') or url_lower.startswith('wss://'):
            return ServiceType.WEBSOCKET.value
        
        if 'jdbc:' in url_lower or 'mongodb://' in url_lower:
            return ServiceType.DATABASE.value
        
        # Check domain patterns
        domain_patterns = {
            'amazonaws.com': ServiceType.CLOUD_STORAGE.value,
            'googleapis.com': ServiceType.CLOUD_STORAGE.value,
            'analytics': ServiceType.ANALYTICS.value,
            'stripe.com': ServiceType.PAYMENT.value,
            'paypal.com': ServiceType.PAYMENT.value,
            'facebook.com': ServiceType.SOCIAL_MEDIA.value,
            'twitter.com': ServiceType.SOCIAL_MEDIA.value
        }
        
        for pattern, service_type in domain_patterns.items():
            if pattern in url_lower:
                return service_type
        
        return ServiceType.OTHER.value
    
    def _detect_http_method(self, url: str, content: str) -> str:
        """Detect HTTP method used for the endpoint."""
        methods = ['POST', 'GET', 'PUT', 'DELETE', 'PATCH']
        
        for method in methods:
            # Look for method in context around the URL
            url_index = content.find(url)
            if url_index != -1:
                context = content[max(0, url_index-200):url_index+200]
                if method in context.upper():
                    return method
        
        # Default based on service type
        if '/api/' in url.lower():
            return 'POST'  # APIs commonly use POST
        
        return 'GET'  # Default assumption
    
    def _extract_parameters(self, query_string: str) -> List[str]:
        """Extract parameter names from query string."""
        if not query_string:
            return []
        
        parameters = []
        for param_pair in query_string.split('&'):
            if '=' in param_pair:
                param_name = param_pair.split('=')[0]
                parameters.append(param_name)
        
        return parameters
    
    def _extract_headers(self, url: str, content: str) -> Dict[str, str]:
        """Extract headers related to the endpoint."""
        headers = {}
        
        # Look for common headers in content
        header_patterns = [
            r'Content-Type:\s*([^\r\n]+)',
            r'Authorization:\s*([^\r\n]+)',
            r'X-API-Key:\s*([^\r\n]+)',
            r'Accept:\s*([^\r\n]+)'
        ]
        
        for pattern in header_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                header_name = pattern.split(':')[0].replace(r'\s*', '').replace('(', '')
                headers[header_name] = match.strip()
        
        return headers
    
    def _detect_authentication(self, url: str, content: str) -> str:
        """Detect authentication mechanism used."""
        auth_patterns = {
            AuthenticationType.BEARER_TOKEN.value: [r'Bearer\s+', r'access_token'],
            AuthenticationType.API_KEY.value: [r'api[_-]?key', r'X-API-Key'],
            AuthenticationType.BASIC_AUTH.value: [r'Basic\s+', r'username.*password'],
            AuthenticationType.OAUTH.value: [r'oauth', r'access_token.*refresh_token'],
            AuthenticationType.JWT.value: [r'jwt', r'jsonwebtoken']
        }
        
        for auth_type, patterns in auth_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return auth_type
        
        return AuthenticationType.NONE.value
    
    def _assess_security_level(self, url: str, content: str) -> str:
        """Assess the security level of the endpoint."""
        # Critical issues
        if url.startswith('http://'):
            return SecurityLevel.INSECURE.value
        
        if self._has_hardcoded_credentials(content):
            return SecurityLevel.CRITICAL.value
        
        # Security indicators
        security_score = 0
        
        if url.startswith('https://'):
            security_score += 2
        
        if self._has_authentication(content):
            security_score += 2
        
        if self._has_input_validation(content):
            security_score += 1
        
        # Map score to security level
        if security_score >= 4:
            return SecurityLevel.SECURE.value
        elif security_score >= 2:
            return SecurityLevel.ACCEPTABLE.value
        else:
            return SecurityLevel.SUSPICIOUS.value
    
    def _detect_vulnerabilities(self, url: str, content: str) -> List[str]:
        """Detect potential vulnerabilities in the endpoint."""
        vulnerabilities = []
        
        # Check for insecure communication
        if url.startswith('http://'):
            vulnerabilities.append(VulnerabilityType.INSECURE_COMMUNICATION.value)
        
        # Check for weak authentication
        if self._has_weak_authentication(content):
            vulnerabilities.append(VulnerabilityType.WEAK_AUTHENTICATION.value)
        
        # Check for data exposure risks
        if self._has_data_exposure_risk(content):
            vulnerabilities.append(VulnerabilityType.DATA_EXPOSURE.value)
        
        # Check for injection risks
        if self._has_injection_risk(content):
            vulnerabilities.append(VulnerabilityType.INJECTION_RISK.value)
        
        return vulnerabilities
    
    def _has_hardcoded_credentials(self, content: str) -> bool:
        """Check for hardcoded credentials."""
        patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']'
        ]
        
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _has_authentication(self, content: str) -> bool:
        """Check if authentication mechanisms are present."""
        auth_indicators = [
            'authorization', 'bearer', 'token', 'api_key', 'oauth'
        ]
        
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in auth_indicators)
    
    def _has_input_validation(self, content: str) -> bool:
        """Check for input validation indicators."""
        validation_patterns = [
            r'validate', r'sanitize', r'escape', r'filter'
        ]
        
        for pattern in validation_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _has_weak_authentication(self, content: str) -> bool:
        """Check for weak authentication patterns."""
        weak_patterns = [
            r'password\s*=\s*["\'][^"\']*["\']',  # Hardcoded passwords
            r'token\s*=\s*["\'][^"\']*["\']',     # Hardcoded tokens
            r'allowsArbitraryLoads.*true'         # Insecure transport
        ]
        
        for pattern in weak_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _has_data_exposure_risk(self, content: str) -> bool:
        """Check for data exposure risks."""
        exposure_patterns = [
            r'user.*data', r'sensitive.*info', r'personal.*information',
            r'credit.*card', r'social.*security', r'phone.*number'
        ]
        
        for pattern in exposure_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _has_injection_risk(self, content: str) -> bool:
        """Check for injection vulnerability risks."""
        injection_patterns = [
            r'sql.*query', r'exec\s*\(', r'eval\s*\(',
            r'system\s*\(', r'shell_exec'
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _get_matched_patterns(self, url: str, content: str) -> List[str]:
        """Get list of patterns that matched the endpoint."""
        matched_patterns = []
        
        for category, patterns in self.compiled_patterns.items():
            for pattern_info in patterns:
                if pattern_info['regex'].search(url) or pattern_info['regex'].search(content):
                    matched_patterns.append(category)
        
        return matched_patterns
    
    def _discover_pattern_endpoints(self, content: str, file_path: str) -> List[ServiceEndpoint]:
        """Discover additional endpoints using pattern matching."""
        endpoints = []
        
        # This would contain additional discovery logic
        # for endpoints that might not be complete URLs
        
        return endpoints 