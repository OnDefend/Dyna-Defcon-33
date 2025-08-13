"""
Service Detection Module for External Service Analysis

This module handles the detection and analysis of external cloud services
including AWS S3, Firebase, Google Cloud, Azure, and other cloud platforms.
"""

import re
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass

from .data_structures import (
    ServiceType, ServiceEndpoint, ServicePattern, SeverityLevel,
    ExternalServiceVulnerability, AnalysisContext
)

logger = logging.getLogger(__name__)

@dataclass
class ServiceMatch:
    """Represents a service pattern match."""
    service_type: ServiceType
    pattern: str
    matched_text: str
    location: str
    confidence: float
    context: str = ""

class ServicePatternLoader:
    """Loads and manages service detection patterns."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize pattern loader."""
        if config_path is None:
            config_path = Path(__file__).parent / "service_patterns_config.yaml"
        
        self.config_path = Path(config_path)
        self.patterns: Dict[ServiceType, ServicePattern] = {}
        self.compiled_patterns: Dict[ServiceType, List[re.Pattern]] = {}
        self._load_patterns()
    
    def _load_patterns(self):
        """Load service patterns from configuration file."""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Map config service names to ServiceType enum
            service_mapping = {
                'aws_s3': ServiceType.AWS_S3,
                'firebase': ServiceType.FIREBASE,
                'google_cloud': ServiceType.GOOGLE_CLOUD,
                'azure': ServiceType.AZURE,
                'dropbox': ServiceType.DROPBOX,
                'box': ServiceType.BOX,
                'onedrive': ServiceType.ONEDRIVE,
                'payment_gateways': ServiceType.PAYMENT_GATEWAY,
                'social_media': ServiceType.SOCIAL_MEDIA,
                'analytics': ServiceType.ANALYTICS,
                'advertising': ServiceType.ADVERTISING
            }
            
            for service_name, service_type in service_mapping.items():
                if service_name in config:
                    service_config = config[service_name]
                    
                    # Create ServicePattern
                    pattern = ServicePattern(
                        service_type=service_type,
                        patterns=service_config.get('patterns', []),
                        description=service_config.get('description', ''),
                        risk_factors=service_config.get('risk_factors', []),
                        confidence_base=service_config.get('confidence_base', 0.8),
                        severity=self._parse_severity(service_config.get('severity', 'medium'))
                    )
                    
                    self.patterns[service_type] = pattern
                    
                    # Compile regex patterns
                    compiled = []
                    for regex_pattern in pattern.patterns:
                        try:
                            compiled.append(re.compile(regex_pattern, re.IGNORECASE))
                        except re.error as e:
                            logger.warning(f"Invalid regex pattern '{regex_pattern}': {e}")
                    
                    self.compiled_patterns[service_type] = compiled
            
            logger.info(f"Loaded {len(self.patterns)} service patterns")
            
        except Exception as e:
            logger.error(f"Failed to load service patterns: {e}")
            # Initialize with empty patterns if loading fails
            self.patterns = {}
            self.compiled_patterns = {}
    
    def _parse_severity(self, severity_str: str) -> SeverityLevel:
        """Parse severity string to SeverityLevel enum."""
        severity_map = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'info': SeverityLevel.INFO
        }
        return severity_map.get(severity_str.lower(), SeverityLevel.MEDIUM)
    
    def get_patterns(self) -> Dict[ServiceType, ServicePattern]:
        """Get all loaded service patterns."""
        return self.patterns.copy()
    
    def get_compiled_patterns(self) -> Dict[ServiceType, List[re.Pattern]]:
        """Get all compiled regex patterns."""
        return self.compiled_patterns.copy()

class ServiceDetector:
    """Detects external services in Android application code and resources."""
    
    def __init__(self, pattern_loader: Optional[ServicePatternLoader] = None):
        """Initialize service detector."""
        self.pattern_loader = pattern_loader or ServicePatternLoader()
        self.patterns = self.pattern_loader.get_patterns()
        self.compiled_patterns = self.pattern_loader.get_compiled_patterns()
        
        # Cache for detected services to avoid duplicates
        self._detected_cache: Set[Tuple[str, str, str]] = set()
    
    def detect_services_in_content(self, content: str, file_path: str, 
                                  context: Optional[AnalysisContext] = None) -> List[ServiceMatch]:
        """
        Detect external services in file content.
        
        Args:
            content: File content to analyze
            file_path: Path to the file being analyzed
            context: Analysis context for confidence calculation
            
        Returns:
            List of detected service matches
        """
        matches = []
        
        if not content or not content.strip():
            return matches
        
        for service_type, compiled_patterns in self.compiled_patterns.items():
            service_pattern = self.patterns[service_type]
            
            for pattern in compiled_patterns:
                for match in pattern.finditer(content):
                    matched_text = match.group(0)
                    start_pos = match.start()
                    
                    # Create cache key to avoid duplicates
                    cache_key = (service_type.value, matched_text, file_path)
                    if cache_key in self._detected_cache:
                        continue
                    
                    self._detected_cache.add(cache_key)
                    
                    # Extract context around the match
                    context_start = max(0, start_pos - 50)
                    context_end = min(len(content), start_pos + len(matched_text) + 50)
                    match_context = content[context_start:context_end]
                    
                    # Calculate confidence based on context
                    confidence = self._calculate_match_confidence(
                        service_pattern, matched_text, match_context, context
                    )
                    
                    service_match = ServiceMatch(
                        service_type=service_type,
                        pattern=pattern.pattern,
                        matched_text=matched_text,
                        location=file_path,
                        confidence=confidence,
                        context=match_context
                    )
                    
                    matches.append(service_match)
        
        return matches
    
    def _calculate_match_confidence(self, service_pattern: ServicePattern, 
                                  matched_text: str, context: str,
                                  analysis_context: Optional[AnalysisContext] = None) -> float:
        """
        Calculate confidence score for a service match.
        
        Args:
            service_pattern: The service pattern that matched
            matched_text: The text that matched the pattern
            context: Surrounding context of the match
            analysis_context: Analysis context information
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        base_confidence = service_pattern.confidence_base
        
        # Adjust based on match characteristics
        confidence_adjustments = 0.0
        
        # Length and complexity of match
        if len(matched_text) > 20:
            confidence_adjustments += 0.05
        if len(matched_text) > 50:
            confidence_adjustments += 0.05
        
        # Context indicators
        if any(keyword in context.lower() for keyword in ['api', 'endpoint', 'url', 'service']):
            confidence_adjustments += 0.05
        
        if any(keyword in context.lower() for keyword in ['key', 'token', 'secret', 'auth']):
            confidence_adjustments += 0.1
        
        # File type adjustments
        if analysis_context and analysis_context.file_type:
            if analysis_context.file_type in ['java', 'kotlin']:
                confidence_adjustments += 0.05
            elif analysis_context.file_type in ['xml', 'json']:
                confidence_adjustments += 0.02
        
        # Multiple pattern matches for same service increase confidence
        if analysis_context and analysis_context.cross_references > 1:
            confidence_adjustments += min(0.1, analysis_context.cross_references * 0.02)
        
        # Calculate final confidence
        final_confidence = base_confidence + confidence_adjustments
        
        # Ensure confidence is within bounds
        return max(0.1, min(1.0, final_confidence))
    
    def create_service_endpoints(self, matches: List[ServiceMatch]) -> List[ServiceEndpoint]:
        """
        Convert service matches to service endpoints.
        
        Args:
            matches: List of service matches
            
        Returns:
            List of service endpoints
        """
        endpoints = []
        
        for match in matches:
            # Extract URL if possible
            url = self._extract_url_from_match(match.matched_text, match.context)
            
            endpoint = ServiceEndpoint(
                url=url or match.matched_text,
                service_type=match.service_type,
                location=match.location,
                confidence=match.confidence
            )
            
            # Try to extract additional information
            endpoint.method = self._extract_http_method(match.context)
            endpoint.authentication = self._detect_authentication_type(match.context)
            endpoint.encryption = self._detect_encryption_type(match.context)
            
            endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_url_from_match(self, matched_text: str, context: str) -> Optional[str]:
        """Extract full URL from matched text and context."""
        # Look for full URLs in the context
        url_patterns = [
            r'https?://[^\s\'"<>]+',
            r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s\'"<>]*)?'
        ]
        
        for pattern in url_patterns:
            matches = re.findall(pattern, context)
            for url in matches:
                if matched_text in url:
                    return url
        
        return None
    
    def _extract_http_method(self, context: str) -> Optional[str]:
        """Extract HTTP method from context."""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        context_upper = context.upper()
        
        for method in methods:
            if method in context_upper:
                return method
        
        return None
    
    def _detect_authentication_type(self, context: str) -> Optional[str]:
        """Detect authentication type from context."""
        auth_indicators = {
            'Bearer': 'bearer_token',
            'Basic': 'basic_auth',
            'OAuth': 'oauth',
            'API-Key': 'api_key',
            'X-API-Key': 'api_key',
            'Authorization': 'token_based'
        }
        
        for indicator, auth_type in auth_indicators.items():
            if indicator in context:
                return auth_type
        
        return None
    
    def _detect_encryption_type(self, context: str) -> Optional[str]:
        """Detect encryption type from context."""
        if 'https://' in context.lower():
            return 'TLS/SSL'
        elif 'http://' in context.lower():
            return 'None'
        
        return None
    
    def create_vulnerabilities_from_matches(self, matches: List[ServiceMatch]) -> List[ExternalServiceVulnerability]:
        """
        Create vulnerability objects from service matches.
        
        Args:
            matches: List of service matches
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        for match in matches:
            service_pattern = self.patterns.get(match.service_type)
            if not service_pattern:
                continue
            
            # Create vulnerability for detected service
            vulnerability = ExternalServiceVulnerability(
                vulnerability_id=f"EXT_SERVICE_{match.service_type.value.upper()}_{hash(match.matched_text) % 10000:04d}",
                title=f"{service_pattern.description} Detection",
                description=f"Detected usage of {service_pattern.description} in the application",
                severity=service_pattern.severity,
                service_type=match.service_type,
                location=match.location,
                evidence={
                    'matched_text': match.matched_text,
                    'pattern': match.pattern,
                    'context': match.context[:200],  # Limit context length
                    'risk_factors': service_pattern.risk_factors
                },
                recommendations=self._generate_recommendations(match.service_type, service_pattern),
                confidence=match.confidence
            )
            
            # Add CWE and MASVS mappings
            vulnerability.cwe = self._get_service_cwe(match.service_type)
            vulnerability.masvs_control = self._get_service_masvs_control(match.service_type)
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _generate_recommendations(self, service_type: ServiceType, 
                                service_pattern: ServicePattern) -> List[str]:
        """Generate security recommendations for detected service."""
        recommendations = [
            f"Review the security configuration of {service_pattern.description}",
            "Ensure proper authentication and authorization mechanisms are in place",
            "Verify that sensitive data is properly encrypted in transit and at rest"
        ]
        
        # Service-specific recommendations
        if service_type == ServiceType.AWS_S3:
            recommendations.extend([
                "Verify S3 bucket permissions and access policies",
                "Ensure S3 buckets are not publicly accessible",
                "Use IAM roles instead of hardcoded credentials"
            ])
        elif service_type == ServiceType.FIREBASE:
            recommendations.extend([
                "Review Firebase security rules",
                "Ensure proper authentication is enabled",
                "Verify database access permissions"
            ])
        elif service_type == ServiceType.PAYMENT_GATEWAY:
            recommendations.extend([
                "Ensure PCI DSS compliance",
                "Verify payment data encryption",
                "Use secure payment tokens instead of card data"
            ])
        
        return recommendations
    
    def _get_service_cwe(self, service_type: ServiceType) -> Optional[str]:
        """Get CWE mapping for service type."""
        cwe_mapping = {
            ServiceType.AWS_S3: "CWE-200",
            ServiceType.FIREBASE: "CWE-200",
            ServiceType.GOOGLE_CLOUD: "CWE-200",
            ServiceType.AZURE: "CWE-200",
            ServiceType.PAYMENT_GATEWAY: "CWE-311",
            ServiceType.SOCIAL_MEDIA: "CWE-359",
            ServiceType.ANALYTICS: "CWE-359"
        }
        return cwe_mapping.get(service_type)
    
    def _get_service_masvs_control(self, service_type: ServiceType) -> Optional[str]:
        """Get MASVS control mapping for service type."""
        masvs_mapping = {
            ServiceType.AWS_S3: "MSTG-NETWORK-01",
            ServiceType.FIREBASE: "MSTG-NETWORK-01",
            ServiceType.GOOGLE_CLOUD: "MSTG-NETWORK-01",
            ServiceType.AZURE: "MSTG-NETWORK-01",
            ServiceType.PAYMENT_GATEWAY: "MSTG-CRYPTO-01",
            ServiceType.SOCIAL_MEDIA: "MSTG-PLATFORM-01",
            ServiceType.ANALYTICS: "MSTG-PLATFORM-01"
        }
        return masvs_mapping.get(service_type)
    
    def get_detection_statistics(self) -> Dict[str, int]:
        """Get statistics about service detection."""
        service_counts = {}
        
        for cache_entry in self._detected_cache:
            service_type = cache_entry[0]
            service_counts[service_type] = service_counts.get(service_type, 0) + 1
        
        return {
            'total_detections': len(self._detected_cache),
            'service_breakdown': service_counts,
            'unique_services': len(service_counts)
        } 