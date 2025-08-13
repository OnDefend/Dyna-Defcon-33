#!/usr/bin/env python3
"""
APK2URL Extraction Plugin - Pattern Analyzer

Advanced pattern matching and validation system for endpoint discovery.
Implements sophisticated regex patterns with context analysis and 
structural validation for URLs, IPs, domains, and API endpoints.
"""

import logging
import re
import ipaddress
import yaml
from typing import Dict, List, Set, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse

from .data_structures import (
    PatternMatch, EndpointType, VALID_TLDS, FRAMEWORK_NOISE_INDICATORS
)

logger = logging.getLogger(__name__)

class PatternAnalyzer:
    """
    Advanced pattern analyzer for endpoint discovery.
    
    Implements configurable pattern matching with validation,
    context analysis, and framework noise detection.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize pattern analyzer with configuration."""
        self.config = config
        
        # Compile patterns from configuration
        self.url_patterns = self._compile_url_patterns()
        self.ip_patterns = self._compile_ip_patterns()
        self.domain_patterns = self._compile_domain_patterns()
        self.api_patterns = self._compile_api_patterns()
        
        # Valid TLDs for domain validation
        self.valid_tlds = VALID_TLDS
        
        # Framework noise indicators
        self.framework_indicators = FRAMEWORK_NOISE_INDICATORS
        
        logger.info("Initialized PatternAnalyzer with compiled patterns")
    
    def analyze_text(self, text: str, file_path: str = "") -> List[PatternMatch]:
        """
        Analyze text for endpoint patterns with context.
        
        Args:
            text: Text content to analyze
            file_path: Source file path for context
            
        Returns:
            List of pattern matches with context and confidence
        """
        matches = []
        
        try:
            # Find URL patterns
            matches.extend(self._find_url_patterns(text, file_path))
            
            # Find IP address patterns
            matches.extend(self._find_ip_patterns(text, file_path))
            
            # Find domain patterns
            matches.extend(self._find_domain_patterns(text, file_path))
            
            # Find API endpoint patterns
            matches.extend(self._find_api_patterns(text, file_path))
            
            # Validate and enrich matches
            validated_matches = []
            for match in matches:
                if self._validate_pattern_match(match):
                    enriched_match = self._enrich_pattern_match(match, text)
                    validated_matches.append(enriched_match)
            
            logger.debug(f"Found {len(validated_matches)} valid patterns in {file_path}")
            return validated_matches
            
        except Exception as e:
            logger.error(f"Error analyzing text patterns: {e}")
            return []
    
    def _compile_url_patterns(self) -> Dict[str, re.Pattern]:
        """Compile URL patterns from configuration."""
        patterns = {}
        
        url_config = self.config.get('url_patterns', {})
        for pattern_name, pattern_config in url_config.items():
            try:
                pattern_str = pattern_config['pattern']
                flags = getattr(re, pattern_config.get('flags', 'IGNORECASE'), re.IGNORECASE)
                patterns[pattern_name] = re.compile(pattern_str, flags)
            except Exception as e:
                logger.warning(f"Error compiling URL pattern {pattern_name}: {e}")
        
        # Fallback patterns if config is missing
        if not patterns:
            patterns = {
                'standard_http': re.compile(
                    r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s\"\'<>]*)?',
                    re.IGNORECASE
                ),
                'custom_scheme': re.compile(
                    r'[a-z][a-z0-9+.-]*://[^\s\"\'<>]+',
                    re.IGNORECASE
                )
            }
        
        return patterns
    
    def _compile_ip_patterns(self) -> Dict[str, re.Pattern]:
        """Compile IP address patterns from configuration."""
        patterns = {}
        
        ip_config = self.config.get('ip_patterns', {})
        for pattern_name, pattern_config in ip_config.items():
            try:
                pattern_str = pattern_config['pattern']
                patterns[pattern_name] = re.compile(pattern_str)
            except Exception as e:
                logger.warning(f"Error compiling IP pattern {pattern_name}: {e}")
        
        # Fallback patterns
        if not patterns:
            patterns = {
                'ipv4_standard': re.compile(
                    r'(?:^|[^\d])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[^\d]|$)'
                )
            }
        
        return patterns
    
    def _compile_domain_patterns(self) -> Dict[str, re.Pattern]:
        """Compile domain patterns from configuration."""
        patterns = {}
        
        domain_config = self.config.get('domain_patterns', {})
        for pattern_name, pattern_config in domain_config.items():
            try:
                pattern_str = pattern_config['pattern']
                flags = getattr(re, pattern_config.get('flags', 'IGNORECASE'), re.IGNORECASE)
                patterns[pattern_name] = re.compile(pattern_str, flags)
            except Exception as e:
                logger.warning(f"Error compiling domain pattern {pattern_name}: {e}")
        
        # Fallback patterns
        if not patterns:
            patterns = {
                'standard_domain': re.compile(
                    r'(?:^|[^\w\-\.])([a-zA-Z0-9\-]+\.(?:[a-zA-Z]{2,}|[a-zA-Z]{2}\.[a-zA-Z]{2}))(?:[^\w\-\.]|$)',
                    re.IGNORECASE
                )
            }
        
        return patterns
    
    def _compile_api_patterns(self) -> Dict[str, re.Pattern]:
        """Compile API endpoint patterns from configuration."""
        patterns = {}
        
        api_config = self.config.get('api_patterns', {})
        for pattern_name, pattern_config in api_config.items():
            try:
                pattern_str = pattern_config['pattern']
                flags = getattr(re, pattern_config.get('flags', 'IGNORECASE'), re.IGNORECASE)
                patterns[pattern_name] = re.compile(pattern_str, flags)
            except Exception as e:
                logger.warning(f"Error compiling API pattern {pattern_name}: {e}")
        
        # Fallback patterns
        if not patterns:
            patterns = {
                'versioned_api': re.compile(
                    r'/api/v?\d+/[a-zA-Z0-9\-_/]+',
                    re.IGNORECASE
                ),
                'rest_endpoints': re.compile(
                    r'/rest/[a-zA-Z0-9\-_/]+',
                    re.IGNORECASE
                )
            }
        
        return patterns
    
    def _find_url_patterns(self, text: str, file_path: str) -> List[PatternMatch]:
        """Find URL patterns in text."""
        matches = []
        
        for pattern_name, pattern in self.url_patterns.items():
            for match in pattern.finditer(text):
                matched_text = match.group(0).strip()
                
                # Additional URL validation
                if self._is_valid_url_structure(matched_text):
                    pattern_match = PatternMatch(
                        pattern_name=pattern_name,
                        matched_text=matched_text,
                        file_path=file_path,
                        confidence=self._get_pattern_confidence(pattern_name)
                    )
                    matches.append(pattern_match)
        
        return matches
    
    def _find_ip_patterns(self, text: str, file_path: str) -> List[PatternMatch]:
        """Find IP address patterns in text."""
        matches = []
        
        for pattern_name, pattern in self.ip_patterns.items():
            for match in pattern.finditer(text):
                matched_text = match.group(1) if match.groups() else match.group(0)
                matched_text = matched_text.strip()
                
                # Validate IP address
                if self._is_valid_ip_address(matched_text):
                    pattern_match = PatternMatch(
                        pattern_name=pattern_name,
                        matched_text=matched_text,
                        file_path=file_path,
                        confidence=self._get_pattern_confidence(pattern_name)
                    )
                    matches.append(pattern_match)
        
        return matches
    
    def _find_domain_patterns(self, text: str, file_path: str) -> List[PatternMatch]:
        """Find domain patterns in text."""
        matches = []
        
        for pattern_name, pattern in self.domain_patterns.items():
            for match in pattern.finditer(text):
                matched_text = match.group(1) if match.groups() else match.group(0)
                matched_text = matched_text.strip()
                
                # Validate domain
                if self._is_valid_domain_name(matched_text):
                    pattern_match = PatternMatch(
                        pattern_name=pattern_name,
                        matched_text=matched_text,
                        file_path=file_path,
                        confidence=self._get_pattern_confidence(pattern_name)
                    )
                    matches.append(pattern_match)
        
        return matches
    
    def _find_api_patterns(self, text: str, file_path: str) -> List[PatternMatch]:
        """Find API endpoint patterns in text."""
        matches = []
        
        for pattern_name, pattern in self.api_patterns.items():
            for match in pattern.finditer(text):
                matched_text = match.group(0).strip()
                
                # Validate API endpoint structure
                if self._is_valid_api_endpoint(matched_text):
                    pattern_match = PatternMatch(
                        pattern_name=pattern_name,
                        matched_text=matched_text,
                        file_path=file_path,
                        confidence=self._get_pattern_confidence(pattern_name)
                    )
                    matches.append(pattern_match)
        
        return matches
    
    def _validate_pattern_match(self, match: PatternMatch) -> bool:
        """Validate a pattern match for quality and relevance."""
        text = match.matched_text
        
        # Basic length validation
        if len(text) < 4 or len(text) > 2048:
            return False
        
        # Check for obvious noise patterns
        if self._is_obvious_noise(text):
            return False
        
        # Check for framework indicators
        if any(indicator in text.lower() for indicator in self.framework_indicators):
            match.is_noise = True
            return False
        
        # Pattern-specific validation
        if 'url' in match.pattern_name.lower():
            return self._validate_url_match(text)
        elif 'ip' in match.pattern_name.lower():
            return self._validate_ip_match(text)
        elif 'domain' in match.pattern_name.lower():
            return self._validate_domain_match(text)
        elif 'api' in match.pattern_name.lower():
            return self._validate_api_match(text)
        
        return True
    
    def _enrich_pattern_match(self, match: PatternMatch, full_text: str) -> PatternMatch:
        """Enrich pattern match with context and additional metadata."""
        try:
            # Find position in text
            start_pos = full_text.find(match.matched_text)
            if start_pos != -1:
                # Extract context before and after
                context_length = 50
                context_start = max(0, start_pos - context_length)
                context_end = min(len(full_text), start_pos + len(match.matched_text) + context_length)
                
                match.context_before = full_text[context_start:start_pos]
                match.context_after = full_text[start_pos + len(match.matched_text):context_end]
                
                # Calculate line number
                lines_before = full_text[:start_pos].count('\n')
                match.line_number = lines_before + 1
            
            return match
            
        except Exception as e:
            logger.warning(f"Error enriching pattern match: {e}")
            return match
    
    def _is_valid_url_structure(self, url: str) -> bool:
        """Validate URL structure."""
        try:
            parsed = urlparse(url)
            
            # Must have scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                return False
            
            # Check for valid scheme
            valid_schemes = ['http', 'https', 'ftp', 'ws', 'wss']
            if parsed.scheme.lower() not in valid_schemes and '://' not in url:
                return False
            
            # Check domain part
            if '.' not in parsed.netloc:
                return False
            
            return True
            
        except Exception:
            return False
    
    def _is_valid_ip_address(self, ip_str: str) -> bool:
        """Validate IP address format."""
        try:
            # Try to parse as IP address
            ip = ipaddress.ip_address(ip_str)
            
            # Exclude certain ranges
            if isinstance(ip, ipaddress.IPv4Address):
                # Exclude version-like patterns (e.g., 1.2.3.4 could be version)
                parts = ip_str.split('.')
                if all(int(part) < 10 for part in parts):
                    return False
                
                # Exclude common non-IP patterns
                if ip_str in ['0.0.0.0', '255.255.255.255']:
                    return False
            
            return True
            
        except ValueError:
            return False
    
    def _is_valid_domain_name(self, domain: str) -> bool:
        """Validate domain name structure."""
        try:
            # Basic format check
            if not domain or len(domain) > 253:
                return False
            
            # Must have at least one dot
            if '.' not in domain:
                return False
            
            # Split into parts
            parts = domain.lower().split('.')
            if len(parts) < 2:
                return False
            
            # Validate TLD
            tld = parts[-1]
            if tld not in self.valid_tlds:
                return False
            
            # Validate each part
            for part in parts:
                if not part or len(part) > 63:
                    return False
                
                # Must contain valid characters
                if not re.match(r'^[a-zA-Z0-9\-]+$', part):
                    return False
                
                # Cannot start or end with hyphen
                if part.startswith('-') or part.endswith('-'):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def _is_valid_api_endpoint(self, endpoint: str) -> bool:
        """Validate API endpoint structure."""
        # Must start with /
        if not endpoint.startswith('/'):
            return False
        
        # Must contain valid path characters
        if not re.match(r'^/[a-zA-Z0-9\-_/\.]*$', endpoint):
            return False
        
        # Should have reasonable length
        if len(endpoint) < 5 or len(endpoint) > 200:
            return False
        
        # Check for obvious UI patterns that aren't APIs
        ui_patterns = ['layout', 'drawable', 'color', 'style', 'anim']
        if any(pattern in endpoint.lower() for pattern in ui_patterns):
            return False
        
        return True
    
    def _is_obvious_noise(self, text: str) -> bool:
        """Check for obvious noise patterns."""
        text_lower = text.lower()
        
        # Very short or very long
        if len(text) < 4 or len(text) > 1000:
            return True
        
        # All same character
        if len(set(text)) == 1:
            return True
        
        # Contains too many special characters
        special_char_ratio = sum(1 for c in text if not c.isalnum()) / len(text)
        if special_char_ratio > 0.7:
            return True
        
        # Common noise patterns
        noise_patterns = [
            'lorem ipsum',
            'placeholder',
            'example.com',
            'test.test',
            'foo.bar',
            'sample.data'
        ]
        
        return any(pattern in text_lower for pattern in noise_patterns)
    
    def _validate_url_match(self, url: str) -> bool:
        """Validate URL match."""
        return self._is_valid_url_structure(url)
    
    def _validate_ip_match(self, ip: str) -> bool:
        """Validate IP match."""
        return self._is_valid_ip_address(ip)
    
    def _validate_domain_match(self, domain: str) -> bool:
        """Validate domain match."""
        return self._is_valid_domain_name(domain)
    
    def _validate_api_match(self, endpoint: str) -> bool:
        """Validate API endpoint match."""
        return self._is_valid_api_endpoint(endpoint)
    
    def _get_pattern_confidence(self, pattern_name: str) -> float:
        """Get confidence score for pattern from configuration."""
        # Check URL patterns
        url_patterns = self.config.get('url_patterns', {})
        if pattern_name in url_patterns:
            return url_patterns[pattern_name].get('confidence', 0.7)
        
        # Check IP patterns
        ip_patterns = self.config.get('ip_patterns', {})
        if pattern_name in ip_patterns:
            return ip_patterns[pattern_name].get('confidence', 0.7)
        
        # Check domain patterns
        domain_patterns = self.config.get('domain_patterns', {})
        if pattern_name in domain_patterns:
            return domain_patterns[pattern_name].get('confidence', 0.7)
        
        # Check API patterns
        api_patterns = self.config.get('api_patterns', {})
        if pattern_name in api_patterns:
            return api_patterns[pattern_name].get('confidence', 0.7)
        
        # Default confidence
        return 0.6
    
    def analyze_pattern_quality(self, matches: List[PatternMatch]) -> Dict[str, Any]:
        """Analyze quality of pattern matches."""
        if not matches:
            return {
                'total_matches': 0,
                'avg_confidence': 0.0,
                'noise_ratio': 0.0,
                'pattern_distribution': {}
            }
        
        # Calculate statistics
        total_matches = len(matches)
        avg_confidence = sum(match.confidence for match in matches) / total_matches
        noise_count = sum(1 for match in matches if match.is_noise)
        noise_ratio = noise_count / total_matches
        
        # Pattern distribution
        pattern_distribution = {}
        for match in matches:
            pattern_name = match.pattern_name
            if pattern_name not in pattern_distribution:
                pattern_distribution[pattern_name] = 0
            pattern_distribution[pattern_name] += 1
        
        return {
            'total_matches': total_matches,
            'avg_confidence': avg_confidence,
            'noise_ratio': noise_ratio,
            'pattern_distribution': pattern_distribution,
            'high_confidence_matches': sum(1 for match in matches if match.confidence > 0.8),
            'low_confidence_matches': sum(1 for match in matches if match.confidence < 0.5)
        } 