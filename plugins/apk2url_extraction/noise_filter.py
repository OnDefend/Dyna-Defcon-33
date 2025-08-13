#!/usr/bin/env python3
"""
APK2URL Extraction Plugin - Noise Filter

Advanced noise filtering system for false positive reduction in endpoint discovery.
Implements framework-specific noise detection, path exclusions, and context-aware
filtering to eliminate false positives from Flutter, React Native, and Android framework patterns.
"""

import logging
import re
from typing import Dict, List, Set, Optional, Any, Tuple
from pathlib import Path

from .data_structures import (
    NoiseFilterResult, PatternMatch, FRAMEWORK_NOISE_INDICATORS
)

logger = logging.getLogger(__name__)

class NoiseFilter:
    """
    Advanced noise filtering system for endpoint discovery.
    
    Implements multi-layered noise detection including framework patterns,
    path exclusions, and context-aware filtering to reduce false positives.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize noise filter with configuration."""
        self.config = config
        
        # Compile framework noise patterns
        self.framework_noise_patterns = self._compile_framework_patterns()
        
        # Compile file path exclusion patterns  
        self.excluded_path_patterns = self._compile_path_exclusions()
        
        # Compile invalid IP patterns
        self.invalid_ip_patterns = self._compile_invalid_ip_patterns()
        
        # Framework noise indicators
        self.framework_indicators = FRAMEWORK_NOISE_INDICATORS
        
        # Noise statistics
        self.noise_stats = {
            'total_filtered': 0,
            'framework_noise': 0,
            'path_exclusions': 0,
            'invalid_formats': 0,
            'context_noise': 0
        }
        
        logger.info("Initialized NoiseFilter with compiled patterns")
    
    def is_framework_noise(self, text: str, file_path: str = "") -> bool:
        """
        Check if text is framework noise that should be filtered.
        
        Args:
            text: Text to check for noise
            file_path: Source file path for context
            
        Returns:
            True if text is identified as framework noise
        """
        try:
            # Check file path exclusions first
            if self._is_excluded_path(file_path):
                self.noise_stats['path_exclusions'] += 1
                return True
            
            # Check framework noise patterns
            if self._matches_framework_patterns(text):
                self.noise_stats['framework_noise'] += 1
                return True
            
            # Check for invalid formats
            if self._is_invalid_format(text):
                self.noise_stats['invalid_formats'] += 1
                return True
            
            # Check context-based noise
            if self._is_context_noise(text, file_path):
                self.noise_stats['context_noise'] += 1
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error in framework noise detection: {e}")
            return False
    
    def filter_findings(self, findings: Dict[str, Set[str]], 
                       file_paths: Dict[str, str] = None) -> Tuple[Dict[str, Set[str]], NoiseFilterResult]:
        """
        Filter findings to remove noise and false positives.
        
        Args:
            findings: Dictionary of findings by category
            file_paths: Optional mapping of findings to file paths
            
        Returns:
            Tuple of (filtered_findings, noise_filter_result)
        """
        try:
            original_count = sum(len(category) for category in findings.values())
            filtered_findings = {}
            
            # Filter each category
            for category, items in findings.items():
                filtered_items = set()
                
                for item in items:
                    # Get file path if available
                    file_path = file_paths.get(item, "") if file_paths else ""
                    
                    # Check if item should be filtered
                    if not self.is_framework_noise(item, file_path):
                        filtered_items.add(item)
                
                filtered_findings[category] = filtered_items
            
            # Calculate filter results
            filtered_count = sum(len(category) for category in filtered_findings.values())
            noise_count = original_count - filtered_count
            filter_efficiency = (noise_count / original_count) if original_count > 0 else 0.0
            
            # Create filter result
            filter_result = NoiseFilterResult(
                original_count=original_count,
                filtered_count=filtered_count,
                noise_count=noise_count,
                filter_efficiency=filter_efficiency,
                noise_patterns_matched=self._get_matched_patterns(),
                excluded_files=self._get_excluded_files()
            )
            
            logger.info(f"Filtered {noise_count}/{original_count} noise items ({filter_efficiency:.1%} efficiency)")
            return filtered_findings, filter_result
            
        except Exception as e:
            logger.error(f"Error filtering findings: {e}")
            return findings, NoiseFilterResult(0, 0, 0, 0.0)
    
    def _compile_framework_patterns(self) -> List[re.Pattern]:
        """Compile framework noise patterns from configuration."""
        patterns = []
        
        framework_config = self.config.get('framework_noise_patterns', {})
        for framework_name, framework_data in framework_config.items():
            pattern_list = framework_data.get('patterns', [])
            
            for pattern_str in pattern_list:
                try:
                    pattern = re.compile(pattern_str, re.IGNORECASE)
                    patterns.append(pattern)
                except Exception as e:
                    logger.warning(f"Error compiling framework pattern {pattern_str}: {e}")
        
        # Fallback patterns if config is missing
        if not patterns:
            fallback_patterns = [
                re.compile(r"^(ThemeData|PointerSignalKind|ImageRepeat|FloatingCursor)", re.IGNORECASE),
                re.compile(r"(pointer|hover|vertex|stack|frame)\.", re.IGNORECASE),
                re.compile(r"(change|event|listener|handler)\.", re.IGNORECASE),
                re.compile(r"\.dart$", re.IGNORECASE),
                re.compile(r"react[\-/]?native", re.IGNORECASE),
                re.compile(r"node_modules/", re.IGNORECASE),
                re.compile(r"^http://schemas\.android\.com/apk/res", re.IGNORECASE),
                re.compile(r"xmlns:", re.IGNORECASE),
                re.compile(r"(objectAnimator|pathData|iconFade)", re.IGNORECASE)
            ]
            patterns.extend(fallback_patterns)
        
        return patterns
    
    def _compile_path_exclusions(self) -> List[re.Pattern]:
        """Compile file path exclusion patterns from configuration."""
        patterns = []
        
        exclusion_config = self.config.get('excluded_file_patterns', {})
        for exclusion_name, exclusion_data in exclusion_config.items():
            pattern_list = exclusion_data.get('patterns', [])
            
            for pattern_str in pattern_list:
                try:
                    pattern = re.compile(pattern_str, re.IGNORECASE)
                    patterns.append(pattern)
                except Exception as e:
                    logger.warning(f"Error compiling path exclusion pattern {pattern_str}: {e}")
        
        # Fallback patterns
        if not patterns:
            fallback_patterns = [
                re.compile(r"/assets/", re.IGNORECASE),
                re.compile(r"/res/raw/", re.IGNORECASE),
                re.compile(r"/lib/[^/]+\.so$", re.IGNORECASE),
                re.compile(r"\.(?:png|jpg|jpeg|gif|webp|svg)$", re.IGNORECASE),
                re.compile(r"flutter/", re.IGNORECASE),
                re.compile(r"react-native/", re.IGNORECASE),
                re.compile(r"node_modules/", re.IGNORECASE),
                re.compile(r"/META-INF/", re.IGNORECASE),
                re.compile(r"/assets/flutter_assets/", re.IGNORECASE)
            ]
            patterns.extend(fallback_patterns)
        
        return patterns
    
    def _compile_invalid_ip_patterns(self) -> List[re.Pattern]:
        """Compile invalid IP patterns from configuration."""
        patterns = []
        
        invalid_ip_config = self.config.get('invalid_ip_patterns', {})
        for pattern_name, pattern_data in invalid_ip_config.items():
            pattern_list = pattern_data.get('patterns', [])
            
            for pattern_str in pattern_list:
                try:
                    pattern = re.compile(pattern_str)
                    patterns.append(pattern)
                except Exception as e:
                    logger.warning(f"Error compiling invalid IP pattern {pattern_str}: {e}")
        
        # Fallback patterns
        if not patterns:
            fallback_patterns = [
                re.compile(r"^::[0-9a-fA-F]{0,3}$"),  # Invalid IPv6 fragments
                re.compile(r"^::$"),  # Empty IPv6
                re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")  # Version-like patterns
            ]
            patterns.extend(fallback_patterns)
        
        return patterns
    
    def _is_excluded_path(self, file_path: str) -> bool:
        """Check if file path should be excluded."""
        if not file_path:
            return False
        
        return any(pattern.search(file_path) for pattern in self.excluded_path_patterns)
    
    def _matches_framework_patterns(self, text: str) -> bool:
        """Check if text matches framework noise patterns."""
        return any(pattern.search(text) for pattern in self.framework_noise_patterns)
    
    def _is_invalid_format(self, text: str) -> bool:
        """Check if text has invalid format that indicates noise."""
        # Check for invalid IP patterns
        if self._looks_like_ip(text):
            return any(pattern.match(text) for pattern in self.invalid_ip_patterns)
        
        # Check for other invalid formats
        return self._is_other_invalid_format(text)
    
    def _is_context_noise(self, text: str, file_path: str) -> bool:
        """Check if text is noise based on context."""
        text_lower = text.lower()
        
        # Check for framework indicators in text
        if any(indicator in text_lower for indicator in self.framework_indicators):
            return True
        
        # Check for development/debug patterns that might be noise
        if self._is_development_noise(text, file_path):
            return True
        
        # Check for UI/animation patterns
        if self._is_ui_animation_noise(text):
            return True
        
        # Check for package/class reference patterns
        if self._is_package_reference_noise(text):
            return True
        
        return False
    
    def _looks_like_ip(self, text: str) -> bool:
        """Check if text looks like an IP address."""
        # Simple pattern to identify IP-like strings
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        return bool(ip_pattern.match(text))
    
    def _is_other_invalid_format(self, text: str) -> bool:
        """Check for other invalid format patterns."""
        # Very short URLs (likely noise)
        if text.startswith(('http://', 'https://')) and len(text) < 15:
            return True
        
        # URLs with obvious placeholder patterns
        placeholder_patterns = [
            'example.com', 'test.test', 'foo.bar', 'sample.data',
            'localhost', '127.0.0.1', 'placeholder'
        ]
        
        return any(pattern in text.lower() for pattern in placeholder_patterns)
    
    def _is_development_noise(self, text: str, file_path: str) -> bool:
        """Check if text is development/debug noise."""
        # Check for debug paths
        if any(debug_path in file_path.lower() for debug_path in 
               ['debug', 'test', 'demo', 'sample', 'example']):
            return True
        
        # Check for development URLs
        dev_patterns = ['test.', 'dev.', 'debug.', 'sample.', 'example.']
        return any(pattern in text.lower() for pattern in dev_patterns)
    
    def _is_ui_animation_noise(self, text: str) -> bool:
        """Check if text is UI/animation framework noise."""
        ui_patterns = [
            'objectAnimator', 'pathData', 'iconFade', 'translationZ',
            'colorSeconda', 'Container', 'Widget', 'layout', 'drawable',
            'animation', 'transition', 'gradient', 'shape', 'solid'
        ]
        
        text_lower = text.lower()
        return any(pattern.lower() in text_lower for pattern in ui_patterns)
    
    def _is_package_reference_noise(self, text: str) -> bool:
        """Check if text is a package/class reference (noise)."""
        # Package name patterns
        package_patterns = [
            re.compile(r'^(com|org|net|io)\.[a-z0-9\.]+$', re.IGNORECASE),
            re.compile(r'^[a-z]+[A-Z][a-zA-Z]*\(', re.IGNORECASE),  # Method calls
            re.compile(r'^[A-Z][a-zA-Z]*\.[A-Z][a-zA-Z]*$')  # Class references
        ]
        
        return any(pattern.match(text) for pattern in package_patterns)
    
    def _get_matched_patterns(self) -> List[str]:
        """Get list of pattern names that matched during filtering."""
        # This would be populated during filtering process
        # For now, return basic categories
        return [
            'framework_noise',
            'path_exclusions', 
            'invalid_formats',
            'context_noise'
        ]
    
    def _get_excluded_files(self) -> List[str]:
        """Get list of files that were excluded during filtering."""
        # This would be populated during filtering process
        # For now, return common excluded patterns
        return [
            '/assets/',
            '/res/raw/',
            'flutter_assets/',
            'node_modules/',
            '/META-INF/'
        ]
    
    def validate_domain(self, domain: str) -> bool:
        """Validate domain name against noise patterns."""
        # Check if domain matches noise patterns
        if self.is_framework_noise(domain):
            return False
        
        # Check for valid domain structure
        if not self._is_valid_domain_structure(domain):
            return False
        
        return True
    
    def validate_url(self, url: str) -> bool:
        """Validate URL against noise patterns."""
        # Check if URL matches noise patterns
        if self.is_framework_noise(url):
            return False
        
        # Check for valid URL structure
        if not self._is_valid_url_structure(url):
            return False
        
        return True
    
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address against noise patterns."""
        # Check if IP matches invalid patterns
        if any(pattern.match(ip) for pattern in self.invalid_ip_patterns):
            return False
        
        # Check for framework noise
        if self.is_framework_noise(ip):
            return False
        
        return True
    
    def _is_valid_domain_structure(self, domain: str) -> bool:
        """Check if domain has valid structure."""
        # Basic domain validation
        if not domain or '.' not in domain:
            return False
        
        # Check length constraints
        if len(domain) < 4 or len(domain) > 253:
            return False
        
        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9\-\.]+$', domain):
            return False
        
        return True
    
    def _is_valid_url_structure(self, url: str) -> bool:
        """Check if URL has valid structure."""
        # Basic URL validation
        if not url or len(url) < 10:
            return False
        
        # Must have scheme
        if '://' not in url:
            return False
        
        # Check for valid scheme
        valid_schemes = ['http', 'https', 'ftp', 'ws', 'wss']
        scheme = url.split('://')[0].lower()
        if scheme not in valid_schemes:
            return False
        
        return True
    
    def get_noise_statistics(self) -> Dict[str, int]:
        """Get noise filtering statistics."""
        return self.noise_stats.copy()
    
    def reset_statistics(self) -> None:
        """Reset noise filtering statistics."""
        self.noise_stats = {
            'total_filtered': 0,
            'framework_noise': 0,
            'path_exclusions': 0,
            'invalid_formats': 0,
            'context_noise': 0
        }
    
    def assess_noise_level(self, text: str, file_path: str = "") -> float:
        """
        Assess noise level of text (0.0 = no noise, 1.0 = definite noise).
        
        Args:
            text: Text to assess
            file_path: Source file path
            
        Returns:
            Noise level score between 0.0 and 1.0
        """
        noise_score = 0.0
        
        # Check framework patterns
        if self._matches_framework_patterns(text):
            noise_score += 0.4
        
        # Check path exclusions
        if self._is_excluded_path(file_path):
            noise_score += 0.3
        
        # Check invalid formats
        if self._is_invalid_format(text):
            noise_score += 0.2
        
        # Check context noise
        if self._is_context_noise(text, file_path):
            noise_score += 0.1
        
        return min(1.0, noise_score)
    
    def create_noise_report(self, findings: Dict[str, Set[str]]) -> Dict[str, Any]:
        """Create detailed noise analysis report."""
        report = {
            'total_items': sum(len(category) for category in findings.values()),
            'noise_statistics': self.get_noise_statistics(),
            'noise_patterns': {
                'framework_patterns': len(self.framework_noise_patterns),
                'path_exclusions': len(self.excluded_path_patterns),
                'invalid_ip_patterns': len(self.invalid_ip_patterns)
            },
            'categories_analyzed': list(findings.keys()),
            'filter_efficiency': 0.0
        }
        
        # Calculate filter efficiency
        total_filtered = sum(self.noise_stats.values())
        if report['total_items'] > 0:
            report['filter_efficiency'] = total_filtered / report['total_items']
        
        return report 