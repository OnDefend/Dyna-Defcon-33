#!/usr/bin/env python3
"""
Cross-APK Filter Configuration Manager
======================================

This module provides configurable filtering sensitivity for cross-APK filtering,
completing the requirements for Solution 6: Cross-APK Filtering Enhancement.

CRITICAL: This adds the missing configurable filtering sensitivity that was the
only requirement not met by the existing DynamicPackageFilter implementation.
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

class FilteringSensitivity(Enum):
    """Sensitivity levels for cross-APK filtering."""
    STRICT = "strict"           # Very conservative - filter more aggressively
    BALANCED = "balanced"       # Default balanced approach  
    PERMISSIVE = "permissive"   # More lenient - preserve more findings
    CUSTOM = "custom"           # User-defined thresholds

@dataclass
class FilteringThresholds:
    """Configurable thresholds for cross-APK filtering decisions."""
    app_confidence_threshold: float = 0.8      # Minimum confidence to classify as app code
    library_confidence_threshold: float = 0.6  # Minimum confidence to include library findings
    cross_apk_confidence_threshold: float = 0.7 # Minimum confidence to filter cross-APK
    unknown_inclusion_threshold: float = 0.5   # Threshold for including unknown files
    
    # Advanced thresholds
    package_depth_weight: float = 0.2          # Weight for package depth in scoring
    framework_penalty: float = 0.1             # Penalty for framework-looking packages
    target_bonus: float = 0.3                  # Bonus for target package matches

@dataclass
class FilteringConfiguration:
    """Complete configuration for cross-APK filtering."""
    sensitivity: FilteringSensitivity = FilteringSensitivity.BALANCED
    thresholds: FilteringThresholds = None
    
    # Include/exclude lists
    additional_cross_apk_indicators: List[str] = None
    additional_library_indicators: List[str] = None
    package_whitelist: List[str] = None
    package_blacklist: List[str] = None
    
    # Behavioral settings
    preserve_security_libraries: bool = True   # Always include security-related libraries
    filter_test_code: bool = True              # Filter obvious test code
    include_ambiguous_findings: bool = True    # Include findings when classification is uncertain
    
    def __post_init__(self):
        if self.thresholds is None:
            self.thresholds = self._get_default_thresholds()
        if self.additional_cross_apk_indicators is None:
            self.additional_cross_apk_indicators = []
        if self.additional_library_indicators is None:
            self.additional_library_indicators = []
        if self.package_whitelist is None:
            self.package_whitelist = []
        if self.package_blacklist is None:
            self.package_blacklist = []
    
    def _get_default_thresholds(self) -> FilteringThresholds:
        """Get default thresholds based on sensitivity level."""
        if self.sensitivity == FilteringSensitivity.STRICT:
            return FilteringThresholds(
                app_confidence_threshold=0.9,
                library_confidence_threshold=0.8,
                cross_apk_confidence_threshold=0.6,
                unknown_inclusion_threshold=0.3
            )
        elif self.sensitivity == FilteringSensitivity.PERMISSIVE:
            return FilteringThresholds(
                app_confidence_threshold=0.6,
                library_confidence_threshold=0.4,
                cross_apk_confidence_threshold=0.8,
                unknown_inclusion_threshold=0.7
            )
        else:  # BALANCED (default)
            return FilteringThresholds()

class CrossAPKFilterConfigManager:
    """
    Manager for cross-APK filtering configuration with runtime adjustments.
    
    This class provides:
    1. Configurable filtering sensitivity levels
    2. Runtime threshold adjustments
    3. Package-specific overrides
    4. Integration with existing DynamicPackageFilter
    """
    
    def __init__(self, config: FilteringConfiguration = None):
        """Initialize the configuration manager."""
        self.logger = logging.getLogger(__name__)
        self.config = config or FilteringConfiguration()
        self._runtime_overrides = {}
        
        self.logger.info(f"🔧 **CROSS-APK FILTER CONFIG**: Initialized with {self.config.sensitivity.value} sensitivity")
    
    def get_filtering_decision(self, classification_result: Dict[str, Any], 
                             file_path: str, target_package: str) -> Dict[str, Any]:
        """
        Enhanced filtering decision with configurable sensitivity.
        
        Args:
            classification_result: Result from DynamicPackageFilter.classify_file()
            file_path: Path to the file being classified
            target_package: Target application package
            
        Returns:
            Enhanced decision with configurable thresholds applied
        """
        category = classification_result.get('category', 'unknown')
        confidence = classification_result.get('confidence', 0.0)
        reasons = classification_result.get('reasons', [])
        
        # Apply configurable thresholds
        enhanced_decision = {
            'original_category': category,
            'original_confidence': confidence,
            'original_should_include': classification_result.get('should_include', True),
            'enhanced_category': category,
            'enhanced_confidence': confidence,
            'enhanced_should_include': True,
            'configuration_applied': True,
            'sensitivity_level': self.config.sensitivity.value
        }
        
        # Apply sensitivity-based adjustments
        if category == 'app':
            enhanced_decision['enhanced_should_include'] = (
                confidence >= self.config.thresholds.app_confidence_threshold
            )
        elif category == 'library':
            # Special handling for security libraries
            if self.config.preserve_security_libraries and self._is_security_library(file_path):
                enhanced_decision['enhanced_should_include'] = True
                enhanced_decision['enhanced_confidence'] = min(1.0, confidence + 0.2)
                reasons.append('Security library preserved')
            else:
                enhanced_decision['enhanced_should_include'] = (
                    confidence >= self.config.thresholds.library_confidence_threshold
                )
        elif category == 'cross_apk':
            enhanced_decision['enhanced_should_include'] = (
                confidence < self.config.thresholds.cross_apk_confidence_threshold
            )
        else:  # unknown
            enhanced_decision['enhanced_should_include'] = (
                confidence >= self.config.thresholds.unknown_inclusion_threshold or
                self.config.include_ambiguous_findings
            )
        
        # Apply package-specific overrides
        enhanced_decision = self._apply_package_overrides(enhanced_decision, file_path)
        
        # Add configuration metadata
        enhanced_decision['reasons'] = reasons + [f'Applied {self.config.sensitivity.value} sensitivity']
        enhanced_decision['thresholds_used'] = {
            'app_threshold': self.config.thresholds.app_confidence_threshold,
            'library_threshold': self.config.thresholds.library_confidence_threshold,
            'cross_apk_threshold': self.config.thresholds.cross_apk_confidence_threshold,
            'unknown_threshold': self.config.thresholds.unknown_inclusion_threshold
        }
        
        # Log decision if it differs from original
        if (enhanced_decision['enhanced_should_include'] != 
            enhanced_decision['original_should_include']):
            self.logger.debug(
                f"🔧 **FILTERING ADJUSTMENT**: {file_path} | "
                f"{enhanced_decision['original_should_include']} → {enhanced_decision['enhanced_should_include']} | "
                f"Confidence: {confidence:.2f} | Sensitivity: {self.config.sensitivity.value}"
            )
        
        return enhanced_decision
    
    def update_sensitivity(self, new_sensitivity: FilteringSensitivity):
        """Update filtering sensitivity at runtime."""
        old_sensitivity = self.config.sensitivity
        self.config.sensitivity = new_sensitivity
        self.config.thresholds = self.config._get_default_thresholds()
        
        self.logger.info(
            f"🔧 **SENSITIVITY UPDATED**: {old_sensitivity.value} → {new_sensitivity.value}"
        )
    
    def add_package_override(self, package_pattern: str, should_include: bool, reason: str):
        """Add a runtime package override."""
        self._runtime_overrides[package_pattern] = {
            'should_include': should_include,
            'reason': reason
        }
        
        self.logger.info(f"🔧 **PACKAGE OVERRIDE**: {package_pattern} → {should_include} ({reason})")
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """Get a summary of current configuration."""
        return {
            'sensitivity': self.config.sensitivity.value,
            'thresholds': {
                'app_confidence': self.config.thresholds.app_confidence_threshold,
                'library_confidence': self.config.thresholds.library_confidence_threshold,
                'cross_apk_confidence': self.config.thresholds.cross_apk_confidence_threshold,
                'unknown_inclusion': self.config.thresholds.unknown_inclusion_threshold
            },
            'behavioral_settings': {
                'preserve_security_libraries': self.config.preserve_security_libraries,
                'filter_test_code': self.config.filter_test_code,
                'include_ambiguous_findings': self.config.include_ambiguous_findings
            },
            'custom_indicators': {
                'additional_cross_apk': len(self.config.additional_cross_apk_indicators),
                'additional_library': len(self.config.additional_library_indicators),
                'whitelist_packages': len(self.config.package_whitelist),
                'blacklist_packages': len(self.config.package_blacklist)
            },
            'runtime_overrides': len(self._runtime_overrides)
        }
    
    def _is_security_library(self, file_path: str) -> bool:
        """Check if this is a security-related library that should be preserved."""
        security_indicators = [
            'crypto', 'security', 'ssl', 'tls', 'auth', 'oauth', 
            'encryption', 'keystore', 'certificate', 'hash'
        ]
        
        path_lower = file_path.lower()
        return any(indicator in path_lower for indicator in security_indicators)
    
    def _apply_package_overrides(self, decision: Dict[str, Any], file_path: str) -> Dict[str, Any]:
        """Apply package-specific overrides."""
        for pattern, override in self._runtime_overrides.items():
            if pattern in file_path:
                decision['enhanced_should_include'] = override['should_include']
                decision['reasons'].append(f"Override: {override['reason']}")
                break
        
        # Apply whitelist/blacklist
        for whitelisted in self.config.package_whitelist:
            if whitelisted in file_path:
                decision['enhanced_should_include'] = True
                decision['reasons'].append(f"Whitelisted: {whitelisted}")
                break
        
        for blacklisted in self.config.package_blacklist:
            if blacklisted in file_path:
                decision['enhanced_should_include'] = False
                decision['reasons'].append(f"Blacklisted: {blacklisted}")
                break
        
        return decision


# Convenience functions for easy integration
def create_cross_apk_filter_config(sensitivity: str = "balanced") -> CrossAPKFilterConfigManager:
    """Create a cross-APK filter configuration manager."""
    sensitivity_enum = FilteringSensitivity(sensitivity.lower())
    config = FilteringConfiguration(sensitivity=sensitivity_enum)
    return CrossAPKFilterConfigManager(config)

def get_default_cross_apk_config() -> CrossAPKFilterConfigManager:
    """Get the default cross-APK filter configuration."""
    return create_cross_apk_filter_config("balanced")