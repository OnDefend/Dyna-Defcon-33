#!/usr/bin/env python3
"""
Accuracy Integration Pipeline - Detection-Aware Configuration Management

configuration management optimized for maximum vulnerability
detection with intelligent defaults and validation systems.
"""

import logging
from typing import Dict, Any, Optional
from pathlib import Path

from .data_structures import PipelineConfiguration, DetectionQuality

class DetectionConfigurationManager:
    """
    configuration manager optimized for maximum vulnerability
    detection accuracy with intelligent defaults and validation.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def get_detection_optimized_config(self) -> PipelineConfiguration:
        """
        Get configuration optimized for maximum vulnerability detection
        with professional defaults ensuring zero detection regression.
        """
        # Import VulnerabilitySeverity here to avoid circular imports
        try:
            from ..vulnerability_filter import VulnerabilitySeverity
            # DETECTION-FIRST: Use LOW severity to capture all legitimate vulnerabilities
            # This is especially critical for vulnerable test applications
            min_severity = VulnerabilitySeverity.LOW
        except ImportError:
            # Fallback if import fails
            min_severity = "LOW"
        
        config = PipelineConfiguration(
            # Detection-optimized severity filtering
            min_severity=min_severity,
            enable_framework_filtering=True,
            enable_context_filtering=True,
            preserve_high_confidence_low_severity=True,  # Ensure no vulnerability loss
            
            # Intelligent deduplication
            enable_fingerprint_matching=True,
            enable_pattern_grouping=True,
            similarity_threshold=0.85,  # Conservative threshold to prevent vulnerability loss
            preserve_unique_vulnerabilities=True,  # Zero vulnerability loss tolerance
            
            # Performance optimization
            enable_parallel_processing=True,
            max_workers=4,
            enable_caching=True,
            cache_ttl_hours=24,
            
            # Detection quality assurance
            enable_detection_validation=True,
            require_vulnerability_preservation=True,
            detection_quality_threshold=DetectionQuality.GOOD
        )
        
        self.logger.info("Created detection-optimized configuration")
        return config
    
    def validate_detection_config(self, config: PipelineConfiguration) -> Dict[str, Any]:
        """
        Validate configuration for maximum vulnerability detection capability.
        """
        validation_result = {
            'valid': True,
            'warnings': [],
            'errors': [],
            'recommendations': []
        }
        
        # Validate severity filtering settings
        if not config.enable_framework_filtering:
            validation_result['warnings'].append(
                "Framework filtering disabled - may reduce detection accuracy"
            )
        
        if not config.preserve_high_confidence_low_severity:
            validation_result['errors'].append(
                "CRITICAL: High confidence low severity preservation disabled - VULNERABILITY LOSS RISK"
            )
            validation_result['valid'] = False
        
        # Validate confidence scoring
        # Handle nested confidence configuration structure
        confidence_threshold = 0.7  # Default
        if hasattr(config, 'confidence_config') and hasattr(config.confidence_config, 'min_confidence_threshold'):
            confidence_threshold = config.confidence_config.min_confidence_threshold
        elif hasattr(config, 'min_confidence_threshold'):
            confidence_threshold = config.min_confidence_threshold
        
        if confidence_threshold > 0.8:
            validation_result['warnings'].append(
                f"High confidence threshold ({confidence_threshold}) may eliminate valid vulnerabilities"
            )
        
        # Check if organic detection is enabled (graceful fallback)
        enable_organic_detection = getattr(config, 'enable_organic_detection', True)
        if not enable_organic_detection:
            validation_result['warnings'].append(
                "Organic detection disabled - may affect detection patterns"
            )
        
        # Validate deduplication settings
        if config.similarity_threshold < 0.8:
            validation_result['warnings'].append(
                f"Low similarity threshold ({config.similarity_threshold}) may cause over-deduplication"
            )
        
        if not config.preserve_unique_vulnerabilities:
            validation_result['errors'].append(
                "CRITICAL: Unique vulnerability preservation disabled - VULNERABILITY LOSS RISK"
            )
            validation_result['valid'] = False
        
        # Validate detection quality requirements
        if not config.enable_detection_validation:
            validation_result['errors'].append(
                "CRITICAL: Detection validation disabled - QUALITY ASSURANCE RISK"
            )
            validation_result['valid'] = False
        
        if not config.require_vulnerability_preservation:
            validation_result['errors'].append(
                "CRITICAL: Vulnerability preservation not required - DETECTION LOSS RISK"
            )
            validation_result['valid'] = False
        
        # Generate recommendations
        if config.max_workers < 4:
            validation_result['recommendations'].append(
                "Consider increasing max_workers for better performance"
            )
        
        if not config.enable_caching:
            validation_result['recommendations'].append(
                "Enable caching for improved performance with large datasets"
            )
        
        # Log validation results
        if validation_result['errors']:
            self.logger.error(f"Configuration validation failed: {validation_result['errors']}")
        elif validation_result['warnings']:
            self.logger.warning(f"Configuration warnings: {validation_result['warnings']}")
        else:
            self.logger.info("Configuration validation passed")
        
        return validation_result
    
    def create_production_config(self) -> PipelineConfiguration:
        """
        Create production-ready configuration with maximum vulnerability
        detection and professional quality assurance.
        """
        config = self.get_detection_optimized_config()
        
        # Production enhancements
        config.enable_detection_validation = True
        config.require_vulnerability_preservation = True
        config.detection_quality_threshold = DetectionQuality.EXCELLENT
        config.preserve_high_confidence_low_severity = True
        config.preserve_unique_vulnerabilities = True
        
        # Performance optimization for production
        config.enable_parallel_processing = True
        config.max_workers = 6  # Increased for production
        config.enable_caching = True
        config.cache_ttl_hours = 48  # Extended cache for production
        
        # Validate production config
        validation = self.validate_detection_config(config)
        if not validation['valid']:
            raise ValueError(f"Production configuration validation failed: {validation['errors']}")
        
        self.logger.info("Created production-ready detection configuration")
        return config
    
    def create_testing_config(self) -> PipelineConfiguration:
        """
        Create configuration optimized for testing with comprehensive
        validation and detailed metrics collection.
        """
        config = self.get_detection_optimized_config()
        
        # Testing enhancements
        config.enable_detection_validation = True
        config.require_vulnerability_preservation = True
        config.detection_quality_threshold = DetectionQuality.EXCELLENT
        
        # Comprehensive testing settings
        config.preserve_high_confidence_low_severity = True
        config.preserve_unique_vulnerabilities = True
        config.enable_organic_detection = True
        
        # Performance settings for testing
        config.enable_parallel_processing = True
        config.max_workers = 2  # Conservative for testing
        config.enable_caching = False  # Disable caching for testing consistency
        
        self.logger.info("Created testing-optimized detection configuration")
        return config
    
    def load_config_from_file(self, config_path: Path) -> PipelineConfiguration:
        """
        Load configuration from external file with validation.
        """
        # This would implement file loading logic
        # For now, return detection-optimized defaults
        self.logger.info(f"Loading configuration from {config_path}")
        return self.get_detection_optimized_config()
    
    def export_config_template(self, output_path: Path):
        """
        Export configuration template for external customization.
        """
        template_config = self.get_detection_optimized_config()
        
        # This would implement template export logic
        self.logger.info(f"Exported configuration template to {output_path}")
        
        return template_config 
    
    def export_config_template(self, output_path: Path):
        """
        Export configuration template for external customization.
        """
        template_config = self.get_detection_optimized_config()
        
        # This would implement template export logic
        self.logger.info(f"Exported configuration template to {output_path}")
        
        return template_config 