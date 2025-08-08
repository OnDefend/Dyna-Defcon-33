#!/usr/bin/env python3
"""
Enterprise Performance Integration - Framework Initializer

Handles initialization and status tracking of all optimization frameworks
with comprehensive error handling and graceful degradation.
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from .data_structures import FrameworkStatus, FrameworkAvailability

class FrameworkInitializer:
    """
    Initializes and manages all optimization frameworks with
    graceful fallback handling and status tracking.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.framework_status: Dict[str, FrameworkStatus] = {}
        self.frameworks: Dict[str, Any] = {}
        
    def initialize_all_frameworks(self):
        """Initialize all available optimization frameworks."""
        self.logger.info("Initializing optimization frameworks...")
        
        # Initialize performance optimizer
        self._initialize_performance_optimizer()
        
        # Initialize enterprise optimizer
        self._initialize_enterprise_optimizer()
        
        # Initialize enterprise integration
        self._initialize_enterprise_integration()
        
        # Initialize accuracy pipeline
        self._initialize_accuracy_pipeline()
        
        # Log initialization summary
        self._log_initialization_summary()
    
    def _initialize_performance_optimizer(self):
        """Initialize AccuracyIntegrationPipeline from accuracy_integration_pipeline."""
        try:
            from core.accuracy_integration_pipeline import AccuracyIntegrationPipeline, PipelineConfiguration
            from core.accuracy_integration_pipeline.data_structures import ConfidenceCalculationConfiguration
            from core.vulnerability_filter import VulnerabilitySeverity
            
            # Create confidence configuration first
            confidence_config = ConfidenceCalculationConfiguration(
                min_confidence_threshold=0.7,
                enable_vulnerability_preservation=True,
                enable_context_enhancement=True,
                enable_evidence_aggregation=True
            )
            
            # Create base accuracy pipeline with proper configuration
            base_config = PipelineConfiguration(
                min_severity=VulnerabilitySeverity.MEDIUM,
                enable_framework_filtering=True,
                enable_context_filtering=True,
                confidence_config=confidence_config,  # Use confidence_config instead of min_confidence_threshold
                enable_fingerprint_matching=True,
                enable_pattern_grouping=True,
                similarity_threshold=0.85,
                enable_parallel_processing=self.config.get('enable_parallel_processing', True),
                max_workers=self.config.get('max_workers', 4),
                enable_caching=self.config.get('cache_enabled', True),
                cache_ttl_hours=self.config.get('cache_ttl_hours', 24)
            )
            
            # Initialize accuracy integration pipeline
            pipeline_config = {"pipeline_config": base_config}
            
            self.frameworks['accuracy_pipeline'] = AccuracyIntegrationPipeline(pipeline_config)
            self.framework_status['accuracy_pipeline'] = FrameworkStatus(
                name='AccuracyIntegrationPipeline',
                availability=FrameworkAvailability.AVAILABLE,
                initialization_success=True,
                capabilities=['accuracy_optimization', 'vulnerability_filtering', 'confidence_scoring']
            )
            
            self.logger.info("AccuracyIntegrationPipeline initialized successfully")
            
        except Exception as e:
            self.framework_status['accuracy_pipeline'] = FrameworkStatus(
                name='AccuracyIntegrationPipeline',
                availability=FrameworkAvailability.ERROR,
                initialization_success=False,
                error_message=str(e)
            )
            self.logger.error(f"Failed to initialize AccuracyIntegrationPipeline: {e}")
    
    def _initialize_enterprise_optimizer(self):
        """Initialize enterprise performance optimization with graceful fallback."""
        try:
            # Try to import enterprise optimization if available
            try:
                from utilities.enterprise_performance_optimization import (
                    EnterprisePerformanceOptimizer, OptimizationConfig
                )
                
                enterprise_config = OptimizationConfig(
                    max_memory_mb=self.config.get('max_memory_mb', 2048),
                    max_workers=self.config.get('max_workers', 4),
                    chunk_size_mb=50,  # 50MB chunks for streaming
                    enable_streaming=self.config.get('enable_streaming_analysis', False),
                    enable_progressive_analysis=self.config.get('enable_progressive_analysis', True),
                    cache_size_mb=self.config.get('cache_size_mb', 512)
                )
                
                self.frameworks['enterprise_optimizer'] = EnterprisePerformanceOptimizer(enterprise_config)
                self.framework_status['enterprise_optimizer'] = FrameworkStatus(
                    name='EnterprisePerformanceOptimizer',
                    availability=FrameworkAvailability.AVAILABLE,
                    initialization_success=True,
                    capabilities=['enterprise_optimization', 'streaming_analysis', 'progressive_analysis']
                )
                
                self.logger.info("EnterprisePerformanceOptimizer initialized successfully")
                
            except ImportError as ie:
                # Enterprise optimization not available - use graceful fallback
                self.framework_status['enterprise_optimizer'] = FrameworkStatus(
                    name='EnterprisePerformanceOptimizer',
                    availability=FrameworkAvailability.FALLBACK,
                    initialization_success=False,
                    error_message=f"Enterprise module not available: {ie}"
                )
                self.logger.warning(f"Enterprise optimization unavailable, using standard optimization: {ie}")
                
        except Exception as e:
            self.framework_status['enterprise_optimizer'] = FrameworkStatus(
                name='EnterprisePerformanceOptimizer',
                availability=FrameworkAvailability.ERROR,
                initialization_success=False,
                error_message=str(e)
            )
            self.logger.error(f"Failed to initialize enterprise optimizer: {e}")
    
    def _initialize_enterprise_integration(self):
        """Initialize enterprise integration with graceful fallback."""
        try:
            # Try to import enterprise integration if available
            try:
                from utilities.ENTERPRISE_PERFORMANCE_INTEGRATION import AODSEnterpriseIntegration
                
                self.frameworks['enterprise_integration'] = AODSEnterpriseIntegration()
                self.frameworks['enterprise_integration'].initialize_enterprise_features()
                
                self.framework_status['enterprise_integration'] = FrameworkStatus(
                    name='AODSEnterpriseIntegration',
                    availability=FrameworkAvailability.AVAILABLE,
                    initialization_success=True,
                    capabilities=['enterprise_features', 'batch_processing']
                )
                
                self.logger.info("AODSEnterpriseIntegration initialized successfully")
                
            except ImportError as ie:
                # Enterprise integration not available - use graceful fallback
                self.framework_status['enterprise_integration'] = FrameworkStatus(
                    name='AODSEnterpriseIntegration',
                    availability=FrameworkAvailability.FALLBACK,
                    initialization_success=False,
                    error_message=f"Enterprise integration module not available: {ie}"
                )
                self.logger.warning(f"Enterprise integration unavailable, using standard features: {ie}")
                
        except Exception as e:
            self.framework_status['enterprise_integration'] = FrameworkStatus(
                name='AODSEnterpriseIntegration',
                availability=FrameworkAvailability.ERROR,
                initialization_success=False,
                error_message=str(e)
            )
            self.logger.error(f"Failed to initialize enterprise integration: {e}")
    
    def _initialize_accuracy_pipeline(self):
        """Initialize base AccuracyIntegrationPipeline with fallback configuration."""
        try:
            from core.accuracy_integration_pipeline import AccuracyIntegrationPipeline
            
            # Use simple dictionary configuration with safe defaults
            pipeline_config = {
                "enable_parallel_processing": self.config.get('enable_parallel_processing', True),
                "max_workers": self.config.get('max_workers', 4),
                "enable_caching": self.config.get('cache_enabled', True)
            }
            
            self.frameworks['base_accuracy_pipeline'] = AccuracyIntegrationPipeline(pipeline_config)
            self.framework_status['base_accuracy_pipeline'] = FrameworkStatus(
                name='AccuracyIntegrationPipeline',
                availability=FrameworkAvailability.AVAILABLE,
                initialization_success=True,
                capabilities=['vulnerability_processing', 'accuracy_enhancement', 'deduplication']
            )
            
            self.logger.info("Base AccuracyIntegrationPipeline initialized successfully")
            
        except Exception as e:
            self.framework_status['base_accuracy_pipeline'] = FrameworkStatus(
                name='AccuracyIntegrationPipeline',
                availability=FrameworkAvailability.ERROR,
                initialization_success=False,
                error_message=str(e)
            )
            self.logger.error(f"Failed to initialize base accuracy pipeline: {e}")
    
    def _log_initialization_summary(self):
        """Log comprehensive initialization summary."""
        total_frameworks = len(self.framework_status)
        successful_frameworks = sum(1 for status in self.framework_status.values() if status.initialization_success)
        
        self.logger.info("Framework Initialization Summary:")
        for name, status in self.framework_status.items():
            availability_icon = "PASS" if status.initialization_success else "FAIL"
            
            self.logger.info(f"   {availability_icon} {status.name}: {status.availability.value}")
            if status.capabilities:
                self.logger.info(f"      Capabilities: {', '.join(status.capabilities)}")
            if status.error_message:
                self.logger.info(f"      Error: {status.error_message}")
        
        success_percentage = (successful_frameworks / total_frameworks) * 100
        self.logger.info(f"Overall Initialization: {success_percentage:.1f}% ({successful_frameworks}/{total_frameworks})")
    
    def get_framework(self, framework_name: str) -> Optional[Any]:
        """Get an initialized framework by name."""
        return self.frameworks.get(framework_name)
    
    def get_framework_status(self, framework_name: str) -> Optional[FrameworkStatus]:
        """Get the status of a specific framework."""
        return self.framework_status.get(framework_name)
    
    def is_framework_available(self, framework_name: str) -> bool:
        """Check if a framework is available and successfully initialized."""
        status = self.get_framework_status(framework_name)
        return status is not None and status.initialization_success
    
    def get_available_capabilities(self) -> Dict[str, List[str]]:
        """Get all available capabilities from successfully initialized frameworks."""
        capabilities = {}
        for name, status in self.framework_status.items():
            if status.initialization_success and status.capabilities:
                capabilities[name] = status.capabilities
        return capabilities
    
    def get_integration_status(self) -> Dict[str, Any]:
        """Get comprehensive integration status information."""
        total_frameworks = len(self.framework_status)
        successful_frameworks = sum(1 for status in self.framework_status.values() if status.initialization_success)
        
        return {
            'total_frameworks': total_frameworks,
            'successful_frameworks': successful_frameworks,
            'success_percentage': (successful_frameworks / total_frameworks) * 100 if total_frameworks > 0 else 0,
            'framework_details': {name: {
                'available': status.initialization_success,
                'availability': status.availability.value,
                'capabilities': status.capabilities,
                'error': status.error_message
            } for name, status in self.framework_status.items()},
            'available_capabilities': self.get_available_capabilities()
        } 


class AODSEnterpriseIntegration:
    """
    AODS Enterprise Integration Interface
    
    Provides enterprise-level integration capabilities for AODS framework
    with graceful degradation and comprehensive error handling.
    
    This class resolves Error 13: Missing Enterprise Module Dependencies
    by providing the expected interface that other modules can import.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize AODS Enterprise Integration.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize framework initializer
        self.framework_initializer = FrameworkInitializer(self.config)
        
        # Enterprise capabilities
        self.enterprise_features_available = False
        self.optimization_level = "standard"
        self.integration_status = {}
        
        # Initialize enterprise components
        self._initialize_enterprise_components()
        
        self.logger.info("AODS Enterprise Integration initialized")
    
    def _initialize_enterprise_components(self):
        """Initialize enterprise-level components with graceful fallback."""
        try:
            # Initialize all optimization frameworks
            self.framework_initializer.initialize_all_frameworks()
            
            # Check enterprise feature availability
            self.integration_status = self.framework_initializer.get_integration_status()
            
            # Determine if enterprise features are available
            success_rate = self.integration_status.get('success_percentage', 0)
            self.enterprise_features_available = success_rate >= 75.0
            
            if self.enterprise_features_available:
                self.optimization_level = "enterprise"
                self.logger.info(f"✅ Enterprise features available: {success_rate:.1f}% framework success rate")
            else:
                self.optimization_level = "standard"
                self.logger.warning(f"⚠️ Enterprise features degraded: {success_rate:.1f}% framework success rate")
                
        except Exception as e:
            self.logger.error(f"Enterprise component initialization failed: {e}")
            self.enterprise_features_available = False
            self.optimization_level = "fallback"
    
    def is_enterprise_available(self) -> bool:
        """Check if enterprise-level features are available."""
        return self.enterprise_features_available
    
    def get_optimization_level(self) -> str:
        """Get current optimization level (enterprise/standard/fallback)."""
        return self.optimization_level
    
    def get_enterprise_status(self) -> Dict[str, Any]:
        """Get comprehensive enterprise integration status."""
        return {
            'enterprise_features_available': self.enterprise_features_available,
            'optimization_level': self.optimization_level,
            'framework_integration': self.integration_status,
            'available_capabilities': self.framework_initializer.get_available_capabilities() if hasattr(self.framework_initializer, 'get_available_capabilities') else {}
        }
    
    def initialize(self) -> bool:
        """
        Initialize enterprise integration.
        
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            self._initialize_enterprise_components()
            return self.enterprise_features_available or self.optimization_level in ["standard", "fallback"]
        except Exception as e:
            self.logger.error(f"Enterprise integration initialization failed: {e}")
            return False
    
    def get_framework_status(self, framework_name: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific framework."""
        if hasattr(self.framework_initializer, 'framework_status'):
            status = self.framework_initializer.framework_status.get(framework_name)
            if status:
                return {
                    'available': status.initialization_success,
                    'availability': status.availability.value,
                    'capabilities': status.capabilities,
                    'error': status.error_message
                }
        return None
    
    def enable_enterprise_mode(self) -> bool:
        """
        Enable enterprise mode if available.
        
        Returns:
            True if enterprise mode enabled, False otherwise
        """
        if self.enterprise_features_available:
            self.optimization_level = "enterprise"
            self.logger.info("Enterprise mode enabled")
            return True
        else:
            self.logger.warning("Enterprise mode not available, falling back to standard mode")
            return False
    
    def get_performance_optimizations(self) -> Dict[str, Any]:
        """Get available performance optimizations."""
        try:
            capabilities = self.framework_initializer.get_available_capabilities()
            return {
                'optimization_level': self.optimization_level,
                'available_optimizations': list(capabilities.keys()),
                'enterprise_features': self.enterprise_features_available,
                'performance_boost_available': len(capabilities) > 0
            }
        except Exception as e:
            self.logger.error(f"Failed to get performance optimizations: {e}")
            return {
                'optimization_level': 'fallback',
                'available_optimizations': [],
                'enterprise_features': False,
                'performance_boost_available': False
            } 