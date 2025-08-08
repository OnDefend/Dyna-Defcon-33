#!/usr/bin/env python3
"""
Environment Manager for AODS Shared Infrastructure

Manages environment-specific configurations, deployment contexts, and runtime
environment adaptation for optimal AODS performance across different environments.

Features:
- Environment detection and classification
- Environment-specific configuration loading
- Runtime environment adaptation
- Deployment context management
- Environment validation and health checks
- Resource optimization per environment
- Security context management
- Performance tuning per environment type

This component ensures AODS adapts appropriately to different deployment
environments from development to production.
"""

import os
import logging
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Set
from dataclasses import dataclass, field
from enum import Enum
import platform
import subprocess

from .system_detection import get_system_detector, SecurityEnvironment, VirtualizationType
from .config_loader import ConfigurationLoader, ConfigSource, LoadedConfiguration
from .validation import get_config_validator, ValidationResult
from ..analysis_exceptions import ConfigurationError

logger = logging.getLogger(__name__)

class EnvironmentType(Enum):
    """Environment types for AODS deployment."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"
    RESEARCH = "research"
    SANDBOX = "sandbox"
    UNKNOWN = "unknown"

class DeploymentContext(Enum):
    """Deployment context for AODS."""
    LOCAL_WORKSTATION = "local_workstation"
    DOCKER_CONTAINER = "docker_container"
    CLOUD_INSTANCE = "cloud_instance"
    CI_CD_PIPELINE = "ci_cd_pipeline"
    SECURITY_LAB = "security_lab"
    ENTERPRISE_SERVER = "enterprise_server"
    UNKNOWN = "unknown"

@dataclass
class EnvironmentProfile:
    """Environment profile with characteristics and constraints."""
    name: str
    environment_type: EnvironmentType
    deployment_context: DeploymentContext
    characteristics: Dict[str, Any] = field(default_factory=dict)
    constraints: Dict[str, Any] = field(default_factory=dict)
    optimizations: Dict[str, Any] = field(default_factory=dict)
    security_level: str = "standard"
    performance_profile: str = "balanced"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'environment_type': self.environment_type.value,
            'deployment_context': self.deployment_context.value,
            'characteristics': self.characteristics,
            'constraints': self.constraints,
            'optimizations': self.optimizations,
            'security_level': self.security_level,
            'performance_profile': self.performance_profile
        }

@dataclass
class EnvironmentConfiguration:
    """Complete environment configuration."""
    profile: EnvironmentProfile
    base_config: Dict[str, Any]
    environment_overrides: Dict[str, Any] = field(default_factory=dict)
    runtime_adjustments: Dict[str, Any] = field(default_factory=dict)
    validation_result: Optional[ValidationResult] = None
    
    def get_effective_config(self) -> Dict[str, Any]:
        """Get effective configuration with all overrides applied."""
        config = self.base_config.copy()
        
        # Apply environment overrides
        config = self._deep_merge(config, self.environment_overrides)
        
        # Apply runtime adjustments
        config = self._deep_merge(config, self.runtime_adjustments)
        
        return config
    
    def _deep_merge(self, base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()
        
        for key, value in overlay.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result

class EnvironmentManager:
    """
    Environment manager for AODS configuration adaptation.
    
    Automatically detects environment characteristics and adapts
    AODS configuration for optimal performance and security.
    """
    
    def __init__(self, base_config_path: Optional[Path] = None):
        """
        Initialize environment manager.
        
        Args:
            base_config_path: Base path for configuration files
        """
        self.base_config_path = base_config_path or Path.cwd() / 'config'
        self.config_loader = ConfigurationLoader(self.base_config_path)
        self.validator = get_config_validator()
        
        # Environment profiles
        self.environment_profiles = self._load_environment_profiles()
        
        # Current environment
        self._current_environment: Optional[EnvironmentProfile] = None
        self._current_config: Optional[EnvironmentConfiguration] = None
        
        # Environment detection cache
        self._detection_cache: Dict[str, Any] = {}
        
        logger.info("Environment manager initialized")
    
    def detect_current_environment(self) -> EnvironmentProfile:
        """
        Detect and classify the current environment.
        
        Returns:
            EnvironmentProfile for the current environment
        """
        if self._current_environment is not None:
            return self._current_environment
        
        try:
            # Get system information
            system_detector = get_system_detector()
            system_profile = system_detector.get_complete_system_profile()
            
            # Detect environment type
            env_type = self._detect_environment_type()
            
            # Detect deployment context
            deployment_context = self._detect_deployment_context(system_profile)
            
            # Create environment profile
            profile = EnvironmentProfile(
                name=f"{env_type.value}_{deployment_context.value}",
                environment_type=env_type,
                deployment_context=deployment_context,
                characteristics=self._extract_environment_characteristics(system_profile),
                constraints=self._determine_environment_constraints(env_type, deployment_context),
                optimizations=self._determine_environment_optimizations(system_profile)
            )
            
            # Set security and performance profiles
            profile.security_level = self._determine_security_level(env_type, deployment_context)
            profile.performance_profile = self._determine_performance_profile(system_profile)
            
            self._current_environment = profile
            logger.info(f"Detected environment: {profile.name}")
            
            return profile
            
        except Exception as e:
            logger.error(f"Environment detection failed: {e}")
            return self._get_fallback_environment()
    
    def get_environment_configuration(self, 
                                    environment_name: Optional[str] = None,
                                    override_config: Optional[Dict[str, Any]] = None) -> EnvironmentConfiguration:
        """
        Get complete environment configuration.
        
        Args:
            environment_name: Specific environment name (auto-detect if None)
            override_config: Additional configuration overrides
            
        Returns:
            EnvironmentConfiguration with all settings
        """
        # Get environment profile
        if environment_name:
            profile = self._get_named_environment_profile(environment_name)
        else:
            profile = self.detect_current_environment()
        
        try:
            # Load base configuration
            base_config = self._load_base_configuration()
            
            # Load environment-specific overrides
            env_overrides = self._load_environment_overrides(profile)
            
            # Apply runtime adjustments
            runtime_adjustments = self._generate_runtime_adjustments(profile)
            
            # Apply additional overrides
            if override_config:
                runtime_adjustments = self._deep_merge(runtime_adjustments, override_config)
            
            # Create environment configuration
            env_config = EnvironmentConfiguration(
                profile=profile,
                base_config=base_config,
                environment_overrides=env_overrides,
                runtime_adjustments=runtime_adjustments
            )
            
            # Validate configuration
            effective_config = env_config.get_effective_config()
            validation_result = self.validator.validate_configuration(
                effective_config,
                config_type="analysis",
                environment_context={'profile': profile.to_dict()}
            )
            env_config.validation_result = validation_result
            
            # Cache current configuration
            self._current_config = env_config
            
            logger.info(f"Environment configuration loaded for: {profile.name}")
            return env_config
            
        except Exception as e:
            logger.error(f"Failed to load environment configuration: {e}")
            raise ConfigurationError(f"Environment configuration failed: {e}")
    
    def adapt_configuration_to_environment(self, 
                                         base_config: Dict[str, Any],
                                         target_environment: Optional[str] = None) -> Dict[str, Any]:
        """
        Adapt base configuration to specific environment.
        
        Args:
            base_config: Base configuration to adapt
            target_environment: Target environment name
            
        Returns:
            Adapted configuration
        """
        env_config = self.get_environment_configuration(target_environment)
        
        # Start with base configuration
        adapted_config = base_config.copy()
        
        # Apply environment optimizations
        adapted_config = self._apply_environment_optimizations(adapted_config, env_config.profile)
        
        # Apply security adjustments
        adapted_config = self._apply_security_adjustments(adapted_config, env_config.profile)
        
        # Apply performance tuning
        adapted_config = self._apply_performance_tuning(adapted_config, env_config.profile)
        
        # Apply resource constraints
        adapted_config = self._apply_resource_constraints(adapted_config, env_config.profile)
        
        return adapted_config
    
    def get_available_environments(self) -> List[str]:
        """Get list of available environment profiles."""
        return list(self.environment_profiles.keys())
    
    def register_environment_profile(self, profile: EnvironmentProfile) -> None:
        """Register a custom environment profile."""
        self.environment_profiles[profile.name] = profile
        logger.info(f"Registered environment profile: {profile.name}")
    
    def validate_environment_health(self, 
                                  environment_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Validate environment health and configuration.
        
        Args:
            environment_name: Environment to validate (current if None)
            
        Returns:
            Health check results
        """
        try:
            profile = (self._get_named_environment_profile(environment_name) 
                      if environment_name else self.detect_current_environment())
            
            health_results = {
                'environment': profile.name,
                'overall_health': 'healthy',
                'checks': {},
                'warnings': [],
                'errors': []
            }
            
            # System resource checks
            health_results['checks']['system_resources'] = self._check_system_resources(profile)
            
            # Configuration validity checks
            health_results['checks']['configuration'] = self._check_configuration_validity(profile)
            
            # Security checks
            health_results['checks']['security'] = self._check_security_configuration(profile)
            
            # Performance checks
            health_results['checks']['performance'] = self._check_performance_configuration(profile)
            
            # Tool availability checks
            health_results['checks']['tool_availability'] = self._check_tool_availability(profile)
            
            # Determine overall health
            failed_checks = [name for name, result in health_results['checks'].items() 
                           if not result.get('passed', False)]
            
            if failed_checks:
                health_results['overall_health'] = 'degraded' if len(failed_checks) < 3 else 'unhealthy'
                health_results['errors'].extend([f"Failed check: {check}" for check in failed_checks])
            
            return health_results
            
        except Exception as e:
            logger.error(f"Environment health check failed: {e}")
            return {
                'environment': environment_name or 'unknown',
                'overall_health': 'error',
                'checks': {},
                'warnings': [],
                'errors': [f"Health check failed: {e}"]
            }
    
    def _detect_environment_type(self) -> EnvironmentType:
        """Detect environment type from various indicators."""
        # Check environment variable
        env_var = os.environ.get('AODS_ENVIRONMENT', '').lower()
        if env_var:
            try:
                return EnvironmentType(env_var)
            except ValueError:
                pass
        
        # Check for CI/CD indicators
        ci_indicators = ['CI', 'CONTINUOUS_INTEGRATION', 'GITHUB_ACTIONS', 'GITLAB_CI', 'JENKINS_URL']
        if any(os.environ.get(indicator) for indicator in ci_indicators):
            return EnvironmentType.TESTING
        
        # Check for Docker indicators
        if Path('/.dockerenv').exists():
            # Could be testing or production in Docker
            return EnvironmentType.TESTING if 'test' in os.environ.get('HOSTNAME', '') else EnvironmentType.PRODUCTION
        
        # Check working directory patterns
        cwd = Path.cwd().name.lower()
        if any(keyword in cwd for keyword in ['dev', 'development']):
            return EnvironmentType.DEVELOPMENT
        elif any(keyword in cwd for keyword in ['test', 'testing']):
            return EnvironmentType.TESTING
        elif any(keyword in cwd for keyword in ['prod', 'production']):
            return EnvironmentType.PRODUCTION
        elif any(keyword in cwd for keyword in ['research', 'lab']):
            return EnvironmentType.RESEARCH
        
        # Check system characteristics
        system_detector = get_system_detector()
        try:
            environment = system_detector.detect_system_environment()
            if environment.security_environment == SecurityEnvironment.KALI_LINUX:
                return EnvironmentType.RESEARCH
        except Exception:
            pass
        
        # Default fallback
        return EnvironmentType.DEVELOPMENT
    
    def _detect_deployment_context(self, system_profile: Dict[str, Any]) -> DeploymentContext:
        """Detect deployment context from system profile."""
        environment = system_profile.get('environment', {})
        
        # Check virtualization type
        virt_type = environment.get('virtualization_type', 'unknown')
        if virt_type == 'docker':
            return DeploymentContext.DOCKER_CONTAINER
        elif virt_type in ['vmware', 'virtualbox', 'kvm']:
            return DeploymentContext.CLOUD_INSTANCE
        
        # Check for CI/CD
        ci_indicators = ['CI', 'CONTINUOUS_INTEGRATION', 'GITHUB_ACTIONS', 'GITLAB_CI']
        if any(os.environ.get(indicator) for indicator in ci_indicators):
            return DeploymentContext.CI_CD_PIPELINE
        
        # Check security environment
        security_env = environment.get('security_environment', 'unknown')
        if security_env == 'kali_linux':
            return DeploymentContext.SECURITY_LAB
        
        # Check system characteristics
        hardware = system_profile.get('hardware', {})
        if hardware.get('memory_total_gb', 0) > 32 and hardware.get('cpu_count', 0) > 8:
            return DeploymentContext.ENTERPRISE_SERVER
        
        # Default to local workstation
        return DeploymentContext.LOCAL_WORKSTATION
    
    def _extract_environment_characteristics(self, system_profile: Dict[str, Any]) -> Dict[str, Any]:
        """Extract environment characteristics from system profile."""
        return {
            'hardware': system_profile.get('hardware', {}),
            'android_environment': system_profile.get('android', {}),
            'security_tools': system_profile.get('security_tools', {}),
            'performance': system_profile.get('performance', {}),
            'system_environment': system_profile.get('environment', {})
        }
    
    def _determine_environment_constraints(self, 
                                         env_type: EnvironmentType, 
                                         deployment: DeploymentContext) -> Dict[str, Any]:
        """Determine environment constraints."""
        constraints = {}
        
        # Memory constraints
        if deployment == DeploymentContext.DOCKER_CONTAINER:
            constraints['max_memory_mb'] = 4096  # Conservative Docker limit
        elif deployment == DeploymentContext.CI_CD_PIPELINE:
            constraints['max_memory_mb'] = 2048  # CI/CD often has limited resources
        
        # Time constraints
        if deployment == DeploymentContext.CI_CD_PIPELINE:
            constraints['max_analysis_time'] = 600  # 10 minutes for CI/CD
        elif env_type == EnvironmentType.TESTING:
            constraints['max_analysis_time'] = 300  # 5 minutes for testing
        
        # Network constraints
        if env_type == EnvironmentType.PRODUCTION:
            constraints['allow_network_access'] = False  # Restrict network in production
        
        # Security constraints
        if env_type == EnvironmentType.PRODUCTION:
            constraints['debug_mode'] = False
            constraints['verbose_logging'] = False
        
        return constraints
    
    def _determine_environment_optimizations(self, system_profile: Dict[str, Any]) -> Dict[str, Any]:
        """Determine environment-specific optimizations."""
        optimizations = {}
        hardware = system_profile.get('hardware', {})
        
        # CPU optimizations
        cpu_count = hardware.get('cpu_count', 4)
        if cpu_count >= 16:
            optimizations['parallel_strategy'] = 'aggressive'
            optimizations['max_workers'] = min(cpu_count - 2, 24)
        elif cpu_count >= 8:
            optimizations['parallel_strategy'] = 'moderate'
            optimizations['max_workers'] = cpu_count - 1
        else:
            optimizations['parallel_strategy'] = 'conservative'
            optimizations['max_workers'] = max(2, cpu_count)
        
        # Memory optimizations
        memory_gb = hardware.get('memory_total_gb', 8)
        if memory_gb >= 32:
            optimizations['cache_strategy'] = 'aggressive'
            optimizations['cache_size_mb'] = 2048
        elif memory_gb >= 16:
            optimizations['cache_strategy'] = 'moderate'
            optimizations['cache_size_mb'] = 1024
        else:
            optimizations['cache_strategy'] = 'conservative'
            optimizations['cache_size_mb'] = 512
        
        # Storage optimizations
        performance = system_profile.get('performance', {})
        disk_speed = performance.get('disk_io_speed', 100)
        if disk_speed > 500:  # Fast SSD
            optimizations['io_strategy'] = 'aggressive'
            optimizations['batch_size'] = 'large'
        elif disk_speed > 100:  # Regular SSD
            optimizations['io_strategy'] = 'moderate'
            optimizations['batch_size'] = 'medium'
        else:  # HDD
            optimizations['io_strategy'] = 'conservative'
            optimizations['batch_size'] = 'small'
        
        return optimizations
    
    def _determine_security_level(self, env_type: EnvironmentType, deployment: DeploymentContext) -> str:
        """Determine appropriate security level."""
        if env_type == EnvironmentType.PRODUCTION:
            return 'high'
        elif deployment == DeploymentContext.SECURITY_LAB:
            return 'enhanced'
        elif env_type in [EnvironmentType.STAGING, EnvironmentType.TESTING]:
            return 'standard'
        else:
            return 'relaxed'
    
    def _determine_performance_profile(self, system_profile: Dict[str, Any]) -> str:
        """Determine appropriate performance profile."""
        hardware = system_profile.get('hardware', {})
        
        cpu_count = hardware.get('cpu_count', 4)
        memory_gb = hardware.get('memory_total_gb', 8)
        
        # High-performance systems
        if cpu_count >= 16 and memory_gb >= 32:
            return 'high_performance'
        # Standard systems
        elif cpu_count >= 8 and memory_gb >= 16:
            return 'balanced'
        # Resource-constrained systems
        elif cpu_count >= 4 and memory_gb >= 8:
            return 'conservative'
        # Very limited systems
        else:
            return 'minimal'
    
    def _load_environment_profiles(self) -> Dict[str, EnvironmentProfile]:
        """Load predefined environment profiles."""
        profiles = {}
        
        # Development profile
        profiles['development'] = EnvironmentProfile(
            name='development',
            environment_type=EnvironmentType.DEVELOPMENT,
            deployment_context=DeploymentContext.LOCAL_WORKSTATION,
            characteristics={'debug_friendly': True, 'fast_iteration': True},
            constraints={'max_analysis_time': 120},
            optimizations={'cache_strategy': 'moderate'},
            security_level='relaxed',
            performance_profile='balanced'
        )
        
        # Testing profile
        profiles['testing'] = EnvironmentProfile(
            name='testing',
            environment_type=EnvironmentType.TESTING,
            deployment_context=DeploymentContext.CI_CD_PIPELINE,
            characteristics={'automated': True, 'time_limited': True},
            constraints={'max_analysis_time': 300, 'max_memory_mb': 2048},
            optimizations={'parallel_strategy': 'moderate'},
            security_level='standard',
            performance_profile='conservative'
        )
        
        # Production profile
        profiles['production'] = EnvironmentProfile(
            name='production',
            environment_type=EnvironmentType.PRODUCTION,
            deployment_context=DeploymentContext.ENTERPRISE_SERVER,
            characteristics={'high_security': True, 'reliable': True},
            constraints={'debug_mode': False, 'allow_network_access': False},
            optimizations={'cache_strategy': 'aggressive'},
            security_level='high',
            performance_profile='high_performance'
        )
        
        return profiles
    
    def _get_named_environment_profile(self, name: str) -> EnvironmentProfile:
        """Get environment profile by name."""
        if name in self.environment_profiles:
            return self.environment_profiles[name]
        else:
            raise ConfigurationError(f"Unknown environment profile: {name}")
    
    def _load_base_configuration(self) -> Dict[str, Any]:
        """Load base AODS configuration."""
        try:
            config_sources = [
                self.base_config_path / 'aods.yaml',
                self.base_config_path / 'aods.yml',
                self.base_config_path / 'aods.json',
                Path('aods.yaml'),
                Path('aods.yml'),
                Path('aods.json')
            ]
            
            existing_sources = [ConfigSource(path=path, format='auto', required=False) 
                              for path in config_sources if path.exists()]
            
            if existing_sources:
                loaded_config = self.config_loader.load_configuration(existing_sources)
                return loaded_config.data
            else:
                logger.warning("No base configuration found, using defaults")
                return self._get_default_configuration()
                
        except Exception as e:
            logger.error(f"Failed to load base configuration: {e}")
            return self._get_default_configuration()
    
    def _load_environment_overrides(self, profile: EnvironmentProfile) -> Dict[str, Any]:
        """Load environment-specific configuration overrides."""
        try:
            override_files = [
                self.base_config_path / 'environments' / f'{profile.environment_type.value}.yaml',
                self.base_config_path / 'environments' / f'{profile.deployment_context.value}.yaml',
                self.base_config_path / 'environments' / f'{profile.name}.yaml'
            ]
            
            overrides = {}
            for override_file in override_files:
                if override_file.exists():
                    try:
                        loaded = self.config_loader.load_configuration([
                            ConfigSource(path=override_file, format='auto', required=False)
                        ])
                        overrides = self._deep_merge(overrides, loaded.data)
                    except Exception as e:
                        logger.warning(f"Failed to load environment override {override_file}: {e}")
            
            return overrides
            
        except Exception as e:
            logger.error(f"Failed to load environment overrides: {e}")
            return {}
    
    def _generate_runtime_adjustments(self, profile: EnvironmentProfile) -> Dict[str, Any]:
        """Generate runtime configuration adjustments."""
        adjustments = {}
        
        # Apply constraints
        adjustments.update(profile.constraints)
        
        # Apply optimizations
        adjustments.update(profile.optimizations)
        
        # Security adjustments
        if profile.security_level == 'high':
            adjustments.update({
                'debug_mode': False,
                'verbose_logging': False,
                'enable_telemetry': False
            })
        elif profile.security_level == 'relaxed':
            adjustments.update({
                'debug_mode': True,
                'verbose_logging': True
            })
        
        # Performance adjustments
        if profile.performance_profile == 'minimal':
            adjustments.update({
                'enable_parallel_processing': False,
                'cache_enabled': False,
                'deep_analysis': False
            })
        elif profile.performance_profile == 'high_performance':
            adjustments.update({
                'enable_parallel_processing': True,
                'cache_enabled': True,
                'deep_analysis': True,
                'aggressive_optimization': True
            })
        
        return adjustments
    
    def _get_fallback_environment(self) -> EnvironmentProfile:
        """Get fallback environment profile."""
        return EnvironmentProfile(
            name='fallback',
            environment_type=EnvironmentType.UNKNOWN,
            deployment_context=DeploymentContext.UNKNOWN,
            security_level='standard',
            performance_profile='conservative'
        )
    
    def _get_default_configuration(self) -> Dict[str, Any]:
        """Get default AODS configuration."""
        return {
            'analysis': {
                'mode': 'hybrid',
                'enable_static': True,
                'enable_dynamic': True,
                'deep_analysis': True
            },
            'performance': {
                'max_memory_mb': 4096,
                'max_threads': 4,
                'timeout_seconds': 300,
                'cache_enabled': True
            },
            'security': {
                'debug_mode': False,
                'verbose_logging': False
            },
            'dynamic_analysis': {
                'frida': {
                    'auto_install_enabled': True,
                    'server_install_timeout': 120,
                    'fallback_version': '16.1.4',
                    'supported_architectures': ['arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86'],
                    'download_timeout': 60,
                    'github_releases_url': 'https://api.github.com/repos/frida/frida/releases/latest'
                }
            }
        }
    
    def _deep_merge(self, base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()
        
        for key, value in overlay.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    # Health check methods
    def _check_system_resources(self, profile: EnvironmentProfile) -> Dict[str, Any]:
        """Check system resource availability."""
        try:
            system_detector = get_system_detector()
            hardware = system_detector.detect_hardware_capabilities()
            
            # Check memory
            min_memory_gb = profile.constraints.get('min_memory_gb', 2)
            memory_ok = hardware.memory_available_gb >= min_memory_gb
            
            # Check CPU
            min_cpu_count = profile.constraints.get('min_cpu_count', 2)
            cpu_ok = hardware.cpu_count >= min_cpu_count
            
            # Check storage
            min_storage_gb = profile.constraints.get('min_storage_gb', 10)
            storage_ok = hardware.storage_available_gb >= min_storage_gb
            
            return {
                'passed': memory_ok and cpu_ok and storage_ok,
                'details': {
                    'memory': {'available_gb': hardware.memory_available_gb, 'sufficient': memory_ok},
                    'cpu': {'count': hardware.cpu_count, 'sufficient': cpu_ok},
                    'storage': {'available_gb': hardware.storage_available_gb, 'sufficient': storage_ok}
                }
            }
            
        except Exception as e:
            return {'passed': False, 'error': str(e)}
    
    def _check_configuration_validity(self, profile: EnvironmentProfile) -> Dict[str, Any]:
        """Check configuration validity."""
        try:
            env_config = self.get_environment_configuration(profile.name)
            validation_result = env_config.validation_result
            
            return {
                'passed': validation_result.is_valid if validation_result else False,
                'errors': len(validation_result.get_errors()) if validation_result else 0,
                'warnings': len(validation_result.get_warnings()) if validation_result else 0
            }
            
        except Exception as e:
            return {'passed': False, 'error': str(e)}
    
    def _check_security_configuration(self, profile: EnvironmentProfile) -> Dict[str, Any]:
        """Check security configuration."""
        try:
            # Basic security checks based on environment type
            checks = []
            
            if profile.environment_type == EnvironmentType.PRODUCTION:
                # Production should have strict security
                checks.append(('debug_mode_disabled', profile.constraints.get('debug_mode', True) == False))
                checks.append(('network_restricted', profile.constraints.get('allow_network_access', True) == False))
            
            passed_checks = sum(1 for _, passed in checks if passed)
            total_checks = len(checks)
            
            return {
                'passed': passed_checks == total_checks,
                'passed_checks': passed_checks,
                'total_checks': total_checks,
                'details': dict(checks)
            }
            
        except Exception as e:
            return {'passed': False, 'error': str(e)}
    
    def _check_performance_configuration(self, profile: EnvironmentProfile) -> Dict[str, Any]:
        """Check performance configuration."""
        try:
            # Check if performance settings are reasonable
            optimizations = profile.optimizations
            
            checks = []
            checks.append(('has_parallel_strategy', 'parallel_strategy' in optimizations))
            checks.append(('has_cache_strategy', 'cache_strategy' in optimizations))
            checks.append(('has_worker_config', 'max_workers' in optimizations))
            
            passed_checks = sum(1 for _, passed in checks if passed)
            total_checks = len(checks)
            
            return {
                'passed': passed_checks >= total_checks * 0.7,  # 70% of checks should pass
                'passed_checks': passed_checks,
                'total_checks': total_checks,
                'details': dict(checks)
            }
            
        except Exception as e:
            return {'passed': False, 'error': str(e)}
    
    def _check_tool_availability(self, profile: EnvironmentProfile) -> Dict[str, Any]:
        """Check availability of required tools."""
        try:
            system_detector = get_system_detector()
            android_env = system_detector.detect_android_environment()
            
            # Check critical tools
            checks = []
            checks.append(('adb_available', android_env.has_adb))
            checks.append(('aapt_available', android_env.has_aapt))
            checks.append(('jadx_available', android_env.has_jadx))
            
            # Frida is optional but recommended
            if android_env.has_frida:
                checks.append(('frida_available', True))
            
            passed_checks = sum(1 for _, passed in checks if passed)
            total_checks = len(checks)
            
            return {
                'passed': passed_checks >= 2,  # At least 2 critical tools should be available
                'passed_checks': passed_checks,
                'total_checks': total_checks,
                'details': dict(checks)
            }
            
        except Exception as e:
            return {'passed': False, 'error': str(e)}

# Global environment manager instance
_environment_manager = None

def get_environment_manager() -> EnvironmentManager:
    """Get global environment manager instance."""
    global _environment_manager
    if _environment_manager is None:
        _environment_manager = EnvironmentManager()
    return _environment_manager

def detect_current_environment() -> EnvironmentProfile:
    """Detect current environment using global manager."""
    return get_environment_manager().detect_current_environment()

def get_environment_configuration(**kwargs) -> EnvironmentConfiguration:
    """Get environment configuration using global manager."""
    return get_environment_manager().get_environment_configuration(**kwargs) 