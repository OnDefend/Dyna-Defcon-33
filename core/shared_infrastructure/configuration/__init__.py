#!/usr/bin/env python3
"""
AODS Unified Configuration Framework

Comprehensive configuration management system that provides:
- System detection and hardware capability analysis
- Multi-format configuration loading (YAML, JSON, TOML, INI)
- Comprehensive validation with schema and business rules
- Environment-specific adaptation and optimization
- Hot-reload capabilities and caching
- Security and performance tuning

This framework replaces and enhances the existing core/config_management
with a more comprehensive, production-ready configuration system.

Key Components:
- SystemDetector: Hardware and environment analysis
- ConfigurationLoader: Multi-format configuration loading
- ConfigurationValidator: Comprehensive validation framework
- EnvironmentManager: Environment-specific adaptation

Usage:
    from core.shared_infrastructure.configuration import (
        get_system_detector,
        get_config_loader,
        get_config_validator,
        get_environment_manager
    )
    
    # Detect system capabilities
    system_profile = get_system_detector().get_complete_system_profile()
    
    # Load configuration
    config = get_config_loader().load_configuration(['config.yaml'])
    
    # Validate configuration
    validation = get_config_validator().validate_configuration(config.data)
    
    # Get environment-specific configuration
    env_config = get_environment_manager().get_environment_configuration()
"""

# System detection components
from .system_detection import (
    SystemDetector,
    HardwareCapabilities,
    SystemEnvironment,
    AndroidEnvironment,
    PerformanceCharacteristics,
    OSType,
    VirtualizationType,
    SecurityEnvironment,
    get_system_detector,
    detect_system_profile,
    get_hardware_capabilities,
    get_android_environment
)

# Configuration loading components
from .config_loader import (
    ConfigurationLoader,
    ConfigSource,
    LoadedConfiguration,
    ConfigFormat,
    ConfigMergeStrategy,
    get_config_loader,
    load_configuration,
    load_plugin_configuration
)

# Configuration validation components
from .validation import (
    ConfigurationValidator,
    ValidationResult,
    ValidationIssue,
    ValidationSeverity,
    ValidationType,
    get_config_validator,
    validate_configuration
)

# Environment management components
from .environment_manager import (
    EnvironmentManager,
    EnvironmentProfile,
    EnvironmentConfiguration,
    EnvironmentType,
    DeploymentContext,
    get_environment_manager,
    detect_current_environment,
    get_environment_configuration
)

# Version information
__version__ = "1.0.0"
__author__ = "AODS Development Team"
__description__ = "Unified Configuration Framework for AODS Shared Infrastructure"

# Public API exports
__all__ = [
    # System Detection
    'SystemDetector',
    'HardwareCapabilities',
    'SystemEnvironment',
    'AndroidEnvironment',
    'PerformanceCharacteristics',
    'OSType',
    'VirtualizationType',
    'SecurityEnvironment',
    'get_system_detector',
    'detect_system_profile',
    'get_hardware_capabilities',
    'get_android_environment',
    
    # Configuration Loading
    'ConfigurationLoader',
    'ConfigSource',
    'LoadedConfiguration',
    'ConfigFormat',
    'ConfigMergeStrategy',
    'get_config_loader',
    'load_configuration',
    'load_plugin_configuration',
    
    # Configuration Validation
    'ConfigurationValidator',
    'ValidationResult',
    'ValidationIssue',
    'ValidationSeverity',
    'ValidationType',
    'get_config_validator',
    'validate_configuration',
    
    # Environment Management
    'EnvironmentManager',
    'EnvironmentProfile',
    'EnvironmentConfiguration',
    'EnvironmentType',
    'DeploymentContext',
    'get_environment_manager',
    'detect_current_environment',
    'get_environment_configuration'
]

# Convenience functions for common operations
def quick_load_config(config_path: str, validate: bool = True) -> LoadedConfiguration:
    """
    Quickly load and optionally validate a configuration file.
    
    Args:
        config_path: Path to configuration file
        validate: Whether to validate the configuration
        
    Returns:
        LoadedConfiguration object
    """
    from pathlib import Path
    
    loader = get_config_loader()
    config = loader.load_configuration([Path(config_path)])
    
    if validate:
        validator = get_config_validator()
        validation_result = validator.validate_configuration(config.data)
        
        if not validation_result.is_valid:
            from ..analysis_exceptions import ConfigurationError
            errors = [str(issue) for issue in validation_result.get_errors()]
            raise ConfigurationError(f"Configuration validation failed: {'; '.join(errors)}")
    
    return config

def get_optimized_config_for_environment(base_config_path: str, 
                                        environment: str = None) -> dict:
    """
    Get configuration optimized for the current or specified environment.
    
    Args:
        base_config_path: Path to base configuration
        environment: Target environment (auto-detect if None)
        
    Returns:
        Dictionary with optimized configuration
    """
    from pathlib import Path
    
    # Load base configuration
    base_config = quick_load_config(base_config_path)
    
    # Get environment manager
    env_manager = get_environment_manager()
    
    # Adapt configuration to environment
    optimized_config = env_manager.adapt_configuration_to_environment(
        base_config.data, 
        environment
    )
    
    return optimized_config

def validate_plugin_config(plugin_name: str, config_data: dict) -> ValidationResult:
    """
    Validate plugin configuration data.
    
    Args:
        plugin_name: Name of the plugin
        config_data: Plugin configuration data
        
    Returns:
        ValidationResult with validation status
    """
    validator = get_config_validator()
    return validator.validate_plugin_configuration(config_data, plugin_name)

def get_system_recommendations() -> dict:
    """
    Get system optimization recommendations based on current environment.
    
    Returns:
        Dictionary with system recommendations
    """
    detector = get_system_detector()
    profile = detector.get_complete_system_profile()
    return profile.get('recommendations', {})

def check_environment_health(environment: str = None) -> dict:
    """
    Check health of current or specified environment.
    
    Args:
        environment: Environment to check (current if None)
        
    Returns:
        Dictionary with health check results
    """
    env_manager = get_environment_manager()
    return env_manager.validate_environment_health(environment)

# Integration helper for existing config_management
def migrate_from_legacy_config(legacy_config_path: str = None) -> dict:
    """
    Helper function to migrate from legacy config_management to new framework.
    
    Args:
        legacy_config_path: Path to legacy configuration (auto-detect if None)
        
    Returns:
        Dictionary with migrated configuration
    """
    from pathlib import Path
    
    # Try to find legacy configuration
    if legacy_config_path is None:
        legacy_paths = [
            Path('config'),
            Path('core/config_management'),
            Path('plugins')
        ]
        
        for path in legacy_paths:
            if path.exists() and path.is_dir():
                legacy_config_path = str(path)
                break
    
    if legacy_config_path is None:
        return {}
    
    # Load legacy configurations
    loader = get_config_loader()
    legacy_files = list(Path(legacy_config_path).rglob('*.yaml')) + \
                   list(Path(legacy_config_path).rglob('*.yml')) + \
                   list(Path(legacy_config_path).rglob('*.json'))
    
    if not legacy_files:
        return {}
    
    # Create configuration sources
    sources = [ConfigSource(path=file_path, format=ConfigFormat.AUTO, required=False) 
               for file_path in legacy_files]
    
    # Load and merge configurations
    try:
        merged_config = loader.load_configuration(sources, merge_strategy=ConfigMergeStrategy.DEEP_MERGE)
        return merged_config.data
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to migrate legacy configuration: {e}")
        return {}

# Framework initialization
def initialize_configuration_framework(base_config_path: str = None, 
                                     auto_detect_environment: bool = True) -> dict:
    """
    Initialize the configuration framework with optional base configuration.
    
    Args:
        base_config_path: Base configuration directory path
        auto_detect_environment: Whether to auto-detect environment
        
    Returns:
        Dictionary with initialization results
    """
    from pathlib import Path
    import logging
    
    logger = logging.getLogger(__name__)
    results = {
        'system_detection': False,
        'configuration_loading': False,
        'environment_detection': False,
        'validation': False,
        'errors': [],
        'warnings': []
    }
    
    try:
        # Initialize system detection
        detector = get_system_detector()
        system_profile = detector.get_complete_system_profile()
        results['system_detection'] = True
        logger.info("System detection initialized successfully")
        
        # Initialize configuration loading
        if base_config_path:
            loader = get_config_loader()
            # Test configuration loading
            test_sources = []
            base_path = Path(base_config_path)
            if base_path.exists():
                test_files = list(base_path.rglob('*.yaml')) + list(base_path.rglob('*.json'))
                if test_files:
                    test_sources = [ConfigSource(path=f, format=ConfigFormat.AUTO, required=False) 
                                  for f in test_files[:3]]  # Test with first 3 files
            
            if test_sources:
                test_config = loader.load_configuration(test_sources)
                results['configuration_loading'] = True
                logger.info("Configuration loading initialized successfully")
        
        # Initialize environment detection
        if auto_detect_environment:
            env_manager = get_environment_manager()
            current_env = env_manager.detect_current_environment()
            results['environment_detection'] = True
            logger.info(f"Environment detection initialized - detected: {current_env.name}")
        
        # Initialize validation
        validator = get_config_validator()
        # Test validation with a simple config
        test_validation = validator.validate_configuration({'test': True})
        results['validation'] = True
        logger.info("Configuration validation initialized successfully")
        
    except Exception as e:
        error_msg = f"Framework initialization failed: {e}"
        results['errors'].append(error_msg)
        logger.error(error_msg)
    
    return results 