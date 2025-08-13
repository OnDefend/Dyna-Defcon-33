#!/usr/bin/env python3
"""
Deduplication Configuration Manager
==================================

This module provides centralized configuration management for deduplication strategies
across the entire AODS system, addressing the current hardcoded inconsistencies.

CRITICAL: This replaces the current hardcoded strategy selections with a
configurable, auditable, and secure configuration system.
"""

import logging
import os
from typing import Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass, field

from core.unified_deduplication_framework import DeduplicationStrategy

class DeduplicationSecurityLevel(Enum):
    """Security levels for deduplication configuration."""
    DEVELOPMENT = "development"      # All options allowed
    STAGING = "staging"             # Restricted options
    PRODUCTION = "production"       # Highly restricted, audited

@dataclass
class DeduplicationConfig:
    """Centralized deduplication configuration."""
    strategy: DeduplicationStrategy = DeduplicationStrategy.AGGRESSIVE
    preserve_evidence: bool = True
    similarity_threshold: float = 0.85
    disabled: bool = False
    security_level: DeduplicationSecurityLevel = DeduplicationSecurityLevel.DEVELOPMENT
    audit_changes: bool = True
    
    # Strategy-specific overrides
    strategy_overrides: Dict[str, DeduplicationStrategy] = field(default_factory=dict)
    
    # Security constraints
    min_threshold: float = 0.6
    max_threshold: float = 0.95
    allow_disable: bool = True

class DeduplicationConfigManager:
    """
    Centralized manager for deduplication configuration across AODS.
    
    This addresses the current problem of inconsistent hardcoded strategies
    by providing a single source of truth for deduplication configuration.
    """
    
    def __init__(self):
        """Initialize the deduplication configuration manager."""
        self.logger = logging.getLogger(__name__)
        self._config = DeduplicationConfig()
        self._component_strategies = {}  # Track per-component strategy usage
        self._change_audit_log = []      # Audit trail for configuration changes
        
        self.logger.info("🔧 **DEDUPLICATION CONFIG MANAGER INITIALIZED**")
    
    def configure_from_cli_args(self, args):
        """
        Configure deduplication from CLI arguments.
        
        Args:
            args: Parsed CLI arguments from argparse
        """
        # Map CLI strategy names to enum values
        strategy_map = {
            "basic": DeduplicationStrategy.BASIC,
            "intelligent": DeduplicationStrategy.INTELLIGENT,
            "aggressive": DeduplicationStrategy.AGGRESSIVE,
            "conservative": DeduplicationStrategy.CONSERVATIVE
        }
        
        # Apply CLI configuration if arguments exist
        if hasattr(args, 'dedup_strategy') and args.dedup_strategy:
            old_strategy = self._config.strategy
            self._config.strategy = strategy_map[args.dedup_strategy]
            self._audit_change('strategy', old_strategy, self._config.strategy, 'cli_argument')
        
        if hasattr(args, 'preserve_evidence'):
            old_preserve = self._config.preserve_evidence
            self._config.preserve_evidence = args.preserve_evidence
            self._audit_change('preserve_evidence', old_preserve, self._config.preserve_evidence, 'cli_argument')
        
        if hasattr(args, 'dedup_threshold') and args.dedup_threshold:
            old_threshold = self._config.similarity_threshold
            self._config.similarity_threshold = args.dedup_threshold
            self._audit_change('similarity_threshold', old_threshold, self._config.similarity_threshold, 'cli_argument')
        
        if hasattr(args, 'disable_deduplication'):
            old_disabled = self._config.disabled
            self._config.disabled = args.disable_deduplication
            self._audit_change('disabled', old_disabled, self._config.disabled, 'cli_argument')
        
        # Set security level based on environment
        if hasattr(args, 'environment') and args.environment:
            self._config.security_level = DeduplicationSecurityLevel(args.environment)
        
        # Validate configuration
        self._validate_configuration()
        
        self.logger.info(f"🔧 **DEDUPLICATION CONFIGURED FROM CLI**:")
        self.logger.info(f"   - Strategy: {self._config.strategy.value}")
        self.logger.info(f"   - Preserve Evidence: {self._config.preserve_evidence}")
        self.logger.info(f"   - Threshold: {self._config.similarity_threshold}")
        self.logger.info(f"   - Disabled: {self._config.disabled}")
    
    def get_strategy_for_component(self, component_name: str) -> DeduplicationStrategy:
        """
        Get the appropriate deduplication strategy for a specific component.
        
        This replaces the current hardcoded strategy selections.
        
        Args:
            component_name: Name of the component requesting strategy
            
        Returns:
            DeduplicationStrategy: The configured strategy for this component
        """
        # Check for component-specific override
        if component_name in self._config.strategy_overrides:
            strategy = self._config.strategy_overrides[component_name]
            self.logger.debug(f"🎯 Component {component_name}: Using override strategy {strategy.value}")
        else:
            strategy = self._config.strategy
            self.logger.debug(f"🎯 Component {component_name}: Using default strategy {strategy.value}")
        
        # Track component usage for auditing
        self._component_strategies[component_name] = strategy
        
        return strategy
    
    def is_deduplication_enabled(self) -> bool:
        """Check if deduplication is enabled."""
        return not self._config.disabled
    
    def get_similarity_threshold(self) -> float:
        """Get the configured similarity threshold."""
        return self._config.similarity_threshold
    
    def should_preserve_evidence(self) -> bool:
        """Check if evidence preservation is enabled."""
        return self._config.preserve_evidence
    
    def set_component_strategy_override(self, 
                                      component_name: str, 
                                      strategy: DeduplicationStrategy,
                                      reason: str = "manual_override"):
        """
        Set a component-specific strategy override.
        
        Args:
            component_name: Name of component to override
            strategy: Strategy to use for this component
            reason: Reason for the override (for auditing)
        """
        old_strategy = self._config.strategy_overrides.get(component_name, self._config.strategy)
        self._config.strategy_overrides[component_name] = strategy
        
        self._audit_change(f'component_override_{component_name}', old_strategy, strategy, reason)
        
        self.logger.info(f"🎯 **COMPONENT OVERRIDE SET**:")
        self.logger.info(f"   - Component: {component_name}")
        self.logger.info(f"   - Strategy: {strategy.value}")
        self.logger.info(f"   - Reason: {reason}")
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """Get a summary of the current deduplication configuration."""
        return {
            'global_strategy': self._config.strategy.value,
            'preserve_evidence': self._config.preserve_evidence,
            'similarity_threshold': self._config.similarity_threshold,
            'disabled': self._config.disabled,
            'security_level': self._config.security_level.value,
            'component_overrides': {
                comp: strategy.value for comp, strategy in self._config.strategy_overrides.items()
            },
            'component_usage': {
                comp: strategy.value for comp, strategy in self._component_strategies.items()
            },
            'audit_log_entries': len(self._change_audit_log)
        }
    
    def get_audit_log(self) -> list:
        """Get the audit log of configuration changes."""
        return self._change_audit_log.copy()
    
    def _validate_configuration(self):
        """Validate the deduplication configuration for security and consistency."""
        # Security level validations
        if self._config.security_level == DeduplicationSecurityLevel.PRODUCTION:
            if self._config.disabled:
                raise ValueError("Deduplication cannot be disabled in production environment")
            
            if self._config.similarity_threshold < 0.7:
                raise ValueError(f"Similarity threshold {self._config.similarity_threshold} too low for production")
        
        # General validations
        if self._config.similarity_threshold < self._config.min_threshold:
            raise ValueError(f"Similarity threshold {self._config.similarity_threshold} below minimum {self._config.min_threshold}")
        
        if self._config.similarity_threshold > self._config.max_threshold:
            raise ValueError(f"Similarity threshold {self._config.similarity_threshold} above maximum {self._config.max_threshold}")
        
        # Security warnings
        if self._config.disabled:
            self.logger.warning("🚨 **SECURITY WARNING**: Deduplication is DISABLED")
            self.logger.warning("   - This will result in duplicate vulnerabilities")
            self.logger.warning("   - Report quality will be degraded")
        
        if self._config.similarity_threshold < 0.7:
            self.logger.warning(f"⚠️  **LOW THRESHOLD WARNING**: {self._config.similarity_threshold}")
            self.logger.warning("   - May miss obvious duplicates")
        
        if self._config.similarity_threshold > 0.9:
            self.logger.warning(f"⚠️  **HIGH THRESHOLD WARNING**: {self._config.similarity_threshold}")
            self.logger.warning("   - May incorrectly merge different vulnerabilities")
    
    def _audit_change(self, property_name: str, old_value: Any, new_value: Any, source: str):
        """Audit a configuration change."""
        if not self._config.audit_changes:
            return
        
        import time
        
        audit_entry = {
            'timestamp': time.time(),
            'property': property_name,
            'old_value': str(old_value),
            'new_value': str(new_value),
            'source': source,
            'security_level': self._config.security_level.value
        }
        
        self._change_audit_log.append(audit_entry)
        
        self.logger.info(f"📋 **AUDIT**: {property_name} changed from {old_value} to {new_value} (source: {source})")

# Global singleton instance
_config_manager_instance = None

def get_deduplication_config_manager() -> DeduplicationConfigManager:
    """
    Get the global deduplication configuration manager instance.
    
    Returns:
        DeduplicationConfigManager: The singleton configuration manager
    """
    global _config_manager_instance
    if _config_manager_instance is None:
        _config_manager_instance = DeduplicationConfigManager()
    return _config_manager_instance

def get_strategy_for_component(component_name: str) -> DeduplicationStrategy:
    """
    **CONVENIENCE FUNCTION**: Get deduplication strategy for a component.
    
    This should replace all hardcoded strategy selections throughout AODS.
    
    Args:
        component_name: Name of the component requesting strategy
        
    Returns:
        DeduplicationStrategy: The appropriate strategy for this component
    """
    manager = get_deduplication_config_manager()
    return manager.get_strategy_for_component(component_name)

def is_deduplication_enabled() -> bool:
    """Check if deduplication is globally enabled."""
    manager = get_deduplication_config_manager()
    return manager.is_deduplication_enabled()

def configure_deduplication_from_cli(args):
    """Configure deduplication from CLI arguments."""
    manager = get_deduplication_config_manager()
    manager.configure_from_cli_args(args)