#!/usr/bin/env python3
"""
Modular Pattern Engine Package

Refactored pattern engine with enhanced modularity, validation, and maintainability.
Maintains full backwards compatibility with the original API.
"""

# Main engine components
from .engine import ModularPatternEngine, create_modular_pattern_engine

# Data models with Pydantic validation
from .models import (
    VulnerabilityPattern,
    PatternTemplate, 
    PatternMatch,
    PatternSourceConfig,
    PatternEngineConfig,
    SeverityLevel,
    PatternType,
    LanguageSupport
)

# Pattern sources
from .sources.base import PatternSource, PatternLoadError, PatternValidationError
from .sources.cve_source import CVEPatternSource
from .sources.template_source import TemplatePatternSource

# Utilities
from .generators.pattern_builder import PatternBuilder, RegexBuilder, PatternValidator

# Backwards compatibility aliases
Pattern = VulnerabilityPattern
Template = PatternTemplate
Match = PatternMatch
SourceConfig = PatternSourceConfig
EngineConfig = PatternEngineConfig

__all__ = [
    # Main engine
    'ModularPatternEngine',
    'create_modular_pattern_engine',
    
    # Data models
    'VulnerabilityPattern',
    'PatternTemplate',
    'PatternMatch', 
    'PatternSourceConfig',
    'PatternEngineConfig',
    'SeverityLevel',
    'PatternType',
    'LanguageSupport',
    
    # Pattern sources
    'PatternSource',
    'PatternLoadError',
    'PatternValidationError',
    'CVEPatternSource',
    'TemplatePatternSource',
    
    # Utilities
    'PatternBuilder',
    'RegexBuilder',
    'PatternValidator',
    
    # Backwards compatibility
    'Pattern',
    'Template',
    'Match',
    'SourceConfig',
    'EngineConfig'
]

# Version information
__version__ = "2.0.0"
__author__ = "AODS Security Team"
__description__ = "Modular vulnerability pattern detection engine" 