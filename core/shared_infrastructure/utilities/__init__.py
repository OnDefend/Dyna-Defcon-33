#!/usr/bin/env python3
"""
AODS Shared Infrastructure Utilities Package

This package provides comprehensive utility functions and helpers used across
all AODS plugins and components. The utilities are organized into specialized
modules for optimal performance and maintainability.

Modules:
- apk_parsers: APK parsing and analysis utilities
- validation_helpers: Input validation and security helpers
- crypto_utilities: Cryptographic operations and security analysis
- file_handlers: File I/O and processing utilities (from shared_infrastructure)
- data_transformers: Data transformation and parsing utilities (from shared_infrastructure)

These utilities provide standardized, efficient, and secure operations for
all AODS components, ensuring consistency and reliability across the framework.
"""

from typing import Dict, List, Any, Optional

# APK parsing utilities
from .apk_parsers import (
    # Core implemented classes
    APKValidator,      # Comprehensive APK validation system
    APKAnalyzer,       # High-level APK analysis orchestrator
    APKParser,         # Main parser class
    ManifestParser,    # Specialized Android manifest parser
    
    # Newly implemented shared infrastructure components
    CertificateAnalyzer,      # Certificate validation and analysis
    DEXAnalyzer,              # DEX file analysis and inspection
    NativeLibraryAnalyzer,    # Native library security analysis
    APKStructureAnalyzer,     # APK structure and integrity analysis
    APKSecurityAnalysis,      # Comprehensive security analysis framework
    
    # Global convenience functions
    parse_apk,
    validate_apk,
    extract_apk_metadata,
    parse_manifest,
    get_apk_parser,
    get_manifest_parser,
    
    # Data structures and enums
    APKValidationResult,
    ArchitectureType,
    APKMetadata,
    APKAnalysisResult,
    CertificateInfo,
    ManifestPermission,
    ManifestComponent,
    NativeLibraryInfo,
    DEXInfo,
    APKStructureInfo,
    APKSecurityAnalysisResult
)

# Validation utilities
from .validation_helpers import (
    SecurityValidator,
    InputValidator,  # Universal input validation utilities
    DataTypeValidator,
    NetworkValidator,
    FileSystemValidator,
    AndroidValidator,  # Available as AndroidValidator (not AndroidSpecificValidator)
    PatternValidator,
    EncodingValidator,
    ValidationResult,
    ValidationSeverity,
)

# Cryptographic utilities
from .crypto_utilities import (
    CryptoSecurityAnalyzer,
    # CryptoAnalyzer,  # TODO: Not found - available as CryptoSecurityAnalyzer
    HashingUtils,
    # SecurityHasher,  # TODO: Not found - available as HashingUtils
    SecureRandomGenerator,
    # RandomGenerator,  # TODO: Not found - available as SecureRandomGenerator
    EncodingUtils,
    # EncodingManager,  # TODO: Not found - available as EncodingUtils
    PasswordHashAnalyzer,
    # PasswordStrengthAnalyzer,  # TODO: Not found - available as PasswordHashAnalyzer
    HashAnalysisResult,
    CryptoPatternMatch,
    HashAlgorithmStrength,
    EncryptionStrength,
    # CryptoValidationResult,  # TODO: Not found - can use HashAnalysisResult
)

# Import file handlers and data transformers from parent shared_infrastructure
try:
    from ..file_handlers import (
        FileTypeDetector,
        SafeFileReader,
        APKFileExtractor,
        DirectoryAnalyzer,
        StringExtractor,
        PathUtils
    )
    FILE_HANDLERS_AVAILABLE = True
except ImportError:
    FILE_HANDLERS_AVAILABLE = False

try:
    from ..data_transformers import (
        CompiledPattern,
        PatternCompiler,
        ContentParser,
        DataValidator,
        EncodingUtils as DataEncodingUtils,
        ContentAnalyzer
    )
    DATA_TRANSFORMERS_AVAILABLE = True
except ImportError:
    DATA_TRANSFORMERS_AVAILABLE = False

# Export all utility classes and functions
__all__ = [
    # APK parsing utilities
    'APKValidator',
    'APKAnalyzer', 
    'ManifestParser',
    'CertificateAnalyzer',
    'DEXAnalyzer',
    'NativeLibraryAnalyzer',
    'APKStructureAnalyzer',
    'APKValidationResult',
    'APKSecurityAnalysis',
    'AndroidManifest',
    'CertificateInfo',
    'DEXFileInfo',
    'NativeLibraryInfo',
    
    # Global convenience functions
    'parse_apk',
    'validate_apk',
    'extract_apk_metadata',
    'parse_manifest',
    'get_apk_parser',
    'get_manifest_parser',
    
    # Validation utilities
    'SecurityValidator',
    'InputValidator',
    'DataTypeValidator',
    'NetworkValidator',
    'FileSystemValidator',
    'AndroidSpecificValidator',
    'PatternValidator',
    'EncodingValidator',
    'ValidationResult',
    'ValidationSeverity',
    'SecurityValidationContext',
    
    # Cryptographic utilities
    'CryptoSecurityAnalyzer',
    'HashingUtils',
    'SecureRandomGenerator',
    'EncodingUtils',
    'PasswordHashAnalyzer',
    'HashAlgorithmStrength',
    'EncryptionStrength',
    'HashAnalysisResult',
    'CryptoPatternMatch',
    'analyze_crypto_content',
    'calculate_content_hash',
    'calculate_file_hash',
    'generate_secure_key',
    'analyze_password_hash',
    'crypto_analyzer',
    'password_analyzer'
]

# Conditionally add file handlers if available
if FILE_HANDLERS_AVAILABLE:
    __all__.extend([
        'FileTypeDetector',
        'SafeFileReader',
        'APKFileExtractor',
        'DirectoryAnalyzer',
        'StringExtractor',
        'PathUtils'
    ])

# Conditionally add data transformers if available
if DATA_TRANSFORMERS_AVAILABLE:
    __all__.extend([
        'CompiledPattern',
        'PatternCompiler',
        'ContentParser',
        'DataValidator',
        'DataEncodingUtils',
        'ContentAnalyzer'
    ])

# Package metadata
__version__ = "2.0.0"
__author__ = "AODS Development Team"
__description__ = "Comprehensive utilities package for AODS framework"
__category__ = "SHARED_INFRASTRUCTURE"

# Utility summary for documentation
UTILITY_CATEGORIES = {
    'apk_analysis': [
        'APKValidator', 'APKAnalyzer', 'ManifestParser', 
        'CertificateAnalyzer', 'DEXAnalyzer', 'NativeLibraryAnalyzer'
    ],
    'validation': [
        'SecurityValidator', 'InputValidator', 'DataTypeValidator',
        'NetworkValidator', 'FileSystemValidator', 'AndroidSpecificValidator'
    ],
    'cryptography': [
        'CryptoSecurityAnalyzer', 'HashingUtils', 'SecureRandomGenerator',
        'PasswordHashAnalyzer', 'EncodingUtils'
    ],
    'file_operations': [
        'FileTypeDetector', 'SafeFileReader', 'APKFileExtractor',
        'DirectoryAnalyzer', 'StringExtractor', 'PathUtils'
    ],
    'data_processing': [
        'PatternCompiler', 'ContentParser', 'DataValidator',
        'ContentAnalyzer', 'CompiledPattern'
    ]
}

def get_available_utilities() -> Dict[str, List[str]]:
    """
    Get a summary of available utilities organized by category.
    
    Returns:
        Dict[str, List[str]]: Dictionary of categories and their utilities
    """
    available = {}
    
    for category, utilities in UTILITY_CATEGORIES.items():
        available_utilities = []
        for utility in utilities:
            if utility in globals():
                available_utilities.append(utility)
        
        if available_utilities:
            available[category] = available_utilities
    
    return available

def create_utility_context(**kwargs) -> Dict[str, Any]:
    """
    Create a utility context with commonly used utility instances.
    
    Args:
        **kwargs: Additional context parameters
        
    Returns:
        Dict[str, Any]: Utility context dictionary
    """
    context = {
        'crypto_analyzer': crypto_analyzer,
        'password_analyzer': password_analyzer,
        'file_handlers_available': FILE_HANDLERS_AVAILABLE,
        'data_transformers_available': DATA_TRANSFORMERS_AVAILABLE,
        'utilities_version': __version__
    }
    
    context.update(kwargs)
    return context 