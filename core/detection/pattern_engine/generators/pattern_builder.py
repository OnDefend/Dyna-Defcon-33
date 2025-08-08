#!/usr/bin/env python3
"""
Pattern Builder Utilities

Reusable utilities for pattern generation that eliminate duplication across sources.
"""

import re
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from ..models import VulnerabilityPattern, PatternType, SeverityLevel, LanguageSupport

class PatternBuilder:
    """Utility class for building vulnerability patterns with consistent logic."""
    
    def __init__(self):
        """Initialize pattern builder."""
        self.logger = logging.getLogger(__name__)
    
    @staticmethod
    def create_pattern(
        pattern_id: str,
        pattern_name: str,
        pattern_regex: str,
        pattern_type: Union[PatternType, str],
        severity: Union[SeverityLevel, str],
        description: str,
        source: str,
        confidence_base: float = 0.8,
        language_support: Optional[List[Union[LanguageSupport, str]]] = None,
        context_requirements: Optional[List[str]] = None,
        false_positive_indicators: Optional[List[str]] = None,
        references: Optional[List[str]] = None,
        source_data: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> VulnerabilityPattern:
        """
        Create a vulnerability pattern with common defaults and validation.
        
        Args:
            pattern_id: Unique pattern identifier
            pattern_name: Human-readable pattern name
            pattern_regex: Regular expression pattern
            pattern_type: Type of vulnerability pattern
            severity: Severity level
            description: Pattern description
            source: Pattern source identifier
            confidence_base: Base confidence score (0.0-1.0)
            language_support: Supported programming languages
            context_requirements: Required context for pattern matching
            false_positive_indicators: Indicators suggesting false positive
            references: Reference URLs or documentation
            source_data: Source-specific metadata
            **kwargs: Additional pattern attributes
            
        Returns:
            Validated vulnerability pattern
        """
        # Convert string enums to enum types
        if isinstance(pattern_type, str):
            pattern_type = PatternType(pattern_type.lower())
        if isinstance(severity, str):
            severity = SeverityLevel(severity.upper())
            
        # Convert language support strings to enums
        if language_support:
            lang_enums = []
            for lang in language_support:
                if isinstance(lang, str):
                    lang_enums.append(LanguageSupport(lang.lower()))
                else:
                    lang_enums.append(lang)
            language_support = lang_enums
        else:
            language_support = [LanguageSupport.JAVA, LanguageSupport.KOTLIN]
        
        # Set default values
        context_requirements = context_requirements or PatternBuilder._get_default_context(pattern_type)
        false_positive_indicators = false_positive_indicators or ["test", "example", "demo", "mock", "sample"]
        references = references or []
        source_data = source_data or {}
        
        # Auto-generate CWE and MASVS mappings
        cwe_id = kwargs.get('cwe_id', PatternBuilder._map_type_to_cwe(pattern_type))
        masvs_category = kwargs.get('masvs_category', PatternBuilder._map_type_to_masvs(pattern_type))
        
        # Calculate validation score
        validation_score = kwargs.get('validation_score', min(confidence_base - 0.05, 0.95))
        
        return VulnerabilityPattern(
            pattern_id=pattern_id,
            pattern_name=pattern_name,
            pattern_regex=pattern_regex,
            pattern_type=pattern_type,
            severity=severity,
            cwe_id=cwe_id,
            masvs_category=masvs_category,
            description=description,
            confidence_base=confidence_base,
            language_support=language_support,
            context_requirements=context_requirements,
            false_positive_indicators=false_positive_indicators,
            validation_score=validation_score,
            source=source,
            source_data=source_data,
            references=references,
            **{k: v for k, v in kwargs.items() if k not in ['cwe_id', 'masvs_category', 'validation_score']}
        )
    
    @staticmethod
    def create_batch(
        pattern_definitions: List[Dict[str, Any]],
        source: str,
        id_prefix: str = "",
        **common_kwargs
    ) -> List[VulnerabilityPattern]:
        """
        Create multiple patterns from a list of definitions.
        
        Args:
            pattern_definitions: List of pattern definition dictionaries
            source: Common source identifier for all patterns
            id_prefix: Prefix for auto-generated pattern IDs
            **common_kwargs: Common attributes for all patterns
            
        Returns:
            List of validated vulnerability patterns
        """
        patterns = []
        logger = logging.getLogger(__name__)
        
        for i, definition in enumerate(pattern_definitions):
            try:
                # Generate pattern ID if not provided
                pattern_id = definition.get('pattern_id', f"{id_prefix}{i:04d}")
                
                # Merge common kwargs with definition
                pattern_kwargs = {**common_kwargs, **definition}
                pattern_kwargs['source'] = source
                pattern_kwargs['pattern_id'] = pattern_id
                
                pattern = PatternBuilder.create_pattern(**pattern_kwargs)
                patterns.append(pattern)
                
            except Exception as e:
                logger.warning(f"Failed to create pattern {i} from batch: {e}")
                
        return patterns
    
    @staticmethod
    def validate_regex(regex_pattern: str) -> bool:
        """
        Validate that a regex pattern is syntactically correct.
        
        Args:
            regex_pattern: Regular expression to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            re.compile(regex_pattern)
            return True
        except re.error:
            return False
    
    @staticmethod
    def generate_variations(
        base_pattern: Dict[str, Any],
        variations: List[Dict[str, Any]],
        source: str
    ) -> List[VulnerabilityPattern]:
        """
        Generate pattern variations from a base pattern and variation definitions.
        
        Args:
            base_pattern: Base pattern definition
            variations: List of variation modifications
            source: Pattern source identifier
            
        Returns:
            List of pattern variations
        """
        patterns = []
        logger = logging.getLogger(__name__)
        
        for i, variation in enumerate(variations):
            try:
                # Create variation by merging base with variation
                variation_def = {**base_pattern, **variation}
                variation_def['pattern_id'] = f"{base_pattern.get('pattern_id', 'var')}_{i:03d}"
                
                # Apply variation-specific transformations
                if 'regex_substitutions' in variation:
                    regex = variation_def.get('pattern_regex', '')
                    for old, new in variation['regex_substitutions'].items():
                        regex = regex.replace(old, new)
                    variation_def['pattern_regex'] = regex
                
                pattern = PatternBuilder.create_pattern(source=source, **variation_def)
                patterns.append(pattern)
                
            except Exception as e:
                logger.warning(f"Failed to create variation {i}: {e}")
                
        return patterns
    
    @staticmethod
    def _get_default_context(pattern_type: PatternType) -> List[str]:
        """Get default context requirements for a pattern type."""
        context_map = {
            PatternType.SQL_INJECTION: ["database", "user_input"],
            PatternType.PATH_TRAVERSAL: ["file_operations", "user_input"],
            PatternType.CODE_INJECTION: ["system_commands", "user_input"],
            PatternType.HARDCODED_SECRETS: ["cryptography", "authentication"],
            PatternType.WEAK_CRYPTOGRAPHY: ["cryptography"],
            PatternType.AUTHENTICATION_BYPASS: ["authentication", "authorization"],
            PatternType.INSECURE_DATA_STORAGE: ["storage", "data_handling"],
            PatternType.INSECURE_COMMUNICATION: ["network", "communication"],
            PatternType.IMPROPER_PLATFORM_USAGE: ["platform", "api_usage"],
            PatternType.WEBVIEW_SECURITY: ["web_content", "browser"],
            PatternType.INFORMATION_DISCLOSURE: ["logging", "debugging"],
            PatternType.XSS: ["web_content", "user_input"],
            PatternType.BUFFER_OVERFLOW: ["memory_management", "bounds_checking"],
            PatternType.USE_AFTER_FREE: ["memory_management", "object_lifecycle"],
            PatternType.INTEGER_OVERFLOW: ["arithmetic", "bounds_checking"],
            PatternType.DATA_LEAKAGE: ["data_handling", "privacy"]
        }
        return context_map.get(pattern_type, ["general"])
    
    @staticmethod
    def _map_type_to_cwe(pattern_type: PatternType) -> str:
        """Map pattern type to CWE ID."""
        mapping = {
            PatternType.SQL_INJECTION: "CWE-89",
            PatternType.PATH_TRAVERSAL: "CWE-22",
            PatternType.CODE_INJECTION: "CWE-78",
            PatternType.HARDCODED_SECRETS: "CWE-798",
            PatternType.WEAK_CRYPTOGRAPHY: "CWE-327",
            PatternType.AUTHENTICATION_BYPASS: "CWE-295",
            PatternType.INSECURE_DATA_STORAGE: "CWE-922",
            PatternType.INSECURE_COMMUNICATION: "CWE-319",
            PatternType.IMPROPER_PLATFORM_USAGE: "CWE-358",
            PatternType.WEBVIEW_SECURITY: "CWE-79",
            PatternType.INFORMATION_DISCLOSURE: "CWE-200",
            PatternType.XSS: "CWE-79",
            PatternType.BUFFER_OVERFLOW: "CWE-119",
            PatternType.USE_AFTER_FREE: "CWE-416",
            PatternType.INTEGER_OVERFLOW: "CWE-190",
            PatternType.DATA_LEAKAGE: "CWE-200"
        }
        return mapping.get(pattern_type, "CWE-200")
    
    @staticmethod
    def _map_type_to_masvs(pattern_type: PatternType) -> str:
        """Map pattern type to MASVS category."""
        mapping = {
            PatternType.SQL_INJECTION: "MSTG-CODE-8",
            PatternType.PATH_TRAVERSAL: "MSTG-STORAGE-2",
            PatternType.CODE_INJECTION: "MSTG-CODE-8",
            PatternType.HARDCODED_SECRETS: "MSTG-CRYPTO-1",
            PatternType.WEAK_CRYPTOGRAPHY: "MSTG-CRYPTO-4",
            PatternType.AUTHENTICATION_BYPASS: "MSTG-NETWORK-3",
            PatternType.INSECURE_DATA_STORAGE: "MSTG-STORAGE-1",
            PatternType.INSECURE_COMMUNICATION: "MSTG-NETWORK-1",
            PatternType.IMPROPER_PLATFORM_USAGE: "MSTG-PLATFORM-1",
            PatternType.WEBVIEW_SECURITY: "MSTG-PLATFORM-2",
            PatternType.INFORMATION_DISCLOSURE: "MSTG-STORAGE-1",
            PatternType.XSS: "MSTG-PLATFORM-2"
        }
        return mapping.get(pattern_type, "MSTG-CODE-8")

class RegexBuilder:
    """Utility class for building regular expressions with common patterns."""
    
    @staticmethod
    def build_method_call_pattern(
        method_name: str,
        with_user_input: bool = True,
        case_insensitive: bool = True
    ) -> str:
        """
        Build regex for method calls with optional user input detection.
        
        Args:
            method_name: Name of the method to match
            with_user_input: Whether to include user input patterns
            case_insensitive: Whether to make pattern case insensitive
            
        Returns:
            Regular expression pattern
        """
        flags = "(?i)" if case_insensitive else ""
        escaped_method = re.escape(method_name)
        
        if with_user_input:
            return f"{flags}{escaped_method}\\s*\\(\\s*[^)]*\\+[^)]*\\)"
        else:
            return f"{flags}{escaped_method}\\s*\\([^)]*\\)"
    
    @staticmethod
    def build_string_literal_pattern(
        prefix: str,
        min_length: int = 8,
        case_insensitive: bool = True
    ) -> str:
        """
        Build regex for string literals (useful for hardcoded secrets).
        
        Args:
            prefix: Prefix to match (e.g., "API_KEY")
            min_length: Minimum length of the string value
            case_insensitive: Whether to make pattern case insensitive
            
        Returns:
            Regular expression pattern
        """
        flags = "(?i)" if case_insensitive else ""
        escaped_prefix = re.escape(prefix)
        
        return f"{flags}{escaped_prefix}\\s*=\\s*[\"'][a-zA-Z0-9+/]{{{min_length},}}[\"']"
    
    @staticmethod
    def build_file_operation_pattern(
        operation: str,
        with_traversal: bool = True,
        case_insensitive: bool = True
    ) -> str:
        """
        Build regex for file operations with optional path traversal detection.
        
        Args:
            operation: File operation to match (e.g., "new File")
            with_traversal: Whether to include path traversal patterns
            case_insensitive: Whether to make pattern case insensitive
            
        Returns:
            Regular expression pattern
        """
        flags = "(?i)" if case_insensitive else ""
        escaped_operation = re.escape(operation)
        
        if with_traversal:
            return f"{flags}{escaped_operation}\\s*\\(\\s*[^)]*\\.\\./?[^)]*\\)"
        else:
            return f"{flags}{escaped_operation}\\s*\\([^)]*\\)"

class PatternValidator:
    """Utility class for validating patterns and their components."""
    
    @staticmethod
    def validate_pattern_definition(definition: Dict[str, Any]) -> List[str]:
        """
        Validate a pattern definition dictionary.
        
        Args:
            definition: Pattern definition to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Required fields
        required_fields = ['pattern_name', 'pattern_regex', 'pattern_type', 'severity', 'description']
        for field in required_fields:
            if field not in definition or not definition[field]:
                errors.append(f"Missing required field: {field}")
        
        # Validate regex
        if 'pattern_regex' in definition:
            if not PatternBuilder.validate_regex(definition['pattern_regex']):
                errors.append("Invalid regular expression pattern")
        
        # Validate enum values
        if 'pattern_type' in definition:
            try:
                PatternType(definition['pattern_type'].lower())
            except (ValueError, AttributeError):
                errors.append(f"Invalid pattern type: {definition.get('pattern_type')}")
        
        if 'severity' in definition:
            try:
                SeverityLevel(definition['severity'].upper())
            except (ValueError, AttributeError):
                errors.append(f"Invalid severity level: {definition.get('severity')}")
        
        # Validate confidence scores
        if 'confidence_base' in definition:
            confidence = definition['confidence_base']
            if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
                errors.append("Confidence base must be a number between 0.0 and 1.0")
        
        return errors
    
    @staticmethod
    def validate_pattern_batch(definitions: List[Dict[str, Any]]) -> Dict[int, List[str]]:
        """
        Validate a batch of pattern definitions.
        
        Args:
            definitions: List of pattern definitions to validate
            
        Returns:
            Dictionary mapping indices to validation errors
        """
        errors = {}
        
        for i, definition in enumerate(definitions):
            validation_errors = PatternValidator.validate_pattern_definition(definition)
            if validation_errors:
                errors[i] = validation_errors
        
        return errors 