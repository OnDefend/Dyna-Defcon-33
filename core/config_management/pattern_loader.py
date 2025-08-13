#!/usr/bin/env python3
"""
Pattern Loader for AODS Configuration Management

This module provides pattern loading and validation capabilities for
external YAML configuration files. It ensures that security patterns
are properly structured and validated before use in analysis plugins.

Features:
- YAML pattern file loading and parsing
- Pattern validation and schema checking
- Error handling and detailed error reporting
- Caching for improved performance
- Hot-reload support for runtime updates
- Multi-file pattern aggregation
"""

import logging
import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Union
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

class PatternLoadError(Exception):
    """Exception raised when pattern loading fails."""
    def __init__(self, message: str, file_path: Optional[str] = None, line_number: Optional[int] = None):
        self.message = message
        self.file_path = file_path
        self.line_number = line_number
        super().__init__(self._format_message())
    
    def _format_message(self) -> str:
        """Format error message with file and line information."""
        if self.file_path:
            if self.line_number:
                return f"{self.message} (in {self.file_path}:{self.line_number})"
            else:
                return f"{self.message} (in {self.file_path})"
        return self.message

@dataclass
class PatternMetadata:
    """Metadata for pattern files and categories."""
    file_path: str
    file_checksum: str
    load_timestamp: float
    pattern_count: int
    categories: Set[str] = field(default_factory=set)
    validation_errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass 
class LoadedPatterns:
    """Container for loaded patterns with metadata."""
    patterns: Dict[str, Dict[str, Any]]
    metadata: PatternMetadata
    source_files: List[str] = field(default_factory=list)
    
    @property
    def pattern_count(self) -> int:
        """Get total number of patterns."""
        return len(self.patterns)
    
    @property
    def categories(self) -> Set[str]:
        """Get all pattern categories."""
        categories = set()
        for pattern in self.patterns.values():
            if 'category' in pattern:
                categories.add(pattern['category'])
        return categories

class PatternLoader:
    """
    Pattern loader for YAML configuration files with validation
    and caching capabilities.
    """

    def __init__(self, 
                 cache_enabled: bool = True,
                 validate_patterns: bool = True,
                 strict_mode: bool = False):
        """
        Initialize the pattern loader.

        Args:
            cache_enabled: Whether to enable pattern caching
            validate_patterns: Whether to validate loaded patterns
            strict_mode: Whether to use strict validation (fail on warnings)
        """
        self.cache_enabled = cache_enabled
        self.validate_patterns = validate_patterns
        self.strict_mode = strict_mode
        
        # Pattern cache
        self.pattern_cache: Dict[str, LoadedPatterns] = {}
        self.file_checksums: Dict[str, str] = {}
        
        # Required pattern fields
        self.required_fields = {
            'name', 'pattern', 'severity', 'category', 'description'
        }
        
        # Optional pattern fields with defaults
        self.optional_fields = {
            'confidence_base': 0.8,
            'flags': re.IGNORECASE | re.MULTILINE,
            'enabled': True,
            'tags': [],
            'masvs_controls': [],
            'references': [],
            'metadata': {}
        }
        
        # Valid severity levels
        self.valid_severities = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
        
        logger.info(f"PatternLoader initialized - cache: {cache_enabled}, validation: {validate_patterns}")

    def load_patterns_from_file(self, file_path: Union[str, Path]) -> LoadedPatterns:
        """
        Load patterns from a single YAML file.

        Args:
            file_path: Path to the YAML pattern file

        Returns:
            LoadedPatterns object containing patterns and metadata

        Raises:
            PatternLoadError: If loading or validation fails
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise PatternLoadError(f"Pattern file not found: {file_path}")
        
        # Check cache first
        if self.cache_enabled:
            cached_patterns = self._get_cached_patterns(file_path)
            if cached_patterns is not None:
                logger.debug(f"Loaded patterns from cache: {file_path}")
                return cached_patterns
        
        try:
            # Load and parse YAML file
            with open(file_path, 'r', encoding='utf-8') as file:
                yaml_content = yaml.safe_load(file)
            
            if yaml_content is None:
                raise PatternLoadError(f"Empty or invalid YAML file", str(file_path))
            
            # Validate YAML structure
            if not isinstance(yaml_content, dict):
                raise PatternLoadError(f"YAML file must contain a dictionary", str(file_path))
            
            # Extract patterns
            patterns = self._extract_patterns(yaml_content, file_path)
            
            # Validate patterns if enabled
            if self.validate_patterns:
                self._validate_patterns(patterns, file_path)
            
            # Create metadata
            file_checksum = self._calculate_file_checksum(file_path)
            metadata = PatternMetadata(
                file_path=str(file_path),
                file_checksum=file_checksum,
                load_timestamp=__import__('time').time(),
                pattern_count=len(patterns)
            )
            
            # Create loaded patterns object
            loaded_patterns = LoadedPatterns(
                patterns=patterns,
                metadata=metadata,
                source_files=[str(file_path)]
            )
            
            # Cache if enabled
            if self.cache_enabled:
                self._cache_patterns(file_path, loaded_patterns)
            
            logger.info(f"Loaded {len(patterns)} patterns from {file_path}")
            return loaded_patterns
            
        except yaml.YAMLError as e:
            raise PatternLoadError(f"YAML parsing error: {e}", str(file_path), getattr(e, 'problem_mark', {}).get('line'))
        except Exception as e:
            raise PatternLoadError(f"Error loading patterns: {e}", str(file_path))

    def load_patterns_from_directory(self, directory_path: Union[str, Path], 
                                   pattern: str = "*.yaml") -> LoadedPatterns:
        """
        Load patterns from all YAML files in a directory.

        Args:
            directory_path: Path to directory containing pattern files
            pattern: File pattern to match (default: "*.yaml")

        Returns:
            LoadedPatterns object containing aggregated patterns

        Raises:
            PatternLoadError: If loading fails
        """
        directory_path = Path(directory_path)
        
        if not directory_path.exists() or not directory_path.is_dir():
            raise PatternLoadError(f"Directory not found: {directory_path}")
        
        # Find pattern files
        pattern_files = list(directory_path.glob(pattern))
        pattern_files.extend(directory_path.glob("*.yml"))  # Also include .yml files
        
        if not pattern_files:
            logger.warning(f"No pattern files found in {directory_path}")
            return LoadedPatterns(patterns={}, metadata=PatternMetadata(
                file_path=str(directory_path),
                file_checksum="",
                load_timestamp=__import__('time').time(),
                pattern_count=0
            ))
        
        # Load patterns from all files
        all_patterns = {}
        source_files = []
        validation_errors = []
        
        for file_path in pattern_files:
            try:
                file_patterns = self.load_patterns_from_file(file_path)
                
                # Check for pattern ID conflicts
                for pattern_id, pattern_data in file_patterns.patterns.items():
                    if pattern_id in all_patterns:
                        error_msg = f"Duplicate pattern ID '{pattern_id}' found in {file_path}"
                        if self.strict_mode:
                            raise PatternLoadError(error_msg)
                        else:
                            logger.warning(error_msg)
                            validation_errors.append(error_msg)
                    
                    all_patterns[pattern_id] = pattern_data
                
                source_files.append(str(file_path))
                
            except PatternLoadError as e:
                error_msg = f"Failed to load patterns from {file_path}: {e.message}"
                validation_errors.append(error_msg)
                
                if self.strict_mode:
                    raise PatternLoadError(error_msg)
                else:
                    logger.error(error_msg)
        
        # Create aggregated metadata
        metadata = PatternMetadata(
            file_path=str(directory_path),
            file_checksum=self._calculate_directory_checksum(pattern_files),
            load_timestamp=__import__('time').time(),
            pattern_count=len(all_patterns),
            validation_errors=validation_errors
        )
        
        loaded_patterns = LoadedPatterns(
            patterns=all_patterns,
            metadata=metadata,
            source_files=source_files
        )
        
        logger.info(f"Loaded {len(all_patterns)} patterns from {len(pattern_files)} files in {directory_path}")
        return loaded_patterns

    def _extract_patterns(self, yaml_content: Dict[str, Any], file_path: Path) -> Dict[str, Dict[str, Any]]:
        """Extract and normalize patterns from YAML content."""
        patterns = {}
        
        # Handle different YAML structures
        if 'patterns' in yaml_content:
            # Structure: { patterns: { pattern_id: { ... } } }
            pattern_dict = yaml_content['patterns']
        elif all(isinstance(v, dict) and any(field in v for field in self.required_fields) for v in yaml_content.values()):
            # Structure: { pattern_id: { ... } }
            pattern_dict = yaml_content
        else:
            raise PatternLoadError(f"Invalid pattern file structure", str(file_path))
        
        for pattern_id, pattern_data in pattern_dict.items():
            if not isinstance(pattern_data, dict):
                raise PatternLoadError(f"Pattern '{pattern_id}' must be a dictionary", str(file_path))
            
            # Normalize pattern data
            normalized_pattern = self._normalize_pattern(pattern_id, pattern_data, file_path)
            patterns[pattern_id] = normalized_pattern
        
        return patterns

    def _normalize_pattern(self, pattern_id: str, pattern_data: Dict[str, Any], file_path: Path) -> Dict[str, Any]:
        """Normalize pattern data with defaults and validation."""
        normalized = {'id': pattern_id}
        
        # Copy required fields
        for field in self.required_fields:
            if field not in pattern_data:
                raise PatternLoadError(f"Pattern '{pattern_id}' missing required field '{field}'", str(file_path))
            normalized[field] = pattern_data[field]
        
        # Copy optional fields with defaults
        for field, default_value in self.optional_fields.items():
            normalized[field] = pattern_data.get(field, default_value)
        
        # Handle regex flags
        if isinstance(normalized['flags'], str):
            normalized['flags'] = self._parse_regex_flags(normalized['flags'])
        elif isinstance(normalized['flags'], list):
            normalized['flags'] = self._parse_regex_flags_list(normalized['flags'])
        
        # Ensure tags and lists are proper types
        if not isinstance(normalized['tags'], list):
            normalized['tags'] = []
        if not isinstance(normalized['masvs_controls'], list):
            normalized['masvs_controls'] = []
        if not isinstance(normalized['references'], list):
            normalized['references'] = []
        if not isinstance(normalized['metadata'], dict):
            normalized['metadata'] = {}
        
        return normalized

    def _validate_patterns(self, patterns: Dict[str, Dict[str, Any]], file_path: Path) -> None:
        """Validate pattern data structure and content."""
        for pattern_id, pattern_data in patterns.items():
            try:
                # Validate severity
                if pattern_data['severity'] not in self.valid_severities:
                    raise PatternLoadError(f"Invalid severity '{pattern_data['severity']}' in pattern '{pattern_id}'", str(file_path))
                
                # Validate confidence_base
                confidence = pattern_data['confidence_base']
                if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
                    raise PatternLoadError(f"Invalid confidence_base '{confidence}' in pattern '{pattern_id}' (must be 0.0-1.0)", str(file_path))
                
                # Validate regex pattern
                try:
                    re.compile(pattern_data['pattern'], pattern_data['flags'])
                except re.error as e:
                    raise PatternLoadError(f"Invalid regex pattern in '{pattern_id}': {e}", str(file_path))
                
                # Validate required string fields are not empty
                for field in ['name', 'description', 'category']:
                    if not pattern_data[field] or not isinstance(pattern_data[field], str):
                        raise PatternLoadError(f"Field '{field}' must be a non-empty string in pattern '{pattern_id}'", str(file_path))
                
            except PatternLoadError:
                raise
            except Exception as e:
                raise PatternLoadError(f"Validation error in pattern '{pattern_id}': {e}", str(file_path))

    def _parse_regex_flags(self, flags_str: str) -> int:
        """Parse regex flags from string representation."""
        flags = 0
        flag_map = {
            'IGNORECASE': re.IGNORECASE,
            'MULTILINE': re.MULTILINE,
            'DOTALL': re.DOTALL,
            'VERBOSE': re.VERBOSE,
            'ASCII': re.ASCII,
            'I': re.IGNORECASE,
            'M': re.MULTILINE,
            'S': re.DOTALL,
            'X': re.VERBOSE,
            'A': re.ASCII
        }
        
        for flag_name in flags_str.upper().split('|'):
            flag_name = flag_name.strip()
            if flag_name in flag_map:
                flags |= flag_map[flag_name]
            elif flag_name:
                logger.warning(f"Unknown regex flag: {flag_name}")
        
        return flags

    def _parse_regex_flags_list(self, flags_list: List[str]) -> int:
        """Parse regex flags from list of strings."""
        return self._parse_regex_flags('|'.join(flags_list))

    def _calculate_file_checksum(self, file_path: Path) -> str:
        """Calculate checksum for file content."""
        import hashlib
        
        try:
            with open(file_path, 'rb') as file:
                content = file.read()
            return hashlib.md5(content).hexdigest()
        except Exception as e:
            logger.warning(f"Failed to calculate checksum for {file_path}: {e}")
            return ""

    def _calculate_directory_checksum(self, files: List[Path]) -> str:
        """Calculate combined checksum for multiple files."""
        import hashlib
        
        checksums = []
        for file_path in sorted(files):
            checksums.append(self._calculate_file_checksum(file_path))
        
        combined = ''.join(checksums)
        return hashlib.md5(combined.encode()).hexdigest()

    def _get_cached_patterns(self, file_path: Path) -> Optional[LoadedPatterns]:
        """Get patterns from cache if valid."""
        cache_key = str(file_path)
        
        if cache_key not in self.pattern_cache:
            return None
        
        # Check if file has changed
        current_checksum = self._calculate_file_checksum(file_path)
        cached_checksum = self.file_checksums.get(cache_key, "")
        
        if current_checksum != cached_checksum:
            # File changed, invalidate cache
            self._invalidate_cache(cache_key)
            return None
        
        return self.pattern_cache[cache_key]

    def _cache_patterns(self, file_path: Path, patterns: LoadedPatterns) -> None:
        """Cache loaded patterns."""
        cache_key = str(file_path)
        self.pattern_cache[cache_key] = patterns
        self.file_checksums[cache_key] = patterns.metadata.file_checksum

    def _invalidate_cache(self, cache_key: str) -> None:
        """Invalidate cache entry."""
        if cache_key in self.pattern_cache:
            del self.pattern_cache[cache_key]
        if cache_key in self.file_checksums:
            del self.file_checksums[cache_key]

    def clear_cache(self) -> None:
        """Clear all cached patterns."""
        self.pattern_cache.clear()
        self.file_checksums.clear()
        logger.info("Pattern cache cleared")

    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get cache usage statistics."""
        total_patterns = sum(len(patterns.patterns) for patterns in self.pattern_cache.values())
        
        return {
            'cached_files': len(self.pattern_cache),
            'total_cached_patterns': total_patterns,
            'cache_enabled': self.cache_enabled,
            'memory_usage_estimate': len(str(self.pattern_cache))  # Rough estimate
        } 