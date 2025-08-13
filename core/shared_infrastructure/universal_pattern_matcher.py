#!/usr/bin/env python3
"""
Universal Pattern Matcher

Enhanced pattern matching system that consolidates and extends pattern matching 
capabilities across all AODS plugins. Provides efficient, cached, and 
configurable pattern matching with advanced features.

Features:
- Multi-category pattern compilation and caching
- Context-aware pattern matching with metadata
- Performance-optimized batch processing
- Configurable pattern libraries from external files
- Advanced matching strategies (exact, fuzzy, contextual)
- Pattern confidence scoring and validation
- Multi-threading support for large-scale analysis
"""

import re
import yaml
import json
import logging
import threading
from typing import Dict, List, Optional, Any, Pattern, Set, Tuple, Union, Callable
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict, namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

logger = logging.getLogger(__name__)

@dataclass
class PatternMatch:
    """Container for pattern match results with metadata."""
    pattern_id: str
    category: str
    matched_text: str
    start_position: int
    end_position: int
    line_number: int
    confidence: float
    context_before: str = ""
    context_after: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def line_context(self) -> str:
        """Get full line context around match."""
        return f"{self.context_before}{self.matched_text}{self.context_after}"

@dataclass
class PatternDefinition:
    """Definition of a pattern with metadata and compilation info."""
    pattern_id: str
    category: str
    pattern_string: str
    compiled_pattern: Optional[Pattern[str]]
    description: str
    severity: str = "MEDIUM"
    confidence_base: float = 0.7
    flags: int = re.IGNORECASE | re.MULTILINE
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    masvs_mapping: List[str] = field(default_factory=list)
    cwe_mapping: List[str] = field(default_factory=list)

class PatternLibrary:
    """Manages collections of patterns with categorization and metadata."""
    
    def __init__(self, name: str):
        self.name = name
        self.patterns: Dict[str, PatternDefinition] = {}
        self.categories: Set[str] = set()
        self._compilation_stats = {
            'total_patterns': 0,
            'compiled_successfully': 0,
            'compilation_errors': 0
        }
    
    def add_pattern(self, pattern_def: PatternDefinition) -> bool:
        """Add pattern to library with compilation."""
        try:
            # Compile pattern
            compiled = re.compile(pattern_def.pattern_string, pattern_def.flags)
            pattern_def.compiled_pattern = compiled
            
            # Store pattern
            self.patterns[pattern_def.pattern_id] = pattern_def
            self.categories.add(pattern_def.category)
            
            self._compilation_stats['compiled_successfully'] += 1
            return True
            
        except re.error as e:
            logger.warning(f"Failed to compile pattern {pattern_def.pattern_id}: {e}")
            self._compilation_stats['compilation_errors'] += 1
            return False
        finally:
            self._compilation_stats['total_patterns'] += 1
    
    def load_from_config(self, config_path: str) -> int:
        """
        Load patterns from configuration file.
        
        Args:
            config_path: Path to YAML configuration file
            
        Returns:
            int: Number of patterns loaded successfully
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            loaded_count = 0
            
            for category, pattern_data in config.items():
                if not isinstance(pattern_data, dict):
                    continue
                
                patterns = pattern_data.get('patterns', [])
                category_info = pattern_data.get('info', {})
                
                for i, pattern_info in enumerate(patterns):
                    if isinstance(pattern_info, str):
                        # Simple string pattern
                        pattern_def = PatternDefinition(
                            pattern_id=f"{category}_{i}",
                            category=category,
                            pattern_string=pattern_info,
                            compiled_pattern=None,
                            description=f"{category} pattern {i}",
                            severity=category_info.get('severity', 'MEDIUM'),
                            confidence_base=category_info.get('confidence', 0.7)
                        )
                    else:
                        # Detailed pattern definition
                        pattern_def = PatternDefinition(
                            pattern_id=pattern_info.get('id', f"{category}_{i}"),
                            category=category,
                            pattern_string=pattern_info['pattern'],
                            compiled_pattern=None,
                            description=pattern_info.get('description', f"{category} pattern"),
                            severity=pattern_info.get('severity', category_info.get('severity', 'MEDIUM')),
                            confidence_base=pattern_info.get('confidence', category_info.get('confidence', 0.7)),
                            tags=pattern_info.get('tags', []),
                            masvs_mapping=pattern_info.get('masvs', []),
                            cwe_mapping=pattern_info.get('cwe', [])
                        )
                    
                    if self.add_pattern(pattern_def):
                        loaded_count += 1
            
            logger.info(f"Loaded {loaded_count} patterns from {config_path}")
            return loaded_count
            
        except Exception as e:
            logger.error(f"Failed to load patterns from {config_path}: {e}")
            return 0
    
    def get_patterns_by_category(self, category: str) -> List[PatternDefinition]:
        """Get all patterns for a specific category."""
        return [p for p in self.patterns.values() if p.category == category]
    
    def get_compilation_stats(self) -> Dict[str, Any]:
        """Get pattern compilation statistics."""
        return self._compilation_stats.copy()

class UniversalPatternMatcher:
    """Advanced universal pattern matching system."""
    
    def __init__(self, thread_pool_size: int = 4):
        """
        Initialize universal pattern matcher.
        
        Args:
            thread_pool_size: Number of threads for parallel processing
        """
        self.libraries: Dict[str, PatternLibrary] = {}
        self.thread_pool_size = thread_pool_size
        self._cache_lock = threading.RLock()
        self._match_cache: Dict[str, List[PatternMatch]] = {}
        self._cache_max_size = 1000
        
        # Performance tracking
        self._performance_stats = {
            'total_matches': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'avg_match_time': 0.0
        }
    
    def register_library(self, library: PatternLibrary) -> None:
        """Register a pattern library."""
        self.libraries[library.name] = library
        logger.info(f"Registered pattern library: {library.name} with {len(library.patterns)} patterns")
    
    def load_library_from_config(self, library_name: str, config_path: str) -> PatternLibrary:
        """
        Load and register a pattern library from configuration.
        
        Args:
            library_name: Name for the pattern library
            config_path: Path to configuration file
            
        Returns:
            PatternLibrary: Loaded pattern library
        """
        library = PatternLibrary(library_name)
        library.load_from_config(config_path)
        self.register_library(library)
        return library
    
    def match_content(self, content: str, libraries: Optional[List[str]] = None,
                     categories: Optional[List[str]] = None,
                     include_context: bool = True,
                     context_size: int = 50) -> List[PatternMatch]:
        """
        Match patterns against content with comprehensive options.
        
        Args:
            content: Content to analyze
            libraries: List of library names to use (None for all)
            categories: List of categories to match (None for all)
            include_context: Whether to include surrounding context
            context_size: Number of characters to include in context
            
        Returns:
            List[PatternMatch]: List of pattern matches found
        """
        start_time = time.time()
        
        # Check cache first
        cache_key = self._create_cache_key(content, libraries, categories)
        if cache_key in self._match_cache:
            with self._cache_lock:
                self._performance_stats['cache_hits'] += 1
                return self._match_cache[cache_key].copy()
        
        # Perform matching
        matches = self._perform_matching(content, libraries, categories, 
                                       include_context, context_size)
        
        # Update cache
        with self._cache_lock:
            if len(self._match_cache) >= self._cache_max_size:
                # Remove oldest entries
                oldest_keys = list(self._match_cache.keys())[:100]
                for key in oldest_keys:
                    del self._match_cache[key]
            
            self._match_cache[cache_key] = matches.copy()
            self._performance_stats['cache_misses'] += 1
            self._performance_stats['total_matches'] += len(matches)
            
            # Update average match time
            match_time = time.time() - start_time
            stats = self._performance_stats
            total_operations = stats['cache_hits'] + stats['cache_misses']
            stats['avg_match_time'] = ((stats['avg_match_time'] * (total_operations - 1)) + match_time) / total_operations
        
        return matches
    
    def _perform_matching(self, content: str, libraries: Optional[List[str]],
                         categories: Optional[List[str]], include_context: bool,
                         context_size: int) -> List[PatternMatch]:
        """Perform the actual pattern matching."""
        matches = []
        
        # Determine which libraries to use
        target_libraries = libraries or list(self.libraries.keys())
        
        # Collect all patterns to use
        patterns_to_match = []
        for lib_name in target_libraries:
            if lib_name not in self.libraries:
                continue
            
            library = self.libraries[lib_name]
            for pattern_def in library.patterns.values():
                if not pattern_def.enabled or not pattern_def.compiled_pattern:
                    continue
                
                if categories and pattern_def.category not in categories:
                    continue
                
                patterns_to_match.append(pattern_def)
        
        # Split content into lines for line number tracking
        lines = content.split('\n')
        line_starts = self._calculate_line_starts(content)
        
        # Match each pattern
        for pattern_def in patterns_to_match:
            try:
                for match in pattern_def.compiled_pattern.finditer(content):
                    # Calculate line number
                    line_num = self._get_line_number(match.start(), line_starts)
                    
                    # Extract context if requested
                    context_before = ""
                    context_after = ""
                    if include_context:
                        context_start = max(0, match.start() - context_size)
                        context_end = min(len(content), match.end() + context_size)
                        context_before = content[context_start:match.start()]
                        context_after = content[match.end():context_end]
                    
                    # Calculate confidence
                    confidence = self._calculate_match_confidence(
                        pattern_def, match, content, line_num
                    )
                    
                    pattern_match = PatternMatch(
                        pattern_id=pattern_def.pattern_id,
                        category=pattern_def.category,
                        matched_text=match.group(),
                        start_position=match.start(),
                        end_position=match.end(),
                        line_number=line_num,
                        confidence=confidence,
                        context_before=context_before,
                        context_after=context_after,
                        metadata={
                            'pattern_description': pattern_def.description,
                            'severity': pattern_def.severity,
                            'tags': pattern_def.tags,
                            'masvs_mapping': pattern_def.masvs_mapping,
                            'cwe_mapping': pattern_def.cwe_mapping
                        }
                    )
                    
                    matches.append(pattern_match)
            
            except Exception as e:
                logger.warning(f"Error matching pattern {pattern_def.pattern_id}: {e}")
        
        return matches
    
    def match_files_parallel(self, file_paths: List[str], 
                           libraries: Optional[List[str]] = None,
                           categories: Optional[List[str]] = None,
                           max_file_size_mb: int = 10) -> Dict[str, List[PatternMatch]]:
        """
        Match patterns against multiple files in parallel.
        
        Args:
            file_paths: List of file paths to analyze
            libraries: List of library names to use
            categories: List of categories to match
            max_file_size_mb: Maximum file size to process
            
        Returns:
            Dict[str, List[PatternMatch]]: Matches grouped by file path
        """
        results = {}
        max_file_size = max_file_size_mb * 1024 * 1024
        
        def process_file(file_path: str) -> Tuple[str, List[PatternMatch]]:
            try:
                # Check file size
                file_size = Path(file_path).stat().st_size
                if file_size > max_file_size:
                    logger.debug(f"Skipping large file: {file_path} ({file_size} bytes)")
                    return file_path, []
                
                # Read file content
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Match patterns
                matches = self.match_content(content, libraries, categories)
                
                # Update file path in matches
                for match in matches:
                    match.metadata['file_path'] = file_path
                
                return file_path, matches
            
            except Exception as e:
                logger.warning(f"Failed to process file {file_path}: {e}")
                return file_path, []
        
        # Process files in parallel
        with ThreadPoolExecutor(max_workers=self.thread_pool_size) as executor:
            future_to_file = {executor.submit(process_file, fp): fp for fp in file_paths}
            
            for future in as_completed(future_to_file):
                file_path, matches = future.result()
                results[file_path] = matches
        
        return results
    
    def get_match_statistics(self, matches: List[PatternMatch]) -> Dict[str, Any]:
        """
        Generate statistics for pattern matches.
        
        Args:
            matches: List of pattern matches
            
        Returns:
            Dict[str, Any]: Match statistics
        """
        if not matches:
            return {'total_matches': 0}
        
        # Group by category
        category_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        confidence_scores = []
        
        for match in matches:
            category_counts[match.category] += 1
            severity = match.metadata.get('severity', 'UNKNOWN')
            severity_counts[severity] += 1
            confidence_scores.append(match.confidence)
        
        return {
            'total_matches': len(matches),
            'unique_patterns': len(set(m.pattern_id for m in matches)),
            'categories': dict(category_counts),
            'severities': dict(severity_counts),
            'avg_confidence': sum(confidence_scores) / len(confidence_scores),
            'min_confidence': min(confidence_scores),
            'max_confidence': max(confidence_scores),
            'high_confidence_matches': len([m for m in matches if m.confidence >= 0.8])
        }
    
    def _create_cache_key(self, content: str, libraries: Optional[List[str]],
                         categories: Optional[List[str]]) -> str:
        """Create cache key for content and parameters."""
        import hashlib
        
        # Create hash of content
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()[:16]
        
        # Create parameter string
        lib_str = ','.join(sorted(libraries or []))
        cat_str = ','.join(sorted(categories or []))
        param_str = f"{lib_str}|{cat_str}"
        
        return f"{content_hash}:{param_str}"
    
    def _calculate_line_starts(self, content: str) -> List[int]:
        """Calculate starting positions of each line."""
        line_starts = [0]
        for i, char in enumerate(content):
            if char == '\n':
                line_starts.append(i + 1)
        return line_starts
    
    def _get_line_number(self, position: int, line_starts: List[int]) -> int:
        """Get line number for a given position."""
        for i, start in enumerate(line_starts):
            if i + 1 >= len(line_starts) or position < line_starts[i + 1]:
                return i + 1
        return len(line_starts)
    
    def _calculate_match_confidence(self, pattern_def: PatternDefinition,
                                  match: re.Match, content: str, line_num: int) -> float:
        """Calculate confidence score for a pattern match."""
        base_confidence = pattern_def.confidence_base
        
        # Adjust based on match characteristics
        matched_text = match.group()
        
        # Length bonus (longer matches tend to be more specific)
        if len(matched_text) > 20:
            base_confidence += 0.1
        elif len(matched_text) < 5:
            base_confidence -= 0.1
        
        # Context analysis (simple heuristics)
        context_start = max(0, match.start() - 100)
        context_end = min(len(content), match.end() + 100)
        context = content[context_start:context_end].lower()
        
        # Reduce confidence if in comments
        if any(indicator in context for indicator in ['/*', '*/', '//', '#']):
            base_confidence -= 0.2
        
        # Reduce confidence if in test files (based on context keywords)
        if any(test_indicator in context for test_indicator in ['test', 'junit', 'mock']):
            base_confidence -= 0.15
        
        # Ensure confidence is within valid range
        return max(0.1, min(1.0, base_confidence))
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        with self._cache_lock:
            stats = self._performance_stats.copy()
            stats['cache_size'] = len(self._match_cache)
            stats['total_libraries'] = len(self.libraries)
            stats['total_patterns'] = sum(len(lib.patterns) for lib in self.libraries.values())
            return stats
    
    def clear_cache(self) -> None:
        """Clear the pattern matching cache."""
        with self._cache_lock:
            self._match_cache.clear()
            logger.info("Pattern matching cache cleared")

# Create a global instance for shared use
global_pattern_matcher = UniversalPatternMatcher()

# Export main classes
__all__ = [
    'PatternMatch',
    'PatternDefinition', 
    'PatternLibrary',
    'UniversalPatternMatcher',
    'global_pattern_matcher'
] 