#!/usr/bin/env python3
"""
Universal Pattern Analyzer for AODS Plugin Modularization

This module provides a reusable, high-performance pattern matching engine
that eliminates code duplication across plugins while optimizing performance
through pre-compiled patterns and intelligent caching.

Features:
- Pre-compiled regex patterns for optimal performance
- Multi-threading support with ThreadPoolExecutor
- Intelligent caching of pattern results
- Generic pattern matching interface
- Context-aware analysis with metadata tracking
- Comprehensive error handling and logging
"""

import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set, Callable, Union
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class PatternMatch:
    """Represents a single pattern match with context."""
    pattern_id: str
    pattern_name: str
    match_text: str
    match_location: str
    line_number: int = 0
    confidence: float = 0.0
    context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CompiledPattern:
    """Represents a compiled regex pattern with metadata."""
    pattern_id: str
    pattern_name: str
    regex: re.Pattern
    severity: str
    category: str
    description: str
    confidence_base: float = 0.8
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AnalysisContext:
    """Context information for pattern analysis."""
    target_name: str
    target_type: str
    source_content: str
    file_path: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

class UniversalPatternAnalyzer:
    """
    Universal pattern analyzer providing reusable pattern matching capabilities
    with performance optimization and multi-threading support.
    """

    def __init__(self, 
                 max_workers: int = 4,
                 enable_caching: bool = True,
                 cache_ttl: int = 3600):
        """
        Initialize the universal pattern analyzer.

        Args:
            max_workers: Maximum number of worker threads for parallel processing
            enable_caching: Whether to enable result caching
            cache_ttl: Cache time-to-live in seconds
        """
        self.max_workers = max_workers
        self.enable_caching = enable_caching
        self.cache_ttl = cache_ttl
        
        # Pattern storage
        self.compiled_patterns: Dict[str, CompiledPattern] = {}
        self.pattern_categories: Dict[str, List[str]] = {}
        
        # Performance optimization
        self.pattern_cache: Dict[str, List[PatternMatch]] = {}
        self.cache_timestamps: Dict[str, float] = {}
        self.cache_lock = threading.Lock()
        
        # Analysis statistics
        self.analysis_stats = {
            'total_analyses': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'pattern_matches': 0,
            'analysis_time': 0.0
        }
        
        logger.info(f"UniversalPatternAnalyzer initialized with {max_workers} workers, caching: {enable_caching}")

    def compile_patterns(self, pattern_definitions: Dict[str, Dict[str, Any]]) -> None:
        """
        Compile regex patterns for optimal performance.

        Args:
            pattern_definitions: Dictionary of pattern definitions
        """
        logger.info(f"Compiling {len(pattern_definitions)} patterns...")
        
        compiled_count = 0
        for pattern_id, pattern_def in pattern_definitions.items():
            try:
                # Extract pattern information
                pattern_regex = pattern_def.get('pattern', '')
                pattern_name = pattern_def.get('name', pattern_id)
                severity = pattern_def.get('severity', 'MEDIUM')
                category = pattern_def.get('category', 'GENERAL')
                description = pattern_def.get('description', '')
                confidence_base = pattern_def.get('confidence_base', 0.8)
                flags = pattern_def.get('flags', re.IGNORECASE | re.MULTILINE)
                
                # Compile regex pattern
                compiled_regex = re.compile(pattern_regex, flags)
                
                # Create compiled pattern object
                compiled_pattern = CompiledPattern(
                    pattern_id=pattern_id,
                    pattern_name=pattern_name,
                    regex=compiled_regex,
                    severity=severity,
                    category=category,
                    description=description,
                    confidence_base=confidence_base,
                    metadata=pattern_def.get('metadata', {})
                )
                
                self.compiled_patterns[pattern_id] = compiled_pattern
                
                # Update category mapping
                if category not in self.pattern_categories:
                    self.pattern_categories[category] = []
                self.pattern_categories[category].append(pattern_id)
                
                compiled_count += 1
                
            except re.error as e:
                logger.error(f"Failed to compile pattern {pattern_id}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error compiling pattern {pattern_id}: {e}")
        
        logger.info(f"Successfully compiled {compiled_count}/{len(pattern_definitions)} patterns")

    def analyze_content(self, 
                       context: AnalysisContext,
                       pattern_categories: Optional[List[str]] = None,
                       parallel: bool = True) -> List[PatternMatch]:
        """
        Analyze content against compiled patterns.

        Args:
            context: Analysis context containing content and metadata
            pattern_categories: Specific categories to analyze (None for all)
            parallel: Whether to use parallel processing

        Returns:
            List of pattern matches found
        """
        start_time = time.time()
        
        # Check cache first
        cache_key = self._generate_cache_key(context, pattern_categories)
        if self.enable_caching:
            cached_result = self._get_cached_result(cache_key)
            if cached_result is not None:
                self.analysis_stats['cache_hits'] += 1
                return cached_result
        
        # Determine patterns to use
        patterns_to_analyze = self._get_patterns_for_categories(pattern_categories)
        
        if not patterns_to_analyze:
            logger.warning("No patterns available for analysis")
            return []
        
        # Perform analysis
        matches = []
        if parallel and len(patterns_to_analyze) > 1:
            matches = self._analyze_parallel(context, patterns_to_analyze)
        else:
            matches = self._analyze_sequential(context, patterns_to_analyze)
        
        # Update statistics
        analysis_time = time.time() - start_time
        self.analysis_stats['total_analyses'] += 1
        self.analysis_stats['cache_misses'] += 1
        self.analysis_stats['pattern_matches'] += len(matches)
        self.analysis_stats['analysis_time'] += analysis_time
        
        # Cache result
        if self.enable_caching:
            self._cache_result(cache_key, matches)
        
        logger.debug(f"Pattern analysis completed in {analysis_time:.3f}s, found {len(matches)} matches")
        return matches

    def _analyze_parallel(self, 
                         context: AnalysisContext, 
                         patterns: List[CompiledPattern]) -> List[PatternMatch]:
        """Analyze patterns in parallel using ThreadPoolExecutor."""
        matches = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit pattern analysis tasks
            future_to_pattern = {
                executor.submit(self._analyze_single_pattern, context, pattern): pattern
                for pattern in patterns
            }
            
            # Collect results
            for future in as_completed(future_to_pattern):
                pattern = future_to_pattern[future]
                try:
                    pattern_matches = future.result()
                    matches.extend(pattern_matches)
                except Exception as e:
                    logger.error(f"Error analyzing pattern {pattern.pattern_id}: {e}")
        
        return matches

    def _analyze_sequential(self, 
                          context: AnalysisContext, 
                          patterns: List[CompiledPattern]) -> List[PatternMatch]:
        """Analyze patterns sequentially."""
        matches = []
        
        for pattern in patterns:
            try:
                pattern_matches = self._analyze_single_pattern(context, pattern)
                matches.extend(pattern_matches)
            except Exception as e:
                logger.error(f"Error analyzing pattern {pattern.pattern_id}: {e}")
        
        return matches

    def _analyze_single_pattern(self, 
                              context: AnalysisContext, 
                              pattern: CompiledPattern) -> List[PatternMatch]:
        """Analyze a single pattern against content."""
        matches = []
        
        try:
            # Find all matches
            for match in pattern.regex.finditer(context.source_content):
                # Calculate line number
                line_number = context.source_content[:match.start()].count('\n') + 1
                
                # Create pattern match
                pattern_match = PatternMatch(
                    pattern_id=pattern.pattern_id,
                    pattern_name=pattern.pattern_name,
                    match_text=match.group(0),
                    match_location=f"{context.target_name}:{line_number}",
                    line_number=line_number,
                    confidence=pattern.confidence_base,
                    context={
                        'target_name': context.target_name,
                        'target_type': context.target_type,
                        'file_path': context.file_path,
                        'severity': pattern.severity,
                        'category': pattern.category,
                        'description': pattern.description
                    },
                    metadata={
                        **context.metadata,
                        **pattern.metadata,
                        'match_start': match.start(),
                        'match_end': match.end(),
                        'groups': match.groups()
                    }
                )
                
                matches.append(pattern_match)
                
        except Exception as e:
            logger.error(f"Error in pattern {pattern.pattern_id} analysis: {e}")
        
        return matches

    def _get_patterns_for_categories(self, categories: Optional[List[str]]) -> List[CompiledPattern]:
        """Get compiled patterns for specified categories."""
        if categories is None:
            return list(self.compiled_patterns.values())
        
        patterns = []
        for category in categories:
            if category in self.pattern_categories:
                for pattern_id in self.pattern_categories[category]:
                    if pattern_id in self.compiled_patterns:
                        patterns.append(self.compiled_patterns[pattern_id])
        
        return patterns

    def _generate_cache_key(self, 
                           context: AnalysisContext, 
                           categories: Optional[List[str]]) -> str:
        """Generate cache key for analysis context."""
        import hashlib
        
        content_hash = hashlib.md5(context.source_content.encode('utf-8')).hexdigest()
        categories_str = ','.join(sorted(categories)) if categories else 'all'
        
        return f"{context.target_name}:{context.target_type}:{content_hash}:{categories_str}"

    def _get_cached_result(self, cache_key: str) -> Optional[List[PatternMatch]]:
        """Get cached analysis result if valid."""
        with self.cache_lock:
            if cache_key in self.pattern_cache:
                timestamp = self.cache_timestamps.get(cache_key, 0)
                if time.time() - timestamp < self.cache_ttl:
                    return self.pattern_cache[cache_key]
                else:
                    # Remove expired cache entry
                    del self.pattern_cache[cache_key]
                    del self.cache_timestamps[cache_key]
        
        return None

    def _cache_result(self, cache_key: str, matches: List[PatternMatch]) -> None:
        """Cache analysis result."""
        with self.cache_lock:
            self.pattern_cache[cache_key] = matches
            self.cache_timestamps[cache_key] = time.time()

    def clear_cache(self) -> None:
        """Clear analysis cache."""
        with self.cache_lock:
            self.pattern_cache.clear()
            self.cache_timestamps.clear()
        logger.info("Pattern analysis cache cleared")

    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        stats = self.analysis_stats.copy()
        
        # Calculate additional metrics
        if stats['total_analyses'] > 0:
            stats['cache_hit_rate'] = stats['cache_hits'] / (stats['cache_hits'] + stats['cache_misses'])
            stats['avg_analysis_time'] = stats['analysis_time'] / stats['total_analyses']
            stats['avg_matches_per_analysis'] = stats['pattern_matches'] / stats['total_analyses']
        
        stats['compiled_patterns'] = len(self.compiled_patterns)
        stats['pattern_categories'] = len(self.pattern_categories)
        stats['cached_results'] = len(self.pattern_cache)
        
        return stats

    def get_pattern_info(self, pattern_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific pattern."""
        if pattern_id in self.compiled_patterns:
            pattern = self.compiled_patterns[pattern_id]
            return {
                'pattern_id': pattern.pattern_id,
                'pattern_name': pattern.pattern_name,
                'severity': pattern.severity,
                'category': pattern.category,
                'description': pattern.description,
                'confidence_base': pattern.confidence_base,
                'pattern': pattern.regex.pattern,
                'flags': pattern.regex.flags,
                'metadata': pattern.metadata
            }
        return None 