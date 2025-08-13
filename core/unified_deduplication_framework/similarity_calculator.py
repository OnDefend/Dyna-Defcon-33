#!/usr/bin/env python3
"""
Unified Deduplication Framework - Similarity Calculator
======================================================

This module contains the unified similarity calculation algorithms that
consolidate the best features from both existing deduplication engines.

Features:
- Multiple similarity calculation methods
- Configurable thresholds and weights
- Performance-optimized comparisons
- Detailed similarity breakdown

"""

import re
import difflib
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass

from .data_structures import SimilarityScore, SimilarityLevel

class UnifiedSimilarityCalculator:
    """
    Unified similarity calculator that consolidates similarity algorithms
    from both existing deduplication engines.
    """
    
    def __init__(self, similarity_thresholds: Dict[str, float]):
        """Initialize the similarity calculator with thresholds."""
        self.thresholds = similarity_thresholds
        
        # Weights for different similarity components
        self.component_weights = {
            'content': 0.4,      # Title + description content
            'location': 0.2,     # File location similarity
            'evidence': 0.2,     # Evidence overlap
            'pattern': 0.2       # Pattern/structure similarity
        }
    
    def calculate_similarity(self, finding1: Dict[str, Any], 
                           finding2: Dict[str, Any]) -> SimilarityScore:
        """
        Calculate comprehensive similarity between two findings.
        
        Args:
            finding1: First finding to compare
            finding2: Second finding to compare
            
        Returns:
            SimilarityScore with detailed breakdown
        """
        # Calculate individual similarity components
        content_sim = self._calculate_content_similarity(finding1, finding2)
        location_sim = self._calculate_location_similarity(finding1, finding2)
        evidence_sim = self._calculate_evidence_similarity(finding1, finding2)
        pattern_sim = self._calculate_pattern_similarity(finding1, finding2)
        
        # Calculate weighted overall similarity
        overall_score = (
            content_sim * self.component_weights['content'] +
            location_sim * self.component_weights['location'] +
            evidence_sim * self.component_weights['evidence'] +
            pattern_sim * self.component_weights['pattern']
        )
        
        # Determine similarity level
        similarity_level = self._determine_similarity_level(overall_score)
        
        # Create detailed comparison
        comparison_details = {
            'content_similarity': content_sim,
            'location_similarity': location_sim,
            'evidence_similarity': evidence_sim,
            'pattern_similarity': pattern_sim,
            'weights_used': self.component_weights.copy(),
            'thresholds_applied': self.thresholds.copy()
        }
        
        return SimilarityScore(
            overall_score=overall_score,
            content_similarity=content_sim,
            location_similarity=location_sim,
            evidence_similarity=evidence_sim,
            pattern_similarity=pattern_sim,
            similarity_level=similarity_level,
            comparison_details=comparison_details
        )
    
    def _calculate_content_similarity(self, finding1: Dict[str, Any], 
                                    finding2: Dict[str, Any]) -> float:
        """Calculate similarity between finding titles and descriptions."""
        # Extract text content
        title1 = finding1.get('title', '').lower().strip()
        title2 = finding2.get('title', '').lower().strip()
        desc1 = finding1.get('description', '').lower().strip()
        desc2 = finding2.get('description', '').lower().strip()
        
        # Combine title and description
        content1 = f"{title1} {desc1}".strip()
        content2 = f"{title2} {desc2}".strip()
        
        if not content1 or not content2:
            return 0.0
        
        # Use multiple similarity measures
        sequence_sim = self._sequence_similarity(content1, content2)
        token_sim = self._token_similarity(content1, content2)
        fuzzy_sim = self._fuzzy_similarity(content1, content2)
        
        # Weighted combination
        return (sequence_sim * 0.4 + token_sim * 0.3 + fuzzy_sim * 0.3)
    
    def _calculate_location_similarity(self, finding1: Dict[str, Any], 
                                     finding2: Dict[str, Any]) -> float:
        """Calculate similarity between finding locations."""
        # Extract location information
        file1 = finding1.get('file_path', '').lower()
        file2 = finding2.get('file_path', '').lower()
        line1 = finding1.get('line_number', 0)
        line2 = finding2.get('line_number', 0)
        
        # File path similarity
        if file1 and file2:
            file_sim = self._path_similarity(file1, file2)
        else:
            file_sim = 1.0 if file1 == file2 else 0.0
        
        # Line number proximity
        if line1 and line2 and line1 > 0 and line2 > 0:
            line_diff = abs(line1 - line2)
            if line_diff == 0:
                line_sim = 1.0
            elif line_diff <= 5:
                line_sim = 0.8
            elif line_diff <= 20:
                line_sim = 0.5
            else:
                line_sim = 0.0
        else:
            line_sim = 1.0 if line1 == line2 else 0.0
        
        # Combine file and line similarities
        return (file_sim * 0.7 + line_sim * 0.3)
    
    def _calculate_evidence_similarity(self, finding1: Dict[str, Any], 
                                     finding2: Dict[str, Any]) -> float:
        """Calculate similarity between finding evidence."""
        evidence1 = set(finding1.get('evidence', []))
        evidence2 = set(finding2.get('evidence', []))
        
        if not evidence1 and not evidence2:
            return 1.0  # Both have no evidence
        
        if not evidence1 or not evidence2:
            return 0.0  # One has evidence, other doesn't
        
        # Calculate Jaccard similarity
        intersection = len(evidence1.intersection(evidence2))
        union = len(evidence1.union(evidence2))
        
        return intersection / union if union > 0 else 0.0
    
    def _calculate_pattern_similarity(self, finding1: Dict[str, Any], 
                                    finding2: Dict[str, Any]) -> float:
        """Calculate similarity between finding patterns and structure."""
        # Extract pattern indicators
        severity1 = finding1.get('severity', '').lower()
        severity2 = finding2.get('severity', '').lower()
        type1 = finding1.get('type', '').lower()
        type2 = finding2.get('type', '').lower()
        category1 = finding1.get('category', '').lower()
        category2 = finding2.get('category', '').lower()
        
        similarities = []
        
        # Severity similarity
        if severity1 and severity2:
            similarities.append(1.0 if severity1 == severity2 else 0.0)
        
        # Type similarity
        if type1 and type2:
            similarities.append(self._fuzzy_similarity(type1, type2))
        
        # Category similarity
        if category1 and category2:
            similarities.append(self._fuzzy_similarity(category1, category2))
        
        # Pattern in content (vulnerability signatures)
        content1 = f"{finding1.get('title', '')} {finding1.get('description', '')}".lower()
        content2 = f"{finding2.get('title', '')} {finding2.get('description', '')}".lower()
        
        pattern_sim = self._pattern_similarity_analysis(content1, content2)
        similarities.append(pattern_sim)
        
        return sum(similarities) / len(similarities) if similarities else 0.0
    
    def _sequence_similarity(self, text1: str, text2: str) -> float:
        """Calculate sequence similarity using difflib."""
        if not text1 or not text2:
            return 0.0
        
        sequence_matcher = difflib.SequenceMatcher(None, text1, text2)
        return sequence_matcher.ratio()
    
    def _token_similarity(self, text1: str, text2: str) -> float:
        """Calculate token-based similarity."""
        if not text1 or not text2:
            return 0.0
        
        # Tokenize and normalize
        tokens1 = set(self._tokenize(text1))
        tokens2 = set(self._tokenize(text2))
        
        if not tokens1 and not tokens2:
            return 1.0
        
        if not tokens1 or not tokens2:
            return 0.0
        
        # Jaccard similarity
        intersection = len(tokens1.intersection(tokens2))
        union = len(tokens1.union(tokens2))
        
        return intersection / union if union > 0 else 0.0
    
    def _fuzzy_similarity(self, text1: str, text2: str) -> float:
        """Calculate fuzzy string similarity."""
        if not text1 or not text2:
            return 0.0
        
        if text1 == text2:
            return 1.0
        
        # Implement fuzzy matching using character-level comparison
        max_len = max(len(text1), len(text2))
        if max_len == 0:
            return 1.0
        
        # Count character differences
        differences = 0
        for i in range(max_len):
            char1 = text1[i] if i < len(text1) else ''
            char2 = text2[i] if i < len(text2) else ''
            if char1 != char2:
                differences += 1
        
        return 1.0 - (differences / max_len)
    
    def _path_similarity(self, path1: str, path2: str) -> float:
        """Calculate file path similarity."""
        if path1 == path2:
            return 1.0
        
        # Split paths into components
        parts1 = path1.split('/')
        parts2 = path2.split('/')
        
        # Calculate component overlap
        common_parts = 0
        max_parts = max(len(parts1), len(parts2))
        
        for i in range(min(len(parts1), len(parts2))):
            if parts1[i] == parts2[i]:
                common_parts += 1
            else:
                break  # Stop at first difference in path hierarchy
        
        return common_parts / max_parts if max_parts > 0 else 0.0
    
    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text for similarity comparison."""
        # Remove special characters and split on whitespace
        cleaned = re.sub(r'[^\w\s]', ' ', text.lower())
        tokens = cleaned.split()
        
        # Filter out very short tokens
        return [token for token in tokens if len(token) > 2]
    
    def _pattern_similarity_analysis(self, content1: str, content2: str) -> float:
        """Analyze pattern similarity in vulnerability descriptions."""
        # Common vulnerability patterns
        vulnerability_patterns = [
            r'sql.{0,10}injection',
            r'cross.{0,10}site.{0,10}scripting',
            r'buffer.{0,10}overflow',
            r'path.{0,10}traversal',
            r'command.{0,10}injection',
            r'hardcoded.{0,10}(password|secret|key)',
            r'weak.{0,10}encryption',
            r'insecure.{0,10}storage',
            r'exported.{0,10}(activity|service|receiver)',
            r'permission.{0,10}(dangerous|sensitive)'
        ]
        
        patterns1 = []
        patterns2 = []
        
        for pattern in vulnerability_patterns:
            if re.search(pattern, content1, re.IGNORECASE):
                patterns1.append(pattern)
            if re.search(pattern, content2, re.IGNORECASE):
                patterns2.append(pattern)
        
        if not patterns1 and not patterns2:
            return 0.5  # Neutral score if no patterns found
        
        if not patterns1 or not patterns2:
            return 0.0  # One has patterns, other doesn't
        
        # Calculate pattern overlap
        common_patterns = len(set(patterns1).intersection(set(patterns2)))
        total_patterns = len(set(patterns1).union(set(patterns2)))
        
        return common_patterns / total_patterns if total_patterns > 0 else 0.0
    
    def _determine_similarity_level(self, score: float) -> SimilarityLevel:
        """Determine similarity level based on score."""
        if score >= self.thresholds.get('exact_match', 1.0):
            return SimilarityLevel.EXACT_MATCH
        elif score >= self.thresholds.get('high_similarity', 0.95):
            return SimilarityLevel.HIGH_SIMILARITY
        elif score >= self.thresholds.get('moderate_similarity', 0.85):
            return SimilarityLevel.MODERATE_SIMILARITY
        elif score >= self.thresholds.get('low_similarity', 0.7):
            return SimilarityLevel.LOW_SIMILARITY
        else:
            return SimilarityLevel.UNRELATED
    
    def update_thresholds(self, new_thresholds: Dict[str, float]):
        """Update similarity thresholds."""
        self.thresholds.update(new_thresholds)
    
    def update_weights(self, new_weights: Dict[str, float]):
        """Update component weights."""
        self.component_weights.update(new_weights)
    
    def get_configuration(self) -> Dict[str, Any]:
        """Get current calculator configuration."""
        return {
            'thresholds': self.thresholds.copy(),
            'weights': self.component_weights.copy()
        } 