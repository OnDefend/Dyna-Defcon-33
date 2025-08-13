"""
Report Consistency Manager for AODS

This module ensures consistency across all report formats (HTML, JSON, CSV)
by eliminating duplicates, standardizing metadata, and validating cross-format
consistency as outlined in the roadmap.

Advanced Report Consistency Management

"""

import logging
import re
import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime

from rich.text import Text

@dataclass
class ConsistencyMetrics:
    """Metrics for tracking report consistency improvements."""
    
    original_sections: int = 0
    deduplicated_sections: int = 0
    duplicates_removed: int = 0
    metadata_fields_standardized: int = 0
    validation_checks_passed: int = 0
    validation_checks_failed: int = 0
    processing_time_ms: float = 0.0

@dataclass
class DuplicatePattern:
    """Pattern definition for identifying duplicate entries."""
    
    base_title: str
    variations: List[str] = field(default_factory=list)
    merge_strategy: str = "highest_severity"  # or "combine_content", "keep_first"
    category: str = "general"

class ReportConsistencyManager:
    """
    Manages consistency across all report formats with comprehensive deduplication
    and standardization capabilities.
    """
    
    def __init__(self):
        """Initialize the consistency manager with predefined patterns."""
        self.duplicate_patterns = self._initialize_duplicate_patterns()
        self.metadata_standardizer = MetadataStandardizer()
        self.metrics = ConsistencyMetrics()
        self.logger = logging.getLogger(__name__)
        
    def _initialize_duplicate_patterns(self) -> List[DuplicatePattern]:
        """Initialize known duplicate patterns for common issues."""
        return [
            # PLATFORM-01 Clear-Text-Traffic variations
            DuplicatePattern(
                base_title="PLATFORM-01: Clear-Text-Traffic Flag Analysis",
                variations=[
                    "PLATFORM-01: Clear-Text-Traffic Flag (FAIL)",
                    "PLATFORM-01: Clear-Text-Traffic Flag",
                    "PLATFORM-01: Clear-Text-Traffic Flag Analysis",
                    "PLATFORM-01 Clear-Text-Traffic Flag",
                    "PLATFORM-01 Clear-Text-Traffic Analysis"
                ],
                merge_strategy="combine_content",
                category="platform"
            ),
            # Other OWASP MASVS patterns
            DuplicatePattern(
                base_title="SQL Injection Vulnerability Analysis",
                variations=[
                    "SQL Injection Vulnerabilities",
                    "SQL Injection Vulnerability",
                    "SQL Injection Test",
                    "SQL Injection Analysis"
                ],
                merge_strategy="highest_severity",
                category="injection"
            ),
            DuplicatePattern(
                base_title="Attack Surface Analysis",
                variations=[
                    "Attack Surface",
                    "Attack Surface Mapping",
                    "Attack Surface Analysis",
                    "Application Attack Surface"
                ],
                merge_strategy="combine_content",
                category="surface"
            ),
            DuplicatePattern(
                base_title="Path Traversal Vulnerability Analysis",
                variations=[
                    "Path Traversal Vulnerabilities",
                    "Path Traversal Vulnerability",
                    "Path Traversal Test",
                    "Traversal Vulnerabilities"
                ],
                merge_strategy="highest_severity",
                category="traversal"
            ),
            # Hardcoded secrets patterns
            DuplicatePattern(
                base_title="Hardcoded Secret Analysis",
                variations=[
                    "Hardcoded Secret:",
                    "Hardcoded Secrets",
                    "Secret Analysis",
                    "Credential Analysis"
                ],
                merge_strategy="combine_content",
                category="secrets"
            )
        ]
    
    def process_report_data(self, report_data: List[Tuple[str, Union[str, Text, Dict[str, Any]]]]) -> Tuple[List[Tuple[str, Union[str, Text, Dict[str, Any]]]], ConsistencyMetrics]:
        """
        Process report data for consistency, eliminating duplicates and standardizing content.
        
        Args:
            report_data: List of (title, content) tuples from report generator
            
        Returns:
            Tuple of (processed_report_data, consistency_metrics)
        """
        start_time = datetime.now()
        
        self.metrics.original_sections = len(report_data)
        self.logger.info(f"🔄 Processing {len(report_data)} report sections for consistency")
        
        # Step 1: Eliminate duplicates
        deduplicated_data = self._eliminate_duplicates(report_data)
        
        # Step 2: Standardize content format
        standardized_data = self._standardize_content_format(deduplicated_data)
        
        # Step 3: Validate consistency
        validation_results = self._validate_consistency(standardized_data)
        
        # Calculate metrics
        end_time = datetime.now()
        self.metrics.deduplicated_sections = len(standardized_data)
        self.metrics.duplicates_removed = self.metrics.original_sections - self.metrics.deduplicated_sections
        self.metrics.processing_time_ms = (end_time - start_time).total_seconds() * 1000
        
        self.logger.info(f"✅ Consistency processing complete: {self.metrics.duplicates_removed} duplicates removed")
        
        return standardized_data, self.metrics
    
    def _eliminate_duplicates(self, report_data: List[Tuple[str, Union[str, Text, Dict[str, Any]]]]) -> List[Tuple[str, Union[str, Text, Dict[str, Any]]]]:
        """
        Eliminate duplicate entries based on predefined patterns and smart matching.
        
        Args:
            report_data: Original report data
            
        Returns:
            Deduplicated report data
        """
        # Group entries by similarity
        similarity_groups = self._group_similar_entries(report_data)
        
        # Process each group to eliminate duplicates
        deduplicated_data = []
        
        for group_key, entries in similarity_groups.items():
            if len(entries) == 1:
                # No duplicates
                deduplicated_data.extend(entries)
            else:
                # Handle duplicates
                merged_entry = self._merge_duplicate_entries(entries, group_key)
                deduplicated_data.append(merged_entry)
                
                self.logger.debug(f"Merged {len(entries)} duplicate entries for: {group_key}")
        
        return deduplicated_data
    
    def _group_similar_entries(self, report_data: List[Tuple[str, Union[str, Text, Dict[str, Any]]]]) -> Dict[str, List[Tuple[str, Union[str, Text, Dict[str, Any]]]]]:
        """
        Group similar entries together for duplicate detection.
        
        Args:
            report_data: List of report entries
            
        Returns:
            Dictionary mapping similarity keys to lists of similar entries
        """
        similarity_groups = defaultdict(list)
        
        for title, content in report_data:
            # Generate similarity key
            similarity_key = self._generate_similarity_key(title, content)
            similarity_groups[similarity_key].append((title, content))
        
        return dict(similarity_groups)
    
    def _generate_similarity_key(self, title: str, content: Union[str, Text, Dict[str, Any]]) -> str:
        """
        Generate a similarity key for grouping duplicate entries.
        
        Args:
            title: Entry title
            content: Entry content
            
        Returns:
            Similarity key for grouping
        """
        # Clean and normalize title
        clean_title = self._clean_title_for_similarity(title)
        
        # Check against known patterns
        for pattern in self.duplicate_patterns:
            if any(self._titles_match_pattern(clean_title, variation) for variation in pattern.variations):
                return f"pattern:{pattern.base_title}"
        
        # Fallback to normalized title
        return f"title:{clean_title}"
    
    def _clean_title_for_similarity(self, title: str) -> str:
        """
        Clean title for similarity comparison.
        
        Args:
            title: Original title
            
        Returns:
            Cleaned title
        """
        # Remove status indicators
        clean_title = re.sub(r'\s*\((?:PASS|FAIL|ERROR|WARNING|INFO)\)', '', title)
        
        # Remove extra whitespace
        clean_title = re.sub(r'\s+', ' ', clean_title.strip())
        
        # Remove common prefixes and suffixes
        clean_title = re.sub(r'^(Test|Analysis|Check|Scan):\s*', '', clean_title, flags=re.IGNORECASE)
        clean_title = re.sub(r'\s*(Test|Analysis|Check|Scan)$', '', clean_title, flags=re.IGNORECASE)
        
        return clean_title.lower()
    
    def _titles_match_pattern(self, title: str, pattern: str) -> bool:
        """
        Check if a title matches a duplicate pattern.
        
        Args:
            title: Title to check
            pattern: Pattern to match against
            
        Returns:
            True if title matches pattern
        """
        # Convert both to lowercase for comparison
        title_clean = self._clean_title_for_similarity(title)
        pattern_clean = self._clean_title_for_similarity(pattern)
        
        # Exact match
        if title_clean == pattern_clean:
            return True
        
        # Partial match with high similarity
        similarity_score = self._calculate_string_similarity(title_clean, pattern_clean)
        return similarity_score > 0.8
    
    def _calculate_string_similarity(self, str1: str, str2: str) -> float:
        """
        Calculate similarity score between two strings.
        
        Args:
            str1: First string
            str2: Second string
            
        Returns:
            Similarity score between 0 and 1
        """
        # Simple implementation using set intersection
        words1 = set(str1.lower().split())
        words2 = set(str2.lower().split())
        
        if not words1 and not words2:
            return 1.0
        if not words1 or not words2:
            return 0.0
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        return len(intersection) / len(union) if union else 0.0
    
    def _merge_duplicate_entries(self, entries: List[Tuple[str, Union[str, Text, Dict[str, Any]]]], group_key: str) -> Tuple[str, Union[str, Text, Dict[str, Any]]]:
        """
        Merge duplicate entries into a single consolidated entry.
        
        Args:
            entries: List of duplicate entries
            group_key: Group identifier for these entries
            
        Returns:
            Single merged entry
        """
        if len(entries) == 1:
            return entries[0]
        
        # Determine merge strategy
        merge_strategy = "highest_severity"  # Default
        for pattern in self.duplicate_patterns:
            if group_key.endswith(pattern.base_title):
                merge_strategy = pattern.merge_strategy
                break
        
        # Apply merge strategy
        if merge_strategy == "highest_severity":
            return self._merge_by_highest_severity(entries)
        elif merge_strategy == "combine_content":
            return self._merge_by_combining_content(entries)
        elif merge_strategy == "keep_first":
            return entries[0]
        else:
            return self._merge_by_combining_content(entries)  # Default fallback
    
    def _merge_by_highest_severity(self, entries: List[Tuple[str, Union[str, Text, Dict[str, Any]]]]) -> Tuple[str, Union[str, Text, Dict[str, Any]]]:
        """
        Merge entries by keeping the one with highest severity.
        
        Args:
            entries: List of duplicate entries
            
        Returns:
            Entry with highest severity
        """
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
        
        best_entry = entries[0]
        best_severity = 5  # Start with lowest priority
        
        for title, content in entries:
            content_str = str(content).upper()
            for severity, priority in severity_order.items():
                if severity in content_str:
                    if priority < best_severity:
                        best_severity = priority
                        best_entry = (title, content)
                    break
        
        return best_entry
    
    def _merge_by_combining_content(self, entries: List[Tuple[str, Union[str, Text, Dict[str, Any]]]]) -> Tuple[str, Union[str, Text, Dict[str, Any]]]:
        """
        Merge entries by combining their content.
        
        Args:
            entries: List of duplicate entries
            
        Returns:
            Entry with combined content
        """
        # Use the cleanest title (usually the shortest)
        best_title = min(entries, key=lambda x: len(x[0]))[0]
        
        # Remove status indicators for cleaner title
        best_title = re.sub(r'\s*\((?:PASS|FAIL|ERROR|WARNING|INFO)\)', '', best_title)
        
        # Combine content
        combined_content_parts = []
        seen_content = set()
        
        for title, content in entries:
            content_str = str(content)
            content_hash = hashlib.md5(content_str.encode()).hexdigest()
            
            if content_hash not in seen_content:
                seen_content.add(content_hash)
                
                # Add source information
                if len(entries) > 1:
                    combined_content_parts.append(f"--- Source: {title} ---")
                combined_content_parts.append(content_str)
                combined_content_parts.append("")
        
        # Add consolidation info
        if len(entries) > 1:
            combined_content_parts.append(f"🔄 Consolidated from {len(entries)} duplicate findings")
            combined_content_parts.append(f"📊 Unique content sources: {len(seen_content)}")
        
        combined_content = "\n".join(combined_content_parts)
        
        return (best_title, combined_content)
    
    def _standardize_content_format(self, report_data: List[Tuple[str, Union[str, Text, Dict[str, Any]]]]) -> List[Tuple[str, Union[str, Text, Dict[str, Any]]]]:
        """
        Standardize content format across all entries.
        
        Args:
            report_data: Report data to standardize
            
        Returns:
            Standardized report data
        """
        standardized_data = []
        
        for title, content in report_data:
            # Standardize title format
            standardized_title = self._standardize_title_format(title)
            
            # Standardize content format
            standardized_content = self._standardize_content_format_single(content)
            
            standardized_data.append((standardized_title, standardized_content))
        
        return standardized_data
    
    def _standardize_title_format(self, title: str) -> str:
        """
        Standardize title format.
        
        Args:
            title: Original title
            
        Returns:
            Standardized title
        """
        # Remove extra whitespace
        title = re.sub(r'\s+', ' ', title.strip())
        
        # Ensure consistent status format
        title = re.sub(r'\s*\(\s*(PASS|FAIL|ERROR|WARNING|INFO)\s*\)', r' (\1)', title)
        
        return title
    
    def _standardize_content_format_single(self, content: Union[str, Text, Dict[str, Any]]) -> Union[str, Text, Dict[str, Any]]:
        """
        Standardize format of a single content item.
        
        Args:
            content: Content to standardize
            
        Returns:
            Standardized content
        """
        if isinstance(content, dict):
            # Ensure standard keys are present
            standardized = content.copy()
            
            # Add missing standard fields
            if "timestamp" not in standardized:
                standardized["timestamp"] = datetime.now().isoformat()
            
            return standardized
        
        # For string content, ensure consistent formatting
        content_str = str(content)
        
        # Normalize line endings
        content_str = content_str.replace('\r\n', '\n').replace('\r', '\n')
        
        # Remove excessive whitespace
        content_str = re.sub(r'\n\s*\n\s*\n', '\n\n', content_str)
        
        return content_str
    
    def _validate_consistency(self, report_data: List[Tuple[str, Union[str, Text, Dict[str, Any]]]]) -> Dict[str, Any]:
        """
        Validate consistency of processed report data.
        
        Args:
            report_data: Processed report data
            
        Returns:
            Validation results
        """
        validation_results = {
            "total_sections": len(report_data),
            "duplicate_check": "PASS",
            "format_check": "PASS",
            "issues": []
        }
        
        # Check for remaining duplicates
        title_counts = defaultdict(int)
        for title, _ in report_data:
            clean_title = self._clean_title_for_similarity(title)
            title_counts[clean_title] += 1
        
        duplicates_found = [(title, count) for title, count in title_counts.items() if count > 1]
        if duplicates_found:
            validation_results["duplicate_check"] = "FAIL"
            validation_results["issues"].extend([f"Duplicate title: {title} ({count} times)" for title, count in duplicates_found])
            self.metrics.validation_checks_failed += 1
        else:
            self.metrics.validation_checks_passed += 1
        
        # Check format consistency
        format_issues = []
        for title, content in report_data:
            if not title or not title.strip():
                format_issues.append("Empty title found")
            if content is None:
                format_issues.append(f"Null content for title: {title}")
        
        if format_issues:
            validation_results["format_check"] = "FAIL"
            validation_results["issues"].extend(format_issues)
            self.metrics.validation_checks_failed += 1
        else:
            self.metrics.validation_checks_passed += 1
        
        self.logger.info(f"🔍 Validation complete: {validation_results['duplicate_check']} duplicates, {validation_results['format_check']} format")
        
        return validation_results

class MetadataStandardizer:
    """Standardizes metadata across all report formats."""
    
    def __init__(self):
        """Initialize the metadata standardizer."""
        self.required_fields = {
            "scan_date", "package_name", "scan_mode", "tool_version",
            "total_tests_run", "scan_duration_ms", "report_generation_time"
        }
        
    def standardize_metadata(self, metadata: Dict[str, Any], additional_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Standardize metadata across all formats.
        
        Args:
            metadata: Original metadata
            additional_data: Additional data to include
            
        Returns:
            Standardized metadata
        """
        standardized = metadata.copy()
        
        # Ensure required fields
        if "report_generation_time" not in standardized:
            standardized["report_generation_time"] = datetime.now().isoformat()
        
        if "scan_duration_ms" not in standardized:
            standardized["scan_duration_ms"] = 0
        
        # Add consistency tracking
        standardized["consistency_applied"] = True
        standardized["deduplication_enabled"] = True
        
        # Add additional data if provided
        if additional_data:
            standardized.update(additional_data)
        
        return standardized

# Convenience functions for integration
def process_report_for_consistency(
    report_data: List[Tuple[str, Union[str, Text, Dict[str, Any]]]]
) -> Tuple[List[Tuple[str, Union[str, Text, Dict[str, Any]]]], ConsistencyMetrics]:
    """
    Convenience function to process report data for consistency.
    
    Args:
        report_data: Report data to process
        
    Returns:
        Tuple of (processed_data, metrics)
    """
    manager = ReportConsistencyManager()
    return manager.process_report_data(report_data)

def standardize_report_metadata(
    metadata: Dict[str, Any], 
    additional_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Convenience function to standardize metadata.
    
    Args:
        metadata: Original metadata
        additional_data: Additional data to include
        
    Returns:
        Standardized metadata
    """
    standardizer = MetadataStandardizer()
    return standardizer.standardize_metadata(metadata, additional_data) 