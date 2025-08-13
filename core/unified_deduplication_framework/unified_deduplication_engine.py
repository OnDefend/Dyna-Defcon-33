#!/usr/bin/env python3
"""
Unified Deduplication Framework - Main Engine
=============================================

This module contains the main unified deduplication engine that consolidates
functionality from both the core deduplication engine and accuracy pipeline
deduplication engine into a single, professional system.

Features:
- Strategy pattern for different deduplication approaches
- Consolidated similarity algorithms from both engines
- vulnerability preservation logic
- Performance-optimized processing with caching
- Comprehensive metrics and analysis

"""

import hashlib
import logging
import re
import time
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from .data_structures import (
    DEFAULT_STRATEGIES,
    PERFORMANCE_LIMITS,
    VULNERABILITY_PATTERNS,
    ConsolidationRule,
    DeduplicationAnalysis,
    DeduplicationConfig,
    DeduplicationMetrics,
    DeduplicationResult,
    DeduplicationStrategy,
    DuplicationGroup,
    DuplicationType,
    PatternDefinition,
    SimilarityLevel,
    SimilarityScore,
    VulnerabilityType
)
from .similarity_calculator import UnifiedSimilarityCalculator

class UnifiedDeduplicationEngine:
    """
    Main unified deduplication engine that consolidates functionality from
    both existing deduplication engines into a single, professional system.
    
    This engine supports multiple strategies:
    - BASIC: Simple exact matching (performance-optimized)
    - INTELLIGENT: Advanced similarity-based consolidation
    - PRESERVATION: Accuracy-preserving deduplication
    - AGGRESSIVE: Maximum duplicate removal
    - CONSERVATIVE: Minimal duplicate removal with high confidence
    """
    
    def __init__(self, config: Optional[DeduplicationConfig] = None):
        """Initialize the unified deduplication engine."""
        self.logger = logging.getLogger(__name__)
        self.config = config or DEFAULT_STRATEGIES[DeduplicationStrategy.INTELLIGENT]
        
        # Initialize components
        self.similarity_calculator = UnifiedSimilarityCalculator(self.config.similarity_thresholds)
        self.vulnerability_patterns = VULNERABILITY_PATTERNS
        self.consolidation_rules = self._load_consolidation_rules()
        
        # Performance optimization
        self._similarity_cache = {}
        self._pattern_cache = {}
        self._group_cache = {}
        
        self.logger.info(f"Unified Deduplication Engine initialized with {self.config.strategy.value} strategy")
    
    def deduplicate_findings(self, findings: List[Dict[str, Any]], 
                           config_override: Optional[DeduplicationConfig] = None) -> DeduplicationResult:
        """
        Main deduplication method that applies the configured strategy to eliminate
        duplicate findings while preserving unique vulnerabilities.
        
        Args:
            findings: List of vulnerability findings to deduplicate
            config_override: Optional configuration override
            
        Returns:
            DeduplicationResult with unique findings and comprehensive analysis
        """
        start_time = time.perf_counter()
        effective_config = config_override or self.config
        
        self.logger.info(f"Starting unified deduplication: {len(findings)} findings")
        self.logger.info(f"Strategy: {effective_config.strategy.value}")
        
        try:
            # Clear caches for new operation
            self._clear_caches()
            
            # Apply strategy-specific deduplication
            if effective_config.strategy == DeduplicationStrategy.BASIC:
                result = self._apply_basic_deduplication(findings, effective_config)
            elif effective_config.strategy == DeduplicationStrategy.PRESERVATION:
                result = self._apply_preservation_deduplication(findings, effective_config)
            elif effective_config.strategy == DeduplicationStrategy.AGGRESSIVE:
                result = self._apply_aggressive_deduplication(findings, effective_config)
            elif effective_config.strategy == DeduplicationStrategy.CONSERVATIVE:
                result = self._apply_conservative_deduplication(findings, effective_config)
            else:  # INTELLIGENT (default)
                result = self._apply_intelligent_deduplication(findings, effective_config)
            
            # Calculate comprehensive metrics
            processing_time = (time.perf_counter() - start_time) * 1000
            result.metrics.processing_time_ms = processing_time
            
            # Perform quality assessment
            result.quality_assessment = self._assess_deduplication_quality(result)
            
            # Generate recommendations
            result.recommendations = self._generate_recommendations(result)
            
            self.logger.info(f"Deduplication completed: {len(findings)} -> {len(result.unique_findings)} "
                           f"({result.metrics.duplicates_removed} duplicates removed in {processing_time:.2f}ms)")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Deduplication failed: {e}")
            # Return fallback result
            return self._create_fallback_result(findings, effective_config, str(e))
    
    def _apply_basic_deduplication(self, findings: List[Dict[str, Any]], 
                                 config: DeduplicationConfig) -> DeduplicationResult:
        """Apply basic exact-match deduplication for performance."""
        seen_hashes = set()
        unique_findings = []
        duplicate_count = 0
        
        for finding in findings:
            finding_hash = self._calculate_finding_hash(finding)
            if finding_hash not in seen_hashes:
                seen_hashes.add(finding_hash)
                unique_findings.append(finding)
            else:
                duplicate_count += 1
        
        metrics = DeduplicationMetrics(
            original_count=len(findings),
            final_count=len(unique_findings),
            duplicates_removed=duplicate_count,
            groups_created=0,
            processing_time_ms=0.0,
            similarity_distribution={'exact': duplicate_count}
        )
        
        return DeduplicationResult(
            unique_findings=unique_findings,
            duplication_groups=[],
            metrics=metrics,
            strategy_used=DeduplicationStrategy.BASIC,
            quality_assessment="Basic exact-match deduplication",
            preservation_applied=False
        )
    
    def _apply_intelligent_deduplication(self, findings: List[Dict[str, Any]], 
                                       config: DeduplicationConfig) -> DeduplicationResult:
        """Apply intelligent similarity-based deduplication."""
        # Step 1: Group findings by similarity
        duplication_groups = self._create_duplication_groups(findings, config)
        
        # Step 2: Select primary findings from each group
        unique_findings = []
        for group in duplication_groups:
            # Use the most comprehensive finding as primary
            primary = self._select_primary_finding(group, config)
            if config.enable_evidence_consolidation:
                primary = self._consolidate_evidence(group, primary, config)
            unique_findings.append(primary)
        
        # Step 3: Add ungrouped findings
        grouped_finding_ids = set()
        for group in duplication_groups:
            grouped_finding_ids.add(id(group.primary_finding))
            for dup in group.duplicate_findings:
                grouped_finding_ids.add(id(dup))
        
        for finding in findings:
            if id(finding) not in grouped_finding_ids:
                unique_findings.append(finding)
        
        # Calculate metrics
        metrics = self._calculate_comprehensive_metrics(
            findings, unique_findings, duplication_groups
        )
        
        return DeduplicationResult(
            unique_findings=unique_findings,
            duplication_groups=duplication_groups,
            metrics=metrics,
            strategy_used=DeduplicationStrategy.INTELLIGENT,
            quality_assessment="Intelligent similarity-based deduplication",
            preservation_applied=config.enable_preservation
        )
    
    def _apply_preservation_deduplication(self, findings: List[Dict[str, Any]], 
                                        config: DeduplicationConfig) -> DeduplicationResult:
        """Apply accuracy-preserving deduplication that maximizes vulnerability retention."""
        # Use very strict similarity thresholds
        strict_config = DeduplicationConfig(
            strategy=DeduplicationStrategy.PRESERVATION,
            similarity_thresholds={
                'exact_match': 1.0,
                'high_similarity': 0.98,
                'moderate_similarity': 0.92,
                'low_similarity': 0.85
            },
            enable_preservation=True,
            enable_evidence_consolidation=True
        )
        
        # Apply preservation logic
        groups = self._create_duplication_groups_conservative(findings, strict_config)
        
        # Preserve high-priority vulnerabilities
        unique_findings = []
        for group in groups:
            if self._should_preserve_group(group, strict_config):
                # Preserve all findings in high-priority groups
                unique_findings.append(group.primary_finding)
                for dup in group.duplicate_findings:
                    if self._is_unique_enough(dup, group.primary_finding, strict_config):
                        unique_findings.append(dup)
            else:
                # Standard consolidation for low-priority groups
                primary = self._select_primary_finding(group, strict_config)
                unique_findings.append(primary)
        
        # Add ungrouped findings
        grouped_ids = set()
        for group in groups:
            grouped_ids.add(id(group.primary_finding))
            for dup in group.duplicate_findings:
                grouped_ids.add(id(dup))
        
        for finding in findings:
            if id(finding) not in grouped_ids:
                unique_findings.append(finding)
        
        metrics = self._calculate_comprehensive_metrics(findings, unique_findings, groups)
        
        return DeduplicationResult(
            unique_findings=unique_findings,
            duplication_groups=groups,
            metrics=metrics,
            strategy_used=DeduplicationStrategy.PRESERVATION,
            quality_assessment="Accuracy-preserving deduplication with maximum vulnerability retention",
            preservation_applied=True
        )
    
    def _apply_aggressive_deduplication(self, findings: List[Dict[str, Any]], 
                                      config: DeduplicationConfig) -> DeduplicationResult:
        """Apply aggressive deduplication for maximum duplicate removal."""
        # Use more lenient similarity thresholds
        aggressive_config = DeduplicationConfig(
            strategy=DeduplicationStrategy.AGGRESSIVE,
            similarity_thresholds={
                'exact_match': 1.0,
                'high_similarity': 0.80,
                'moderate_similarity': 0.65,
                'low_similarity': 0.50
            },
            enable_preservation=False,
            performance_mode=True
        )
        
        # Group with lenient thresholds
        groups = self._create_duplication_groups(findings, aggressive_config)
        
        # Select only the best finding from each group
        unique_findings = []
        for group in groups:
            primary = self._select_best_finding(group, aggressive_config)
            unique_findings.append(primary)
        
        # Add ungrouped findings
        grouped_ids = set()
        for group in groups:
            grouped_ids.add(id(group.primary_finding))
            for dup in group.duplicate_findings:
                grouped_ids.add(id(dup))
        
        for finding in findings:
            if id(finding) not in grouped_ids:
                unique_findings.append(finding)
        
        metrics = self._calculate_comprehensive_metrics(findings, unique_findings, groups)
        
        return DeduplicationResult(
            unique_findings=unique_findings,
            duplication_groups=groups,
            metrics=metrics,
            strategy_used=DeduplicationStrategy.AGGRESSIVE,
            quality_assessment="Aggressive deduplication with maximum duplicate removal",
            preservation_applied=False
        )
    
    def _apply_conservative_deduplication(self, findings: List[Dict[str, Any]], 
                                        config: DeduplicationConfig) -> DeduplicationResult:
        """Apply conservative deduplication with minimal grouping."""
        # Only group exact matches
        exact_groups = []
        exact_hashes = defaultdict(list)
        
        for finding in findings:
            finding_hash = self._calculate_finding_hash(finding)
            exact_hashes[finding_hash].append(finding)
        
        # Create groups only for exact duplicates
        for finding_hash, duplicate_findings in exact_hashes.items():
            if len(duplicate_findings) > 1:
                primary = duplicate_findings[0]
                duplicates = duplicate_findings[1:]
                
                group = DuplicationGroup(
                    group_id=finding_hash[:12],
                    primary_finding=primary,
                    duplicate_findings=duplicates,
                    duplication_type=DuplicationType.EXACT,
                    confidence_score=1.0,
                    consolidated_evidence=[],
                    reasoning=["Exact hash match"]
                )
                exact_groups.append(group)
        
        # Select unique findings
        unique_findings = []
        for finding_hash, duplicate_findings in exact_hashes.items():
            unique_findings.append(duplicate_findings[0])  # Take first of each group
        
        metrics = self._calculate_comprehensive_metrics(findings, unique_findings, exact_groups)
        
        return DeduplicationResult(
            unique_findings=unique_findings,
            duplication_groups=exact_groups,
            metrics=metrics,
            strategy_used=DeduplicationStrategy.CONSERVATIVE,
            quality_assessment="Conservative deduplication with exact matches only",
            preservation_applied=True
        )
    
    def _create_duplication_groups(self, findings: List[Dict[str, Any]], 
                                 config: DeduplicationConfig) -> List[DuplicationGroup]:
        """Create duplication groups using similarity analysis."""
        if len(findings) > PERFORMANCE_LIMITS['max_findings_per_batch'] and config.performance_mode:
            return self._create_groups_optimized(findings, config)
        
        groups = []
        processed_indices = set()
        
        for i, finding in enumerate(findings):
            if i in processed_indices:
                continue
            
            # Find similar findings
            similar_findings = []
            group_reasoning = []
            
            for j, other_finding in enumerate(findings[i+1:], i+1):
                if j in processed_indices:
                    continue
                
                similarity = self.similarity_calculator.calculate_similarity(finding, other_finding)
                
                if similarity.similarity_level in [SimilarityLevel.EXACT_MATCH, SimilarityLevel.HIGH_SIMILARITY]:
                    similar_findings.append(other_finding)
                    processed_indices.add(j)
                    group_reasoning.append(f"Similarity: {similarity.overall_score:.2f}")
            
            # Create group if duplicates found
            if similar_findings:
                group_id = hashlib.md5(str(id(finding)).encode()).hexdigest()[:12]
                
                group = DuplicationGroup(
                    group_id=group_id,
                    primary_finding=finding,
                    duplicate_findings=similar_findings,
                    duplication_type=self._determine_duplication_type(finding, similar_findings),
                    confidence_score=self._calculate_group_confidence(finding, similar_findings),
                    consolidated_evidence=[],
                    reasoning=group_reasoning,
                    vulnerability_type=self._classify_vulnerability_type(finding)
                )
                
                groups.append(group)
                processed_indices.add(i)
        
        return groups
    
    def _create_duplication_groups_conservative(self, findings: List[Dict[str, Any]], 
                                              config: DeduplicationConfig) -> List[DuplicationGroup]:
        """Create duplication groups with conservative similarity thresholds."""
        groups = []
        processed_indices = set()
        
        for i, finding in enumerate(findings):
            if i in processed_indices:
                continue
            
            similar_findings = []
            for j, other_finding in enumerate(findings[i+1:], i+1):
                if j in processed_indices:
                    continue
                
                similarity = self.similarity_calculator.calculate_similarity(finding, other_finding)
                
                # Very strict similarity requirements for preservation
                if similarity.overall_score >= config.similarity_thresholds.get('high_similarity', 0.98):
                    similar_findings.append(other_finding)
                    processed_indices.add(j)
            
            if similar_findings:
                group_id = hashlib.md5(str(id(finding)).encode()).hexdigest()[:12]
                
                group = DuplicationGroup(
                    group_id=group_id,
                    primary_finding=finding,
                    duplicate_findings=similar_findings,
                    duplication_type=DuplicationType.EXACT,
                    confidence_score=1.0,
                    consolidated_evidence=[],
                    reasoning=["Conservative high-similarity match"],
                    vulnerability_type=self._classify_vulnerability_type(finding)
                )
                
                groups.append(group)
                processed_indices.add(i)
        
        return groups
    
    def _select_primary_finding(self, group: DuplicationGroup, config: DeduplicationConfig) -> Dict[str, Any]:
        """Select the primary finding from a duplication group."""
        all_findings = [group.primary_finding] + group.duplicate_findings
        
        # Score findings based on completeness and quality
        best_finding = group.primary_finding
        best_score = self._calculate_finding_quality_score(best_finding)
        
        for finding in group.duplicate_findings:
            score = self._calculate_finding_quality_score(finding)
            if score > best_score:
                best_score = score
                best_finding = finding
        
        return best_finding
    
    def _calculate_finding_quality_score(self, finding: Dict[str, Any]) -> float:
        """Calculate quality score for finding selection."""
        score = 0.0
        
        # Evidence completeness
        evidence = finding.get('evidence', [])
        score += len(evidence) * 0.1
        
        # Description quality
        description = finding.get('description', '')
        score += len(description) / 100  # Longer descriptions are often better
        
        # Severity consideration
        severity = finding.get('severity', '').lower()
        if severity in ['critical', 'high']:
            score += 2.0
        elif severity == 'medium':
            score += 1.0
        
        # Confidence score
        confidence = finding.get('confidence', 0.0)
        if isinstance(confidence, (int, float)):
            score += confidence
        
        return score
    
    def _consolidate_evidence(self, group: DuplicationGroup, primary: Dict[str, Any], 
                            config: DeduplicationConfig) -> Dict[str, Any]:
        """Consolidate evidence from all findings in the group."""
        if not config.enable_evidence_consolidation:
            return primary
        
        consolidated = primary.copy()
        all_evidence = set(primary.get('evidence', []))
        
        # Collect evidence from all findings
        for finding in group.duplicate_findings:
            finding_evidence = finding.get('evidence', [])
            all_evidence.update(finding_evidence)
        
        consolidated['evidence'] = list(all_evidence)
        consolidated['consolidated_from'] = len(group.duplicate_findings) + 1
        
        return consolidated
    
    def _calculate_comprehensive_metrics(self, original_findings: List[Dict[str, Any]], 
                                       unique_findings: List[Dict[str, Any]], 
                                       groups: List[DuplicationGroup]) -> DeduplicationMetrics:
        """Calculate comprehensive deduplication metrics."""
        duplicates_removed = len(original_findings) - len(unique_findings)
        
        # Similarity distribution
        similarity_dist = defaultdict(int)
        for group in groups:
            similarity_dist[group.duplication_type.value] += len(group.duplicate_findings)
        
        # Vulnerability type distribution
        vuln_types = defaultdict(int)
        for finding in original_findings:
            vuln_type = self._classify_vulnerability_type(finding)
            if vuln_type:
                vuln_types[vuln_type.value] += 1
        
        return DeduplicationMetrics(
            original_count=len(original_findings),
            final_count=len(unique_findings),
            duplicates_removed=duplicates_removed,
            groups_created=len(groups),
            processing_time_ms=0.0,  # Set by caller
            similarity_distribution=dict(similarity_dist),
            vulnerability_type_counts=dict(vuln_types),
            preservation_stats={
                'groups_with_preservation': sum(1 for g in groups if g.confidence_score > 0.8),
                'evidence_consolidated': sum(1 for g in groups if g.consolidated_evidence)
            }
        )
    
    def _calculate_finding_hash(self, finding: Dict[str, Any]) -> str:
        """Calculate hash for exact duplicate detection."""
        # Create stable hash from key identifying fields
        hash_content = []
        
        for key in ['title', 'description', 'location', 'file_path', 'line_number']:
            value = finding.get(key, '')
            hash_content.append(f"{key}:{value}")
        
        content_str = '|'.join(hash_content)
        return hashlib.md5(content_str.encode('utf-8')).hexdigest()
    
    def _classify_vulnerability_type(self, finding: Dict[str, Any]) -> Optional[VulnerabilityType]:
        """Classify finding into vulnerability type for prioritization."""
        title = finding.get('title', '').lower()
        description = finding.get('description', '').lower()
        content = f"{title} {description}"
        
        # Check against known patterns
        for vuln_type, pattern_def in self.vulnerability_patterns.items():
            for pattern in pattern_def.regex_patterns:
                if re.search(pattern, content):
                    return vuln_type
            
            for keyword in pattern_def.keywords:
                if keyword in content:
                    return vuln_type
        
        return VulnerabilityType.GENERIC
    
    def _determine_duplication_type(self, primary: Dict[str, Any], 
                                  duplicates: List[Dict[str, Any]]) -> DuplicationType:
        """Determine the type of duplication in the group."""
        # Simple heuristic based on similarity
        primary_hash = self._calculate_finding_hash(primary)
        
        for duplicate in duplicates:
            dup_hash = self._calculate_finding_hash(duplicate)
            if primary_hash == dup_hash:
                return DuplicationType.EXACT
        
        return DuplicationType.SIMILAR
    
    def _calculate_group_confidence(self, primary: Dict[str, Any], 
                                  duplicates: List[Dict[str, Any]]) -> float:
        """Calculate confidence score for the duplication group."""
        if not duplicates:
            return 1.0
        
        similarities = []
        for duplicate in duplicates:
            similarity = self.similarity_calculator.calculate_similarity(primary, duplicate)
            similarities.append(similarity.overall_score)
        
        return sum(similarities) / len(similarities) if similarities else 0.0
    
    def _assess_deduplication_quality(self, result: DeduplicationResult) -> str:
        """Assess the quality of deduplication results."""
        metrics = result.metrics
        reduction_rate = metrics.duplicates_removed / metrics.original_count if metrics.original_count > 0 else 0
        
        if reduction_rate > 0.5:
            return "Excellent deduplication - high duplicate reduction achieved"
        elif reduction_rate > 0.3:
            return "Good deduplication - moderate duplicate reduction"
        elif reduction_rate > 0.1:
            return "Acceptable deduplication - some duplicates removed"
        else:
            return "Minimal deduplication - few duplicates detected"
    
    def _generate_recommendations(self, result: DeduplicationResult) -> List[str]:
        """Generate recommendations based on deduplication results."""
        recommendations = []
        metrics = result.metrics
        
        if metrics.duplicates_removed == 0:
            recommendations.append("No duplicates found - consider reviewing similarity thresholds")
        
        if metrics.groups_created > 50:
            recommendations.append("Many duplication groups found - consider more aggressive deduplication")
        
        if result.strategy_used == DeduplicationStrategy.BASIC and metrics.duplicates_removed > 10:
            recommendations.append("Consider using INTELLIGENT strategy for better consolidation")
        
        return recommendations
    
    def _create_fallback_result(self, findings: List[Dict[str, Any]], 
                              config: DeduplicationConfig, error_msg: str) -> DeduplicationResult:
        """Create fallback result when deduplication fails."""
        metrics = DeduplicationMetrics(
            original_count=len(findings),
            final_count=len(findings),
            duplicates_removed=0,
            groups_created=0,
            processing_time_ms=0.0
        )
        
        return DeduplicationResult(
            unique_findings=findings,
            duplication_groups=[],
            metrics=metrics,
            strategy_used=config.strategy,
            quality_assessment=f"Deduplication failed: {error_msg}",
            preservation_applied=False,
            analysis_details={'error': error_msg}
        )
    
    def _clear_caches(self):
        """Clear internal caches for new operation."""
        self._similarity_cache.clear()
        self._pattern_cache.clear()
        self._group_cache.clear()
    
    def _load_consolidation_rules(self) -> List[ConsolidationRule]:
        """Load consolidation rules for evidence merging."""
        return [
            ConsolidationRule(
                rule_id="high_priority_preserve",
                rule_name="High Priority Vulnerability Preservation",
                applicable_types=[VulnerabilityType.SQL_INJECTION, VulnerabilityType.HARDCODED_SECRETS],
                consolidation_logic="Preserve all instances of high-priority vulnerabilities",
                priority=10
            ),
            ConsolidationRule(
                rule_id="evidence_merge",
                rule_name="Evidence Consolidation",
                applicable_types=list(VulnerabilityType),
                consolidation_logic="Merge evidence from similar findings",
                priority=5
            )
        ]
    
    # Additional helper methods for strategy-specific logic
    def _should_preserve_group(self, group: DuplicationGroup, config: DeduplicationConfig) -> bool:
        """Determine if a group should be preserved (multiple findings kept)."""
        if not config.enable_preservation:
            return False
        
        vuln_type = group.vulnerability_type
        if vuln_type and vuln_type in [VulnerabilityType.SQL_INJECTION, VulnerabilityType.HARDCODED_SECRETS]:
            return True
        
        return group.confidence_score < 0.9  # Preserve when not highly confident
    
    def _is_unique_enough(self, finding: Dict[str, Any], primary: Dict[str, Any], 
                         config: DeduplicationConfig) -> bool:
        """Check if a finding is unique enough to preserve separately."""
        similarity = self.similarity_calculator.calculate_similarity(finding, primary)
        return similarity.overall_score < config.similarity_thresholds.get('moderate_similarity', 0.85)
    
    def _select_best_finding(self, group: DuplicationGroup, config: DeduplicationConfig) -> Dict[str, Any]:
        """Select the single best finding from a group (for aggressive strategy)."""
        return self._select_primary_finding(group, config)
    
    def _create_groups_optimized(self, findings: List[Dict[str, Any]], 
                               config: DeduplicationConfig) -> List[DuplicationGroup]:
        """Optimized grouping for large datasets."""
        # Use hash-based pre-grouping for performance
        hash_groups = defaultdict(list)
        
        for finding in findings:
            finding_hash = self._calculate_finding_hash(finding)[:8]  # Shorter hash for grouping
            hash_groups[finding_hash].append(finding)
        
        groups = []
        for hash_key, group_findings in hash_groups.items():
            if len(group_findings) > 1:
                primary = group_findings[0]
                duplicates = group_findings[1:]
                
                group = DuplicationGroup(
                    group_id=hash_key,
                    primary_finding=primary,
                    duplicate_findings=duplicates,
                    duplication_type=DuplicationType.SIMILAR,
                    confidence_score=0.8,
                    consolidated_evidence=[],
                    reasoning=["Hash-based grouping (performance mode)"]
                )
                groups.append(group)
        
        return groups 