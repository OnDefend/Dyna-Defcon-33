#!/usr/bin/env python3
"""
Unified Deduplication Framework - Data Structures
=================================================

This module contains all data structures and enums used throughout the
unified deduplication framework, consolidating the best features from
both existing deduplication engines.

Features:
- Unified deduplication result structures
- Comprehensive metrics tracking
- Strategy pattern support data models
- Performance and accuracy tracking

"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

class DuplicationType(Enum):
    """Types of duplication detected by the engine."""
    EXACT = "EXACT"                 # Identical findings
    SIMILAR = "SIMILAR"             # Similar patterns/content
    RELATED = "RELATED"             # Related vulnerability types
    EVIDENCE = "EVIDENCE"           # Same evidence, different analysis
    LOCATION = "LOCATION"           # Same location, different details
    PATTERN = "PATTERN"             # Same vulnerability pattern

class DeduplicationStrategy(Enum):
    """Available deduplication strategies."""
    BASIC = "BASIC"                 # Simple exact matching
    INTELLIGENT = "INTELLIGENT"     # Advanced similarity-based
    PRESERVATION = "PRESERVATION"   # Accuracy-preserving consolidation
    AGGRESSIVE = "AGGRESSIVE"       # Maximum duplicate removal
    CONSERVATIVE = "CONSERVATIVE"   # Minimal duplicate removal

class SimilarityLevel(Enum):
    """Levels of similarity between findings."""
    EXACT_MATCH = "EXACT_MATCH"           # 100% identical
    HIGH_SIMILARITY = "HIGH_SIMILARITY"   # 95%+ similar
    MODERATE_SIMILARITY = "MODERATE_SIMILARITY"  # 80-95% similar
    LOW_SIMILARITY = "LOW_SIMILARITY"     # 60-80% similar
    UNRELATED = "UNRELATED"               # <60% similar

class VulnerabilityType(Enum):
    """Vulnerability types with preservation priorities."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHY = "cryptography"
    HARDCODED_SECRETS = "hardcoded_secrets"
    SSL_TLS = "ssl_tls"
    PERMISSIONS = "permissions"
    INFO_DISCLOSURE = "info_disclosure"
    EXPORTED_COMPONENTS = "exported_components"
    INJECTION_VULNERABILITIES = "injection_vulnerabilities"
    GENERIC = "generic"

@dataclass
class SimilarityScore:
    """Detailed similarity scoring between two findings."""
    overall_score: float
    content_similarity: float
    location_similarity: float
    evidence_similarity: float
    pattern_similarity: float
    similarity_level: SimilarityLevel
    comparison_details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DuplicationGroup:
    """Group of duplicate or similar findings."""
    group_id: str
    primary_finding: Dict[str, Any]
    duplicate_findings: List[Dict[str, Any]]
    duplication_type: DuplicationType
    confidence_score: float
    consolidated_evidence: List[str]
    reasoning: List[str]
    similarity_scores: List[SimilarityScore] = field(default_factory=list)
    preservation_priority: int = 5
    vulnerability_type: Optional[VulnerabilityType] = None

@dataclass
class DeduplicationMetrics:
    """Comprehensive metrics for deduplication operations."""
    original_count: int
    final_count: int
    duplicates_removed: int
    groups_created: int
    processing_time_ms: float
    similarity_distribution: Dict[str, int] = field(default_factory=dict)
    vulnerability_type_counts: Dict[str, int] = field(default_factory=dict)
    preservation_stats: Dict[str, int] = field(default_factory=dict)
    accuracy_metrics: Dict[str, float] = field(default_factory=dict)

@dataclass
class DeduplicationResult:
    """Complete result of deduplication operation."""
    unique_findings: List[Dict[str, Any]]
    duplication_groups: List[DuplicationGroup]
    metrics: DeduplicationMetrics
    strategy_used: DeduplicationStrategy
    quality_assessment: str
    preservation_applied: bool
    recommendations: List[str] = field(default_factory=list)
    analysis_details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DeduplicationConfig:
    """Configuration for deduplication operations."""
    strategy: DeduplicationStrategy = DeduplicationStrategy.INTELLIGENT
    similarity_thresholds: Dict[str, float] = field(default_factory=lambda: {
        'exact_match': 1.0,
        'high_similarity': 0.95,
        'moderate_similarity': 0.85,
        'low_similarity': 0.7,
        'location_match': 0.90,
        'content_similarity': 0.75,
        'evidence_overlap': 0.70,
        'pattern_match': 0.80
    })
    preservation_priorities: Dict[str, int] = field(default_factory=lambda: {
        'sql_injection': 10,
        'xss': 9,
        'authentication': 8,
        'authorization': 8,
        'cryptography': 9,
        'hardcoded_secrets': 10,
        'ssl_tls': 8,
        'permissions': 6,
        'info_disclosure': 4,
        'exported_components': 7,
        'injection_vulnerabilities': 9,
        'generic': 2
    })
    enable_preservation: bool = True
    enable_evidence_consolidation: bool = True
    max_group_size: int = 50
    performance_mode: bool = False

@dataclass
class PatternDefinition:
    """Definition of a vulnerability pattern for grouping."""
    pattern_id: str
    vulnerability_type: VulnerabilityType
    regex_patterns: List[str]
    keywords: List[str]
    severity_indicators: List[str]
    exclusion_patterns: List[str] = field(default_factory=list)
    weight: float = 1.0

@dataclass
class ConsolidationRule:
    """Rule for consolidating evidence and findings."""
    rule_id: str
    rule_name: str
    applicable_types: List[VulnerabilityType]
    consolidation_logic: str  # Description of consolidation approach
    priority: int = 5
    enabled: bool = True

@dataclass
class DeduplicationAnalysis:
    """Analysis of duplication patterns in the dataset."""
    total_findings: int
    duplication_rate: float
    most_common_duplicates: List[Tuple[str, int]]
    vulnerability_type_distribution: Dict[str, int]
    similarity_patterns: Dict[str, List[str]]
    recommendation_summary: List[str]

# Default configurations for different strategies
DEFAULT_STRATEGIES = {
    DeduplicationStrategy.BASIC: DeduplicationConfig(
        strategy=DeduplicationStrategy.BASIC,
        similarity_thresholds={'exact_match': 1.0},
        enable_preservation=False,
        performance_mode=True
    ),
    
    DeduplicationStrategy.INTELLIGENT: DeduplicationConfig(
        strategy=DeduplicationStrategy.INTELLIGENT,
        enable_preservation=True,
        enable_evidence_consolidation=True
    ),
    
    DeduplicationStrategy.PRESERVATION: DeduplicationConfig(
        strategy=DeduplicationStrategy.PRESERVATION,
        similarity_thresholds={
            'exact_match': 1.0,
            'high_similarity': 0.98,  # Very strict
            'moderate_similarity': 0.90,
            'low_similarity': 0.80
        },
        enable_preservation=True,
        enable_evidence_consolidation=True
    ),
    
    DeduplicationStrategy.AGGRESSIVE: DeduplicationConfig(
        strategy=DeduplicationStrategy.AGGRESSIVE,
        similarity_thresholds={
            'exact_match': 1.0,
            'high_similarity': 0.85,  # More lenient
            'moderate_similarity': 0.70,
            'low_similarity': 0.60
        },
        enable_preservation=False,
        performance_mode=True
    ),
    
    DeduplicationStrategy.CONSERVATIVE: DeduplicationConfig(
        strategy=DeduplicationStrategy.CONSERVATIVE,
        similarity_thresholds={'exact_match': 1.0},
        enable_preservation=True,
        max_group_size=10
    )
}

# Vulnerability type classification patterns
VULNERABILITY_PATTERNS = {
    VulnerabilityType.SQL_INJECTION: PatternDefinition(
        pattern_id="sql_injection",
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        regex_patterns=[
            r"(?i)sql.*injection",
            r"(?i)database.*injection",
            r"(?i)query.*injection"
        ],
        keywords=["sql", "injection", "database", "query", "sqlite"],
        severity_indicators=["high", "critical", "severe"],
        weight=2.0
    ),
    
    VulnerabilityType.XSS: PatternDefinition(
        pattern_id="xss",
        vulnerability_type=VulnerabilityType.XSS,
        regex_patterns=[
            r"(?i)cross.*site.*scripting",
            r"(?i)xss",
            r"(?i)script.*injection"
        ],
        keywords=["xss", "scripting", "javascript", "script"],
        severity_indicators=["high", "medium"],
        weight=1.8
    ),
    
    VulnerabilityType.HARDCODED_SECRETS: PatternDefinition(
        pattern_id="hardcoded_secrets",
        vulnerability_type=VulnerabilityType.HARDCODED_SECRETS,
        regex_patterns=[
            r"(?i)hardcoded.*password",
            r"(?i)hardcoded.*secret",
            r"(?i)hardcoded.*key",
            r"(?i)hardcoded.*token"
        ],
        keywords=["hardcoded", "secret", "password", "key", "token", "api"],
        severity_indicators=["high", "critical"],
        weight=2.0
    )
}

# Performance optimization constants
PERFORMANCE_LIMITS = {
    'max_findings_per_batch': 1000,
    'max_comparison_operations': 50000,
    'similarity_calculation_timeout': 30,  # seconds
    'max_pattern_matches': 100,
    'cache_size_limit': 10000
} 