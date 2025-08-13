#!/usr/bin/env python3
"""
Unified Deduplication Framework
==============================

This package provides a comprehensive, unified deduplication system that
consolidates functionality from both the core deduplication engine and
the accuracy integration pipeline deduplication engine.

Key Features:
- Strategy pattern with multiple deduplication approaches
- Consolidated similarity algorithms from both engines
- vulnerability preservation logic
- Performance-optimized processing with caching
- Comprehensive metrics and analysis
- 100% backward compatibility with existing systems

Usage:
    from core.unified_deduplication_framework import (
        UnifiedDeduplicationEngine, 
        DeduplicationStrategy,
        create_deduplication_engine
    )
    
    # Create engine with intelligent strategy
    engine = create_deduplication_engine(DeduplicationStrategy.INTELLIGENT)
    
    # Deduplicate findings
    result = engine.deduplicate_findings(findings)

"""

from .data_structures import (
    # Core data structures
    DeduplicationConfig,
    DeduplicationResult,
    DeduplicationMetrics,
    DeduplicationAnalysis,
    DuplicationGroup,
    SimilarityScore,
    
    # Enums
    DeduplicationStrategy,
    DuplicationType,
    SimilarityLevel,
    VulnerabilityType,
    
    # Configuration and patterns
    DEFAULT_STRATEGIES,
    VULNERABILITY_PATTERNS,
    PERFORMANCE_LIMITS,
    
    # Additional structures
    PatternDefinition,
    ConsolidationRule
)

from .unified_deduplication_engine import UnifiedDeduplicationEngine
from .similarity_calculator import UnifiedSimilarityCalculator

# Version information
__version__ = "1.0.0"
__author__ = "AODS Development Team"
__description__ = "Unified Deduplication Framework for AODS"

# Compatibility aliases for existing code
DeduplicationEngine = UnifiedDeduplicationEngine  # Backward compatibility
IntelligentDeduplicationEngine = UnifiedDeduplicationEngine  # Accuracy pipeline compatibility

def create_deduplication_engine(strategy: DeduplicationStrategy = DeduplicationStrategy.INTELLIGENT,
                               custom_config: DeduplicationConfig = None) -> UnifiedDeduplicationEngine:
    """
    Create a deduplication engine with the specified strategy.
    
    Args:
        strategy: Deduplication strategy to use
        custom_config: Optional custom configuration
        
    Returns:
        Configured UnifiedDeduplicationEngine instance
    """
    if custom_config:
        config = custom_config
    else:
        config = DEFAULT_STRATEGIES.get(strategy, DEFAULT_STRATEGIES[DeduplicationStrategy.INTELLIGENT])
    
    return UnifiedDeduplicationEngine(config)

def deduplicate_findings(findings, strategy: DeduplicationStrategy = DeduplicationStrategy.INTELLIGENT):
    """
    Convenience function to deduplicate findings with default settings.
    
    Args:
        findings: List of vulnerability findings to deduplicate
        strategy: Deduplication strategy to use
        
    Returns:
        DeduplicationResult with unique findings and analysis
    """
    engine = create_deduplication_engine(strategy)
    return engine.deduplicate_findings(findings)

def create_similarity_calculator(thresholds: dict = None) -> UnifiedSimilarityCalculator:
    """
    Create a similarity calculator with optional custom thresholds.
    
    Args:
        thresholds: Optional custom similarity thresholds
        
    Returns:
        Configured UnifiedSimilarityCalculator instance
    """
    default_thresholds = DEFAULT_STRATEGIES[DeduplicationStrategy.INTELLIGENT].similarity_thresholds
    effective_thresholds = thresholds or default_thresholds
    
    return UnifiedSimilarityCalculator(effective_thresholds)

def analyze_deduplication_potential(findings) -> DeduplicationAnalysis:
    """
    Analyze the deduplication potential of a set of findings.
    
    Args:
        findings: List of vulnerability findings to analyze
        
    Returns:
        DeduplicationAnalysis with insights about duplication patterns
    """
    from collections import defaultdict, Counter
    import hashlib
    
    # Quick analysis without full deduplication
    total_findings = len(findings)
    finding_hashes = []
    vuln_types = defaultdict(int)
    titles = []
    
    for finding in findings:
        # Calculate hash for exact duplicates
        hash_content = f"{finding.get('title', '')}{finding.get('file_path', '')}"
        finding_hash = hashlib.md5(hash_content.encode()).hexdigest()
        finding_hashes.append(finding_hash)
        
        # Count vulnerability types
        title = finding.get('title', '').lower()
        titles.append(title)
        
        # Simple classification
        if 'sql' in title or 'injection' in title:
            vuln_types['sql_injection'] += 1
        elif 'xss' in title or 'scripting' in title:
            vuln_types['xss'] += 1
        elif 'hardcoded' in title or 'secret' in title:
            vuln_types['hardcoded_secrets'] += 1
        else:
            vuln_types['generic'] += 1
    
    # Calculate duplication rate
    unique_hashes = len(set(finding_hashes))
    duplication_rate = (total_findings - unique_hashes) / total_findings if total_findings > 0 else 0
    
    # Find most common duplicates
    hash_counts = Counter(finding_hashes)
    most_common = [(hash_val[:8], count) for hash_val, count in hash_counts.most_common(5) if count > 1]
    
    # Generate recommendations
    recommendations = []
    if duplication_rate > 0.3:
        recommendations.append("High duplication rate detected - consider AGGRESSIVE strategy")
    elif duplication_rate > 0.1:
        recommendations.append("Moderate duplication rate - INTELLIGENT strategy recommended")
    else:
        recommendations.append("Low duplication rate - CONSERVATIVE strategy may be sufficient")
    
    if vuln_types.get('sql_injection', 0) > 5:
        recommendations.append("Many SQL injection findings - consider PRESERVATION strategy")
    
    return DeduplicationAnalysis(
        total_findings=total_findings,
        duplication_rate=duplication_rate,
        most_common_duplicates=most_common,
        vulnerability_type_distribution=dict(vuln_types),
        similarity_patterns={},  # Simplified for quick analysis
        recommendation_summary=recommendations
    )

def migrate_from_legacy_engine(legacy_result):
    """
    Migrate results from legacy deduplication engines to unified format.
    
    Args:
        legacy_result: Result from old deduplication engine
        
    Returns:
        DeduplicationResult in unified format
    """
    # Handle different legacy result formats
    if isinstance(legacy_result, dict):
        unique_findings = legacy_result.get('unique_findings', [])
        original_count = legacy_result.get('original_count', len(unique_findings))
        
        metrics = DeduplicationMetrics(
            original_count=original_count,
            final_count=len(unique_findings),
            duplicates_removed=original_count - len(unique_findings),
            groups_created=legacy_result.get('groups_created', 0),
            processing_time_ms=legacy_result.get('processing_time', 0.0)
        )
        
        return DeduplicationResult(
            unique_findings=unique_findings,
            duplication_groups=[],
            metrics=metrics,
            strategy_used=DeduplicationStrategy.INTELLIGENT,
            quality_assessment="Migrated from legacy engine",
            preservation_applied=legacy_result.get('preservation_applied', False)
        )
    
    # If it's already a list, assume it's just the unique findings
    elif isinstance(legacy_result, list):
        metrics = DeduplicationMetrics(
            original_count=len(legacy_result),
            final_count=len(legacy_result),
            duplicates_removed=0,
            groups_created=0,
            processing_time_ms=0.0
        )
        
        return DeduplicationResult(
            unique_findings=legacy_result,
            duplication_groups=[],
            metrics=metrics,
            strategy_used=DeduplicationStrategy.BASIC,
            quality_assessment="Migrated from legacy list format",
            preservation_applied=False
        )
    
    else:
        raise ValueError(f"Unsupported legacy result format: {type(legacy_result)}")

def get_framework_info() -> dict:
    """
    Get information about the unified deduplication framework.
    
    Returns:
        Dictionary with framework information
    """
    return {
        'version': __version__,
        'author': __author__,
        'description': __description__,
        'strategies_available': [strategy.value for strategy in DeduplicationStrategy],
        'vulnerability_types_supported': [vtype.value for vtype in VulnerabilityType],
        'features': [
            'Strategy pattern with multiple approaches',
            'Consolidated similarity algorithms',
            'Vulnerability preservation logic',
            'Performance optimization with caching',
            'Comprehensive metrics and analysis',
            'Backward compatibility with existing systems'
        ],
        'performance_limits': PERFORMANCE_LIMITS.copy()
    }

def validate_findings_format(findings) -> bool:
    """
    Validate that findings are in the expected format.
    
    Args:
        findings: List of findings to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not isinstance(findings, list):
        return False
    
    for finding in findings:
        if not isinstance(finding, dict):
            return False
        
        # Check for required fields (flexible requirements)
        if not any(key in finding for key in ['title', 'description', 'type']):
            return False
    
    return True

# Export all public components
__all__ = [
    # Main classes
    'UnifiedDeduplicationEngine',
    'UnifiedSimilarityCalculator',
    
    # Data structures
    'DeduplicationConfig',
    'DeduplicationResult',
    'DeduplicationMetrics',
    'DeduplicationAnalysis',
    'DuplicationGroup',
    'SimilarityScore',
    
    # Enums
    'DeduplicationStrategy',
    'DuplicationType',
    'SimilarityLevel',
    'VulnerabilityType',
    
    # Configuration
    'DEFAULT_STRATEGIES',
    'VULNERABILITY_PATTERNS',
    'PERFORMANCE_LIMITS',
    
    # Convenience functions
    'create_deduplication_engine',
    'deduplicate_findings',
    'create_similarity_calculator',
    'analyze_deduplication_potential',
    'migrate_from_legacy_engine',
    'get_framework_info',
    'validate_findings_format',
    
    # Backward compatibility aliases
    'DeduplicationEngine',
    'IntelligentDeduplicationEngine'
]

# Framework initialization message
import logging
logger = logging.getLogger(__name__)
logger.info(f"Unified Deduplication Framework v{__version__} initialized")
logger.info(f"Available strategies: {[s.value for s in DeduplicationStrategy]}")
logger.info("Framework ready for vulnerability finding deduplication") 