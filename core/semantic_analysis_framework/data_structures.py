"""
Core Data Structures for AODS Semantic Analysis Framework

This module defines the fundamental data structures used throughout the semantic
analysis framework, following AODS design patterns and conventions.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, Any, Set
from enum import Enum
import time


class SemanticNodeType(Enum):
    """Types of semantic nodes in the AST."""
    
    # Core language constructs
    METHOD = "method"
    CLASS = "class"
    VARIABLE = "variable"
    EXPRESSION = "expression"
    STATEMENT = "statement"
    
    # Security-relevant constructs
    API_CALL = "api_call"
    PERMISSION_REQUEST = "permission_request"
    NETWORK_REQUEST = "network_request"
    FILE_ACCESS = "file_access"
    CRYPTO_OPERATION = "crypto_operation"
    
    # Android-specific constructs
    INTENT = "intent"
    BROADCAST_RECEIVER = "broadcast_receiver"
    SERVICE = "service"
    ACTIVITY = "activity"
    CONTENT_PROVIDER = "content_provider"
    
    # Vulnerability patterns
    SQL_INJECTION = "sql_injection"
    XSS_VULNERABILITY = "xss_vulnerability"
    PATH_TRAVERSAL = "path_traversal"
    WEAK_CRYPTO = "weak_crypto"
    HARDCODED_SECRET = "hardcoded_secret"


class VulnerabilitySeverity(Enum):
    """Severity levels for detected vulnerabilities."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LanguageType(Enum):
    """Supported programming languages."""
    
    JAVA = "java"
    KOTLIN = "kotlin"
    JAVASCRIPT = "javascript"
    SMALI = "smali"
    XML = "xml"
    UNKNOWN = "unknown"


@dataclass
class LanguageInfo:
    """Information about the programming language being analyzed."""
    
    language: LanguageType
    version: Optional[str] = None
    framework: Optional[str] = None  # e.g., "android", "spring", "react"
    dialect: Optional[str] = None    # e.g., "dalvik" for Smali
    
    def __post_init__(self):
        if isinstance(self.language, str):
            self.language = LanguageType(self.language.lower())


@dataclass
class SemanticNode:
    """
    Represents a node in the semantic AST.
    
    This is the fundamental building block of the semantic analysis,
    containing code structure information and metadata.
    """
    
    node_type: SemanticNodeType
    name: str
    start_line: int
    end_line: int
    source_code: str
    
    # Hierarchical structure
    parent: Optional['SemanticNode'] = None
    children: List['SemanticNode'] = field(default_factory=list)
    
    # Semantic metadata
    attributes: Dict[str, Any] = field(default_factory=dict)
    annotations: List[str] = field(default_factory=list)
    
    # Security-related metadata
    security_relevant: bool = False
    potential_vulnerabilities: List['VulnerabilityPattern'] = field(default_factory=list)
    
    # Analysis metadata
    confidence_score: float = 0.0
    analysis_timestamp: float = field(default_factory=time.time)
    
    def add_child(self, child: 'SemanticNode'):
        """Add a child node and set parent relationship."""
        child.parent = self
        self.children.append(child)
    
    def get_ancestors(self) -> List['SemanticNode']:
        """Get all ancestor nodes up to the root."""
        ancestors = []
        current = self.parent
        while current:
            ancestors.append(current)
            current = current.parent
        return ancestors
    
    def get_descendants(self) -> List['SemanticNode']:
        """Get all descendant nodes recursively."""
        descendants = []
        for child in self.children:
            descendants.append(child)
            descendants.extend(child.get_descendants())
        return descendants
    
    def find_nodes_by_type(self, node_type: SemanticNodeType) -> List['SemanticNode']:
        """Find all descendant nodes of a specific type."""
        matches = []
        if self.node_type == node_type:
            matches.append(self)
        for child in self.children:
            matches.extend(child.find_nodes_by_type(node_type))
        return matches


@dataclass
class VulnerabilityPattern:
    """
    Represents a detected vulnerability pattern.
    """
    
    pattern_id: str
    pattern_name: str
    severity: VulnerabilitySeverity
    category: str  # OWASP category
    
    # Location information
    source_node: SemanticNode
    affected_lines: List[int]
    
    # Pattern details
    description: str
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.0
    
    # Remediation information
    recommendation: str = ""
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    
    # Context information
    context_data: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if isinstance(self.severity, str):
            self.severity = VulnerabilitySeverity(self.severity.lower())


@dataclass
class ParsingContext:
    """
    Context information for semantic parsing.
    """
    
    file_path: str
    language_info: LanguageInfo
    
    # Parsing options
    include_comments: bool = True
    include_imports: bool = True
    include_annotations: bool = True
    
    # Analysis depth
    max_depth: int = 50
    max_nodes: int = 10000
    
    # Performance settings
    timeout_seconds: int = 300
    enable_caching: bool = True
    
    # Framework integration
    use_shared_infrastructure: bool = True
    optimization_level: str = "balanced"  # "fast", "balanced", "comprehensive"
    
    # Security analysis settings
    vulnerability_detection: bool = True
    pattern_matching: bool = True
    semantic_analysis: bool = True


@dataclass
class ParsingStatistics:
    """Statistics about the parsing process."""
    
    # Timing information
    start_time: float
    end_time: float
    duration_seconds: float = field(init=False)
    
    # Parsing metrics
    total_nodes: int = 0
    parsed_lines: int = 0
    skipped_lines: int = 0
    
    # Analysis results
    vulnerabilities_found: int = 0
    patterns_matched: int = 0
    confidence_average: float = 0.0
    
    # Performance metrics
    memory_usage_mb: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    
    # Error information
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        self.duration_seconds = self.end_time - self.start_time


@dataclass
class SemanticParsingResult:
    """
    Complete result of semantic parsing and analysis.
    
    This is the main result structure returned by the semantic parser,
    containing all discovered information and analysis results.
    """
    
    # Basic information
    success: bool
    context: ParsingContext
    statistics: ParsingStatistics
    
    # Parsed structure
    root_node: Optional[SemanticNode] = None
    all_nodes: List[SemanticNode] = field(default_factory=list)
    
    # Security analysis results
    vulnerabilities: List[VulnerabilityPattern] = field(default_factory=list)
    security_nodes: List[SemanticNode] = field(default_factory=list)
    
    # Language-specific information
    imports: List[str] = field(default_factory=list)
    classes: List[SemanticNode] = field(default_factory=list)
    methods: List[SemanticNode] = field(default_factory=list)
    
    # Error handling
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    
    # Integration data
    raw_ast: Optional[Any] = None  # Original AST from language parser
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_vulnerabilities_by_severity(self, severity: VulnerabilitySeverity) -> List[VulnerabilityPattern]:
        """Get all vulnerabilities of a specific severity level."""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_critical_vulnerabilities(self) -> List[VulnerabilityPattern]:
        """Get all critical severity vulnerabilities."""
        return self.get_vulnerabilities_by_severity(VulnerabilitySeverity.CRITICAL)
    
    def get_high_vulnerabilities(self) -> List[VulnerabilityPattern]:
        """Get all high severity vulnerabilities."""
        return self.get_vulnerabilities_by_severity(VulnerabilitySeverity.HIGH)
    
    def get_vulnerability_summary(self) -> Dict[str, int]:
        """Get summary of vulnerabilities by severity."""
        summary = {severity.value: 0 for severity in VulnerabilitySeverity}
        for vuln in self.vulnerabilities:
            summary[vuln.severity.value] += 1
        return summary
    
    def has_critical_issues(self) -> bool:
        """Check if any critical vulnerabilities were found."""
        return any(v.severity == VulnerabilitySeverity.CRITICAL for v in self.vulnerabilities)


# Utility functions for data structure manipulation

def create_parsing_context(file_path: str, 
                          language: Union[str, LanguageType],
                          **kwargs) -> ParsingContext:
    """
    Factory function to create a parsing context with sensible defaults.
    
    Args:
        file_path: Path to the file being analyzed
        language: Programming language (string or enum)
        **kwargs: Additional context parameters
        
    Returns:
        Configured ParsingContext instance
    """
    if isinstance(language, str):
        language = LanguageType(language.lower())
    
    language_info = LanguageInfo(language=language)
    
    return ParsingContext(
        file_path=file_path,
        language_info=language_info,
        **kwargs
    )


def merge_parsing_results(results: List[SemanticParsingResult]) -> SemanticParsingResult:
    """
    Merge multiple parsing results into a single comprehensive result.
    
    This is useful when analyzing multiple files or combining results
    from different analysis passes.
    
    Args:
        results: List of parsing results to merge
        
    Returns:
        Merged parsing result
    """
    if not results:
        raise ValueError("Cannot merge empty list of results")
    
    if len(results) == 1:
        return results[0]
    
    # Use first result as base
    merged = results[0]
    
    # Merge data from other results
    for result in results[1:]:
        merged.all_nodes.extend(result.all_nodes)
        merged.vulnerabilities.extend(result.vulnerabilities)
        merged.security_nodes.extend(result.security_nodes)
        merged.imports.extend(result.imports)
        merged.classes.extend(result.classes)
        merged.methods.extend(result.methods)
        merged.warnings.extend(result.warnings)
    
    # Update statistics
    merged.statistics.total_nodes = len(merged.all_nodes)
    merged.statistics.vulnerabilities_found = len(merged.vulnerabilities)
    
    return merged 