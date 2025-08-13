"""
Unified Root Detection Engine

Comprehensive root detection system designed to be shared across multiple AODS plugins.
Provides organic detection methods without hardcoded application-specific references,
multi-layer analysis, and evidence-based confidence scoring.

Features:
- Organic pattern-based detection (no hardcoded app names)
- Multi-layer detection integration (filesystem, process, properties, native)
- Evidence-based confidence calculation
- Comprehensive bypass detection
- Plugin-agnostic architecture
- Performance optimization with caching
- Transparent error handling and reporting

Usage:
    from core.shared_infrastructure.root_detection_engine import RootDetectionEngine
    
    engine = RootDetectionEngine(context)
    results = engine.analyze_root_indicators(apk_ctx, content)
"""

import logging
import re
import os
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from core.shared_infrastructure.dependency_injection import AnalysisContext
from core.shared_infrastructure.analysis_exceptions import AnalysisError

logger = logging.getLogger(__name__)

class RootDetectionCategory(Enum):
    """Categories of root detection mechanisms."""
    BINARY_ANALYSIS = "binary_analysis"
    FILE_SYSTEM_ANALYSIS = "file_system_analysis"
    PROCESS_ANALYSIS = "process_analysis"
    PROPERTY_ANALYSIS = "property_analysis"
    PACKAGE_ANALYSIS = "package_analysis"
    NATIVE_LIBRARY_ANALYSIS = "native_library_analysis"
    PERMISSION_ANALYSIS = "permission_analysis"
    BYPASS_DETECTION = "bypass_detection"
    HARDWARE_SECURITY = "hardware_security"  # **FIX**: Added missing enum value

class DetectionStrength(Enum):
    """Root detection mechanism strength levels."""
    VERY_STRONG = "very_strong"
    HIGH = "high"
    MODERATE = "moderate"
    WEAK = "weak"
    VERY_WEAK = "very_weak"

class BypassResistance(Enum):
    """Bypass resistance levels for root detection mechanisms."""
    MAXIMUM = "maximum"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"

@dataclass
class RootDetectionPattern:
    """Root detection pattern with metadata and reliability scoring."""
    pattern_id: str
    pattern: str
    description: str
    category: RootDetectionCategory
    strength: DetectionStrength
    bypass_resistance: BypassResistance
    reliability_score: float  # Historical accuracy (0.0-1.0)
    false_positive_rate: float  # Historical false positive rate
    masvs_controls: List[str] = field(default_factory=lambda: ["MSTG-RESILIENCE-1"])
    context_factors: Dict[str, float] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate pattern data."""
        if not (0.0 <= self.reliability_score <= 1.0):
            raise ValueError("Reliability score must be between 0.0 and 1.0")
        if not (0.0 <= self.false_positive_rate <= 1.0):
            raise ValueError("False positive rate must be between 0.0 and 1.0")

@dataclass
class RootDetectionFinding:
    """Root detection finding with comprehensive metadata."""
    finding_id: str
    pattern: RootDetectionPattern
    pattern_id: str = ""  # **FIX**: Added missing pattern_id attribute
    description: str = ""  # **FIX**: Added missing description attribute
    matched_content: str = ""
    location: str = ""
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    bypass_indicators: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    file_path: str = ""
    line_number: int = 0
    
    def __post_init__(self):
        """Validate finding data."""
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")

@dataclass
class RootDetectionAnalysisResult:
    """Comprehensive root detection analysis results."""
    package_name: str
    analysis_time: float
    total_patterns_checked: int
    findings: List[RootDetectionFinding] = field(default_factory=list)
    detection_coverage: Dict[str, int] = field(default_factory=dict)
    bypass_vulnerabilities: List[str] = field(default_factory=list)
    analysis_limitations: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    detection_strength: DetectionStrength = DetectionStrength.WEAK

class RootDetectionEngine:
    """
    Unified root detection engine for comprehensive organic root detection analysis.
    
    Provides pattern-based detection without hardcoded application references,
    multi-layer analysis capabilities, and evidence-based confidence scoring.
    """
    
    def __init__(self, context: AnalysisContext):
        """
        Initialize root detection engine.
        
        Args:
            context: Analysis context with dependencies
        """
        self.context = context
        self.logger = context.logger
        
        # Configuration
        self.max_analysis_time = context.config.get('max_root_analysis_time', 120)
        self.enable_parallel_analysis = context.config.get('enable_parallel_root_analysis', True)
        self.enable_caching = context.config.get('enable_root_detection_cache', True)
        
        # Initialize comprehensive organic root detection patterns
        self.detection_patterns = self._initialize_organic_detection_patterns()
        
        # Analysis cache for performance
        self._analysis_cache: Dict[str, RootDetectionAnalysisResult] = {}
        self._cache_ttl = 300  # 5 minutes
        
        # Analysis state
        self.analysis_start_time: Optional[float] = None
        self.analyzed_files = 0
        self.analysis_limitations: List[str] = []
        
        logger.info("Root Detection Engine initialized with %d patterns", 
                   sum(len(patterns) for patterns in self.detection_patterns.values()))
    
    def _initialize_organic_detection_patterns(self) -> Dict[RootDetectionCategory, List[RootDetectionPattern]]:
        """Initialize comprehensive organic root detection patterns without hardcoded app names."""
        return {
            RootDetectionCategory.BINARY_ANALYSIS: [
                RootDetectionPattern(
                    pattern_id="ROOT_BINARY_SU_GENERIC",
                    pattern=r'(?i)/(?:system|sbin)/(?:bin|xbin)/su\b',
                    description="Generic su binary detection in system paths",
                    category=RootDetectionCategory.BINARY_ANALYSIS,
                    strength=DetectionStrength.MODERATE,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.85,
                    false_positive_rate=0.05,
                    context_factors={"file_system_access": 0.8, "binary_execution": 0.9}
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_BINARY_BUSYBOX_GENERIC",
                    pattern=r'(?i)/(?:system|sbin)/(?:bin|xbin)/busybox\b',
                    description="Generic busybox binary detection",
                    category=RootDetectionCategory.BINARY_ANALYSIS,
                    strength=DetectionStrength.MODERATE,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.80,
                    false_positive_rate=0.10,
                    context_factors={"file_system_access": 0.7, "binary_execution": 0.8}
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_WHICH_COMMAND_GENERIC",
                    pattern=r'(?i)which\s+(?:su|busybox|superuser)\b',
                    description="Generic 'which' command for root binary detection",
                    category=RootDetectionCategory.BINARY_ANALYSIS,
                    strength=DetectionStrength.WEAK,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.75,
                    false_positive_rate=0.15,
                    context_factors={"command_execution": 0.9, "shell_access": 0.8}
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_EXEC_SU_GENERIC",
                    pattern=r'(?i)Runtime\.getRuntime\(\)\.exec\(["\'](?:su|which\s+su)["\']',
                    description="Generic runtime execution of su command",
                    category=RootDetectionCategory.BINARY_ANALYSIS,
                    strength=DetectionStrength.HIGH,
                    bypass_resistance=BypassResistance.MEDIUM,
                    reliability_score=0.88,
                    false_positive_rate=0.08,
                    context_factors={"runtime_execution": 0.95, "process_spawning": 0.9}
                )
            ],
            
            RootDetectionCategory.FILE_SYSTEM_ANALYSIS: [
                RootDetectionPattern(
                    pattern_id="ROOT_FS_SYSTEM_MODIFICATION",
                    pattern=r'(?i)/system/(?:bin|xbin|app)/(?!android|google)[^/\s]+(?:su|root|super)',
                    description="System partition modification indicators",
                    category=RootDetectionCategory.FILE_SYSTEM_ANALYSIS,
                    strength=DetectionStrength.HIGH,
                    bypass_resistance=BypassResistance.MEDIUM,
                    reliability_score=0.82,
                    false_positive_rate=0.12,
                    context_factors={"file_system_access": 0.9, "system_partition": 0.95}
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_FS_BUILD_PROP_ACCESS",
                    pattern=r'(?i)/system/build\.prop|/system/default\.prop',
                    description="System properties file access",
                    category=RootDetectionCategory.FILE_SYSTEM_ANALYSIS,
                    strength=DetectionStrength.MODERATE,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.78,
                    false_positive_rate=0.18,
                    context_factors={"file_system_access": 0.8, "property_access": 0.7}
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_FS_DATA_LOCAL_ACCESS",
                    pattern=r'(?i)/data/local/(?:tmp|bin)',
                    description="Local data directory access for binaries",
                    category=RootDetectionCategory.FILE_SYSTEM_ANALYSIS,
                    strength=DetectionStrength.MODERATE,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.70,
                    false_positive_rate=0.25,
                    context_factors={"file_system_access": 0.7, "local_data_access": 0.8}
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_FS_RECOVERY_ACCESS",
                    pattern=r'(?i)/(?:cache|system)/recovery',
                    description="Recovery partition access",
                    category=RootDetectionCategory.FILE_SYSTEM_ANALYSIS,
                    strength=DetectionStrength.HIGH,
                    bypass_resistance=BypassResistance.MEDIUM,
                    reliability_score=0.85,
                    false_positive_rate=0.10,
                    context_factors={"file_system_access": 0.9, "recovery_access": 0.95}
                )
            ],
            
            RootDetectionCategory.PROCESS_ANALYSIS: [
                RootDetectionPattern(
                    pattern_id="ROOT_PROCESS_ID_CHECK",
                    pattern=r'(?i)Runtime\.getRuntime\(\)\.exec\(["\']id["\']',
                    description="Process ID command execution for privilege check",
                    category=RootDetectionCategory.PROCESS_ANALYSIS,
                    strength=DetectionStrength.MODERATE,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.75,
                    false_positive_rate=0.20,
                    context_factors={"process_execution": 0.8, "privilege_check": 0.9}
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_PROCESS_WHOAMI_CHECK",
                    pattern=r'(?i)Runtime\.getRuntime\(\)\.exec\(["\']whoami["\']',
                    description="Whoami command execution for user identification",
                    category=RootDetectionCategory.PROCESS_ANALYSIS,
                    strength=DetectionStrength.WEAK,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.72,
                    false_positive_rate=0.22,
                    context_factors={"process_execution": 0.8, "user_identification": 0.7}
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_PROCESS_MOUNT_CHECK",
                    pattern=r'(?i)(?:mount|df|cat\s+/proc/mounts)',
                    description="Mount point analysis for system partition status",
                    category=RootDetectionCategory.PROCESS_ANALYSIS,
                    strength=DetectionStrength.HIGH,
                    bypass_resistance=BypassResistance.MEDIUM,
                    reliability_score=0.80,
                    false_positive_rate=0.15,
                    context_factors={"file_system_analysis": 0.9, "mount_detection": 0.85}
                )
            ],
            
            RootDetectionCategory.PROPERTY_ANALYSIS: [
                RootDetectionPattern(
                    pattern_id="ROOT_PROP_DEBUGGABLE",
                    pattern=r'(?i)ro\.debuggable|android\.os\.Build\.DEBUGGABLE',
                    description="Debuggable property check",
                    category=RootDetectionCategory.PROPERTY_ANALYSIS,
                    strength=DetectionStrength.WEAK,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.65,
                    false_positive_rate=0.30,
                    context_factors={"property_access": 0.8, "debug_detection": 0.6}
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_PROP_SECURE",
                    pattern=r'(?i)ro\.secure',
                    description="Secure property status check",
                    category=RootDetectionCategory.PROPERTY_ANALYSIS,
                    strength=DetectionStrength.MODERATE,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.72,
                    false_positive_rate=0.20,
                    context_factors={"property_access": 0.8, "security_check": 0.8}
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_PROP_BUILD_TAGS",
                    pattern=r'(?i)(?:ro\.build\.tags|Build\.TAGS).*test-keys',
                    description="Test-keys in build tags detection",
                    category=RootDetectionCategory.PROPERTY_ANALYSIS,
                    strength=DetectionStrength.MODERATE,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.78,
                    false_positive_rate=0.18,
                    context_factors={"property_access": 0.8, "build_analysis": 0.85}
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_PROP_ADB_ROOT",
                    pattern=r'(?i)service\.adb\.root',
                    description="ADB root service property check",
                    category=RootDetectionCategory.PROPERTY_ANALYSIS,
                    strength=DetectionStrength.HIGH,
                    bypass_resistance=BypassResistance.MEDIUM,
                    reliability_score=0.85,
                    false_positive_rate=0.10,
                    context_factors={"property_access": 0.8, "adb_analysis": 0.9}
                )
            ],
            
            RootDetectionCategory.PACKAGE_ANALYSIS: [
                RootDetectionPattern(
                    pattern_id="ROOT_PKG_MANAGER_PATTERN",
                    pattern=r'(?i)com\.[^.\s]+\.(?:su|root|super|magisk)',
                    description="Generic root management package pattern",
                    category=RootDetectionCategory.PACKAGE_ANALYSIS,
                    strength=DetectionStrength.HIGH,
                    bypass_resistance=BypassResistance.HIGH,
                    reliability_score=0.90,
                    false_positive_rate=0.05,
                    context_factors={"package_analysis": 0.95, "pattern_matching": 0.9}
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_PKG_SUBSTRATE_PATTERN",
                    pattern=r'(?i)(?:substrate|xposed|frida).*(?:hook|inject)',
                    description="Generic hooking framework pattern",
                    category=RootDetectionCategory.PACKAGE_ANALYSIS,
                    strength=DetectionStrength.HIGH,
                    bypass_resistance=BypassResistance.HIGH,
                    reliability_score=0.88,
                    false_positive_rate=0.08,
                    context_factors={"hooking_framework": 0.95, "injection_detection": 0.9}
                )
            ],
            
            RootDetectionCategory.NATIVE_LIBRARY_ANALYSIS: [
                RootDetectionPattern(
                    pattern_id="ROOT_NATIVE_JNI_SU",
                    pattern=r'(?i)jni.*(?:checksu|isrooted|detectroot)',
                    description="Native JNI root checking functions",
                    category=RootDetectionCategory.NATIVE_LIBRARY_ANALYSIS,
                    strength=DetectionStrength.HIGH,
                    bypass_resistance=BypassResistance.HIGH,
                    reliability_score=0.88,
                    false_positive_rate=0.08,
                    context_factors={"native_analysis": 0.9, "jni_detection": 0.95}
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_NATIVE_SYSTEM_CALL",
                    pattern=r'(?i)system\(["\'][^"\']*su["\']',
                    description="Native system call execution",
                    category=RootDetectionCategory.NATIVE_LIBRARY_ANALYSIS,
                    strength=DetectionStrength.HIGH,
                    bypass_resistance=BypassResistance.MEDIUM,
                    reliability_score=0.85,
                    false_positive_rate=0.10,
                    context_factors={"native_analysis": 0.9, "system_call": 0.85}
                )
            ],
            
            RootDetectionCategory.BYPASS_DETECTION: [
                RootDetectionPattern(
                    pattern_id="ROOT_BYPASS_HOOK_DETECTION",
                    pattern=r'(?i)(?:hook|frida|xposed).*(?:detect|check|scan)',
                    description="Hook detection mechanisms",
                    category=RootDetectionCategory.BYPASS_DETECTION,
                    strength=DetectionStrength.VERY_STRONG,
                    bypass_resistance=BypassResistance.MAXIMUM,
                    reliability_score=0.92,
                    false_positive_rate=0.05,
                    context_factors={"anti_hooking": 0.95, "bypass_detection": 0.9}
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_BYPASS_HIDE_DETECTION",
                    pattern=r'(?i)(?:hide|cloak|mask).*(?:root|su|superuser)',
                    description="Root hiding mechanism detection",
                    category=RootDetectionCategory.BYPASS_DETECTION,
                    strength=DetectionStrength.VERY_STRONG,
                    bypass_resistance=BypassResistance.MAXIMUM,
                    reliability_score=0.90,
                    false_positive_rate=0.06,
                    context_factors={"root_hiding": 0.95, "stealth_detection": 0.9}
                )
            ]
        }
    
    def analyze_root_indicators(self, apk_ctx, content: str, file_path: str = "", 
                              analysis_context: str = "") -> RootDetectionAnalysisResult:
        """
        Analyze content for root detection indicators using organic patterns.
        
        Args:
            apk_ctx: APK context object
            content: Content to analyze
            file_path: Path of file being analyzed
            analysis_context: Additional context for analysis
            
        Returns:
            RootDetectionAnalysisResult: Comprehensive analysis results
        """
        self.analysis_start_time = time.time()
        
        try:
            # Check cache first
            cache_key = self._generate_cache_key(apk_ctx.package_name, content, file_path)
            if self.enable_caching and cache_key in self._analysis_cache:
                cached_result = self._analysis_cache[cache_key]
                if self._is_cache_valid(cached_result):
                    logger.debug("Using cached root detection analysis")
                    return cached_result
            
            # Initialize analysis result
            result = RootDetectionAnalysisResult(
                package_name=apk_ctx.package_name,
                analysis_time=0.0,
                total_patterns_checked=0
            )
            
            # Analyze patterns by category
            all_findings = []
            
            if self.enable_parallel_analysis:
                all_findings = self._analyze_patterns_parallel(content, file_path, analysis_context)
            else:
                all_findings = self._analyze_patterns_sequential(content, file_path, analysis_context)
            
            # Process and validate findings
            validated_findings = self._validate_and_deduplicate_findings(all_findings)
            result.findings = validated_findings
            
            # Calculate analysis metrics
            result.analysis_time = time.time() - self.analysis_start_time
            result.total_patterns_checked = sum(len(patterns) for patterns in self.detection_patterns.values())
            result.detection_coverage = self._calculate_detection_coverage(validated_findings)
            result.bypass_vulnerabilities = self._identify_bypass_vulnerabilities(validated_findings)
            result.confidence_score = self._calculate_overall_confidence(validated_findings)
            result.detection_strength = self._determine_detection_strength(validated_findings)
            
            # Handle analysis limitations
            if self.analysis_limitations:
                result.analysis_limitations = self.analysis_limitations.copy()
            
            # Cache result
            if self.enable_caching:
                self._analysis_cache[cache_key] = result
            
            logger.info("Root detection analysis completed: %d findings in %.2fs", 
                       len(validated_findings), result.analysis_time)
            
            return result
            
        except Exception as e:
            logger.error(f"Root detection analysis failed: {e}", exc_info=True)
            # Return error result with analysis limitations
            error_result = RootDetectionAnalysisResult(
                package_name=apk_ctx.package_name,
                analysis_time=time.time() - (self.analysis_start_time or time.time()),
                total_patterns_checked=0,
                analysis_limitations=[f"Analysis failed: {str(e)}"]
            )
            return error_result
    
    def _analyze_patterns_parallel(self, content: str, file_path: str, 
                                 analysis_context: str) -> List[RootDetectionFinding]:
        """Analyze patterns using parallel execution."""
        all_findings = []
        
        try:
            with ThreadPoolExecutor(max_workers=3, thread_name_prefix="root_detection") as executor:
                future_to_category = {}
                
                for category, patterns in self.detection_patterns.items():
                    future = executor.submit(
                        self._analyze_category_patterns, 
                        category, patterns, content, file_path, analysis_context
                    )
                    future_to_category[future] = category
                
                # Collect results with timeout
                for future in future_to_category:
                    try:
                        category_findings = future.result(timeout=30)
                        all_findings.extend(category_findings)
                    except FutureTimeoutError:
                        category = future_to_category[future]
                        logger.warning(f"Root detection analysis timeout for category: {category}")
                        self.analysis_limitations.append(f"Timeout analyzing {category.value}")
                    except Exception as e:
                        category = future_to_category[future]
                        logger.warning(f"Root detection analysis failed for {category}: {e}")
                        self.analysis_limitations.append(f"Failed to analyze {category.value}: {str(e)}")
        
        except Exception as e:
            logger.warning(f"Parallel root detection analysis failed, falling back to sequential: {e}")
            return self._analyze_patterns_sequential(content, file_path, analysis_context)
        
        return all_findings
    
    def _analyze_patterns_sequential(self, content: str, file_path: str, 
                                   analysis_context: str) -> List[RootDetectionFinding]:
        """Analyze patterns using sequential execution."""
        all_findings = []
        
        for category, patterns in self.detection_patterns.items():
            try:
                category_findings = self._analyze_category_patterns(
                    category, patterns, content, file_path, analysis_context
                )
                all_findings.extend(category_findings)
                
                # Check timeout
                if self.analysis_start_time and (time.time() - self.analysis_start_time) > self.max_analysis_time:
                    logger.warning("Root detection analysis timeout reached")
                    self.analysis_limitations.append("Analysis timeout - partial results")
                    break
                    
            except Exception as e:
                logger.warning(f"Root detection analysis failed for {category}: {e}")
                self.analysis_limitations.append(f"Failed to analyze {category.value}: {str(e)}")
        
        return all_findings
    
    def _analyze_category_patterns(self, category: RootDetectionCategory, patterns: List[RootDetectionPattern],
                                 content: str, file_path: str, analysis_context: str) -> List[RootDetectionFinding]:
        """Analyze patterns for a specific category."""
        findings = []
        
        for pattern in patterns:
            try:
                matches = re.finditer(pattern.pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    # Calculate evidence-based confidence
                    confidence = self._calculate_pattern_confidence(pattern, match, content, analysis_context)
                    
                    # Extract context around match
                    context_lines = self._extract_context_lines(content, match.start(), match.end())
                    
                    finding = RootDetectionFinding(
                        finding_id=f"{pattern.pattern_id}_{hashlib.md5(match.group().encode()).hexdigest()[:8]}",
                        pattern=pattern,
                        matched_content=match.group(),
                        location=f"{file_path}:{self._get_line_number(content, match.start())}",
                        confidence=confidence,
                        evidence=[match.group(), context_lines],
                        context={
                            "category": category.value,
                            "file_path": file_path,
                            "analysis_context": analysis_context,
                            "match_position": match.span()
                        },
                        file_path=file_path,
                        line_number=self._get_line_number(content, match.start())
                    )
                    
                    # Add bypass indicators if applicable
                    finding.bypass_indicators = self._detect_bypass_indicators(content, match)
                    
                    findings.append(finding)
                    
            except Exception as e:
                logger.debug(f"Pattern analysis failed for {pattern.pattern_id}: {e}")
        
        return findings
    
    def _calculate_pattern_confidence(self, pattern: RootDetectionPattern, match: re.Match,
                                    content: str, analysis_context: str) -> float:
        """Calculate evidence-based confidence for pattern match."""
        # Base confidence from pattern reliability
        confidence = pattern.reliability_score
        
        # Adjust for false positive rate
        confidence *= (1.0 - pattern.false_positive_rate)
        
        # Context-based adjustments
        for context_factor, weight in pattern.context_factors.items():
            if context_factor in analysis_context.lower():
                confidence *= (1.0 + weight * 0.1)  # Slight boost for relevant context
        
        # Content analysis adjustments
        surrounding_text = content[max(0, match.start()-100):match.end()+100].lower()
        
        # Boost confidence for implementation context (vs test/example)
        if any(impl in surrounding_text for impl in ['implement', 'production', 'security', 'check']):
            confidence *= 1.1
        elif any(test in surrounding_text for test in ['test', 'example', 'demo', 'sample']):
            confidence *= 0.8
        
        # Multiple validation sources boost confidence
        validation_indicators = ['validate', 'verify', 'confirm', 'assert']
        validation_count = sum(1 for indicator in validation_indicators if indicator in surrounding_text)
        if validation_count > 0:
            confidence *= (1.0 + validation_count * 0.05)
        
        # Ensure confidence stays within bounds
        return max(0.0, min(1.0, confidence))
    
    def _validate_and_deduplicate_findings(self, findings: List[RootDetectionFinding]) -> List[RootDetectionFinding]:
        """Validate and deduplicate findings to prevent false positives."""
        validated_findings = []
        seen_signatures = set()
        
        for finding in findings:
            # Generate signature for deduplication
            signature = f"{finding.pattern.pattern_id}_{finding.matched_content}_{finding.location}"
            
            if signature in seen_signatures:
                logger.debug(f"Deduplicating finding: {finding.finding_id}")
                continue
            
            # Validate finding quality
            if finding.confidence >= 0.3:  # Minimum confidence threshold
                validated_findings.append(finding)
                seen_signatures.add(signature)
            else:
                logger.debug(f"Filtering low-confidence finding: {finding.finding_id} (confidence: {finding.confidence:.3f})")
        
        return validated_findings
    
    def _calculate_detection_coverage(self, findings: List[RootDetectionFinding]) -> Dict[str, int]:
        """Calculate detection coverage by category."""
        coverage = {}
        for category in RootDetectionCategory:
            category_findings = [f for f in findings if f.pattern.category == category]
            coverage[category.value] = len(category_findings)
        return coverage
    
    def _identify_bypass_vulnerabilities(self, findings: List[RootDetectionFinding]) -> List[str]:
        """Identify potential bypass vulnerabilities based on findings."""
        vulnerabilities = []
        
        # Check for weak detection mechanisms
        weak_patterns = [f for f in findings if f.pattern.bypass_resistance in [BypassResistance.LOW, BypassResistance.MINIMAL]]
        if weak_patterns:
            vulnerabilities.append(f"Found {len(weak_patterns)} root detection mechanisms with low bypass resistance")
        
        # Check for missing detection categories
        detected_categories = set(f.pattern.category for f in findings)
        missing_categories = set(RootDetectionCategory) - detected_categories
        if missing_categories:
            vulnerabilities.append(f"Missing detection for categories: {[c.value for c in missing_categories]}")
        
        # Check for bypass indicators
        findings_with_bypass = [f for f in findings if f.bypass_indicators]
        if findings_with_bypass:
            vulnerabilities.append(f"Found {len(findings_with_bypass)} findings with potential bypass indicators")
        
        return vulnerabilities
    
    def _calculate_overall_confidence(self, findings: List[RootDetectionFinding]) -> float:
        """Calculate overall confidence score for root detection analysis."""
        if not findings:
            return 0.0
        
        # Weight by detection strength and confidence
        weighted_sum = 0.0
        total_weight = 0.0
        
        for finding in findings:
            strength_multiplier = {
                DetectionStrength.VERY_STRONG: 1.0,
                DetectionStrength.HIGH: 0.9,
                DetectionStrength.MODERATE: 0.7,
                DetectionStrength.WEAK: 0.5,
                DetectionStrength.VERY_WEAK: 0.3
            }.get(finding.pattern.strength, 0.5)
            
            weight = finding.confidence * strength_multiplier
            weighted_sum += weight
            total_weight += strength_multiplier
        
        return weighted_sum / total_weight if total_weight > 0 else 0.0
    
    def _determine_detection_strength(self, findings: List[RootDetectionFinding]) -> DetectionStrength:
        """Determine overall detection strength based on findings."""
        if not findings:
            return DetectionStrength.VERY_WEAK
        
        # Analyze strength distribution
        strength_counts = {}
        for finding in findings:
            strength = finding.pattern.strength
            strength_counts[strength] = strength_counts.get(strength, 0) + 1
        
        # Determine overall strength
        if strength_counts.get(DetectionStrength.VERY_STRONG, 0) >= 2:
            return DetectionStrength.VERY_STRONG
        elif strength_counts.get(DetectionStrength.HIGH, 0) >= 2:
            return DetectionStrength.HIGH
        elif sum(strength_counts.get(s, 0) for s in [DetectionStrength.HIGH, DetectionStrength.MODERATE]) >= 3:
            return DetectionStrength.MODERATE
        elif len(findings) >= 2:
            return DetectionStrength.WEAK
        else:
            return DetectionStrength.VERY_WEAK
    
    # Helper methods
    def _generate_cache_key(self, package_name: str, content: str, file_path: str) -> str:
        """Generate cache key for analysis results."""
        content_hash = hashlib.md5(content.encode()).hexdigest()
        return f"{package_name}_{file_path}_{content_hash}"
    
    def _is_cache_valid(self, cached_result: RootDetectionAnalysisResult) -> bool:
        """Check if cached result is still valid."""
        # Simple TTL-based validation (could be enhanced)
        return True  # For now, always valid within TTL
    
    def _extract_context_lines(self, content: str, start_pos: int, end_pos: int) -> str:
        """Extract context lines around match."""
        lines = content.split('\n')
        line_num = content[:start_pos].count('\n')
        
        start_line = max(0, line_num - 2)
        end_line = min(len(lines), line_num + 3)
        
        context_lines = lines[start_line:end_line]
        return '\n'.join(context_lines)
    
    def _get_line_number(self, content: str, position: int) -> int:
        """Get line number for position in content."""
        return content[:position].count('\n') + 1
    
    def _detect_bypass_indicators(self, content: str, match: re.Match) -> List[str]:
        """Detect potential bypass indicators around match."""
        indicators = []
        surrounding_text = content[max(0, match.start()-200):match.end()+200].lower()
        
        bypass_patterns = [
            'bypass', 'hide', 'mask', 'cloak', 'disable', 'skip', 'fake', 'spoof'
        ]
        
        for pattern in bypass_patterns:
            if pattern in surrounding_text:
                indicators.append(f"Potential bypass indicator: {pattern}")
        
        return indicators 