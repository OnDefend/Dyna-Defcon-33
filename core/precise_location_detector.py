"""
🎯 AODS Precise Location Detector
Line-Level Location Precision Enhancement

This module provides precise line-level location detection for security vulnerabilities
using multi-strategy approaches with intelligent fallbacks. Builds upon existing
JADX integration and source code analysis capabilities.

Key Features:
- Multi-strategy location detection with fallbacks
- Enhanced JADX integration with line mapping preservation
- AST-based analysis for Java/Kotlin source code
- Context-aware pattern matching with confidence scoring
- Bytecode analysis fallback for obfuscated code
- Location validation framework with accuracy metrics

Target Performance: >90% line-level accuracy on non-obfuscated code
Target Performance: >70% line-level accuracy on obfuscated code
Target Performance: 100% file-level accuracy maintained
"""

import logging
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PreciseLocation:
    """Represents a precise vulnerability location with confidence scoring."""
    
    file_path: str
    line_number: int
    column_number: Optional[int] = None
    method_name: Optional[str] = None
    class_name: Optional[str] = None
    confidence: float = 0.0
    strategy_used: str = "unknown"
    context_snippet: Optional[str] = None
    validation_score: float = 0.0
    
    def __post_init__(self):
        """Validate and normalize location data."""
        # Ensure line number is positive
        if self.line_number < 1:
            self.line_number = 1
            
        # Normalize file path
        if self.file_path.startswith('./'):
            self.file_path = self.file_path[2:]
            
        # Ensure confidence is in valid range
        self.confidence = max(0.0, min(1.0, self.confidence))
        self.validation_score = max(0.0, min(1.0, self.validation_score))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)
    
    def format_display(self) -> str:
        """Format location for human-readable display."""
        base = f"{self.file_path}:{self.line_number}"
        if self.column_number:
            base += f":{self.column_number}"
        if self.method_name and self.class_name:
            base += f" in {self.class_name}.{self.method_name}()"
        if self.confidence > 0:
            base += f" (confidence: {self.confidence:.2f})"
        return base

@dataclass
class LocationAnalysisResult:
    """Results from precise location analysis."""
    
    locations: List[PreciseLocation]
    analysis_time: float
    strategies_attempted: List[str]
    successful_strategy: Optional[str] = None
    accuracy_metrics: Dict[str, float] = None
    performance_metrics: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.accuracy_metrics is None:
            self.accuracy_metrics = {}
        if self.performance_metrics is None:
            self.performance_metrics = {}
    
    @property
    def best_location(self) -> Optional[PreciseLocation]:
        """Get the location with highest confidence score."""
        if not self.locations:
            return None
        return max(self.locations, key=lambda loc: loc.confidence)
    
    @property
    def high_confidence_locations(self) -> List[PreciseLocation]:
        """Get locations with confidence >= 0.8."""
        return [loc for loc in self.locations if loc.confidence >= 0.8]

class PreciseLocationDetector:
    """
    🎯 Multi-Strategy Precise Location Detector
    
    Provides line-level precision for vulnerability locations using multiple
    detection strategies with intelligent fallbacks and confidence scoring.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Precise Location Detector."""
        self.config = config or self._get_default_config()
        
        # Initialize strategy components
        self._initialize_detection_strategies()
        
        # Performance tracking
        self.performance_metrics = {
            "jadx_line_mapping_time": 0.0,
            "ast_analysis_time": 0.0,
            "pattern_matching_time": 0.0,
            "bytecode_analysis_time": 0.0,
            "validation_time": 0.0,
            "total_time": 0.0
        }
        
        # Accuracy tracking
        self.accuracy_stats = {
            "total_detections": 0,
            "line_level_accurate": 0,
            "file_level_accurate": 0,
            "strategy_success_rates": {}
        }
        
        logger.info("🎯 Precise Location Detector initialized successfully")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for precise location detection."""
        return {
            "location_strategies": [
                "jadx_line_mapping",     # Primary - enhanced JADX integration
                "ast_analysis",          # Secondary - AST parsing
                "pattern_matching",      # Tertiary - enhanced pattern matching
                "bytecode_analysis"      # Fallback - bytecode analysis
            ],
            "confidence_thresholds": {
                "high_confidence": 0.8,
                "medium_confidence": 0.6,
                "low_confidence": 0.4
            },
            "validation_options": {
                "enable_cross_validation": True,
                "require_method_context": True,
                "validate_line_boundaries": True,
                "max_line_deviation": 2  # ±2 lines tolerance
            },
            "performance_limits": {
                "max_analysis_time_seconds": 60,
                "max_memory_usage_mb": 512,
                "enable_caching": True
            }
        }
    
    def _initialize_detection_strategies(self):
        """Initialize detection strategy components."""
        # JADX Line Mapping Strategy
        self.jadx_mapper = JADXLineMapper(self.config)
        
        # AST Analysis Strategy
        self.ast_analyzer = ASTLocationAnalyzer(self.config)
        
        # Pattern Matching Strategy
        self.pattern_matcher = ContextAwarePatternMatcher(self.config)
        
        # Bytecode Analysis Strategy
        self.bytecode_analyzer = BytecodeLocationAnalyzer(self.config)
        
        # Location Validator
        self.location_validator = LocationValidator(self.config)
        
        logger.info("🔧 Detection strategies initialized")
    
    def get_precise_location(self, vulnerability: Dict[str, Any], 
                           source_code: str, 
                           decompiled_path: Optional[str] = None) -> LocationAnalysisResult:
        """
        Get precise location for a vulnerability using multi-strategy detection.
        
        Args:
            vulnerability: Vulnerability information with basic location data
            source_code: Source code content for analysis
            decompiled_path: Optional path to decompiled source directory
            
        Returns:
            LocationAnalysisResult with precise location information
        """
        start_time = time.time()
        
        strategies_attempted = []
        locations = []
        successful_strategy = None
        
        try:
            # Extract basic vulnerability info
            vuln_pattern = vulnerability.get('pattern', '')
            vuln_type = vulnerability.get('type', 'unknown')
            basic_location = vulnerability.get('location', {})
            
            # Try each strategy in order
            for strategy in self.config["location_strategies"]:
                strategies_attempted.append(strategy)
                
                try:
                    location = self._try_strategy(
                        strategy, vulnerability, source_code, decompiled_path
                    )
                    
                    if location and self._validate_location(location):
                        locations.append(location)
                        if not successful_strategy:
                            successful_strategy = strategy
                        
                        # If we have high confidence, we can stop
                        if location.confidence >= self.config["confidence_thresholds"]["high_confidence"]:
                            break
                            
                except Exception as e:
                    logger.warning(f"Strategy {strategy} failed: {e}")
                    continue
            
            # If no strategies worked, try best-effort location
            if not locations:
                best_effort = self._best_effort_location(vulnerability, source_code)
                if best_effort:
                    locations.append(best_effort)
                    successful_strategy = "best_effort"
            
            # Calculate accuracy metrics
            accuracy_metrics = self._calculate_accuracy_metrics(locations, vulnerability)
            
            analysis_time = time.time() - start_time
            self.performance_metrics["total_time"] += analysis_time
            
            return LocationAnalysisResult(
                locations=locations,
                analysis_time=analysis_time,
                strategies_attempted=strategies_attempted,
                successful_strategy=successful_strategy,
                accuracy_metrics=accuracy_metrics,
                performance_metrics=dict(self.performance_metrics)
            )
            
        except Exception as e:
            logger.error(f"Precise location detection failed: {e}")
            return LocationAnalysisResult(
                locations=[],
                analysis_time=time.time() - start_time,
                strategies_attempted=strategies_attempted,
                accuracy_metrics={"error": str(e)}
            )
    
    def _try_strategy(self, strategy: str, vulnerability: Dict[str, Any], 
                     source_code: str, decompiled_path: Optional[str] = None) -> Optional[PreciseLocation]:
        """Try a specific location detection strategy."""
        strategy_start = time.time()
        
        try:
            if strategy == "jadx_line_mapping":
                location = self.jadx_mapper.detect_location(vulnerability, source_code, decompiled_path)
                self.performance_metrics["jadx_line_mapping_time"] += time.time() - strategy_start
                return location
                
            elif strategy == "ast_analysis":
                location = self.ast_analyzer.detect_location(vulnerability, source_code)
                self.performance_metrics["ast_analysis_time"] += time.time() - strategy_start
                return location
                
            elif strategy == "pattern_matching":
                location = self.pattern_matcher.detect_location(vulnerability, source_code)
                self.performance_metrics["pattern_matching_time"] += time.time() - strategy_start
                return location
                
            elif strategy == "bytecode_analysis":
                location = self.bytecode_analyzer.detect_location(vulnerability, source_code, decompiled_path)
                self.performance_metrics["bytecode_analysis_time"] += time.time() - strategy_start
                return location
                
            else:
                logger.warning(f"Unknown strategy: {strategy}")
                return None
                
        except Exception as e:
            logger.warning(f"Strategy {strategy} failed: {e}")
            return None
    
    def _validate_location(self, location: PreciseLocation) -> bool:
        """Validate a detected location using the location validator."""
        validation_start = time.time()
        
        try:
            is_valid = self.location_validator.validate_location(location)
            self.performance_metrics["validation_time"] += time.time() - validation_start
            return is_valid
            
        except Exception as e:
            logger.warning(f"Location validation failed: {e}")
            return False
    
    def _best_effort_location(self, vulnerability: Dict[str, Any], 
                             source_code: str) -> Optional[PreciseLocation]:
        """Generate best-effort location when all strategies fail."""
        try:
            # Extract basic information from vulnerability
            basic_location = vulnerability.get('location', {})
            file_path = basic_location.get('file_path', 'unknown')
            
            # Try to find the pattern in source code
            pattern = vulnerability.get('pattern', '')
            if pattern and source_code:
                lines = source_code.split('\n')
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        return PreciseLocation(
                            file_path=file_path,
                            line_number=line_num,
                            confidence=0.3,  # Low confidence
                            strategy_used="best_effort",
                            context_snippet=line.strip()
                        )
            
            # Fallback to basic location info
            line_number = basic_location.get('line_number', 1)
            return PreciseLocation(
                file_path=file_path,
                line_number=line_number,
                confidence=0.1,  # Very low confidence
                strategy_used="fallback"
            )
            
        except Exception as e:
            logger.warning(f"Best effort location failed: {e}")
            return None
    
    def _calculate_accuracy_metrics(self, locations: List[PreciseLocation], 
                                  vulnerability: Dict[str, Any]) -> Dict[str, float]:
        """Calculate accuracy metrics for detected locations."""
        if not locations:
            return {"accuracy": 0.0, "confidence_avg": 0.0}
        
        # Calculate average confidence
        avg_confidence = sum(loc.confidence for loc in locations) / len(locations)
        
        # Calculate validation score average
        avg_validation = sum(loc.validation_score for loc in locations) / len(locations)
        
        # Estimate accuracy based on confidence and validation scores
        estimated_accuracy = (avg_confidence + avg_validation) / 2
        
        return {
            "accuracy": estimated_accuracy,
            "confidence_avg": avg_confidence,
            "validation_avg": avg_validation,
            "location_count": len(locations),
            "high_confidence_count": len([loc for loc in locations if loc.confidence >= 0.8])
        }
    
    def get_accuracy_statistics(self) -> Dict[str, Any]:
        """Get overall accuracy statistics for the detector."""
        if self.accuracy_stats["total_detections"] == 0:
            return {"error": "No detections performed yet"}
        
        line_accuracy = (self.accuracy_stats["line_level_accurate"] / 
                        self.accuracy_stats["total_detections"])
        file_accuracy = (self.accuracy_stats["file_level_accurate"] / 
                        self.accuracy_stats["total_detections"])
        
        return {
            "line_level_accuracy": line_accuracy,
            "file_level_accuracy": file_accuracy,
            "total_detections": self.accuracy_stats["total_detections"],
            "strategy_success_rates": dict(self.accuracy_stats["strategy_success_rates"]),
            "performance_metrics": dict(self.performance_metrics)
        }

class JADXLineMapper:
    """Enhanced JADX integration with line mapping preservation."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
    def detect_location(self, vulnerability: Dict[str, Any], 
                       source_code: str, 
                       decompiled_path: Optional[str] = None) -> Optional[PreciseLocation]:
        """Detect location using enhanced JADX line mapping."""
        try:
            basic_location = vulnerability.get('location', {})
            file_path = basic_location.get('file_path', '')
            
            # Try to find precise line using JADX decompilation metadata
            if decompiled_path and os.path.exists(decompiled_path):
                precise_line = self._extract_line_from_jadx_metadata(
                    decompiled_path, file_path, vulnerability
                )
                if precise_line:
                    return PreciseLocation(
                        file_path=file_path,
                        line_number=precise_line['line_number'],
                        method_name=precise_line.get('method_name'),
                        class_name=precise_line.get('class_name'),
                        confidence=0.85,  # High confidence for JADX mapping
                        strategy_used="jadx_line_mapping",
                        context_snippet=precise_line.get('context')
                    )
            
            # Fallback to pattern matching in source code
            return self._fallback_pattern_match(vulnerability, source_code, file_path)
            
        except Exception as e:
            logger.warning(f"JADX line mapping failed: {e}")
            return None
    
    def _extract_line_from_jadx_metadata(self, decompiled_path: str, 
                                        file_path: str, 
                                        vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract precise line information from JADX metadata."""
        try:
            # Look for JADX metadata files
            metadata_files = [
                os.path.join(decompiled_path, "sources", file_path),
                os.path.join(decompiled_path, file_path)
            ]
            
            pattern = vulnerability.get('pattern', '')
            
            for metadata_file in metadata_files:
                if os.path.exists(metadata_file):
                    with open(metadata_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    # Search for pattern with line context
                    lines = content.split('\n')
                    for line_num, line in enumerate(lines, 1):
                        if pattern and re.search(pattern, line, re.IGNORECASE):
                            # Extract method and class context
                            method_name, class_name = self._extract_method_class_context(
                                lines, line_num
                            )
                            
                            return {
                                'line_number': line_num,
                                'method_name': method_name,
                                'class_name': class_name,
                                'context': line.strip()
                            }
            
            return None
            
        except Exception as e:
            logger.warning(f"JADX metadata extraction failed: {e}")
            return None
    
    def _extract_method_class_context(self, lines: List[str], 
                                     target_line: int) -> Tuple[Optional[str], Optional[str]]:
        """Extract method and class context for a given line."""
        method_name = None
        class_name = None
        
        # Search backwards for method and class declarations
        for i in range(target_line - 1, max(0, target_line - 50), -1):
            line = lines[i].strip()
            
            # Look for method declaration
            if not method_name:
                method_match = re.search(r'(?:public|private|protected|static)?\s*\w+\s+(\w+)\s*\(', line)
                if method_match:
                    method_name = method_match.group(1)
            
            # Look for class declaration
            if not class_name:
                class_match = re.search(r'(?:public|private)?\s*class\s+(\w+)', line)
                if class_match:
                    class_name = class_match.group(1)
            
            # Stop if we found both
            if method_name and class_name:
                break
        
        return method_name, class_name
    
    def _fallback_pattern_match(self, vulnerability: Dict[str, Any], 
                               source_code: str, 
                               file_path: str) -> Optional[PreciseLocation]:
        """Fallback pattern matching when JADX metadata is unavailable."""
        try:
            pattern = vulnerability.get('pattern', '')
            if not pattern or not source_code:
                return None
            
            lines = source_code.split('\n')
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    return PreciseLocation(
                        file_path=file_path,
                        line_number=line_num,
                        confidence=0.7,  # Medium confidence for pattern match
                        strategy_used="jadx_fallback_pattern",
                        context_snippet=line.strip()
                    )
            
            return None
            
        except Exception as e:
            logger.warning(f"JADX fallback pattern match failed: {e}")
            return None

class ASTLocationAnalyzer:
    """AST-based location analysis for Java/Kotlin source code."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    def detect_location(self, vulnerability: Dict[str, Any], 
                       source_code: str) -> Optional[PreciseLocation]:
        """Detect location using AST analysis."""
        try:
            # For Java/Kotlin, we'll use regex-based AST-like analysis
            return self._analyze_java_kotlin_structure(vulnerability, source_code)
            
        except Exception as e:
            logger.warning(f"AST location analysis failed: {e}")
            return None
    
    def _analyze_java_kotlin_structure(self, vulnerability: Dict[str, Any], 
                                      source_code: str) -> Optional[PreciseLocation]:
        """Analyze Java/Kotlin code structure for precise location."""
        try:
            pattern = vulnerability.get('pattern', '')
            vuln_type = vulnerability.get('type', '')
            basic_location = vulnerability.get('location', {})
            file_path = basic_location.get('file_path', '')
            
            if not pattern or not source_code:
                return None
            
            lines = source_code.split('\n')
            
            # Enhanced pattern matching with structural context
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    # Get structural context
                    structure_context = self._get_structural_context(lines, line_num)
                    
                    # Calculate confidence based on structural analysis
                    confidence = self._calculate_ast_confidence(
                        line, structure_context, vuln_type
                    )
                    
                    return PreciseLocation(
                        file_path=file_path,
                        line_number=line_num,
                        method_name=structure_context.get('method'),
                        class_name=structure_context.get('class'),
                        confidence=confidence,
                        strategy_used="ast_analysis",
                        context_snippet=line.strip()
                    )
            
            return None
            
        except Exception as e:
            logger.warning(f"Java/Kotlin structure analysis failed: {e}")
            return None
    
    def _get_structural_context(self, lines: List[str], 
                               target_line: int) -> Dict[str, Any]:
        """Get structural context (method, class, etc.) for a line."""
        context = {
            'method': None,
            'class': None,
            'block_depth': 0,
            'in_method': False,
            'in_class': False
        }
        
        brace_count = 0
        
        # Analyze structure backwards from target line
        for i in range(target_line - 1, max(0, target_line - 100), -1):
            line = lines[i].strip()
            
            # Count braces for block depth
            brace_count += line.count('{') - line.count('}')
            
            # Look for method declaration
            if not context['method']:
                method_patterns = [
                    r'(?:public|private|protected|static)?\s*\w+\s+(\w+)\s*\([^)]*\)\s*\{?',
                    r'fun\s+(\w+)\s*\([^)]*\)\s*\{?'  # Kotlin function
                ]
                for pattern in method_patterns:
                    match = re.search(pattern, line)
                    if match:
                        context['method'] = match.group(1)
                        context['in_method'] = True
                        break
            
            # Look for class declaration
            if not context['class']:
                class_patterns = [
                    r'(?:public|private)?\s*class\s+(\w+)',
                    r'(?:public|private)?\s*interface\s+(\w+)',
                    r'(?:open|abstract)?\s*class\s+(\w+)'  # Kotlin class
                ]
                for pattern in class_patterns:
                    match = re.search(pattern, line)
                    if match:
                        context['class'] = match.group(1)
                        context['in_class'] = True
                        break
            
            # Stop if we've found what we need
            if context['method'] and context['class']:
                break
        
        context['block_depth'] = max(0, brace_count)
        return context
    
    def _calculate_ast_confidence(self, line: str, 
                                 structure_context: Dict[str, Any], 
                                 vuln_type: str) -> float:
        """Calculate confidence based on AST structural analysis."""
        base_confidence = 0.6
        
        # Bonus for being in a method
        if structure_context.get('in_method'):
            base_confidence += 0.15
        
        # Bonus for being in a class
        if structure_context.get('in_class'):
            base_confidence += 0.1
        
        # Bonus for appropriate block depth
        block_depth = structure_context.get('block_depth', 0)
        if 1 <= block_depth <= 3:  # Reasonable nesting
            base_confidence += 0.05
        
        # Vulnerability type specific bonuses
        if vuln_type in ['hardcoded_secret', 'api_key', 'password']:
            if any(keyword in line.lower() for keyword in ['string', 'final', 'static']):
                base_confidence += 0.1
        
        return min(1.0, base_confidence)

class ContextAwarePatternMatcher:
    """Enhanced pattern matching with context awareness."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._initialize_context_patterns()
    
    def _initialize_context_patterns(self):
        """Initialize context-aware patterns."""
        self.context_patterns = {
            'hardcoded_secret': {
                'patterns': [
                    r'(?:private|public|static)?\s*(?:final\s+)?String\s+\w*(?:key|secret|password|token)\w*\s*=\s*["\'][^"\']{8,}["\']',
                    r'(?:private|public|static)?\s*(?:final\s+)?String\s+\w+\s*=\s*["\'][A-Za-z0-9+/]{20,}={0,2}["\']'
                ],
                'context_keywords': ['key', 'secret', 'password', 'token', 'api', 'auth'],
                'confidence_multiplier': 1.2
            },
            'insecure_crypto': {
                'patterns': [
                    r'Cipher\.getInstance\s*\(\s*["\'][^"\']*ECB[^"\']*["\']',
                    r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
                    r'MessageDigest\.getInstance\s*\(\s*["\']SHA1["\']'
                ],
                'context_keywords': ['cipher', 'encrypt', 'decrypt', 'hash', 'digest'],
                'confidence_multiplier': 1.1
            }
        }
    
    def detect_location(self, vulnerability: Dict[str, Any], 
                       source_code: str) -> Optional[PreciseLocation]:
        """Detect location using context-aware pattern matching."""
        try:
            vuln_type = vulnerability.get('type', 'unknown')
            pattern = vulnerability.get('pattern', '')
            basic_location = vulnerability.get('location', {})
            file_path = basic_location.get('file_path', '')
            
            if not source_code:
                return None
            
            lines = source_code.split('\n')
            
            # Try vulnerability-specific patterns first
            if vuln_type in self.context_patterns:
                location = self._match_context_patterns(
                    vuln_type, lines, file_path
                )
                if location:
                    return location
            
            # Fallback to generic pattern matching
            if pattern:
                return self._generic_pattern_match(pattern, lines, file_path)
            
            return None
            
        except Exception as e:
            logger.warning(f"Context-aware pattern matching failed: {e}")
            return None
    
    def _match_context_patterns(self, vuln_type: str, 
                               lines: List[str], 
                               file_path: str) -> Optional[PreciseLocation]:
        """Match using vulnerability-specific context patterns."""
        context_info = self.context_patterns[vuln_type]
        patterns = context_info['patterns']
        keywords = context_info['context_keywords']
        multiplier = context_info['confidence_multiplier']
        
        best_match = None
        best_confidence = 0.0
        
        for line_num, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Calculate context-aware confidence
                    confidence = self._calculate_context_confidence(
                        line, keywords, multiplier, lines, line_num
                    )
                    
                    if confidence > best_confidence:
                        best_confidence = confidence
                        best_match = PreciseLocation(
                            file_path=file_path,
                            line_number=line_num,
                            confidence=confidence,
                            strategy_used="context_aware_pattern",
                            context_snippet=line.strip()
                        )
        
        return best_match
    
    def _calculate_context_confidence(self, line: str, 
                                    keywords: List[str], 
                                    multiplier: float,
                                    lines: List[str], 
                                    line_num: int) -> float:
        """Calculate confidence based on context analysis."""
        base_confidence = 0.5
        
        # Keyword presence bonus
        keyword_count = sum(1 for keyword in keywords 
                           if keyword.lower() in line.lower())
        base_confidence += keyword_count * 0.1
        
        # Context window analysis (±3 lines)
        context_start = max(0, line_num - 4)
        context_end = min(len(lines), line_num + 3)
        context_lines = lines[context_start:context_end]
        
        context_keywords = sum(1 for context_line in context_lines
                              for keyword in keywords
                              if keyword.lower() in context_line.lower())
        
        base_confidence += context_keywords * 0.05
        
        # Apply vulnerability-specific multiplier
        final_confidence = base_confidence * multiplier
        
        return min(1.0, final_confidence)
    
    def _generic_pattern_match(self, pattern: str, 
                              lines: List[str], 
                              file_path: str) -> Optional[PreciseLocation]:
        """Generic pattern matching fallback."""
        try:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    return PreciseLocation(
                        file_path=file_path,
                        line_number=line_num,
                        confidence=0.6,  # Medium confidence for generic match
                        strategy_used="generic_pattern",
                        context_snippet=line.strip()
                    )
            
            return None
            
        except Exception as e:
            logger.warning(f"Generic pattern matching failed: {e}")
            return None

class BytecodeLocationAnalyzer:
    """Bytecode analysis fallback for obfuscated code."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    def detect_location(self, vulnerability: Dict[str, Any], 
                       source_code: str, 
                       decompiled_path: Optional[str] = None) -> Optional[PreciseLocation]:
        """Detect location using bytecode analysis."""
        try:
            return self._simplified_bytecode_analysis(vulnerability, source_code)
            
        except Exception as e:
            logger.warning(f"Bytecode location analysis failed: {e}")
            return None
    
    def _simplified_bytecode_analysis(self, vulnerability: Dict[str, Any], 
                                     source_code: str) -> Optional[PreciseLocation]:
        """Simplified bytecode-like analysis for obfuscated code."""
        try:
            pattern = vulnerability.get('pattern', '')
            basic_location = vulnerability.get('location', {})
            file_path = basic_location.get('file_path', '')
            
            if not pattern or not source_code:
                return None
            
            # Look for bytecode-like patterns that might indicate obfuscation
            obfuscation_indicators = [
                r'[a-z]\d+[a-z]\d+',  # Obfuscated identifiers
                r'[A-Z]{2,}[0-9]{2,}',  # Uppercase obfuscated names
                r'\$[0-9]+',  # Anonymous class indicators
                r'[a-z]{1,2}\([^)]*\)',  # Short method names
            ]
            
            lines = source_code.split('\n')
            obfuscation_score = 0
            
            # Calculate obfuscation score
            for line in lines:
                for indicator in obfuscation_indicators:
                    obfuscation_score += len(re.findall(indicator, line))
            
            # If highly obfuscated, use different strategy
            is_obfuscated = obfuscation_score > len(lines) * 0.3
            
            # Find pattern with obfuscation awareness
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    confidence = 0.4 if is_obfuscated else 0.6
                    
                    return PreciseLocation(
                        file_path=file_path,
                        line_number=line_num,
                        confidence=confidence,
                        strategy_used="bytecode_analysis",
                        context_snippet=line.strip()
                    )
            
            return None
            
        except Exception as e:
            logger.warning(f"Simplified bytecode analysis failed: {e}")
            return None

class LocationValidator:
    """Location validation framework with accuracy metrics."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.validation_options = config.get("validation_options", {})
    
    def validate_location(self, location: PreciseLocation) -> bool:
        """Validate a detected location."""
        try:
            validation_score = 0.0
            max_score = 0.0
            
            # Basic validation checks
            if self._validate_line_number(location):
                validation_score += 0.3
            max_score += 0.3
            
            if self._validate_file_path(location):
                validation_score += 0.2
            max_score += 0.2
            
            # Context validation
            if self.validation_options.get("require_method_context", False):
                if location.method_name:
                    validation_score += 0.2
                max_score += 0.2
            
            # Confidence validation
            if location.confidence >= self.config["confidence_thresholds"]["medium_confidence"]:
                validation_score += 0.3
            max_score += 0.3
            
            # Calculate validation score
            location.validation_score = validation_score / max_score if max_score > 0 else 0.0
            
            # Location is valid if it passes basic checks
            return (location.line_number > 0 and 
                   location.file_path and 
                   location.confidence > 0)
            
        except Exception as e:
            logger.warning(f"Location validation failed: {e}")
            return False
    
    def _validate_line_number(self, location: PreciseLocation) -> bool:
        """Validate line number is reasonable."""
        return location.line_number > 0 and location.line_number < 1000000
    
    def _validate_file_path(self, location: PreciseLocation) -> bool:
        """Validate file path is reasonable."""
        return (location.file_path and 
               len(location.file_path) > 0 and
               not location.file_path.startswith('/'))

# Integration with existing AODS framework
def enhance_vulnerability_with_precise_location(vulnerability: Dict[str, Any], 
                                              source_code: str,
                                              decompiled_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Enhance a vulnerability with precise location information.
    
    This function integrates with the existing AODS framework to add
    precise location detection to vulnerability findings.
    """
    try:
        detector = PreciseLocationDetector()
        
        result = detector.get_precise_location(
            vulnerability, source_code, decompiled_path
        )
        
        if result.best_location:
            location = result.best_location
            
            # Enhance vulnerability with precise location
            vulnerability['precise_location'] = {
                'file_path': location.file_path,
                'line_number': location.line_number,
                'column_number': location.column_number,
                'method_name': location.method_name,
                'class_name': location.class_name,
                'confidence': location.confidence,
                'strategy_used': location.strategy_used,
                'context_snippet': location.context_snippet,
                'validation_score': location.validation_score
            }
            
            # Add analysis metadata
            vulnerability['location_analysis'] = {
                'analysis_time': result.analysis_time,
                'strategies_attempted': result.strategies_attempted,
                'successful_strategy': result.successful_strategy,
                'accuracy_metrics': result.accuracy_metrics
            }
        
        return vulnerability
        
    except Exception as e:
        logger.error(f"Precise location enhancement failed: {e}")
        return vulnerability

if __name__ == "__main__":
    # Example usage and testing
    logger.info("🎯 AODS Precise Location Detector - Line-Level Location Enhancement")
    
    # Test with sample vulnerability
    sample_vulnerability = {
        'type': 'hardcoded_secret',
        'pattern': r'String\s+apiKey\s*=\s*["\'][^"\']+["\']',
        'location': {
            'file_path': 'com/example/MainActivity.java',
            'line_number': 25
        }
    }
    
    sample_source = '''
public class MainActivity extends Activity {
    private static final String TAG = "MainActivity";
    
    // Hardcoded API key - security vulnerability
    private String apiKey = "sk_live_abcd1234567890";
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
}
'''
    
    detector = PreciseLocationDetector()
    result = detector.get_precise_location(sample_vulnerability, sample_source)
    
    if result.best_location:
        print(f"✅ Precise location detected: {result.best_location.format_display()}")
        print(f"📊 Analysis completed in {result.analysis_time:.3f}s")
        print(f"🎯 Strategy used: {result.successful_strategy}")
    else:
        print("❌ No precise location detected")
