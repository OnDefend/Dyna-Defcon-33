"""
Parsing Strategies for AODS Semantic Analysis Framework

This module implements different parsing strategies following the strategy pattern,
allowing the framework to adapt to different code characteristics and requirements.
"""

import logging
import time
import ast
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Set
import re

from .data_structures import (
    SemanticParsingResult, ParsingContext, ParsingStatistics,
    LanguageType, SemanticNode, SemanticNodeType, VulnerabilityPattern,
    VulnerabilitySeverity
)

logger = logging.getLogger(__name__)


class ParsingStrategy(ABC):
    """
    Base class for all parsing strategies.
    
    This abstract class defines the interface that all parsing strategies
    must implement, following AODS modular patterns.
    """
    
    def __init__(self, name: str, description: str):
        """
        Initialize the parsing strategy.
        
        Args:
            name: Strategy name
            description: Strategy description
        """
        self.name = name
        self.description = description
        self.supported_languages = set()
        self.performance_characteristics = {}
        
        # Statistics tracking
        self.parse_count = 0
        self.success_count = 0
        self.total_processing_time = 0.0
    
    @abstractmethod
    def parse(self, 
             source_code: str, 
             language: LanguageType, 
             context: ParsingContext) -> SemanticParsingResult:
        """
        Parse source code and return semantic analysis result.
        
        Args:
            source_code: Source code to analyze
            language: Programming language
            context: Parsing context with configuration
            
        Returns:
            Semantic parsing result
        """
        pass
    
    def supports_language(self, language: LanguageType) -> bool:
        """Check if strategy supports the given language."""
        return language in self.supported_languages
    
    def get_confidence_score(self, result: SemanticParsingResult) -> float:
        """Calculate confidence score for parsing result."""
        if not result.success:
            return 0.0
        
        # Base confidence calculation
        base_confidence = 0.8
        
        # Adjust based on parsing statistics
        if result.statistics.errors:
            base_confidence -= 0.1 * len(result.statistics.errors)
        
        if result.statistics.warnings:
            base_confidence -= 0.05 * len(result.statistics.warnings)
        
        return max(0.0, min(1.0, base_confidence))
    
    def _create_base_result(self, 
                          context: ParsingContext, 
                          start_time: float) -> SemanticParsingResult:
        """Create a base parsing result structure."""
        end_time = time.time()
        
        statistics = ParsingStatistics(
            start_time=start_time,
            end_time=end_time
        )
        
        return SemanticParsingResult(
            success=False,
            context=context,
            statistics=statistics
        )
    
    def _update_statistics(self, success: bool, processing_time: float):
        """Update strategy statistics."""
        self.parse_count += 1
        if success:
            self.success_count += 1
        self.total_processing_time += processing_time
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get strategy performance statistics."""
        return {
            'name': self.name,
            'parse_count': self.parse_count,
            'success_count': self.success_count,
            'success_rate': self.success_count / max(1, self.parse_count),
            'total_processing_time': self.total_processing_time,
            'average_processing_time': self.total_processing_time / max(1, self.parse_count)
        }


class ComprehensiveParsingStrategy(ParsingStrategy):
    """
    Comprehensive parsing strategy for maximum accuracy and detail.
    
    This strategy prioritizes accuracy over speed, performing deep
    semantic analysis with extensive vulnerability detection.
    """
    
    def __init__(self):
        super().__init__(
            name="comprehensive",
            description="Deep semantic analysis with maximum accuracy"
        )
        self.supported_languages = {
            LanguageType.JAVA, LanguageType.KOTLIN, 
            LanguageType.JAVASCRIPT, LanguageType.SMALI
        }
        self.performance_characteristics = {
            'speed': 'slow',
            'accuracy': 'high',
            'memory_usage': 'high',
            'recommended_for': ['security_analysis', 'detailed_review']
        }
    
    def parse(self, 
             source_code: str, 
             language: LanguageType, 
             context: ParsingContext) -> SemanticParsingResult:
        """
        Perform comprehensive semantic parsing.
        
        This method implements deep analysis including:
        - Complete AST construction
        - Vulnerability pattern detection
        - Security-relevant node identification
        - Comprehensive metadata extraction
        """
        start_time = time.time()
        result = self._create_base_result(context, start_time)
        
        try:
            logger.debug(f"Starting comprehensive parsing for {language.value}")
            
            # Step 1: Build complete AST
            root_node = self._build_comprehensive_ast(source_code, language, context)
            if not root_node:
                result.error_message = "Failed to build AST"
                return result
            
            result.root_node = root_node
            result.all_nodes = self._collect_all_nodes(root_node)
            
            # Step 2: Extract language-specific constructs
            self._extract_language_constructs(result, language)
            
            # Step 3: Perform comprehensive vulnerability analysis
            vulnerabilities = self._detect_vulnerabilities_comprehensive(result.all_nodes, language)
            result.vulnerabilities = vulnerabilities
            
            # Step 4: Identify security-relevant nodes
            result.security_nodes = self._identify_security_nodes(result.all_nodes)
            
            # Step 5: Update statistics
            result.statistics.total_nodes = len(result.all_nodes)
            result.statistics.vulnerabilities_found = len(vulnerabilities)
            result.statistics.parsed_lines = source_code.count('\n') + 1
            
            result.success = True
            logger.debug(f"Comprehensive parsing completed: {len(result.all_nodes)} nodes, "
                        f"{len(vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Comprehensive parsing failed: {e}")
            result.error_message = str(e)
            result.statistics.errors.append(str(e))
        
        finally:
            processing_time = time.time() - start_time
            self._update_statistics(result.success, processing_time)
        
        return result
    
    def _build_comprehensive_ast(self, 
                               source_code: str, 
                               language: LanguageType, 
                               context: ParsingContext) -> Optional[SemanticNode]:
        """Build a comprehensive AST for the given language."""
        try:
            if language == LanguageType.JAVA:
                return self._parse_java_comprehensive(source_code)
            elif language == LanguageType.JAVASCRIPT:
                return self._parse_javascript_comprehensive(source_code)
            elif language == LanguageType.SMALI:
                return self._parse_smali_comprehensive(source_code)
            else:
                return self._parse_generic_comprehensive(source_code, language)
        except Exception as e:
            logger.warning(f"AST building failed for {language.value}: {e}")
            return None
    
    def _parse_java_comprehensive(self, source_code: str) -> SemanticNode:
        """Parse Java code with comprehensive analysis."""
        # For now, implement a simple regex-based parser
        # In production, this would use a proper Java parser like ANTLR
        
        root = SemanticNode(
            node_type=SemanticNodeType.CLASS,
            name="<root>",
            start_line=1,
            end_line=source_code.count('\n') + 1,
            source_code=source_code
        )
        
        # Extract classes
        class_pattern = r'class\s+(\w+)'
        for match in re.finditer(class_pattern, source_code):
            class_node = SemanticNode(
                node_type=SemanticNodeType.CLASS,
                name=match.group(1),
                start_line=source_code[:match.start()].count('\n') + 1,
                end_line=source_code[:match.start()].count('\n') + 1,
                source_code=match.group(0)
            )
            root.add_child(class_node)
        
        # Extract methods
        method_pattern = r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\([^)]*\)'
        for match in re.finditer(method_pattern, source_code):
            method_node = SemanticNode(
                node_type=SemanticNodeType.METHOD,
                name=match.group(1),
                start_line=source_code[:match.start()].count('\n') + 1,
                end_line=source_code[:match.start()].count('\n') + 1,
                source_code=match.group(0)
            )
            root.add_child(method_node)
        
        return root
    
    def _parse_javascript_comprehensive(self, source_code: str) -> SemanticNode:
        """Parse JavaScript code with comprehensive analysis."""
        root = SemanticNode(
            node_type=SemanticNodeType.EXPRESSION,
            name="<root>",
            start_line=1,
            end_line=source_code.count('\n') + 1,
            source_code=source_code
        )
        
        # Extract functions
        function_pattern = r'function\s+(\w+)\s*\([^)]*\)'
        for match in re.finditer(function_pattern, source_code):
            func_node = SemanticNode(
                node_type=SemanticNodeType.METHOD,
                name=match.group(1),
                start_line=source_code[:match.start()].count('\n') + 1,
                end_line=source_code[:match.start()].count('\n') + 1,
                source_code=match.group(0)
            )
            root.add_child(func_node)
        
        return root
    
    def _parse_smali_comprehensive(self, source_code: str) -> SemanticNode:
        """Parse Smali code with comprehensive analysis."""
        root = SemanticNode(
            node_type=SemanticNodeType.CLASS,
            name="<smali_root>",
            start_line=1,
            end_line=source_code.count('\n') + 1,
            source_code=source_code
        )
        
        # Extract class definitions
        class_pattern = r'\.class\s+(.+)'
        for match in re.finditer(class_pattern, source_code):
            class_node = SemanticNode(
                node_type=SemanticNodeType.CLASS,
                name=match.group(1),
                start_line=source_code[:match.start()].count('\n') + 1,
                end_line=source_code[:match.start()].count('\n') + 1,
                source_code=match.group(0)
            )
            root.add_child(class_node)
        
        # Extract method definitions
        method_pattern = r'\.method\s+(.+)'
        for match in re.finditer(method_pattern, source_code):
            method_node = SemanticNode(
                node_type=SemanticNodeType.METHOD,
                name=match.group(1),
                start_line=source_code[:match.start()].count('\n') + 1,
                end_line=source_code[:match.start()].count('\n') + 1,
                source_code=match.group(0)
            )
            root.add_child(method_node)
        
        return root
    
    def _parse_generic_comprehensive(self, source_code: str, language: LanguageType) -> SemanticNode:
        """Parse code using generic patterns."""
        return SemanticNode(
            node_type=SemanticNodeType.EXPRESSION,
            name=f"<{language.value}_root>",
            start_line=1,
            end_line=source_code.count('\n') + 1,
            source_code=source_code
        )
    
    def _collect_all_nodes(self, root_node: SemanticNode) -> List[SemanticNode]:
        """Collect all nodes from the AST."""
        nodes = [root_node]
        nodes.extend(root_node.get_descendants())
        return nodes
    
    def _extract_language_constructs(self, result: SemanticParsingResult, language: LanguageType):
        """Extract language-specific constructs."""
        for node in result.all_nodes:
            if node.node_type == SemanticNodeType.CLASS:
                result.classes.append(node)
            elif node.node_type == SemanticNodeType.METHOD:
                result.methods.append(node)
    
    def _detect_vulnerabilities_comprehensive(self, 
                                            nodes: List[SemanticNode], 
                                            language: LanguageType) -> List[VulnerabilityPattern]:
        """Detect vulnerabilities using comprehensive analysis."""
        vulnerabilities = []
        
        for node in nodes:
            # SQL Injection detection
            if 'query' in node.source_code.lower() and '+' in node.source_code:
                vuln = VulnerabilityPattern(
                    pattern_id="SQL_INJECTION_001",
                    pattern_name="Potential SQL Injection",
                    severity=VulnerabilitySeverity.HIGH,
                    category="A03:2021 – Injection",
                    source_node=node,
                    affected_lines=[node.start_line],
                    description="Potential SQL injection vulnerability detected",
                    evidence=[node.source_code],
                    confidence=0.7,
                    recommendation="Use parameterized queries"
                )
                vulnerabilities.append(vuln)
            
            # Hardcoded secrets detection
            secret_patterns = [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']'
            ]
            
            for pattern in secret_patterns:
                if re.search(pattern, node.source_code, re.IGNORECASE):
                    vuln = VulnerabilityPattern(
                        pattern_id="HARDCODED_SECRET_001",
                        pattern_name="Hardcoded Secret",
                        severity=VulnerabilitySeverity.MEDIUM,
                        category="A02:2021 – Cryptographic Failures",
                        source_node=node,
                        affected_lines=[node.start_line],
                        description="Hardcoded secret detected",
                        evidence=[node.source_code],
                        confidence=0.8,
                        recommendation="Use secure configuration management"
                    )
                    vulnerabilities.append(vuln)
                    break
        
        return vulnerabilities
    
    def _identify_security_nodes(self, nodes: List[SemanticNode]) -> List[SemanticNode]:
        """Identify nodes that are security-relevant."""
        security_nodes = []
        
        security_keywords = {
            'password', 'secret', 'key', 'token', 'auth', 'login',
            'crypto', 'hash', 'encrypt', 'decrypt', 'ssl', 'tls',
            'permission', 'security', 'admin', 'root'
        }
        
        for node in nodes:
            source_lower = node.source_code.lower()
            if any(keyword in source_lower for keyword in security_keywords):
                node.security_relevant = True
                security_nodes.append(node)
        
        return security_nodes


class PerformanceParsingStrategy(ParsingStrategy):
    """
    Performance-optimized parsing strategy for speed.
    
    This strategy prioritizes speed over completeness, using
    lightweight analysis suitable for large codebases.
    """
    
    def __init__(self):
        super().__init__(
            name="performance_optimized",
            description="Fast parsing with balanced accuracy"
        )
        self.supported_languages = {
            LanguageType.JAVA, LanguageType.KOTLIN,
            LanguageType.JAVASCRIPT, LanguageType.SMALI
        }
        self.performance_characteristics = {
            'speed': 'fast',
            'accuracy': 'medium',
            'memory_usage': 'low',
            'recommended_for': ['large_codebases', 'quick_scanning']
        }
    
    def parse(self, 
             source_code: str, 
             language: LanguageType, 
             context: ParsingContext) -> SemanticParsingResult:
        """
        Perform performance-optimized semantic parsing.
        """
        start_time = time.time()
        result = self._create_base_result(context, start_time)
        
        try:
            logger.debug(f"Starting performance parsing for {language.value}")
            
            # Lightweight AST construction
            root_node = self._build_lightweight_ast(source_code, language)
            result.root_node = root_node
            result.all_nodes = [root_node] + root_node.get_descendants()
            
            # Quick vulnerability scanning
            vulnerabilities = self._quick_vulnerability_scan(source_code, language)
            result.vulnerabilities = vulnerabilities
            
            # Update basic statistics
            result.statistics.total_nodes = len(result.all_nodes)
            result.statistics.vulnerabilities_found = len(vulnerabilities)
            result.statistics.parsed_lines = source_code.count('\n') + 1
            
            result.success = True
            
        except Exception as e:
            logger.error(f"Performance parsing failed: {e}")
            result.error_message = str(e)
        
        finally:
            processing_time = time.time() - start_time
            self._update_statistics(result.success, processing_time)
        
        return result
    
    def _build_lightweight_ast(self, source_code: str, language: LanguageType) -> SemanticNode:
        """Build a lightweight AST for performance."""
        return SemanticNode(
            node_type=SemanticNodeType.EXPRESSION,
            name="<performance_root>",
            start_line=1,
            end_line=source_code.count('\n') + 1,
            source_code=source_code[:1000]  # Truncate for performance
        )
    
    def _quick_vulnerability_scan(self, source_code: str, language: LanguageType) -> List[VulnerabilityPattern]:
        """Perform quick vulnerability scanning using regex patterns."""
        vulnerabilities = []
        
        # Quick pattern matching for common vulnerabilities
        patterns = {
            r'eval\s*\(': ("Code Injection", VulnerabilitySeverity.HIGH),
            r'exec\s*\(': ("Command Injection", VulnerabilitySeverity.HIGH),
            r'password\s*=\s*["\'][^"\']+["\']': ("Hardcoded Password", VulnerabilitySeverity.MEDIUM)
        }
        
        for pattern, (name, severity) in patterns.items():
            for match in re.finditer(pattern, source_code, re.IGNORECASE):
                line_num = source_code[:match.start()].count('\n') + 1
                
                # Create a dummy node for the vulnerability
                dummy_node = SemanticNode(
                    node_type=SemanticNodeType.EXPRESSION,
                    name="<quick_scan>",
                    start_line=line_num,
                    end_line=line_num,
                    source_code=match.group(0)
                )
                
                vuln = VulnerabilityPattern(
                    pattern_id=f"QUICK_SCAN_{len(vulnerabilities)}",
                    pattern_name=name,
                    severity=severity,
                    category="Quick Scan",
                    source_node=dummy_node,
                    affected_lines=[line_num],
                    description=f"Quick scan detected: {name}",
                    evidence=[match.group(0)],
                    confidence=0.6  # Lower confidence for quick scan
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities


class FallbackParsingStrategy(ParsingStrategy):
    """
    Fallback parsing strategy for error recovery.
    
    This strategy provides basic parsing capabilities when
    other strategies fail, ensuring the system remains functional.
    """
    
    def __init__(self):
        super().__init__(
            name="fallback",
            description="Basic parsing for error recovery"
        )
        self.supported_languages = set(LanguageType)  # Supports all languages
        self.performance_characteristics = {
            'speed': 'fast',
            'accuracy': 'basic',
            'memory_usage': 'minimal',
            'recommended_for': ['error_recovery', 'unknown_formats']
        }
    
    def parse(self, 
             source_code: str, 
             language: LanguageType, 
             context: ParsingContext) -> SemanticParsingResult:
        """
        Perform basic fallback parsing.
        """
        start_time = time.time()
        result = self._create_base_result(context, start_time)
        
        try:
            # Create minimal AST
            root_node = SemanticNode(
                node_type=SemanticNodeType.EXPRESSION,
                name="<fallback_root>",
                start_line=1,
                end_line=source_code.count('\n') + 1,
                source_code=source_code if len(source_code) < 500 else source_code[:500] + "..."
            )
            
            result.root_node = root_node
            result.all_nodes = [root_node]
            result.statistics.total_nodes = 1
            result.statistics.parsed_lines = source_code.count('\n') + 1
            result.success = True
            
            logger.debug("Fallback parsing completed successfully")
            
        except Exception as e:
            logger.error(f"Even fallback parsing failed: {e}")
            result.error_message = str(e)
        
        finally:
            processing_time = time.time() - start_time
            self._update_statistics(result.success, processing_time)
        
        return result


class LargeFileParsingStrategy(ParsingStrategy):
    """
    Specialized parsing strategy for large files.
    
    This strategy handles large files by using chunked processing
    and memory-efficient techniques.
    """
    
    def __init__(self):
        super().__init__(
            name="large_file",
            description="Memory-efficient parsing for large files"
        )
        self.supported_languages = {
            LanguageType.JAVA, LanguageType.KOTLIN,
            LanguageType.JAVASCRIPT, LanguageType.SMALI
        }
        self.performance_characteristics = {
            'speed': 'medium',
            'accuracy': 'medium',
            'memory_usage': 'optimized',
            'recommended_for': ['large_files', 'memory_constrained']
        }
        self.chunk_size = 10000  # Process in 10KB chunks
    
    def parse(self, 
             source_code: str, 
             language: LanguageType, 
             context: ParsingContext) -> SemanticParsingResult:
        """
        Perform chunked parsing for large files.
        """
        start_time = time.time()
        result = self._create_base_result(context, start_time)
        
        try:
            logger.debug(f"Starting large file parsing: {len(source_code)} characters")
            
            # Process code in chunks
            chunks = self._split_into_chunks(source_code)
            all_vulnerabilities = []
            
            for i, chunk in enumerate(chunks):
                chunk_vulnerabilities = self._process_chunk(chunk, i, language)
                all_vulnerabilities.extend(chunk_vulnerabilities)
            
            # Create minimal AST
            root_node = SemanticNode(
                node_type=SemanticNodeType.EXPRESSION,
                name="<large_file_root>",
                start_line=1,
                end_line=source_code.count('\n') + 1,
                source_code=f"<Large file: {len(source_code)} characters>"
            )
            
            result.root_node = root_node
            result.all_nodes = [root_node]
            result.vulnerabilities = all_vulnerabilities
            result.statistics.total_nodes = len(chunks)
            result.statistics.vulnerabilities_found = len(all_vulnerabilities)
            result.statistics.parsed_lines = source_code.count('\n') + 1
            result.success = True
            
        except Exception as e:
            logger.error(f"Large file parsing failed: {e}")
            result.error_message = str(e)
        
        finally:
            processing_time = time.time() - start_time
            self._update_statistics(result.success, processing_time)
        
        return result
    
    def _split_into_chunks(self, source_code: str) -> List[str]:
        """Split source code into manageable chunks."""
        chunks = []
        for i in range(0, len(source_code), self.chunk_size):
            chunks.append(source_code[i:i + self.chunk_size])
        return chunks
    
    def _process_chunk(self, chunk: str, chunk_index: int, language: LanguageType) -> List[VulnerabilityPattern]:
        """Process a single chunk and return vulnerabilities."""
        vulnerabilities = []
        
        # Simple pattern matching in chunk
        if 'password' in chunk.lower():
            dummy_node = SemanticNode(
                node_type=SemanticNodeType.EXPRESSION,
                name=f"<chunk_{chunk_index}>",
                start_line=chunk_index * (self.chunk_size // 100),
                end_line=chunk_index * (self.chunk_size // 100) + 1,
                source_code=chunk[:100]
            )
            
            vuln = VulnerabilityPattern(
                pattern_id=f"LARGE_FILE_CHUNK_{chunk_index}",
                pattern_name="Potential Security Issue",
                severity=VulnerabilitySeverity.LOW,
                category="Large File Analysis",
                source_node=dummy_node,
                affected_lines=[chunk_index * (self.chunk_size // 100)],
                description="Potential security issue found in large file chunk",
                confidence=0.4  # Lower confidence for chunked analysis
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities 