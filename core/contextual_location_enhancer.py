"""
🔍 AODS Contextual Location Enhancer
Context-Aware Location Enhancement

This module provides rich contextual information for vulnerability locations,
including method context, class context, data flow analysis, and call chain analysis.
Builds upon the PreciseLocationDetector to add comprehensive context understanding.

Key Features:
- Method and class context extraction
- Code snippets with configurable context window
- Data flow analysis for security-relevant findings
- Call chain analysis for complex vulnerabilities
- Context confidence scoring and validation

Target Performance: >95% method and class context for findings
Target Performance: Code snippets with ±5 lines context
Target Performance: Data flow analysis for security-relevant findings
Target Performance: Call chain analysis for complex vulnerabilities
"""

import logging
import os
import re
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class MethodContext:
    """Method context information for a vulnerability location."""
    
    method_name: str
    method_signature: str
    return_type: Optional[str] = None
    parameters: List[Dict[str, str]] = None
    modifiers: List[str] = None
    line_start: int = 0
    line_end: int = 0
    is_constructor: bool = False
    is_static: bool = False
    is_public: bool = False
    is_private: bool = False
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = []
        if self.modifiers is None:
            self.modifiers = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

@dataclass
class ClassContext:
    """Class context information for a vulnerability location."""
    
    class_name: str
    package_name: Optional[str] = None
    superclass: Optional[str] = None
    interfaces: List[str] = None
    modifiers: List[str] = None
    line_start: int = 0
    line_end: int = 0
    is_abstract: bool = False
    is_final: bool = False
    is_public: bool = False
    nested_classes: List[str] = None
    
    def __post_init__(self):
        if self.interfaces is None:
            self.interfaces = []
        if self.modifiers is None:
            self.modifiers = []
        if self.nested_classes is None:
            self.nested_classes = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

@dataclass
class DataFlowContext:
    """Data flow analysis context for a vulnerability."""
    
    variable_name: Optional[str] = None
    data_sources: List[str] = None
    data_sinks: List[str] = None
    taint_flow: List[Dict[str, Any]] = None
    security_implications: List[str] = None
    risk_level: str = "UNKNOWN"
    
    def __post_init__(self):
        if self.data_sources is None:
            self.data_sources = []
        if self.data_sinks is None:
            self.data_sinks = []
        if self.taint_flow is None:
            self.taint_flow = []
        if self.security_implications is None:
            self.security_implications = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

@dataclass
class CallChainContext:
    """Call chain analysis context for complex vulnerabilities."""
    
    call_sequence: List[Dict[str, Any]] = None
    entry_points: List[str] = None
    critical_paths: List[List[str]] = None
    external_calls: List[str] = None
    security_boundaries: List[str] = None
    complexity_score: float = 0.0
    
    def __post_init__(self):
        if self.call_sequence is None:
            self.call_sequence = []
        if self.entry_points is None:
            self.entry_points = []
        if self.critical_paths is None:
            self.critical_paths = []
        if self.external_calls is None:
            self.external_calls = []
        if self.security_boundaries is None:
            self.security_boundaries = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

@dataclass
class ContextualLocationInfo:
    """Complete contextual information for a vulnerability location."""
    
    file_path: str
    line_number: int
    code_snippet: str
    method_context: Optional[MethodContext] = None
    class_context: Optional[ClassContext] = None
    data_flow_context: Optional[DataFlowContext] = None
    call_chain_context: Optional[CallChainContext] = None
    context_confidence: float = 0.0
    analysis_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)
    
    def format_display(self) -> str:
        """Format contextual location for human-readable display."""
        base = f"{self.file_path}:{self.line_number}"
        
        if self.method_context and self.class_context:
            base += f" in {self.class_context.class_name}.{self.method_context.method_name}()"
        elif self.method_context:
            base += f" in {self.method_context.method_name}()"
        elif self.class_context:
            base += f" in class {self.class_context.class_name}"
        
        if self.context_confidence > 0:
            base += f" (context confidence: {self.context_confidence:.2f})"
        
        return base

class ContextualLocationEnhancer:
    """
    🔍 Context-Aware Location Enhancement Engine
    
    Provides rich contextual information for vulnerability locations including
    method context, class context, data flow analysis, and call chain analysis.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Contextual Location Enhancer."""
        self.config = config or self._get_default_config()
        
        # Initialize context extractors
        self.context_extractors = {
            "method_context": MethodContextExtractor(self.config),
            "class_context": ClassContextExtractor(self.config),
            "flow_context": DataFlowAnalyzer(self.config),
            "call_context": CallGraphAnalyzer(self.config)
        }
        
        # Performance tracking
        self.performance_metrics = {
            "method_extraction_time": 0.0,
            "class_extraction_time": 0.0,
            "data_flow_time": 0.0,
            "call_chain_time": 0.0,
            "total_enhancement_time": 0.0
        }
        
        logger.info("🔍 Contextual Location Enhancer initialized successfully")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for contextual enhancement."""
        return {
            "context_options": {
                "code_snippet_lines": int(os.getenv('AODS_CODE_CONTEXT_LINES', '10')),  # Configurable context lines
                "enable_method_context": True,
                "enable_class_context": True,
                "enable_data_flow": True,
                "enable_call_chain": True
            },
            "analysis_limits": {
                "max_call_chain_depth": 10,
                "max_data_flow_steps": 20,
                "max_analysis_time_seconds": 30
            },
            "confidence_thresholds": {
                "high_context_confidence": 0.8,
                "medium_context_confidence": 0.6,
                "low_context_confidence": 0.4
            }
        }
    
    def enhance_location_with_context(self, location: Dict[str, Any], 
                                    source_code: str) -> ContextualLocationInfo:
        """
        Add rich context to vulnerability locations.
        
        Args:
            location: Basic location information (file_path, line_number)
            source_code: Source code content for analysis
            
        Returns:
            ContextualLocationInfo with comprehensive context
        """
        start_time = time.time()
        
        try:
            file_path = location.get('file_path', '')
            line_number = location.get('line_number', 1)
            
            # Extract code snippet
            code_snippet = self._extract_code_snippet(
                source_code, line_number, 
                self.config["context_options"]["code_snippet_lines"]
            )
            
            # Initialize contextual info
            contextual_info = ContextualLocationInfo(
                file_path=file_path,
                line_number=line_number,
                code_snippet=code_snippet
            )
            
            # Extract method context
            if self.config["context_options"]["enable_method_context"]:
                contextual_info.method_context = self._extract_method_context(
                    source_code, line_number
                )
            
            # Extract class context
            if self.config["context_options"]["enable_class_context"]:
                contextual_info.class_context = self._extract_class_context(
                    source_code, line_number
                )
            
            # Analyze data flow
            if self.config["context_options"]["enable_data_flow"]:
                contextual_info.data_flow_context = self._analyze_data_flow(
                    source_code, line_number, location
                )
            
            # Analyze call chain
            if self.config["context_options"]["enable_call_chain"]:
                contextual_info.call_chain_context = self._analyze_call_chain(
                    source_code, line_number, contextual_info.method_context
                )
            
            # Calculate context confidence
            contextual_info.context_confidence = self._calculate_context_confidence(
                contextual_info
            )
            
            contextual_info.analysis_time = time.time() - start_time
            self.performance_metrics["total_enhancement_time"] += contextual_info.analysis_time
            
            return contextual_info
            
        except Exception as e:
            logger.error(f"Context enhancement failed: {e}")
            return ContextualLocationInfo(
                file_path=location.get('file_path', ''),
                line_number=location.get('line_number', 1),
                code_snippet="",
                analysis_time=time.time() - start_time
            )
    
    def _extract_code_snippet(self, source_code: str, line_number: int, 
                             context_lines: int) -> str:
        """Extract code snippet with context lines."""
        try:
            lines = source_code.split('\n')
            start_line = max(0, line_number - context_lines - 1)
            end_line = min(len(lines), line_number + context_lines)
            
            snippet_lines = []
            for i in range(start_line, end_line):
                line_num = i + 1
                prefix = ">>> " if line_num == line_number else "    "
                snippet_lines.append(f"{prefix}{line_num:3d}: {lines[i]}")
            
            return '\n'.join(snippet_lines)
            
        except Exception as e:
            logger.warning(f"Code snippet extraction failed: {e}")
            return ""
    
    def _extract_method_context(self, source_code: str, 
                               line_number: int) -> Optional[MethodContext]:
        """Extract method context for the given line."""
        extraction_start = time.time()
        
        try:
            extractor = self.context_extractors["method_context"]
            method_context = extractor.extract_context(source_code, line_number)
            
            self.performance_metrics["method_extraction_time"] += time.time() - extraction_start
            return method_context
            
        except Exception as e:
            logger.warning(f"Method context extraction failed: {e}")
            return None
    
    def _extract_class_context(self, source_code: str, 
                              line_number: int) -> Optional[ClassContext]:
        """Extract class context for the given line."""
        extraction_start = time.time()
        
        try:
            extractor = self.context_extractors["class_context"]
            class_context = extractor.extract_context(source_code, line_number)
            
            self.performance_metrics["class_extraction_time"] += time.time() - extraction_start
            return class_context
            
        except Exception as e:
            logger.warning(f"Class context extraction failed: {e}")
            return None
    
    def _analyze_data_flow(self, source_code: str, line_number: int, 
                          location: Dict[str, Any]) -> Optional[DataFlowContext]:
        """Analyze data flow for security-relevant findings."""
        analysis_start = time.time()
        
        try:
            analyzer = self.context_extractors["flow_context"]
            data_flow = analyzer.analyze_flow(source_code, line_number, location)
            
            self.performance_metrics["data_flow_time"] += time.time() - analysis_start
            return data_flow
            
        except Exception as e:
            logger.warning(f"Data flow analysis failed: {e}")
            return None
    
    def _analyze_call_chain(self, source_code: str, line_number: int, 
                           method_context: Optional[MethodContext]) -> Optional[CallChainContext]:
        """Analyze call chain for complex vulnerabilities."""
        analysis_start = time.time()
        
        try:
            analyzer = self.context_extractors["call_context"]
            call_chain = analyzer.analyze_calls(source_code, line_number, method_context)
            
            self.performance_metrics["call_chain_time"] += time.time() - analysis_start
            return call_chain
            
        except Exception as e:
            logger.warning(f"Call chain analysis failed: {e}")
            return None
    
    def _calculate_context_confidence(self, contextual_info: ContextualLocationInfo) -> float:
        """Calculate overall context confidence score."""
        confidence_score = 0.0
        max_score = 0.0
        
        # Method context confidence
        if contextual_info.method_context:
            confidence_score += 0.3
        max_score += 0.3
        
        # Class context confidence
        if contextual_info.class_context:
            confidence_score += 0.2
        max_score += 0.2
        
        # Data flow context confidence
        if contextual_info.data_flow_context:
            confidence_score += 0.25
        max_score += 0.25
        
        # Call chain context confidence
        if contextual_info.call_chain_context:
            confidence_score += 0.25
        max_score += 0.25
        
        return confidence_score / max_score if max_score > 0 else 0.0
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for context enhancement."""
        return dict(self.performance_metrics)

class MethodContextExtractor:
    """Extracts method context information from source code."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    def extract_context(self, source_code: str, line_number: int) -> Optional[MethodContext]:
        """Extract method context for the given line number."""
        try:
            lines = source_code.split('\n')
            
            # Search backwards for method declaration
            method_info = self._find_method_declaration(lines, line_number)
            if not method_info:
                return None
            
            # Parse method signature
            method_context = self._parse_method_signature(method_info)
            
            # Find method boundaries
            method_context.line_start = method_info['line_number']
            method_context.line_end = self._find_method_end(lines, method_info['line_number'])
            
            return method_context
            
        except Exception as e:
            logger.warning(f"Method context extraction failed: {e}")
            return None
    
    def _find_method_declaration(self, lines: List[str], 
                                target_line: int) -> Optional[Dict[str, Any]]:
        """Find the method declaration for the target line."""
        method_patterns = [
            # Java method patterns
            r'^\s*((?:public|private|protected|static|final|abstract|synchronized|native)\s+)*(\w+)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[^{]+)?\s*\{?',
            # Kotlin function patterns
            r'^\s*((?:public|private|protected|internal|inline|suspend)\s+)*fun\s+(\w+)\s*\([^)]*\)\s*(?::\s*\w+)?\s*\{?',
            # Constructor patterns
            r'^\s*((?:public|private|protected)\s+)?(\w+)\s*\([^)]*\)\s*(?:throws\s+[^{]+)?\s*\{?'
        ]
        
        for i in range(target_line - 1, max(0, target_line - 50), -1):
            line = lines[i].strip()
            
            for pattern in method_patterns:
                match = re.search(pattern, line)
                if match:
                    return {
                        'line_number': i + 1,
                        'line_content': line,
                        'match': match
                    }
        
        return None
    
    def _parse_method_signature(self, method_info: Dict[str, Any]) -> MethodContext:
        """Parse method signature into MethodContext."""
        line = method_info['line_content']
        match = method_info['match']
        
        # Extract modifiers
        modifiers = []
        if match.group(1):
            modifiers = [mod.strip() for mod in match.group(1).split() if mod.strip()]
        
        # Determine method name and return type
        if 'fun ' in line:  # Kotlin function
            method_name = match.group(2)
            return_type = self._extract_kotlin_return_type(line)
        else:  # Java method or constructor
            if len(match.groups()) >= 3:
                return_type = match.group(2)
                method_name = match.group(3)
            else:
                return_type = None
                method_name = match.group(2)
        
        # Extract parameters
        parameters = self._extract_parameters(line)
        
        # Determine method properties
        is_constructor = return_type is None or return_type == method_name
        is_static = 'static' in modifiers
        is_public = 'public' in modifiers
        is_private = 'private' in modifiers
        
        return MethodContext(
            method_name=method_name,
            method_signature=line.strip(),
            return_type=return_type,
            parameters=parameters,
            modifiers=modifiers,
            is_constructor=is_constructor,
            is_static=is_static,
            is_public=is_public,
            is_private=is_private
        )
    
    def _extract_kotlin_return_type(self, line: str) -> Optional[str]:
        """Extract return type from Kotlin function signature."""
        return_match = re.search(r':\s*(\w+)', line)
        return return_match.group(1) if return_match else None
    
    def _extract_parameters(self, line: str) -> List[Dict[str, str]]:
        """Extract parameters from method signature."""
        try:
            # Find parameter list
            param_match = re.search(r'\(([^)]*)\)', line)
            if not param_match or not param_match.group(1).strip():
                return []
            
            param_str = param_match.group(1)
            parameters = []
            
            # Split parameters by comma (simple approach)
            for param in param_str.split(','):
                param = param.strip()
                if param:
                    # Parse parameter (type name or name: type for Kotlin)
                    if ':' in param:  # Kotlin style
                        name, param_type = param.split(':', 1)
                        parameters.append({
                            'name': name.strip(),
                            'type': param_type.strip()
                        })
                    else:  # Java style
                        parts = param.split()
                        if len(parts) >= 2:
                            parameters.append({
                                'type': ' '.join(parts[:-1]),
                                'name': parts[-1]
                            })
            
            return parameters
            
        except Exception as e:
            logger.warning(f"Parameter extraction failed: {e}")
            return []
    
    def _find_method_end(self, lines: List[str], start_line: int) -> int:
        """Find the end line of the method."""
        brace_count = 0
        found_opening = False
        
        for i in range(start_line - 1, len(lines)):
            line = lines[i]
            
            # Count braces
            for char in line:
                if char == '{':
                    brace_count += 1
                    found_opening = True
                elif char == '}':
                    brace_count -= 1
                    
                    # Method ends when braces are balanced
                    if found_opening and brace_count == 0:
                        return i + 1
        
        # If we can't find the end, estimate based on typical method length
        return min(len(lines), start_line + 50)

class ClassContextExtractor:
    """Extracts class context information from source code."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    def extract_context(self, source_code: str, line_number: int) -> Optional[ClassContext]:
        """Extract class context for the given line number."""
        try:
            lines = source_code.split('\n')
            
            # Search backwards for class declaration
            class_info = self._find_class_declaration(lines, line_number)
            if not class_info:
                return None
            
            # Parse class signature
            class_context = self._parse_class_signature(class_info)
            
            # Extract additional class information
            class_context.package_name = self._extract_package_name(lines)
            class_context.line_start = class_info['line_number']
            class_context.line_end = self._find_class_end(lines, class_info['line_number'])
            
            return class_context
            
        except Exception as e:
            logger.warning(f"Class context extraction failed: {e}")
            return None
    
    def _find_class_declaration(self, lines: List[str], 
                               target_line: int) -> Optional[Dict[str, Any]]:
        """Find the class declaration for the target line."""
        class_patterns = [
            # Java class patterns
            r'^\s*((?:public|private|protected|static|final|abstract)\s+)*class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([^{]+))?\s*\{?',
            # Java interface patterns
            r'^\s*((?:public|private|protected)\s+)*interface\s+(\w+)(?:\s+extends\s+([^{]+))?\s*\{?',
            # Kotlin class patterns
            r'^\s*((?:public|private|protected|internal|abstract|open|final)\s+)*class\s+(\w+)(?:\s*:\s*([^{]+))?\s*\{?'
        ]
        
        for i in range(target_line - 1, max(0, target_line - 100), -1):
            line = lines[i].strip()
            
            for pattern in class_patterns:
                match = re.search(pattern, line)
                if match:
                    return {
                        'line_number': i + 1,
                        'line_content': line,
                        'match': match
                    }
        
        return None
    
    def _parse_class_signature(self, class_info: Dict[str, Any]) -> ClassContext:
        """Parse class signature into ClassContext."""
        line = class_info['line_content']
        match = class_info['match']
        
        # Extract modifiers
        modifiers = []
        if match.group(1):
            modifiers = [mod.strip() for mod in match.group(1).split() if mod.strip()]
        
        # Extract class name
        class_name = match.group(2)
        
        # Extract superclass and interfaces
        superclass = None
        interfaces = []
        
        if 'extends' in line:
            extends_match = re.search(r'extends\s+(\w+)', line)
            if extends_match:
                superclass = extends_match.group(1)
        
        if 'implements' in line:
            implements_match = re.search(r'implements\s+([^{]+)', line)
            if implements_match:
                interfaces = [iface.strip() for iface in implements_match.group(1).split(',')]
        
        # Handle Kotlin inheritance syntax
        if ':' in line and 'class' in line:
            inheritance_match = re.search(r':\s*([^{]+)', line)
            if inheritance_match:
                inheritance_list = [item.strip() for item in inheritance_match.group(1).split(',')]
                # First item is typically the superclass in Kotlin
                if inheritance_list:
                    superclass = inheritance_list[0]
                    interfaces.extend(inheritance_list[1:])
        
        # Determine class properties
        is_abstract = 'abstract' in modifiers
        is_final = 'final' in modifiers
        is_public = 'public' in modifiers
        
        return ClassContext(
            class_name=class_name,
            superclass=superclass,
            interfaces=interfaces,
            modifiers=modifiers,
            is_abstract=is_abstract,
            is_final=is_final,
            is_public=is_public
        )
    
    def _extract_package_name(self, lines: List[str]) -> Optional[str]:
        """Extract package name from source code."""
        for line in lines[:20]:  # Check first 20 lines
            line = line.strip()
            if line.startswith('package '):
                package_match = re.search(r'package\s+([^;]+)', line)
                if package_match:
                    return package_match.group(1).strip()
        return None
    
    def _find_class_end(self, lines: List[str], start_line: int) -> int:
        """Find the end line of the class."""
        brace_count = 0
        found_opening = False
        
        for i in range(start_line - 1, len(lines)):
            line = lines[i]
            
            # Count braces
            for char in line:
                if char == '{':
                    brace_count += 1
                    found_opening = True
                elif char == '}':
                    brace_count -= 1
                    
                    # Class ends when braces are balanced
                    if found_opening and brace_count == 0:
                        return i + 1
        
        # If we can't find the end, return end of file
        return len(lines)

class DataFlowAnalyzer:
    """Analyzes data flow for security-relevant findings."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._initialize_security_patterns()
    
    def _initialize_security_patterns(self):
        """Initialize security-relevant data flow patterns."""
        self.security_sources = [
            r'getIntent\(\)',
            r'getExtras\(\)',
            r'getStringExtra\(',
            r'getSharedPreferences\(',
            r'openFileInput\(',
            r'getInputStream\(',
            r'readLine\(\)',
            r'Scanner\(',
            r'BufferedReader\('
        ]
        
        self.security_sinks = [
            r'execSQL\(',
            r'rawQuery\(',
            r'Runtime\.exec\(',
            r'ProcessBuilder\(',
            r'startActivity\(',
            r'sendBroadcast\(',
            r'writeToFile\(',
            r'openFileOutput\(',
            r'getOutputStream\('
        ]
    
    def analyze_flow(self, source_code: str, line_number: int, 
                    location: Dict[str, Any]) -> Optional[DataFlowContext]:
        """Analyze data flow for the given location."""
        try:
            lines = source_code.split('\n')
            target_line = lines[line_number - 1] if line_number <= len(lines) else ""
            
            # Extract variable name from the target line
            variable_name = self._extract_variable_name(target_line)
            
            # Find data sources and sinks
            data_sources = self._find_data_sources(lines, variable_name)
            data_sinks = self._find_data_sinks(lines, variable_name)
            
            # Analyze taint flow
            taint_flow = self._analyze_taint_flow(lines, variable_name, line_number)
            
            # Assess security implications
            security_implications = self._assess_security_implications(
                data_sources, data_sinks, taint_flow
            )
            
            # Determine risk level
            risk_level = self._determine_risk_level(data_sources, data_sinks, security_implications)
            
            return DataFlowContext(
                variable_name=variable_name,
                data_sources=data_sources,
                data_sinks=data_sinks,
                taint_flow=taint_flow,
                security_implications=security_implications,
                risk_level=risk_level
            )
            
        except Exception as e:
            logger.warning(f"Data flow analysis failed: {e}")
            return None
    
    def _extract_variable_name(self, line: str) -> Optional[str]:
        """Extract variable name from a line of code."""
        # Look for variable assignments
        assignment_patterns = [
            r'(\w+)\s*=',
            r'String\s+(\w+)\s*=',
            r'(\w+)\s*\.',
            r'(\w+)\s*\('
        ]
        
        for pattern in assignment_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        
        return None
    
    def _find_data_sources(self, lines: List[str], variable_name: Optional[str]) -> List[str]:
        """Find data sources in the code."""
        sources = []
        
        for line_num, line in enumerate(lines, 1):
            for source_pattern in self.security_sources:
                if re.search(source_pattern, line):
                    sources.append(f"Line {line_num}: {line.strip()}")
        
        return sources
    
    def _find_data_sinks(self, lines: List[str], variable_name: Optional[str]) -> List[str]:
        """Find data sinks in the code."""
        sinks = []
        
        for line_num, line in enumerate(lines, 1):
            for sink_pattern in self.security_sinks:
                if re.search(sink_pattern, line):
                    sinks.append(f"Line {line_num}: {line.strip()}")
        
        return sinks
    
    def _analyze_taint_flow(self, lines: List[str], variable_name: Optional[str], 
                           target_line: int) -> List[Dict[str, Any]]:
        """Analyze taint flow for the variable."""
        taint_flow = []
        
        if not variable_name:
            return taint_flow
        
        # Simple taint analysis - track variable usage
        for line_num, line in enumerate(lines, 1):
            if variable_name in line:
                taint_flow.append({
                    'line_number': line_num,
                    'line_content': line.strip(),
                    'taint_type': self._classify_taint_operation(line)
                })
        
        return taint_flow
    
    def _classify_taint_operation(self, line: str) -> str:
        """Classify the type of taint operation."""
        if any(re.search(pattern, line) for pattern in self.security_sources):
            return "SOURCE"
        elif any(re.search(pattern, line) for pattern in self.security_sinks):
            return "SINK"
        elif '=' in line:
            return "ASSIGNMENT"
        elif '(' in line:
            return "METHOD_CALL"
        else:
            return "REFERENCE"
    
    def _assess_security_implications(self, data_sources: List[str], 
                                    data_sinks: List[str], 
                                    taint_flow: List[Dict[str, Any]]) -> List[str]:
        """Assess security implications of the data flow."""
        implications = []
        
        if data_sources and data_sinks:
            implications.append("Potential data flow from source to sink")
        
        if len(data_sources) > 0:
            implications.append("Data originates from external source")
        
        if len(data_sinks) > 0:
            implications.append("Data flows to security-sensitive sink")
        
        source_sink_pairs = [
            ("getIntent", "execSQL", "Intent data used in SQL query"),
            ("getStringExtra", "Runtime.exec", "Intent extra used in command execution"),
            ("getSharedPreferences", "startActivity", "Shared preference data used in intent")
        ]
        
        for source, sink, implication in source_sink_pairs:
            if (any(source in src for src in data_sources) and 
                any(sink in snk for snk in data_sinks)):
                implications.append(implication)
        
        return implications
    
    def _determine_risk_level(self, data_sources: List[str], data_sinks: List[str], 
                             security_implications: List[str]) -> str:
        """Determine risk level based on data flow analysis."""
        if len(security_implications) >= 3:
            return "HIGH"
        elif len(security_implications) >= 2:
            return "MEDIUM"
        elif len(security_implications) >= 1:
            return "LOW"
        else:
            return "UNKNOWN"

class CallGraphAnalyzer:
    """Analyzes call chains for complex vulnerabilities."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.max_depth = config.get("analysis_limits", {}).get("max_call_chain_depth", 10)
    
    def analyze_calls(self, source_code: str, line_number: int, 
                     method_context: Optional[MethodContext]) -> Optional[CallChainContext]:
        """Analyze call chain for the given location."""
        try:
            lines = source_code.split('\n')
            
            # Find method calls in the current method
            call_sequence = self._find_method_calls(lines, method_context)
            
            # Find entry points
            entry_points = self._find_entry_points(lines, method_context)
            
            # Analyze critical paths
            critical_paths = self._find_critical_paths(call_sequence)
            
            # Find external calls
            external_calls = self._find_external_calls(call_sequence)
            
            # Identify security boundaries
            security_boundaries = self._identify_security_boundaries(call_sequence)
            
            # Calculate complexity score
            complexity_score = self._calculate_complexity_score(
                call_sequence, critical_paths, external_calls
            )
            
            return CallChainContext(
                call_sequence=call_sequence,
                entry_points=entry_points,
                critical_paths=critical_paths,
                external_calls=external_calls,
                security_boundaries=security_boundaries,
                complexity_score=complexity_score
            )
            
        except Exception as e:
            logger.warning(f"Call chain analysis failed: {e}")
            return None
    
    def _find_method_calls(self, lines: List[str], 
                          method_context: Optional[MethodContext]) -> List[Dict[str, Any]]:
        """Find method calls in the source code."""
        calls = []
        
        method_call_pattern = r'(\w+)\.(\w+)\s*\('
        
        for line_num, line in enumerate(lines, 1):
            matches = re.finditer(method_call_pattern, line)
            for match in matches:
                calls.append({
                    'line_number': line_num,
                    'object': match.group(1),
                    'method': match.group(2),
                    'full_call': match.group(0),
                    'line_content': line.strip()
                })
        
        return calls
    
    def _find_entry_points(self, lines: List[str], 
                          method_context: Optional[MethodContext]) -> List[str]:
        """Find potential entry points for the code."""
        entry_points = []
        
        entry_patterns = [
            r'onCreate\s*\(',
            r'onStart\s*\(',
            r'onResume\s*\(',
            r'onClick\s*\(',
            r'onReceive\s*\(',
            r'doInBackground\s*\(',
            r'run\s*\(',
            r'main\s*\('
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in entry_patterns:
                if re.search(pattern, line):
                    entry_points.append(f"Line {line_num}: {line.strip()}")
        
        return entry_points
    
    def _find_critical_paths(self, call_sequence: List[Dict[str, Any]]) -> List[List[str]]:
        """Find critical execution paths."""
        critical_paths = []
        
        # Group calls by security relevance
        security_calls = []
        for call in call_sequence:
            if self._is_security_relevant_call(call):
                security_calls.append(call)
        
        # Create paths from security calls
        if len(security_calls) >= 2:
            path = [f"{call['object']}.{call['method']}" for call in security_calls]
            critical_paths.append(path)
        
        return critical_paths
    
    def _is_security_relevant_call(self, call: Dict[str, Any]) -> bool:
        """Check if a method call is security relevant."""
        security_methods = [
            'execSQL', 'rawQuery', 'exec', 'startActivity', 'sendBroadcast',
            'openFileInput', 'openFileOutput', 'getSharedPreferences',
            'checkPermission', 'requestPermissions'
        ]
        
        return call['method'] in security_methods
    
    def _find_external_calls(self, call_sequence: List[Dict[str, Any]]) -> List[str]:
        """Find calls to external APIs or libraries."""
        external_calls = []
        
        external_indicators = [
            'android.', 'java.', 'javax.', 'org.', 'com.google.',
            'retrofit', 'okhttp', 'gson', 'jackson'
        ]
        
        for call in call_sequence:
            if any(indicator in call['line_content'].lower() for indicator in external_indicators):
                external_calls.append(f"{call['object']}.{call['method']}")
        
        return list(set(external_calls))  # Remove duplicates
    
    def _identify_security_boundaries(self, call_sequence: List[Dict[str, Any]]) -> List[str]:
        """Identify security boundaries in the call sequence."""
        boundaries = []
        
        boundary_indicators = [
            ('permission', 'Permission check'),
            ('authentication', 'Authentication boundary'),
            ('encryption', 'Encryption boundary'),
            ('validation', 'Input validation'),
            ('sanitization', 'Data sanitization')
        ]
        
        for call in call_sequence:
            line_lower = call['line_content'].lower()
            for indicator, boundary_type in boundary_indicators:
                if indicator in line_lower:
                    boundaries.append(f"{boundary_type} at line {call['line_number']}")
        
        return boundaries
    
    def _calculate_complexity_score(self, call_sequence: List[Dict[str, Any]], 
                                   critical_paths: List[List[str]], 
                                   external_calls: List[str]) -> float:
        """Calculate complexity score for the call chain."""
        base_score = len(call_sequence) * 0.1
        path_score = len(critical_paths) * 0.3
        external_score = len(external_calls) * 0.2
        
        total_score = base_score + path_score + external_score
        return min(1.0, total_score)

# Integration function for existing AODS framework
def enhance_vulnerability_with_contextual_location(vulnerability: Dict[str, Any], 
                                                 source_code: str) -> Dict[str, Any]:
    """
    Enhance a vulnerability with contextual location information.
    
    This function integrates with the existing AODS framework to add
    rich contextual information to vulnerability findings.
    """
    try:
        enhancer = ContextualLocationEnhancer()
        
        # Extract basic location info
        location = vulnerability.get('location', {})
        if 'precise_location' in vulnerability:
            location = vulnerability['precise_location']
        
        # Enhance with contextual information
        contextual_info = enhancer.enhance_location_with_context(location, source_code)
        
        # Add contextual information to vulnerability
        vulnerability['contextual_location'] = contextual_info.to_dict()
        
        return vulnerability
        
    except Exception as e:
        logger.error(f"Contextual location enhancement failed: {e}")
        return vulnerability

if __name__ == "__main__":
    # Example usage and testing
    logger.info("🔍 AODS Contextual Location Enhancer - Context-Aware Location Enhancement")
    
    # Test with sample location and source code
    sample_location = {
        'file_path': 'com/example/MainActivity.java',
        'line_number': 15
    }
    
    sample_source = '''
package com.example;

import android.app.Activity;
import android.os.Bundle;
import android.content.Intent;

public class MainActivity extends Activity {
    private static final String TAG = "MainActivity";
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Hardcoded API key - security vulnerability
        String apiKey = "sk_live_abcd1234567890";
        
        Intent intent = getIntent();
        String userData = intent.getStringExtra("user_data");
        
        // Potential SQL injection
        String query = "SELECT * FROM users WHERE name = '" + userData + "'";
        database.execSQL(query);
    }
    
    private void processUserData(String data) {
        // Process user data
    }
}
'''
    
    enhancer = ContextualLocationEnhancer()
    contextual_info = enhancer.enhance_location_with_context(sample_location, sample_source)
    
    print(f"✅ Contextual location enhanced: {contextual_info.format_display()}")
    print(f"📊 Analysis completed in {contextual_info.analysis_time:.3f}s")
    print(f"🎯 Context confidence: {contextual_info.context_confidence:.2f}")
    
    if contextual_info.method_context:
        print(f"🔧 Method: {contextual_info.method_context.method_name}")
    
    if contextual_info.class_context:
        print(f"📁 Class: {contextual_info.class_context.class_name}")
    
    if contextual_info.data_flow_context:
        print(f"🌊 Data flow risk: {contextual_info.data_flow_context.risk_level}")