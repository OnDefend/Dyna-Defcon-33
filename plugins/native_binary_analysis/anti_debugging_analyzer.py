#!/usr/bin/env python3
"""
Anti-Debugging Analyzer for Native Binary Analysis

This module provides comprehensive anti-debugging mechanism detection and analysis
for native binary components. It detects various anti-debugging techniques,
evaluates their effectiveness, and provides detailed security assessments.

Features:
- Multi-layer anti-debugging detection
- Debugger tool detection and analysis
- Timing-based detection analysis
- Exception-based detection analysis
- Native anti-debugging mechanism assessment
- VM/Sandbox detection analysis
- Comprehensive security scoring
- vulnerability reporting

"""

import logging
import re
import struct
from typing import Dict, List, Optional, Any, Set, Tuple
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
import yaml

from core.shared_infrastructure.analysis_exceptions import AnalysisError
from core.shared_infrastructure.dependency_injection import AnalysisContext
from .data_structures import (
    NativeBinaryVulnerability, VulnerabilitySeverity, AntiDebuggingStrength,
    AntiDebuggingTechnique, DetectionMethod, ProtectionLevel
)

class AntiDebuggingCategory(Enum):
    """Anti-debugging mechanism categories."""
    DEBUG_DETECTION = "debug_detection"
    PROCESS_MONITORING = "process_monitoring"
    TIMING_BASED = "timing_based"
    EXCEPTION_BASED = "exception_based"
    NATIVE_CALLS = "native_calls"
    REGISTER_MANIPULATION = "register_manipulation"
    INSTRUCTION_LEVEL = "instruction_level"
    VM_DETECTION = "vm_detection"
    SANDBOX_DETECTION = "sandbox_detection"
    DEBUGGER_TOOLS = "debugger_tools"

@dataclass
class AntiDebuggingMechanism:
    """Represents an anti-debugging mechanism found in binary."""
    mechanism_id: str
    category: AntiDebuggingCategory
    technique: AntiDebuggingTechnique
    detection_method: DetectionMethod
    strength: AntiDebuggingStrength
    function_name: str
    location: str
    pattern_matched: str
    confidence: float
    bypass_difficulty: str
    security_impact: str
    implementation_details: Dict[str, Any]

@dataclass
class AntiDebuggingAnalysis:
    """Comprehensive anti-debugging analysis results."""
    total_mechanisms: int
    mechanisms_by_category: Dict[AntiDebuggingCategory, List[AntiDebuggingMechanism]]
    mechanisms_by_strength: Dict[AntiDebuggingStrength, List[AntiDebuggingMechanism]]
    overall_protection_level: ProtectionLevel
    coverage_analysis: Dict[str, float]
    effectiveness_score: float
    bypass_resistance_score: float
    implementation_quality_score: float
    security_recommendations: List[str]
    vulnerabilities: List[NativeBinaryVulnerability]

class AntiDebuggingAnalyzer:
    """
    Comprehensive anti-debugging mechanism analyzer.
    
    Analyzes native binaries for anti-debugging techniques, evaluates their
    effectiveness, and provides detailed security assessments.
    """
    
    def __init__(self, context: AnalysisContext):
        """
        Initialize anti-debugging analyzer.
        
        Args:
            context: Analysis context with dependency injection
        """
        self.context = context
        self.logger = context.logger if hasattr(context, 'logger') else logging.getLogger(__name__)
        
        # Load configuration
        self.config = self._load_configuration()
        
        # Anti-debugging patterns
        self.anti_debugging_patterns = self.config.get('anti_debugging_patterns', {})
        self.debugger_tools = self.config.get('debugger_tools', {})
        self.anti_debugging_techniques = self.config.get('anti_debugging_techniques', {})
        
        # Pattern reliability scores
        self.pattern_reliability = self.config.get('pattern_reliability', {})
        
        self.logger.info("Anti-debugging analyzer initialized with enhanced detection patterns")
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load configuration from external YAML file."""
        try:
            config_path = Path(__file__).parent / 'binary_patterns_config.yaml'
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f)
            else:
                self.logger.warning(f"Configuration file not found: {config_path}")
                return {}
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            return {}
    
    def analyze_anti_debugging_mechanisms(self, binary_path: Path, 
                                        binary_data: bytes) -> AntiDebuggingAnalysis:
        """
        Analyze anti-debugging mechanisms in native binary.
        
        Args:
            binary_path: Path to the binary file
            binary_data: Binary file contents
            
        Returns:
            Comprehensive anti-debugging analysis
        """
        try:
            self.logger.info(f"Analyzing anti-debugging mechanisms in {binary_path}")
            
            # Initialize analysis result
            analysis = AntiDebuggingAnalysis(
                total_mechanisms=0,
                mechanisms_by_category={},
                mechanisms_by_strength={},
                overall_protection_level=ProtectionLevel.MINIMAL,
                coverage_analysis={},
                effectiveness_score=0.0,
                bypass_resistance_score=0.0,
                implementation_quality_score=0.0,
                security_recommendations=[],
                vulnerabilities=[]
            )
            
            # Detect anti-debugging mechanisms
            mechanisms = self._detect_anti_debugging_mechanisms(binary_path, binary_data)
            analysis.total_mechanisms = len(mechanisms)
            
            # Categorize mechanisms
            analysis.mechanisms_by_category = self._categorize_mechanisms(mechanisms)
            analysis.mechanisms_by_strength = self._categorize_by_strength(mechanisms)
            
            # Assess protection level and effectiveness
            analysis.overall_protection_level = self._assess_protection_level(mechanisms)
            analysis.coverage_analysis = self._analyze_coverage(mechanisms)
            analysis.effectiveness_score = self._calculate_effectiveness_score(mechanisms)
            analysis.bypass_resistance_score = self._calculate_bypass_resistance_score(mechanisms)
            analysis.implementation_quality_score = self._calculate_implementation_quality_score(mechanisms)
            
            # Generate security recommendations
            analysis.security_recommendations = self._generate_security_recommendations(analysis)
            
            # Generate vulnerabilities
            analysis.vulnerabilities = self._generate_vulnerabilities(analysis, binary_path)
            
            self.logger.info(f"Anti-debugging analysis completed. Found {len(mechanisms)} mechanisms.")
            return analysis
            
        except Exception as e:
            self.logger.error(f"Anti-debugging analysis failed: {e}")
            raise AnalysisError(f"Failed to analyze anti-debugging mechanisms: {e}")
    
    def _detect_anti_debugging_mechanisms(self, binary_path: Path, 
                                        binary_data: bytes) -> List[AntiDebuggingMechanism]:
        """Detect anti-debugging mechanisms in binary."""
        mechanisms = []
        
        try:
            # Convert binary data to string for pattern matching
            binary_str = binary_data.decode('utf-8', errors='ignore')
            
            # Detect debug detection functions
            debug_mechanisms = self._detect_debug_detection_functions(binary_str, binary_path)
            mechanisms.extend(debug_mechanisms)
            
            # Detect process monitoring functions
            process_mechanisms = self._detect_process_monitoring_functions(binary_str, binary_path)
            mechanisms.extend(process_mechanisms)
            
            # Detect timing-based detection
            timing_mechanisms = self._detect_timing_based_detection(binary_str, binary_path)
            mechanisms.extend(timing_mechanisms)
            
            # Detect exception-based detection
            exception_mechanisms = self._detect_exception_based_detection(binary_str, binary_path)
            mechanisms.extend(exception_mechanisms)
            
            # Detect native anti-debugging calls
            native_mechanisms = self._detect_native_anti_debugging(binary_str, binary_path)
            mechanisms.extend(native_mechanisms)
            
            # Detect register manipulation
            register_mechanisms = self._detect_register_manipulation(binary_str, binary_path)
            mechanisms.extend(register_mechanisms)
            
            # Detect instruction-level detection
            instruction_mechanisms = self._detect_instruction_level_detection(binary_data, binary_path)
            mechanisms.extend(instruction_mechanisms)
            
            # Detect VM/Sandbox detection
            vm_mechanisms = self._detect_vm_sandbox_detection(binary_str, binary_path)
            mechanisms.extend(vm_mechanisms)
            
            # Detect debugger tool detection
            tool_mechanisms = self._detect_debugger_tool_detection(binary_str, binary_path)
            mechanisms.extend(tool_mechanisms)
            
            # Phase 2.5.2 Enhancement: Debug symbol analysis
            symbol_mechanisms = self._analyze_debugging_symbols(binary_path, binary_data)
            mechanisms.extend(symbol_mechanisms)
            
            # Phase 2.5.2 Enhancement: Enhanced native code pattern analysis
            enhanced_pattern_mechanisms = self._analyze_enhanced_native_patterns(binary_str, binary_path)
            mechanisms.extend(enhanced_pattern_mechanisms)
            
            # Phase 2.5.2 Enhancement: System call monitoring detection
            syscall_mechanisms = self._detect_system_call_monitoring(binary_str, binary_path)
            mechanisms.extend(syscall_mechanisms)
            
            # Phase 2.5.2 Enhancement: Runtime debugging prevention analysis
            runtime_prevention_mechanisms = self._analyze_runtime_debugging_prevention(binary_str, binary_path)
            mechanisms.extend(runtime_prevention_mechanisms)
            
            return mechanisms
            
        except Exception as e:
            self.logger.error(f"Mechanism detection failed: {e}")
            return []
    
    def _detect_debug_detection_functions(self, binary_str: str, 
                                        binary_path: Path) -> List[AntiDebuggingMechanism]:
        """Detect debug detection functions."""
        mechanisms = []
        
        try:
            debug_functions = self.anti_debugging_patterns.get('debug_detection_functions', [])
            
            for func_name in debug_functions:
                if func_name in binary_str:
                    # Calculate confidence based on pattern reliability
                    reliability = self.pattern_reliability.get('anti_debugging_detection', {})
                    confidence = reliability.get('confidence_weight', 0.85)
                    
                    # Determine strength based on function type
                    if func_name in ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent']:
                        strength = AntiDebuggingStrength.BASIC
                        bypass_difficulty = "Easy"
                    elif func_name in ['OutputDebugString', 'DebugActiveProcess']:
                        strength = AntiDebuggingStrength.MODERATE
                        bypass_difficulty = "Moderate"
                    else:
                        strength = AntiDebuggingStrength.ADVANCED
                        bypass_difficulty = "Advanced"
                    
                    mechanism = AntiDebuggingMechanism(
                        mechanism_id=f"DEBUG_DETECT_{func_name}_{len(mechanisms)}",
                        category=AntiDebuggingCategory.DEBUG_DETECTION,
                        technique=AntiDebuggingTechnique.DEBUGGER_DETECTION,
                        detection_method=DetectionMethod.PATTERN_MATCHING,
                        strength=strength,
                        function_name=func_name,
                        location=str(binary_path),
                        pattern_matched=func_name,
                        confidence=confidence,
                        bypass_difficulty=bypass_difficulty,
                        security_impact=f"Detects debugger attachment using {func_name}",
                        implementation_details={
                            'function_type': 'debug_detection',
                            'api_category': 'windows_debug_api' if func_name.startswith('Debug') else 'generic',
                            'detection_scope': 'runtime'
                        }
                    )
                    
                    mechanisms.append(mechanism)
            
            return mechanisms
            
        except Exception as e:
            self.logger.error(f"Debug detection function analysis failed: {e}")
            return []
    
    def _detect_process_monitoring_functions(self, binary_str: str, 
                                           binary_path: Path) -> List[AntiDebuggingMechanism]:
        """Detect process monitoring functions."""
        mechanisms = []
        
        try:
            process_functions = self.anti_debugging_patterns.get('process_monitoring_functions', [])
            
            for func_name in process_functions:
                if func_name in binary_str:
                    # Calculate confidence
                    reliability = self.pattern_reliability.get('anti_debugging_detection', {})
                    confidence = reliability.get('confidence_weight', 0.85)
                    
                    # Determine strength
                    if func_name in ['GetCurrentProcessId', 'GetProcessId']:
                        strength = AntiDebuggingStrength.BASIC
                        bypass_difficulty = "Easy"
                    elif func_name in ['OpenProcess', 'ReadProcessMemory']:
                        strength = AntiDebuggingStrength.MODERATE
                        bypass_difficulty = "Moderate"
                    else:
                        strength = AntiDebuggingStrength.ADVANCED
                        bypass_difficulty = "Advanced"
                    
                    mechanism = AntiDebuggingMechanism(
                        mechanism_id=f"PROCESS_MONITOR_{func_name}_{len(mechanisms)}",
                        category=AntiDebuggingCategory.PROCESS_MONITORING,
                        technique=AntiDebuggingTechnique.PROCESS_MONITORING,
                        detection_method=DetectionMethod.PATTERN_MATCHING,
                        strength=strength,
                        function_name=func_name,
                        location=str(binary_path),
                        pattern_matched=func_name,
                        confidence=confidence,
                        bypass_difficulty=bypass_difficulty,
                        security_impact=f"Monitors process state using {func_name}",
                        implementation_details={
                            'function_type': 'process_monitoring',
                            'monitoring_scope': 'process_enumeration' if 'Process' in func_name else 'memory_access',
                            'detection_scope': 'runtime'
                        }
                    )
                    
                    mechanisms.append(mechanism)
            
            return mechanisms
            
        except Exception as e:
            self.logger.error(f"Process monitoring function analysis failed: {e}")
            return []
    
    def _detect_timing_based_detection(self, binary_str: str, 
                                     binary_path: Path) -> List[AntiDebuggingMechanism]:
        """Detect timing-based detection mechanisms."""
        mechanisms = []
        
        try:
            timing_functions = self.anti_debugging_patterns.get('timing_based_detection', [])
            
            for func_name in timing_functions:
                if func_name in binary_str:
                    # Calculate confidence
                    reliability = self.pattern_reliability.get('timing_based_detection', {})
                    confidence = reliability.get('confidence_weight', 0.85)
                    
                    # Determine strength based on timing precision
                    if func_name in ['GetTickCount', 'time']:
                        strength = AntiDebuggingStrength.BASIC
                        bypass_difficulty = "Easy"
                    elif func_name in ['QueryPerformanceCounter', 'gettimeofday']:
                        strength = AntiDebuggingStrength.MODERATE
                        bypass_difficulty = "Moderate"
                    elif func_name in ['rdtsc', 'rdtscp']:
                        strength = AntiDebuggingStrength.ADVANCED
                        bypass_difficulty = "Advanced"
                    else:
                        strength = AntiDebuggingStrength.EXPERT
                        bypass_difficulty = "Expert"
                    
                    mechanism = AntiDebuggingMechanism(
                        mechanism_id=f"TIMING_DETECT_{func_name}_{len(mechanisms)}",
                        category=AntiDebuggingCategory.TIMING_BASED,
                        technique=AntiDebuggingTechnique.TIMING_CHECKS,
                        detection_method=DetectionMethod.PATTERN_MATCHING,
                        strength=strength,
                        function_name=func_name,
                        location=str(binary_path),
                        pattern_matched=func_name,
                        confidence=confidence,
                        bypass_difficulty=bypass_difficulty,
                        security_impact=f"Detects debugger through timing analysis using {func_name}",
                        implementation_details={
                            'function_type': 'timing_detection',
                            'timing_precision': 'high' if func_name in ['rdtsc', 'rdtscp'] else 'medium',
                            'detection_scope': 'runtime'
                        }
                    )
                    
                    mechanisms.append(mechanism)
            
            return mechanisms
            
        except Exception as e:
            self.logger.error(f"Timing-based detection analysis failed: {e}")
            return []
    
    def _detect_exception_based_detection(self, binary_str: str, 
                                        binary_path: Path) -> List[AntiDebuggingMechanism]:
        """Detect exception-based detection mechanisms."""
        mechanisms = []
        
        try:
            exception_functions = self.anti_debugging_patterns.get('exception_based_detection', [])
            
            for func_name in exception_functions:
                if func_name in binary_str:
                    # Calculate confidence
                    reliability = self.pattern_reliability.get('anti_debugging_detection', {})
                    confidence = reliability.get('confidence_weight', 0.85)
                    
                    # Determine strength
                    if func_name in ['__try', '__except']:
                        strength = AntiDebuggingStrength.BASIC
                        bypass_difficulty = "Easy"
                    elif func_name in ['SetUnhandledExceptionFilter']:
                        strength = AntiDebuggingStrength.MODERATE
                        bypass_difficulty = "Moderate"
                    else:
                        strength = AntiDebuggingStrength.ADVANCED
                        bypass_difficulty = "Advanced"
                    
                    mechanism = AntiDebuggingMechanism(
                        mechanism_id=f"EXCEPTION_DETECT_{func_name}_{len(mechanisms)}",
                        category=AntiDebuggingCategory.EXCEPTION_BASED,
                        technique=AntiDebuggingTechnique.EXCEPTION_BASED,
                        detection_method=DetectionMethod.PATTERN_MATCHING,
                        strength=strength,
                        function_name=func_name,
                        location=str(binary_path),
                        pattern_matched=func_name,
                        confidence=confidence,
                        bypass_difficulty=bypass_difficulty,
                        security_impact=f"Detects debugger through exception handling using {func_name}",
                        implementation_details={
                            'function_type': 'exception_detection',
                            'exception_scope': 'structured' if '__' in func_name else 'vectored',
                            'detection_scope': 'runtime'
                        }
                    )
                    
                    mechanisms.append(mechanism)
            
            return mechanisms
            
        except Exception as e:
            self.logger.error(f"Exception-based detection analysis failed: {e}")
            return []
    
    def _detect_native_anti_debugging(self, binary_str: str, 
                                    binary_path: Path) -> List[AntiDebuggingMechanism]:
        """Detect native anti-debugging mechanisms."""
        mechanisms = []
        
        try:
            native_functions = self.anti_debugging_patterns.get('native_anti_debugging', [])
            
            for func_name in native_functions:
                if func_name in binary_str:
                    # Calculate confidence
                    reliability = self.pattern_reliability.get('native_anti_debugging', {})
                    confidence = reliability.get('confidence_weight', 0.95)
                    
                    # Determine strength based on function sophistication
                    if func_name in ['getppid', 'kill']:
                        strength = AntiDebuggingStrength.BASIC
                        bypass_difficulty = "Easy"
                    elif func_name in ['prctl', 'signal']:
                        strength = AntiDebuggingStrength.MODERATE
                        bypass_difficulty = "Moderate"
                    elif func_name in ['ptrace', 'PTRACE_TRACEME']:
                        strength = AntiDebuggingStrength.ADVANCED
                        bypass_difficulty = "Advanced"
                    else:
                        strength = AntiDebuggingStrength.EXPERT
                        bypass_difficulty = "Expert"
                    
                    mechanism = AntiDebuggingMechanism(
                        mechanism_id=f"NATIVE_ANTIDEBUG_{func_name}_{len(mechanisms)}",
                        category=AntiDebuggingCategory.NATIVE_CALLS,
                        technique=AntiDebuggingTechnique.NATIVE_CALLS,
                        detection_method=DetectionMethod.PATTERN_MATCHING,
                        strength=strength,
                        function_name=func_name,
                        location=str(binary_path),
                        pattern_matched=func_name,
                        confidence=confidence,
                        bypass_difficulty=bypass_difficulty,
                        security_impact=f"Native anti-debugging using {func_name}",
                        implementation_details={
                            'function_type': 'native_anti_debugging',
                            'platform': 'linux' if func_name in ['ptrace', 'prctl'] else 'generic',
                            'detection_scope': 'runtime'
                        }
                    )
                    
                    mechanisms.append(mechanism)
            
            return mechanisms
            
        except Exception as e:
            self.logger.error(f"Native anti-debugging analysis failed: {e}")
            return []
    
    def _detect_register_manipulation(self, binary_str: str, 
                                    binary_path: Path) -> List[AntiDebuggingMechanism]:
        """Detect register manipulation mechanisms."""
        mechanisms = []
        
        try:
            register_patterns = self.anti_debugging_patterns.get('register_manipulation', [])
            
            for pattern in register_patterns:
                if pattern in binary_str:
                    # Calculate confidence
                    confidence = 0.90  # High confidence for register manipulation
                    
                    # Determine strength
                    if pattern in ['DR0', 'DR1', 'DR2', 'DR3']:
                        strength = AntiDebuggingStrength.ADVANCED
                        bypass_difficulty = "Advanced"
                    elif pattern in ['DR6', 'DR7']:
                        strength = AntiDebuggingStrength.EXPERT
                        bypass_difficulty = "Expert"
                    else:
                        strength = AntiDebuggingStrength.MODERATE
                        bypass_difficulty = "Moderate"
                    
                    mechanism = AntiDebuggingMechanism(
                        mechanism_id=f"REGISTER_MANIP_{pattern}_{len(mechanisms)}",
                        category=AntiDebuggingCategory.REGISTER_MANIPULATION,
                        technique=AntiDebuggingTechnique.REGISTER_MANIPULATION,
                        detection_method=DetectionMethod.PATTERN_MATCHING,
                        strength=strength,
                        function_name=pattern,
                        location=str(binary_path),
                        pattern_matched=pattern,
                        confidence=confidence,
                        bypass_difficulty=bypass_difficulty,
                        security_impact=f"Hardware debug register manipulation using {pattern}",
                        implementation_details={
                            'function_type': 'register_manipulation',
                            'register_type': 'debug' if pattern.startswith('DR') else 'context',
                            'detection_scope': 'hardware'
                        }
                    )
                    
                    mechanisms.append(mechanism)
            
            return mechanisms
            
        except Exception as e:
            self.logger.error(f"Register manipulation analysis failed: {e}")
            return []
    
    def _detect_instruction_level_detection(self, binary_data: bytes, 
                                          binary_path: Path) -> List[AntiDebuggingMechanism]:
        """Detect instruction-level detection mechanisms."""
        mechanisms = []
        
        try:
            # Look for specific instruction patterns
            instruction_patterns = {
                b'\xCC': 'INT3',
                b'\xCD\x03': 'INT_3',
                b'\xF1': 'ICEBP',
                b'\x0F\x0B': 'UD2'
            }
            
            for opcode, instruction in instruction_patterns.items():
                if opcode in binary_data:
                    # Calculate confidence
                    confidence = 0.95  # Very high confidence for instruction detection
                    
                    # Determine strength
                    if instruction in ['INT3', 'INT_3']:
                        strength = AntiDebuggingStrength.BASIC
                        bypass_difficulty = "Easy"
                    elif instruction == 'ICEBP':
                        strength = AntiDebuggingStrength.ADVANCED
                        bypass_difficulty = "Advanced"
                    else:
                        strength = AntiDebuggingStrength.EXPERT
                        bypass_difficulty = "Expert"
                    
                    mechanism = AntiDebuggingMechanism(
                        mechanism_id=f"INSTRUCTION_DETECT_{instruction}_{len(mechanisms)}",
                        category=AntiDebuggingCategory.INSTRUCTION_LEVEL,
                        technique=AntiDebuggingTechnique.INSTRUCTION_LEVEL,
                        detection_method=DetectionMethod.BINARY_ANALYSIS,
                        strength=strength,
                        function_name=instruction,
                        location=str(binary_path),
                        pattern_matched=f"Opcode: {opcode.hex()}",
                        confidence=confidence,
                        bypass_difficulty=bypass_difficulty,
                        security_impact=f"Instruction-level anti-debugging using {instruction}",
                        implementation_details={
                            'function_type': 'instruction_level',
                            'instruction_type': instruction,
                            'opcode': opcode.hex(),
                            'detection_scope': 'assembly'
                        }
                    )
                    
                    mechanisms.append(mechanism)
            
            return mechanisms
            
        except Exception as e:
            self.logger.error(f"Instruction-level detection analysis failed: {e}")
            return []
    
    def _detect_vm_sandbox_detection(self, binary_str: str, 
                                   binary_path: Path) -> List[AntiDebuggingMechanism]:
        """Detect VM and sandbox detection mechanisms."""
        mechanisms = []
        
        try:
            # VM detection patterns
            vm_patterns = self.anti_debugging_patterns.get('vm_detection_patterns', [])
            sandbox_patterns = self.anti_debugging_patterns.get('sandbox_detection', [])
            
            all_patterns = vm_patterns + sandbox_patterns
            
            for pattern in all_patterns:
                if pattern.lower() in binary_str.lower():
                    # Calculate confidence
                    reliability = self.pattern_reliability.get('vm_sandbox_detection', {})
                    confidence = reliability.get('confidence_weight', 0.90)
                    
                    # Determine strength
                    if pattern in ['VMware', 'VirtualBox', 'QEMU']:
                        strength = AntiDebuggingStrength.BASIC
                        bypass_difficulty = "Easy"
                    elif pattern in ['Cuckoo', 'Anubis', 'JoeBox']:
                        strength = AntiDebuggingStrength.MODERATE
                        bypass_difficulty = "Moderate"
                    else:
                        strength = AntiDebuggingStrength.ADVANCED
                        bypass_difficulty = "Advanced"
                    
                    category = AntiDebuggingCategory.VM_DETECTION if pattern in vm_patterns else AntiDebuggingCategory.SANDBOX_DETECTION
                    
                    mechanism = AntiDebuggingMechanism(
                        mechanism_id=f"VM_SANDBOX_DETECT_{pattern}_{len(mechanisms)}",
                        category=category,
                        technique=AntiDebuggingTechnique.VM_DETECTION,
                        detection_method=DetectionMethod.PATTERN_MATCHING,
                        strength=strength,
                        function_name=pattern,
                        location=str(binary_path),
                        pattern_matched=pattern,
                        confidence=confidence,
                        bypass_difficulty=bypass_difficulty,
                        security_impact=f"VM/Sandbox detection using {pattern}",
                        implementation_details={
                            'function_type': 'vm_sandbox_detection',
                            'detection_target': pattern,
                            'detection_scope': 'environment'
                        }
                    )
                    
                    mechanisms.append(mechanism)
            
            return mechanisms
            
        except Exception as e:
            self.logger.error(f"VM/Sandbox detection analysis failed: {e}")
            return []
    
    def _detect_debugger_tool_detection(self, binary_str: str, 
                                      binary_path: Path) -> List[AntiDebuggingMechanism]:
        """Detect debugger tool detection mechanisms."""
        mechanisms = []
        
        try:
            # Get all debugger tools
            common_debuggers = self.debugger_tools.get('common_debuggers', [])
            dynamic_tools = self.debugger_tools.get('dynamic_analysis_tools', [])
            monitoring_tools = self.debugger_tools.get('monitoring_tools', [])
            
            all_tools = common_debuggers + dynamic_tools + monitoring_tools
            
            for tool in all_tools:
                if tool.lower() in binary_str.lower():
                    # Calculate confidence
                    reliability = self.pattern_reliability.get('debugger_tool_detection', {})
                    confidence = reliability.get('confidence_weight', 0.88)
                    
                    # Determine strength based on tool type
                    if tool in ['gdb', 'lldb', 'ida']:
                        strength = AntiDebuggingStrength.MODERATE
                        bypass_difficulty = "Moderate"
                    elif tool in ['frida', 'xposed']:
                        strength = AntiDebuggingStrength.ADVANCED
                        bypass_difficulty = "Advanced"
                    else:
                        strength = AntiDebuggingStrength.BASIC
                        bypass_difficulty = "Easy"
                    
                    mechanism = AntiDebuggingMechanism(
                        mechanism_id=f"DEBUGGER_TOOL_DETECT_{tool}_{len(mechanisms)}",
                        category=AntiDebuggingCategory.DEBUGGER_TOOLS,
                        technique=AntiDebuggingTechnique.TOOL_DETECTION,
                        detection_method=DetectionMethod.PATTERN_MATCHING,
                        strength=strength,
                        function_name=tool,
                        location=str(binary_path),
                        pattern_matched=tool,
                        confidence=confidence,
                        bypass_difficulty=bypass_difficulty,
                        security_impact=f"Debugger tool detection targeting {tool}",
                        implementation_details={
                            'function_type': 'debugger_tool_detection',
                            'tool_category': 'dynamic_analysis' if tool in dynamic_tools else 'static_analysis',
                            'detection_scope': 'environment'
                        }
                    )
                    
                    mechanisms.append(mechanism)
            
            return mechanisms
            
        except Exception as e:
            self.logger.error(f"Debugger tool detection analysis failed: {e}")
            return []
    
    # Phase 2.5.2 Enhancement: Debug symbol analysis for anti-debugging indicators
    def _analyze_debugging_symbols(self, binary_path: Path, binary_data: bytes) -> List[AntiDebuggingMechanism]:
        """
        Analyze debugging symbols for anti-debugging indicators.
        
        This method examines symbol tables, debug information, and function names
        to identify anti-debugging mechanisms embedded at compile time.
        """
        mechanisms = []
        
        try:
            self.logger.info("Analyzing debugging symbols for anti-debugging indicators")
            
            # Convert binary data for string analysis
            binary_str = binary_data.decode('utf-8', errors='ignore')
            
            # Symbol table anti-debugging patterns
            symbol_patterns = {
                'debug_symbol_stripping': [
                    '.debug_info', '.debug_line', '.debug_str', '.debug_abbrev',
                    '.debug_aranges', '.debug_ranges', '.debug_loc'
                ],
                'anti_debug_symbols': [
                    '__anti_debug__', '_check_debugger_', 'detect_debug',
                    'anti_debugger', 'debugger_check', 'is_being_debugged',
                    'debug_detection', 'prevent_debug', 'block_debugger'
                ],
                'obfuscated_symbols': [
                    '__obfuscated__', '__packed__', '__encrypted__',
                    'decrypt_runtime', 'unpack_code', 'deobfuscate'
                ],
                'control_flow_symbols': [
                    'cfi_check', '__cfi_slowpath', '__cfi_check',
                    'control_flow_guard', '__guard_check_icall'
                ]
            }
            
            # Analyze each symbol pattern category
            for category, patterns in symbol_patterns.items():
                for pattern in patterns:
                    if pattern in binary_str:
                        # Calculate confidence based on pattern type
                        if category == 'debug_symbol_stripping':
                            confidence = 0.95  # High confidence for debug sections
                            strength = AntiDebuggingStrength.EXPERT
                            bypass_difficulty = "Expert"
                            security_impact = f"Debug symbols stripped to prevent analysis: {pattern}"
                        elif category == 'anti_debug_symbols':
                            confidence = 0.90
                            strength = AntiDebuggingStrength.ADVANCED
                            bypass_difficulty = "Advanced"
                            security_impact = f"Dedicated anti-debugging symbol: {pattern}"
                        elif category == 'obfuscated_symbols':
                            confidence = 0.85
                            strength = AntiDebuggingStrength.MODERATE
                            bypass_difficulty = "Moderate"
                            security_impact = f"Code obfuscation symbol: {pattern}"
                        else:  # control_flow_symbols
                            confidence = 0.80
                            strength = AntiDebuggingStrength.ADVANCED
                            bypass_difficulty = "Advanced"
                            security_impact = f"Control flow integrity symbol: {pattern}"
                        
                        mechanism = AntiDebuggingMechanism(
                            mechanism_id=f"SYMBOL_ANALYSIS_{pattern}_{len(mechanisms)}",
                            category=AntiDebuggingCategory.DEBUG_DETECTION,
                            technique=AntiDebuggingTechnique.SYMBOL_ANALYSIS,
                            detection_method=DetectionMethod.SYMBOL_TABLE_ANALYSIS,
                            strength=strength,
                            function_name=pattern,
                            location=str(binary_path),
                            pattern_matched=pattern,
                            confidence=confidence,
                            bypass_difficulty=bypass_difficulty,
                            security_impact=security_impact,
                            implementation_details={
                                'symbol_category': category,
                                'analysis_type': 'symbol_table',
                                'detection_scope': 'compile_time'
                            }
                        )
                        
                        mechanisms.append(mechanism)
            
            self.logger.info(f"Symbol analysis found {len(mechanisms)} anti-debugging indicators")
            return mechanisms
            
        except Exception as e:
            self.logger.error(f"Debugging symbol analysis failed: {e}")
            return []
    
    # Phase 2.5.2 Enhancement: Enhanced native code pattern analysis
    def _analyze_enhanced_native_patterns(self, binary_str: str, binary_path: Path) -> List[AntiDebuggingMechanism]:
        """
        Enhanced native code pattern analysis for debugging prevention mechanisms.
        
        This method performs deep pattern analysis to identify sophisticated
        anti-debugging techniques embedded in native code.
        """
        mechanisms = []
        
        try:
            self.logger.info("Performing enhanced native code pattern analysis")
            
            # Enhanced anti-debugging patterns
            enhanced_patterns = {
                'memory_protection_patterns': [
                    'VirtualProtect', 'mprotect', 'mmap', 'munmap',
                    'VirtualAlloc', 'VirtualFree', 'HeapCreate'
                ],
                'code_injection_detection': [
                    'SetWindowsHookEx', 'CreateRemoteThread', 'WriteProcessMemory',
                    'VirtualAllocEx', 'LoadLibrary', 'GetProcAddress'
                ],
                'debug_heap_detection': [
                    'RtlQueryInformationHeap', 'GetProcessHeap', 'HeapValidate',
                    '_CrtSetDbgFlag', '_CrtCheckMemory', 'debug_heap'
                ],
                'peb_analysis_patterns': [
                    'ProcessEnvironmentBlock', 'BeingDebugged', 'NtGlobalFlag',
                    'ProcessHeapFlags', 'ForceFlags', 'Heap.Flags'
                ],
                'anti_attach_patterns': [
                    'NtSetInformationThread', 'ThreadHideFromDebugger',
                    'NtQueryInformationProcess', 'ProcessDebugPort',
                    'ProcessDebugObjectHandle', 'ProcessDebugFlags'
                ],
                'code_integrity_patterns': [
                    'CRC32', 'MD5', 'SHA1', 'checksum', 'hash_verification',
                    'integrity_check', 'code_verification', 'self_check'
                ]
            }
            
            # Analyze each enhanced pattern category
            for category, patterns in enhanced_patterns.items():
                for pattern in patterns:
                    if pattern in binary_str:
                        # Calculate confidence and strength based on pattern sophistication
                        if category == 'memory_protection_patterns':
                            confidence = 0.85
                            strength = AntiDebuggingStrength.MODERATE
                            bypass_difficulty = "Moderate"
                            security_impact = f"Memory protection anti-debugging: {pattern}"
                        elif category == 'code_injection_detection':
                            confidence = 0.90
                            strength = AntiDebuggingStrength.ADVANCED
                            bypass_difficulty = "Advanced"
                            security_impact = f"Code injection detection: {pattern}"
                        elif category == 'debug_heap_detection':
                            confidence = 0.95
                            strength = AntiDebuggingStrength.EXPERT
                            bypass_difficulty = "Expert"
                            security_impact = f"Debug heap detection: {pattern}"
                        elif category == 'peb_analysis_patterns':
                            confidence = 0.92
                            strength = AntiDebuggingStrength.EXPERT
                            bypass_difficulty = "Expert"
                            security_impact = f"PEB-based debugging detection: {pattern}"
                        elif category == 'anti_attach_patterns':
                            confidence = 0.93
                            strength = AntiDebuggingStrength.EXPERT
                            bypass_difficulty = "Expert"
                            security_impact = f"Anti-attach debugging technique: {pattern}"
                        else:  # code_integrity_patterns
                            confidence = 0.88
                            strength = AntiDebuggingStrength.ADVANCED
                            bypass_difficulty = "Advanced"
                            security_impact = f"Code integrity verification: {pattern}"
                        
                        mechanism = AntiDebuggingMechanism(
                            mechanism_id=f"ENHANCED_PATTERN_{pattern}_{len(mechanisms)}",
                            category=AntiDebuggingCategory.NATIVE_CALLS,
                            technique=AntiDebuggingTechnique.ADVANCED_DETECTION,
                            detection_method=DetectionMethod.ENHANCED_PATTERN_ANALYSIS,
                            strength=strength,
                            function_name=pattern,
                            location=str(binary_path),
                            pattern_matched=pattern,
                            confidence=confidence,
                            bypass_difficulty=bypass_difficulty,
                            security_impact=security_impact,
                            implementation_details={
                                'pattern_category': category,
                                'analysis_type': 'enhanced_native_pattern',
                                'detection_scope': 'runtime',
                                'sophistication_level': 'high'
                            }
                        )
                        
                        mechanisms.append(mechanism)
            
            self.logger.info(f"Enhanced pattern analysis found {len(mechanisms)} mechanisms")
            return mechanisms
            
        except Exception as e:
            self.logger.error(f"Enhanced native pattern analysis failed: {e}")
            return []
    
    # Phase 2.5.2 Enhancement: System call monitoring detection
    def _detect_system_call_monitoring(self, binary_str: str, binary_path: Path) -> List[AntiDebuggingMechanism]:
        """
        Detect system call monitoring for debugging detection patterns.
        
        This method identifies system calls used to monitor debugging activities
        and detect debugging attempts through system-level analysis.
        """
        mechanisms = []
        
        try:
            self.logger.info("Detecting system call monitoring patterns")
            
            # System call monitoring patterns
            syscall_patterns = {
                'ptrace_monitoring': [
                    'ptrace', 'PTRACE_TRACEME', 'PTRACE_ATTACH', 'PTRACE_DETACH',
                    'PTRACE_CONT', 'PTRACE_KILL', 'PTRACE_SINGLESTEP'
                ],
                'process_monitoring_syscalls': [
                    'prctl', 'PR_SET_DUMPABLE', 'getppid', 'kill', 'waitpid',
                    'proc_self_stat', 'proc_self_status', 'proc_self_cmdline'
                ],
                'signal_monitoring': [
                    'signal', 'sigaction', 'SIGTRAP', 'SIGILL', 'SIGFPE',
                    'SIGSEGV', 'SIGINT', 'sigprocmask', 'sigaltstack'
                ],
                'file_system_monitoring': [
                    'access', 'stat', 'fstat', 'lstat', 'open', 'openat',
                    'readlink', 'realpath', 'proc_self_maps'
                ],
                'memory_monitoring_syscalls': [
                    'mmap', 'munmap', 'mprotect', 'mremap', 'msync',
                    'madvise', 'mincore', 'mlock', 'munlock'
                ],
                'timing_monitoring_syscalls': [
                    'gettimeofday', 'clock_gettime', 'clock_getres',
                    'times', 'getrusage', 'clock_nanosleep'
                ]
            }
            
            # Analyze each syscall pattern category
            for category, patterns in syscall_patterns.items():
                for pattern in patterns:
                    if pattern in binary_str:
                        # Calculate confidence based on syscall type
                        if category == 'ptrace_monitoring':
                            confidence = 0.95
                            strength = AntiDebuggingStrength.EXPERT
                            bypass_difficulty = "Expert"
                            security_impact = f"Ptrace-based debugging detection: {pattern}"
                        elif category == 'process_monitoring_syscalls':
                            confidence = 0.90
                            strength = AntiDebuggingStrength.ADVANCED
                            bypass_difficulty = "Advanced"
                            security_impact = f"Process monitoring syscall: {pattern}"
                        elif category == 'signal_monitoring':
                            confidence = 0.88
                            strength = AntiDebuggingStrength.ADVANCED
                            bypass_difficulty = "Advanced"
                            security_impact = f"Signal-based debugging detection: {pattern}"
                        elif category == 'file_system_monitoring':
                            confidence = 0.85
                            strength = AntiDebuggingStrength.MODERATE
                            bypass_difficulty = "Moderate"
                            security_impact = f"File system monitoring: {pattern}"
                        elif category == 'memory_monitoring_syscalls':
                            confidence = 0.87
                            strength = AntiDebuggingStrength.ADVANCED
                            bypass_difficulty = "Advanced"
                            security_impact = f"Memory monitoring syscall: {pattern}"
                        else:  # timing_monitoring_syscalls
                            confidence = 0.83
                            strength = AntiDebuggingStrength.MODERATE
                            bypass_difficulty = "Moderate"
                            security_impact = f"Timing-based monitoring: {pattern}"
                        
                        mechanism = AntiDebuggingMechanism(
                            mechanism_id=f"SYSCALL_MONITOR_{pattern}_{len(mechanisms)}",
                            category=AntiDebuggingCategory.NATIVE_CALLS,
                            technique=AntiDebuggingTechnique.SYSTEM_CALL_MONITORING,
                            detection_method=DetectionMethod.SYSCALL_ANALYSIS,
                            strength=strength,
                            function_name=pattern,
                            location=str(binary_path),
                            pattern_matched=pattern,
                            confidence=confidence,
                            bypass_difficulty=bypass_difficulty,
                            security_impact=security_impact,
                            implementation_details={
                                'syscall_category': category,
                                'analysis_type': 'system_call_monitoring',
                                'detection_scope': 'system_level',
                                'monitoring_target': 'debugging_activity'
                            }
                        )
                        
                        mechanisms.append(mechanism)
            
            self.logger.info(f"System call monitoring analysis found {len(mechanisms)} patterns")
            return mechanisms
            
        except Exception as e:
            self.logger.error(f"System call monitoring detection failed: {e}")
            return []
    
    # Phase 2.5.2 Enhancement: Runtime debugging prevention analysis
    def _analyze_runtime_debugging_prevention(self, binary_str: str, binary_path: Path) -> List[AntiDebuggingMechanism]:
        """
        Analyze runtime debugging prevention techniques.
        
        This method identifies techniques used to prevent or disrupt debugging
        attempts during runtime execution.
        """
        mechanisms = []
        
        try:
            self.logger.info("Analyzing runtime debugging prevention techniques")
            
            # Runtime debugging prevention patterns
            prevention_patterns = {
                'thread_manipulation': [
                    'CreateThread', 'ExitThread', 'TerminateThread', 'SuspendThread',
                    'ResumeThread', 'SetThreadPriority', 'SetThreadContext'
                ],
                'exception_manipulation': [
                    'SetUnhandledExceptionFilter', 'AddVectoredExceptionHandler',
                    'RaiseException', 'UnhandledExceptionFilter', '__try', '__except'
                ],
                'api_hooking_prevention': [
                    'VirtualProtect', 'WriteProcessMemory', 'FlushInstructionCache',
                    'SetWindowsHookEx', 'UnhookWindowsHookEx', 'CallNextHookEx'
                ],
                'debug_string_manipulation': [
                    'OutputDebugString', 'OutputDebugStringA', 'OutputDebugStringW',
                    'DebugPrint', 'KdPrint', 'DbgPrint'
                ],
                'breakpoint_manipulation': [
                    'FlushInstructionCache', 'VirtualProtect', 'ReadProcessMemory',
                    'WriteProcessMemory', 'GetThreadContext', 'SetThreadContext'
                ],
                'anti_single_step': [
                    'EFLAGS', 'trap_flag', 'single_step', 'step_over',
                    'CONTEXT_CONTROL', 'CONTEXT_DEBUG_REGISTERS'
                ]
            }
            
            # Analyze each prevention pattern category
            for category, patterns in prevention_patterns.items():
                for pattern in patterns:
                    if pattern in binary_str:
                        # Calculate confidence based on prevention technique
                        if category == 'thread_manipulation':
                            confidence = 0.85
                            strength = AntiDebuggingStrength.MODERATE
                            bypass_difficulty = "Moderate"
                            security_impact = f"Thread manipulation for debug prevention: {pattern}"
                        elif category == 'exception_manipulation':
                            confidence = 0.90
                            strength = AntiDebuggingStrength.ADVANCED
                            bypass_difficulty = "Advanced"
                            security_impact = f"Exception handling manipulation: {pattern}"
                        elif category == 'api_hooking_prevention':
                            confidence = 0.93
                            strength = AntiDebuggingStrength.EXPERT
                            bypass_difficulty = "Expert"
                            security_impact = f"API hooking prevention: {pattern}"
                        elif category == 'debug_string_manipulation':
                            confidence = 0.80
                            strength = AntiDebuggingStrength.BASIC
                            bypass_difficulty = "Easy"
                            security_impact = f"Debug string manipulation: {pattern}"
                        elif category == 'breakpoint_manipulation':
                            confidence = 0.92
                            strength = AntiDebuggingStrength.EXPERT
                            bypass_difficulty = "Expert"
                            security_impact = f"Breakpoint manipulation: {pattern}"
                        else:  # anti_single_step
                            confidence = 0.95
                            strength = AntiDebuggingStrength.EXPERT
                            bypass_difficulty = "Expert"
                            security_impact = f"Anti-single-step protection: {pattern}"
                        
                        mechanism = AntiDebuggingMechanism(
                            mechanism_id=f"RUNTIME_PREVENT_{pattern}_{len(mechanisms)}",
                            category=AntiDebuggingCategory.INSTRUCTION_LEVEL,
                            technique=AntiDebuggingTechnique.RUNTIME_PREVENTION,
                            detection_method=DetectionMethod.RUNTIME_ANALYSIS,
                            strength=strength,
                            function_name=pattern,
                            location=str(binary_path),
                            pattern_matched=pattern,
                            confidence=confidence,
                            bypass_difficulty=bypass_difficulty,
                            security_impact=security_impact,
                            implementation_details={
                                'prevention_category': category,
                                'analysis_type': 'runtime_prevention',
                                'detection_scope': 'runtime',
                                'prevention_target': 'debug_disruption'
                            }
                        )
                        
                        mechanisms.append(mechanism)
            
            self.logger.info(f"Runtime prevention analysis found {len(mechanisms)} techniques")
            return mechanisms
            
        except Exception as e:
            self.logger.error(f"Runtime debugging prevention analysis failed: {e}")
            return []
    
    def _categorize_mechanisms(self, mechanisms: List[AntiDebuggingMechanism]) -> Dict[AntiDebuggingCategory, List[AntiDebuggingMechanism]]:
        """Categorize mechanisms by category."""
        categorized = {}
        
        for mechanism in mechanisms:
            if mechanism.category not in categorized:
                categorized[mechanism.category] = []
            categorized[mechanism.category].append(mechanism)
        
        return categorized
    
    def _categorize_by_strength(self, mechanisms: List[AntiDebuggingMechanism]) -> Dict[AntiDebuggingStrength, List[AntiDebuggingMechanism]]:
        """Categorize mechanisms by strength."""
        categorized = {}
        
        for mechanism in mechanisms:
            if mechanism.strength not in categorized:
                categorized[mechanism.strength] = []
            categorized[mechanism.strength].append(mechanism)
        
        return categorized
    
    def _assess_protection_level(self, mechanisms: List[AntiDebuggingMechanism]) -> ProtectionLevel:
        """Assess overall protection level."""
        if not mechanisms:
            return ProtectionLevel.MINIMAL
        
        # Count mechanisms by strength
        strength_counts = {}
        for mechanism in mechanisms:
            strength_counts[mechanism.strength] = strength_counts.get(mechanism.strength, 0) + 1
        
        # Assess based on strength distribution
        expert_count = strength_counts.get(AntiDebuggingStrength.EXPERT, 0)
        advanced_count = strength_counts.get(AntiDebuggingStrength.ADVANCED, 0)
        moderate_count = strength_counts.get(AntiDebuggingStrength.MODERATE, 0)
        basic_count = strength_counts.get(AntiDebuggingStrength.BASIC, 0)
        
        if expert_count >= 3 or (advanced_count >= 5 and expert_count >= 1):
            return ProtectionLevel.MAXIMUM
        elif advanced_count >= 3 or (moderate_count >= 5 and advanced_count >= 1):
            return ProtectionLevel.HIGH
        elif moderate_count >= 3 or (basic_count >= 5 and moderate_count >= 1):
            return ProtectionLevel.MEDIUM
        elif basic_count >= 2:
            return ProtectionLevel.LOW
        else:
            return ProtectionLevel.MINIMAL
    
    def _analyze_coverage(self, mechanisms: List[AntiDebuggingMechanism]) -> Dict[str, float]:
        """Analyze coverage across different categories."""
        coverage = {}
        
        # Define expected categories
        expected_categories = [
            AntiDebuggingCategory.DEBUG_DETECTION,
            AntiDebuggingCategory.PROCESS_MONITORING,
            AntiDebuggingCategory.TIMING_BASED,
            AntiDebuggingCategory.EXCEPTION_BASED,
            AntiDebuggingCategory.NATIVE_CALLS,
            AntiDebuggingCategory.REGISTER_MANIPULATION,
            AntiDebuggingCategory.INSTRUCTION_LEVEL,
            AntiDebuggingCategory.VM_DETECTION,
            AntiDebuggingCategory.SANDBOX_DETECTION,
            AntiDebuggingCategory.DEBUGGER_TOOLS
        ]
        
        # Calculate coverage for each category
        for category in expected_categories:
            category_mechanisms = [m for m in mechanisms if m.category == category]
            coverage[category.value] = len(category_mechanisms) / max(len(mechanisms), 1)
        
        return coverage
    
    def _calculate_effectiveness_score(self, mechanisms: List[AntiDebuggingMechanism]) -> float:
        """Calculate effectiveness score."""
        if not mechanisms:
            return 0.0
        
        # Weight mechanisms by strength
        strength_weights = {
            AntiDebuggingStrength.BASIC: 1.0,
            AntiDebuggingStrength.MODERATE: 2.0,
            AntiDebuggingStrength.ADVANCED: 3.0,
            AntiDebuggingStrength.EXPERT: 4.0
        }
        
        total_weight = sum(strength_weights.get(m.strength, 1.0) * m.confidence for m in mechanisms)
        max_possible_weight = len(mechanisms) * 4.0  # Max strength * max confidence
        
        return min(total_weight / max_possible_weight, 1.0)
    
    def _calculate_bypass_resistance_score(self, mechanisms: List[AntiDebuggingMechanism]) -> float:
        """Calculate bypass resistance score."""
        if not mechanisms:
            return 0.0
        
        # Weight by bypass difficulty
        difficulty_weights = {
            "Easy": 1.0,
            "Moderate": 2.0,
            "Advanced": 3.0,
            "Expert": 4.0
        }
        
        total_weight = sum(difficulty_weights.get(m.bypass_difficulty, 1.0) for m in mechanisms)
        max_possible_weight = len(mechanisms) * 4.0
        
        return min(total_weight / max_possible_weight, 1.0)
    
    def _calculate_implementation_quality_score(self, mechanisms: List[AntiDebuggingMechanism]) -> float:
        """Calculate implementation quality score."""
        if not mechanisms:
            return 0.0
        
        # Consider diversity and coverage
        categories_covered = len(set(m.category for m in mechanisms))
        max_categories = len(AntiDebuggingCategory)
        
        # Consider confidence levels
        avg_confidence = sum(m.confidence for m in mechanisms) / len(mechanisms)
        
        # Combine factors
        diversity_score = categories_covered / max_categories
        quality_score = (diversity_score + avg_confidence) / 2
        
        return min(quality_score, 1.0)
    
    def _generate_security_recommendations(self, analysis: AntiDebuggingAnalysis) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        # Based on protection level
        if analysis.overall_protection_level == ProtectionLevel.MINIMAL:
            recommendations.append("Implement comprehensive anti-debugging mechanisms across multiple categories")
            recommendations.append("Add native ptrace-based anti-debugging for Linux platforms")
            recommendations.append("Implement timing-based debugger detection")
            
        elif analysis.overall_protection_level == ProtectionLevel.LOW:
            recommendations.append("Strengthen existing anti-debugging mechanisms")
            recommendations.append("Add advanced detection techniques like register manipulation")
            recommendations.append("Implement instruction-level anti-debugging")
            
        elif analysis.overall_protection_level == ProtectionLevel.MEDIUM:
            recommendations.append("Add expert-level anti-debugging techniques")
            recommendations.append("Implement multiple concurrent detection layers")
            recommendations.append("Add VM and sandbox detection capabilities")
            
        # Based on coverage gaps
        if analysis.coverage_analysis.get('native_calls', 0) < 0.2:
            recommendations.append("Add native system call based anti-debugging")
            
        if analysis.coverage_analysis.get('timing_based', 0) < 0.1:
            recommendations.append("Implement timing-based debugger detection")
            
        if analysis.coverage_analysis.get('vm_detection', 0) < 0.1:
            recommendations.append("Add virtual machine and sandbox detection")
            
        # Based on effectiveness
        if analysis.effectiveness_score < 0.3:
            recommendations.append("Significantly improve anti-debugging implementation quality")
            
        if analysis.bypass_resistance_score < 0.5:
            recommendations.append("Strengthen bypass resistance with advanced techniques")
            
        return recommendations
    
    def _generate_vulnerabilities(self, analysis: AntiDebuggingAnalysis, 
                                binary_path: Path) -> List[NativeBinaryVulnerability]:
        """Generate vulnerabilities based on analysis."""
        vulnerabilities = []
        
        # Missing anti-debugging protection
        if analysis.overall_protection_level == ProtectionLevel.MINIMAL:
            vulnerability = NativeBinaryVulnerability(
                vulnerability_id="NATIVE_MISSING_ANTI_DEBUG",
                title="Missing Anti-Debugging Protection",
                severity=VulnerabilitySeverity.HIGH,
                confidence=0.95,
                description="Native binary lacks comprehensive anti-debugging mechanisms, "
                           "making it vulnerable to runtime analysis and manipulation.",
                location=str(binary_path),
                evidence=f"No or minimal anti-debugging mechanisms detected. "
                         f"Protection level: {analysis.overall_protection_level.value}",
                attack_vectors=[
                    "Debugger attachment and code analysis",
                    "Runtime manipulation and hooking",
                    "Dynamic analysis and reverse engineering",
                    "Memory inspection and modification"
                ],
                remediation="Implement comprehensive anti-debugging mechanisms including "
                           "native calls, timing checks, and process monitoring",
                cwe_id="CWE-489",
                masvs_refs=["MSTG-RESILIENCE-2"],
                risk_score=85,
                pattern_type="anti_debugging_mechanisms"
            )
            vulnerabilities.append(vulnerability)
            
        # Weak anti-debugging implementation
        elif analysis.overall_protection_level in [ProtectionLevel.LOW, ProtectionLevel.MEDIUM]:
            vulnerability = NativeBinaryVulnerability(
                vulnerability_id="NATIVE_WEAK_ANTI_DEBUG",
                title="Weak Anti-Debugging Implementation",
                severity=VulnerabilitySeverity.MEDIUM,
                confidence=0.85,
                description="Native binary has limited anti-debugging mechanisms that "
                           "may be insufficient against sophisticated analysis tools.",
                location=str(binary_path),
                evidence=f"Limited anti-debugging protection detected. "
                         f"Protection level: {analysis.overall_protection_level.value}, "
                         f"Effectiveness: {analysis.effectiveness_score:.2f}",
                attack_vectors=[
                    "Advanced debugger bypass techniques",
                    "Multi-vector analysis approaches",
                    "Sophisticated tooling and automation"
                ],
                remediation="Strengthen anti-debugging implementation with additional "
                           "detection layers and advanced techniques",
                cwe_id="CWE-489",
                masvs_refs=["MSTG-RESILIENCE-2"],
                risk_score=65,
                pattern_type="anti_debugging_mechanisms"
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities

def create_anti_debugging_analyzer(context: AnalysisContext) -> AntiDebuggingAnalyzer:
    """
    Factory function to create anti-debugging analyzer.
    
    Args:
        context: Analysis context with dependency injection
        
    Returns:
        Configured anti-debugging analyzer instance
    """
    return AntiDebuggingAnalyzer(context) 