"""
Memory Security Analyzer Module

Specialized analyzer for comprehensive memory security analysis.
Advanced implementation with memory protection assessment and vulnerability detection.

Features:
- Stack protection mechanism analysis
- Heap security validation
- Memory leak pattern detection
- Buffer overflow vulnerability scanning
- Use-after-free detection
- Double-free pattern analysis
- Memory corruption vulnerability assessment
- Security scoring and reporting
"""

import logging
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from core.shared_infrastructure.dependency_injection import AnalysisContext
from core.shared_infrastructure.analysis_exceptions import BinaryAnalysisError
from .data_structures import (
    MemorySecurityAnalysis, 
    NativeBinaryVulnerability, 
    VulnerabilitySeverity,
    MemoryProtectionLevel
)
from .confidence_calculator import BinaryConfidenceCalculator

class MemoryAnalyzer:
    """Advanced memory security analyzer with comprehensive vulnerability detection."""
    
    def __init__(self, context: AnalysisContext, confidence_calculator: BinaryConfidenceCalculator, logger: logging.Logger):
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = logger
        
        # Memory vulnerability patterns
        self.memory_vulnerability_patterns = {
            'buffer_overflow': [
                r'strcpy\s*\([^)]*\)(?![^;]*length.*check)',
                r'strcat\s*\([^)]*\)(?![^;]*size.*check)', 
                r'sprintf\s*\([^)]*\)(?![^;]*snprintf)',
                r'gets\s*\([^)]*\)',  # Always vulnerable
                r'scanf\s*\([^)]*\)(?![^;]*.*%\d+)',  # Without width specifier
                r'memcpy\s*\([^)]*\)(?![^;]*size.*check)',
                r'memmove\s*\([^)]*\)(?![^;]*bounds.*check)',
                r'alloca\s*\([^)]*\)(?![^;]*size.*limit)'
            ],
            'stack_overflow': [
                r'char\s+\w+\[\d{3,}\]',  # Large stack arrays
                r'alloca\s*\([^)]*\)(?![^;]*size.*validation)',
                r'VLA.*\[\s*\w+\s*\](?![^;]*bounds.*check)',  # Variable length arrays
                r'__builtin_alloca\s*\([^)]*\)(?![^;]*limit)'
            ],
            'heap_corruption': [
                r'malloc\s*\([^)]*\*[^)]*\)(?![^;]*overflow.*check)',  # Integer overflow in malloc
                r'realloc\s*\([^,]*,\s*[^)]*\*[^)]*\)',  # Potential integer overflow
                r'calloc\s*\([^,]*,\s*[^)]*\)(?![^;]*overflow.*check)',
                r'free\s*\([^)]+\).*free\s*\([^)]+\)',  # Double free pattern
                r'new\s+\w+\[.*\*.*\](?![^;]*check)'  # C++ new with multiplication
            ],
            'use_after_free': [
                r'free\s*\([^)]+\);(?![^;]*\w+\s*=\s*NULL).*\*\s*\w+',
                r'delete\s+\w+;(?![^;]*\w+\s*=\s*null).*\w+\s*->',
                r'delete\[\]\s*\w+;(?![^;]*\w+\s*=\s*null).*\w+\[',
                r'munmap\s*\([^)]*\)(?![^;]*.*=.*NULL).*\*'
            ],
            'memory_leaks': [
                r'malloc\s*\([^)]*\)(?![^;]*free)',
                r'calloc\s*\([^)]*\)(?![^;]*free)',
                r'realloc\s*\([^)]*\)(?![^;]*free)',
                r'new\s+\w+(?![^;]*delete)',
                r'new\s+\w+\[.*\](?![^;]*delete\[\])',
                r'strdup\s*\([^)]*\)(?![^;]*free)',
                r'mmap\s*\([^)]*\)(?![^;]*munmap)'
            ],
            'format_string': [
                r'printf\s*\([^,)]*\)(?![^;]*format.*check)',
                r'sprintf\s*\([^,]+,\s*[^,)]*\)(?![^;]*format.*validation)',
                r'fprintf\s*\([^,]+,\s*[^,)]*\)(?![^;]*format.*check)',
                r'snprintf\s*\([^,]+,\s*[^,]+,\s*[^,)]*\)(?![^;]*validation)'
            ],
            'integer_overflow': [
                r'malloc\s*\([^)]*\+[^)]*\)(?![^;]*overflow.*check)',
                r'calloc\s*\([^,]*,\s*[^)]*\+[^)]*\)',
                r'size\s*\*\s*count(?![^;]*overflow.*check)',
                r'\w+\s*\+\s*\w+(?![^;]*.*<.*\w+).*malloc'  # Addition without overflow check
            ]
        }
        
        # Stack protection mechanisms
        self.stack_protection_patterns = {
            'stack_canaries': [
                r'__stack_chk_fail',
                r'__stack_chk_guard', 
                r'__GI___stack_chk_fail',
                r'stack_chk_fail'
            ],
            'nx_bit': [
                r'GNU_STACK.*NX',
                r'PROT_EXEC.*PROT_READ.*PROT_WRITE',
                r'mprotect.*PROT_EXEC'
            ],
            'aslr': [
                r'PIE',
                r'DYNAMIC.*INTERP',
                r'randomize_va_space'
            ]
        }
        
        # Heap protection mechanisms
        self.heap_protection_patterns = {
            'heap_hardening': [
                r'tcmalloc',
                r'jemalloc', 
                r'dlmalloc',
                r'__libc_malloc',
                r'malloc_check'
            ],
            'heap_guard': [
                r'AddressSanitizer',
                r'HWAddressSanitizer',
                r'MemorySanitizer',
                r'__asan_',
                r'__hwasan_',
                r'__msan_'
            ]
        }
    
    def analyze(self, lib_path: Path) -> MemorySecurityAnalysis:
        """
        Analyze memory security vulnerabilities and protections.
        
        Args:
            lib_path: Path to the native library to analyze
            
        Returns:
            MemorySecurityAnalysis: Comprehensive memory security analysis results
        """
        analysis = MemorySecurityAnalysis(library_name=lib_path.name)
        
        try:
            # Extract library content for analysis
            content = self._extract_library_content(lib_path)
            if not content:
                self.logger.warning(f"Could not extract content from {lib_path.name}")
                return analysis
            
            # Analyze memory protection mechanisms
            self._analyze_stack_protection(content, analysis)
            self._analyze_heap_protection(content, analysis)
            self._analyze_memory_hardening(lib_path, analysis)
            
            # Detect memory vulnerabilities
            self._detect_buffer_overflow_vulnerabilities(content, analysis)
            self._detect_stack_overflow_vulnerabilities(content, analysis)
            self._detect_heap_corruption_vulnerabilities(content, analysis)
            self._detect_use_after_free_vulnerabilities(content, analysis)
            self._detect_memory_leak_patterns(content, analysis)
            self._detect_format_string_vulnerabilities(content, analysis)
            self._detect_integer_overflow_vulnerabilities(content, analysis)
            
            # Advanced memory analysis
            self._analyze_memory_layout_security(lib_path, analysis)
            self._analyze_dynamic_memory_allocation(content, analysis)
            self._validate_memory_sanitizer_usage(content, analysis)
            
            # Enhanced memory analysis features (Phase 2.1.2 roadmap requirements)
            self._analyze_stack_canary_bypass_detection(content, analysis)
            self._analyze_heap_protection_validation(content, lib_path, analysis)
            self._analyze_advanced_memory_leak_patterns(content, analysis)
            self._analyze_buffer_overflow_vulnerability_scanning(content, analysis)
            self._analyze_memory_corruption_patterns(content, analysis)
            self._analyze_control_flow_integrity(content, lib_path, analysis)
            
            # Calculate memory security score
            analysis.security_score = self._calculate_memory_security_score(analysis)
            
            # Determine protection level
            analysis.protection_level = self._determine_memory_protection_level(analysis)
            
            # Generate vulnerabilities based on findings
            self._generate_memory_vulnerabilities(analysis)
            
        except Exception as e:
            self.logger.error(f"Memory security analysis failed for {lib_path.name}: {e}")
            # Create error vulnerability
            error_vuln = NativeBinaryVulnerability(
                id=f"memory_analysis_error_{lib_path.name}",
                title="Memory Analysis Error",
                description=f"Memory security analysis failed: {str(e)}",
                severity=VulnerabilitySeverity.LOW,
                masvs_control="MSTG-CODE-8",
                affected_files=[lib_path.name],
                evidence=[str(e)],
                remediation="Ensure library is accessible and not corrupted",
                cwe_id="CWE-693"
            )
            analysis.vulnerabilities.append(error_vuln)
        
        return analysis
    
    def _extract_library_content(self, lib_path: Path) -> str:
        """Extract strings and symbols from native library."""
        content = ""
        
        try:
            # Extract strings
            strings_result = subprocess.run(
                ["strings", str(lib_path)], 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            if strings_result.returncode == 0:
                content += strings_result.stdout
            
            # Extract symbols
            nm_result = subprocess.run(
                ["nm", "-D", str(lib_path)], 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            if nm_result.returncode == 0:
                content += nm_result.stdout
            
            # Extract disassembly for deeper analysis
            objdump_result = subprocess.run(
                ["objdump", "-d", str(lib_path)], 
                capture_output=True, 
                text=True, 
                timeout=45
            )
            if objdump_result.returncode == 0:
                content += objdump_result.stdout
                
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Timeout extracting content from {lib_path.name}")
        except Exception as e:
            self.logger.debug(f"Content extraction failed for {lib_path.name}: {e}")
        
        return content
    
    def _analyze_stack_protection(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Analyze stack protection mechanisms."""
        try:
            # Check for stack canaries
            canary_found = False
            for pattern in self.stack_protection_patterns['stack_canaries']:
                if pattern in content:
                    analysis.stack_protection_mechanisms.append(f"Stack canary: {pattern}")
                    canary_found = True
            
            if not canary_found:
                analysis.missing_protections.append("Stack canaries not detected")
            
            # Check for NX bit
            nx_found = False
            for pattern in self.stack_protection_patterns['nx_bit']:
                if re.search(pattern, content, re.IGNORECASE):
                    analysis.stack_protection_mechanisms.append(f"NX bit: {pattern}")
                    nx_found = True
            
            if not nx_found:
                analysis.missing_protections.append("NX bit protection not detected")
            
            # Check for ASLR
            aslr_found = False
            for pattern in self.stack_protection_patterns['aslr']:
                if pattern in content:
                    analysis.stack_protection_mechanisms.append(f"ASLR: {pattern}")
                    aslr_found = True
            
            if not aslr_found:
                analysis.missing_protections.append("ASLR not detected")
                
        except Exception as e:
            self.logger.debug(f"Stack protection analysis failed: {e}")
    
    def _analyze_heap_protection(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Analyze heap protection mechanisms."""
        try:
            # Check for heap hardening
            for pattern in self.heap_protection_patterns['heap_hardening']:
                if pattern in content:
                    analysis.heap_protection_mechanisms.append(f"Heap hardening: {pattern}")
            
            # Check for heap guards/sanitizers
            for pattern in self.heap_protection_patterns['heap_guard']:
                if pattern in content:
                    analysis.heap_protection_mechanisms.append(f"Heap guard: {pattern}")
            
            # If no heap protection found
            if not analysis.heap_protection_mechanisms:
                analysis.missing_protections.append("Heap protection mechanisms not detected")
                
        except Exception as e:
            self.logger.debug(f"Heap protection analysis failed: {e}")
    
    def _analyze_memory_hardening(self, lib_path: Path, analysis: MemorySecurityAnalysis) -> None:
        """Analyze memory hardening features using readelf."""
        try:
            # Check for RELRO
            readelf_result = subprocess.run(
                ["readelf", "-l", str(lib_path)], 
                capture_output=True, 
                text=True, 
                timeout=15
            )
            
            if readelf_result.returncode == 0:
                readelf_output = readelf_result.stdout
                
                if "GNU_RELRO" in readelf_output:
                    analysis.memory_hardening_features.append("RELRO (Read-Only Relocations)")
                else:
                    analysis.missing_protections.append("RELRO not detected")
                
                if "GNU_STACK" in readelf_output:
                    if "RWE" in readelf_output:
                        analysis.memory_vulnerabilities.append("Executable stack detected")
                    else:
                        analysis.memory_hardening_features.append("Non-executable stack")
                
                # Check for PIE
                if "DYN" in readelf_output and "INTERP" in readelf_output:
                    analysis.memory_hardening_features.append("PIE (Position Independent Executable)")
                elif "EXEC" in readelf_output:
                    analysis.missing_protections.append("PIE not enabled")
            
        except Exception as e:
            self.logger.debug(f"Memory hardening analysis failed for {lib_path.name}: {e}")
    
    def _detect_buffer_overflow_vulnerabilities(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Detect buffer overflow vulnerabilities."""
        for pattern in self.memory_vulnerability_patterns['buffer_overflow']:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                analysis.buffer_overflow_vulnerabilities.append(f"Buffer overflow risk: {match.strip()}")
    
    def _detect_stack_overflow_vulnerabilities(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Detect stack overflow vulnerabilities."""
        for pattern in self.memory_vulnerability_patterns['stack_overflow']:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                analysis.stack_overflow_vulnerabilities.append(f"Stack overflow risk: {match.strip()}")
    
    def _detect_heap_corruption_vulnerabilities(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Detect heap corruption vulnerabilities."""
        for pattern in self.memory_vulnerability_patterns['heap_corruption']:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                analysis.heap_corruption_vulnerabilities.append(f"Heap corruption risk: {match.strip()}")
    
    def _detect_use_after_free_vulnerabilities(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Detect use-after-free vulnerabilities."""
        for pattern in self.memory_vulnerability_patterns['use_after_free']:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                analysis.use_after_free_vulnerabilities.append(f"Use-after-free risk: {match.strip()}")
    
    def _detect_memory_leak_patterns(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Detect memory leak patterns."""
        for pattern in self.memory_vulnerability_patterns['memory_leaks']:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                analysis.memory_leak_patterns.append(f"Memory leak risk: {match.strip()}")
    
    def _detect_format_string_vulnerabilities(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Detect format string vulnerabilities."""
        for pattern in self.memory_vulnerability_patterns['format_string']:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                analysis.format_string_vulnerabilities.append(f"Format string risk: {match.strip()}")
    
    def _detect_integer_overflow_vulnerabilities(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Detect integer overflow vulnerabilities."""
        for pattern in self.memory_vulnerability_patterns['integer_overflow']:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                analysis.integer_overflow_vulnerabilities.append(f"Integer overflow risk: {match.strip()}")
    
    def _analyze_memory_layout_security(self, lib_path: Path, analysis: MemorySecurityAnalysis) -> None:
        """Analyze memory layout security features."""
        try:
            # Check section permissions
            readelf_result = subprocess.run(
                ["readelf", "-S", str(lib_path)], 
                capture_output=True, 
                text=True, 
                timeout=15
            )
            
            if readelf_result.returncode == 0:
                sections = readelf_result.stdout
                
                # Check for executable sections
                if re.search(r'\.text.*AX', sections):
                    analysis.memory_layout_features.append("Executable .text section (normal)")
                
                # Check for writable and executable sections (dangerous)
                if re.search(r'\..*WAX', sections):
                    analysis.memory_vulnerabilities.append("Writable and executable section detected")
                
                # Check for stack section
                if re.search(r'\.stack.*', sections):
                    analysis.memory_layout_features.append("Stack section present")
                
        except Exception as e:
            self.logger.debug(f"Memory layout analysis failed for {lib_path.name}: {e}")
    
    def _analyze_dynamic_memory_allocation(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Analyze dynamic memory allocation patterns."""
        try:
            # Count memory allocation functions
            malloc_count = len(re.findall(r'\bmalloc\s*\(', content, re.IGNORECASE))
            free_count = len(re.findall(r'\bfree\s*\(', content, re.IGNORECASE))
            
            if malloc_count > 0:
                analysis.dynamic_allocation_patterns.append(f"malloc calls: {malloc_count}")
                analysis.dynamic_allocation_patterns.append(f"free calls: {free_count}")
                
                # Check for potential memory leaks
                if malloc_count > free_count:
                    leak_potential = malloc_count - free_count
                    analysis.memory_vulnerabilities.append(f"Potential memory leaks: {leak_potential} unmatched malloc calls")
            
            # Check for C++ new/delete
            new_count = len(re.findall(r'\bnew\s+', content, re.IGNORECASE))
            delete_count = len(re.findall(r'\bdelete\s+', content, re.IGNORECASE))
            
            if new_count > 0:
                analysis.dynamic_allocation_patterns.append(f"new calls: {new_count}")
                analysis.dynamic_allocation_patterns.append(f"delete calls: {delete_count}")
                
                if new_count > delete_count:
                    leak_potential = new_count - delete_count
                    analysis.memory_vulnerabilities.append(f"Potential C++ memory leaks: {leak_potential} unmatched new calls")
            
        except Exception as e:
            self.logger.debug(f"Dynamic memory allocation analysis failed: {e}")
    
    def _validate_memory_sanitizer_usage(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Validate memory sanitizer usage."""
        try:
            # Check for AddressSanitizer
            if "__asan_" in content or "AddressSanitizer" in content:
                analysis.memory_sanitizers.append("AddressSanitizer detected")
            
            # Check for MemorySanitizer
            if "__msan_" in content or "MemorySanitizer" in content:
                analysis.memory_sanitizers.append("MemorySanitizer detected")
            
            # Check for HWAddressSanitizer
            if "__hwasan_" in content or "HWAddressSanitizer" in content:
                analysis.memory_sanitizers.append("HWAddressSanitizer detected")
            
            # Check for Valgrind usage
            if "valgrind" in content.lower():
                analysis.memory_sanitizers.append("Valgrind usage detected")
            
            if not analysis.memory_sanitizers:
                analysis.missing_protections.append("Memory sanitizers not detected")
                
        except Exception as e:
            self.logger.debug(f"Memory sanitizer validation failed: {e}")
    
    def _calculate_memory_security_score(self, analysis: MemorySecurityAnalysis) -> float:
        """Calculate memory security score (0-100 scale)."""
        score = 100.0  # Start with perfect score
        
        # Deduct points for vulnerabilities
        score -= len(analysis.buffer_overflow_vulnerabilities) * 25
        score -= len(analysis.stack_overflow_vulnerabilities) * 20
        score -= len(analysis.heap_corruption_vulnerabilities) * 25
        score -= len(analysis.use_after_free_vulnerabilities) * 30
        score -= len(analysis.memory_leak_patterns) * 10
        score -= len(analysis.format_string_vulnerabilities) * 25
        score -= len(analysis.integer_overflow_vulnerabilities) * 20
        score -= len(analysis.memory_vulnerabilities) * 15
        
        # Deduct points for missing protections
        score -= len(analysis.missing_protections) * 15
        
        # Add points for protection mechanisms
        score += len(analysis.stack_protection_mechanisms) * 5
        score += len(analysis.heap_protection_mechanisms) * 5
        score += len(analysis.memory_hardening_features) * 5
        score += len(analysis.memory_sanitizers) * 10
        
        # Ensure score doesn't go below 0
        return max(score, 0.0)
    
    def _determine_memory_protection_level(self, analysis: MemorySecurityAnalysis) -> MemoryProtectionLevel:
        """Determine memory protection level based on findings."""
        protection_score = (
            len(analysis.stack_protection_mechanisms) +
            len(analysis.heap_protection_mechanisms) +
            len(analysis.memory_hardening_features) +
            len(analysis.memory_sanitizers) * 2  # Sanitizers are more valuable
        )
        
        vulnerability_score = (
            len(analysis.buffer_overflow_vulnerabilities) +
            len(analysis.stack_overflow_vulnerabilities) +
            len(analysis.heap_corruption_vulnerabilities) +
            len(analysis.use_after_free_vulnerabilities) +
            len(analysis.memory_vulnerabilities)
        )
        
        if protection_score >= 10 and vulnerability_score == 0:
            return MemoryProtectionLevel.MAXIMUM
        elif protection_score >= 7 and vulnerability_score <= 2:
            return MemoryProtectionLevel.HIGH
        elif protection_score >= 4 and vulnerability_score <= 5:
            return MemoryProtectionLevel.MEDIUM
        elif protection_score >= 2 and vulnerability_score <= 10:
            return MemoryProtectionLevel.LOW
        else:
            return MemoryProtectionLevel.MINIMAL
    
    def _generate_memory_vulnerabilities(self, analysis: MemorySecurityAnalysis) -> None:
        """Generate vulnerability objects for memory security issues."""
        
        # Buffer overflow vulnerabilities
        if analysis.buffer_overflow_vulnerabilities:
            vuln = NativeBinaryVulnerability(
                id=f"buffer_overflow_{analysis.library_name}",
                title="Buffer Overflow Vulnerabilities",
                description=f"Native library contains {len(analysis.buffer_overflow_vulnerabilities)} potential buffer overflow vulnerabilities",
                severity=VulnerabilitySeverity.CRITICAL,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.buffer_overflow_vulnerabilities[:5],
                remediation="Use safe string functions (strncpy, strncat, snprintf) and validate buffer sizes",
                cwe_id="CWE-120"
            )
            analysis.vulnerabilities.append(vuln)
        
        # Stack overflow vulnerabilities
        if analysis.stack_overflow_vulnerabilities:
            vuln = NativeBinaryVulnerability(
                id=f"stack_overflow_{analysis.library_name}",
                title="Stack Overflow Vulnerabilities",
                description=f"Native library contains {len(analysis.stack_overflow_vulnerabilities)} potential stack overflow vulnerabilities",
                severity=VulnerabilitySeverity.HIGH,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.stack_overflow_vulnerabilities[:5],
                remediation="Limit stack allocation sizes and validate input sizes for variable length arrays",
                cwe_id="CWE-121"
            )
            analysis.vulnerabilities.append(vuln)
        
        # Heap corruption vulnerabilities
        if analysis.heap_corruption_vulnerabilities:
            vuln = NativeBinaryVulnerability(
                id=f"heap_corruption_{analysis.library_name}",
                title="Heap Corruption Vulnerabilities",
                description=f"Native library contains {len(analysis.heap_corruption_vulnerabilities)} potential heap corruption vulnerabilities",
                severity=VulnerabilitySeverity.CRITICAL,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.heap_corruption_vulnerabilities[:5],
                remediation="Implement proper memory management, avoid double-free, and check for integer overflows in memory allocation",
                cwe_id="CWE-122"
            )
            analysis.vulnerabilities.append(vuln)
        
        # Use-after-free vulnerabilities
        if analysis.use_after_free_vulnerabilities:
            vuln = NativeBinaryVulnerability(
                id=f"use_after_free_{analysis.library_name}",
                title="Use-After-Free Vulnerabilities",
                description=f"Native library contains {len(analysis.use_after_free_vulnerabilities)} potential use-after-free vulnerabilities",
                severity=VulnerabilitySeverity.CRITICAL,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.use_after_free_vulnerabilities[:3],
                remediation="Set pointers to NULL after freeing and implement proper object lifecycle management",
                cwe_id="CWE-416"
            )
            analysis.vulnerabilities.append(vuln)
        
        # Memory leak patterns
        if analysis.memory_leak_patterns:
            vuln = NativeBinaryVulnerability(
                id=f"memory_leaks_{analysis.library_name}",
                title="Memory Leak Patterns",
                description=f"Native library contains {len(analysis.memory_leak_patterns)} potential memory leak patterns",
                severity=VulnerabilitySeverity.MEDIUM,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.memory_leak_patterns[:5],
                remediation="Ensure all allocated memory is freed and implement proper resource management",
                cwe_id="CWE-401"
            )
            analysis.vulnerabilities.append(vuln)
        
        # Format string vulnerabilities
        if analysis.format_string_vulnerabilities:
            vuln = NativeBinaryVulnerability(
                id=f"format_string_{analysis.library_name}",
                title="Format String Vulnerabilities",
                description=f"Native library contains {len(analysis.format_string_vulnerabilities)} potential format string vulnerabilities",
                severity=VulnerabilitySeverity.HIGH,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.format_string_vulnerabilities[:5],
                remediation="Use format strings with proper specifiers and validate format string inputs",
                cwe_id="CWE-134"
            )
            analysis.vulnerabilities.append(vuln)
        
        # Integer overflow vulnerabilities
        if analysis.integer_overflow_vulnerabilities:
            vuln = NativeBinaryVulnerability(
                id=f"integer_overflow_{analysis.library_name}",
                title="Integer Overflow Vulnerabilities",
                description=f"Native library contains {len(analysis.integer_overflow_vulnerabilities)} potential integer overflow vulnerabilities",
                severity=VulnerabilitySeverity.HIGH,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.integer_overflow_vulnerabilities[:5],
                remediation="Implement overflow checks before arithmetic operations and use safe integer libraries",
                cwe_id="CWE-190"
            )
            analysis.vulnerabilities.append(vuln)
        
        # Missing protection mechanisms
        if analysis.missing_protections:
            vuln = NativeBinaryVulnerability(
                id=f"missing_protections_{analysis.library_name}",
                title="Missing Memory Protection Mechanisms",
                description=f"Native library is missing {len(analysis.missing_protections)} memory protection mechanisms",
                severity=VulnerabilitySeverity.MEDIUM,
                masvs_control="MSTG-CODE-9",
                affected_files=[analysis.library_name],
                evidence=analysis.missing_protections,
                remediation="Enable memory protection mechanisms: stack canaries, NX bit, ASLR, RELRO, PIE",
                cwe_id="CWE-693"
            )
            analysis.vulnerabilities.append(vuln)
        
        # General memory vulnerabilities
        if analysis.memory_vulnerabilities:
            vuln = NativeBinaryVulnerability(
                id=f"memory_vulnerabilities_{analysis.library_name}",
                title="Memory Security Vulnerabilities",
                description=f"Native library has {len(analysis.memory_vulnerabilities)} memory security vulnerabilities",
                severity=VulnerabilitySeverity.HIGH,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.memory_vulnerabilities[:5],
                remediation="Review and fix identified memory security vulnerabilities",
                cwe_id="CWE-691"
            )
            analysis.vulnerabilities.append(vuln) 

    def _analyze_stack_canary_bypass_detection(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """
        Advanced stack canary bypass detection analysis.
        
        This method detects potential bypasses and weaknesses in stack canary implementation
        that could be exploited by sophisticated attackers.
        """
        try:
            self.logger.debug("Performing advanced stack canary bypass detection")
            
            # Stack canary bypass patterns
            bypass_patterns = {
                'canary_leak_vulnerabilities': [
                    r'__stack_chk_guard.*printf',  # Potential canary leakage via printf
                    r'__stack_chk_guard.*sprintf',  # Potential canary leakage via sprintf
                    r'__stack_chk_guard.*fprintf',  # Potential canary leakage via fprintf
                    r'__stack_chk_guard.*memcpy',  # Potential canary leakage via memcpy
                    r'__stack_chk_guard.*memmove',  # Potential canary leakage via memmove
                    r'stack_chk_guard.*write',  # Potential canary leakage via write
                    r'stack_chk_guard.*send',  # Potential canary leakage via send
                    r'stack_chk_guard.*log',  # Potential canary leakage via logging
                ],
                'canary_brute_force_vulnerabilities': [
                    r'__stack_chk_fail.*exit',  # Weak canary failure handling
                    r'__stack_chk_fail.*abort',  # Weak canary failure handling
                    r'__stack_chk_fail.*_exit',  # Weak canary failure handling
                    r'__stack_chk_fail.*(?!.*random)',  # Canary failure without randomization
                    r'fork.*__stack_chk_fail',  # Fork-based canary brute force potential
                ],
                'canary_overwrite_vulnerabilities': [
                    r'__stack_chk_guard.*=.*[^x]',  # Direct canary overwrite
                    r'memset.*__stack_chk_guard',  # Canary overwrite via memset
                    r'memcpy.*__stack_chk_guard',  # Canary overwrite via memcpy
                    r'memmove.*__stack_chk_guard',  # Canary overwrite via memmove
                    r'strcpy.*__stack_chk_guard',  # Canary overwrite via strcpy
                    r'strncpy.*__stack_chk_guard',  # Canary overwrite via strncpy
                ],
                'canary_implementation_weaknesses': [
                    r'__stack_chk_guard.*static',  # Static canary (weak)
                    r'__stack_chk_guard.*const',  # Constant canary (weak)
                    r'__stack_chk_guard.*0x[0-9a-fA-F]{1,4}',  # Weak canary entropy
                    r'__stack_chk_guard.*NULL',  # Null canary (disabled)
                    r'__stack_chk_guard.*0',  # Zero canary (disabled)
                ],
                'canary_bypass_techniques': [
                    r'ret2libc.*__stack_chk_fail',  # ret2libc bypass
                    r'ROP.*__stack_chk_fail',  # ROP bypass
                    r'JOP.*__stack_chk_fail',  # JOP bypass
                    r'sigreturn.*__stack_chk_fail',  # sigreturn bypass
                    r'longjmp.*__stack_chk_fail',  # longjmp bypass
                    r'exception.*__stack_chk_fail',  # exception bypass
                ],
                'stack_pivot_vulnerabilities': [
                    r'mov.*esp.*eax',  # Stack pivot (x86)
                    r'mov.*rsp.*rax',  # Stack pivot (x64)
                    r'mov.*sp.*r\d+',  # Stack pivot (ARM)
                    r'add.*esp.*0x[0-9a-fA-F]+',  # Stack adjustment
                    r'sub.*esp.*0x[0-9a-fA-F]+',  # Stack adjustment
                    r'xchg.*esp.*eax',  # Stack exchange
                ],
                'canary_timing_attacks': [
                    r'__stack_chk_fail.*time',  # Timing-based canary detection
                    r'__stack_chk_fail.*clock',  # Clock-based canary detection
                    r'__stack_chk_fail.*gettimeofday',  # Time-based canary detection
                    r'__stack_chk_fail.*rdtsc',  # Cycle-based canary detection
                ]
            }
            
            # Analyze each bypass category
            for bypass_type, patterns in bypass_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        analysis.stack_protection_mechanisms.append(f"canary_bypass_{bypass_type}: {match.strip()}")
            
            # Advanced canary analysis
            self._analyze_canary_entropy(content, analysis)
            self._analyze_canary_placement(content, analysis)
            self._analyze_canary_reuse(content, analysis)
            
        except Exception as e:
            self.logger.debug(f"Stack canary bypass detection failed: {e}")
    
    def _analyze_canary_entropy(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Analyze stack canary entropy and randomness."""
        try:
            # Check for weak canary entropy
            weak_entropy_patterns = [
                r'__stack_chk_guard.*=.*0x[0-9a-fA-F]{1,4}(?![0-9a-fA-F])',  # Low entropy
                r'__stack_chk_guard.*=.*0x[0-9a-fA-F]*[0]{4,}',  # Many zeros
                r'__stack_chk_guard.*=.*0x[fF]{4,}',  # All F's
                r'__stack_chk_guard.*=.*0x[a-fA-F]{8}',  # Pattern-based
                r'__stack_chk_guard.*=.*time',  # Time-based (predictable)
                r'__stack_chk_guard.*=.*pid',  # PID-based (predictable)
            ]
            
            for pattern in weak_entropy_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    analysis.stack_protection_mechanisms.append(f"canary_weak_entropy: {match.strip()}")
            
        except Exception as e:
            self.logger.debug(f"Canary entropy analysis failed: {e}")
    
    def _analyze_canary_placement(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Analyze stack canary placement effectiveness."""
        try:
            # Check for canary placement issues
            placement_issues = [
                r'__stack_chk_guard.*(?=.*return)(?!.*check)',  # Canary without check before return
                r'return.*(?!.*__stack_chk_fail).*__stack_chk_guard',  # Return before canary check
                r'goto.*(?!.*__stack_chk_fail).*__stack_chk_guard',  # Goto bypassing canary
                r'longjmp.*(?!.*__stack_chk_fail).*__stack_chk_guard',  # Longjmp bypassing canary
            ]
            
            for pattern in placement_issues:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    analysis.stack_protection_mechanisms.append(f"canary_placement_issue: {match.strip()}")
            
        except Exception as e:
            self.logger.debug(f"Canary placement analysis failed: {e}")
    
    def _analyze_canary_reuse(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Analyze stack canary reuse vulnerabilities."""
        try:
            # Check for canary reuse issues
            reuse_issues = [
                r'static.*__stack_chk_guard',  # Static canary reuse
                r'global.*__stack_chk_guard',  # Global canary reuse
                r'__stack_chk_guard.*thread',  # Thread canary reuse
                r'__stack_chk_guard.*process',  # Process canary reuse
            ]
            
            for pattern in reuse_issues:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    analysis.stack_protection_mechanisms.append(f"canary_reuse_issue: {match.strip()}")
            
        except Exception as e:
            self.logger.debug(f"Canary reuse analysis failed: {e}")
    
    def _analyze_heap_protection_validation(self, content: str, lib_path: Path, analysis: MemorySecurityAnalysis) -> None:
        """
        Enhanced heap protection mechanism validation.
        
        This method performs comprehensive validation of heap protection mechanisms
        and identifies potential bypasses or weaknesses.
        """
        try:
            self.logger.debug("Performing enhanced heap protection validation")
            
            # Advanced heap protection patterns
            heap_protection_patterns = {
                'heap_hardening_mechanisms': [
                    r'tcmalloc',  # Google's heap allocator
                    r'jemalloc',  # Facebook's heap allocator
                    r'dlmalloc',  # Doug Lea's malloc
                    r'ptmalloc',  # Pthread malloc
                    r'scudo',  # Scudo hardened allocator
                    r'__libc_malloc',  # Standard libc malloc
                    r'malloc_check',  # Malloc debugging
                    r'malloc_hook',  # Malloc hook functionality
                    r'__malloc_hook',  # Malloc hook implementation
                ],
                'heap_guard_mechanisms': [
                    r'AddressSanitizer',  # ASan
                    r'HWAddressSanitizer',  # HWASan
                    r'MemorySanitizer',  # MSan
                    r'__asan_',  # ASan functions
                    r'__hwasan_',  # HWASan functions
                    r'__msan_',  # MSan functions
                    r'GuardMalloc',  # Guard malloc
                    r'PageHeap',  # Page heap
                    r'HeapGuard',  # Heap guard
                ],
                'heap_metadata_protection': [
                    r'heap_guard_page',  # Guard page protection
                    r'heap_metadata_check',  # Metadata validation
                    r'chunk_size_check',  # Chunk size validation
                    r'free_list_check',  # Free list validation
                    r'heap_canary',  # Heap canaries
                    r'heap_cookie',  # Heap cookies
                    r'heap_magic',  # Heap magic numbers
                ],
                'heap_randomization': [
                    r'heap_randomize',  # Heap randomization
                    r'malloc_random',  # Malloc randomization
                    r'heap_aslr',  # Heap ASLR
                    r'heap_entropy',  # Heap entropy
                    r'mmap_randomize',  # mmap randomization
                ],
                'heap_overflow_protection': [
                    r'heap_overflow_check',  # Heap overflow detection
                    r'chunk_overflow_check',  # Chunk overflow detection
                    r'heap_bounds_check',  # Heap bounds checking
                    r'malloc_size_check',  # Malloc size validation
                    r'heap_sentinel',  # Heap sentinel values
                ],
                'heap_use_after_free_protection': [
                    r'heap_quarantine',  # Heap quarantine
                    r'delayed_free',  # Delayed free
                    r'free_poison',  # Free poisoning
                    r'use_after_free_check',  # UAF detection
                    r'heap_poison',  # Heap poisoning
                ]
            }
            
            # Analyze heap protection mechanisms
            for protection_type, patterns in heap_protection_patterns.items():
                protection_found = False
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        analysis.heap_protection_mechanisms.append(f"{protection_type}: {pattern}")
                        protection_found = True
                
                if not protection_found:
                    analysis.missing_protections.append(f"{protection_type} not detected")
            
            # Advanced heap validation
            self._validate_heap_implementation(content, analysis)
            self._analyze_heap_bypass_vulnerabilities(content, analysis)
            self._validate_heap_sanitizer_integration(content, analysis)
            
        except Exception as e:
            self.logger.debug(f"Heap protection validation failed: {e}")
    
    def _validate_heap_implementation(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Validate heap implementation security."""
        try:
            # Check for heap implementation issues
            implementation_issues = [
                r'malloc.*(?!.*size.*check)',  # Malloc without size check
                r'free.*(?!.*null.*check)',  # Free without null check
                r'realloc.*(?!.*size.*validation)',  # Realloc without validation
                r'calloc.*(?!.*overflow.*check)',  # Calloc without overflow check
                r'mmap.*(?!.*size.*validation)',  # mmap without validation
                r'munmap.*(?!.*size.*check)',  # munmap without size check
            ]
            
            for pattern in implementation_issues:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    analysis.heap_protection_mechanisms.append(f"heap_implementation_issue: {match.strip()}")
            
        except Exception as e:
            self.logger.debug(f"Heap implementation validation failed: {e}")
    
    def _analyze_heap_bypass_vulnerabilities(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Analyze heap protection bypass vulnerabilities."""
        try:
            # Heap bypass patterns
            bypass_patterns = [
                r'mprotect.*PROT_EXEC',  # Heap execution bypass
                r'mmap.*PROT_EXEC',  # Executable heap mapping
                r'VirtualProtect.*PAGE_EXECUTE',  # Windows heap execution
                r'heap_spray',  # Heap spray technique
                r'heap_feng_shui',  # Heap feng shui
                r'heap_grooming',  # Heap grooming
                r'heap_massage',  # Heap massage
            ]
            
            for pattern in bypass_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    analysis.heap_protection_mechanisms.append(f"heap_bypass_vulnerability: {match.strip()}")
            
        except Exception as e:
            self.logger.debug(f"Heap bypass analysis failed: {e}")
    
    def _validate_heap_sanitizer_integration(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Validate heap sanitizer integration."""
        try:
            # Check for sanitizer integration
            sanitizer_patterns = [
                r'__asan_init',  # ASan initialization
                r'__msan_init',  # MSan initialization
                r'__hwasan_init',  # HWASan initialization
                r'__tsan_init',  # TSan initialization
                r'__ubsan_init',  # UBSan initialization
            ]
            
            sanitizer_found = False
            for pattern in sanitizer_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    analysis.memory_sanitizers.append(f"sanitizer_integration: {pattern}")
                    sanitizer_found = True
            
            if not sanitizer_found:
                analysis.missing_protections.append("Memory sanitizer integration not detected")
            
        except Exception as e:
            self.logger.debug(f"Heap sanitizer validation failed: {e}")
    
    def _analyze_advanced_memory_leak_patterns(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """
        Advanced memory leak pattern detection.
        
        This method detects sophisticated memory leak patterns that might be
        missed by basic static analysis.
        """
        try:
            self.logger.debug("Performing advanced memory leak pattern analysis")
            
            # Advanced memory leak patterns
            leak_patterns = {
                'allocation_without_deallocation': [
                    r'malloc\s*\([^)]*\)(?![^}]*free)',  # malloc without free in same scope
                    r'calloc\s*\([^)]*\)(?![^}]*free)',  # calloc without free in same scope
                    r'realloc\s*\([^)]*\)(?![^}]*free)',  # realloc without free in same scope
                    r'new\s+\w+(?![^}]*delete)',  # new without delete in same scope
                    r'new\s+\w+\[.*\](?![^}]*delete\[\])',  # new[] without delete[] in same scope
                    r'strdup\s*\([^)]*\)(?![^}]*free)',  # strdup without free
                    r'strndup\s*\([^)]*\)(?![^}]*free)',  # strndup without free
                    r'mmap\s*\([^)]*\)(?![^}]*munmap)',  # mmap without munmap
                ],
                'conditional_allocation_leaks': [
                    r'if\s*\([^)]*\)\s*\{[^}]*malloc[^}]*\}(?![^}]*free)',  # Conditional malloc leak
                    r'if\s*\([^)]*\)\s*\{[^}]*new[^}]*\}(?![^}]*delete)',  # Conditional new leak
                    r'for\s*\([^)]*\)\s*\{[^}]*malloc[^}]*\}(?![^}]*free)',  # Loop malloc leak
                    r'while\s*\([^)]*\)\s*\{[^}]*malloc[^}]*\}(?![^}]*free)',  # While malloc leak
                ],
                'exception_based_leaks': [
                    r'try\s*\{[^}]*malloc[^}]*\}(?![^}]*free).*catch',  # Try-catch malloc leak
                    r'try\s*\{[^}]*new[^}]*\}(?![^}]*delete).*catch',  # Try-catch new leak
                    r'throw[^;]*;(?=.*malloc)(?![^}]*free)',  # Exception after malloc
                    r'return[^;]*;(?=.*malloc)(?![^}]*free)',  # Early return after malloc
                ],
                'recursive_allocation_leaks': [
                    r'function.*malloc.*function',  # Recursive malloc
                    r'recursion.*malloc',  # Recursive allocation
                    r'self.*call.*malloc',  # Self-calling malloc
                    r'tail.*recursion.*malloc',  # Tail recursion malloc
                ],
                'thread_based_leaks': [
                    r'pthread_create.*malloc',  # Thread creation with malloc
                    r'std::thread.*malloc',  # C++ thread with malloc
                    r'CreateThread.*malloc',  # Windows thread with malloc
                    r'async.*malloc',  # Async allocation
                ],
                'callback_based_leaks': [
                    r'callback.*malloc',  # Callback with malloc
                    r'function.*pointer.*malloc',  # Function pointer malloc
                    r'signal.*handler.*malloc',  # Signal handler malloc
                    r'interrupt.*handler.*malloc',  # Interrupt handler malloc
                ],
                'container_based_leaks': [
                    r'std::vector.*malloc',  # Vector with malloc
                    r'std::list.*malloc',  # List with malloc
                    r'std::map.*malloc',  # Map with malloc
                    r'std::set.*malloc',  # Set with malloc
                    r'container.*malloc',  # Generic container malloc
                ],
                'smart_pointer_misuse': [
                    r'std::unique_ptr.*malloc',  # Unique_ptr with malloc
                    r'std::shared_ptr.*malloc',  # Shared_ptr with malloc
                    r'std::weak_ptr.*malloc',  # Weak_ptr with malloc
                    r'auto_ptr.*malloc',  # auto_ptr with malloc
                ]
            }
            
            # Analyze each leak pattern category
            for leak_type, patterns in leak_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        analysis.memory_leak_patterns.append(f"{leak_type}: {match.strip()}")
            
            # Advanced leak analysis
            self._analyze_memory_ownership_patterns(content, analysis)
            self._analyze_lifecycle_management(content, analysis)
            
        except Exception as e:
            self.logger.debug(f"Advanced memory leak pattern analysis failed: {e}")
    
    def _analyze_memory_ownership_patterns(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Analyze memory ownership patterns for potential leaks."""
        try:
            # Memory ownership issues
            ownership_issues = [
                r'return.*malloc',  # Returning malloc'd memory
                r'return.*new',  # Returning new'd memory
                r'global.*malloc',  # Global malloc'd memory
                r'static.*malloc',  # Static malloc'd memory
                r'extern.*malloc',  # External malloc'd memory
            ]
            
            for pattern in ownership_issues:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    analysis.memory_leak_patterns.append(f"ownership_issue: {match.strip()}")
            
        except Exception as e:
            self.logger.debug(f"Memory ownership analysis failed: {e}")
    
    def _analyze_lifecycle_management(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Analyze memory lifecycle management patterns."""
        try:
            # Lifecycle management issues
            lifecycle_issues = [
                r'constructor.*malloc(?![^}]*destructor.*free)',  # Constructor malloc without destructor free
                r'init.*malloc(?![^}]*cleanup.*free)',  # Init malloc without cleanup free
                r'open.*malloc(?![^}]*close.*free)',  # Open malloc without close free
                r'create.*malloc(?![^}]*destroy.*free)',  # Create malloc without destroy free
            ]
            
            for pattern in lifecycle_issues:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    analysis.memory_leak_patterns.append(f"lifecycle_issue: {match.strip()}")
            
        except Exception as e:
            self.logger.debug(f"Memory lifecycle analysis failed: {e}")
    
    def _analyze_buffer_overflow_vulnerability_scanning(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """
        Comprehensive buffer overflow vulnerability scanning.
        
        This method performs deep analysis of buffer overflow vulnerabilities
        using advanced pattern matching and context analysis.
        """
        try:
            self.logger.debug("Performing comprehensive buffer overflow vulnerability scanning")
            
            # Advanced buffer overflow patterns
            overflow_patterns = {
                'classic_buffer_overflows': [
                    r'strcpy\s*\([^)]*\)(?![^;]*strncpy)',  # strcpy without strncpy
                    r'strcat\s*\([^)]*\)(?![^;]*strncat)',  # strcat without strncat
                    r'sprintf\s*\([^)]*\)(?![^;]*snprintf)',  # sprintf without snprintf
                    r'gets\s*\([^)]*\)(?![^;]*fgets)',  # gets without fgets
                    r'scanf\s*\([^)]*\)(?![^;]*.*%\d+)',  # scanf without width specifier
                    r'vsprintf\s*\([^)]*\)(?![^;]*vsnprintf)',  # vsprintf without vsnprintf
                ],
                'memory_copy_overflows': [
                    r'memcpy\s*\([^)]*\)(?![^;]*size.*check)',  # memcpy without size check
                    r'memmove\s*\([^)]*\)(?![^;]*bounds.*check)',  # memmove without bounds check
                    r'memset\s*\([^)]*\)(?![^;]*size.*validation)',  # memset without validation
                    r'bcopy\s*\([^)]*\)(?![^;]*size.*check)',  # bcopy without size check
                    r'wmemcpy\s*\([^)]*\)(?![^;]*size.*check)',  # wmemcpy without size check
                ],
                'string_handling_overflows': [
                    r'strncpy\s*\([^)]*\)(?![^;]*null.*termination)',  # strncpy without null termination
                    r'strncat\s*\([^)]*\)(?![^;]*space.*check)',  # strncat without space check
                    r'snprintf\s*\([^)]*\)(?![^;]*return.*check)',  # snprintf without return check
                    r'strlcpy\s*\([^)]*\)(?![^;]*return.*check)',  # strlcpy without return check
                    r'strlcat\s*\([^)]*\)(?![^;]*return.*check)',  # strlcat without return check
                ],
                'stack_buffer_overflows': [
                    r'char\s+\w+\[\d+\].*strcpy',  # Fixed-size buffer with strcpy
                    r'char\s+\w+\[\d+\].*strcat',  # Fixed-size buffer with strcat
                    r'char\s+\w+\[\d+\].*sprintf',  # Fixed-size buffer with sprintf
                    r'char\s+\w+\[\d+\].*gets',  # Fixed-size buffer with gets
                    r'alloca\s*\([^)]*\)(?![^;]*size.*limit)',  # alloca without size limit
                ],
                'heap_buffer_overflows': [
                    r'malloc\s*\([^)]*\).*strcpy',  # malloc with strcpy
                    r'malloc\s*\([^)]*\).*strcat',  # malloc with strcat
                    r'malloc\s*\([^)]*\).*sprintf',  # malloc with sprintf
                    r'calloc\s*\([^)]*\).*strcpy',  # calloc with strcpy
                    r'realloc\s*\([^)]*\).*strcpy',  # realloc with strcpy
                ],
                'integer_overflow_to_buffer_overflow': [
                    r'malloc\s*\([^)]*\*[^)]*\)(?![^;]*overflow.*check)',  # malloc with multiplication
                    r'calloc\s*\([^,]*,\s*[^)]*\*[^)]*\)',  # calloc with multiplication
                    r'realloc\s*\([^,]*,\s*[^)]*\*[^)]*\)',  # realloc with multiplication
                    r'new\s+\w+\[.*\*.*\](?![^;]*check)',  # new with multiplication
                    r'size\s*\*\s*count(?![^;]*overflow.*check)',  # size * count without check
                ],
                'format_string_to_buffer_overflow': [
                    r'printf\s*\([^,)]*%[^,)]*\)(?![^;]*format.*check)',  # printf format string
                    r'sprintf\s*\([^,]+,\s*[^,)]*%[^,)]*\)(?![^;]*validation)',  # sprintf format string
                    r'fprintf\s*\([^,]+,\s*[^,)]*%[^,)]*\)(?![^;]*check)',  # fprintf format string
                    r'snprintf\s*\([^,]+,\s*[^,]+,\s*[^,)]*%[^,)]*\)(?![^;]*validation)',  # snprintf format string
                ],
                'array_index_overflows': [
                    r'\w+\[\s*\w+\s*\](?![^;]*bounds.*check)',  # Array access without bounds check
                    r'\w+\[\s*\w+\s*\+\s*\w+\s*\](?![^;]*check)',  # Array access with addition
                    r'\w+\[\s*\w+\s*\*\s*\w+\s*\](?![^;]*check)',  # Array access with multiplication
                    r'GetArrayElement.*(?![^;]*index.*check)',  # Array element access
                ],
                'loop_based_overflows': [
                    r'for\s*\([^)]*\)\s*\{[^}]*strcpy[^}]*\}',  # Loop with strcpy
                    r'for\s*\([^)]*\)\s*\{[^}]*strcat[^}]*\}',  # Loop with strcat
                    r'while\s*\([^)]*\)\s*\{[^}]*strcpy[^}]*\}',  # While with strcpy
                    r'do\s*\{[^}]*strcpy[^}]*\}.*while',  # Do-while with strcpy
                ]
            }
            
            # Analyze each overflow pattern category
            for overflow_type, patterns in overflow_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        analysis.buffer_overflow_vulnerabilities.append(f"{overflow_type}: {match.strip()}")
            
            # Advanced overflow analysis
            self._analyze_buffer_boundaries(content, analysis)
            self._analyze_input_validation_gaps(content, analysis)
            
        except Exception as e:
            self.logger.debug(f"Buffer overflow vulnerability scanning failed: {e}")
    
    def _analyze_buffer_boundaries(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Analyze buffer boundary validation patterns."""
        try:
            # Buffer boundary issues
            boundary_issues = [
                r'strlen\s*\([^)]*\)(?![^;]*.*<.*sizeof)',  # strlen without sizeof check
                r'size\s*=\s*strlen\s*\([^)]*\)(?![^;]*size.*check)',  # size = strlen without check
                r'len\s*=\s*strlen\s*\([^)]*\)(?![^;]*len.*check)',  # len = strlen without check
                r'count\s*=\s*strlen\s*\([^)]*\)(?![^;]*count.*check)',  # count = strlen without check
            ]
            
            for pattern in boundary_issues:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    analysis.buffer_overflow_vulnerabilities.append(f"boundary_issue: {match.strip()}")
            
        except Exception as e:
            self.logger.debug(f"Buffer boundary analysis failed: {e}")
    
    def _analyze_input_validation_gaps(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Analyze input validation gaps that could lead to buffer overflows."""
        try:
            # Input validation gaps
            validation_gaps = [
                r'fgets\s*\([^)]*\)(?![^;]*.*null.*check)',  # fgets without null check
                r'fread\s*\([^)]*\)(?![^;]*.*return.*check)',  # fread without return check
                r'recv\s*\([^)]*\)(?![^;]*.*size.*check)',  # recv without size check
                r'read\s*\([^)]*\)(?![^;]*.*return.*check)',  # read without return check
                r'getline\s*\([^)]*\)(?![^;]*.*return.*check)',  # getline without return check
            ]
            
            for pattern in validation_gaps:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    analysis.buffer_overflow_vulnerabilities.append(f"validation_gap: {match.strip()}")
            
        except Exception as e:
            self.logger.debug(f"Input validation gap analysis failed: {e}")
    
    def _analyze_memory_corruption_patterns(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """
        Analyze advanced memory corruption patterns.
        
        This method detects sophisticated memory corruption vulnerabilities
        that go beyond basic buffer overflows.
        """
        try:
            self.logger.debug("Analyzing advanced memory corruption patterns")
            
            # Advanced memory corruption patterns
            corruption_patterns = {
                'double_free_vulnerabilities': [
                    r'free\s*\([^)]+\);.*free\s*\([^)]+\)',  # Double free pattern
                    r'delete\s+\w+;.*delete\s+\w+',  # Double delete pattern
                    r'delete\[\]\s*\w+;.*delete\[\]\s*\w+',  # Double delete[] pattern
                    r'munmap\s*\([^)]*\);.*munmap\s*\([^)]*\)',  # Double munmap
                ],
                'use_after_free_vulnerabilities': [
                    r'free\s*\([^)]+\);(?![^;]*\w+\s*=\s*NULL).*\*\s*\w+',  # Use after free
                    r'delete\s+\w+;(?![^;]*\w+\s*=\s*null).*\w+\s*->',  # Use after delete
                    r'delete\[\]\s*\w+;(?![^;]*\w+\s*=\s*null).*\w+\[',  # Use after delete[]
                    r'munmap\s*\([^)]*\)(?![^;]*.*=.*NULL).*\*',  # Use after munmap
                ],
                'heap_metadata_corruption': [
                    r'malloc\s*\([^)]*\).*\*\s*\([^)]*\+\s*-\d+\)',  # Heap metadata write
                    r'free\s*\([^)]*\+\s*\d+\)',  # Free with offset
                    r'realloc\s*\([^)]*\+\s*\d+',  # Realloc with offset
                    r'chunk\s*\+\s*size.*=',  # Chunk size manipulation
                ],
                'vtable_corruption': [
                    r'vtable.*=.*malloc',  # vtable corruption via malloc
                    r'vptr.*=.*malloc',  # vptr corruption via malloc
                    r'virtual.*table.*corruption',  # Virtual table corruption
                    r'__vt.*=',  # vtable assignment
                ],
                'function_pointer_corruption': [
                    r'function.*pointer.*=.*malloc',  # Function pointer from malloc
                    r'callback.*=.*malloc',  # Callback from malloc
                    r'handler.*=.*malloc',  # Handler from malloc
                    r'\*\s*func.*=.*malloc',  # Function pointer assignment
                ],
                'return_address_corruption': [
                    r'return.*address.*overflow',  # Return address overflow
                    r'stack.*return.*corruption',  # Stack return corruption
                    r'ROP.*chain',  # ROP chain
                    r'ret2libc',  # ret2libc attack
                ],
                'exception_handler_corruption': [
                    r'exception.*handler.*corruption',  # Exception handler corruption
                    r'SEH.*corruption',  # SEH corruption
                    r'__try.*__except.*corruption',  # Try-except corruption
                    r'unwind.*corruption',  # Unwind corruption
                ],
                'format_string_corruption': [
                    r'printf\s*\([^,)]*%n[^,)]*\)',  # %n format specifier
                    r'sprintf\s*\([^,]+,\s*[^,)]*%n[^,)]*\)',  # sprintf %n
                    r'fprintf\s*\([^,]+,\s*[^,)]*%n[^,)]*\)',  # fprintf %n
                    r'snprintf\s*\([^,]+,\s*[^,]+,\s*[^,)]*%n[^,)]*\)',  # snprintf %n
                ]
            }
            
            # Analyze each corruption pattern category
            for corruption_type, patterns in corruption_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        analysis.memory_vulnerabilities.append(f"{corruption_type}: {match.strip()}")
            
        except Exception as e:
            self.logger.debug(f"Memory corruption pattern analysis failed: {e}")
    
    def _analyze_control_flow_integrity(self, content: str, lib_path: Path, analysis: MemorySecurityAnalysis) -> None:
        """
        Analyze control flow integrity mechanisms.
        
        This method checks for CFI (Control Flow Integrity) protections
        and identifies potential bypass vulnerabilities.
        """
        try:
            self.logger.debug("Analyzing control flow integrity mechanisms")
            
            # CFI protection patterns
            cfi_patterns = [
                r'__cfi_check',  # CFI check function
                r'__cfi_slowpath',  # CFI slowpath
                r'__cfi_',  # CFI prefix
                r'cfi_check',  # CFI check
                r'control_flow_integrity',  # CFI keyword
                r'CFI_CHECK',  # CFI check macro
                r'CFI_CLANG',  # Clang CFI
                r'CFI_ICALL',  # CFI indirect call
                r'CFI_VCALL',  # CFI virtual call
            ]
            
            cfi_found = False
            for pattern in cfi_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    analysis.memory_hardening_features.append(f"CFI: {pattern}")
                    cfi_found = True
            
            if not cfi_found:
                analysis.missing_protections.append("Control Flow Integrity (CFI) not detected")
            
            # Additional CFI analysis
            self._analyze_cfi_bypass_patterns(content, analysis)
            
        except Exception as e:
            self.logger.debug(f"Control flow integrity analysis failed: {e}")
    
    def _analyze_cfi_bypass_patterns(self, content: str, analysis: MemorySecurityAnalysis) -> None:
        """Analyze CFI bypass patterns."""
        try:
            # CFI bypass patterns
            bypass_patterns = [
                r'JOP.*gadget',  # Jump-oriented programming
                r'ROP.*gadget',  # Return-oriented programming
                r'ret2.*',  # Return-to-* attacks
                r'gadget.*chain',  # Gadget chaining
                r'indirect.*call.*corruption',  # Indirect call corruption
                r'virtual.*call.*corruption',  # Virtual call corruption
            ]
            
            for pattern in bypass_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    analysis.memory_vulnerabilities.append(f"CFI_bypass: {match.strip()}")
            
        except Exception as e:
            self.logger.debug(f"CFI bypass pattern analysis failed: {e}") 