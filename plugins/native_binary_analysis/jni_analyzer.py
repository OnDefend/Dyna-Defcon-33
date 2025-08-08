"""
JNI Security Analyzer Module

Specialized analyzer for JNI (Java Native Interface) security analysis.
Comprehensive implementation with advanced vulnerability detection and security scoring.

Features:
- JNI function call validation
- Reference leak detection
- Exception handling analysis
- Buffer overflow detection
- Privilege escalation risk assessment
- Method signature validation
- Native-Java boundary security
- Comprehensive security scoring
"""

import logging
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from core.shared_infrastructure.dependency_injection import AnalysisContext
from core.shared_infrastructure.analysis_exceptions import BinaryAnalysisError
from .data_structures import (
    JNISecurityAnalysis, 
    NativeBinaryVulnerability, 
    VulnerabilitySeverity,
    JNISecurityRisk
)
from .confidence_calculator import BinaryConfidenceCalculator

class JNIAnalyzer:
    """Advanced JNI security analyzer with comprehensive vulnerability detection."""
    
    def __init__(self, context: AnalysisContext, confidence_calculator: BinaryConfidenceCalculator, logger: logging.Logger):
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = logger
        
        # JNI function categories for security analysis
        self.jni_functions = {
            'critical_functions': {
                'GetStringUTFChars', 'ReleaseStringUTFChars', 'GetStringCritical', 'ReleaseStringCritical',
                'GetPrimitiveArrayCritical', 'ReleasePrimitiveArrayCritical', 'NewGlobalRef', 'DeleteGlobalRef',
                'NewLocalRef', 'DeleteLocalRef', 'NewWeakGlobalRef', 'DeleteWeakGlobalRef'
            },
            'array_functions': {
                'GetArrayElements', 'ReleaseArrayElements', 'GetArrayLength', 'NewArray',
                'GetBooleanArrayElements', 'GetByteArrayElements', 'GetCharArrayElements',
                'GetShortArrayElements', 'GetIntArrayElements', 'GetLongArrayElements',
                'GetFloatArrayElements', 'GetDoubleArrayElements'
            },
            'object_functions': {
                'NewObject', 'NewObjectA', 'NewObjectV', 'GetObjectClass', 'IsInstanceOf',
                'GetMethodID', 'GetStaticMethodID', 'GetFieldID', 'GetStaticFieldID',
                'CallObjectMethod', 'CallBooleanMethod', 'CallByteMethod', 'CallCharMethod',
                'CallStaticObjectMethod', 'CallStaticBooleanMethod', 'CallStaticByteMethod'
            },
            'exception_functions': {
                'ExceptionCheck', 'ExceptionOccurred', 'ExceptionDescribe', 'ExceptionClear',
                'Throw', 'ThrowNew', 'FatalError'
            }
        }
        
        # JNI vulnerability detection patterns
        self.jni_vulnerability_patterns = {
            'reference_leaks': [
                r'NewGlobalRef\s*\([^)]*\)(?![^;]*DeleteGlobalRef)',
                r'NewLocalRef\s*\([^)]*\)(?![^;]*DeleteLocalRef)',
                r'GetStringChars\s*\([^)]*\)(?![^;]*ReleaseStringChars)',
                r'GetStringUTFChars\s*\([^)]*\)(?![^;]*ReleaseStringUTFChars)',
                r'GetByteArrayElements\s*\([^)]*\)(?![^;]*ReleaseByteArrayElements)',
                r'GetPrimitiveArrayCritical\s*\([^)]*\)(?![^;]*ReleasePrimitiveArrayCritical)'
            ],
            'unchecked_exceptions': [
                r'CallObjectMethod\s*\([^)]*\)(?![^;]*ExceptionCheck)',
                r'CallVoidMethod\s*\([^)]*\)(?![^;]*ExceptionCheck)',
                r'GetFieldID\s*\([^)]*\)(?![^;]*ExceptionCheck)',
                r'GetMethodID\s*\([^)]*\)(?![^;]*ExceptionCheck)',
                r'NewObject\s*\([^)]*\)(?![^;]*ExceptionCheck)',
                r'FindClass\s*\([^)]*\)(?![^;]*ExceptionCheck)',
                r'ThrowNew\s*\([^)]*\)(?![^;]*ExceptionCheck)'
            ],
            'buffer_overflows': [
                r'GetStringUTFChars.*strcpy(?!_s)',
                r'GetStringChars.*wcscpy(?!_s)',
                r'GetByteArrayElements.*memcpy(?![^;]*length.*check)',
                r'GetArrayLength.*(?![^;]*bounds.*check).*\[\s*\w+\s*\]',
                r'GetStringUTFLength.*buffer.*overflow'
            ],
            'privilege_escalation': [
                r'AttachCurrentThread.*root',
                r'AttachCurrentThread.*system',
                r'JNI_OnLoad.*setuid',
                r'JNI_OnLoad.*setgid',
                r'system\s*\([^)]*\).*JNI',
                r'exec[vl]\s*\([^)]*\).*JNI'
            ],
            'boundary_violations': [
                r'GetArrayLength.*index.*out.*of.*bounds',
                r'GetObjectArrayElement.*(?![^;]*index.*validation)',
                r'SetObjectArrayElement.*(?![^;]*index.*validation)',
                r'GetByteArrayRegion.*(?![^;]*bounds.*check)',
                r'SetByteArrayRegion.*(?![^;]*bounds.*check)'
            ]
        }
    
    def analyze(self, lib_path: Path) -> JNISecurityAnalysis:
        """
        Analyze JNI implementation security vulnerabilities.
        
        Args:
            lib_path: Path to the native library to analyze
            
        Returns:
            JNISecurityAnalysis: Comprehensive JNI security analysis results
        """
        analysis = JNISecurityAnalysis(library_name=lib_path.name)
        
        try:
            # Extract library content for analysis
            content = self._extract_library_content(lib_path)
            if not content:
                self.logger.warning(f"Could not extract content from {lib_path.name}")
                return analysis
            
            # Detect JNI functions used
            self._detect_jni_functions(content, analysis)
            
            # Analyze JNI vulnerability patterns
            self._detect_jni_reference_leaks(content, analysis)
            self._detect_jni_exception_issues(content, analysis)
            self._detect_jni_buffer_overflows(content, analysis)
            self._detect_jni_privilege_escalation(content, analysis)
            self._detect_jni_boundary_violations(content, analysis)
            
            # Enhanced JNI deep inspection analysis
            self._analyze_jni_method_signatures(content, analysis)
            self._analyze_native_library_dependencies(lib_path, analysis)
            self._analyze_cross_compilation_security(content, analysis)
            self._detect_native_code_obfuscation(content, analysis)
            self._enumerate_jni_attack_surface(content, analysis)
            self._detect_native_vulnerability_patterns(content, analysis)
            self._generate_runtime_monitoring_hooks(content, analysis)
            self._verify_native_code_integrity(lib_path, analysis)
            
            # Advanced JNI Security Analysis Enhancement
            self._enhanced_jni_security_analysis(content, analysis)
            
            # Calculate JNI security score
            analysis.security_score = self._calculate_jni_security_score(analysis)
            
            # Determine risk level
            analysis.risk_level = self._determine_jni_risk_level(analysis)
            
            # Generate vulnerabilities based on findings
            self._generate_jni_vulnerabilities(analysis)
            
        except Exception as e:
            self.logger.error(f"JNI security analysis failed for {lib_path.name}: {e}")
            # Create error vulnerability
            error_vuln = NativeBinaryVulnerability(
                id=f"jni_analysis_error_{lib_path.name}",
                title="JNI Analysis Error",
                description=f"JNI security analysis failed: {str(e)}",
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
                
            # Extract readelf info
            readelf_result = subprocess.run(
                ["readelf", "-s", str(lib_path)], 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            if readelf_result.returncode == 0:
                content += readelf_result.stdout
                
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Timeout extracting content from {lib_path.name}")
        except Exception as e:
            self.logger.debug(f"Content extraction failed for {lib_path.name}: {e}")
        
        return content
    
    def _detect_jni_functions(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Detect JNI functions used in the library."""
        for category, functions in self.jni_functions.items():
            for func in functions:
                if func in content:
                    analysis.jni_functions_found.append(f"{category}:{func}")
    
    def _detect_jni_reference_leaks(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Detect potential JNI reference leaks."""
        for pattern in self.jni_vulnerability_patterns['reference_leaks']:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                analysis.reference_leaks.append(match.strip())
    
    def _detect_jni_exception_issues(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Detect JNI exception handling issues."""
        for pattern in self.jni_vulnerability_patterns['unchecked_exceptions']:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                analysis.exception_handling_issues.append(match.strip())
    
    def _detect_jni_buffer_overflows(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Detect potential JNI buffer overflow vulnerabilities."""
        for pattern in self.jni_vulnerability_patterns['buffer_overflows']:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                analysis.unsafe_jni_calls.append(f"Buffer overflow risk: {match.strip()}")
    
    def _detect_jni_privilege_escalation(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Detect potential JNI privilege escalation vulnerabilities."""
        for pattern in self.jni_vulnerability_patterns['privilege_escalation']:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                analysis.privilege_escalation_risks.append(match.strip())
    
    def _detect_jni_boundary_violations(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Detect JNI boundary violations."""
        for pattern in self.jni_vulnerability_patterns['boundary_violations']:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                analysis.boundary_violations.append(match.strip())
    
    def _analyze_jni_method_signatures(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Analyze JNI method signatures and validate their security."""
        try:
            # JNI method signature patterns
            jni_method_patterns = [
                r'JNIEXPORT\s+(\w+)\s+JNICALL\s+(\w+)\s*\(',
                r'Java_[\w_]+_[\w_]+\s*\(',
                r'JNI_OnLoad\s*\(',
                r'JNI_OnUnload\s*\(',
            ]
            
            for pattern in jni_method_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    if isinstance(match, tuple):
                        signature = f"{match[0]} {match[1]}"
                    else:
                        signature = match
                    analysis.jni_method_signatures.append(signature)
            
            # Validate signatures for security issues
            invalid_signature_patterns = [
                r'Java_[\w_]+_[\w_]+.*\(JNIEnv\s*\*\s*env\s*\)',  # Missing jobject parameter
                r'JNIEXPORT\s+void\s+JNICALL.*\(.*\*\s*\*',  # Double pointer parameters
                r'Java_[\w_]+_[\w_]+.*\(.*,\s*\.\.\.\s*\)',  # Variadic parameters
            ]
            
            for pattern in invalid_signature_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    analysis.invalid_signatures.append(f"Invalid signature: {match}")
            
        except Exception as e:
            self.logger.debug(f"JNI method signature analysis failed: {e}")
    
    def _analyze_native_library_dependencies(self, lib_path: Path, analysis: JNISecurityAnalysis) -> None:
        """Analyze native library dependencies for security issues."""
        try:
            ldd_result = subprocess.run(
                ["ldd", str(lib_path)], 
                capture_output=True, 
                text=True, 
                timeout=15
            )
            
            if ldd_result.returncode == 0:
                dependencies = []
                for line in ldd_result.stdout.split('\n'):
                    if '=>' in line:
                        dep = line.split('=>')[0].strip()
                        dependencies.append(dep)
                        analysis.dependency_graph[lib_path.name] = dependencies
                
                # Check for suspicious dependencies
                suspicious_deps = ['libroot', 'libsystem', 'libhack', 'libcrack']
                for dep in dependencies:
                    for suspicious in suspicious_deps:
                        if suspicious in dep.lower():
                            analysis.cross_compilation_issues.append(f"Suspicious dependency: {dep}")
            
        except Exception as e:
            self.logger.debug(f"Dependency analysis failed for {lib_path.name}: {e}")
    
    def _analyze_cross_compilation_security(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Analyze cross-compilation security issues."""
        try:
            # Cross-compilation security patterns
            cross_compilation_patterns = [
                r'__ANDROID_API__.*(?![^;]*security.*check)',
                r'#ifdef\s+__arm__.*(?![^;]*security)',
                r'#ifdef\s+__aarch64__.*(?![^;]*security)',
                r'#if\s+defined\(.*android.*\).*(?![^;]*security)',
                r'__NDK_VERSION__.*(?![^;]*compatible)',
            ]
            
            for pattern in cross_compilation_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    analysis.cross_compilation_issues.append(f"Cross-compilation issue: {match.strip()}")
            
        except Exception as e:
            self.logger.debug(f"Cross-compilation analysis failed: {e}")
    
    def _detect_native_code_obfuscation(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Detect native code obfuscation indicators."""
        try:
            # Obfuscation patterns
            obfuscation_patterns = [
                r'[a-zA-Z]{1}[0-9a-fA-F]{7,}',  # Hex-like identifiers
                r'_Z\w{10,}',  # Mangled names
                r'sub_[0-9A-F]{6,}',  # IDA-style function names
                r'j_[a-zA-Z0-9_]{10,}',  # Jump functions
                r'nullsub_\w+',  # Null subroutines
            ]
            
            for pattern in obfuscation_patterns:
                matches = re.findall(pattern, content)
                if len(matches) > 10:  # Threshold for obfuscation
                    analysis.obfuscation_indicators.append(f"Pattern {pattern}: {len(matches)} occurrences")
            
            # Check for string obfuscation
            if len(re.findall(r'\\x[0-9a-fA-F]{2}', content)) > 50:
                analysis.obfuscation_indicators.append("Hex-encoded strings detected")
            
            # Check for control flow obfuscation
            if len(re.findall(r'goto\s+\w+', content)) > 20:
                analysis.obfuscation_indicators.append("Control flow obfuscation detected")
            
        except Exception as e:
            self.logger.debug(f"Obfuscation detection failed: {e}")
    
    def _enumerate_jni_attack_surface(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Enumerate JNI attack surface vectors."""
        try:
            # JNI attack surface patterns
            attack_surface_patterns = {
                'exported_functions': [
                    r'JNIEXPORT.*JNICALL\s+([a-zA-Z_][a-zA-Z0-9_]*)',
                    r'Java_[\w_]+_([\w_]+)',
                ],
                'native_callbacks': [
                    r'RegisterNatives.*\(\s*([^,]+)',
                    r'GetMethodID.*\(\s*[^,]+,\s*"([^"]+)"',
                ],
                'data_access_points': [
                    r'GetStringUTFChars.*\(\s*[^,]+,\s*([^,]+)',
                    r'GetArrayElements.*\(\s*[^,]+,\s*([^,]+)',
                    r'GetFieldID.*\(\s*[^,]+,\s*"([^"]+)"',
                ],
                'system_interfaces': [
                    r'system\s*\(\s*([^)]+)\s*\)',
                    r'exec[vl].*\(\s*([^,]+)',
                    r'dlopen\s*\(\s*([^,]+)',
                    r'dlsym\s*\(\s*[^,]+,\s*([^,]+)',
                ],
            }
            
            for category, patterns in attack_surface_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        analysis.attack_surface_vectors.append(f"{category}: {match}")
            
            # Check for JNI registration vulnerabilities
            if 'RegisterNatives' in content:
                analysis.attack_surface_vectors.append("Dynamic JNI registration detected")
            
            # Check for reflection usage
            reflection_patterns = [
                r'FindClass.*\(\s*[^,]+,\s*"([^"]+)"',
                r'CallObjectMethod.*\(\s*[^,]+,\s*([^,]+)',
                r'CallStaticMethod.*\(\s*[^,]+,\s*([^,]+)',
            ]
            
            for pattern in reflection_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    analysis.attack_surface_vectors.append(f"Reflection usage: {len(matches)} instances")
            
        except Exception as e:
            self.logger.debug(f"Attack surface enumeration failed: {e}")
    
    def _detect_native_vulnerability_patterns(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Detect native vulnerability patterns."""
        try:
            # Native vulnerability patterns
            vuln_patterns = {
                'format_string': [
                    r'printf\s*\([^,]+\s*\)',
                    r'sprintf\s*\([^,]+,[^,]+\s*\)',
                    r'fprintf\s*\([^,]+,[^,]+\s*\)',
                ],
                'integer_overflow': [
                    r'malloc\s*\([^)]*\*[^)]*\)',
                    r'calloc\s*\([^)]*\*[^)]*\)',
                    r'realloc\s*\([^,]*,[^)]*\*[^)]*\)',
                ],
                'race_conditions': [
                    r'pthread_\w+.*(?![^;]*mutex)',
                    r'CreateThread.*(?![^;]*synchroniz)',
                    r'static\s+\w+.*(?![^;]*volatile)',
                ],
                'use_after_free': [
                    r'free\s*\([^)]+\).*(?![^;]*\w+\s*=\s*NULL)',
                    r'delete\s+\w+.*(?![^;]*\w+\s*=\s*null)',
                ],
            }
            
            for vuln_type, patterns in vuln_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        analysis.vulnerability_patterns.append(f"{vuln_type}: {match.strip()}")
            
        except Exception as e:
            self.logger.debug(f"Vulnerability pattern detection failed: {e}")
    
    def _generate_runtime_monitoring_hooks(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Generate runtime monitoring hooks for detected JNI functions."""
        try:
            # Generate hooks for critical JNI functions
            critical_functions = ['NewGlobalRef', 'DeleteGlobalRef', 'GetStringUTFChars', 'ReleaseStringUTFChars']
            
            for func in critical_functions:
                if func in content:
                    hook = f"Frida.Interceptor.attach(Module.findExportByName('libnative.so', '{func}'), {{"
                    hook += f"onEnter: function(args) {{ console.log('[+] {func} called'); }},"
                    hook += f"onLeave: function(retval) {{ console.log('[+] {func} returned:', retval); }}"
                    hook += "});"
                    analysis.runtime_monitoring_hooks.append(hook)
            
        except Exception as e:
            self.logger.debug(f"Runtime hook generation failed: {e}")
    
    def _verify_native_code_integrity(self, lib_path: Path, analysis: JNISecurityAnalysis) -> None:
        """Verify native code integrity."""
        try:
            # Check for tampering indicators
            file_result = subprocess.run(
                ["file", str(lib_path)], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            if file_result.returncode == 0:
                file_info = file_result.stdout.lower()
                
                # Check for integrity issues
                integrity_issues = []
                if 'stripped' in file_info:
                    integrity_issues.append("Binary is stripped (debugging symbols removed)")
                if 'packed' in file_info:
                    integrity_issues.append("Binary appears to be packed")
                if 'upx' in file_info:
                    integrity_issues.append("UPX packer detected")
                
                analysis.integrity_violations.extend(integrity_issues)
            
        except Exception as e:
            self.logger.debug(f"Integrity verification failed for {lib_path.name}: {e}")
    
    def _enhanced_jni_security_analysis(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Enhanced JNI security analysis with advanced validation."""
        try:
            # Advanced JNI function call validation
            self._advanced_jni_function_call_validation(content, analysis)
            
            # Enhanced JNI object reference analysis
            self._enhanced_jni_object_reference_analysis(content, analysis)
            
            # Native-Java boundary security assessment
            self._native_java_boundary_security_assessment(content, analysis)
            
            # Analyze JNI callback security
            callback_security_patterns = [
                r'CallVoidMethod\s*\([^)]*\)(?![^;]*.*security.*check)',
                r'CallObjectMethod\s*\([^)]*\)(?![^;]*.*validate.*return)',
                r'CallStaticMethod\s*\([^)]*\)(?![^;]*.*permission.*check)'
            ]
            
            for pattern in callback_security_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    analysis.unsafe_jni_calls.append(f"Callback security: {match.strip()}")
            
            # Analyze JNI thread safety
            thread_safety_patterns = [
                r'static\s+jobject\s+\w+(?![^;]*.*thread.*safe)',
                r'static\s+jclass\s+\w+(?![^;]*.*thread.*safe)',
                r'GetStaticField\s*\([^)]*\)(?![^;]*.*synchroniz)'
            ]
            
            for pattern in thread_safety_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    analysis.unsafe_jni_calls.append(f"Thread safety: {match.strip()}")
            
        except Exception as e:
            self.logger.debug(f"Enhanced JNI security analysis failed: {e}")
    
    def _advanced_jni_function_call_validation(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Advanced JNI function call validation with comprehensive security pattern detection."""
        try:
            # Enhanced JNI function call patterns for advanced security analysis
            jni_call_patterns = {
                'unchecked_array_access': [
                    r'GetArrayElements\s*\([^)]*\)(?![^;]*ReleaseArrayElements)',
                    r'GetPrimitiveArrayCritical\s*\([^)]*\)(?![^;]*ReleasePrimitiveArrayCritical)',
                    r'GetStringChars\s*\([^)]*\)(?![^;]*ReleaseStringChars)',
                    r'GetStringUTFChars\s*\([^)]*\)(?![^;]*ReleaseStringUTFChars)',
                    r'GetStringCritical\s*\([^)]*\)(?![^;]*ReleaseStringCritical)'
                ],
                'improper_exception_handling': [
                    r'Call\w+Method\s*\([^)]*\)(?![^;]*ExceptionCheck)',
                    r'ThrowNew\s*\([^)]*\)(?![^;]*ExceptionCheck)',
                    r'FindClass\s*\([^)]*\)(?![^;]*ExceptionCheck)',
                    r'GetMethodID\s*\([^)]*\)(?![^;]*ExceptionCheck)',
                    r'GetFieldID\s*\([^)]*\)(?![^;]*ExceptionCheck)',
                    r'NewObject\s*\([^)]*\)(?![^;]*ExceptionCheck)'
                ],
                'unsafe_type_casting': [
                    r'\(\s*j\w+\s*\)\s*\(\s*void\s*\*\s*\)',
                    r'reinterpret_cast\s*<\s*j\w+\s*>',
                    r'static_cast\s*<\s*j\w+\s*>\s*\(\s*\w+\s*\*\s*\)',
                    r'const_cast\s*<\s*j\w+\s*>',
                    r'dynamic_cast\s*<\s*j\w+\s*>'
                ],
                'memory_management_issues': [
                    r'NewGlobalRef\s*\([^)]*\)(?![^;]*DeleteGlobalRef)',
                    r'NewWeakGlobalRef\s*\([^)]*\)(?![^;]*DeleteWeakGlobalRef)',
                    r'NewLocalRef\s*\([^)]*\)(?![^;]*DeleteLocalRef)',
                    r'malloc\s*\([^)]*\)(?![^;]*free)',
                    r'calloc\s*\([^)]*\)(?![^;]*free)',
                    r'realloc\s*\([^)]*\)(?![^;]*free)'
                ],
                'threading_race_conditions': [
                    r'static\s+j\w+\s+\w+(?![^;]*pthread_mutex)',
                    r'static\s+j\w+\s+\w+(?![^;]*std::mutex)',
                    r'GetStaticFieldID\s*\([^)]*\)(?![^;]*synchroniz)',
                    r'SetStaticObjectField\s*\([^)]*\)(?![^;]*lock)',
                    r'CallStaticMethod\s*\([^)]*\)(?![^;]*thread.*safe)'
                ],
                'privilege_escalation_patterns': [
                    r'setuid\s*\([^)]*\)',
                    r'setgid\s*\([^)]*\)',
                    r'seteuid\s*\([^)]*\)',
                    r'setegid\s*\([^)]*\)',
                    r'system\s*\([^)]*su[^)]*\)',
                    r'execve\s*\([^)]*su[^)]*\)',
                    r'fork\s*\([^)]*\).*exec.*su'
                ],
                'buffer_overflow_patterns': [
                    r'strcpy\s*\([^)]*\)(?![^;]*strncpy)',
                    r'strcat\s*\([^)]*\)(?![^;]*strncat)',
                    r'sprintf\s*\([^)]*\)(?![^;]*snprintf)',
                    r'gets\s*\([^)]*\)(?![^;]*fgets)',
                    r'GetStringUTFChars.*strcpy(?![^;]*length.*check)',
                    r'GetArrayElements.*memcpy(?![^;]*size.*check)'
                ],
                'jni_version_mismatch': [
                    r'JNI_VERSION_1_[1-4](?![^;]*compatibility.*check)',
                    r'GetVersion\s*\([^)]*\)(?![^;]*version.*validation)',
                    r'JNI_OnLoad.*return.*JNI_VERSION(?![^;]*supported.*check)'
                ],
                'callback_security_issues': [
                    r'RegisterNatives\s*\([^)]*\)(?![^;]*security.*validation)',
                    r'UnregisterNatives\s*\([^)]*\)(?![^;]*proper.*cleanup)',
                    r'CallVoidMethod\s*\([^)]*\)(?![^;]*security.*check)',
                    r'CallObjectMethod\s*\([^)]*\)(?![^;]*validate.*return)',
                    r'CallStaticMethod\s*\([^)]*\)(?![^;]*permission.*check)'
                ],
                'debug_information_leaks': [
                    r'__android_log_print\s*\([^)]*\).*password|key|token|secret',
                    r'printf\s*\([^)]*\).*password|key|token|secret',
                    r'fprintf\s*\([^)]*\).*password|key|token|secret',
                    r'ALOGD\s*\([^)]*\).*password|key|token|secret',
                    r'ALOGI\s*\([^)]*\).*password|key|token|secret'
                ]
            }
            
            # Enhanced pattern matching with context analysis
            for issue_type, patterns in jni_call_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        # Extract surrounding context for better analysis
                        match_context = self._extract_code_context(content, match)
                        analysis.unsafe_jni_calls.append(f"{issue_type}: {match.strip()} [Context: {match_context}]")
            
            # Advanced security validation patterns
            security_validation_patterns = [
                r'(?:input|parameter|argument).*validat(?:ion|e)',
                r'(?:bounds|range|size).*check',
                r'(?:null|nullptr).*check',
                r'(?:security|permission|authorization).*check',
                r'(?:sanitiz|clean|filter).*input'
            ]
            
            # Check for missing security validations
            missing_validations = []
            for pattern in security_validation_patterns:
                if not re.search(pattern, content, re.IGNORECASE):
                    missing_validations.append(pattern.replace('(?:', '').replace(')', ''))
            
            if missing_validations:
                analysis.unsafe_jni_calls.append(f"missing_security_validations: {', '.join(missing_validations[:3])}")
        
        except Exception as e:
            self.logger.debug(f"Advanced JNI function call validation failed: {e}")
    
    def _extract_code_context(self, content: str, match: str) -> str:
        """Extract code context around a match for better analysis."""
        try:
            # Find the position of the match
            match_pos = content.find(match)
            if match_pos == -1:
                return "unknown"
            
            # Extract 100 characters before and after
            start = max(0, match_pos - 100)
            end = min(len(content), match_pos + len(match) + 100)
            context = content[start:end]
            
            # Clean up the context
            context = ' '.join(context.split())
            return context[:100] + "..." if len(context) > 100 else context
        except Exception:
            return "unknown"

    def _enhanced_jni_object_reference_analysis(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Enhanced JNI object reference analysis with lifecycle tracking."""
        try:
            # Enhanced object reference patterns with lifecycle analysis
            ref_patterns = {
                'global_ref_leaks': [
                    r'NewGlobalRef\s*\([^)]*\)(?![^;]*DeleteGlobalRef)',
                    r'env\s*->\s*NewGlobalRef\s*\([^)]*\)(?![^;]*DeleteGlobalRef)',
                    r'JNI_NewGlobalRef\s*\([^)]*\)(?![^;]*JNI_DeleteGlobalRef)'
                ],
                'local_ref_overflow': [
                    r'NewLocalRef\s*\([^)]*\).*(?:loop|while|for)',
                    r'GetObjectArrayElement\s*\([^)]*\).*for.*\(',
                    r'FindClass\s*\([^)]*\).*(?:loop|while|for)',
                    r'GetObjectClass\s*\([^)]*\).*(?:loop|while|for)'
                ],
                'weak_ref_issues': [
                    r'NewWeakGlobalRef\s*\([^)]*\)(?![^;]*IsSameObject)',
                    r'weak.*ref.*(?![^;]*null.*check)',
                    r'DeleteWeakGlobalRef\s*\([^)]*\)(?![^;]*IsSameObject.*check)'
                ],
                'reference_counting_errors': [
                    r'AddRef\s*\([^)]*\)(?![^;]*Release)',
                    r'Retain\s*\([^)]*\)(?![^;]*Release)',
                    r'acquire\s*\([^)]*\)(?![^;]*release)'
                ],
                'circular_reference_risks': [
                    r'static.*NewGlobalRef.*static',
                    r'global.*ref.*callback.*global',
                    r'NewGlobalRef.*RegisterNatives.*NewGlobalRef'
                ],
                'reference_thread_safety': [
                    r'DeleteGlobalRef\s*\([^)]*\)(?![^;]*(?:mutex|lock|synchroniz))',
                    r'NewGlobalRef\s*\([^)]*\)(?![^;]*(?:mutex|lock|synchroniz))',
                    r'static.*jobject.*(?![^;]*(?:volatile|atomic))'
                ],
                'array_reference_issues': [
                    r'GetObjectArrayElement\s*\([^)]*\)(?![^;]*DeleteLocalRef)',
                    r'NewObjectArray\s*\([^)]*\)(?![^;]*DeleteLocalRef)',
                    r'SetObjectArrayElement\s*\([^)]*\)(?![^;]*exception.*check)'
                ],
                'string_reference_leaks': [
                    r'NewStringUTF\s*\([^)]*\)(?![^;]*DeleteLocalRef)',
                    r'GetStringUTFChars\s*\([^)]*\)(?![^;]*ReleaseStringUTFChars)',
                    r'GetStringCritical\s*\([^)]*\)(?![^;]*ReleaseStringCritical)'
                ]
            }
            
            # Enhanced pattern matching with lifecycle validation
            for issue_type, patterns in ref_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        # Perform lifecycle analysis
                        lifecycle_info = self._analyze_reference_lifecycle(content, match)
                        analysis.reference_leaks.append(f"{issue_type}: {match.strip()} [Lifecycle: {lifecycle_info}]")
            
            # Advanced reference tracking analysis
            self._analyze_reference_tracking_patterns(content, analysis)
            
            # JNI reference capacity analysis
            self._analyze_reference_capacity_usage(content, analysis)
        
        except Exception as e:
            self.logger.debug(f"Enhanced JNI object reference analysis failed: {e}")
    
    def _analyze_reference_lifecycle(self, content: str, match: str) -> str:
        """Analyze the lifecycle of a JNI reference."""
        try:
            # Look for corresponding cleanup calls
            cleanup_patterns = {
                'NewGlobalRef': 'DeleteGlobalRef',
                'NewLocalRef': 'DeleteLocalRef',
                'NewWeakGlobalRef': 'DeleteWeakGlobalRef',
                'GetStringUTFChars': 'ReleaseStringUTFChars',
                'GetStringCritical': 'ReleaseStringCritical',
                'GetArrayElements': 'ReleaseArrayElements'
            }
            
            for create_pattern, cleanup_pattern in cleanup_patterns.items():
                if create_pattern in match:
                    # Check if cleanup is present
                    if cleanup_pattern in content:
                        return "managed"
                    else:
                        return "leaked"
            
            return "unknown"
        except Exception:
            return "unknown"
    
    def _analyze_reference_tracking_patterns(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Analyze reference tracking patterns for memory management issues."""
        try:
            # Reference tracking patterns
            tracking_issues = []
            
            # Look for reference counting without proper cleanup
            if 'NewGlobalRef' in content and 'DeleteGlobalRef' not in content:
                tracking_issues.append("Global references created without cleanup")
            
            # Look for excessive local reference creation
            local_ref_count = content.count('NewLocalRef')
            if local_ref_count > 10:
                tracking_issues.append(f"Excessive local reference creation: {local_ref_count} instances")
            
            # Look for static global references (potential memory leaks)
            static_global_refs = re.findall(r'static.*jobject', content)
            if static_global_refs:
                tracking_issues.append(f"Static global references: {len(static_global_refs)} instances")
            
            # Add tracking issues to analysis
            analysis.reference_leaks.extend([f"reference_tracking: {issue}" for issue in tracking_issues])
            
        except Exception as e:
            self.logger.debug(f"Reference tracking analysis failed: {e}")
    
    def _analyze_reference_capacity_usage(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Analyze JNI reference capacity usage patterns."""
        try:
            # Calculate reference usage patterns
            ref_usage_patterns = {
                'local_refs': len(re.findall(r'NewLocalRef|GetObjectClass|FindClass', content)),
                'global_refs': len(re.findall(r'NewGlobalRef', content)),
                'weak_refs': len(re.findall(r'NewWeakGlobalRef', content)),
                'string_refs': len(re.findall(r'NewStringUTF|GetStringUTFChars', content)),
                'array_refs': len(re.findall(r'NewObjectArray|GetObjectArrayElement', content))
            }
            
            # Check for potential capacity issues
            capacity_issues = []
            if ref_usage_patterns['local_refs'] > 16:  # Default local reference limit
                capacity_issues.append(f"High local reference usage: {ref_usage_patterns['local_refs']} (limit: 16)")
            
            if ref_usage_patterns['global_refs'] > 50:  # Reasonable global reference limit
                capacity_issues.append(f"High global reference usage: {ref_usage_patterns['global_refs']}")
            
            # Add capacity issues to analysis
            analysis.reference_leaks.extend([f"capacity_usage: {issue}" for issue in capacity_issues])
            
        except Exception as e:
            self.logger.debug(f"Reference capacity analysis failed: {e}")

    def _native_java_boundary_security_assessment(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Comprehensive native-Java boundary security assessment."""
        try:
            # Enhanced boundary security patterns
            boundary_patterns = {
                'data_validation': [
                    r'GetStringUTFChars\s*\([^)]*\)(?![^;]*(?:validate|check.*null|strlen))',
                    r'GetByteArrayElements\s*\([^)]*\)(?![^;]*(?:size.*check|length.*valid))',
                    r'CallObjectMethod\s*\([^)]*\)(?![^;]*(?:null.*check|validate.*return))',
                    r'GetArrayLength\s*\([^)]*\)(?![^;]*(?:positive.*check|range.*valid))',
                    r'GetIntField\s*\([^)]*\)(?![^;]*(?:range.*check|validate.*value))'
                ],
                'privilege_boundary': [
                    r'AttachCurrentThread.*(?![^;]*(?:permission.*check|security.*valid))',
                    r'CallStaticMethod.*(?:system|exec|runtime).*(?![^;]*(?:security|permission))',
                    r'GetMethodID.*(?:setuid|setgid|su).*(?![^;]*(?:authorization|permission))',
                    r'RegisterNatives.*(?![^;]*(?:permission.*check|security.*valid))',
                    r'CallVoidMethod.*(?:Runtime|Process).*(?![^;]*(?:security|permission))'
                ],
                'memory_boundary': [
                    r'memcpy\s*\([^)]*\)(?![^;]*(?:bounds.*check|size.*valid))',
                    r'strcpy\s*\([^)]*\)(?![^;]*(?:length.*check|buffer.*size))',
                    r'GetArrayRegion\s*\([^)]*\)(?![^;]*(?:range.*validation|bounds.*check))',
                    r'SetArrayRegion\s*\([^)]*\)(?![^;]*(?:range.*validation|bounds.*check))',
                    r'GetStringRegion\s*\([^)]*\)(?![^;]*(?:range.*validation|bounds.*check))'
                ],
                'type_safety_boundary': [
                    r'Cast\s*\([^)]*\)(?![^;]*(?:type.*check|instance.*valid))',
                    r'reinterpret_cast\s*<.*>(?![^;]*(?:type.*safe|valid.*cast))',
                    r'static_cast\s*<.*>(?![^;]*(?:type.*check|safe.*cast))',
                    r'IsInstanceOf\s*\([^)]*\)(?![^;]*(?:result.*check|valid.*type))'
                ],
                'exception_boundary': [
                    r'ThrowNew\s*\([^)]*\)(?![^;]*(?:exception.*clear|proper.*cleanup))',
                    r'Throw\s*\([^)]*\)(?![^;]*(?:exception.*clear|proper.*cleanup))',
                    r'CallMethod.*(?![^;]*(?:ExceptionCheck|exception.*occurred))',
                    r'GetMethodID.*(?![^;]*(?:ExceptionCheck|exception.*occurred))'
                ],
                'threading_boundary': [
                    r'AttachCurrentThread\s*\([^)]*\)(?![^;]*(?:DetachCurrentThread|thread.*cleanup))',
                    r'MonitorEnter\s*\([^)]*\)(?![^;]*(?:MonitorExit|unlock))',
                    r'static.*jobject.*(?![^;]*(?:volatile|atomic|synchroniz))',
                    r'GetStaticFieldID.*(?![^;]*(?:thread.*safe|synchroniz))'
                ],
                'resource_boundary': [
                    r'fopen\s*\([^)]*\)(?![^;]*(?:fclose|resource.*cleanup))',
                    r'malloc\s*\([^)]*\)(?![^;]*(?:free|memory.*cleanup))',
                    r'dlopen\s*\([^)]*\)(?![^;]*(?:dlclose|library.*cleanup))',
                    r'socket\s*\([^)]*\)(?![^;]*(?:close|socket.*cleanup))'
                ],
                'input_sanitization': [
                    r'GetStringUTFChars.*(?![^;]*(?:sanitiz|clean|filter|escape))',
                    r'CallObjectMethod.*String.*(?![^;]*(?:sanitiz|clean|filter|validate))',
                    r'GetByteArrayElements.*(?![^;]*(?:sanitiz|clean|filter|validate))'
                ]
            }
            
            # Advanced boundary analysis with context
            for boundary_type, patterns in boundary_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        # Enhanced boundary analysis
                        boundary_risk = self._assess_boundary_risk(content, match, boundary_type)
                        analysis.boundary_violations.append(f"{boundary_type}: {match.strip()} [Risk: {boundary_risk}]")
            
            # Advanced boundary security checks
            self._analyze_boundary_validation_patterns(content, analysis)
            self._analyze_data_flow_boundaries(content, analysis)
            
        except Exception as e:
            self.logger.debug(f"Native-Java boundary security assessment failed: {e}")
    
    def _assess_boundary_risk(self, content: str, match: str, boundary_type: str) -> str:
        """Assess the risk level of a boundary violation."""
        try:
            # Risk assessment based on boundary type and context
            risk_weights = {
                'privilege_boundary': 'CRITICAL',
                'memory_boundary': 'HIGH',
                'exception_boundary': 'MEDIUM',
                'data_validation': 'HIGH',
                'type_safety_boundary': 'MEDIUM',
                'threading_boundary': 'HIGH',
                'resource_boundary': 'MEDIUM',
                'input_sanitization': 'HIGH'
            }
            
            # Check for additional risk factors
            risk_factors = []
            if 'system' in match.lower() or 'exec' in match.lower():
                risk_factors.append('system_call')
            if 'root' in match.lower() or 'su' in match.lower():
                risk_factors.append('privilege_escalation')
            if 'password' in match.lower() or 'key' in match.lower():
                risk_factors.append('sensitive_data')
            
            base_risk = risk_weights.get(boundary_type, 'LOW')
            
            # Escalate risk if additional factors are present
            if risk_factors:
                if base_risk == 'LOW':
                    base_risk = 'MEDIUM'
                elif base_risk == 'MEDIUM':
                    base_risk = 'HIGH'
                elif base_risk == 'HIGH':
                    base_risk = 'CRITICAL'
            
            return f"{base_risk} ({', '.join(risk_factors)})" if risk_factors else base_risk
            
        except Exception:
            return 'UNKNOWN'
    
    def _analyze_boundary_validation_patterns(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Analyze boundary validation patterns for comprehensive security assessment."""
        try:
            # Look for validation patterns
            validation_patterns = [
                r'(?:if|while|for).*(?:null|NULL|nullptr).*check',
                r'(?:if|while|for).*(?:length|size|count).*[><=]',
                r'(?:if|while|for).*(?:valid|invalid|error)',
                r'(?:assert|verify|validate|check).*\(',
                r'(?:bounds|range|limit).*check'
            ]
            
            validation_count = 0
            for pattern in validation_patterns:
                validation_count += len(re.findall(pattern, content, re.IGNORECASE))
            
            # Calculate validation coverage
            total_jni_calls = len(re.findall(r'(?:Call|Get|Set|New|Find)\w*(?:Method|Field|Class|Object)', content))
            
            if total_jni_calls > 0:
                validation_coverage = (validation_count / total_jni_calls) * 100
                if validation_coverage < 20:  # Less than 20% validation coverage
                    analysis.boundary_violations.append(f"insufficient_validation: {validation_coverage:.1f}% validation coverage")
            
        except Exception as e:
            self.logger.debug(f"Boundary validation analysis failed: {e}")
    
    def _analyze_data_flow_boundaries(self, content: str, analysis: JNISecurityAnalysis) -> None:
        """Analyze data flow across native-Java boundaries."""
        try:
            # Data flow patterns
            data_flow_issues = []
            
            # Input data flow (Java to Native)
            input_patterns = [
                r'GetStringUTFChars.*(?=.*strcpy|strcat|sprintf)',
                r'GetByteArrayElements.*(?=.*memcpy|memmove)',
                r'GetIntField.*(?=.*array.*index)',
                r'CallObjectMethod.*(?=.*cast|convert)'
            ]
            
            for pattern in input_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    data_flow_issues.append(f"unsafe_input_flow: {len(matches)} patterns")
            
            # Output data flow (Native to Java)
            output_patterns = [
                r'NewStringUTF.*(?=.*sensitive|password|key)',
                r'NewByteArray.*(?=.*sensitive|private|key)',
                r'SetObjectField.*(?=.*sensitive|private)',
                r'CallStaticMethod.*(?=.*sensitive|private)'
            ]
            
            for pattern in output_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    data_flow_issues.append(f"sensitive_output_flow: {len(matches)} patterns")
            
            # Add data flow issues to analysis
            analysis.boundary_violations.extend(data_flow_issues)
            
        except Exception as e:
            self.logger.debug(f"Data flow boundary analysis failed: {e}")
    
    def _calculate_jni_security_score(self, analysis: JNISecurityAnalysis) -> float:
        """Calculate JNI security score (0-100 scale)."""
        score = 100.0  # Start with perfect score
        
        # Deduct points for vulnerabilities
        score -= len(analysis.reference_leaks) * 15
        score -= len(analysis.exception_handling_issues) * 10
        score -= len(analysis.unsafe_jni_calls) * 20
        score -= len(analysis.privilege_escalation_risks) * 25
        score -= len(analysis.boundary_violations) * 12
        
        # Deduct points for enhanced analysis findings
        score -= len(analysis.invalid_signatures) * 15
        score -= len(analysis.cross_compilation_issues) * 12
        score -= len(analysis.obfuscation_indicators) * 8
        score -= len(analysis.attack_surface_vectors) * 5
        score -= len(analysis.vulnerability_patterns) * 10
        score -= len(analysis.integrity_violations) * 18
        
        # Bonus points for comprehensive analysis
        if analysis.jni_method_signatures:
            score += 5  # Found JNI methods to analyze
        if analysis.dependency_graph:
            score += 3  # Analyzed dependencies
        if analysis.runtime_monitoring_hooks:
            score += 2  # Generated monitoring hooks
        
        # Ensure score doesn't go below 0
        return max(score, 0.0)
    
    def _determine_jni_risk_level(self, analysis: JNISecurityAnalysis) -> JNISecurityRisk:
        """Determine JNI risk level based on findings."""
        if analysis.security_score >= 80:
            return JNISecurityRisk.NEGLIGIBLE
        elif analysis.security_score >= 60:
            return JNISecurityRisk.LOW
        elif analysis.security_score >= 40:
            return JNISecurityRisk.MEDIUM
        elif analysis.security_score >= 20:
            return JNISecurityRisk.HIGH
        else:
            return JNISecurityRisk.CRITICAL
    
    def _generate_jni_vulnerabilities(self, analysis: JNISecurityAnalysis) -> None:
        """Generate vulnerability objects for JNI security issues."""
        
        # Reference leak vulnerabilities
        if analysis.reference_leaks:
            vuln = NativeBinaryVulnerability(
                id=f"jni_reference_leaks_{analysis.library_name}",
                title="JNI Reference Leaks Detected",
                description=f"Native library contains {len(analysis.reference_leaks)} potential JNI reference leaks",
                severity=VulnerabilitySeverity.HIGH,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.reference_leaks[:5],  # Limit evidence to first 5
                remediation="Ensure all JNI references are properly released (e.g., ReleaseStringUTFChars, DeleteGlobalRef)",
                cwe_id="CWE-401"
            )
            analysis.vulnerabilities.append(vuln)
        
        # Exception handling vulnerabilities
        if analysis.exception_handling_issues:
            vuln = NativeBinaryVulnerability(
                id=f"jni_exception_handling_{analysis.library_name}",
                title="JNI Exception Handling Issues",
                description=f"Native library has {len(analysis.exception_handling_issues)} unchecked JNI exception scenarios",
                severity=VulnerabilitySeverity.MEDIUM,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.exception_handling_issues[:5],
                remediation="Add ExceptionCheck() calls after JNI operations that can throw exceptions",
                cwe_id="CWE-248"
            )
            analysis.vulnerabilities.append(vuln)
        
        # Buffer overflow vulnerabilities
        if analysis.unsafe_jni_calls:
            vuln = NativeBinaryVulnerability(
                id=f"jni_buffer_overflow_{analysis.library_name}",
                title="JNI Buffer Overflow Risks",
                description=f"Native library contains {len(analysis.unsafe_jni_calls)} potential buffer overflow vulnerabilities in JNI code",
                severity=VulnerabilitySeverity.CRITICAL,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.unsafe_jni_calls[:3],
                remediation="Validate buffer sizes and implement bounds checking for all JNI string and array operations",
                cwe_id="CWE-120"
            )
            analysis.vulnerabilities.append(vuln)
        
        # Privilege escalation vulnerabilities
        if analysis.privilege_escalation_risks:
            vuln = NativeBinaryVulnerability(
                id=f"jni_privilege_escalation_{analysis.library_name}",
                title="JNI Privilege Escalation Risks",
                description=f"Native library contains {len(analysis.privilege_escalation_risks)} potential privilege escalation vectors",
                severity=VulnerabilitySeverity.CRITICAL,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.privilege_escalation_risks,
                remediation="Remove or secure privileged operations in native code; use Android security framework",
                cwe_id="CWE-250"
            )
            analysis.vulnerabilities.append(vuln)
        
        # Enhanced JNI analysis vulnerabilities
        if analysis.invalid_signatures:
            vuln = NativeBinaryVulnerability(
                id=f"jni_invalid_signatures_{analysis.library_name}",
                title="Invalid JNI Method Signatures",
                description=f"Native library contains {len(analysis.invalid_signatures)} invalid JNI method signatures",
                severity=VulnerabilitySeverity.HIGH,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.invalid_signatures[:5],
                remediation="Correct JNI method signatures to match Java method declarations",
                cwe_id="CWE-20"
            )
            analysis.vulnerabilities.append(vuln)
        
        if analysis.cross_compilation_issues:
            vuln = NativeBinaryVulnerability(
                id=f"jni_cross_compilation_{analysis.library_name}",
                title="Cross-Compilation Security Issues",
                description=f"Native library has {len(analysis.cross_compilation_issues)} cross-compilation security concerns",
                severity=VulnerabilitySeverity.MEDIUM,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.cross_compilation_issues[:3],
                remediation="Review cross-compilation settings and ensure proper security flags are used",
                cwe_id="CWE-704"
            )
            analysis.vulnerabilities.append(vuln)
        
        if analysis.obfuscation_indicators:
            vuln = NativeBinaryVulnerability(
                id=f"jni_obfuscation_{analysis.library_name}",
                title="Native Code Obfuscation Detected",
                description=f"Native library shows {len(analysis.obfuscation_indicators)} obfuscation indicators",
                severity=VulnerabilitySeverity.MEDIUM,
                masvs_control="MSTG-RESILIENCE-1",
                affected_files=[analysis.library_name],
                evidence=analysis.obfuscation_indicators[:3],
                remediation="Review obfuscated code for security implications and malicious behavior",
                cwe_id="CWE-506"
            )
            analysis.vulnerabilities.append(vuln)
        
        if analysis.attack_surface_vectors:
            vuln = NativeBinaryVulnerability(
                id=f"jni_attack_surface_{analysis.library_name}",
                title="Extensive JNI Attack Surface",
                description=f"Native library exposes {len(analysis.attack_surface_vectors)} attack surface vectors",
                severity=VulnerabilitySeverity.LOW,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.attack_surface_vectors[:5],
                remediation="Minimize exposed JNI functions and validate all input parameters",
                cwe_id="CWE-693"
            )
            analysis.vulnerabilities.append(vuln)
        
        if analysis.vulnerability_patterns:
            vuln = NativeBinaryVulnerability(
                id=f"jni_vulnerability_patterns_{analysis.library_name}",
                title="Native Vulnerability Patterns",
                description=f"Native library contains {len(analysis.vulnerability_patterns)} vulnerability patterns",
                severity=VulnerabilitySeverity.HIGH,
                masvs_control="MSTG-CODE-8",
                affected_files=[analysis.library_name],
                evidence=analysis.vulnerability_patterns[:5],
                remediation="Review and fix identified vulnerability patterns in native code",
                cwe_id="CWE-691"
            )
            analysis.vulnerabilities.append(vuln)
        
        if analysis.integrity_violations:
            vuln = NativeBinaryVulnerability(
                id=f"jni_integrity_violations_{analysis.library_name}",
                title="Native Code Integrity Issues",
                description=f"Native library has {len(analysis.integrity_violations)} integrity violations",
                severity=VulnerabilitySeverity.MEDIUM,
                masvs_control="MSTG-RESILIENCE-1",
                affected_files=[analysis.library_name],
                evidence=analysis.integrity_violations,
                remediation="Ensure binary integrity and review for tampering indicators",
                cwe_id="CWE-345"
            )
            analysis.vulnerabilities.append(vuln) 