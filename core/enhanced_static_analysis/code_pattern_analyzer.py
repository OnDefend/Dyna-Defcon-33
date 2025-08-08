#!/usr/bin/env python3
"""
Code Pattern Analyzer

Analyzes source code and bytecode for security vulnerability patterns,
including insecure API usage, hardcoded secrets, and dangerous practices.

This analyzer examines Java source code, Smali bytecode, and other text files
within APK files to identify potential security issues using pattern matching
and contextual analysis.
"""

import re
from typing import List

from .data_structures import SecurityFinding
from .confidence_calculator import StaticAnalysisConfidenceCalculator

class CodePatternAnalyzer:
    """Advanced code pattern analysis for vulnerability detection."""

    def __init__(self):
        """Initialize the code pattern analyzer."""
        
        # Initialize professional confidence calculator
        self.confidence_calculator = StaticAnalysisConfidenceCalculator()

        # SQL Injection patterns
        self.sql_injection_patterns = [
            re.compile(r'execSQL\s*\(\s*["\'].*\+.*["\']', re.MULTILINE | re.DOTALL),
            re.compile(r'rawQuery\s*\(\s*["\'].*\+.*["\']', re.MULTILINE | re.DOTALL),
            re.compile(r'query\s*\([^)]*["\'].*\+.*["\']', re.MULTILINE | re.DOTALL),
        ]

        # XSS patterns in WebViews
        self.xss_patterns = [
            re.compile(r'loadUrl\s*\(\s*["\']javascript:.*\+', re.MULTILINE),
            re.compile(r"evaluateJavascript\s*\([^)]*\+", re.MULTILINE),
            re.compile(r"addJavascriptInterface\s*\(", re.MULTILINE),
        ]

        # Path traversal patterns
        self.path_traversal_patterns = [
            re.compile(r'new\s+File\s*\([^)]*\+', re.MULTILINE),
            re.compile(r'openFileOutput\s*\([^)]*\+', re.MULTILINE),
            re.compile(r'FileInputStream\s*\([^)]*\+', re.MULTILINE),
        ]

        # Command injection patterns
        self.command_injection_patterns = [
            re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+', re.MULTILINE),
            re.compile(r'ProcessBuilder\s*\([^)]*\+', re.MULTILINE),
            re.compile(r'getRuntime\(\)\.exec\s*\([^)]*\+', re.MULTILINE),
        ]

        # Crypto misuse patterns
        self.crypto_misuse_patterns = [
            re.compile(r'DES|TripleDES|DESede', re.IGNORECASE),
            re.compile(r'MD5|SHA1(?!28)', re.IGNORECASE), 
            re.compile(r'AES(?!/GCM|/CBC)', re.IGNORECASE),
            re.compile(r'Cipher\.getInstance\s*\([^)]*"[^"]*"[^)]*\)', re.MULTILINE),
        ]

        # Insecure storage patterns
        self.storage_patterns = [
            re.compile(r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE', re.IGNORECASE),
            re.compile(r'getSharedPreferences\s*\([^)]*MODE_WORLD', re.MULTILINE),
            re.compile(r'openFileOutput\s*\([^)]*MODE_WORLD', re.MULTILINE),
        ]

    def analyze_code(self, code: str, file_path: str) -> List[SecurityFinding]:
        """Analyze code for security vulnerabilities."""
        findings = []
        
        # Run all vulnerability checks
        findings.extend(self._check_sql_injection(code, file_path))
        findings.extend(self._check_xss_vulnerabilities(code, file_path))
        findings.extend(self._check_path_traversal(code, file_path))
        findings.extend(self._check_command_injection(code, file_path))
        findings.extend(self._check_crypto_misuse(code, file_path))
        findings.extend(self._check_insecure_storage(code, file_path))
        
        return findings

    def _check_sql_injection(self, code: str, file_path: str) -> List[SecurityFinding]:
        """Check for SQL injection vulnerabilities."""
        findings = []
        
        for pattern in self.sql_injection_patterns:
            matches = pattern.finditer(code)
            for match in matches:
                # Calculate professional confidence
                confidence = self.confidence_calculator.calculate_static_analysis_confidence(
                    pattern_type="sql_injection",
                    severity="HIGH",
                    context=match.group(0),
                    file_path=file_path,
                    code_snippet=match.group(0),
                    evidence=[f"Pattern found: {match.group(0)}"]
                )
                
                findings.append(
                    SecurityFinding(
                        finding_id="SQLI-001",
                        title="Potential SQL Injection Vulnerability",
                        description="Code appears to construct SQL queries using string concatenation, which may lead to SQL injection vulnerabilities.",
                        severity="HIGH",
                        category="INJECTION",
                        confidence=confidence,
                        file_path=file_path,
                        code_snippet=match.group(0),
                        evidence=[f"Pattern found: {match.group(0)}"],
                        recommendations=[
                            "Use parameterized queries or prepared statements",
                            "Validate and sanitize all user inputs",
                            "Use SQLiteDatabase.query() with selection arguments",
                        ],
                        cwe_ids=["CWE-89"],
                        owasp_refs=["A3:2021-Injection"],
                    )
                )

        return findings

    def _check_xss_vulnerabilities(self, code: str, file_path: str) -> List[SecurityFinding]:
        """Check for XSS vulnerabilities in WebViews."""
        findings = []

        for pattern in self.xss_patterns:
            matches = pattern.finditer(code)
            for match in matches:
                # Calculate professional confidence
                confidence = self.confidence_calculator.calculate_static_analysis_confidence(
                    pattern_type="xss_vulnerabilities",
                    severity="HIGH",
                    context=match.group(0),
                    file_path=file_path,
                    code_snippet=match.group(0),
                    evidence=[f"Pattern found: {match.group(0)}"]
                )
                
                findings.append(
                    SecurityFinding(
                        finding_id="XSS-001",
                        title="Potential XSS Vulnerability in WebView",
                        description="WebView code appears to execute JavaScript with user-controlled input, which may lead to XSS vulnerabilities.",
                        severity="HIGH",
                        category="XSS",
                        confidence=confidence,
                        file_path=file_path,
                        code_snippet=match.group(0),
                        evidence=[f"Pattern found: {match.group(0)}"],
                        recommendations=[
                            "Disable JavaScript if not required",
                            "Sanitize all inputs before executing JavaScript",
                            "Use Content Security Policy (CSP)",
                            "Validate URLs before loading",
                        ],
                        cwe_ids=["CWE-79"],
                        owasp_refs=["A7:2021-Cross-site Scripting"],
                    )
                )

        return findings

    def _check_path_traversal(self, code: str, file_path: str) -> List[SecurityFinding]:
        """Check for path traversal vulnerabilities."""
        findings = []

        for pattern in self.path_traversal_patterns:
            matches = pattern.finditer(code)
            for match in matches:
                # Calculate professional confidence
                confidence = self.confidence_calculator.calculate_static_analysis_confidence(
                    pattern_type="path_traversal",
                    severity="MEDIUM",
                    context=match.group(0),
                    file_path=file_path,
                    code_snippet=match.group(0),
                    evidence=[f"Pattern found: {match.group(0)}"]
                )
                
                findings.append(
                    SecurityFinding(
                        finding_id="PATH-001",
                        title="Potential Path Traversal Vulnerability",
                        description="Code appears to construct file paths using user input, which may lead to path traversal vulnerabilities.",
                        severity="MEDIUM",
                        category="PATH_TRAVERSAL",
                        confidence=confidence,
                        file_path=file_path,
                        code_snippet=match.group(0),
                        evidence=[f"Pattern found: {match.group(0)}"],
                        recommendations=[
                            "Validate and sanitize file paths",
                            "Use canonical paths and check bounds",
                            "Implement whitelist of allowed files/directories",
                            "Use Path.normalize() and validate results",
                        ],
                        cwe_ids=["CWE-22"],
                        owasp_refs=["A1:2021-Broken Access Control"],
                    )
                )

        return findings

    def _check_command_injection(self, code: str, file_path: str) -> List[SecurityFinding]:
        """Check for command injection vulnerabilities."""
        findings = []

        for pattern in self.command_injection_patterns:
            matches = pattern.finditer(code)
            for match in matches:
                # Calculate professional confidence
                confidence = self.confidence_calculator.calculate_static_analysis_confidence(
                    pattern_type="command_injection",
                    severity="CRITICAL",
                    context=match.group(0),
                    file_path=file_path,
                    code_snippet=match.group(0),
                    evidence=[f"Pattern found: {match.group(0)}"]
                )
                
                findings.append(
                    SecurityFinding(
                        finding_id="CMD-001",
                        title="Potential Command Injection Vulnerability",
                        description="Code appears to execute system commands with user input, which may lead to command injection vulnerabilities.",
                        severity="CRITICAL",
                        category="INJECTION",
                        confidence=confidence,
                        file_path=file_path,
                        code_snippet=match.group(0),
                        evidence=[f"Pattern found: {match.group(0)}"],
                        recommendations=[
                            "Avoid executing system commands if possible",
                            "Use parameterized command execution",
                            "Validate and sanitize all inputs",
                            "Use whitelisting for allowed commands",
                        ],
                        cwe_ids=["CWE-78"],
                        owasp_refs=["A3:2021-Injection"],
                    )
                )

        return findings

    def _check_crypto_misuse(self, code: str, file_path: str) -> List[SecurityFinding]:
        """Check for cryptographic misuse patterns."""
        findings = []

        for pattern in self.crypto_misuse_patterns:
            matches = pattern.finditer(code)
            for match in matches:
                snippet = match.group(0)

                if "DES" in snippet:
                    severity = "HIGH"
                    title = "Weak Encryption Algorithm (DES)"
                    description = "DES encryption is cryptographically weak and should not be used."
                elif "MD5" in snippet or "SHA1" in snippet:
                    severity = "MEDIUM"
                    title = "Weak Hash Algorithm"
                    description = (
                        "MD5 and SHA1 are cryptographically weak for security purposes."
                    )
                elif "AES" in snippet and (
                    "CBC" not in snippet and "GCM" not in snippet
                ):
                    severity = "MEDIUM"
                    title = "Incomplete AES Configuration"
                    description = (
                        "AES cipher should specify mode and padding explicitly."
                    )
                else:
                    severity = "LOW"
                    title = "Cryptographic Implementation Review Required"
                    description = (
                        "Cryptographic implementation should be reviewed for security."
                    )

                # Calculate professional confidence
                confidence = self.confidence_calculator.calculate_static_analysis_confidence(
                    pattern_type="crypto_misuse",
                    severity=severity,
                    context=snippet,
                    file_path=file_path,
                    code_snippet=snippet,
                    evidence=[f"Pattern found: {snippet}"]
                )

                findings.append(
                    SecurityFinding(
                        finding_id="CRYPTO-001",
                        title=title,
                        description=description,
                        severity=severity,
                        category="CRYPTOGRAPHY",
                        confidence=confidence,
                        file_path=file_path,
                        code_snippet=snippet,
                        evidence=[f"Pattern found: {snippet}"],
                        recommendations=[
                            "Use strong encryption algorithms (AES-256)",
                            "Specify secure modes (GCM, CBC with HMAC)",
                            "Use strong hash algorithms (SHA-256, SHA-3)",
                            "Use SecureRandom with proper seeding",
                        ],
                        cwe_ids=["CWE-327", "CWE-328"],
                        owasp_refs=["A2:2021-Cryptographic Failures"],
                    )
                )

        return findings

    def _check_insecure_storage(self, code: str, file_path: str) -> List[SecurityFinding]:
        """Check for insecure storage patterns."""
        findings = []

        for pattern in self.storage_patterns:
            matches = pattern.finditer(code)
            for match in matches:
                # Calculate professional confidence
                confidence = self.confidence_calculator.calculate_static_analysis_confidence(
                    pattern_type="insecure_storage",
                    severity="HIGH",
                    context=match.group(0),
                    file_path=file_path,
                    code_snippet=match.group(0),
                    evidence=[f"Pattern found: {match.group(0)}"]
                )
                
                findings.append(
                    SecurityFinding(
                        finding_id="STORAGE-001",
                        title="Insecure File Storage Mode",
                        description="File is created with world-readable or world-writable permissions, which may expose sensitive data.",
                        severity="HIGH",
                        category="STORAGE",
                        confidence=confidence,
                        file_path=file_path,
                        code_snippet=match.group(0),
                        evidence=[f"Pattern found: {match.group(0)}"],
                        recommendations=[
                            "Use MODE_PRIVATE for sensitive files",
                            "Encrypt sensitive data before storage",
                            "Implement proper access controls",
                            "Use Android Keystore for sensitive keys",
                        ],
                        cwe_ids=["CWE-200"],
                        owasp_refs=["A1:2021-Broken Access Control"],
                    )
                )

        return findings

# Export the analyzer
__all__ = ['CodePatternAnalyzer'] 