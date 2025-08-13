"""
Pattern Libraries for Code Quality & Injection Analysis Plugin

This module contains comprehensive patterns for detecting various types of
injection vulnerabilities and unsafe coding practices.
"""

from typing import Dict, List
import re

class InjectionPatterns:
    """Comprehensive injection vulnerability patterns"""
    
    @staticmethod
    def get_sql_injection_patterns() -> List[str]:
        """SQL injection vulnerability patterns"""
        return [
            # Raw SQL query construction
            r'query\s*=\s*["\'].*\+.*["\']',
            r'SELECT\s+.*\+.*FROM',
            r'INSERT\s+.*\+.*VALUES',
            r'UPDATE\s+.*\+.*SET',
            r'DELETE\s+.*\+.*WHERE',
            
            # String concatenation with user input
            r'rawQuery\s*\(["\'].*\+',
            r'execSQL\s*\(["\'].*\+',
            r'query\s*\(["\'].*\+',
            
            # Dynamic SQL construction patterns
            r'StringBuilder.*append.*SELECT',
            r'StringBuilder.*append.*INSERT',
            r'StringBuilder.*append.*UPDATE',
            r'StringBuilder.*append.*DELETE',
            r'String\.format.*SELECT.*%s',
            r'String\.format.*INSERT.*%s',
            
            # Vulnerable database methods
            r'db\.rawQuery\s*\(["\'][^"\']*\+',
            r'database\.execSQL\s*\(["\'][^"\']*\+',
            r'\.query\s*\(["\'][^"\']*\+',
            
            # ContentResolver vulnerabilities
            r'contentResolver\.query\s*\([^)]*\+',
            r'getContentResolver\(\)\.query\s*\([^)]*\+',
        ]
    
    @staticmethod
    def get_xss_webview_patterns() -> List[str]:
        """XSS and WebView vulnerability patterns"""
        return [
            # JavaScript execution with user input
            r'loadUrl\s*\(["\']javascript:.*\+',
            r'evaluateJavascript\s*\(["\'].*\+',
            r'loadDataWithBaseURL.*<script>.*\+',
            r'loadData.*<script>.*\+',
            
            # Unsafe WebView settings
            r'setJavaScriptEnabled\s*\(\s*true\s*\)',
            r'setAllowFileAccess\s*\(\s*true\s*\)',
            r'setAllowContentAccess\s*\(\s*true\s*\)',
            r'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)',
            r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)',
            
            # JavaScript interface without proper validation
            r'addJavascriptInterface\s*\(',
            r'@JavascriptInterface',
            
            # HTML content injection
            r'loadData\s*\(["\'].*<.*\+',
            r'loadDataWithBaseURL\s*\([^)]*["\'].*<.*\+',
            
            # URL manipulation
            r'loadUrl\s*\(["\'].*\+.*["\']',
            r'webView\.loadUrl\s*\(["\'].*\+',
        ]
    
    @staticmethod
    def get_code_injection_patterns() -> List[str]:
        """Code injection vulnerability patterns"""
        return [
            # Dynamic class loading
            r'Class\.forName\s*\(["\'].*\+',
            r'ClassLoader\.loadClass\s*\(["\'].*\+',
            r'DexClassLoader\s*\(["\'].*\+',
            r'PathClassLoader\s*\(["\'].*\+',
            
            # Reflection with user input
            r'Method\.invoke\s*\([^)]*\+',
            r'getMethod\s*\(["\'].*\+',
            r'getDeclaredMethod\s*\(["\'].*\+',
            
            # Script execution
            r'ScriptEngine\.eval\s*\(["\'].*\+',
            r'Runtime\.getRuntime\(\)\.exec\s*\(["\'].*\+',
            r'ProcessBuilder\s*\(["\'].*\+',
            
            # JavaScript evaluation
            r'evaluateJavascript\s*\(["\'].*\+',
            r'loadUrl\s*\(["\']javascript:.*\+',
            
            # Dynamic compilation
            r'JavaCompiler\.compile\s*\(["\'].*\+',
            r'ToolProvider\.getSystemJavaCompiler\(\)\.run\s*\([^)]*\+',
        ]
    
    @staticmethod
    def get_object_injection_patterns() -> List[str]:
        """Object injection vulnerability patterns"""
        return [
            # Unsafe deserialization
            r'ObjectInputStream\s*\([^)]*\)\.readObject\s*\(',
            r'readObject\s*\(\s*\)',
            r'ObjectInputStream.*readObject',
            
            # JSON deserialization without validation
            r'Gson\(\)\.fromJson\s*\([^)]*\.class\)',
            r'new\s+Gson\(\)\.fromJson\s*\(',
            r'JsonParser\.parseString\s*\([^)]*\+',
            
            # XML deserialization
            r'XMLDecoder\s*\([^)]*\)\.readObject\s*\(',
            r'XStream\(\)\.fromXML\s*\(',
            r'ObjectInputStream.*XMLDecoder',
            
            # Custom serialization
            r'Serializable.*readObject\s*\(',
            r'readExternal\s*\([^)]*\+',
            r'Externalizable.*readExternal',
            
            # Intent serialization
            r'getSerializableExtra\s*\(["\'].*\+',
            r'putExtra\s*\([^)]*Serializable',
        ]
    
    @staticmethod
    def get_path_traversal_patterns() -> List[str]:
        """Path traversal vulnerability patterns"""
        return [
            # File operations with user input
            r'new\s+File\s*\(["\'].*\+',
            r'File\s*\(["\'].*\+.*["\']',
            r'FileInputStream\s*\(["\'].*\+',
            r'FileOutputStream\s*\(["\'].*\+',
            
            # Path manipulation
            r'Paths\.get\s*\(["\'].*\+',
            r'FileSystems\.getDefault\(\)\.getPath\s*\(["\'].*\+',
            r'\.getCanonicalPath\s*\(\).*\+',
            
            # External storage access
            r'Environment\.getExternalStorageDirectory\(\).*\+',
            r'getExternalFilesDir\s*\([^)]*\).*\+',
            r'openFileOutput\s*\(["\'].*\+',
            
            # Content provider file access
            r'ParcelFileDescriptor\.open\s*\([^)]*\+',
            r'contentResolver\.openInputStream\s*\([^)]*\+',
            
            # ZIP extraction without validation
            r'ZipEntry\.getName\s*\(\).*\+',
            r'ZipInputStream.*\.getNextEntry\s*\(\).*\+',
        ]
    
    @staticmethod
    def get_command_injection_patterns() -> List[str]:
        """Command injection vulnerability patterns"""
        return [
            # Runtime execution
            r'Runtime\.getRuntime\(\)\.exec\s*\(["\'].*\+',
            r'ProcessBuilder\s*\(["\'].*\+.*["\']',
            r'Process\s*=\s*Runtime\.getRuntime\(\)\.exec\s*\(["\'].*\+',
            
            # Shell command construction
            r'sh\s+-c.*\+',
            r'/bin/sh.*\+',
            r'cmd\.exe.*\+',
            
            # System property manipulation
            r'System\.setProperty\s*\(["\'].*\+',
            r'System\.getProperty\s*\(["\'].*\+.*["\']',
            
            # Native method calls
            r'native.*\([^)]*\+[^)]*\)',
            r'JNI.*\([^)]*\+[^)]*\)',
        ]
    
    @staticmethod
    def get_unsafe_patterns() -> Dict[str, List[str]]:
        """Unsafe coding patterns by category"""
        return {
            "weak_crypto": [
                r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
                r'MessageDigest\.getInstance\s*\(\s*["\']SHA1["\']',
                r'Cipher\.getInstance\s*\(\s*["\']DES["\']',
                r'Cipher\.getInstance\s*\(\s*["\']RC4["\']',
                r'new\s+SecureRandom\s*\(\s*\)',  # Without seed
            ],
            
            "insecure_random": [
                r'new\s+Random\s*\(',
                r'Math\.random\s*\(',
                r'System\.currentTimeMillis\s*\(\).*seed',
            ],
            
            "hardcoded_secrets": [
                r'password\s*=\s*["\'][^"\']{8,}["\']',
                r'api_key\s*=\s*["\'][^"\']{10,}["\']',
                r'secret\s*=\s*["\'][^"\']{8,}["\']',
                r'token\s*=\s*["\'][^"\']{10,}["\']',
            ],
            
            "debug_code": [
                r'Log\.d\s*\(',
                r'Log\.v\s*\(',
                r'System\.out\.println\s*\(',
                r'printStackTrace\s*\(\s*\)',
            ],
            
            "unsafe_ssl": [
                r'TrustAllCertificates',
                r'TrustManager\[\]\s*\{\s*new\s+X509TrustManager',
                r'HostnameVerifier\s*\(\s*\)\s*\{\s*return\s+true',
                r'setHostnameVerifier\s*\([^)]*ALLOW_ALL',
            ],
        }

class PatternValidator:
    """Validates and filters pattern matches"""
    
    @staticmethod
    def is_valid_sql_pattern(line: str, pattern: str) -> bool:
        """Validate SQL injection pattern match"""
        # Exclude false positives in comments or test files
        if re.search(r'^\s*//', line) or re.search(r'^\s*\*', line):
            return False
        if 'test' in line.lower() and 'example' in line.lower():
            return False
        return True
    
    @staticmethod
    def is_valid_xss_pattern(line: str, pattern: str) -> bool:
        """Validate XSS pattern match"""
        # Exclude documentation and examples
        if 'example' in line.lower() or 'sample' in line.lower():
            return False
        if re.search(r'^\s*//', line):
            return False
        return True
    
    @staticmethod
    def is_valid_injection_pattern(line: str, pattern: str, vuln_type: str) -> bool:
        """Generic injection pattern validation"""
        # Common false positive filters
        if re.search(r'^\s*/[/*]', line):  # Comments
            return False
        if 'TODO' in line.upper() or 'FIXME' in line.upper():
            return False
        if 'test' in line.lower() and 'mock' in line.lower():
            return False
        
        # Type-specific validation
        if vuln_type == "sql_injection":
            return PatternValidator.is_valid_sql_pattern(line, pattern)
        elif vuln_type == "xss_webview":
            return PatternValidator.is_valid_xss_pattern(line, pattern)
        
        return True

class PatternExtractor:
    """Extracts relevant information from pattern matches"""
    
    @staticmethod
    def extract_sql_query(line: str) -> str:
        """Extract SQL query from line"""
        # Look for SQL keywords and extract the query
        sql_match = re.search(r'["\']([^"\']*(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*)["\']', line, re.IGNORECASE)
        if sql_match:
            return sql_match.group(1)
        return line.strip()
    
    @staticmethod
    def extract_javascript_code(line: str) -> str:
        """Extract JavaScript code from line"""
        js_match = re.search(r'javascript:([^"\']*)', line)
        if js_match:
            return js_match.group(1)
        return line.strip()
    
    @staticmethod
    def extract_file_path(line: str) -> str:
        """Extract file path from line"""
        path_match = re.search(r'["\']([^"\']*(?:/|\\)[^"\']*)["\']', line)
        if path_match:
            return path_match.group(1)
        return line.strip()
    
    @staticmethod
    def extract_class_method(line: str) -> str:
        """Extract class and method from reflection call"""
        method_match = re.search(r'["\']([^"\']*\.[^"\']*)["\']', line)
        if method_match:
            return method_match.group(1)
        return line.strip()
    
    @staticmethod
    def extract_command(line: str) -> str:
        """Extract command from execution line"""
        cmd_match = re.search(r'exec\s*\(\s*["\']([^"\']*)["\']', line)
        if cmd_match:
            return cmd_match.group(1)
        return line.strip()

# Pattern compilation for performance
class CompiledPatterns:
    """Pre-compiled regex patterns for better performance"""
    
    def __init__(self):
        self.sql_patterns = [re.compile(p, re.IGNORECASE) for p in InjectionPatterns.get_sql_injection_patterns()]
        self.xss_patterns = [re.compile(p, re.IGNORECASE) for p in InjectionPatterns.get_xss_webview_patterns()]
        self.code_patterns = [re.compile(p, re.IGNORECASE) for p in InjectionPatterns.get_code_injection_patterns()]
        self.object_patterns = [re.compile(p, re.IGNORECASE) for p in InjectionPatterns.get_object_injection_patterns()]
        self.path_patterns = [re.compile(p, re.IGNORECASE) for p in InjectionPatterns.get_path_traversal_patterns()]
        self.command_patterns = [re.compile(p, re.IGNORECASE) for p in InjectionPatterns.get_command_injection_patterns()]
        
        # Compile unsafe patterns
        self.unsafe_patterns = {}
        for category, patterns in InjectionPatterns.get_unsafe_patterns().items():
            self.unsafe_patterns[category] = [re.compile(p, re.IGNORECASE) for p in patterns]
    
    def get_patterns_for_type(self, vuln_type: str):
        """Get compiled patterns for specific vulnerability type"""
        pattern_map = {
            "sql_injection": self.sql_patterns,
            "xss_webview": self.xss_patterns,
            "code_injection": self.code_patterns,
            "object_injection": self.object_patterns,
            "path_traversal": self.path_patterns,
            "command_injection": self.command_patterns,
        }
        return pattern_map.get(vuln_type, []) 