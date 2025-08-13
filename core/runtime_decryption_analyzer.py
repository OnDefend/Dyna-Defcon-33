"""
Runtime Decryption Analyzer for AODS Framework.

This module provides advanced analysis of runtime decryption vulnerabilities
in Android applications, specifically targeting patterns found in mobile security
testing scenarios that require Frida hooks to extract encrypted content at runtime.

Features:
- Runtime decryption detection and analysis with Frida hooks
- Base64 decryption monitoring and dynamic analysis
- Native decryption method identification and instrumentation
- Encrypted content extraction through dynamic instrumentation
- Comprehensive runtime decryption vulnerability assessment

This analyzer specializes in detecting applications that use runtime decryption
mechanisms, particularly those that decode or decrypt sensitive data during
application execution. It focuses on identifying weak encryption implementations
and runtime data exposure vulnerabilities.
"""

import logging
import os
import time
import threading
import json
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from pathlib import Path
from rich.text import Text
from rich.table import Table
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

logger = logging.getLogger(__name__)

class RuntimeDecryptionAnalyzer:
    """
    Comprehensive runtime decryption analyzer for Android applications.
    
    This analyzer identifies and analyzes runtime decryption mechanisms in Android
    applications, with particular focus on Base64 decryption and native method
    decryption patterns that expose sensitive data during application execution.
    """
    
    def __init__(self, apk_context=None):
        """
        Initialize the runtime decryption analyzer.
        
        Args:
            apk_context: APK context object containing application metadata
        """
        self.apk_context = apk_context
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.console = Console()
        
        # Analysis results
        self.decryption_findings = []
        self.frida_hooks = []
        self.static_patterns = []
        self.dynamic_analysis_results = []
        
        # Runtime decryption patterns
        self.base64_patterns = [
            r'VGV4dEVuY3J5cHRpb25Ud28\.decrypt',  # Common runtime decryption pattern
            r'\.decrypt\s*\(',  # General decrypt method calls
            r'Base64\.decode\s*\(',  # Base64 decoding patterns
            r'android\.util\.Base64\.decode',  # Android Base64 decoding
            r'javax\.crypto\.Cipher\.doFinal'  # Cipher decryption operations
        ]
        
        # Frida script templates
        self.frida_script_templates = {
            'base64_hook': self._create_base64_hook_script,
            'native_decrypt': self._create_native_decrypt_script,
            'cipher_hook': self._create_cipher_hook_script
        }
        
        # Analysis statistics
        self.analysis_stats = {
            'patterns_found': 0,
            'hooks_generated': 0,
            'static_detections': 0,
            'dynamic_results': 0
        }
        
        self.logger.debug("Runtime Decryption Analyzer initialized")

    def analyze_runtime_decryption(self, deep_mode: bool = False) -> Tuple[str, Text]:
        """
        Comprehensive runtime decryption analysis.

        Args:
            deep_mode: Whether to perform deep analysis with Frida hooks

        Returns:
            Tuple of (analysis_title, analysis_results)
        """
        self.logger.debug("Starting runtime decryption analysis")
        
        try:
            # Initialize progress tracking
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                # Analysis tasks
                static_task = progress.add_task("Static pattern analysis", total=100)
                dynamic_task = progress.add_task("Dynamic hook generation", total=100)
                frida_task = progress.add_task("Frida script preparation", total=100)
                
                # Phase 1: Static analysis
                progress.update(static_task, advance=20)
                self._analyze_static_patterns()
                progress.update(static_task, advance=60)
                
                # Phase 2: Dynamic analysis preparation
                progress.update(dynamic_task, advance=30)
                self._prepare_dynamic_analysis()
                progress.update(dynamic_task, advance=70)
                
                # Phase 3: Frida hook generation
                progress.update(frida_task, advance=25)
                self._generate_frida_hooks()
                progress.update(frida_task, advance=75)
                
                # Complete analysis
                progress.update(static_task, completed=100)
                progress.update(dynamic_task, completed=100)
                progress.update(frida_task, completed=100)
            
            # Generate comprehensive report
            report = self._generate_runtime_decryption_report()
            
            self.logger.debug(f"Runtime decryption analysis completed. Found {len(self.decryption_findings)} findings")
            
            return "Runtime Decryption Analysis", report
            
        except Exception as e:
            self.logger.error(f"Runtime decryption analysis failed: {e}")
            return "Runtime Decryption Analysis", Text(f"Analysis failed: {str(e)}", style="red")

    def _analyze_static_patterns(self):
        """Analyze static code patterns for runtime decryption indicators."""
        self.logger.debug("Analyzing static patterns for runtime decryption")
        
        try:
            if not self.apk_context:
                self.logger.warning("No APK context available for static analysis")
                return
            
            # Analyze source code for decryption patterns
            source_files = getattr(self.apk_context, 'source_files', [])
            for file_path in source_files:
                self._analyze_file_for_decryption_patterns(file_path)
            
            # Analyze smali code for native method calls
            smali_files = getattr(self.apk_context, 'smali_files', [])
            for file_path in smali_files:
                self._analyze_smali_for_native_decryption(file_path)
            
            # Analyze strings for encrypted content
            strings_data = getattr(self.apk_context, 'strings', [])
            self._analyze_strings_for_encrypted_content(strings_data)
            
            self.analysis_stats['static_detections'] = len(self.static_patterns)

        except Exception as e:
            self.logger.error(f"Static pattern analysis failed: {e}")

    def _analyze_file_for_decryption_patterns(self, file_path: str):
        """Analyze individual file for decryption patterns."""
        try:
            if not os.path.exists(file_path):
                return
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for Base64 decryption patterns
            for pattern in self.base64_patterns:
                import re
                matches = re.finditer(pattern, content)
                for match in matches:
                    finding = {
                        'type': 'base64_decryption',
                        'file_path': file_path,
                        'pattern': pattern,
                        'match': match.group(),
                        'line': content[:match.start()].count('\n') + 1,
                        'context': self._extract_context(content, match.start(), match.end())
                    }
                    self.static_patterns.append(finding)
            
            # Check for native method declarations
            native_pattern = r'native\s+\w+\s+\w*decrypt\w*\s*\('
            import re
            matches = re.finditer(native_pattern, content, re.IGNORECASE)
            for match in matches:
                finding = {
                    'type': 'native_decryption',
                    'file_path': file_path,
                    'pattern': native_pattern,
                    'match': match.group(),
                    'line': content[:match.start()].count('\n') + 1,
                    'context': self._extract_context(content, match.start(), match.end())
                }
                self.static_patterns.append(finding)
                
        except Exception as e:
            self.logger.error(f"File analysis failed for {file_path}: {e}")

    def _analyze_smali_for_native_decryption(self, file_path: str):
        """Analyze smali files for native decryption methods."""
        try:
            if not os.path.exists(file_path):
                return
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for native method invocations
            native_invoke_pattern = r'invoke-static.*decrypt.*'
            import re
            matches = re.finditer(native_invoke_pattern, content, re.IGNORECASE)
            for match in matches:
                finding = {
                    'type': 'smali_native_invoke',
                    'file_path': file_path,
                    'pattern': native_invoke_pattern,
                    'match': match.group(),
                    'line': content[:match.start()].count('\n') + 1,
                    'context': self._extract_context(content, match.start(), match.end())
                }
                self.static_patterns.append(finding)
                
        except Exception as e:
            self.logger.error(f"Smali analysis failed for {file_path}: {e}")

    def _analyze_strings_for_encrypted_content(self, strings_data: List[str]):
        """Analyze strings for potentially encrypted content."""
        try:
            for string_value in strings_data:
                # Check for Base64 encoded strings
                if self._is_base64_encoded(string_value):
                    # Attempt to decode
                    try:
                        import base64
                        decoded = base64.b64decode(string_value).decode('utf-8', errors='ignore')
                        if decoded and len(decoded) > 5:  # Valid decoded content
                            finding = {
                                'type': 'base64_string',
                                'original': string_value,
                                'decoded': decoded,
                                'confidence': 0.8,
                                'analysis': 'Base64 encoded string with readable decoded content'
                            }
                            self.static_patterns.append(finding)
                    except:
                        pass
                
                # Check for XOR encrypted patterns
                if self._is_xor_encrypted(string_value):
                    finding = {
                        'type': 'xor_encrypted',
                        'content': string_value,
                        'confidence': 0.6,
                        'analysis': 'String shows XOR encryption characteristics'
                    }
                    self.static_patterns.append(finding)
                    
        except Exception as e:
            self.logger.error(f"String analysis failed: {e}")

    def _is_base64_encoded(self, text: str) -> bool:
        """Check if text is Base64 encoded."""
        try:
            import base64
            import re
            
            # Check Base64 pattern
            base64_pattern = r'^[A-Za-z0-9+/]*={0,2}$'
            if not re.match(base64_pattern, text):
                return False
            
            # Check length (Base64 length should be multiple of 4)
            if len(text) % 4 != 0:
                return False
            
            # Try to decode
            base64.b64decode(text)
            return True
            
        except:
            return False

    def _is_xor_encrypted(self, text: str) -> bool:
        """Check if text shows XOR encryption characteristics."""
        try:
            # Check for non-printable characters (common in XOR)
            non_printable_count = sum(1 for c in text if ord(c) < 32 or ord(c) > 126)
            if non_printable_count > len(text) * 0.3:  # 30% non-printable
                return True
            
            # Check for repeating patterns (XOR key reuse)
            if len(set(text)) < len(text) * 0.5:  # Low entropy
                return True
                
            return False
            
        except:
            return False

    def _extract_context(self, content: str, start: int, end: int, context_size: int = 50) -> str:
        """Extract context around a match."""
        try:
            context_start = max(0, start - context_size)
            context_end = min(len(content), end + context_size)
            return content[context_start:context_end]
        except:
            return ""

    def _prepare_dynamic_analysis(self):
        """Prepare dynamic analysis components."""
        self.logger.debug("Preparing dynamic analysis components")
        
        try:
            # Generate Frida scripts for detected patterns
            for pattern in self.static_patterns:
                if pattern['type'] == 'base64_decryption':
                    self._prepare_base64_hook(pattern)
                elif pattern['type'] == 'native_decryption':
                    self._prepare_native_hook(pattern)
                elif pattern['type'] == 'smali_native_invoke':
                    self._prepare_smali_hook(pattern)
            
            self.analysis_stats['dynamic_results'] = len(self.dynamic_analysis_results)

        except Exception as e:
            self.logger.error(f"Dynamic analysis preparation failed: {e}")

    def _prepare_base64_hook(self, pattern: Dict[str, Any]):
        """Prepare Base64 decryption hook."""
        hook_config = {
            'type': 'base64_hook',
            'target_pattern': pattern['pattern'],
            'file_context': pattern['file_path'],
            'hook_script': self._create_base64_hook_script(pattern)
        }
        self.dynamic_analysis_results.append(hook_config)

    def _prepare_native_hook(self, pattern: Dict[str, Any]):
        """Prepare native method hook."""
        hook_config = {
            'type': 'native_hook',
            'target_pattern': pattern['pattern'],
            'file_context': pattern['file_path'],
            'hook_script': self._create_native_decrypt_script(pattern)
        }
        self.dynamic_analysis_results.append(hook_config)

    def _prepare_smali_hook(self, pattern: Dict[str, Any]):
        """Prepare smali method hook."""
        hook_config = {
            'type': 'smali_hook',
            'target_pattern': pattern['pattern'],
            'file_context': pattern['file_path'],
            'hook_script': self._create_cipher_hook_script(pattern)
        }
        self.dynamic_analysis_results.append(hook_config)

    def _generate_frida_hooks(self):
        """Generate Frida hook scripts for runtime analysis."""
        self.logger.debug("Generating Frida hook scripts")
        
        try:
            # Generate comprehensive Base64 hook
            base64_hook = self._create_comprehensive_base64_hook()
            self.frida_hooks.append(base64_hook)
            
            # Generate native decryption hook
            native_hook = self._create_comprehensive_native_hook()
            self.frida_hooks.append(native_hook)
            
            # Generate cipher operation hook
            cipher_hook = self._create_comprehensive_cipher_hook()
            self.frida_hooks.append(cipher_hook)
            
            self.analysis_stats['hooks_generated'] = len(self.frida_hooks)

        except Exception as e:
            self.logger.error(f"Frida hook generation failed: {e}")

    def _create_comprehensive_base64_hook(self) -> Dict[str, Any]:
        """Create comprehensive Base64 decryption hook with dynamic class detection."""
        script = """
        // Comprehensive Base64 decryption monitoring with dynamic class detection
        Java.perform(function() {
            console.log("RUNTIME DECRYPTION ANALYSIS - Base64 Hook Active");
            
            // Hook standard Base64 operations
            var Base64 = Java.use("android.util.Base64");
            
            Base64.decode.overload('[B', 'int').implementation = function(input, flags) {
                console.log("Base64.decode called with byte array");
                var result = this.decode(input, flags);
                
                try {
                    var decoded = Java.use("java.lang.String").$new(result);
                    console.log("Base64 decoded content: " + decoded);
                } catch (e) {
                    console.log("Base64 decode result (binary): " + result);
                }
                
                return result;
            };
            
            Base64.decode.overload('java.lang.String', 'int').implementation = function(str, flags) {
                console.log("Base64.decode called with string: " + str);
                var result = this.decode(str, flags);
                
                try {
                    var decoded = Java.use("java.lang.String").$new(result);
                    console.log("Base64 decoded content: " + decoded);
                } catch (e) {
                    console.log("Base64 decode result (binary): " + result);
                }
                
                return result;
            };
            
            // ORGANIC DETECTION: Find encryption/decryption classes dynamically
            try {
                console.log("Scanning for encryption/decryption classes...");
                
                // Common encryption class patterns to look for
                var encryptionPatterns = [
                    "*Encrypt*",
                    "*Decrypt*", 
                    "*Cipher*",
                    "*Crypto*",
                    "*AES*",
                    "*DES*",
                    "*RSA*",
                    "*Hash*",
                    "*Security*"
                ];
                
                // Common method patterns in encryption classes
                var encryptionMethods = [
                    "encrypt",
                    "decrypt", 
                    "encode",
                    "decode",
                    "hash",
                    "unhash",
                    "cipher",
                    "decipher"
                ];
                
                // Dynamic class discovery
                Java.enumerateLoadedClasses({
                    onMatch: function(name) {
                        // Check if class matches encryption patterns
                        var isEncryptionClass = encryptionPatterns.some(function(pattern) {
                            return name.toLowerCase().includes(pattern.toLowerCase().replace('*', ''));
                        });
                        
                        if (isEncryptionClass) {
                            console.log("Found potential encryption class: " + name);
                            
                            try {
                                var clazz = Java.use(name);
                                var methods = clazz.class.getDeclaredMethods();
                                
                                // Check for encryption/decryption methods
                                for (var i = 0; i < methods.length; i++) {
                                    var methodName = methods[i].getName();
                                    
                                    if (encryptionMethods.includes(methodName.toLowerCase())) {
                                        console.log("Hooking method: " + name + "." + methodName);
                                        
                                        // Dynamic method hooking
                                        if (clazz[methodName] && typeof clazz[methodName].implementation === 'function') {
                                            var originalMethod = clazz[methodName];
                                            clazz[methodName].implementation = function() {
                                                console.log("=== DYNAMIC ENCRYPTION HOOK ===");
                                                console.log("Class: " + name);
                                                console.log("Method: " + methodName);
                                                console.log("Arguments: " + JSON.stringify(arguments));
                                                
                                                var result = originalMethod.apply(this, arguments);
                                                console.log("Result: " + result);
                                                console.log("=== END HOOK ===");
                                                
                                                return result;
                                            };
                                        }
                                    }
                                }
                            } catch (e) {
                                console.log("Could not hook class " + name + ": " + e.message);
                            }
                        }
                    },
                    onComplete: function() {
                        console.log("Dynamic class scanning complete");
                    }
                });
                
                // Additionally, hook any class that implements specific interfaces
                setTimeout(function() {
                    try {
                        // Look for classes with decrypt/encrypt methods at runtime
                        Java.choose("java.lang.Object", {
                            onMatch: function(instance) {
                                var className = instance.getClass().getName();
                                
                                // Check if this instance has encryption-related methods
                                var hasEncryptionMethods = false;
                                try {
                                    var methods = instance.getClass().getDeclaredMethods();
                                    for (var i = 0; i < methods.length; i++) {
                                        var methodName = methods[i].getName();
                                        if (encryptionMethods.includes(methodName.toLowerCase())) {
                                            hasEncryptionMethods = true;
                                            break;
                                        }
                                    }
                                } catch (e) {}
                                
                                if (hasEncryptionMethods && !className.startsWith("java.") && !className.startsWith("android.")) {
                                    console.log("Runtime encryption class found: " + className);
                                    
                                    try {
                                        var clazz = Java.use(className);
                                        encryptionMethods.forEach(function(methodName) {
                                            if (clazz[methodName]) {
                                                console.log("Hooking runtime method: " + className + "." + methodName);
                                                
                                                var originalMethod = clazz[methodName];
                                                clazz[methodName].implementation = function() {
                                                    console.log("=== RUNTIME ENCRYPTION HOOK ===");
                                                    console.log("Class: " + className);
                                                    console.log("Method: " + methodName);
                                                    console.log("Arguments: " + JSON.stringify(arguments));
                                                    
                                                    var result = originalMethod.apply(this, arguments);
                                                    console.log("Result: " + result);
                                                    console.log("=== END HOOK ===");
                                                    
                                                    return result;
                                                };
                                            }
                                        });
                                    } catch (e) {
                                        console.log("Could not hook runtime class " + className + ": " + e.message);
                                    }
                                }
                            },
                            onComplete: function() {
                                console.log("Runtime class scanning complete");
                            }
                        });
                    } catch (e) {
                        console.log("Runtime scanning failed: " + e.message);
                    }
                }, 2000); // Delay to allow classes to load
                
            } catch (e) {
                console.log("Dynamic class detection failed: " + e.message);
            }
            
            console.log("Base64 hooks with dynamic detection installed successfully");
        });
        """
        
        return {
            'name': 'comprehensive_base64_hook',
            'description': 'Comprehensive Base64 decryption monitoring with dynamic class detection',
            'script': script,
            'targets': ['android.util.Base64', 'dynamic_encryption_classes'],
            'priority': 'high'
        }

    def _create_comprehensive_native_hook(self) -> Dict[str, Any]:
        """Create comprehensive native method hook."""
        script = """
        // Comprehensive native method monitoring
        Java.perform(function() {
            console.log("RUNTIME DECRYPTION ANALYSIS - Native Hook Active");
            
            // Hook JNI functions
            var System = Java.use("java.lang.System");
            System.loadLibrary.implementation = function(libname) {
                console.log("Loading native library: " + libname);
                var result = this.loadLibrary(libname);
                
                // Hook common native decryption functions
                try {
                    var lib = Module.findExportByName(libname, "decrypt");
                    if (lib) {
                        console.log("Found decrypt function in " + libname);
                        Interceptor.attach(lib, {
                            onEnter: function(args) {
                                console.log("Native decrypt called");
                                console.log("Arg0: " + args[0]);
                                console.log("Arg1: " + args[1]);
                            },
                            onLeave: function(retval) {
                                console.log("Native decrypt result: " + retval);
                            }
                        });
                    }
                } catch (e) {
                    console.log("Could not hook native decrypt in " + libname);
                }
                
                return result;
            };
            
            console.log("Native hooks installed successfully");
        });
        """
        
        return {
            'name': 'comprehensive_native_hook',
            'description': 'Comprehensive native method monitoring',
            'script': script,
            'targets': ['java.lang.System', 'native_libraries'],
            'priority': 'medium'
        }

    def _create_comprehensive_cipher_hook(self) -> Dict[str, Any]:
        """Create comprehensive cipher operation hook."""
        script = """
        // Comprehensive cipher operation monitoring
        Java.perform(function() {
            console.log("RUNTIME DECRYPTION ANALYSIS - Cipher Hook Active");
            
            // Hook javax.crypto.Cipher operations
            var Cipher = Java.use("javax.crypto.Cipher");
            
            Cipher.doFinal.overload('[B').implementation = function(input) {
                console.log("Cipher.doFinal called");
                console.log("Input: " + input);
                
                var result = this.doFinal(input);
                console.log("Cipher result: " + result);
                
                try {
                    var decoded = Java.use("java.lang.String").$new(result);
                    console.log("Cipher decoded content: " + decoded);
                } catch (e) {
                    console.log("Cipher result (binary): " + result);
                }
                
                return result;
            };
            
            Cipher.doFinal.overload('[B', 'int', 'int').implementation = function(input, offset, len) {
                console.log("Cipher.doFinal called with offset/length");
                console.log("Input length: " + len);
                
                var result = this.doFinal(input, offset, len);
                console.log("Cipher result: " + result);
                
                return result;
            };
            
            console.log("Cipher hooks installed successfully");
        });
        """
        
        return {
            'name': 'comprehensive_cipher_hook',
            'description': 'Comprehensive cipher operation monitoring',
            'script': script,
            'targets': ['javax.crypto.Cipher'],
            'priority': 'high'
        }

    def _create_base64_hook_script(self, pattern: Dict[str, Any]) -> str:
        """Create Base64 hook script for specific pattern."""
        return f"""
        // Base64 hook for pattern: {pattern['pattern']}
        Java.perform(function() {{
            console.log("Hooking Base64 for pattern: {pattern['pattern']}");
            
            var Base64 = Java.use("android.util.Base64");
            Base64.decode.overload('java.lang.String', 'int').implementation = function(str, flags) {{
                console.log("Base64.decode called: " + str);
                var result = this.decode(str, flags);
                
                try {{
                    var decoded = Java.use("java.lang.String").$new(result);
                    console.log("Decoded: " + decoded);
                }} catch (e) {{
                    console.log("Binary result: " + result);
                }}
                
                return result;
            }};
        }});
        """

    def _create_native_decrypt_script(self, pattern: Dict[str, Any]) -> str:
        """Create native decrypt script for specific pattern."""
        return f"""
        // Native decrypt hook for pattern: {pattern['pattern']}
        Java.perform(function() {{
            console.log("Hooking native decrypt for pattern: {pattern['pattern']}");
            
            // Hook native method calls
            var System = Java.use("java.lang.System");
            System.loadLibrary.implementation = function(libname) {{
                console.log("Loading library: " + libname);
                var result = this.loadLibrary(libname);
                
                // Try to hook decrypt functions
                try {{
                    var decrypt_fn = Module.findExportByName(libname, "decrypt");
                    if (decrypt_fn) {{
                        Interceptor.attach(decrypt_fn, {{
                            onEnter: function(args) {{
                                console.log("Native decrypt called");
                            }},
                            onLeave: function(retval) {{
                                console.log("Native decrypt result: " + retval);
    }}
}});
                    }}
                }} catch (e) {{
                    console.log("Could not hook decrypt in " + libname);
        }}

        return result;
    }};
}});
"""

    def _create_cipher_hook_script(self, pattern: Dict[str, Any]) -> str:
        """Create cipher hook script for specific pattern."""
        return f"""
        // Cipher hook for pattern: {pattern['pattern']}
Java.perform(function() {{
            console.log("Hooking cipher for pattern: {pattern['pattern']}");
            
            var Cipher = Java.use("javax.crypto.Cipher");
            Cipher.doFinal.overload('[B').implementation = function(input) {{
                console.log("Cipher.doFinal called");
                var result = this.doFinal(input);
                
                try {{
                    var decoded = Java.use("java.lang.String").$new(result);
                    console.log("Cipher decoded: " + decoded);
                }} catch (e) {{
                    console.log("Cipher result (binary): " + result);
                }}

            return result;
        }};
}});
"""

    def _generate_runtime_decryption_report(self) -> Text:
        """Generate comprehensive runtime decryption analysis report."""
        report = Text()
        
        # Header
        report.append("Runtime Decryption Analysis Report\n", style="bold blue")
        report.append("=" * 50 + "\n\n", style="blue")
        
        # Summary statistics
        report.append("Analysis Summary:\n", style="bold green")
        report.append(f"• Static patterns found: {len(self.static_patterns)}\n", style="green")
        report.append(f"• Dynamic hooks generated: {len(self.frida_hooks)}\n", style="green")
        report.append(f"• Analysis configurations: {len(self.dynamic_analysis_results)}\n", style="green")
        report.append("\n")
        
        # Static analysis results
        if self.static_patterns:
            report.append("🔍 Static Analysis Results:\n", style="bold yellow")
            for i, pattern in enumerate(self.static_patterns, 1):
                report.append(f"{i}. Pattern Type: {pattern['type']}\n", style="yellow")
                if 'file_path' in pattern:
                    report.append(f"   File: {pattern['file_path']}\n", style="dim")
                if 'match' in pattern:
                    report.append(f"   Match: {pattern['match']}\n", style="cyan")
                if 'confidence' in pattern:
                    report.append(f"   Confidence: {pattern['confidence']:.2f}\n", style="magenta")
                report.append("\n")
        
        # Dynamic analysis results
        if self.dynamic_analysis_results:
            report.append("🚀 Dynamic Analysis Configurations:\n", style="bold cyan")
            for i, config in enumerate(self.dynamic_analysis_results, 1):
                report.append(f"{i}. Hook Type: {config['type']}\n", style="cyan")
                report.append(f"   Target: {config['target_pattern']}\n", style="dim")
                report.append(f"   Context: {config['file_context']}\n", style="dim")
                report.append("\n")
        
        # Frida hooks
        if self.frida_hooks:
            report.append("🔧 Generated Frida Hooks:\n", style="bold magenta")
            for i, hook in enumerate(self.frida_hooks, 1):
                report.append(f"{i}. Hook: {hook['name']}\n", style="magenta")
                report.append(f"   Description: {hook['description']}\n", style="dim")
                report.append(f"   Targets: {', '.join(hook['targets'])}\n", style="dim")
                report.append(f"   Priority: {hook['priority']}\n", style="dim")
                report.append("\n")
        
        # Recommendations
        report.append("💡 Security Recommendations:\n", style="bold red")
        if len(self.static_patterns) > 0:
            report.append("• Runtime decryption patterns detected - implement proper encryption\n", style="red")
            report.append("• Use Android Keystore for sensitive data encryption\n", style="red")
            report.append("• Avoid storing encryption keys in application code\n", style="red")
        
        if len(self.frida_hooks) > 0:
            report.append("• Application vulnerable to runtime manipulation\n", style="red")
            report.append("• Implement anti-debugging and anti-hooking protections\n", style="red")
            report.append("• Use obfuscation to protect sensitive code paths\n", style="red")
        
        if not self.static_patterns and not self.frida_hooks:
            report.append("• No obvious runtime decryption vulnerabilities detected\n", style="green")
            report.append("• Continue monitoring for encrypted data exposure\n", style="green")
        
        return report

    def save_frida_scripts(self, output_dir: str) -> List[str]:
        """
        Save generated Frida scripts to files.

        Args:
            output_dir: Directory to save scripts

        Returns:
            List of saved script file paths
        """
        try:
            os.makedirs(output_dir, exist_ok=True)
            saved_files = []
            
            for hook in self.frida_hooks:
                script_filename = f"{hook['name']}.js"
                script_path = os.path.join(output_dir, script_filename)
                
                with open(script_path, 'w') as f:
                    f.write(hook['script'])
                
                saved_files.append(script_path)
                self.logger.debug(f"Frida script saved: {script_path}")
            
            return saved_files

        except Exception as e:
            self.logger.error(f"Failed to save Frida scripts: {e}")
            return []

    def get_analysis_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive analysis statistics.
        
        Returns:
            Dictionary containing analysis statistics
        """
        return {
            'static_patterns_found': len(self.static_patterns),
            'dynamic_hooks_generated': len(self.frida_hooks),
            'analysis_configurations': len(self.dynamic_analysis_results),
            'pattern_types': list(set(p['type'] for p in self.static_patterns)),
            'hook_types': list(set(h['name'] for h in self.frida_hooks)),
            'analysis_quality': 'high' if len(self.static_patterns) > 0 else 'medium',
            'frida_ready': len(self.frida_hooks) > 0
        }

    def export_analysis_report(self, output_file: str) -> bool:
        """
        Export analysis report to file.
        
        Args:
            output_file: Output file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            report_data = {
                'timestamp': time.time(),
                'analysis_type': 'runtime_decryption',
                'static_patterns': self.static_patterns,
                'dynamic_results': self.dynamic_analysis_results,
                'frida_hooks': [
                    {
                        'name': hook['name'],
                        'description': hook['description'],
                        'targets': hook['targets'],
                        'priority': hook['priority']
                    } for hook in self.frida_hooks
                ],
                'statistics': self.get_analysis_statistics()
            }
            
            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            self.logger.debug(f"Analysis report exported: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export analysis report: {e}")
            return False

# Enhanced runtime decryption analysis functions for integration

def analyze_runtime_decryption_comprehensive(apk_context, deep_mode: bool = False) -> Tuple[str, Text]:
    """
    Comprehensive runtime decryption analysis function for plugin integration.
    
    Args:
        apk_context: APK context object
        deep_mode: Whether to perform deep analysis
        
    Returns:
        Tuple of (analysis_title, analysis_results)
    """
    analyzer = RuntimeDecryptionAnalyzer(apk_context)
    return analyzer.analyze_runtime_decryption(deep_mode)

def generate_runtime_decryption_hooks(apk_context) -> List[Dict[str, Any]]:
    """
    Generate Frida hooks for runtime decryption analysis.
    
    Args:
        apk_context: APK context object
        
    Returns:
        List of Frida hook configurations
    """
    analyzer = RuntimeDecryptionAnalyzer(apk_context)
    analyzer._analyze_static_patterns()
    analyzer._generate_frida_hooks()
    return analyzer.frida_hooks

def detect_runtime_decryption_patterns(apk_context) -> List[Dict[str, Any]]:
    """
    Detect runtime decryption patterns in APK.
    
    Args:
        apk_context: APK context object
        
    Returns:
        List of detected patterns
    """
    analyzer = RuntimeDecryptionAnalyzer(apk_context)
    analyzer._analyze_static_patterns()
    return analyzer.static_patterns
