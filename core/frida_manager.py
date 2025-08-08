"""
Frida Integration Framework for Dynamic Android Security Testing.

This module provides comprehensive Frida-based dynamic analysis capabilities for Android
applications, including SSL pinning bypass, WebView testing, anti-Frida detection,
and runtime security analysis as required by MASVS standards.
"""

import json
import logging
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any

from rich.text import Text

# Enhanced imports for Flutter integration
try:
    from .flutter_analyzer import FlutterSecurityAnalyzer, FlutterArchitectureInfo, FlutterSSLBypassCapability
    FLUTTER_ANALYZER_AVAILABLE = True
except ImportError:
    FLUTTER_ANALYZER_AVAILABLE = False
    logging.warning("Flutter analyzer not available for Frida integration")

class FridaManager:
    """
    Advanced Frida Manager with enhanced Flutter SSL bypass capabilities.
    
    This manager provides comprehensive dynamic analysis capabilities including:
    - Traditional Android SSL pinning bypass
    - Architecture-aware Flutter SSL bypass
    - WebView security testing
    - Anti-Frida detection bypass
    - Advanced memory scanning and pattern matching
    - BoringSSL-specific hooks for Flutter applications
    """

    def __init__(self):
        self.device = None
        self.session = None
        self.scripts = {}
        self.analysis_results = {}
        self.is_available = False
        self.connection_timeout = 30
        self.analysis_duration = 60
        
        # Enhanced Flutter capabilities
        self.flutter_analyzer = FlutterSecurityAnalyzer() if FLUTTER_ANALYZER_AVAILABLE else None
        self.flutter_architecture_info: Optional[FlutterArchitectureInfo] = None
        self.flutter_bypass_capabilities: List[FlutterSSLBypassCapability] = []
        self.flutter_scripts_loaded = False
        
        # Initialize Frida availability check
        self._check_frida_availability()

    def _check_frida_availability(self):
        """Check if Frida is available and properly configured."""
        try:
            import frida
            self.frida = frida
            
            # Check for USB devices
            devices = frida.enumerate_devices()
            usb_devices = [d for d in devices if d.type == 'usb']
            
            if usb_devices:
                self.device = usb_devices[0]
                self.is_available = True
                logging.info(f"Frida available with device: {self.device.name}")
            else:
                logging.warning("No USB devices found for Frida")
                self.is_available = False
                
        except ImportError:
            logging.error("Frida not installed - dynamic analysis unavailable")
            self.is_available = False
        except Exception as e:
            logging.error(f"Frida initialization failed: {e}")
            self.is_available = False

    def analyze_flutter_app(self, apk_path: str, package_name: str) -> Dict[str, Any]:
        """
        Comprehensive Flutter application analysis with architecture-aware SSL bypass.
        
        This method combines static analysis of the APK to detect Flutter architecture
        with dynamic Frida-based SSL bypass testing using architecture-specific patterns.
        
        Args:
            apk_path: Path to the Flutter APK file
            package_name: Package name of the Flutter application
            
        Returns:
            Dictionary containing Flutter analysis results and SSL bypass capabilities
        """
        results = {
            "flutter_detected": False,
            "architecture_info": None,
            "ssl_bypass_capabilities": [],
            "dynamic_analysis_results": {},
            "frida_scripts_generated": [],
            "analysis_success": False
        }
        
        if not self.flutter_analyzer:
            logging.error("Flutter analyzer not available")
            return results
        
        try:
            # Step 1: Analyze Flutter architecture from APK
            logging.info("Analyzing Flutter architecture from APK...")
            architecture_info = self.flutter_analyzer.analyze_flutter_architecture(apk_path)
            
            if architecture_info:
                results["flutter_detected"] = True
                results["architecture_info"] = {
                    "architecture": architecture_info.architecture,
                    "libflutter_path": architecture_info.libflutter_path,
                    "jni_onload_offset": architecture_info.jni_onload_offset,
                    "ssl_verify_function_offset": architecture_info.ssl_verify_function_offset,
                    "confidence": architecture_info.confidence,
                    "assembly_patterns_count": len(architecture_info.assembly_patterns)
                }
                self.flutter_architecture_info = architecture_info
                logging.info(f"Flutter architecture detected: {architecture_info.architecture}")
            
            # Step 2: Analyze SSL bypass capabilities
            logging.info("Analyzing Flutter SSL bypass capabilities...")
            bypass_capabilities = self.flutter_analyzer.analyze_flutter_ssl_bypass_capabilities()
            
            if bypass_capabilities:
                results["ssl_bypass_capabilities"] = [
                    {
                        "bypass_method": cap.bypass_method,
                        "architecture_support": cap.architecture_support,
                        "success_probability": cap.success_probability,
                        "technical_details": cap.technical_details
                    }
                    for cap in bypass_capabilities
                ]
                self.flutter_bypass_capabilities = bypass_capabilities
                logging.info(f"Detected {len(bypass_capabilities)} SSL bypass capabilities")
            
            # Step 3: Generate and test Frida scripts
            if self.is_available and architecture_info:
                logging.info("Generating architecture-aware Frida scripts...")
                frida_scripts = self._generate_flutter_frida_scripts()
                results["frida_scripts_generated"] = frida_scripts
                
                # Step 4: Execute dynamic analysis
                dynamic_results = self._execute_flutter_dynamic_analysis(package_name)
                results["dynamic_analysis_results"] = dynamic_results
                results["analysis_success"] = True
            else:
                logging.warning("Frida not available or Flutter architecture not detected - skipping dynamic analysis")
            
        except Exception as e:
            logging.error(f"Flutter analysis failed: {e}")
            results["error"] = str(e)
        
        return results

    def _generate_flutter_frida_scripts(self) -> List[str]:
        """
        Generate Flutter-specific Frida scripts based on detected architecture.
        
        Returns:
            List of generated script names
        """
        scripts_generated = []
        
        if not self.flutter_analyzer or not self.flutter_architecture_info:
            return scripts_generated
        
        try:
            # Generate architecture-aware SSL bypass script
            architecture_script = self.flutter_analyzer.generate_architecture_aware_frida_script("memory_scanning")
            if architecture_script:
                script_name = "flutter_architecture_ssl_bypass"
                self._save_frida_script(script_name, architecture_script)
                scripts_generated.append(script_name)
                logging.info(f"Generated {script_name} for {self.flutter_architecture_info.architecture}")
            
            # Generate capability-specific scripts
            for capability in self.flutter_bypass_capabilities:
                if capability.frida_script:
                    script_name = f"flutter_{capability.bypass_method}_bypass"
                    self._save_frida_script(script_name, capability.frida_script)
                    scripts_generated.append(script_name)
                    logging.info(f"Generated {script_name}")
            
            # Generate comprehensive Flutter bypass script
            comprehensive_script = self._generate_comprehensive_flutter_script()
            if comprehensive_script:
                script_name = "flutter_comprehensive_bypass"
                self._save_frida_script(script_name, comprehensive_script)
                scripts_generated.append(script_name)
                logging.info("Generated comprehensive Flutter bypass script")
            
        except Exception as e:
            logging.error(f"Frida script generation failed: {e}")
        
        return scripts_generated

    def _save_frida_script(self, script_name: str, script_content: str):
        """Save Frida script to temporary file for execution."""
        try:
            script_dir = Path("/tmp/aods_frida_scripts")
            script_dir.mkdir(exist_ok=True)
            
            script_file = script_dir / f"{script_name}.js"
            with open(script_file, 'w') as f:
                f.write(script_content)
            
            logging.info(f"Saved Frida script: {script_file}")
            
        except Exception as e:
            logging.error(f"Failed to save Frida script {script_name}: {e}")

    def _generate_comprehensive_flutter_script(self) -> str:
        """
        Generate comprehensive Flutter SSL bypass script combining all available methods.
        
        Returns:
            JavaScript code for comprehensive Flutter SSL bypass
        """
        if not self.flutter_architecture_info:
            return ""
        
        arch = self.flutter_architecture_info.architecture
        patterns = self.flutter_architecture_info.assembly_patterns
        
        comprehensive_script = f"""
        // Comprehensive Flutter SSL Bypass for {arch}
        // AODS - Advanced architecture-aware SSL bypass implementation
        
        console.log("[+] AODS Flutter SSL Bypass - Starting comprehensive analysis");
        console.log("[+] Target architecture: {arch}");
        
        function comprehensiveFlutterSSLBypass() {{
            var bypassResults = {{
                architecture: "{arch}",
                methods_attempted: [],
                methods_successful: [],
                errors: []
            }};
            
            // Method 1: Architecture-specific memory scanning
            try {{
                console.log("[+] Method 1: Architecture-specific memory scanning");
                bypassResults.methods_attempted.push("memory_scanning");
                
                var libflutter = Process.findModuleByName("libflutter.so");
                if (libflutter) {{
                    console.log("[+] libflutter.so found at: " + libflutter.base);
                    
                    var patterns = {json.dumps(patterns)};
                    var patternFound = false;
                    
                    patterns.forEach(function(pattern, index) {{
                        if (patternFound) return;
                        
                        console.log("[+] Scanning pattern " + (index + 1) + "/" + patterns.length);
                        var patternBytes = pattern.replace(/\\s+/g, '').match(/.{{2}}/g);
                        
                        if (patternBytes) {{
                            try {{
                                Memory.scan(libflutter.base, libflutter.size, pattern.replace(/\\s+/g, ' '), {{
                                    onMatch: function(address, size) {{
                                        console.log("[+] SSL function found at: " + address);
                                        
                                        // Hook the function
                                        Interceptor.replace(address, new NativeCallback(function(ssl, cert_chain) {{
                                            console.log("[+] ssl_crypto_x509_session_verify_cert_chain bypassed!");
                                            bypassResults.methods_successful.push("memory_scanning");
                                            return 1; // Always return success
                                        }}, 'int', ['pointer', 'pointer']));
                                        
                                        patternFound = true;
                                        return 'stop';
                                    }},
                                    onError: function(reason) {{
                                        console.log("[-] Pattern scan error: " + reason);
                                    }}
                                }});
                            }} catch (e) {{
                                console.log("[-] Pattern scan failed: " + e);
                            }}
                        }}
                    }});
                    
                    if (!patternFound) {{
                        console.log("[-] No architecture patterns matched");
                    }}
                }} else {{
                    console.log("[-] libflutter.so not found");
                }}
                
            }} catch (e) {{
                console.log("[-] Memory scanning failed: " + e);
                bypassResults.errors.push("memory_scanning: " + e.toString());
            }}
            
            // Method 2: JNI offset calculation
            try {{
                console.log("[+] Method 2: JNI offset calculation");
                bypassResults.methods_attempted.push("jni_offset_calculation");
                
                {self._generate_jni_offset_calculation_script()}
                
            }} catch (e) {{
                console.log("[-] JNI offset calculation failed: " + e);
                bypassResults.errors.push("jni_offset_calculation: " + e.toString());
            }}
            
            // Method 3: BoringSSL function hooking
            try {{
                console.log("[+] Method 3: BoringSSL function hooking");
                bypassResults.methods_attempted.push("boringssl_hooking");
                
                var boringssl_functions = [
                    "SSL_CTX_set_verify",
                    "SSL_set_verify", 
                    "X509_verify_cert",
                    "ssl_crypto_x509_session_verify_cert_chain"
                ];
                
                var functionsHooked = 0;
                boringssl_functions.forEach(function(func_name) {{
                    var func_addr = Module.findExportByName("libflutter.so", func_name);
                    if (func_addr) {{
                        console.log("[+] Hooking " + func_name + " at: " + func_addr);
                        
                        if (func_name === "X509_verify_cert") {{
                            Interceptor.replace(func_addr, new NativeCallback(function(ctx) {{
                                console.log("[+] " + func_name + " bypassed");
                                return 1; // Return success
                            }}, 'int', ['pointer']));
                        }} else if (func_name === "ssl_crypto_x509_session_verify_cert_chain") {{
                            Interceptor.replace(func_addr, new NativeCallback(function(ssl, cert_chain) {{
                                console.log("[+] " + func_name + " bypassed");
                                return 1; // Return success
                            }}, 'int', ['pointer', 'pointer']));
                        }} else {{
                            Interceptor.replace(func_addr, new NativeCallback(function(ctx, mode, callback) {{
                                console.log("[+] " + func_name + " bypassed");
                                return; // Don't set verification
                            }}, 'void', ['pointer', 'int', 'pointer']));
                        }}
                        
                        functionsHooked++;
                    }}
                }});
                
                if (functionsHooked > 0) {{
                    console.log("[+] Successfully hooked " + functionsHooked + " BoringSSL functions");
                    bypassResults.methods_successful.push("boringssl_hooking");
                }} else {{
                    console.log("[-] No BoringSSL functions found to hook");
                }}
                
            }} catch (e) {{
                console.log("[-] BoringSSL hooking failed: " + e);
                bypassResults.errors.push("boringssl_hooking: " + e.toString());
            }}
            
            // Method 4: Dart-level fallback
            try {{
                console.log("[+] Method 4: Dart-level fallback bypass");
                bypassResults.methods_attempted.push("dart_level_bypass");
                
                // This is a placeholder for Dart runtime manipulation
                // Actual implementation would require deeper Dart VM integration
                console.log("[+] Dart-level bypass attempted (placeholder)");
                
            }} catch (e) {{
                console.log("[-] Dart-level bypass failed: " + e);
                bypassResults.errors.push("dart_level_bypass: " + e.toString());
            }}
            
            // Report results
            console.log("[+] ========== BYPASS SUMMARY ==========");
            console.log("[+] Architecture: " + bypassResults.architecture);
            console.log("[+] Methods attempted: " + bypassResults.methods_attempted.length);
            console.log("[+] Methods successful: " + bypassResults.methods_successful.length);
            console.log("[+] Successful methods: " + bypassResults.methods_successful.join(", "));
            
            if (bypassResults.errors.length > 0) {{
                console.log("[-] Errors encountered: " + bypassResults.errors.length);
                bypassResults.errors.forEach(function(error) {{
                    console.log("[-] " + error);
                }});
            }}
            
            send({{
                type: "flutter_bypass_results",
                data: bypassResults
            }});
            
            return bypassResults;
        }}
        
        // Execute comprehensive bypass
        Java.perform(function() {{
            comprehensiveFlutterSSLBypass();
        }});
        """
        
        return comprehensive_script

    def _generate_jni_offset_calculation_script(self) -> str:
        """
        Generate enhanced JNI offset calculation script with architecture-specific patterns.
        
        Research-based enhancement: Dynamic offset calculation with multi-architecture support.
        """
        if not self.flutter_architecture_info:
            return ""
        
        arch = self.flutter_architecture_info.architecture
        jni_offset = self.flutter_architecture_info.jni_onload_offset or 0
        ssl_offset = self.flutter_architecture_info.ssl_verify_function_offset or 0
        
        return f"""
        // Enhanced JNI offset calculation for {arch}
        try {{
            console.log("[+] Enhanced JNI offset calculation for {arch}");
            
            var libflutter = Process.findModuleByName("libflutter.so");
            if (!libflutter) {{
                console.log("[-] libflutter.so not found");
                return;
            }}
            
            console.log("[+] libflutter.so base: " + libflutter.base);
            console.log("[+] libflutter.so size: " + libflutter.size);
            
            // Phase 1: JNI_OnLoad based calculation
            if ({jni_offset} > 0) {{
                var jni_onload_address = libflutter.base.add({jni_offset});
                console.log("[+] JNI_OnLoad found at: " + jni_onload_address);
                
                // Phase 2: SSL verify function calculation  
                if ({ssl_offset} > 0) {{
                    var ssl_verify_address = libflutter.base.add({ssl_offset});
                    console.log("[+] ssl_crypto_x509_session_verify_cert_chain calculated at: " + ssl_verify_address);
                    
                    // Hook the calculated address
                    Interceptor.replace(ssl_verify_address, new NativeCallback(function(ssl, cert_chain) {{
                        console.log("[+] ssl_crypto_x509_session_verify_cert_chain bypassed via offset calculation");
                        return 1; // Return success
                    }}, 'int', ['pointer', 'pointer']));
                    
                    bypassResults.methods_successful.push("jni_offset_calculation");
                }}
            }}
            
            // Phase 3: Architecture-specific pattern scanning
            {self._generate_architecture_specific_scanning_script()}
            
            // Phase 4: String reference-based symbol location
            {self._generate_string_reference_script()}
            
            // Phase 5: Multi-version compatibility check
            {self._generate_version_compatibility_script()}
            
        }} catch (e) {{
            console.log("[-] Enhanced JNI offset calculation failed: " + e);
            bypassResults.errors.push("enhanced_jni_calculation: " + e.toString());
        }}
        """

    def _generate_architecture_specific_scanning_script(self) -> str:
        """
        Generate architecture-specific memory scanning script.
        
        Research-based enhancement: ARM64, ARM32, x86_64 specific patterns.
        """
        if not self.flutter_architecture_info:
            return ""
        
        arch = self.flutter_architecture_info.architecture
        patterns = self.flutter_architecture_info.assembly_patterns
        enhanced_patterns = getattr(self.flutter_architecture_info, 'enhanced_patterns', [])
        
        # Architecture-specific assembly patterns from research
        arch_patterns = {
            'arm64': {
                'ssl_verify_patterns': [
                    "55 41 57 41 56 41 55 41 54 53 48 83 ec 38 c6 02 50 48 8b af a8 00 00 00",
                    "fd 7b bf a9 fd 03 00 91 f4 4f 01 a9 f6 57 02 a9 f8 5f 03 a9 fa 67 04 a9",
                    "ff 43 00 d1 fe 0f 00 f9 fd 7b 00 a9 fd 03 00 91 f4 4f 01 a9 f6 57 02 a9"
                ],
                'instruction_length': 4,
                'endianness': 'little'
            },
            'arm32': {
                'ssl_verify_patterns': [
                    "2d e9 f0 4f a3 b0 82 46 50 20 10 70",
                    "00 48 2d e9 04 b0 8d e2 00 30 a0 e1 0c 00 93 e5",
                    "f0 4f 2d e9 04 b0 8d e2 00 50 a0 e1 00 40 a0 e1"
                ],
                'instruction_length': 4,
                'endianness': 'little'
            },
            'x86_64': {
                'ssl_verify_patterns': [
                    "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 38",
                    "55 48 89 e5 53 48 83 ec 18 48 89 7d f0 48 89 75 e8",
                    "55 48 89 e5 41 54 53 48 83 ec 10 49 89 fc 48 89 f3"
                ],
                'instruction_length': 1,
                'endianness': 'little'
            }
        }
        
        arch_config = arch_patterns.get(arch, arch_patterns['arm64'])
        all_patterns = arch_config['ssl_verify_patterns'] + patterns + enhanced_patterns
        
        return f"""
        // Architecture-specific pattern scanning for {arch}
        try {{
            console.log("[+] Architecture-specific pattern scanning for {arch}");
            
            var libflutter = Process.findModuleByName("libflutter.so");
            if (!libflutter) {{
                console.log("[-] libflutter.so not found for pattern scanning");
                return;
            }}
            
            // Enhanced pattern scanning with architecture awareness
            var patterns = {json.dumps(all_patterns)};
            var arch_config = {{
                instruction_length: {arch_config['instruction_length']},
                endianness: "{arch_config['endianness']}"
            }};
            
            console.log("[+] Scanning " + patterns.length + " architecture-specific patterns");
            
            var patternFound = false;
            var scanCount = 0;
            
            patterns.forEach(function(pattern, index) {{
                if (patternFound) return;
                
                scanCount++;
                console.log("[+] Scanning pattern " + scanCount + "/" + patterns.length + " for {arch}");
                
                try {{
                    // Convert pattern to bytes
                    var patternBytes = pattern.replace(/\\s+/g, '');
                    if (patternBytes.length < 8) {{
                        console.log("[-] Pattern too short: " + pattern);
                        return;
                    }}
                    
                    // Architecture-specific memory scanning
                    Memory.scan(libflutter.base, libflutter.size, patternBytes, {{
                        onMatch: function(address, size) {{
                            console.log("[+] Architecture pattern matched at: " + address);
                            console.log("[+] Pattern: " + pattern.substring(0, 50) + "...");
                            
                            // Verify this is actually the SSL verify function
                            var isSSLFunction = {arch}ArchitectureValidator(address, arch_config);
                            
                            if (isSSLFunction) {{
                                console.log("[+] SSL verify function confirmed at: " + address);
                                
                                // Hook the function with architecture-specific callback
                                var hookCallback = create{arch.upper()}SSLHook(address);
                                if (hookCallback) {{
                                    console.log("[+] Successfully hooked SSL verify function");
                                    bypassResults.methods_successful.push("architecture_specific_scanning");
                                    patternFound = true;
                                }}
                            }} else {{
                                console.log("[-] Pattern matched but not SSL function");
                            }}
                            
                            return patternFound ? 'stop' : 'continue';
                        }},
                        onError: function(reason) {{
                            console.log("[-] Pattern scan error: " + reason);
                        }},
                        onComplete: function() {{
                            console.log("[+] Pattern scan complete");
                        }}
                    }});
                    
                }} catch (e) {{
                    console.log("[-] Pattern scan failed: " + e);
                }}
            }});
            
            if (!patternFound) {{
                console.log("[-] No architecture-specific patterns matched for {arch}");
            }}
            
        }} catch (e) {{
            console.log("[-] Architecture-specific scanning failed: " + e);
        }}
        
        // Architecture-specific validation function
        function {arch}ArchitectureValidator(address, config) {{
            try {{
                // Read a few bytes to validate instruction pattern
                var bytes = Memory.readByteArray(address, 16);
                var u8 = new Uint8Array(bytes);
                
                // Architecture-specific validation
                if ("{arch}" === "arm64") {{
                    // ARM64 instruction validation
                    return validateARM64Instructions(u8);
                }} else if ("{arch}" === "arm32") {{
                    // ARM32 instruction validation
                    return validateARM32Instructions(u8);
                }} else if ("{arch}" === "x86_64") {{
                    // x86_64 instruction validation
                    return validateX86_64Instructions(u8);
                }}
                
                return true; // Default validation
                
            }} catch (e) {{
                console.log("[-] Architecture validation failed: " + e);
                return false;
            }}
        }}
        
        // ARM64 instruction validation
        function validateARM64Instructions(bytes) {{
            // Check for common ARM64 SSL function patterns
            // STP (Store Pair) instruction pattern: 0x29 or 0xA9
            // LDP (Load Pair) instruction pattern: 0x29 or 0xA9
            return bytes.length >= 4 && (bytes[0] === 0x29 || bytes[0] === 0xA9 || bytes[3] === 0x29 || bytes[3] === 0xA9);
        }}
        
        // ARM32 instruction validation
        function validateARM32Instructions(bytes) {{
            // Check for common ARM32 SSL function patterns
            // PUSH instruction pattern: 0x2D, 0xE9
            // MOV instruction pattern: 0x00, 0x00, 0xA0, 0xE1
            return bytes.length >= 4 && (bytes[0] === 0x2D || bytes[0] === 0x00);
        }}
        
        // x86_64 instruction validation
        function validateX86_64Instructions(bytes) {{
            // Check for common x86_64 SSL function patterns
            // PUSH RBP: 0x55
            // MOV RBP, RSP: 0x48, 0x89, 0xE5
            return bytes.length >= 4 && (bytes[0] === 0x55 || (bytes[0] === 0x48 && bytes[1] === 0x89 && bytes[2] === 0xE5));
        }}
        
        // Create architecture-specific SSL hook
        function create{arch.upper()}SSLHook(address) {{
            try {{
                if ("{arch}" === "arm64") {{
                    return createARM64SSLHook(address);
                }} else if ("{arch}" === "arm32") {{
                    return createARM32SSLHook(address);
                }} else if ("{arch}" === "x86_64") {{
                    return createX86_64SSLHook(address);
                }}
                return null;
                
            }} catch (e) {{
                console.log("[-] Failed to create {arch} SSL hook: " + e);
                return null;
            }}
        }}
        
        // ARM64 SSL hook
        function createARM64SSLHook(address) {{
            Interceptor.replace(address, new NativeCallback(function(ssl, cert_chain) {{
                console.log("[+] ARM64 SSL verify function bypassed");
                return 1; // Return success
            }}, 'int', ['pointer', 'pointer']));
            return true;
        }}
        
        // ARM32 SSL hook
        function createARM32SSLHook(address) {{
            Interceptor.replace(address, new NativeCallback(function(ssl, cert_chain) {{
                console.log("[+] ARM32 SSL verify function bypassed");
                return 1; // Return success
            }}, 'int', ['pointer', 'pointer']));
            return true;
        }}
        
        // x86_64 SSL hook
        function createX86_64SSLHook(address) {{
            Interceptor.replace(address, new NativeCallback(function(ssl, cert_chain) {{
                console.log("[+] x86_64 SSL verify function bypassed");
                return 1; // Return success
            }}, 'int', ['pointer', 'pointer']));
            return true;
        }}
        """

    def _generate_string_reference_script(self) -> str:
        """
        Generate string reference-based symbol location script.
        
        Research-based enhancement: Use string references to locate SSL functions.
        """
        return """
        // String reference-based symbol location
        try {
            console.log("[+] String reference-based symbol location");
            
            var libflutter = Process.findModuleByName("libflutter.so");
            if (!libflutter) {
                console.log("[-] libflutter.so not found for string reference analysis");
                return;
            }
            
            // SSL-related string patterns for function identification
            var sslStrings = [
                "ssl_client",
                "ssl_server", 
                "ssl_verify",
                "cert_chain",
                "x509_verify",
                "boringssl",
                "ssl_crypto",
                "tls_handshake",
                "certificate_verify"
            ];
            
            var stringReferences = [];
            
            // Scan for SSL strings
            sslStrings.forEach(function(sslString) {
                try {
                    Memory.scan(libflutter.base, libflutter.size, sslString, {
                        onMatch: function(address, size) {
                            console.log("[+] Found SSL string '" + sslString + "' at: " + address);
                            stringReferences.push({
                                string: sslString,
                                address: address,
                                size: size
                            });
                        },
                        onError: function(reason) {
                            console.log("[-] String scan error for '" + sslString + "': " + reason);
                        }
                    });
                } catch (e) {
                    console.log("[-] String scan failed for '" + sslString + "': " + e);
                }
            });
            
            // Use string references to locate functions
            if (stringReferences.length > 0) {
                console.log("[+] Found " + stringReferences.length + " SSL string references");
                
                // Advanced: Cross-reference analysis to find actual functions
                stringReferences.forEach(function(ref) {
                    try {
                        // Search for code references to this string
                        var codeRefs = findCodeReferences(ref.address, libflutter);
                        codeRefs.forEach(function(codeRef) {
                            console.log("[+] Code reference to '" + ref.string + "' at: " + codeRef);
                            
                            // Attempt to hook nearby functions
                            var nearbyFunctions = findNearbyFunctions(codeRef, libflutter);
                            nearbyFunctions.forEach(function(funcAddr) {
                                console.log("[+] Nearby function at: " + funcAddr);
                                
                                // Hook as potential SSL verify function
                                try {
                                    Interceptor.replace(funcAddr, new NativeCallback(function(ssl, cert_chain) {
                                        console.log("[+] String-reference SSL function bypassed");
                                        return 1; // Return success
                                    }, 'int', ['pointer', 'pointer']));
                                } catch (e) {
                                    console.log("[-] Failed to hook function at " + funcAddr + ": " + e);
                                }
                            });
                        });
                    } catch (e) {
                        console.log("[-] Code reference analysis failed: " + e);
                    }
                });
            } else {
                console.log("[-] No SSL string references found");
            }
            
        } catch (e) {
            console.log("[-] String reference analysis failed: " + e);
        }
        
        // Find code references to string
        function findCodeReferences(stringAddr, module) {
            var codeRefs = [];
            
            try {
                // Search for pointer references to the string
                Memory.scan(module.base, module.size, stringAddr.toString(16), {
                    onMatch: function(address, size) {
                        codeRefs.push(address);
                    },
                    onError: function(reason) {
                        console.log("[-] Code reference scan error: " + reason);
                    }
                });
            } catch (e) {
                console.log("[-] Code reference search failed: " + e);
            }
            
            return codeRefs;
        }
        
        // Find nearby functions
        function findNearbyFunctions(codeAddr, module) {
            var functions = [];
            
            try {
                // Search for function prologue patterns near code reference
                var searchRange = 0x1000; // 4KB search range
                var startAddr = codeAddr.sub(searchRange);
                var endAddr = codeAddr.add(searchRange);
                
                // ARM64 function prologue patterns
                var arm64Prologues = ["fd7bbfa9", "fd030091", "ff430091"]; // Common ARM64 patterns
                
                // ARM32 function prologue patterns
                var arm32Prologues = ["2de9f04f", "0048a0e1", "04b08de2"]; // Common ARM32 patterns
                
                // x86_64 function prologue patterns
                var x86_64Prologues = ["554889e5", "4883ec10", "53488bfc"]; // Common x86_64 patterns
                
                var allPrologues = arm64Prologues.concat(arm32Prologues).concat(x86_64Prologues);
                
                allPrologues.forEach(function(prologue) {
                    try {
                        Memory.scan(startAddr, searchRange * 2, prologue, {
                            onMatch: function(address, size) {
                                functions.push(address);
                            },
                            onError: function(reason) {
                                console.log("[-] Function prologue scan error: " + reason);
                            }
                        });
                    } catch (e) {
                        console.log("[-] Function prologue scan failed: " + e);
                    }
                });
                
            } catch (e) {
                console.log("[-] Nearby function search failed: " + e);
            }
            
            return functions;
        }
        """

    def _generate_version_compatibility_script(self) -> str:
        """
        Generate multi-version compatibility script.
        
        Research-based enhancement: Multi-version Flutter compatibility.
        """
        return """
        // Multi-version Flutter compatibility check
        try {
            console.log("[+] Multi-version Flutter compatibility check");
            
            var libflutter = Process.findModuleByName("libflutter.so");
            if (!libflutter) {
                console.log("[-] libflutter.so not found for version compatibility");
                return;
            }
            
            // Version-specific patterns and offsets
            var versionPatterns = {
                "flutter_3.x": {
                    "ssl_verify_patterns": [
                        "ssl_crypto_x509_session_verify_cert_chain",
                        "SSL_CTX_set_verify",
                        "SSL_set_verify"
                    ],
                    "expected_offsets": [0x1000, 0x2000, 0x3000]
                },
                "flutter_2.x": {
                    "ssl_verify_patterns": [
                        "ssl_crypto_x509_session_verify_cert_chain",
                        "SSL_CTX_set_verify"
                    ],
                    "expected_offsets": [0x800, 0x1000]
                },
                "flutter_1.x": {
                    "ssl_verify_patterns": [
                        "SSL_CTX_set_verify",
                        "SSL_set_verify"
                    ],
                    "expected_offsets": [0x400, 0x800]
                }
            };
            
            // Detect Flutter version
            var detectedVersion = detectFlutterVersion(libflutter);
            console.log("[+] Detected Flutter version: " + detectedVersion);
            
            // Apply version-specific bypass
            var versionConfig = versionPatterns[detectedVersion];
            if (versionConfig) {
                console.log("[+] Applying version-specific bypass for " + detectedVersion);
                
                // Try version-specific patterns
                var success = false;
                versionConfig.ssl_verify_patterns.forEach(function(pattern) {
                    if (success) return;
                    
                    var funcAddr = Module.findExportByName("libflutter.so", pattern);
                    if (funcAddr) {
                        console.log("[+] Found version-specific function: " + pattern);
                        
                        try {
                            Interceptor.replace(funcAddr, new NativeCallback(function(ssl, cert_chain) {
                                console.log("[+] Version-specific SSL function bypassed: " + pattern);
                                return 1;
                            }, 'int', ['pointer', 'pointer']));
                            
                            success = true;
                            bypassResults.methods_successful.push("version_specific_bypass");
                        } catch (e) {
                            console.log("[-] Failed to hook version-specific function: " + e);
                        }
                    }
                });
                
                // Try version-specific offsets
                if (!success) {
                    versionConfig.expected_offsets.forEach(function(offset) {
                        if (success) return;
                        
                        try {
                            var funcAddr = libflutter.base.add(offset);
                            console.log("[+] Trying version-specific offset: " + funcAddr);
                            
                            Interceptor.replace(funcAddr, new NativeCallback(function(ssl, cert_chain) {
                                console.log("[+] Version-specific offset SSL function bypassed");
                                return 1;
                            }, 'int', ['pointer', 'pointer']));
                            
                            success = true;
                            bypassResults.methods_successful.push("version_specific_offset");
                        } catch (e) {
                            console.log("[-] Version-specific offset failed: " + e);
                        }
                    });
                }
            } else {
                console.log("[-] Unknown Flutter version, using generic bypass");
            }
            
        } catch (e) {
            console.log("[-] Version compatibility check failed: " + e);
        }
        
        // Detect Flutter version
        function detectFlutterVersion(module) {
            try {
                // Search for version strings
                var versionStrings = [
                    "Flutter 3.",
                    "Flutter 2.",
                    "Flutter 1.",
                    "flutter_engine 3.",
                    "flutter_engine 2.",
                    "flutter_engine 1."
                ];
                
                for (var i = 0; i < versionStrings.length; i++) {
                    var versionString = versionStrings[i];
                    
                    try {
                        Memory.scan(module.base, module.size, versionString, {
                            onMatch: function(address, size) {
                                console.log("[+] Found version string: " + versionString);
                                
                                if (versionString.includes("3.")) {
                                    return "flutter_3.x";
                                } else if (versionString.includes("2.")) {
                                    return "flutter_2.x";
                                } else if (versionString.includes("1.")) {
                                    return "flutter_1.x";
                                }
                            },
                            onError: function(reason) {
                                console.log("[-] Version string scan error: " + reason);
                            }
                        });
                    } catch (e) {
                        console.log("[-] Version string scan failed: " + e);
                    }
                }
                
                return "unknown";
                
            } catch (e) {
                console.log("[-] Version detection failed: " + e);
                return "unknown";
            }
        }
        """

    def _execute_flutter_dynamic_analysis(self, package_name: str) -> Dict[str, Any]:
        """
        Execute dynamic analysis with Flutter-specific SSL bypass testing.

        Args:
            package_name: Target Flutter application package name
            
        Returns:
            Dynamic analysis results
        """
        results = {
            "analysis_started": False,
            "scripts_executed": [],
            "bypass_results": {},
            "errors": []
        }
        
        if not self.is_available:
            results["errors"].append("Frida not available")
            return results
        
        try:
            # Attach to or spawn the Flutter application
            if not self._attach_to_app(package_name):
                results["errors"].append("Failed to attach to application")
                return results
            
            results["analysis_started"] = True
            
            # Execute Flutter-specific scripts
            script_results = self._execute_flutter_scripts()
            results["scripts_executed"] = script_results["executed"]
            results["bypass_results"] = script_results["results"]
            results["errors"].extend(script_results["errors"])
            
            # Wait for analysis completion
            time.sleep(self.analysis_duration)
            
            logging.info("Flutter dynamic analysis completed")
            
        except Exception as e:
            logging.error(f"Flutter dynamic analysis failed: {e}")
            results["errors"].append(str(e))
        finally:
            self._cleanup_session()
        
        return results

    def _execute_flutter_scripts(self) -> Dict[str, Any]:
        """Execute all Flutter-specific Frida scripts."""
        results = {
            "executed": [],
            "results": {},
            "errors": []
        }
        
        try:
            # Load and execute comprehensive Flutter bypass script
            comprehensive_script = self._generate_comprehensive_flutter_script()
            if comprehensive_script:
                script = self.session.create_script(comprehensive_script)
                script.on("message", self._on_flutter_message)
                script.load()
                self.scripts["flutter_comprehensive"] = script
                results["executed"].append("flutter_comprehensive")
                logging.info("Loaded comprehensive Flutter bypass script")
            
            # Execute capability-specific scripts
            for capability in self.flutter_bypass_capabilities:
                if capability.frida_script:
                    try:
                        script = self.session.create_script(capability.frida_script)
                        script.on("message", self._on_flutter_message)
                        script.load()
                        script_name = f"flutter_{capability.bypass_method}"
                        self.scripts[script_name] = script
                        results["executed"].append(script_name)
                        logging.info(f"Loaded {script_name} script")
                    except Exception as e:
                        error_msg = f"Failed to load {capability.bypass_method} script: {e}"
                        logging.error(error_msg)
                        results["errors"].append(error_msg)
            
        except Exception as e:
            error_msg = f"Flutter script execution failed: {e}"
            logging.error(error_msg)
            results["errors"].append(error_msg)
        
        return results

    def _on_flutter_message(self, message, data):
        """Handle messages from Flutter-specific Frida scripts."""
        if message["type"] == "send":
            payload = message.get("payload", {})
            
            if isinstance(payload, dict):
                msg_type = payload.get("type", "flutter_info")
                
                if "flutter_analysis" not in self.analysis_results:
                    self.analysis_results["flutter_analysis"] = []
                
                self.analysis_results["flutter_analysis"].append(payload)
                logging.info(f"Flutter Analysis: {payload}")
                
                # Handle specific Flutter bypass results
                if msg_type == "flutter_bypass_results":
                    bypass_data = payload.get("data", {})
                    logging.info(f"Flutter SSL Bypass Results: {bypass_data}")
                    
                    successful_methods = bypass_data.get("methods_successful", [])
                    if successful_methods:
                        logging.info(f"Successfully bypassed SSL using: {', '.join(successful_methods)}")
                    else:
                        logging.warning("No Flutter SSL bypass methods succeeded")

    def check_frida_availability(self) -> Tuple[bool, str]:
        """
        Check if Frida is available and properly configured.

        Returns:
            Tuple of (is_available, status_message)
        """
        try:
            # Check if frida-tools is installed
            result = subprocess.run(
                ["frida", "--version"], capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0:
                return (
                    False,
                    "Frida CLI not found. Install with: pip install frida-tools",
                )

            frida_version = result.stdout.strip()

            # Check if device is connected
            device_check = subprocess.run(
                ["frida-ls-devices"], capture_output=True, text=True, timeout=10
            )

            if device_check.returncode != 0:
                return False, "Failed to list Frida devices"

            devices_output = device_check.stdout
            if (
                "usb" not in devices_output.lower()
                and "emulator" not in devices_output.lower()
            ):
                return (
                    False,
                    "No USB or emulator devices found. Ensure device is connected and Frida server is running.",
                )

            return True, f"Frida {frida_version} available with connected devices"

        except subprocess.TimeoutExpired:
            return False, "Frida command timed out"
        except Exception as e:
            return False, f"Frida check failed: {str(e)}"

    def start_frida_server(self) -> bool:
        """
        Start Frida server on the target device.

        Returns:
            bool: True if server started successfully, False otherwise
        """
        try:
            logging.info("Starting Frida server on device...")

            # Check if Frida server is already running
            check_cmd = (
                ["frida-ps", "-U"]
                if not self.device_id
                else ["frida-ps", "-D", self.device_id]
            )
            result = subprocess.run(
                check_cmd, capture_output=True, text=True, timeout=15
            )

            if result.returncode == 0:
                logging.info("Frida server is already running")
                return True

            # Try to start Frida server via adb
            adb_cmd = ["adb"]
            if self.device_id:
                adb_cmd.extend(["-s", self.device_id])

            # Push and start frida-server (assuming it's available on device)
            server_start_cmd = adb_cmd + [
                "shell",
                "su",
                "-c",
                "/data/local/tmp/frida-server &",
            ]

            subprocess.run(server_start_cmd, capture_output=True, text=True, timeout=10)

            # Wait a moment for server to start
            time.sleep(3)

            # Verify server is running
            verify_result = subprocess.run(
                check_cmd, capture_output=True, text=True, timeout=10
            )

            if verify_result.returncode == 0:
                logging.info("Frida server started successfully")
                return True
            else:
                logging.warning(
                    "Frida server may not be running. Continuing with analysis..."
                )
                return False

        except Exception as e:
            logging.error(f"Failed to start Frida server: {e}")
            return False

    def attach_to_app(self) -> bool:
        """
        Attach Frida to the target application.

        Returns:
            bool: True if attachment successful, False otherwise
        """
        try:
            import frida

            # Get device
            if self.device_id:
                device = frida.get_device(self.device_id)
            else:
                device = frida.get_usb_device()

            # Try to attach to running process first
            try:
                self.session = device.attach(self.package_name)
                logging.info(f"Attached to running process: {self.package_name}")
                return True
            except frida.ProcessNotFoundError:
                # App not running, try to spawn it
                logging.info(
                    f"App not running, attempting to spawn: {self.package_name}"
                )
                pid = device.spawn([self.package_name])
                self.session = device.attach(pid)
                device.resume(pid)
                logging.info(f"Spawned and attached to: {self.package_name}")
                return True

        except ImportError:
            logging.error(
                "Frida Python bindings not installed. Install with: pip install frida"
            )
            return False
        except Exception as e:
            logging.error(f"Failed to attach to app: {e}")
            return False

    def load_ssl_pinning_bypass_script(self) -> bool:
        """
        Load SSL pinning bypass script.

        Returns:
            bool: True if script loaded successfully, False otherwise
        """
        ssl_bypass_script = """
        Java.perform(function() {
            console.log("[+] SSL Pinning Bypass Script Loaded");

            // Android SSL Pinning Bypass
            try {
                var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                var SSLContext = Java.use('javax.net.ssl.SSLContext');
                var TrustManager = Java.use('javax.net.ssl.TrustManager');
                var X509Certificate = Java.use('java.security.cert.X509Certificate');

                // Create custom TrustManager
                var TrustManagerImpl = Java.registerClass({
                    name: 'com.frida.TrustManagerImpl',
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function(chain, authType) {
                            console.log('[+] checkClientTrusted bypassed');
                        },
                        checkServerTrusted: function(chain, authType) {
                            console.log('[+] checkServerTrusted bypassed');
                        },
                        getAcceptedIssuers: function() {
                            return [];
                        }
                    }
                });

                // Hook SSLContext.init
                SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManagers, trustManagers, secureRandom) {
                    console.log('[+] SSLContext.init() bypassed');
                    var customTrustManager = TrustManagerImpl.$new();
                    this.init(keyManagers, [customTrustManager], secureRandom);
                };

                console.log('[+] SSL Pinning bypass for Android SSL completed');

            } catch (e) {
                console.log('[-] Android SSL bypass failed: ' + e);
            }

            // OkHttp3 SSL Pinning Bypass
            try {
                var OkHttpClient = Java.use('okhttp3.OkHttpClient');
                var Builder = Java.use('okhttp3.OkHttpClient$Builder');
                var CertificatePinner = Java.use('okhttp3.CertificatePinner');

                // Hook CertificatePinner.check
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                    console.log('[+] OkHttp3 CertificatePinner.check() bypassed for: ' + hostname);
                    return;
                };

                console.log('[+] OkHttp3 SSL Pinning bypass completed');

            } catch (e) {
                console.log('[-] OkHttp3 bypass failed: ' + e);
            }

            // Retrofit SSL Pinning Bypass
            try {
                var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
                HostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(hostname, session) {
                    console.log('[+] HostnameVerifier.verify() bypassed for: ' + hostname);
                    return true;
                };

                console.log('[+] HostnameVerifier bypass completed');

            } catch (e) {
                console.log('[-] HostnameVerifier bypass failed: ' + e);
            }
        });
        """

        try:
            if not self.session:
                logging.error("No active Frida session for SSL bypass script")
                return False

            script = self.session.create_script(ssl_bypass_script)
            script.on("message", self._on_ssl_message)
            script.load()
            self.scripts["ssl_bypass"] = script

            logging.info("SSL pinning bypass script loaded successfully")
            return True

        except Exception as e:
            logging.error(f"Failed to load SSL bypass script: {e}")
            return False

    def load_webview_security_script(self) -> bool:
        """
        Load WebView security testing script.

        Returns:
            bool: True if script loaded successfully, False otherwise
        """
        webview_script = """
        Java.perform(function() {
            console.log("[+] WebView Security Analysis Script Loaded");

            try {
                var WebView = Java.use('android.webkit.WebView');
                var WebSettings = Java.use('android.webkit.WebSettings');
                var WebViewClient = Java.use('android.webkit.WebViewClient');

                // Hook WebView.loadUrl
                WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
                    console.log('[+] WebView.loadUrl() called with: ' + url);
                    send({type: 'webview_url', data: url});
                    return this.loadUrl(url);
                };

                // Hook WebSettings for security analysis
                WebSettings.setJavaScriptEnabled.implementation = function(enabled) {
                    console.log('[+] WebSettings.setJavaScriptEnabled: ' + enabled);
                    send({type: 'webview_js_enabled', data: enabled});
                    return this.setJavaScriptEnabled(enabled);
                };

                WebSettings.setAllowFileAccess.implementation = function(enabled) {
                    console.log('[+] WebSettings.setAllowFileAccess: ' + enabled);
                    send({type: 'webview_file_access', data: enabled});
                    return this.setAllowFileAccess(enabled);
                };

                WebSettings.setAllowContentAccess.implementation = function(enabled) {
                    console.log('[+] WebSettings.setAllowContentAccess: ' + enabled);
                    send({type: 'webview_content_access', data: enabled});
                    return this.setAllowContentAccess(enabled);
                };

                WebSettings.setAllowFileAccessFromFileURLs.implementation = function(enabled) {
                    console.log('[+] WebSettings.setAllowFileAccessFromFileURLs: ' + enabled);
                    send({type: 'webview_file_url_access', data: enabled});
                    return this.setAllowFileAccessFromFileURLs(enabled);
                };

                WebSettings.setAllowUniversalAccessFromFileURLs.implementation = function(enabled) {
                    console.log('[+] WebSettings.setAllowUniversalAccessFromFileURLs: ' + enabled);
                    send({type: 'webview_universal_access', data: enabled});
                    return this.setAllowUniversalAccessFromFileURLs(enabled);
                };

                // Hook addJavascriptInterface for bridge analysis
                WebView.addJavascriptInterface.implementation = function(obj, name) {
                    console.log('[+] WebView.addJavascriptInterface: ' + name);
                    send({type: 'webview_js_interface', data: {name: name, object: obj.toString()}});
                    return this.addJavascriptInterface(obj, name);
                };

                console.log('[+] WebView security hooks installed');

            } catch (e) {
                console.log('[-] WebView security analysis failed: ' + e);
            }
        });
        """

        try:
            if not self.session:
                logging.error("No active Frida session for WebView script")
                return False

            script = self.session.create_script(webview_script)
            script.on("message", self._on_webview_message)
            script.load()
            self.scripts["webview_security"] = script

            logging.info("WebView security script loaded successfully")
            return True

        except Exception as e:
            logging.error(f"Failed to load WebView security script: {e}")
            return False

    def load_anti_frida_detection_script(self) -> bool:
        """
        Load anti-Frida detection and bypass script.

        Returns:
            bool: True if script loaded successfully, False otherwise
        """
        anti_frida_script = """
        Java.perform(function() {
            console.log("[+] Anti-Frida Detection Script Loaded");

            // Hook common anti-Frida checks
            try {
                // Hook File.exists for frida-server detection
                var File = Java.use('java.io.File');
                File.exists.implementation = function() {
                    var path = this.getAbsolutePath();
                    if (path.indexOf('frida') !== -1 || path.indexOf('gum') !== -1) {
                        console.log('[+] Blocked File.exists() check for: ' + path);
                        send({type: 'anti_frida_file_check', data: path});
                        return false;
                    }
                    return this.exists();
                };

                // Hook Runtime.exec for process detection
                var Runtime = Java.use('java.lang.Runtime');
                Runtime.exec.overload('java.lang.String').implementation = function(command) {
                    if (command.indexOf('frida') !== -1 || command.indexOf('gum') !== -1) {
                        console.log('[+] Blocked Runtime.exec() for: ' + command);
                        send({type: 'anti_frida_exec_check', data: command});
                        throw new Error('Command blocked');
                    }
                    return this.exec(command);
                };

                // Hook port scanning attempts
                var Socket = Java.use('java.net.Socket');
                Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
                    if (port === 27042 || port === 27043) {
                        console.log('[+] Blocked socket connection to Frida port: ' + port);
                        send({type: 'anti_frida_port_check', data: {host: host, port: port}});
                        throw new Error('Connection refused');
                    }
                    return this.$init(host, port);
                };

                console.log('[+] Anti-Frida detection bypasses installed');

            } catch (e) {
                console.log('[-] Anti-Frida bypass failed: ' + e);
            }
        });
        """

        try:
            if not self.session:
                logging.error("No active Frida session for anti-Frida script")
                return False

            script = self.session.create_script(anti_frida_script)
            script.on("message", self._on_anti_frida_message)
            script.load()
            self.scripts["anti_frida"] = script

            logging.info("Anti-Frida detection script loaded successfully")
            return True

        except Exception as e:
            logging.error(f"Failed to load anti-Frida script: {e}")
            return False

    def _on_ssl_message(self, message, data):
        """Handle SSL bypass script messages."""
        if message["type"] == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict):
                msg_type = payload.get("type", "ssl_info")
                if "ssl_bypass" not in self.analysis_results:
                    self.analysis_results["ssl_bypass"] = []
                self.analysis_results["ssl_bypass"].append(payload)
                logging.info(f"SSL Bypass: {payload}")

    def _on_webview_message(self, message, data):
        """Handle WebView security script messages."""
        if message["type"] == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict):
                msg_type = payload.get("type", "webview_info")
                if "webview_security" not in self.analysis_results:
                    self.analysis_results["webview_security"] = []
                self.analysis_results["webview_security"].append(payload)
                logging.info(f"WebView Security: {payload}")

    def _on_anti_frida_message(self, message, data):
        """Handle anti-Frida detection script messages."""
        if message["type"] == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict):
                msg_type = payload.get("type", "anti_frida_info")
                if "anti_frida_detection" not in self.analysis_results:
                    self.analysis_results["anti_frida_detection"] = []
                self.analysis_results["anti_frida_detection"].append(payload)
                logging.info(f"Anti-Frida Detection: {payload}")

    def run_comprehensive_analysis(self, duration: int = 30) -> Dict[str, Any]:
        """
        Run comprehensive Frida-based analysis.

        Args:
            duration: Analysis duration in seconds

        Returns:
            Dict containing analysis results
        """
        analysis_report = {
            "status": "success",
            "package_name": self.package_name,
            "analysis_duration": duration,
            "frida_version": "unknown",
            "scripts_loaded": [],
            "findings": {},
            "recommendations": [],
        }

        try:
            # Check Frida availability
            is_available, status_msg = self.check_frida_availability()
            if not is_available:
                analysis_report["status"] = "failed"
                analysis_report["error"] = status_msg
                return analysis_report

            # Start Frida server
            if not self.start_frida_server():
                logging.warning("Frida server start failed, continuing with analysis")

            # Attach to application
            if not self.attach_to_app():
                analysis_report["status"] = "failed"
                analysis_report["error"] = "Failed to attach to application"
                return analysis_report

            # Load analysis scripts
            scripts_status = {
                "ssl_bypass": self.load_ssl_pinning_bypass_script(),
                "webview_security": self.load_webview_security_script(),
                "anti_frida": self.load_anti_frida_detection_script(),
            }

            analysis_report["scripts_loaded"] = [
                name for name, loaded in scripts_status.items() if loaded
            ]

            # Run analysis for specified duration
            logging.info(f"Running Frida analysis for {duration} seconds...")
            time.sleep(duration)

            # Collect results
            analysis_report["findings"] = self.analysis_results.copy()

            # Generate recommendations
            analysis_report["recommendations"] = self._generate_recommendations()

        except Exception as e:
            logging.error(f"Frida analysis failed: {e}")
            analysis_report["status"] = "failed"
            analysis_report["error"] = str(e)

        finally:
            self.cleanup()

        return analysis_report

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on analysis results."""
        recommendations = []

        # SSL/TLS recommendations
        if (
            "ssl_bypass" in self.analysis_results
            and self.analysis_results["ssl_bypass"]
        ):
            recommendations.append("Implement certificate pinning with backup pins")
            recommendations.append("Use certificate transparency monitoring")
            recommendations.append(
                "Implement anti-tampering checks for SSL configuration"
            )

        # WebView recommendations
        if "webview_security" in self.analysis_results:
            webview_findings = self.analysis_results["webview_security"]
            for finding in webview_findings:
                if finding.get("type") == "webview_js_enabled" and finding.get("data"):
                    recommendations.append(
                        "Review JavaScript bridge security and input validation"
                    )
                if finding.get("type") == "webview_file_access" and finding.get("data"):
                    recommendations.append(
                        "Disable file access in WebView unless absolutely necessary"
                    )
                if finding.get("type") == "webview_universal_access" and finding.get(
                    "data"
                ):
                    recommendations.append("Disable universal access from file URLs")

        # Anti-Frida recommendations
        if (
            "anti_frida_detection" in self.analysis_results
            and self.analysis_results["anti_frida_detection"]
        ):
            recommendations.append(
                "Implement runtime application self-protection (RASP)"
            )
            recommendations.append("Add integrity checks and anti-tampering mechanisms")
            recommendations.append("Use code obfuscation and anti-debugging techniques")

        return recommendations

    def cleanup(self) -> None:
        """Clean up Frida session and temporary files."""
        try:
            # Unload scripts
            for script_name, script in self.scripts.items():
                try:
                    script.unload()
                    logging.info(f"Unloaded Frida script: {script_name}")
                except Exception as e:
                    logging.warning(f"Failed to unload script {script_name}: {e}")

            # Detach session
            if self.session:
                try:
                    self.session.detach()
                    logging.info("Detached Frida session")
                except Exception as e:
                    logging.warning(f"Failed to detach Frida session: {e}")

            # Clean up temp directory
            if self.temp_dir and self.temp_dir.exists():
                import shutil

                shutil.rmtree(self.temp_dir)
                logging.info(f"Cleaned up Frida temp directory: {self.temp_dir}")

        except Exception as e:
            logging.warning(f"Frida cleanup failed: {e}")

def run_frida_analysis(apk_ctx, duration: int = 30) -> Tuple[str, Union[str, Text]]:
    """
    Run comprehensive Frida-based dynamic analysis.

    Args:
        apk_ctx: APKContext instance
        duration: Analysis duration in seconds

    Returns:
        Tuple containing title and formatted results
    """
    if not apk_ctx.package_name:
        return (
            "Frida Dynamic Analysis",
            Text.from_markup("[red]Error: Package name not available[/red]"),
        )

    try:
        # Initialize Frida manager
        frida_manager = FridaManager(apk_ctx.package_name)

        # Run comprehensive analysis
        analysis = frida_manager.run_comprehensive_analysis(duration)

        # Format results for display
        result = _format_frida_results(analysis)

        return ("Frida Dynamic Analysis", result)

    except Exception as e:
        logging.error(f"Frida analysis failed: {e}")
        return (
            "Frida Dynamic Analysis",
            Text.from_markup(f"[red]Analysis failed: {e}[/red]"),
        )

def _format_frida_results(analysis: Dict) -> Text:
    """Format Frida analysis results for display."""
    output = Text()

    # Header
    output.append("Frida Dynamic Security Analysis\n", style="bold blue")
    output.append("=" * 50 + "\n\n", style="blue")

    if analysis["status"] == "failed":
        output.append("❌ Analysis Failed\n", style="red")
        output.append(f"Error: {analysis.get('error', 'Unknown error')}\n", style="red")

        # Provide installation guidance if Frida is not available
        if "not found" in analysis.get("error", "").lower():
            output.append("\nFrida Installation Guide\n", style="bold yellow")
            output.append("• Install Frida tools: pip install frida-tools\n")
            output.append("• Download frida-server for your device architecture\n")
            output.append(
                "• Push frida-server to device: adb push frida-server /data/local/tmp/\n"
            )
            output.append(
                "• Make executable: adb shell chmod 755 /data/local/tmp/frida-server\n"
            )
            output.append(
                "• Run as root: adb shell su -c '/data/local/tmp/frida-server &'\n"
            )

        return output

    # Analysis summary
    output.append("Analysis Summary\n", style="bold")
    output.append(f"• Package: {analysis.get('package_name', 'unknown')}\n")
    output.append(f"• Duration: {analysis.get('analysis_duration', 0)} seconds\n")
    output.append(f"• Scripts Loaded: {len(analysis.get('scripts_loaded', []))}\n")

    scripts_loaded = analysis.get("scripts_loaded", [])
    if scripts_loaded:
        output.append("• Active Scripts: ", style="cyan")
        output.append(f"{', '.join(scripts_loaded)}\n", style="cyan")

    output.append("\n")

    # Findings
    findings = analysis.get("findings", {})

    # SSL/TLS Analysis
    ssl_findings = findings.get("ssl_bypass", [])
    if ssl_findings:
        output.append("🔒 SSL/TLS Security Analysis\n", style="bold red")
        output.append(f"• SSL Bypass Events: {len(ssl_findings)}\n", style="red")
        output.append("• Certificate pinning may be bypassable\n", style="red")
        output.append("• Network traffic interception possible\n", style="red")
        output.append("\n")
    else:
        output.append("🔒 SSL/TLS Security Analysis\n", style="bold green")
        output.append("• No SSL bypass events detected\n", style="green")
        output.append("• Certificate pinning appears to be working\n", style="green")
        output.append("\n")

    # WebView Security Analysis
    webview_findings = findings.get("webview_security", [])
    if webview_findings:
        output.append("🌐 WebView Security Analysis\n", style="bold yellow")
        output.append(f"• WebView Events: {len(webview_findings)}\n", style="yellow")

        # Analyze specific WebView security issues
        js_enabled = any(
            f.get("type") == "webview_js_enabled" and f.get("data")
            for f in webview_findings
        )
        file_access = any(
            f.get("type") == "webview_file_access" and f.get("data")
            for f in webview_findings
        )
        universal_access = any(
            f.get("type") == "webview_universal_access" and f.get("data")
            for f in webview_findings
        )

        if js_enabled:
            output.append("• ⚠️  JavaScript enabled in WebView\n", style="yellow")
        if file_access:
            output.append("• ⚠️  File access enabled in WebView\n", style="yellow")
        if universal_access:
            output.append("• ❌ Universal access from file URLs enabled\n", style="red")

        output.append("\n")

    # Anti-Frida Detection
    anti_frida_findings = findings.get("anti_frida_detection", [])
    if anti_frida_findings:
        output.append("🛡️  Anti-Tampering Analysis\n", style="bold red")
        output.append(f"• Anti-Frida Events: {len(anti_frida_findings)}\n", style="red")
        output.append("• Application has anti-tampering mechanisms\n", style="red")
        output.append("• Runtime protection detected\n", style="red")
        output.append("\n")
    else:
        output.append("🛡️  Anti-Tampering Analysis\n", style="bold yellow")
        output.append("• No anti-Frida detection observed\n", style="yellow")
        output.append(
            "• Application may be vulnerable to runtime manipulation\n", style="yellow"
        )
        output.append("\n")

    # Recommendations
    recommendations = analysis.get("recommendations", [])
    if recommendations:
        output.append("Security Recommendations\n", style="bold green")
        for rec in recommendations:
            output.append(f"• {rec}\n", style="green")
        output.append("\n")

    # MASVS Mappings
    output.append("MASVS Control Mappings\n", style="bold blue")
    output.append("• MSTG-NETWORK-03: SSL/TLS certificate validation\n", style="cyan")
    output.append(
        "• MSTG-NETWORK-04: Certificate pinning implementation\n", style="cyan"
    )
    output.append("• MASVS-PLATFORM-3: WebView security configuration\n", style="cyan")
    output.append("• MSTG-RESILIENCE-01: Anti-tampering mechanisms\n", style="cyan")
    output.append(
        "• MSTG-RESILIENCE-02: Runtime application self-protection\n", style="cyan"
    )

    return output
