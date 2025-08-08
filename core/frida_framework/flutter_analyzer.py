#!/usr/bin/env python3
"""
Flutter Analyzer for Frida Framework

Flutter-specific analysis and script generation for dynamic security testing.
Provides architecture-aware SSL bypass capabilities and comprehensive Flutter support.

Components:
- FlutterAnalyzer: Main Flutter analysis coordination
- Architecture detection and analysis
- Flutter-specific Frida script generation
- SSL bypass capability assessment

"""

import logging
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    from ..flutter_analyzer import FlutterSecurityAnalyzer, FlutterArchitectureInfo, FlutterSSLBypassCapability
    FLUTTER_ANALYZER_AVAILABLE = True
except ImportError:
    FLUTTER_ANALYZER_AVAILABLE = False
    logging.warning("Flutter analyzer not available for Frida integration")
    
    # Create placeholder classes for type hints
    class FlutterSecurityAnalyzer:
        pass
    
    class FlutterArchitectureInfo:
        pass
    
    class FlutterSSLBypassCapability:
        pass

class FlutterAnalyzer:
    """Flutter-specific analysis and script generation for Frida."""

    def __init__(self):
        """Initialize Flutter analyzer."""
        self.flutter_analyzer = FlutterSecurityAnalyzer() if FLUTTER_ANALYZER_AVAILABLE else None
        self.flutter_architecture_info: Optional[FlutterArchitectureInfo] = None
        self.flutter_bypass_capabilities: List[FlutterSSLBypassCapability] = []
        self.flutter_scripts_loaded = False
        self.generated_scripts: Dict[str, str] = {}

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
            
            # Step 3: Generate Frida scripts
            if architecture_info:
                logging.info("Generating architecture-aware Frida scripts...")
                frida_scripts = self._generate_flutter_frida_scripts()
                results["frida_scripts_generated"] = frida_scripts
                results["analysis_success"] = True
            else:
                logging.warning("Flutter architecture not detected - skipping script generation")
            
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
                if hasattr(capability, 'frida_script') and capability.frida_script:
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
            logging.error(f"Flutter script generation failed: {e}")
        
        return scripts_generated

    def _save_frida_script(self, script_name: str, script_content: str) -> None:
        """Save Frida script to temporary file."""
        try:
            # Create temp directory if it doesn't exist
            temp_dir = Path(tempfile.gettempdir()) / "frida_scripts"
            temp_dir.mkdir(exist_ok=True)
            
            # Save script content
            script_path = temp_dir / f"{script_name}.js"
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            # Store in memory for later use
            self.generated_scripts[script_name] = script_content
            logging.info(f"Saved Frida script: {script_path}")
            
        except Exception as e:
            logging.error(f"Failed to save Frida script {script_name}: {e}")

    def _generate_comprehensive_flutter_script(self) -> str:
        """Generate comprehensive Flutter SSL bypass script."""
        if not self.flutter_architecture_info:
            return ""
        
        script_template = '''
// Comprehensive Flutter SSL Bypass Script
// Architecture: {architecture}
// Generated for package: {package_name}

Java.perform(function() {{
    console.log("[+] Starting Flutter SSL bypass for {architecture}");
    
    try {{
        // Hook Flutter SSL verification functions
        var libflutter = Module.findBaseAddress("libflutter.so");
        if (libflutter) {{
            console.log("[+] Found libflutter.so at: " + libflutter);
            
            // Hook SSL verification offset: {ssl_verify_offset}
            var ssl_verify_ptr = libflutter.add({ssl_verify_offset});
            Interceptor.attach(ssl_verify_ptr, {{
                onEnter: function(args) {{
                    console.log("[+] SSL verification called");
                }},
                onLeave: function(retval) {{
                    console.log("[+] Bypassing SSL verification - returning 1");
                    retval.replace(1);
                }}
            }});
            
            console.log("[+] Flutter SSL bypass hooks installed");
        }} else {{
            console.log("[-] libflutter.so not found");
        }}
        
        // Additional BoringSSL hooks for Flutter
        var boringssl = Module.findBaseAddress("libssl.so");
        if (boringssl) {{
            console.log("[+] Found BoringSSL library");
            
            // Hook common SSL verification functions
            var ssl_verify_cert_chain = Module.findExportByName("libssl.so", "SSL_verify_cert_chain");
            if (ssl_verify_cert_chain) {{
                Interceptor.attach(ssl_verify_cert_chain, {{
                    onLeave: function(retval) {{
                        console.log("[+] Bypassing SSL_verify_cert_chain");
                        retval.replace(1);
                    }}
                }});
            }}
        }}
        
    }} catch (e) {{
        console.log("[-] Flutter SSL bypass error: " + e.message);
    }}
}});
'''
        
        return script_template.format(
            architecture=self.flutter_architecture_info.architecture,
            package_name="flutter_app",  # This would be passed in
            ssl_verify_offset=getattr(self.flutter_architecture_info, 'ssl_verify_function_offset', '0x0')
        )

    def _generate_jni_offset_calculation_script(self) -> str:
        """Generate JNI offset calculation script for Flutter."""
        script = '''
// JNI Offset Calculation for Flutter
Java.perform(function() {
    console.log("[+] Starting JNI offset calculation");
    
    var libflutter = Module.findBaseAddress("libflutter.so");
    if (libflutter) {
        console.log("[+] libflutter.so base address: " + libflutter);
        
        // Calculate JNI_OnLoad offset
        var jni_onload = Module.findExportByName("libflutter.so", "JNI_OnLoad");
        if (jni_onload) {
            var offset = jni_onload.sub(libflutter);
            console.log("[+] JNI_OnLoad offset: " + offset);
        }
        
        // Scan for SSL verification patterns
        Memory.scan(libflutter, Process.pageSize, "48 89 e5 41 57 41 56", {
            onMatch: function(address, size) {
                var offset = address.sub(libflutter);
                console.log("[+] Potential SSL verification function at offset: " + offset);
            },
            onComplete: function() {
                console.log("[+] Memory scan complete");
            }
        });
    }
});
'''
        return script

    def _generate_architecture_specific_scanning_script(self) -> str:
        """Generate architecture-specific memory scanning script."""
        if not self.flutter_architecture_info:
            return ""
        
        arch = self.flutter_architecture_info.architecture
        
        if arch == "arm64":
            patterns = ["48 89 e5 41 57 41 56", "fd 7b bf a9 fd 03 00 91"]
        elif arch == "arm":
            patterns = ["80 b5 82 b0", "00 48 2d e9 04 b0 8d e2"]
        else:
            patterns = ["48 89 e5 41 57 41 56"]
        
        script = f'''
// Architecture-specific scanning for {arch}
Java.perform(function() {{
    console.log("[+] Starting {arch} architecture scanning");
    
    var libflutter = Module.findBaseAddress("libflutter.so");
    if (libflutter) {{
        var patterns = {patterns};
        
        patterns.forEach(function(pattern) {{
            Memory.scan(libflutter, Process.pageSize * 100, pattern, {{
                onMatch: function(address, size) {{
                    var offset = address.sub(libflutter);
                    console.log("[+] Pattern match at offset: " + offset + " (pattern: " + pattern + ")");
                }},
                onComplete: function() {{
                    console.log("[+] Scan complete for pattern: " + pattern);
                }}
            }});
        }});
    }}
}});
'''
        return script

    def get_generated_scripts(self) -> Dict[str, str]:
        """Get all generated Flutter scripts."""
        return self.generated_scripts.copy()

    def is_flutter_analyzer_available(self) -> bool:
        """Check if Flutter analyzer is available."""
        return FLUTTER_ANALYZER_AVAILABLE and self.flutter_analyzer is not None

    def get_architecture_info(self) -> Optional[FlutterArchitectureInfo]:
        """Get detected Flutter architecture information."""
        return self.flutter_architecture_info

    def get_bypass_capabilities(self) -> List[FlutterSSLBypassCapability]:
        """Get detected Flutter SSL bypass capabilities."""
        return self.flutter_bypass_capabilities.copy()

# Export the Flutter analyzer
__all__ = ['FlutterAnalyzer'] 