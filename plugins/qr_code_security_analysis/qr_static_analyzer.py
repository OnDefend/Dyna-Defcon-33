"""
QR Code Static Analyzer

Analyzes APKs for QR code libraries, camera permissions, and QR-related code patterns.
Detects potential security issues in QR code implementations through static analysis.
"""

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from core.apk_ctx import APKContext

logger = logging.getLogger(__name__)

@dataclass
class QRLibraryInfo:
    """Information about detected QR code library."""
    name: str
    package: str
    version: Optional[str] = None
    usage_patterns: List[str] = None
    security_features: List[str] = None
    known_vulnerabilities: List[str] = None

class QRCodeStaticAnalyzer:
    """Static analyzer for QR code security vulnerabilities."""
    
    def __init__(self):
        """Initialize the static analyzer."""
        self.logger = logger
        
        # Common QR code libraries and their patterns
        self.qr_libraries = {
            "zxing": {
                "packages": [
                    "com.google.zxing",
                    "com.journeyapps.barcodescanner",
                    "me.dm7.barcodescanner"
                ],
                "classes": [
                    "BarcodeReader", "IntentIntegrator", "DecodeThread",
                    "CaptureActivity", "QRCodeReader", "MultiFormatReader"
                ],
                "methods": [
                    "decode", "decodeWithState", "getReader", "scan",
                    "initializeFromIntent", "parseActivityResult"
                ]
            },
            "mlkit": {
                "packages": [
                    "com.google.mlkit.vision.barcode",
                    "com.google.android.gms.vision.barcode"
                ],
                "classes": [
                    "BarcodeDetector", "BarcodeScanning", "Barcode",
                    "BarcodeScannerOptions", "BarcodeDetectorOptions"
                ],
                "methods": [
                    "process", "detectInImage", "getClient",
                    "setBarcodeFormats", "build"
                ]
            },
            "qr_generator": {
                "packages": [
                    "androidmads.library.qrgenearator",
                    "com.github.kenglxn.QRGen"
                ],
                "classes": [
                    "QRGContents", "QRGEncoder", "QRCodeGenerator"
                ],
                "methods": [
                    "createQRCode", "encodeAsBitmap", "generateQRCode"
                ]
            }
        }
        
        # QR code vulnerability patterns
        self.vulnerability_patterns = {
            "url_injection": [
                r'loadUrl\s*\(\s*qr.*\)',
                r'startActivity\s*\(\s*.*qr.*\)',
                r'javascript:\s*\+\s*qr',
                r'file://\s*\+\s*qr'
            ],
            "intent_injection": [
                r'Intent\.parseUri\s*\(\s*qr.*\)',
                r'Intent\s*\(\s*.*qr.*\)',
                r'setData\s*\(\s*Uri\.parse\s*\(\s*qr.*\)\s*\)'
            ],
            "input_validation_bypass": [
                r'qr.*\.substring\s*\(',
                r'qr.*\.replace\s*\(',
                r'qr.*\.trim\s*\(',
                r'new\s+URL\s*\(\s*qr.*\)'
            ],
            "camera_permission_abuse": [
                r'Camera\.open\s*\(',
                r'camera\.startPreview\s*\(',
                r'SurfaceView.*camera'
            ]
        }
    
    def analyze_qr_libraries(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Analyze APK for QR code libraries and related security issues.
        
        Args:
            apk_ctx: The APK context for analysis
            
        Returns:
            Dictionary containing static analysis results
        """
        try:
            self.logger.info("Starting QR code static analysis")
            
            results = {
                "libraries_detected": [],
                "libraries_found": 0,
                "camera_permissions": [],
                "has_camera_permission": False,
                "qr_activities": [],
                "vulnerability_patterns": [],
                "code_analysis": {
                    "files_analyzed": 0,
                    "patterns_detected": 0
                },
                "security_assessment": {}
            }
            
            # Analyze manifest for camera permissions and QR-related activities
            manifest_analysis = self._analyze_manifest(apk_ctx)
            results.update(manifest_analysis)
            
            # Detect QR code libraries
            library_analysis = self._detect_qr_libraries(apk_ctx)
            results["libraries_detected"] = library_analysis
            results["libraries_found"] = len(library_analysis)
            
            # Analyze source code for QR-related vulnerabilities
            code_analysis = self._analyze_source_code(apk_ctx)
            results["vulnerability_patterns"] = code_analysis["patterns"]
            results["code_analysis"] = code_analysis["stats"]
            
            # Generate security assessment
            security_assessment = self._generate_security_assessment(results)
            results["security_assessment"] = security_assessment
            
            self.logger.info(f"QR static analysis completed: {results['libraries_found']} libraries detected")
            return results
            
        except Exception as e:
            self.logger.error(f"QR static analysis failed: {e}")
            return {
                "error": str(e),
                "libraries_detected": [],
                "libraries_found": 0
            }
    
    def _analyze_manifest(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """Analyze AndroidManifest.xml for camera permissions and QR activities."""
        manifest_results = {
            "camera_permissions": [],
            "has_camera_permission": False,
            "qr_activities": []
        }
        
        try:
            # Get manifest path
            manifest_path = self._get_manifest_path(apk_ctx)
            if not manifest_path or not manifest_path.exists():
                self.logger.warning("AndroidManifest.xml not found")
                return manifest_results
            
            # Parse manifest
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Check for camera permissions
            permissions = root.findall(".//uses-permission")
            for permission in permissions:
                name = permission.get('{http://schemas.android.com/apk/res/android}name', '')
                if 'CAMERA' in name:
                    manifest_results["camera_permissions"].append(name)
                    manifest_results["has_camera_permission"] = True
            
            # Check for QR-related activities
            activities = root.findall(".//activity")
            for activity in activities:
                name = activity.get('{http://schemas.android.com/apk/res/android}name', '')
                if any(qr_term in name.lower() for qr_term in ['qr', 'barcode', 'scan', 'capture']):
                    manifest_results["qr_activities"].append(name)
            
        except Exception as e:
            self.logger.error(f"Manifest analysis failed: {e}")
        
        return manifest_results
    
    def _detect_qr_libraries(self, apk_ctx: APKContext) -> List[QRLibraryInfo]:
        """Detect QR code libraries in the APK."""
        detected_libraries = []
        
        try:
            # Search in decompiled source code
            source_paths = self._get_source_paths(apk_ctx)
            
            for lib_name, lib_info in self.qr_libraries.items():
                library_detected = False
                usage_patterns = []
                
                # Check for package imports
                for source_path in source_paths:
                    if not source_path.exists():
                        continue
                    
                    for java_file in source_path.rglob("*.java"):
                        try:
                            with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            
                            # Check for package imports
                            for package in lib_info["packages"]:
                                if f"import {package}" in content:
                                    library_detected = True
                                    usage_patterns.append(f"Import: {package}")
                            
                            # Check for class usage
                            for class_name in lib_info["classes"]:
                                if class_name in content:
                                    library_detected = True
                                    usage_patterns.append(f"Class: {class_name}")
                            
                            # Check for method calls
                            for method in lib_info["methods"]:
                                if f".{method}(" in content or f"{method}(" in content:
                                    usage_patterns.append(f"Method: {method}")
                        
                        except Exception as e:
                            self.logger.debug(f"Error reading {java_file}: {e}")
                            continue
                
                if library_detected:
                    library = QRLibraryInfo(
                        name=lib_name,
                        package=lib_info["packages"][0],
                        usage_patterns=list(set(usage_patterns))
                    )
                    detected_libraries.append(library)
                    self.logger.info(f"Detected QR library: {lib_name}")
        
        except Exception as e:
            self.logger.error(f"Library detection failed: {e}")
        
        return detected_libraries
    
    def _analyze_source_code(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """Analyze source code for QR-related vulnerability patterns."""
        analysis_results = {
            "patterns": [],
            "stats": {
                "files_analyzed": 0,
                "patterns_detected": 0
            }
        }
        
        try:
            source_paths = self._get_source_paths(apk_ctx)
            
            for source_path in source_paths:
                if not source_path.exists():
                    continue
                
                for java_file in source_path.rglob("*.java"):
                    try:
                        with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        analysis_results["stats"]["files_analyzed"] += 1
                        
                        # Check for vulnerability patterns
                        for vuln_type, patterns in self.vulnerability_patterns.items():
                            for pattern in patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                                for match in matches:
                                    analysis_results["patterns"].append({
                                        "type": vuln_type,
                                        "pattern": pattern,
                                        "file": str(java_file.relative_to(source_path)),
                                        "match": match.group(0),
                                        "line": content[:match.start()].count('\n') + 1
                                    })
                                    analysis_results["stats"]["patterns_detected"] += 1
                    
                    except Exception as e:
                        self.logger.debug(f"Error analyzing {java_file}: {e}")
                        continue
        
        except Exception as e:
            self.logger.error(f"Source code analysis failed: {e}")
        
        return analysis_results
    
    def _generate_security_assessment(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate security assessment based on static analysis results."""
        assessment = {
            "has_qr_functionality": results["libraries_found"] > 0,
            "camera_permission_granted": results["has_camera_permission"],
            "potential_vulnerabilities": len(results.get("vulnerability_patterns", [])),
            "risk_factors": []
        }
        
        # Identify risk factors
        if results["libraries_found"] > 0 and not results["has_camera_permission"]:
            assessment["risk_factors"].append("QR library without camera permission - possible hidden scanning")
        
        if results["has_camera_permission"] and results["libraries_found"] == 0:
            assessment["risk_factors"].append("Camera permission without QR library - manual implementation risk")
        
        if assessment["potential_vulnerabilities"] > 5:
            assessment["risk_factors"].append("High number of potential vulnerability patterns detected")
        
        # Determine overall risk level
        risk_score = 0
        if assessment["has_qr_functionality"]:
            risk_score += 1
        if assessment["potential_vulnerabilities"] > 0:
            risk_score += assessment["potential_vulnerabilities"] // 2
        if len(assessment["risk_factors"]) > 0:
            risk_score += len(assessment["risk_factors"])
        
        if risk_score >= 5:
            assessment["risk_level"] = "HIGH"
        elif risk_score >= 2:
            assessment["risk_level"] = "MEDIUM"
        else:
            assessment["risk_level"] = "LOW"
        
        return assessment
    
    def _get_manifest_path(self, apk_ctx: APKContext) -> Optional[Path]:
        """Get path to AndroidManifest.xml."""
        if hasattr(apk_ctx, 'get_decompiled_path'):
            decompiled_path = apk_ctx.get_decompiled_path()
            if decompiled_path:
                return Path(decompiled_path) / "AndroidManifest.xml"
        
        # Fallback to workspace
        if hasattr(apk_ctx, 'workspace_dir'):
            return Path(apk_ctx.workspace_dir) / "AndroidManifest.xml"
        
        return None
    
    def _get_source_paths(self, apk_ctx: APKContext) -> List[Path]:
        """Get paths to source code directories."""
        source_paths = []
        
        if hasattr(apk_ctx, 'get_decompiled_path'):
            decompiled_path = apk_ctx.get_decompiled_path()
            if decompiled_path:
                source_paths.append(Path(decompiled_path) / "sources")
                source_paths.append(Path(decompiled_path) / "smali")
        
        if hasattr(apk_ctx, 'workspace_dir'):
            workspace_path = Path(apk_ctx.workspace_dir)
            source_paths.append(workspace_path)
            source_paths.append(workspace_path / "sources")
        
        return [p for p in source_paths if p.exists()]