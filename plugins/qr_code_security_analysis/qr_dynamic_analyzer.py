"""
QR Code Dynamic Analyzer

Provides runtime monitoring of QR code scanning APIs using Frida hooks.
Detects malicious QR code content and unsafe QR code handling patterns.
"""

import logging
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from core.apk_ctx import APKContext

logger = logging.getLogger(__name__)

@dataclass
class QRRuntimeEvent:
    """Represents a QR code runtime event."""
    event_type: str
    timestamp: float
    qr_content: str
    library: str
    risk_level: str
    evidence: Dict[str, Any]

class QRCodeDynamicAnalyzer:
    """Dynamic analyzer for QR code runtime security monitoring."""
    
    def __init__(self):
        """Initialize the dynamic analyzer."""
        self.logger = logger
        self.runtime_events = []
        
        # Malicious QR code patterns
        self.malicious_patterns = {
            "url_injection": [
                r"javascript:",
                r"data:",
                r"file:",
                r"ftp:",
                r"vbscript:",
                r"about:"
            ],
            "intent_injection": [
                r"intent://.*#Intent.*scheme=",
                r"content://settings",
                r"content://.*secure",
                r"content://.*system"
            ],
            "phishing_indicators": [
                r"bit\.ly",
                r"tinyurl",
                r"goo\.gl",
                r"t\.co",
                r"ow\.ly"
            ],
            "sensitive_data_exposure": [
                r"password=",
                r"token=",
                r"api_key=",
                r"secret=",
                r"auth="
            ]
        }
    
    def analyze_qr_runtime(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Perform runtime analysis of QR code scanning.
        
        Args:
            apk_ctx: The APK context for analysis
            
        Returns:
            Dictionary containing dynamic analysis results
        """
        try:
            self.logger.info("Starting QR code dynamic analysis")
            
            results = {
                "runtime_monitoring": {},
                "malicious_qr_detected": [],
                "qr_events": [],
                "vulnerability_detections": [],
                "monitoring_stats": {
                    "total_events": 0,
                    "malicious_events": 0,
                    "monitoring_duration": 0
                }
            }
            
            # Start runtime monitoring if Frida manager is available
            if hasattr(apk_ctx, 'frida_manager') and apk_ctx.frida_manager:
                monitoring_results = self._start_qr_monitoring(apk_ctx.frida_manager)
                results["runtime_monitoring"] = monitoring_results
                
                # Analyze collected events
                analysis = self._analyze_runtime_events()
                results.update(analysis)
            else:
                self.logger.warning("Frida manager not available - skipping dynamic QR analysis")
                results["runtime_monitoring"] = {"error": "Frida manager not available"}
            
            return results
            
        except Exception as e:
            self.logger.error(f"QR dynamic analysis failed: {e}")
            return {
                "error": str(e),
                "runtime_monitoring": {},
                "malicious_qr_detected": []
            }
    
    def _start_qr_monitoring(self, frida_manager) -> Dict[str, Any]:
        """Start Frida-based QR code monitoring."""
        try:
            self.logger.info("Starting Frida QR code monitoring")
            
            # Load and execute QR monitoring script
            qr_script = self._generate_qr_monitoring_script()
            
            # Execute the script using Frida manager
            script_result = frida_manager.execute_script(qr_script, "qr_code_monitoring")
            
            if script_result and script_result.get("success"):
                return {
                    "status": "monitoring_active",
                    "script_loaded": True,
                    "monitoring_targets": [
                        "ZXing BarcodeReader",
                        "ML Kit BarcodeDetector", 
                        "Intent handling",
                        "WebView URL loading",
                        "Camera API"
                    ]
                }
            else:
                return {
                    "status": "monitoring_failed",
                    "script_loaded": False,
                    "error": script_result.get("error", "Unknown error")
                }
                
        except Exception as e:
            self.logger.error(f"QR monitoring startup failed: {e}")
            return {
                "status": "monitoring_error",
                "error": str(e)
            }
    
    def _generate_qr_monitoring_script(self) -> str:
        """Generate Frida script for QR code monitoring."""
        script = """
        Java.perform(function() {
            console.log("[QR-MONITOR] QR code monitoring started");
            
            var qrEvents = [];
            
            // Helper function to send QR event
            function sendQREvent(eventType, content, library, evidence) {
                var event = {
                    type: "qr_code_event",
                    event_type: eventType,
                    timestamp: Date.now(),
                    qr_content: content ? content.substring(0, 500) : "",
                    library: library,
                    evidence: evidence || {}
                };
                
                // Check for malicious patterns
                if (content) {
                    event.risk_level = analyzeMaliciousContent(content);
                }
                
                console.log("[QR-EVENT] " + JSON.stringify(event));
                send(event);
            }
            
            // Analyze QR content for malicious patterns
            function analyzeMaliciousContent(content) {
                var lowerContent = content.toLowerCase();
                
                // Check for dangerous URL schemes
                if (lowerContent.includes("javascript:") || lowerContent.includes("file:") || 
                    lowerContent.includes("data:") || lowerContent.includes("vbscript:")) {
                    return "HIGH";
                }
                
                // Check for intent injection
                if (lowerContent.includes("intent://") && lowerContent.includes("#intent")) {
                    return "MEDIUM";
                }
                
                // Check for sensitive content providers
                if (lowerContent.includes("content://settings") || lowerContent.includes("content://secure")) {
                    return "HIGH";
                }
                
                // Check for URL shorteners (potential phishing)
                if (lowerContent.includes("bit.ly") || lowerContent.includes("tinyurl") || 
                    lowerContent.includes("goo.gl") || lowerContent.includes("t.co")) {
                    return "MEDIUM";
                }
                
                // Check for sensitive data exposure
                if (lowerContent.includes("password=") || lowerContent.includes("token=") || 
                    lowerContent.includes("api_key=") || lowerContent.includes("secret=")) {
                    return "HIGH";
                }
                
                return "LOW";
            }
            
            try {
                // Hook ZXing BarcodeReader
                var BarcodeReader = Java.use("com.google.zxing.BarcodeReader");
                if (BarcodeReader) {
                    BarcodeReader.decode.implementation = function(image) {
                        var result = this.decode(image);
                        if (result) {
                            var qrText = result.getText();
                            sendQREvent("qr_decode", qrText, "ZXing", {
                                method: "BarcodeReader.decode",
                                format: result.getBarcodeFormat().toString(),
                                stack_trace: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                            });
                        }
                        return result;
                    };
                }
            } catch (e) {
                console.log("[QR-MONITOR] ZXing BarcodeReader not found: " + e);
            }
            
            try {
                // Hook ZXing IntentIntegrator
                var IntentIntegrator = Java.use("com.google.zxing.integration.android.IntentIntegrator");
                if (IntentIntegrator) {
                    IntentIntegrator.parseActivityResult.implementation = function(requestCode, resultCode, intent) {
                        var result = this.parseActivityResult(requestCode, resultCode, intent);
                        if (result && result.getContents()) {
                            sendQREvent("qr_scan_result", result.getContents(), "ZXing-Intent", {
                                method: "IntentIntegrator.parseActivityResult",
                                format: result.getFormatName(),
                                request_code: requestCode,
                                result_code: resultCode
                            });
                        }
                        return result;
                    };
                }
            } catch (e) {
                console.log("[QR-MONITOR] ZXing IntentIntegrator not found: " + e);
            }
            
            try {
                // Hook ML Kit BarcodeDetector
                var BarcodeDetector = Java.use("com.google.android.gms.vision.barcode.BarcodeDetector");
                if (BarcodeDetector) {
                    BarcodeDetector.detect.implementation = function(frame) {
                        var barcodes = this.detect(frame);
                        if (barcodes && barcodes.size() > 0) {
                            for (var i = 0; i < barcodes.size(); i++) {
                                var barcode = barcodes.valueAt(i);
                                if (barcode.displayValue) {
                                    sendQREvent("qr_detect", barcode.displayValue, "MLKit", {
                                        method: "BarcodeDetector.detect",
                                        value_format: barcode.valueFormat,
                                        corner_points: barcode.cornerPoints ? barcode.cornerPoints.length : 0
                                    });
                                }
                            }
                        }
                        return barcodes;
                    };
                }
            } catch (e) {
                console.log("[QR-MONITOR] ML Kit BarcodeDetector not found: " + e);
            }
            
            try {
                // Hook Intent creation from QR codes
                var Intent = Java.use("android.content.Intent");
                var originalInit = Intent.$init.overload('java.lang.String', 'android.net.Uri');
                originalInit.implementation = function(action, uri) {
                    if (uri) {
                        var uriString = uri.toString();
                        // Check if this might be from a QR code (heuristic)
                        if (uriString.length > 10 && (uriString.startsWith("http") || 
                            uriString.startsWith("intent://") || uriString.startsWith("content://"))) {
                            sendQREvent("intent_from_qr", uriString, "Intent", {
                                method: "Intent.init",
                                action: action,
                                uri_scheme: uri.getScheme(),
                                stack_trace: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                            });
                        }
                    }
                    return originalInit.call(this, action, uri);
                };
            } catch (e) {
                console.log("[QR-MONITOR] Intent hooking failed: " + e);
            }
            
            try {
                // Hook WebView URL loading (potential QR code URLs)
                var WebView = Java.use("android.webkit.WebView");
                WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
                    // Check for suspicious URLs that might come from QR codes
                    if (url && (url.startsWith("javascript:") || url.startsWith("file:") || 
                        url.startsWith("data:") || url.includes("qr") || url.includes("scan"))) {
                        sendQREvent("webview_qr_url", url, "WebView", {
                            method: "WebView.loadUrl",
                            url_scheme: url.split(":")[0],
                            suspicious: true
                        });
                    }
                    return this.loadUrl(url);
                };
            } catch (e) {
                console.log("[QR-MONITOR] WebView hooking failed: " + e);
            }
            
            try {
                // Hook Camera API for QR scanning detection
                var Camera = Java.use("android.hardware.Camera");
                Camera.open.overload('int').implementation = function(cameraId) {
                    sendQREvent("camera_open", "", "Camera", {
                        method: "Camera.open",
                        camera_id: cameraId,
                        potential_qr_scanning: true
                    });
                    return this.open(cameraId);
                };
            } catch (e) {
                console.log("[QR-MONITOR] Camera hooking failed: " + e);
            }
            
            console.log("[QR-MONITOR] QR code monitoring hooks installed successfully");
        });
        """
        
        return script
    
    def _analyze_runtime_events(self) -> Dict[str, Any]:
        """Analyze collected runtime events for vulnerabilities."""
        analysis = {
            "malicious_qr_detected": [],
            "qr_events": [],
            "vulnerability_detections": [],
            "monitoring_stats": {
                "total_events": len(self.runtime_events),
                "malicious_events": 0,
                "monitoring_duration": 0
            }
        }
        
        malicious_count = 0
        
        for event in self.runtime_events:
            analysis["qr_events"].append({
                "type": event.event_type,
                "timestamp": event.timestamp,
                "content": event.qr_content[:100] + "..." if len(event.qr_content) > 100 else event.qr_content,
                "library": event.library,
                "risk_level": event.risk_level
            })
            
            if event.risk_level in ["HIGH", "MEDIUM"]:
                malicious_count += 1
                analysis["malicious_qr_detected"].append({
                    "content": event.qr_content,
                    "risk_level": event.risk_level,
                    "detection_reason": self._get_detection_reason(event.qr_content),
                    "library": event.library,
                    "timestamp": event.timestamp
                })
                
                # Create vulnerability detection
                vulnerability = self._create_vulnerability_from_event(event)
                if vulnerability:
                    analysis["vulnerability_detections"].append(vulnerability)
        
        analysis["monitoring_stats"]["malicious_events"] = malicious_count
        
        return analysis
    
    def _get_detection_reason(self, content: str) -> str:
        """Get reason why QR content was flagged as malicious."""
        content_lower = content.lower()
        
        if any(pattern in content_lower for pattern in self.malicious_patterns["url_injection"]):
            return "Dangerous URL scheme detected"
        elif any(pattern in content_lower for pattern in self.malicious_patterns["intent_injection"]):
            return "Intent injection pattern detected"
        elif any(pattern in content_lower for pattern in self.malicious_patterns["phishing_indicators"]):
            return "Potential phishing URL detected"
        elif any(pattern in content_lower for pattern in self.malicious_patterns["sensitive_data_exposure"]):
            return "Sensitive data exposure detected"
        else:
            return "Suspicious pattern detected"
    
    def _create_vulnerability_from_event(self, event: QRRuntimeEvent) -> Optional[Dict[str, Any]]:
        """Create vulnerability report from runtime event."""
        if event.risk_level == "LOW":
            return None
        
        vulnerability = {
            "type": "qr_code_vulnerability",
            "subtype": self._determine_vulnerability_subtype(event.qr_content),
            "severity": "HIGH" if event.risk_level == "HIGH" else "MEDIUM",
            "title": f"Malicious QR Code Content Detected",
            "description": f"QR code scanning detected malicious content: {event.qr_content[:100]}",
            "evidence": {
                "qr_content": event.qr_content,
                "detection_library": event.library,
                "risk_level": event.risk_level,
                "timestamp": event.timestamp,
                "detection_reason": self._get_detection_reason(event.qr_content)
            },
            "cwe_id": "CWE-20",  # Improper Input Validation
            "masvs_control": "MASVS-CODE-4",
            "recommendations": [
                "Implement input validation for QR code content",
                "Sanitize URLs before processing",
                "Use allowlists for acceptable URL schemes",
                "Validate intent URIs before launching activities"
            ]
        }
        
        return vulnerability
    
    def _determine_vulnerability_subtype(self, content: str) -> str:
        """Determine specific vulnerability subtype based on QR content."""
        content_lower = content.lower()
        
        if any(pattern in content_lower for pattern in self.malicious_patterns["url_injection"]):
            return "url_injection"
        elif any(pattern in content_lower for pattern in self.malicious_patterns["intent_injection"]):
            return "intent_injection"
        elif any(pattern in content_lower for pattern in self.malicious_patterns["phishing_indicators"]):
            return "phishing_url"
        elif any(pattern in content_lower for pattern in self.malicious_patterns["sensitive_data_exposure"]):
            return "data_exposure"
        else:
            return "input_validation_bypass"