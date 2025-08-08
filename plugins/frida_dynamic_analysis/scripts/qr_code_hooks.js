/**
 * QR Code Security Monitoring Script
 * 
 * Comprehensive Frida hooks for monitoring QR code scanning and processing.
 * Detects malicious QR code content, intent injection, and input validation bypasses.
 * 
 * Features:
 * - ZXing library monitoring (BarcodeReader, IntentIntegrator)
 * - ML Kit barcode detection monitoring
 * - Intent handling from QR codes
 * - WebView URL loading from QR content
 * - Camera API usage tracking
 * - Malicious pattern detection
 * 
 * @version 1.0.0
 * @author AODS Security Team
 */

Java.perform(function() {
    console.log("[QR-MONITOR] Starting comprehensive QR code security monitoring");
    
    var qrEvents = [];
    var maliciousPatterns = {
        url_injection: ["javascript:", "file:", "data:", "vbscript:", "about:"],
        intent_injection: ["intent://", "#Intent", "content://settings", "content://secure"],
        phishing: ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"],
        sensitive_data: ["password=", "token=", "api_key=", "secret=", "auth="]
    };
    
    // Helper function to send QR event to AODS
    function sendQREvent(eventType, content, library, evidence) {
        var event = {
            type: "qr_code_vulnerability",
            event_type: eventType,
            timestamp: Date.now(),
            qr_content: content ? content.substring(0, 500) : "",
            library: library,
            evidence: evidence || {},
            risk_level: analyzeMaliciousContent(content || ""),
            stack_trace: getCurrentStackTrace()
        };
        
        console.log("[QR-EVENT] " + JSON.stringify(event));
        send(event);
        qrEvents.push(event);
    }
    
    // Analyze QR content for malicious patterns
    function analyzeMaliciousContent(content) {
        if (!content) return "LOW";
        
        var lowerContent = content.toLowerCase();
        
        // Check for dangerous URL schemes (HIGH risk)
        for (var i = 0; i < maliciousPatterns.url_injection.length; i++) {
            if (lowerContent.includes(maliciousPatterns.url_injection[i])) {
                return "HIGH";
            }
        }
        
        // Check for intent injection (MEDIUM-HIGH risk)
        for (var i = 0; i < maliciousPatterns.intent_injection.length; i++) {
            if (lowerContent.includes(maliciousPatterns.intent_injection[i])) {
                return lowerContent.includes("content://settings") || lowerContent.includes("content://secure") ? "HIGH" : "MEDIUM";
            }
        }
        
        // Check for sensitive data exposure (HIGH risk)
        for (var i = 0; i < maliciousPatterns.sensitive_data.length; i++) {
            if (lowerContent.includes(maliciousPatterns.sensitive_data[i])) {
                return "HIGH";
            }
        }
        
        // Check for phishing URLs (MEDIUM risk)
        for (var i = 0; i < maliciousPatterns.phishing.length; i++) {
            if (lowerContent.includes(maliciousPatterns.phishing[i])) {
                return "MEDIUM";
            }
        }
        
        // Check for suspicious patterns
        if (content.length > 1000 || lowerContent.includes("eval(") || lowerContent.includes("<script")) {
            return "MEDIUM";
        }
        
        return "LOW";
    }
    
    // Get current stack trace for evidence
    function getCurrentStackTrace() {
        try {
            var Exception = Java.use("java.lang.Exception");
            var Log = Java.use("android.util.Log");
            return Log.getStackTraceString(Exception.$new());
        } catch (e) {
            return "Stack trace unavailable";
        }
    }
    
    // ================================
    // ZXING LIBRARY MONITORING
    // ================================
    
    try {
        console.log("[QR-MONITOR] Setting up ZXing BarcodeReader hooks...");
        
        var BarcodeReader = Java.use("com.google.zxing.BarcodeReader");
        
        // Hook primary decode method
        BarcodeReader.decode.implementation = function(image) {
            console.log("[QR-SCAN] ZXing BarcodeReader.decode() called");
            
            var result = this.decode(image);
            if (result) {
                var qrText = result.getText();
                var format = result.getBarcodeFormat().toString();
                
                sendQREvent("qr_decode", qrText, "ZXing-BarcodeReader", {
                    method: "BarcodeReader.decode",
                    format: format,
                    raw_bytes: result.getRawBytes() ? result.getRawBytes().length : 0,
                    result_points: result.getResultPoints() ? result.getResultPoints().length : 0
                });
                
                // Check for malicious content
                var riskLevel = analyzeMaliciousContent(qrText);
                if (riskLevel === "HIGH" || riskLevel === "MEDIUM") {
                    console.log("[QR-VULN] Malicious QR content detected: " + qrText.substring(0, 100));
                }
            }
            
            return result;
        };
        
        // Hook decode with hints
        if (BarcodeReader.decode.overload) {
            BarcodeReader.decode.overload('com.google.zxing.BinaryBitmap', 'java.util.Map').implementation = function(image, hints) {
                console.log("[QR-SCAN] ZXing BarcodeReader.decode() with hints called");
                
                var result = this.decode(image, hints);
                if (result) {
                    var qrText = result.getText();
                    sendQREvent("qr_decode_hints", qrText, "ZXing-BarcodeReader", {
                        method: "BarcodeReader.decode(hints)",
                        format: result.getBarcodeFormat().toString(),
                        hints_used: hints ? hints.size() : 0
                    });
                }
                
                return result;
            };
        }
        
        console.log("[QR-MONITOR] ✅ ZXing BarcodeReader hooks installed");
    } catch (e) {
        console.log("[QR-MONITOR] ❌ ZXing BarcodeReader not found or hook failed: " + e);
    }
    
    try {
        console.log("[QR-MONITOR] Setting up ZXing IntentIntegrator hooks...");
        
        var IntentIntegrator = Java.use("com.google.zxing.integration.android.IntentIntegrator");
        
        // Hook parseActivityResult for scan results
        IntentIntegrator.parseActivityResult.implementation = function(requestCode, resultCode, intent) {
            console.log("[QR-SCAN] ZXing IntentIntegrator.parseActivityResult() called");
            
            var result = this.parseActivityResult(requestCode, resultCode, intent);
            if (result && result.getContents()) {
                var qrContent = result.getContents();
                var format = result.getFormatName();
                
                sendQREvent("qr_scan_result", qrContent, "ZXing-IntentIntegrator", {
                    method: "IntentIntegrator.parseActivityResult",
                    format: format,
                    request_code: requestCode,
                    result_code: resultCode,
                    cancelled: result.getContents() === null
                });
            }
            
            return result;
        };
        
        // Hook initiateScan for scan initiation
        if (IntentIntegrator.initiateScan) {
            IntentIntegrator.initiateScan.implementation = function() {
                console.log("[QR-SCAN] ZXing scan initiated");
                sendQREvent("qr_scan_initiated", "", "ZXing-IntentIntegrator", {
                    method: "IntentIntegrator.initiateScan"
                });
                return this.initiateScan();
            };
        }
        
        console.log("[QR-MONITOR] ✅ ZXing IntentIntegrator hooks installed");
    } catch (e) {
        console.log("[QR-MONITOR] ❌ ZXing IntentIntegrator not found or hook failed: " + e);
    }
    
    // ================================
    // ML KIT BARCODE DETECTION
    // ================================
    
    try {
        console.log("[QR-MONITOR] Setting up ML Kit BarcodeDetector hooks...");
        
        var BarcodeDetector = Java.use("com.google.android.gms.vision.barcode.BarcodeDetector");
        
        BarcodeDetector.detect.implementation = function(frame) {
            console.log("[QR-SCAN] ML Kit BarcodeDetector.detect() called");
            
            var barcodes = this.detect(frame);
            if (barcodes && barcodes.size() > 0) {
                console.log("[QR-SCAN] ML Kit detected " + barcodes.size() + " barcodes");
                
                for (var i = 0; i < barcodes.size(); i++) {
                    var barcode = barcodes.valueAt(i);
                    if (barcode.displayValue) {
                        sendQREvent("qr_mlkit_detect", barcode.displayValue, "MLKit-BarcodeDetector", {
                            method: "BarcodeDetector.detect",
                            value_format: barcode.valueFormat,
                            corner_points: barcode.cornerPoints ? barcode.cornerPoints.length : 0,
                            barcode_index: i
                        });
                    }
                }
            }
            
            return barcodes;
        };
        
        console.log("[QR-MONITOR] ✅ ML Kit BarcodeDetector hooks installed");
    } catch (e) {
        console.log("[QR-MONITOR] ❌ ML Kit BarcodeDetector not found or hook failed: " + e);
    }
    
    try {
        console.log("[QR-MONITOR] Setting up new ML Kit BarcodeScanning hooks...");
        
        var BarcodeScanning = Java.use("com.google.mlkit.vision.barcode.BarcodeScanning");
        
        // Hook getClient method
        if (BarcodeScanning.getClient) {
            BarcodeScanning.getClient.overload().implementation = function() {
                console.log("[QR-SCAN] ML Kit BarcodeScanning.getClient() called");
                sendQREvent("qr_mlkit_client", "", "MLKit-BarcodeScanning", {
                    method: "BarcodeScanning.getClient"
                });
                return this.getClient();
            };
        }
        
        console.log("[QR-MONITOR] ✅ ML Kit BarcodeScanning hooks installed");
    } catch (e) {
        console.log("[QR-MONITOR] ❌ New ML Kit BarcodeScanning not found or hook failed: " + e);
    }
    
    // ================================
    // INTENT HANDLING MONITORING
    // ================================
    
    try {
        console.log("[QR-MONITOR] Setting up Intent monitoring hooks...");
        
        var Intent = Java.use("android.content.Intent");
        
        // Hook Intent constructor with action and URI
        Intent.$init.overload('java.lang.String', 'android.net.Uri').implementation = function(action, uri) {
            if (uri) {
                var uriString = uri.toString();
                
                // Heuristic: Check if this might be from a QR code
                if (uriString.length > 10 && (
                    uriString.startsWith("http") || 
                    uriString.startsWith("https") ||
                    uriString.startsWith("intent://") || 
                    uriString.startsWith("content://") ||
                    uriString.includes("qr") || 
                    uriString.includes("scan") ||
                    uriString.includes("barcode")
                )) {
                    sendQREvent("intent_from_qr", uriString, "Intent", {
                        method: "Intent.init(action, uri)",
                        action: action,
                        uri_scheme: uri.getScheme(),
                        uri_host: uri.getHost(),
                        potential_qr_source: true
                    });
                }
            }
            
            return this.$init(action, uri);
        };
        
        // Hook Intent parseUri for intent:// URLs
        if (Intent.parseUri) {
            Intent.parseUri.implementation = function(uri, flags) {
                console.log("[QR-INTENT] Intent.parseUri() called with: " + uri.substring(0, 100));
                
                if (uri.startsWith("intent://")) {
                    sendQREvent("intent_parse_uri", uri, "Intent", {
                        method: "Intent.parseUri",
                        flags: flags,
                        potential_qr_intent: true
                    });
                }
                
                return this.parseUri(uri, flags);
            };
        }
        
        console.log("[QR-MONITOR] ✅ Intent monitoring hooks installed");
    } catch (e) {
        console.log("[QR-MONITOR] ❌ Intent monitoring hooks failed: " + e);
    }
    
    // ================================
    // WEBVIEW URL LOADING MONITORING
    // ================================
    
    try {
        console.log("[QR-MONITOR] Setting up WebView monitoring hooks...");
        
        var WebView = Java.use("android.webkit.WebView");
        
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log("[QR-WEBVIEW] WebView.loadUrl() called with: " + url.substring(0, 100));
            
            // Check for suspicious URLs that might come from QR codes
            if (url && (
                url.startsWith("javascript:") || 
                url.startsWith("file:") || 
                url.startsWith("data:") ||
                url.includes("qr") || 
                url.includes("scan") ||
                analyzeMaliciousContent(url) !== "LOW"
            )) {
                sendQREvent("webview_qr_url", url, "WebView", {
                    method: "WebView.loadUrl",
                    url_scheme: url.split(":")[0],
                    suspicious: true,
                    potential_qr_source: url.includes("qr") || url.includes("scan")
                });
            }
            
            return this.loadUrl(url);
        };
        
        // Hook loadData for data URLs
        WebView.loadData.implementation = function(data, mimeType, encoding) {
            if (data && data.length > 50) {
                console.log("[QR-WEBVIEW] WebView.loadData() called with data length: " + data.length);
                
                // Check for script injection in loaded data
                if (data.includes("<script") || data.includes("javascript:") || data.includes("onerror=")) {
                    sendQREvent("webview_script_injection", data.substring(0, 200), "WebView", {
                        method: "WebView.loadData",
                        mime_type: mimeType,
                        encoding: encoding,
                        data_length: data.length,
                        contains_script: true
                    });
                }
            }
            
            return this.loadData(data, mimeType, encoding);
        };
        
        console.log("[QR-MONITOR] ✅ WebView monitoring hooks installed");
    } catch (e) {
        console.log("[QR-MONITOR] ❌ WebView monitoring hooks failed: " + e);
    }
    
    // ================================
    // CAMERA API MONITORING
    // ================================
    
    try {
        console.log("[QR-MONITOR] Setting up Camera API monitoring hooks...");
        
        var Camera = Java.use("android.hardware.Camera");
        
        Camera.open.overload('int').implementation = function(cameraId) {
            console.log("[QR-CAMERA] Camera.open() called with camera ID: " + cameraId);
            
            sendQREvent("camera_open", "", "Camera", {
                method: "Camera.open",
                camera_id: cameraId,
                potential_qr_scanning: true,
                timestamp: Date.now()
            });
            
            return this.open(cameraId);
        };
        
        // Hook Camera.open() without parameters
        Camera.open.overload().implementation = function() {
            console.log("[QR-CAMERA] Camera.open() called (default camera)");
            
            sendQREvent("camera_open_default", "", "Camera", {
                method: "Camera.open(default)",
                potential_qr_scanning: true
            });
            
            return this.open();
        };
        
        console.log("[QR-MONITOR] ✅ Camera API monitoring hooks installed");
    } catch (e) {
        console.log("[QR-MONITOR] ❌ Camera API monitoring hooks failed: " + e);
    }
    
    // ================================
    // CAMERA2 API MONITORING
    // ================================
    
    try {
        console.log("[QR-MONITOR] Setting up Camera2 API monitoring hooks...");
        
        var CameraManager = Java.use("android.hardware.camera2.CameraManager");
        
        CameraManager.openCamera.implementation = function(cameraId, callback, backgroundHandler) {
            console.log("[QR-CAMERA2] CameraManager.openCamera() called with camera ID: " + cameraId);
            
            sendQREvent("camera2_open", "", "Camera2", {
                method: "CameraManager.openCamera",
                camera_id: cameraId,
                potential_qr_scanning: true
            });
            
            return this.openCamera(cameraId, callback, backgroundHandler);
        };
        
        console.log("[QR-MONITOR] ✅ Camera2 API monitoring hooks installed");
    } catch (e) {
        console.log("[QR-MONITOR] ❌ Camera2 API monitoring hooks failed: " + e);
    }
    
    // ================================
    // SUMMARY AND STATS
    // ================================
    
    // Periodic summary of QR events
    setInterval(function() {
        if (qrEvents.length > 0) {
            var summary = {
                type: "qr_monitoring_summary",
                total_events: qrEvents.length,
                high_risk_events: qrEvents.filter(e => e.risk_level === "HIGH").length,
                medium_risk_events: qrEvents.filter(e => e.risk_level === "MEDIUM").length,
                libraries_detected: [...new Set(qrEvents.map(e => e.library))],
                monitoring_duration: Date.now()
            };
            
            console.log("[QR-SUMMARY] " + JSON.stringify(summary));
            send(summary);
        }
    }, 30000); // Every 30 seconds
    
    console.log("[QR-MONITOR] ✅ QR code security monitoring fully initialized");
    console.log("[QR-MONITOR] Monitoring targets:");
    console.log("  • ZXing BarcodeReader & IntentIntegrator");
    console.log("  • ML Kit BarcodeDetector & BarcodeScanning");
    console.log("  • Intent creation and parsing");
    console.log("  • WebView URL loading and data injection");
    console.log("  • Camera & Camera2 API usage");
    console.log("  • Malicious pattern detection for QR content");
    console.log("[QR-MONITOR] 🔍 Ready to detect QR code security vulnerabilities!");
});