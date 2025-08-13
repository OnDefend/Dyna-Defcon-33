// AODS WebView URL Redirection Detector
// Runtime monitoring of WebView navigation and URL redirection vulnerabilities
// No hardcoded URLs - discovers and tests all WebView interactions organically

Java.perform(function() {
    console.log("[AODS-WEBVIEW] WebView URL redirection detector initialized");
    
    var webViewFindings = [];
    var monitoredWebViews = new Set();
    var navigationAttempts = [];
    var redirectionTests = [];
    
    // Suspicious URL patterns that could indicate vulnerabilities
    var suspiciousURLPatterns = [
        // Local file access
        /file:\/\//gi,
        /content:\/\//gi,
        /android_asset:\/\//gi,
        
        // JavaScript injection
        /javascript:/gi,
        /data:text\/html/gi,
        /data:application\/x-javascript/gi,
        
        // External redirects
        /http:\/\/(?!localhost|127\.0\.0\.1)/gi,
        
        // Intent schemes
        /intent:/gi,
        /market:/gi,
        /tel:/gi,
        /mailto:/gi,
        /sms:/gi
    ];
    
    var sensitiveURLComponents = [
        "admin", "debug", "test", "dev", "internal",
        "private", "secret", "hidden", "secure",
        "auth", "login", "password", "token",
        "api", "service", "endpoint", "webhook"
    ];
    
    // Hook WebView class
    try {
        var WebView = Java.use("android.webkit.WebView");
        
        // Monitor loadUrl method
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log("[AODS-WEBVIEW] loadUrl called: " + url);
            
            analyzeWebViewURL(url, "loadUrl", this);
            monitorWebViewInstance(this);
            
            return this.loadUrl(url);
        };
        
        WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, headers) {
            console.log("[AODS-WEBVIEW] loadUrl with headers called: " + url);
            
            analyzeWebViewURL(url, "loadUrlWithHeaders", this);
            analyzeWebViewHeaders(headers);
            monitorWebViewInstance(this);
            
            return this.loadUrl(url, headers);
        };
        
        // Monitor loadData method
        WebView.loadData.implementation = function(data, mimeType, encoding) {
            console.log("[AODS-WEBVIEW] loadData called with mimeType: " + mimeType);
            
            analyzeWebViewData(data, mimeType, "loadData");
            monitorWebViewInstance(this);
            
            return this.loadData(data, mimeType, encoding);
        };
        
        // Monitor loadDataWithBaseURL method
        WebView.loadDataWithBaseURL.implementation = function(baseUrl, data, mimeType, encoding, historyUrl) {
            console.log("[AODS-WEBVIEW] loadDataWithBaseURL called - baseUrl: " + baseUrl + ", historyUrl: " + historyUrl);
            
            if (baseUrl) analyzeWebViewURL(baseUrl, "loadDataWithBaseURL_base", this);
            if (historyUrl) analyzeWebViewURL(historyUrl, "loadDataWithBaseURL_history", this);
            analyzeWebViewData(data, mimeType, "loadDataWithBaseURL");
            monitorWebViewInstance(this);
            
            return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
        };
        
        // Monitor evaluateJavaScript method
        WebView.evaluateJavascript.implementation = function(script, resultCallback) {
            console.log("[AODS-WEBVIEW] evaluateJavascript called");
            
            analyzeJavaScriptInjection(script);
            monitorWebViewInstance(this);
            
            return this.evaluateJavascript(script, resultCallback);
        };
        
    } catch (e) {
        console.log("[AODS-WEBVIEW] Error hooking WebView: " + e);
    }
    
    // Hook WebViewClient for navigation monitoring
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        
        // Monitor shouldOverrideUrlLoading
        WebViewClient.shouldOverrideUrlLoading.overload('android.webkit.WebView', 'java.lang.String').implementation = function(view, url) {
            console.log("[AODS-WEBVIEW] shouldOverrideUrlLoading: " + url);
            
            var result = this.shouldOverrideUrlLoading(view, url);
            
            // Test URL redirection behavior
            testURLRedirection(view, url, result);
            
            return result;
        };
        
        WebViewClient.shouldOverrideUrlLoading.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest').implementation = function(view, request) {
            var url = request.getUrl().toString();
            console.log("[AODS-WEBVIEW] shouldOverrideUrlLoading (WebResourceRequest): " + url);
            
            var result = this.shouldOverrideUrlLoading(view, request);
            
            // Test URL redirection behavior
            testURLRedirection(view, url, result);
            
            return result;
        };
        
        // Monitor onPageStarted
        WebViewClient.onPageStarted.implementation = function(view, url, favicon) {
            console.log("[AODS-WEBVIEW] onPageStarted: " + url);
            
            analyzePageLoad(url, "page_started");
            
            return this.onPageStarted(view, url, favicon);
        };
        
        // Monitor onPageFinished
        WebViewClient.onPageFinished.implementation = function(view, url) {
            console.log("[AODS-WEBVIEW] onPageFinished: " + url);
            
            analyzePageLoad(url, "page_finished");
            performWebViewSecurityTests(view, url);
            
            return this.onPageFinished(view, url);
        };
        
        // Monitor onReceivedError
        WebViewClient.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function(view, errorCode, description, failingUrl) {
            console.log("[AODS-WEBVIEW] onReceivedError: " + failingUrl + " - " + description);
            
            webViewFindings.push({
                type: "webview_load_error",
                url: failingUrl,
                error_code: errorCode,
                description: description,
                timestamp: Date.now()
            });
            
            return this.onReceivedError(view, errorCode, description, failingUrl);
        };
        
    } catch (e) {
        console.log("[AODS-WEBVIEW] Error hooking WebViewClient: " + e);
    }
    
    // Hook WebChromeClient for additional monitoring
    try {
        var WebChromeClient = Java.use("android.webkit.WebChromeClient");
        
        // Monitor onJsAlert for JavaScript injection testing
        WebChromeClient.onJsAlert.implementation = function(view, url, message, result) {
            console.log("[AODS-WEBVIEW] JavaScript alert: " + message + " from " + url);
            
            webViewFindings.push({
                type: "javascript_alert",
                url: url,
                message: message,
                timestamp: Date.now()
            });
            
            return this.onJsAlert(view, url, message, result);
        };
        
        // Monitor onJsConfirm
        WebChromeClient.onJsConfirm.implementation = function(view, url, message, result) {
            console.log("[AODS-WEBVIEW] JavaScript confirm: " + message + " from " + url);
            
            webViewFindings.push({
                type: "javascript_confirm",
                url: url,
                message: message,
                timestamp: Date.now()
            });
            
            return this.onJsConfirm(view, url, message, result);
        };
        
    } catch (e) {
        console.log("[AODS-WEBVIEW] Error hooking WebChromeClient: " + e);
    }
    
    // Hook WebSettings for security configuration analysis
    try {
        var WebSettings = Java.use("android.webkit.WebSettings");
        
        // Monitor JavaScript enabling
        WebSettings.setJavaScriptEnabled.implementation = function(flag) {
            console.log("[AODS-WEBVIEW] JavaScript enabled: " + flag);
            
            if (flag) {
                webViewFindings.push({
                    type: "javascript_enabled",
                    security_risk: "MEDIUM",
                    timestamp: Date.now()
                });
            }
            
            return this.setJavaScriptEnabled(flag);
        };
        
        // Monitor file access settings
        WebSettings.setAllowFileAccess.implementation = function(allow) {
            console.log("[AODS-WEBVIEW] File access allowed: " + allow);
            
            if (allow) {
                webViewFindings.push({
                    type: "file_access_enabled",
                    security_risk: "HIGH",
                    timestamp: Date.now()
                });
            }
            
            return this.setAllowFileAccess(allow);
        };
        
        // Monitor universal access from file URLs
        WebSettings.setAllowUniversalAccessFromFileURLs.implementation = function(flag) {
            console.log("[AODS-WEBVIEW] Universal access from file URLs: " + flag);
            
            if (flag) {
                webViewFindings.push({
                    type: "universal_file_access_enabled",
                    security_risk: "CRITICAL",
                    timestamp: Date.now()
                });
            }
            
            return this.setAllowUniversalAccessFromFileURLs(flag);
        };
        
        // Monitor file access from file URLs
        WebSettings.setAllowFileAccessFromFileURLs.implementation = function(flag) {
            console.log("[AODS-WEBVIEW] File access from file URLs: " + flag);
            
            if (flag) {
                webViewFindings.push({
                    type: "file_access_from_file_urls_enabled",
                    security_risk: "HIGH",
                    timestamp: Date.now()
                });
            }
            
            return this.setAllowFileAccessFromFileURLs(flag);
        };
        
    } catch (e) {
        console.log("[AODS-WEBVIEW] Error hooking WebSettings: " + e);
    }
    
    // Analyze WebView URL for security issues
    function analyzeWebViewURL(url, context, webView) {
        if (!url) return;
        
        console.log("[AODS-WEBVIEW] Analyzing URL in context " + context + ": " + url);
        
        // Check for suspicious URL patterns
        for (var pattern of suspiciousURLPatterns) {
            if (pattern.test(url)) {
                console.log("[AODS-WEBVIEW] SUSPICIOUS: URL matches suspicious pattern - " + pattern);
                webViewFindings.push({
                    type: "suspicious_url_pattern",
                    url: url,
                    pattern: pattern.toString(),
                    context: context,
                    security_risk: getSuspiciousPatternRisk(pattern),
                    timestamp: Date.now()
                });
            }
        }
        
        // Check for sensitive URL components
        var urlLower = url.toLowerCase();
        for (var component of sensitiveURLComponents) {
            if (urlLower.includes(component)) {
                console.log("[AODS-WEBVIEW] SENSITIVE: URL contains sensitive component - " + component);
                webViewFindings.push({
                    type: "sensitive_url_component",
                    url: url,
                    component: component,
                    context: context,
                    timestamp: Date.now()
                });
            }
        }
        
        // Record navigation attempt
        navigationAttempts.push({
            url: url,
            context: context,
            timestamp: Date.now()
        });
    }
    
    // Analyze WebView headers
    function analyzeWebViewHeaders(headers) {
        if (!headers) return;
        
        try {
            var headersKeySet = headers.keySet();
            var iterator = headersKeySet.iterator();
            
            while (iterator.hasNext()) {
                var key = iterator.next();
                var value = headers.get(key);
                
                console.log("[AODS-WEBVIEW] Header: " + key + " = " + value);
                
                // Check for sensitive headers
                if (key.toLowerCase().includes("authorization") || 
                    key.toLowerCase().includes("cookie") ||
                    key.toLowerCase().includes("token")) {
                    
                    webViewFindings.push({
                        type: "sensitive_header",
                        header_name: key,
                        header_value: value ? value.substring(0, 50) : "null",
                        timestamp: Date.now()
                    });
                }
            }
        } catch (e) {
            console.log("[AODS-WEBVIEW] Error analyzing headers: " + e);
        }
    }
    
    // Analyze WebView data content
    function analyzeWebViewData(data, mimeType, context) {
        if (!data) return;
        
        console.log("[AODS-WEBVIEW] Analyzing data content in context " + context);
        
        // Check for JavaScript injection in data
        if (data.toLowerCase().includes("<script") || data.toLowerCase().includes("javascript:")) {
            console.log("[AODS-WEBVIEW] SUSPICIOUS: JavaScript found in data content");
            webViewFindings.push({
                type: "javascript_in_data",
                mime_type: mimeType,
                context: context,
                data_sample: data.substring(0, 100),
                security_risk: "HIGH",
                timestamp: Date.now()
            });
        }
        
        // Check for sensitive data patterns
        if (data.toLowerCase().includes("password") || data.toLowerCase().includes("token") ||
            data.toLowerCase().includes("secret") || data.toLowerCase().includes("api_key")) {
            
            console.log("[AODS-WEBVIEW] SENSITIVE: Sensitive data found in WebView content");
            webViewFindings.push({
                type: "sensitive_data_in_content",
                mime_type: mimeType,
                context: context,
                timestamp: Date.now()
            });
        }
    }
    
    // Analyze JavaScript injection
    function analyzeJavaScriptInjection(script) {
        if (!script) return;
        
        console.log("[AODS-WEBVIEW] Analyzing JavaScript injection");
        
        webViewFindings.push({
            type: "javascript_injection",
            script_sample: script.substring(0, 100),
            timestamp: Date.now()
        });
        
        // Check for potentially dangerous JavaScript patterns
        var dangerousPatterns = [
            "document.cookie",
            "localStorage",
            "sessionStorage",
            "XMLHttpRequest",
            "fetch(",
            "eval(",
            "Function(",
            "window.location"
        ];
        
        for (var pattern of dangerousPatterns) {
            if (script.includes(pattern)) {
                console.log("[AODS-WEBVIEW] DANGEROUS: Dangerous JavaScript pattern - " + pattern);
                webViewFindings.push({
                    type: "dangerous_javascript_pattern",
                    pattern: pattern,
                    script_sample: script.substring(0, 100),
                    security_risk: "HIGH",
                    timestamp: Date.now()
                });
            }
        }
    }
    
    // Test URL redirection behavior
    function testURLRedirection(webView, url, shouldOverride) {
        console.log("[AODS-WEBVIEW] Testing URL redirection for: " + url + " (override: " + shouldOverride + ")");
        
        var redirectionTest = {
            original_url: url,
            should_override: shouldOverride,
            redirection_detected: false,
            timestamp: Date.now()
        };
        
        // Test various redirection scenarios
        testRedirectionScenarios(webView, url, redirectionTest);
        
        redirectionTests.push(redirectionTest);
    }
    
    // Test various redirection scenarios
    function testRedirectionScenarios(webView, url, redirectionTest) {
        try {
            // Test 1: Try to redirect to a test URL
            setTimeout(function() {
                try {
                    var testURLs = [
                        "javascript:alert('AODS-TEST')",
                        "data:text/html,<script>alert('AODS-TEST')</script>",
                        "file:///android_asset/test.html"
                    ];
                    
                    for (var testUrl of testURLs) {
                        testSingleRedirection(webView, testUrl, redirectionTest);
                    }
                    
                } catch (testError) {
                    console.log("[AODS-WEBVIEW] Error in redirection test: " + testError);
                }
            }, 500);
            
        } catch (e) {
            console.log("[AODS-WEBVIEW] Error testing redirection scenarios: " + e);
        }
    }
    
    // Test single URL redirection
    function testSingleRedirection(webView, testUrl, redirectionTest) {
        try {
            console.log("[AODS-WEBVIEW] Testing redirection to: " + testUrl);
            
            // This is a passive test - we analyze the capability but don't actually redirect
            // Real redirection testing would require more complex setup
            
            var canRedirect = analyzeRedirectionCapability(webView, testUrl);
            if (canRedirect) {
                console.log("[AODS-WEBVIEW] VULNERABLE: WebView appears vulnerable to URL redirection");
                redirectionTest.redirection_detected = true;
                
                webViewFindings.push({
                    type: "url_redirection_vulnerability",
                    test_url: testUrl,
                    security_risk: "HIGH",
                    timestamp: Date.now()
                });
            }
            
        } catch (e) {
            console.log("[AODS-WEBVIEW] Error testing single redirection: " + e);
        }
    }
    
    // Analyze redirection capability (passive analysis)
    function analyzeRedirectionCapability(webView, testUrl) {
        try {
            // Check WebView settings that might allow redirection
            var settings = webView.getSettings();
            
            // If JavaScript is enabled and file access is allowed, redirection is possible
            var jsEnabled = settings.getJavaScriptEnabled();
            var fileAccessAllowed = settings.getAllowFileAccess();
            
            if (jsEnabled && (testUrl.startsWith("javascript:") || testUrl.startsWith("data:"))) {
                return true;
            }
            
            if (fileAccessAllowed && testUrl.startsWith("file://")) {
                return true;
            }
            
            return false;
            
        } catch (e) {
            console.log("[AODS-WEBVIEW] Error analyzing redirection capability: " + e);
            return false;
        }
    }
    
    // Analyze page load for security issues
    function analyzePageLoad(url, phase) {
        console.log("[AODS-WEBVIEW] Page load " + phase + ": " + url);
        
        // Track page loads for pattern analysis
        webViewFindings.push({
            type: "page_load_tracked",
            url: url,
            phase: phase,
            timestamp: Date.now()
        });
    }
    
    // Perform WebView security tests after page load
    function performWebViewSecurityTests(webView, url) {
        console.log("[AODS-WEBVIEW] Performing security tests for loaded page: " + url);
        
        // Test JavaScript injection capability
        testJavaScriptInjection(webView, url);
        
        // Test file access capability
        testFileAccess(webView, url);
        
        // Test cross-origin access
        testCrossOriginAccess(webView, url);
    }
    
    // Test JavaScript injection capability
    function testJavaScriptInjection(webView, url) {
        try {
            var settings = webView.getSettings();
            
            if (settings.getJavaScriptEnabled()) {
                console.log("[AODS-WEBVIEW] JavaScript injection test - JS enabled");
                
                // Test safe JavaScript to verify injection capability
                setTimeout(function() {
                    try {
                        webView.evaluateJavascript("console.log('AODS-JS-TEST')", null);
                        
                        webViewFindings.push({
                            type: "javascript_injection_possible",
                            url: url,
                            security_risk: "MEDIUM",
                            timestamp: Date.now()
                        });
                        
                    } catch (jsError) {
                        console.log("[AODS-WEBVIEW] JavaScript injection blocked");
                    }
                }, 100);
            }
            
        } catch (e) {
            console.log("[AODS-WEBVIEW] Error testing JavaScript injection: " + e);
        }
    }
    
    // Test file access capability
    function testFileAccess(webView, url) {
        try {
            var settings = webView.getSettings();
            
            if (settings.getAllowFileAccess()) {
                console.log("[AODS-WEBVIEW] VULNERABLE: File access enabled");
                
                webViewFindings.push({
                    type: "file_access_vulnerability",
                    url: url,
                    security_risk: "HIGH",
                    timestamp: Date.now()
                });
            }
            
        } catch (e) {
            console.log("[AODS-WEBVIEW] Error testing file access: " + e);
        }
    }
    
    // Test cross-origin access capability
    function testCrossOriginAccess(webView, url) {
        try {
            var settings = webView.getSettings();
            
            if (settings.getAllowUniversalAccessFromFileURLs()) {
                console.log("[AODS-WEBVIEW] VULNERABLE: Universal access from file URLs enabled");
                
                webViewFindings.push({
                    type: "cross_origin_access_vulnerability",
                    url: url,
                    security_risk: "CRITICAL",
                    timestamp: Date.now()
                });
            }
            
        } catch (e) {
            console.log("[AODS-WEBVIEW] Error testing cross-origin access: " + e);
        }
    }
    
    // Monitor WebView instance
    function monitorWebViewInstance(webView) {
        var webViewId = webView.toString();
        
        if (!monitoredWebViews.has(webViewId)) {
            monitoredWebViews.add(webViewId);
            console.log("[AODS-WEBVIEW] Monitoring new WebView instance: " + webViewId);
        }
    }
    
    // Get security risk level for suspicious patterns
    function getSuspiciousPatternRisk(pattern) {
        var patternStr = pattern.toString();
        
        if (patternStr.includes("javascript:") || patternStr.includes("file://")) {
            return "HIGH";
        } else if (patternStr.includes("intent:") || patternStr.includes("data:")) {
            return "MEDIUM";
        } else {
            return "LOW";
        }
    }
    
    // Export findings for AODS analysis
    function exportFindings() {
        return {
            webview_findings: webViewFindings,
            monitored_webviews: Array.from(monitoredWebViews),
            navigation_attempts: navigationAttempts,
            redirection_tests: redirectionTests,
            total_findings: webViewFindings.length
        };
    }
    
    // Make findings available globally
    global.AODSWebViewFindings = exportFindings;
    
    console.log("[AODS-WEBVIEW] WebView URL redirection detector ready");
});