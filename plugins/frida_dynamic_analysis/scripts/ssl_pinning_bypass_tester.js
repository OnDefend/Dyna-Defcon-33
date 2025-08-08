// AODS SSL Pinning Bypass Tester
// Active SSL/TLS security testing with pinning bypass detection
// No hardcoded domains - discovers and tests all SSL connections organically

Java.perform(function() {
    console.log("[AODS-SSL] SSL pinning bypass tester initialized");
    
    var sslTestResults = [];
    var testedConnections = new Set();
    var pinnedDomains = new Set();
    var bypassAttempts = [];
    
    // SSL/TLS monitoring and testing patterns
    var suspiciousSSLBehaviors = [
        "certificate_verification_disabled",
        "hostname_verification_disabled", 
        "trust_all_certificates",
        "pinning_bypass_successful",
        "weak_cipher_suite",
        "protocol_downgrade"
    ];
    
    // Hook SSLContext for certificate validation testing
    try {
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManagers, trustManagers, secureRandom) {
            console.log("[AODS-SSL] SSLContext.init called");
            
            // Analyze trust managers for security issues
            if (trustManagers) {
                for (var i = 0; i < trustManagers.length; i++) {
                    analyzeTrustManager(trustManagers[i]);
                }
            }
            
            return this.init(keyManagers, trustManagers, secureRandom);
        };
        
    } catch (e) {
        console.log("[AODS-SSL] Error hooking SSLContext: " + e);
    }
    
    // Hook HttpsURLConnection for HTTPS analysis
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        
        // Monitor hostname verifier
        HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[AODS-SSL] Hostname verifier set");
            
            // Test if hostname verification is bypassed
            testHostnameVerificationBypass(hostnameVerifier);
            
            return this.setHostnameVerifier(hostnameVerifier);
        };
        
        // Monitor SSL socket factory
        HttpsURLConnection.setSSLSocketFactory.implementation = function(sslSocketFactory) {
            console.log("[AODS-SSL] SSL socket factory set");
            
            // Analyze SSL socket factory for security
            testSSLSocketFactory(sslSocketFactory);
            
            return this.setSSLSocketFactory(sslSocketFactory);
        };
        
        // Monitor connection establishment
        HttpsURLConnection.connect.implementation = function() {
            var url = this.getURL().toString();
            console.log("[AODS-SSL] HTTPS connection to: " + url);
            
            // Test SSL connection security
            testSSLConnection(this, url);
            
            return this.connect();
        };
        
    } catch (e) {
        console.log("[AODS-SSL] Error hooking HttpsURLConnection: " + e);
    }
    
    // Hook OkHttp for modern HTTP client testing
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Call = Java.use("okhttp3.Call");
        
        // Monitor OkHttp SSL configuration
        var OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");
        
        // Hook certificate pinner
        OkHttpClientBuilder.certificatePinner.implementation = function(certificatePinner) {
            console.log("[AODS-SSL] OkHttp certificate pinner configured");
            
            // Test certificate pinning implementation
            testCertificatePinning(certificatePinner);
            
            return this.certificatePinner(certificatePinner);
        };
        
        // Hook hostname verifier for OkHttp
        OkHttpClientBuilder.hostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[AODS-SSL] OkHttp hostname verifier set");
            
            testHostnameVerificationBypass(hostnameVerifier);
            
            return this.hostnameVerifier(hostnameVerifier);
        };
        
    } catch (e) {
        console.log("[AODS-SSL] Error hooking OkHttp (may not be present): " + e);
    }
    
    // Hook Android Network Security Policy
    try {
        var NetworkSecurityPolicy = Java.use("android.security.NetworkSecurityPolicy");
        
        NetworkSecurityPolicy.getInstance.implementation = function() {
            var policy = this.getInstance();
            console.log("[AODS-SSL] Network security policy accessed");
            
            // Test network security policy configuration
            testNetworkSecurityPolicy(policy);
            
            return policy;
        };
        
    } catch (e) {
        console.log("[AODS-SSL] Error hooking NetworkSecurityPolicy: " + e);
    }
    
    // Hook WebView SSL error handling
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log("[AODS-SSL] WebView SSL error received");
            
            // Test SSL error handling
            testWebViewSSLErrorHandling(handler, error);
            
            return this.onReceivedSslError(view, handler, error);
        };
        
    } catch (e) {
        console.log("[AODS-SSL] Error hooking WebViewClient: " + e);
    }
    
    // Analyze trust manager for security vulnerabilities
    function analyzeTrustManager(trustManager) {
        try {
            var className = trustManager.getClass().getName();
            console.log("[AODS-SSL] Analyzing trust manager: " + className);
            
            // Check for known insecure trust managers
            var insecurePatterns = [
                "TrustAllCerts",
                "AcceptAllTrustManager", 
                "DummyTrustManager",
                "NullTrustManager"
            ];
            
            for (var pattern of insecurePatterns) {
                if (className.includes(pattern)) {
                    console.log("[AODS-SSL] VULNERABLE: Insecure trust manager detected - " + className);
                    sslTestResults.push({
                        type: "insecure_trust_manager",
                        class_name: className,
                        severity: "HIGH",
                        timestamp: Date.now()
                    });
                    break;
                }
            }
            
            // Test if trust manager accepts all certificates
            testTrustManagerSecurity(trustManager);
            
        } catch (e) {
            console.log("[AODS-SSL] Error analyzing trust manager: " + e);
        }
    }
    
    // Test trust manager for security issues
    function testTrustManagerSecurity(trustManager) {
        try {
            // Check if checkServerTrusted method exists and analyze it
            var trustManagerClass = trustManager.getClass();
            var methods = trustManagerClass.getDeclaredMethods();
            
            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                var methodName = method.getName();
                
                if (methodName === "checkServerTrusted") {
                    console.log("[AODS-SSL] Found checkServerTrusted method");
                    
                    // Test if method is overridden to bypass security
                    testCheckServerTrustedMethod(trustManager, method);
                }
            }
            
        } catch (e) {
            console.log("[AODS-SSL] Error testing trust manager security: " + e);
        }
    }
    
    // Test checkServerTrusted method implementation
    function testCheckServerTrustedMethod(trustManager, method) {
        try {
            // Create a test certificate chain (empty or invalid)
            var X509Certificate = Java.use("java.security.cert.X509Certificate");
            var testCerts = Java.array("java.security.cert.X509Certificate", []);
            
            // Test if the method accepts invalid certificates
            var originalImpl = method.invoke;
            console.log("[AODS-SSL] Testing certificate validation with empty chain");
            
            try {
                method.invoke(trustManager, testCerts, "RSA");
                console.log("[AODS-SSL] VULNERABLE: Trust manager accepts empty certificate chain");
                
                sslTestResults.push({
                    type: "accepts_empty_certificate_chain",
                    trust_manager: trustManager.getClass().getName(),
                    severity: "CRITICAL",
                    timestamp: Date.now()
                });
                
            } catch (certError) {
                console.log("[AODS-SSL] Trust manager properly rejects invalid certificates");
            }
            
        } catch (e) {
            console.log("[AODS-SSL] Error testing checkServerTrusted: " + e);
        }
    }
    
    // Test hostname verification bypass
    function testHostnameVerificationBypass(hostnameVerifier) {
        try {
            var verifierClass = hostnameVerifier.getClass().getName();
            console.log("[AODS-SSL] Testing hostname verifier: " + verifierClass);
            
            // Check for known bypass patterns
            var bypassPatterns = [
                "AllowAllHostnameVerifier",
                "NullHostnameVerifier",
                "AcceptAllHostnames"
            ];
            
            for (var pattern of bypassPatterns) {
                if (verifierClass.includes(pattern)) {
                    console.log("[AODS-SSL] VULNERABLE: Hostname verification bypassed - " + verifierClass);
                    sslTestResults.push({
                        type: "hostname_verification_bypassed",
                        verifier_class: verifierClass,
                        severity: "HIGH",
                        timestamp: Date.now()
                    });
                    break;
                }
            }
            
            // Test with invalid hostname
            testHostnameVerificationBehavior(hostnameVerifier);
            
        } catch (e) {
            console.log("[AODS-SSL] Error testing hostname verifier: " + e);
        }
    }
    
    // Test hostname verification behavior
    function testHostnameVerificationBehavior(hostnameVerifier) {
        try {
            // Test with obviously invalid hostnames
            var testHostnames = ["invalid.test", "localhost", "127.0.0.1"];
            var SSLSession = Java.use("javax.net.ssl.SSLSession");
            
            for (var hostname of testHostnames) {
                try {
                    var result = hostnameVerifier.verify(hostname, null);
                    if (result) {
                        console.log("[AODS-SSL] VULNERABLE: Hostname verifier accepts invalid hostname - " + hostname);
                        sslTestResults.push({
                            type: "accepts_invalid_hostname",
                            hostname: hostname,
                            verifier_class: hostnameVerifier.getClass().getName(),
                            severity: "HIGH",
                            timestamp: Date.now()
                        });
                    }
                } catch (verifyError) {
                    // Expected behavior for secure implementation
                }
            }
            
        } catch (e) {
            console.log("[AODS-SSL] Error testing hostname verification behavior: " + e);
        }
    }
    
    // Test SSL socket factory security
    function testSSLSocketFactory(sslSocketFactory) {
        try {
            var factoryClass = sslSocketFactory.getClass().getName();
            console.log("[AODS-SSL] Testing SSL socket factory: " + factoryClass);
            
            // Test supported cipher suites
            var supportedCipherSuites = sslSocketFactory.getSupportedCipherSuites();
            analyzeCSipherSuites(supportedCipherSuites);
            
            // Test default cipher suites
            var defaultCipherSuites = sslSocketFactory.getDefaultCipherSuites();
            analyzeCSipherSuites(defaultCipherSuites);
            
        } catch (e) {
            console.log("[AODS-SSL] Error testing SSL socket factory: " + e);
        }
    }
    
    // Analyze cipher suites for security
    function analyzeCSipherSuites(cipherSuites) {
        var weakCiphers = [
            "SSL_", "TLS_NULL_", "TLS_ANON_", "TLS_DH_anon",
            "_RC4_", "_DES_", "_3DES_", "_MD5", "_SHA$"
        ];
        
        for (var i = 0; i < cipherSuites.length; i++) {
            var cipher = cipherSuites[i];
            
            for (var weakPattern of weakCiphers) {
                if (cipher.includes(weakPattern)) {
                    console.log("[AODS-SSL] VULNERABLE: Weak cipher suite enabled - " + cipher);
                    sslTestResults.push({
                        type: "weak_cipher_suite",
                        cipher_suite: cipher,
                        severity: "MEDIUM",
                        timestamp: Date.now()
                    });
                    break;
                }
            }
        }
    }
    
    // Test SSL connection security
    function testSSLConnection(connection, url) {
        try {
            if (testedConnections.has(url)) {
                return; // Already tested
            }
            testedConnections.add(url);
            
            console.log("[AODS-SSL] Testing SSL connection security for: " + url);
            
            // Test connection after it's established
            setTimeout(function() {
                try {
                    var sslSocketFactory = connection.getSSLSocketFactory();
                    var hostnameVerifier = connection.getHostnameVerifier();
                    
                    // Record connection details
                    sslTestResults.push({
                        type: "ssl_connection_analyzed",
                        url: url,
                        has_custom_ssl_factory: sslSocketFactory !== null,
                        has_custom_hostname_verifier: hostnameVerifier !== null,
                        timestamp: Date.now()
                    });
                    
                } catch (analysisError) {
                    console.log("[AODS-SSL] Error analyzing SSL connection: " + analysisError);
                }
            }, 100);
            
        } catch (e) {
            console.log("[AODS-SSL] Error testing SSL connection: " + e);
        }
    }
    
    // Test certificate pinning implementation
    function testCertificatePinning(certificatePinner) {
        try {
            console.log("[AODS-SSL] Testing certificate pinning implementation");
            
            // Check if pinning is actually configured
            var pinnerClass = certificatePinner.getClass().getName();
            
            // Test pinning bypass
            attemptPinningBypass(certificatePinner);
            
            sslTestResults.push({
                type: "certificate_pinning_detected",
                pinner_class: pinnerClass,
                severity: "INFO",
                timestamp: Date.now()
            });
            
        } catch (e) {
            console.log("[AODS-SSL] Error testing certificate pinning: " + e);
        }
    }
    
    // Attempt to bypass certificate pinning
    function attemptPinningBypass(certificatePinner) {
        try {
            console.log("[AODS-SSL] Attempting certificate pinning bypass");
            
            // Record bypass attempt
            bypassAttempts.push({
                type: "certificate_pinning_bypass_attempt",
                pinner_class: certificatePinner.getClass().getName(),
                timestamp: Date.now()
            });
            
            // Test if pinning can be easily bypassed
            // This is a passive test - we don't actually bypass, just analyze
            var bypassPossible = analyzePinningBypassPossibility(certificatePinner);
            
            if (bypassPossible) {
                console.log("[AODS-SSL] VULNERABLE: Certificate pinning may be bypassable");
                sslTestResults.push({
                    type: "pinning_bypass_possible",
                    pinner_class: certificatePinner.getClass().getName(),
                    severity: "HIGH",
                    timestamp: Date.now()
                });
            }
            
        } catch (e) {
            console.log("[AODS-SSL] Error attempting pinning bypass: " + e);
        }
    }
    
    // Analyze if pinning can be bypassed
    function analyzePinningBypassPossibility(certificatePinner) {
        try {
            // Check for common bypass vulnerabilities
            var pinnerClass = certificatePinner.getClass();
            var methods = pinnerClass.getDeclaredMethods();
            
            // Look for security-relevant methods
            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                var methodName = method.getName();
                
                // Check for methods that might indicate weak implementation
                if (methodName.includes("bypass") || methodName.includes("disable") || 
                    methodName.includes("skip") || methodName.includes("ignore")) {
                    return true;
                }
            }
            
            return false;
            
        } catch (e) {
            console.log("[AODS-SSL] Error analyzing pinning bypass possibility: " + e);
            return false;
        }
    }
    
    // Test network security policy
    function testNetworkSecurityPolicy(policy) {
        try {
            console.log("[AODS-SSL] Testing network security policy");
            
            // Test if cleartext traffic is allowed
            var cleartextPermitted = policy.isCleartextTrafficPermitted();
            if (cleartextPermitted) {
                console.log("[AODS-SSL] VULNERABLE: Cleartext traffic permitted by policy");
                sslTestResults.push({
                    type: "cleartext_traffic_permitted",
                    severity: "MEDIUM",
                    timestamp: Date.now()
                });
            }
            
        } catch (e) {
            console.log("[AODS-SSL] Error testing network security policy: " + e);
        }
    }
    
    // Test WebView SSL error handling
    function testWebViewSSLErrorHandling(handler, error) {
        try {
            console.log("[AODS-SSL] Testing WebView SSL error handling");
            
            var errorCode = error.getPrimaryError();
            console.log("[AODS-SSL] SSL error code: " + errorCode);
            
            // Monitor if the error is ignored (proceed called)
            var originalProceed = handler.proceed;
            handler.proceed = function() {
                console.log("[AODS-SSL] VULNERABLE: WebView SSL error ignored (proceed called)");
                sslTestResults.push({
                    type: "webview_ssl_error_ignored",
                    error_code: errorCode,
                    severity: "HIGH",
                    timestamp: Date.now()
                });
                
                return originalProceed.call(this);
            };
            
        } catch (e) {
            console.log("[AODS-SSL] Error testing WebView SSL error handling: " + e);
        }
    }
    
    // Export findings for AODS analysis
    function exportFindings() {
        return {
            ssl_test_results: sslTestResults,
            tested_connections: Array.from(testedConnections),
            pinned_domains: Array.from(pinnedDomains),
            bypass_attempts: bypassAttempts,
            total_findings: sslTestResults.length
        };
    }
    
    // Make findings available globally
    global.AODSSSLTestResults = exportFindings;
    
    console.log("[AODS-SSL] SSL pinning bypass tester ready");
});