/**
 * Network Communication Hooks
 * 
 * Frida JavaScript code to intercept network communications
 * and detect insecure network connections during runtime.
 * 
 * Author: AODS Team
 * Date: January 2025
 */

Java.perform(function() {
    console.log("[+] Network hooks loaded - monitoring network communications");
    
    try {
        // Hook URL constructor for URL monitoring
        var URL = Java.use("java.net.URL");
        URL.$init.overload("java.lang.String").implementation = function(spec) {
            var result = this.$init(spec);
            
            send({
                type: "network_communication",
                url: spec,
                timestamp: Date.now(),
                is_https: spec.startsWith("https://"),
                protocol: spec.split(":")[0].toUpperCase(),
                method: "URL.init",
                thread: Java.use("java.lang.Thread").currentThread().getName()
            });
            
            console.log("[NETWORK] URL created: " + spec);
            return result;
        };
        
        // Hook HttpURLConnection for HTTP request monitoring
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.setRequestMethod.implementation = function(method) {
            var result = this.setRequestMethod(method);
            
            // Get URL from connection
            var url = "";
            try {
                url = this.getURL().toString();
            } catch (e) {
                url = "unknown";
            }
            
            send({
                type: "network_communication",
                url: url,
                method: method,
                timestamp: Date.now(),
                is_https: url.startsWith("https://"),
                connection_type: "HttpURLConnection"
            });
            
            console.log("[NETWORK] HTTP request: " + method + " " + url);
            return result;
        };
        
        // Hook URLConnection.connect for connection monitoring
        var URLConnection = Java.use("java.net.URLConnection");
        URLConnection.connect.implementation = function() {
            var result = this.connect();
            
            var url = "";
            try {
                url = this.getURL().toString();
            } catch (e) {
                url = "unknown";
            }
            
            send({
                type: "network_communication",
                url: url,
                operation: "connect",
                timestamp: Date.now(),
                is_https: url.startsWith("https://"),
                connection_type: "URLConnection"
            });
            
            console.log("[NETWORK] Connection established: " + url);
            return result;
        };
        
        // Hook OkHttp (popular HTTP client library)
        try {
            var Request = Java.use("okhttp3.Request");
            var RequestBuilder = Java.use("okhttp3.Request$Builder");
            
            RequestBuilder.url.overload("java.lang.String").implementation = function(url) {
                var result = this.url(url);
                
                send({
                    type: "network_communication",
                    url: url,
                    timestamp: Date.now(),
                    is_https: url.startsWith("https://"),
                    library: "OkHttp",
                    method: "Request.Builder.url"
                });
                
                console.log("[NETWORK] OkHttp request URL: " + url);
                return result;
            };
            
        } catch (e) {
            console.log("[INFO] OkHttp not available: " + e);
        }
        
        // Hook Apache HttpClient (if available)
        try {
            var HttpGet = Java.use("org.apache.http.client.methods.HttpGet");
            HttpGet.$init.overload("java.lang.String").implementation = function(uri) {
                var result = this.$init(uri);
                
                send({
                    type: "network_communication",
                    url: uri,
                    method: "GET",
                    timestamp: Date.now(),
                    is_https: uri.startsWith("https://"),
                    library: "Apache HttpClient"
                });
                
                console.log("[NETWORK] Apache HttpClient GET: " + uri);
                return result;
            };
            
            var HttpPost = Java.use("org.apache.http.client.methods.HttpPost");
            HttpPost.$init.overload("java.lang.String").implementation = function(uri) {
                var result = this.$init(uri);
                
                send({
                    type: "network_communication",
                    url: uri,
                    method: "POST",
                    timestamp: Date.now(),
                    is_https: uri.startsWith("https://"),
                    library: "Apache HttpClient"
                });
                
                console.log("[NETWORK] Apache HttpClient POST: " + uri);
                return result;
            };
            
        } catch (e) {
            console.log("[INFO] Apache HttpClient not available: " + e);
        }
        
        // Hook Socket connections for low-level network monitoring
        var Socket = Java.use("java.net.Socket");
        Socket.$init.overload("java.lang.String", "int").implementation = function(host, port) {
            var result = this.$init(host, port);
            
            send({
                type: "network_communication",
                host: host,
                port: port,
                timestamp: Date.now(),
                connection_type: "Socket",
                is_secure: port === 443 || port === 8443
            });
            
            console.log("[NETWORK] Socket connection: " + host + ":" + port);
            return result;
        };
        
        // Hook SSLSocket for SSL/TLS monitoring
        try {
            var SSLSocket = Java.use("javax.net.ssl.SSLSocket");
            SSLSocket.startHandshake.implementation = function() {
                var result = this.startHandshake();
                
                var host = "";
                var port = 0;
                try {
                    host = this.getInetAddress().getHostName();
                    port = this.getPort();
                } catch (e) {
                    host = "unknown";
                }
                
                send({
                    type: "network_communication",
                    host: host,
                    port: port,
                    operation: "ssl_handshake",
                    timestamp: Date.now(),
                    connection_type: "SSLSocket",
                    is_secure: true
                });
                
                console.log("[NETWORK] SSL handshake: " + host + ":" + port);
                return result;
            };
            
        } catch (e) {
            console.log("[INFO] SSLSocket not available: " + e);
        }
        
        // Hook Volley (popular Android HTTP library)
        try {
            var StringRequest = Java.use("com.android.volley.toolbox.StringRequest");
            StringRequest.$init.overload("int", "java.lang.String", "com.android.volley.Response$Listener", "com.android.volley.Response$ErrorListener").implementation = function(method, url, listener, errorListener) {
                var result = this.$init(method, url, listener, errorListener);
                
                var methodName = "UNKNOWN";
                try {
                    if (method === 0) methodName = "GET";
                    else if (method === 1) methodName = "POST";
                    else if (method === 2) methodName = "PUT";
                    else if (method === 3) methodName = "DELETE";
                } catch (e) {
                    methodName = "METHOD_" + method;
                }
                
                send({
                    type: "network_communication",
                    url: url,
                    method: methodName,
                    timestamp: Date.now(),
                    is_https: url.startsWith("https://"),
                    library: "Volley"
                });
                
                console.log("[NETWORK] Volley request: " + methodName + " " + url);
                return result;
            };
            
        } catch (e) {
            console.log("[INFO] Volley not available: " + e);
        }
        
        // Hook Retrofit (popular REST client)
        try {
            var Retrofit = Java.use("retrofit2.Retrofit");
            Retrofit.$init.overload("okhttp3.Call$Factory", "okhttp3.HttpUrl", "java.util.List", "java.util.List", "java.util.concurrent.Executor", "boolean").implementation = function(callFactory, baseUrl, converterFactories, adapterFactories, callbackExecutor, validateEagerly) {
                var result = this.$init(callFactory, baseUrl, converterFactories, adapterFactories, callbackExecutor, validateEagerly);
                
                var url = "";
                try {
                    url = baseUrl.toString();
                } catch (e) {
                    url = "unknown";
                }
                
                send({
                    type: "network_communication",
                    url: url,
                    operation: "retrofit_init",
                    timestamp: Date.now(),
                    is_https: url.startsWith("https://"),
                    library: "Retrofit"
                });
                
                console.log("[NETWORK] Retrofit base URL: " + url);
                return result;
            };
            
        } catch (e) {
            console.log("[INFO] Retrofit not available: " + e);
        }
        
        console.log("[+] All network hooks successfully installed");
        
    } catch (e) {
        console.log("[-] Error installing network hooks: " + e);
        send({
            type: "hook_error",
            error: e.toString(),
            hook_type: "network",
            timestamp: Date.now()
        });
    }
});

// Additional network security monitoring
Java.perform(function() {
    try {
        // Monitor certificate pinning bypass attempts
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
            
            send({
                type: "network_security",
                operation: "certificate_pinning_check",
                hostname: hostname,
                certificate_count: peerCertificates.size(),
                timestamp: Date.now()
            });
            
            console.log("[NETWORK] Certificate pinning check for: " + hostname);
            return this.check(hostname, peerCertificates);
        };
        
    } catch (e) {
        console.log("[INFO] Certificate pinning hooks not available: " + e);
    }
    
    try {
        // Monitor trust manager implementations
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        X509TrustManager.checkServerTrusted.implementation = function(chain, authType) {
            
            send({
                type: "network_security",
                operation: "server_trust_check",
                chain_length: chain.length,
                auth_type: authType,
                timestamp: Date.now()
            });
            
            console.log("[NETWORK] Server trust check - auth type: " + authType);
            return this.checkServerTrusted(chain, authType);
        };
        
    } catch (e) {
        console.log("[INFO] Trust manager hooks not available: " + e);
    }
    
    // ========================================================================
    // CERTIFICATE PINNING MONITORING (TASK 1.5)
    // ========================================================================
    
    console.log("[CERT-PINNING] 🚀 Initializing comprehensive certificate pinning monitoring");
    
    try {
        /**
         * Get current stack trace for evidence
         */
        function getCurrentStackTrace() {
            try {
                var Exception = Java.use("java.lang.Exception");
                var exception = Exception.$new();
                return exception.getStackTrace().toString();
            } catch (e) {
                return "Stack trace unavailable";
            }
        }
        
        /**
         * Extract certificate information
         */
        function extractCertificateInfo(cert) {
            try {
                var info = {
                    subject: cert.getSubjectDN().toString(),
                    issuer: cert.getIssuerDN().toString(),
                    serial: cert.getSerialNumber().toString(),
                    algorithm: cert.getSigAlgName(),
                    version: cert.getVersion()
                };
                
                // Get validity dates
                try {
                    info.notBefore = cert.getNotBefore().toString();
                    info.notAfter = cert.getNotAfter().toString();
                } catch (e) {
                    info.notBefore = "unknown";
                    info.notAfter = "unknown";
                }
                
                return info;
            } catch (e) {
                return {subject: "unknown", issuer: "unknown", serial: "unknown"};
            }
        }
        
        // Hook SSLSocketFactory for certificate pinning bypass detection
        try {
            var SSLSocketFactory = Java.use("javax.net.ssl.SSLSocketFactory");
            var originalGetDefault = SSLSocketFactory.getDefault;
            
            SSLSocketFactory.getDefault.implementation = function() {
                var result = originalGetDefault.call(this);
                
                send({
                    type: "certificate_pinning_monitoring",
                    operation: "ssl_socket_factory_default",
                    timestamp: Date.now(),
                    stack_trace: getCurrentStackTrace(),
                    description: "Default SSL socket factory accessed"
                });
                
                console.log("[CERT-PINNING] Default SSL socket factory accessed");
                return result;
            };
        } catch (e) {
            console.log("[CERT-PINNING] ⚠️ SSLSocketFactory hooks not available: " + e);
        }
        
        // Hook SSLContext for SSL configuration monitoring
        try {
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            
            SSLContext.init.implementation = function(keyManagers, trustManagers, secureRandom) {
                this.init(keyManagers, trustManagers, secureRandom);
                
                var hasPinning = false;
                var trustManagerTypes = [];
                
                if (trustManagers) {
                    for (var i = 0; i < trustManagers.length; i++) {
                        var tmClass = trustManagers[i].getClass().getName();
                        trustManagerTypes.push(tmClass);
                        
                        // Check for custom trust managers (potential pinning)
                        if (!tmClass.startsWith("com.android.org.conscrypt") && 
                            !tmClass.startsWith("sun.security.ssl") &&
                            !tmClass.equals("com.android.org.conscrypt.TrustManagerImpl")) {
                            hasPinning = true;
                        }
                    }
                }
                
                // Detect potential certificate pinning bypass attempts
                if (!hasPinning && trustManagers && trustManagers.length > 0) {
                    send({
                        type: "certificate_pinning_vulnerability",
                        vulnerability_type: "weak_certificate_validation",
                        trust_managers: trustManagerTypes,
                        has_custom_pinning: hasPinning,
                        timestamp: Date.now(),
                        stack_trace: getCurrentStackTrace(),
                        severity: "MEDIUM",
                        description: "SSL context initialized with default trust managers (no certificate pinning detected)",
                        evidence: {
                            operation: "SSLContext.init",
                            trust_manager_types: trustManagerTypes,
                            pinning_detected: false,
                            validation_strength: "default"
                        }
                    });
                    
                    console.log("[CERT-PINNING-VULN] 🚨 WEAK VALIDATION: Default trust managers used");
                }
                
                send({
                    type: "certificate_pinning_monitoring",
                    operation: "ssl_context_init",
                    trust_managers: trustManagerTypes,
                    has_custom_pinning: hasPinning,
                    timestamp: Date.now(),
                    stack_trace: getCurrentStackTrace()
                });
                
                console.log("[CERT-PINNING] SSL context initialized - Custom pinning: " + hasPinning);
            };
        } catch (e) {
            console.log("[CERT-PINNING] ⚠️ SSLContext hooks not available: " + e);
        }
        
        // Hook HttpsURLConnection for HTTPS-specific monitoring
        try {
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            
            // Hook setHostnameVerifier for hostname verification bypass detection
            HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
                this.setHostnameVerifier(hostnameVerifier);
                
                var verifierClass = hostnameVerifier ? hostnameVerifier.getClass().getName() : "null";
                var isCustomVerifier = verifierClass && !verifierClass.startsWith("com.android.okhttp");
                
                // Check for insecure hostname verification
                if (hostnameVerifier && verifierClass.indexOf("AllowAll") >= 0) {
                    send({
                        type: "certificate_pinning_vulnerability",
                        vulnerability_type: "hostname_verification_bypass",
                        hostname_verifier: verifierClass,
                        timestamp: Date.now(),
                        stack_trace: getCurrentStackTrace(),
                        severity: "HIGH",
                        description: "Hostname verification bypassed with permissive verifier",
                        evidence: {
                            operation: "setHostnameVerifier",
                            verifier_class: verifierClass,
                            bypass_detected: true,
                            security_risk: "mitm_vulnerability"
                        }
                    });
                    
                    console.log("[CERT-PINNING-VULN] 🚨 HOSTNAME BYPASS: " + verifierClass);
                }
                
                send({
                    type: "certificate_pinning_monitoring",
                    operation: "hostname_verifier_set",
                    verifier_class: verifierClass,
                    is_custom: isCustomVerifier,
                    timestamp: Date.now()
                });
                
                console.log("[CERT-PINNING] Hostname verifier set: " + verifierClass);
            };
            
            // Hook setSSLSocketFactory for custom SSL factory monitoring
            HttpsURLConnection.setSSLSocketFactory.implementation = function(factory) {
                this.setSSLSocketFactory(factory);
                
                var factoryClass = factory ? factory.getClass().getName() : "null";
                
                send({
                    type: "certificate_pinning_monitoring",
                    operation: "ssl_socket_factory_set",
                    factory_class: factoryClass,
                    timestamp: Date.now(),
                    stack_trace: getCurrentStackTrace()
                });
                
                console.log("[CERT-PINNING] SSL socket factory set: " + factoryClass);
            };
        } catch (e) {
            console.log("[CERT-PINNING] ⚠️ HttpsURLConnection hooks not available: " + e);
        }
        
        // Hook X509TrustManager for certificate validation monitoring
        try {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            
            // Monitor certificate chain validation
            X509TrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(chain, authType) {
                try {
                    // Extract certificate information
                    var certInfo = [];
                    for (var i = 0; i < chain.length; i++) {
                        certInfo.push(extractCertificateInfo(chain[i]));
                    }
                    
                    // Check if this is a custom trust manager (potential pinning)
                    var tmClass = this.getClass().getName();
                    var isCustomTM = !tmClass.startsWith("com.android.org.conscrypt") && 
                                     !tmClass.startsWith("sun.security.ssl");
                    
                    send({
                        type: "certificate_pinning_monitoring",
                        operation: "certificate_validation",
                        trust_manager_class: tmClass,
                        is_custom_trust_manager: isCustomTM,
                        certificate_chain: certInfo,
                        auth_type: authType,
                        timestamp: Date.now(),
                        stack_trace: getCurrentStackTrace()
                    });
                    
                    if (isCustomTM) {
                        console.log("[CERT-PINNING] ✅ CUSTOM VALIDATION: " + tmClass + " (potential pinning)");
                    } else {
                        console.log("[CERT-PINNING] 📋 Default validation: " + tmClass);
                    }
                    
                } catch (e) {
                    console.log("[CERT-PINNING] ⚠️ Certificate extraction failed: " + e);
                }
                
                // Call original method
                return this.checkServerTrusted(chain, authType);
            };
        } catch (e) {
            console.log("[CERT-PINNING] ⚠️ X509TrustManager hooks not available: " + e);
        }
        
        // Hook OkHttp CertificatePinner for OkHttp-specific pinning detection
        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                try {
                    var result = this.check(hostname, peerCertificates);
                    
                    send({
                        type: "certificate_pinning_monitoring",
                        operation: "okhttp_certificate_pinning",
                        hostname: hostname,
                        certificate_count: peerCertificates.size(),
                        pinning_library: "OkHttp",
                        timestamp: Date.now(),
                        stack_trace: getCurrentStackTrace(),
                        description: "OkHttp certificate pinning verification performed"
                    });
                    
                    console.log("[CERT-PINNING] ✅ OKHTTP PINNING: " + hostname + " (" + peerCertificates.size() + " certs)");
                    return result;
                    
                } catch (e) {
                    // Pinning failure
                    send({
                        type: "certificate_pinning_vulnerability",
                        vulnerability_type: "certificate_pinning_failure",
                        hostname: hostname,
                        certificate_count: peerCertificates ? peerCertificates.size() : 0,
                        pinning_library: "OkHttp",
                        timestamp: Date.now(),
                        stack_trace: getCurrentStackTrace(),
                        severity: "CRITICAL",
                        description: "OkHttp certificate pinning validation failed",
                        evidence: {
                            operation: "okhttp_pinning_check",
                            failure_reason: e.toString(),
                            hostname: hostname,
                            pinning_enforced: true
                        }
                    });
                    
                    console.log("[CERT-PINNING-VULN] 🚨 PINNING FAILURE: " + hostname + " - " + e);
                    throw e;
                }
            };
        } catch (e) {
            console.log("[CERT-PINNING] ⚠️ OkHttp CertificatePinner not available: " + e);
        }
        
        // Hook Network Security Config for Android 7+ certificate pinning
        try {
            var NetworkSecurityPolicy = Java.use("android.security.NetworkSecurityPolicy");
            
            NetworkSecurityPolicy.getInstance.implementation = function() {
                var result = this.getInstance();
                
                send({
                    type: "certificate_pinning_monitoring",
                    operation: "network_security_policy",
                    timestamp: Date.now(),
                    description: "Network Security Policy accessed (Android 7+ certificate configuration)"
                });
                
                console.log("[CERT-PINNING] Network Security Policy accessed");
                return result;
            };
        } catch (e) {
            console.log("[CERT-PINNING] ⚠️ NetworkSecurityPolicy not available: " + e);
        }
        
        // Generic certificate pinning bypass detection
        // Monitor for common patterns indicating pinning bypass attempts
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                // Look for certificate pinning bypass classes
                if (className.toLowerCase().includes('trustall') || 
                    className.toLowerCase().includes('trusteverything') ||
                    className.toLowerCase().includes('nocertcheck') ||
                    className.toLowerCase().includes('bypassssl')) {
                    
                    try {
                        var SuspiciousClass = Java.use(className);
                        
                        send({
                            type: "certificate_pinning_vulnerability",
                            vulnerability_type: "pinning_bypass_detected",
                            suspicious_class: className,
                            timestamp: Date.now(),
                            stack_trace: getCurrentStackTrace(),
                            severity: "HIGH",
                            description: "Suspicious certificate validation bypass class detected",
                            evidence: {
                                operation: "class_enumeration",
                                class_name: className,
                                bypass_type: "suspicious_class_naming",
                                security_risk: "certificate_validation_bypass"
                            }
                        });
                        
                        console.log("[CERT-PINNING-VULN] 🚨 SUSPICIOUS CLASS: " + className);
                        
                    } catch (e) {
                        // Class might not be accessible
                    }
                }
            },
            onComplete: function() {
                console.log("[CERT-PINNING] 🔍 Certificate pinning bypass class enumeration complete");
            }
        });
        
        console.log("[CERT-PINNING] ✅ All certificate pinning hooks installed successfully");
        
    } catch (e) {
        console.log("[CERT-PINNING] ❌ Failed to install certificate pinning hooks: " + e);
    }
});