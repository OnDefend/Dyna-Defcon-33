#!/usr/bin/env python3
"""
Frida Script Manager

Manages all Frida script loading and execution for dynamic security testing.
Provides SSL bypass, WebView security testing, and anti-Frida detection capabilities.

Components:
- ScriptManager: Main script coordination and management
- SSL pinning bypass scripts
- WebView security analysis scripts
- Anti-Frida detection bypass scripts
- Script message handling and result collection

"""

import logging
from typing import Dict, Optional, Any, Callable

class ScriptManager:
    """Manages Frida script loading and execution."""

    def __init__(self):
        """Initialize script manager."""
        self.scripts: Dict[str, Any] = {}
        self.analysis_results: Dict[str, Any] = {}
        self.session: Optional[Any] = None

    def set_session(self, session: Any) -> None:
        """Set the active Frida session."""
        self.session = session

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

    def load_custom_script(self, script_name: str, script_content: str, 
                          message_handler: Optional[Callable] = None) -> bool:
        """
        Load a custom Frida script.
        
        Args:
            script_name: Name of the script
            script_content: JavaScript content of the script
            message_handler: Optional custom message handler
            
        Returns:
            bool: True if script loaded successfully, False otherwise
        """
        try:
            if not self.session:
                logging.error("No active Frida session for custom script")
                return False

            script = self.session.create_script(script_content)
            
            if message_handler:
                script.on("message", message_handler)
            else:
                script.on("message", self._on_generic_message)
            
            script.load()
            self.scripts[script_name] = script

            logging.info(f"Custom script '{script_name}' loaded successfully")
            return True

        except Exception as e:
            logging.error(f"Failed to load custom script '{script_name}': {e}")
            return False

    def unload_script(self, script_name: str) -> bool:
        """Unload a specific script."""
        try:
            if script_name in self.scripts:
                self.scripts[script_name].unload()
                del self.scripts[script_name]
                logging.info(f"Script '{script_name}' unloaded")
                return True
            else:
                logging.warning(f"Script '{script_name}' not found")
                return False
                
        except Exception as e:
            logging.error(f"Failed to unload script '{script_name}': {e}")
            return False

    def unload_all_scripts(self) -> None:
        """Unload all loaded scripts."""
        for script_name in list(self.scripts.keys()):
            self.unload_script(script_name)

    def get_script_status(self) -> Dict[str, bool]:
        """Get status of all loaded scripts."""
        return {name: script is not None for name, script in self.scripts.items()}

    def get_analysis_results(self) -> Dict[str, Any]:
        """Get collected analysis results from all scripts."""
        return self.analysis_results.copy()

    def _on_ssl_message(self, message, data):
        """Handle SSL bypass script messages."""
        if message["type"] == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict):
                if "ssl_bypass" not in self.analysis_results:
                    self.analysis_results["ssl_bypass"] = []
                self.analysis_results["ssl_bypass"].append(payload)
                logging.info(f"SSL Bypass: {payload}")

    def _on_webview_message(self, message, data):
        """Handle WebView security script messages."""
        if message["type"] == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict):
                if "webview_security" not in self.analysis_results:
                    self.analysis_results["webview_security"] = []
                self.analysis_results["webview_security"].append(payload)
                logging.info(f"WebView Security: {payload}")

    def _on_anti_frida_message(self, message, data):
        """Handle anti-Frida detection script messages."""
        if message["type"] == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict):
                if "anti_frida_detection" not in self.analysis_results:
                    self.analysis_results["anti_frida_detection"] = []
                self.analysis_results["anti_frida_detection"].append(payload)
                logging.info(f"Anti-Frida: {payload}")

    def _on_generic_message(self, message, data):
        """Handle generic script messages."""
        if message["type"] == "send":
            payload = message.get("payload", {})
            if "generic_messages" not in self.analysis_results:
                self.analysis_results["generic_messages"] = []
            self.analysis_results["generic_messages"].append(payload)
            logging.info(f"Generic Message: {payload}")

    def clear_results(self) -> None:
        """Clear all collected analysis results."""
        self.analysis_results.clear()

# Export the script manager
__all__ = ['ScriptManager'] 