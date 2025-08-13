/**
 * Crypto Function Hooks
 * 
 * Frida JavaScript code to intercept cryptographic function calls
 * and detect weak cryptographic algorithms during runtime.
 * 
 * Author: AODS Team
 * Date: January 2025
 */

Java.perform(function() {
    console.log("[+] Crypto hooks loaded - monitoring cryptographic operations");
    
    try {
        // Hook MessageDigest.getInstance for algorithm detection
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.getInstance.overload("java.lang.String").implementation = function(algorithm) {
            var result = this.getInstance(algorithm);
            
            // Get current stack trace for evidence
            var stackTrace = "";
            try {
                var Thread = Java.use("java.lang.Thread");
                var elements = Thread.currentThread().getStackTrace();
                for (var i = 0; i < Math.min(elements.length, 5); i++) {
                    stackTrace += elements[i].toString() + "\n";
                }
            } catch (e) {
                stackTrace = "Stack trace unavailable: " + e;
            }
            
            // Send vulnerability data
            send({
                type: "crypto_vulnerability", 
                algorithm: algorithm,
                timestamp: Date.now(),
                stack_trace: stackTrace,
                method: "MessageDigest.getInstance",
                thread: Java.use("java.lang.Thread").currentThread().getName()
            });
            
            console.log("[CRYPTO] MessageDigest algorithm: " + algorithm);
            return result;
        };
        
        // Hook Cipher.getInstance for cipher algorithm detection
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.getInstance.overload("java.lang.String").implementation = function(transformation) {
            var result = this.getInstance(transformation);
            
            // Extract algorithm from transformation (e.g., "AES/CBC/PKCS5Padding" -> "AES")
            var algorithm = transformation.split('/')[0];
            
            send({
                type: "crypto_vulnerability",
                algorithm: algorithm,
                transformation: transformation,
                timestamp: Date.now(),
                method: "Cipher.getInstance",
                thread: Java.use("java.lang.Thread").currentThread().getName()
            });
            
            console.log("[CRYPTO] Cipher transformation: " + transformation);
            return result;
        };
        
        // Hook KeyGenerator.getInstance for key generation algorithm detection
        var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
        KeyGenerator.getInstance.overload("java.lang.String").implementation = function(algorithm) {
            var result = this.getInstance(algorithm);
            
            send({
                type: "crypto_vulnerability",
                algorithm: algorithm,
                timestamp: Date.now(),
                method: "KeyGenerator.getInstance",
                thread: Java.use("java.lang.Thread").currentThread().getName()
            });
            
            console.log("[CRYPTO] KeyGenerator algorithm: " + algorithm);
            return result;
        };
        
        // Hook Mac.getInstance for MAC algorithm detection
        var Mac = Java.use("javax.crypto.Mac");
        Mac.getInstance.overload("java.lang.String").implementation = function(algorithm) {
            var result = this.getInstance(algorithm);
            
            send({
                type: "crypto_vulnerability",
                algorithm: algorithm,
                timestamp: Date.now(),
                method: "Mac.getInstance",
                thread: Java.use("java.lang.Thread").currentThread().getName()
            });
            
            console.log("[CRYPTO] Mac algorithm: " + algorithm);
            return result;
        };
        
        // Hook SecureRandom for random number generation monitoring
        var SecureRandom = Java.use("java.security.SecureRandom");
        SecureRandom.$init.overload().implementation = function() {
            var result = this.$init();
            
            send({
                type: "crypto_operation",
                operation: "SecureRandom.init",
                timestamp: Date.now(),
                method: "SecureRandom.init",
                thread: Java.use("java.lang.Thread").currentThread().getName()
            });
            
            console.log("[CRYPTO] SecureRandom initialized");
            return result;
        };
        
        // Hook KeyStore operations for key storage monitoring
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.load.overload("java.io.InputStream", "[C").implementation = function(stream, password) {
            var result = this.load(stream, password);
            
            send({
                type: "crypto_operation",
                operation: "KeyStore.load",
                has_password: password !== null,
                timestamp: Date.now(),
                method: "KeyStore.load",
                thread: Java.use("java.lang.Thread").currentThread().getName()
            });
            
            console.log("[CRYPTO] KeyStore loaded with password: " + (password !== null));
            return result;
        };
        
        // Hook signature verification for digital signature monitoring
        var Signature = Java.use("java.security.Signature");
        Signature.getInstance.overload("java.lang.String").implementation = function(algorithm) {
            var result = this.getInstance(algorithm);
            
            send({
                type: "crypto_vulnerability",
                algorithm: algorithm,
                timestamp: Date.now(),
                method: "Signature.getInstance",
                thread: Java.use("java.lang.Thread").currentThread().getName()
            });
            
            console.log("[CRYPTO] Signature algorithm: " + algorithm);
            return result;
        };
        
        console.log("[+] All crypto hooks successfully installed");
        
    } catch (e) {
        console.log("[-] Error installing crypto hooks: " + e);
        send({
            type: "hook_error",
            error: e.toString(),
            hook_type: "crypto",
            timestamp: Date.now()
        });
    }
});

// Additional utility functions for crypto analysis
Java.perform(function() {
    // Monitor custom crypto implementations that might use weak algorithms
    try {
        // Hook common base64 encoding/decoding (often used with crypto)
        var Base64 = Java.use("android.util.Base64");
        
        Base64.encodeToString.overload("[B", "int").implementation = function(input, flags) {
            var result = this.encodeToString(input, flags);
            
            send({
                type: "crypto_operation",
                operation: "Base64.encode",
                data_length: input.length,
                timestamp: Date.now(),
                method: "Base64.encodeToString"
            });
            
            return result;
        };
        
        Base64.decode.overload("java.lang.String", "int").implementation = function(str, flags) {
            var result = this.decode(str, flags);
            
            send({
                type: "crypto_operation",
                operation: "Base64.decode",
                timestamp: Date.now(),
                method: "Base64.decode"
            });
            
            return result;
        };
        
    } catch (e) {
        console.log("[-] Error installing Base64 hooks: " + e);
    }
});