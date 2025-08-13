/**
 * Universal Emulator Detection Bypass
 * 
 * Generic emulator detection bypass that works across different APKs
 * by detecting common patterns and method names rather than hardcoded classes.
 * 
 * Author: AODS Team
 * Date: January 2025
 */

Java.perform(function() {
    console.log("[+] Universal Emulator Detection Bypass loaded");
    
    // Common emulator detection method names to hook
    var commonEmulatorMethods = [
        'isEmulator',
        'isRealDevice', 
        'checkEmulator',
        'detectEmulator',
        'isPhysicalDevice',
        'isDeviceReal',
        'emulatorDetection',
        'antiEmulator',
        'checkDevice',
        'validateDevice',
        'isGenuineDevice',
        'deviceValidation'
    ];
    
    // Common class name patterns that might contain emulator detection
    var emulatorDetectionPatterns = [
        /.*[Ee]mulator.*[Cc]heck.*/,
        /.*[Ee]mulator.*[Dd]etect.*/,
        /.*[Dd]evice.*[Cc]heck.*/,
        /.*[Dd]evice.*[Vv]alid.*/,
        /.*[Aa]nti.*[Ee]mu.*/,
        /.*[Ss]ecurity.*[Cc]heck.*/,
        /.*[Ee]nvironment.*[Cc]heck.*/
    ];
    
    /**
     * Generic emulator detection bypass using class enumeration
     */
    function universalEmulatorBypass() {
        console.log("[*] Starting universal emulator detection bypass...");
        
        try {
            // Get all loaded classes
            var loadedClasses = Java.enumerateLoadedClassesSync();
            var bypassedClasses = 0;
            var bypassedMethods = 0;
            
            loadedClasses.forEach(function(className) {
                try {
                    // Check if class name matches emulator detection patterns
                    var isEmulatorClass = emulatorDetectionPatterns.some(function(pattern) {
                        return pattern.test(className);
                    });
                    
                    if (isEmulatorClass) {
                        console.log("[*] Found potential emulator detection class: " + className);
                        
                        try {
                            var targetClass = Java.use(className);
                            bypassedClasses++;
                            
                            // Try to hook common emulator detection methods
                            commonEmulatorMethods.forEach(function(methodName) {
                                try {
                                    if (targetClass[methodName]) {
                                        // Hook method to always return false (not emulator)
                                        targetClass[methodName].implementation = function() {
                                            console.log("[BYPASS] " + className + "." + methodName + "() → returning false");
                                            return false;
                                        };
                                        bypassedMethods++;
                                        console.log("[+] Hooked: " + className + "." + methodName);
                                    }
                                } catch (e) {
                                    // Method might have different signature or not exist
                                    console.log("[DEBUG] Could not hook " + className + "." + methodName + ": " + e);
                                }
                            });
                            
                        } catch (classError) {
                            console.log("[DEBUG] Could not instantiate class " + className + ": " + classError);
                        }
                    }
                } catch (e) {
                    // Skip problematic classes
                }
            });
            
            console.log("[+] Universal bypass complete: " + bypassedClasses + " classes, " + bypassedMethods + " methods hooked");
            
        } catch (e) {
            console.log("[-] Universal emulator bypass failed: " + e);
        }
    }
    
    /**
     * Generate device-specific ID from seed for realistic spoofing
     */
    function generateDeviceSpecificId(seed) {
        // Simple hash function for generating realistic device IDs
        var hash = 0;
        for (var i = 0; i < seed.length; i++) {
            var char = seed.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        
        // Convert to hex and pad to 16 characters
        var hex = Math.abs(hash).toString(16);
        while (hex.length < 16) {
            hex = hex + Math.abs(hash * (i + 1)).toString(16).substring(0, 1);
        }
        return hex.substring(0, 16);
    }
    
    /**
     * Hook common Android APIs used for emulator detection
     */
    function hookCommonEmulatorAPIs() {
        console.log("[*] Hooking common emulator detection APIs...");
        
        try {
            // Hook Build properties with universal device profiles
            var Build = Java.use("android.os.Build");
            
            // Universal device profiles for realistic spoofing
            var deviceProfiles = [
                {
                    name: "Samsung Galaxy S21 5G",
                    fingerprint: "samsung/o1sks/o1s:12/SP1A.210812.016/G991BXXU5CVLL:user/release-keys",
                    model: "SM-G991B",
                    brand: "samsung",
                    manufacturer: "samsung",
                    device: "o1s",
                    hardware: "exynos2100",
                    product: "o1sks",
                    board: "exynos2100",
                    bootloader: "G991BXXU5CVLL"
                },
                {
                    name: "Google Pixel 6 Pro",
                    fingerprint: "google/raven/raven:13/TQ1A.230105.002/9325679:user/release-keys",
                    model: "Pixel 6 Pro",
                    brand: "google",
                    manufacturer: "Google",
                    device: "raven",
                    hardware: "raven",
                    product: "raven",
                    board: "raven",
                    bootloader: "slider-1.2-8893284"
                },
                {
                    name: "OnePlus 9 Pro",
                    fingerprint: "OnePlus/OnePlus9Pro/OnePlus9Pro:12/RKQ1.201105.002/2203151841:user/release-keys",
                    model: "LE2125",
                    brand: "OnePlus",
                    manufacturer: "OnePlus",
                    device: "OnePlus9Pro",
                    hardware: "qcom",
                    product: "OnePlus9Pro",
                    board: "kona",
                    bootloader: "unknown"
                },
                {
                    name: "Xiaomi Mi 11",
                    fingerprint: "Xiaomi/venus/venus:12/RKQ1.200826.002/V13.0.3.0.SKBCNXM:user/release-keys",
                    model: "M2011K2C",
                    brand: "Xiaomi",
                    manufacturer: "Xiaomi",
                    device: "venus",
                    hardware: "qcom",
                    product: "venus",
                    board: "kona",
                    bootloader: "unknown"
                }
            ];
            
            // Randomly select a device profile for realistic variation
            var selectedProfile = deviceProfiles[Math.floor(Math.random() * deviceProfiles.length)];
            
            // Apply selected device profile
            Build.FINGERPRINT.value = selectedProfile.fingerprint;
            Build.MODEL.value = selectedProfile.model;
            Build.BRAND.value = selectedProfile.brand;
            Build.MANUFACTURER.value = selectedProfile.manufacturer;
            Build.DEVICE.value = selectedProfile.device;
            Build.HARDWARE.value = selectedProfile.hardware;
            Build.PRODUCT.value = selectedProfile.product;
            Build.BOARD.value = selectedProfile.board;
            Build.BOOTLOADER.value = selectedProfile.bootloader;
            
            console.log("[+] Build properties spoofed to " + selectedProfile.name + " (Universal Profile)");
            
        } catch (e) {
            console.log("[-] Build properties spoofing failed: " + e);
        }
        
        try {
            // Hook SystemProperties
            var SystemProperties = Java.use("android.os.SystemProperties");
            
            SystemProperties.get.overload('java.lang.String').implementation = function(name) {
                // Use the same device profile as Build properties for consistency
                var spoofed = {
                    "ro.kernel.qemu": "0",
                    "ro.hardware": selectedProfile.hardware,
                    "ro.bootloader": selectedProfile.bootloader, 
                    "ro.product.model": selectedProfile.model,
                    "ro.product.device": selectedProfile.device,
                    "ro.product.brand": selectedProfile.brand,
                    "ro.product.manufacturer": selectedProfile.manufacturer,
                    "ro.product.board": selectedProfile.board,
                    "ro.product.name": selectedProfile.product,
                    "ro.build.fingerprint": selectedProfile.fingerprint,
                    "init.svc.qemud": "",
                    "init.svc.qemu-props": "",
                    "qemu.hw.mainkeys": "",
                    "qemu.sf.fake_camera": "",
                    "ro.bootmode": "unknown",
                    "ro.secure": "1",
                    "ro.debuggable": "0",
                    "ro.build.type": "user",
                    "ro.build.tags": "release-keys",
                    "ro.boot.verifiedbootstate": "green",
                    "ro.boot.flash.locked": "1"
                };
                
                if (name in spoofed) {
                    console.log("[BYPASS] SystemProperties.get(" + name + ") → " + spoofed[name] + " [" + selectedProfile.name + "]");
                    return spoofed[name];
                }
                return this.get(name);
            };
            
            console.log("[+] SystemProperties bypass applied");
            
        } catch (e) {
            console.log("[-] SystemProperties bypass failed: " + e);
        }
        
        try {
            // Hook File system checks
            var File = Java.use("java.io.File");
            
            File.exists.implementation = function() {
                var path = this.getAbsolutePath();
                            var emulatorPaths = [
                // QEMU/Android Emulator paths
                "/dev/socket/qemud",
                "/dev/qemu_pipe", 
                "/system/lib/libc_malloc_debug_qemu.so",
                "/sys/qemu_trace",
                "/system/bin/qemu-props",
                "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
                
                // Genymotion paths
                "/dev/socket/genyd",
                "/dev/socket/baseband_genyd",
                "/dev/socket/genymotion",
                "/system/lib/libdroid4x.so",
                
                // BlueStacks paths
                "/data/app/com.bluestacks.appmart",
                "/data/bluestacks.prop",
                "/data/data/com.bluestacks.settings",
                "/system/bin/bstk",
                "/system/lib/libbstshared.so",
                
                // Nox Player paths
                "/system/bin/nox",
                "/system/lib/libnoxspeedup.so", 
                "/data/data/com.bignox.app",
                "/system/noxspeedup",
                
                // MEmu paths
                "/system/lib/libmemu.so",
                "/data/data/com.microvirt.launcher",
                "/system/bin/memuc",
                
                // LDPlayer paths
                "/system/lib/libldplayer.so",
                "/data/data/com.ldplayer.launcher",
                
                // Andy Android Emulator
                "/system/lib/libandydrv.so",
                "/data/data/com.andyroid.appmart",
                
                // Generic emulator indicators
                "/proc/ioports",
                "/proc/version",
                "/system/lib/modules/vboxguest.ko",
                "/system/lib/modules/vboxsf.ko",
                "/dev/vboxuser",
                "/system/usr/keylayout/qwerty2.kl",
                "/system/etc/init.goldfish.rc",
                "/sys/devices/virtual/tty",
                "/dev/goldfish_pipe",
                "/dev/goldfish_sync",
                "/system/lib/hw/camera.goldfish.so",
                "/system/lib/hw/gps.goldfish.so",
                "/system/lib/hw/sensors.goldfish.so"
            ];
                
                for (var i = 0; i < emulatorPaths.length; i++) {
                    if (path.includes(emulatorPaths[i])) {
                        console.log("[BYPASS] File.exists(" + path + ") → false");
                        return false;
                    }
                }
                
                // Also block generic emulator indicators
                var lowerPath = path.toLowerCase();
                if (lowerPath.includes("qemu") || lowerPath.includes("goldfish") || 
                    lowerPath.includes("ranchu") || lowerPath.includes("genymotion") ||
                    lowerPath.includes("vbox") || lowerPath.includes("ttvm")) {
                    console.log("[BYPASS] File.exists(" + path + ") → false (generic)");
                    return false;
                }
                
                return this.exists();
            };
            
            console.log("[+] File system bypass applied");
            
        } catch (e) {
            console.log("[-] File system bypass failed: " + e);
        }
        
        try {
            // Hook Settings.Secure for android_id spoofing
            var Secure = Java.use("android.provider.Settings$Secure");
            
            Secure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(resolver, name) {
                if (name === "android_id") {
                    // Generate device-specific but realistic Android ID
                    var deviceSeed = selectedProfile.model + selectedProfile.device + selectedProfile.fingerprint.substring(0, 8);
                    var androidId = generateDeviceSpecificId(deviceSeed);
                    console.log("[BYPASS] Settings.Secure.getString(android_id) → " + androidId + " [" + selectedProfile.name + "]");
                    return androidId;
                }
                return this.getString(resolver, name);
            };
            
            console.log("[+] Settings.Secure bypass applied");
            
        } catch (e) {
            console.log("[-] Settings.Secure bypass failed: " + e);
        }
    }
    
    /**
     * Runtime method discovery and hooking
     */
    function discoverAndHookMethods() {
        console.log("[*] Starting runtime method discovery...");
        
        // Use Java.choose to find instances with emulator detection methods
        commonEmulatorMethods.forEach(function(methodName) {
            try {
                Java.enumerateLoadedClasses({
                    onMatch: function(className) {
                        try {
                            var clazz = Java.use(className);
                            if (clazz[methodName] && typeof clazz[methodName] === 'function') {
                                console.log("[*] Found method " + methodName + " in " + className);
                                
                                clazz[methodName].implementation = function() {
                                    console.log("[BYPASS] " + className + "." + methodName + "() → false");
                                    return false;
                                };
                                
                                console.log("[+] Hooked: " + className + "." + methodName);
                            }
                        } catch (e) {
                            // Skip classes that can't be processed
                        }
                    },
                    onComplete: function() {
                        console.log("[*] Method discovery complete for: " + methodName);
                    }
                });
            } catch (e) {
                console.log("[-] Method discovery failed for " + methodName + ": " + e);
            }
        });
    }
    
    /**
     * Hook return value patterns (boolean methods that might indicate emulator)
     */
    function hookBooleanReturnPatterns() {
        console.log("[*] Setting up boolean return pattern hooks...");
        
        // This is more aggressive - hook any boolean method that might return emulator status
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                try {
                    if (className.toLowerCase().includes("emulator") || 
                        className.toLowerCase().includes("device") ||
                        className.toLowerCase().includes("security")) {
                        
                        var clazz = Java.use(className);
                        var methods = clazz.class.getDeclaredMethods();
                        
                        methods.forEach(function(method) {
                            var methodName = method.getName();
                            var returnType = method.getReturnType().getName();
                            
                            // Hook boolean methods that might be emulator detection
                            if (returnType === "boolean" && 
                                (methodName.toLowerCase().includes("emulator") ||
                                 methodName.toLowerCase().includes("real") ||
                                 methodName.toLowerCase().includes("genuine") ||
                                 methodName.toLowerCase().includes("valid"))) {
                                
                                try {
                                    clazz[methodName].implementation = function() {
                                        console.log("[PATTERN_BYPASS] " + className + "." + methodName + "() → false");
                                        return false;
                                    };
                                    console.log("[+] Pattern hooked: " + className + "." + methodName);
                                } catch (e) {
                                    // Method might have parameters or be overloaded
                                }
                            }
                        });
                    }
                } catch (e) {
                    // Skip problematic classes
                }
            },
            onComplete: function() {
                console.log("[*] Boolean pattern hooking complete");
            }
        });
    }
    
    // Execute all bypass strategies
    console.log("[*] Executing universal emulator detection bypass strategies...");
    
    // Strategy 1: Hook common Android APIs
    hookCommonEmulatorAPIs();
    
    // Strategy 2: Universal class-based bypass
    setTimeout(function() {
        universalEmulatorBypass();
    }, 1000);
    
    // Strategy 3: Runtime method discovery
    setTimeout(function() {
        discoverAndHookMethods();
    }, 2000);
    
    // Strategy 4: Boolean pattern hooking (more aggressive)
    setTimeout(function() {
        hookBooleanReturnPatterns();
    }, 3000);
    
    console.log("[+] Universal emulator detection bypass setup complete");
    console.log("[*] This bypass works for AndroGoat, OWASP apps, and any APK with emulator detection");
});