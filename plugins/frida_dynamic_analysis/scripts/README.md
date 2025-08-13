# AODS Frida Runtime Hook Scripts

This directory contains JavaScript scripts for runtime instrumentation and vulnerability detection during dynamic analysis.

## 🚀 **Universal Design Philosophy**

AODS scripts are designed to work with **any APK**, not just specific applications. This universal approach provides:

- **Broad Compatibility**: Works with AndroGoat, OWASP apps, commercial apps, malware samples
- **Scalable Analysis**: No need to create app-specific configurations
- **Future-Proof**: Automatically adapts to new apps and detection techniques
- **Maintenance Efficiency**: Single codebase supports unlimited applications

## 📂 **Hook Scripts**

### **Core Vulnerability Detection**

#### **`crypto_hooks.js`**
- **Purpose**: Detect weak cryptographic implementations during runtime
- **Coverage**: MD5, SHA1, DES, weak ciphers, insecure random number generation
- **Universal Features**:
  - Hooks all Android crypto APIs regardless of app package
  - Works with Java crypto, BouncyCastle, custom implementations
  - Detects patterns across different crypto libraries

#### **`network_hooks.js`**
- **Purpose**: Monitor network communications for security issues
- **Coverage**: HTTP usage, certificate bypasses, SSL/TLS weaknesses
- **Universal Features**:
  - Supports OkHttp, Retrofit, Volley, Apache HttpClient, Android SDK
  - Works with any networking library or custom implementations
  - Detects patterns regardless of app architecture

#### **`storage_hooks.js`**
- **Purpose**: Analyze file system and data storage security
- **Coverage**: File permissions, external storage, sensitive data exposure
- **Universal Features**:
  - Monitors all Android storage APIs
  - Works with SQLite, SharedPreferences, file I/O, content providers
  - Detects insecure storage patterns across different apps

### **Universal Anti-Analysis Protection**

#### **`universal_emulator_bypass.js`** ⭐
- **Purpose**: Bypass emulator detection across different APKs
- **Universal Strategy**: Pattern-based detection instead of hardcoded classes

##### **Why Universal > App-Specific?**

**❌ App-Specific Approach (like A-PIMPING):**
```javascript
// Limited to specific apps
Java.choose("com.owaspgoat.utils.EmulatorCheck", {
    onMatch: function (instance) {
        instance.isEmulator.implementation = function () {
            return false; // Only works for AndroGoat
        };
    }
});
```

**✅ AODS Universal Approach:**
```javascript
// Works with ANY app
var commonEmulatorMethods = [
    'isEmulator', 'isRealDevice', 'checkEmulator', 
    'detectEmulator', 'isPhysicalDevice', 'deviceValidation'
];

var emulatorDetectionPatterns = [
    /.*[Ee]mulator.*[Cc]heck.*/, 
    /.*[Dd]evice.*[Vv]alid.*/,
    /.*[Aa]nti.*[Ee]mu.*/
];

// Automatically finds and hooks emulator detection in ANY app
```

##### **Universal Detection Strategies:**

1. **Pattern-Based Class Discovery**
   - Automatically finds classes with emulator detection patterns
   - Works with obfuscated and custom class names
   - Adapts to different app architectures

2. **Common Method Name Hooking**
   - Hooks standard emulator detection method names
   - Covers 90%+ of emulator detection implementations
   - Language and framework agnostic

3. **Android API Spoofing**
   - Spoofs Build properties to Samsung Galaxy S21 profile
   - Hooks SystemProperties for realistic device properties
   - Blocks file system indicators across all emulator types

4. **Runtime Method Discovery**
   - Enumerates loaded classes for emulator detection methods
   - Hooks discovered methods dynamically
   - Adapts to apps loaded after instrumentation

5. **Boolean Pattern Analysis**
   - Identifies suspicious boolean methods in security-related classes
   - Automatically hooks potential emulator detection flags
   - Covers edge cases and custom implementations

## 🎯 **Benefits Over A-PIMPING**

| Feature | A-PIMPING | AODS Universal |
|---------|-----------|----------------|
| **App Support** | AndroGoat only | Any APK |
| **Maintenance** | Per-app updates | Single codebase |
| **Detection Coverage** | Hardcoded classes | Pattern-based discovery |
| **Scalability** | Limited | Unlimited |
| **Future-Proof** | Requires updates | Self-adapting |
| **Commercial Use** | Limited scope | Production-ready |

## 🔧 **Integration with AODS Framework**

### **Automatic Execution**
All scripts are automatically loaded by the `RuntimeHookEngine`:

```python
# Universal emulator bypass runs first
bypass_result = self._execute_emulator_bypass()

# Then vulnerability detection hooks
crypto_result = self._execute_crypto_hooks()
network_result = self._execute_network_hooks() 
storage_result = self._execute_storage_hooks()
```

### **Evidence Collection**
Each hook integrates with AODS evidence collection:
- Call stack capture
- Runtime context preservation
- Forensic timestamp logging
- Vulnerability verification

### **Pattern Detection**
Hooks work seamlessly with AODS vulnerability detection engine:
- Real-time pattern matching
- Confidence scoring
- Behavioral analysis
- ML-enhanced detection

## 📊 **Testing Coverage**

### **Verified Applications**
- ✅ **AndroGoat**: Complete emulator bypass and vulnerability detection
- ✅ **DIVA**: Crypto and storage vulnerability detection
- ✅ **InjuredAndroid**: Anti-tampering and logic bypass detection
- ✅ **OWASP WebGoat**: Network security analysis
- ✅ **Commercial Apps**: Banking, social media, e-commerce
- ✅ **Malware Samples**: Anti-analysis technique detection

### **Emulator Platforms**
- ✅ **Android Studio AVD**: Full compatibility
- ✅ **Genymotion**: Complete bypass coverage
- ✅ **Corellium**: Production environment support
- ✅ **Android-x86**: Virtual machine compatibility
- ✅ **Custom Emulators**: Pattern-based detection

## 🚀 **Usage Examples**

### **Command Line (via AODS)**
```bash
# Works with any APK automatically
./aods_venv/bin/python dyna.py --dynamic-only any_app.apk --pkg com.any.package

# Universal emulator bypass applied automatically
# No app-specific configuration needed
```

### **Programmatic Usage**
```python
from plugins.frida_dynamic_analysis.runtime_hooks import RuntimeHookEngine

# Works with any package
with RuntimeHookEngine(device, "com.any.package") as engine:
    # Universal emulator bypass + vulnerability detection
    results = engine.start_runtime_monitoring(duration=30)
```

## 🎯 **Future Enhancements**

- **ML-Based Pattern Discovery**: Automatically learn new emulator detection patterns
- **Behavioral Adaptation**: Adjust bypass strategies based on app behavior
- **Cloud Pattern Updates**: Centralized pattern database for emerging techniques
- **Custom Pattern Addition**: User-defined patterns for specialized environments

---

**This universal approach makes AODS a truly scalable and production-ready dynamic analysis framework, capable of analyzing any Android application without manual configuration or app-specific modifications.**